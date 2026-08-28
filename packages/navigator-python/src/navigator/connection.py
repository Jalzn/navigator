import asyncio
import base64
import hashlib
import json
import math
import os
import platform
import secrets
import shutil
import signal
import stat
import tempfile
from dataclasses import dataclass
from importlib import resources
from pathlib import Path, PurePosixPath
from typing import Any, Optional

import grpc

from .errors import (
    IncompatibleProtocol,
    InvalidRequest,
    NavigatorError,
    TransportUnavailable,
    Unsupported,
)
from .models import RetryClass

_AUTH_HEADER = "x-navigator-bootstrap"
_MAX_BINARY_BYTES = 256 * 1024 * 1024
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_STARTUP_DIAGNOSTIC_BYTES = 4096
_MAX_CHANNEL_CLOSE_SECONDS = 1.0
_MIN_CLEANUP_WAIT_SECONDS = 0.05
_DEFAULT_STARTUP_TIMEOUT_SECONDS = 30.0
_DEFAULT_SHUTDOWN_TIMEOUT_SECONDS = 10.0
_DEFAULT_OPERATION_REPORT_DEADLINE_SECONDS = 600.0
_MAX_CLEANUP_WAIT_SECONDS = 30.0
_MAX_GROUP_OBSERVATION_SECONDS = 0.25
_RUNTIME_PACKAGE = "navigator._runtime"
_CAPABILITIES = (
    "approvals.v1",
    "artifacts.v1",
    "consumer.tools.v1",
    "events.replay.v1",
    "operation.execution.v1",
    "operation.cancellation.v1",
    "recovery.resolution.v1",
    "resource.snapshots.v1",
    "session.lifecycle.v1",
    "session.open-modes.v1",
)


class _AuthenticatedStub:
    def __init__(self, stub: Any, credential: str) -> None:
        self._stub = stub
        self._metadata = ((_AUTH_HEADER, credential),)

    def __getattr__(self, name: str) -> Any:
        method = getattr(self._stub, name)

        def authenticated(request: Any) -> Any:
            return method(request, metadata=self._metadata)

        return authenticated


async def connect(
    endpoint: str,
    credential: str,
    *,
    capabilities: tuple[str, ...] = _CAPABILITIES,
    timeout: float = 5.0,
) -> Any:
    """Connect, authenticate, and negotiate before exposing a mutable client."""
    from ._transport.navigator.consumer.v1 import consumer_pb2_grpc
    from .client import Navigator

    if not endpoint.startswith("unix:") or "\x00" in endpoint:
        raise InvalidRequest(1, "A Unix-domain endpoint is required", RetryClass.NEVER)
    if not credential or any(ord(value) < 0x21 or ord(value) > 0x7E for value in credential):
        raise InvalidRequest(1, "Invalid bootstrap credential", RetryClass.NEVER)
    # gRPC's UDS resolver may otherwise derive an invalid HTTP/2 `:authority`
    # from the socket path. Hyper/tonic correctly rejects that at the protocol
    # layer before the RPC reaches Navigator authentication.
    channel = grpc.aio.insecure_channel(
        endpoint,
        options=(("grpc.default_authority", "localhost"),),
    )
    stub = _AuthenticatedStub(consumer_pb2_grpc.NavigatorConsumerStub(channel), credential)
    client = Navigator(stub, None, channel)
    try:
        await asyncio.wait_for(client.negotiate(capabilities=capabilities), timeout)
    except BaseException:
        try:
            await asyncio.wait_for(channel.close(grace=0), min(1.0, max(0.05, timeout)))
        except (asyncio.TimeoutError, asyncio.CancelledError):
            pass
        raise
    return client


def _verified_binary(path: Path, expected_sha256: str) -> Path:
    if len(expected_sha256) != 64 or any(
        value not in "0123456789abcdef" for value in expected_sha256
    ):
        raise InvalidRequest(1, "Invalid executable digest", RetryClass.NEVER)
    if path.is_symlink():
        raise InvalidRequest(1, "Executable must not be a symbolic link", RetryClass.NEVER)
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_size > _MAX_BINARY_BYTES:
        raise InvalidRequest(1, "Invalid executable", RetryClass.NEVER)
    if details.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise InvalidRequest(1, "Executable is not trusted", RetryClass.NEVER)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != expected_sha256:
        raise InvalidRequest(1, "Executable digest mismatch", RetryClass.NEVER)
    return path.resolve(strict=True)


@dataclass(frozen=True)
class _RuntimeRecord:
    path: str
    sha256: str
    size: int


@dataclass(frozen=True)
class _BundledRuntime:
    root: Path
    target: str
    driver_id: str
    pi_working_directory: str
    navigatord: _RuntimeRecord
    node: _RuntimeRecord
    pi_entrypoint: _RuntimeRecord
    acceptance_provider: _RuntimeRecord
    pi_tree: tuple[_RuntimeRecord, ...]
    trusted_artifacts: tuple[_RuntimeRecord, ...]


def _runtime_record(value: Any, target: str) -> _RuntimeRecord:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size"}:
        raise ValueError
    relative = value["path"]
    digest = value["sha256"]
    size = value["size"]
    if not isinstance(relative, str) or not isinstance(digest, str):
        raise TypeError
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() != relative
        or path.parts[0] != target
        or any(part in ("", ".", "..") for part in path.parts)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or size > _MAX_BINARY_BYTES
    ):
        raise ValueError
    return _RuntimeRecord(path.as_posix(), digest, size)


def _verify_runtime_record(root: Path, record: _RuntimeRecord) -> None:
    path = root.joinpath(*PurePosixPath(record.path).parts)
    if path.is_symlink():
        raise ValueError
    details = path.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_size != record.size:
        raise ValueError
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    if digest.hexdigest() != record.sha256:
        raise ValueError


def _bundled_runtime() -> _BundledRuntime:
    machine = platform.machine().lower()
    architecture = "arm64" if machine in ("arm64", "aarch64") else machine
    target = f"{platform.system().lower()}-{architecture}"
    try:
        root = resources.files(_RUNTIME_PACKAGE)
        raw = root.joinpath("manifest.json").read_bytes()
        if len(raw) > _MAX_MANIFEST_BYTES:
            raise ValueError
        manifest = json.loads(raw)
        if not isinstance(manifest, dict) or set(manifest) != {"artifacts", "version"}:
            raise ValueError
        artifacts = manifest["artifacts"]
        if not isinstance(artifacts, dict) or target not in artifacts:
            raise KeyError(target)
        if manifest["version"] != 2 or not artifacts:
            raise ValueError
        parsed: dict[str, _BundledRuntime] = {}
        filesystem_root = Path(str(root))
        for artifact_target, value in artifacts.items():
            if (
                not isinstance(artifact_target, str)
                or not artifact_target
                or PurePosixPath(artifact_target).parts != (artifact_target,)
                or artifact_target in (".", "..")
                or not isinstance(value, dict)
                or set(value)
                != {
                    "acceptance_provider",
                    "driver_id",
                    "navigatord",
                    "node",
                    "pi_entrypoint",
                    "pi_tree",
                    "pi_working_directory",
                    "trusted_artifacts",
                }
            ):
                raise ValueError
            driver_id = value["driver_id"]
            working = value["pi_working_directory"]
            if (
                not isinstance(driver_id, str)
                or len(driver_id) != 32
                or int(driver_id, 16) == 0
                or not isinstance(working, str)
                or PurePosixPath(working).parts != (artifact_target, "pi")
            ):
                raise ValueError
            navigatord = _runtime_record(value["navigatord"], artifact_target)
            node = _runtime_record(value["node"], artifact_target)
            entrypoint = _runtime_record(value["pi_entrypoint"], artifact_target)
            provider = _runtime_record(value["acceptance_provider"], artifact_target)
            if any(record.size == 0 for record in (navigatord, node, entrypoint, provider)):
                raise ValueError
            if PurePosixPath(navigatord.path).parts != (artifact_target, "navigatord"):
                raise ValueError
            if PurePosixPath(node.path).parts != (artifact_target, "node"):
                raise ValueError
            tree_value = value["pi_tree"]
            trusted_value = value["trusted_artifacts"]
            if (
                not isinstance(tree_value, list)
                or not tree_value
                or not isinstance(trusted_value, list)
            ):
                raise ValueError
            tree = tuple(_runtime_record(item, artifact_target) for item in tree_value)
            trusted = tuple(_runtime_record(item, artifact_target) for item in trusted_value)
            if (
                [item.path for item in tree] != sorted(item.path for item in tree)
                or len({item.path for item in tree}) != len(tree)
                or entrypoint not in tree
                or trusted != (node, entrypoint, provider)
            ):
                raise ValueError
            recorded_pi = {item.path for item in tree}
            pi_paths = tuple(filesystem_root.joinpath(artifact_target, "pi").rglob("*"))
            if any(path.is_symlink() for path in pi_paths):
                raise ValueError
            actual_pi = {
                path.relative_to(filesystem_root).as_posix() for path in pi_paths if path.is_file()
            }
            if recorded_pi != actual_pi:
                raise ValueError
            records = (navigatord, node, provider, *tree)
            if len({item.path for item in records}) != len(records):
                raise ValueError
            for item in records:
                _verify_runtime_record(filesystem_root, item)
            parsed[artifact_target] = _BundledRuntime(
                filesystem_root,
                artifact_target,
                driver_id,
                working,
                navigatord,
                node,
                entrypoint,
                provider,
                tree,
                trusted,
            )
        if target not in parsed:
            raise KeyError(target)
        return parsed[target]
    except (FileNotFoundError, KeyError, OSError, TypeError):
        raise Unsupported(
            17, f"No packaged Navigator runtime for {target}", RetryClass.NEVER
        ) from None
    except (OverflowError, ValueError):
        raise InvalidRequest(1, "Invalid packaged Navigator runtime", RetryClass.NEVER) from None


def _private_verified_copy(
    source: Path,
    destination: Path,
    expected_sha256: str,
    *,
    mode: int,
    kind: str,
    allow_empty: bool = False,
) -> Path:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    source_descriptor = os.open(source, flags)
    try:
        destination_descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except BaseException:
        os.close(source_descriptor)
        raise
    digest = hashlib.sha256()
    total = 0
    try:
        details = os.fstat(source_descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise InvalidRequest(1, f"Invalid {kind}", RetryClass.NEVER)
        while block := os.read(source_descriptor, 1024 * 1024):
            total += len(block)
            if total > _MAX_BINARY_BYTES:
                raise InvalidRequest(1, f"Invalid {kind}", RetryClass.NEVER)
            digest.update(block)
            view = memoryview(block)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    raise OSError("short executable copy")
                view = view[written:]
        os.fsync(destination_descriptor)
    finally:
        os.close(source_descriptor)
        os.close(destination_descriptor)
    if (total == 0 and not allow_empty) or digest.hexdigest() != expected_sha256:
        destination.unlink(missing_ok=True)
        raise InvalidRequest(1, f"{kind.capitalize()} digest mismatch", RetryClass.NEVER)
    return destination


def _private_binary_copy(source: Path, destination: Path, expected_sha256: str) -> Path:
    return _private_verified_copy(
        source, destination, expected_sha256, mode=0o700, kind="executable"
    )


def _verify_socket(path: Path) -> None:
    details = path.lstat()
    if (
        not stat.S_ISSOCK(details.st_mode)
        or details.st_uid != os.getuid()
        or stat.S_IMODE(details.st_mode) & 0o077
    ):
        raise InvalidRequest(1, "Managed socket is not private", RetryClass.NEVER)


def _startup_diagnostic(path: Path, credential: str) -> str:
    try:
        raw = path.read_bytes()[:_MAX_STARTUP_DIAGNOSTIC_BYTES]
    except OSError:
        return ""
    return " ".join(raw.decode("utf-8", errors="replace").replace(credential, "<redacted>").split())


async def _capture_bounded_diagnostic(descriptor: int, path: Path) -> None:
    """Drain child stderr without ever retaining more than the public diagnostic bound."""
    retained = bytearray()
    os.set_blocking(descriptor, False)
    try:
        while True:
            try:
                block = os.read(descriptor, 64 * 1024)
            except BlockingIOError:
                await asyncio.sleep(0.01)
                continue
            if not block:
                return
            retained.extend(block)
            if len(retained) > _MAX_STARTUP_DIAGNOSTIC_BYTES:
                del retained[:-_MAX_STARTUP_DIAGNOSTIC_BYTES]
            with path.open("r+b") as destination:
                destination.write(retained)
                destination.truncate()
            await asyncio.sleep(0)
    finally:
        os.close(descriptor)


class _SpawnedProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self._returncode: Optional[int] = None

    @property
    def returncode(self) -> Optional[int]:
        self._poll()
        return self._returncode

    def _poll(self) -> None:
        if self._returncode is not None:
            return
        try:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            # Another owner may have won the waitpid race.  There is no child
            # left for us to reap, so wait() must be allowed to complete.
            self._returncode = 0
            return
        if waited == self.pid:
            self._returncode = os.waitstatus_to_exitcode(status)

    def terminate(self) -> None:
        try:
            os.kill(self.pid, signal.SIGTERM)
        except ProcessLookupError:
            self._poll()

    def kill(self) -> None:
        try:
            os.kill(self.pid, signal.SIGKILL)
        except ProcessLookupError:
            self._poll()

    def signal_group(self, value: signal.Signals) -> None:
        try:
            os.killpg(self.pid, value)
        except ProcessLookupError:
            pass

    def group_exists(self) -> bool:
        try:
            os.killpg(self.pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            # EPERM proves that a process group still exists; it does not prove
            # that cleanup succeeded.
            return True
        return True

    async def wait(self) -> int:
        while self.returncode is None:
            await asyncio.sleep(0.01)
        assert self._returncode is not None
        return self._returncode


def _spawn(arguments: list[str], diagnostic_descriptor: int) -> _SpawnedProcess:
    null_descriptor = os.open(os.devnull, os.O_RDWR)
    try:
        actions: list[tuple[int, ...]] = [
            (os.POSIX_SPAWN_DUP2, null_descriptor, 0),
            (os.POSIX_SPAWN_DUP2, null_descriptor, 1),
            (os.POSIX_SPAWN_DUP2, diagnostic_descriptor, 2),
        ]
        # A private process group lets cleanup reach descendants which retain
        # the inherited group.  A descendant that deliberately calls setsid(2)
        # has left this ownership boundary and cannot be claimed as managed.
        inherited = {
            key: os.environ[key]
            for key in ("LANG", "LC_ALL", "PATH", "TMPDIR")
            if key in os.environ
        }
        pid = os.posix_spawn(arguments[0], arguments, inherited, file_actions=actions, setpgroup=0)
    finally:
        os.close(null_descriptor)
    return _SpawnedProcess(pid)


class LocalNavigator:
    """Owns one explicitly selected navigatord child, never the durable Session."""

    _PI_TOOL_ALLOWLIST = frozenset({"read", "grep", "find", "ls", "bash", "edit", "write"})

    def __init__(
        self,
        *,
        data_dir: os.PathLike[str],
        binary: Optional[os.PathLike[str]] = None,
        binary_sha256: Optional[str] = None,
        startup_timeout: float = _DEFAULT_STARTUP_TIMEOUT_SECONDS,
        shutdown_timeout: float = _DEFAULT_SHUTDOWN_TIMEOUT_SECONDS,
        operation_report_deadline: float = _DEFAULT_OPERATION_REPORT_DEADLINE_SECONDS,
        capabilities: tuple[str, ...] = _CAPABILITIES,
        driver_catalog: Optional[os.PathLike[str]] = None,
        driver_catalog_sha256: Optional[str] = None,
        driver_profiles: tuple[str, ...] = (),
        pi_auth_path: Optional[os.PathLike[str]] = None,
        codex_auth_path: Optional[os.PathLike[str]] = None,
        pi_provider: str = "faux",
        pi_model: str = "faux-1",
        pi_cwd: Optional[os.PathLike[str]] = None,
        pi_tools: tuple[str, ...] = (),
        pi_hierarchy_tools: bool = True,
    ) -> None:
        self._binary = Path(binary) if binary is not None else None
        self._digest = binary_sha256
        self._data_dir = Path(data_dir)
        self._startup_timeout = startup_timeout
        self._shutdown_timeout = shutdown_timeout
        self._operation_report_deadline = operation_report_deadline
        self._capabilities = capabilities
        self._driver_catalog = Path(driver_catalog) if driver_catalog is not None else None
        self._driver_catalog_sha256 = driver_catalog_sha256
        self._driver_profiles = driver_profiles
        self._pi_auth_path = Path(pi_auth_path) if pi_auth_path is not None else None
        self._codex_auth_path = Path(codex_auth_path) if codex_auth_path is not None else None
        self._pi_provider = pi_provider
        self._pi_model = pi_model
        self._pi_cwd = Path(pi_cwd) if pi_cwd is not None else None
        self._pi_tools = pi_tools
        self._pi_hierarchy_tools = pi_hierarchy_tools
        self._runtime: Optional[Path] = None
        self._process: Optional[_SpawnedProcess] = None
        self._client: Any = None
        self._diagnostic_path: Optional[Path] = None
        self._diagnostic_task: Optional[asyncio.Task[None]] = None
        self._cleanup_task: Optional[asyncio.Task[None]] = None

    async def __aenter__(self) -> Any:
        if not math.isfinite(self._startup_timeout) or self._startup_timeout <= 0:
            raise InvalidRequest(1, "Invalid startup timeout", RetryClass.NEVER)
        if not math.isfinite(self._shutdown_timeout) or self._shutdown_timeout < 0:
            raise InvalidRequest(1, "Invalid shutdown timeout", RetryClass.NEVER)
        if (
            not math.isfinite(self._operation_report_deadline)
            or self._operation_report_deadline <= 0
            or self._operation_report_deadline > 86_400
        ):
            raise InvalidRequest(1, "Invalid operation report deadline", RetryClass.NEVER)
        if self._cleanup_task is not None:
            if not self._cleanup_task.done():
                raise InvalidRequest(1, "Managed cleanup is in progress", RetryClass.NEVER)
            self._cleanup_task = None
        if (self._binary is None) != (self._digest is None):
            raise InvalidRequest(1, "Executable override identity is incomplete", RetryClass.NEVER)
        if any(not isinstance(tool, str) for tool in self._pi_tools) or len(
            self._pi_tools
        ) != len(set(self._pi_tools)) or any(
            tool not in self._PI_TOOL_ALLOWLIST for tool in self._pi_tools
        ):
            raise InvalidRequest(1, "Pi tools must be unique and allowlisted", RetryClass.NEVER)
        if not isinstance(self._pi_hierarchy_tools, bool):
            raise InvalidRequest(1, "Pi hierarchy tools selection must be boolean", RetryClass.NEVER)
        pi_cwd: Optional[Path] = None
        if self._pi_cwd is not None:
            try:
                supplied_details = self._pi_cwd.lstat()
                pi_cwd = self._pi_cwd.resolve(strict=True)
                resolved_details = pi_cwd.stat()
            except (FileNotFoundError, OSError) as error:
                raise InvalidRequest(1, "Pi working directory is invalid", RetryClass.NEVER) from error
            if (
                stat.S_ISLNK(supplied_details.st_mode)
                or not stat.S_ISDIR(resolved_details.st_mode)
                or resolved_details.st_uid != os.getuid()
            ):
                raise InvalidRequest(1, "Pi working directory must be an owned directory, not a symbolic link", RetryClass.NEVER)
        bundled: Optional[_BundledRuntime] = None
        if self._binary is None:
            bundled = _bundled_runtime()
            binary_source = bundled.root.joinpath(*PurePosixPath(bundled.navigatord.path).parts)
            binary_digest = bundled.navigatord.sha256
        else:
            assert self._digest is not None
            binary_source = _verified_binary(self._binary, self._digest)
            binary_digest = self._digest
        catalog_source: Optional[Path] = None
        catalog_digest: Optional[str] = None
        if self._driver_catalog is not None:
            if self._driver_catalog_sha256 is None or not self._driver_profiles:
                raise InvalidRequest(1, "Driver catalog identity is incomplete", RetryClass.NEVER)
            catalog_source = _verified_binary(self._driver_catalog, self._driver_catalog_sha256)
            catalog_digest = self._driver_catalog_sha256
        elif self._driver_catalog_sha256 is not None or self._driver_profiles:
            raise InvalidRequest(1, "Driver catalog is missing", RetryClass.NEVER)
        if self._data_dir.is_symlink():
            raise InvalidRequest(
                1, "Managed data directory must not be a symbolic link", RetryClass.NEVER
            )
        self._data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        data_details = self._data_dir.stat()
        if (
            not stat.S_ISDIR(data_details.st_mode)
            or data_details.st_uid != os.getuid()
            or stat.S_IMODE(data_details.st_mode) & 0o077
        ):
            raise InvalidRequest(1, "Managed data directory must be private", RetryClass.NEVER)
        runtime = Path(tempfile.mkdtemp(prefix="navigator-", dir="/tmp"))
        runtime.chmod(0o700)
        self._runtime = runtime
        generated_catalog = False
        try:
            binary = _private_binary_copy(binary_source, runtime / "navigatord", binary_digest)
            catalog: Optional[Path] = None
            if catalog_source is not None:
                assert catalog_digest is not None
                catalog = _private_verified_copy(
                    catalog_source,
                    runtime / "drivers.json",
                    catalog_digest,
                    mode=0o600,
                    kind="driver catalog",
                )
            elif bundled is not None:
                generated_catalog = True
                copied: dict[str, Path] = {}
                for record in (bundled.node, bundled.acceptance_provider, *bundled.pi_tree):
                    relative = PurePosixPath(record.path)
                    destination = runtime.joinpath(*relative.parts[1:])
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    copied[record.path] = _private_verified_copy(
                        bundled.root.joinpath(*relative.parts),
                        destination,
                        record.sha256,
                        mode=0o700 if record == bundled.node else 0o600,
                        kind="runtime artifact",
                        allow_empty=record.size == 0,
                    )
                workspace = runtime / "workspace"
                workspace.mkdir(mode=0o700)
                provider_module: Optional[str]
                if self._pi_auth_path is not None and self._codex_auth_path is not None:
                    raise InvalidRequest(1, "Pi auth and Codex auth are mutually exclusive", RetryClass.NEVER)
                if self._pi_auth_path is None and self._codex_auth_path is None:
                    auth = runtime / "pi-auth.json"
                    auth.write_text("{}\n", encoding="ascii")
                    auth.chmod(0o600)
                    provider_module = os.fspath(copied[bundled.acceptance_provider.path])
                else:
                    source_auth = (self._pi_auth_path or self._codex_auth_path)
                    assert source_auth is not None
                    source_auth = source_auth.resolve(strict=True)
                    auth_details = source_auth.lstat()
                    if (
                        not stat.S_ISREG(auth_details.st_mode)
                        or source_auth.is_symlink()
                        or auth_details.st_uid != os.getuid()
                        or stat.S_IMODE(auth_details.st_mode) & 0o077
                    ):
                        raise InvalidRequest(1, "Pi auth file must be a private regular file", RetryClass.NEVER)
                    if self._codex_auth_path is None:
                        auth = source_auth
                    else:
                        try:
                            codex_auth = json.loads(source_auth.read_text(encoding="utf-8"))
                            tokens = codex_auth["tokens"]
                            access = tokens["access_token"]
                            refresh = tokens["refresh_token"]
                            account_id = tokens["account_id"]
                            payload = access.split(".")[1]
                            decoded = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
                            expires = int(decoded["exp"]) * 1000
                            if not all(isinstance(value, str) and value for value in (access, refresh, account_id)):
                                raise ValueError("invalid token fields")
                        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as error:
                            raise InvalidRequest(1, "Codex auth file is incompatible", RetryClass.NEVER) from error
                        auth = runtime / "pi-auth.json"
                        auth.write_text(json.dumps({"openai-codex": {
                            "type": "oauth", "access": access, "refresh": refresh,
                            "expires": expires, "accountId": account_id,
                        }}, separators=(",", ":")) + "\n", encoding="utf-8")
                        auth.chmod(0o600)
                    provider_module = None
                entrypoint = copied[bundled.pi_entrypoint.path]
                node = copied[bundled.node.path]
                driver_uuid = (
                    f"{bundled.driver_id[:8]}-{bundled.driver_id[8:12]}-"
                    f"{bundled.driver_id[12:16]}-{bundled.driver_id[16:20]}-"
                    f"{bundled.driver_id[20:]}"
                )
                document = {
                    "entries": {
                        "pi": {
                            "driver_id": driver_uuid,
                            "executable": os.fspath(node),
                            "executable_sha256": bundled.node.sha256,
                            "arguments": ["--preserve-symlinks", os.fspath(entrypoint)],
                            "working_directory": os.fspath(
                                runtime.joinpath(
                                    *PurePosixPath(bundled.pi_working_directory).parts[1:]
                                )
                            ),
                            "environment": {},
                            "protocol_version": 1,
                            "ownership_channel": "dedicated_fd",
                            "capabilities": [{"name": "durable.acceptance", "version": 1}],
                            "bootstrap_configuration": {
                                "provider": self._pi_provider,
                                "model": self._pi_model,
                                "authPath": os.fspath(auth),
                                **({"providerModule": provider_module} if provider_module is not None else {}),
                                "cwd": os.fspath(pi_cwd or workspace),
                                "tools": list(self._pi_tools),
                                "hierarchyTools": self._pi_hierarchy_tools,
                                "implicitTerminalText": self._pi_auth_path is not None or self._codex_auth_path is not None,
                            },
                            "trusted_artifacts": [
                                {
                                    "path": os.fspath(copied[item.path]),
                                    "sha256": item.sha256,
                                }
                                for item in bundled.trusted_artifacts
                            ],
                        }
                    }
                }
                catalog = runtime / "drivers.json"
                catalog.write_text(
                    json.dumps(document, separators=(",", ":"), sort_keys=True) + "\n",
                    encoding="ascii",
                )
                catalog.chmod(0o600)
        except BaseException:
            await self._cleanup_before_propagating()
            raise
        socket = runtime / "navigator.sock"
        credential_file = runtime / "bootstrap.credential"
        credential = secrets.token_hex(32)
        descriptor = os.open(credential_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, credential.encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        database = self._data_dir / "navigator.sqlite"
        diagnostic = runtime / "startup.stderr"
        diagnostic_descriptor = os.open(diagnostic, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(diagnostic_descriptor)
        diagnostic_read, diagnostic_write = os.pipe()
        self._diagnostic_task = asyncio.create_task(
            _capture_bounded_diagnostic(diagnostic_read, diagnostic)
        )
        self._diagnostic_path = diagnostic
        try:
            arguments = [
                os.fspath(binary),
                "--database",
                os.fspath(database),
                "--socket",
                os.fspath(socket),
                "--credential-file",
                os.fspath(credential_file),
                "--shutdown-timeout-ms",
                str(max(1, int(self._shutdown_timeout * 1000))),
                "--operation-report-deadline-ms",
                str(max(1, int(self._operation_report_deadline * 1000))),
            ]
            if catalog is not None:
                arguments.extend(("--driver-catalog", os.fspath(catalog)))
                arguments.extend(("--driver-runtime", os.fspath(runtime / "drivers")))
                profiles = ("pi",) if generated_catalog else self._driver_profiles
                for profile in profiles:
                    arguments.extend(("--driver-entry", profile))
            self._process = _spawn(arguments, diagnostic_write)
            os.close(diagnostic_write)
            diagnostic_write = -1
            self._client = await self._await_connection(socket, credential)
            return self._client
        except BaseException:
            try:
                if diagnostic_write >= 0:
                    os.close(diagnostic_write)
            except OSError:
                pass
            await self._cleanup_before_propagating()
            raise

    async def _await_connection(self, socket: Path, credential: str) -> Any:
        assert self._process is not None
        deadline = asyncio.get_running_loop().time() + self._startup_timeout
        last_error: Optional[BaseException] = None
        while asyncio.get_running_loop().time() < deadline:
            if self._process.returncode is not None:
                diagnostic = _startup_diagnostic(self._diagnostic_path or Path(), credential)
                raise TransportUnavailable(
                    7,
                    "Managed Navigator exited during startup"
                    + (f": {diagnostic}" if diagnostic else ""),
                    RetryClass.SAFE,
                )
            if not socket.exists():
                await asyncio.sleep(0.01)
                continue
            _verify_socket(socket)
            try:
                remaining = max(0.05, deadline - asyncio.get_running_loop().time())
                return await connect(
                    f"unix://{socket}",
                    credential,
                    capabilities=self._capabilities,
                    timeout=remaining,
                )
            except (Unsupported, IncompatibleProtocol):
                raise
            except asyncio.TimeoutError as error:
                last_error = error
            except NavigatorError as error:
                last_error = error
            await asyncio.sleep(0.01)
        diagnostic = _startup_diagnostic(self._diagnostic_path or Path(), credential)
        raise TransportUnavailable(
            7,
            "Managed Navigator startup timed out" + (f": {diagnostic}" if diagnostic else ""),
            RetryClass.SAFE,
        ) from last_error

    async def __aexit__(self, *_: object) -> None:
        await self._cleanup_before_propagating()

    async def _cleanup_before_propagating(self) -> None:
        cleanup = self._cleanup_task
        if cleanup is None:
            cleanup = asyncio.create_task(self._cleanup())
            self._cleanup_task = cleanup
        cancelled = False
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                # Drain the one shared cleanup even under repeated cancellation.
                # Each caller still observes cancellation after ownership is gone.
                cancelled = True
        try:
            cleanup.result()
        except asyncio.CancelledError:
            cancelled = True
        if cancelled:
            raise asyncio.CancelledError

    async def _cleanup(self) -> None:
        error: Optional[BaseException] = None
        loop = asyncio.get_running_loop()
        wait_timeout = max(_MIN_CLEANUP_WAIT_SECONDS, self._shutdown_timeout)
        close_budget = min(_MAX_CHANNEL_CLOSE_SECONDS, wait_timeout)
        # One finite deadline covers channel close, graceful child-first exit,
        # descendant cleanup, hard escalation, and final reap.
        deadline = loop.time() + min(
            _MAX_CLEANUP_WAIT_SECONDS,
            close_budget + (3 * wait_timeout),
        )

        def remaining(until: Optional[float] = None) -> float:
            return max(0.0, (deadline if until is None else min(deadline, until)) - loop.time())

        client, self._client = self._client, None
        if client is not None:
            try:
                close_timeout = min(
                    close_budget,
                    remaining(),
                )
                if close_timeout > 0:
                    await asyncio.wait_for(client.aclose(), close_timeout)
            except asyncio.TimeoutError:
                # A stuck transport cannot retain ownership of the subprocess.
                pass
            except BaseException as caught:
                error = caught
        try:
            process, self._process = self._process, None
            if process is not None:
                leader_exited = process.returncode is not None
                if process.returncode is None:
                    try:
                        process.terminate()
                    except (ChildProcessError, ProcessLookupError):
                        leader_exited = process.returncode is not None
                    except BaseException as caught:
                        if error is None:
                            error = caught
                    graceful_deadline = loop.time() + remaining() / 2
                    try:
                        timeout = remaining(graceful_deadline)
                        if timeout > 0:
                            await asyncio.wait_for(process.wait(), timeout)
                            leader_exited = True
                    except (ChildProcessError, ProcessLookupError):
                        leader_exited = True
                    except asyncio.TimeoutError:
                        pass
                    except BaseException as caught:
                        if error is None:
                            error = caught

                group_alive = True
                try:
                    group_alive = process.group_exists()
                except BaseException as caught:
                    if error is None:
                        error = caught
                if leader_exited and group_alive:
                    try:
                        process.signal_group(signal.SIGTERM)
                    except BaseException as caught:
                        if error is None:
                            error = caught
                    term_deadline = loop.time() + min(
                        _MAX_GROUP_OBSERVATION_SECONDS, remaining() / 2
                    )
                    while remaining(term_deadline) > 0:
                        try:
                            group_alive = process.group_exists()
                        except BaseException as caught:
                            if error is None:
                                error = caught
                            group_alive = True
                        if not group_alive:
                            break
                        await asyncio.sleep(0.01)

                # Hard escalation is attempted even when terminate(), wait(),
                # or group inspection failed.  The group is exclusively ours.
                if not leader_exited or group_alive:
                    try:
                        process.signal_group(signal.SIGKILL)
                    except BaseException as caught:
                        if error is None:
                            error = caught
                    if not leader_exited and remaining() > 0:
                        try:
                            await asyncio.wait_for(process.wait(), remaining())
                            leader_exited = True
                        except (asyncio.TimeoutError, ChildProcessError, ProcessLookupError):
                            pass
                        except BaseException as caught:
                            if error is None:
                                error = caught
                    observation_deadline = loop.time() + min(
                        _MAX_GROUP_OBSERVATION_SECONDS, remaining()
                    )
                    while remaining(observation_deadline) > 0:
                        try:
                            if not process.group_exists():
                                break
                        except BaseException as caught:
                            if error is None:
                                error = caught
                            break
                        await asyncio.sleep(min(0.01, remaining(observation_deadline)))
        except (ChildProcessError, ProcessLookupError):
            pass
        except BaseException as caught:
            if error is None:
                error = caught
        finally:
            diagnostic_task, self._diagnostic_task = self._diagnostic_task, None
            if diagnostic_task is not None:
                try:
                    await asyncio.wait_for(diagnostic_task, _MAX_GROUP_OBSERVATION_SECONDS)
                except asyncio.TimeoutError:
                    diagnostic_task.cancel()
                    try:
                        await diagnostic_task
                    except asyncio.CancelledError:
                        pass
                except BaseException as caught:
                    if error is None:
                        error = caught
            runtime, self._runtime = self._runtime, None
            try:
                if runtime is not None:
                    shutil.rmtree(runtime)
            except BaseException as caught:
                if error is None:
                    error = caught
            self._diagnostic_path = None
        if error is not None:
            raise error
