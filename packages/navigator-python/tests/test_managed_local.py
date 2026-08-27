from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import sqlite3
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any, cast

import pytest

from navigator import Navigator
from navigator.connection import _capture_bounded_diagnostic, _startup_diagnostic
from navigator.errors import (
    AuthenticationError,
    CleanupRequired,
    InvalidRequest,
    NavigatorError,
    StaleOwnership,
    TransportUnavailable,
    Unsupported,
)
from navigator.models import (
    CapabilityRequirement,
    DoNotRetry,
    Identity,
    ResourceBounds,
    RetryClass,
    Template,
)


@pytest.mark.asyncio
async def test_packaged_runtime_starts_without_binary_override(tmp_path: Path) -> None:
    data = tmp_path / "packaged-data"
    context = Navigator.local(data_dir=data)
    async with context as client:
        assert client is not None
        runtime_binary = context._runtime / "navigatord"  # type: ignore[attr-defined]
        assert runtime_binary.is_file()
        assert stat.S_IMODE(runtime_binary.stat().st_mode) == 0o700


def test_managed_local_default_startup_budget_covers_packaged_validation(tmp_path: Path) -> None:
    context = Navigator.local(data_dir=tmp_path / "data")
    assert context._startup_timeout == 30.0  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_missing_packaged_platform_fails_before_data_side_effect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from navigator import connection

    data = tmp_path / "must-not-exist"
    monkeypatch.setattr(connection.platform, "system", lambda: "UnsupportedOS")
    monkeypatch.setattr(connection.platform, "machine", lambda: "unsupported-arch")
    with pytest.raises(Unsupported):
        async with Navigator.local(data_dir=data):
            raise AssertionError("unsupported runtime must not launch")
    assert not data.exists()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _runtime_v2(tmp_path: Path) -> tuple[Path, dict[str, object]]:
    root = tmp_path / "runtime-package"
    target = root / "darwin-arm64"
    (target / "pi/dist").mkdir(parents=True)
    (target / "acceptance").mkdir()
    files = {
        "darwin-arm64/navigatord": b"#!/bin/sh\nexit 23\n",
        "darwin-arm64/node": b"#!/bin/sh\nexit 24\n",
        "darwin-arm64/pi/dist/main.js": b"export {};\n",
        "darwin-arm64/pi/package.json": b"{}\n",
        "darwin-arm64/acceptance/provider.mjs": b"export function register() {}\n",
    }
    for relative, payload in files.items():
        path = root / relative
        path.write_bytes(payload)
        path.chmod(0o755 if path.name in ("navigatord", "node") else 0o644)

    def record(relative: str) -> dict[str, object]:
        path = root / relative
        return {"path": relative, "sha256": _digest(path), "size": path.stat().st_size}

    node = record("darwin-arm64/node")
    entrypoint = record("darwin-arm64/pi/dist/main.js")
    provider = record("darwin-arm64/acceptance/provider.mjs")
    tree = [
        record("darwin-arm64/pi/dist/main.js"),
        record("darwin-arm64/pi/package.json"),
    ]
    manifest: dict[str, object] = {
        "artifacts": {
            "darwin-arm64": {
                "acceptance_provider": provider,
                "driver_id": "00000000000000000000000000000001",
                "navigatord": record("darwin-arm64/navigatord"),
                "node": node,
                "pi_entrypoint": entrypoint,
                "pi_tree": tree,
                "pi_working_directory": "darwin-arm64/pi",
                "trusted_artifacts": [node, entrypoint, provider],
            }
        },
        "version": 2,
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="ascii")
    return root, manifest


@pytest.mark.parametrize("damage", ("malformed", "traversal", "digest"))
def test_packaged_runtime_manifest_v2_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str
) -> None:
    from navigator import connection

    root, manifest = _runtime_v2(tmp_path)
    target = manifest["artifacts"]["darwin-arm64"]  # type: ignore[index]
    if damage == "malformed":
        (root / "manifest.json").write_bytes(b"{not-json")
    elif damage == "traversal":
        target["node"]["path"] = "darwin-arm64/../node"  # type: ignore[index]
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="ascii")
    else:
        target["pi_tree"][0]["sha256"] = "0" * 64  # type: ignore[index]
        (root / "manifest.json").write_text(json.dumps(manifest), encoding="ascii")
    monkeypatch.setattr(connection.resources, "files", lambda _: root)
    monkeypatch.setattr(connection.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(connection.platform, "machine", lambda: "arm64")
    with pytest.raises(InvalidRequest, match="Invalid packaged Navigator runtime"):
        connection._bundled_runtime()


@pytest.mark.asyncio
async def test_packaged_runtime_v2_generates_private_strict_pi_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from navigator import connection

    root, _ = _runtime_v2(tmp_path)
    monkeypatch.setattr(connection.resources, "files", lambda _: root)
    monkeypatch.setattr(connection.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(connection.platform, "machine", lambda: "arm64")
    spawned = connection._spawn
    observed: dict[str, object] = {}

    def inspect_spawn(arguments: list[str], diagnostic_descriptor: int) -> object:
        catalog_path = Path(arguments[arguments.index("--driver-catalog") + 1])
        document = json.loads(catalog_path.read_text(encoding="ascii"))
        entry = document["entries"]["pi"]
        observed["arguments"] = arguments
        observed["catalog"] = document
        observed["catalog_mode"] = stat.S_IMODE(catalog_path.stat().st_mode)
        observed["auth_mode"] = stat.S_IMODE(
            Path(entry["bootstrap_configuration"]["authPath"]).stat().st_mode
        )
        observed["workspace_mode"] = stat.S_IMODE(
            Path(entry["bootstrap_configuration"]["cwd"]).stat().st_mode
        )
        observed["artifact_modes"] = [
            stat.S_IMODE(Path(item["path"]).stat().st_mode) for item in entry["trusted_artifacts"]
        ]
        return spawned(arguments, diagnostic_descriptor)

    monkeypatch.setattr(connection, "_spawn", inspect_spawn)
    data = tmp_path / "data"
    context = Navigator.local(data_dir=data, startup_timeout=1.0)
    with pytest.raises(TransportUnavailable, match="exited during startup"):
        async with context:
            raise AssertionError("fixture daemon exits")

    arguments = observed["arguments"]
    assert isinstance(arguments, list)
    assert arguments[arguments.index("--driver-entry") + 1] == "pi"
    assert observed["catalog_mode"] == 0o600
    assert observed["auth_mode"] == 0o600
    assert observed["workspace_mode"] == 0o700
    assert observed["artifact_modes"] == [0o700, 0o600, 0o600]
    entry = observed["catalog"]["entries"]["pi"]  # type: ignore[index]
    assert entry["driver_id"] == "00000000-0000-0000-0000-000000000001"
    assert entry["arguments"][0] == "--preserve-symlinks"
    assert entry["ownership_channel"] == "dedicated_fd"
    assert entry["capabilities"] == [{"name": "durable.acceptance", "version": 1}]


def _daemon() -> Path:
    configured = os.environ.get("NAVIGATORD_TEST_BINARY")
    candidate = (
        Path(configured) if configured else Path(__file__).parents[3] / "target/debug/navigatord"
    )
    if not candidate.is_file():
        pytest.skip("build navigatord or set NAVIGATORD_TEST_BINARY")
    return candidate


def _id() -> Identity:
    return Identity(uuid.uuid4().bytes)


def _template() -> Template:
    return Template(
        id=_id(),
        role="root",
        driver_id=_id(),
        required_capabilities=(
            CapabilityRequirement(capability="task.execute", minimum_version=1),
        ),
        base_instructions="execute the admitted task",
        resources=ResourceBounds(
            memory_bytes=64 * 1024 * 1024,
            cpu_millis=1_000,
            max_concurrent_operations=1,
        ),
    )


def test_startup_diagnostics_are_bounded_and_redacted(tmp_path: Path) -> None:
    credential = "secret-bootstrap-value"
    path = tmp_path / "stderr"
    path.write_bytes((credential + " diagnostic " + "x" * 8192).encode())
    diagnostic = _startup_diagnostic(path, credential)
    assert credential not in diagnostic
    assert "<redacted>" in diagnostic
    assert len(diagnostic.encode()) <= 4096 + len("<redacted>")


@pytest.mark.asyncio
async def test_diagnostic_capture_is_physically_bounded(tmp_path: Path) -> None:
    path = tmp_path / "diagnostic"
    path.touch(mode=0o600)
    reader, writer = os.pipe()
    capture = asyncio.create_task(_capture_bounded_diagnostic(reader, path))
    payload = b"a" * 8192 + b"tail"
    await asyncio.to_thread(os.write, writer, payload)
    os.close(writer)
    await capture
    assert path.stat().st_size == 4096
    assert path.read_bytes().endswith(b"tail")


def _configured_template() -> Template:
    value = _template()
    return value.model_copy(
        update={
            "driver_id": Identity(bytes.fromhex("01" * 16)),
            "required_capabilities": (
                CapabilityRequirement(capability="durable.acceptance", minimum_version=1),
            ),
        }
    )


def _configured_fake(
    tmp_path: Path,
    *,
    crash_barrier: Path | None = None,
    delivery_fault: str = "crash_after_durable_acceptance",
) -> tuple[Path, Path, Path, Path]:
    fake = Path(__file__).parents[3] / "target/debug/navigator-driver-fake"
    if not fake.is_file():
        pytest.skip("build navigator-driver-fake")
    scenario = tmp_path / "scenario.json"
    journal = tmp_path / "journals"
    effects = tmp_path / "effects.log"
    journal.mkdir(mode=0o700)
    scenario.write_text(
        '{"capabilities":["durable.acceptance"],'
        f'"delivery_fault":"{delivery_fault}","events":[]}}',
        encoding="utf-8",
    )
    catalog = tmp_path / "drivers.json"
    environment = {
        "FAKE_DRIVER_SCENARIO_FILE": str(scenario),
        "FAKE_DRIVER_JOURNAL_FILE": str(journal),
        "FAKE_DRIVER_EFFECT_FILE": str(effects),
    }
    if crash_barrier is not None:
        environment["FAKE_DRIVER_DURABLE_ACCEPTANCE_CRASH_BARRIER"] = str(crash_barrier)
    if delivery_fault == "restart_after_durable_acceptance":
        environment["FAKE_DRIVER_AUTO_RESTART"] = "1"
        environment["FAKE_DRIVER_PID_FILE"] = str(tmp_path / "driver-pids.log")
    catalog.write_text(
        json.dumps(
            {
                "entries": {
                    "fake": {
                        "driver_id": "01010101-0101-0101-0101-010101010101",
                        "executable": str(fake),
                        "executable_sha256": _digest(fake),
                        "arguments": [],
                        "working_directory": str(tmp_path),
                        "environment": environment,
                        "protocol_version": 1,
                        "ownership_channel": "stdin",
                        "capabilities": [
                            {"name": "durable.acceptance", "version": 1},
                        ],
                        "bootstrap_configuration": {},
                        "trusted_artifacts": [],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return catalog, scenario, effects, fake


async def _open(client: Navigator) -> tuple[Identity, Identity]:
    session_id = _id()
    opened = await client.open(
        _id(), session_id, "python-managed", b"", _template(), configuration_identity=b""
    )
    return session_id, opened.root_id


@pytest.mark.asyncio
async def test_managed_local_negotiates_real_daemon_and_only_owns_child(tmp_path: Path) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(binary=daemon, binary_sha256=_digest(daemon), data_dir=data)
    async with context as client:
        negotiated = await client.negotiate(capabilities=("session.lifecycle.v1",))
        assert negotiated.protocol.major == 1
        assert negotiated.configuration_identity
        process = context._process
        assert process is not None and process.returncode is None
        pid = process.pid
        runtime = context._runtime
        assert runtime is not None
        assert stat.S_IMODE(runtime.stat().st_mode) == 0o700
        assert stat.S_IMODE((runtime / "bootstrap.credential").stat().st_mode) == 0o600
        assert (data / "navigator.sqlite").exists()
    assert context._process is None
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert not runtime.exists()
    assert (data / "navigator.sqlite").exists()


@pytest.mark.asyncio
async def test_real_daemon_negotiates_slice10_capabilities_only_at_minor_one(
    tmp_path: Path,
) -> None:
    import grpc

    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb
    from navigator._transport.navigator.consumer.v1 import consumer_pb2_grpc

    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(binary=daemon, binary_sha256=_digest(daemon), data_dir=data)
    async with context:
        runtime = context._runtime
        assert runtime is not None
        credential = (runtime / "bootstrap.credential").read_text(encoding="ascii")
        channel = grpc.aio.insecure_channel(
            f"unix://{runtime / 'navigator.sock'}",
            options=(("grpc.default_authority", "localhost"),),
        )
        stub = consumer_pb2_grpc.NavigatorConsumerStub(channel)
        metadata = (("x-navigator-bootstrap", credential),)
        # The unconfigured daemon intentionally omits Tool routing; Artifact
        # storage is configured independently and still proves minor gating.
        requested = ("artifacts.v1",)
        minor_one = await stub.Negotiate(
            pb.NegotiateRequest(
                minimum_version=pb.ProtocolVersion(major=1, minor=0),
                maximum_version=pb.ProtocolVersion(major=1, minor=1),
                capabilities=requested,
            ),
            metadata=metadata,
        )
        assert minor_one.negotiated.protocol_version.minor == 1
        assert tuple(minor_one.negotiated.capabilities) == requested
        minor_zero = await stub.Negotiate(
            pb.NegotiateRequest(
                minimum_version=pb.ProtocolVersion(major=1, minor=0),
                maximum_version=pb.ProtocolVersion(major=1, minor=0),
                capabilities=requested,
            ),
            metadata=metadata,
        )
        assert minor_zero.negotiated.protocol_version.minor == 0
        assert tuple(minor_zero.negotiated.capabilities) == ()
        await channel.close()


@pytest.mark.asyncio
async def test_default_capabilities_enable_real_resource_snapshots(tmp_path: Path) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    async with Navigator.local(
        binary=daemon, binary_sha256=_digest(daemon), data_dir=data
    ) as client:
        session_id, root_id = await _open(client)
        participant = await client.participant(session_id, root_id)
        assert participant.id == root_id
        with pytest.raises(NavigatorError) as missing_message:
            await client.message(session_id, _id())
        assert not isinstance(missing_message.value, Unsupported)


@pytest.mark.asyncio
async def test_default_capabilities_enable_real_recovery_rpcs_when_configured(
    tmp_path: Path,
) -> None:
    daemon = _daemon()
    catalog, _, _, _ = _configured_fake(tmp_path)
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    async with Navigator.local(
        binary=daemon,
        binary_sha256=_digest(daemon),
        data_dir=data,
        driver_catalog=catalog,
        driver_catalog_sha256=_digest(catalog),
        driver_profiles=("fake",),
    ) as client:
        session_id = _id()
        await client.open(_id(), session_id, "default-recovery", b"", _configured_template())
        try:
            report = await client.resume(_id(), session_id)
        except NavigatorError as recovery:
            assert not isinstance(recovery, Unsupported)
        else:
            assert report.session_id == session_id
        with pytest.raises(NavigatorError) as missing_resolution:
            await client.resolve(
                _id(), session_id, _id(), _id(), "prove negotiated recovery", DoNotRetry()
            )
        assert not isinstance(missing_resolution.value, Unsupported)


@pytest.mark.asyncio
async def test_unknown_optional_capability_is_ignored_and_real_child_is_cleaned_up(
    tmp_path: Path,
) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(
        binary=daemon,
        binary_sha256=_digest(daemon),
        data_dir=data,
        capabilities=("unsupported.capability.v1",),
        startup_timeout=2.0,
    )
    async with context as client:
        negotiated = await client.negotiate(capabilities=("unsupported.capability.v1",))
        assert negotiated.capabilities == ()
        process = context._process
        assert process is not None
        pid = process.pid
    assert context._process is None
    assert context._runtime is None
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.asyncio
async def test_early_exit_is_reported_and_runtime_is_removed(tmp_path: Path) -> None:
    executable = tmp_path / "exits"
    executable.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
    executable.chmod(0o700)
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(
        binary=executable,
        binary_sha256=_digest(executable),
        data_dir=data,
        startup_timeout=1.0,
    )
    with pytest.raises(TransportUnavailable, match="exited during startup"):
        async with context:
            raise AssertionError("exited daemon must not be published")
    assert context._runtime is None


@pytest.mark.asyncio
async def test_startup_timeout_is_deterministic_and_reaps_child(tmp_path: Path) -> None:
    executable = tmp_path / "waits"
    executable.write_text("#!/bin/sh\nwhile :; do sleep 1; done\n", encoding="utf-8")
    executable.chmod(0o700)
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(
        binary=executable,
        binary_sha256=_digest(executable),
        data_dir=data,
        startup_timeout=0.01,
    )
    with pytest.raises(TransportUnavailable, match="startup timed out"):
        async with context:
            raise AssertionError("unready daemon must not be published")
    assert context._process is None
    assert context._runtime is None


@pytest.mark.asyncio
@pytest.mark.parametrize("close_behavior", ("fails", "hangs"))
async def test_cleanup_reaps_process_and_runtime_when_channel_close_is_broken(
    tmp_path: Path, close_behavior: str
) -> None:
    class Client:
        async def aclose(self) -> None:
            if close_behavior == "fails":
                raise RuntimeError("channel close failed")
            await asyncio.Event().wait()

    class Process:
        def __init__(self) -> None:
            self.pid = os.getpid()
            self.returncode: int | None = None
            self.terminated = False
            self.group_signals: list[signal.Signals] = []

        def terminate(self) -> None:
            self.terminated = True

        async def wait(self) -> int:
            self.returncode = 0
            return 0

        def group_exists(self) -> bool:
            return False

        def signal_group(self, value: signal.Signals) -> None:
            self.group_signals.append(value)

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    context = Navigator.local(data_dir=tmp_path / "data", shutdown_timeout=0.0)
    process = Process()
    context._client = Client()  # type: ignore[attr-defined]
    context._process = process  # type: ignore[attr-defined]
    context._runtime = runtime  # type: ignore[attr-defined]

    if close_behavior == "fails":
        with pytest.raises(RuntimeError, match="channel close failed"):
            await context._cleanup_before_propagating()  # type: ignore[attr-defined]
    else:
        await asyncio.wait_for(
            context._cleanup_before_propagating(),  # type: ignore[attr-defined]
            0.5,
        )
    assert process.terminated
    assert context._process is None  # type: ignore[attr-defined]
    assert context._runtime is None  # type: ignore[attr-defined]
    assert not runtime.exists()


@pytest.mark.asyncio
async def test_cleanup_bounds_wait_after_sigkill(tmp_path: Path) -> None:
    class Process:
        def __init__(self) -> None:
            self.pid = os.getpid()
            self.returncode = None
            self.signals: list[signal.Signals] = []

        def terminate(self) -> None:
            pass

        async def wait(self) -> int:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        def signal_group(self, value: signal.Signals) -> None:
            self.signals.append(value)

        def group_exists(self) -> bool:
            return False

    context = Navigator.local(data_dir=tmp_path / "data", shutdown_timeout=0.0)
    process = Process()
    context._process = process  # type: ignore[attr-defined]
    await asyncio.wait_for(
        context._cleanup_before_propagating(),  # type: ignore[attr-defined]
        0.5,
    )
    assert process.signals == [signal.SIGKILL]
    assert context._process is None  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_concurrent_cleanup_callers_share_one_cleanup(tmp_path: Path) -> None:
    class Client:
        calls = 0

        async def aclose(self) -> None:
            self.calls += 1
            await asyncio.sleep(0.02)

    class Process:
        pid = os.getpid()
        returncode: int | None = None
        terminate_calls = 0

        def terminate(self) -> None:
            self.terminate_calls += 1

        async def wait(self) -> int:
            await asyncio.sleep(0.02)
            self.returncode = 0
            return 0

        def group_exists(self) -> bool:
            return False

        def signal_group(self, _: signal.Signals) -> None:
            raise AssertionError("no group escalation expected")

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    context = Navigator.local(data_dir=tmp_path / "data", shutdown_timeout=0.1)
    client, process = Client(), Process()
    context._client = client  # type: ignore[attr-defined]
    context._process = process  # type: ignore[attr-defined]
    context._runtime = runtime  # type: ignore[attr-defined]
    await asyncio.gather(
        context._cleanup_before_propagating(),  # type: ignore[attr-defined]
        context._cleanup_before_propagating(),  # type: ignore[attr-defined]
    )
    assert client.calls == 1
    assert process.terminate_calls == 1
    assert not runtime.exists()


@pytest.mark.asyncio
async def test_repeated_cancellation_still_drains_shared_cleanup(tmp_path: Path) -> None:
    class Client:
        async def aclose(self) -> None:
            await asyncio.Event().wait()

    class Process:
        pid = os.getpid()
        returncode: int | None = None
        terminated = False

        def terminate(self) -> None:
            self.terminated = True

        async def wait(self) -> int:
            self.returncode = 0
            return 0

        def group_exists(self) -> bool:
            return False

        def signal_group(self, _: signal.Signals) -> None:
            raise AssertionError("no escalation expected")

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    context = Navigator.local(data_dir=tmp_path / "data", shutdown_timeout=0.05)
    process = Process()
    context._client = Client()  # type: ignore[attr-defined]
    context._process = process  # type: ignore[attr-defined]
    context._runtime = runtime  # type: ignore[attr-defined]
    caller = asyncio.create_task(
        context._cleanup_before_propagating()  # type: ignore[attr-defined]
    )
    await asyncio.sleep(0)
    caller.cancel()
    await asyncio.sleep(0)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    assert process.terminated
    assert not runtime.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ("terminate", "wait"))
async def test_cleanup_hard_escalates_after_process_api_fault(tmp_path: Path, fault: str) -> None:
    class Process:
        pid = os.getpid()
        returncode = None

        def __init__(self) -> None:
            self.signals: list[signal.Signals] = []

        def terminate(self) -> None:
            if fault == "terminate":
                raise RuntimeError("terminate fault")

        async def wait(self) -> int:
            if fault == "wait":
                raise RuntimeError("wait fault")
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

        def group_exists(self) -> bool:
            return bool(not self.signals)

        def signal_group(self, value: signal.Signals) -> None:
            self.signals.append(value)

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    context = Navigator.local(data_dir=tmp_path / "data", shutdown_timeout=0.0)
    process = Process()
    context._process = process  # type: ignore[attr-defined]
    context._runtime = runtime  # type: ignore[attr-defined]
    with pytest.raises(RuntimeError, match=f"{fault} fault"):
        await context._cleanup_before_propagating()  # type: ignore[attr-defined]
    assert signal.SIGKILL in process.signals
    assert not runtime.exists()


@pytest.mark.asyncio
async def test_leader_exit_then_persistent_group_preserves_child_first_order(
    tmp_path: Path,
) -> None:
    class Process:
        pid = os.getpid()
        returncode: int | None = None

        def __init__(self) -> None:
            self.actions: list[str] = []
            self.group_alive = True

        def terminate(self) -> None:
            self.actions.append("child:TERM")

        async def wait(self) -> int:
            self.actions.append("child:exit")
            self.returncode = 0
            return 0

        def group_exists(self) -> bool:
            return self.group_alive

        def signal_group(self, value: signal.Signals) -> None:
            self.actions.append(f"group:{value.name}")
            self.group_alive = False

    context = Navigator.local(data_dir=tmp_path / "data", shutdown_timeout=0.05)
    process = Process()
    context._process = process  # type: ignore[attr-defined]
    await context._cleanup_before_propagating()  # type: ignore[attr-defined]
    assert process.actions == ["child:TERM", "child:exit", "group:SIGTERM"]


@pytest.mark.asyncio
async def test_spawned_process_wait_completes_if_child_was_already_reaped(tmp_path: Path) -> None:
    from navigator import connection

    diagnostic = os.open(tmp_path / "diagnostic", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        process = connection._spawn(["/bin/sh", "-c", "exit 0"], diagnostic)
    finally:
        os.close(diagnostic)
    await asyncio.to_thread(os.waitpid, process.pid, 0)
    assert await asyncio.wait_for(process.wait(), 0.5) == 0


def test_spawn_environment_does_not_inherit_ambient_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from navigator import connection

    observed: dict[str, str] = {}

    def inspect_spawn(
        path: str,
        arguments: list[str],
        environment: dict[str, str],
        **options: object,
    ) -> int:
        del path, arguments, options
        observed.update(environment)
        return 999_999

    monkeypatch.setenv("NAVIGATOR_TEST_SECRET", "must-not-cross-process-boundary")
    monkeypatch.setattr(os, "posix_spawn", inspect_spawn)
    diagnostic = os.open(tmp_path / "diagnostic", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        connection._spawn(["/trusted/navigatord"], diagnostic)
    finally:
        os.close(diagnostic)
    assert "NAVIGATOR_TEST_SECRET" not in observed
    assert set(observed).issubset({"LANG", "LC_ALL", "PATH", "TMPDIR"})


def test_process_group_permission_error_is_not_reported_as_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from navigator import connection

    process = connection._SpawnedProcess(999_999)

    def denied(_: int, __: int | signal.Signals) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(os, "killpg", denied)
    assert process.group_exists()
    with pytest.raises(PermissionError, match="denied"):
        process.signal_group(signal.SIGKILL)


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", (float("nan"), float("inf"), -1.0))
async def test_non_finite_or_negative_shutdown_timeout_fails_before_side_effects(
    tmp_path: Path, timeout: float
) -> None:
    executable = tmp_path / "daemon"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    data = tmp_path / "absent"
    context = Navigator.local(
        binary=executable,
        binary_sha256=_digest(executable),
        data_dir=data,
        shutdown_timeout=timeout,
    )
    with pytest.raises(InvalidRequest, match="shutdown timeout"):
        async with context:
            raise AssertionError("invalid deadline must not launch")
    assert not data.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("timeout", (float("nan"), float("inf"), 0.0, -1.0))
async def test_non_positive_or_non_finite_startup_timeout_fails_before_side_effects(
    tmp_path: Path, timeout: float
) -> None:
    executable = tmp_path / "daemon"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    data = tmp_path / "absent"
    context = Navigator.local(
        binary=executable,
        binary_sha256=_digest(executable),
        data_dir=data,
        startup_timeout=timeout,
    )
    with pytest.raises(InvalidRequest, match="startup timeout"):
        async with context:
            raise AssertionError("invalid deadline must not launch")
    assert not data.exists()


@pytest.mark.asyncio
async def test_cleanup_kills_shell_descendant_process_group(tmp_path: Path) -> None:
    from navigator import connection

    descendant_file = tmp_path / "descendant.pid"
    executable = tmp_path / "daemon-shell"
    executable.write_text(
        "#!/bin/sh\n"
        "(trap '' TERM; while :; do sleep 1; done) &\n"
        f"echo $! > {descendant_file}\n"
        "while :; do sleep 1; done\n",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    diagnostic = os.open(tmp_path / "diagnostic", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        process = connection._spawn([os.fspath(executable)], diagnostic)
    finally:
        os.close(diagnostic)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    context = Navigator.local(data_dir=tmp_path / "data", shutdown_timeout=0.1)
    context._process = process  # type: ignore[attr-defined]
    context._runtime = runtime  # type: ignore[attr-defined]
    for _ in range(500):
        if descendant_file.exists():
            break
        await asyncio.sleep(0.01)
    assert descendant_file.exists()
    descendant_pid = int(descendant_file.read_text(encoding="ascii"))
    await context._cleanup_before_propagating()  # type: ignore[attr-defined]

    for _ in range(200):
        try:
            os.kill(descendant_pid, 0)
        except ProcessLookupError:
            break
        await asyncio.sleep(0.01)
    with pytest.raises(ProcessLookupError):
        os.kill(descendant_pid, 0)
    assert context._runtime is None  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_driver_catalog_is_a_verified_private_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from navigator import connection

    executable = tmp_path / "exits"
    executable.write_text("#!/bin/sh\nexit 23\n", encoding="utf-8")
    executable.chmod(0o700)
    catalog = tmp_path / "drivers.json"
    trusted = b'{"entries":{}}'
    catalog.write_bytes(trusted)
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    spawned = connection._spawn
    observed: dict[str, object] = {}

    def adversarial_spawn(arguments: list[str], diagnostic_descriptor: int) -> object:
        catalog.write_bytes(b'{"entries":{"attacker":{}}}')
        catalog_argument = Path(arguments[arguments.index("--driver-catalog") + 1])
        observed["path"] = catalog_argument
        observed["contents"] = catalog_argument.read_bytes()
        observed["mode"] = stat.S_IMODE(catalog_argument.stat().st_mode)
        return spawned(arguments, diagnostic_descriptor)

    monkeypatch.setattr(connection, "_spawn", adversarial_spawn)
    context = Navigator.local(
        binary=executable,
        binary_sha256=_digest(executable),
        data_dir=data,
        driver_catalog=catalog,
        driver_catalog_sha256=hashlib.sha256(trusted).hexdigest(),
        driver_profiles=("fake",),
        startup_timeout=1.0,
    )
    with pytest.raises(TransportUnavailable, match="exited during startup"):
        async with context:
            raise AssertionError("exited daemon must not be published")

    snapshot = observed["path"]
    assert isinstance(snapshot, Path)
    assert snapshot != catalog
    assert snapshot.parent != catalog.parent
    assert observed["contents"] == trusted
    assert observed["mode"] == 0o600
    assert context._runtime is None


@pytest.mark.asyncio
async def test_binary_digest_is_checked_before_bootstrap(tmp_path: Path) -> None:
    executable = tmp_path / "daemon"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    data = tmp_path / "absent"
    context = Navigator.local(binary=executable, binary_sha256="0" * 64, data_dir=data)
    with pytest.raises(InvalidRequest, match="digest mismatch"):
        async with context:
            raise AssertionError("untrusted executable must not launch")
    assert not data.exists()


@pytest.mark.asyncio
async def test_client_context_exit_closes_transport_without_closing_session() -> None:
    class Channel:
        closed = False

        async def close(self) -> None:
            self.closed = True

    class Stub:
        close_session_calls = 0

        async def CloseSession(self, request: object) -> object:
            self.close_session_calls += 1
            raise AssertionError("context exit must not mutate durable Session state")

    channel = Channel()
    stub = Stub()
    async with Navigator(stub, object(), channel):
        pass
    assert channel.closed
    assert stub.close_session_calls == 0


@pytest.mark.asyncio
async def test_unconfigured_real_daemon_fails_closed_before_driver_execution(
    tmp_path: Path,
) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(binary=daemon, binary_sha256=_digest(daemon), data_dir=data)
    async with context as client:
        session_id, participant_id = await _open(client)
        with pytest.raises(NavigatorError) as caught:
            await client.start(_id(), session_id, participant_id, b"{}")
        assert caught.value.code == 7
        assert (await client.session(session_id)).status == 1


@pytest.mark.asyncio
async def test_restart_and_external_connect_observe_same_durable_session(tmp_path: Path) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    digest = _digest(daemon)
    first = Navigator.local(binary=daemon, binary_sha256=digest, data_dir=data)
    async with first as owner:
        session_id, _ = await _open(owner)
        runtime = first._runtime
        assert runtime is not None
        credential = (runtime / "bootstrap.credential").read_text(encoding="ascii")
        async with await Navigator.connect(
            f"unix://{runtime / 'navigator.sock'}",
            credential,
            capabilities=("session.lifecycle.v1",),
        ) as peer:
            assert (await peer.session(session_id)).id == session_id
    second = Navigator.local(binary=daemon, binary_sha256=digest, data_dir=data)
    async with second as restarted:
        snapshot = await restarted.session(session_id)
        assert snapshot.id == session_id
        assert snapshot.status == 1


@pytest.mark.asyncio
async def test_external_event_replay_resumes_after_saved_position(tmp_path: Path) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(binary=daemon, binary_sha256=_digest(daemon), data_dir=data)
    async with context as owner:
        session_id, open_request_id, template = _id(), _id(), _template()
        await owner.open(
            open_request_id,
            session_id,
            "python-managed",
            b"",
            template,
            configuration_identity=b"",
        )
        runtime = context._runtime
        assert runtime is not None
        credential = (runtime / "bootstrap.credential").read_text(encoding="ascii")
        first_stream = owner.events(session_id)
        first = await asyncio.wait_for(first_stream.__anext__(), 1.0)
        await first_stream.aclose()
        async with await Navigator.connect(
            f"unix://{runtime / 'navigator.sock'}",
            credential,
            capabilities=(
                "events.replay.v1",
                "session.lifecycle.v1",
            ),
        ) as peer:
            # Exact replay while the original owner is live legitimately binds
            # this negotiation to the same durable consumer. Ownership is then
            # released before the bounded read.
            await peer.open(
                open_request_id,
                session_id,
                "python-managed",
                b"",
                template,
                configuration_identity=b"",
            )
            await owner.close(_id(), session_id)
            page = await peer.read_events(session_id, after=first.position, page_size=1)
            resumed = page.events[0]
        assert resumed.position > first.position
        assert resumed.session_id == session_id


@pytest.mark.asyncio
async def test_external_event_subscription_remains_fenced_after_ownership_release(
    tmp_path: Path,
) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(binary=daemon, binary_sha256=_digest(daemon), data_dir=data)
    async with context as owner:
        session_id, open_request_id, template = _id(), _id(), _template()
        await owner.open(
            open_request_id,
            session_id,
            "python-managed",
            b"",
            template,
            configuration_identity=b"",
        )
        runtime = context._runtime
        assert runtime is not None
        credential = (runtime / "bootstrap.credential").read_text(encoding="ascii")
        async with await Navigator.connect(
            f"unix://{runtime / 'navigator.sock'}",
            credential,
            capabilities=(
                "events.replay.v1",
                "session.lifecycle.v1",
            ),
        ) as peer:
            await peer.open(
                open_request_id,
                session_id,
                "python-managed",
                b"",
                template,
                configuration_identity=b"",
            )
            await owner.close(_id(), session_id)
            replay = peer.events(session_id)
            with pytest.raises(StaleOwnership):
                await asyncio.wait_for(replay.__anext__(), 1.0)
            await cast(Any, replay).aclose()


@pytest.mark.asyncio
async def test_local_and_external_preserve_idempotency_and_reject_changed_semantics(
    tmp_path: Path,
) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(binary=daemon, binary_sha256=_digest(daemon), data_dir=data)
    async with context as owner:
        session_id, request_id, template = _id(), _id(), _template()
        first = await owner.open(request_id, session_id, "stable", b"", template)
        runtime = context._runtime
        assert runtime is not None
        credential = (runtime / "bootstrap.credential").read_text(encoding="ascii")
        async with await Navigator.connect(
            f"unix://{runtime / 'navigator.sock'}",
            credential,
            capabilities=("session.lifecycle.v1",),
        ) as peer:
            replay = await peer.open(request_id, session_id, "stable", b"", template)
            assert replay == first
            with pytest.raises(AuthenticationError):
                await peer.open(request_id, session_id, "changed", b"", template)


@pytest.mark.asyncio
async def test_two_managed_daemons_share_store_but_not_child_ownership(tmp_path: Path) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    digest = _digest(daemon)
    first = Navigator.local(binary=daemon, binary_sha256=digest, data_dir=data)
    second = Navigator.local(binary=daemon, binary_sha256=digest, data_dir=data)
    async with first as first_client:
        session_id = _id()
        template = _template()
        await first_client.open(
            _id(), session_id, "python-managed", b"", template, configuration_identity=b""
        )
        with pytest.raises(TransportUnavailable):
            async with second:
                raise AssertionError("a second daemon must not share one Artifact root")
        first_pid = first._process.pid
        assert (await first_client.session(session_id)).id == session_id
    with pytest.raises(ProcessLookupError):
        os.kill(first_pid, 0)


def test_two_real_python_sdk_processes_are_fenced_and_reap_their_daemons(tmp_path: Path) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    coordination = tmp_path / "coordination"
    coordination.mkdir(mode=0o700)
    config = tmp_path / "multiprocess.json"
    config.write_text(
        json.dumps(
            {
                "coordination": str(coordination),
                "daemon": str(daemon),
                "data": str(data),
                "session_id": str(uuid.uuid4()),
                "request_id": str(uuid.uuid4()),
                "resume_request_id": str(uuid.uuid4()),
                "template_id": str(uuid.uuid4()),
            }
        ),
        encoding="utf-8",
    )
    worker = Path(__file__).with_name("managed_process_worker.py")
    environment = os.environ.copy()
    source = str(Path(__file__).parents[1] / "src")
    environment["PYTHONPATH"] = source + os.pathsep + environment.get("PYTHONPATH", "")
    owner = subprocess.Popen(
        [sys.executable, str(worker), "owner", str(config)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    contender = subprocess.Popen(
        [sys.executable, str(worker), "contender", str(config)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        for _ in range(1_000):
            if (coordination / "contender-fenced").exists():
                break
            if owner.poll() is not None or contender.poll() is not None:
                break
            import time

            time.sleep(0.01)
        if not (coordination / "contender-fenced").exists():
            failed = owner if owner.poll() is not None else contender
            output = failed.communicate(timeout=5)
            pytest.fail(f"multiprocess worker exited early: {output}")
        (coordination / "owner-release").touch()
        owner_stdout, owner_stderr = owner.communicate(timeout=15)
        contender_stdout, contender_stderr = contender.communicate(timeout=15)
        assert owner.returncode == 0, (owner_stdout, owner_stderr)
        assert contender.returncode == 0, (contender_stdout, contender_stderr)
    finally:
        for process in (owner, contender):
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    proofs = [
        json.loads((coordination / name).read_text(encoding="utf-8"))
        for name in ("owner-clean", "contender-clean")
    ]
    assert all(proof["reaped"] for proof in proofs)
    assert len({proof["worker_pid"] for proof in proofs}) == 2
    assert len({proof["daemon_pid"] for proof in proofs}) == 2
    for proof in proofs:
        with pytest.raises(ProcessLookupError):
            os.kill(proof["daemon_pid"], 0)
    with sqlite3.connect(data / "navigator.sqlite") as database:
        owner_host, epoch = database.execute(
            "SELECT owner_host_id, owner_epoch FROM sessions"
        ).fetchone()
    assert owner_host is None
    assert epoch >= 2


@pytest.mark.asyncio
async def test_cancellation_during_startup_reaps_exact_child(tmp_path: Path) -> None:
    executable = tmp_path / "waits"
    executable.write_text("#!/bin/sh\nwhile :; do sleep 1; done\n", encoding="utf-8")
    executable.chmod(0o700)
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(
        binary=executable,
        binary_sha256=_digest(executable),
        data_dir=data,
        startup_timeout=30.0,
    )
    entering = asyncio.create_task(context.__aenter__())
    while context._process is None:
        await asyncio.sleep(0)
    pid = context._process.pid
    entering.cancel()
    with pytest.raises(asyncio.CancelledError):
        await entering
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
    assert context._runtime is None


@pytest.mark.asyncio
async def test_data_directory_symlink_and_unsafe_mode_are_rejected(tmp_path: Path) -> None:
    daemon = _daemon()
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    linked = Navigator.local(binary=daemon, binary_sha256=_digest(daemon), data_dir=link)
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    public = Navigator.local(binary=daemon, binary_sha256=_digest(daemon), data_dir=unsafe)

    async def rejected(context: object) -> None:
        with pytest.raises(InvalidRequest, match="private|symbolic"):
            async with context:  # type: ignore[attr-defined]
                raise AssertionError("unsafe path must not launch")

    await rejected(linked)
    await rejected(public)


@pytest.mark.asyncio
async def test_binary_symlink_is_rejected_before_runtime_creation(tmp_path: Path) -> None:
    daemon = _daemon()
    linked = tmp_path / "navigatord-link"
    linked.symlink_to(daemon)
    data = tmp_path / "absent"
    context = Navigator.local(binary=linked, binary_sha256=_digest(daemon), data_dir=data)
    with pytest.raises(InvalidRequest, match="symbolic link"):
        async with context:
            raise AssertionError("linked executable must not launch")
    assert not data.exists()


@pytest.mark.asyncio
async def test_cancelling_event_stream_does_not_leak_managed_child(tmp_path: Path) -> None:
    daemon = _daemon()
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    context = Navigator.local(binary=daemon, binary_sha256=_digest(daemon), data_dir=data)
    async with context as client:
        session_id, _ = await _open(client)
        events = client.events(session_id)
        first = await asyncio.wait_for(events.__anext__(), 1.0)
        pending = asyncio.create_task(events.__anext__())
        await asyncio.sleep(0)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        await events.aclose()
        process = context._process
        assert process is not None
        pid = process.pid
        assert first.session_id == session_id
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.asyncio
async def test_sdk_reconciles_crash_after_durable_acceptance_without_redelivery(
    tmp_path: Path,
) -> None:
    daemon = _daemon()
    catalog, scenario, effects, _ = _configured_fake(tmp_path)
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    capabilities = (
        "events.replay.v1",
        "operation.execution.v1",
        "operation.cancellation.v1",
        "session.lifecycle.v1",
        "recovery.resolution.v1",
    )
    options = {
        "binary": daemon,
        "binary_sha256": _digest(daemon),
        "data_dir": data,
        "capabilities": capabilities,
        "driver_catalog": catalog,
        "driver_catalog_sha256": _digest(catalog),
        "driver_profiles": ("fake",),
    }
    first = Navigator.local(**options)
    async with first as client:
        session_id = _id()
        opened = await client.open(
            _id(),
            session_id,
            "python-recovery",
            b"",
            _configured_template(),
            configuration_identity=b"",
        )
        request_id = _id()
        operation = await client.start(request_id, session_id, opened.root_id, b"{}")
        for _ in range(800):
            snapshot = await client.operation(session_id, operation.id)
            if snapshot.status.value == 10:
                break
            await asyncio.sleep(0.01)
        diagnostic_path = first._diagnostic_path
        diagnostic = diagnostic_path.read_text(encoding="utf-8") if diagnostic_path else ""
        assert snapshot.status.value == 10, (snapshot.terminal_failure, diagnostic)
        events = client.events(session_id)
        expected_message = ""
        for _ in range(12):
            event = await asyncio.wait_for(events.__anext__(), 1.0)
            if event.type == "message.enqueued":
                payload = json.loads(event.data)
                if payload["operation_id"].replace("-", "") == operation.id.hex():
                    expected_message = payload["message_id"].replace("-", "")
                    break
        await events.aclose()
        assert expected_message
        process = first._process
        assert process is not None
        process.kill()
        await process.wait()
    assert effects.read_text(encoding="utf-8").splitlines() == [expected_message]
    scenario.write_text('{"capabilities":["durable.acceptance"],"events":[]}', encoding="utf-8")
    second = Navigator.local(**options)
    async with second as restarted:
        recovery_request = _id()
        with pytest.raises(CleanupRequired) as first_recovery:
            await restarted.resume(recovery_request, session_id)
        with pytest.raises(CleanupRequired) as replayed_recovery:
            await restarted.resume(recovery_request, session_id)
        assert first_recovery.value.retry is RetryClass.AFTER_RECONCILIATION
        assert replayed_recovery.value.code == first_recovery.value.code
        assert (await restarted.operation(session_id, operation.id)).status.value == 10
    assert effects.read_text(encoding="utf-8").splitlines() == [expected_message]


@pytest.mark.asyncio
async def test_mailbox_fake_restart_reconciles_to_succeeded_exactly_once(tmp_path: Path) -> None:
    daemon = _daemon()
    crash_barrier = tmp_path / "allow-driver-crash"
    catalog, scenario, effects, _ = _configured_fake(
        tmp_path,
        crash_barrier=crash_barrier,
        delivery_fault="restart_after_durable_acceptance",
    )
    data = tmp_path / "private"
    data.mkdir(mode=0o700)
    capabilities = (
        "events.replay.v1",
        "operation.execution.v1",
        "operation.cancellation.v1",
        "session.lifecycle.v1",
        "recovery.resolution.v1",
    )
    options = {
        "binary": daemon,
        "binary_sha256": _digest(daemon),
        "data_dir": data,
        "capabilities": capabilities,
        "driver_catalog": catalog,
        "driver_catalog_sha256": _digest(catalog),
        "driver_profiles": ("fake",),
    }
    first = Navigator.local(**options)
    async with first as client:
        session_id = _id()
        opened = await client.open(
            _id(), session_id, "python-success-recovery", b"", _configured_template()
        )
        operation = await client.start(_id(), session_id, opened.root_id, b"{}")
        events = client.events(session_id)
        message_id = ""
        for _ in range(16):
            event = await asyncio.wait_for(events.__anext__(), 1.0)
            if event.type == "message.enqueued":
                payload = json.loads(event.data)
                if payload["operation_id"].replace("-", "") == operation.id.hex():
                    message_id = payload["message_id"].replace("-", "")
                    break
        await events.aclose()
        assert message_id
        for _ in range(500):
            if effects.exists() and effects.read_text(encoding="utf-8").strip():
                break
            await asyncio.sleep(0.01)
        assert effects.read_text(encoding="utf-8").splitlines() == [message_id]
        # The first Driver has durably accepted the mailbox item and is held at
        # its crash boundary. Its replacement reads this scenario after the
        # barrier is released, proves acceptance from the durable journal, and
        # reports the one terminal outcome without redelivery.
        scenario.write_text(
            json.dumps(
                {
                    "capabilities": ["durable.acceptance"],
                    "events": [
                        {
                            "kind": "outcome",
                            "operation_id": operation.id.hex(),
                            "message_id": message_id,
                            "outcome": "succeeded",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        crash_barrier.touch()
        for _ in range(500):
            snapshot = await client.operation(session_id, operation.id)
            if snapshot.status.value == 7:
                break
            await asyncio.sleep(0.01)
        assert snapshot.status.value == 7, snapshot.terminal_failure

        replay = client.events(session_id)
        terminal_events = 0
        try:
            while True:
                event = await asyncio.wait_for(replay.__anext__(), 0.1)
                if event.type == "operation.succeeded":
                    payload = json.loads(event.data)
                    terminal_events += (
                        payload.get("operation_id", "").replace("-", "") == operation.id.hex()
                    )
        except asyncio.TimeoutError:
            pass
        finally:
            await replay.aclose()
        assert terminal_events == 1
        driver_pids = (tmp_path / "driver-pids.log").read_text(encoding="ascii").splitlines()
        assert len(driver_pids) == 2
        assert len(set(driver_pids)) == 2
        journals = list((tmp_path / "journals").glob("*.journal.json"))
        assert len(journals) == 1
        durable = json.loads(journals[0].read_text(encoding="utf-8"))
        assert durable["acceptance_query_count"] >= 1
        assert durable["delivery_count"] == 1
        await client.close(_id(), session_id)
        durable = json.loads(journals[0].read_text(encoding="utf-8"))
        assert durable["stop_process_ids"] == [int(driver_pids[1])]
        assert int(driver_pids[0]) not in durable["stop_process_ids"]
        for pid_text in driver_pids:
            pid = int(pid_text)
            for _ in range(200):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                await asyncio.sleep(0.01)
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)
    assert effects.read_text(encoding="utf-8").splitlines() == [message_id]
    with sqlite3.connect(data / "navigator.sqlite") as database:
        terminal_rows = database.execute(
            "SELECT COUNT(*) FROM events WHERE session_id = ? AND event_type = ?",
            (str(uuid.UUID(bytes=bytes(session_id))), "operation.succeeded"),
        ).fetchone()[0]
    assert terminal_rows == 1
