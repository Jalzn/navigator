from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

DRIVER_ID = "00000000000000000000000000000001"


def _record(path: Path, relative: PurePosixPath) -> dict[str, str | int]:
    return {
        "path": relative.as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": path.stat().st_size,
    }


def _copy_file(source: Path, destination: Path, *, executable: bool = False) -> None:
    if source.is_symlink() or not source.is_file():
        raise SystemExit(f"runtime input must be a regular, non-symlink file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o755 if executable else 0o644)


def _files(root: Path) -> Iterable[Path]:
    return sorted(
        (path for path in root.rglob("*") if path.is_file() and not path.is_symlink()),
        key=lambda path: path.as_posix(),
    )


def _production_packages(lock: dict[str, Any]) -> set[str]:
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise SystemExit("Pi package-lock.json must contain a packages object")
    result: set[str] = set()
    for name, metadata in packages.items():
        if (
            not isinstance(name, str)
            or not name.startswith("node_modules/")
            or not isinstance(metadata, dict)
            or metadata.get("dev") is True
        ):
            continue
        operating_systems = metadata.get("os", [])
        architectures = metadata.get("cpu", [])
        if operating_systems and "darwin" not in operating_systems:
            continue
        if architectures and "arm64" not in architectures:
            continue
        package_name = name.removeprefix("node_modules/")
        relative = PurePosixPath(package_name)
        if relative.is_absolute() or ".." in relative.parts:
            raise SystemExit(f"unsafe package-lock path: {name}")
        result.add(package_name)
    return result


def _copy_tree_files(source: Path, destination: Path) -> None:
    if source.is_symlink():
        raise SystemExit(f"unexpected symlink in runtime dependency: {source}")
    for path in sorted(source.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            if ".bin" in path.relative_to(source).parts:
                continue
            raise SystemExit(f"unexpected symlink in runtime dependency: {path}")
        if path.is_file():
            _copy_file(path, destination / path.relative_to(source))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare the complete Pi runtime for a Python wheel"
    )
    parser.add_argument("binary", type=Path, help="prebuilt navigatord")
    parser.add_argument("--target", choices=("darwin-arm64",), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--node", type=Path, default=Path(shutil.which("node") or "node"))
    parser.add_argument("--pi-package", type=Path)
    parser.add_argument("--protocol-package", type=Path)
    arguments = parser.parse_args()

    repository = Path(__file__).resolve().parents[3]
    pi_source = (arguments.pi_package or repository / "packages/navigator-driver-pi").resolve()
    protocol_source = (
        arguments.protocol_package or repository / "crates/navigator-driver-protocol/typescript"
    ).resolve()
    binary = arguments.binary.resolve(strict=True)
    node = arguments.node.resolve(strict=True)
    for name, source in (("navigatord", binary), ("node", node)):
        details = source.stat()
        if not stat.S_ISREG(details.st_mode) or not os.access(source, os.X_OK):
            raise SystemExit(f"{name} must be an executable regular file")
    for package in (pi_source, protocol_source):
        if not package.joinpath("package.json").is_file() or not package.joinpath("dist").is_dir():
            raise SystemExit(f"runtime package must have package.json and built dist/: {package}")

    lock = json.loads((pi_source / "package-lock.json").read_text(encoding="utf-8"))
    output = arguments.output.resolve()
    temporary = output / f".{arguments.target}.tmp"
    destination = output / arguments.target
    if temporary.exists():
        shutil.rmtree(temporary)
    temporary.mkdir(parents=True)
    _copy_file(binary, temporary / "navigatord", executable=True)
    _copy_file(node, temporary / "node", executable=True)

    pi_destination = temporary / "pi"
    for name in ("package.json", "package-lock.json"):
        _copy_file(pi_source / name, pi_destination / name)
    _copy_tree_files(pi_source / "dist", pi_destination / "dist")
    for package_name in sorted(_production_packages(lock)):
        source = pi_source / "node_modules" / package_name
        if package_name == "@navigator/driver-protocol":
            continue
        if not source.exists():
            raise SystemExit(f"production dependency is not installed: {package_name}")
        if source.is_symlink():
            raise SystemExit(f"production dependency must not be a symlink: {source}")
        _copy_tree_files(source, pi_destination / "node_modules" / package_name)

    protocol_destination = pi_destination / "node_modules/@navigator/driver-protocol"
    _copy_file(protocol_source / "package.json", protocol_destination / "package.json")
    _copy_tree_files(protocol_source / "dist", protocol_destination / "dist")

    provider = temporary / "acceptance/provider.mjs"
    provider.parent.mkdir(parents=True)
    provider.write_text(
        "import { fauxAssistantMessage, fauxProvider, fauxToolCall } from '../pi/node_modules/@earendil-works/pi-ai/dist/index.js';\n"
        "export function register(runtime) {\n"
        "  const faux = fauxProvider({ tokensPerSecond: 1000 });\n"
        "  faux.setResponses([\n"
        "    fauxAssistantMessage(fauxToolCall('navigator_report', { kind: 'succeeded', payload: 'done' }), { stopReason: 'toolUse' }),\n"
        "    fauxAssistantMessage('settled'),\n"
        "  ]);\n"
        "  runtime.registerNativeProvider(faux.provider);\n"
        "}\n",
        encoding="ascii",
    )
    provider.chmod(0o644)
    if destination.exists():
        shutil.rmtree(destination)
    os.replace(temporary, destination)

    prefix = PurePosixPath(arguments.target)
    navigatord_record = _record(destination / "navigatord", prefix / "navigatord")
    node_record = _record(destination / "node", prefix / "node")
    entrypoint_record = _record(destination / "pi/dist/main.js", prefix / "pi/dist/main.js")
    provider_record = _record(
        destination / "acceptance/provider.mjs", prefix / "acceptance/provider.mjs"
    )
    pi_tree = [
        _record(path, prefix / path.relative_to(destination)) for path in _files(destination / "pi")
    ]
    manifest = {
        "artifacts": {
            arguments.target: {
                "acceptance_provider": provider_record,
                "driver_id": DRIVER_ID,
                "navigatord": navigatord_record,
                "node": node_record,
                "pi_entrypoint": entrypoint_record,
                "pi_tree": pi_tree,
                "pi_working_directory": f"{arguments.target}/pi",
                "trusted_artifacts": [node_record, entrypoint_record, provider_record],
            }
        },
        "version": 2,
    }
    encoded = json.dumps(manifest, separators=(",", ":"), sort_keys=True) + "\n"
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = output / "manifest.json"
    manifest_path.write_text(encoded, encoding="ascii")
    manifest_path.chmod(0o644)


if __name__ == "__main__":
    main()
