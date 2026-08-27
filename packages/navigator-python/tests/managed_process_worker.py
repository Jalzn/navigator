"""Black-box worker used by the managed-local multiprocess acceptance test."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import uuid
from pathlib import Path

from navigator import Navigator
from navigator.errors import TransportUnavailable
from navigator.models import CapabilityRequirement, Identity, ResourceBounds, Template


def identity(value: str) -> Identity:
    return Identity(uuid.UUID(value).bytes)


def template(value: str) -> Template:
    return Template(
        id=identity(value),
        role="root",
        driver_id=Identity(bytes.fromhex("02" * 16)),
        required_capabilities=(
            CapabilityRequirement(capability="task.execute", minimum_version=1),
        ),
        base_instructions="multiprocess ownership proof",
        resources=ResourceBounds(
            memory_bytes=64 * 1024 * 1024,
            cpu_millis=1_000,
            max_concurrent_operations=1,
        ),
    )


async def wait_for(path: Path) -> None:
    for _ in range(1_000):
        if path.exists():
            return
        await asyncio.sleep(0.01)
    raise TimeoutError(str(path))


def publish(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value), encoding="utf-8")
    os.replace(temporary, path)


async def main() -> None:
    role, config_path = sys.argv[1:]
    config = json.loads(Path(config_path).read_text(encoding="utf-8"))
    root = Path(config["coordination"])
    daemon = Path(config["daemon"])
    digest = hashlib.sha256(daemon.read_bytes()).hexdigest()
    context = Navigator.local(
        binary=daemon,
        binary_sha256=digest,
        data_dir=Path(config["data"]),
        capabilities=("session.lifecycle.v1",),
    )
    session_id = identity(config["session_id"])
    request_id = identity(config["request_id"])
    specification = template(config["template_id"])
    pid = 0
    if role == "owner":
        async with context as client:
            opened = await client.open(
                request_id,
                session_id,
                "multiprocess-owner",
                b"",
                specification,
                configuration_identity=b"",
            )
            assert opened.root_id
            assert context._process is not None
            pid = context._process.pid
            publish(root / "owner-ready", {"daemon_pid": pid, "worker_pid": os.getpid()})
            await wait_for(root / "owner-release")
        publish(
            root / "owner-clean",
            {"daemon_pid": pid, "worker_pid": os.getpid(), "reaped": context._process is None},
        )
        return

    await wait_for(root / "owner-ready")
    try:
        async with context:
            raise AssertionError("a contender daemon shared an exclusively owned Artifact root")
    except TransportUnavailable:
        publish(root / "contender-fenced", {"worker_pid": os.getpid()})
    await wait_for(root / "owner-clean")
    context = Navigator.local(binary=daemon, binary_sha256=digest, data_dir=Path(config["data"]))
    async with context as client:
        assert context._process is not None
        pid = context._process.pid
        reopened = await client.open(
            request_id,
            session_id,
            "multiprocess-owner",
            b"",
            specification,
            configuration_identity=b"",
        )
        assert reopened.root_id
    publish(
        root / "contender-clean",
        {"daemon_pid": pid, "worker_pid": os.getpid(), "reaped": context._process is None},
    )


if __name__ == "__main__":
    asyncio.run(main())
