"""Run one task using only Navigator's public managed-local API."""

import asyncio
import json
import sys
from pathlib import Path

from navigator import Navigator, Operation, OperationStatus, managed_template, new_identity

_TERMINAL = {
    OperationStatus.SUCCEEDED,
    OperationStatus.FAILED,
    OperationStatus.CANCELLED,
    OperationStatus.UNCERTAIN,
}


async def run(navigator: Navigator, task: str) -> Operation:
    template = managed_template("Complete the supplied task and report the result.")
    session = await navigator.open(
        new_identity(), new_identity(), "managed-work-example", b"", template
    )
    operation = await navigator.start(
        new_identity(),
        session.id,
        session.root_id,
        json.dumps({"task": task}, separators=(",", ":")).encode("utf-8"),
    )

    async for event in navigator.events(session.id):
        print(event.type)
        operation = await navigator.operation(session.id, operation.id)
        if operation.status in _TERMINAL:
            break

    if operation.status is not OperationStatus.SUCCEEDED:
        raise RuntimeError(f"operation terminated with {operation.status.name}")
    print("result:" + (operation.result or b"").decode("utf-8"))
    return operation


async def main(data_dir: Path, task: str) -> None:
    async with Navigator.local(data_dir=data_dir) as navigator:
        await run(navigator, task)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: managed_work.py DATA_DIR TASK")
    asyncio.run(main(Path(sys.argv[1]), sys.argv[2]))
