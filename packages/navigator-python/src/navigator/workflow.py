from __future__ import annotations

import json
import os
import tempfile
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .client import Navigator, SessionSpec
from .models import (
    Cancellation,
    CapabilityRequirement,
    Event,
    EventPosition,
    Identity,
    InputField,
    InputKind,
    Operation,
    RecoveryReport,
    ResourceBounds,
    Session,
    Template,
)

_MANAGED_DRIVER_ID = Identity(bytes.fromhex("00000000000000000000000000000001"))


def managed_template(
    base_instructions: str,
    *,
    role: str = "root",
    resources: ResourceBounds | None = None,
    required_capabilities: tuple[CapabilityRequirement, ...] = (),
    secret_names: tuple[str, ...] = (),
) -> Template:
    """Create a Template for Navigator's managed generic agent runtime.

    The runtime identity is deliberately an SDK implementation detail: consumers
    describe trusted behavior and bounds without depending on the bundled agent
    implementation.
    """
    return Template(
        id=new_identity(),
        role=role,
        driver_id=_MANAGED_DRIVER_ID,
        required_capabilities=required_capabilities,
        base_instructions=base_instructions,
        secret_names=secret_names,
        input_fields=(
            InputField(
                name="task", kind=InputKind.STRING, required=True, max_string_bytes=64 * 1024
            ),
        ),
        resources=resources
        or ResourceBounds(
            memory_bytes=256 * 1024 * 1024,
            cpu_millis=1_000,
            max_concurrent_operations=1,
        ),
    )


def new_identity() -> Identity:
    """Create an opaque identity suitable for a new request or durable entity."""
    return Identity(uuid.uuid4().bytes)


@dataclass(frozen=True)
class Deployment:
    mode: Literal["external", "local"]
    endpoint: str | None = None
    credential: str | None = None
    binary: Path | None = None
    binary_sha256: str | None = None
    data_dir: Path | None = None


@asynccontextmanager
async def configured_navigator(deployment: Deployment) -> AsyncIterator[Navigator]:
    """Select external or managed-local transport without changing workflow code."""
    if deployment.mode == "external":
        if deployment.endpoint is None or deployment.credential is None:
            raise ValueError("external deployment requires endpoint and credential")
        client = await Navigator.connect(deployment.endpoint, deployment.credential)
        async with client:
            yield client
        return
    if deployment.mode == "local":
        if deployment.data_dir is None:
            raise ValueError("local deployment requires a data directory")
        if (deployment.binary is None) != (deployment.binary_sha256 is None):
            raise ValueError("local executable override requires binary and digest")
        options: dict[str, Any] = {"data_dir": deployment.data_dir}
        if deployment.binary is not None:
            options.update(binary=deployment.binary, binary_sha256=deployment.binary_sha256)
        async with Navigator.local(**options) as client:
            yield client
        return
    raise ValueError("unsupported deployment mode")


class CursorFile:
    """Small durable event cursor; writes are atomic and never contain event data."""

    def __init__(self, path: Path) -> None:
        self._path = path

    def load(self, session_id: Identity) -> EventPosition:
        try:
            raw = self._path.read_text(encoding="ascii")
        except FileNotFoundError:
            return EventPosition(0)
        value = json.loads(raw)
        if value != {"position": value.get("position"), "session": bytes(session_id).hex()}:
            return EventPosition(0)
        return EventPosition(int(value["position"]))

    def save(self, session_id: Identity, position: EventPosition) -> None:
        self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".cursor-", dir=self._path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            payload = json.dumps(
                {"position": int(position), "session": bytes(session_id).hex()},
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            os.write(descriptor, payload)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.replace(temporary, self._path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


class AcceptanceWorkflow:
    """Executable consumer workflow built only from Navigator's public API."""

    def __init__(self, navigator: Navigator, cursor: CursorFile) -> None:
        self.navigator = navigator
        self.cursor = cursor

    async def open(
        self, template: Template, consumer_key: str, compatibility_identity: bytes
    ) -> Session:
        return await self.navigator.sessions.open(
            SessionSpec(
                consumer_key=consumer_key,
                compatibility_identity=compatibility_identity,
                root_template=template,
            ),
            mode="open",
        )

    async def run(self, session: Session, participant_id: Identity, payload: bytes) -> Operation:
        return await self.navigator.start(new_identity(), session.id, participant_id, payload)

    async def subscribe(
        self,
        session: Session,
        handle: Callable[[Event], Any],
        *,
        limit: int | None = None,
    ) -> int:
        """Resume after the last handled event and save only after successful handling."""
        count = 0
        async for event in self.navigator.events(session.id, self.cursor.load(session.id)):
            result = handle(event)
            if hasattr(result, "__await__"):
                await result
            self.cursor.save(session.id, event.position)
            count += 1
            if limit is not None and count >= limit:
                break
        return count

    async def cancel(self, session: Session, participant_id: Identity) -> Cancellation:
        return await self.navigator.cancel(new_identity(), session.id, participant_id)

    async def resume(self, session: Session) -> RecoveryReport:
        return await self.navigator.resume(new_identity(), session.id)

    async def reset(
        self,
        previous: Session,
        template: Template,
        consumer_key: str,
        compatibility_identity: bytes,
        *,
        request_id: Identity | None = None,
        session_id: Identity | None = None,
    ) -> Session:
        """Atomically replace the keyed Session while retaining its audit history."""
        _ = previous  # The daemon resolves the durable predecessor by consumer_key.
        return await self.navigator.sessions.open(
            SessionSpec(
                consumer_key=consumer_key,
                compatibility_identity=compatibility_identity,
                root_template=template,
            ),
            mode="reset",
            request_id=request_id,
            session_id=session_id,
        )
