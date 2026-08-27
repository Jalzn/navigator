from __future__ import annotations

import asyncio
import importlib.util
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from navigator import (
    AcceptanceWorkflow,
    CleanupRequired,
    CursorFile,
    Event,
    EventPosition,
    Identity,
    OperationStatus,
    ResourceBounds,
    Session,
    SessionSpec,
    SessionStatus,
    Template,
    TransportUnavailable,
    managed_template,
)
from navigator.errors import RetryClass


def oid(last: int) -> Identity:
    return Identity(bytes(15) + bytes([last]))


def snapshot(identifier: Identity) -> Session:
    now = datetime.fromtimestamp(1, tz=timezone.utc)
    return Session(id=identifier, root_id=oid(2), consumer_key="example",
                   status=SessionStatus.OPEN, revision=1,
                   compatibility_identity=bytes(32), created_at=now, updated_at=now)


class SemanticEndpoint:
    def __init__(self) -> None:
        self.sessions = self
        self.session_snapshots: dict[Identity, Session] = {}
        self.audit: list[tuple[str, Identity]] = []
        self.requests: list[str] = []
        self.events_after: list[int] = []
        self.operation_status = OperationStatus.RUNNING
        self.reset_attempts = 0
        self.reset_identities: list[tuple[Identity | None, Identity | None]] = []

    async def open(
        self,
        spec: SessionSpec,
        *,
        mode: str = "open",
        request_id: Identity | None = None,
        session_id: Identity | None = None,
    ) -> Session:
        del spec
        self.requests.append(mode)
        if mode == "reset":
            self.reset_identities.append((request_id, session_id))
        if mode == "reset" and self.reset_attempts == 0:
            self.reset_attempts += 1
            raise CleanupRequired(15, "cleanup pending", RetryClass.AFTER_RECONCILIATION)
        resolved_session_id = session_id or oid(30 + len(self.session_snapshots))
        value = snapshot(resolved_session_id)
        self.session_snapshots[resolved_session_id] = value
        self.audit.append(("opened", resolved_session_id))
        return value

    async def start(self, request_id: Identity, session_id: Identity,
                    participant_id: Identity, input: bytes) -> Any:
        del request_id, session_id, participant_id, input
        self.requests.append("run")
        return SimpleNamespace(id=oid(20), status=self.operation_status)

    async def events(self, session_id: Identity,
                     after: EventPosition = EventPosition(0)) -> Any:
        self.events_after.append(int(after))
        for position in (1, 2):
            if position > after:
                now = datetime.fromtimestamp(position, tz=timezone.utc)
                yield Event(id=oid(10 + position), session_id=session_id,
                            position=EventPosition(position), revision=position,
                            type="operation.updated", schema_version=1, data=b"{}",
                            occurred_at=now)

    async def cancel(self, request_id: Identity, session_id: Identity,
                     root_participant_id: Identity) -> Any:
        del request_id, session_id, root_participant_id
        self.requests.append("cancel")
        return SimpleNamespace()

    async def resume(self, request_id: Identity, session_id: Identity) -> Any:
        del request_id, session_id
        self.requests.append("resume")
        self.operation_status = OperationStatus.CANCELLED
        return SimpleNamespace()

    async def operation(self, session_id: Identity, operation_id: Identity) -> Any:
        del session_id
        assert operation_id == oid(20)
        self.requests.append("operation")
        return SimpleNamespace(id=operation_id, status=self.operation_status)

    async def close(self, request_id: Identity, session_id: Identity) -> Session:
        del request_id
        self.requests.append("close")
        self.audit.append(("closed", session_id))
        return self.session_snapshots[session_id]


def load_example() -> ModuleType:
    path = Path(__file__).parents[1] / "examples" / "acceptance_workflow.py"
    spec = importlib.util.spec_from_file_location("acceptance_workflow", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_managed_example() -> ModuleType:
    path = Path(__file__).parents[1] / "examples" / "managed_work.py"
    spec = importlib.util.spec_from_file_location("managed_work", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_managed_template_hides_stable_runtime_identity() -> None:
    first = managed_template("Do the work")
    second = managed_template("Do other work")
    assert first.driver_id == second.driver_id
    assert bytes(first.driver_id).hex() == "00000000000000000000000000000001"
    assert first.id != second.id
    assert first.base_instructions == "Do the work"
    assert first.resources.max_concurrent_operations == 1


@pytest.mark.asyncio
async def test_minimal_managed_example_streams_until_confirmed_success() -> None:
    now = datetime.fromtimestamp(1, tz=timezone.utc)
    session = snapshot(oid(1))
    queued = SimpleNamespace(id=oid(20), status=OperationStatus.QUEUED)
    succeeded = SimpleNamespace(id=oid(20), status=OperationStatus.SUCCEEDED, result=b"done")

    class Endpoint:
        def __init__(self) -> None:
            self.snapshots = [queued, succeeded]
            self.seen_input = b""

        async def open(self, *args: Any) -> Session:
            assert isinstance(args[-1], Template)
            return session

        async def start(self, *args: Any) -> Any:
            self.seen_input = args[-1]
            return queued

        async def events(self, session_id: Identity) -> Any:
            for position in (1, 2):
                yield Event(id=oid(10 + position), session_id=session_id,
                            position=EventPosition(position), revision=position,
                            type="operation.updated", schema_version=1, data=b"{}",
                            occurred_at=now)

        async def operation(self, session_id: Identity, operation_id: Identity) -> Any:
            del session_id, operation_id
            return self.snapshots.pop(0)

    endpoint = Endpoint()
    result = await load_managed_example().run(endpoint, "public task")
    assert result.status is OperationStatus.SUCCEEDED
    assert endpoint.seen_input == b'{"task":"public task"}'


@pytest.mark.asyncio
async def test_minimal_example_configures_local_runtime_with_only_data_dir(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    example = load_managed_example()
    endpoint = object()
    observed: dict[str, Any] = {}

    class LocalContext:
        async def __aenter__(self) -> object:
            return endpoint

        async def __aexit__(self, *args: object) -> None:
            del args

    class PublicNavigator:
        @staticmethod
        def local(**options: Any) -> LocalContext:
            observed.update(options)
            return LocalContext()

    async def run(received: object, task: str) -> None:
        assert received is endpoint
        observed["task"] = task

    monkeypatch.setattr(example, "Navigator", PublicNavigator)
    monkeypatch.setattr(example, "run", run)
    await example.main(tmp_path, "work")
    assert observed == {"data_dir": tmp_path, "task": "work"}


@pytest.mark.asyncio
async def test_public_example_executes_complete_semantic_workflow(tmp_path: Path) -> None:
    endpoint = SemanticEndpoint()
    workflow = AcceptanceWorkflow(endpoint, CursorFile(tmp_path / "cursor"))  # type: ignore[arg-type]
    template = Template(id=oid(3), role="root", driver_id=oid(4), base_instructions="work",
                        resources=ResourceBounds(memory_bytes=1, cpu_millis=1,
                                                 max_concurrent_operations=1))
    await load_example().run_example(workflow, template)
    assert endpoint.requests == [
        "open", "run", "cancel", "resume", "operation", "reset", "reset"
    ]
    assert len(endpoint.reset_identities) == 2
    assert endpoint.reset_identities[0] != endpoint.reset_identities[1]
    assert all(
        identifier is not None
        for attempt in endpoint.reset_identities
        for identifier in attempt
    )
    opened = [identifier for action, identifier in endpoint.audit if action == "opened"]
    assert len(opened) == 2 and opened[0] != opened[1]
    assert endpoint.session_snapshots.keys() >= set(opened)  # reset retained prior audit/session


@pytest.mark.asyncio
async def test_reset_replays_exact_identities_after_uncertain_transport(tmp_path: Path) -> None:
    example = load_example()

    class Endpoint(SemanticEndpoint):
        async def open(
            self,
            spec: SessionSpec,
            *,
            mode: str = "open",
            request_id: Identity | None = None,
            session_id: Identity | None = None,
        ) -> Session:
            if mode != "reset":
                return await super().open(
                    spec, mode=mode, request_id=request_id, session_id=session_id
                )
            self.reset_identities.append((request_id, session_id))
            if len(self.reset_identities) == 1:
                raise TransportUnavailable(7, "response lost", RetryClass.SAFE)
            assert self.reset_identities[1] == self.reset_identities[0]
            assert session_id is not None
            return snapshot(session_id)

    endpoint = Endpoint()
    endpoint.reset_attempts = 1
    workflow = AcceptanceWorkflow(endpoint, CursorFile(tmp_path / "cursor"))  # type: ignore[arg-type]
    result = await example.reset_after_reconciliation(
        workflow, snapshot(oid(1)), managed_template("work")
    )
    assert result.id == endpoint.reset_identities[0][1]
    assert endpoint.reset_identities[0] == endpoint.reset_identities[1]


@pytest.mark.asyncio
async def test_permanent_cleanup_is_bounded_and_not_busy_polled(tmp_path: Path) -> None:
    example = load_example()

    class Endpoint(SemanticEndpoint):
        async def open(
            self,
            spec: SessionSpec,
            *,
            mode: str = "open",
            request_id: Identity | None = None,
            session_id: Identity | None = None,
        ) -> Session:
            del spec
            assert mode == "reset"
            self.reset_identities.append((request_id, session_id))
            raise CleanupRequired(15, "cleanup pending", RetryClass.AFTER_RECONCILIATION)

    endpoint = Endpoint()
    workflow = AcceptanceWorkflow(endpoint, CursorFile(tmp_path / "cursor"))  # type: ignore[arg-type]
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(
            example.reset_after_reconciliation(
                workflow, snapshot(oid(1)), managed_template("work")
            ),
            timeout=0.18,
        )
    assert 2 <= len(endpoint.reset_identities) <= 3
    assert len(set(endpoint.reset_identities)) == len(endpoint.reset_identities)


@pytest.mark.asyncio
async def test_permanent_transport_reuses_ids_without_busy_polling(tmp_path: Path) -> None:
    example = load_example()

    class Endpoint(SemanticEndpoint):
        async def open(
            self,
            spec: SessionSpec,
            *,
            mode: str = "open",
            request_id: Identity | None = None,
            session_id: Identity | None = None,
        ) -> Session:
            del spec
            assert mode == "reset"
            self.reset_identities.append((request_id, session_id))
            raise TransportUnavailable(7, "offline", RetryClass.SAFE)

    endpoint = Endpoint()
    workflow = AcceptanceWorkflow(endpoint, CursorFile(tmp_path / "cursor"))  # type: ignore[arg-type]
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(
            example.reset_after_reconciliation(
                workflow, snapshot(oid(1)), managed_template("work")
            ),
            timeout=0.18,
        )
    assert 2 <= len(endpoint.reset_identities) <= 3
    assert len(set(endpoint.reset_identities)) == 1


@pytest.mark.asyncio
async def test_reconnect_starts_strictly_after_persisted_cursor(tmp_path: Path) -> None:
    endpoint = SemanticEndpoint()
    workflow = AcceptanceWorkflow(endpoint, CursorFile(tmp_path / "cursor"))  # type: ignore[arg-type]
    session = snapshot(oid(1))
    handled: list[int] = []
    await workflow.subscribe(session, lambda event: handled.append(int(event.position)), limit=1)
    await workflow.subscribe(session, lambda event: handled.append(int(event.position)), limit=1)
    assert handled == [1, 2]
    assert endpoint.events_after == [0, 1]


@pytest.mark.asyncio
async def test_handler_failure_does_not_advance_cursor(tmp_path: Path) -> None:
    endpoint = SemanticEndpoint()
    cursor = CursorFile(tmp_path / "cursor")
    workflow = AcceptanceWorkflow(endpoint, cursor)  # type: ignore[arg-type]
    session = snapshot(oid(1))

    def fail(event: Event) -> None:
        raise RuntimeError(str(event.position))

    with pytest.raises(RuntimeError):
        await workflow.subscribe(session, fail, limit=1)
    assert cursor.load(session.id) == 0


def test_example_switches_deployment_only_through_configuration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    example = load_example()
    monkeypatch.setenv("NAVIGATOR_MODE", "external")
    monkeypatch.setenv("NAVIGATOR_ENDPOINT", "unix:///private/navigator.sock")
    monkeypatch.setenv("NAVIGATOR_CREDENTIAL", "credential")
    external = example.deployment_from_environment()
    assert external.mode == "external"

    monkeypatch.setenv("NAVIGATOR_MODE", "local")
    monkeypatch.setenv("NAVIGATOR_BINARY", str(tmp_path / "navigatord"))
    monkeypatch.setenv("NAVIGATOR_BINARY_SHA256", "0" * 64)
    monkeypatch.setenv("NAVIGATOR_DATA_DIR", str(tmp_path / "data"))
    local = example.deployment_from_environment()
    assert local.mode == "local"
