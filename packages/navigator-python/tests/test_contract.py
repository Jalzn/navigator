import asyncio
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any
from uuid import UUID

import pytest
from pydantic import ValidationError

from navigator.client import Navigator
from navigator.errors import (
    AuthorizationError,
    CorruptedState,
    IncompatibleProtocol,
    InvalidRequest,
    NavigatorError,
    RetryClass,
    TransportUnavailable,
    from_failure,
)
from navigator.models import (
    AuthorityEvent,
    AuthorityProfile,
    AuthorityRule,
    ConfirmCompleted,
    DoNotRetry,
    EffectProof,
    EffectProofKind,
    EffectResolutionEvent,
    EmptyEvent,
    EventPosition,
    Identity,
    InputKind,
    MessageEvent,
    OperationEvent,
    OperationStatus,
    ParticipantCreatedEvent,
    RecoveryActionStatus,
    RecoveryClassifiedEvent,
    RecoveryDisposition,
    ResourceBounds,
    RetryWithEffectProof,
    Session,
    SessionStatus,
    Template,
    UnknownEvent,
)


def oid(last: int) -> Identity:
    return Identity(bytes(15) + bytes([last]))


def test_models_are_frozen_and_identities_are_opaque() -> None:
    value = Session(
        id=oid(1),
        root_id=oid(2),
        consumer_key="consumer",
        status=1,
        revision=1,
        compatibility_identity=bytes(32),
        created_at=datetime.fromtimestamp(1, tz=timezone.utc),
        updated_at=datetime.fromtimestamp(2, tz=timezone.utc),
    )
    with pytest.raises(ValidationError):
        value.revision = 2
    assert "opaque" in repr(value.id)
    assert bytes(value.id) not in repr(value).encode()
    with pytest.raises(ValueError):
        Identity(bytes(16))
    for invalid_position in (-1, 1 << 64, True, 1.0, "1"):
        with pytest.raises(ValueError):
            EventPosition(invalid_position)  # type: ignore[arg-type]
    assert EventPosition(0) == 0
    assert EventPosition((1 << 64) - 1) == (1 << 64) - 1


def test_template_authority_is_exact_bounded_and_default_deny() -> None:
    rule = AuthorityRule(
        capability="durable.acceptance", resource="operation", resource_id=oid(9)
    )
    assert AuthorityProfile() == AuthorityProfile(active=(), delegable=())
    with pytest.raises(ValidationError, match="duplicate authority rule"):
        AuthorityProfile(active=(rule, rule))
    with pytest.raises(ValidationError, match="delegable authority must also be active"):
        AuthorityProfile(delegable=(rule,))
    with pytest.raises(ValidationError, match="too many authority rules"):
        AuthorityProfile(
            active=tuple(
                AuthorityRule(
                    capability="durable.acceptance",
                    resource="operation",
                    resource_id=Identity(index.to_bytes(16, "big")),
                )
                for index in range(1, 66)
            )
        )


def test_template_authority_wire_preserves_typed_scope_and_exact_identity() -> None:
    from navigator.models import ResourceBounds

    operation = oid(9)
    rule = AuthorityRule(
        capability="durable.acceptance", resource="operation", resource_id=operation
    )
    template = Template(
        id=oid(1),
        role="root",
        driver_id=oid(2),
        base_instructions="bounded",
        resources=ResourceBounds(
            memory_bytes=1, cpu_millis=1, max_concurrent_operations=1
        ),
        authority=AuthorityProfile(active=(rule,), delegable=(rule,)),
    )
    encoded = Navigator._template(template)
    assert len(encoded.authority_profile.active) == 1
    assert encoded.authority_profile.active[0].WhichOneof("resource") == "operation_id"
    assert encoded.authority_profile.active[0].operation_id == bytes(operation)
    assert encoded.authority_profile.delegable[0] == encoded.authority_profile.active[0]


@pytest.mark.asyncio
async def test_native_cancellation_is_not_wrapped() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        async def Snapshot(self, request: object) -> object:
            raise asyncio.CancelledError

    with pytest.raises(asyncio.CancelledError):
        await Navigator(Stub(), pb.RequestMetadata()).session(oid(1))


@pytest.mark.asyncio
async def test_negotiation_accepts_any_selected_version_in_overlap() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        async def Negotiate(self, request: object) -> object:
            return pb.NegotiateResponse(
                negotiated=pb.Negotiated(
                    protocol_version=pb.ProtocolVersion(major=2, minor=7),
                    negotiation_id=bytes(oid(1)),
                    configuration_identity=b"config",
                )
            )

    negotiated = await Navigator(Stub(), None).negotiate(minimum=1, maximum=2)
    assert (negotiated.protocol.major, negotiated.protocol.minor) == (2, 7)


@pytest.mark.asyncio
async def test_negotiation_treats_requested_capabilities_as_optional_offers() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        async def Negotiate(self, request: object) -> object:
            return pb.NegotiateResponse(
                negotiated=pb.Negotiated(
                    protocol_version=pb.ProtocolVersion(major=1),
                    capabilities=["session.lifecycle.v1"],
                    negotiation_id=bytes(oid(1)),
                    configuration_identity=b"config",
                )
            )

    negotiated = await Navigator(Stub(), None).negotiate(
        capabilities=("session.lifecycle.v1", "session.open-modes.v1")
    )
    assert negotiated.capabilities == ("session.lifecycle.v1",)


@pytest.mark.asyncio
async def test_transport_errors_are_stable_redacted_and_chained_without_raw_error() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    secret = "token-super-secret"

    class Stub:
        async def Snapshot(self, request: object) -> object:
            raise RuntimeError(secret)

    with pytest.raises(TransportUnavailable) as caught:
        await Navigator(Stub(), pb.RequestMetadata()).session(oid(1))
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)
    assert caught.value.__cause__ is None


def test_python_golden_matches_rust_prost_encoding() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    request = pb.NegotiateRequest(
        minimum_version=pb.ProtocolVersion(major=1),
        maximum_version=pb.ProtocolVersion(major=1),
        capabilities=["events.replay"],
    )
    assert request.SerializeToString().hex() == "0a020801120208011a0d6576656e74732e7265706c6179"


def test_unknown_optional_wire_field_is_ignored() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    golden = bytes.fromhex("0a020801120208011a0d6576656e74732e7265706c6179")
    decoded = pb.NegotiateRequest.FromString(golden + bytes.fromhex("980601"))
    assert decoded.minimum_version.major == 1
    assert decoded.capabilities == ["events.replay"]


@pytest.mark.asyncio
async def test_resource_snapshot_clients_bind_queries_to_session_and_freeze_results() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        async def ParticipantSnapshot(self, request: object) -> object:
            assert request.session_id == bytes(oid(1))
            assert request.participant_id == bytes(oid(2))
            return pb.ParticipantSnapshotResponse(
                snapshot=pb.ParticipantSnapshot(
                    session_id=bytes(oid(1)), participant_id=bytes(oid(2)), depth=0,
                    template_id=bytes(oid(3)), template_compatibility=b"compat", revision=1,
                )
            )

        async def MessageSnapshot(self, request: object) -> object:
            assert request.session_id == bytes(oid(1))
            assert request.message_id == bytes(oid(4))
            return pb.MessageSnapshotResponse(
                snapshot=pb.MessageSnapshot(
                    session_id=bytes(oid(1)), message_id=bytes(oid(4)),
                    source_participant_id=bytes(oid(2)), destination_participant_id=bytes(oid(5)),
                    mailbox_sequence=1, priority=pb.MESSAGE_PRIORITY_CONTROL,
                    envelope=b'{}', delivery_status=77, revision=1,
                    created_at=pb.Timestamp(unix_seconds=1), updated_at=pb.Timestamp(unix_seconds=2),
                )
            )

    client = Navigator(Stub(), pb.RequestMetadata())
    participant = await client.participant(oid(1), oid(2))
    message = await client.message(oid(1), oid(4))
    assert participant.session_id == oid(1) and participant.parent_id is None
    assert message.delivery_status == 77
    assert message.delivery_status.name == "UNKNOWN_77"
    with pytest.raises(ValidationError):
        message.revision = 2


def test_event_wrapper_preserves_opaque_future_wire_fields() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    event = pb.SessionEvent(
        event_id=bytes(oid(1)),
        session_id=bytes(oid(2)),
        position=1,
        revision=1,
        event_type="future.event",
        schema_version=99,
        data=b"opaque",
        occurred_at=pb.Timestamp(unix_seconds=1),
    )
    future_wire = event.SerializeToString() + bytes.fromhex("980601")
    wrapped = Navigator._event(pb.SessionEvent.FromString(future_wire))
    assert wrapped.type == "future.event" and wrapped.data == b"opaque"
    assert wrapped.opaque_wire == future_wire


def _wire_event(session_id: Identity, position: int) -> Any:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    return pb.SessionEvent(
        event_id=bytes(oid(position + 32)),
        session_id=bytes(session_id),
        position=position,
        revision=1,
        event_type="future.event",
        schema_version=99,
        data=b"opaque",
        occurred_at=pb.Timestamp(unix_seconds=1),
    )


@pytest.mark.asyncio
async def test_read_events_returns_bounded_immutable_page() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        async def ReadEvents(self, request: object) -> object:
            assert request.session_id == bytes(oid(2))  # type: ignore[attr-defined]
            assert request.after_position == 7  # type: ignore[attr-defined]
            assert request.page_size == 2  # type: ignore[attr-defined]
            return pb.ReadEventsResponse(
                page=pb.EventPage(
                    events=[_wire_event(oid(2), 8), _wire_event(oid(2), 9)],
                    has_more=True,
                )
            )

    page = await Navigator(Stub(), pb.RequestMetadata()).read_events(
        oid(2), EventPosition(7), page_size=2
    )
    assert tuple(int(event.position) for event in page.events) == (8, 9)
    assert page.has_more is True
    with pytest.raises(ValidationError):
        page.has_more = False
    with pytest.raises(ValidationError):
        type(page)(events=(), has_more=1)


@pytest.mark.asyncio
async def test_read_events_maps_failure_and_rejects_bounds_before_transport() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        calls = 0

        async def ReadEvents(self, request: object) -> object:
            self.calls += 1
            return SimpleNamespace(
                failure=SimpleNamespace(
                    code=1,
                    message="bad page",
                    retry=1,
                    related_id=b"",
                    details=b"",
                    HasField=lambda _: False,
                ),
                WhichOneof=lambda _: "failure",
            )

    stub = Stub()
    client = Navigator(stub, pb.RequestMetadata())
    for invalid in (0, 129, True, 1.5, "1"):
        with pytest.raises(ValueError):
            await client.read_events(oid(2), page_size=invalid)  # type: ignore[arg-type]
    assert stub.calls == 0
    for invalid_after in (True, -1, 1 << 64, 1.0, "1"):
        with pytest.raises(ValueError):
            await client.read_events(oid(2), invalid_after, page_size=1)  # type: ignore[arg-type]
    assert stub.calls == 0
    with pytest.raises(InvalidRequest):
        await client.read_events(oid(2), page_size=1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "events,page_size",
    [
        ([_wire_event(oid(3), 8)], 1),
        ([_wire_event(oid(2), 7)], 1),
        ([_wire_event(oid(2), 9), _wire_event(oid(2), 8)], 2),
        ([_wire_event(oid(2), 9)], 1),
        ([_wire_event(oid(2), 8), _wire_event(oid(2), 9)], 1),
    ],
)
async def test_read_events_rejects_forged_pages(events: list[Any], page_size: int) -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        async def ReadEvents(self, request: object) -> object:
            return pb.ReadEventsResponse(page=pb.EventPage(events=events))

    with pytest.raises(CorruptedState):
        await Navigator(Stub(), pb.RequestMetadata()).read_events(
            oid(2), EventPosition(7), page_size=page_size
        )


@pytest.mark.asyncio
async def test_read_events_rejects_empty_page_that_claims_more() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        async def ReadEvents(self, request: object) -> object:
            return pb.ReadEventsResponse(page=pb.EventPage(has_more=True))

    with pytest.raises(CorruptedState):
        await Navigator(Stub(), pb.RequestMetadata()).read_events(oid(2), page_size=1)


def test_event_wrapper_parses_known_payload_and_retains_future_payload_fields() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    payload = {
        "schema": 1,
        "operation_id": str(UUID(bytes=bytes(oid(3)))),
        "participant_id": str(UUID(bytes=bytes(oid(4)))),
        "state": "running",
        "input_message_id": str(UUID(bytes=bytes(oid(5)))),
        "future_detail": {"retained": True},
    }
    wire = pb.SessionEvent(
        event_id=bytes(oid(1)),
        session_id=bytes(oid(2)),
        position=7,
        revision=3,
        event_type="operation.running",
        schema_version=1,
        data=json.dumps(payload).encode(),
        occurred_at=pb.Timestamp(unix_seconds=1),
    )

    wrapped = Navigator._event(wire)

    assert isinstance(wrapped, OperationEvent)
    assert wrapped.payload.operation_id == oid(3)
    assert wrapped.payload.participant_id == oid(4)
    assert wrapped.payload.input_message_id == oid(5)
    assert wrapped.payload.model_extra == {"future_detail": {"retained": True}}
    assert wrapped.data == wire.data


def test_payloadless_known_event_accepts_extensible_object_payload() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    wire = pb.SessionEvent(
        event_id=bytes(oid(1)),
        session_id=bytes(oid(2)),
        position=1,
        revision=1,
        event_type="session.created",
        schema_version=1,
        data=b'{"future_detail":true}',
        occurred_at=pb.Timestamp(unix_seconds=1),
    )

    wrapped = Navigator._event(wire)

    assert isinstance(wrapped, EmptyEvent)
    assert wrapped.payload.model_extra == {"future_detail": True}


@pytest.mark.parametrize(
    ("event_type", "payload", "expected_class"),
    [
        (
            "participant.created",
            {
                "schema": 1,
                "participant_id": str(UUID(bytes=bytes(oid(3)))),
                "template_id": str(UUID(bytes=bytes(oid(4)))),
            },
            ParticipantCreatedEvent,
        ),
        (
            "message.accepted",
            {
                "message_id": str(UUID(bytes=bytes(oid(3)))),
                "source": str(UUID(bytes=bytes(oid(4)))),
                "destination": str(UUID(bytes=bytes(oid(5)))),
                "mailbox_sequence": 1,
                "operation_id": None,
                "in_reply_to": None,
                "state": "accepted",
            },
            MessageEvent,
        ),
        (
            "authority.grant_issued",
            {"schema": 1, "participant_id": str(UUID(bytes=bytes(oid(3))))},
            AuthorityEvent,
        ),
        (
            "effect.uncertainty_resolved",
            {
                "effect_request_id": str(UUID(bytes=bytes(oid(3)))),
                "operation_id": str(UUID(bytes=bytes(oid(4)))),
                "participant_id": str(UUID(bytes=bytes(oid(5)))),
                "resolution": "do_not_retry",
                "reason": "redacted",
            },
            EffectResolutionEvent,
        ),
        ("recovery.classified", [{"future_classification": True}], RecoveryClassifiedEvent),
    ],
)
def test_each_structured_event_family_has_a_typed_variant(
    event_type: str, payload: object, expected_class: type[object]
) -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    wire = pb.SessionEvent(
        event_id=bytes(oid(1)),
        session_id=bytes(oid(2)),
        position=1,
        revision=1,
        event_type=event_type,
        schema_version=1,
        data=json.dumps(payload).encode(),
        occurred_at=pb.Timestamp(unix_seconds=1),
    )

    assert isinstance(Navigator._event(wire), expected_class)


@pytest.mark.parametrize(
    ("event_type", "state"),
    [
        ("operation.resumed", "running"),
        ("operation.resumed", "waiting"),
        ("message.accepted", "leased"),
    ],
)
def test_event_type_must_agree_with_payload_state(event_type: str, state: str) -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    if event_type.startswith("operation."):
        payload = {
            "schema": 1,
            "operation_id": str(UUID(bytes=bytes(oid(3)))),
            "participant_id": str(UUID(bytes=bytes(oid(4)))),
            "state": state,
            "input_message_id": str(UUID(bytes=bytes(oid(5)))),
        }
    else:
        payload = {
            "message_id": str(UUID(bytes=bytes(oid(3)))),
            "source": str(UUID(bytes=bytes(oid(4)))),
            "destination": str(UUID(bytes=bytes(oid(5)))),
            "mailbox_sequence": 1,
            "operation_id": None,
            "in_reply_to": None,
            "state": state,
        }
    wire = pb.SessionEvent(
        event_id=bytes(oid(1)), session_id=bytes(oid(2)), position=1, revision=1,
        event_type=event_type, schema_version=1, data=json.dumps(payload).encode(),
        occurred_at=pb.Timestamp(unix_seconds=1),
    )

    wrapped = Navigator._event(wire)

    if event_type == "operation.resumed" and state == "running":
        assert isinstance(wrapped, OperationEvent)
    else:
        assert isinstance(wrapped, UnknownEvent)


@pytest.mark.parametrize(
    ("event_type", "schema_version", "data"),
    [
        ("operation.running", 2, b'{"schema":1}'),
        ("operation.running", 1, b"not-json"),
        (
            "operation.running",
            1,
            json.dumps(
                {
                    "schema": 1,
                    "operation_id": str(UUID(bytes=bytes(oid(3)))),
                    "participant_id": str(UUID(bytes=bytes(oid(4)))),
                    "state": "running",
                    "input_message_id": None,
                }
            ).encode(),
        ),
        (
            "operation.running",
            1,
            json.dumps(
                {
                    "schema": 1,
                    "operation_id": str(UUID(bytes=bytes(oid(3)))),
                    "participant_id": str(UUID(bytes=bytes(oid(4)))),
                    "state": "succeeded",
                    "input_message_id": None,
                }
            ).encode(),
        ),
    ],
)
def test_known_event_with_unrecognized_semantics_degrades_losslessly(
    event_type: str, schema_version: int, data: bytes
) -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    wire = pb.SessionEvent(
        event_id=bytes(oid(1)),
        session_id=bytes(oid(2)),
        position=7,
        revision=3,
        event_type=event_type,
        schema_version=schema_version,
        data=data,
        occurred_at=pb.Timestamp(unix_seconds=1),
    )

    wrapped = Navigator._event(wire)

    assert isinstance(wrapped, UnknownEvent)
    assert (wrapped.type, wrapped.schema_version, wrapped.data) == (
        event_type,
        schema_version,
        data,
    )
    assert wrapped.opaque_wire == wire.SerializeToString()


def test_failure_mapping_does_not_expose_wire_details() -> None:
    failure = SimpleNamespace(
        code=10,
        message="denied",
        retry=1,
        related_id=bytes(16),
        details=b"secret",
        HasField=lambda _: False,
    )
    response = SimpleNamespace(failure=failure, WhichOneof=lambda _: "failure")
    with pytest.raises(NavigatorError) as caught:
        Navigator._outcome(response, "snapshot")
    assert "secret" not in repr(caught.value)
    assert caught.value.details == {}


@pytest.mark.asyncio
async def test_complete_wrapper_builds_exact_requests_and_keeps_transport_private() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    operation = pb.OperationSnapshot(
        operation_id=bytes(oid(4)),
        session_id=bytes(oid(2)),
        participant_id=bytes(oid(3)),
        request_id=bytes(oid(5)),
        status=pb.OPERATION_STATUS_RUNNING,
        revision=1,
        created_at=pb.Timestamp(unix_seconds=1),
        updated_at=pb.Timestamp(unix_seconds=2),
    )

    class Stub:
        requests: list[object]

        def __init__(self) -> None:
            self.requests = []

        async def Negotiate(self, request: object) -> object:
            self.requests.append(request)
            return pb.NegotiateResponse(
                negotiated=pb.Negotiated(
                    protocol_version=pb.ProtocolVersion(major=1),
                    capabilities=["events.replay"],
                    negotiation_id=bytes(oid(1)),
                    configuration_identity=b"config",
                )
            )

        async def StartOperation(self, request: object) -> object:
            self.requests.append(request)
            return pb.StartOperationResponse(snapshot=operation)

        async def CancelSubtree(self, request: object) -> object:
            self.requests.append(request)
            return pb.CancelSubtreeResponse(
                cancellation=pb.CancellationSnapshot(
                    root_participant_id=bytes(oid(3)),
                    operations=[
                        pb.CancellationOperation(
                            operation=operation,
                            notification_message_id=b"",
                            cleanup_confirmed=True,
                        )
                    ],
                )
            )

        async def ResolveUncertainty(self, request: object) -> object:
            self.requests.append(request)
            return pb.ResolveUncertaintyResponse(
                resolution=pb.ResolutionSnapshot(
                    operation=operation,
                    action=pb.RESOLUTION_ACTION_DO_NOT_RETRY,
                    authority_grant_id=bytes(oid(7)),
                    reason="reviewed",
                    request_id=bytes(oid(8)),
                    session_id=bytes(oid(2)),
                    revision=2,
                    audit_event_position=9,
                    action_status=pb.RECOVERY_ACTION_STATUS_EXECUTED,
                )
            )

    stub = Stub()
    client = Navigator(stub, pb.RequestMetadata(protocol_version=pb.ProtocolVersion(major=1)))
    negotiated = await client.negotiate(capabilities=("events.replay",))
    started = await client.start(oid(5), oid(2), oid(3), b"input")
    cancelled = await client.cancel(oid(6), oid(2), oid(3))
    resolved = await client.resolve(oid(8), oid(2), oid(4), oid(7), "reviewed", DoNotRetry())
    assert negotiated.capabilities == ("events.replay",)
    assert started.id == oid(4)
    assert cancelled.operations[0].cleanup_confirmed is True
    assert cancelled.operations[0].notification_message_id is None
    assert resolved.audit_event_position == 9
    assert not hasattr(client, "stub")
    assert stub.requests[1].input == b"input"  # type: ignore[attr-defined]
    assert stub.requests[3].WhichOneof("resolution") == "do_not_retry"  # type: ignore[attr-defined]


def test_failure_codes_map_to_typed_redacted_errors() -> None:
    failure = SimpleNamespace(
        code=10,
        message="denied token-super-secret",
        retry=1,
        related_id=b"",
        details=b"raw-secret",
        HasField=lambda _: False,
    )
    response = SimpleNamespace(failure=failure, WhichOneof=lambda _: "failure")
    with pytest.raises(AuthorizationError) as caught:
        Navigator._outcome(response, "snapshot")
    assert "raw-secret" not in repr(caught.value)


def test_wire_enums_reject_unspecified_and_preserve_future_values() -> None:
    with pytest.raises(ValueError):
        OperationStatus(0)
    assert int(OperationStatus(99)) == 99
    assert OperationStatus(99).name == "UNKNOWN_99"
    with pytest.raises(ValueError):
        SessionStatus(0)
    assert InputKind(77).name == "UNKNOWN_77"


def test_wire_enum_names_preserve_consumer_protocol_semantics() -> None:
    import navigator

    assert RecoveryDisposition(1) is RecoveryDisposition.SAFE_TO_CONTINUE
    assert RecoveryDisposition(2) is RecoveryDisposition.SAFE_TO_REDELIVER
    assert RecoveryDisposition(3) is RecoveryDisposition.EFFECT_UNCERTAIN
    assert RecoveryDisposition(5) is RecoveryDisposition.EXTERNALLY_ALIVE
    assert RecoveryDisposition(6) is RecoveryDisposition.CLEANUP_REQUIRED
    assert RecoveryActionStatus(4) is RecoveryActionStatus.BLOCKED_BY_UNCERTAINTY
    assert RecoveryActionStatus(5) is RecoveryActionStatus.BLOCKED_BY_CLEANUP
    assert EffectProofKind(1) is EffectProofKind.EXTERNAL_COMMIT
    assert EffectProofKind(2) is EffectProofKind.IDEMPOTENCY_RECEIPT
    assert EffectProofKind(3) is EffectProofKind.EFFECT_ABSENT
    assert navigator.RecoveryDisposition is RecoveryDisposition
    assert navigator.RecoveryActionStatus is RecoveryActionStatus
    assert navigator.EffectProofKind is EffectProofKind

    assert not hasattr(RecoveryDisposition, "RESUMED")
    assert not hasattr(RecoveryActionStatus, "BLOCKED_AUTHORITY")
    assert not hasattr(EffectProofKind, "PROVIDER_RECEIPT")


def test_failure_preserves_public_message_redacts_details_and_types_retry() -> None:
    message = "protocol version is incompatible"
    secret = b"server-secret"
    failure = SimpleNamespace(
        code=18,
        message=message,
        retry=1,
        related_id=b"",
        details=secret,
        HasField=lambda _: False,
    )
    error = from_failure(failure)
    assert isinstance(error, IncompatibleProtocol)
    assert error.retry is RetryClass.NEVER
    assert str(error) == message
    assert error.args == (message,)
    assert error.details == {}
    assert secret.decode() not in repr(error)


@pytest.mark.asyncio
async def test_sync_stub_exception_is_redacted_transport_failure() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    class Stub:
        def Snapshot(self, request: object) -> object:
            raise RuntimeError("sync-secret")

    with pytest.raises(TransportUnavailable) as caught:
        await Navigator(Stub(), pb.RequestMetadata()).session(oid(1))
    assert "sync-secret" not in str(caught.value)
    assert caught.value.retry is RetryClass.SAFE


@pytest.mark.asyncio
async def test_every_remaining_rpc_and_all_resolution_actions() -> None:
    from navigator._transport.navigator.consumer.v1 import consumer_pb2 as pb

    stamp = pb.Timestamp(unix_seconds=10, nanoseconds=20)
    session = pb.SessionSnapshot(
        session_id=bytes(oid(2)),
        root_participant_id=bytes(oid(3)),
        consumer_key="consumer",
        status=pb.SESSION_STATUS_OPEN,
        revision=1,
        compatibility_identity=bytes(32),
        created_at=stamp,
        updated_at=stamp,
    )
    operation = pb.OperationSnapshot(
        operation_id=bytes(oid(4)),
        session_id=bytes(oid(2)),
        participant_id=bytes(oid(3)),
        request_id=bytes(oid(5)),
        status=pb.OPERATION_STATUS_RUNNING,
        revision=1,
        created_at=stamp,
        updated_at=stamp,
    )

    class Stub:
        def __init__(self) -> None:
            self.resolutions: list[object] = []

        async def OpenSession(self, request: object) -> object:
            return pb.OpenSessionResponse(snapshot=session)

        async def Snapshot(self, request: object) -> object:
            return pb.SnapshotResponse(snapshot=session)

        async def CloseSession(self, request: object) -> object:
            return pb.CloseSessionResponse(snapshot=session)

        async def OperationSnapshot(self, request: object) -> object:
            return pb.OperationSnapshotResponse(snapshot=operation)

        async def ResumeSession(self, request: object) -> object:
            return pb.ResumeSessionResponse(report=pb.RecoveryReport(session_id=bytes(oid(2))))

        def SubscribeEvents(self, request: object) -> object:
            async def responses() -> object:
                yield pb.SubscribeEventsResponse(
                    event=pb.SessionEvent(
                        event_id=bytes(oid(9)),
                        session_id=bytes(oid(2)),
                        position=1,
                        revision=1,
                        event_type="operation.updated",
                        schema_version=1,
                        data=b"{}",
                        occurred_at=stamp,
                    )
                )

            return responses()

        async def ResolveUncertainty(self, request: object) -> object:
            self.resolutions.append(request)
            return pb.ResolveUncertaintyResponse(
                resolution=pb.ResolutionSnapshot(
                    operation=operation,
                    action=pb.RESOLUTION_ACTION_DO_NOT_RETRY,
                    authority_grant_id=bytes(oid(7)),
                    reason="reviewed",
                    request_id=bytes(oid(8)),
                    session_id=bytes(oid(2)),
                    revision=2,
                    audit_event_position=9,
                    action_status=pb.RECOVERY_ACTION_STATUS_EXECUTED,
                )
            )

    template = Template(
        id=oid(10),
        role="root",
        driver_id=oid(11),
        base_instructions="work",
        resources=ResourceBounds(memory_bytes=1, cpu_millis=1, max_concurrent_operations=1),
    )
    stub = Stub()
    client = Navigator(stub, pb.RequestMetadata())
    opened = await client.open(oid(1), oid(2), "consumer", bytes(32), template)
    assert opened.created_at.timestamp() == pytest.approx(10.00000002)
    await client.session(oid(2))
    await client.close(oid(1), oid(2))
    await client.operation(oid(2), oid(4))
    await client.resume(oid(1), oid(2))
    assert [event.position async for event in client.events(oid(2))] == [1]
    proof = EffectProof(kind=EffectProofKind.EXTERNAL_COMMIT, digest=b"digest")
    actions = (
        ConfirmCompleted(proof=proof, effect_id=oid(12)),
        DoNotRetry(),
        RetryWithEffectProof(proof=proof, effect_id=oid(13)),
    )
    for action in actions:
        await client.resolve(oid(8), oid(2), oid(4), oid(7), "reviewed", action)
    assert [request.WhichOneof("resolution") for request in stub.resolutions] == [  # type: ignore[attr-defined]
        "confirm_completed",
        "do_not_retry",
        "retry_with_effect_proof",
    ]
    assert stub.resolutions[0].effect_id == bytes(oid(12))  # type: ignore[attr-defined]
    assert stub.resolutions[2].effect_id == bytes(oid(13))  # type: ignore[attr-defined]


def test_protocol_bounds_count_utf8_bytes() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Template(
            id=oid(1),
            role="é" * 65,
            driver_id=oid(2),
            base_instructions="work",
            resources=ResourceBounds(memory_bytes=1, cpu_millis=1, max_concurrent_operations=1),
        )
