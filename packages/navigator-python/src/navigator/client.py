from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from .approvals import Approvals
    from .artifacts import Artifacts
    from .tools import Tools

from .errors import (
    CorruptedState,
    IncompatibleProtocol,
    NavigatorError,
    TransportUnavailable,
    from_failure,
)
from .models import (
    MAX_CAPABILITIES,
    MAX_CAPABILITY_BYTES,
    MAX_CONSUMER_KEY_BYTES,
    MAX_OPERATION_INPUT_BYTES,
    MAX_RESOLUTION_REASON_BYTES,
    Cancellation,
    CancellationOperation,
    ConfirmCompleted,
    DoNotRetry,
    EffectProof,
    Event,
    EventPage,
    EventPosition,
    EventVariant,
    Identity,
    Message,
    MessageDeliveryStatus,
    MessagePriority,
    Negotiated,
    Operation,
    OperationStatus,
    Participant,
    ProtocolVersion,
    RecoveryActionStatus,
    RecoveryClassification,
    RecoveryDisposition,
    RecoveryReport,
    Resolution,
    ResolutionAction,
    ResolutionSnapshot,
    RetryClass,
    RetryWithEffectProof,
    Session,
    SessionOpenMode,
    SessionStatus,
    Template,
    parse_event,
    timestamp,
)


@dataclass(frozen=True)
class SessionSpec:
    """Immutable specification used by the consumer-key session facade."""

    consumer_key: str
    compatibility_identity: bytes
    root_template: Template
    compatible_templates: tuple[Template, ...] = ()
    configuration_identity: bytes = b""


class Sessions:
    """Idiomatic session resource group; identities are resolved by Navigator."""

    def __init__(self, navigator: Navigator) -> None:
        self._navigator = navigator

    async def open(
        self,
        spec: SessionSpec,
        *,
        mode: str = "open",
        request_id: Identity | None = None,
        session_id: Identity | None = None,
    ) -> Session:
        modes = {
            "open": SessionOpenMode.OPEN,
            "resume": SessionOpenMode.RESUME,
            "reset": SessionOpenMode.RESET,
        }
        try:
            selected = modes[mode]
        except KeyError as error:
            raise ValueError("mode must be 'open', 'resume', or 'reset'") from error
        # These are idempotency/candidate identities, not client-side session
        # resolution. The daemon atomically resolves consumer_key.
        return await self._navigator.open(
            request_id or Identity(os.urandom(16)),
            session_id or Identity(os.urandom(16)),
            spec.consumer_key,
            spec.compatibility_identity,
            spec.root_template,
            spec.compatible_templates,
            spec.configuration_identity,
            mode=selected,
        )


class Navigator:
    """Stable async facade. The generated stub is deliberately private."""

    def __init__(self, stub: Any, metadata: Any, channel: Any = None) -> None:
        self.__stub, self.__metadata, self.__channel = stub, metadata, channel

    @classmethod
    async def connect(
        cls,
        endpoint: str,
        credential: str,
        *,
        capabilities: tuple[str, ...] = (
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
        ),
        timeout: float = 5.0,
    ) -> Navigator:
        from .connection import connect

        return await connect(endpoint, credential, capabilities=capabilities, timeout=timeout)

    @classmethod
    def local(cls, **kwargs: Any) -> Any:
        from .connection import LocalNavigator

        return LocalNavigator(**kwargs)

    @property
    def _stub(self) -> Any:
        return self.__stub

    @property
    def _metadata(self) -> Any:
        return self.__metadata

    @property
    def tools(self) -> Tools:
        from .tools import Tools

        return Tools(self)

    @property
    def artifacts(self) -> Artifacts:
        from .artifacts import Artifacts

        return Artifacts(self)

    @property
    def approvals(self) -> Approvals:
        from .approvals import Approvals

        return Approvals(self)

    async def __aenter__(self) -> Navigator:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self.__channel is not None:
            await self.__channel.close()
            self.__channel = None

    async def negotiate(
        self, minimum: int = 1, maximum: int = 1, capabilities: tuple[str, ...] = ()
    ) -> Negotiated:
        if len(capabilities) > MAX_CAPABILITIES or any(
            not value or len(value.encode("utf-8")) > MAX_CAPABILITY_BYTES for value in capabilities
        ):
            raise ValueError("capabilities violate protocol bounds")
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._invoke(
            self.__stub.Negotiate,
            pb.NegotiateRequest(
                minimum_version=pb.ProtocolVersion(major=minimum, minor=0),
                maximum_version=pb.ProtocolVersion(major=maximum, minor=2),
                capabilities=capabilities,
            ),
        )
        value = self._outcome(response, "negotiated")
        requested = set(capabilities)
        selected = tuple(value.capabilities)
        selected_version = (value.protocol_version.major, value.protocol_version.minor)
        if (
            selected_version < (minimum, 0)
            or selected_version > (maximum, (1 << 32) - 1)
            or not set(selected).issubset(requested)
            or len(value.negotiation_id) != 16
            or not value.configuration_identity
        ):
            raise IncompatibleProtocol(
                18, "Navigator negotiation was incompatible", RetryClass.NEVER
            )
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        self.__metadata = pb.RequestMetadata(
            protocol_version=value.protocol_version,
            capabilities=selected,
            negotiation_id=value.negotiation_id,
        )
        return Negotiated(
            protocol=ProtocolVersion(
                major=value.protocol_version.major, minor=value.protocol_version.minor
            ),
            capabilities=tuple(value.capabilities),
            negotiation_id=Identity(value.negotiation_id),
            configuration_identity=bytes(value.configuration_identity),
        )

    async def open(
        self,
        request_id: Identity,
        session_id: Identity,
        consumer_key: str,
        compatibility_identity: bytes,
        root_template: Template,
        compatible_templates: tuple[Template, ...] = (),
        configuration_identity: bytes = b"",
        mode: SessionOpenMode | None = None,
    ) -> Session:
        if not consumer_key or len(consumer_key.encode("utf-8")) > MAX_CONSUMER_KEY_BYTES:
            raise ValueError("consumer key violates protocol bounds")
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._invoke(
            self.__stub.OpenSession,
            pb.OpenSessionRequest(
                metadata=self.__metadata,
                request_id=bytes(request_id),
                session_id=bytes(session_id),
                consumer_key=consumer_key,
                compatibility_identity=compatibility_identity,
                root_template=self._template(root_template),
                compatible_templates=[self._template(v) for v in compatible_templates],
                configuration_identity=configuration_identity,
                mode=cast(Any, 0 if mode is None else int(mode)),
            ),
        )
        return self._session(self._outcome(response, "snapshot"))

    @property
    def sessions(self) -> Sessions:
        return Sessions(self)

    async def close(self, request_id: Identity, session_id: Identity) -> Session:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._invoke(
            self.__stub.CloseSession,
            pb.CloseSessionRequest(
                metadata=self.__metadata, request_id=bytes(request_id), session_id=bytes(session_id)
            ),
        )
        return self._session(self._outcome(response, "snapshot"))

    async def start(
        self, request_id: Identity, session_id: Identity, participant_id: Identity, input: bytes
    ) -> Operation:
        if not input or len(input) > MAX_OPERATION_INPUT_BYTES:
            raise ValueError("operation input violates protocol bounds")
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._invoke(
            self.__stub.StartOperation,
            pb.StartOperationRequest(
                metadata=self.__metadata,
                request_id=bytes(request_id),
                session_id=bytes(session_id),
                participant_id=bytes(participant_id),
                input=input,
            ),
        )
        return self._operation(self._outcome(response, "snapshot"))

    async def cancel(
        self, request_id: Identity, session_id: Identity, root_participant_id: Identity
    ) -> Cancellation:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._invoke(
            self.__stub.CancelSubtree,
            pb.CancelSubtreeRequest(
                metadata=self.__metadata,
                request_id=bytes(request_id),
                session_id=bytes(session_id),
                root_participant_id=bytes(root_participant_id),
            ),
        )
        return self._cancellation(self._outcome(response, "cancellation"))

    async def resume(self, request_id: Identity, session_id: Identity) -> RecoveryReport:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._invoke(
            self.__stub.ResumeSession,
            pb.ResumeSessionRequest(
                metadata=self.__metadata, request_id=bytes(request_id), session_id=bytes(session_id)
            ),
        )
        return self._recovery(self._outcome(response, "report"))

    async def resolve(
        self,
        request_id: Identity,
        session_id: Identity,
        operation_id: Identity,
        authority_grant_id: Identity,
        reason: str,
        resolution: Resolution,
    ) -> ResolutionSnapshot:
        if not reason or len(reason.encode("utf-8")) > MAX_RESOLUTION_REASON_BYTES:
            raise ValueError("resolution reason violates protocol bounds")
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        values: dict[str, Any] = {}
        if isinstance(resolution, ConfirmCompleted):
            values["confirm_completed"] = self._proof(resolution.proof)
            values["effect_id"] = bytes(resolution.effect_id)
        elif isinstance(resolution, RetryWithEffectProof):
            values["retry_with_effect_proof"] = self._proof(resolution.proof)
            values["effect_id"] = bytes(resolution.effect_id)
        elif isinstance(resolution, DoNotRetry):
            values["do_not_retry"] = pb.DoNotRetry()
        else:
            raise TypeError("unsupported resolution")
        response = await self._invoke(
            self.__stub.ResolveUncertainty,
            pb.ResolveUncertaintyRequest(
                metadata=self.__metadata,
                request_id=bytes(request_id),
                session_id=bytes(session_id),
                operation_id=bytes(operation_id),
                authority_grant_id=bytes(authority_grant_id),
                reason=reason,
                **values,
            ),
        )
        return self._resolution(self._outcome(response, "resolution"))

    async def session(self, session_id: Identity) -> Session:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._invoke(
            self.__stub.Snapshot,
            pb.SnapshotRequest(metadata=self.__metadata, session_id=bytes(session_id)),
        )
        return self._session(self._outcome(response, "snapshot"))

    async def operation(self, session_id: Identity, operation_id: Identity) -> Operation:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._invoke(
            self.__stub.OperationSnapshot,
            pb.OperationSnapshotRequest(
                metadata=self.__metadata,
                session_id=bytes(session_id),
                operation_id=bytes(operation_id),
            ),
        )
        return self._operation(self._outcome(response, "snapshot"))

    async def participant(self, session_id: Identity, participant_id: Identity) -> Participant:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._invoke(
            self.__stub.ParticipantSnapshot,
            pb.ParticipantSnapshotRequest(
                metadata=self.__metadata,
                session_id=bytes(session_id),
                participant_id=bytes(participant_id),
            ),
        )
        return self._participant(self._outcome(response, "snapshot"))

    async def message(self, session_id: Identity, message_id: Identity) -> Message:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        response = await self._invoke(
            self.__stub.MessageSnapshot,
            pb.MessageSnapshotRequest(
                metadata=self.__metadata,
                session_id=bytes(session_id),
                message_id=bytes(message_id),
            ),
        )
        return self._message(self._outcome(response, "snapshot"))

    async def events(
        self, session_id: Identity, after: EventPosition = EventPosition(0)
    ) -> AsyncIterator[Event]:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        try:
            call = self.__stub.SubscribeEvents(
                pb.SubscribeEventsRequest(
                    metadata=self.__metadata,
                    session_id=bytes(session_id),
                    after_position=int(after),
                )
            )
            async for response in call:
                yield self._event(self._outcome(response, "event"))
        except asyncio.CancelledError:
            raise
        except NavigatorError:
            raise
        except Exception:
            raise TransportUnavailable(
                7, "Navigator transport unavailable", RetryClass.SAFE
            ) from None

    async def read_events(
        self,
        session_id: Identity,
        after: EventPosition = EventPosition(0),
        *,
        page_size: int = 128,
    ) -> EventPage:
        """Read one bounded Event page without acquiring Session ownership."""
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        if type(page_size) is not int or page_size < 1 or page_size > 128:
            raise ValueError("page_size must be between 1 and 128")
        if type(after) is not EventPosition:
            raise ValueError("after must be an EventPosition")
        after_position = int(after)
        response = await self._invoke(
            self.__stub.ReadEvents,
            pb.ReadEventsRequest(
                metadata=self.__metadata,
                session_id=bytes(session_id),
                after_position=after_position,
                page_size=page_size,
            ),
        )
        wire = self._outcome(response, "page")
        if len(wire.events) > page_size or (not wire.events and wire.has_more):
            raise CorruptedState(16, "Navigator returned an invalid Event page", RetryClass.NEVER)
        events = tuple(self._event(value) for value in wire.events)
        previous = after_position
        for event in events:
            if event.session_id != session_id or int(event.position) != previous + 1:
                raise CorruptedState(
                    16, "Navigator returned an invalid Event page", RetryClass.NEVER
                )
            previous = int(event.position)
        return EventPage(events=events, has_more=wire.has_more)

    async def _unary(self, call: Any) -> Any:
        try:
            return await call
        except asyncio.CancelledError:
            raise
        except NavigatorError:
            raise
        except Exception:
            raise TransportUnavailable(
                7, "Navigator transport unavailable", RetryClass.SAFE
            ) from None

    async def _invoke(self, method: Any, request: Any) -> Any:
        try:
            call = method(request)
        except asyncio.CancelledError:
            raise
        except NavigatorError:
            raise
        except Exception:
            raise TransportUnavailable(
                7, "Navigator transport unavailable", RetryClass.SAFE
            ) from None
        return await self._unary(call)

    @staticmethod
    def _outcome(response: Any, success: str) -> Any:
        selected = response.WhichOneof("outcome")
        if selected == "failure":
            raise from_failure(response.failure)
        if selected != success:
            raise NavigatorError(8, "Malformed Navigator response", RetryClass.NEVER)
        return getattr(response, success)

    @staticmethod
    def _session(v: Any) -> Session:
        return Session(
            id=Identity(v.session_id),
            root_id=Identity(v.root_participant_id),
            consumer_key=v.consumer_key,
            status=SessionStatus(v.status),
            revision=v.revision,
            compatibility_identity=bytes(v.compatibility_identity),
            created_at=timestamp(v.created_at.unix_seconds, v.created_at.nanoseconds),
            updated_at=timestamp(v.updated_at.unix_seconds, v.updated_at.nanoseconds),
        )

    @staticmethod
    def _operation(v: Any) -> Operation:
        return Operation(
            id=Identity(v.operation_id),
            session_id=Identity(v.session_id),
            participant_id=Identity(v.participant_id),
            request_id=Identity(v.request_id),
            status=OperationStatus(v.status),
            revision=v.revision,
            result=bytes(v.result) if v.HasField("result") else None,
            terminal_failure=Navigator._failure(v.terminal_failure)
            if v.HasField("terminal_failure")
            else None,
            created_at=timestamp(v.created_at.unix_seconds, v.created_at.nanoseconds),
            updated_at=timestamp(v.updated_at.unix_seconds, v.updated_at.nanoseconds),
        )

    @staticmethod
    def _participant(v: Any) -> Participant:
        return Participant(
            id=Identity(v.participant_id),
            session_id=Identity(v.session_id),
            parent_id=Identity(v.parent_participant_id)
            if v.HasField("parent_participant_id")
            else None,
            depth=v.depth,
            template_id=Identity(v.template_id),
            template_compatibility=bytes(v.template_compatibility),
            revision=v.revision,
        )

    @staticmethod
    def _message(v: Any) -> Message:
        return Message(
            id=Identity(v.message_id),
            session_id=Identity(v.session_id),
            source_participant_id=Identity(v.source_participant_id),
            destination_participant_id=Identity(v.destination_participant_id),
            mailbox_sequence=v.mailbox_sequence,
            priority=MessagePriority(v.priority),
            operation_id=Identity(v.operation_id) if v.HasField("operation_id") else None,
            in_reply_to=Identity(v.in_reply_to) if v.HasField("in_reply_to") else None,
            envelope=bytes(v.envelope),
            attempt_count=v.attempt_count,
            delivery_status=MessageDeliveryStatus(v.delivery_status),
            revision=v.revision,
            created_at=timestamp(v.created_at.unix_seconds, v.created_at.nanoseconds),
            updated_at=timestamp(v.updated_at.unix_seconds, v.updated_at.nanoseconds),
        )

    @staticmethod
    def _failure(v: Any) -> Any:
        from .models import Failure

        return Failure(
            code=v.code,
            message=v.message,
            retry=RetryClass(v.retry),
            related_id=Identity(v.related_id) if v.HasField("related_id") else None,
        )

    @staticmethod
    def _template(v: Template) -> Any:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        def authority_rule(rule: Any) -> Any:
            return pb.ScopedCapabilitySpecification(
                capability=rule.capability,
                **{f"{rule.resource}_id": bytes(rule.resource_id)},
            )

        return pb.RootTemplateSpecification(
            template_id=bytes(v.id),
            role=v.role,
            driver_id=bytes(v.driver_id),
            required_capabilities=[
                pb.DriverCapabilityRequirement(
                    capability=c.capability,
                    minimum_version=c.minimum_version,
                    parameters=[
                        pb.CapabilityParameter(key=k, value=value)
                        for k, value in sorted(c.parameters.items())
                    ],
                )
                for c in v.required_capabilities
            ],
            trusted_configuration=pb.TrustedTemplateConfiguration(
                base_instructions=v.base_instructions, secret_names=v.secret_names
            ),
            resources=pb.ParticipantResourceBounds(**v.resources.model_dump()),
            input_schema=pb.InputSchema(
                fields=[
                    pb.InputField(
                        name=f.name,
                        kind=cast(Any, f.kind),
                        required=f.required,
                        **(
                            {"max_string_bytes": f.max_string_bytes}
                            if f.max_string_bytes is not None
                            else {}
                        ),
                    )
                    for f in v.input_fields
                ]
            ),
            authority_profile=pb.AuthorityProfileSpecification(
                active=[authority_rule(rule) for rule in v.authority.active],
                delegable=[authority_rule(rule) for rule in v.authority.delegable],
            ),
        )

    @staticmethod
    def _proof(v: EffectProof) -> Any:
        from ._transport.navigator.consumer.v1 import consumer_pb2 as pb

        return pb.EffectProof(kind=cast(Any, v.kind), digest=v.digest, evidence=v.evidence)

    @classmethod
    def _cancellation(cls, v: Any) -> Cancellation:
        return Cancellation(
            root_participant_id=Identity(v.root_participant_id),
            operations=tuple(
                CancellationOperation(
                    operation=cls._operation(item.operation),
                    notification_message_id=(
                        Identity(item.notification_message_id)
                        if item.notification_message_id
                        else None
                    ),
                    driver_acknowledged=item.driver_acknowledged,
                )
                for item in v.operations
            ),
        )

    @staticmethod
    def _classification(v: Any) -> RecoveryClassification:
        for name in (
            "session_id",
            "participant_id",
            "launch_attempt_id",
            "operation_id",
            "message_id",
            "effect_id",
        ):
            if v.HasField(name):
                return RecoveryClassification(
                    entity_kind=name.removesuffix("_id"),
                    entity_id=Identity(getattr(v, name)),
                    disposition=RecoveryDisposition(v.disposition),
                    allowed_actions=tuple(ResolutionAction(x) for x in v.allowed_actions),
                    reason=v.reason,
                    action_status=RecoveryActionStatus(v.action_status),
                )
        raise NavigatorError(8, "Malformed Navigator response", RetryClass.NEVER)

    @classmethod
    def _recovery(cls, v: Any) -> RecoveryReport:
        return RecoveryReport(
            session_id=Identity(v.session_id),
            classifications=tuple(cls._classification(x) for x in v.classifications),
        )

    @classmethod
    def _resolution(cls, v: Any) -> ResolutionSnapshot:
        return ResolutionSnapshot(
            operation=cls._operation(v.operation),
            action=ResolutionAction(v.action),
            authority_grant_id=Identity(v.authority_grant_id),
            reason=v.reason,
            request_id=Identity(v.request_id),
            session_id=Identity(v.session_id),
            effect_id=Identity(v.effect_id) if v.effect_id else None,
            revision=v.revision,
            audit_event_position=EventPosition(v.audit_event_position),
            action_status=RecoveryActionStatus(v.action_status),
        )

    @staticmethod
    def _event(v: Any) -> EventVariant:
        return parse_event(
            {
                "id": Identity(v.event_id),
                "session_id": Identity(v.session_id),
                "position": EventPosition(v.position),
                "revision": v.revision,
                "type": v.event_type,
                "schema_version": v.schema_version,
                "data": bytes(v.data),
                "occurred_at": timestamp(v.occurred_at.unix_seconds, v.occurred_at.nanoseconds),
                "related_request_id": Identity(v.related_request_id)
                if v.HasField("related_request_id")
                else None,
                "opaque_wire": bytes(v.SerializeToString()),
            }
        )
