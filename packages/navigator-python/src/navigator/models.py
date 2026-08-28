import json
import unicodedata
from collections.abc import Mapping
from datetime import datetime, timezone
from enum import IntEnum
from typing import Any, Literal, Optional, Union, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

MAX_CAPABILITIES = 32
MAX_CAPABILITY_BYTES = 128
MAX_CONSUMER_KEY_BYTES = 256
MAX_OPERATION_INPUT_BYTES = 64 * 1024
MAX_EFFECT_PROOF_BYTES = 16 * 1024
MAX_RESOLUTION_REASON_BYTES = 1024
MAX_TEMPLATE_ROLE_BYTES = 128
MAX_TEMPLATE_INSTRUCTIONS_BYTES = 64 * 1024
MAX_TEMPLATE_CAPABILITIES = 32
MAX_TEMPLATE_PARAMETERS = 16
MAX_TEMPLATE_SECRET_NAMES = 32
MAX_TEMPLATE_INPUT_FIELDS = 32
MAX_TEMPLATE_NAME_BYTES = 64
MAX_TEMPLATE_PARAMETER_BYTES = 256
MAX_AUTHORITY_RULES = 64
MAX_TOOL_NAME_BYTES = 128
MAX_TOOL_VERSION_BYTES = 64
MAX_TOOL_SCHEMA_BYTES = 16 * 1024
MAX_TOOL_INLINE_BYTES = 64 * 1024
MAX_TOOL_FAILURE_MESSAGE_BYTES = 1024
MAX_TOOL_TIMEOUT_MILLIS = 3_600_000
MAX_TOOL_ARTIFACT_REFS = 32
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_MEDIA_TYPE_BYTES = 255
MAX_APPROVAL_RESOURCE_BYTES = 16 * 1024
MAX_APPROVAL_SUMMARY_BYTES = 1024
MAX_APPROVAL_USES = 1024


class Identity(bytes):
    """Opaque 128-bit Navigator identity; its byte representation is not semantic."""

    def __new__(cls, value: bytes) -> "Identity":
        if len(value) != 16 or not any(value):
            raise ValueError("Navigator identities must be non-zero 16-byte values")
        return bytes.__new__(cls, value)

    def __repr__(self) -> str:
        return "Identity(<opaque>)"


class EventPosition(int):
    def __new__(cls, value: int) -> "EventPosition":
        if type(value) is not int or value < 0 or value > (1 << 64) - 1:
            raise ValueError("event position must be an unsigned 64-bit integer")
        return int.__new__(cls, value)


class _WireEnum(IntEnum):
    """Reject UNSPECIFIED, while retaining positive future wire values."""

    @classmethod
    def _missing_(cls, value: object) -> "_WireEnum | None":
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            return None
        member = int.__new__(cls, value)
        member._name_ = f"UNKNOWN_{value}"
        member._value_ = value
        return member


class SessionStatus(_WireEnum):
    OPEN = 1
    CLOSED = 2


class SessionOpenMode(_WireEnum):
    OPEN = 1
    RESUME = 2
    RESET = 3


class OperationStatus(_WireEnum):
    QUEUED = 1
    STARTING = 2
    RUNNING = 3
    WAITING = 4
    BLOCKED = 5
    CANCELLING = 6
    SUCCEEDED = 7
    FAILED = 8
    CANCELLED = 9
    UNCERTAIN = 10
    DELIVERING = 11


class MessagePriority(_WireEnum):
    CONTROL = 1
    ORDINARY = 2


class MessageDeliveryStatus(_WireEnum):
    QUEUED = 1
    RETRY_SCHEDULED = 2
    LEASED = 3
    ACCEPTANCE_PENDING = 4
    ACCEPTANCE_UNKNOWN = 5
    ACCEPTED = 6
    UNCERTAIN = 7
    DEAD_LETTER = 8


class InputKind(_WireEnum):
    STRING = 1
    INTEGER = 2
    BOOLEAN = 3


class RecoveryDisposition(_WireEnum):
    SAFE_TO_CONTINUE = 1
    SAFE_TO_REDELIVER = 2
    EFFECT_UNCERTAIN = 3
    TERMINAL = 4
    EXTERNALLY_ALIVE = 5
    CLEANUP_REQUIRED = 6


class RecoveryActionStatus(_WireEnum):
    EXECUTED = 1
    NO_OP = 2
    PENDING = 3
    BLOCKED_BY_UNCERTAINTY = 4
    BLOCKED_BY_CLEANUP = 5


class ResolutionAction(_WireEnum):
    CONFIRM_COMPLETED = 1
    DO_NOT_RETRY = 2
    RETRY_WITH_EFFECT_PROOF = 3


class EffectProofKind(_WireEnum):
    EXTERNAL_COMMIT = 1
    IDEMPOTENCY_RECEIPT = 2
    EFFECT_ABSENT = 3


class RetryClass(_WireEnum):
    NEVER = 1
    SAFE = 2
    AFTER_RECONCILIATION = 3


class ToolCancellation(_WireEnum):
    COOPERATIVE = 1
    UNSUPPORTED = 2


class ToolEffectClass(_WireEnum):
    READ_ONLY = 1
    IDEMPOTENT = 2
    TRANSACTIONAL = 3
    NON_IDEMPOTENT = 4
    UNKNOWN = 5


class ToolIdempotencyContract(_WireEnum):
    NO_EXTERNAL_EFFECT = 1
    INVOCATION_IDENTITY = 2
    EXTERNAL_TRANSACTION_PROOF = 3
    NEVER_REPLAY = 4


class ArtifactStatus(_WireEnum):
    AVAILABLE = 1
    LOGICALLY_DELETED = 2
    ERASURE_ELIGIBLE = 3
    ERASED = 4
    CORRUPTED = 5


class ApprovalStatus(_WireEnum):
    PENDING = 1
    GRANTED = 2
    CONSUMED = 3
    DENIED = 4
    EXPIRED = 5
    REVOKED = 6


class ApprovalDecisionSource(_WireEnum):
    TRUSTED_CONSUMER = 1


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow", arbitrary_types_allowed=True)


class ProtocolVersion(_Frozen):
    major: int = Field(ge=0)
    minor: int = Field(default=0, ge=0)


class Negotiated(_Frozen):
    protocol: ProtocolVersion
    capabilities: tuple[str, ...]
    negotiation_id: Identity
    configuration_identity: bytes = Field(repr=False)


def _canonical_json(value: object, maximum: int, *, object_only: bool = False) -> bytes:
    if isinstance(value, (bytes, str)):
        decoded = json.loads(value)
    else:
        decoded = value
    if object_only and not isinstance(decoded, dict):
        raise ValueError("tool schema must be a JSON object")
    encoded = json.dumps(
        decoded, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    if len(encoded) > maximum:
        raise ValueError("JSON violates protocol bounds")
    return encoded


def _approval_resource(value: object) -> bytes:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate approval resource key")
            result[key] = item
        return result

    def integer(raw: str) -> int:
        if raw == "-0":
            raise ValueError("non-canonical approval integer")
        return int(raw)

    def reject_float(_: str) -> float:
        raise ValueError("approval resource numbers must be integers")

    if isinstance(value, bytes):
        if not value or len(value) > MAX_APPROVAL_RESOURCE_BYTES:
            raise ValueError("approval resource violates protocol bounds")
        decoded = json.loads(
            value,
            object_pairs_hook=unique,
            parse_int=integer,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    elif isinstance(value, str):
        decoded = json.loads(
            value,
            object_pairs_hook=unique,
            parse_int=integer,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    else:
        decoded = value

    def validate(item: object, depth: int) -> None:
        if depth > 32:
            raise ValueError("approval resource nesting exceeds its bound")
        if item is None or isinstance(item, (bool, str)):
            return
        if isinstance(item, int) and not isinstance(item, bool):
            if not -(1 << 63) <= item <= (1 << 64) - 1:
                raise ValueError("approval resource integer is out of range")
            return
        if isinstance(item, list):
            for child in item:
                validate(child, depth + 1)
            return
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            for child in item.values():
                validate(child, depth + 1)
            return
        raise ValueError("approval resource must contain canonical JSON values")

    if not isinstance(decoded, dict):
        raise TypeError("approval resource must be a JSON object")
    validate(decoded, 0)
    encoded = json.dumps(
        decoded, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    if not encoded or len(encoded) > MAX_APPROVAL_RESOURCE_BYTES:
        raise ValueError("approval resource violates protocol bounds")
    return encoded


def _validate_schema_shape(value: object, depth: int = 0) -> None:
    if depth > 32 or not isinstance(value, dict):
        raise ValueError("unsupported tool schema")
    allowed = {"type", "required", "properties", "items", "additionalProperties"}
    if not set(value).issubset(allowed):
        raise ValueError("unsupported tool schema keyword")
    if not value:
        return
    kind = value.get("type")
    if kind not in {"object", "array", "string", "integer", "number", "boolean", "null"}:
        raise ValueError("unsupported tool schema type")
    required = value.get("required", [])
    if not isinstance(required, list) or any(not isinstance(item, str) for item in required):
        raise ValueError("invalid tool schema required list")
    properties = value.get("properties", {})
    if not isinstance(properties, dict) or any(not isinstance(key, str) for key in properties):
        raise ValueError("invalid tool schema properties")
    for child in properties.values():
        _validate_schema_shape(child, depth + 1)
    if "items" in value:
        _validate_schema_shape(value["items"], depth + 1)
    additional = value.get("additionalProperties", True)
    if not isinstance(additional, bool):
        raise TypeError("invalid additionalProperties")


class ToolDefinition(_Frozen):
    name: str
    version: str
    input_schema: bytes
    output_schema: bytes
    required_authority: str
    timeout_millis: int = Field(gt=0, le=MAX_TOOL_TIMEOUT_MILLIS)
    cancellation: ToolCancellation
    effect_class: ToolEffectClass
    idempotency: ToolIdempotencyContract

    @model_validator(mode="before")
    @classmethod
    def canonicalize_schemas(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        result = dict(value)
        for field in ("input_schema", "output_schema"):
            encoded = _canonical_json(result.get(field), MAX_TOOL_SCHEMA_BYTES, object_only=True)
            _validate_schema_shape(json.loads(encoded))
            result[field] = encoded
        return result

    @model_validator(mode="after")
    def validate_contract(self) -> "ToolDefinition":
        import re

        if (
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", self.name)
            or len(self.name.encode()) > MAX_TOOL_NAME_BYTES
        ):
            raise ValueError("invalid stable tool name")
        if (
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", self.version)
            or len(self.version.encode()) > MAX_TOOL_VERSION_BYTES
        ):
            raise ValueError("invalid stable tool version")
        if (
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?", self.required_authority)
            or len(self.required_authority.encode()) > MAX_CAPABILITY_BYTES
        ):
            raise ValueError("invalid required authority")
        expected = {
            ToolEffectClass.READ_ONLY: ToolIdempotencyContract.NO_EXTERNAL_EFFECT,
            ToolEffectClass.IDEMPOTENT: ToolIdempotencyContract.INVOCATION_IDENTITY,
            ToolEffectClass.TRANSACTIONAL: ToolIdempotencyContract.EXTERNAL_TRANSACTION_PROOF,
            ToolEffectClass.NON_IDEMPOTENT: ToolIdempotencyContract.NEVER_REPLAY,
            ToolEffectClass.UNKNOWN: ToolIdempotencyContract.NEVER_REPLAY,
        }
        if expected[self.effect_class] != self.idempotency:
            raise ValueError("effect class and idempotency contract conflict")
        return self


class ArtifactRef(_Frozen):
    id: Identity
    session_id: Identity
    creator_participant_id: Identity
    creator_operation_id: Identity
    media_type: str
    size: int = Field(ge=0, le=MAX_ARTIFACT_BYTES)
    sha256: bytes = Field(min_length=32, max_length=32, repr=False)

    @field_validator("media_type")
    @classmethod
    def validate_media_type(cls, value: str) -> str:
        return _bounded_text(value, MAX_MEDIA_TYPE_BYTES)


class ArtifactSnapshot(ArtifactRef):
    status: ArtifactStatus
    retain_until: datetime
    created_at: datetime
    updated_at: datetime
    revision: int = Field(ge=1)


class ApprovalRequest(_Frozen):
    id: Identity
    session_id: Identity
    requester_participant_id: Identity
    operation_id: Identity
    capability: str
    resource: bytes = Field(repr=False)
    summary: str = Field(repr=False)
    status: ApprovalStatus
    expires_at: datetime
    grant_id: Optional[Identity] = None
    decision_source: Optional[ApprovalDecisionSource] = None
    created_at: datetime
    decided_at: Optional[datetime] = None
    revision: int = Field(ge=1)

    @field_validator("capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        return _bounded_text(value, MAX_CAPABILITY_BYTES)

    @field_validator("resource", mode="before")
    @classmethod
    def validate_resource(cls, value: object) -> bytes:
        return _approval_resource(value)

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        value = _bounded_text(value, MAX_APPROVAL_SUMMARY_BYTES)
        if not value.strip() or any(unicodedata.category(character) == "Cc" for character in value):
            raise ValueError("invalid approval summary")
        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "ApprovalRequest":
        pending = self.status in (ApprovalStatus.PENDING, ApprovalStatus.EXPIRED)
        denied = self.status is ApprovalStatus.DENIED
        decided = self.status in (
            ApprovalStatus.GRANTED,
            ApprovalStatus.CONSUMED,
            ApprovalStatus.REVOKED,
        )
        coherent = (
            pending
            and self.grant_id is None
            and self.decision_source is None
            and self.decided_at is None
            or denied
            and self.grant_id is None
            and self.decision_source is ApprovalDecisionSource.TRUSTED_CONSUMER
            and self.decided_at is not None
            or decided
            and self.grant_id is not None
            and self.decision_source is ApprovalDecisionSource.TRUSTED_CONSUMER
            and self.decided_at is not None
        )
        if (
            not coherent
            or self.created_at >= self.expires_at
            or self.decided_at is not None
            and not self.created_at <= self.decided_at < self.expires_at
        ):
            raise ValueError("invalid Approval request lifecycle")
        return self


class ApprovalGrant(_Frozen):
    id: Identity
    approval_id: Identity
    session_id: Identity
    subject_participant_id: Identity
    operation_id: Identity
    capability: str
    resource_hash: bytes = Field(min_length=32, max_length=32, repr=False)
    issued_by: ApprovalDecisionSource
    max_uses: int = Field(gt=0, le=MAX_APPROVAL_USES)
    used_count: int = Field(ge=0, le=MAX_APPROVAL_USES)
    expires_at: datetime
    revoked_at: Optional[datetime] = None
    created_at: datetime
    revision: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> "ApprovalGrant":
        if self.used_count > self.max_uses or self.created_at >= self.expires_at:
            raise ValueError("invalid approval Grant lifecycle")
        if self.revoked_at is not None and self.revoked_at < self.created_at:
            raise ValueError("invalid approval revocation timestamp")
        return self


class Approval(_Frozen):
    request: ApprovalRequest
    grant: Optional[ApprovalGrant] = None

    @model_validator(mode="after")
    def validate_binding(self) -> "Approval":
        if self.grant is None:
            if self.request.grant_id is not None:
                raise ValueError("Approval response omitted its bound Grant")
            return self
        grant = self.grant
        if (
            self.request.grant_id != grant.id
            or self.request.id != grant.approval_id
            or self.request.session_id != grant.session_id
            or self.request.requester_participant_id != grant.subject_participant_id
            or self.request.operation_id != grant.operation_id
            or self.request.capability != grant.capability
        ):
            raise ValueError("Approval and Grant bindings conflict")
        return self


class ToolRegistration(_Frozen):
    id: Identity
    session_id: Identity
    request_id: Identity
    definition: ToolDefinition
    revision: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime
    active: bool


class ToolInvocation(_Frozen):
    id: Identity
    dispatch_id: Identity
    registration_id: Identity
    session_id: Identity
    operation_id: Identity
    participant_id: Identity
    server_sequence: int = Field(gt=0)
    tool_name: str
    tool_version: str
    input: bytes = Field(max_length=MAX_TOOL_INLINE_BYTES, repr=False)
    deadline: datetime

    @field_validator("input", mode="before")
    @classmethod
    def validate_input_json(cls, value: object) -> bytes:
        return _canonical_json(value, MAX_TOOL_INLINE_BYTES)

    def input_json(self) -> object:
        return json.loads(self.input)


class ToolResult(_Frozen):
    output: bytes
    artifacts: tuple[ArtifactRef, ...] = ()

    @model_validator(mode="before")
    @classmethod
    def canonicalize_output(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        result = dict(value)
        result["output"] = _canonical_json(result.get("output"), MAX_TOOL_INLINE_BYTES)
        return result

    @field_validator("artifacts")
    @classmethod
    def validate_artifacts(cls, value: tuple[ArtifactRef, ...]) -> tuple[ArtifactRef, ...]:
        if len(value) > MAX_TOOL_ARTIFACT_REFS:
            raise ValueError("too many artifact references")
        return value


class ToolFailure(_Frozen):
    code: int = Field(gt=0)
    message: str
    retry: RetryClass

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        return _bounded_text(value, MAX_TOOL_FAILURE_MESSAGE_BYTES)


class CapabilityRequirement(_Frozen):
    capability: str
    minimum_version: int = Field(ge=1)
    parameters: Mapping[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_bounds(self) -> "CapabilityRequirement":
        _bounded_text(self.capability, MAX_CAPABILITY_BYTES)
        if len(self.parameters) > MAX_TEMPLATE_PARAMETERS:
            raise ValueError("too many capability parameters")
        for key, value in self.parameters.items():
            _bounded_text(key, MAX_TEMPLATE_NAME_BYTES)
            _bounded_text(value, MAX_TEMPLATE_PARAMETER_BYTES)
        return self


class ResourceBounds(_Frozen):
    memory_bytes: int = Field(gt=0)
    cpu_millis: int = Field(gt=0)
    max_concurrent_operations: int = Field(gt=0)


class InputField(_Frozen):
    name: str
    kind: InputKind
    required: bool = False
    max_string_bytes: Optional[int] = Field(default=None, gt=0)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _bounded_text(value, MAX_TEMPLATE_NAME_BYTES)


class AuthorityRule(_Frozen):
    capability: str
    resource: Literal["session", "participant", "operation", "artifact"]
    resource_id: Identity

    @field_validator("capability")
    @classmethod
    def validate_capability(cls, value: str) -> str:
        import re

        if not re.fullmatch(r"[a-z0-9._-]+", value):
            raise ValueError("invalid authority capability")
        return _bounded_text(value, MAX_CAPABILITY_BYTES)


class AuthorityProfile(_Frozen):
    active: tuple[AuthorityRule, ...] = ()
    delegable: tuple[AuthorityRule, ...] = ()

    @model_validator(mode="after")
    def validate_rules(self) -> "AuthorityProfile":
        if len(self.active) > MAX_AUTHORITY_RULES or len(self.delegable) > MAX_AUTHORITY_RULES:
            raise ValueError("too many authority rules")
        if len(set(self.active)) != len(self.active) or len(set(self.delegable)) != len(
            self.delegable
        ):
            raise ValueError("duplicate authority rule")
        if not set(self.delegable).issubset(self.active):
            raise ValueError("delegable authority must also be active")
        return self


class Template(_Frozen):
    id: Identity
    role: str
    driver_id: Identity
    required_capabilities: tuple[CapabilityRequirement, ...] = ()
    base_instructions: str
    secret_names: tuple[str, ...] = ()
    resources: ResourceBounds
    input_fields: tuple[InputField, ...] = ()
    authority: AuthorityProfile = AuthorityProfile()

    @model_validator(mode="after")
    def validate_bounds(self) -> "Template":
        _bounded_text(self.role, MAX_TEMPLATE_ROLE_BYTES)
        _bounded_text(self.base_instructions, MAX_TEMPLATE_INSTRUCTIONS_BYTES)
        if len(self.required_capabilities) > MAX_TEMPLATE_CAPABILITIES:
            raise ValueError("too many template capabilities")
        if len(self.secret_names) > MAX_TEMPLATE_SECRET_NAMES:
            raise ValueError("too many secret names")
        if len(self.input_fields) > MAX_TEMPLATE_INPUT_FIELDS:
            raise ValueError("too many input fields")
        for name in self.secret_names:
            _bounded_text(name, MAX_TEMPLATE_NAME_BYTES)
        return self


class Session(_Frozen):
    id: Identity
    root_id: Identity
    consumer_key: str
    status: SessionStatus
    revision: int = Field(ge=1)
    compatibility_identity: bytes = Field(repr=False)
    created_at: datetime
    updated_at: datetime


class Operation(_Frozen):
    id: Identity
    session_id: Identity
    participant_id: Identity
    request_id: Identity
    status: OperationStatus
    revision: int = Field(ge=1)
    result: Optional[bytes] = None
    terminal_failure: Optional["Failure"] = None
    created_at: datetime
    updated_at: datetime


class Participant(_Frozen):
    id: Identity
    session_id: Identity
    parent_id: Optional[Identity] = None
    depth: int = Field(ge=0)
    template_id: Identity
    template_compatibility: bytes = Field(repr=False)
    revision: int = Field(ge=1)


class Message(_Frozen):
    id: Identity
    session_id: Identity
    source_participant_id: Identity
    destination_participant_id: Identity
    mailbox_sequence: int = Field(ge=1)
    priority: MessagePriority
    operation_id: Optional[Identity] = None
    in_reply_to: Optional[Identity] = None
    envelope: bytes = Field(repr=False)
    attempt_count: int = Field(ge=0)
    delivery_status: MessageDeliveryStatus
    revision: int = Field(ge=1)
    created_at: datetime
    updated_at: datetime


class Event(_Frozen):
    id: Identity
    session_id: Identity
    position: EventPosition
    revision: int
    type: str
    schema_version: int
    data: bytes
    occurred_at: datetime
    related_request_id: Optional[Identity] = None
    unknown: Mapping[str, Any] = Field(default_factory=dict, repr=False)
    opaque_wire: bytes = Field(default=b"", repr=False)


class EventPage(_Frozen):
    """Bounded immutable page returned by read-only Event polling."""

    events: tuple[Event, ...]
    has_more: StrictBool


class UnknownEvent(Event):
    """An event not understood by this SDK, retained without losing wire data."""


class EmptyEventData(_Frozen):
    """The extensible object carried by lifecycle events with no v1 fields."""


class EmptyEvent(Event):
    """A known v1 event whose payload has no required fields."""

    type: Literal[
        "session.created",
        "session.closed",
        "ownership.acquired",
        "ownership.released",
        "artifact.published",
        "artifact.logically_deleted",
        "artifact.physically_erased",
    ]
    schema_version: Literal[1]
    payload: EmptyEventData


class ParticipantEventData(_Frozen):
    payload_schema: Literal[1] = Field(alias="schema")
    participant_id: Identity
    template_id: Identity
    parent_participant_id: Optional[Identity] = None
    depth: Optional[int] = Field(default=None, ge=1)

    @field_validator("participant_id", "template_id", "parent_participant_id", mode="before")
    @classmethod
    def parse_identity(cls, value: object) -> object:
        return _json_identity(value)


class ParticipantCreatedEvent(Event):
    type: Literal["participant.created"]
    schema_version: Literal[1]
    payload: ParticipantEventData


class OperationEventData(_Frozen):
    payload_schema: Literal[1] = Field(alias="schema")
    operation_id: Identity
    participant_id: Identity
    state: Literal[
        "queued",
        "starting",
        "running",
        "waiting",
        "cancelling",
        "succeeded",
        "failed",
        "cancelled",
        "blocked",
        "uncertain",
    ]
    input_message_id: Identity

    @field_validator("operation_id", "participant_id", "input_message_id", mode="before")
    @classmethod
    def parse_identity(cls, value: object) -> object:
        return _json_identity(value)


class OperationEvent(Event):
    type: Literal[
        "operation.queued",
        "operation.starting",
        "operation.running",
        "operation.waiting",
        "operation.resumed",
        "operation.cancelling",
        "operation.succeeded",
        "operation.failed",
        "operation.cancelled",
        "operation.blocked",
        "operation.uncertain",
    ]
    schema_version: Literal[1]
    payload: OperationEventData

    @model_validator(mode="after")
    def validate_type_matches_state(self) -> "OperationEvent":
        expected = (
            "running" if self.type == "operation.resumed" else self.type.removeprefix("operation.")
        )
        if self.payload.state != expected:
            raise ValueError("operation event type and payload state disagree")
        return self


class MessageEventData(_Frozen):
    message_id: Identity
    source: Identity
    destination: Identity
    mailbox_sequence: int = Field(ge=1)
    operation_id: Optional[Identity] = None
    in_reply_to: Optional[Identity] = None
    state: Literal[
        "queued",
        "retry_scheduled",
        "leased",
        "acceptance_pending",
        "acceptance_unknown",
        "accepted",
        "uncertain",
        "dead_lettered",
    ]

    @field_validator(
        "message_id", "source", "destination", "operation_id", "in_reply_to", mode="before"
    )
    @classmethod
    def parse_identity(cls, value: object) -> object:
        return _json_identity(value)


class MessageEvent(Event):
    type: Literal[
        "message.enqueued",
        "message.retry_scheduled",
        "message.leased",
        "message.acceptance_pending",
        "message.acceptance_unknown",
        "message.accepted",
        "message.uncertain",
        "message.dead_lettered",
    ]
    schema_version: Literal[1]
    payload: MessageEventData

    @model_validator(mode="after")
    def validate_type_matches_state(self) -> "MessageEvent":
        if self.payload.state != self.type.removeprefix("message."):
            raise ValueError("message event type and payload state disagree")
        return self


class AuthorityEventData(_Frozen):
    payload_schema: Literal[1] = Field(alias="schema")
    participant_id: Identity

    @field_validator("participant_id", mode="before")
    @classmethod
    def parse_identity(cls, value: object) -> object:
        return _json_identity(value)


class AuthorityEvent(Event):
    type: Literal[
        "authority.allowed",
        "authority.denied",
        "authority.policy_applied",
        "authority.grant_issued",
        "authority.grant_revoked",
    ]
    schema_version: Literal[1]
    payload: AuthorityEventData


class EffectResolutionEventData(_Frozen):
    effect_request_id: Identity
    operation_id: Identity
    participant_id: Identity
    resolution: Literal["confirm_completed", "do_not_retry", "retry_with_effect_proof"]
    reason: Literal["redacted"]

    @field_validator("effect_request_id", "operation_id", "participant_id", mode="before")
    @classmethod
    def parse_identity(cls, value: object) -> object:
        return _json_identity(value)


class EffectResolutionEvent(Event):
    type: Literal["effect.uncertainty_resolved"]
    schema_version: Literal[1]
    payload: EffectResolutionEventData


class RecoveryClassifiedEvent(Event):
    type: Literal["recovery.classified"]
    schema_version: Literal[1]
    payload: tuple[Mapping[str, Any], ...]


KnownEvent = Union[
    EmptyEvent,
    ParticipantCreatedEvent,
    OperationEvent,
    MessageEvent,
    AuthorityEvent,
    EffectResolutionEvent,
    RecoveryClassifiedEvent,
]
EventVariant = Union[KnownEvent, UnknownEvent]


_EMPTY_EVENT_TYPES = {
    "session.created",
    "session.closed",
    "ownership.acquired",
    "ownership.released",
    "artifact.published",
    "artifact.logically_deleted",
    "artifact.physically_erased",
}
_OPERATION_EVENT_TYPES = {
    "operation.queued",
    "operation.starting",
    "operation.running",
    "operation.waiting",
    "operation.resumed",
    "operation.cancelling",
    "operation.succeeded",
    "operation.failed",
    "operation.cancelled",
    "operation.blocked",
    "operation.uncertain",
}
_MESSAGE_EVENT_TYPES = {
    "message.enqueued",
    "message.retry_scheduled",
    "message.leased",
    "message.acceptance_pending",
    "message.acceptance_unknown",
    "message.accepted",
    "message.uncertain",
    "message.dead_lettered",
}


def parse_event(fields: Mapping[str, Any]) -> EventVariant:
    """Parse a wire envelope into a known event, or preserve it as unknown.

    A known name is not enough: unsupported schemas and invalid payloads remain
    observable as ``UnknownEvent`` instead of terminating an event stream.
    """

    envelope = dict(fields)
    event_type = envelope.get("type")
    schema_version = envelope.get("schema_version")
    event_class: type[Event] | None = None
    if schema_version == 1:
        if event_type in _EMPTY_EVENT_TYPES:
            event_class = EmptyEvent
        elif event_type == "participant.created":
            event_class = ParticipantCreatedEvent
        elif event_type in _OPERATION_EVENT_TYPES:
            event_class = OperationEvent
        elif event_type in _MESSAGE_EVENT_TYPES:
            event_class = MessageEvent
        elif event_type in {
            "authority.allowed",
            "authority.denied",
            "authority.policy_applied",
            "authority.grant_issued",
            "authority.grant_revoked",
        }:
            event_class = AuthorityEvent
        elif event_type == "effect.uncertainty_resolved":
            event_class = EffectResolutionEvent
        elif event_type == "recovery.classified":
            event_class = RecoveryClassifiedEvent
    if event_class is not None:
        try:
            payload = json.loads(envelope["data"])
            if event_class is RecoveryClassifiedEvent:
                if not isinstance(payload, list) or not all(
                    isinstance(item, dict) for item in payload
                ):
                    raise TypeError("recovery payload is not a list of objects")
            elif not isinstance(payload, dict):
                raise TypeError("event payload is not an object")
            return cast(EventVariant, event_class.model_validate({**envelope, "payload": payload}))
        except (KeyError, TypeError, ValueError):
            pass
    return UnknownEvent.model_validate(envelope)


class Failure(_Frozen):
    code: int
    message: str = Field(repr=False)
    retry: RetryClass
    related_id: Optional[Identity] = None


class CancellationOperation(_Frozen):
    operation: Operation
    notification_message_id: Optional[Identity]
    cleanup_confirmed: bool


class Cancellation(_Frozen):
    root_participant_id: Identity
    operations: tuple[CancellationOperation, ...]


class RecoveryClassification(_Frozen):
    entity_kind: str
    entity_id: Identity
    disposition: RecoveryDisposition
    allowed_actions: tuple[ResolutionAction, ...]
    reason: str
    action_status: RecoveryActionStatus


class RecoveryReport(_Frozen):
    session_id: Identity
    classifications: tuple[RecoveryClassification, ...]


class EffectProof(_Frozen):
    kind: EffectProofKind
    digest: bytes
    evidence: bytes = Field(default=b"", repr=False)

    @model_validator(mode="after")
    def validate_bounds(self) -> "EffectProof":
        if not self.digest or len(self.evidence) > MAX_EFFECT_PROOF_BYTES:
            raise ValueError("invalid effect proof bounds")
        return self


class ConfirmCompleted(_Frozen):
    action: Literal["confirm_completed"] = "confirm_completed"
    proof: EffectProof
    effect_id: Identity


class DoNotRetry(_Frozen):
    action: Literal["do_not_retry"] = "do_not_retry"


class RetryWithEffectProof(_Frozen):
    action: Literal["retry_with_effect_proof"] = "retry_with_effect_proof"
    proof: EffectProof
    effect_id: Identity


Resolution = Union[ConfirmCompleted, DoNotRetry, RetryWithEffectProof]


class ResolutionSnapshot(_Frozen):
    operation: Operation
    action: ResolutionAction
    authority_grant_id: Identity
    reason: str
    request_id: Identity
    session_id: Identity
    effect_id: Optional[Identity]
    revision: int = Field(ge=1)
    audit_event_position: EventPosition
    action_status: RecoveryActionStatus


def _bounded_text(value: str, maximum: int) -> str:
    size = len(value.encode("utf-8"))
    if size == 0 or size > maximum:
        raise ValueError("text violates protocol bounds")
    return value


def _json_identity(value: object) -> object:
    if value is None or isinstance(value, Identity):
        return value
    if not isinstance(value, str):
        raise TypeError("event identity must be a UUID string")
    try:
        return Identity(UUID(value).bytes)
    except (ValueError, AttributeError) as error:
        raise ValueError("event identity must be a non-zero UUID") from error


def timestamp(seconds: int, nanos: int) -> datetime:
    return datetime.fromtimestamp(seconds + nanos / 1_000_000_000, tz=timezone.utc)
