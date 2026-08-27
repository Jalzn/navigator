from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SessionOpenMode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SESSION_OPEN_MODE_UNSPECIFIED: _ClassVar[SessionOpenMode]
    SESSION_OPEN_MODE_OPEN: _ClassVar[SessionOpenMode]
    SESSION_OPEN_MODE_RESUME: _ClassVar[SessionOpenMode]
    SESSION_OPEN_MODE_RESET: _ClassVar[SessionOpenMode]

class InputKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INPUT_KIND_UNSPECIFIED: _ClassVar[InputKind]
    INPUT_KIND_STRING: _ClassVar[InputKind]
    INPUT_KIND_INTEGER: _ClassVar[InputKind]
    INPUT_KIND_BOOLEAN: _ClassVar[InputKind]

class ProjectionView(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PROJECTION_VIEW_UNSPECIFIED: _ClassVar[ProjectionView]
    PROJECTION_VIEW_SESSION_TREE: _ClassVar[ProjectionView]
    PROJECTION_VIEW_ACTIVE_WORK: _ClassVar[ProjectionView]
    PROJECTION_VIEW_DELIVERY: _ClassVar[ProjectionView]
    PROJECTION_VIEW_APPROVAL: _ClassVar[ProjectionView]
    PROJECTION_VIEW_RECOVERY: _ClassVar[ProjectionView]
    PROJECTION_VIEW_CAPACITY: _ClassVar[ProjectionView]
    PROJECTION_VIEW_FAILURE: _ClassVar[ProjectionView]

class RecoveryActionStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RECOVERY_ACTION_STATUS_UNSPECIFIED: _ClassVar[RecoveryActionStatus]
    RECOVERY_ACTION_STATUS_EXECUTED: _ClassVar[RecoveryActionStatus]
    RECOVERY_ACTION_STATUS_NO_OP: _ClassVar[RecoveryActionStatus]
    RECOVERY_ACTION_STATUS_PENDING: _ClassVar[RecoveryActionStatus]
    RECOVERY_ACTION_STATUS_BLOCKED_BY_UNCERTAINTY: _ClassVar[RecoveryActionStatus]
    RECOVERY_ACTION_STATUS_BLOCKED_BY_CLEANUP: _ClassVar[RecoveryActionStatus]

class RecoveryDisposition(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RECOVERY_DISPOSITION_UNSPECIFIED: _ClassVar[RecoveryDisposition]
    RECOVERY_DISPOSITION_SAFE_TO_CONTINUE: _ClassVar[RecoveryDisposition]
    RECOVERY_DISPOSITION_SAFE_TO_REDELIVER: _ClassVar[RecoveryDisposition]
    RECOVERY_DISPOSITION_EFFECT_UNCERTAIN: _ClassVar[RecoveryDisposition]
    RECOVERY_DISPOSITION_TERMINAL: _ClassVar[RecoveryDisposition]
    RECOVERY_DISPOSITION_EXTERNALLY_ALIVE: _ClassVar[RecoveryDisposition]
    RECOVERY_DISPOSITION_CLEANUP_REQUIRED: _ClassVar[RecoveryDisposition]

class ResolutionAction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RESOLUTION_ACTION_UNSPECIFIED: _ClassVar[ResolutionAction]
    RESOLUTION_ACTION_CONFIRM_COMPLETED: _ClassVar[ResolutionAction]
    RESOLUTION_ACTION_DO_NOT_RETRY: _ClassVar[ResolutionAction]
    RESOLUTION_ACTION_RETRY_WITH_EFFECT_PROOF: _ClassVar[ResolutionAction]

class EffectProofKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EFFECT_PROOF_KIND_UNSPECIFIED: _ClassVar[EffectProofKind]
    EFFECT_PROOF_KIND_EXTERNAL_COMMIT: _ClassVar[EffectProofKind]
    EFFECT_PROOF_KIND_IDEMPOTENCY_RECEIPT: _ClassVar[EffectProofKind]
    EFFECT_PROOF_KIND_EFFECT_ABSENT: _ClassVar[EffectProofKind]

class MessagePriority(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MESSAGE_PRIORITY_UNSPECIFIED: _ClassVar[MessagePriority]
    MESSAGE_PRIORITY_CONTROL: _ClassVar[MessagePriority]
    MESSAGE_PRIORITY_ORDINARY: _ClassVar[MessagePriority]

class MessageDeliveryStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MESSAGE_DELIVERY_STATUS_UNSPECIFIED: _ClassVar[MessageDeliveryStatus]
    MESSAGE_DELIVERY_STATUS_QUEUED: _ClassVar[MessageDeliveryStatus]
    MESSAGE_DELIVERY_STATUS_RETRY_SCHEDULED: _ClassVar[MessageDeliveryStatus]
    MESSAGE_DELIVERY_STATUS_LEASED: _ClassVar[MessageDeliveryStatus]
    MESSAGE_DELIVERY_STATUS_ACCEPTANCE_PENDING: _ClassVar[MessageDeliveryStatus]
    MESSAGE_DELIVERY_STATUS_ACCEPTANCE_UNKNOWN: _ClassVar[MessageDeliveryStatus]
    MESSAGE_DELIVERY_STATUS_ACCEPTED: _ClassVar[MessageDeliveryStatus]
    MESSAGE_DELIVERY_STATUS_UNCERTAIN: _ClassVar[MessageDeliveryStatus]
    MESSAGE_DELIVERY_STATUS_DEAD_LETTER: _ClassVar[MessageDeliveryStatus]

class OperationStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    OPERATION_STATUS_UNSPECIFIED: _ClassVar[OperationStatus]
    OPERATION_STATUS_QUEUED: _ClassVar[OperationStatus]
    OPERATION_STATUS_STARTING: _ClassVar[OperationStatus]
    OPERATION_STATUS_RUNNING: _ClassVar[OperationStatus]
    OPERATION_STATUS_WAITING: _ClassVar[OperationStatus]
    OPERATION_STATUS_BLOCKED: _ClassVar[OperationStatus]
    OPERATION_STATUS_CANCELLING: _ClassVar[OperationStatus]
    OPERATION_STATUS_SUCCEEDED: _ClassVar[OperationStatus]
    OPERATION_STATUS_FAILED: _ClassVar[OperationStatus]
    OPERATION_STATUS_CANCELLED: _ClassVar[OperationStatus]
    OPERATION_STATUS_UNCERTAIN: _ClassVar[OperationStatus]
    OPERATION_STATUS_DELIVERING: _ClassVar[OperationStatus]

class SessionStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SESSION_STATUS_UNSPECIFIED: _ClassVar[SessionStatus]
    SESSION_STATUS_OPEN: _ClassVar[SessionStatus]
    SESSION_STATUS_CLOSED: _ClassVar[SessionStatus]

class FailureCode(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    FAILURE_CODE_UNSPECIFIED: _ClassVar[FailureCode]
    FAILURE_CODE_INVALID_REQUEST: _ClassVar[FailureCode]
    FAILURE_CODE_UNSUPPORTED_VERSION: _ClassVar[FailureCode]
    FAILURE_CODE_UNSUPPORTED_CAPABILITY: _ClassVar[FailureCode]
    FAILURE_CODE_NOT_FOUND: _ClassVar[FailureCode]
    FAILURE_CODE_CONFLICT: _ClassVar[FailureCode]
    FAILURE_CODE_STALE_OWNERSHIP: _ClassVar[FailureCode]
    FAILURE_CODE_UNAVAILABLE: _ClassVar[FailureCode]
    FAILURE_CODE_INTERNAL: _ClassVar[FailureCode]
    FAILURE_CODE_AUTHENTICATION: _ClassVar[FailureCode]
    FAILURE_CODE_AUTHORIZATION: _ClassVar[FailureCode]
    FAILURE_CODE_CAPACITY: _ClassVar[FailureCode]
    FAILURE_CODE_TIMEOUT: _ClassVar[FailureCode]
    FAILURE_CODE_CANCELLED: _ClassVar[FailureCode]
    FAILURE_CODE_UNCERTAIN_EFFECT: _ClassVar[FailureCode]
    FAILURE_CODE_CLEANUP_REQUIRED: _ClassVar[FailureCode]
    FAILURE_CODE_CORRUPTED_STATE: _ClassVar[FailureCode]
    FAILURE_CODE_UNSUPPORTED: _ClassVar[FailureCode]
    FAILURE_CODE_INCOMPATIBLE: _ClassVar[FailureCode]

class RetryClass(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RETRY_CLASS_UNSPECIFIED: _ClassVar[RetryClass]
    RETRY_CLASS_NEVER: _ClassVar[RetryClass]
    RETRY_CLASS_SAFE: _ClassVar[RetryClass]
    RETRY_CLASS_AFTER_RECONCILIATION: _ClassVar[RetryClass]

class ToolCancellationBehavior(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TOOL_CANCELLATION_BEHAVIOR_UNSPECIFIED: _ClassVar[ToolCancellationBehavior]
    TOOL_CANCELLATION_BEHAVIOR_COOPERATIVE: _ClassVar[ToolCancellationBehavior]
    TOOL_CANCELLATION_BEHAVIOR_UNSUPPORTED: _ClassVar[ToolCancellationBehavior]

class ToolEffectClass(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TOOL_EFFECT_CLASS_UNSPECIFIED: _ClassVar[ToolEffectClass]
    TOOL_EFFECT_CLASS_READ_ONLY: _ClassVar[ToolEffectClass]
    TOOL_EFFECT_CLASS_IDEMPOTENT: _ClassVar[ToolEffectClass]
    TOOL_EFFECT_CLASS_TRANSACTIONAL: _ClassVar[ToolEffectClass]
    TOOL_EFFECT_CLASS_NON_IDEMPOTENT: _ClassVar[ToolEffectClass]
    TOOL_EFFECT_CLASS_UNKNOWN: _ClassVar[ToolEffectClass]

class ToolIdempotencyContract(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TOOL_IDEMPOTENCY_CONTRACT_UNSPECIFIED: _ClassVar[ToolIdempotencyContract]
    TOOL_IDEMPOTENCY_CONTRACT_NO_EXTERNAL_EFFECT: _ClassVar[ToolIdempotencyContract]
    TOOL_IDEMPOTENCY_CONTRACT_INVOCATION_IDENTITY: _ClassVar[ToolIdempotencyContract]
    TOOL_IDEMPOTENCY_CONTRACT_EXTERNAL_TRANSACTION_PROOF: _ClassVar[ToolIdempotencyContract]
    TOOL_IDEMPOTENCY_CONTRACT_NEVER_REPLAY: _ClassVar[ToolIdempotencyContract]

class ToolProviderAckKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TOOL_PROVIDER_ACK_KIND_UNSPECIFIED: _ClassVar[ToolProviderAckKind]
    TOOL_PROVIDER_ACK_KIND_STARTED: _ClassVar[ToolProviderAckKind]
    TOOL_PROVIDER_ACK_KIND_TERMINAL: _ClassVar[ToolProviderAckKind]

class ArtifactStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ARTIFACT_STATUS_UNSPECIFIED: _ClassVar[ArtifactStatus]
    ARTIFACT_STATUS_AVAILABLE: _ClassVar[ArtifactStatus]
    ARTIFACT_STATUS_LOGICALLY_DELETED: _ClassVar[ArtifactStatus]
    ARTIFACT_STATUS_ERASURE_ELIGIBLE: _ClassVar[ArtifactStatus]
    ARTIFACT_STATUS_ERASED: _ClassVar[ArtifactStatus]
    ARTIFACT_STATUS_CORRUPTED: _ClassVar[ArtifactStatus]

class ApprovalStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    APPROVAL_STATUS_UNSPECIFIED: _ClassVar[ApprovalStatus]
    APPROVAL_STATUS_PENDING: _ClassVar[ApprovalStatus]
    APPROVAL_STATUS_GRANTED: _ClassVar[ApprovalStatus]
    APPROVAL_STATUS_CONSUMED: _ClassVar[ApprovalStatus]
    APPROVAL_STATUS_DENIED: _ClassVar[ApprovalStatus]
    APPROVAL_STATUS_EXPIRED: _ClassVar[ApprovalStatus]
    APPROVAL_STATUS_REVOKED: _ClassVar[ApprovalStatus]

class ApprovalDecisionSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    APPROVAL_DECISION_SOURCE_UNSPECIFIED: _ClassVar[ApprovalDecisionSource]
    APPROVAL_DECISION_SOURCE_TRUSTED_CONSUMER: _ClassVar[ApprovalDecisionSource]
SESSION_OPEN_MODE_UNSPECIFIED: SessionOpenMode
SESSION_OPEN_MODE_OPEN: SessionOpenMode
SESSION_OPEN_MODE_RESUME: SessionOpenMode
SESSION_OPEN_MODE_RESET: SessionOpenMode
INPUT_KIND_UNSPECIFIED: InputKind
INPUT_KIND_STRING: InputKind
INPUT_KIND_INTEGER: InputKind
INPUT_KIND_BOOLEAN: InputKind
PROJECTION_VIEW_UNSPECIFIED: ProjectionView
PROJECTION_VIEW_SESSION_TREE: ProjectionView
PROJECTION_VIEW_ACTIVE_WORK: ProjectionView
PROJECTION_VIEW_DELIVERY: ProjectionView
PROJECTION_VIEW_APPROVAL: ProjectionView
PROJECTION_VIEW_RECOVERY: ProjectionView
PROJECTION_VIEW_CAPACITY: ProjectionView
PROJECTION_VIEW_FAILURE: ProjectionView
RECOVERY_ACTION_STATUS_UNSPECIFIED: RecoveryActionStatus
RECOVERY_ACTION_STATUS_EXECUTED: RecoveryActionStatus
RECOVERY_ACTION_STATUS_NO_OP: RecoveryActionStatus
RECOVERY_ACTION_STATUS_PENDING: RecoveryActionStatus
RECOVERY_ACTION_STATUS_BLOCKED_BY_UNCERTAINTY: RecoveryActionStatus
RECOVERY_ACTION_STATUS_BLOCKED_BY_CLEANUP: RecoveryActionStatus
RECOVERY_DISPOSITION_UNSPECIFIED: RecoveryDisposition
RECOVERY_DISPOSITION_SAFE_TO_CONTINUE: RecoveryDisposition
RECOVERY_DISPOSITION_SAFE_TO_REDELIVER: RecoveryDisposition
RECOVERY_DISPOSITION_EFFECT_UNCERTAIN: RecoveryDisposition
RECOVERY_DISPOSITION_TERMINAL: RecoveryDisposition
RECOVERY_DISPOSITION_EXTERNALLY_ALIVE: RecoveryDisposition
RECOVERY_DISPOSITION_CLEANUP_REQUIRED: RecoveryDisposition
RESOLUTION_ACTION_UNSPECIFIED: ResolutionAction
RESOLUTION_ACTION_CONFIRM_COMPLETED: ResolutionAction
RESOLUTION_ACTION_DO_NOT_RETRY: ResolutionAction
RESOLUTION_ACTION_RETRY_WITH_EFFECT_PROOF: ResolutionAction
EFFECT_PROOF_KIND_UNSPECIFIED: EffectProofKind
EFFECT_PROOF_KIND_EXTERNAL_COMMIT: EffectProofKind
EFFECT_PROOF_KIND_IDEMPOTENCY_RECEIPT: EffectProofKind
EFFECT_PROOF_KIND_EFFECT_ABSENT: EffectProofKind
MESSAGE_PRIORITY_UNSPECIFIED: MessagePriority
MESSAGE_PRIORITY_CONTROL: MessagePriority
MESSAGE_PRIORITY_ORDINARY: MessagePriority
MESSAGE_DELIVERY_STATUS_UNSPECIFIED: MessageDeliveryStatus
MESSAGE_DELIVERY_STATUS_QUEUED: MessageDeliveryStatus
MESSAGE_DELIVERY_STATUS_RETRY_SCHEDULED: MessageDeliveryStatus
MESSAGE_DELIVERY_STATUS_LEASED: MessageDeliveryStatus
MESSAGE_DELIVERY_STATUS_ACCEPTANCE_PENDING: MessageDeliveryStatus
MESSAGE_DELIVERY_STATUS_ACCEPTANCE_UNKNOWN: MessageDeliveryStatus
MESSAGE_DELIVERY_STATUS_ACCEPTED: MessageDeliveryStatus
MESSAGE_DELIVERY_STATUS_UNCERTAIN: MessageDeliveryStatus
MESSAGE_DELIVERY_STATUS_DEAD_LETTER: MessageDeliveryStatus
OPERATION_STATUS_UNSPECIFIED: OperationStatus
OPERATION_STATUS_QUEUED: OperationStatus
OPERATION_STATUS_STARTING: OperationStatus
OPERATION_STATUS_RUNNING: OperationStatus
OPERATION_STATUS_WAITING: OperationStatus
OPERATION_STATUS_BLOCKED: OperationStatus
OPERATION_STATUS_CANCELLING: OperationStatus
OPERATION_STATUS_SUCCEEDED: OperationStatus
OPERATION_STATUS_FAILED: OperationStatus
OPERATION_STATUS_CANCELLED: OperationStatus
OPERATION_STATUS_UNCERTAIN: OperationStatus
OPERATION_STATUS_DELIVERING: OperationStatus
SESSION_STATUS_UNSPECIFIED: SessionStatus
SESSION_STATUS_OPEN: SessionStatus
SESSION_STATUS_CLOSED: SessionStatus
FAILURE_CODE_UNSPECIFIED: FailureCode
FAILURE_CODE_INVALID_REQUEST: FailureCode
FAILURE_CODE_UNSUPPORTED_VERSION: FailureCode
FAILURE_CODE_UNSUPPORTED_CAPABILITY: FailureCode
FAILURE_CODE_NOT_FOUND: FailureCode
FAILURE_CODE_CONFLICT: FailureCode
FAILURE_CODE_STALE_OWNERSHIP: FailureCode
FAILURE_CODE_UNAVAILABLE: FailureCode
FAILURE_CODE_INTERNAL: FailureCode
FAILURE_CODE_AUTHENTICATION: FailureCode
FAILURE_CODE_AUTHORIZATION: FailureCode
FAILURE_CODE_CAPACITY: FailureCode
FAILURE_CODE_TIMEOUT: FailureCode
FAILURE_CODE_CANCELLED: FailureCode
FAILURE_CODE_UNCERTAIN_EFFECT: FailureCode
FAILURE_CODE_CLEANUP_REQUIRED: FailureCode
FAILURE_CODE_CORRUPTED_STATE: FailureCode
FAILURE_CODE_UNSUPPORTED: FailureCode
FAILURE_CODE_INCOMPATIBLE: FailureCode
RETRY_CLASS_UNSPECIFIED: RetryClass
RETRY_CLASS_NEVER: RetryClass
RETRY_CLASS_SAFE: RetryClass
RETRY_CLASS_AFTER_RECONCILIATION: RetryClass
TOOL_CANCELLATION_BEHAVIOR_UNSPECIFIED: ToolCancellationBehavior
TOOL_CANCELLATION_BEHAVIOR_COOPERATIVE: ToolCancellationBehavior
TOOL_CANCELLATION_BEHAVIOR_UNSUPPORTED: ToolCancellationBehavior
TOOL_EFFECT_CLASS_UNSPECIFIED: ToolEffectClass
TOOL_EFFECT_CLASS_READ_ONLY: ToolEffectClass
TOOL_EFFECT_CLASS_IDEMPOTENT: ToolEffectClass
TOOL_EFFECT_CLASS_TRANSACTIONAL: ToolEffectClass
TOOL_EFFECT_CLASS_NON_IDEMPOTENT: ToolEffectClass
TOOL_EFFECT_CLASS_UNKNOWN: ToolEffectClass
TOOL_IDEMPOTENCY_CONTRACT_UNSPECIFIED: ToolIdempotencyContract
TOOL_IDEMPOTENCY_CONTRACT_NO_EXTERNAL_EFFECT: ToolIdempotencyContract
TOOL_IDEMPOTENCY_CONTRACT_INVOCATION_IDENTITY: ToolIdempotencyContract
TOOL_IDEMPOTENCY_CONTRACT_EXTERNAL_TRANSACTION_PROOF: ToolIdempotencyContract
TOOL_IDEMPOTENCY_CONTRACT_NEVER_REPLAY: ToolIdempotencyContract
TOOL_PROVIDER_ACK_KIND_UNSPECIFIED: ToolProviderAckKind
TOOL_PROVIDER_ACK_KIND_STARTED: ToolProviderAckKind
TOOL_PROVIDER_ACK_KIND_TERMINAL: ToolProviderAckKind
ARTIFACT_STATUS_UNSPECIFIED: ArtifactStatus
ARTIFACT_STATUS_AVAILABLE: ArtifactStatus
ARTIFACT_STATUS_LOGICALLY_DELETED: ArtifactStatus
ARTIFACT_STATUS_ERASURE_ELIGIBLE: ArtifactStatus
ARTIFACT_STATUS_ERASED: ArtifactStatus
ARTIFACT_STATUS_CORRUPTED: ArtifactStatus
APPROVAL_STATUS_UNSPECIFIED: ApprovalStatus
APPROVAL_STATUS_PENDING: ApprovalStatus
APPROVAL_STATUS_GRANTED: ApprovalStatus
APPROVAL_STATUS_CONSUMED: ApprovalStatus
APPROVAL_STATUS_DENIED: ApprovalStatus
APPROVAL_STATUS_EXPIRED: ApprovalStatus
APPROVAL_STATUS_REVOKED: ApprovalStatus
APPROVAL_DECISION_SOURCE_UNSPECIFIED: ApprovalDecisionSource
APPROVAL_DECISION_SOURCE_TRUSTED_CONSUMER: ApprovalDecisionSource

class ProtocolVersion(_message.Message):
    __slots__ = ("major", "minor")
    MAJOR_FIELD_NUMBER: _ClassVar[int]
    MINOR_FIELD_NUMBER: _ClassVar[int]
    major: int
    minor: int
    def __init__(self, major: _Optional[int] = ..., minor: _Optional[int] = ...) -> None: ...

class RequestMetadata(_message.Message):
    __slots__ = ("protocol_version", "capabilities", "negotiation_id")
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    NEGOTIATION_ID_FIELD_NUMBER: _ClassVar[int]
    protocol_version: ProtocolVersion
    capabilities: _containers.RepeatedScalarFieldContainer[str]
    negotiation_id: bytes
    def __init__(self, protocol_version: _Optional[_Union[ProtocolVersion, _Mapping]] = ..., capabilities: _Optional[_Iterable[str]] = ..., negotiation_id: _Optional[bytes] = ...) -> None: ...

class NegotiateRequest(_message.Message):
    __slots__ = ("minimum_version", "maximum_version", "capabilities")
    MINIMUM_VERSION_FIELD_NUMBER: _ClassVar[int]
    MAXIMUM_VERSION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    minimum_version: ProtocolVersion
    maximum_version: ProtocolVersion
    capabilities: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, minimum_version: _Optional[_Union[ProtocolVersion, _Mapping]] = ..., maximum_version: _Optional[_Union[ProtocolVersion, _Mapping]] = ..., capabilities: _Optional[_Iterable[str]] = ...) -> None: ...

class NegotiateResponse(_message.Message):
    __slots__ = ("negotiated", "failure")
    NEGOTIATED_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    negotiated: Negotiated
    failure: Failure
    def __init__(self, negotiated: _Optional[_Union[Negotiated, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class Negotiated(_message.Message):
    __slots__ = ("protocol_version", "capabilities", "negotiation_id", "configuration_identity")
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    NEGOTIATION_ID_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    protocol_version: ProtocolVersion
    capabilities: _containers.RepeatedScalarFieldContainer[str]
    negotiation_id: bytes
    configuration_identity: bytes
    def __init__(self, protocol_version: _Optional[_Union[ProtocolVersion, _Mapping]] = ..., capabilities: _Optional[_Iterable[str]] = ..., negotiation_id: _Optional[bytes] = ..., configuration_identity: _Optional[bytes] = ...) -> None: ...

class OpenSessionRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id", "consumer_key", "compatibility_identity", "root_template", "compatible_templates", "configuration_identity", "mode")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    CONSUMER_KEY_FIELD_NUMBER: _ClassVar[int]
    COMPATIBILITY_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    ROOT_TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    COMPATIBLE_TEMPLATES_FIELD_NUMBER: _ClassVar[int]
    CONFIGURATION_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    MODE_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    consumer_key: str
    compatibility_identity: bytes
    root_template: RootTemplateSpecification
    compatible_templates: _containers.RepeatedCompositeFieldContainer[RootTemplateSpecification]
    configuration_identity: bytes
    mode: SessionOpenMode
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., consumer_key: _Optional[str] = ..., compatibility_identity: _Optional[bytes] = ..., root_template: _Optional[_Union[RootTemplateSpecification, _Mapping]] = ..., compatible_templates: _Optional[_Iterable[_Union[RootTemplateSpecification, _Mapping]]] = ..., configuration_identity: _Optional[bytes] = ..., mode: _Optional[_Union[SessionOpenMode, str]] = ...) -> None: ...

class RootTemplateSpecification(_message.Message):
    __slots__ = ("template_id", "role", "driver_id", "required_capabilities", "trusted_configuration", "resources", "input_schema", "authority_profile")
    TEMPLATE_ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    DRIVER_ID_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    TRUSTED_CONFIGURATION_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    INPUT_SCHEMA_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_PROFILE_FIELD_NUMBER: _ClassVar[int]
    template_id: bytes
    role: str
    driver_id: bytes
    required_capabilities: _containers.RepeatedCompositeFieldContainer[DriverCapabilityRequirement]
    trusted_configuration: TrustedTemplateConfiguration
    resources: ParticipantResourceBounds
    input_schema: InputSchema
    authority_profile: AuthorityProfileSpecification
    def __init__(self, template_id: _Optional[bytes] = ..., role: _Optional[str] = ..., driver_id: _Optional[bytes] = ..., required_capabilities: _Optional[_Iterable[_Union[DriverCapabilityRequirement, _Mapping]]] = ..., trusted_configuration: _Optional[_Union[TrustedTemplateConfiguration, _Mapping]] = ..., resources: _Optional[_Union[ParticipantResourceBounds, _Mapping]] = ..., input_schema: _Optional[_Union[InputSchema, _Mapping]] = ..., authority_profile: _Optional[_Union[AuthorityProfileSpecification, _Mapping]] = ...) -> None: ...

class AuthorityProfileSpecification(_message.Message):
    __slots__ = ("active", "delegable")
    ACTIVE_FIELD_NUMBER: _ClassVar[int]
    DELEGABLE_FIELD_NUMBER: _ClassVar[int]
    active: _containers.RepeatedCompositeFieldContainer[ScopedCapabilitySpecification]
    delegable: _containers.RepeatedCompositeFieldContainer[ScopedCapabilitySpecification]
    def __init__(self, active: _Optional[_Iterable[_Union[ScopedCapabilitySpecification, _Mapping]]] = ..., delegable: _Optional[_Iterable[_Union[ScopedCapabilitySpecification, _Mapping]]] = ...) -> None: ...

class ScopedCapabilitySpecification(_message.Message):
    __slots__ = ("capability", "session_id", "participant_id", "operation_id", "artifact_id")
    CAPABILITY_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    capability: str
    session_id: bytes
    participant_id: bytes
    operation_id: bytes
    artifact_id: bytes
    def __init__(self, capability: _Optional[str] = ..., session_id: _Optional[bytes] = ..., participant_id: _Optional[bytes] = ..., operation_id: _Optional[bytes] = ..., artifact_id: _Optional[bytes] = ...) -> None: ...

class DriverCapabilityRequirement(_message.Message):
    __slots__ = ("capability", "minimum_version", "parameters")
    CAPABILITY_FIELD_NUMBER: _ClassVar[int]
    MINIMUM_VERSION_FIELD_NUMBER: _ClassVar[int]
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    capability: str
    minimum_version: int
    parameters: _containers.RepeatedCompositeFieldContainer[CapabilityParameter]
    def __init__(self, capability: _Optional[str] = ..., minimum_version: _Optional[int] = ..., parameters: _Optional[_Iterable[_Union[CapabilityParameter, _Mapping]]] = ...) -> None: ...

class CapabilityParameter(_message.Message):
    __slots__ = ("key", "value")
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    value: str
    def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...

class TrustedTemplateConfiguration(_message.Message):
    __slots__ = ("base_instructions", "secret_names")
    BASE_INSTRUCTIONS_FIELD_NUMBER: _ClassVar[int]
    SECRET_NAMES_FIELD_NUMBER: _ClassVar[int]
    base_instructions: str
    secret_names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, base_instructions: _Optional[str] = ..., secret_names: _Optional[_Iterable[str]] = ...) -> None: ...

class ParticipantResourceBounds(_message.Message):
    __slots__ = ("memory_bytes", "cpu_millis", "max_concurrent_operations")
    MEMORY_BYTES_FIELD_NUMBER: _ClassVar[int]
    CPU_MILLIS_FIELD_NUMBER: _ClassVar[int]
    MAX_CONCURRENT_OPERATIONS_FIELD_NUMBER: _ClassVar[int]
    memory_bytes: int
    cpu_millis: int
    max_concurrent_operations: int
    def __init__(self, memory_bytes: _Optional[int] = ..., cpu_millis: _Optional[int] = ..., max_concurrent_operations: _Optional[int] = ...) -> None: ...

class InputSchema(_message.Message):
    __slots__ = ("fields",)
    FIELDS_FIELD_NUMBER: _ClassVar[int]
    fields: _containers.RepeatedCompositeFieldContainer[InputField]
    def __init__(self, fields: _Optional[_Iterable[_Union[InputField, _Mapping]]] = ...) -> None: ...

class InputField(_message.Message):
    __slots__ = ("name", "kind", "required", "max_string_bytes")
    NAME_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    MAX_STRING_BYTES_FIELD_NUMBER: _ClassVar[int]
    name: str
    kind: InputKind
    required: bool
    max_string_bytes: int
    def __init__(self, name: _Optional[str] = ..., kind: _Optional[_Union[InputKind, str]] = ..., required: bool = ..., max_string_bytes: _Optional[int] = ...) -> None: ...

class OpenSessionResponse(_message.Message):
    __slots__ = ("snapshot", "failure")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    snapshot: SessionSnapshot
    failure: Failure
    def __init__(self, snapshot: _Optional[_Union[SessionSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class SnapshotRequest(_message.Message):
    __slots__ = ("metadata", "session_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ...) -> None: ...

class SnapshotResponse(_message.Message):
    __slots__ = ("snapshot", "failure")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    snapshot: SessionSnapshot
    failure: Failure
    def __init__(self, snapshot: _Optional[_Union[SessionSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class CloseSessionRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ...) -> None: ...

class CloseSessionResponse(_message.Message):
    __slots__ = ("snapshot", "failure")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    snapshot: SessionSnapshot
    failure: Failure
    def __init__(self, snapshot: _Optional[_Union[SessionSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class SubscribeEventsRequest(_message.Message):
    __slots__ = ("metadata", "session_id", "after_position")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    AFTER_POSITION_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    after_position: int
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ..., after_position: _Optional[int] = ...) -> None: ...

class SubscribeEventsResponse(_message.Message):
    __slots__ = ("event", "failure")
    EVENT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    event: SessionEvent
    failure: Failure
    def __init__(self, event: _Optional[_Union[SessionEvent, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ReadEventsRequest(_message.Message):
    __slots__ = ("metadata", "session_id", "after_position", "page_size")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    AFTER_POSITION_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    after_position: int
    page_size: int
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ..., after_position: _Optional[int] = ..., page_size: _Optional[int] = ...) -> None: ...

class EventPage(_message.Message):
    __slots__ = ("events", "has_more")
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    HAS_MORE_FIELD_NUMBER: _ClassVar[int]
    events: _containers.RepeatedCompositeFieldContainer[SessionEvent]
    has_more: bool
    def __init__(self, events: _Optional[_Iterable[_Union[SessionEvent, _Mapping]]] = ..., has_more: bool = ...) -> None: ...

class ReadEventsResponse(_message.Message):
    __slots__ = ("page", "failure")
    PAGE_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    page: EventPage
    failure: Failure
    def __init__(self, page: _Optional[_Union[EventPage, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ReadProjectionRequest(_message.Message):
    __slots__ = ("metadata", "session_id", "view", "page_size", "page_token", "consumer_key")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    VIEW_FIELD_NUMBER: _ClassVar[int]
    PAGE_SIZE_FIELD_NUMBER: _ClassVar[int]
    PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    CONSUMER_KEY_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    view: ProjectionView
    page_size: int
    page_token: str
    consumer_key: str
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ..., view: _Optional[_Union[ProjectionView, str]] = ..., page_size: _Optional[int] = ..., page_token: _Optional[str] = ..., consumer_key: _Optional[str] = ...) -> None: ...

class ProjectionItem(_message.Message):
    __slots__ = ("key", "redacted_json")
    KEY_FIELD_NUMBER: _ClassVar[int]
    REDACTED_JSON_FIELD_NUMBER: _ClassVar[int]
    key: str
    redacted_json: bytes
    def __init__(self, key: _Optional[str] = ..., redacted_json: _Optional[bytes] = ...) -> None: ...

class ProjectionPage(_message.Message):
    __slots__ = ("session_id", "view", "generation", "checkpoint_position", "source_head_position", "items", "next_page_token")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    VIEW_FIELD_NUMBER: _ClassVar[int]
    GENERATION_FIELD_NUMBER: _ClassVar[int]
    CHECKPOINT_POSITION_FIELD_NUMBER: _ClassVar[int]
    SOURCE_HEAD_POSITION_FIELD_NUMBER: _ClassVar[int]
    ITEMS_FIELD_NUMBER: _ClassVar[int]
    NEXT_PAGE_TOKEN_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    view: ProjectionView
    generation: int
    checkpoint_position: int
    source_head_position: int
    items: _containers.RepeatedCompositeFieldContainer[ProjectionItem]
    next_page_token: str
    def __init__(self, session_id: _Optional[bytes] = ..., view: _Optional[_Union[ProjectionView, str]] = ..., generation: _Optional[int] = ..., checkpoint_position: _Optional[int] = ..., source_head_position: _Optional[int] = ..., items: _Optional[_Iterable[_Union[ProjectionItem, _Mapping]]] = ..., next_page_token: _Optional[str] = ...) -> None: ...

class ReadProjectionResponse(_message.Message):
    __slots__ = ("page", "failure")
    PAGE_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    page: ProjectionPage
    failure: Failure
    def __init__(self, page: _Optional[_Union[ProjectionPage, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class StartOperationRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id", "participant_id", "input")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    INPUT_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    participant_id: bytes
    input: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., participant_id: _Optional[bytes] = ..., input: _Optional[bytes] = ...) -> None: ...

class StartOperationResponse(_message.Message):
    __slots__ = ("snapshot", "failure")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    snapshot: OperationSnapshot
    failure: Failure
    def __init__(self, snapshot: _Optional[_Union[OperationSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class OperationSnapshotRequest(_message.Message):
    __slots__ = ("metadata", "session_id", "operation_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    operation_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ..., operation_id: _Optional[bytes] = ...) -> None: ...

class OperationSnapshotResponse(_message.Message):
    __slots__ = ("snapshot", "failure")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    snapshot: OperationSnapshot
    failure: Failure
    def __init__(self, snapshot: _Optional[_Union[OperationSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ParticipantSnapshotRequest(_message.Message):
    __slots__ = ("metadata", "session_id", "participant_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    participant_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ..., participant_id: _Optional[bytes] = ...) -> None: ...

class ParticipantSnapshotResponse(_message.Message):
    __slots__ = ("snapshot", "failure")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    snapshot: ParticipantSnapshot
    failure: Failure
    def __init__(self, snapshot: _Optional[_Union[ParticipantSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class MessageSnapshotRequest(_message.Message):
    __slots__ = ("metadata", "session_id", "message_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    message_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ..., message_id: _Optional[bytes] = ...) -> None: ...

class MessageSnapshotResponse(_message.Message):
    __slots__ = ("snapshot", "failure")
    SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    snapshot: MessageSnapshot
    failure: Failure
    def __init__(self, snapshot: _Optional[_Union[MessageSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class CancelSubtreeRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id", "root_participant_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ROOT_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    root_participant_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., root_participant_id: _Optional[bytes] = ...) -> None: ...

class CancelSubtreeResponse(_message.Message):
    __slots__ = ("cancellation", "failure")
    CANCELLATION_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    cancellation: CancellationSnapshot
    failure: Failure
    def __init__(self, cancellation: _Optional[_Union[CancellationSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ResumeSessionRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ...) -> None: ...

class ResumeSessionResponse(_message.Message):
    __slots__ = ("report", "failure")
    REPORT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    report: RecoveryReport
    failure: Failure
    def __init__(self, report: _Optional[_Union[RecoveryReport, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class RecoveryReport(_message.Message):
    __slots__ = ("session_id", "classifications")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    CLASSIFICATIONS_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    classifications: _containers.RepeatedCompositeFieldContainer[RecoveryClassification]
    def __init__(self, session_id: _Optional[bytes] = ..., classifications: _Optional[_Iterable[_Union[RecoveryClassification, _Mapping]]] = ...) -> None: ...

class RecoveryClassification(_message.Message):
    __slots__ = ("session_id", "participant_id", "launch_attempt_id", "operation_id", "message_id", "effect_id", "disposition", "allowed_actions", "reason", "action_status")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    LAUNCH_ATTEMPT_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    EFFECT_ID_FIELD_NUMBER: _ClassVar[int]
    DISPOSITION_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_ACTIONS_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    ACTION_STATUS_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    participant_id: bytes
    launch_attempt_id: bytes
    operation_id: bytes
    message_id: bytes
    effect_id: bytes
    disposition: RecoveryDisposition
    allowed_actions: _containers.RepeatedScalarFieldContainer[ResolutionAction]
    reason: str
    action_status: RecoveryActionStatus
    def __init__(self, session_id: _Optional[bytes] = ..., participant_id: _Optional[bytes] = ..., launch_attempt_id: _Optional[bytes] = ..., operation_id: _Optional[bytes] = ..., message_id: _Optional[bytes] = ..., effect_id: _Optional[bytes] = ..., disposition: _Optional[_Union[RecoveryDisposition, str]] = ..., allowed_actions: _Optional[_Iterable[_Union[ResolutionAction, str]]] = ..., reason: _Optional[str] = ..., action_status: _Optional[_Union[RecoveryActionStatus, str]] = ...) -> None: ...

class ResolveUncertaintyRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id", "operation_id", "authority_grant_id", "reason", "confirm_completed", "do_not_retry", "retry_with_effect_proof", "effect_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_GRANT_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    CONFIRM_COMPLETED_FIELD_NUMBER: _ClassVar[int]
    DO_NOT_RETRY_FIELD_NUMBER: _ClassVar[int]
    RETRY_WITH_EFFECT_PROOF_FIELD_NUMBER: _ClassVar[int]
    EFFECT_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    operation_id: bytes
    authority_grant_id: bytes
    reason: str
    confirm_completed: EffectProof
    do_not_retry: DoNotRetry
    retry_with_effect_proof: EffectProof
    effect_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., operation_id: _Optional[bytes] = ..., authority_grant_id: _Optional[bytes] = ..., reason: _Optional[str] = ..., confirm_completed: _Optional[_Union[EffectProof, _Mapping]] = ..., do_not_retry: _Optional[_Union[DoNotRetry, _Mapping]] = ..., retry_with_effect_proof: _Optional[_Union[EffectProof, _Mapping]] = ..., effect_id: _Optional[bytes] = ...) -> None: ...

class DoNotRetry(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EffectProof(_message.Message):
    __slots__ = ("kind", "digest", "evidence")
    KIND_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    kind: EffectProofKind
    digest: bytes
    evidence: bytes
    def __init__(self, kind: _Optional[_Union[EffectProofKind, str]] = ..., digest: _Optional[bytes] = ..., evidence: _Optional[bytes] = ...) -> None: ...

class ResolveUncertaintyResponse(_message.Message):
    __slots__ = ("resolution", "failure")
    RESOLUTION_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    resolution: ResolutionSnapshot
    failure: Failure
    def __init__(self, resolution: _Optional[_Union[ResolutionSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ResolutionSnapshot(_message.Message):
    __slots__ = ("operation", "action", "authority_grant_id", "reason", "request_id", "session_id", "effect_id", "revision", "audit_event_position", "action_status")
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_GRANT_ID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    EFFECT_ID_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    AUDIT_EVENT_POSITION_FIELD_NUMBER: _ClassVar[int]
    ACTION_STATUS_FIELD_NUMBER: _ClassVar[int]
    operation: OperationSnapshot
    action: ResolutionAction
    authority_grant_id: bytes
    reason: str
    request_id: bytes
    session_id: bytes
    effect_id: bytes
    revision: int
    audit_event_position: int
    action_status: RecoveryActionStatus
    def __init__(self, operation: _Optional[_Union[OperationSnapshot, _Mapping]] = ..., action: _Optional[_Union[ResolutionAction, str]] = ..., authority_grant_id: _Optional[bytes] = ..., reason: _Optional[str] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., effect_id: _Optional[bytes] = ..., revision: _Optional[int] = ..., audit_event_position: _Optional[int] = ..., action_status: _Optional[_Union[RecoveryActionStatus, str]] = ...) -> None: ...

class CancellationSnapshot(_message.Message):
    __slots__ = ("root_participant_id", "operations")
    ROOT_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATIONS_FIELD_NUMBER: _ClassVar[int]
    root_participant_id: bytes
    operations: _containers.RepeatedCompositeFieldContainer[CancellationOperation]
    def __init__(self, root_participant_id: _Optional[bytes] = ..., operations: _Optional[_Iterable[_Union[CancellationOperation, _Mapping]]] = ...) -> None: ...

class CancellationOperation(_message.Message):
    __slots__ = ("operation", "notification_message_id", "driver_acknowledged")
    OPERATION_FIELD_NUMBER: _ClassVar[int]
    NOTIFICATION_MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    DRIVER_ACKNOWLEDGED_FIELD_NUMBER: _ClassVar[int]
    operation: OperationSnapshot
    notification_message_id: bytes
    driver_acknowledged: bool
    def __init__(self, operation: _Optional[_Union[OperationSnapshot, _Mapping]] = ..., notification_message_id: _Optional[bytes] = ..., driver_acknowledged: bool = ...) -> None: ...

class OperationSnapshot(_message.Message):
    __slots__ = ("operation_id", "session_id", "participant_id", "request_id", "status", "result", "terminal_failure", "revision", "created_at", "updated_at")
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    TERMINAL_FAILURE_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    operation_id: bytes
    session_id: bytes
    participant_id: bytes
    request_id: bytes
    status: OperationStatus
    result: bytes
    terminal_failure: Failure
    revision: int
    created_at: Timestamp
    updated_at: Timestamp
    def __init__(self, operation_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., participant_id: _Optional[bytes] = ..., request_id: _Optional[bytes] = ..., status: _Optional[_Union[OperationStatus, str]] = ..., result: _Optional[bytes] = ..., terminal_failure: _Optional[_Union[Failure, _Mapping]] = ..., revision: _Optional[int] = ..., created_at: _Optional[_Union[Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[Timestamp, _Mapping]] = ...) -> None: ...

class ParticipantSnapshot(_message.Message):
    __slots__ = ("session_id", "participant_id", "parent_participant_id", "depth", "template_id", "template_compatibility", "revision")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    PARENT_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    DEPTH_FIELD_NUMBER: _ClassVar[int]
    TEMPLATE_ID_FIELD_NUMBER: _ClassVar[int]
    TEMPLATE_COMPATIBILITY_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    participant_id: bytes
    parent_participant_id: bytes
    depth: int
    template_id: bytes
    template_compatibility: bytes
    revision: int
    def __init__(self, session_id: _Optional[bytes] = ..., participant_id: _Optional[bytes] = ..., parent_participant_id: _Optional[bytes] = ..., depth: _Optional[int] = ..., template_id: _Optional[bytes] = ..., template_compatibility: _Optional[bytes] = ..., revision: _Optional[int] = ...) -> None: ...

class MessageSnapshot(_message.Message):
    __slots__ = ("session_id", "message_id", "source_participant_id", "destination_participant_id", "mailbox_sequence", "priority", "operation_id", "in_reply_to", "envelope", "attempt_count", "delivery_status", "revision", "created_at", "updated_at")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    SOURCE_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    DESTINATION_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    MAILBOX_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    PRIORITY_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    IN_REPLY_TO_FIELD_NUMBER: _ClassVar[int]
    ENVELOPE_FIELD_NUMBER: _ClassVar[int]
    ATTEMPT_COUNT_FIELD_NUMBER: _ClassVar[int]
    DELIVERY_STATUS_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    message_id: bytes
    source_participant_id: bytes
    destination_participant_id: bytes
    mailbox_sequence: int
    priority: MessagePriority
    operation_id: bytes
    in_reply_to: bytes
    envelope: bytes
    attempt_count: int
    delivery_status: MessageDeliveryStatus
    revision: int
    created_at: Timestamp
    updated_at: Timestamp
    def __init__(self, session_id: _Optional[bytes] = ..., message_id: _Optional[bytes] = ..., source_participant_id: _Optional[bytes] = ..., destination_participant_id: _Optional[bytes] = ..., mailbox_sequence: _Optional[int] = ..., priority: _Optional[_Union[MessagePriority, str]] = ..., operation_id: _Optional[bytes] = ..., in_reply_to: _Optional[bytes] = ..., envelope: _Optional[bytes] = ..., attempt_count: _Optional[int] = ..., delivery_status: _Optional[_Union[MessageDeliveryStatus, str]] = ..., revision: _Optional[int] = ..., created_at: _Optional[_Union[Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[Timestamp, _Mapping]] = ...) -> None: ...

class SessionSnapshot(_message.Message):
    __slots__ = ("session_id", "consumer_key", "compatibility_identity", "status", "revision", "created_at", "updated_at", "root_participant_id")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    CONSUMER_KEY_FIELD_NUMBER: _ClassVar[int]
    COMPATIBILITY_IDENTITY_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    ROOT_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    consumer_key: str
    compatibility_identity: bytes
    status: SessionStatus
    revision: int
    created_at: Timestamp
    updated_at: Timestamp
    root_participant_id: bytes
    def __init__(self, session_id: _Optional[bytes] = ..., consumer_key: _Optional[str] = ..., compatibility_identity: _Optional[bytes] = ..., status: _Optional[_Union[SessionStatus, str]] = ..., revision: _Optional[int] = ..., created_at: _Optional[_Union[Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[Timestamp, _Mapping]] = ..., root_participant_id: _Optional[bytes] = ...) -> None: ...

class SessionEvent(_message.Message):
    __slots__ = ("event_id", "session_id", "position", "revision", "event_type", "schema_version", "related_request_id", "data", "occurred_at")
    EVENT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    POSITION_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    EVENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_VERSION_FIELD_NUMBER: _ClassVar[int]
    RELATED_REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    OCCURRED_AT_FIELD_NUMBER: _ClassVar[int]
    event_id: bytes
    session_id: bytes
    position: int
    revision: int
    event_type: str
    schema_version: int
    related_request_id: bytes
    data: bytes
    occurred_at: Timestamp
    def __init__(self, event_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., position: _Optional[int] = ..., revision: _Optional[int] = ..., event_type: _Optional[str] = ..., schema_version: _Optional[int] = ..., related_request_id: _Optional[bytes] = ..., data: _Optional[bytes] = ..., occurred_at: _Optional[_Union[Timestamp, _Mapping]] = ...) -> None: ...

class Timestamp(_message.Message):
    __slots__ = ("unix_seconds", "nanoseconds")
    UNIX_SECONDS_FIELD_NUMBER: _ClassVar[int]
    NANOSECONDS_FIELD_NUMBER: _ClassVar[int]
    unix_seconds: int
    nanoseconds: int
    def __init__(self, unix_seconds: _Optional[int] = ..., nanoseconds: _Optional[int] = ...) -> None: ...

class Failure(_message.Message):
    __slots__ = ("code", "message", "retry", "related_id", "details")
    CODE_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RETRY_FIELD_NUMBER: _ClassVar[int]
    RELATED_ID_FIELD_NUMBER: _ClassVar[int]
    DETAILS_FIELD_NUMBER: _ClassVar[int]
    code: FailureCode
    message: str
    retry: RetryClass
    related_id: bytes
    details: bytes
    def __init__(self, code: _Optional[_Union[FailureCode, str]] = ..., message: _Optional[str] = ..., retry: _Optional[_Union[RetryClass, str]] = ..., related_id: _Optional[bytes] = ..., details: _Optional[bytes] = ...) -> None: ...

class RegisterToolRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id", "tool")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    TOOL_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    tool: ToolSpecification
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., tool: _Optional[_Union[ToolSpecification, _Mapping]] = ...) -> None: ...

class RegisterToolResponse(_message.Message):
    __slots__ = ("registration", "failure")
    REGISTRATION_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    registration: ToolRegistrationSnapshot
    failure: Failure
    def __init__(self, registration: _Optional[_Union[ToolRegistrationSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ToolSpecification(_message.Message):
    __slots__ = ("name", "version", "input_schema", "output_schema", "required_authority", "timeout_millis", "cancellation_behavior", "effect_class", "idempotency_contract", "requires_approval")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    INPUT_SCHEMA_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_SCHEMA_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_AUTHORITY_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_MILLIS_FIELD_NUMBER: _ClassVar[int]
    CANCELLATION_BEHAVIOR_FIELD_NUMBER: _ClassVar[int]
    EFFECT_CLASS_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_CONTRACT_FIELD_NUMBER: _ClassVar[int]
    REQUIRES_APPROVAL_FIELD_NUMBER: _ClassVar[int]
    name: str
    version: str
    input_schema: bytes
    output_schema: bytes
    required_authority: str
    timeout_millis: int
    cancellation_behavior: ToolCancellationBehavior
    effect_class: ToolEffectClass
    idempotency_contract: ToolIdempotencyContract
    requires_approval: bool
    def __init__(self, name: _Optional[str] = ..., version: _Optional[str] = ..., input_schema: _Optional[bytes] = ..., output_schema: _Optional[bytes] = ..., required_authority: _Optional[str] = ..., timeout_millis: _Optional[int] = ..., cancellation_behavior: _Optional[_Union[ToolCancellationBehavior, str]] = ..., effect_class: _Optional[_Union[ToolEffectClass, str]] = ..., idempotency_contract: _Optional[_Union[ToolIdempotencyContract, str]] = ..., requires_approval: bool = ...) -> None: ...

class ToolRegistrationSnapshot(_message.Message):
    __slots__ = ("registration_id", "session_id", "tool", "revision", "created_at", "updated_at", "active", "request_id")
    REGISTRATION_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    TOOL_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    ACTIVE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    registration_id: bytes
    session_id: bytes
    tool: ToolSpecification
    revision: int
    created_at: Timestamp
    updated_at: Timestamp
    active: bool
    request_id: bytes
    def __init__(self, registration_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., tool: _Optional[_Union[ToolSpecification, _Mapping]] = ..., revision: _Optional[int] = ..., created_at: _Optional[_Union[Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[Timestamp, _Mapping]] = ..., active: bool = ..., request_id: _Optional[bytes] = ...) -> None: ...

class ToolProviderRequest(_message.Message):
    __slots__ = ("connect", "started", "result", "failure")
    CONNECT_FIELD_NUMBER: _ClassVar[int]
    STARTED_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    connect: ConnectToolProvider
    started: ToolHandlerStarted
    result: ToolHandlerResult
    failure: ToolHandlerFailure
    def __init__(self, connect: _Optional[_Union[ConnectToolProvider, _Mapping]] = ..., started: _Optional[_Union[ToolHandlerStarted, _Mapping]] = ..., result: _Optional[_Union[ToolHandlerResult, _Mapping]] = ..., failure: _Optional[_Union[ToolHandlerFailure, _Mapping]] = ...) -> None: ...

class ConnectToolProvider(_message.Message):
    __slots__ = ("metadata", "session_id", "provider_id", "connection_id", "after_server_sequence", "registration_ids")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_ID_FIELD_NUMBER: _ClassVar[int]
    AFTER_SERVER_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    REGISTRATION_IDS_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    provider_id: bytes
    connection_id: bytes
    after_server_sequence: int
    registration_ids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ..., provider_id: _Optional[bytes] = ..., connection_id: _Optional[bytes] = ..., after_server_sequence: _Optional[int] = ..., registration_ids: _Optional[_Iterable[bytes]] = ...) -> None: ...

class ToolHandlerStarted(_message.Message):
    __slots__ = ("session_id", "provider_id", "connection_id", "invocation_id", "dispatch_id", "server_sequence", "started_at")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_ID_FIELD_NUMBER: _ClassVar[int]
    INVOCATION_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    SERVER_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    STARTED_AT_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    provider_id: bytes
    connection_id: bytes
    invocation_id: bytes
    dispatch_id: bytes
    server_sequence: int
    started_at: Timestamp
    def __init__(self, session_id: _Optional[bytes] = ..., provider_id: _Optional[bytes] = ..., connection_id: _Optional[bytes] = ..., invocation_id: _Optional[bytes] = ..., dispatch_id: _Optional[bytes] = ..., server_sequence: _Optional[int] = ..., started_at: _Optional[_Union[Timestamp, _Mapping]] = ...) -> None: ...

class ToolHandlerResult(_message.Message):
    __slots__ = ("session_id", "provider_id", "connection_id", "invocation_id", "dispatch_id", "server_sequence", "output", "artifacts")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_ID_FIELD_NUMBER: _ClassVar[int]
    INVOCATION_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    SERVER_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    OUTPUT_FIELD_NUMBER: _ClassVar[int]
    ARTIFACTS_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    provider_id: bytes
    connection_id: bytes
    invocation_id: bytes
    dispatch_id: bytes
    server_sequence: int
    output: bytes
    artifacts: _containers.RepeatedCompositeFieldContainer[ArtifactReference]
    def __init__(self, session_id: _Optional[bytes] = ..., provider_id: _Optional[bytes] = ..., connection_id: _Optional[bytes] = ..., invocation_id: _Optional[bytes] = ..., dispatch_id: _Optional[bytes] = ..., server_sequence: _Optional[int] = ..., output: _Optional[bytes] = ..., artifacts: _Optional[_Iterable[_Union[ArtifactReference, _Mapping]]] = ...) -> None: ...

class ToolHandlerFailure(_message.Message):
    __slots__ = ("session_id", "provider_id", "connection_id", "invocation_id", "dispatch_id", "server_sequence", "failure")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_ID_FIELD_NUMBER: _ClassVar[int]
    INVOCATION_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    SERVER_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    provider_id: bytes
    connection_id: bytes
    invocation_id: bytes
    dispatch_id: bytes
    server_sequence: int
    failure: Failure
    def __init__(self, session_id: _Optional[bytes] = ..., provider_id: _Optional[bytes] = ..., connection_id: _Optional[bytes] = ..., invocation_id: _Optional[bytes] = ..., dispatch_id: _Optional[bytes] = ..., server_sequence: _Optional[int] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ToolProviderResponse(_message.Message):
    __slots__ = ("connected", "invocation", "cancellation", "acknowledgement", "failure")
    CONNECTED_FIELD_NUMBER: _ClassVar[int]
    INVOCATION_FIELD_NUMBER: _ClassVar[int]
    CANCELLATION_FIELD_NUMBER: _ClassVar[int]
    ACKNOWLEDGEMENT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    connected: ToolProviderConnected
    invocation: ToolInvocation
    cancellation: ToolInvocationCancel
    acknowledgement: ToolProviderAck
    failure: Failure
    def __init__(self, connected: _Optional[_Union[ToolProviderConnected, _Mapping]] = ..., invocation: _Optional[_Union[ToolInvocation, _Mapping]] = ..., cancellation: _Optional[_Union[ToolInvocationCancel, _Mapping]] = ..., acknowledgement: _Optional[_Union[ToolProviderAck, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ToolProviderConnected(_message.Message):
    __slots__ = ("session_id", "provider_id", "connection_id", "next_server_sequence", "accepted_after_server_sequence", "high_water_server_sequence")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    CONNECTION_ID_FIELD_NUMBER: _ClassVar[int]
    NEXT_SERVER_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    ACCEPTED_AFTER_SERVER_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    HIGH_WATER_SERVER_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    provider_id: bytes
    connection_id: bytes
    next_server_sequence: int
    accepted_after_server_sequence: int
    high_water_server_sequence: int
    def __init__(self, session_id: _Optional[bytes] = ..., provider_id: _Optional[bytes] = ..., connection_id: _Optional[bytes] = ..., next_server_sequence: _Optional[int] = ..., accepted_after_server_sequence: _Optional[int] = ..., high_water_server_sequence: _Optional[int] = ...) -> None: ...

class ToolInvocation(_message.Message):
    __slots__ = ("session_id", "registration_id", "invocation_id", "dispatch_id", "operation_id", "participant_id", "server_sequence", "tool_name", "tool_version", "input", "deadline")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    REGISTRATION_ID_FIELD_NUMBER: _ClassVar[int]
    INVOCATION_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    SERVER_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    TOOL_NAME_FIELD_NUMBER: _ClassVar[int]
    TOOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    INPUT_FIELD_NUMBER: _ClassVar[int]
    DEADLINE_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    registration_id: bytes
    invocation_id: bytes
    dispatch_id: bytes
    operation_id: bytes
    participant_id: bytes
    server_sequence: int
    tool_name: str
    tool_version: str
    input: bytes
    deadline: Timestamp
    def __init__(self, session_id: _Optional[bytes] = ..., registration_id: _Optional[bytes] = ..., invocation_id: _Optional[bytes] = ..., dispatch_id: _Optional[bytes] = ..., operation_id: _Optional[bytes] = ..., participant_id: _Optional[bytes] = ..., server_sequence: _Optional[int] = ..., tool_name: _Optional[str] = ..., tool_version: _Optional[str] = ..., input: _Optional[bytes] = ..., deadline: _Optional[_Union[Timestamp, _Mapping]] = ...) -> None: ...

class ToolInvocationCancel(_message.Message):
    __slots__ = ("session_id", "invocation_id", "dispatch_id", "server_sequence", "cancellation_id", "requested_at")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    INVOCATION_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    SERVER_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    CANCELLATION_ID_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_AT_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    invocation_id: bytes
    dispatch_id: bytes
    server_sequence: int
    cancellation_id: bytes
    requested_at: Timestamp
    def __init__(self, session_id: _Optional[bytes] = ..., invocation_id: _Optional[bytes] = ..., dispatch_id: _Optional[bytes] = ..., server_sequence: _Optional[int] = ..., cancellation_id: _Optional[bytes] = ..., requested_at: _Optional[_Union[Timestamp, _Mapping]] = ...) -> None: ...

class ToolProviderAck(_message.Message):
    __slots__ = ("session_id", "invocation_id", "dispatch_id", "server_sequence", "kind", "duplicate")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    INVOCATION_ID_FIELD_NUMBER: _ClassVar[int]
    DISPATCH_ID_FIELD_NUMBER: _ClassVar[int]
    SERVER_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    KIND_FIELD_NUMBER: _ClassVar[int]
    DUPLICATE_FIELD_NUMBER: _ClassVar[int]
    session_id: bytes
    invocation_id: bytes
    dispatch_id: bytes
    server_sequence: int
    kind: ToolProviderAckKind
    duplicate: bool
    def __init__(self, session_id: _Optional[bytes] = ..., invocation_id: _Optional[bytes] = ..., dispatch_id: _Optional[bytes] = ..., server_sequence: _Optional[int] = ..., kind: _Optional[_Union[ToolProviderAckKind, str]] = ..., duplicate: bool = ...) -> None: ...

class WriteArtifactRequest(_message.Message):
    __slots__ = ("begin", "chunk")
    BEGIN_FIELD_NUMBER: _ClassVar[int]
    CHUNK_FIELD_NUMBER: _ClassVar[int]
    begin: BeginArtifactWrite
    chunk: ArtifactChunk
    def __init__(self, begin: _Optional[_Union[BeginArtifactWrite, _Mapping]] = ..., chunk: _Optional[_Union[ArtifactChunk, _Mapping]] = ...) -> None: ...

class BeginArtifactWrite(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id", "artifact_id", "media_type", "declared_size", "declared_sha256", "retain_until", "authority_grant_id", "creator_participant_id", "creator_operation_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    MEDIA_TYPE_FIELD_NUMBER: _ClassVar[int]
    DECLARED_SIZE_FIELD_NUMBER: _ClassVar[int]
    DECLARED_SHA256_FIELD_NUMBER: _ClassVar[int]
    RETAIN_UNTIL_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_GRANT_ID_FIELD_NUMBER: _ClassVar[int]
    CREATOR_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    CREATOR_OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    artifact_id: bytes
    media_type: str
    declared_size: int
    declared_sha256: bytes
    retain_until: Timestamp
    authority_grant_id: bytes
    creator_participant_id: bytes
    creator_operation_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., artifact_id: _Optional[bytes] = ..., media_type: _Optional[str] = ..., declared_size: _Optional[int] = ..., declared_sha256: _Optional[bytes] = ..., retain_until: _Optional[_Union[Timestamp, _Mapping]] = ..., authority_grant_id: _Optional[bytes] = ..., creator_participant_id: _Optional[bytes] = ..., creator_operation_id: _Optional[bytes] = ...) -> None: ...

class ArtifactChunk(_message.Message):
    __slots__ = ("artifact_id", "offset", "content")
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    artifact_id: bytes
    offset: int
    content: bytes
    def __init__(self, artifact_id: _Optional[bytes] = ..., offset: _Optional[int] = ..., content: _Optional[bytes] = ...) -> None: ...

class WriteArtifactResponse(_message.Message):
    __slots__ = ("artifact", "failure")
    ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    artifact: ArtifactSnapshot
    failure: Failure
    def __init__(self, artifact: _Optional[_Union[ArtifactSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ReadArtifactRequest(_message.Message):
    __slots__ = ("metadata", "session_id", "artifact_id", "offset", "length", "authority_grant_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_GRANT_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    artifact_id: bytes
    offset: int
    length: int
    authority_grant_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ..., artifact_id: _Optional[bytes] = ..., offset: _Optional[int] = ..., length: _Optional[int] = ..., authority_grant_id: _Optional[bytes] = ...) -> None: ...

class ReadArtifactResponse(_message.Message):
    __slots__ = ("header", "chunk", "failure")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    CHUNK_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    header: ArtifactReadHeader
    chunk: ArtifactChunk
    failure: Failure
    def __init__(self, header: _Optional[_Union[ArtifactReadHeader, _Mapping]] = ..., chunk: _Optional[_Union[ArtifactChunk, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ArtifactReadHeader(_message.Message):
    __slots__ = ("artifact", "range_offset", "range_length")
    ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    RANGE_OFFSET_FIELD_NUMBER: _ClassVar[int]
    RANGE_LENGTH_FIELD_NUMBER: _ClassVar[int]
    artifact: ArtifactSnapshot
    range_offset: int
    range_length: int
    def __init__(self, artifact: _Optional[_Union[ArtifactSnapshot, _Mapping]] = ..., range_offset: _Optional[int] = ..., range_length: _Optional[int] = ...) -> None: ...

class ArtifactSnapshotRequest(_message.Message):
    __slots__ = ("metadata", "session_id", "artifact_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    artifact_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ..., artifact_id: _Optional[bytes] = ...) -> None: ...

class ArtifactSnapshotResponse(_message.Message):
    __slots__ = ("artifact", "failure")
    ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    artifact: ArtifactSnapshot
    failure: Failure
    def __init__(self, artifact: _Optional[_Union[ArtifactSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class DeleteArtifactRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id", "artifact_id", "authority_grant_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    AUTHORITY_GRANT_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    artifact_id: bytes
    authority_grant_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., artifact_id: _Optional[bytes] = ..., authority_grant_id: _Optional[bytes] = ...) -> None: ...

class DeleteArtifactResponse(_message.Message):
    __slots__ = ("artifact", "failure")
    ARTIFACT_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    artifact: ArtifactSnapshot
    failure: Failure
    def __init__(self, artifact: _Optional[_Union[ArtifactSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ArtifactReference(_message.Message):
    __slots__ = ("artifact_id", "session_id", "media_type", "size", "sha256", "creator_participant_id", "creator_operation_id")
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MEDIA_TYPE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    CREATOR_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    CREATOR_OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    artifact_id: bytes
    session_id: bytes
    media_type: str
    size: int
    sha256: bytes
    creator_participant_id: bytes
    creator_operation_id: bytes
    def __init__(self, artifact_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., media_type: _Optional[str] = ..., size: _Optional[int] = ..., sha256: _Optional[bytes] = ..., creator_participant_id: _Optional[bytes] = ..., creator_operation_id: _Optional[bytes] = ...) -> None: ...

class ArtifactSnapshot(_message.Message):
    __slots__ = ("artifact_id", "session_id", "media_type", "size", "sha256", "storage_relative_locator", "status", "retain_until", "created_at", "updated_at", "revision", "creator_participant_id", "creator_operation_id")
    ARTIFACT_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    MEDIA_TYPE_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    STORAGE_RELATIVE_LOCATOR_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RETAIN_UNTIL_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    UPDATED_AT_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    CREATOR_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    CREATOR_OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    artifact_id: bytes
    session_id: bytes
    media_type: str
    size: int
    sha256: bytes
    storage_relative_locator: str
    status: ArtifactStatus
    retain_until: Timestamp
    created_at: Timestamp
    updated_at: Timestamp
    revision: int
    creator_participant_id: bytes
    creator_operation_id: bytes
    def __init__(self, artifact_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., media_type: _Optional[str] = ..., size: _Optional[int] = ..., sha256: _Optional[bytes] = ..., storage_relative_locator: _Optional[str] = ..., status: _Optional[_Union[ArtifactStatus, str]] = ..., retain_until: _Optional[_Union[Timestamp, _Mapping]] = ..., created_at: _Optional[_Union[Timestamp, _Mapping]] = ..., updated_at: _Optional[_Union[Timestamp, _Mapping]] = ..., revision: _Optional[int] = ..., creator_participant_id: _Optional[bytes] = ..., creator_operation_id: _Optional[bytes] = ...) -> None: ...

class ApprovalSnapshotRequest(_message.Message):
    __slots__ = ("metadata", "session_id", "approval_id")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_ID_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    session_id: bytes
    approval_id: bytes
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., session_id: _Optional[bytes] = ..., approval_id: _Optional[bytes] = ...) -> None: ...

class ApprovalSnapshotResponse(_message.Message):
    __slots__ = ("approval", "failure")
    APPROVAL_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    approval: ApprovalSnapshot
    failure: Failure
    def __init__(self, approval: _Optional[_Union[ApprovalSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ApproveApprovalRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id", "approval_id", "expected_revision", "grant_id", "grant_expires_at", "max_uses")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    GRANT_ID_FIELD_NUMBER: _ClassVar[int]
    GRANT_EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    MAX_USES_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    approval_id: bytes
    expected_revision: int
    grant_id: bytes
    grant_expires_at: Timestamp
    max_uses: int
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., approval_id: _Optional[bytes] = ..., expected_revision: _Optional[int] = ..., grant_id: _Optional[bytes] = ..., grant_expires_at: _Optional[_Union[Timestamp, _Mapping]] = ..., max_uses: _Optional[int] = ...) -> None: ...

class ApproveApprovalResponse(_message.Message):
    __slots__ = ("approval", "failure")
    APPROVAL_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    approval: ApprovalSnapshot
    failure: Failure
    def __init__(self, approval: _Optional[_Union[ApprovalSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class DenyApprovalRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id", "approval_id", "expected_revision")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    approval_id: bytes
    expected_revision: int
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., approval_id: _Optional[bytes] = ..., expected_revision: _Optional[int] = ...) -> None: ...

class DenyApprovalResponse(_message.Message):
    __slots__ = ("approval", "failure")
    APPROVAL_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    approval: ApprovalSnapshot
    failure: Failure
    def __init__(self, approval: _Optional[_Union[ApprovalSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class RevokeApprovalGrantRequest(_message.Message):
    __slots__ = ("metadata", "request_id", "session_id", "grant_id", "expected_revision")
    METADATA_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    GRANT_ID_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_REVISION_FIELD_NUMBER: _ClassVar[int]
    metadata: RequestMetadata
    request_id: bytes
    session_id: bytes
    grant_id: bytes
    expected_revision: int
    def __init__(self, metadata: _Optional[_Union[RequestMetadata, _Mapping]] = ..., request_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., grant_id: _Optional[bytes] = ..., expected_revision: _Optional[int] = ...) -> None: ...

class RevokeApprovalGrantResponse(_message.Message):
    __slots__ = ("approval", "failure")
    APPROVAL_FIELD_NUMBER: _ClassVar[int]
    FAILURE_FIELD_NUMBER: _ClassVar[int]
    approval: ApprovalSnapshot
    failure: Failure
    def __init__(self, approval: _Optional[_Union[ApprovalSnapshot, _Mapping]] = ..., failure: _Optional[_Union[Failure, _Mapping]] = ...) -> None: ...

class ApprovalSnapshot(_message.Message):
    __slots__ = ("request", "grant")
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    GRANT_FIELD_NUMBER: _ClassVar[int]
    request: ApprovalRequestSnapshot
    grant: ApprovalGrantSnapshot
    def __init__(self, request: _Optional[_Union[ApprovalRequestSnapshot, _Mapping]] = ..., grant: _Optional[_Union[ApprovalGrantSnapshot, _Mapping]] = ...) -> None: ...

class ApprovalRequestSnapshot(_message.Message):
    __slots__ = ("approval_id", "session_id", "requester_participant_id", "operation_id", "capability", "resource", "summary", "status", "expires_at", "grant_id", "decision_source", "created_at", "decided_at", "revision")
    APPROVAL_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    REQUESTER_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    SUMMARY_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    GRANT_ID_FIELD_NUMBER: _ClassVar[int]
    DECISION_SOURCE_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    DECIDED_AT_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    approval_id: bytes
    session_id: bytes
    requester_participant_id: bytes
    operation_id: bytes
    capability: str
    resource: bytes
    summary: str
    status: ApprovalStatus
    expires_at: Timestamp
    grant_id: bytes
    decision_source: ApprovalDecisionSource
    created_at: Timestamp
    decided_at: Timestamp
    revision: int
    def __init__(self, approval_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., requester_participant_id: _Optional[bytes] = ..., operation_id: _Optional[bytes] = ..., capability: _Optional[str] = ..., resource: _Optional[bytes] = ..., summary: _Optional[str] = ..., status: _Optional[_Union[ApprovalStatus, str]] = ..., expires_at: _Optional[_Union[Timestamp, _Mapping]] = ..., grant_id: _Optional[bytes] = ..., decision_source: _Optional[_Union[ApprovalDecisionSource, str]] = ..., created_at: _Optional[_Union[Timestamp, _Mapping]] = ..., decided_at: _Optional[_Union[Timestamp, _Mapping]] = ..., revision: _Optional[int] = ...) -> None: ...

class ApprovalGrantSnapshot(_message.Message):
    __slots__ = ("grant_id", "approval_id", "session_id", "subject_participant_id", "operation_id", "capability", "resource_hash", "issued_by", "max_uses", "used_count", "expires_at", "revoked_at", "created_at", "revision")
    GRANT_ID_FIELD_NUMBER: _ClassVar[int]
    APPROVAL_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_PARTICIPANT_ID_FIELD_NUMBER: _ClassVar[int]
    OPERATION_ID_FIELD_NUMBER: _ClassVar[int]
    CAPABILITY_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_HASH_FIELD_NUMBER: _ClassVar[int]
    ISSUED_BY_FIELD_NUMBER: _ClassVar[int]
    MAX_USES_FIELD_NUMBER: _ClassVar[int]
    USED_COUNT_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_AT_FIELD_NUMBER: _ClassVar[int]
    REVOKED_AT_FIELD_NUMBER: _ClassVar[int]
    CREATED_AT_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    grant_id: bytes
    approval_id: bytes
    session_id: bytes
    subject_participant_id: bytes
    operation_id: bytes
    capability: str
    resource_hash: bytes
    issued_by: ApprovalDecisionSource
    max_uses: int
    used_count: int
    expires_at: Timestamp
    revoked_at: Timestamp
    created_at: Timestamp
    revision: int
    def __init__(self, grant_id: _Optional[bytes] = ..., approval_id: _Optional[bytes] = ..., session_id: _Optional[bytes] = ..., subject_participant_id: _Optional[bytes] = ..., operation_id: _Optional[bytes] = ..., capability: _Optional[str] = ..., resource_hash: _Optional[bytes] = ..., issued_by: _Optional[_Union[ApprovalDecisionSource, str]] = ..., max_uses: _Optional[int] = ..., used_count: _Optional[int] = ..., expires_at: _Optional[_Union[Timestamp, _Mapping]] = ..., revoked_at: _Optional[_Union[Timestamp, _Mapping]] = ..., created_at: _Optional[_Union[Timestamp, _Mapping]] = ..., revision: _Optional[int] = ...) -> None: ...
