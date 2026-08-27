//! Canonical, infrastructure-independent Navigator domain types.

mod approval;
mod artifact;
mod authority;
mod bounded;
mod clock;
mod digest;
mod error;
mod identity;
mod message;
mod operation;
mod recovery;
mod revision;
mod session;
mod template;
mod tool;

pub use approval::{
    ApprovalDecisionSource, ApprovalDomainError, ApprovalEffectIntent, ApprovalEffectPhase,
    ApprovalGrant, ApprovalRequest, ApprovalResource, ApprovalStatus, ApprovalSummary,
    MAX_APPROVAL_RESOURCE_BYTES, MAX_APPROVAL_SUMMARY_BYTES, MAX_APPROVAL_USES,
    TerminalApprovalEffectPhase,
};
pub use artifact::{
    ARTIFACT_SHA256_BYTES, ArtifactDigest, ArtifactMediaType, ArtifactRef, ArtifactRefError,
    ArtifactSnapshot, ArtifactState, MAX_ARTIFACT_BYTES, MAX_MEDIA_TYPE_BYTES,
};
pub use authority::{
    Authority, AuthorityCeilings, AuthorityDecision, AuthorityError, AuthorityOrigin,
    AuthorityProfile, Capability, Grant, MAX_AUTHORITY_RULES, ResourceScope, ScopedCapability,
};
pub use bounded::{BoundError, BoundedBytes, BoundedText, Deadline, DeadlineWire, Secret};
pub use clock::{Clock, MonotonicInstant};
pub use digest::SemanticDigest;
pub use error::{ErrorCode, ErrorInfo, InvalidErrorMessage, NavigatorError};
pub use identity::{
    ApprovalRequestId, ArtifactId, CorrelationId, DeliveryAttemptId, DriverId, EnvelopeId, EventId,
    GrantId, HostId, IdentitySource, InstanceId, InvalidIdentity, LaunchAttemptId, MessageId,
    OperationId, ParticipantId, RequestId, SessionId, TemplateId, ToolCancellationId,
    ToolConnectionId, ToolDispatchId, ToolInvocationId, ToolProviderId, ToolRegistrationId,
};
pub use message::{
    ControlMessageKind, FeedbackKind, MAX_VALIDATED_MESSAGE_BYTES, MessageBody, MessageKind,
    MessageValidationError, PublicOperationOutcome, ValidatedMessageEnvelope,
};
pub use operation::{Operation, OperationAction, OperationState, TransitionError};
pub use recovery::{
    EffectClass, EffectPhase, EffectProof, EffectProofError, EffectProofKind,
    EmptyResolutionReason, LiveObservation, MAX_EFFECT_PROOF_BYTES, MAX_RESOLUTION_REASON_BYTES,
    RecoveryAction, RecoveryClass, RecoveryContradiction, RecoveryDecision, RecoveryReason,
    RecoveryState, ResolveUncertaintyDecision, UncertaintyResolution, classify_recovery,
};
pub use revision::{FencingEpoch, Revision};
pub use session::{
    CompatibilityIdentity, ConsumerKey, EventPosition, EventSchemaVersion, EventType,
    MAX_CONSUMER_KEY_BYTES, MAX_EVENT_DATA_BYTES, MAX_EVENT_TYPE_BYTES, MAX_SESSION_TEMPLATES,
    OwnershipSnapshot, RedactedEventData, SessionCompatibilityManifest, SessionDomainError,
    SessionEvent, SessionSnapshot, SessionStatus, TemplateCompatibilityBinding, Timestamp,
};
pub use template::{
    DriverCapabilityRequirement, DriverRequirement, InputField, InputKind, InputSchema,
    LaunchIdentity, MAX_DRIVER_CAPABILITIES, MAX_FIELD_NAME_BYTES, MAX_INPUT_BYTES,
    MAX_INPUT_FIELDS, MAX_PARAMETER_BYTES, ParticipantDomainError, RegisteredTemplateSnapshot,
    ResourceBounds, RootParticipant, RootParticipantSnapshot, Template, TemplateDomainError,
    TemplatePublicSnapshot, TemplateSecrets, TrustedConfiguration, ValidatedTaskInput,
};
pub use tool::{
    CanonicalJson, IdempotencyContract, MAX_TOOL_ARTIFACT_REFS, MAX_TOOL_FAILURE_MESSAGE_BYTES,
    MAX_TOOL_INLINE_BYTES, MAX_TOOL_NAME_BYTES, MAX_TOOL_SCHEMA_BYTES, MAX_TOOL_TIMEOUT_MILLIS,
    MAX_TOOL_VERSION_BYTES, ToolCancellation, ToolDefinition, ToolDomainError, ToolFailure,
    ToolFailureKind, ToolInvocation, ToolName, ToolResult, ToolTimeout, ToolVersion,
};

#[cfg(test)]
mod tests {
    use super::{
        ArtifactId, BoundError, BoundedBytes, BoundedText, Capability, CorrelationId, Deadline,
        DeadlineWire, DeliveryAttemptId, DriverId, EffectClass, EffectPhase, EnvelopeId, ErrorCode,
        ErrorInfo, EventId, FencingEpoch, GrantId, HostId, InstanceId, LaunchAttemptId, MessageId,
        OperationId, ParticipantId, RecoveryClass, RequestId, Revision, Secret, SemanticDigest,
        SessionId, TemplateId, ToolCancellationId, ToolConnectionId, ToolDispatchId,
        ToolInvocationId, ToolProviderId, ToolRegistrationId,
    };
    use proptest::prelude::*;

    #[test]
    fn validation_cannot_be_bypassed_by_deserialization() {
        assert!(serde_json::from_str::<FencingEpoch>("0").is_err());
        assert!(serde_json::from_str::<Revision>("0").is_err());
        assert!(
            serde_json::from_str::<SessionId>("\"00000000-0000-0000-0000-000000000000\"").is_err()
        );
        assert!(serde_json::from_str::<Capability>("\"UPPERCASE\"").is_err());
        assert!(serde_json::from_str::<Capability>("\"valid.capability\"").is_ok());
        assert!(
            serde_json::from_str::<ErrorInfo>(&format!(
                "{{\"code\":\"validation\",\"message\":\"{}\",\"retryable\":false}}",
                "x".repeat(1025)
            ))
            .is_err()
        );
    }

    #[test]
    fn semantic_digest_is_domain_separated_and_stable() {
        let action = Capability::new("operation.start").unwrap();
        let same = SemanticDigest::v1(&action, br#"{"task":"x"}"#);
        assert_eq!(same, SemanticDigest::v1(&action, br#"{"task":"x"}"#));
        assert_ne!(same, SemanticDigest::v1(&action, br#"{"task":"y"}"#));
        assert_ne!(
            same,
            SemanticDigest::v1(
                &Capability::new("operation.cancel").unwrap(),
                br#"{"task":"x"}"#
            )
        );
    }

    #[test]
    fn public_error_debug_and_display_do_not_repeat_message() {
        let info = ErrorInfo::new(super::ErrorCode::Internal, "secret-sentinel", false).unwrap();
        assert!(!format!("{info:?}").contains("secret-sentinel"));
        let error = super::NavigatorError { info };
        assert!(!error.to_string().contains("secret-sentinel"));
        assert!(!format!("{error:?}").contains("secret-sentinel"));
    }

    #[test]
    fn deadline_enforces_future_window() {
        let now = time::macros::datetime!(2026-01-01 0:00 UTC);
        assert_eq!(
            Deadline::new(now, now, time::Duration::hours(1)),
            Err(BoundError::NotFuture)
        );
        assert_eq!(
            Deadline::new(
                now + time::Duration::hours(2),
                now,
                time::Duration::hours(1)
            ),
            Err(BoundError::TooFarInFuture)
        );
        assert!(
            Deadline::new(
                now + time::Duration::hours(1),
                now,
                time::Duration::hours(1)
            )
            .is_ok()
        );
    }

    #[test]
    fn secret_never_exposes_value_through_debug() {
        let secret = Secret::new("secret-sentinel".to_owned());
        assert_eq!(secret.expose(), "secret-sentinel");
        assert!(!format!("{secret:?}").contains("secret-sentinel"));
    }

    #[test]
    fn canonical_identity_snapshots_are_stable() {
        let uuid = uuid::Uuid::from_u128(1);
        let expected = r#""00000000-0000-0000-0000-000000000001""#;
        macro_rules! assert_id {
            ($type:ty) => {
                assert_eq!(
                    serde_json::to_string(&<$type>::from_uuid(uuid).unwrap()).unwrap(),
                    expected
                );
            };
        }
        assert_id!(SessionId);
        assert_id!(HostId);
        assert_id!(ParticipantId);
        assert_id!(InstanceId);
        assert_id!(TemplateId);
        assert_id!(ArtifactId);
        assert_id!(ToolInvocationId);
        assert_id!(ToolRegistrationId);
        assert_id!(ToolProviderId);
        assert_id!(ToolConnectionId);
        assert_id!(ToolDispatchId);
        assert_id!(ToolCancellationId);
        assert_id!(GrantId);
        assert_id!(DriverId);
        assert_id!(LaunchAttemptId);
        assert_id!(OperationId);
        assert_id!(MessageId);
        assert_id!(DeliveryAttemptId);
        assert_id!(EventId);
        assert_id!(RequestId);
        assert_id!(CorrelationId);
        assert_id!(EnvelopeId);
    }

    #[test]
    fn canonical_scalar_and_bound_snapshots_are_stable() {
        assert_eq!(
            serde_json::to_string(&Revision::new(7).unwrap()).unwrap(),
            "7"
        );
        assert_eq!(
            serde_json::to_string(&FencingEpoch::new(9).unwrap()).unwrap(),
            "9"
        );
        assert_eq!(
            serde_json::to_string(&BoundedText::<9>::new("navigator").unwrap()).unwrap(),
            r#""navigator""#
        );
        assert_eq!(
            serde_json::to_string(&BoundedBytes::<4>::new([0, 1, 2, 255]).unwrap()).unwrap(),
            "[0,1,2,255]"
        );
    }

    #[test]
    fn canonical_error_effect_and_deadline_snapshots_are_stable() {
        let error = ErrorInfo::new(ErrorCode::Unavailable, "temporarily offline", true).unwrap();
        assert_eq!(
            serde_json::to_string(&error).unwrap(),
            r#"{"code":"unavailable","message":"temporarily offline","retryable":true}"#
        );
        assert_eq!(
            serde_json::to_string(&(EffectClass::Transactional, EffectPhase::Started)).unwrap(),
            r#"["transactional","started"]"#
        );
        assert_eq!(
            serde_json::to_string(&RecoveryClass::EffectUncertain).unwrap(),
            r#""effect_uncertain""#
        );

        let now = time::macros::datetime!(2026-01-01 0:00 UTC);
        let wire: DeadlineWire =
            serde_json::from_str(r#"{"unix_seconds":1767229200,"nanoseconds":0}"#).unwrap();
        let deadline = wire.validate(now, time::Duration::hours(2)).unwrap();
        assert_eq!(
            serde_json::to_string(&deadline).unwrap(),
            r#"{"unix_seconds":1767229200,"nanoseconds":0}"#
        );
    }

    #[test]
    fn deadline_wire_requires_explicit_contextual_validation() {
        let now = time::macros::datetime!(2026-01-01 0:00 UTC);
        let expired: DeadlineWire =
            serde_json::from_str(r#"{"unix_seconds":1767225599,"nanoseconds":0}"#).unwrap();
        assert_eq!(
            expired.validate(now, time::Duration::hours(1)),
            Err(BoundError::NotFuture)
        );
        assert_eq!(
            DeadlineWire::new(1_767_229_200, 1_000_000_000),
            Err(BoundError::InvalidTimestamp)
        );
    }

    static_assertions::assert_not_impl_any!(Secret<String>: std::fmt::Display, serde::Serialize);
    static_assertions::assert_not_impl_any!(Deadline: serde::de::DeserializeOwned);

    proptest! {
        #[test]
        fn bounded_text_and_bytes_enforce_exact_edges(extra in 0usize..64) {
            let exact = "x".repeat(32);
            prop_assert!(BoundedText::<32>::new(exact).is_ok());
            prop_assert!(BoundedText::<32>::new("x".repeat(33 + extra)).is_err());
            prop_assert!(BoundedBytes::<32>::new(vec![0; 32]).is_ok());
            prop_assert!(BoundedBytes::<32>::new(vec![0; 33 + extra]).is_err());
        }

        #[test]
        fn validated_identity_round_trips(value in 1u128..u128::MAX) {
            let identity = SessionId::from_uuid(uuid::Uuid::from_u128(value)).unwrap();
            let encoded = serde_json::to_string(&identity).unwrap();
            let decoded: SessionId = serde_json::from_str(&encoded).unwrap();
            prop_assert_eq!(identity, decoded);
        }
    }
}
