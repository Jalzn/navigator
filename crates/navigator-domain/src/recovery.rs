use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{BoundedBytes, BoundedText, OperationId, SessionId};

pub const MAX_EFFECT_PROOF_BYTES: usize = 16_384;
pub const MAX_RESOLUTION_REASON_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum EffectProofError {
    #[error("effect proof digest must be non-zero")]
    ZeroDigest,
    #[error("effect proof evidence must be non-empty")]
    EmptyEvidence,
    #[error("effect proof digest does not match its evidence")]
    DigestMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectProofKind {
    ExternalCommit,
    IdempotencyReceipt,
    EffectAbsent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "EffectProofWire", into = "EffectProofWire")]
pub struct EffectProof {
    kind: EffectProofKind,
    digest: [u8; 32],
    evidence: BoundedBytes<MAX_EFFECT_PROOF_BYTES>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct EffectProofWire {
    kind: EffectProofKind,
    digest: [u8; 32],
    evidence: BoundedBytes<MAX_EFFECT_PROOF_BYTES>,
}

impl TryFrom<EffectProofWire> for EffectProof {
    type Error = EffectProofError;

    fn try_from(value: EffectProofWire) -> Result<Self, Self::Error> {
        Self::new(value.kind, value.digest, value.evidence)
    }
}

impl From<EffectProof> for EffectProofWire {
    fn from(value: EffectProof) -> Self {
        Self {
            kind: value.kind,
            digest: value.digest,
            evidence: value.evidence,
        }
    }
}

impl EffectProof {
    pub fn new(
        kind: EffectProofKind,
        digest: [u8; 32],
        evidence: BoundedBytes<MAX_EFFECT_PROOF_BYTES>,
    ) -> Result<Self, EffectProofError> {
        if digest.iter().all(|byte| *byte == 0) {
            return Err(EffectProofError::ZeroDigest);
        }
        if evidence.as_slice().is_empty() {
            return Err(EffectProofError::EmptyEvidence);
        }
        if digest != <[u8; 32]>::from(Sha256::digest(evidence.as_slice())) {
            return Err(EffectProofError::DigestMismatch);
        }
        Ok(Self {
            kind,
            digest,
            evidence,
        })
    }

    #[must_use]
    pub const fn kind(&self) -> EffectProofKind {
        self.kind
    }
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        self.evidence.as_slice()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncertaintyResolution {
    ConfirmCompleted { proof: EffectProof },
    DoNotRetry,
    RetryWithEffectProof { proof: EffectProof },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    try_from = "ResolveUncertaintyDecisionWire",
    into = "ResolveUncertaintyDecisionWire"
)]
pub struct ResolveUncertaintyDecision {
    session_id: SessionId,
    operation_id: OperationId,
    reason: BoundedText<MAX_RESOLUTION_REASON_BYTES>,
    resolution: UncertaintyResolution,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ResolveUncertaintyDecisionWire {
    session_id: SessionId,
    operation_id: OperationId,
    reason: BoundedText<MAX_RESOLUTION_REASON_BYTES>,
    resolution: UncertaintyResolution,
}

impl TryFrom<ResolveUncertaintyDecisionWire> for ResolveUncertaintyDecision {
    type Error = EmptyResolutionReason;

    fn try_from(value: ResolveUncertaintyDecisionWire) -> Result<Self, Self::Error> {
        Self::new(
            value.session_id,
            value.operation_id,
            value.reason,
            value.resolution,
        )
    }
}

impl From<ResolveUncertaintyDecision> for ResolveUncertaintyDecisionWire {
    fn from(value: ResolveUncertaintyDecision) -> Self {
        Self {
            session_id: value.session_id,
            operation_id: value.operation_id,
            reason: value.reason,
            resolution: value.resolution,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("uncertainty resolution reason must be non-empty")]
pub struct EmptyResolutionReason;

impl ResolveUncertaintyDecision {
    pub fn new(
        session_id: SessionId,
        operation_id: OperationId,
        reason: BoundedText<MAX_RESOLUTION_REASON_BYTES>,
        resolution: UncertaintyResolution,
    ) -> Result<Self, EmptyResolutionReason> {
        if reason.as_str().trim().is_empty() {
            return Err(EmptyResolutionReason);
        }
        Ok(Self {
            session_id,
            operation_id,
            reason,
            resolution,
        })
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    #[must_use]
    pub fn reason(&self) -> &str {
        self.reason.as_str()
    }
    #[must_use]
    pub const fn resolution(&self) -> &UncertaintyResolution {
        &self.resolution
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    ReadOnly,
    Idempotent,
    Transactional,
    NonIdempotent,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectPhase {
    Reserved,
    Started,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryClass {
    SafeToContinue,
    SafeToRedeliver,
    ExternallyAlive,
    EffectUncertain,
    CleanupRequired,
    Terminal,
}

/// Durable state normalized for reconciliation. Executor-native states do not
/// enter this type.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    SessionOpen,
    ParticipantRegistered,
    InstancePrepared,
    InstanceAttached,
    InstanceReady,
    InstanceStopping,
    InstanceCleanupRequired,
    InstanceStopped,
    OperationQueued,
    OperationStarting,
    OperationRunning,
    OperationWaiting,
    OperationCancelling,
    OperationTerminal,
    MessageQueued,
    MessageRetryScheduled,
    MessageRetryDeferred,
    MessageLeased,
    MessageLeaseActive,
    MessageAcceptancePending,
    MessageAcceptanceUnknown,
    MessageAccepted,
    MessageUncertain,
    MessageDeadLetter,
    EffectReserved,
    EffectStartedRetryable,
    EffectStartedUnsafe,
    EffectCompleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveObservation {
    NotApplicable,
    NotInspected,
    Absent,
    SameAuthenticatedInstance,
    SameUnauthenticatedInstance,
    DifferentInstance,
    Unreachable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    Continue,
    RedeliverExactMessage,
    ReconnectExactInstance,
    ScheduleExistingOperation,
    CleanupVerifiedResource,
    AwaitResolution,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryReason {
    DurableWorkNotStarted,
    ExactMessageIsDeduplicated,
    DeclaredEffectIsRetryable,
    ExactAuthenticatedInstanceObserved,
    ExternalEffectMayHaveOccurred,
    StaleVerifiedResourceObserved,
    DurableOutcomeExists,
    LiveIdentityCannotBeProven,
    EligibilityWindowNotReached,
}

impl RecoveryReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DurableWorkNotStarted => "durable_work_not_started",
            Self::ExactMessageIsDeduplicated => "exact_message_is_deduplicated",
            Self::DeclaredEffectIsRetryable => "declared_effect_is_retryable",
            Self::ExactAuthenticatedInstanceObserved => "exact_authenticated_instance_observed",
            Self::ExternalEffectMayHaveOccurred => "external_effect_may_have_occurred",
            Self::StaleVerifiedResourceObserved => "stale_verified_resource_observed",
            Self::DurableOutcomeExists => "durable_outcome_exists",
            Self::LiveIdentityCannotBeProven => "live_identity_cannot_be_proven",
            Self::EligibilityWindowNotReached => "eligibility_window_not_reached",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryDecision {
    pub class: RecoveryClass,
    pub reason: RecoveryReason,
    pub action: RecoveryAction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryContradiction {
    InspectionRequired,
    UnexpectedLiveObservation,
    TerminalStateHasLiveWork,
}

/// The conservative semantic table used by every recovery implementation.
/// Invalid state/observation pairs are errors, never implicit safe actions.
#[expect(
    clippy::too_many_lines,
    clippy::match_same_arms,
    reason = "one explicit table keeps every durable-state/observation mapping auditable"
)]
pub const fn classify_recovery(
    state: RecoveryState,
    observation: LiveObservation,
) -> Result<RecoveryDecision, RecoveryContradiction> {
    use LiveObservation as O;
    use RecoveryAction as A;
    use RecoveryClass as C;
    use RecoveryReason as R;
    use RecoveryState as S;

    let decision = match (state, observation) {
        (S::InstanceAttached | S::InstanceReady, O::SameAuthenticatedInstance) => {
            RecoveryDecision {
                class: C::ExternallyAlive,
                reason: R::ExactAuthenticatedInstanceObserved,
                action: A::ReconnectExactInstance,
            }
        }
        (
            S::InstanceStopping | S::InstanceCleanupRequired,
            O::SameAuthenticatedInstance | O::SameUnauthenticatedInstance,
        ) => RecoveryDecision {
            class: C::CleanupRequired,
            reason: R::StaleVerifiedResourceObserved,
            action: A::CleanupVerifiedResource,
        },
        (S::InstancePrepared, O::Absent) => RecoveryDecision {
            class: C::SafeToContinue,
            reason: R::DurableWorkNotStarted,
            action: A::Continue,
        },
        (
            S::InstanceAttached
            | S::InstanceReady
            | S::InstanceStopping
            | S::InstanceCleanupRequired,
            O::Absent,
        ) => RecoveryDecision {
            class: C::CleanupRequired,
            reason: R::StaleVerifiedResourceObserved,
            action: A::CleanupVerifiedResource,
        },
        (
            S::InstancePrepared
            | S::InstanceAttached
            | S::InstanceReady
            | S::InstanceStopping
            | S::InstanceCleanupRequired,
            O::NotInspected,
        ) => return Err(RecoveryContradiction::InspectionRequired),
        (
            S::InstancePrepared
            | S::InstanceAttached
            | S::InstanceReady
            | S::InstanceStopping
            | S::InstanceCleanupRequired,
            O::DifferentInstance | O::Unreachable | O::SameUnauthenticatedInstance,
        ) => RecoveryDecision {
            class: C::EffectUncertain,
            reason: R::LiveIdentityCannotBeProven,
            action: A::AwaitResolution,
        },
        (S::InstanceStopped, O::SameAuthenticatedInstance | O::SameUnauthenticatedInstance) => {
            return Err(RecoveryContradiction::TerminalStateHasLiveWork);
        }
        (S::InstanceStopped, O::Absent | O::NotApplicable) => terminal(),

        (S::OperationQueued, O::NotApplicable) => RecoveryDecision {
            class: C::SafeToContinue,
            reason: R::DurableWorkNotStarted,
            action: A::ScheduleExistingOperation,
        },
        (
            S::OperationStarting
            | S::OperationRunning
            | S::OperationWaiting
            | S::OperationCancelling,
            O::NotApplicable,
        ) => RecoveryDecision {
            class: C::EffectUncertain,
            reason: R::ExternalEffectMayHaveOccurred,
            action: A::AwaitResolution,
        },
        (S::OperationTerminal, O::NotApplicable) => terminal(),

        (S::MessageQueued | S::MessageRetryScheduled | S::MessageLeased, O::NotApplicable) => {
            RecoveryDecision {
                class: C::SafeToRedeliver,
                reason: R::ExactMessageIsDeduplicated,
                action: A::RedeliverExactMessage,
            }
        }
        (S::MessageRetryDeferred | S::MessageLeaseActive, O::NotApplicable) => RecoveryDecision {
            class: C::SafeToContinue,
            reason: R::EligibilityWindowNotReached,
            action: A::Continue,
        },
        (
            S::MessageAcceptancePending | S::MessageAcceptanceUnknown | S::MessageUncertain,
            O::NotApplicable,
        ) => RecoveryDecision {
            class: C::EffectUncertain,
            reason: R::ExternalEffectMayHaveOccurred,
            action: A::AwaitResolution,
        },
        (S::MessageAccepted | S::MessageDeadLetter, O::NotApplicable) => terminal(),

        (S::EffectReserved, O::NotApplicable) => RecoveryDecision {
            class: C::SafeToContinue,
            reason: R::DurableWorkNotStarted,
            action: A::Continue,
        },
        (S::EffectStartedRetryable, O::NotApplicable) => RecoveryDecision {
            class: C::SafeToContinue,
            reason: R::DeclaredEffectIsRetryable,
            action: A::Continue,
        },
        (S::EffectStartedUnsafe, O::NotApplicable) => RecoveryDecision {
            class: C::EffectUncertain,
            reason: R::ExternalEffectMayHaveOccurred,
            action: A::AwaitResolution,
        },
        (S::EffectCompleted, O::NotApplicable) => terminal(),

        (S::SessionOpen | S::ParticipantRegistered, O::NotApplicable) => RecoveryDecision {
            class: C::SafeToContinue,
            reason: R::DurableWorkNotStarted,
            action: A::Continue,
        },
        _ => return Err(RecoveryContradiction::UnexpectedLiveObservation),
    };
    Ok(decision)
}

const fn terminal() -> RecoveryDecision {
    RecoveryDecision {
        class: RecoveryClass::Terminal,
        reason: RecoveryReason::DurableOutcomeExists,
        action: RecoveryAction::None,
    }
}

impl RecoveryClass {
    /// A started effect is retryable only when its declared semantics prove it.
    #[must_use]
    pub const fn for_effect(class: EffectClass, phase: EffectPhase) -> Self {
        match phase {
            EffectPhase::Completed => Self::Terminal,
            EffectPhase::Reserved => Self::SafeToContinue,
            EffectPhase::Started => match class {
                EffectClass::ReadOnly | EffectClass::Idempotent => Self::SafeToContinue,
                EffectClass::Transactional | EffectClass::NonIdempotent | EffectClass::Unknown => {
                    Self::EffectUncertain
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[expect(
        clippy::too_many_lines,
        clippy::match_same_arms,
        reason = "independent exhaustive oracle is intentionally explicit"
    )]
    fn expected_recovery(
        state: RecoveryState,
        observation: LiveObservation,
    ) -> Result<RecoveryDecision, RecoveryContradiction> {
        use LiveObservation as O;
        use RecoveryAction as A;
        use RecoveryClass as C;
        use RecoveryContradiction as X;
        use RecoveryReason as R;
        use RecoveryState as S;

        let decision = match (state, observation) {
            (S::InstanceAttached | S::InstanceReady, O::SameAuthenticatedInstance) => decision(
                C::ExternallyAlive,
                R::ExactAuthenticatedInstanceObserved,
                A::ReconnectExactInstance,
            ),
            (
                S::InstanceStopping | S::InstanceCleanupRequired,
                O::SameAuthenticatedInstance | O::SameUnauthenticatedInstance,
            ) => decision(
                C::CleanupRequired,
                R::StaleVerifiedResourceObserved,
                A::CleanupVerifiedResource,
            ),
            (S::InstancePrepared, O::Absent) => {
                decision(C::SafeToContinue, R::DurableWorkNotStarted, A::Continue)
            }
            (
                S::InstanceAttached
                | S::InstanceReady
                | S::InstanceStopping
                | S::InstanceCleanupRequired,
                O::Absent,
            ) => decision(
                C::CleanupRequired,
                R::StaleVerifiedResourceObserved,
                A::CleanupVerifiedResource,
            ),
            (
                S::InstancePrepared
                | S::InstanceAttached
                | S::InstanceReady
                | S::InstanceStopping
                | S::InstanceCleanupRequired,
                O::NotInspected,
            ) => return Err(X::InspectionRequired),
            (
                S::InstancePrepared
                | S::InstanceAttached
                | S::InstanceReady
                | S::InstanceStopping
                | S::InstanceCleanupRequired,
                O::DifferentInstance | O::Unreachable | O::SameUnauthenticatedInstance,
            ) => decision(
                C::EffectUncertain,
                R::LiveIdentityCannotBeProven,
                A::AwaitResolution,
            ),
            (S::InstanceStopped, O::SameAuthenticatedInstance | O::SameUnauthenticatedInstance) => {
                return Err(X::TerminalStateHasLiveWork);
            }
            (S::InstanceStopped, O::Absent | O::NotApplicable)
            | (
                S::OperationTerminal
                | S::MessageAccepted
                | S::MessageDeadLetter
                | S::EffectCompleted,
                O::NotApplicable,
            ) => decision(C::Terminal, R::DurableOutcomeExists, A::None),
            (S::OperationQueued, O::NotApplicable) => decision(
                C::SafeToContinue,
                R::DurableWorkNotStarted,
                A::ScheduleExistingOperation,
            ),
            (
                S::OperationStarting
                | S::OperationRunning
                | S::OperationWaiting
                | S::OperationCancelling,
                O::NotApplicable,
            ) => decision(
                C::EffectUncertain,
                R::ExternalEffectMayHaveOccurred,
                A::AwaitResolution,
            ),
            (S::MessageQueued | S::MessageRetryScheduled | S::MessageLeased, O::NotApplicable) => {
                decision(
                    C::SafeToRedeliver,
                    R::ExactMessageIsDeduplicated,
                    A::RedeliverExactMessage,
                )
            }
            (S::MessageRetryDeferred | S::MessageLeaseActive, O::NotApplicable) => decision(
                C::SafeToContinue,
                R::EligibilityWindowNotReached,
                A::Continue,
            ),
            (
                S::MessageAcceptancePending | S::MessageAcceptanceUnknown | S::MessageUncertain,
                O::NotApplicable,
            ) => decision(
                C::EffectUncertain,
                R::ExternalEffectMayHaveOccurred,
                A::AwaitResolution,
            ),
            (S::EffectReserved | S::SessionOpen | S::ParticipantRegistered, O::NotApplicable) => {
                decision(C::SafeToContinue, R::DurableWorkNotStarted, A::Continue)
            }
            (S::EffectStartedRetryable, O::NotApplicable) => {
                decision(C::SafeToContinue, R::DeclaredEffectIsRetryable, A::Continue)
            }
            (S::EffectStartedUnsafe, O::NotApplicable) => decision(
                C::EffectUncertain,
                R::ExternalEffectMayHaveOccurred,
                A::AwaitResolution,
            ),
            _ => return Err(X::UnexpectedLiveObservation),
        };
        Ok(decision)
    }

    const fn decision(
        class: RecoveryClass,
        reason: RecoveryReason,
        action: RecoveryAction,
    ) -> RecoveryDecision {
        RecoveryDecision {
            class,
            reason,
            action,
        }
    }

    #[test]
    fn queued_child_uses_the_existing_operation_scheduler() {
        let decision = classify_recovery(
            RecoveryState::OperationQueued,
            LiveObservation::NotApplicable,
        )
        .unwrap();
        assert_eq!(decision.class, RecoveryClass::SafeToContinue);
        assert_eq!(decision.action, RecoveryAction::ScheduleExistingOperation);
        assert_eq!(decision.reason.as_str(), "durable_work_not_started");
    }

    #[test]
    fn uncertainty_never_silently_maps_to_safe() {
        for observation in [
            LiveObservation::DifferentInstance,
            LiveObservation::Unreachable,
            LiveObservation::SameUnauthenticatedInstance,
        ] {
            let decision = classify_recovery(RecoveryState::InstanceReady, observation).unwrap();
            assert_eq!(decision.class, RecoveryClass::EffectUncertain);
            assert_eq!(decision.action, RecoveryAction::AwaitResolution);
        }
        assert_eq!(
            classify_recovery(RecoveryState::InstanceReady, LiveObservation::NotInspected),
            Err(RecoveryContradiction::InspectionRequired)
        );
    }

    #[test]
    fn terminal_state_with_live_instance_is_a_contradiction() {
        assert_eq!(
            classify_recovery(
                RecoveryState::InstanceStopped,
                LiveObservation::SameAuthenticatedInstance
            ),
            Err(RecoveryContradiction::TerminalStateHasLiveWork)
        );
    }

    #[test]
    fn mailbox_recovery_only_redelivers_at_an_eligible_boundary() {
        for state in [
            RecoveryState::MessageRetryDeferred,
            RecoveryState::MessageLeaseActive,
        ] {
            let decision = classify_recovery(state, LiveObservation::NotApplicable).unwrap();
            assert_eq!(decision.class, RecoveryClass::SafeToContinue);
            assert_eq!(decision.action, RecoveryAction::Continue);
        }
        for state in [
            RecoveryState::MessageRetryScheduled,
            RecoveryState::MessageLeased,
        ] {
            let decision = classify_recovery(state, LiveObservation::NotApplicable).unwrap();
            assert_eq!(decision.class, RecoveryClass::SafeToRedeliver);
            assert_eq!(decision.action, RecoveryAction::RedeliverExactMessage);
        }
        for state in [
            RecoveryState::MessageAcceptancePending,
            RecoveryState::MessageAcceptanceUnknown,
        ] {
            let decision = classify_recovery(state, LiveObservation::NotApplicable).unwrap();
            assert_eq!(decision.class, RecoveryClass::EffectUncertain);
            assert_eq!(decision.action, RecoveryAction::AwaitResolution);
        }
    }

    #[test]
    fn table_explicitly_covers_every_state_observation_pair() {
        let states = [
            RecoveryState::SessionOpen,
            RecoveryState::ParticipantRegistered,
            RecoveryState::InstancePrepared,
            RecoveryState::InstanceAttached,
            RecoveryState::InstanceReady,
            RecoveryState::InstanceStopping,
            RecoveryState::InstanceCleanupRequired,
            RecoveryState::InstanceStopped,
            RecoveryState::OperationQueued,
            RecoveryState::OperationStarting,
            RecoveryState::OperationRunning,
            RecoveryState::OperationWaiting,
            RecoveryState::OperationCancelling,
            RecoveryState::OperationTerminal,
            RecoveryState::MessageQueued,
            RecoveryState::MessageRetryScheduled,
            RecoveryState::MessageRetryDeferred,
            RecoveryState::MessageLeased,
            RecoveryState::MessageLeaseActive,
            RecoveryState::MessageAcceptancePending,
            RecoveryState::MessageAcceptanceUnknown,
            RecoveryState::MessageAccepted,
            RecoveryState::MessageUncertain,
            RecoveryState::MessageDeadLetter,
            RecoveryState::EffectReserved,
            RecoveryState::EffectStartedRetryable,
            RecoveryState::EffectStartedUnsafe,
            RecoveryState::EffectCompleted,
        ];
        let observations = [
            LiveObservation::NotApplicable,
            LiveObservation::NotInspected,
            LiveObservation::Absent,
            LiveObservation::SameAuthenticatedInstance,
            LiveObservation::SameUnauthenticatedInstance,
            LiveObservation::DifferentInstance,
            LiveObservation::Unreachable,
        ];
        let mut pairs = 0;
        for state in states {
            for observation in observations {
                pairs += 1;
                assert_eq!(
                    classify_recovery(state, observation),
                    expected_recovery(state, observation),
                    "unexpected recovery semantics for {state:?}/{observation:?}"
                );
                if let Ok(decision) = classify_recovery(state, observation) {
                    if decision.class == RecoveryClass::EffectUncertain {
                        assert_eq!(decision.action, RecoveryAction::AwaitResolution);
                    }
                    if matches!(
                        observation,
                        LiveObservation::DifferentInstance
                            | LiveObservation::SameUnauthenticatedInstance
                            | LiveObservation::Unreachable
                    ) {
                        assert!(!matches!(
                            decision.class,
                            RecoveryClass::SafeToContinue | RecoveryClass::SafeToRedeliver
                        ));
                    }
                    if decision.class == RecoveryClass::Terminal {
                        assert_eq!(decision.action, RecoveryAction::None);
                    }
                }
            }
        }
        assert_eq!(pairs, states.len() * observations.len());
    }

    #[test]
    fn effect_proof_is_nonempty_nonzero_and_deserialization_revalidates() {
        assert_eq!(
            EffectProof::new(
                EffectProofKind::ExternalCommit,
                [0; 32],
                BoundedBytes::new(b"receipt".to_vec()).unwrap(),
            ),
            Err(EffectProofError::ZeroDigest)
        );
        assert_eq!(
            EffectProof::new(
                EffectProofKind::EffectAbsent,
                [1; 32],
                BoundedBytes::new(Vec::new()).unwrap(),
            ),
            Err(EffectProofError::EmptyEvidence)
        );
        let invalid = serde_json::json!({
            "kind": "external_commit",
            "digest": vec![0; 32],
            "evidence": [1]
        });
        assert!(serde_json::from_value::<EffectProof>(invalid).is_err());
    }
}
