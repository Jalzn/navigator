use std::{future::Future, time::Duration};

use navigator_domain::{
    BoundedBytes, BoundedText, Capability, EffectClass, EffectProofKind, EventPosition,
    FencingEpoch, GrantId, HostId, OperationId, ParticipantId, RecoveryClass, RequestId,
    ResolveUncertaintyDecision, Revision, SemanticDigest, SessionId, Timestamp,
};

use crate::{
    AuthorityDecisionWire, CanonicalInput, MutableRequest, Mutation, OperationSnapshot,
    RequestContext, StoreAction, StoreError,
};

pub const MAX_EFFECT_RESULT_BYTES: usize = 65_536;
pub const MAX_EFFECT_FAILURE_ID_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum EffectJournalPhase {
    Reserved,
    Started,
    Uncertain,
    Completed,
    Failed,
    RetryAuthorized,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum EffectTerminal {
    Completed(BoundedBytes<MAX_EFFECT_RESULT_BYTES>),
    Failed(BoundedText<MAX_EFFECT_FAILURE_ID_BYTES>),
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EffectJournalEntry {
    pub request_id: RequestId,
    pub session_id: SessionId,
    pub participant_id: ParticipantId,
    pub operation_id: OperationId,
    pub caller: HostId,
    pub action: Capability,
    pub semantic_digest: SemanticDigest,
    pub effect_class: EffectClass,
    pub resolution_contract: EffectResolutionContract,
    pub phase: EffectJournalPhase,
    pub owner_host: HostId,
    pub owner_epoch: FencingEpoch,
    pub lease_expires_at: Timestamp,
    pub terminal: Option<EffectTerminal>,
    pub revision: Revision,
}

impl EffectJournalEntry {
    #[must_use]
    pub const fn recovery_class(&self) -> RecoveryClass {
        match self.phase {
            EffectJournalPhase::Reserved | EffectJournalPhase::RetryAuthorized => {
                RecoveryClass::SafeToContinue
            }
            EffectJournalPhase::Started => match self.effect_class {
                EffectClass::ReadOnly | EffectClass::Idempotent => RecoveryClass::SafeToContinue,
                EffectClass::Transactional | EffectClass::NonIdempotent | EffectClass::Unknown => {
                    RecoveryClass::EffectUncertain
                }
            },
            EffectJournalPhase::Uncertain => RecoveryClass::EffectUncertain,
            EffectJournalPhase::Completed | EffectJournalPhase::Failed => RecoveryClass::Terminal,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveEffect {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub participant_id: ParticipantId,
    pub operation_id: OperationId,
    pub owner_epoch: FencingEpoch,
    pub action: Capability,
    pub semantic_digest: SemanticDigest,
    pub effect_class: EffectClass,
    pub resolution_contract: EffectResolutionContract,
    pub lease_duration: Duration,
}

impl ReserveEffect {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: RequestContext,
        session_id: SessionId,
        participant_id: ParticipantId,
        operation_id: OperationId,
        owner_epoch: FencingEpoch,
        action: Capability,
        canonical_input: &[u8],
        effect_class: EffectClass,
        resolution_contract: EffectResolutionContract,
        lease_duration: Duration,
    ) -> Self {
        let linked = serde_json::to_vec(&(
            participant_id,
            operation_id,
            &resolution_contract,
            canonical_input,
        ))
        .expect("effect reservation serializes");
        let semantic_digest = SemanticDigest::v1(&action, &linked);
        Self {
            context,
            session_id,
            participant_id,
            operation_id,
            owner_epoch,
            action,
            semantic_digest,
            effect_class,
            resolution_contract,
            lease_duration,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EffectResolutionContract {
    pub allow_confirm_completed: bool,
    pub allow_do_not_retry: bool,
    pub allow_retry_with_proof: bool,
    pub allowed_proof_kinds: Vec<EffectProofKind>,
}

impl EffectResolutionContract {
    #[must_use]
    pub fn conservative() -> Self {
        Self {
            allow_confirm_completed: true,
            allow_do_not_retry: true,
            allow_retry_with_proof: false,
            allowed_proof_kinds: vec![EffectProofKind::ExternalCommit],
        }
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        let mut kinds = self.allowed_proof_kinds.clone();
        kinds.sort_by_key(|kind| *kind as u8);
        kinds.dedup();
        (self.allow_confirm_completed || self.allow_do_not_retry || self.allow_retry_with_proof)
            && kinds.len() == self.allowed_proof_kinds.len()
            && kinds.len() <= 3
            && (!self.allow_confirm_completed
                || kinds.iter().copied().any(Self::is_completion_proof))
            && (!self.allow_retry_with_proof || kinds.contains(&EffectProofKind::EffectAbsent))
    }

    /// Completion proof establishes that an effect committed (or supplies an
    /// idempotency receipt). An absence proof can never establish completion.
    #[must_use]
    pub fn allows_completion_proof(&self, kind: EffectProofKind) -> bool {
        self.allow_confirm_completed
            && Self::is_completion_proof(kind)
            && self.allowed_proof_kinds.contains(&kind)
    }

    /// Retrying a non-idempotent effect is safe only when the declared proof
    /// establishes absence. Commit/receipt proofs have the opposite meaning.
    #[must_use]
    pub fn allows_retry_proof(&self, kind: EffectProofKind) -> bool {
        self.allow_retry_with_proof
            && kind == EffectProofKind::EffectAbsent
            && self.allowed_proof_kinds.contains(&kind)
    }

    #[must_use]
    pub fn allows_confirm_completed(&self) -> bool {
        self.allow_confirm_completed
            && self
                .allowed_proof_kinds
                .iter()
                .copied()
                .any(Self::is_completion_proof)
    }

    #[must_use]
    pub const fn allows_do_not_retry(&self) -> bool {
        self.allow_do_not_retry
    }

    #[must_use]
    pub fn allows_retry_with_proof(&self) -> bool {
        self.allow_retry_with_proof
            && self
                .allowed_proof_kinds
                .contains(&EffectProofKind::EffectAbsent)
    }

    const fn is_completion_proof(kind: EffectProofKind) -> bool {
        matches!(
            kind,
            EffectProofKind::ExternalCommit | EffectProofKind::IdempotencyReceipt
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectTransition {
    context: RequestContext,
    effect_request_id: RequestId,
    owner_epoch: FencingEpoch,
    expected_revision: Revision,
    resolution: Option<EffectResolution>,
    semantic_digest: SemanticDigest,
}

impl EffectTransition {
    #[must_use]
    pub fn start(
        context: RequestContext,
        effect_request_id: RequestId,
        owner_epoch: FencingEpoch,
        expected_revision: Revision,
    ) -> Self {
        Self::build(
            context,
            effect_request_id,
            owner_epoch,
            expected_revision,
            None,
        )
    }

    #[must_use]
    pub fn resolve(
        context: RequestContext,
        effect_request_id: RequestId,
        owner_epoch: FencingEpoch,
        expected_revision: Revision,
        resolution: EffectResolution,
    ) -> Self {
        Self::build(
            context,
            effect_request_id,
            owner_epoch,
            expected_revision,
            Some(resolution),
        )
    }

    fn build(
        context: RequestContext,
        effect_request_id: RequestId,
        owner_epoch: FencingEpoch,
        expected_revision: Revision,
        resolution: Option<EffectResolution>,
    ) -> Self {
        let action = Capability::new(if resolution.is_some() {
            "effect.resolve"
        } else {
            "effect.start"
        })
        .expect("valid journal capability");
        let canonical_input = transition_input(
            effect_request_id,
            owner_epoch,
            expected_revision,
            resolution.as_ref(),
        );
        Self {
            context,
            effect_request_id,
            owner_epoch,
            expected_revision,
            resolution,
            semantic_digest: SemanticDigest::v1(&action, &canonical_input),
        }
    }

    #[must_use]
    pub const fn context(&self) -> RequestContext {
        self.context
    }
    #[must_use]
    pub const fn effect_request_id(&self) -> RequestId {
        self.effect_request_id
    }
    #[must_use]
    pub const fn owner_epoch(&self) -> FencingEpoch {
        self.owner_epoch
    }
    #[must_use]
    pub const fn expected_revision(&self) -> Revision {
        self.expected_revision
    }
    #[must_use]
    pub const fn semantic_digest(&self) -> SemanticDigest {
        self.semantic_digest
    }
    #[must_use]
    pub const fn resolution(&self) -> Option<&EffectResolution> {
        self.resolution.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum EffectResolution {
    Completed(BoundedBytes<MAX_EFFECT_RESULT_BYTES>),
    Failed(BoundedText<MAX_EFFECT_FAILURE_ID_BYTES>),
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TakeoverEffect {
    pub context: RequestContext,
    pub effect_request_id: RequestId,
    pub owner_epoch: FencingEpoch,
    pub expected_revision: Revision,
    pub lease_duration: Duration,
    pub semantic_digest: SemanticDigest,
}

impl TakeoverEffect {
    #[must_use]
    pub fn new(
        context: RequestContext,
        effect_request_id: RequestId,
        owner_epoch: FencingEpoch,
        expected_revision: Revision,
        lease_duration: Duration,
    ) -> Self {
        let mut input = Vec::new();
        input.extend_from_slice(effect_request_id.as_uuid().as_bytes());
        input.extend_from_slice(&owner_epoch.get().to_be_bytes());
        input.extend_from_slice(&expected_revision.get().to_be_bytes());
        input.extend_from_slice(
            &u64::try_from(lease_duration.as_millis())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        let action = Capability::new("effect.takeover").expect("valid journal capability");
        Self {
            context,
            effect_request_id,
            owner_epoch,
            expected_revision,
            lease_duration,
            semantic_digest: SemanticDigest::v1(&action, &input),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveAuthorizedEffect {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner_epoch: FencingEpoch,
    pub participant_id: ParticipantId,
    pub grant_id: GrantId,
    pub effect_request_id: RequestId,
    pub expected_effect_revision: Revision,
    pub decision: ResolveUncertaintyDecision,
    /// Required when the effect belongs to a Tool invocation and the
    /// reconciliation decision is terminal. It binds the externally proven
    /// effect outcome to the durable Tool outcome in the same transaction.
    pub tool_terminal: Option<crate::ToolTerminal>,
}
impl MutableRequest for ResolveAuthorizedEffect {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::ResolveAuthorizedEffect
    }
    fn digest(&self) -> SemanticDigest {
        let bytes = serde_json::to_vec(&(
            self.session_id,
            self.participant_id,
            self.grant_id,
            self.effect_request_id,
            &self.decision,
            &self.tool_terminal,
        ))
        .expect("resolution serializes");
        let mut input = CanonicalInput::new();
        input.bytes(&bytes);
        input.finish(self.action())
    }
}
impl ResolveAuthorizedEffect {
    /// Binds a generic proof assertion to this exact effect identity and its
    /// immutable reservation semantics. This does not claim to verify the
    /// external system; authority policy decides whether the assertion is
    /// sufficient for the declared resolution contract.
    #[must_use]
    pub fn assertion_digest(&self, effect_semantic_digest: SemanticDigest) -> SemanticDigest {
        let proof_digest = match self.decision.resolution() {
            navigator_domain::UncertaintyResolution::ConfirmCompleted { proof }
            | navigator_domain::UncertaintyResolution::RetryWithEffectProof { proof } => {
                Some(proof.digest())
            }
            navigator_domain::UncertaintyResolution::DoNotRetry => None,
        };
        let mut input = Vec::new();
        input.extend_from_slice(self.effect_request_id.as_uuid().as_bytes());
        input.extend_from_slice(effect_semantic_digest.as_bytes());
        if let Some(digest) = proof_digest {
            input.extend_from_slice(digest);
        }
        SemanticDigest::v1(
            &Capability::new("effect.resolution.assertion.v1").expect("static capability"),
            &input,
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuthorizedEffectResolution {
    pub effect_entry: EffectJournalEntry,
    pub current_operation: OperationSnapshot,
    pub audit_event_position: EventPosition,
    pub authority_decision: AuthorityDecisionWire,
}

fn transition_input(
    id: RequestId,
    epoch: FencingEpoch,
    revision: Revision,
    resolution: Option<&EffectResolution>,
) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(id.as_uuid().as_bytes());
    value.extend_from_slice(&epoch.get().to_be_bytes());
    value.extend_from_slice(&revision.get().to_be_bytes());
    match resolution {
        None => value.push(0),
        Some(EffectResolution::Uncertain) => value.push(1),
        Some(EffectResolution::Completed(bytes)) => {
            value.push(2);
            value.extend_from_slice(&(bytes.as_slice().len() as u64).to_be_bytes());
            value.extend_from_slice(bytes.as_slice());
        }
        Some(EffectResolution::Failed(id)) => {
            value.push(3);
            value.extend_from_slice(&(id.as_str().len() as u64).to_be_bytes());
            value.extend_from_slice(id.as_str().as_bytes());
        }
    }
    value
}

pub trait EffectJournalStore: Send + Sync {
    fn reserve_effect(
        &self,
        command: ReserveEffect,
    ) -> impl Future<Output = Result<EffectJournalEntry, StoreError>> + Send;
    fn start_effect(
        &self,
        command: EffectTransition,
    ) -> impl Future<Output = Result<EffectJournalEntry, StoreError>> + Send;
    fn resolve_effect(
        &self,
        command: EffectTransition,
    ) -> impl Future<Output = Result<EffectJournalEntry, StoreError>> + Send;
    fn takeover_effect(
        &self,
        command: TakeoverEffect,
    ) -> impl Future<Output = Result<EffectJournalEntry, StoreError>> + Send;
    fn resolve_authorized_effect(
        &self,
        command: ResolveAuthorizedEffect,
    ) -> impl Future<Output = Result<Mutation<AuthorizedEffectResolution>, StoreError>> + Send;
    fn read_effect(
        &self,
        request_id: RequestId,
    ) -> impl Future<Output = Result<Option<EffectJournalEntry>, StoreError>> + Send;
    fn list_effects(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<Vec<EffectJournalEntry>, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_contract_rejects_actions_without_semantically_compatible_proof() {
        let impossible_confirm = EffectResolutionContract {
            allow_confirm_completed: true,
            allow_do_not_retry: false,
            allow_retry_with_proof: false,
            allowed_proof_kinds: vec![EffectProofKind::EffectAbsent],
        };
        assert!(!impossible_confirm.is_valid());
        assert!(!impossible_confirm.allows_confirm_completed());

        let impossible_retry = EffectResolutionContract {
            allow_confirm_completed: false,
            allow_do_not_retry: false,
            allow_retry_with_proof: true,
            allowed_proof_kinds: vec![EffectProofKind::ExternalCommit],
        };
        assert!(!impossible_retry.is_valid());
        assert!(!impossible_retry.allows_retry_with_proof());

        let complete = EffectResolutionContract {
            allow_confirm_completed: true,
            allow_do_not_retry: true,
            allow_retry_with_proof: true,
            allowed_proof_kinds: vec![
                EffectProofKind::ExternalCommit,
                EffectProofKind::EffectAbsent,
            ],
        };
        assert!(complete.is_valid());
        assert!(complete.allows_confirm_completed());
        assert!(complete.allows_do_not_retry());
        assert!(complete.allows_retry_with_proof());
    }
}
