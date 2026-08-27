use std::future::Future;

use navigator_domain::{
    AuthorityDecision, AuthorityProfile, Grant, GrantId, ParticipantId, ScopedCapability,
    SemanticDigest, SessionId, TemplateId, Timestamp, ValidatedTaskInput,
};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuthorityTemplatePolicy {
    pub template_id: TemplateId,
    pub allowed_parent_templates: std::collections::BTreeSet<TemplateId>,
    pub template: AuthorityProfile,
    pub relationship: AuthorityProfile,
    pub subject: AuthorityProfile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterAuthorityTemplatePolicy {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: navigator_domain::FencingEpoch,
    pub policy: AuthorityTemplatePolicy,
}

impl MutableRequest for RegisterAuthorityTemplatePolicy {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::RegisterAuthorityTemplatePolicy
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.bytes(&serde_json::to_vec(&self.policy).expect("validated policy serializes"));
        input.finish(self.action())
    }
}

use crate::{
    CanonicalInput, MutableRequest, Mutation, ParticipantSnapshot, RequestContext, StoreAction,
    StoreError,
};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuthorityPolicySnapshot {
    pub session_id: SessionId,
    pub participant_id: ParticipantId,
    pub session: AuthorityProfile,
    pub parent: AuthorityProfile,
    pub template: AuthorityProfile,
    pub relationship: AuthorityProfile,
    pub subject: AuthorityProfile,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PutAuthorityPolicy {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: navigator_domain::FencingEpoch,
    pub policy: AuthorityPolicySnapshot,
}

impl MutableRequest for PutAuthorityPolicy {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::PutAuthorityPolicy
    }
    fn digest(&self) -> SemanticDigest {
        let bytes = serde_json::to_vec(&self.policy).expect("validated policy serializes");
        let mut input = CanonicalInput::new();
        input.bytes(&bytes);
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GrantSnapshot {
    pub grant: Grant,
    pub single_use: bool,
    pub consumed_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueGrant {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: navigator_domain::FencingEpoch,
    pub grant: Grant,
    pub single_use: bool,
}

impl MutableRequest for IssueGrant {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::IssueGrant
    }
    fn digest(&self) -> SemanticDigest {
        let bytes = serde_json::to_vec(&(&self.grant, self.single_use))
            .expect("validated grant serializes");
        let mut input = CanonicalInput::new();
        input.bytes(&bytes);
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeGrant {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: navigator_domain::FencingEpoch,
    pub grant_id: GrantId,
}

impl MutableRequest for RevokeGrant {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::RevokeGrant
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.grant_id.as_uuid().as_bytes());
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckAuthorityEffect {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: navigator_domain::FencingEpoch,
    pub participant_id: ParticipantId,
    pub requested: ScopedCapability,
    pub grant_id: Option<GrantId>,
}

impl MutableRequest for CheckAuthorityEffect {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::CheckAuthorityEffect
    }
    fn digest(&self) -> SemanticDigest {
        let bytes = serde_json::to_vec(&(&self.participant_id, &self.requested, self.grant_id))
            .expect("validated authority request serializes");
        let mut input = CanonicalInput::new();
        input.bytes(&bytes);
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "outcome")]
pub enum AuthorityEffectOutcome {
    Allowed { decision: AuthorityDecisionWire },
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateAuthorizedChild {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: navigator_domain::FencingEpoch,
    pub parent_participant_id: ParticipantId,
    pub participant_id: ParticipantId,
    pub template_id: navigator_domain::TemplateId,
    pub expected_compatibility: navigator_domain::CompatibilityIdentity,
    pub requested: ScopedCapability,
    pub grant_id: Option<GrantId>,
    pub operation_id: navigator_domain::OperationId,
    pub input_message_id: navigator_domain::MessageId,
    pub input: ValidatedTaskInput,
}

impl MutableRequest for CreateAuthorizedChild {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::CreateAuthorizedChild
    }
    fn digest(&self) -> SemanticDigest {
        let bytes = serde_json::to_vec(&(
            self.parent_participant_id,
            self.template_id,
            self.expected_compatibility,
            &self.requested,
            self.grant_id,
            self.input.as_bytes(),
        ))
        .expect("validated authorized child serializes");
        let mut input = CanonicalInput::new();
        input.bytes(&bytes);
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AuthorizedChildOutcome {
    Allowed {
        participant: ParticipantSnapshot,
        policy: Box<AuthorityPolicySnapshot>,
        operation: Box<crate::OperationSnapshot>,
        decision: AuthorityDecisionWire,
    },
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AuthorityDecisionWire {
    pub authority: ScopedCapability,
    pub origins: std::collections::BTreeSet<navigator_domain::AuthorityOrigin>,
}

impl From<AuthorityDecision> for AuthorityDecisionWire {
    fn from(value: AuthorityDecision) -> Self {
        Self {
            authority: value.authority,
            origins: value.origins,
        }
    }
}

pub trait AuthorityStore: Send + Sync {
    fn register_authority_template_policy(
        &self,
        command: RegisterAuthorityTemplatePolicy,
    ) -> impl Future<Output = Result<Mutation<AuthorityTemplatePolicy>, StoreError>> + Send;
    fn put_authority_policy(
        &self,
        command: PutAuthorityPolicy,
    ) -> impl Future<Output = Result<Mutation<AuthorityPolicySnapshot>, StoreError>> + Send;
    fn issue_grant(
        &self,
        command: IssueGrant,
    ) -> impl Future<Output = Result<Mutation<GrantSnapshot>, StoreError>> + Send;
    fn revoke_grant(
        &self,
        command: RevokeGrant,
    ) -> impl Future<Output = Result<Mutation<GrantSnapshot>, StoreError>> + Send;
    fn check_authority_effect(
        &self,
        command: CheckAuthorityEffect,
    ) -> impl Future<Output = Result<Mutation<AuthorityEffectOutcome>, StoreError>> + Send;
    fn create_authorized_child(
        &self,
        command: CreateAuthorizedChild,
    ) -> impl Future<Output = Result<Mutation<AuthorizedChildOutcome>, StoreError>> + Send;
    fn load_authority_policy(
        &self,
        participant_id: ParticipantId,
    ) -> impl Future<Output = Result<AuthorityPolicySnapshot, StoreError>> + Send;
    fn load_grant(
        &self,
        grant_id: GrantId,
    ) -> impl Future<Output = Result<GrantSnapshot, StoreError>> + Send;
    fn load_authority_template_policy(
        &self,
        template_id: TemplateId,
    ) -> impl Future<Output = Result<AuthorityTemplatePolicy, StoreError>> + Send;
}
