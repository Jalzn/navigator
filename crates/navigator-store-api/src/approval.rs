use std::future::Future;

use navigator_domain::{
    ApprovalEffectIntent, ApprovalGrant, ApprovalRequest, ApprovalRequestId, ApprovalResource,
    ApprovalSummary, Capability, DeliveryAttemptId, FencingEpoch, GrantId, MessageId, OperationId,
    ParticipantId, RequestId, Revision, SemanticDigest, SessionId, TerminalApprovalEffectPhase,
    Timestamp,
};

use crate::{Mutation, RequestContext, StoreError};

fn digest(name: &str, value: &impl serde::Serialize) -> SemanticDigest {
    SemanticDigest::v1(
        &Capability::new(name).expect("static approval action"),
        &serde_json::to_vec(value).expect("validated approval command serializes"),
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestApproval {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner_epoch: FencingEpoch,
    pub approval_id: ApprovalRequestId,
    pub requester_id: ParticipantId,
    pub operation_id: OperationId,
    pub source_message_id: MessageId,
    pub source_delivery_attempt_id: DeliveryAttemptId,
    pub capability: Capability,
    pub resource: ApprovalResource,
    pub summary: ApprovalSummary,
    pub expires_at: Timestamp,
}

impl RequestApproval {
    #[must_use]
    pub fn digest(&self) -> SemanticDigest {
        digest(
            "approval.request",
            &(
                self.context.request_id(),
                self.context.caller(),
                self.session_id,
                self.owner_epoch,
                self.approval_id,
                self.requester_id,
                self.operation_id,
                self.source_message_id,
                self.source_delivery_attempt_id,
                &self.capability,
                &self.resource,
                &self.summary,
                self.expires_at,
            ),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApproveRequest {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner_epoch: FencingEpoch,
    pub approval_id: ApprovalRequestId,
    pub expected_revision: Revision,
    pub grant_id: GrantId,
    pub grant_expires_at: Timestamp,
    pub max_uses: u32,
}

impl ApproveRequest {
    pub fn validate_against(
        &self,
        request: &ApprovalRequest,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        if request.id != self.approval_id
            || request.session_id != self.session_id
            || request.status != navigator_domain::ApprovalStatus::Pending
            || request.revision != self.expected_revision
            || now >= request.expires_at
            || self.grant_expires_at > request.expires_at
            || self.grant_expires_at <= now
            || self.max_uses == 0
            || self.max_uses > navigator_domain::MAX_APPROVAL_USES
        {
            Err(StoreError::Invalid)
        } else {
            Ok(())
        }
    }

    #[must_use]
    pub fn digest(&self) -> SemanticDigest {
        digest(
            "approval.approve",
            &(
                self.context.request_id(),
                self.context.caller(),
                self.session_id,
                self.owner_epoch,
                self.approval_id,
                self.expected_revision,
                self.grant_id,
                self.grant_expires_at,
                self.max_uses,
            ),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ApprovedRequest {
    pub request: ApprovalRequest,
    pub grant: ApprovalGrant,
}

impl ApprovedRequest {
    pub fn validate(self) -> Result<Self, StoreError> {
        if self.request.clone().validate().is_ok()
            && self.grant.clone().validate().is_ok()
            && self.request.status == navigator_domain::ApprovalStatus::Granted
            && self.request.grant_id == Some(self.grant.id)
            && self.grant.request_id == self.request.id
            && self.grant.session_id == self.request.session_id
            && self.grant.subject_id == self.request.requester_id
            && self.grant.operation_id == self.request.operation_id
            && self.grant.capability == self.request.capability
            && self.grant.resource_hash == self.request.resource.digest()
            && self.grant.max_uses > 0
            && self.grant.expires_at <= self.request.expires_at
            && self.grant.created_at == self.request.decided_at.expect("Granted validated above")
            && self.grant.issued_by == navigator_domain::ApprovalDecisionSource::TrustedConsumer
        {
            Ok(self)
        } else {
            Err(StoreError::Invalid)
        }
    }
}

impl<'de> serde::Deserialize<'de> for ApprovedRequest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Wire {
            request: ApprovalRequest,
            grant: ApprovalGrant,
        }
        let wire = <Wire as serde::Deserialize>::deserialize(d)?;
        Self {
            request: wire.request,
            grant: wire.grant,
        }
        .validate()
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DenyRequest {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner_epoch: FencingEpoch,
    pub approval_id: ApprovalRequestId,
    pub expected_revision: Revision,
}

impl DenyRequest {
    pub fn validate_against(
        &self,
        request: &ApprovalRequest,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        if request.id == self.approval_id
            && request.session_id == self.session_id
            && request.status == navigator_domain::ApprovalStatus::Pending
            && request.revision == self.expected_revision
            && now < request.expires_at
        {
            Ok(())
        } else {
            Err(StoreError::Invalid)
        }
    }

    #[must_use]
    pub fn digest(&self) -> SemanticDigest {
        digest(
            "approval.deny",
            &(
                self.context.request_id(),
                self.context.caller(),
                self.session_id,
                self.owner_epoch,
                self.approval_id,
                self.expected_revision,
            ),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpireApproval {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner_epoch: FencingEpoch,
    pub approval_id: ApprovalRequestId,
    pub expected_revision: Revision,
}

impl ExpireApproval {
    /// Row existence, operation liveness, and ownership fencing remain Store checks.
    pub fn validate_against(
        &self,
        request: &ApprovalRequest,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        if request.id == self.approval_id
            && request.session_id == self.session_id
            && request.revision == self.expected_revision
            && now >= request.expires_at
            && request.status == navigator_domain::ApprovalStatus::Pending
        {
            Ok(())
        } else {
            Err(StoreError::Invalid)
        }
    }

    #[must_use]
    pub fn digest(&self) -> SemanticDigest {
        digest(
            "approval.expire",
            &(
                self.context.request_id(),
                self.context.caller(),
                self.session_id,
                self.owner_epoch,
                self.approval_id,
                self.expected_revision,
            ),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevokeApprovalGrant {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner_epoch: FencingEpoch,
    pub grant_id: GrantId,
    pub expected_revision: Revision,
}

impl RevokeApprovalGrant {
    /// Row existence, operation liveness, and ownership fencing remain Store checks.
    pub fn validate_against(
        &self,
        request: &ApprovalRequest,
        grant: &ApprovalGrant,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        if grant.id == self.grant_id
            && grant.session_id == self.session_id
            && grant.request_id == request.id
            && request.session_id == self.session_id
            && request.grant_id == Some(grant.id)
            && request.status == navigator_domain::ApprovalStatus::Granted
            && request.requester_id == grant.subject_id
            && request.operation_id == grant.operation_id
            && request.capability == grant.capability
            && request.resource.digest() == grant.resource_hash
            && grant.revision == self.expected_revision
            && grant.revoked_at.is_none()
            && grant.used_count < grant.max_uses
            && now < grant.expires_at
        {
            Ok(())
        } else {
            Err(StoreError::Invalid)
        }
    }

    #[must_use]
    pub fn digest(&self) -> SemanticDigest {
        digest(
            "approval.revoke",
            &(
                self.context.request_id(),
                self.context.caller(),
                self.session_id,
                self.owner_epoch,
                self.grant_id,
                self.expected_revision,
            ),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumeApprovalGrant {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner_epoch: FencingEpoch,
    pub grant_id: GrantId,
    pub expected_revision: Revision,
    pub effect_id: RequestId,
    pub subject_id: ParticipantId,
    pub operation_id: OperationId,
    pub capability: Capability,
    pub resource_hash: SemanticDigest,
}

impl ConsumeApprovalGrant {
    /// Validates immutable Approval bindings and grant usability only. The Store
    /// must additionally prove row existence, operation liveness, and ownership
    /// fencing in the same transaction that reserves the effect.
    pub fn validate_against(
        &self,
        grant: &ApprovalGrant,
        request: &ApprovalRequest,
        now: Timestamp,
    ) -> Result<navigator_domain::ApprovalStatus, StoreError> {
        if grant.id == self.grant_id
            && grant.session_id == self.session_id
            && grant.request_id == request.id
            && request.session_id == self.session_id
            && request.grant_id == Some(grant.id)
            && request.requester_id == grant.subject_id
            && request.operation_id == grant.operation_id
            && request.capability == grant.capability
            && request.resource.digest() == grant.resource_hash
            && request.status == navigator_domain::ApprovalStatus::Granted
            && grant.subject_id == self.subject_id
            && grant.operation_id == self.operation_id
            && grant.capability == self.capability
            && grant.resource_hash == self.resource_hash
            && grant.revision == self.expected_revision
            && grant.is_usable_at(now)
        {
            Ok(if grant.used_count + 1 == grant.max_uses {
                navigator_domain::ApprovalStatus::Consumed
            } else {
                navigator_domain::ApprovalStatus::Granted
            })
        } else {
            Err(StoreError::Invalid)
        }
    }

    #[must_use]
    pub fn digest(&self) -> SemanticDigest {
        digest(
            "approval.consume",
            &(
                self.context.request_id(),
                self.context.caller(),
                self.session_id,
                self.owner_epoch,
                self.grant_id,
                self.expected_revision,
                self.effect_id,
                self.subject_id,
                self.operation_id,
                &self.capability,
                self.resource_hash,
            ),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct ConsumedApprovalGrant {
    pub grant: ApprovalGrant,
    pub effect: ApprovalEffectIntent,
}

impl ConsumedApprovalGrant {
    pub fn validate(self) -> Result<Self, StoreError> {
        if self.grant.clone().validate().is_ok()
            && self.effect.clone().validate().is_ok()
            && self.grant.used_count > 0
            && self.effect.session_id == self.grant.session_id
            && self.effect.grant_id == self.grant.id
            && self.effect.subject_id == self.grant.subject_id
            && self.effect.operation_id == self.grant.operation_id
            && self.effect.capability == self.grant.capability
            && self.effect.resource_hash == self.grant.resource_hash
            && self.effect.phase == navigator_domain::ApprovalEffectPhase::Reserved
        {
            Ok(self)
        } else {
            Err(StoreError::Invalid)
        }
    }
}

impl<'de> serde::Deserialize<'de> for ConsumedApprovalGrant {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Wire {
            grant: ApprovalGrant,
            effect: ApprovalEffectIntent,
        }
        let wire = <Wire as serde::Deserialize>::deserialize(d)?;
        Self {
            grant: wire.grant,
            effect: wire.effect,
        }
        .validate()
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishApprovalEffect {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub owner_epoch: FencingEpoch,
    pub effect_id: RequestId,
    pub expected_revision: Revision,
    pub phase: TerminalApprovalEffectPhase,
}

impl FinishApprovalEffect {
    /// Row existence, operation liveness, and ownership fencing remain Store checks.
    pub fn validate_against(&self, effect: &ApprovalEffectIntent) -> Result<(), StoreError> {
        if effect.effect_id == self.effect_id
            && effect.session_id == self.session_id
            && effect.revision == self.expected_revision
            && effect.phase == navigator_domain::ApprovalEffectPhase::Reserved
            && effect.finished_at.is_none()
        {
            Ok(())
        } else {
            Err(StoreError::Invalid)
        }
    }

    #[must_use]
    pub fn digest(&self) -> SemanticDigest {
        digest(
            "approval.effect.finish",
            &(
                self.context.request_id(),
                self.context.caller(),
                self.session_id,
                self.owner_epoch,
                self.effect_id,
                self.expected_revision,
                self.phase,
            ),
        )
    }
}

pub trait ApprovalStore: Send + Sync {
    /// Recovery index for durable approval effects which were reserved before
    /// their backend outcome was reconciled.
    fn list_reserved_approval_effects(
        &self,
        _session_id: SessionId,
    ) -> impl Future<Output = Result<Vec<ApprovalEffectIntent>, StoreError>> + Send {
        async { Err(StoreError::Unavailable) }
    }
    fn request_approval(
        &self,
        command: RequestApproval,
    ) -> impl Future<Output = Result<Mutation<ApprovalRequest>, StoreError>> + Send;
    fn approve_request(
        &self,
        command: ApproveRequest,
    ) -> impl Future<Output = Result<Mutation<ApprovedRequest>, StoreError>> + Send;
    fn deny_request(
        &self,
        command: DenyRequest,
    ) -> impl Future<Output = Result<Mutation<ApprovalRequest>, StoreError>> + Send;
    fn expire_approval(
        &self,
        command: ExpireApproval,
    ) -> impl Future<Output = Result<Mutation<ApprovalRequest>, StoreError>> + Send;
    fn revoke_approval_grant(
        &self,
        command: RevokeApprovalGrant,
    ) -> impl Future<Output = Result<Mutation<ApprovalGrant>, StoreError>> + Send;
    fn consume_approval_grant(
        &self,
        command: ConsumeApprovalGrant,
    ) -> impl Future<Output = Result<Mutation<ConsumedApprovalGrant>, StoreError>> + Send;
    fn finish_approval_effect(
        &self,
        command: FinishApprovalEffect,
    ) -> impl Future<Output = Result<Mutation<ApprovalEffectIntent>, StoreError>> + Send;
    fn load_approval_request(
        &self,
        approval_id: ApprovalRequestId,
    ) -> impl Future<Output = Result<ApprovalRequest, StoreError>> + Send;
    fn load_approval_grant(
        &self,
        grant_id: GrantId,
    ) -> impl Future<Output = Result<ApprovalGrant, StoreError>> + Send;
    fn load_approval_effect(
        &self,
        effect_id: RequestId,
    ) -> impl Future<Output = Result<ApprovalEffectIntent, StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use navigator_domain::HostId;
    use uuid::Uuid;

    fn id<T, E: std::fmt::Debug>(value: u128, make: impl FnOnce(Uuid) -> Result<T, E>) -> T {
        make(Uuid::from_u128(value)).unwrap()
    }

    #[test]
    fn consume_digest_binds_every_authority_field() {
        let command = ConsumeApprovalGrant {
            context: RequestContext::new(id(1, RequestId::from_uuid), id(2, HostId::from_uuid)),
            session_id: id(3, SessionId::from_uuid),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            grant_id: id(4, GrantId::from_uuid),
            expected_revision: Revision::initial(),
            effect_id: id(5, RequestId::from_uuid),
            subject_id: id(6, ParticipantId::from_uuid),
            operation_id: id(7, OperationId::from_uuid),
            capability: Capability::new("repository.publish").unwrap(),
            resource_hash: SemanticDigest::v1(
                &Capability::new("approval.resource.v1").unwrap(),
                b"resource",
            ),
        };
        let baseline = command.digest();
        let mut mutants = Vec::new();
        let mut value = command.clone();
        value.context =
            RequestContext::new(id(70, RequestId::from_uuid), id(71, HostId::from_uuid));
        mutants.push(value);
        let mut value = command.clone();
        value.session_id = id(72, SessionId::from_uuid);
        mutants.push(value);
        let mut value = command.clone();
        value.owner_epoch = FencingEpoch::new(2).unwrap();
        mutants.push(value);
        let mut value = command.clone();
        value.expected_revision = Revision::new(2).unwrap();
        mutants.push(value);
        let mut value = command.clone();
        value.effect_id = id(73, RequestId::from_uuid);
        mutants.push(value);
        let mut value = command.clone();
        value.grant_id = id(8, GrantId::from_uuid);
        mutants.push(value);
        let mut value = command.clone();
        value.subject_id = id(9, ParticipantId::from_uuid);
        mutants.push(value);
        let mut value = command.clone();
        value.operation_id = id(10, OperationId::from_uuid);
        mutants.push(value);
        let mut value = command.clone();
        value.capability = Capability::new("repository.delete").unwrap();
        mutants.push(value);
        let mut value = command.clone();
        value.resource_hash =
            SemanticDigest::v1(&Capability::new("approval.resource.v1").unwrap(), b"other");
        mutants.push(value);
        assert!(mutants.into_iter().all(|value| value.digest() != baseline));
    }

    fn approved_fixture() -> ApprovedRequest {
        let grant_id = id(14, GrantId::from_uuid);
        let resource = ApprovalResource::new(br#"{"branch":"main"}"#).unwrap();
        let request = ApprovalRequest {
            id: id(10, ApprovalRequestId::from_uuid),
            session_id: id(11, SessionId::from_uuid),
            requester_id: id(12, ParticipantId::from_uuid),
            operation_id: id(13, OperationId::from_uuid),
            source_message_id: id(15, MessageId::from_uuid),
            source_delivery_attempt_id: id(16, DeliveryAttemptId::from_uuid),
            coordinator_id: id(17, ParticipantId::from_uuid),
            capability: Capability::new("repository.publish").unwrap(),
            resource: resource.clone(),
            summary: ApprovalSummary::new("publish main").unwrap(),
            status: navigator_domain::ApprovalStatus::Granted,
            expires_at: Timestamp::new(200, 0).unwrap(),
            grant_id: Some(grant_id),
            decision_source: Some(navigator_domain::ApprovalDecisionSource::TrustedConsumer),
            created_at: Timestamp::new(100, 0).unwrap(),
            decided_at: Some(Timestamp::new(110, 0).unwrap()),
            revision: Revision::new(2).unwrap(),
        };
        let grant = ApprovalGrant {
            id: grant_id,
            request_id: request.id,
            session_id: request.session_id,
            subject_id: request.requester_id,
            operation_id: request.operation_id,
            capability: request.capability.clone(),
            resource_hash: resource.digest(),
            issued_by: navigator_domain::ApprovalDecisionSource::TrustedConsumer,
            max_uses: 2,
            used_count: 1,
            expires_at: Timestamp::new(190, 0).unwrap(),
            revoked_at: None,
            created_at: Timestamp::new(110, 0).unwrap(),
            revision: Revision::initial(),
        };
        ApprovedRequest { request, grant }
    }

    fn rejects_composite<T>(value: T, validate: impl FnOnce(T) -> Result<T, StoreError>)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone,
    {
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(validate(value).is_err());
        assert!(serde_json::from_slice::<T>(&bytes).is_err());
    }

    #[test]
    fn approved_and_consumed_relations_fail_closed_on_every_binding() {
        let base = approved_fixture();
        let mut approved = Vec::new();
        let mut v = base.clone();
        v.grant.request_id = id(30, ApprovalRequestId::from_uuid);
        approved.push(v);
        let mut v = base.clone();
        v.grant.session_id = id(31, SessionId::from_uuid);
        approved.push(v);
        let mut v = base.clone();
        v.grant.subject_id = id(32, ParticipantId::from_uuid);
        approved.push(v);
        let mut v = base.clone();
        v.grant.operation_id = id(33, OperationId::from_uuid);
        approved.push(v);
        let mut v = base.clone();
        v.grant.capability = Capability::new("repository.delete").unwrap();
        approved.push(v);
        let mut v = base.clone();
        v.grant.resource_hash =
            SemanticDigest::v1(&Capability::new("approval.resource.v1").unwrap(), b"other");
        approved.push(v);
        let mut v = base.clone();
        v.grant.expires_at = Timestamp::new(201, 0).unwrap();
        approved.push(v);
        let mut v = base.clone();
        v.request.status = navigator_domain::ApprovalStatus::Consumed;
        approved.push(v);
        let mut v = base.clone();
        v.request.decided_at = Some(v.request.expires_at);
        approved.push(v);
        let mut v = base.clone();
        v.grant.used_count = v.grant.max_uses + 1;
        approved.push(v);
        let mut v = base.clone();
        v.grant.max_uses = 0;
        approved.push(v);
        let mut v = base.clone();
        v.grant.created_at = Timestamp::new(111, 0).unwrap();
        approved.push(v);
        for value in approved {
            rejects_composite(value, ApprovedRequest::validate);
        }
        let effect = ApprovalEffectIntent {
            effect_id: id(40, RequestId::from_uuid),
            session_id: base.grant.session_id,
            grant_id: base.grant.id,
            subject_id: base.grant.subject_id,
            operation_id: base.grant.operation_id,
            capability: base.grant.capability.clone(),
            resource_hash: base.grant.resource_hash,
            phase: navigator_domain::ApprovalEffectPhase::Reserved,
            created_at: Timestamp::new(120, 0).unwrap(),
            finished_at: None,
            revision: Revision::initial(),
        };
        let consumed = ConsumedApprovalGrant {
            grant: base.grant,
            effect,
        };
        let mut cases = Vec::new();
        let mut v = consumed.clone();
        v.effect.session_id = id(41, SessionId::from_uuid);
        cases.push(v);
        let mut v = consumed.clone();
        v.effect.grant_id = id(42, GrantId::from_uuid);
        cases.push(v);
        let mut v = consumed.clone();
        v.effect.subject_id = id(43, ParticipantId::from_uuid);
        cases.push(v);
        let mut v = consumed.clone();
        v.effect.operation_id = id(44, OperationId::from_uuid);
        cases.push(v);
        let mut v = consumed.clone();
        v.effect.capability = Capability::new("repository.delete").unwrap();
        cases.push(v);
        let mut v = consumed.clone();
        v.effect.resource_hash =
            SemanticDigest::v1(&Capability::new("approval.resource.v1").unwrap(), b"other");
        cases.push(v);
        let mut v = consumed.clone();
        v.grant.used_count = 0;
        cases.push(v);
        let mut v = consumed;
        v.effect.phase = navigator_domain::ApprovalEffectPhase::Succeeded;
        v.effect.finished_at = Some(Timestamp::new(130, 0).unwrap());
        cases.push(v);
        for value in cases {
            rejects_composite(value, ConsumedApprovalGrant::validate);
        }
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the seven command digest matrices are deliberately explicit"
    )]
    fn every_command_digest_binds_context_session_epoch_and_action_fields() {
        let approved = approved_fixture();
        let context = RequestContext::new(id(50, RequestId::from_uuid), id(51, HostId::from_uuid));
        let other_context =
            RequestContext::new(id(52, RequestId::from_uuid), id(53, HostId::from_uuid));
        let request = RequestApproval {
            context,
            session_id: approved.request.session_id,
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id: approved.request.id,
            requester_id: approved.request.requester_id,
            operation_id: approved.request.operation_id,
            source_message_id: approved.request.source_message_id,
            source_delivery_attempt_id: approved.request.source_delivery_attempt_id,
            capability: approved.request.capability.clone(),
            resource: approved.request.resource.clone(),
            summary: approved.request.summary.clone(),
            expires_at: approved.request.expires_at,
        };
        let mut request_mutants = Vec::new();
        let mut v = request.clone();
        v.context = other_context;
        request_mutants.push(v);
        let mut v = request.clone();
        v.session_id = id(54, SessionId::from_uuid);
        request_mutants.push(v);
        let mut v = request.clone();
        v.owner_epoch = FencingEpoch::new(2).unwrap();
        request_mutants.push(v);
        let mut v = request.clone();
        v.approval_id = id(55, ApprovalRequestId::from_uuid);
        request_mutants.push(v);
        let mut v = request.clone();
        v.requester_id = id(56, ParticipantId::from_uuid);
        request_mutants.push(v);
        let mut v = request.clone();
        v.operation_id = id(57, OperationId::from_uuid);
        request_mutants.push(v);
        let mut v = request.clone();
        v.source_message_id = id(58, MessageId::from_uuid);
        request_mutants.push(v);
        let mut v = request.clone();
        v.source_delivery_attempt_id = id(59, DeliveryAttemptId::from_uuid);
        request_mutants.push(v);
        let mut v = request.clone();
        v.capability = Capability::new("repository.delete").unwrap();
        request_mutants.push(v);
        let mut v = request.clone();
        v.resource = ApprovalResource::new(br#"{"branch":"other"}"#).unwrap();
        request_mutants.push(v);
        let mut v = request.clone();
        v.summary = ApprovalSummary::new("other").unwrap();
        request_mutants.push(v);
        let mut v = request.clone();
        v.expires_at = Timestamp::new(199, 0).unwrap();
        request_mutants.push(v);
        assert!(
            request_mutants
                .into_iter()
                .all(|v| v.digest() != request.digest())
        );
        let approve = ApproveRequest {
            context,
            session_id: request.session_id,
            owner_epoch: request.owner_epoch,
            approval_id: request.approval_id,
            expected_revision: Revision::initial(),
            grant_id: approved.grant.id,
            grant_expires_at: approved.grant.expires_at,
            max_uses: 2,
        };
        let mut variants = Vec::new();
        let mut v = approve.clone();
        v.context = other_context;
        variants.push(v);
        let mut v = approve.clone();
        v.session_id = id(60, SessionId::from_uuid);
        variants.push(v);
        let mut v = approve.clone();
        v.owner_epoch = FencingEpoch::new(2).unwrap();
        variants.push(v);
        let mut v = approve.clone();
        v.approval_id = id(61, ApprovalRequestId::from_uuid);
        variants.push(v);
        let mut v = approve.clone();
        v.expected_revision = Revision::new(2).unwrap();
        variants.push(v);
        let mut v = approve.clone();
        v.grant_id = id(62, GrantId::from_uuid);
        variants.push(v);
        let mut v = approve.clone();
        v.grant_expires_at = Timestamp::new(189, 0).unwrap();
        variants.push(v);
        let mut v = approve.clone();
        v.max_uses = 3;
        variants.push(v);
        assert!(variants.into_iter().all(|v| v.digest() != approve.digest()));
        let deny = DenyRequest {
            context,
            session_id: request.session_id,
            owner_epoch: request.owner_epoch,
            approval_id: request.approval_id,
            expected_revision: Revision::initial(),
        };
        let expire = ExpireApproval {
            context,
            session_id: deny.session_id,
            owner_epoch: deny.owner_epoch,
            approval_id: deny.approval_id,
            expected_revision: deny.expected_revision,
        };
        assert_ne!(deny.digest(), {
            let mut v = deny.clone();
            v.context = other_context;
            v.digest()
        });
        assert_ne!(deny.digest(), {
            let mut v = deny.clone();
            v.session_id = id(63, SessionId::from_uuid);
            v.digest()
        });
        assert_ne!(deny.digest(), {
            let mut v = deny.clone();
            v.owner_epoch = FencingEpoch::new(2).unwrap();
            v.digest()
        });
        assert_ne!(deny.digest(), {
            let mut v = deny.clone();
            v.approval_id = id(64, ApprovalRequestId::from_uuid);
            v.digest()
        });
        assert_ne!(deny.digest(), {
            let mut v = deny.clone();
            v.expected_revision = Revision::new(2).unwrap();
            v.digest()
        });
        assert_ne!(expire.digest(), {
            let mut v = expire.clone();
            v.context = other_context;
            v.digest()
        });
        assert_ne!(expire.digest(), {
            let mut v = expire.clone();
            v.expected_revision = Revision::new(2).unwrap();
            v.digest()
        });
        assert_ne!(expire.digest(), {
            let mut v = expire.clone();
            v.session_id = id(74, SessionId::from_uuid);
            v.digest()
        });
        assert_ne!(expire.digest(), {
            let mut v = expire.clone();
            v.owner_epoch = FencingEpoch::new(2).unwrap();
            v.digest()
        });
        assert_ne!(expire.digest(), {
            let mut v = expire.clone();
            v.approval_id = id(75, ApprovalRequestId::from_uuid);
            v.digest()
        });
        let revoke = RevokeApprovalGrant {
            context,
            session_id: request.session_id,
            owner_epoch: request.owner_epoch,
            grant_id: approved.grant.id,
            expected_revision: Revision::initial(),
        };
        assert_ne!(revoke.digest(), {
            let mut v = revoke.clone();
            v.context = other_context;
            v.digest()
        });
        assert_ne!(revoke.digest(), {
            let mut v = revoke.clone();
            v.session_id = id(65, SessionId::from_uuid);
            v.digest()
        });
        assert_ne!(revoke.digest(), {
            let mut v = revoke.clone();
            v.owner_epoch = FencingEpoch::new(2).unwrap();
            v.digest()
        });
        assert_ne!(revoke.digest(), {
            let mut v = revoke.clone();
            v.grant_id = id(66, GrantId::from_uuid);
            v.digest()
        });
        assert_ne!(revoke.digest(), {
            let mut v = revoke.clone();
            v.expected_revision = Revision::new(2).unwrap();
            v.digest()
        });
        let finish = FinishApprovalEffect {
            context,
            session_id: request.session_id,
            owner_epoch: request.owner_epoch,
            effect_id: id(67, RequestId::from_uuid),
            expected_revision: Revision::initial(),
            phase: TerminalApprovalEffectPhase::Succeeded,
        };
        assert_ne!(finish.digest(), {
            let mut v = finish.clone();
            v.context = other_context;
            v.digest()
        });
        assert_ne!(finish.digest(), {
            let mut v = finish.clone();
            v.session_id = id(68, SessionId::from_uuid);
            v.digest()
        });
        assert_ne!(finish.digest(), {
            let mut v = finish.clone();
            v.owner_epoch = FencingEpoch::new(2).unwrap();
            v.digest()
        });
        assert_ne!(finish.digest(), {
            let mut v = finish.clone();
            v.effect_id = id(69, RequestId::from_uuid);
            v.digest()
        });
        assert_ne!(finish.digest(), {
            let mut v = finish.clone();
            v.expected_revision = Revision::new(2).unwrap();
            v.digest()
        });
        assert_ne!(finish.digest(), {
            let mut v = finish.clone();
            v.phase = TerminalApprovalEffectPhase::Failed;
            v.digest()
        });
    }
}
