use std::future::Future;

use navigator_domain::{
    FeedbackKind, FencingEpoch, GrantId, MessageId, OperationId, ParticipantId, SemanticDigest,
    SessionId, ValidatedMessageEnvelope,
};

use crate::{
    CanonicalInput, MessageSnapshot, MutableRequest, Mutation, OperationSnapshot,
    ParticipantSnapshot, RequestContext, StoreAction, StoreError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedStatus {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub caller_participant_id: ParticipantId,
    pub target_participant_id: ParticipantId,
    pub operation_id: Option<OperationId>,
}

impl MutableRequest for AuthorizedStatus {
    fn context(&self) -> RequestContext {
        self.context
    }

    fn action(&self) -> StoreAction {
        StoreAction::CheckAuthorityEffect
    }

    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.caller_participant_id.as_uuid().as_bytes());
        input.identity(*self.target_participant_id.as_uuid().as_bytes());
        match self.operation_id {
            Some(operation_id) => {
                input.bytes(b"operation:some");
                input.identity(*operation_id.as_uuid().as_bytes());
            }
            None => input.bytes(b"operation:none"),
        }
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AuthorizedStatusOutcome {
    Allowed {
        participant: Box<ParticipantSnapshot>,
        operation: Option<Box<OperationSnapshot>>,
    },
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HierarchyEffect {
    QuestionUpward {
        message_id: MessageId,
        operation_id: OperationId,
        delivered_message_id: MessageId,
        code: navigator_domain::Capability,
        grant_id: Option<GrantId>,
    },
    Send {
        message_id: MessageId,
        destination: ParticipantId,
        envelope: ValidatedMessageEnvelope,
        grant_id: Option<GrantId>,
    },
    CancelChild {
        message_id: MessageId,
        child_id: ParticipantId,
        operation_id: OperationId,
        grant_id: Option<GrantId>,
    },
    ResumeChild {
        message_id: MessageId,
        child_id: ParticipantId,
        operation_id: OperationId,
        in_reply_to: MessageId,
        feedback: FeedbackKind,
        grant_id: Option<GrantId>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplyHierarchyEffect {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub caller_participant_id: ParticipantId,
    pub effect: HierarchyEffect,
}

impl MutableRequest for ApplyHierarchyEffect {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::ApplyHierarchyEffect
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.caller_participant_id.as_uuid().as_bytes());
        match &self.effect {
            HierarchyEffect::QuestionUpward {
                operation_id,
                delivered_message_id,
                code,
                grant_id,
                ..
            } => {
                input.bytes(b"question");
                input.identity(*operation_id.as_uuid().as_bytes());
                input.identity(*delivered_message_id.as_uuid().as_bytes());
                input.bytes(code.as_str().as_bytes());
                optional_grant(&mut input, *grant_id);
            }
            HierarchyEffect::Send {
                destination,
                envelope,
                grant_id,
                ..
            } => {
                input.bytes(b"send");
                input.identity(*destination.as_uuid().as_bytes());
                input.bytes(envelope.as_bytes());
                optional_grant(&mut input, *grant_id);
            }
            HierarchyEffect::CancelChild {
                child_id,
                operation_id,
                grant_id,
                ..
            } => {
                input.bytes(b"cancel");
                input.identity(*child_id.as_uuid().as_bytes());
                input.identity(*operation_id.as_uuid().as_bytes());
                optional_grant(&mut input, *grant_id);
            }
            HierarchyEffect::ResumeChild {
                child_id,
                operation_id,
                in_reply_to,
                feedback,
                grant_id,
                ..
            } => {
                input.bytes(b"resume");
                input.identity(*child_id.as_uuid().as_bytes());
                input.identity(*operation_id.as_uuid().as_bytes());
                input.identity(*in_reply_to.as_uuid().as_bytes());
                input.bytes(match feedback {
                    FeedbackKind::Acknowledged => b"ack",
                    FeedbackKind::Rejected => b"reject",
                });
                optional_grant(&mut input, *grant_id);
            }
        }
        input.finish(self.action())
    }
}

fn optional_grant(input: &mut CanonicalInput, value: Option<GrantId>) {
    match value {
        Some(id) => {
            input.bytes(b"grant:some");
            input.identity(*id.as_uuid().as_bytes());
        }
        None => input.bytes(b"grant:none"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum HierarchyEffectOutcome {
    Allowed {
        message: Box<MessageSnapshot>,
        operation: Option<Box<OperationSnapshot>>,
    },
    Denied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelSubtree {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub root_participant_id: ParticipantId,
}

impl MutableRequest for CancelSubtree {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::CancelSubtree
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.root_participant_id.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CancellationRecord {
    pub operation: OperationSnapshot,
    pub notification: Option<MessageSnapshot>,
}

impl CancellationRecord {
    #[must_use]
    pub fn cleanup_confirmed(&self) -> bool {
        self.notification.as_ref().map_or_else(
            || self.operation.state.is_terminal(),
            |message| matches!(message.state, crate::MessageDeliveryState::Accepted { .. }),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CancelSubtreeOutcome {
    pub root_participant_id: ParticipantId,
    pub records: Vec<CancellationRecord>,
}

pub trait HierarchyStore: Send + Sync {
    fn apply_hierarchy_effect(
        &self,
        command: ApplyHierarchyEffect,
    ) -> impl Future<Output = Result<Mutation<HierarchyEffectOutcome>, StoreError>> + Send;
    fn authorized_status(
        &self,
        query: AuthorizedStatus,
    ) -> impl Future<Output = Result<Mutation<AuthorizedStatusOutcome>, StoreError>> + Send;
    fn cancel_subtree(
        &self,
        command: CancelSubtree,
    ) -> impl Future<Output = Result<Mutation<CancelSubtreeOutcome>, StoreError>> + Send;
    /// Reads the current cancellation evidence without issuing another cancel
    /// notification. Intended for lifecycle reconciliation after a driver has
    /// already terminated.
    fn inspect_subtree_cancellation(
        &self,
        _session_id: SessionId,
        _root_participant_id: ParticipantId,
    ) -> impl Future<Output = Result<CancelSubtreeOutcome, StoreError>> + Send {
        async { Err(StoreError::Unavailable) }
    }
    fn cancellation_requested(
        &self,
        participant_id: ParticipantId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}
