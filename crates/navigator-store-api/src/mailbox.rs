use std::{future::Future, time::Duration};

use navigator_domain::{
    BoundedText, DeliveryAttemptId, FencingEpoch, HostId, InstanceId, LaunchAttemptId, MessageId,
    MessageKind, OperationId, ParticipantId, Revision, SemanticDigest, SessionId, Timestamp,
    ValidatedMessageEnvelope,
};

use crate::{CanonicalInput, MutableRequest, Mutation, RequestContext, StoreAction, StoreError};

pub const MAX_MESSAGE_BYTES: usize = navigator_domain::MAX_VALIDATED_MESSAGE_BYTES;
pub const MAX_MAILBOX_QUEUED_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_MAILBOX_QUEUED_MESSAGES: u64 = 4_096;
pub const MAX_MAILBOX_RESERVED_OUTCOMES: u64 = 64;
pub const MAX_MAILBOX_RESERVED_OUTCOME_BYTES: u64 = 64 * 1024;
pub const MAX_DELIVERY_ATTEMPTS: u32 = 32;
pub const MAX_DELIVERY_REASON_BYTES: usize = 1_024;
pub const MAX_SESSION_DELIVERY_WORK: usize = 128;

/// A mailbox head which may be leased now, paired with the destination's
/// unique unfinished operation. This is a hint only: leasing remains the
/// atomic authority and revalidates all mailbox invariants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionDeliveryWork {
    pub message: MessageSnapshot,
    pub operation: crate::OperationSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessagePriority {
    Control,
    Ordinary,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MessageCorrelation {
    pub operation_id: Option<OperationId>,
    pub in_reply_to: Option<MessageId>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeliveryLease {
    pub attempt_id: DeliveryAttemptId,
    pub owner: HostId,
    pub ownership_epoch: FencingEpoch,
    pub driver_ownership_epoch: FencingEpoch,
    pub driver_launch_attempt_id: LaunchAttemptId,
    pub instance_id: InstanceId,
    pub expires_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MessageDeliveryState {
    Queued,
    RetryScheduled {
        not_before: Timestamp,
    },
    Leased {
        lease: DeliveryLease,
    },
    AcceptancePending {
        lease: DeliveryLease,
    },
    AcceptanceUnknown {
        lease: DeliveryLease,
    },
    Accepted {
        attempt_id: DeliveryAttemptId,
        proof_digest: [u8; 32],
        accepted_at: Timestamp,
    },
    Uncertain {
        attempt_id: DeliveryAttemptId,
        reason: BoundedText<MAX_DELIVERY_REASON_BYTES>,
    },
    DeadLetter {
        reason: BoundedText<MAX_DELIVERY_REASON_BYTES>,
    },
}

impl MessageDeliveryState {
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Accepted { .. } | Self::Uncertain { .. } | Self::DeadLetter { .. }
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MessageSnapshot {
    pub session_id: SessionId,
    pub message_id: MessageId,
    pub source: ParticipantId,
    pub destination: ParticipantId,
    pub mailbox_sequence: u64,
    pub priority: MessagePriority,
    pub correlation: MessageCorrelation,
    pub envelope: ValidatedMessageEnvelope,
    pub attempt_count: u32,
    pub state: MessageDeliveryState,
    pub revision: Revision,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl MessageSnapshot {
    #[must_use]
    pub fn is_structurally_valid(&self) -> bool {
        if self.mailbox_sequence == 0
            || self.attempt_count > MAX_DELIVERY_ATTEMPTS
            || self.created_at > self.updated_at
            || self.priority != priority_for(self.envelope.kind())
        {
            return false;
        }
        match &self.state {
            MessageDeliveryState::Queued => self.attempt_count == 0,
            MessageDeliveryState::RetryScheduled { not_before } => {
                self.attempt_count > 0 && *not_before >= self.updated_at
            }
            MessageDeliveryState::Leased { lease }
            | MessageDeliveryState::AcceptancePending { lease }
            | MessageDeliveryState::AcceptanceUnknown { lease } => {
                self.attempt_count > 0 && lease.expires_at > self.updated_at
            }
            MessageDeliveryState::Accepted { accepted_at, .. } => {
                self.attempt_count > 0 && *accepted_at == self.updated_at
            }
            MessageDeliveryState::Uncertain { .. } => self.attempt_count > 0,
            // A queued message may be retired without fabricating an external delivery attempt
            // when its correlated operation becomes terminal in the same Store transaction.
            MessageDeliveryState::DeadLetter { .. } => true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnqueueMessage {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub message_id: MessageId,
    pub source: ParticipantId,
    pub destination: ParticipantId,
    pub correlation: MessageCorrelation,
    pub envelope: ValidatedMessageEnvelope,
}

impl MutableRequest for EnqueueMessage {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::EnqueueMessage
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.message_id.as_uuid().as_bytes());
        input.identity(*self.source.as_uuid().as_bytes());
        input.identity(*self.destination.as_uuid().as_bytes());
        input.bytes(match priority_for(self.envelope.kind()) {
            MessagePriority::Control => b"control",
            MessagePriority::Ordinary => b"ordinary",
        });
        match self.correlation.operation_id {
            Some(id) => {
                input.bytes(b"operation:some");
                input.identity(*id.as_uuid().as_bytes());
            }
            None => input.bytes(b"operation:none"),
        }
        match self.correlation.in_reply_to {
            Some(id) => {
                input.bytes(b"reply:some");
                input.identity(*id.as_uuid().as_bytes());
            }
            None => input.bytes(b"reply:none"),
        }
        input.bytes(self.envelope.as_bytes());
        input.finish(self.action())
    }
}

#[must_use]
pub const fn priority_for(kind: MessageKind) -> MessagePriority {
    match kind {
        MessageKind::OperationInput | MessageKind::Question => MessagePriority::Ordinary,
        MessageKind::OperationOutcome
        | MessageKind::CorrelatedFeedback
        | MessageKind::Control
        | MessageKind::ApprovalDecision => MessagePriority::Control,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseNextMessage {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub destination: ParticipantId,
    pub instance_id: InstanceId,
    pub driver_launch_attempt_id: LaunchAttemptId,
    pub proposed_attempt_id: DeliveryAttemptId,
    pub lease_duration: Duration,
}

impl MutableRequest for LeaseNextMessage {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::LeaseNextMessage
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.identity(*self.destination.as_uuid().as_bytes());
        input.identity(*self.instance_id.as_uuid().as_bytes());
        input.identity(*self.driver_launch_attempt_id.as_uuid().as_bytes());
        input.u64(
            self.lease_duration
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
        );
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryTransition {
    AcceptancePending,
    AcceptanceUnknown,
    RetryAfter {
        delay: Duration,
    },
    Accepted {
        proof_digest: [u8; 32],
    },
    Uncertain {
        reason: BoundedText<MAX_DELIVERY_REASON_BYTES>,
    },
    DeadLetter {
        reason: BoundedText<MAX_DELIVERY_REASON_BYTES>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionMessageDelivery {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub message_id: MessageId,
    pub attempt_id: DeliveryAttemptId,
    pub expected_revision: Revision,
    pub transition: DeliveryTransition,
}

impl MutableRequest for TransitionMessageDelivery {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::TransitionMessageDelivery
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.message_id.as_uuid().as_bytes());
        input.identity(*self.attempt_id.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.u64(self.expected_revision.get());
        match &self.transition {
            DeliveryTransition::AcceptancePending => input.bytes(b"acceptance_pending"),
            DeliveryTransition::AcceptanceUnknown => input.bytes(b"acceptance_unknown"),
            DeliveryTransition::RetryAfter { delay } => {
                input.bytes(b"retry_after");
                input.u64(delay.as_millis().try_into().unwrap_or(u64::MAX));
            }
            DeliveryTransition::Accepted { proof_digest } => {
                input.bytes(b"accepted");
                input.fixed(proof_digest);
            }
            DeliveryTransition::Uncertain { reason } => {
                input.bytes(b"uncertain");
                input.bytes(reason.as_str().as_bytes());
            }
            DeliveryTransition::DeadLetter { reason } => {
                input.bytes(b"dead_letter");
                input.bytes(reason.as_str().as_bytes());
            }
        }
        input.finish(self.action())
    }
}

pub trait MailboxStore: crate::SessionStore + Send + Sync {
    fn enqueue_message(
        &self,
        command: EnqueueMessage,
    ) -> impl Future<Output = Result<Mutation<MessageSnapshot>, StoreError>> + Send;
    fn lease_next_message(
        &self,
        command: LeaseNextMessage,
    ) -> impl Future<Output = Result<Mutation<Option<MessageSnapshot>>, StoreError>> + Send;
    fn transition_message_delivery(
        &self,
        command: TransitionMessageDelivery,
    ) -> impl Future<Output = Result<Mutation<MessageSnapshot>, StoreError>> + Send;
    fn load_message(
        &self,
        message_id: MessageId,
    ) -> impl Future<Output = Result<MessageSnapshot, StoreError>> + Send;
    fn load_mailbox(
        &self,
        destination: ParticipantId,
    ) -> impl Future<Output = Result<Vec<MessageSnapshot>, StoreError>> + Send;
    fn load_due_session_delivery_work(
        &self,
        session_id: SessionId,
        limit: usize,
    ) -> impl Future<Output = Result<Vec<SessionDeliveryWork>, StoreError>> + Send;
}
