use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ApprovalRequestId, ApprovalStatus, BoundedBytes, GrantId, MessageId, OperationId};

pub const MAX_VALIDATED_MESSAGE_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    OperationInput,
    Question,
    OperationOutcome,
    CorrelatedFeedback,
    Control,
    ApprovalDecision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlMessageKind {
    Cancel,
    Reminder,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackKind {
    Acknowledged,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicOperationOutcome {
    Succeeded,
    Failed,
    Cancelled,
    Blocked,
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessageBody {
    OperationInput {
        operation_id: OperationId,
        input_digest: [u8; 32],
    },
    CorrelatedFeedback {
        operation_id: OperationId,
        in_reply_to: MessageId,
        feedback: FeedbackKind,
    },
    Question {
        operation_id: OperationId,
        code: crate::Capability,
    },
    OperationOutcome {
        operation_id: OperationId,
        outcome: PublicOperationOutcome,
        result_digest: [u8; 32],
    },
    Control {
        operation_id: OperationId,
        command: ControlMessageKind,
    },
    ApprovalDecision {
        approval_id: ApprovalRequestId,
        operation_id: OperationId,
        status: ApprovalStatus,
        grant_id: Option<GrantId>,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub struct ValidatedMessageEnvelope {
    schema_version: u16,
    body: MessageBody,
    encoded: BoundedBytes<MAX_VALIDATED_MESSAGE_BYTES>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeWire {
    schema_version: u16,
    body: MessageBody,
}

impl Serialize for ValidatedMessageEnvelope {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        EnvelopeWire {
            schema_version: self.schema_version,
            body: self.body.clone(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ValidatedMessageEnvelope {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = EnvelopeWire::deserialize(deserializer)?;
        Self::new(wire.schema_version, wire.body).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MessageValidationError {
    #[error("message schema version is unsupported")]
    UnsupportedSchema,
    #[error("message payload is malformed or exceeds its bound")]
    InvalidPayload,
}

impl ValidatedMessageEnvelope {
    fn new(schema_version: u16, body: MessageBody) -> Result<Self, MessageValidationError> {
        if schema_version != 1 {
            return Err(MessageValidationError::UnsupportedSchema);
        }
        let encoded = serde_json::to_vec(&EnvelopeWire {
            schema_version,
            body: body.clone(),
        })
        .map_err(|_| MessageValidationError::InvalidPayload)?;
        Ok(Self {
            schema_version,
            body,
            encoded: BoundedBytes::new(encoded)
                .map_err(|_| MessageValidationError::InvalidPayload)?,
        })
    }

    #[must_use]
    pub fn operation_input(operation_id: OperationId, input_digest: [u8; 32]) -> Self {
        Self::new(
            1,
            MessageBody::OperationInput {
                operation_id,
                input_digest,
            },
        )
        .expect("closed operation input is bounded")
    }

    #[must_use]
    pub fn correlated_feedback(
        operation_id: OperationId,
        in_reply_to: MessageId,
        feedback: FeedbackKind,
    ) -> Self {
        Self::new(
            1,
            MessageBody::CorrelatedFeedback {
                operation_id,
                in_reply_to,
                feedback,
            },
        )
        .expect("closed feedback is bounded")
    }

    #[must_use]
    pub fn question(operation_id: OperationId, code: crate::Capability) -> Self {
        Self::new(1, MessageBody::Question { operation_id, code })
            .expect("closed question is bounded")
    }

    #[must_use]
    pub fn operation_outcome(
        operation_id: OperationId,
        outcome: PublicOperationOutcome,
        result_digest: [u8; 32],
    ) -> Self {
        Self::new(
            1,
            MessageBody::OperationOutcome {
                operation_id,
                outcome,
                result_digest,
            },
        )
        .expect("closed operation outcome is bounded")
    }

    #[must_use]
    pub fn control(operation_id: OperationId, command: ControlMessageKind) -> Self {
        Self::new(
            1,
            MessageBody::Control {
                operation_id,
                command,
            },
        )
        .expect("closed control is bounded")
    }

    #[must_use]
    pub fn approval_decision(
        approval_id: ApprovalRequestId,
        operation_id: OperationId,
        status: ApprovalStatus,
        grant_id: Option<GrantId>,
    ) -> Self {
        Self::new(
            1,
            MessageBody::ApprovalDecision {
                approval_id,
                operation_id,
                status,
                grant_id,
            },
        )
        .expect("closed approval decision is bounded")
    }

    #[must_use]
    pub const fn kind(&self) -> MessageKind {
        match self.body {
            MessageBody::OperationInput { .. } => MessageKind::OperationInput,
            MessageBody::Question { .. } => MessageKind::Question,
            MessageBody::OperationOutcome { .. } => MessageKind::OperationOutcome,
            MessageBody::CorrelatedFeedback { .. } => MessageKind::CorrelatedFeedback,
            MessageBody::Control { .. } => MessageKind::Control,
            MessageBody::ApprovalDecision { .. } => MessageKind::ApprovalDecision,
        }
    }
    #[must_use]
    pub const fn body(&self) -> &MessageBody {
        &self.body
    }
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.encoded.as_slice()
    }
}

impl fmt::Debug for ValidatedMessageEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedMessageEnvelope")
            .field("kind", &self.kind())
            .field("schema_version", &self.schema_version)
            .field("payload_bytes", &self.encoded.as_slice().len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn operation_id(value: u128) -> OperationId {
        OperationId::from_uuid(uuid::Uuid::from_u128(value)).unwrap()
    }

    #[test]
    fn closed_body_has_no_slot_for_secret_values() {
        let envelope = ValidatedMessageEnvelope::operation_input(operation_id(1), [7; 32]);
        let serialized = serde_json::to_vec(&envelope).unwrap();
        assert!(!serialized.windows(6).any(|part| part == b"secret"));
        assert!(!format!("{envelope:?}").contains("SENTINEL"));
        let injected = format!(
            r#"{{"schema_version":1,"body":{{"kind":"operation_input","operation_id":"{}","input_digest":[{}],"secret":"SENTINEL"}}}}"#,
            operation_id(1),
            std::iter::repeat_n("7", 32).collect::<Vec<_>>().join(",")
        );
        assert!(serde_json::from_str::<ValidatedMessageEnvelope>(&injected).is_err());
    }

    #[test]
    fn persisted_envelope_is_revalidated() {
        let envelope =
            ValidatedMessageEnvelope::control(operation_id(2), ControlMessageKind::Reminder);
        let mut encoded = serde_json::to_value(&envelope).unwrap();
        encoded["schema_version"] = serde_json::json!(2);
        assert!(serde_json::from_value::<ValidatedMessageEnvelope>(encoded).is_err());
    }
}
