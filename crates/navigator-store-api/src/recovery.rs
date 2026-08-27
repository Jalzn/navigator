use std::future::Future;

use navigator_domain::{
    FencingEpoch, LaunchAttemptId, LiveObservation, MessageId, OperationId, ParticipantId,
    RecoveryDecision, RecoveryState, RequestId, SessionId, Timestamp,
};

use crate::{
    EffectJournalEntry, LaunchSnapshot, MessageSnapshot, OperationSnapshot, ParticipantSnapshot,
    RequestContext, StoreError,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryInventory {
    pub session_id: SessionId,
    /// Fenced store time used to decide retry/lease eligibility.
    pub snapshot_at: Timestamp,
    pub launches: Vec<LaunchSnapshot>,
    pub participants: Vec<ParticipantSnapshot>,
    pub operations: Vec<OperationSnapshot>,
    pub messages: Vec<MessageSnapshot>,
    pub effects: Vec<EffectJournalEntry>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum RecoveryEventEntity {
    Session(SessionId),
    Participant(ParticipantId),
    Instance(LaunchAttemptId),
    Operation(OperationId),
    Message(MessageId),
    Effect(RequestId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryEventClassification {
    pub entity: RecoveryEventEntity,
    pub state: RecoveryState,
    pub observation: LiveObservation,
    pub decision: RecoveryDecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordRecoveryClassifications {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub classifications: Vec<RecoveryEventClassification>,
}

pub const MAX_RECOVERY_CLASSIFICATIONS: usize = 16_384;

impl RecordRecoveryClassifications {
    #[must_use]
    pub fn is_structurally_valid(&self) -> bool {
        if self.classifications.is_empty()
            || self.classifications.len() > MAX_RECOVERY_CLASSIFICATIONS
        {
            return false;
        }
        let mut previous = None;
        for classification in &self.classifications {
            if navigator_domain::classify_recovery(classification.state, classification.observation)
                != Ok(classification.decision)
            {
                return false;
            }
            if matches!(classification.entity, RecoveryEventEntity::Session(id) if id != self.session_id)
            {
                return false;
            }
            let key = entity_key(classification.entity);
            if previous.is_some_and(|value| value >= key) {
                return false;
            }
            previous = Some(key);
        }
        true
    }
}

fn entity_key(entity: RecoveryEventEntity) -> (u8, [u8; 16]) {
    match entity {
        RecoveryEventEntity::Session(id) => (1, *id.as_uuid().as_bytes()),
        RecoveryEventEntity::Participant(id) => (2, *id.as_uuid().as_bytes()),
        RecoveryEventEntity::Instance(id) => (3, *id.as_uuid().as_bytes()),
        RecoveryEventEntity::Operation(id) => (4, *id.as_uuid().as_bytes()),
        RecoveryEventEntity::Message(id) => (5, *id.as_uuid().as_bytes()),
        RecoveryEventEntity::Effect(id) => (6, *id.as_uuid().as_bytes()),
    }
}

pub trait RecoveryStore: Send + Sync {
    /// Returns one stable, identity-ordered snapshot after validating current
    /// fenced ownership. Terminal rows are omitted except where needed to
    /// expose a durable contradiction.
    fn load_recovery_inventory(
        &self,
        session_id: SessionId,
        owner: navigator_domain::HostId,
        epoch: FencingEpoch,
    ) -> impl Future<Output = Result<RecoveryInventory, StoreError>> + Send;

    /// Commits the complete classification set and its Event atomically.
    fn record_recovery_classifications(
        &self,
        command: RecordRecoveryClassifications,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use navigator_domain::{LiveObservation, RecoveryState, classify_recovery};
    use uuid::Uuid;

    fn session(value: u128) -> SessionId {
        SessionId::from_uuid(Uuid::from_u128(value)).unwrap()
    }

    #[test]
    fn classification_batch_rejects_duplicates_reordering_and_cross_session_rows() {
        let decision =
            classify_recovery(RecoveryState::SessionOpen, LiveObservation::NotApplicable).unwrap();
        let row = RecoveryEventClassification {
            entity: RecoveryEventEntity::Session(session(1)),
            state: RecoveryState::SessionOpen,
            observation: LiveObservation::NotApplicable,
            decision,
        };
        let base = RecordRecoveryClassifications {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(2)).unwrap(),
                navigator_domain::HostId::from_uuid(Uuid::from_u128(3)).unwrap(),
            ),
            session_id: session(1),
            epoch: FencingEpoch::new(1).unwrap(),
            classifications: vec![row],
        };
        assert!(base.is_structurally_valid());
        let mut duplicate = base.clone();
        duplicate.classifications.push(row);
        assert!(!duplicate.is_structurally_valid());
        let participant_decision = classify_recovery(
            RecoveryState::ParticipantRegistered,
            LiveObservation::NotApplicable,
        )
        .unwrap();
        let mut reordered = base.clone();
        reordered.classifications.insert(
            0,
            RecoveryEventClassification {
                entity: RecoveryEventEntity::Participant(
                    ParticipantId::from_uuid(Uuid::from_u128(8)).unwrap(),
                ),
                state: RecoveryState::ParticipantRegistered,
                observation: LiveObservation::NotApplicable,
                decision: participant_decision,
            },
        );
        assert!(!reordered.is_structurally_valid());
        let mut cross_session = base;
        cross_session.classifications[0].entity = RecoveryEventEntity::Session(session(9));
        assert!(!cross_session.is_structurally_valid());
    }

    #[test]
    fn classification_batch_accepts_maximum_and_rejects_max_plus_one() {
        let decision = classify_recovery(
            RecoveryState::ParticipantRegistered,
            LiveObservation::NotApplicable,
        )
        .unwrap();
        let classifications = (1..=MAX_RECOVERY_CLASSIFICATIONS)
            .map(|value| RecoveryEventClassification {
                entity: RecoveryEventEntity::Participant(
                    ParticipantId::from_uuid(Uuid::from_u128(value as u128)).unwrap(),
                ),
                state: RecoveryState::ParticipantRegistered,
                observation: LiveObservation::NotApplicable,
                decision,
            })
            .collect::<Vec<_>>();
        let mut command = RecordRecoveryClassifications {
            context: RequestContext::new(
                RequestId::from_uuid(Uuid::from_u128(20_000)).unwrap(),
                navigator_domain::HostId::from_uuid(Uuid::from_u128(20_001)).unwrap(),
            ),
            session_id: session(20_002),
            epoch: FencingEpoch::new(1).unwrap(),
            classifications,
        };
        assert!(command.is_structurally_valid());
        command.classifications.push(RecoveryEventClassification {
            entity: RecoveryEventEntity::Participant(
                ParticipantId::from_uuid(Uuid::from_u128(20_000)).unwrap(),
            ),
            state: RecoveryState::ParticipantRegistered,
            observation: LiveObservation::NotApplicable,
            decision,
        });
        assert!(!command.is_structurally_valid());
    }
}
