use serde::{Deserialize, Serialize};

use crate::{ArtifactId, BoundedText, OperationId, ParticipantId, Revision, SessionId, Timestamp};

pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_MEDIA_TYPE_BYTES: usize = 255;
pub const ARTIFACT_SHA256_BYTES: usize = 32;

pub type ArtifactMediaType = BoundedText<MAX_MEDIA_TYPE_BYTES>;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactDigest([u8; ARTIFACT_SHA256_BYTES]);

impl ArtifactDigest {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ARTIFACT_SHA256_BYTES]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(self) -> [u8; ARTIFACT_SHA256_BYTES] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactState {
    Available,
    LogicallyDeleted,
    PhysicallyErased,
}

/// Immutable, authority-linkable reference carried in Tool results and Messages.
/// Storage locators deliberately remain outside this public value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ArtifactRefWire", into = "ArtifactRefWire")]
pub struct ArtifactRef {
    artifact_id: ArtifactId,
    session_id: SessionId,
    creator_participant_id: ParticipantId,
    creator_operation_id: OperationId,
    media_type: ArtifactMediaType,
    size: u64,
    digest: ArtifactDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ArtifactRefWire {
    artifact_id: ArtifactId,
    session_id: SessionId,
    creator_participant_id: ParticipantId,
    creator_operation_id: OperationId,
    media_type: ArtifactMediaType,
    size: u64,
    digest: ArtifactDigest,
}

impl ArtifactRef {
    pub fn new(
        artifact_id: ArtifactId,
        session_id: SessionId,
        creator_participant_id: ParticipantId,
        creator_operation_id: OperationId,
        media_type: ArtifactMediaType,
        size: u64,
        digest: ArtifactDigest,
    ) -> Result<Self, ArtifactRefError> {
        if size > MAX_ARTIFACT_BYTES {
            return Err(ArtifactRefError::TooLarge);
        }
        Ok(Self {
            artifact_id,
            session_id,
            creator_participant_id,
            creator_operation_id,
            media_type,
            size,
            digest,
        })
    }

    #[must_use]
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
    }
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
    #[must_use]
    pub const fn creator_participant_id(&self) -> ParticipantId {
        self.creator_participant_id
    }
    #[must_use]
    pub const fn creator_operation_id(&self) -> OperationId {
        self.creator_operation_id
    }
    #[must_use]
    pub fn media_type(&self) -> &ArtifactMediaType {
        &self.media_type
    }
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }
    #[must_use]
    pub const fn digest(&self) -> ArtifactDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ArtifactRefError {
    #[error("artifact reference exceeds the content size limit")]
    TooLarge,
}

impl TryFrom<ArtifactRefWire> for ArtifactRef {
    type Error = ArtifactRefError;
    fn try_from(value: ArtifactRefWire) -> Result<Self, Self::Error> {
        Self::new(
            value.artifact_id,
            value.session_id,
            value.creator_participant_id,
            value.creator_operation_id,
            value.media_type,
            value.size,
            value.digest,
        )
    }
}

impl From<ArtifactRef> for ArtifactRefWire {
    fn from(value: ArtifactRef) -> Self {
        Self {
            artifact_id: value.artifact_id,
            session_id: value.session_id,
            creator_participant_id: value.creator_participant_id,
            creator_operation_id: value.creator_operation_id,
            media_type: value.media_type,
            size: value.size,
            digest: value.digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactSnapshot {
    pub artifact_id: ArtifactId,
    pub session_id: SessionId,
    pub creator_participant_id: ParticipantId,
    pub creator_operation_id: OperationId,
    pub media_type: ArtifactMediaType,
    pub size: u64,
    pub digest: ArtifactDigest,
    pub locator: String,
    pub state: ArtifactState,
    pub revision: Revision,
    pub retention_until: Timestamp,
    pub created_at: Timestamp,
    pub deleted_at: Option<Timestamp>,
}

impl ArtifactSnapshot {
    #[must_use]
    pub fn structurally_valid(&self) -> bool {
        self.size <= MAX_ARTIFACT_BYTES
            && !self.locator.is_empty()
            && !self.locator.starts_with('/')
            && !self
                .locator
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            && match self.state {
                ArtifactState::Available => self.deleted_at.is_none(),
                ArtifactState::LogicallyDeleted | ArtifactState::PhysicallyErased => {
                    self.deleted_at.is_some()
                }
            }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn snapshot(locator: &str) -> ArtifactSnapshot {
        ArtifactSnapshot {
            artifact_id: ArtifactId::from_uuid(Uuid::from_u128(1)).unwrap(),
            session_id: SessionId::from_uuid(Uuid::from_u128(2)).unwrap(),
            creator_participant_id: ParticipantId::from_uuid(Uuid::from_u128(3)).unwrap(),
            creator_operation_id: OperationId::from_uuid(Uuid::from_u128(4)).unwrap(),
            media_type: ArtifactMediaType::new("application/octet-stream").unwrap(),
            size: 3,
            digest: ArtifactDigest::from_bytes([7; 32]),
            locator: locator.into(),
            state: ArtifactState::Available,
            revision: Revision::initial(),
            retention_until: Timestamp::new(10, 0).unwrap(),
            created_at: Timestamp::new(1, 0).unwrap(),
            deleted_at: None,
        }
    }

    #[test]
    fn locator_and_state_semantics_fail_closed() {
        assert!(snapshot("session/artifact.blob").structurally_valid());
        for invalid in ["", "/absolute", "../escape", "a/../escape", "a//b", "./a"] {
            assert!(!snapshot(invalid).structurally_valid(), "{invalid}");
        }
        let mut deleted = snapshot("session/artifact.blob");
        deleted.state = ArtifactState::LogicallyDeleted;
        assert!(!deleted.structurally_valid());
        deleted.deleted_at = Some(Timestamp::new(2, 0).unwrap());
        assert!(deleted.structurally_valid());
    }
}
