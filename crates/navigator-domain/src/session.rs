use core::fmt;

use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    BoundError, BoundedBytes, BoundedText, EventId, FencingEpoch, HostId, RequestId, Revision,
    SessionId, TemplateId,
};

pub const MAX_CONSUMER_KEY_BYTES: usize = 256;
pub const MAX_EVENT_TYPE_BYTES: usize = 128;
pub const MAX_EVENT_DATA_BYTES: usize = 65_536;
pub const MAX_SESSION_TEMPLATES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CompatibilityIdentity([u8; 32]);

impl CompatibilityIdentity {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn digest(canonical_compatibility_input: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"navigator.compatibility.v1\0");
        digest.update(canonical_compatibility_input);
        Self(digest.finalize().into())
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TemplateCompatibilityBinding {
    pub template_id: TemplateId,
    pub compatibility: CompatibilityIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionCompatibilityManifest {
    configuration_identity: CompatibilityIdentity,
    templates: Vec<TemplateCompatibilityBinding>,
    compatibility: CompatibilityIdentity,
}

impl SessionCompatibilityManifest {
    pub fn new(
        configuration_identity: CompatibilityIdentity,
        mut templates: Vec<TemplateCompatibilityBinding>,
    ) -> Result<Self, SessionDomainError> {
        templates.sort_unstable_by_key(|binding| binding.template_id);
        if templates.is_empty()
            || templates.len() > MAX_SESSION_TEMPLATES
            || templates
                .windows(2)
                .any(|pair| pair[0].template_id == pair[1].template_id)
        {
            return Err(SessionDomainError::InvalidCompatibilityManifest);
        }
        let mut canonical = Vec::with_capacity(40 + templates.len() * 48);
        canonical.extend_from_slice(b"navigator.session.compatibility-manifest.v1\0");
        canonical.extend_from_slice(configuration_identity.as_bytes());
        canonical.extend_from_slice(&(templates.len() as u64).to_be_bytes());
        for binding in &templates {
            canonical.extend_from_slice(binding.template_id.as_uuid().as_bytes());
            canonical.extend_from_slice(binding.compatibility.as_bytes());
        }
        let compatibility = CompatibilityIdentity::digest(&canonical);
        Ok(Self {
            configuration_identity,
            templates,
            compatibility,
        })
    }

    #[must_use]
    pub const fn configuration_identity(&self) -> CompatibilityIdentity {
        self.configuration_identity
    }

    #[must_use]
    pub fn templates(&self) -> &[TemplateCompatibilityBinding] {
        &self.templates
    }

    #[must_use]
    pub const fn compatibility(&self) -> CompatibilityIdentity {
        self.compatibility
    }

    #[must_use]
    pub fn contains(&self, template_id: TemplateId, compatibility: CompatibilityIdentity) -> bool {
        self.templates
            .binary_search_by_key(&template_id, |binding| binding.template_id)
            .is_ok_and(|index| self.templates[index].compatibility == compatibility)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConsumerKey(BoundedText<MAX_CONSUMER_KEY_BYTES>);

impl ConsumerKey {
    pub fn new(value: impl Into<String>) -> Result<Self, BoundError> {
        BoundedText::new(value).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Open,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct EventPosition(u64);

impl EventPosition {
    pub const fn new(value: u64) -> Result<Self, SessionDomainError> {
        if value == 0 {
            Err(SessionDomainError::ZeroEventPosition)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn initial() -> Self {
        Self(1)
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EventSchemaVersion(u16);

impl EventSchemaVersion {
    pub const V1: Self = Self(1);

    pub const fn new(value: u16) -> Result<Self, SessionDomainError> {
        if value == 0 {
            Err(SessionDomainError::ZeroEventSchemaVersion)
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for EventSchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u16::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for EventPosition {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Timestamp {
    unix_seconds: i64,
    nanoseconds: u32,
}

impl Timestamp {
    pub fn new(unix_seconds: i64, nanoseconds: u32) -> Result<Self, SessionDomainError> {
        if nanoseconds >= 1_000_000_000 {
            return Err(SessionDomainError::InvalidTimestamp);
        }
        OffsetDateTime::from_unix_timestamp(unix_seconds)
            .and_then(|value| value.replace_nanosecond(nanoseconds))
            .map_err(|_| SessionDomainError::InvalidTimestamp)?;
        Ok(Self {
            unix_seconds,
            nanoseconds,
        })
    }

    #[must_use]
    pub fn from_datetime(value: OffsetDateTime) -> Self {
        Self {
            unix_seconds: value.unix_timestamp(),
            nanoseconds: value.nanosecond(),
        }
    }

    pub fn to_datetime(self) -> Result<OffsetDateTime, SessionDomainError> {
        OffsetDateTime::from_unix_timestamp(self.unix_seconds)
            .and_then(|value| value.replace_nanosecond(self.nanoseconds))
            .map_err(|_| SessionDomainError::InvalidTimestamp)
    }

    #[must_use]
    pub const fn unix_seconds(self) -> i64 {
        self.unix_seconds
    }

    #[must_use]
    pub const fn nanoseconds(self) -> u32 {
        self.nanoseconds
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            unix_seconds: i64,
            nanoseconds: u32,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.unix_seconds, wire.nanoseconds).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionSnapshot {
    id: SessionId,
    consumer_key: ConsumerKey,
    compatibility: CompatibilityIdentity,
    status: SessionStatus,
    revision: Revision,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl SessionSnapshot {
    pub fn new(
        id: SessionId,
        consumer_key: ConsumerKey,
        compatibility: CompatibilityIdentity,
        status: SessionStatus,
        revision: Revision,
        created_at: Timestamp,
        updated_at: Timestamp,
    ) -> Result<Self, SessionDomainError> {
        if updated_at < created_at {
            return Err(SessionDomainError::TimestampRegression);
        }
        if status == SessionStatus::Closed && revision == Revision::initial() {
            return Err(SessionDomainError::InvalidClosedRevision);
        }
        Ok(Self {
            id,
            consumer_key,
            compatibility,
            status,
            revision,
            created_at,
            updated_at,
        })
    }

    pub fn close(&mut self, at: Timestamp) -> Result<(), SessionDomainError> {
        if self.status == SessionStatus::Closed {
            return Err(SessionDomainError::AlreadyClosed);
        }
        if at < self.updated_at {
            return Err(SessionDomainError::TimestampRegression);
        }
        self.revision = self
            .revision
            .next()
            .ok_or(SessionDomainError::RevisionExhausted)?;
        self.status = SessionStatus::Closed;
        self.updated_at = at;
        Ok(())
    }

    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }
    #[must_use]
    pub fn consumer_key(&self) -> &ConsumerKey {
        &self.consumer_key
    }
    #[must_use]
    pub const fn compatibility(&self) -> CompatibilityIdentity {
        self.compatibility
    }
    #[must_use]
    pub const fn status(&self) -> SessionStatus {
        self.status
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    #[must_use]
    pub const fn created_at(&self) -> Timestamp {
        self.created_at
    }
    #[must_use]
    pub const fn updated_at(&self) -> Timestamp {
        self.updated_at
    }
}

impl<'de> Deserialize<'de> for SessionSnapshot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            id: SessionId,
            consumer_key: ConsumerKey,
            compatibility: CompatibilityIdentity,
            status: SessionStatus,
            revision: Revision,
            created_at: Timestamp,
            updated_at: Timestamp,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.id,
            wire.consumer_key,
            wire.compatibility,
            wire.status,
            wire.revision,
            wire.created_at,
            wire.updated_at,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OwnershipSnapshot {
    Unowned,
    Owned {
        host_id: HostId,
        epoch: FencingEpoch,
        expires_at: Timestamp,
    },
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventType(BoundedText<MAX_EVENT_TYPE_BYTES>);

impl EventType {
    pub fn new(value: impl Into<String>) -> Result<Self, BoundError> {
        BoundedText::new(value).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RedactedEventData(BoundedBytes<MAX_EVENT_DATA_BYTES>);

impl RedactedEventData {
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, BoundError> {
        BoundedBytes::new(value).map(Self)
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for RedactedEventData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RedactedEventData(<redacted>)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionEvent {
    id: EventId,
    session_id: SessionId,
    position: EventPosition,
    revision: Revision,
    event_type: EventType,
    schema_version: EventSchemaVersion,
    related_request_id: Option<RequestId>,
    data: RedactedEventData,
    occurred_at: Timestamp,
}

impl SessionEvent {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: EventId,
        session_id: SessionId,
        position: EventPosition,
        revision: Revision,
        event_type: EventType,
        schema_version: EventSchemaVersion,
        related_request_id: Option<RequestId>,
        data: RedactedEventData,
        occurred_at: Timestamp,
    ) -> Self {
        Self {
            id,
            session_id,
            position,
            revision,
            event_type,
            schema_version,
            related_request_id,
            data,
            occurred_at,
        }
    }

    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
    #[must_use]
    pub const fn position(&self) -> EventPosition {
        self.position
    }
    #[must_use]
    pub const fn revision(&self) -> Revision {
        self.revision
    }
    #[must_use]
    pub fn event_type(&self) -> &EventType {
        &self.event_type
    }
    #[must_use]
    pub const fn schema_version(&self) -> EventSchemaVersion {
        self.schema_version
    }
    #[must_use]
    pub const fn related_request_id(&self) -> Option<RequestId> {
        self.related_request_id
    }
    #[must_use]
    pub fn data(&self) -> &RedactedEventData {
        &self.data
    }
    #[must_use]
    pub const fn occurred_at(&self) -> Timestamp {
        self.occurred_at
    }
}

impl<'de> Deserialize<'de> for SessionEvent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            id: EventId,
            session_id: SessionId,
            position: EventPosition,
            revision: Revision,
            event_type: EventType,
            schema_version: EventSchemaVersion,
            related_request_id: Option<RequestId>,
            data: RedactedEventData,
            occurred_at: Timestamp,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self::new(
            wire.id,
            wire.session_id,
            wire.position,
            wire.revision,
            wire.event_type,
            wire.schema_version,
            wire.related_request_id,
            wire.data,
            wire.occurred_at,
        ))
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionDomainError {
    #[error("session compatibility manifest is empty, duplicated, or exceeds capacity")]
    InvalidCompatibilityManifest,
    #[error("event position must be greater than zero")]
    ZeroEventPosition,
    #[error("event schema version must be greater than zero")]
    ZeroEventSchemaVersion,
    #[error("timestamp is invalid")]
    InvalidTimestamp,
    #[error("timestamp cannot move backwards")]
    TimestampRegression,
    #[error("session is already closed")]
    AlreadyClosed,
    #[error("session revision is exhausted")]
    RevisionExhausted,
    #[error("a closed session must include a closing revision")]
    InvalidClosedRevision,
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn session() -> SessionSnapshot {
        SessionSnapshot::new(
            SessionId::from_uuid(Uuid::from_u128(1)).unwrap(),
            ConsumerKey::new("consumer-a").unwrap(),
            CompatibilityIdentity::from_bytes([7; 32]),
            SessionStatus::Open,
            Revision::initial(),
            Timestamp::new(100, 0).unwrap(),
            Timestamp::new(100, 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_session_snapshot_is_stable() {
        assert_eq!(
            serde_json::to_string(&session()).unwrap(),
            concat!(
                r#"{"id":"00000000-0000-0000-0000-000000000001","consumer_key":"consumer-a","compatibility":["#,
                "7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7",
                r#"],"status":"open","revision":1,"created_at":{"unix_seconds":100,"nanoseconds":0},"updated_at":{"unix_seconds":100,"nanoseconds":0}}"#
            )
        );
    }

    #[test]
    fn invalid_session_decode_cannot_bypass_invariants() {
        let mut value = serde_json::to_value(session()).unwrap();
        value["updated_at"]["unix_seconds"] = 99.into();
        assert!(serde_json::from_value::<SessionSnapshot>(value).is_err());
        assert!(serde_json::from_str::<EventPosition>("0").is_err());
        assert!(
            serde_json::from_str::<Timestamp>(r#"{"unix_seconds":0,"nanoseconds":1000000000}"#)
                .is_err()
        );
        assert!(Timestamp::new(i64::MAX, 0).is_err());
        assert!(serde_json::from_str::<ConsumerKey>(&format!(r#""{}""#, "x".repeat(257))).is_err());
    }

    #[test]
    fn close_is_monotonic_and_irreversible() {
        let mut value = session();
        assert_eq!(
            value.close(Timestamp::new(99, 0).unwrap()),
            Err(SessionDomainError::TimestampRegression)
        );
        value.close(Timestamp::new(101, 0).unwrap()).unwrap();
        assert_eq!(value.status(), SessionStatus::Closed);
        assert_eq!(value.revision().get(), 2);
        assert_eq!(
            value.close(Timestamp::new(102, 0).unwrap()),
            Err(SessionDomainError::AlreadyClosed)
        );
    }

    #[test]
    fn event_data_is_bounded_and_debug_redacted() {
        assert!(RedactedEventData::new(vec![0; MAX_EVENT_DATA_BYTES]).is_ok());
        assert!(RedactedEventData::new(vec![0; MAX_EVENT_DATA_BYTES + 1]).is_err());
        let data = RedactedEventData::new(b"secret-sentinel".to_vec()).unwrap();
        assert!(!format!("{data:?}").contains("secret-sentinel"));
    }

    #[test]
    fn canonical_event_and_ownership_snapshots_are_stable() {
        let event = SessionEvent::new(
            EventId::from_uuid(Uuid::from_u128(2)).unwrap(),
            SessionId::from_uuid(Uuid::from_u128(1)).unwrap(),
            EventPosition::initial(),
            Revision::initial(),
            EventType::new("session.opened").unwrap(),
            EventSchemaVersion::V1,
            Some(RequestId::from_uuid(Uuid::from_u128(4)).unwrap()),
            RedactedEventData::new([1, 2, 3]).unwrap(),
            Timestamp::new(100, 5).unwrap(),
        );
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"id":"00000000-0000-0000-0000-000000000002","session_id":"00000000-0000-0000-0000-000000000001","position":1,"revision":1,"event_type":"session.opened","schema_version":1,"related_request_id":"00000000-0000-0000-0000-000000000004","data":[1,2,3],"occurred_at":{"unix_seconds":100,"nanoseconds":5}}"#
        );
        let ownership = OwnershipSnapshot::Owned {
            host_id: HostId::from_uuid(Uuid::from_u128(3)).unwrap(),
            epoch: FencingEpoch::new(4).unwrap(),
            expires_at: Timestamp::new(200, 0).unwrap(),
        };
        assert_eq!(
            serde_json::to_string(&ownership).unwrap(),
            r#"{"state":"owned","host_id":"00000000-0000-0000-0000-000000000003","epoch":4,"expires_at":{"unix_seconds":200,"nanoseconds":0}}"#
        );
    }

    #[test]
    fn invalid_event_decode_cannot_bypass_bounds() {
        let valid = r#"{"id":"00000000-0000-0000-0000-000000000002","session_id":"00000000-0000-0000-0000-000000000001","position":1,"revision":1,"event_type":"session.opened","schema_version":1,"related_request_id":null,"data":[],"occurred_at":{"unix_seconds":100,"nanoseconds":0}}"#;
        assert!(serde_json::from_str::<SessionEvent>(valid).is_ok());
        assert!(
            serde_json::from_str::<SessionEvent>(
                &valid.replace("\"schema_version\":1", "\"schema_version\":0")
            )
            .is_err()
        );

        let oversized_type = valid.replace("session.opened", &"x".repeat(MAX_EVENT_TYPE_BYTES + 1));
        assert!(serde_json::from_str::<SessionEvent>(&oversized_type).is_err());
        let nil_id = valid.replace(
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000000",
        );
        assert!(serde_json::from_str::<SessionEvent>(&nil_id).is_err());
    }

    #[test]
    fn compatibility_digest_is_domain_separated_and_stable() {
        let first = CompatibilityIdentity::digest(b"schema-a");
        assert_eq!(first, CompatibilityIdentity::digest(b"schema-a"));
        assert_ne!(first, CompatibilityIdentity::digest(b"schema-b"));
        assert_ne!(first.as_bytes(), Sha256::digest(b"schema-a").as_slice());
    }

    #[test]
    fn compatibility_manifest_is_canonical_and_binds_configuration() {
        let first = TemplateCompatibilityBinding {
            template_id: TemplateId::from_uuid(Uuid::from_u128(11)).unwrap(),
            compatibility: CompatibilityIdentity::from_bytes([1; 32]),
        };
        let second = TemplateCompatibilityBinding {
            template_id: TemplateId::from_uuid(Uuid::from_u128(12)).unwrap(),
            compatibility: CompatibilityIdentity::from_bytes([2; 32]),
        };
        let configuration = CompatibilityIdentity::from_bytes([9; 32]);
        let ordered =
            SessionCompatibilityManifest::new(configuration, vec![first, second]).unwrap();
        let reversed =
            SessionCompatibilityManifest::new(configuration, vec![second, first]).unwrap();
        assert_eq!(ordered, reversed);
        assert!(ordered.contains(first.template_id, first.compatibility));
        assert_ne!(
            ordered.compatibility(),
            SessionCompatibilityManifest::new(
                CompatibilityIdentity::from_bytes([8; 32]),
                vec![first, second],
            )
            .unwrap()
            .compatibility()
        );
        assert_eq!(
            SessionCompatibilityManifest::new(configuration, vec![first, first]),
            Err(SessionDomainError::InvalidCompatibilityManifest)
        );
    }
}
