//! Version, identity, bounds, and negotiation shared by Navigator protocols.

use navigator_domain::{
    Capability, CorrelationId, EnvelopeId, ErrorCode, FencingEpoch, InstanceId, LaunchAttemptId,
    ParticipantId, RequestId, SessionId,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

pub const CURRENT_MAJOR: u16 = 1;
pub const CURRENT_MINOR: u16 = 0;
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_REQUIRED_FEATURES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct VersionRange {
    major: u16,
    min_minor: u16,
    max_minor: u16,
}

impl VersionRange {
    pub const CURRENT: Self = Self {
        major: CURRENT_MAJOR,
        min_minor: 0,
        max_minor: CURRENT_MINOR,
    };

    pub const fn new(
        major: u16,
        min_minor: u16,
        max_minor: u16,
    ) -> Result<Self, ProtocolViolation> {
        if min_minor > max_minor {
            Err(ProtocolViolation::InvalidVersionRange)
        } else {
            Ok(Self {
                major,
                min_minor,
                max_minor,
            })
        }
    }

    #[must_use]
    pub const fn major(self) -> u16 {
        self.major
    }

    #[must_use]
    pub const fn min_minor(self) -> u16 {
        self.min_minor
    }

    #[must_use]
    pub const fn max_minor(self) -> u16 {
        self.max_minor
    }
}

impl<'de> Deserialize<'de> for VersionRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            major: u16,
            min_minor: u16,
            max_minor: u16,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.major, wire.min_minor, wire.max_minor).map_err(serde::de::Error::custom)
    }
}

pub fn negotiate_version(
    local: VersionRange,
    peer: VersionRange,
) -> Result<ProtocolVersion, ProtocolViolation> {
    if local.min_minor > local.max_minor || peer.min_minor > peer.max_minor {
        return Err(ProtocolViolation::InvalidVersionRange);
    }
    if local.major != peer.major {
        return Err(ProtocolViolation::NoCompatibleVersion);
    }
    let min = local.min_minor.max(peer.min_minor);
    let max = local.max_minor.min(peer.max_minor);
    if min > max {
        return Err(ProtocolViolation::NoCompatibleVersion);
    }
    Ok(ProtocolVersion {
        major: local.major,
        minor: max,
    })
}

pub struct BoundedFrame<'a>(&'a [u8]);

impl<'a> BoundedFrame<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, ProtocolViolation> {
        if bytes.len() > MAX_FRAME_BYTES {
            Err(ProtocolViolation::FrameTooLarge {
                actual: bytes.len(),
            })
        } else {
            Ok(Self(bytes))
        }
    }

    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Envelope<T> {
    version: ProtocolVersion,
    #[serde(rename = "envelope_id")]
    id: EnvelopeId,
    message_type: Capability,
    request_id: RequestId,
    correlation_id: Option<CorrelationId>,
    required_features: Vec<Capability>,
    payload: T,
}

impl<T> Envelope<T> {
    pub fn new(
        version: ProtocolVersion,
        envelope_id: EnvelopeId,
        message_type: Capability,
        request_id: RequestId,
        correlation_id: Option<CorrelationId>,
        required_features: Vec<Capability>,
        payload: T,
    ) -> Result<Self, ProtocolViolation> {
        validate_required_features(&required_features)?;
        Ok(Self {
            version,
            id: envelope_id,
            message_type,
            request_id,
            correlation_id,
            required_features,
            payload,
        })
    }

    pub fn validate(
        &self,
        negotiated_version: ProtocolVersion,
        supported_features: &[&str],
    ) -> Result<(), ProtocolViolation> {
        if self.version != negotiated_version {
            return Err(ProtocolViolation::IncompatibleVersion {
                received: self.version,
                negotiated: negotiated_version,
            });
        }
        for feature in &self.required_features {
            if !supported_features.contains(&feature.as_str()) {
                return Err(ProtocolViolation::UnsupportedFeature(
                    feature.as_str().to_owned(),
                ));
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn version(&self) -> ProtocolVersion {
        self.version
    }

    #[must_use]
    pub const fn envelope_id(&self) -> EnvelopeId {
        self.id
    }

    #[must_use]
    pub fn message_type(&self) -> &Capability {
        &self.message_type
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn correlation_id(&self) -> Option<CorrelationId> {
        self.correlation_id
    }

    #[must_use]
    pub fn required_features(&self) -> &[Capability] {
        &self.required_features
    }

    #[must_use]
    pub fn payload(&self) -> &T {
        &self.payload
    }

    #[must_use]
    pub fn into_payload(self) -> T {
        self.payload
    }
}

fn validate_required_features(features: &[Capability]) -> Result<(), ProtocolViolation> {
    if features.len() > MAX_REQUIRED_FEATURES {
        return Err(ProtocolViolation::TooManyRequiredFeatures);
    }
    let mut unique = BTreeSet::new();
    for feature in features {
        if !unique.insert(feature) {
            return Err(ProtocolViolation::DuplicateRequiredFeature);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct WireEnvelope<T> {
    version: ProtocolVersion,
    envelope_id: EnvelopeId,
    message_type: Capability,
    request_id: RequestId,
    correlation_id: Option<CorrelationId>,
    required_features: Vec<Capability>,
    payload: T,
}

pub fn decode_json<T: DeserializeOwned>(
    bytes: &[u8],
    negotiated_version: ProtocolVersion,
    supported_features: &[&str],
) -> Result<Envelope<T>, ProtocolViolation> {
    decode_with(bytes, |bounded| {
        let wire: WireEnvelope<T> =
            serde_json::from_slice(bounded).map_err(|_| ProtocolViolation::MalformedFrame)?;
        let envelope = Envelope::new(
            wire.version,
            wire.envelope_id,
            wire.message_type,
            wire.request_id,
            wire.correlation_id,
            wire.required_features,
            wire.payload,
        )?;
        envelope.validate(negotiated_version, supported_features)?;
        Ok(envelope)
    })
}

fn decode_with<T>(
    bytes: &[u8],
    decoder: impl FnOnce(&[u8]) -> Result<T, ProtocolViolation>,
) -> Result<T, ProtocolViolation> {
    decoder(BoundedFrame::new(bytes)?.bytes())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstanceBinding {
    pub session_id: SessionId,
    pub participant_id: ParticipantId,
    pub instance_id: InstanceId,
    pub launch_attempt_id: LaunchAttemptId,
    pub owner_epoch: FencingEpoch,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProtocolViolation {
    #[error("protocol version {received:?} differs from negotiated version {negotiated:?}")]
    IncompatibleVersion {
        received: ProtocolVersion,
        negotiated: ProtocolVersion,
    },
    #[error("protocol version range is invalid")]
    InvalidVersionRange,
    #[error("protocol version ranges do not overlap")]
    NoCompatibleVersion,
    #[error("frame has {actual} bytes and exceeds the protocol limit")]
    FrameTooLarge { actual: usize },
    #[error("protocol frame is malformed")]
    MalformedFrame,
    #[error("too many required protocol features")]
    TooManyRequiredFeatures,
    #[error("required protocol feature is duplicated")]
    DuplicateRequiredFeature,
    #[error("required feature {0} is unsupported")]
    UnsupportedFeature(String),
}

impl ProtocolViolation {
    #[must_use]
    pub const fn error_code(&self) -> ErrorCode {
        match self {
            Self::IncompatibleVersion { .. }
            | Self::InvalidVersionRange
            | Self::NoCompatibleVersion
            | Self::UnsupportedFeature(_) => ErrorCode::Incompatible,
            Self::FrameTooLarge { .. }
            | Self::MalformedFrame
            | Self::TooManyRequiredFeatures
            | Self::DuplicateRequiredFeature => ErrorCode::Validation,
        }
    }
}

#[cfg(test)]
mod tests {
    use navigator_domain::{Capability, EnvelopeId, RequestId};
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use uuid::Uuid;

    use super::{
        BoundedFrame, Envelope, MAX_FRAME_BYTES, MAX_REQUIRED_FEATURES, ProtocolVersion,
        ProtocolViolation, VersionRange, decode_json, decode_with, negotiate_version,
    };

    fn capability(value: &str) -> Capability {
        Capability::new(value).unwrap()
    }

    fn envelope(required_features: Vec<Capability>) -> Envelope<()> {
        Envelope::new(
            ProtocolVersion { major: 1, minor: 0 },
            EnvelopeId::from_uuid(Uuid::from_u128(1)).unwrap(),
            capability("test.command.v1"),
            RequestId::from_uuid(Uuid::from_u128(2)).unwrap(),
            None,
            required_features,
            (),
        )
        .unwrap()
    }

    #[test]
    fn raw_frame_is_bounded_before_decode() {
        assert!(BoundedFrame::new(&vec![0; MAX_FRAME_BYTES]).is_ok());
        assert_eq!(
            BoundedFrame::new(&vec![0; MAX_FRAME_BYTES + 1]).map(BoundedFrame::bytes),
            Err(ProtocolViolation::FrameTooLarge {
                actual: MAX_FRAME_BYTES + 1
            })
        );
    }

    #[test]
    fn negotiation_selects_highest_mutual_minor() {
        let local = VersionRange::new(1, 1, 5).unwrap();
        let peer = VersionRange::new(1, 3, 7).unwrap();
        assert_eq!(
            negotiate_version(local, peer),
            Ok(ProtocolVersion { major: 1, minor: 5 })
        );
    }

    #[test]
    fn negotiation_rejects_invalid_or_disjoint_ranges() {
        assert_eq!(
            VersionRange::new(1, 2, 1),
            Err(ProtocolViolation::InvalidVersionRange)
        );
        assert_eq!(
            negotiate_version(
                VersionRange::new(1, 0, 1).unwrap(),
                VersionRange::new(1, 2, 3).unwrap()
            ),
            Err(ProtocolViolation::NoCompatibleVersion)
        );
        assert_eq!(
            negotiate_version(
                VersionRange::new(1, 0, 1).unwrap(),
                VersionRange::new(2, 0, 1).unwrap()
            ),
            Err(ProtocolViolation::NoCompatibleVersion)
        );
    }

    #[test]
    fn required_features_are_explicitly_negotiated() {
        assert!(
            envelope(vec![capability("durable_acceptance.v1")])
                .validate(
                    ProtocolVersion { major: 1, minor: 0 },
                    &["durable_acceptance.v1"]
                )
                .is_ok()
        );
        assert!(matches!(
            envelope(vec![capability("durable_acceptance.v2")]).validate(
                ProtocolVersion { major: 1, minor: 0 },
                &["durable_acceptance.v1"]
            ),
            Err(ProtocolViolation::UnsupportedFeature(_))
        ));
    }

    #[test]
    fn required_feature_count_is_bounded() {
        let features = (0..=MAX_REQUIRED_FEATURES)
            .map(|index| capability(&format!("feature.{index}")))
            .collect();
        assert_eq!(
            Envelope::new(
                ProtocolVersion { major: 1, minor: 0 },
                EnvelopeId::from_uuid(Uuid::from_u128(1)).unwrap(),
                capability("test.command.v1"),
                RequestId::from_uuid(Uuid::from_u128(2)).unwrap(),
                None,
                features,
                (),
            ),
            Err(ProtocolViolation::TooManyRequiredFeatures)
        );
    }

    #[test]
    fn duplicate_required_feature_is_rejected() {
        let result = Envelope::new(
            ProtocolVersion { major: 1, minor: 0 },
            EnvelopeId::from_uuid(Uuid::from_u128(1)).unwrap(),
            capability("test.command.v1"),
            RequestId::from_uuid(Uuid::from_u128(2)).unwrap(),
            None,
            vec![capability("feature.v1"), capability("feature.v1")],
            (),
        );
        assert_eq!(result, Err(ProtocolViolation::DuplicateRequiredFeature));
    }

    #[test]
    fn incompatible_envelope_major_is_rejected() {
        let value = envelope(Vec::new());
        assert_eq!(
            value.validate(ProtocolVersion { major: 1, minor: 1 }, &[]),
            Err(ProtocolViolation::IncompatibleVersion {
                received: ProtocolVersion { major: 1, minor: 0 },
                negotiated: ProtocolVersion { major: 1, minor: 1 },
            })
        );
    }

    #[test]
    fn semantic_fixture_tolerates_unknown_optional_field() {
        let fixture = include_str!("../tests/fixtures/envelope-v1.json");
        let decoded: Envelope<serde_json::Value> = decode_json(
            fixture.as_bytes(),
            ProtocolVersion { major: 1, minor: 0 },
            &["durable_acceptance.v1"],
        )
        .unwrap();
        assert_eq!(decoded.message_type().as_str(), "test.command.v1");
        assert_eq!(
            decoded.payload(),
            &serde_json::json!({"task": "semantic-fixture"})
        );
    }

    #[test]
    fn oversized_input_never_reaches_decoder() {
        let calls = AtomicUsize::new(0);
        let bytes = vec![0; MAX_FRAME_BYTES + 1];
        let result: Result<(), _> = decode_with(&bytes, |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(
            result,
            Err(ProtocolViolation::FrameTooLarge {
                actual: bytes.len()
            })
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn invalid_version_range_cannot_be_deserialized() {
        let result =
            serde_json::from_str::<VersionRange>(r#"{"major":1,"min_minor":5,"max_minor":4}"#);
        assert!(result.is_err());
    }

    proptest! {
        #[test]
        fn negotiation_matches_enumerated_intersection(
            major in any::<u8>(),
            a in 0_u8..32,
            b in 0_u8..32,
            c in 0_u8..32,
            d in 0_u8..32,
        ) {
            let (local_min, local_max) = (a.min(b), a.max(b));
            let (peer_min, peer_max) = (c.min(d), c.max(d));
            let local = VersionRange::new(major.into(), local_min.into(), local_max.into()).unwrap();
            let peer = VersionRange::new(major.into(), peer_min.into(), peer_max.into()).unwrap();
            let expected = (0_u16..=31)
                .filter(|minor| *minor >= u16::from(local_min) && *minor <= u16::from(local_max))
                .filter(|minor| *minor >= u16::from(peer_min) && *minor <= u16::from(peer_max))
                .max()
                .map(|minor| ProtocolVersion { major: major.into(), minor });
            prop_assert_eq!(negotiate_version(local, peer).ok(), expected);
            prop_assert_eq!(negotiate_version(local, peer), negotiate_version(peer, local));
        }
    }
}
