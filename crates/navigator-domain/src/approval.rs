use std::fmt;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;
use thiserror::Error;

use crate::{
    ApprovalRequestId, Capability, GrantId, OperationId, ParticipantId, RequestId, Revision,
    SemanticDigest, SessionId, Timestamp,
};

pub const MAX_APPROVAL_RESOURCE_BYTES: usize = 16 * 1024;
pub const MAX_APPROVAL_SUMMARY_BYTES: usize = 1024;
pub const MAX_APPROVAL_USES: u32 = 1024;
const MAX_JSON_DEPTH: usize = 32;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ApprovalDomainError {
    #[error("approval resource must be a bounded JSON object")]
    InvalidResource,
    #[error("approval summary must be non-empty and bounded")]
    InvalidSummary,
    #[error("approval request lifecycle fields are inconsistent")]
    InvalidRequest,
    #[error("approval grant fields are inconsistent")]
    InvalidGrant,
    #[error("approval effect lifecycle fields are inconsistent")]
    InvalidEffect,
}

/// A canonical, bounded resource description. Display text is deliberately not
/// part of this value and therefore cannot change the authority being granted.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ApprovalResource(Vec<u8>);

impl ApprovalResource {
    pub fn new(bytes: &[u8]) -> Result<Self, ApprovalDomainError> {
        if bytes.is_empty() || bytes.len() > MAX_APPROVAL_RESOURCE_BYTES {
            return Err(ApprovalDomainError::InvalidResource);
        }
        let value = serde_json::from_slice::<UniqueValue>(bytes)
            .map_err(|_| ApprovalDomainError::InvalidResource)?
            .0;
        if !value.is_object() || !valid_json(&value, 0) {
            return Err(ApprovalDomainError::InvalidResource);
        }
        let canonical =
            serde_json::to_vec(&value).map_err(|_| ApprovalDomainError::InvalidResource)?;
        if canonical.len() > MAX_APPROVAL_RESOURCE_BYTES {
            return Err(ApprovalDomainError::InvalidResource);
        }
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn digest(&self) -> SemanticDigest {
        SemanticDigest::v1(
            &Capability::new("approval.resource.v1").expect("static capability"),
            &self.0,
        )
    }
}

fn valid_json(value: &Value, depth: usize) -> bool {
    if depth > MAX_JSON_DEPTH {
        return false;
    }
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => true,
        Value::Number(value) => value.is_i64() || value.is_u64(),
        Value::Array(values) => values.iter().all(|value| valid_json(value, depth + 1)),
        Value::Object(values) => values.values().all(|value| valid_json(value, depth + 1)),
    }
}

struct UniqueValue(Value);

impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON without duplicate object keys")
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                self.visit_unit()
            }
            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Bool(value)))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::Number(value.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(UniqueValue)
                    .ok_or_else(|| E::custom("non-finite number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value.to_owned())))
            }
            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(UniqueValue(Value::String(value)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueValue>()? {
                    values.push(value.0);
                }
                Ok(UniqueValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueValue>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate object key"));
                    }
                    values.insert(key, value.0);
                }
                Ok(UniqueValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(UniqueVisitor)
    }
}

impl std::fmt::Debug for ApprovalResource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ApprovalResource(<redacted>)")
    }
}

impl Serialize for ApprovalResource {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ApprovalResource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Self::new(&bytes).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ApprovalSummary(String);

impl ApprovalSummary {
    pub fn new(value: impl Into<String>) -> Result<Self, ApprovalDomainError> {
        let value = value.into();
        if value.trim().is_empty()
            || value.len() > MAX_APPROVAL_SUMMARY_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(ApprovalDomainError::InvalidSummary);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ApprovalSummary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ApprovalSummary(<redacted>)")
    }
}

impl Serialize for ApprovalSummary {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ApprovalSummary {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Granted,
    Consumed,
    Denied,
    /// A request that expired before decision. An expired grant does not rewrite
    /// its request: the decision remains `Granted`, while the grant is unusable
    /// and expiry is recorded in audit history.
    Expired,
    Revoked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecisionSource {
    TrustedConsumer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApprovalRequest {
    pub id: ApprovalRequestId,
    pub session_id: SessionId,
    pub requester_id: ParticipantId,
    pub operation_id: OperationId,
    pub source_message_id: crate::MessageId,
    pub source_delivery_attempt_id: crate::DeliveryAttemptId,
    pub coordinator_id: ParticipantId,
    pub capability: Capability,
    pub resource: ApprovalResource,
    pub summary: ApprovalSummary,
    pub status: ApprovalStatus,
    pub expires_at: Timestamp,
    pub grant_id: Option<GrantId>,
    pub decision_source: Option<ApprovalDecisionSource>,
    pub created_at: Timestamp,
    pub decided_at: Option<Timestamp>,
    pub revision: Revision,
}

impl ApprovalRequest {
    pub fn validate(self) -> Result<Self, ApprovalDomainError> {
        let state = match self.status {
            ApprovalStatus::Pending | ApprovalStatus::Expired => {
                self.grant_id.is_none()
                    && self.decision_source.is_none()
                    && self.decided_at.is_none()
            }
            ApprovalStatus::Denied => {
                self.grant_id.is_none()
                    && self.decision_source.is_some()
                    && self.decided_at.is_some()
            }
            ApprovalStatus::Granted | ApprovalStatus::Consumed | ApprovalStatus::Revoked => {
                self.grant_id.is_some()
                    && self.decision_source.is_some()
                    && self.decided_at.is_some()
            }
        };
        if state
            && self.created_at < self.expires_at
            && self
                .decided_at
                .is_none_or(|at| at >= self.created_at && at < self.expires_at)
        {
            Ok(self)
        } else {
            Err(ApprovalDomainError::InvalidRequest)
        }
    }
}

impl<'de> Deserialize<'de> for ApprovalRequest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            id: ApprovalRequestId,
            session_id: SessionId,
            requester_id: ParticipantId,
            operation_id: OperationId,
            source_message_id: crate::MessageId,
            source_delivery_attempt_id: crate::DeliveryAttemptId,
            coordinator_id: ParticipantId,
            capability: Capability,
            resource: ApprovalResource,
            summary: ApprovalSummary,
            status: ApprovalStatus,
            expires_at: Timestamp,
            grant_id: Option<GrantId>,
            decision_source: Option<ApprovalDecisionSource>,
            created_at: Timestamp,
            decided_at: Option<Timestamp>,
            revision: Revision,
        }
        let v = Wire::deserialize(d)?;
        ApprovalRequest {
            id: v.id,
            session_id: v.session_id,
            requester_id: v.requester_id,
            operation_id: v.operation_id,
            source_message_id: v.source_message_id,
            source_delivery_attempt_id: v.source_delivery_attempt_id,
            coordinator_id: v.coordinator_id,
            capability: v.capability,
            resource: v.resource,
            summary: v.summary,
            status: v.status,
            expires_at: v.expires_at,
            grant_id: v.grant_id,
            decision_source: v.decision_source,
            created_at: v.created_at,
            decided_at: v.decided_at,
            revision: v.revision,
        }
        .validate()
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApprovalGrant {
    pub id: GrantId,
    pub request_id: ApprovalRequestId,
    pub session_id: SessionId,
    pub subject_id: ParticipantId,
    pub operation_id: OperationId,
    pub capability: Capability,
    pub resource_hash: SemanticDigest,
    pub issued_by: ApprovalDecisionSource,
    pub max_uses: u32,
    pub used_count: u32,
    pub expires_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
    pub created_at: Timestamp,
    pub revision: Revision,
}

impl ApprovalGrant {
    pub fn validate(self) -> Result<Self, ApprovalDomainError> {
        if self.max_uses > 0
            && self.max_uses <= MAX_APPROVAL_USES
            && self.used_count <= self.max_uses
            && self.created_at < self.expires_at
            && self.revoked_at.is_none_or(|at| at >= self.created_at)
        {
            Ok(self)
        } else {
            Err(ApprovalDomainError::InvalidGrant)
        }
    }
    #[must_use]
    pub fn is_usable_at(&self, now: Timestamp) -> bool {
        self.revoked_at.is_none()
            && now < self.expires_at
            && self.used_count < self.max_uses
            && self.max_uses > 0
            && self.max_uses <= MAX_APPROVAL_USES
    }
}

impl<'de> Deserialize<'de> for ApprovalGrant {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            id: GrantId,
            request_id: ApprovalRequestId,
            session_id: SessionId,
            subject_id: ParticipantId,
            operation_id: OperationId,
            capability: Capability,
            resource_hash: SemanticDigest,
            issued_by: ApprovalDecisionSource,
            max_uses: u32,
            used_count: u32,
            expires_at: Timestamp,
            revoked_at: Option<Timestamp>,
            created_at: Timestamp,
            revision: Revision,
        }
        let v = Wire::deserialize(d)?;
        ApprovalGrant {
            id: v.id,
            request_id: v.request_id,
            session_id: v.session_id,
            subject_id: v.subject_id,
            operation_id: v.operation_id,
            capability: v.capability,
            resource_hash: v.resource_hash,
            issued_by: v.issued_by,
            max_uses: v.max_uses,
            used_count: v.used_count,
            expires_at: v.expires_at,
            revoked_at: v.revoked_at,
            created_at: v.created_at,
            revision: v.revision,
        }
        .validate()
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalEffectPhase {
    Reserved,
    Succeeded,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalApprovalEffectPhase {
    Succeeded,
    Failed,
    Uncertain,
}

impl From<TerminalApprovalEffectPhase> for ApprovalEffectPhase {
    fn from(value: TerminalApprovalEffectPhase) -> Self {
        match value {
            TerminalApprovalEffectPhase::Succeeded => Self::Succeeded,
            TerminalApprovalEffectPhase::Failed => Self::Failed,
            TerminalApprovalEffectPhase::Uncertain => Self::Uncertain,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApprovalEffectIntent {
    pub effect_id: RequestId,
    pub session_id: SessionId,
    pub grant_id: GrantId,
    pub subject_id: ParticipantId,
    pub operation_id: OperationId,
    pub capability: Capability,
    pub resource_hash: SemanticDigest,
    pub phase: ApprovalEffectPhase,
    pub created_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub revision: Revision,
}

impl ApprovalEffectIntent {
    pub fn validate(self) -> Result<Self, ApprovalDomainError> {
        let phase =
            matches!(self.phase, ApprovalEffectPhase::Reserved) == self.finished_at.is_none();
        if phase && self.finished_at.is_none_or(|at| at >= self.created_at) {
            Ok(self)
        } else {
            Err(ApprovalDomainError::InvalidEffect)
        }
    }
}

impl<'de> Deserialize<'de> for ApprovalEffectIntent {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            effect_id: RequestId,
            session_id: SessionId,
            grant_id: GrantId,
            subject_id: ParticipantId,
            operation_id: OperationId,
            capability: Capability,
            resource_hash: SemanticDigest,
            phase: ApprovalEffectPhase,
            created_at: Timestamp,
            finished_at: Option<Timestamp>,
            revision: Revision,
        }
        let v = Wire::deserialize(d)?;
        ApprovalEffectIntent {
            effect_id: v.effect_id,
            session_id: v.session_id,
            grant_id: v.grant_id,
            subject_id: v.subject_id,
            operation_id: v.operation_id,
            capability: v.capability,
            resource_hash: v.resource_hash,
            phase: v.phase,
            created_at: v.created_at,
            finished_at: v.finished_at,
            revision: v.revision,
        }
        .validate()
        .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn resource_is_canonical_bounded_and_rejects_ambiguous_json() {
        assert_eq!(
            ApprovalResource::new(br#"{"z":1,"a":{"b":2}}"#)
                .unwrap()
                .as_bytes(),
            br#"{"a":{"b":2},"z":1}"#
        );
        for invalid in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":{"b":1,"b":2}}"#,
            br#"{"a":1.5}"#,
            br#"{"a":18446744073709551616}"#,
            b"\xff",
            br"[]",
        ] {
            assert!(
                ApprovalResource::new(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        let deep = format!("{{\"a\":{}}}", "[".repeat(33) + "0" + &"]".repeat(33));
        assert!(ApprovalResource::new(deep.as_bytes()).is_err());
        let oversized = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_APPROVAL_RESOURCE_BYTES));
        assert!(ApprovalResource::new(oversized.as_bytes()).is_err());
    }

    #[test]
    fn summary_rejects_blank_control_and_oversize_text() {
        for invalid in ["", " \t", "line\nfeed"] {
            assert!(ApprovalSummary::new(invalid).is_err());
        }
        assert!(ApprovalSummary::new("x".repeat(MAX_APPROVAL_SUMMARY_BYTES + 1)).is_err());
    }

    fn valid_request() -> ApprovalRequest {
        ApprovalRequest {
            id: ApprovalRequestId::from_uuid(Uuid::from_u128(1)).unwrap(),
            session_id: SessionId::from_uuid(Uuid::from_u128(2)).unwrap(),
            requester_id: ParticipantId::from_uuid(Uuid::from_u128(3)).unwrap(),
            operation_id: OperationId::from_uuid(Uuid::from_u128(4)).unwrap(),
            source_message_id: crate::MessageId::from_uuid(Uuid::from_u128(5)).unwrap(),
            source_delivery_attempt_id: crate::DeliveryAttemptId::from_uuid(Uuid::from_u128(6))
                .unwrap(),
            coordinator_id: ParticipantId::from_uuid(Uuid::from_u128(7)).unwrap(),
            capability: Capability::new("repository.publish").unwrap(),
            resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
            summary: ApprovalSummary::new("publish main").unwrap(),
            status: ApprovalStatus::Pending,
            expires_at: Timestamp::new(200, 0).unwrap(),
            grant_id: None,
            decision_source: None,
            created_at: Timestamp::new(100, 0).unwrap(),
            decided_at: None,
            revision: Revision::initial(),
        }
    }

    #[test]
    fn request_deserialize_rejects_status_and_decision_time_mutants() {
        let mut value = serde_json::to_value(valid_request()).unwrap();
        value["status"] = serde_json::json!("granted");
        assert!(serde_json::from_value::<ApprovalRequest>(value).is_err());

        let mut decided = valid_request();
        decided.status = ApprovalStatus::Denied;
        decided.decision_source = Some(ApprovalDecisionSource::TrustedConsumer);
        decided.decided_at = Some(decided.expires_at);
        let bytes = serde_json::to_vec(&decided).unwrap();
        assert!(serde_json::from_slice::<ApprovalRequest>(&bytes).is_err());
    }

    #[test]
    fn grant_and_effect_deserialize_reject_use_time_and_phase_mutants() {
        let request = valid_request();
        let grant_id = GrantId::from_uuid(Uuid::from_u128(5)).unwrap();
        let grant = ApprovalGrant {
            id: grant_id,
            request_id: request.id,
            session_id: request.session_id,
            subject_id: request.requester_id,
            operation_id: request.operation_id,
            capability: request.capability.clone(),
            resource_hash: request.resource.digest(),
            issued_by: ApprovalDecisionSource::TrustedConsumer,
            max_uses: 1,
            used_count: 2,
            expires_at: request.expires_at,
            revoked_at: None,
            created_at: request.created_at,
            revision: Revision::initial(),
        };
        assert!(
            serde_json::from_slice::<ApprovalGrant>(&serde_json::to_vec(&grant).unwrap()).is_err()
        );
        let effect = ApprovalEffectIntent {
            effect_id: RequestId::from_uuid(Uuid::from_u128(6)).unwrap(),
            session_id: request.session_id,
            grant_id,
            subject_id: request.requester_id,
            operation_id: request.operation_id,
            capability: request.capability,
            resource_hash: request.resource.digest(),
            phase: ApprovalEffectPhase::Succeeded,
            created_at: request.created_at,
            finished_at: None,
            revision: Revision::initial(),
        };
        assert!(
            serde_json::from_slice::<ApprovalEffectIntent>(&serde_json::to_vec(&effect).unwrap())
                .is_err()
        );
    }

    fn rejects_both<T>(value: T, validate: impl FnOnce(T) -> Result<T, ApprovalDomainError>)
    where
        T: Serialize + serde::de::DeserializeOwned + Clone,
    {
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(validate(value).is_err());
        assert!(serde_json::from_slice::<T>(&bytes).is_err());
    }

    #[test]
    fn exhaustive_request_invariant_matrix_fails_closed() {
        let base = valid_request();
        let grant = GrantId::from_uuid(Uuid::from_u128(9)).unwrap();
        let source = ApprovalDecisionSource::TrustedConsumer;
        let decided = Timestamp::new(110, 0).unwrap();
        for status in [
            ApprovalStatus::Pending,
            ApprovalStatus::Granted,
            ApprovalStatus::Consumed,
            ApprovalStatus::Denied,
            ApprovalStatus::Expired,
            ApprovalStatus::Revoked,
        ] {
            for grant_id in [None, Some(grant)] {
                for decision_source in [None, Some(source)] {
                    for decided_at in [None, Some(decided)] {
                        let mut value = base.clone();
                        value.status = status;
                        value.grant_id = grant_id;
                        value.decision_source = decision_source;
                        value.decided_at = decided_at;
                        let valid =
                            matches!(status, ApprovalStatus::Pending | ApprovalStatus::Expired)
                                && grant_id.is_none()
                                && decision_source.is_none()
                                && decided_at.is_none()
                                || matches!(
                                    status,
                                    ApprovalStatus::Granted
                                        | ApprovalStatus::Consumed
                                        | ApprovalStatus::Revoked
                                ) && grant_id.is_some()
                                    && decision_source.is_some()
                                    && decided_at.is_some()
                                || status == ApprovalStatus::Denied
                                    && grant_id.is_none()
                                    && decision_source.is_some()
                                    && decided_at.is_some();
                        if !valid {
                            rejects_both(value, ApprovalRequest::validate);
                        }
                    }
                }
            }
        }
        for (created, expires, decided_at) in [
            (200, 200, None),
            (201, 200, None),
            (100, 200, Some(99)),
            (100, 200, Some(200)),
            (100, 200, Some(201)),
        ] {
            let mut value = base.clone();
            value.created_at = Timestamp::new(created, 0).unwrap();
            value.expires_at = Timestamp::new(expires, 0).unwrap();
            if decided_at.is_some() {
                value.status = ApprovalStatus::Denied;
                value.decision_source = Some(source);
                value.decided_at = decided_at.map(|v| Timestamp::new(v, 0).unwrap());
            }
            rejects_both(value, ApprovalRequest::validate);
        }
    }

    #[test]
    fn exhaustive_grant_and_effect_invariant_matrices_fail_closed() {
        let request = valid_request();
        let grant_id = GrantId::from_uuid(Uuid::from_u128(20)).unwrap();
        let base = ApprovalGrant {
            id: grant_id,
            request_id: request.id,
            session_id: request.session_id,
            subject_id: request.requester_id,
            operation_id: request.operation_id,
            capability: request.capability.clone(),
            resource_hash: request.resource.digest(),
            issued_by: ApprovalDecisionSource::TrustedConsumer,
            max_uses: 2,
            used_count: 1,
            expires_at: request.expires_at,
            revoked_at: None,
            created_at: request.created_at,
            revision: Revision::initial(),
        };
        let mut cases = Vec::new();
        let mut v = base.clone();
        v.max_uses = 0;
        cases.push(v);
        let mut v = base.clone();
        v.max_uses = MAX_APPROVAL_USES + 1;
        cases.push(v);
        let mut v = base.clone();
        v.used_count = 3;
        cases.push(v);
        let mut v = base.clone();
        v.created_at = v.expires_at;
        cases.push(v);
        let mut v = base.clone();
        v.created_at = Timestamp::new(201, 0).unwrap();
        cases.push(v);
        let mut v = base.clone();
        v.revoked_at = Some(Timestamp::new(99, 0).unwrap());
        cases.push(v);
        for value in cases {
            rejects_both(value, ApprovalGrant::validate);
        }
        for phase in [
            ApprovalEffectPhase::Reserved,
            ApprovalEffectPhase::Succeeded,
            ApprovalEffectPhase::Failed,
            ApprovalEffectPhase::Uncertain,
        ] {
            for finished_at in [
                None,
                Some(Timestamp::new(99, 0).unwrap()),
                Some(Timestamp::new(110, 0).unwrap()),
            ] {
                let value = ApprovalEffectIntent {
                    effect_id: RequestId::from_uuid(Uuid::from_u128(21)).unwrap(),
                    session_id: request.session_id,
                    grant_id,
                    subject_id: request.requester_id,
                    operation_id: request.operation_id,
                    capability: request.capability.clone(),
                    resource_hash: request.resource.digest(),
                    phase,
                    created_at: request.created_at,
                    finished_at,
                    revision: Revision::initial(),
                };
                let valid = phase == ApprovalEffectPhase::Reserved && finished_at.is_none()
                    || phase != ApprovalEffectPhase::Reserved
                        && finished_at == Some(Timestamp::new(110, 0).unwrap());
                if !valid {
                    rejects_both(value, ApprovalEffectIntent::validate);
                }
            }
        }
    }

    #[test]
    fn resource_accepts_exact_depth_and_canonical_boundary() {
        let depth32 = format!("{{\"a\":{}}}", "[".repeat(31) + "0" + &"]".repeat(31));
        assert!(ApprovalResource::new(depth32.as_bytes()).is_ok());
        let ordered = ApprovalResource::new(" { \"é\" : 2, \"a\" : 1 } ".as_bytes()).unwrap();
        assert_eq!(ordered.as_bytes(), "{\"a\":1,\"é\":2}".as_bytes());
        assert!(ApprovalResource::new(br#"{"\u0061":1,"a":2}"#).is_err());
        let exact_canonical = format!(
            "{{\"a\":\"{}\"}}",
            "x".repeat(MAX_APPROVAL_RESOURCE_BYTES - 8)
        );
        assert_eq!(exact_canonical.len(), MAX_APPROVAL_RESOURCE_BYTES);
        assert!(ApprovalResource::new(exact_canonical.as_bytes()).is_ok());
        let exact_input = format!(
            " {{\"a\":\"{}\"}}",
            "x".repeat(MAX_APPROVAL_RESOURCE_BYTES - 9)
        );
        assert_eq!(exact_input.len(), MAX_APPROVAL_RESOURCE_BYTES);
        assert!(ApprovalResource::new(exact_input.as_bytes()).is_ok());
        let first = ApprovalResource::new(" {\"é\":2,\"a\":1} ".as_bytes()).unwrap();
        let escaped = ApprovalResource::new(br#"{"a":1,"\u00e9":2}"#).unwrap();
        assert_eq!(first.digest(), escaped.digest());
        let zero = ApprovalResource::new(br#"{"n":0}"#).unwrap();
        assert_eq!(zero.as_bytes(), br#"{"n":0}"#);
        assert!(
            ApprovalResource::new(br#"{"n":-0}"#).is_err(),
            "negative zero is rejected rather than aliased to integer zero"
        );
    }
}
