use std::{collections::BTreeMap, num::NonZeroU64};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::{
    ArtifactRef, BoundedText, Capability, EffectClass, GrantId, OperationId, ParticipantId,
    RequestId, SessionId, ToolInvocationId,
};

pub const MAX_TOOL_NAME_BYTES: usize = 128;
pub const MAX_TOOL_VERSION_BYTES: usize = 64;
pub const MAX_TOOL_SCHEMA_BYTES: usize = 16_384;
pub const MAX_TOOL_INLINE_BYTES: usize = 65_536;
pub const MAX_TOOL_FAILURE_MESSAGE_BYTES: usize = 1_024;
pub const MAX_TOOL_TIMEOUT_MILLIS: u64 = 3_600_000;
pub const MAX_TOOL_ARTIFACT_REFS: usize = 32;

pub type ToolName = BoundedText<MAX_TOOL_NAME_BYTES>;
pub type ToolVersion = BoundedText<MAX_TOOL_VERSION_BYTES>;

/// Canonical JSON bytes. Objects are recursively key-sorted, so semantically
/// identical inputs have one durable representation and one request digest.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CanonicalJson<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> CanonicalJson<MAX> {
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, ToolDomainError> {
        let value: Value =
            serde_json::from_slice(bytes.as_ref()).map_err(|_| ToolDomainError::InvalidJson)?;
        let canonical =
            serde_json::to_vec(&canonicalize(value)).map_err(|_| ToolDomainError::InvalidJson)?;
        if canonical.len() > MAX {
            return Err(ToolDomainError::TooLarge);
        }
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        scalar => scalar,
    }
}

impl<const MAX: usize> Serialize for CanonicalJson<MAX> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(std::str::from_utf8(&self.0).expect("canonical JSON is UTF-8"))
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for CanonicalJson<MAX> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        Self::new(encoded.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolCancellation {
    Cooperative,
    Unsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyContract {
    NoExternalEffect,
    InvocationIdentity,
    ExternalTransactionProof,
    NeverReplay,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct ToolTimeout(NonZeroU64);

impl ToolTimeout {
    pub fn from_millis(value: u64) -> Result<Self, ToolDomainError> {
        let value = NonZeroU64::new(value).ok_or(ToolDomainError::InvalidTimeout)?;
        if value.get() > MAX_TOOL_TIMEOUT_MILLIS {
            return Err(ToolDomainError::InvalidTimeout);
        }
        Ok(Self(value))
    }
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0.get()
    }
}
impl TryFrom<u64> for ToolTimeout {
    type Error = ToolDomainError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        Self::from_millis(value)
    }
}
impl From<ToolTimeout> for u64 {
    fn from(value: ToolTimeout) -> Self {
        value.as_millis()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ToolDefinitionWire", into = "ToolDefinitionWire")]
pub struct ToolDefinition {
    name: ToolName,
    version: ToolVersion,
    input_schema: CanonicalJson<MAX_TOOL_SCHEMA_BYTES>,
    output_schema: CanonicalJson<MAX_TOOL_SCHEMA_BYTES>,
    required_authority: Capability,
    timeout: ToolTimeout,
    cancellation: ToolCancellation,
    effect_class: EffectClass,
    idempotency: IdempotencyContract,
    requires_approval: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ToolDefinitionWire {
    name: ToolName,
    version: ToolVersion,
    input_schema: CanonicalJson<MAX_TOOL_SCHEMA_BYTES>,
    output_schema: CanonicalJson<MAX_TOOL_SCHEMA_BYTES>,
    required_authority: Capability,
    timeout: ToolTimeout,
    cancellation: ToolCancellation,
    effect_class: EffectClass,
    idempotency: IdempotencyContract,
    #[serde(default)]
    requires_approval: bool,
}

impl ToolDefinition {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: ToolName,
        version: ToolVersion,
        input_schema: CanonicalJson<MAX_TOOL_SCHEMA_BYTES>,
        output_schema: CanonicalJson<MAX_TOOL_SCHEMA_BYTES>,
        required_authority: Capability,
        timeout: ToolTimeout,
        cancellation: ToolCancellation,
        effect_class: EffectClass,
        idempotency: IdempotencyContract,
    ) -> Result<Self, ToolDomainError> {
        validate_stable_identifier(name.as_str())?;
        validate_stable_identifier(version.as_str())?;
        if !json_is_object(input_schema.as_bytes()) || !json_is_object(output_schema.as_bytes()) {
            return Err(ToolDomainError::SchemaMustBeObject);
        }
        validate_schema_shape(
            &serde_json::from_slice(input_schema.as_bytes())
                .map_err(|_| ToolDomainError::InvalidJson)?,
            0,
        )?;
        validate_schema_shape(
            &serde_json::from_slice(output_schema.as_bytes())
                .map_err(|_| ToolDomainError::InvalidJson)?,
            0,
        )?;
        let coherent = matches!(
            (effect_class, idempotency),
            (EffectClass::ReadOnly, IdempotencyContract::NoExternalEffect)
                | (
                    EffectClass::Idempotent,
                    IdempotencyContract::InvocationIdentity
                )
                | (
                    EffectClass::Transactional,
                    IdempotencyContract::ExternalTransactionProof
                )
                | (
                    EffectClass::NonIdempotent | EffectClass::Unknown,
                    IdempotencyContract::NeverReplay
                )
        );
        if !coherent {
            return Err(ToolDomainError::ContradictoryIdempotency);
        }
        Ok(Self {
            name,
            version,
            input_schema,
            output_schema,
            required_authority,
            timeout,
            cancellation,
            effect_class,
            idempotency,
            requires_approval: false,
        })
    }
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }
    #[must_use]
    pub fn version(&self) -> &str {
        self.version.as_str()
    }
    #[must_use]
    pub fn input_schema(&self) -> &[u8] {
        self.input_schema.as_bytes()
    }
    #[must_use]
    pub fn output_schema(&self) -> &[u8] {
        self.output_schema.as_bytes()
    }
    #[must_use]
    pub const fn required_authority(&self) -> &Capability {
        &self.required_authority
    }
    #[must_use]
    pub const fn timeout(&self) -> ToolTimeout {
        self.timeout
    }
    #[must_use]
    pub const fn cancellation(&self) -> ToolCancellation {
        self.cancellation
    }
    #[must_use]
    pub const fn effect_class(&self) -> EffectClass {
        self.effect_class
    }
    #[must_use]
    pub const fn idempotency(&self) -> IdempotencyContract {
        self.idempotency
    }
    #[must_use]
    pub const fn with_required_approval(mut self) -> Self {
        self.requires_approval = true;
        self
    }
    #[must_use]
    pub const fn requires_approval(&self) -> bool {
        self.requires_approval
    }

    /// Validate the closed, bounded JSON-Schema subset accepted by Navigator:
    /// `type`, `required`, `properties`, `items`, and `additionalProperties`.
    /// Unknown schema keywords are rejected at registration, rather than
    /// silently promising validation that will not occur.
    pub fn validate_input(&self, value: &[u8]) -> Result<(), ToolDomainError> {
        validate_json_value(self.input_schema.as_bytes(), value)
    }

    pub fn validate_output(&self, value: &[u8]) -> Result<(), ToolDomainError> {
        validate_json_value(self.output_schema.as_bytes(), value)
    }
}

fn json_is_object(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes).is_ok_and(|value| value.is_object())
}

fn validate_json_value(schema: &[u8], value: &[u8]) -> Result<(), ToolDomainError> {
    let schema: Value = serde_json::from_slice(schema).map_err(|_| ToolDomainError::InvalidJson)?;
    let value: Value = serde_json::from_slice(value).map_err(|_| ToolDomainError::InvalidJson)?;
    validate_schema_node(&schema, &value, 0)
}

fn validate_schema_shape(schema: &Value, depth: usize) -> Result<(), ToolDomainError> {
    if depth > 32 {
        return Err(ToolDomainError::UnsupportedSchema);
    }
    let object = schema
        .as_object()
        .ok_or(ToolDomainError::UnsupportedSchema)?;
    if object.is_empty() {
        return Ok(());
    }
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "type" | "required" | "properties" | "items" | "additionalProperties"
        )
    }) {
        return Err(ToolDomainError::UnsupportedSchema);
    }
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(ToolDomainError::UnsupportedSchema)?;
    if !matches!(
        kind,
        "object" | "array" | "string" | "integer" | "number" | "boolean" | "null"
    ) {
        return Err(ToolDomainError::UnsupportedSchema);
    }
    if let Some(required) = object.get("required") {
        let values = required
            .as_array()
            .ok_or(ToolDomainError::UnsupportedSchema)?;
        if values.iter().any(|v| v.as_str().is_none()) {
            return Err(ToolDomainError::UnsupportedSchema);
        }
    }
    if let Some(properties) = object.get("properties") {
        let values = properties
            .as_object()
            .ok_or(ToolDomainError::UnsupportedSchema)?;
        for child in values.values() {
            validate_schema_shape(child, depth + 1)?;
        }
    }
    if let Some(items) = object.get("items") {
        validate_schema_shape(items, depth + 1)?;
    }
    if object
        .get("additionalProperties")
        .is_some_and(|v| !v.is_boolean())
    {
        return Err(ToolDomainError::UnsupportedSchema);
    }
    Ok(())
}

fn validate_schema_node(
    schema: &Value,
    value: &Value,
    depth: usize,
) -> Result<(), ToolDomainError> {
    if depth > 32 {
        return Err(ToolDomainError::UnsupportedSchema);
    }
    let object = schema
        .as_object()
        .ok_or(ToolDomainError::UnsupportedSchema)?;
    if object.is_empty() {
        return Ok(());
    }
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "type" | "required" | "properties" | "items" | "additionalProperties"
        )
    }) {
        return Err(ToolDomainError::UnsupportedSchema);
    }
    let expected = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(ToolDomainError::UnsupportedSchema)?;
    let type_matches = match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => return Err(ToolDomainError::UnsupportedSchema),
    };
    if !type_matches {
        return Err(ToolDomainError::SchemaMismatch);
    }
    if expected == "object" {
        let values = value.as_object().expect("type checked");
        let properties = object.get("properties").and_then(Value::as_object);
        if let Some(required) = object.get("required") {
            let required = required
                .as_array()
                .ok_or(ToolDomainError::UnsupportedSchema)?;
            for key in required {
                let key = key.as_str().ok_or(ToolDomainError::UnsupportedSchema)?;
                if !values.contains_key(key) {
                    return Err(ToolDomainError::SchemaMismatch);
                }
            }
        }
        if object.get("additionalProperties") == Some(&Value::Bool(false))
            && values
                .keys()
                .any(|key| properties.is_none_or(|p| !p.contains_key(key)))
        {
            return Err(ToolDomainError::SchemaMismatch);
        }
        if let Some(properties) = properties {
            for (key, child) in properties {
                if let Some(child_value) = values.get(key) {
                    validate_schema_node(child, child_value, depth + 1)?;
                }
            }
        }
    } else if expected == "array" {
        if let Some(items) = object.get("items") {
            for item in value.as_array().expect("type checked") {
                validate_schema_node(items, item, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn validate_stable_identifier(value: &str) -> Result<(), ToolDomainError> {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !value.starts_with(['.', '-', '_'])
        && !value.ends_with(['.', '-', '_'])
    {
        Ok(())
    } else {
        Err(ToolDomainError::InvalidStableIdentifier)
    }
}

impl TryFrom<ToolDefinitionWire> for ToolDefinition {
    type Error = ToolDomainError;
    fn try_from(v: ToolDefinitionWire) -> Result<Self, Self::Error> {
        let definition = Self::new(
            v.name,
            v.version,
            v.input_schema,
            v.output_schema,
            v.required_authority,
            v.timeout,
            v.cancellation,
            v.effect_class,
            v.idempotency,
        )?;
        Ok(if v.requires_approval {
            definition.with_required_approval()
        } else {
            definition
        })
    }
}
impl From<ToolDefinition> for ToolDefinitionWire {
    fn from(v: ToolDefinition) -> Self {
        Self {
            name: v.name,
            version: v.version,
            input_schema: v.input_schema,
            output_schema: v.output_schema,
            required_authority: v.required_authority,
            timeout: v.timeout,
            cancellation: v.cancellation,
            effect_class: v.effect_class,
            idempotency: v.idempotency,
            requires_approval: v.requires_approval,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ToolInvocationWire", into = "ToolInvocationWire")]
pub struct ToolInvocation {
    invocation_id: ToolInvocationId,
    request_id: RequestId,
    session_id: SessionId,
    participant_id: ParticipantId,
    operation_id: OperationId,
    tool_name: ToolName,
    tool_version: ToolVersion,
    input: CanonicalJson<MAX_TOOL_INLINE_BYTES>,
    authority_grant_id: Option<GrantId>,
    approval_grant_id: Option<GrantId>,
    approval_effect_id: Option<RequestId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ToolInvocationWire {
    invocation_id: ToolInvocationId,
    request_id: RequestId,
    session_id: SessionId,
    participant_id: ParticipantId,
    operation_id: OperationId,
    tool_name: ToolName,
    tool_version: ToolVersion,
    input: CanonicalJson<MAX_TOOL_INLINE_BYTES>,
    authority_grant_id: Option<GrantId>,
    #[serde(default)]
    approval_grant_id: Option<GrantId>,
    #[serde(default)]
    approval_effect_id: Option<RequestId>,
}

impl ToolInvocation {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        invocation_id: ToolInvocationId,
        request_id: RequestId,
        session_id: SessionId,
        participant_id: ParticipantId,
        operation_id: OperationId,
        tool_name: ToolName,
        tool_version: ToolVersion,
        input: CanonicalJson<MAX_TOOL_INLINE_BYTES>,
    ) -> Result<Self, ToolDomainError> {
        validate_stable_identifier(tool_name.as_str())?;
        validate_stable_identifier(tool_version.as_str())?;
        Ok(Self {
            invocation_id,
            request_id,
            session_id,
            participant_id,
            operation_id,
            tool_name,
            tool_version,
            input,
            authority_grant_id: None,
            approval_grant_id: None,
            approval_effect_id: None,
        })
    }
    #[must_use]
    pub const fn with_authority_grant(mut self, grant_id: GrantId) -> Self {
        self.authority_grant_id = Some(grant_id);
        self
    }
    #[must_use]
    pub const fn with_approval_grant(mut self, grant_id: GrantId, effect_id: RequestId) -> Self {
        self.approval_grant_id = Some(grant_id);
        self.approval_effect_id = Some(effect_id);
        self
    }
    #[must_use]
    pub const fn invocation_id(&self) -> ToolInvocationId {
        self.invocation_id
    }
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }
    #[must_use]
    pub const fn participant_id(&self) -> ParticipantId {
        self.participant_id
    }
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }
    #[must_use]
    pub fn tool_name(&self) -> &str {
        self.tool_name.as_str()
    }
    #[must_use]
    pub fn tool_version(&self) -> &str {
        self.tool_version.as_str()
    }
    #[must_use]
    pub fn input(&self) -> &[u8] {
        self.input.as_bytes()
    }
    #[must_use]
    pub const fn authority_grant_id(&self) -> Option<GrantId> {
        self.authority_grant_id
    }
    #[must_use]
    pub const fn approval_grant_id(&self) -> Option<GrantId> {
        self.approval_grant_id
    }
    #[must_use]
    pub const fn approval_effect_id(&self) -> Option<RequestId> {
        self.approval_effect_id
    }
}
impl TryFrom<ToolInvocationWire> for ToolInvocation {
    type Error = ToolDomainError;
    fn try_from(v: ToolInvocationWire) -> Result<Self, Self::Error> {
        let invocation = Self::new(
            v.invocation_id,
            v.request_id,
            v.session_id,
            v.participant_id,
            v.operation_id,
            v.tool_name,
            v.tool_version,
            v.input,
        )?;
        Ok(Self {
            authority_grant_id: v.authority_grant_id,
            approval_grant_id: v.approval_grant_id,
            approval_effect_id: v.approval_effect_id,
            ..invocation
        })
    }
}
impl From<ToolInvocation> for ToolInvocationWire {
    fn from(v: ToolInvocation) -> Self {
        Self {
            invocation_id: v.invocation_id,
            request_id: v.request_id,
            session_id: v.session_id,
            participant_id: v.participant_id,
            operation_id: v.operation_id,
            tool_name: v.tool_name,
            tool_version: v.tool_version,
            input: v.input,
            authority_grant_id: v.authority_grant_id,
            approval_grant_id: v.approval_grant_id,
            approval_effect_id: v.approval_effect_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolFailureKind {
    InvalidInput,
    InvalidOutput,
    Unauthorized,
    TimedOut,
    Cancelled,
    ProviderUnavailable,
    HandlerFailed,
    EffectUncertain,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolFailure {
    pub invocation_id: ToolInvocationId,
    pub kind: ToolFailureKind,
    pub message: BoundedText<MAX_TOOL_FAILURE_MESSAGE_BYTES>,
    pub retryable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ToolResultWire", into = "ToolResultWire")]
pub struct ToolResult {
    invocation_id: ToolInvocationId,
    output: CanonicalJson<MAX_TOOL_INLINE_BYTES>,
    artifacts: Vec<ArtifactRef>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ToolResultWire {
    invocation_id: ToolInvocationId,
    output: CanonicalJson<MAX_TOOL_INLINE_BYTES>,
    artifacts: Vec<ArtifactRef>,
}
impl ToolResult {
    pub fn new(
        invocation_id: ToolInvocationId,
        output: CanonicalJson<MAX_TOOL_INLINE_BYTES>,
        artifacts: Vec<ArtifactRef>,
    ) -> Result<Self, ToolDomainError> {
        if artifacts.len() > MAX_TOOL_ARTIFACT_REFS {
            return Err(ToolDomainError::TooManyArtifacts);
        }
        Ok(Self {
            invocation_id,
            output,
            artifacts,
        })
    }
    #[must_use]
    pub const fn invocation_id(&self) -> ToolInvocationId {
        self.invocation_id
    }
    #[must_use]
    pub fn output(&self) -> &[u8] {
        self.output.as_bytes()
    }
    #[must_use]
    pub fn artifacts(&self) -> &[ArtifactRef] {
        &self.artifacts
    }
}
impl TryFrom<ToolResultWire> for ToolResult {
    type Error = ToolDomainError;
    fn try_from(v: ToolResultWire) -> Result<Self, Self::Error> {
        Self::new(v.invocation_id, v.output, v.artifacts)
    }
}
impl From<ToolResult> for ToolResultWire {
    fn from(v: ToolResult) -> Self {
        Self {
            invocation_id: v.invocation_id,
            output: v.output,
            artifacts: v.artifacts,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ToolDomainError {
    #[error("invalid JSON")]
    InvalidJson,
    #[error("value exceeds its bound")]
    TooLarge,
    #[error("tool name or version is not a stable identifier")]
    InvalidStableIdentifier,
    #[error("tool timeout is zero or exceeds its bound")]
    InvalidTimeout,
    #[error("effect class contradicts the idempotency contract")]
    ContradictoryIdempotency,
    #[error("tool result contains too many artifact references")]
    TooManyArtifacts,
    #[error("input and output schemas must be JSON objects")]
    SchemaMustBeObject,
    #[error("JSON schema uses an unsupported or excessively deep construct")]
    UnsupportedSchema,
    #[error("JSON value does not satisfy its declared schema")]
    SchemaMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactDigest, ArtifactId, ArtifactMediaType};
    use uuid::Uuid;

    fn id<T>(value: u128, make: impl FnOnce(Uuid) -> Result<T, crate::InvalidIdentity>) -> T {
        make(Uuid::from_u128(value)).unwrap()
    }

    fn schema(value: &str) -> CanonicalJson<MAX_TOOL_SCHEMA_BYTES> {
        CanonicalJson::new(value).unwrap()
    }

    fn definition(
        class: EffectClass,
        contract: IdempotencyContract,
    ) -> Result<ToolDefinition, ToolDomainError> {
        ToolDefinition::new(
            ToolName::new("files.read").unwrap(),
            ToolVersion::new("v1").unwrap(),
            schema(r#"{"type":"object","properties":{"b":{},"a":{}}}"#),
            schema(r#"{"type":"object"}"#),
            Capability::new("tool.files.read").unwrap(),
            ToolTimeout::from_millis(5_000).unwrap(),
            ToolCancellation::Cooperative,
            class,
            contract,
        )
    }

    #[test]
    fn canonical_json_collapses_whitespace_and_recursive_object_order() {
        let left = CanonicalJson::<128>::new(br#" { "z": {"b":2,"a":1}, "a": 0 } "#).unwrap();
        let right = CanonicalJson::<128>::new(br#"{"a":0,"z":{"a":1,"b":2}}"#).unwrap();
        assert_eq!(left, right);
        assert_eq!(left.as_bytes(), br#"{"a":0,"z":{"a":1,"b":2}}"#);
    }

    #[test]
    fn every_effect_class_rejects_a_replay_contract_mutant() {
        let valid = [
            (EffectClass::ReadOnly, IdempotencyContract::NoExternalEffect),
            (
                EffectClass::Idempotent,
                IdempotencyContract::InvocationIdentity,
            ),
            (
                EffectClass::Transactional,
                IdempotencyContract::ExternalTransactionProof,
            ),
            (EffectClass::NonIdempotent, IdempotencyContract::NeverReplay),
            (EffectClass::Unknown, IdempotencyContract::NeverReplay),
        ];
        for (class, contract) in valid {
            assert!(definition(class, contract).is_ok());
        }
        assert_eq!(
            definition(
                EffectClass::NonIdempotent,
                IdempotencyContract::InvocationIdentity
            ),
            Err(ToolDomainError::ContradictoryIdempotency)
        );
        assert_eq!(
            definition(EffectClass::Unknown, IdempotencyContract::NoExternalEffect),
            Err(ToolDomainError::ContradictoryIdempotency)
        );
        assert_eq!(
            definition(EffectClass::Transactional, IdempotencyContract::NeverReplay),
            Err(ToolDomainError::ContradictoryIdempotency)
        );
    }

    #[test]
    fn persisted_definition_revalidates_identifier_schema_timeout_and_contract() {
        let encoded = serde_json::to_value(
            definition(
                EffectClass::Idempotent,
                IdempotencyContract::InvocationIdentity,
            )
            .unwrap(),
        )
        .unwrap();
        for (field, mutant) in [
            ("name", serde_json::json!("../escape")),
            ("input_schema", serde_json::json!("[]")),
            ("timeout", serde_json::json!(0)),
            ("idempotency", serde_json::json!("never_replay")),
        ] {
            let mut changed = encoded.clone();
            changed[field] = mutant;
            assert!(
                serde_json::from_value::<ToolDefinition>(changed).is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn result_and_artifact_reference_bounds_revalidate_on_decode() {
        let artifact = ArtifactRef::new(
            id(1, ArtifactId::from_uuid),
            id(2, SessionId::from_uuid),
            id(3, ParticipantId::from_uuid),
            id(4, OperationId::from_uuid),
            ArtifactMediaType::new("application/octet-stream").unwrap(),
            12,
            ArtifactDigest::from_bytes([9; 32]),
        )
        .unwrap();
        let invocation_id = id(5, ToolInvocationId::from_uuid);
        let result = ToolResult::new(
            invocation_id,
            CanonicalJson::new("{}").unwrap(),
            vec![artifact],
        )
        .unwrap();
        let mut encoded = serde_json::to_value(result).unwrap();
        encoded["artifacts"][0]["size"] = serde_json::json!(crate::MAX_ARTIFACT_BYTES + 1);
        assert!(serde_json::from_value::<ToolResult>(encoded).is_err());

        let artifacts = (0..=MAX_TOOL_ARTIFACT_REFS)
            .map(|_| {
                ArtifactRef::new(
                    id(1, ArtifactId::from_uuid),
                    id(2, SessionId::from_uuid),
                    id(3, ParticipantId::from_uuid),
                    id(4, OperationId::from_uuid),
                    ArtifactMediaType::new("text/plain").unwrap(),
                    1,
                    ArtifactDigest::from_bytes([1; 32]),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            ToolResult::new(invocation_id, CanonicalJson::new("{}").unwrap(), artifacts),
            Err(ToolDomainError::TooManyArtifacts)
        );
    }
}
