#![allow(clippy::doc_markdown, clippy::must_use_candidate)]

use hmac::{Hmac, Mac};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use subtle::ConstantTimeEq;
use thiserror::Error;

pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/navigator.driver.v1.rs"));
}

pub const PROTOCOL_V1: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
pub const MAX_CAPABILITIES: usize = 64;
pub const MAX_CAPABILITY_PARAMETERS: usize = 32;
pub const MAX_CAPABILITY_ID_BYTES: usize = 128;
pub const MAX_PARAMETER_KEY_BYTES: usize = 64;
pub const MAX_PARAMETER_VALUE_BYTES: usize = 1024;
pub const MAX_CONFIGURATION_BYTES: usize = 64 * 1024;
pub const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_PENDING_CORRELATIONS: usize = 128;
pub const MAX_PUBLIC_MESSAGE_BYTES: usize = 1024;
pub const MAX_IMPLEMENTATION_BYTES: usize = 128;
pub const MAX_TOOL_NAME_BYTES: usize = 128;
pub const MAX_TOOL_VERSION_BYTES: usize = 64;
pub const MAX_TOOL_INPUT_BYTES: usize = MAX_PAYLOAD_BYTES;
pub const MAX_TOOL_OUTPUT_BYTES: usize = MAX_PAYLOAD_BYTES;
pub const MAX_TOOL_ARTIFACT_REFS: usize = 32;
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_ARTIFACT_MEDIA_TYPE_BYTES: usize = 255;
pub const ARTIFACT_SHA256_BYTES: usize = 32;
pub const MAX_PENDING_TOOL_REQUESTS: usize = 128;
pub const ID_BYTES: usize = 16;
pub const AUTHENTICATOR_BYTES: usize = 32;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolCorrelationDisposition {
    New,
    Duplicate,
}

/// Bounded, effect-free correlation state for one Driver connection. Durable
/// replay remains the responsibility of the Navigator Tool broker.
#[derive(Debug, Default)]
pub struct ToolCorrelationGuard {
    commands: HashMap<Vec<u8>, [u8; 32]>,
    bindings: HashMap<Vec<u8>, ([u8; 32], Vec<u8>)>,
    terminals: HashMap<Vec<u8>, [u8; 32]>,
}

impl ToolCorrelationGuard {
    pub fn forget(&mut self, request_id: &[u8]) {
        self.commands.remove(request_id);
        self.bindings.remove(request_id);
        self.terminals.remove(request_id);
    }
    pub fn observe_command(
        &mut self,
        command: &v1::ToolCommand,
    ) -> Result<ToolCorrelationDisposition, ValidationError> {
        id(&command.request_id, "tool.request_id")?;
        let digest: [u8; 32] = Sha256::digest(command.encode_to_vec()).into();
        match self.commands.get(&command.request_id) {
            Some(existing) if existing == &digest => Ok(ToolCorrelationDisposition::Duplicate),
            Some(_) => Err(ValidationError::Invalid("tool.request_conflict")),
            None if self.commands.len() >= MAX_PENDING_TOOL_REQUESTS => {
                Err(ValidationError::Oversized("tool.pending_requests"))
            }
            None => {
                self.commands.insert(command.request_id.clone(), digest);
                Ok(ToolCorrelationDisposition::New)
            }
        }
    }

    pub fn observe_scoped_command(
        &mut self,
        instance: &v1::InstanceIdentity,
        command: &v1::ToolCommand,
    ) -> Result<ToolCorrelationDisposition, ValidationError> {
        let disposition = self.observe_command(command)?;
        let binding = (
            Sha256::digest(instance.encode_to_vec()).into(),
            command.operation_id.clone(),
        );
        match self.bindings.get(&command.request_id) {
            Some(existing) if existing != &binding => {
                Err(ValidationError::Invalid("tool.request_scope_conflict"))
            }
            Some(_) => Ok(disposition),
            None => {
                self.bindings.insert(command.request_id.clone(), binding);
                Ok(disposition)
            }
        }
    }

    pub fn observe_result(
        &mut self,
        result: &v1::ToolResultRequest,
    ) -> Result<ToolCorrelationDisposition, ValidationError> {
        if !self.commands.contains_key(&result.tool_request_id) {
            return Err(ValidationError::Invalid("tool.unknown_request"));
        }
        let digest: [u8; 32] = Sha256::digest(result.encode_to_vec()).into();
        match self.terminals.get(&result.tool_request_id) {
            Some(existing) if existing == &digest => Ok(ToolCorrelationDisposition::Duplicate),
            Some(_) => Err(ValidationError::Invalid("tool.terminal_conflict")),
            None => {
                self.terminals
                    .insert(result.tool_request_id.clone(), digest);
                Ok(ToolCorrelationDisposition::New)
            }
        }
    }

    pub fn observe_scoped_result(
        &mut self,
        operation_id: &[u8],
        result: &v1::ToolResultRequest,
    ) -> Result<ToolCorrelationDisposition, ValidationError> {
        let instance = result
            .instance
            .as_ref()
            .ok_or(ValidationError::Missing("instance"))?;
        let binding = (
            Sha256::digest(instance.encode_to_vec()).into(),
            operation_id.to_vec(),
        );
        if self.bindings.get(&result.tool_request_id) != Some(&binding) {
            return Err(ValidationError::Invalid("tool.result_scope_conflict"));
        }
        self.observe_result(result)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SettlementAction {
    Continue,
    Remind,
    Deadline,
    Terminal(v1::ReportKind),
    Disconnected,
}

#[derive(Debug)]
pub struct OperationReportGuard {
    operation_id: Vec<u8>,
    message_id: Vec<u8>,
    instance: v1::InstanceIdentity,
    reminder_issued: bool,
    terminal_seen: bool,
    pending_terminal: Option<(Vec<u8>, v1::ReportKind)>,
}

impl OperationReportGuard {
    pub fn new(
        operation_id: Vec<u8>,
        message_id: Vec<u8>,
        expected_instance: v1::InstanceIdentity,
    ) -> Result<Self, ValidationError> {
        id(&operation_id, "operation_id")?;
        id(&message_id, "message_id")?;
        instance(Some(&expected_instance))?;
        Ok(Self {
            operation_id,
            message_id,
            instance: expected_instance,
            reminder_issued: false,
            terminal_seen: false,
            pending_terminal: None,
        })
    }

    pub fn observe(
        &mut self,
        event: &v1::DriverEvent,
    ) -> Result<SettlementAction, ValidationError> {
        v1::Envelope {
            envelope_id: event.event_id.clone(),
            response_authenticator: Vec::new(),
            response_to_request_id: Vec::new(),
            body: Some(v1::envelope::Body::Event(event.clone())),
        }
        .validate()?;
        if event.instance.as_ref() != Some(&self.instance) {
            return Err(ValidationError::Invalid("report.instance"));
        }
        match event
            .event
            .as_ref()
            .ok_or(ValidationError::Missing("event"))?
        {
            v1::driver_event::Event::Report(report) => {
                if report.operation_id != self.operation_id || report.message_id != self.message_id
                {
                    return Err(ValidationError::Invalid("report.correlation"));
                }
                if self.terminal_seen {
                    return Err(ValidationError::Invalid("report.after_terminal"));
                }
                let result = report
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("report.result"))?;
                let kind = match result {
                    v1::report::Result::Outcome(outcome) => v1::ReportKind::try_from(outcome.kind)
                        .map_err(|_| ValidationError::Invalid("report.kind"))?,
                    v1::report::Result::Failure(_) => v1::ReportKind::ReportFailed,
                    v1::report::Result::ApprovalRequest(_) => {
                        return Ok(SettlementAction::Continue);
                    }
                };
                if matches!(
                    kind,
                    v1::ReportKind::Progress | v1::ReportKind::Question | v1::ReportKind::Blocked
                ) {
                    if self.pending_terminal.is_some() {
                        return Err(ValidationError::Invalid("report.after_terminal"));
                    }
                    Ok(SettlementAction::Continue)
                } else {
                    match &self.pending_terminal {
                        Some((event_id, pending_kind))
                            if event_id == &event.event_id && *pending_kind == kind => {}
                        Some(_) => {
                            return Err(ValidationError::Invalid("report.terminal_conflict"));
                        }
                        None => {
                            self.pending_terminal = Some((event.event_id.clone(), kind));
                        }
                    }
                    Ok(SettlementAction::Terminal(kind))
                }
            }
            v1::driver_event::Event::Disconnected(_) => Ok(SettlementAction::Disconnected),
            _ => Ok(SettlementAction::Continue),
        }
    }

    pub fn terminal_committed(&mut self, event_id: &[u8]) -> Result<(), ValidationError> {
        match self.pending_terminal.as_ref() {
            Some((pending_id, _)) if pending_id == event_id => {
                self.pending_terminal = None;
                self.terminal_seen = true;
                Ok(())
            }
            _ => Err(ValidationError::Invalid("report.terminal_commit")),
        }
    }

    pub fn settled_without_report(&mut self) -> SettlementAction {
        if self.terminal_seen || self.pending_terminal.is_some() {
            return SettlementAction::Continue;
        }
        if self.reminder_issued {
            SettlementAction::Deadline
        } else {
            self.reminder_issued = true;
            SettlementAction::Remind
        }
    }
}

pub fn request_digest(canonical_request_body: &[u8]) -> [u8; 32] {
    Sha256::digest(canonical_request_body).into()
}

pub fn sign_response(secret: &[u8], envelope: &mut v1::Envelope) -> Result<(), ValidationError> {
    if !is_response(envelope) {
        return Err(ValidationError::Invalid("response"));
    }
    envelope.response_authenticator.clear();
    let digest = Sha256::digest(envelope.encode_to_vec());
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| ValidationError::Invalid("response.authentication"))?;
    mac.update(b"navigator.driver.response.v1\0");
    mac.update(&digest);
    envelope.response_authenticator = mac.finalize().into_bytes().to_vec();
    Ok(())
}

pub fn verify_response(secret: &[u8], envelope: &v1::Envelope) -> Result<(), ValidationError> {
    if !is_response(envelope) || envelope.response_authenticator.len() != AUTHENTICATOR_BYTES {
        return Err(ValidationError::Invalid("response.authentication"));
    }
    let mut canonical = envelope.clone();
    canonical.response_authenticator.clear();
    let digest = Sha256::digest(canonical.encode_to_vec());
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| ValidationError::Invalid("response.authentication"))?;
    mac.update(b"navigator.driver.response.v1\0");
    mac.update(&digest);
    let expected = mac.finalize().into_bytes();
    if expected
        .ct_eq(envelope.response_authenticator.as_slice())
        .unwrap_u8()
        == 1
    {
        Ok(())
    } else {
        Err(ValidationError::Invalid("response.authentication"))
    }
}

fn is_response(envelope: &v1::Envelope) -> bool {
    use v1::envelope::Body;
    matches!(
        envelope.body,
        Some(
            Body::DescribeResponse(_)
                | Body::StartResponse(_)
                | Body::InspectResponse(_)
                | Body::DeliverResponse(_)
                | Body::AcceptanceResponse(_)
                | Body::CancelResponse(_)
                | Body::StopResponse(_)
                | Body::Event(_)
                | Body::ObserveResponse(_)
                | Body::RemindResponse(_)
                | Body::HierarchyResultResponse(_)
                | Body::ToolResultResponse(_)
        )
    )
}

pub fn canonical_request_digest(envelope: &v1::Envelope) -> Result<[u8; 32], ValidationError> {
    let mut canonical = envelope.clone();
    let metadata =
        request_metadata_mut(&mut canonical).ok_or(ValidationError::Invalid("request"))?;
    let authentication = metadata
        .authentication
        .as_mut()
        .ok_or(ValidationError::Missing("authentication"))?;
    authentication.authenticator.clear();
    authentication.request_digest.clear();
    Ok(request_digest(&canonical.encode_to_vec()))
}

#[derive(Debug)]
pub struct ReplayGuard {
    capacity: usize,
    order: VecDeque<(Vec<u8>, Vec<u8>, i64)>,
    seen: HashSet<(Vec<u8>, Vec<u8>)>,
}

impl ReplayGuard {
    pub fn new(capacity: usize) -> Result<Self, ValidationError> {
        if capacity == 0 {
            return Err(ValidationError::Invalid("replay_guard.capacity"));
        }
        Ok(Self {
            capacity,
            order: VecDeque::with_capacity(capacity),
            seen: HashSet::with_capacity(capacity),
        })
    }

    pub fn consume(
        &mut self,
        key_id: &[u8],
        nonce: &[u8],
        expires: i64,
        now: i64,
    ) -> Result<(), ValidationError> {
        while self.order.front().is_some_and(|entry| entry.2 <= now) {
            let (key, nonce, _) = self.order.pop_front().expect("front exists");
            self.seen.remove(&(key, nonce));
        }
        let entry = (key_id.to_vec(), nonce.to_vec());
        if self.seen.contains(&entry) {
            return Err(ValidationError::Invalid("authentication.replay"));
        }
        if self.order.len() == self.capacity {
            return Err(ValidationError::Oversized("replay_guard"));
        }
        self.seen.insert(entry.clone());
        self.order.push_back((entry.0, entry.1, expires));
        Ok(())
    }
}

pub fn verify_envelope_authentication(
    secret: &[u8],
    envelope: &v1::Envelope,
    participant_scope: &[u8],
    launch_scope: &[u8],
    now_unix_ms: i64,
    replay_guard: &mut ReplayGuard,
) -> Result<(), ValidationError> {
    envelope.validate_before_decode()?;
    let metadata = request_metadata(envelope).ok_or(ValidationError::Invalid("request"))?;
    let authentication = metadata
        .authentication
        .as_ref()
        .ok_or(ValidationError::Missing("authentication"))?;
    let actual_digest = canonical_request_digest(envelope)?;
    if actual_digest
        .ct_eq(authentication.request_digest.as_slice())
        .unwrap_u8()
        != 1
    {
        return Err(ValidationError::Invalid("authentication.request_digest"));
    }
    verify_authentication(
        secret,
        &envelope.envelope_id,
        metadata,
        participant_scope,
        launch_scope,
        now_unix_ms,
    )?;
    replay_guard.consume(
        &authentication.key_id,
        &authentication.nonce,
        authentication.expires_unix_ms,
        now_unix_ms,
    )
}

pub fn authentication_tag(
    secret: &[u8],
    envelope_id: &[u8],
    request_id: &[u8],
    protocol_version: u32,
    authentication: &v1::Authentication,
    participant_scope: &[u8],
    launch_scope: &[u8],
) -> Result<[u8; 32], ValidationError> {
    id(envelope_id, "envelope_id")?;
    id(request_id, "request_id")?;
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| ValidationError::Invalid("authentication.secret"))?;
    mac.update(b"navigator.driver.v1\0");
    for value in [
        envelope_id,
        request_id,
        &authentication.key_id,
        &authentication.nonce,
        &authentication.request_digest,
        participant_scope,
        launch_scope,
    ] {
        mac.update(&(value.len() as u64).to_be_bytes());
        mac.update(value);
    }
    mac.update(&protocol_version.to_be_bytes());
    mac.update(&authentication.expires_unix_ms.to_be_bytes());
    Ok(mac.finalize().into_bytes().into())
}

pub fn verify_authentication(
    secret: &[u8],
    envelope_id: &[u8],
    metadata: &v1::RequestMetadata,
    participant_scope: &[u8],
    launch_scope: &[u8],
    now_unix_ms: i64,
) -> Result<(), ValidationError> {
    let auth = metadata
        .authentication
        .as_ref()
        .ok_or(ValidationError::Missing("authentication"))?;
    if auth.expires_unix_ms <= now_unix_ms {
        return Err(ValidationError::Invalid("authentication.expired"));
    }
    let expected = authentication_tag(
        secret,
        envelope_id,
        &metadata.request_id,
        metadata.protocol_version,
        auth,
        participant_scope,
        launch_scope,
    )?;
    if expected
        .as_slice()
        .ct_eq(auth.authenticator.as_slice())
        .unwrap_u8()
        != 1
    {
        return Err(ValidationError::Invalid("authentication.tag"));
    }
    Ok(())
}

fn request_metadata(value: &v1::Envelope) -> Option<&v1::RequestMetadata> {
    use v1::envelope::Body;
    match value.body.as_ref()? {
        Body::DescribeRequest(v) => v.metadata.as_ref(),
        Body::StartRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::InspectRequest(v) => v.metadata.as_ref(),
        Body::DeliverRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::AcceptanceRequest(v) => v.metadata.as_ref(),
        Body::CancelRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::StopRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::ObserveRequest(v) => v.metadata.as_ref(),
        Body::RemindRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::HierarchyResultRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        Body::ToolResultRequest(v) => v.metadata.as_ref()?.request.as_ref(),
        _ => None,
    }
}

fn request_metadata_mut(value: &mut v1::Envelope) -> Option<&mut v1::RequestMetadata> {
    use v1::envelope::Body;
    match value.body.as_mut()? {
        Body::DescribeRequest(v) => v.metadata.as_mut(),
        Body::StartRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::InspectRequest(v) => v.metadata.as_mut(),
        Body::DeliverRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::AcceptanceRequest(v) => v.metadata.as_mut(),
        Body::CancelRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::StopRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::ObserveRequest(v) => v.metadata.as_mut(),
        Body::RemindRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::HierarchyResultRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        Body::ToolResultRequest(v) => v.metadata.as_mut()?.request.as_mut(),
        _ => None,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("encoded frame exceeds the limit")]
    FrameTooLarge,
    #[error("required field is absent: {0}")]
    Missing(&'static str),
    #[error("invalid field: {0}")]
    Invalid(&'static str),
    #[error("field exceeds its limit: {0}")]
    Oversized(&'static str),
    #[error("protocol version is unsupported")]
    UnsupportedVersion,
    #[error("required capability is unsupported: {0}")]
    UnsupportedCapability(String),
}

pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
    fn validate_before_decode(&self) -> Result<(), ValidationError>
    where
        Self: Message,
    {
        if self.encoded_len() > MAX_FRAME_BYTES {
            return Err(ValidationError::FrameTooLarge);
        }
        self.validate()
    }
}

pub fn decode_envelope(bytes: &[u8]) -> Result<v1::Envelope, ValidationError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ValidationError::FrameTooLarge);
    }
    let envelope = v1::Envelope::decode(bytes).map_err(|_| ValidationError::Invalid("envelope"))?;
    envelope.validate()?;
    Ok(envelope)
}

fn id(bytes: &[u8], field: &'static str) -> Result<(), ValidationError> {
    if bytes.len() != ID_BYTES || bytes.iter().all(|byte| *byte == 0) {
        return Err(ValidationError::Invalid(field));
    }
    Ok(())
}

fn bounded(bytes: &[u8], limit: usize, field: &'static str) -> Result<(), ValidationError> {
    if bytes.len() > limit {
        return Err(ValidationError::Oversized(field));
    }
    Ok(())
}

fn canonical_json(bytes: &[u8], limit: usize, field: &'static str) -> Result<(), ValidationError> {
    bounded(bytes, limit, field)?;
    if bytes.is_empty() {
        return Err(ValidationError::Invalid(field));
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| ValidationError::Invalid(field))?;
    let encoded = serde_json::to_vec(&value).map_err(|_| ValidationError::Invalid(field))?;
    if encoded == bytes {
        Ok(())
    } else {
        Err(ValidationError::Invalid(field))
    }
}

fn tool_identifier(value: &str, limit: usize, field: &'static str) -> Result<(), ValidationError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || value.starts_with(['.', '-', '_'])
        || value.ends_with(['.', '-', '_'])
    {
        return Err(ValidationError::Invalid(field));
    }
    bounded(value.as_bytes(), limit, field)
}

fn tool_result(value: &v1::ToolCallResult) -> Result<(), ValidationError> {
    canonical_json(&value.output, MAX_TOOL_OUTPUT_BYTES, "tool.output")?;
    if value.artifacts.len() > MAX_TOOL_ARTIFACT_REFS {
        return Err(ValidationError::Oversized("tool.artifacts"));
    }
    for artifact in &value.artifacts {
        id(&artifact.artifact_id, "tool.artifact.artifact_id")?;
        id(&artifact.session_id, "tool.artifact.session_id")?;
        id(
            &artifact.creator_participant_id,
            "tool.artifact.creator_participant_id",
        )?;
        id(
            &artifact.creator_operation_id,
            "tool.artifact.creator_operation_id",
        )?;
        if artifact.media_type.is_empty() {
            return Err(ValidationError::Invalid("tool.artifact.media_type"));
        }
        bounded(
            artifact.media_type.as_bytes(),
            MAX_ARTIFACT_MEDIA_TYPE_BYTES,
            "tool.artifact.media_type",
        )?;
        if artifact.size > MAX_ARTIFACT_BYTES {
            return Err(ValidationError::Oversized("tool.artifact.size"));
        }
        if artifact.sha256.len() != ARTIFACT_SHA256_BYTES {
            return Err(ValidationError::Invalid("tool.artifact.sha256"));
        }
    }
    Ok(())
}

fn metadata(value: &v1::RequestMetadata) -> Result<(), ValidationError> {
    if value.protocol_version != PROTOCOL_V1 {
        return Err(ValidationError::UnsupportedVersion);
    }
    if value.required_capabilities.len() > MAX_CAPABILITIES {
        return Err(ValidationError::Oversized("required_capabilities"));
    }
    let auth = value
        .authentication
        .as_ref()
        .ok_or(ValidationError::Missing("authentication"))?;
    id(&auth.key_id, "authentication.key_id")?;
    id(&auth.nonce, "authentication.nonce")?;
    if auth.expires_unix_ms <= 0
        || auth.authenticator.len() != AUTHENTICATOR_BYTES
        || auth.request_digest.len() != 32
    {
        return Err(ValidationError::Invalid("authentication"));
    }
    for requirement in &value.required_capabilities {
        capability_requirement(requirement)?;
    }
    id(&value.request_id, "request_id")?;
    Ok(())
}

fn mutation(value: Option<&v1::MutationMetadata>) -> Result<(), ValidationError> {
    let value = value.ok_or(ValidationError::Missing("metadata"))?;
    let request = value
        .request
        .as_ref()
        .ok_or(ValidationError::Missing("request_metadata"))?;
    metadata(request)
}

fn capability_requirement(value: &v1::CapabilityRequirement) -> Result<(), ValidationError> {
    if value.id.is_empty() || value.minimum_version == 0 {
        return Err(ValidationError::Invalid("capability_requirement"));
    }
    bounded(
        value.id.as_bytes(),
        MAX_CAPABILITY_ID_BYTES,
        "capability.id",
    )?;
    parameters(&value.parameters)
}

fn capability(value: &v1::Capability) -> Result<(), ValidationError> {
    if value.id.is_empty() || value.version == 0 {
        return Err(ValidationError::Invalid("capability"));
    }
    bounded(
        value.id.as_bytes(),
        MAX_CAPABILITY_ID_BYTES,
        "capability.id",
    )?;
    parameters(&value.parameters)
}

fn parameters(values: &[v1::CapabilityParameter]) -> Result<(), ValidationError> {
    if values.len() > MAX_CAPABILITY_PARAMETERS {
        return Err(ValidationError::Oversized("capability.parameters"));
    }
    let mut keys = HashSet::new();
    for value in values {
        if value.key.is_empty() {
            return Err(ValidationError::Invalid("capability.parameter.key"));
        }
        bounded(
            value.key.as_bytes(),
            MAX_PARAMETER_KEY_BYTES,
            "capability.parameter.key",
        )?;
        bounded(
            value.value.as_bytes(),
            MAX_PARAMETER_VALUE_BYTES,
            "capability.parameter.value",
        )?;
        if !keys.insert(value.key.as_str()) {
            return Err(ValidationError::Invalid("capability.parameter.duplicate"));
        }
    }
    Ok(())
}

pub fn require_capabilities(
    required: &[v1::CapabilityRequirement],
    supported: &[v1::Capability],
) -> Result<(), ValidationError> {
    let mut supported_by_id = HashMap::new();
    for item in supported {
        capability(item)?;
        if supported_by_id.insert(item.id.as_str(), item).is_some() {
            return Err(ValidationError::Invalid("capability.duplicate"));
        }
    }
    let mut required_ids = HashSet::new();
    for requirement in required {
        capability_requirement(requirement)?;
        if !required_ids.insert(requirement.id.as_str()) {
            return Err(ValidationError::Invalid("capability_requirement.duplicate"));
        }
        let Some(supported) = supported_by_id.get(requirement.id.as_str()) else {
            return Err(ValidationError::UnsupportedCapability(
                requirement.id.clone(),
            ));
        };
        let supported_parameters: HashMap<&str, &str> = supported
            .parameters
            .iter()
            .map(|p| (p.key.as_str(), p.value.as_str()))
            .collect();
        if supported.version < requirement.minimum_version
            || requirement
                .parameters
                .iter()
                .any(|p| supported_parameters.get(p.key.as_str()) != Some(&p.value.as_str()))
        {
            return Err(ValidationError::UnsupportedCapability(
                requirement.id.clone(),
            ));
        }
    }
    Ok(())
}

fn instance(value: Option<&v1::InstanceIdentity>) -> Result<(), ValidationError> {
    let value = value.ok_or(ValidationError::Missing("instance"))?;
    id(&value.driver_id, "driver_id")?;
    id(&value.participant_id, "participant_id")?;
    id(&value.launch_attempt_id, "launch_attempt_id")?;
    id(&value.instance_id, "instance_id").and_then(|()| id(&value.session_id, "session_id"))?;
    if value.ownership_epoch == 0 {
        return Err(ValidationError::Invalid("ownership_epoch"));
    }
    Ok(())
}

fn failure(value: Option<&v1::Failure>) -> Result<(), ValidationError> {
    if let Some(value) = value {
        bounded(
            value.message.as_bytes(),
            MAX_PUBLIC_MESSAGE_BYTES,
            "failure.message",
        )?;
        if v1::FailureCode::try_from(value.code).is_err()
            || value.code == v1::FailureCode::Unspecified as i32
        {
            return Err(ValidationError::Invalid("failure.code"));
        }
    }
    Ok(())
}

fn reply(id_value: &[u8]) -> Result<(), ValidationError> {
    id(id_value, "in_reply_to")
}

fn acceptance(value: i32) -> Result<(), ValidationError> {
    if v1::Acceptance::try_from(value).is_err() || value == 0 {
        Err(ValidationError::Invalid("acceptance"))
    } else {
        Ok(())
    }
}

fn stop_result(value: &v1::StopResponse) -> Result<(), ValidationError> {
    reply(&value.in_reply_to)?;
    match value
        .result
        .as_ref()
        .ok_or(ValidationError::Missing("stop.result"))?
    {
        v1::stop_response::Result::Success(success) => {
            if v1::StopDisposition::try_from(success.disposition).is_err()
                || success.disposition == 0
            {
                Err(ValidationError::Invalid("stop.disposition"))
            } else {
                Ok(())
            }
        }
        v1::stop_response::Result::Failure(value) => failure(Some(value)),
    }
}

impl Validate for v1::Envelope {
    #[allow(clippy::too_many_lines)]
    fn validate(&self) -> Result<(), ValidationError> {
        use v1::envelope::Body;
        id(&self.envelope_id, "envelope_id")?;
        if !is_response(self)
            && (!self.response_authenticator.is_empty() || !self.response_to_request_id.is_empty())
        {
            return Err(ValidationError::Invalid("request.response_authentication"));
        }
        match self.body.as_ref().ok_or(ValidationError::Missing("body"))? {
            Body::DescribeRequest(value) => metadata(
                value
                    .metadata
                    .as_ref()
                    .ok_or(ValidationError::Missing("metadata"))?,
            ),
            Body::DescribeResponse(value) => {
                reply(&value.in_reply_to)?;
                let result = value
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("describe.result"))?;
                let v1::describe_response::Result::Success(value) = result else {
                    let v1::describe_response::Result::Failure(value) = result else {
                        unreachable!()
                    };
                    return failure(Some(value));
                };
                id(&value.driver_id, "driver_id")?;
                if value.implementation.is_empty() || value.implementation_version.is_empty() {
                    return Err(ValidationError::Invalid("implementation"));
                }
                bounded(
                    value.implementation.as_bytes(),
                    MAX_IMPLEMENTATION_BYTES,
                    "implementation",
                )?;
                bounded(
                    value.implementation_version.as_bytes(),
                    MAX_IMPLEMENTATION_BYTES,
                    "implementation_version",
                )?;
                let protocol = value
                    .protocol
                    .as_ref()
                    .ok_or(ValidationError::Missing("protocol"))?;
                if protocol.minimum == 0 || protocol.minimum > protocol.maximum {
                    return Err(ValidationError::Invalid("protocol_range"));
                }
                if value.capabilities.len() > MAX_CAPABILITIES {
                    return Err(ValidationError::Oversized("capabilities"));
                }
                let mut ids = HashSet::new();
                for item in &value.capabilities {
                    capability(item)?;
                    if !ids.insert(item.id.as_str()) {
                        return Err(ValidationError::Invalid("capability.duplicate"));
                    }
                }
                Ok(())
            }
            Body::StartRequest(value) => {
                mutation(value.metadata.as_ref())?;
                id(&value.participant_id, "participant_id")?;
                id(&value.launch_attempt_id, "launch_attempt_id")?;
                id(&value.instance_id, "instance_id")?;
                id(&value.session_id, "session_id")?;
                if value.ownership_epoch == 0 {
                    return Err(ValidationError::Invalid("ownership_epoch"));
                }
                bounded(
                    &value.trusted_configuration,
                    MAX_CONFIGURATION_BYTES,
                    "trusted_configuration",
                )
            }
            Body::StartResponse(value) => {
                reply(&value.in_reply_to)?;
                match value
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("start.result"))?
                {
                    v1::start_response::Result::Failure(value) => failure(Some(value)),
                    v1::start_response::Result::Success(value) => {
                        match v1::StartDisposition::try_from(value.disposition) {
                            Ok(v1::StartDisposition::Started) => instance(value.instance.as_ref()),
                            Ok(v1::StartDisposition::StartUnknown) if value.instance.is_none() => {
                                Ok(())
                            }
                            _ => Err(ValidationError::Invalid("start.outcome")),
                        }
                    }
                }
            }
            Body::InspectRequest(value) => {
                metadata(
                    value
                        .metadata
                        .as_ref()
                        .ok_or(ValidationError::Missing("metadata"))?,
                )?;
                instance(value.instance.as_ref())
            }
            Body::InspectResponse(value) => {
                reply(&value.in_reply_to)?;
                match value
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("inspect.result"))?
                {
                    v1::inspect_response::Result::Failure(value) => failure(Some(value)),
                    v1::inspect_response::Result::Success(value) => {
                        if v1::InstanceState::try_from(value.state).is_err() || value.state == 0 {
                            Err(ValidationError::Invalid("instance.state"))
                        } else {
                            Ok(())
                        }
                    }
                }
            }
            Body::DeliverRequest(value) => {
                mutation(value.metadata.as_ref())?;
                instance(value.instance.as_ref())?;
                id(&value.message_id, "message_id")?;
                id(&value.delivery_attempt_id, "delivery_attempt_id")?;
                if !value.operation_id.is_empty() {
                    id(&value.operation_id, "operation_id")?;
                }
                bounded(&value.payload, MAX_PAYLOAD_BYTES, "payload")?;
                if value.pending_correlations.len() > MAX_PENDING_CORRELATIONS {
                    return Err(ValidationError::Oversized("pending_correlations"));
                }
                let mut correlation_ids = HashSet::new();
                let mut parent_ids = HashSet::new();
                for correlation in &value.pending_correlations {
                    id(&correlation.correlation_id, "correlation_id")?;
                    id(&correlation.parent_message_id, "parent_message_id")?;
                    if correlation.parent_message_id == value.message_id
                        || !correlation_ids.insert(correlation.correlation_id.as_slice())
                        || !parent_ids.insert(correlation.parent_message_id.as_slice())
                    {
                        return Err(ValidationError::Invalid("pending_correlations.ambiguous"));
                    }
                }
                Ok(())
            }
            Body::DeliverResponse(value) => {
                reply(&value.in_reply_to)?;
                match value
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("delivery.result"))?
                {
                    v1::deliver_response::Result::Failure(value) => failure(Some(value)),
                    v1::deliver_response::Result::Success(value) => {
                        acceptance(value.acceptance)?;
                        id(&value.message_id, "message_id")?;
                        id(&value.delivery_attempt_id, "delivery_attempt_id")
                    }
                }
            }
            Body::AcceptanceRequest(value) => {
                metadata(
                    value
                        .metadata
                        .as_ref()
                        .ok_or(ValidationError::Missing("metadata"))?,
                )?;
                instance(value.instance.as_ref())?;
                id(&value.message_id, "message_id")?;
                id(&value.delivery_attempt_id, "delivery_attempt_id")
            }
            Body::AcceptanceResponse(value) => {
                reply(&value.in_reply_to)?;
                match value
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("acceptance.result"))?
                {
                    v1::acceptance_response::Result::Failure(value) => failure(Some(value)),
                    v1::acceptance_response::Result::Success(value) => {
                        acceptance(value.acceptance)?;
                        id(&value.delivery_attempt_id, "delivery_attempt_id")
                    }
                }
            }
            Body::CancelRequest(value) => {
                mutation(value.metadata.as_ref())?;
                instance(value.instance.as_ref())?;
                id(&value.operation_id, "operation_id")
            }
            Body::CancelResponse(value) => {
                reply(&value.in_reply_to)?;
                match value
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("cancel.result"))?
                {
                    v1::cancel_response::Result::Failure(value) => failure(Some(value)),
                    v1::cancel_response::Result::Success(value) => {
                        if v1::CancelDisposition::try_from(value.disposition).is_err()
                            || value.disposition == 0
                        {
                            Err(ValidationError::Invalid("cancel.disposition"))
                        } else {
                            Ok(())
                        }
                    }
                }
            }
            Body::StopRequest(value) => {
                mutation(value.metadata.as_ref())?;
                instance(value.instance.as_ref())
            }
            Body::StopResponse(value) => stop_result(value),
            Body::ObserveRequest(value) => {
                metadata(
                    value
                        .metadata
                        .as_ref()
                        .ok_or(ValidationError::Missing("metadata"))?,
                )?;
                instance(value.instance.as_ref())
            }
            Body::RemindRequest(value) => {
                mutation(value.metadata.as_ref())?;
                instance(value.instance.as_ref())?;
                id(&value.operation_id, "operation_id")?;
                id(&value.message_id, "message_id")
            }
            Body::RemindResponse(value) => {
                reply(&value.in_reply_to)?;
                match value
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("remind.result"))?
                {
                    v1::remind_response::Result::Failure(value) => failure(Some(value)),
                    v1::remind_response::Result::Success(value) => {
                        if value.disposition == v1::RemindDisposition::ReminderRequested as i32 {
                            Ok(())
                        } else {
                            Err(ValidationError::Invalid("remind.disposition"))
                        }
                    }
                }
            }
            Body::HierarchyResultRequest(value) => {
                mutation(value.metadata.as_ref())?;
                instance(value.instance.as_ref())?;
                id(&value.hierarchy_request_id, "hierarchy.request_id")?;
                match value
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("hierarchy.result"))?
                {
                    v1::hierarchy_result_request::Result::Spawned(result) => {
                        id(&result.participant_id, "hierarchy.participant_id")?;
                        id(&result.operation_id, "hierarchy.operation_id")?;
                        id(&result.input_message_id, "hierarchy.input_message_id")
                    }
                    v1::hierarchy_result_request::Result::Status(result) => {
                        id(&result.participant_id, "hierarchy.participant_id")?;
                        if !result.operation_id.is_empty() {
                            id(&result.operation_id, "hierarchy.operation_id")?;
                        }
                        bounded(
                            result.state.as_bytes(),
                            MAX_PUBLIC_MESSAGE_BYTES,
                            "hierarchy.state",
                        )
                    }
                    v1::hierarchy_result_request::Result::Sent(result) => {
                        id(&result.message_id, "hierarchy.message_id")
                    }
                    v1::hierarchy_result_request::Result::Cancelled(result) => {
                        id(&result.operation_id, "hierarchy.operation_id")
                    }
                    v1::hierarchy_result_request::Result::Failure(value) => failure(Some(value)),
                }
            }
            Body::HierarchyResultResponse(value) => {
                reply(&value.in_reply_to)?;
                id(&value.hierarchy_request_id, "hierarchy.request_id")
            }
            Body::ToolResultRequest(value) => {
                mutation(value.metadata.as_ref())?;
                instance(value.instance.as_ref())?;
                id(&value.tool_request_id, "tool.request_id")?;
                match value
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("tool.result"))?
                {
                    v1::tool_result_request::Result::Success(result) => tool_result(result),
                    v1::tool_result_request::Result::Failure(value) => failure(Some(value)),
                }
            }
            Body::ToolResultResponse(value) => {
                reply(&value.in_reply_to)?;
                id(&value.tool_request_id, "tool.request_id")
            }
            Body::ObserveResponse(value) => {
                reply(&value.in_reply_to)?;
                match value
                    .result
                    .as_ref()
                    .ok_or(ValidationError::Missing("observe.result"))?
                {
                    v1::observe_response::Result::Event(event) => v1::Envelope {
                        envelope_id: event.event_id.clone(),
                        response_authenticator: Vec::new(),
                        response_to_request_id: Vec::new(),
                        body: Some(Body::Event(event.as_ref().clone())),
                    }
                    .validate(),
                    v1::observe_response::Result::NoEvent(_) => Ok(()),
                }
            }
            Body::Event(value) => {
                id(&value.event_id, "event_id")?;
                id(&value.in_reply_to, "in_reply_to")?;
                instance(value.instance.as_ref())?;
                if value.sequence == 0 {
                    return Err(ValidationError::Invalid("event.sequence"));
                }
                let event = value
                    .event
                    .as_ref()
                    .ok_or(ValidationError::Missing("event"))?;
                if let v1::driver_event::Event::Report(report) = event {
                    id(&report.operation_id, "operation_id")?;
                    id(&report.message_id, "message_id")?;
                    id(&report.delivery_attempt_id, "delivery_attempt_id")?;
                    match report
                        .result
                        .as_ref()
                        .ok_or(ValidationError::Missing("report.result"))?
                    {
                        v1::report::Result::Failure(value) => failure(Some(value))?,
                        v1::report::Result::Outcome(value) => {
                            if v1::ReportKind::try_from(value.kind).is_err() || value.kind == 0 {
                                return Err(ValidationError::Invalid("report.kind"));
                            }
                            bounded(&value.payload, MAX_PAYLOAD_BYTES, "report.payload")?;
                        }
                        v1::report::Result::ApprovalRequest(value) => {
                            bounded(value.capability.as_bytes(), 128, "approval.capability")?;
                            if value.capability.is_empty() {
                                return Err(ValidationError::Invalid("approval.capability"));
                            }
                            bounded(&value.resource, 16 * 1024, "approval.resource")?;
                            if value.resource.is_empty() {
                                return Err(ValidationError::Invalid("approval.resource"));
                            }
                            bounded(value.summary.as_bytes(), 1024, "approval.summary")?;
                            if value.summary.trim().is_empty()
                                || value.summary.chars().any(char::is_control)
                            {
                                return Err(ValidationError::Invalid("approval.summary"));
                            }
                            let expires_at = value
                                .expires_at
                                .as_ref()
                                .ok_or(ValidationError::Missing("approval.expires_at"))?;
                            if expires_at.nanoseconds >= 1_000_000_000 {
                                return Err(ValidationError::Invalid("approval.expires_at"));
                            }
                        }
                    }
                }
                if let Some(v1::driver_event::Event::Disconnected(disconnected)) = &value.event {
                    bounded(
                        disconnected.reason.as_bytes(),
                        MAX_PUBLIC_MESSAGE_BYTES,
                        "disconnect.reason",
                    )?;
                }
                if let v1::driver_event::Event::Acceptance(acceptance) = event {
                    id(&acceptance.message_id, "message_id")?;
                    id(&acceptance.delivery_attempt_id, "delivery_attempt_id")?;
                    if v1::Acceptance::try_from(acceptance.acceptance).is_err()
                        || acceptance.acceptance == 0
                    {
                        return Err(ValidationError::Invalid("acceptance"));
                    }
                }
                if let v1::driver_event::Event::Ready(ready) = event {
                    if ready.capabilities.len() > MAX_CAPABILITIES {
                        return Err(ValidationError::Oversized("capabilities"));
                    }
                    let mut ids = HashSet::new();
                    for item in &ready.capabilities {
                        capability(item)?;
                        if !ids.insert(item.id.as_str()) {
                            return Err(ValidationError::Invalid("capability.duplicate"));
                        }
                    }
                }
                if let v1::driver_event::Event::Stopped(stopped) = event {
                    stop_result(stopped)?;
                }
                if let v1::driver_event::Event::HierarchyCommand(command) = event {
                    id(&command.request_id, "hierarchy.request_id")?;
                    match command
                        .command
                        .as_ref()
                        .ok_or(ValidationError::Missing("hierarchy.command"))?
                    {
                        v1::hierarchy_command::Command::SpawnChild(value) => {
                            id(&value.template_id, "hierarchy.template_id")?;
                            bounded(&value.task_input, MAX_PAYLOAD_BYTES, "hierarchy.input")?;
                            if !value.grant_id.is_empty() {
                                id(&value.grant_id, "hierarchy.grant_id")?;
                            }
                        }
                        v1::hierarchy_command::Command::Send(value) => {
                            id(
                                &value.destination_participant_id,
                                "hierarchy.destination_participant_id",
                            )?;
                            bounded(
                                &value.validated_envelope,
                                MAX_PAYLOAD_BYTES,
                                "hierarchy.envelope",
                            )?;
                        }
                        v1::hierarchy_command::Command::Status(value) => {
                            id(&value.participant_id, "hierarchy.participant_id")?;
                            if !value.operation_id.is_empty() {
                                id(&value.operation_id, "hierarchy.operation_id")?;
                            }
                        }
                        v1::hierarchy_command::Command::Cancel(value) => {
                            id(&value.participant_id, "hierarchy.participant_id")?;
                            id(&value.operation_id, "hierarchy.operation_id")?;
                        }
                    }
                }
                if let v1::driver_event::Event::ToolCommand(command) = event {
                    let bound = value
                        .instance
                        .as_ref()
                        .ok_or(ValidationError::Missing("instance"))?;
                    id(&command.request_id, "tool.request_id")?;
                    id(&command.session_id, "tool.session_id")?;
                    id(&command.participant_id, "tool.participant_id")?;
                    id(&command.operation_id, "tool.operation_id")?;
                    if command.session_id != bound.session_id
                        || command.participant_id != bound.participant_id
                    {
                        return Err(ValidationError::Invalid("tool.caller_context"));
                    }
                    tool_identifier(&command.tool_name, MAX_TOOL_NAME_BYTES, "tool.name")?;
                    tool_identifier(
                        &command.tool_version,
                        MAX_TOOL_VERSION_BYTES,
                        "tool.version",
                    )?;
                    canonical_json(&command.input, MAX_TOOL_INPUT_BYTES, "tool.input")?;
                    if !command.authority_grant_id.is_empty() {
                        id(&command.authority_grant_id, "tool.authority_grant_id")?;
                    }
                    if !command.approval_grant_id.is_empty() {
                        id(&command.approval_grant_id, "tool.approval_grant_id")?;
                    }
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests;
