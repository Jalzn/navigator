//! Versioned gRPC contract for Navigator consumers.

use std::collections::{BTreeMap, BTreeSet};

use prost::Message;
use thiserror::Error;
use uuid::Uuid;

use navigator_domain::{
    ArtifactId, AuthorityProfile, BoundedText, CanonicalJson, Capability, CompatibilityIdentity,
    DriverCapabilityRequirement, DriverId, DriverRequirement, EffectClass, IdempotencyContract,
    InputField, InputKind, InputSchema, MAX_SESSION_TEMPLATES, OperationId, ParticipantId,
    ResourceBounds, ResourceScope, ScopedCapability, SessionCompatibilityManifest, SessionId,
    Template, TemplateCompatibilityBinding, TemplateId, ToolCancellation, ToolDefinition, ToolName,
    ToolTimeout, ToolVersion, TrustedConfiguration,
};

#[allow(clippy::all, clippy::pedantic)]
pub mod v1 {
    tonic::include_proto!("navigator.consumer.v1");

    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("navigator-consumer-v1");
}

pub const CURRENT_MAJOR: u32 = 1;
pub const CURRENT_MINOR: u32 = 2;
pub const CAPABILITY_CONSUMER_TOOLS_V1: &str = "consumer.tools.v1";
pub const CAPABILITY_ARTIFACTS_V1: &str = "artifacts.v1";
pub const CAPABILITY_APPROVALS_V1: &str = "approvals.v1";
pub const CAPABILITY_OPERATIONAL_PROJECTIONS_V1: &str = "operational.projections.v1";
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;
pub const MAX_CAPABILITIES: usize = 32;
pub const MAX_CAPABILITY_BYTES: usize = 128;
pub const MAX_CONSUMER_KEY_BYTES: usize = 256;
pub const MAX_FAILURE_MESSAGE_BYTES: usize = 2048;
pub const MAX_FAILURE_DETAILS_BYTES: usize = 16 * 1024;
pub const MAX_EVENT_TYPE_BYTES: usize = 128;
pub const MAX_EVENT_DATA_BYTES: usize = 64 * 1024;
pub const MAX_PROJECTION_PAGE_SIZE: u32 = 128;
pub const MAX_PROJECTION_TOKEN_BYTES: usize = 2_048;
pub const MAX_OPERATION_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_OPERATION_RESULT_BYTES: usize = 64 * 1024;
pub const MAX_CANCELLATION_OPERATIONS: usize = 1_024;
pub const MAX_RECOVERY_OPERATIONS: usize = 1_024;
pub const MAX_EFFECT_PROOF_BYTES: usize = 16 * 1024;
pub const MAX_RESOLUTION_REASON_BYTES: usize = 1_024;
pub const MAX_TEMPLATE_ROLE_BYTES: usize = 128;
pub const MAX_TEMPLATE_INSTRUCTIONS_BYTES: usize = 64 * 1024;
pub const MAX_TEMPLATE_CAPABILITIES: usize = 32;
pub const MAX_TEMPLATE_PARAMETERS: usize = 16;
pub const MAX_TEMPLATE_SECRET_NAMES: usize = 32;
pub const MAX_TEMPLATE_INPUT_FIELDS: usize = 32;
pub const MAX_TEMPLATE_NAME_BYTES: usize = 64;
pub const MAX_TEMPLATE_PARAMETER_BYTES: usize = 256;
pub const MAX_TEMPLATE_AUTHORITY_RULES: usize = 64;
pub const MAX_TOOL_NAME_BYTES: usize = 128;
pub const MAX_TOOL_VERSION_BYTES: usize = 64;
pub const MAX_TOOL_SCHEMA_BYTES: usize = navigator_domain::MAX_TOOL_SCHEMA_BYTES;
pub const MAX_TOOL_AUTHORITY_BYTES: usize = 128;
pub const MAX_TOOL_TIMEOUT_MILLIS: u64 = navigator_domain::MAX_TOOL_TIMEOUT_MILLIS;
pub const MAX_TOOL_REGISTRATIONS_PER_PROVIDER: usize = 1_024;
pub const MAX_TOOL_OUTPUT_BYTES: usize = 64 * 1024;
pub const MAX_TOOL_ARTIFACTS: usize = 32;
pub const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_ARTIFACT_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_MEDIA_TYPE_BYTES: usize = 255;
pub const MAX_ARTIFACT_LOCATOR_BYTES: usize = 1_024;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ValidationError {
    #[error("request exceeds the encoded size limit")]
    RequestTooLarge,
    #[error("required protocol field is absent")]
    MissingField,
    #[error("protocol version is unsupported")]
    UnsupportedVersion,
    #[error("protocol version range is invalid")]
    InvalidVersionRange,
    #[error("identity must be exactly 16 non-nil UUID bytes")]
    InvalidIdentity,
    #[error("field violates its byte bound")]
    InvalidBound,
    #[error("capability is invalid or duplicated")]
    InvalidCapability,
    #[error("numeric protocol value must be non-zero")]
    ZeroValue,
    #[error("protocol enum value is unknown or unspecified")]
    InvalidEnum,
    #[error("timestamp is invalid")]
    InvalidTimestamp,
    #[error("protobuf request is malformed")]
    MalformedRequest,
    #[error("root Template specification is invalid")]
    InvalidTemplate,
    #[error("expected compatibility identity does not match root Template content")]
    CompatibilityMismatch,
}

pub trait ValidateRequest: Message {
    fn validate_fields(&self) -> Result<(), ValidationError>;

    fn validate_request(&self) -> Result<(), ValidationError> {
        if self.encoded_len() > MAX_REQUEST_BYTES {
            return Err(ValidationError::RequestTooLarge);
        }
        self.validate_fields()
    }
}

impl ValidateRequest for v1::NegotiateRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        let minimum = self
            .minimum_version
            .as_ref()
            .ok_or(ValidationError::MissingField)?;
        let maximum = self
            .maximum_version
            .as_ref()
            .ok_or(ValidationError::MissingField)?;
        if minimum.major != CURRENT_MAJOR || maximum.major != CURRENT_MAJOR {
            return Err(ValidationError::UnsupportedVersion);
        }
        if minimum.minor > maximum.minor || minimum.minor > CURRENT_MINOR {
            return Err(ValidationError::InvalidVersionRange);
        }
        validate_capabilities(&self.capabilities)
    }
}

impl ValidateRequest for v1::OpenSessionRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)?;
        if self.consumer_key.is_empty() || self.consumer_key.len() > MAX_CONSUMER_KEY_BYTES {
            return Err(ValidationError::InvalidBound);
        }
        let mode =
            v1::SessionOpenMode::try_from(self.mode).map_err(|_| ValidationError::InvalidEnum)?;
        if mode != v1::SessionOpenMode::Unspecified
            && !self.metadata.as_ref().is_some_and(|metadata| {
                metadata
                    .capabilities
                    .iter()
                    .any(|value| value == "session.open-modes.v1")
            })
        {
            return Err(ValidationError::InvalidCapability);
        }
        validate_text(&self.consumer_key, MAX_CONSUMER_KEY_BYTES)?;
        validated_session_templates(self).map(|_| ())
    }
}

pub fn validated_root_template(
    request: &v1::OpenSessionRequest,
) -> Result<Template, ValidationError> {
    let specification = request
        .root_template
        .as_ref()
        .ok_or(ValidationError::MissingField)?;
    validated_template_specification(specification)
}

pub fn validated_session_templates(
    request: &v1::OpenSessionRequest,
) -> Result<
    (
        Template,
        Vec<Template>,
        Option<SessionCompatibilityManifest>,
    ),
    ValidationError,
> {
    if request.configuration_identity.is_empty() {
        if !request.compatible_templates.is_empty() {
            return Err(ValidationError::InvalidTemplate);
        }
        let root = validated_root_template(request)?;
        if !request.compatibility_identity.is_empty() {
            validate_exact_bytes(&request.compatibility_identity, 32)?;
            if request.compatibility_identity.as_slice() != root.compatibility().as_bytes() {
                return Err(ValidationError::CompatibilityMismatch);
            }
        }
        return Ok((root, Vec::new(), None));
    }
    if request.compatible_templates.len() >= MAX_SESSION_TEMPLATES {
        return Err(ValidationError::InvalidTemplate);
    }
    let root = validated_root_template(request)?;
    let mut templates = request
        .compatible_templates
        .iter()
        .map(validated_template_specification)
        .collect::<Result<Vec<_>, _>>()?;
    if templates
        .iter()
        .any(|template| template.template_id() == root.template_id())
    {
        return Err(ValidationError::InvalidTemplate);
    }
    let configuration_identity = CompatibilityIdentity::from_bytes(
        request
            .configuration_identity
            .as_slice()
            .try_into()
            .map_err(|_| ValidationError::InvalidBound)?,
    );
    let bindings = std::iter::once(&root)
        .chain(templates.iter())
        .map(|template| TemplateCompatibilityBinding {
            template_id: template.template_id(),
            compatibility: template.compatibility(),
        })
        .collect();
    let manifest = SessionCompatibilityManifest::new(configuration_identity, bindings)
        .map_err(|_| ValidationError::InvalidTemplate)?;
    if !request.compatibility_identity.is_empty() {
        validate_exact_bytes(&request.compatibility_identity, 32)?;
        if request.compatibility_identity.as_slice() != manifest.compatibility().as_bytes() {
            return Err(ValidationError::CompatibilityMismatch);
        }
    }
    templates.sort_unstable_by_key(Template::template_id);
    Ok((root, templates, Some(manifest)))
}

fn validated_template_specification(
    specification: &v1::RootTemplateSpecification,
) -> Result<Template, ValidationError> {
    let template_id = TemplateId::from_uuid(parse_id(&specification.template_id)?)
        .map_err(|_| ValidationError::InvalidIdentity)?;
    let driver_id = DriverId::from_uuid(parse_id(&specification.driver_id)?)
        .map_err(|_| ValidationError::InvalidIdentity)?;
    validate_text(&specification.role, MAX_TEMPLATE_ROLE_BYTES)?;
    if specification.required_capabilities.len() > MAX_TEMPLATE_CAPABILITIES {
        return Err(ValidationError::InvalidTemplate);
    }
    let capabilities = specification
        .required_capabilities
        .iter()
        .map(wire_driver_capability)
        .collect::<Result<Vec<_>, _>>()?;
    let driver = DriverRequirement::new(driver_id, capabilities)
        .map_err(|_| ValidationError::InvalidTemplate)?;
    let trusted = specification
        .trusted_configuration
        .as_ref()
        .ok_or(ValidationError::MissingField)?;
    validate_text(&trusted.base_instructions, MAX_TEMPLATE_INSTRUCTIONS_BYTES)?;
    if trusted.secret_names.len() > MAX_TEMPLATE_SECRET_NAMES {
        return Err(ValidationError::InvalidTemplate);
    }
    let secret_names = trusted
        .secret_names
        .iter()
        .map(|name| {
            validate_template_name(name)?;
            bounded_text::<MAX_TEMPLATE_NAME_BYTES>(name)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let trusted = TrustedConfiguration::new(
        bounded_text::<MAX_TEMPLATE_INSTRUCTIONS_BYTES>(&trusted.base_instructions)?,
        secret_names,
    )
    .map_err(|_| ValidationError::InvalidTemplate)?;
    let resources = wire_resources(
        specification
            .resources
            .as_ref()
            .ok_or(ValidationError::MissingField)?,
    )?;
    let schema = wire_input_schema(
        specification
            .input_schema
            .as_ref()
            .ok_or(ValidationError::MissingField)?,
    )?;
    let authority = wire_authority_profile(specification.authority_profile.as_ref())?;
    let template = Template::register_with_authority(
        template_id,
        bounded_text::<MAX_TEMPLATE_ROLE_BYTES>(&specification.role)?,
        driver,
        trusted,
        resources,
        schema,
        authority,
    )
    .map_err(|_| ValidationError::InvalidTemplate)?;
    Ok(template)
}

fn wire_authority_profile(
    value: Option<&v1::AuthorityProfileSpecification>,
) -> Result<AuthorityProfile, ValidationError> {
    let Some(value) = value else {
        return Ok(AuthorityProfile::default());
    };
    if value.active.len() > MAX_TEMPLATE_AUTHORITY_RULES
        || value.delegable.len() > MAX_TEMPLATE_AUTHORITY_RULES
    {
        return Err(ValidationError::InvalidTemplate);
    }
    let active = value
        .active
        .iter()
        .map(wire_authority_rule)
        .collect::<Result<Vec<_>, _>>()?;
    let delegable = value
        .delegable
        .iter()
        .map(wire_authority_rule)
        .collect::<Result<Vec<_>, _>>()?;
    if active.iter().collect::<BTreeSet<_>>().len() != active.len()
        || delegable.iter().collect::<BTreeSet<_>>().len() != delegable.len()
        || delegable.iter().any(|rule| !active.contains(rule))
    {
        return Err(ValidationError::InvalidTemplate);
    }
    AuthorityProfile::new(active, delegable).map_err(|_| ValidationError::InvalidTemplate)
}

fn wire_authority_rule(
    value: &v1::ScopedCapabilitySpecification,
) -> Result<ScopedCapability, ValidationError> {
    use v1::scoped_capability_specification::Resource;
    let capability =
        Capability::new(&value.capability).map_err(|_| ValidationError::InvalidCapability)?;
    let resource = match value
        .resource
        .as_ref()
        .ok_or(ValidationError::MissingField)?
    {
        Resource::SessionId(value) => ResourceScope::Session(
            SessionId::from_uuid(parse_id(value)?).map_err(|_| ValidationError::InvalidIdentity)?,
        ),
        Resource::ParticipantId(value) => ResourceScope::Participant(
            ParticipantId::from_uuid(parse_id(value)?)
                .map_err(|_| ValidationError::InvalidIdentity)?,
        ),
        Resource::OperationId(value) => ResourceScope::Operation(
            OperationId::from_uuid(parse_id(value)?)
                .map_err(|_| ValidationError::InvalidIdentity)?,
        ),
        Resource::ArtifactId(value) => ResourceScope::Artifact(
            ArtifactId::from_uuid(parse_id(value)?)
                .map_err(|_| ValidationError::InvalidIdentity)?,
        ),
    };
    Ok(ScopedCapability::new(capability, resource))
}

fn wire_driver_capability(
    value: &v1::DriverCapabilityRequirement,
) -> Result<DriverCapabilityRequirement, ValidationError> {
    if value.parameters.len() > MAX_TEMPLATE_PARAMETERS {
        return Err(ValidationError::InvalidTemplate);
    }
    let capability = Capability::new(value.capability.clone())
        .map_err(|_| ValidationError::InvalidCapability)?;
    let parameters = value
        .parameters
        .iter()
        .map(|parameter| {
            Ok((
                bounded_text::<MAX_TEMPLATE_NAME_BYTES>(&parameter.key)?,
                bounded_text::<MAX_TEMPLATE_PARAMETER_BYTES>(&parameter.value)?,
            ))
        })
        .collect::<Result<Vec<_>, ValidationError>>()?;
    DriverCapabilityRequirement::new(capability, value.minimum_version, parameters)
        .map_err(|_| ValidationError::InvalidTemplate)
}

fn wire_resources(
    value: &v1::ParticipantResourceBounds,
) -> Result<ResourceBounds, ValidationError> {
    let concurrency = u16::try_from(value.max_concurrent_operations)
        .map_err(|_| ValidationError::InvalidTemplate)?;
    ResourceBounds::new(value.memory_bytes, value.cpu_millis, concurrency)
        .map_err(|_| ValidationError::InvalidTemplate)
}

fn wire_input_schema(value: &v1::InputSchema) -> Result<InputSchema, ValidationError> {
    if value.fields.len() > MAX_TEMPLATE_INPUT_FIELDS {
        return Err(ValidationError::InvalidTemplate);
    }
    let fields = value
        .fields
        .iter()
        .map(|field| {
            let kind = match v1::InputKind::try_from(field.kind) {
                Ok(v1::InputKind::String) => InputKind::String,
                Ok(v1::InputKind::Integer) => InputKind::Integer,
                Ok(v1::InputKind::Boolean) => InputKind::Boolean,
                _ => return Err(ValidationError::InvalidTemplate),
            };
            let maximum = field
                .max_string_bytes
                .map(usize::try_from)
                .transpose()
                .map_err(|_| ValidationError::InvalidTemplate)?;
            InputField::new(
                bounded_text::<MAX_TEMPLATE_NAME_BYTES>(&field.name)?,
                kind,
                field.required,
                maximum,
            )
            .map_err(|_| ValidationError::InvalidTemplate)
        })
        .collect::<Result<Vec<_>, _>>()?;
    InputSchema::new(fields).map_err(|_| ValidationError::InvalidTemplate)
}

fn bounded_text<const MAX: usize>(value: &str) -> Result<BoundedText<MAX>, ValidationError> {
    BoundedText::new(value.to_owned()).map_err(|_| ValidationError::InvalidBound)
}

fn validate_template_name(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > MAX_TEMPLATE_NAME_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        Err(ValidationError::InvalidTemplate)
    } else {
        Ok(())
    }
}

fn parse_id(bytes: &[u8]) -> Result<Uuid, ValidationError> {
    let value = Uuid::from_slice(bytes).map_err(|_| ValidationError::InvalidIdentity)?;
    if value.is_nil() {
        Err(ValidationError::InvalidIdentity)
    } else {
        Ok(value)
    }
}

pub fn decode_and_validate<M>(bytes: &[u8]) -> Result<M, ValidationError>
where
    M: ValidateRequest + Default,
{
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(ValidationError::RequestTooLarge);
    }
    let request = M::decode(bytes).map_err(|_| ValidationError::MalformedRequest)?;
    request.validate_request()?;
    Ok(request)
}

pub fn negotiate(
    request: &v1::NegotiateRequest,
    supported_capabilities: &[&str],
    negotiation_id: Vec<u8>,
) -> Result<v1::Negotiated, ValidationError> {
    request.validate_request()?;
    validate_id(&negotiation_id)?;
    let supported = supported_capabilities
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let capabilities = request
        .capabilities
        .iter()
        .filter(|value| supported.contains(value.as_str()))
        .cloned()
        .collect();
    Ok(v1::Negotiated {
        protocol_version: Some(v1::ProtocolVersion {
            major: CURRENT_MAJOR,
            minor: request
                .maximum_version
                .as_ref()
                .expect("validated maximum version")
                .minor
                .min(CURRENT_MINOR),
        }),
        capabilities,
        negotiation_id,
        configuration_identity: Vec::new(),
    })
}

pub fn validate_negotiated(negotiated: &v1::Negotiated) -> Result<(), ValidationError> {
    let version = negotiated
        .protocol_version
        .as_ref()
        .ok_or(ValidationError::MissingField)?;
    if version.major != CURRENT_MAJOR || version.minor > CURRENT_MINOR {
        return Err(ValidationError::UnsupportedVersion);
    }
    validate_capabilities(&negotiated.capabilities)?;
    validate_id(&negotiated.negotiation_id)?;
    if !negotiated.configuration_identity.is_empty() {
        validate_exact_bytes(&negotiated.configuration_identity, 32)?;
    }
    Ok(())
}

pub fn validate_negotiated_capabilities(
    metadata: &v1::RequestMetadata,
    negotiated: &[String],
) -> Result<(), ValidationError> {
    validate_metadata(Some(metadata))?;
    let negotiated = negotiated
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if metadata
        .capabilities
        .iter()
        .all(|value| negotiated.contains(value.as_str()))
    {
        Ok(())
    } else {
        Err(ValidationError::InvalidCapability)
    }
}

impl ValidateRequest for v1::SnapshotRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.session_id)
    }
}

impl ValidateRequest for v1::CloseSessionRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)
    }
}

impl ValidateRequest for v1::SubscribeEventsRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.session_id)
    }
}

impl ValidateRequest for v1::ReadEventsRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.session_id)?;
        if self.page_size == 0 || self.page_size > 128 {
            return Err(ValidationError::InvalidBound);
        }
        Ok(())
    }
}

impl ValidateRequest for v1::ReadProjectionRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_capability_metadata(
            self.metadata.as_ref(),
            CAPABILITY_OPERATIONAL_PROJECTIONS_V1,
        )?;
        validate_id(&self.session_id)?;
        if self.consumer_key.is_empty() || self.consumer_key.len() > MAX_CONSUMER_KEY_BYTES {
            return Err(ValidationError::InvalidBound);
        }
        if v1::ProjectionView::try_from(self.view).map_err(|_| ValidationError::InvalidEnum)?
            == v1::ProjectionView::Unspecified
            || self.page_size == 0
            || self.page_size > MAX_PROJECTION_PAGE_SIZE
            || self.page_token.len() > MAX_PROJECTION_TOKEN_BYTES
        {
            return Err(ValidationError::InvalidBound);
        }
        Ok(())
    }
}

impl ValidateRequest for v1::StartOperationRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)?;
        validate_id(&self.participant_id)?;
        validate_nonempty_bytes(&self.input, MAX_OPERATION_INPUT_BYTES)
    }
}

impl ValidateRequest for v1::OperationSnapshotRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.session_id)?;
        validate_id(&self.operation_id)
    }
}

impl ValidateRequest for v1::ParticipantSnapshotRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.session_id)?;
        validate_id(&self.participant_id)
    }
}

impl ValidateRequest for v1::MessageSnapshotRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.session_id)?;
        validate_id(&self.message_id)
    }
}

impl ValidateRequest for v1::CancelSubtreeRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)?;
        validate_id(&self.root_participant_id)
    }
}

impl ValidateRequest for v1::ResumeSessionRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)
    }
}

impl ValidateRequest for v1::ResolveUncertaintyRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_metadata(self.metadata.as_ref())?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)?;
        validate_id(&self.operation_id)?;
        validate_id(&self.effect_id)?;
        validate_id(&self.authority_grant_id)?;
        validate_text(&self.reason, MAX_RESOLUTION_REASON_BYTES)?;
        if self.reason.trim().is_empty() {
            return Err(ValidationError::InvalidBound);
        }
        match self
            .resolution
            .as_ref()
            .ok_or(ValidationError::MissingField)?
        {
            v1::resolve_uncertainty_request::Resolution::ConfirmCompleted(proof)
            | v1::resolve_uncertainty_request::Resolution::RetryWithEffectProof(proof) => {
                validate_effect_proof(proof)
            }
            v1::resolve_uncertainty_request::Resolution::DoNotRetry(_) => Ok(()),
        }
    }
}

fn validate_effect_proof(proof: &v1::EffectProof) -> Result<(), ValidationError> {
    v1::EffectProofKind::try_from(proof.kind)
        .ok()
        .filter(|kind| *kind != v1::EffectProofKind::Unspecified)
        .ok_or(ValidationError::InvalidEnum)?;
    if proof.digest.len() != 32 || proof.digest.iter().all(|byte| *byte == 0) {
        return Err(ValidationError::InvalidBound);
    }
    validate_nonempty_bytes(&proof.evidence, MAX_EFFECT_PROOF_BYTES)
}

pub fn validate_recovery_report(report: &v1::RecoveryReport) -> Result<(), ValidationError> {
    validate_id(&report.session_id)?;
    if report.classifications.len() > MAX_RECOVERY_OPERATIONS {
        return Err(ValidationError::InvalidBound);
    }
    let mut operations = BTreeSet::new();
    for classification in &report.classifications {
        let entity = classification
            .entity
            .as_ref()
            .ok_or(ValidationError::MissingField)?;
        let identity = match entity {
            v1::recovery_classification::Entity::SessionId(value)
            | v1::recovery_classification::Entity::ParticipantId(value)
            | v1::recovery_classification::Entity::LaunchAttemptId(value)
            | v1::recovery_classification::Entity::OperationId(value)
            | v1::recovery_classification::Entity::MessageId(value)
            | v1::recovery_classification::Entity::EffectId(value) => value,
        };
        validate_id(identity)?;
        if !operations.insert((entity_kind(entity), identity.as_slice())) {
            return Err(ValidationError::InvalidIdentity);
        }
        let disposition = v1::RecoveryDisposition::try_from(classification.disposition)
            .ok()
            .filter(|value| *value != v1::RecoveryDisposition::Unspecified)
            .ok_or(ValidationError::InvalidEnum)?;
        v1::RecoveryActionStatus::try_from(classification.action_status)
            .ok()
            .filter(|value| *value != v1::RecoveryActionStatus::Unspecified)
            .ok_or(ValidationError::InvalidEnum)?;
        let mut actions = BTreeSet::new();
        for action in &classification.allowed_actions {
            let action = v1::ResolutionAction::try_from(*action)
                .ok()
                .filter(|value| *value != v1::ResolutionAction::Unspecified)
                .ok_or(ValidationError::InvalidEnum)?;
            if !actions.insert(action as i32) {
                return Err(ValidationError::InvalidEnum);
            }
        }
        if disposition != v1::RecoveryDisposition::EffectUncertain && !actions.is_empty() {
            return Err(ValidationError::InvalidEnum);
        }
        validate_text(&classification.reason, MAX_FAILURE_MESSAGE_BYTES)?;
        if classification.reason.trim().is_empty() {
            return Err(ValidationError::InvalidBound);
        }
    }
    Ok(())
}

pub fn validate_resolution_snapshot(
    snapshot: &v1::ResolutionSnapshot,
) -> Result<(), ValidationError> {
    validate_operation_snapshot(
        snapshot
            .operation
            .as_ref()
            .ok_or(ValidationError::MissingField)?,
    )?;
    v1::ResolutionAction::try_from(snapshot.action)
        .ok()
        .filter(|value| *value != v1::ResolutionAction::Unspecified)
        .ok_or(ValidationError::InvalidEnum)?;
    v1::RecoveryActionStatus::try_from(snapshot.action_status)
        .ok()
        .filter(|value| *value != v1::RecoveryActionStatus::Unspecified)
        .ok_or(ValidationError::InvalidEnum)?;
    validate_id(&snapshot.authority_grant_id)?;
    validate_id(&snapshot.request_id)?;
    validate_id(&snapshot.session_id)?;
    validate_id(&snapshot.effect_id)?;
    if snapshot.revision == 0 || snapshot.audit_event_position == 0 {
        return Err(ValidationError::ZeroValue);
    }
    validate_text(&snapshot.reason, MAX_RESOLUTION_REASON_BYTES)?;
    if snapshot.reason.trim().is_empty() {
        return Err(ValidationError::InvalidBound);
    }
    Ok(())
}

const fn entity_kind(entity: &v1::recovery_classification::Entity) -> u8 {
    match entity {
        v1::recovery_classification::Entity::SessionId(_) => 1,
        v1::recovery_classification::Entity::ParticipantId(_) => 2,
        v1::recovery_classification::Entity::LaunchAttemptId(_) => 3,
        v1::recovery_classification::Entity::OperationId(_) => 4,
        v1::recovery_classification::Entity::MessageId(_) => 5,
        v1::recovery_classification::Entity::EffectId(_) => 6,
    }
}

pub fn validate_cancellation_snapshot(
    snapshot: &v1::CancellationSnapshot,
) -> Result<(), ValidationError> {
    validate_id(&snapshot.root_participant_id)?;
    if snapshot.operations.len() > MAX_CANCELLATION_OPERATIONS {
        return Err(ValidationError::InvalidBound);
    }
    let mut operations = BTreeSet::new();
    for record in &snapshot.operations {
        let operation = record
            .operation
            .as_ref()
            .ok_or(ValidationError::MissingField)?;
        validate_operation_snapshot(operation)?;
        if !operations.insert(operation.operation_id.as_slice()) {
            return Err(ValidationError::InvalidIdentity);
        }
        if !record.notification_message_id.is_empty() {
            validate_id(&record.notification_message_id)?;
        } else if record.cleanup_confirmed {
            let status = v1::OperationStatus::try_from(operation.status)
                .map_err(|_| ValidationError::InvalidEnum)?;
            if !matches!(
                status,
                v1::OperationStatus::Succeeded
                    | v1::OperationStatus::Failed
                    | v1::OperationStatus::Cancelled
                    | v1::OperationStatus::Blocked
                    | v1::OperationStatus::Uncertain
            ) {
                return Err(ValidationError::MissingField);
            }
        }
    }
    Ok(())
}

pub fn validate_operation_snapshot(
    snapshot: &v1::OperationSnapshot,
) -> Result<(), ValidationError> {
    validate_id(&snapshot.operation_id)?;
    validate_id(&snapshot.session_id)?;
    validate_id(&snapshot.participant_id)?;
    validate_id(&snapshot.request_id)?;
    let status = v1::OperationStatus::try_from(snapshot.status)
        .ok()
        .filter(|status| *status != v1::OperationStatus::Unspecified)
        .ok_or(ValidationError::InvalidEnum)?;
    let terminal = matches!(
        status,
        v1::OperationStatus::Succeeded
            | v1::OperationStatus::Failed
            | v1::OperationStatus::Cancelled
            | v1::OperationStatus::Blocked
            | v1::OperationStatus::Uncertain
    );
    match status {
        v1::OperationStatus::Succeeded => {
            let result = snapshot
                .result
                .as_deref()
                .ok_or(ValidationError::MissingField)?;
            validate_bytes(result, MAX_OPERATION_RESULT_BYTES)?;
            if snapshot.terminal_failure.is_some() {
                return Err(ValidationError::InvalidEnum);
            }
        }
        v1::OperationStatus::Failed
        | v1::OperationStatus::Cancelled
        | v1::OperationStatus::Blocked
        | v1::OperationStatus::Uncertain => {
            if snapshot.result.is_some() {
                return Err(ValidationError::InvalidEnum);
            }
            validate_failure(
                snapshot
                    .terminal_failure
                    .as_ref()
                    .ok_or(ValidationError::MissingField)?,
            )?;
        }
        _ if snapshot.result.is_some() || snapshot.terminal_failure.is_some() => {
            return Err(ValidationError::InvalidEnum);
        }
        _ => {}
    }
    debug_assert_eq!(
        terminal,
        snapshot.result.is_some() || snapshot.terminal_failure.is_some()
    );
    if snapshot.revision == 0 {
        return Err(ValidationError::ZeroValue);
    }
    validate_timestamp(snapshot.created_at.as_ref())?;
    validate_timestamp(snapshot.updated_at.as_ref())?;
    validate_timestamp_order(snapshot.created_at.as_ref(), snapshot.updated_at.as_ref())
}

pub fn validate_failure(failure: &v1::Failure) -> Result<(), ValidationError> {
    if v1::FailureCode::try_from(failure.code)
        .ok()
        .is_none_or(|code| code == v1::FailureCode::Unspecified)
        || v1::RetryClass::try_from(failure.retry)
            .ok()
            .is_none_or(|retry| retry == v1::RetryClass::Unspecified)
    {
        return Err(ValidationError::InvalidEnum);
    }
    validate_text(&failure.message, MAX_FAILURE_MESSAGE_BYTES)?;
    if let Some(related_id) = &failure.related_id {
        validate_id(related_id)?;
    }
    validate_bytes(&failure.details, MAX_FAILURE_DETAILS_BYTES)
}

pub fn validate_snapshot(snapshot: &v1::SessionSnapshot) -> Result<(), ValidationError> {
    validate_id(&snapshot.session_id)?;
    validate_id(&snapshot.root_participant_id)?;
    validate_text(&snapshot.consumer_key, MAX_CONSUMER_KEY_BYTES)?;
    validate_exact_bytes(&snapshot.compatibility_identity, 32)?;
    if v1::SessionStatus::try_from(snapshot.status)
        .ok()
        .is_none_or(|status| status == v1::SessionStatus::Unspecified)
    {
        return Err(ValidationError::InvalidEnum);
    }
    if snapshot.revision == 0 {
        return Err(ValidationError::ZeroValue);
    }
    validate_timestamp(snapshot.created_at.as_ref())?;
    validate_timestamp(snapshot.updated_at.as_ref())?;
    validate_timestamp_order(snapshot.created_at.as_ref(), snapshot.updated_at.as_ref())
}

pub fn validate_event(event: &v1::SessionEvent) -> Result<(), ValidationError> {
    validate_id(&event.event_id)?;
    validate_id(&event.session_id)?;
    if event.position == 0 || event.revision == 0 || event.schema_version == 0 {
        return Err(ValidationError::ZeroValue);
    }
    validate_text(&event.event_type, MAX_EVENT_TYPE_BYTES)?;
    if let Some(request_id) = &event.related_request_id {
        validate_id(request_id)?;
    }
    validate_bytes(&event.data, MAX_EVENT_DATA_BYTES)?;
    validate_timestamp(event.occurred_at.as_ref())
}

fn validate_metadata(metadata: Option<&v1::RequestMetadata>) -> Result<(), ValidationError> {
    let metadata = metadata.ok_or(ValidationError::MissingField)?;
    let version = metadata
        .protocol_version
        .as_ref()
        .ok_or(ValidationError::MissingField)?;
    if version.major != CURRENT_MAJOR || version.minor > CURRENT_MINOR {
        return Err(ValidationError::UnsupportedVersion);
    }
    validate_capabilities(&metadata.capabilities)?;
    validate_id(&metadata.negotiation_id)
}

fn validate_capabilities(capabilities: &[String]) -> Result<(), ValidationError> {
    if capabilities.len() > MAX_CAPABILITIES {
        return Err(ValidationError::InvalidCapability);
    }
    let mut unique = BTreeSet::new();
    for capability in capabilities {
        if capability.is_empty()
            || capability.len() > MAX_CAPABILITY_BYTES
            || !capability.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
            || !unique.insert(capability)
        {
            return Err(ValidationError::InvalidCapability);
        }
    }
    Ok(())
}

fn validate_id(value: &[u8]) -> Result<(), ValidationError> {
    let uuid = Uuid::from_slice(value).map_err(|_| ValidationError::InvalidIdentity)?;
    if uuid.is_nil() {
        Err(ValidationError::InvalidIdentity)
    } else {
        Ok(())
    }
}

fn validate_text(value: &str, maximum: usize) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > maximum {
        Err(ValidationError::InvalidBound)
    } else {
        Ok(())
    }
}

fn validate_bytes(value: &[u8], maximum: usize) -> Result<(), ValidationError> {
    if value.len() > maximum {
        Err(ValidationError::InvalidBound)
    } else {
        Ok(())
    }
}

fn validate_nonempty_bytes(value: &[u8], maximum: usize) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > maximum {
        Err(ValidationError::InvalidBound)
    } else {
        Ok(())
    }
}

fn validate_exact_bytes(value: &[u8], expected: usize) -> Result<(), ValidationError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(ValidationError::InvalidBound)
    }
}

fn validate_timestamp(timestamp: Option<&v1::Timestamp>) -> Result<(), ValidationError> {
    let timestamp = timestamp.ok_or(ValidationError::MissingField)?;
    if timestamp.nanoseconds >= 1_000_000_000 {
        Err(ValidationError::InvalidTimestamp)
    } else {
        Ok(())
    }
}

fn validate_timestamp_order(
    created: Option<&v1::Timestamp>,
    updated: Option<&v1::Timestamp>,
) -> Result<(), ValidationError> {
    let created = created.ok_or(ValidationError::MissingField)?;
    let updated = updated.ok_or(ValidationError::MissingField)?;
    if (updated.unix_seconds, updated.nanoseconds) < (created.unix_seconds, created.nanoseconds) {
        Err(ValidationError::InvalidTimestamp)
    } else {
        Ok(())
    }
}

impl ValidateRequest for v1::RegisterToolRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_capability_metadata(self.metadata.as_ref(), CAPABILITY_CONSUMER_TOOLS_V1)?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)?;
        validate_tool_specification(self.tool.as_ref().ok_or(ValidationError::MissingField)?)
    }
}

impl ValidateRequest for v1::ReadArtifactRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_capability_metadata(self.metadata.as_ref(), CAPABILITY_ARTIFACTS_V1)?;
        validate_id(&self.session_id)?;
        validate_id(&self.artifact_id)?;
        validate_optional_id(&self.authority_grant_id)?;
        if self.offset > MAX_ARTIFACT_BYTES
            || self.length.is_some_and(|length| {
                length == 0
                    || length > MAX_ARTIFACT_BYTES
                    || self
                        .offset
                        .checked_add(length)
                        .is_none_or(|end| end > MAX_ARTIFACT_BYTES)
            })
        {
            return Err(ValidationError::InvalidBound);
        }
        Ok(())
    }
}

impl ValidateRequest for v1::ArtifactSnapshotRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_capability_metadata(self.metadata.as_ref(), CAPABILITY_ARTIFACTS_V1)?;
        validate_id(&self.session_id)?;
        validate_id(&self.artifact_id)
    }
}

impl ValidateRequest for v1::DeleteArtifactRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_capability_metadata(self.metadata.as_ref(), CAPABILITY_ARTIFACTS_V1)?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)?;
        validate_id(&self.artifact_id)?;
        validate_optional_id(&self.authority_grant_id)
    }
}

impl ValidateRequest for v1::ApprovalSnapshotRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_capability_metadata(self.metadata.as_ref(), CAPABILITY_APPROVALS_V1)?;
        validate_id(&self.session_id)?;
        validate_id(&self.approval_id)
    }
}

impl ValidateRequest for v1::ApproveApprovalRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_capability_metadata(self.metadata.as_ref(), CAPABILITY_APPROVALS_V1)?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)?;
        validate_id(&self.approval_id)?;
        validate_id(&self.grant_id)?;
        if self.expected_revision == 0
            || self.max_uses == 0
            || self.max_uses > navigator_domain::MAX_APPROVAL_USES
        {
            return Err(ValidationError::InvalidBound);
        }
        validate_timestamp(self.grant_expires_at.as_ref())
    }
}

impl ValidateRequest for v1::DenyApprovalRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_capability_metadata(self.metadata.as_ref(), CAPABILITY_APPROVALS_V1)?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)?;
        validate_id(&self.approval_id)?;
        if self.expected_revision == 0 {
            return Err(ValidationError::InvalidBound);
        }
        Ok(())
    }
}

impl ValidateRequest for v1::RevokeApprovalGrantRequest {
    fn validate_fields(&self) -> Result<(), ValidationError> {
        validate_capability_metadata(self.metadata.as_ref(), CAPABILITY_APPROVALS_V1)?;
        validate_id(&self.request_id)?;
        validate_id(&self.session_id)?;
        validate_id(&self.grant_id)?;
        if self.expected_revision == 0 {
            return Err(ValidationError::InvalidBound);
        }
        Ok(())
    }
}

fn validate_capability_metadata(
    metadata: Option<&v1::RequestMetadata>,
    capability: &str,
) -> Result<(), ValidationError> {
    validate_metadata(metadata)?;
    if metadata.is_some_and(|value| value.capabilities.iter().any(|item| item == capability)) {
        Ok(())
    } else {
        Err(ValidationError::InvalidCapability)
    }
}

pub fn validate_tool_specification(tool: &v1::ToolSpecification) -> Result<(), ValidationError> {
    let name = ToolName::new(tool.name.clone()).map_err(|_| ValidationError::InvalidBound)?;
    let version =
        ToolVersion::new(tool.version.clone()).map_err(|_| ValidationError::InvalidBound)?;
    let input = validated_canonical_json::<MAX_TOOL_SCHEMA_BYTES>(&tool.input_schema)?;
    let output = validated_canonical_json::<MAX_TOOL_SCHEMA_BYTES>(&tool.output_schema)?;
    let authority = Capability::new(tool.required_authority.clone())
        .map_err(|_| ValidationError::InvalidCapability)?;
    let timeout =
        ToolTimeout::from_millis(tool.timeout_millis).map_err(|_| ValidationError::InvalidBound)?;
    let cancellation =
        match enum_nonzero::<v1::ToolCancellationBehavior>(tool.cancellation_behavior)? {
            v1::ToolCancellationBehavior::Cooperative => ToolCancellation::Cooperative,
            v1::ToolCancellationBehavior::Unsupported => ToolCancellation::Unsupported,
            v1::ToolCancellationBehavior::Unspecified => return Err(ValidationError::InvalidEnum),
        };
    let effect = enum_nonzero::<v1::ToolEffectClass>(tool.effect_class)?;
    let idempotency = enum_nonzero::<v1::ToolIdempotencyContract>(tool.idempotency_contract)?;
    let effect = match effect {
        v1::ToolEffectClass::ReadOnly => EffectClass::ReadOnly,
        v1::ToolEffectClass::Idempotent => EffectClass::Idempotent,
        v1::ToolEffectClass::Transactional => EffectClass::Transactional,
        v1::ToolEffectClass::NonIdempotent => EffectClass::NonIdempotent,
        v1::ToolEffectClass::Unknown => EffectClass::Unknown,
        v1::ToolEffectClass::Unspecified => return Err(ValidationError::InvalidEnum),
    };
    let idempotency = match idempotency {
        v1::ToolIdempotencyContract::NoExternalEffect => IdempotencyContract::NoExternalEffect,
        v1::ToolIdempotencyContract::InvocationIdentity => IdempotencyContract::InvocationIdentity,
        v1::ToolIdempotencyContract::ExternalTransactionProof => {
            IdempotencyContract::ExternalTransactionProof
        }
        v1::ToolIdempotencyContract::NeverReplay => IdempotencyContract::NeverReplay,
        v1::ToolIdempotencyContract::Unspecified => return Err(ValidationError::InvalidEnum),
    };
    ToolDefinition::new(
        name,
        version,
        input,
        output,
        authority,
        timeout,
        cancellation,
        effect,
        idempotency,
    )
    .map(|_| ())
    .map_err(|_| ValidationError::InvalidEnum)
}

pub fn validate_tool_registration_snapshot(
    snapshot: &v1::ToolRegistrationSnapshot,
) -> Result<(), ValidationError> {
    validate_id(&snapshot.registration_id)?;
    validate_id(&snapshot.session_id)?;
    validate_id(&snapshot.request_id)?;
    validate_tool_specification(
        snapshot
            .tool
            .as_ref()
            .ok_or(ValidationError::MissingField)?,
    )?;
    if snapshot.revision == 0 {
        return Err(ValidationError::ZeroValue);
    }
    validate_timestamp(snapshot.created_at.as_ref())?;
    validate_timestamp(snapshot.updated_at.as_ref())?;
    validate_timestamp_order(snapshot.created_at.as_ref(), snapshot.updated_at.as_ref())
}

pub fn validate_register_tool_response(
    response: &v1::RegisterToolResponse,
) -> Result<(), ValidationError> {
    match response
        .outcome
        .as_ref()
        .ok_or(ValidationError::MissingField)?
    {
        v1::register_tool_response::Outcome::Registration(value) => {
            validate_tool_registration_snapshot(value)
        }
        v1::register_tool_response::Outcome::Failure(value) => validate_failure(value),
    }
}

pub fn validate_tool_provider_request(
    frame: &v1::ToolProviderRequest,
) -> Result<(), ValidationError> {
    if frame.encoded_len() > MAX_REQUEST_BYTES {
        return Err(ValidationError::RequestTooLarge);
    }
    match frame.frame.as_ref().ok_or(ValidationError::MissingField)? {
        v1::tool_provider_request::Frame::Connect(value) => {
            validate_capability_metadata(value.metadata.as_ref(), CAPABILITY_CONSUMER_TOOLS_V1)?;
            validate_id(&value.session_id)?;
            validate_id(&value.provider_id)?;
            validate_id(&value.connection_id)?;
            if value.registration_ids.is_empty()
                || value.registration_ids.len() > MAX_TOOL_REGISTRATIONS_PER_PROVIDER
            {
                return Err(ValidationError::InvalidBound);
            }
            validate_unique_ids(&value.registration_ids)
        }
        v1::tool_provider_request::Frame::Started(value) => {
            validate_provider_correlation(
                &value.session_id,
                &value.provider_id,
                &value.connection_id,
                &value.invocation_id,
                &value.dispatch_id,
                value.server_sequence,
            )?;
            validate_timestamp(value.started_at.as_ref())
        }
        v1::tool_provider_request::Frame::Result(value) => {
            validate_provider_correlation(
                &value.session_id,
                &value.provider_id,
                &value.connection_id,
                &value.invocation_id,
                &value.dispatch_id,
                value.server_sequence,
            )?;
            validated_canonical_json::<MAX_TOOL_OUTPUT_BYTES>(&value.output)?;
            if value.artifacts.len() > MAX_TOOL_ARTIFACTS {
                return Err(ValidationError::InvalidBound);
            }
            let mut ids = BTreeSet::new();
            for artifact in &value.artifacts {
                validate_artifact_reference(artifact)?;
                if !ids.insert(artifact.artifact_id.as_slice()) {
                    return Err(ValidationError::InvalidIdentity);
                }
            }
            Ok(())
        }
        v1::tool_provider_request::Frame::Failure(value) => {
            validate_provider_correlation(
                &value.session_id,
                &value.provider_id,
                &value.connection_id,
                &value.invocation_id,
                &value.dispatch_id,
                value.server_sequence,
            )?;
            validate_failure(
                value
                    .failure
                    .as_ref()
                    .ok_or(ValidationError::MissingField)?,
            )
        }
    }
}

pub fn validate_tool_provider_response(
    frame: &v1::ToolProviderResponse,
) -> Result<(), ValidationError> {
    if frame.encoded_len() > MAX_REQUEST_BYTES {
        return Err(ValidationError::RequestTooLarge);
    }
    match frame.frame.as_ref().ok_or(ValidationError::MissingField)? {
        v1::tool_provider_response::Frame::Connected(value) => {
            validate_id(&value.session_id)?;
            validate_id(&value.provider_id)?;
            validate_id(&value.connection_id)?;
            if value.next_server_sequence == 0
                || value.accepted_after_server_sequence > value.high_water_server_sequence
                || value.high_water_server_sequence.checked_add(1)
                    != Some(value.next_server_sequence)
            {
                Err(ValidationError::ZeroValue)
            } else {
                Ok(())
            }
        }
        v1::tool_provider_response::Frame::Invocation(value) => {
            validate_id(&value.session_id)?;
            validate_id(&value.registration_id)?;
            validate_id(&value.invocation_id)?;
            validate_id(&value.dispatch_id)?;
            validate_id(&value.operation_id)?;
            validate_id(&value.participant_id)?;
            if value.server_sequence == 0 {
                return Err(ValidationError::ZeroValue);
            }
            validate_stable_identifier(&value.tool_name, MAX_TOOL_NAME_BYTES)?;
            validate_stable_identifier(&value.tool_version, MAX_TOOL_VERSION_BYTES)?;
            validated_canonical_json::<MAX_OPERATION_INPUT_BYTES>(&value.input)?;
            validate_timestamp(value.deadline.as_ref())
        }
        v1::tool_provider_response::Frame::Cancellation(value) => {
            validate_id(&value.session_id)?;
            validate_id(&value.invocation_id)?;
            validate_id(&value.dispatch_id)?;
            validate_id(&value.cancellation_id)?;
            if value.server_sequence == 0 {
                return Err(ValidationError::ZeroValue);
            }
            validate_timestamp(value.requested_at.as_ref())
        }
        v1::tool_provider_response::Frame::Acknowledgement(value) => {
            validate_id(&value.session_id)?;
            validate_id(&value.invocation_id)?;
            validate_id(&value.dispatch_id)?;
            if value.server_sequence == 0 {
                return Err(ValidationError::ZeroValue);
            }
            enum_nonzero::<v1::ToolProviderAckKind>(value.kind).map(|_| ())
        }
        v1::tool_provider_response::Frame::Failure(value) => validate_failure(value),
    }
}

fn validate_provider_correlation(
    session: &[u8],
    provider: &[u8],
    connection: &[u8],
    invocation: &[u8],
    dispatch: &[u8],
    sequence: u64,
) -> Result<(), ValidationError> {
    validate_id(session)?;
    validate_id(provider)?;
    validate_id(connection)?;
    validate_id(invocation)?;
    validate_id(dispatch)?;
    if sequence == 0 {
        Err(ValidationError::ZeroValue)
    } else {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct ToolProviderStreamValidator {
    connected: bool,
    session_id: Vec<u8>,
    provider_id: Vec<u8>,
    connection_id: Vec<u8>,
    after_server_sequence: u64,
    dispatch_sequences: BTreeMap<(Vec<u8>, Vec<u8>), u64>,
    invocation_dispatches: BTreeMap<Vec<u8>, Vec<u8>>,
    sequence_dispatches: BTreeMap<u64, (Vec<u8>, Vec<u8>)>,
    terminal_dispatches: BTreeSet<(Vec<u8>, Vec<u8>)>,
}

impl ToolProviderStreamValidator {
    pub fn accept(&mut self, frame: &v1::ToolProviderRequest) -> Result<(), ValidationError> {
        validate_tool_provider_request(frame)?;
        match frame.frame.as_ref().ok_or(ValidationError::MissingField)? {
            v1::tool_provider_request::Frame::Connect(value) if !self.connected => {
                self.connected = true;
                self.session_id.clone_from(&value.session_id);
                self.provider_id.clone_from(&value.provider_id);
                self.connection_id.clone_from(&value.connection_id);
                self.after_server_sequence = value.after_server_sequence;
                Ok(())
            }
            v1::tool_provider_request::Frame::Connect(_) => Err(ValidationError::MalformedRequest),
            v1::tool_provider_request::Frame::Started(value) => {
                self.accept_correlated(
                    &value.session_id,
                    &value.provider_id,
                    &value.connection_id,
                    value.server_sequence,
                )?;
                let key = (value.invocation_id.clone(), value.dispatch_id.clone());
                if self.terminal_dispatches.contains(&key) {
                    return Err(ValidationError::MalformedRequest);
                }
                if self
                    .invocation_dispatches
                    .get(&value.invocation_id)
                    .is_some_and(|dispatch| dispatch != &value.dispatch_id)
                    || self
                        .dispatch_sequences
                        .get(&key)
                        .is_some_and(|sequence| *sequence != value.server_sequence)
                    || self
                        .sequence_dispatches
                        .get(&value.server_sequence)
                        .is_some_and(|existing| existing != &key)
                {
                    return Err(ValidationError::InvalidIdentity);
                }
                self.invocation_dispatches
                    .insert(value.invocation_id.clone(), value.dispatch_id.clone());
                self.dispatch_sequences
                    .insert(key.clone(), value.server_sequence);
                self.sequence_dispatches.insert(value.server_sequence, key);
                Ok(())
            }
            v1::tool_provider_request::Frame::Result(value) => self.accept_terminal(
                &value.session_id,
                &value.provider_id,
                &value.connection_id,
                &value.invocation_id,
                &value.dispatch_id,
                value.server_sequence,
            ),
            v1::tool_provider_request::Frame::Failure(value) => self.accept_terminal(
                &value.session_id,
                &value.provider_id,
                &value.connection_id,
                &value.invocation_id,
                &value.dispatch_id,
                value.server_sequence,
            ),
        }
    }
    fn accept_terminal(
        &mut self,
        session: &[u8],
        provider: &[u8],
        connection: &[u8],
        invocation: &[u8],
        dispatch: &[u8],
        sequence: u64,
    ) -> Result<(), ValidationError> {
        self.accept_correlated(session, provider, connection, sequence)?;
        let key = (invocation.to_vec(), dispatch.to_vec());
        if self.dispatch_sequences.get(&key) != Some(&sequence)
            || self.invocation_dispatches.get(invocation) != Some(&dispatch.to_vec())
            || self.sequence_dispatches.get(&sequence) != Some(&key)
        {
            return Err(ValidationError::MissingField);
        }
        self.terminal_dispatches.insert(key);
        Ok(())
    }
    fn accept_correlated(
        &mut self,
        session: &[u8],
        provider: &[u8],
        connection: &[u8],
        sequence: u64,
    ) -> Result<(), ValidationError> {
        if !self.connected {
            return Err(ValidationError::MissingField);
        }
        if session != self.session_id
            || provider != self.provider_id
            || connection != self.connection_id
            || sequence <= self.after_server_sequence
        {
            return Err(ValidationError::InvalidIdentity);
        }
        Ok(())
    }
}

pub fn validate_begin_artifact_write(
    value: &v1::BeginArtifactWrite,
) -> Result<(), ValidationError> {
    validate_capability_metadata(value.metadata.as_ref(), CAPABILITY_ARTIFACTS_V1)?;
    validate_id(&value.request_id)?;
    validate_id(&value.session_id)?;
    validate_id(&value.artifact_id)?;
    validate_media_type(&value.media_type)?;
    if value.declared_size > MAX_ARTIFACT_BYTES {
        return Err(ValidationError::InvalidBound);
    }
    validate_exact_bytes(&value.declared_sha256, 32)?;
    validate_timestamp(value.retain_until.as_ref())?;
    validate_optional_id(&value.authority_grant_id)
        .and_then(|()| validate_id(&value.creator_participant_id))
        .and_then(|()| validate_id(&value.creator_operation_id))
}

pub fn validate_artifact_chunk(value: &v1::ArtifactChunk) -> Result<(), ValidationError> {
    validate_id(&value.artifact_id)?;
    if value.offset > MAX_ARTIFACT_BYTES {
        return Err(ValidationError::InvalidBound);
    }
    validate_nonempty_bytes(&value.content, MAX_ARTIFACT_CHUNK_BYTES)
}

#[derive(Debug, Default)]
pub struct ArtifactWriteStreamValidator {
    artifact_id: Option<Vec<u8>>,
    next_offset: u64,
    declared_size: u64,
    complete: bool,
}

impl ArtifactWriteStreamValidator {
    pub fn accept(&mut self, frame: &v1::WriteArtifactRequest) -> Result<(), ValidationError> {
        if frame.encoded_len() > MAX_REQUEST_BYTES {
            return Err(ValidationError::RequestTooLarge);
        }
        match frame.frame.as_ref().ok_or(ValidationError::MissingField)? {
            v1::write_artifact_request::Frame::Begin(value) if self.artifact_id.is_none() => {
                validate_begin_artifact_write(value)?;
                self.artifact_id = Some(value.artifact_id.clone());
                self.declared_size = value.declared_size;
                self.complete = value.declared_size == 0;
                Ok(())
            }
            v1::write_artifact_request::Frame::Begin(_) => Err(ValidationError::MalformedRequest),
            v1::write_artifact_request::Frame::Chunk(value) => {
                validate_artifact_chunk(value)?;
                if self.complete
                    || self.artifact_id.as_deref() != Some(value.artifact_id.as_slice())
                    || value.offset != self.next_offset
                {
                    return Err(ValidationError::InvalidIdentity);
                }
                self.next_offset = self
                    .next_offset
                    .checked_add(value.content.len() as u64)
                    .ok_or(ValidationError::InvalidBound)?;
                if self.next_offset > self.declared_size {
                    return Err(ValidationError::InvalidBound);
                }
                self.complete = self.next_offset == self.declared_size;
                Ok(())
            }
        }
    }
    pub fn finish(&self) -> Result<(), ValidationError> {
        if self.artifact_id.is_some() && self.complete {
            Ok(())
        } else {
            Err(ValidationError::InvalidBound)
        }
    }
}

pub fn validate_artifact_reference(value: &v1::ArtifactReference) -> Result<(), ValidationError> {
    validate_id(&value.artifact_id)?;
    validate_id(&value.session_id)?;
    validate_media_type(&value.media_type)?;
    if value.size > MAX_ARTIFACT_BYTES {
        return Err(ValidationError::InvalidBound);
    }
    validate_exact_bytes(&value.sha256, 32)
        .and_then(|()| validate_id(&value.creator_participant_id))
        .and_then(|()| validate_id(&value.creator_operation_id))
}

pub fn validate_artifact_snapshot(value: &v1::ArtifactSnapshot) -> Result<(), ValidationError> {
    validate_artifact_reference(&v1::ArtifactReference {
        artifact_id: value.artifact_id.clone(),
        session_id: value.session_id.clone(),
        media_type: value.media_type.clone(),
        size: value.size,
        sha256: value.sha256.clone(),
        creator_participant_id: value.creator_participant_id.clone(),
        creator_operation_id: value.creator_operation_id.clone(),
    })?;
    validate_locator(&value.storage_relative_locator)?;
    enum_nonzero::<v1::ArtifactStatus>(value.status)?;
    validate_timestamp(value.retain_until.as_ref())?;
    validate_timestamp(value.created_at.as_ref())?;
    validate_timestamp(value.updated_at.as_ref())?;
    validate_timestamp_order(value.created_at.as_ref(), value.updated_at.as_ref())?;
    if value.revision == 0 {
        Err(ValidationError::ZeroValue)
    } else {
        Ok(())
    }
}

pub fn validate_artifact_read_header(
    value: &v1::ArtifactReadHeader,
) -> Result<(), ValidationError> {
    let artifact = value
        .artifact
        .as_ref()
        .ok_or(ValidationError::MissingField)?;
    validate_artifact_snapshot(artifact)?;
    if (value.range_length == 0 && artifact.size != 0)
        || value
            .range_offset
            .checked_add(value.range_length)
            .is_none_or(|end| end > artifact.size)
    {
        Err(ValidationError::InvalidBound)
    } else {
        Ok(())
    }
}

pub fn validate_write_artifact_response(
    response: &v1::WriteArtifactResponse,
) -> Result<(), ValidationError> {
    match response
        .outcome
        .as_ref()
        .ok_or(ValidationError::MissingField)?
    {
        v1::write_artifact_response::Outcome::Artifact(value) => validate_artifact_snapshot(value),
        v1::write_artifact_response::Outcome::Failure(value) => validate_failure(value),
    }
}

pub fn validate_artifact_snapshot_response(
    response: &v1::ArtifactSnapshotResponse,
) -> Result<(), ValidationError> {
    match response
        .outcome
        .as_ref()
        .ok_or(ValidationError::MissingField)?
    {
        v1::artifact_snapshot_response::Outcome::Artifact(value) => {
            validate_artifact_snapshot(value)
        }
        v1::artifact_snapshot_response::Outcome::Failure(value) => validate_failure(value),
    }
}

pub fn validate_delete_artifact_response(
    response: &v1::DeleteArtifactResponse,
) -> Result<(), ValidationError> {
    match response
        .outcome
        .as_ref()
        .ok_or(ValidationError::MissingField)?
    {
        v1::delete_artifact_response::Outcome::Artifact(value) => validate_artifact_snapshot(value),
        v1::delete_artifact_response::Outcome::Failure(value) => validate_failure(value),
    }
}

#[derive(Debug, Default)]
pub struct ArtifactReadStreamValidator {
    artifact_id: Option<Vec<u8>>,
    next_offset: u64,
    end_offset: u64,
    failed: bool,
}

impl ArtifactReadStreamValidator {
    /// True only after a complete, failure-free range. Callers must not expose
    /// buffered bytes as an Artifact unless this returns true after `finish`.
    #[must_use]
    pub fn completed_successfully(&self) -> bool {
        !self.failed && self.artifact_id.is_some() && self.next_offset == self.end_offset
    }

    pub fn accept(&mut self, response: &v1::ReadArtifactResponse) -> Result<(), ValidationError> {
        if response.encoded_len() > MAX_REQUEST_BYTES {
            return Err(ValidationError::RequestTooLarge);
        }
        match response
            .outcome
            .as_ref()
            .ok_or(ValidationError::MissingField)?
        {
            v1::read_artifact_response::Outcome::Header(value)
                if self.artifact_id.is_none() && !self.failed =>
            {
                validate_artifact_read_header(value)?;
                let artifact = value
                    .artifact
                    .as_ref()
                    .ok_or(ValidationError::MissingField)?;
                self.artifact_id = Some(artifact.artifact_id.clone());
                self.next_offset = value.range_offset;
                self.end_offset = value.range_offset + value.range_length;
                Ok(())
            }
            v1::read_artifact_response::Outcome::Chunk(value) => {
                validate_artifact_chunk(value)?;
                if self.failed
                    || self.artifact_id.as_deref() != Some(value.artifact_id.as_slice())
                    || value.offset != self.next_offset
                {
                    return Err(ValidationError::InvalidIdentity);
                }
                self.next_offset = self
                    .next_offset
                    .checked_add(value.content.len() as u64)
                    .ok_or(ValidationError::InvalidBound)?;
                if self.next_offset > self.end_offset {
                    return Err(ValidationError::InvalidBound);
                }
                Ok(())
            }
            v1::read_artifact_response::Outcome::Failure(value) if !self.failed => {
                validate_failure(value)?;
                self.failed = true;
                Ok(())
            }
            v1::read_artifact_response::Outcome::Header(_)
            | v1::read_artifact_response::Outcome::Failure(_) => {
                Err(ValidationError::MalformedRequest)
            }
        }
    }

    pub fn finish(&self) -> Result<(), ValidationError> {
        if self.failed || self.completed_successfully() {
            Ok(())
        } else {
            Err(ValidationError::InvalidBound)
        }
    }
}

fn enum_nonzero<E>(value: i32) -> Result<E, ValidationError>
where
    E: TryFrom<i32> + Copy + Into<i32>,
{
    let parsed = E::try_from(value).map_err(|_| ValidationError::InvalidEnum)?;
    if parsed.into() == 0 {
        Err(ValidationError::InvalidEnum)
    } else {
        Ok(parsed)
    }
}

fn validate_unique_ids(values: &[Vec<u8>]) -> Result<(), ValidationError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_id(value)?;
        if !unique.insert(value.as_slice()) {
            return Err(ValidationError::InvalidIdentity);
        }
    }
    Ok(())
}

fn validate_optional_id(value: &[u8]) -> Result<(), ValidationError> {
    if value.is_empty() {
        Ok(())
    } else {
        validate_id(value)
    }
}
fn validated_canonical_json<const MAX: usize>(
    value: &[u8],
) -> Result<CanonicalJson<MAX>, ValidationError> {
    let canonical = CanonicalJson::<MAX>::new(value).map_err(|_| ValidationError::InvalidBound)?;
    if canonical.as_bytes() == value {
        Ok(canonical)
    } else {
        Err(ValidationError::InvalidBound)
    }
}
fn validate_stable_identifier(value: &str, maximum: usize) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > maximum
        || !value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        Err(ValidationError::InvalidBound)
    } else {
        Ok(())
    }
}
fn validate_media_type(value: &str) -> Result<(), ValidationError> {
    let (kind, subtype) = value.split_once('/').unwrap_or_default();
    if kind.is_empty()
        || subtype.is_empty()
        || value.len() > MAX_MEDIA_TYPE_BYTES
        || value.matches('/').count() != 1
        || !value.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-' | b'/'
                )
        })
    {
        Err(ValidationError::InvalidBound)
    } else {
        Ok(())
    }
}
fn validate_locator(value: &str) -> Result<(), ValidationError> {
    use std::path::{Component, Path};
    if value.is_empty()
        || value.len() > MAX_ARTIFACT_LOCATOR_BYTES
        || value.contains('\\')
        || value
            .split('/')
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        || Path::new(value)
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        Err(ValidationError::InvalidBound)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
