use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize, de::MapAccess, de::Visitor};
use thiserror::Error;

use crate::{
    AuthorityProfile, BoundError, BoundedBytes, BoundedText, Capability, CompatibilityIdentity,
    DriverId, FencingEpoch, InstanceId, LaunchAttemptId, ParticipantId, Secret, SessionId,
    TemplateId,
};

pub const MAX_DRIVER_CAPABILITIES: usize = 32;
pub const MAX_CAPABILITY_PARAMETERS: usize = 16;
pub const MAX_INPUT_FIELDS: usize = 32;
pub const MAX_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_TRUSTED_CONFIGURATION_BYTES: usize = 64 * 1024;
pub const MAX_ROLE_BYTES: usize = 128;
pub const MAX_FIELD_NAME_BYTES: usize = 64;
pub const MAX_PARAMETER_BYTES: usize = 256;
pub const MAX_PARTICIPANT_MEMORY_BYTES: u64 = 1 << 40;
pub const MAX_PARTICIPANT_CPU_MILLIS: u64 = 86_400_000;
pub const MAX_TEMPLATE_SECRETS: usize = 32;

#[derive(Debug, Default)]
pub struct TemplateSecrets(
    BTreeMap<BoundedText<MAX_FIELD_NAME_BYTES>, Secret<BoundedBytes<MAX_PARAMETER_BYTES>>>,
);

impl TemplateSecrets {
    pub fn new(
        values: impl IntoIterator<
            Item = (
                BoundedText<MAX_FIELD_NAME_BYTES>,
                Secret<BoundedBytes<MAX_PARAMETER_BYTES>>,
            ),
        >,
    ) -> Result<Self, TemplateDomainError> {
        let mut collected = BTreeMap::new();
        for (name, value) in values {
            if collected.insert(name, value).is_some() {
                return Err(TemplateDomainError::DuplicateSecretName);
            }
            if collected.len() > MAX_TEMPLATE_SECRETS {
                return Err(TemplateDomainError::TooManySecrets);
            }
        }
        Ok(Self(collected))
    }

    #[must_use]
    pub fn get(
        &self,
        name: &BoundedText<MAX_FIELD_NAME_BYTES>,
    ) -> Option<&Secret<BoundedBytes<MAX_PARAMETER_BYTES>>> {
        self.0.get(name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DriverCapabilityRequirement {
    capability: Capability,
    minimum_version: u32,
    parameters: BTreeMap<BoundedText<MAX_FIELD_NAME_BYTES>, BoundedText<MAX_PARAMETER_BYTES>>,
}

impl DriverCapabilityRequirement {
    pub fn new(
        capability: Capability,
        minimum_version: u32,
        parameters: impl IntoIterator<
            Item = (
                BoundedText<MAX_FIELD_NAME_BYTES>,
                BoundedText<MAX_PARAMETER_BYTES>,
            ),
        >,
    ) -> Result<Self, TemplateDomainError> {
        if minimum_version == 0 {
            return Err(TemplateDomainError::ZeroCapabilityVersion);
        }
        let mut collected = BTreeMap::new();
        for (key, value) in parameters {
            if collected.insert(key, value).is_some() {
                return Err(TemplateDomainError::DuplicateCapabilityParameter);
            }
            if collected.len() > MAX_CAPABILITY_PARAMETERS {
                return Err(TemplateDomainError::TooManyCapabilityParameters);
            }
        }
        Ok(Self {
            capability,
            minimum_version,
            parameters: collected,
        })
    }

    #[must_use]
    pub fn capability(&self) -> &Capability {
        &self.capability
    }

    #[must_use]
    pub const fn minimum_version(&self) -> u32 {
        self.minimum_version
    }

    #[must_use]
    pub fn parameters(
        &self,
    ) -> &BTreeMap<BoundedText<MAX_FIELD_NAME_BYTES>, BoundedText<MAX_PARAMETER_BYTES>> {
        &self.parameters
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DriverRequirement {
    driver_id: DriverId,
    capabilities: Vec<DriverCapabilityRequirement>,
}

impl DriverRequirement {
    pub fn new(
        driver_id: DriverId,
        mut capabilities: Vec<DriverCapabilityRequirement>,
    ) -> Result<Self, TemplateDomainError> {
        if capabilities.len() > MAX_DRIVER_CAPABILITIES {
            return Err(TemplateDomainError::TooManyDriverCapabilities);
        }
        capabilities.sort_by(|left, right| left.capability.cmp(&right.capability));
        if capabilities
            .windows(2)
            .any(|pair| pair[0].capability == pair[1].capability)
        {
            return Err(TemplateDomainError::DuplicateDriverCapability);
        }
        Ok(Self {
            driver_id,
            capabilities,
        })
    }

    #[must_use]
    pub const fn driver_id(&self) -> DriverId {
        self.driver_id
    }

    #[must_use]
    pub fn capabilities(&self) -> &[DriverCapabilityRequirement] {
        &self.capabilities
    }

    #[must_use]
    pub fn is_satisfied_by(
        &self,
        offered_driver_id: DriverId,
        offered: &[DriverCapabilityRequirement],
    ) -> bool {
        let unique = offered
            .iter()
            .map(|item| &item.capability)
            .collect::<BTreeSet<_>>()
            .len()
            == offered.len();
        unique
            && offered_driver_id == self.driver_id
            && self.capabilities.iter().all(|required| {
                offered.iter().any(|actual| {
                    actual.capability == required.capability
                        && actual.minimum_version >= required.minimum_version
                        && required.parameters.iter().all(|(key, value)| {
                            actual
                                .parameters
                                .get(key)
                                .is_some_and(|actual| actual == value)
                        })
                })
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    String,
    Integer,
    Boolean,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InputField {
    name: BoundedText<MAX_FIELD_NAME_BYTES>,
    kind: InputKind,
    required: bool,
    max_string_bytes: Option<usize>,
}

impl InputField {
    pub fn new(
        name: BoundedText<MAX_FIELD_NAME_BYTES>,
        kind: InputKind,
        required: bool,
        max_string_bytes: Option<usize>,
    ) -> Result<Self, TemplateDomainError> {
        match (kind, max_string_bytes) {
            (InputKind::String, Some(1..=MAX_INPUT_BYTES) | None)
            | (InputKind::Integer | InputKind::Boolean, None) => Ok(Self {
                name,
                kind,
                required,
                max_string_bytes,
            }),
            _ => Err(TemplateDomainError::InvalidFieldBound),
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    #[must_use]
    pub const fn kind(&self) -> InputKind {
        self.kind
    }

    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    #[must_use]
    pub const fn max_string_bytes(&self) -> Option<usize> {
        self.max_string_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InputSchema(Vec<InputField>);

impl InputSchema {
    pub fn new(mut fields: Vec<InputField>) -> Result<Self, TemplateDomainError> {
        if fields.len() > MAX_INPUT_FIELDS {
            return Err(TemplateDomainError::TooManyInputFields);
        }
        fields.sort_by(|left, right| left.name.as_str().cmp(right.name.as_str()));
        if fields.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(TemplateDomainError::DuplicateInputField);
        }
        Ok(Self(fields))
    }

    pub fn validate(&self, input: &[u8]) -> Result<ValidatedTaskInput, TemplateDomainError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(TemplateDomainError::InputTooLarge);
        }
        let object: UniqueObject =
            serde_json::from_slice(input).map_err(|_| TemplateDomainError::InvalidTaskInput)?;
        if object.0.len() > self.0.len() {
            return Err(TemplateDomainError::UnknownInputField);
        }
        let allowed: BTreeSet<_> = self.0.iter().map(|field| field.name.as_str()).collect();
        if object.0.keys().any(|key| !allowed.contains(key.as_str())) {
            return Err(TemplateDomainError::UnknownInputField);
        }
        for field in &self.0 {
            let value = object.0.get(field.name.as_str());
            if field.required && value.is_none() {
                return Err(TemplateDomainError::MissingInputField);
            }
            if let Some(value) = value {
                validate_field(field, value)?;
            }
        }
        let canonical =
            serde_json::to_vec(&object.0).map_err(|_| TemplateDomainError::InvalidTaskInput)?;
        BoundedBytes::new(canonical)
            .map(ValidatedTaskInput)
            .map_err(TemplateDomainError::Bound)
    }

    #[must_use]
    pub fn fields(&self) -> &[InputField] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TrustedConfiguration {
    base_instructions: BoundedText<MAX_TRUSTED_CONFIGURATION_BYTES>,
    secret_names: BTreeSet<BoundedText<MAX_FIELD_NAME_BYTES>>,
}

impl TrustedConfiguration {
    pub fn new(
        base_instructions: BoundedText<MAX_TRUSTED_CONFIGURATION_BYTES>,
        secret_names: impl IntoIterator<Item = BoundedText<MAX_FIELD_NAME_BYTES>>,
    ) -> Result<Self, TemplateDomainError> {
        let mut collected = BTreeSet::new();
        for name in secret_names {
            if !collected.insert(name) {
                return Err(TemplateDomainError::DuplicateSecretName);
            }
            if collected.len() > MAX_TEMPLATE_SECRETS {
                return Err(TemplateDomainError::TooManySecrets);
            }
        }
        Ok(Self {
            base_instructions,
            secret_names: collected,
        })
    }

    #[must_use]
    pub fn base_instructions(&self) -> &str {
        self.base_instructions.as_str()
    }

    pub fn secret_names(&self) -> impl Iterator<Item = &str> {
        self.secret_names.iter().map(BoundedText::as_str)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ValidatedTaskInput(BoundedBytes<MAX_INPUT_BYTES>);

impl ValidatedTaskInput {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceBounds {
    pub memory_bytes: u64,
    pub cpu_millis: u64,
    pub max_concurrent_operations: u16,
}

impl ResourceBounds {
    pub fn new(
        memory_bytes: u64,
        cpu_millis: u64,
        max_concurrent_operations: u16,
    ) -> Result<Self, TemplateDomainError> {
        if memory_bytes == 0
            || memory_bytes > MAX_PARTICIPANT_MEMORY_BYTES
            || cpu_millis == 0
            || cpu_millis > MAX_PARTICIPANT_CPU_MILLIS
            || max_concurrent_operations != 1
        {
            Err(TemplateDomainError::InvalidResourceBounds)
        } else {
            Ok(Self {
                memory_bytes,
                cpu_millis,
                max_concurrent_operations,
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Template {
    identity: TemplateId,
    role: BoundedText<MAX_ROLE_BYTES>,
    driver: DriverRequirement,
    trusted_configuration: TrustedConfiguration,
    resources: ResourceBounds,
    input_schema: InputSchema,
    authority: AuthorityProfile,
    compatibility: CompatibilityIdentity,
}

impl Template {
    pub fn register(
        template_id: TemplateId,
        role: BoundedText<MAX_ROLE_BYTES>,
        driver: DriverRequirement,
        trusted_configuration: TrustedConfiguration,
        resources: ResourceBounds,
        input_schema: InputSchema,
    ) -> Result<Self, TemplateDomainError> {
        Self::register_with_authority(
            template_id,
            role,
            driver,
            trusted_configuration,
            resources,
            input_schema,
            AuthorityProfile::default(),
        )
    }

    pub fn register_with_authority(
        template_id: TemplateId,
        role: BoundedText<MAX_ROLE_BYTES>,
        driver: DriverRequirement,
        trusted_configuration: TrustedConfiguration,
        resources: ResourceBounds,
        input_schema: InputSchema,
        authority: AuthorityProfile,
    ) -> Result<Self, TemplateDomainError> {
        let canonical =
            if authority.active().next().is_none() && authority.delegable().next().is_none() {
                serde_json::to_vec(&(
                    template_id,
                    &role,
                    &driver,
                    &trusted_configuration,
                    resources,
                    &input_schema,
                ))
            } else {
                serde_json::to_vec(&(
                    template_id,
                    &role,
                    &driver,
                    &trusted_configuration,
                    resources,
                    &input_schema,
                    &authority,
                ))
            }
            .map_err(|_| TemplateDomainError::Canonicalization)?;
        let compatibility = CompatibilityIdentity::digest(&canonical);
        Ok(Self {
            identity: template_id,
            role,
            driver,
            trusted_configuration,
            resources,
            input_schema,
            authority,
            compatibility,
        })
    }

    pub fn restore_registered(
        template_id: TemplateId,
        role: BoundedText<MAX_ROLE_BYTES>,
        driver: DriverRequirement,
        trusted_configuration: TrustedConfiguration,
        resources: ResourceBounds,
        input_schema: InputSchema,
        expected_compatibility: CompatibilityIdentity,
    ) -> Result<Self, TemplateDomainError> {
        Self::restore_registered_with_authority(
            template_id,
            role,
            driver,
            trusted_configuration,
            resources,
            input_schema,
            AuthorityProfile::default(),
            expected_compatibility,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "durable restoration verifies every independently persisted template field"
    )]
    pub fn restore_registered_with_authority(
        template_id: TemplateId,
        role: BoundedText<MAX_ROLE_BYTES>,
        driver: DriverRequirement,
        trusted_configuration: TrustedConfiguration,
        resources: ResourceBounds,
        input_schema: InputSchema,
        authority: AuthorityProfile,
        expected_compatibility: CompatibilityIdentity,
    ) -> Result<Self, TemplateDomainError> {
        let template = Self::register_with_authority(
            template_id,
            role,
            driver,
            trusted_configuration,
            resources,
            input_schema,
            authority,
        )?;
        if template.compatibility == expected_compatibility {
            Ok(template)
        } else {
            Err(TemplateDomainError::CompatibilityMismatch)
        }
    }

    #[must_use]
    pub const fn template_id(&self) -> TemplateId {
        self.identity
    }

    #[must_use]
    pub const fn compatibility(&self) -> CompatibilityIdentity {
        self.compatibility
    }

    #[must_use]
    pub fn matches_registration(
        &self,
        template_id: TemplateId,
        compatibility: CompatibilityIdentity,
    ) -> bool {
        self.identity == template_id && self.compatibility == compatibility
    }

    pub fn validate_input(&self, input: &[u8]) -> Result<ValidatedTaskInput, TemplateDomainError> {
        self.input_schema.validate(input)
    }

    #[must_use]
    pub fn trusted_configuration(&self) -> &TrustedConfiguration {
        &self.trusted_configuration
    }

    #[must_use]
    pub fn role(&self) -> &str {
        self.role.as_str()
    }

    #[must_use]
    pub const fn driver_requirement(&self) -> &DriverRequirement {
        &self.driver
    }

    #[must_use]
    pub const fn resources(&self) -> ResourceBounds {
        self.resources
    }

    #[must_use]
    pub const fn input_schema(&self) -> &InputSchema {
        &self.input_schema
    }

    #[must_use]
    pub const fn authority(&self) -> &AuthorityProfile {
        &self.authority
    }

    #[must_use]
    pub fn public_snapshot(&self) -> TemplatePublicSnapshot {
        TemplatePublicSnapshot {
            template_id: self.identity,
            compatibility: self.compatibility,
            role: self.role.clone(),
            driver: self.driver.clone(),
            resources: self.resources,
            input_schema: self.input_schema.clone(),
        }
    }

    #[must_use]
    pub fn registration_snapshot(&self) -> RegisteredTemplateSnapshot {
        RegisteredTemplateSnapshot {
            identity: self.identity,
            role: self.role.clone(),
            driver: self.driver.clone(),
            trusted_configuration: self.trusted_configuration.clone(),
            resources: self.resources,
            input_schema: self.input_schema.clone(),
            authority: self.authority.clone(),
            compatibility: self.compatibility,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegisteredTemplateSnapshot {
    pub identity: TemplateId,
    pub role: BoundedText<MAX_ROLE_BYTES>,
    pub driver: DriverRequirement,
    pub trusted_configuration: TrustedConfiguration,
    pub resources: ResourceBounds,
    pub input_schema: InputSchema,
    pub authority: AuthorityProfile,
    pub compatibility: CompatibilityIdentity,
}

impl TryFrom<RegisteredTemplateSnapshot> for Template {
    type Error = TemplateDomainError;

    fn try_from(value: RegisteredTemplateSnapshot) -> Result<Self, Self::Error> {
        Self::restore_registered_with_authority(
            value.identity,
            value.role,
            value.driver,
            value.trusted_configuration,
            value.resources,
            value.input_schema,
            value.authority,
            value.compatibility,
        )
    }
}

impl<'de> Deserialize<'de> for RegisteredTemplateSnapshot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = RegistrationWire::deserialize(deserializer)?;
        let template = wire.into_template().map_err(serde::de::Error::custom)?;
        Ok(template.registration_snapshot())
    }
}

#[derive(Deserialize)]
struct RegistrationWire {
    identity: TemplateId,
    role: String,
    driver: DriverRegistrationWire,
    trusted_configuration: TrustedRegistrationWire,
    resources: ResourceRegistrationWire,
    input_schema: Vec<InputRegistrationWire>,
    #[serde(default)]
    authority: AuthorityProfile,
    compatibility: CompatibilityIdentity,
}

impl RegistrationWire {
    fn into_template(self) -> Result<Template, TemplateDomainError> {
        let capabilities = self
            .driver
            .capabilities
            .into_iter()
            .map(DriverCapabilityRegistrationWire::validate)
            .collect::<Result<Vec<_>, _>>()?;
        let driver = DriverRequirement::new(self.driver.driver_id, capabilities)?;
        let trusted = TrustedConfiguration::new(
            BoundedText::new(self.trusted_configuration.base_instructions)?,
            self.trusted_configuration
                .secret_names
                .into_iter()
                .map(BoundedText::new)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        let input_schema = InputSchema::new(
            self.input_schema
                .into_iter()
                .map(InputRegistrationWire::validate)
                .collect::<Result<Vec<_>, _>>()?,
        )?;
        Template::restore_registered_with_authority(
            self.identity,
            BoundedText::new(self.role)?,
            driver,
            trusted,
            ResourceBounds::new(
                self.resources.memory_bytes,
                self.resources.cpu_millis,
                self.resources.max_concurrent_operations,
            )?,
            input_schema,
            self.authority,
            self.compatibility,
        )
    }
}

#[derive(Deserialize)]
struct DriverRegistrationWire {
    driver_id: DriverId,
    capabilities: Vec<DriverCapabilityRegistrationWire>,
}

#[derive(Deserialize)]
struct DriverCapabilityRegistrationWire {
    capability: Capability,
    minimum_version: u32,
    parameters: BTreeMap<String, String>,
}

impl DriverCapabilityRegistrationWire {
    fn validate(self) -> Result<DriverCapabilityRequirement, TemplateDomainError> {
        DriverCapabilityRequirement::new(
            self.capability,
            self.minimum_version,
            self.parameters
                .into_iter()
                .map(|(key, value)| Ok((BoundedText::new(key)?, BoundedText::new(value)?)))
                .collect::<Result<Vec<_>, TemplateDomainError>>()?,
        )
    }
}

#[derive(Deserialize)]
struct TrustedRegistrationWire {
    base_instructions: String,
    secret_names: Vec<String>,
}

#[derive(Deserialize)]
struct ResourceRegistrationWire {
    memory_bytes: u64,
    cpu_millis: u64,
    max_concurrent_operations: u16,
}

#[derive(Deserialize)]
struct InputRegistrationWire {
    name: String,
    kind: InputKind,
    required: bool,
    max_string_bytes: Option<usize>,
}

impl InputRegistrationWire {
    fn validate(self) -> Result<InputField, TemplateDomainError> {
        InputField::new(
            BoundedText::new(self.name)?,
            self.kind,
            self.required,
            self.max_string_bytes,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TemplatePublicSnapshot {
    pub template_id: TemplateId,
    pub compatibility: CompatibilityIdentity,
    pub role: BoundedText<MAX_ROLE_BYTES>,
    pub driver: DriverRequirement,
    pub resources: ResourceBounds,
    pub input_schema: InputSchema,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LaunchIdentity {
    pub session_id: SessionId,
    pub participant_id: ParticipantId,
    pub launch_attempt_id: LaunchAttemptId,
    pub instance_id: InstanceId,
    pub driver_id: DriverId,
    pub ownership_epoch: FencingEpoch,
}

struct UniqueObject(BTreeMap<String, serde_json::Value>);

impl<'de> Deserialize<'de> for UniqueObject {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ObjectVisitor;
        impl<'de> Visitor<'de> for ObjectVisitor {
            type Value = UniqueObject;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object with unique field names")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, serde_json::Value>()? {
                    if values.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate input field"));
                    }
                }
                Ok(UniqueObject(values))
            }
        }
        deserializer.deserialize_map(ObjectVisitor)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RootParticipant {
    participant_id: ParticipantId,
    session_id: SessionId,
    template_id: TemplateId,
    template_compatibility: CompatibilityIdentity,
    expected_driver_id: DriverId,
    current_launch: Option<LaunchIdentity>,
}

impl RootParticipant {
    #[must_use]
    pub const fn new(
        participant_id: ParticipantId,
        session_id: SessionId,
        template: &Template,
    ) -> Self {
        Self {
            participant_id,
            session_id,
            template_id: template.identity,
            template_compatibility: template.compatibility,
            expected_driver_id: template.driver.driver_id,
            current_launch: None,
        }
    }

    pub fn bind_launch(
        &mut self,
        current_ownership_epoch: FencingEpoch,
        launch: LaunchIdentity,
    ) -> Result<(), ParticipantDomainError> {
        if launch.session_id != self.session_id
            || launch.participant_id != self.participant_id
            || launch.driver_id != self.expected_driver_id
            || !launch.ownership_epoch.is_current(current_ownership_epoch)
        {
            return Err(ParticipantDomainError::LaunchIdentityMismatch);
        }
        if self
            .current_launch
            .as_ref()
            .is_some_and(|current| current != &launch)
        {
            return Err(ParticipantDomainError::CurrentInstanceConflict);
        }
        self.current_launch = Some(launch);
        Ok(())
    }

    #[must_use]
    pub fn snapshot(&self) -> RootParticipantSnapshot {
        RootParticipantSnapshot {
            participant_id: self.participant_id,
            session_id: self.session_id,
            template_id: self.template_id,
            template_compatibility: self.template_compatibility,
            expected_driver_id: self.expected_driver_id,
            current_launch: self.current_launch,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RootParticipantSnapshot {
    pub participant_id: ParticipantId,
    pub session_id: SessionId,
    pub template_id: TemplateId,
    pub template_compatibility: CompatibilityIdentity,
    pub expected_driver_id: DriverId,
    pub current_launch: Option<LaunchIdentity>,
}

fn validate_field(
    field: &InputField,
    value: &serde_json::Value,
) -> Result<(), TemplateDomainError> {
    let valid = match field.kind {
        InputKind::String => value.as_str().is_some_and(|value| {
            field
                .max_string_bytes
                .is_none_or(|maximum| value.len() <= maximum)
        }),
        InputKind::Integer => value.as_i64().is_some(),
        InputKind::Boolean => value.as_bool().is_some(),
    };
    if valid {
        Ok(())
    } else {
        Err(TemplateDomainError::InputFieldType)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TemplateDomainError {
    #[error("bounded Template value is invalid")]
    Bound(#[from] BoundError),
    #[error("Driver capability version must be nonzero")]
    ZeroCapabilityVersion,
    #[error("too many Driver capability parameters")]
    TooManyCapabilityParameters,
    #[error("Driver capability parameter is duplicated")]
    DuplicateCapabilityParameter,
    #[error("too many Driver capabilities")]
    TooManyDriverCapabilities,
    #[error("Driver capability is duplicated")]
    DuplicateDriverCapability,
    #[error("input field bound is invalid")]
    InvalidFieldBound,
    #[error("too many input fields")]
    TooManyInputFields,
    #[error("input field is duplicated")]
    DuplicateInputField,
    #[error("task input exceeds its bound")]
    InputTooLarge,
    #[error("task input is invalid")]
    InvalidTaskInput,
    #[error("task input has an unknown field")]
    UnknownInputField,
    #[error("task input is missing a required field")]
    MissingInputField,
    #[error("task input field has the wrong type or bound")]
    InputFieldType,
    #[error("resource bounds are invalid")]
    InvalidResourceBounds,
    #[error("Template canonicalization failed")]
    Canonicalization,
    #[error("registered Template content does not match its compatibility identity")]
    CompatibilityMismatch,
    #[error("too many Template secrets")]
    TooManySecrets,
    #[error("Template secret name is duplicated")]
    DuplicateSecretName,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ParticipantDomainError {
    #[error("launch identity does not belong to the root Participant")]
    LaunchIdentityMismatch,
    #[error("a different current Instance is already bound")]
    CurrentInstanceConflict,
}
