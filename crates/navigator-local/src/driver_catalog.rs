use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use navigator_core::ExecutorError;
use navigator_domain::{
    BoundedText, Capability, DriverCapabilityRequirement, DriverId, DriverRequirement,
    MAX_FIELD_NAME_BYTES, MAX_PARAMETER_BYTES, Template,
};
use navigator_store_api::TemplateRecord;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{DriverConfigResolver, SupervisedDriverConfig};

pub const SUPPORTED_DRIVER_PROTOCOL_VERSION: u32 = navigator_driver_protocol::PROTOCOL_V1;
const MAX_CATALOG_BYTES: usize = 1_048_576;
const MAX_CATALOG_ENTRIES: usize = 128;
const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_BYTES: usize = 4_096;
const MAX_ENVIRONMENT: usize = 128;
const MAX_ENTRY_NAME_BYTES: usize = 64;
const MAX_TRUSTED_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum DriverCatalogError {
    #[error("trusted Driver catalog is not configured")]
    MissingCatalog,
    #[error("Driver catalog entry is unknown")]
    UnknownEntry,
    #[error("Driver selection came from untrusted task input")]
    UntrustedSelection,
    #[error("Driver catalog is invalid")]
    InvalidCatalog,
    #[error("Driver capability or identity mismatch")]
    CapabilityMismatch,
    #[error("Driver catalog could not be read")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverSelectionSource {
    TrustedConfiguration,
    UntrustedTaskInput,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    entries: BTreeMap<String, CatalogEntryFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntryFile {
    driver_id: String,
    executable: PathBuf,
    executable_sha256: String,
    #[serde(default)]
    arguments: Vec<String>,
    working_directory: PathBuf,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    protocol_version: u32,
    #[serde(default)]
    capabilities: Vec<CapabilityFile>,
    #[serde(default)]
    ownership_channel: OwnershipChannelFile,
    #[serde(default)]
    process_io_mode: ProcessIoModeFile,
    #[serde(default)]
    bootstrap_configuration: serde_json::Value,
    #[serde(default)]
    trusted_artifacts: Vec<TrustedArtifactFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedArtifactFile {
    path: PathBuf,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnershipChannelFile {
    #[default]
    Stdin,
    DedicatedFd,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProcessIoModeFile {
    #[default]
    Headless,
    TerminalPty,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityFile {
    name: String,
    version: u32,
    #[serde(default)]
    parameters: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct TrustedDriverEntry {
    driver_id: DriverId,
    executable: PathBuf,
    executable_identity: [u8; 32],
    arguments: Vec<OsString>,
    working_directory: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    protocol_version: u32,
    capabilities: Vec<DriverCapabilityRequirement>,
    ownership_channel: OwnershipChannelFile,
    process_io_mode: ProcessIoModeFile,
    bootstrap_configuration: Vec<u8>,
    trusted_artifacts: Vec<(PathBuf, [u8; 32])>,
}

impl std::fmt::Debug for TrustedDriverEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedDriverEntry")
            .field("driver_id", &self.driver_id)
            .field("executable", &self.executable)
            .field("executable_identity", &self.executable_identity)
            .field("working_directory", &self.working_directory)
            .field("protocol_version", &self.protocol_version)
            .field("capabilities", &self.capabilities)
            .field("ownership_channel", &self.ownership_channel)
            .field("process_io_mode", &self.process_io_mode)
            .field("arguments", &"[redacted]")
            .field("environment", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default)]
pub struct TrustedDriverCatalog {
    entries: BTreeMap<String, TrustedDriverEntry>,
}

impl TrustedDriverCatalog {
    #[must_use]
    pub fn configuration_identity(&self, profiles: &BTreeSet<String>) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"navigator.driver.catalog.configuration.v1\0");
        for profile in profiles {
            digest.update(
                u64::try_from(profile.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            digest.update(profile.as_bytes());
            if let Some(entry) = self.entries.get(profile) {
                digest.update(entry.driver_id.as_uuid().as_bytes());
                digest.update(entry.executable_identity);
                digest.update(entry.protocol_version.to_be_bytes());
                let working_directory = entry.working_directory.as_os_str().as_encoded_bytes();
                digest.update(
                    u64::try_from(working_directory.len())
                        .unwrap_or(u64::MAX)
                        .to_be_bytes(),
                );
                digest.update(working_directory);
                for argument in &entry.arguments {
                    let bytes = argument.as_encoded_bytes();
                    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
                    digest.update(bytes);
                }
                for (key, value) in &entry.environment {
                    let key = key.as_encoded_bytes();
                    let value = value.as_encoded_bytes();
                    digest.update(u64::try_from(key.len()).unwrap_or(u64::MAX).to_be_bytes());
                    digest.update(key);
                    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
                    digest.update(value);
                }
                digest.update(
                    u64::try_from(entry.bootstrap_configuration.len())
                        .unwrap_or(u64::MAX)
                        .to_be_bytes(),
                );
                digest.update(&entry.bootstrap_configuration);
                digest.update([entry.ownership_channel as u8, entry.process_io_mode as u8]);
                for (path, identity) in &entry.trusted_artifacts {
                    let bytes = path.as_os_str().as_encoded_bytes();
                    digest.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
                    digest.update(bytes);
                    digest.update(identity);
                }
                for capability in &entry.capabilities {
                    digest.update(capability.capability().as_str().as_bytes());
                    digest.update(capability.minimum_version().to_be_bytes());
                    for (key, value) in capability.parameters() {
                        digest.update(key.as_str().as_bytes());
                        digest.update(value.as_str().as_bytes());
                    }
                }
            }
        }
        digest.finalize().into()
    }
}

/// Trusted per-Template profile selection. Profile names are operator allowlisted and are
/// never read from operation input. When several profiles satisfy a requirement, the least
/// privileged capability set wins; equal candidates fail closed.
#[derive(Clone)]
pub struct CatalogDriverConfigResolver {
    catalog: TrustedDriverCatalog,
    allowed_profiles: Option<BTreeSet<String>>,
    control_directory: PathBuf,
}

impl CatalogDriverConfigResolver {
    #[must_use]
    pub fn new(
        catalog: TrustedDriverCatalog,
        allowed_profiles: Option<BTreeSet<String>>,
        control_directory: PathBuf,
    ) -> Self {
        Self {
            catalog,
            allowed_profiles,
            control_directory,
        }
    }
}

impl DriverConfigResolver for CatalogDriverConfigResolver {
    fn resolve(
        &self,
        registered: &TemplateRecord,
    ) -> Result<SupervisedDriverConfig, ExecutorError> {
        let template = Template::try_from(registered.clone()).map_err(|_| resolver_error())?;
        let requirement = template.driver_requirement();
        let candidates = self
            .catalog
            .entries
            .iter()
            .filter(|(profile, entry)| {
                self.allowed_profiles
                    .as_ref()
                    .is_none_or(|allowed| allowed.contains(*profile))
                    && requirement.is_satisfied_by(entry.driver_id, &entry.capabilities)
            })
            .collect::<Vec<_>>();
        let minimal = candidates
            .iter()
            .filter(|(_, candidate)| {
                !candidates.iter().any(|(_, other)| {
                    !std::ptr::eq(*candidate, *other)
                        && capabilities_are_subset(&other.capabilities, &candidate.capabilities)
                        && !capabilities_are_subset(&candidate.capabilities, &other.capabilities)
                })
            })
            .collect::<Vec<_>>();
        let [(_, selected)] = minimal.as_slice() else {
            return Err(resolver_error());
        };
        Ok(selected.supervised_config(self.control_directory.clone()))
    }
}

fn capabilities_are_subset(
    lesser: &[DriverCapabilityRequirement],
    greater: &[DriverCapabilityRequirement],
) -> bool {
    lesser.iter().all(|required| {
        greater.iter().any(|offered| {
            offered.capability() == required.capability()
                && offered.minimum_version() >= required.minimum_version()
                && required.parameters().iter().all(|(key, value)| {
                    offered
                        .parameters()
                        .get(key)
                        .is_some_and(|other| other == value)
                })
        })
    })
}

fn resolver_error() -> ExecutorError {
    ExecutorError {
        message: "trusted Driver profile resolution failed".into(),
    }
}

impl TrustedDriverCatalog {
    pub fn from_path(path: Option<&Path>) -> Result<Self, DriverCatalogError> {
        let path = path.ok_or(DriverCatalogError::MissingCatalog)?;
        validate_trusted_file(path)?;
        let file = std::fs::File::open(path)?;
        if usize::try_from(file.metadata()?.len()).map_or(true, |length| length > MAX_CATALOG_BYTES)
        {
            return Err(DriverCatalogError::InvalidCatalog);
        }
        let mut bytes = Vec::new();
        file.take(u64::try_from(MAX_CATALOG_BYTES + 1).unwrap())
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CATALOG_BYTES {
            return Err(DriverCatalogError::InvalidCatalog);
        }
        let parsed: CatalogFile =
            serde_json::from_slice(&bytes).map_err(|_| DriverCatalogError::InvalidCatalog)?;
        let mut entries = BTreeMap::new();
        if parsed.entries.len() > MAX_CATALOG_ENTRIES {
            return Err(DriverCatalogError::InvalidCatalog);
        }
        for (name, entry) in parsed.entries {
            if name.is_empty()
                || name.len() > MAX_ENTRY_NAME_BYTES
                || entry.protocol_version != SUPPORTED_DRIVER_PROTOCOL_VERSION
                || entry.arguments.len() > MAX_ARGUMENTS
                || entry.arguments.iter().any(|value| invalid_argument(value))
                || entry.environment.len() > MAX_ENVIRONMENT
            {
                return Err(DriverCatalogError::InvalidCatalog);
            }
            let driver_id = uuid::Uuid::parse_str(&entry.driver_id)
                .ok()
                .and_then(|value| DriverId::from_uuid(value).ok())
                .ok_or(DriverCatalogError::InvalidCatalog)?;
            let executable = validate_absolute_file(&entry.executable)?;
            let executable_identity = parse_digest(&entry.executable_sha256)?;
            if digest_file(&executable)? != executable_identity {
                return Err(DriverCatalogError::InvalidCatalog);
            }
            validate_trusted_directory(&entry.working_directory)?;
            let working_directory = entry.working_directory.canonicalize()?;
            if !working_directory.is_dir() {
                return Err(DriverCatalogError::InvalidCatalog);
            }
            let capabilities = entry
                .capabilities
                .into_iter()
                .map(capability)
                .collect::<Result<Vec<_>, _>>()?;
            let bootstrap_configuration = serde_json::to_vec(&entry.bootstrap_configuration)
                .map_err(|_| DriverCatalogError::InvalidCatalog)?;
            if bootstrap_configuration.len() > MAX_CATALOG_BYTES {
                return Err(DriverCatalogError::InvalidCatalog);
            }
            let trusted_artifacts = trusted_artifacts(entry.trusted_artifacts)?;
            DriverRequirement::new(driver_id, capabilities.clone())
                .map_err(|_| DriverCatalogError::InvalidCatalog)?;
            if entry.environment.keys().any(|key| {
                key.is_empty()
                    || key.contains('=')
                    || key.as_bytes().contains(&0)
                    || key.starts_with("NAVIGATOR_")
                    || credential_like(key)
                    || entry.environment[key]
                        .bytes()
                        .any(|byte| byte == 0 || byte.is_ascii_control())
            }) {
                return Err(DriverCatalogError::InvalidCatalog);
            }
            let environment: BTreeMap<OsString, OsString> = entry
                .environment
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect();
            entries.insert(
                name,
                TrustedDriverEntry {
                    driver_id,
                    executable,
                    executable_identity,
                    arguments: entry.arguments.into_iter().map(Into::into).collect(),
                    working_directory,
                    environment,
                    protocol_version: entry.protocol_version,
                    capabilities,
                    ownership_channel: entry.ownership_channel,
                    process_io_mode: entry.process_io_mode,
                    bootstrap_configuration,
                    trusted_artifacts,
                },
            );
        }
        if entries.is_empty() {
            return Err(DriverCatalogError::InvalidCatalog);
        }
        Ok(Self { entries })
    }

    pub fn resolve(
        &self,
        entry: Option<&str>,
        source: DriverSelectionSource,
        requirement: &DriverRequirement,
    ) -> Result<&TrustedDriverEntry, DriverCatalogError> {
        if source != DriverSelectionSource::TrustedConfiguration {
            return Err(DriverCatalogError::UntrustedSelection);
        }
        let entry = entry.ok_or(DriverCatalogError::UnknownEntry)?;
        let resolved = self
            .entries
            .get(entry)
            .ok_or(DriverCatalogError::UnknownEntry)?;
        if !requirement.is_satisfied_by(resolved.driver_id, &resolved.capabilities) {
            return Err(DriverCatalogError::CapabilityMismatch);
        }
        Ok(resolved)
    }

    pub fn trusted_entry(&self, entry: &str) -> Result<&TrustedDriverEntry, DriverCatalogError> {
        self.entries
            .get(entry)
            .ok_or(DriverCatalogError::UnknownEntry)
    }

    pub fn resolve_requirement(
        &self,
        allowed_entries: Option<&BTreeSet<String>>,
        requirement: &DriverRequirement,
    ) -> Result<&TrustedDriverEntry, DriverCatalogError> {
        let matches = self.entries.iter().filter(|(name, entry)| {
            allowed_entries.is_none_or(|allowed| allowed.contains(*name))
                && entry.driver_id == requirement.driver_id()
        });
        let mut matches = matches.map(|(_, entry)| entry);
        let entry = matches.next().ok_or(DriverCatalogError::UnknownEntry)?;
        if matches.next().is_some() {
            return Err(DriverCatalogError::InvalidCatalog);
        }
        if !requirement.is_satisfied_by(entry.driver_id, &entry.capabilities) {
            return Err(DriverCatalogError::CapabilityMismatch);
        }
        Ok(entry)
    }
}

impl TrustedDriverEntry {
    #[must_use]
    pub fn supervised_config(&self, control_directory: PathBuf) -> SupervisedDriverConfig {
        SupervisedDriverConfig {
            driver_id: self.driver_id,
            program: self.executable.clone(),
            expected_executable_identity: self.executable_identity,
            arguments: self.arguments.clone(),
            working_directory: self.working_directory.clone(),
            environment: self.environment.clone(),
            environment_allowlist: self.environment.keys().cloned().collect(),
            control_directory,
            control_socket_environment: "NAVIGATOR_CONTROL_SOCKET".into(),
            // Starting a trusted driver may include a cold language-runtime startup. Five
            // seconds was short enough for a healthy Node driver to be compensated under
            // concurrent conformance load, after durable launch intent had already been
            // recorded. Keep this bounded, but leave enough room for that cold start.
            connect_timeout: Duration::from_secs(15),
            offered_capabilities: self.capabilities.clone(),
            ownership_channel: match self.ownership_channel {
                OwnershipChannelFile::Stdin => navigator_supervisor::OwnershipChannel::Stdin,
                OwnershipChannelFile::DedicatedFd => {
                    navigator_supervisor::OwnershipChannel::DedicatedFd
                }
            },
            process_io_mode: match self.process_io_mode {
                ProcessIoModeFile::Headless => navigator_supervisor::ProcessIoMode::Headless,
                ProcessIoModeFile::TerminalPty => navigator_supervisor::ProcessIoMode::TerminalPty,
            },
            bootstrap_configuration: self.bootstrap_configuration.clone(),
            trusted_artifacts: self.trusted_artifacts.clone(),
        }
    }

    #[must_use]
    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }
}

fn validate_absolute_file(path: &Path) -> Result<PathBuf, DriverCatalogError> {
    if !path.is_absolute() {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    validate_trusted_file(path)?;
    let canonical = path.canonicalize()?;
    validate_trusted_file(&canonical)?;
    if !canonical.is_file() {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    Ok(canonical)
}

#[cfg(unix)]
fn validate_trusted_directory(path: &Path) -> Result<(), DriverCatalogError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !path.is_absolute() {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    let metadata = std::fs::symlink_metadata(path)?;
    let self_uid = std::fs::metadata(std::env::current_exe()?)?.uid();
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o022 != 0
        || (metadata.uid() != self_uid && metadata.uid() != 0)
    {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_trusted_directory(path: &Path) -> Result<(), DriverCatalogError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !path.is_absolute() || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<[u8; 32], DriverCatalogError> {
    let mut file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_TRUSTED_ARTIFACT_BYTES {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    let mut digest = Sha256::new();
    std::io::copy(&mut file, &mut digest)?;
    Ok(digest.finalize().into())
}

fn trusted_artifacts(
    artifacts: Vec<TrustedArtifactFile>,
) -> Result<Vec<(PathBuf, [u8; 32])>, DriverCatalogError> {
    artifacts
        .into_iter()
        .map(|artifact| {
            let path = validate_absolute_file(&artifact.path)?;
            let digest = parse_digest(&artifact.sha256)?;
            if digest_file(&path)? != digest {
                return Err(DriverCatalogError::InvalidCatalog);
            }
            Ok((path, digest))
        })
        .collect()
}

fn parse_digest(value: &str) -> Result<[u8; 32], DriverCatalogError> {
    let encoded = value.as_bytes();
    if encoded.len() != 64 || !encoded.iter().all(u8::is_ascii_hexdigit) {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let high = hex_nibble(encoded[index * 2]).ok_or(DriverCatalogError::InvalidCatalog)?;
        let low = hex_nibble(encoded[index * 2 + 1]).ok_or(DriverCatalogError::InvalidCatalog)?;
        *byte = (high << 4) | low;
    }
    Ok(digest)
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn invalid_argument(value: &str) -> bool {
    value.len() > MAX_ARGUMENT_BYTES
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
        || credential_like(value)
}

fn credential_like(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    ["SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "API_KEY"]
        .iter()
        .any(|word| upper.contains(word))
}

#[cfg(unix)]
fn validate_trusted_file(path: &Path) -> Result<(), DriverCatalogError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    let self_uid = std::fs::metadata(std::env::current_exe()?)?.uid();
    if metadata.uid() != self_uid && metadata.uid() != 0 {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    let parent = path.parent().ok_or(DriverCatalogError::InvalidCatalog)?;
    let parent_metadata = std::fs::metadata(parent)?;
    if parent_metadata.permissions().mode() & 0o022 != 0
        || (parent_metadata.uid() != self_uid && parent_metadata.uid() != 0)
    {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_trusted_file(path: &Path) -> Result<(), DriverCatalogError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(DriverCatalogError::InvalidCatalog);
    }
    Ok(())
}

fn capability(value: CapabilityFile) -> Result<DriverCapabilityRequirement, DriverCatalogError> {
    let name = Capability::new(value.name).map_err(|_| DriverCatalogError::InvalidCatalog)?;
    let parameters = value
        .parameters
        .into_iter()
        .map(|(key, value)| {
            Ok((
                BoundedText::<MAX_FIELD_NAME_BYTES>::new(key)
                    .map_err(|_| DriverCatalogError::InvalidCatalog)?,
                BoundedText::<MAX_PARAMETER_BYTES>::new(value)
                    .map_err(|_| DriverCatalogError::InvalidCatalog)?,
            ))
        })
        .collect::<Result<Vec<_>, DriverCatalogError>>()?;
    DriverCapabilityRequirement::new(name, value.version, parameters)
        .map_err(|_| DriverCatalogError::InvalidCatalog)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::os::unix::fs::PermissionsExt;

    use navigator_domain::{
        DriverId, DriverRequirement, InputSchema, ResourceBounds, TemplateId, TrustedConfiguration,
    };
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;

    fn requirement(id: DriverId, capability: &str) -> DriverRequirement {
        DriverRequirement::new(
            id,
            vec![
                DriverCapabilityRequirement::new(Capability::new(capability).unwrap(), 1, [])
                    .unwrap(),
            ],
        )
        .unwrap()
    }

    fn registered_template(driver_id: DriverId, capabilities: &[&str]) -> TemplateRecord {
        let requirements = capabilities
            .iter()
            .map(|name| {
                DriverCapabilityRequirement::new(Capability::new(*name).unwrap(), 1, []).unwrap()
            })
            .collect();
        Template::register(
            TemplateId::from_uuid(Uuid::from_u128(91)).unwrap(),
            BoundedText::new("resolver fixture".to_owned()).unwrap(),
            DriverRequirement::new(driver_id, requirements).unwrap(),
            TrustedConfiguration::new(BoundedText::new("trusted".to_owned()).unwrap(), []).unwrap(),
            ResourceBounds::new(1024, 1000, 1).unwrap(),
            InputSchema::new(vec![]).unwrap(),
        )
        .unwrap()
        .registration_snapshot()
    }

    #[test]
    fn per_template_resolver_selects_unique_least_privileged_profile_and_rejects_ties() {
        let (directory, catalog, driver_id) = fixture();
        let base = catalog.entries.values().next().unwrap().clone();
        let mut interactive = base.clone();
        interactive.capabilities.push(
            DriverCapabilityRequirement::new(
                Capability::new("driver.interactive-terminal").unwrap(),
                1,
                [],
            )
            .unwrap(),
        );
        let profiles = TrustedDriverCatalog {
            entries: BTreeMap::from([
                ("headless".to_owned(), base.clone()),
                ("interactive".to_owned(), interactive),
            ]),
        };
        let resolver = CatalogDriverConfigResolver::new(
            profiles.clone(),
            None,
            directory.path().join("control"),
        );
        assert_eq!(
            resolver
                .resolve(&registered_template(driver_id, &["driver.fake"]))
                .unwrap()
                .offered_capabilities
                .len(),
            1
        );
        assert_eq!(
            resolver
                .resolve(&registered_template(
                    driver_id,
                    &["driver.fake", "driver.interactive-terminal"],
                ))
                .unwrap()
                .offered_capabilities
                .len(),
            2
        );
        let ambiguous = CatalogDriverConfigResolver::new(
            TrustedDriverCatalog {
                entries: BTreeMap::from([
                    ("one".to_owned(), base.clone()),
                    ("two".to_owned(), base),
                ]),
            },
            None,
            directory.path().join("control"),
        );
        assert!(
            ambiguous
                .resolve(&registered_template(driver_id, &["driver.fake"]))
                .is_err()
        );
    }

    fn fixture() -> (TempDir, TrustedDriverCatalog, DriverId) {
        let directory = TempDir::new().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable = directory.path().join("fake-driver");
        std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let driver_id = DriverId::from_uuid(Uuid::from_u128(7)).unwrap();
        let catalog_path = directory.path().join("drivers.json");
        let output = directory.path().join("driver-output");
        std::fs::write(
            &executable,
            b"#!/bin/sh\nprintf '%s' \"$2\" > \"$1\"\nsleep 1\n",
        )
        .unwrap();
        let executable_sha256 = digest_file(&executable).unwrap().iter().fold(
            String::with_capacity(64),
            |mut output, byte| {
                write!(output, "{byte:02x}").unwrap();
                output
            },
        );
        let document = serde_json::json!({
            "entries": { "fake": {
                "driver_id": driver_id.to_string(),
                "executable": executable,
                "executable_sha256": executable_sha256,
                "arguments": [output, "; touch should-not-exist"],
                "working_directory": directory.path(),
                "environment": { "SAFE_SETTING": "fixed" },
                "protocol_version": 1,
                "capabilities": [{ "name": "driver.fake", "version": 1 }]
            }}
        });
        std::fs::write(&catalog_path, serde_json::to_vec(&document).unwrap()).unwrap();
        let catalog = TrustedDriverCatalog::from_path(Some(&catalog_path)).unwrap();
        (directory, catalog, driver_id)
    }

    #[test]
    fn fake_driver_resolves_through_trusted_catalog_without_shell_or_inherited_environment() {
        let (directory, catalog, driver_id) = fixture();
        let entry = catalog
            .resolve(
                Some("fake"),
                DriverSelectionSource::TrustedConfiguration,
                &requirement(driver_id, "driver.fake"),
            )
            .unwrap();
        let config = entry.supervised_config(directory.path().join("control"));
        assert_eq!(config.connect_timeout, Duration::from_secs(15));
        assert_eq!(config.arguments[1], "; touch should-not-exist");
        assert_eq!(config.environment.len(), 1);
        assert_eq!(
            config.environment.get(&OsString::from("SAFE_SETTING")),
            Some(&OsString::from("fixed"))
        );
        assert_eq!(entry.protocol_version(), 1);
        assert_eq!(
            config.ownership_channel,
            navigator_supervisor::OwnershipChannel::Stdin
        );
        let debug = format!("{entry:?}");
        assert!(!debug.contains("touch should-not-exist"));
        assert!(!debug.contains("SAFE_SETTING"));
        let config_debug = format!("{config:?}");
        assert!(!config_debug.contains("touch should-not-exist"));
        assert!(!config_debug.contains("SAFE_SETTING"));
        assert!(!directory.path().join("should-not-exist").exists());
    }

    #[test]
    fn ownership_channel_is_closed_trusted_catalog_configuration() {
        let (directory, _, driver_id) = fixture();
        let path = directory.path().join("drivers.json");
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        document["entries"]["fake"]["ownership_channel"] = "dedicated_fd".into();
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        let catalog = TrustedDriverCatalog::from_path(Some(&path)).unwrap();
        let config = catalog
            .resolve(
                Some("fake"),
                DriverSelectionSource::TrustedConfiguration,
                &requirement(driver_id, "driver.fake"),
            )
            .unwrap()
            .supervised_config(directory.path().join("control"));
        assert_eq!(
            config.ownership_channel,
            navigator_supervisor::OwnershipChannel::DedicatedFd
        );
        assert!(format!("{config:?}").contains("DedicatedFd"));

        document["entries"]["fake"]["ownership_channel"] = "model_selected".into();
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(matches!(
            TrustedDriverCatalog::from_path(Some(&path)),
            Err(DriverCatalogError::InvalidCatalog)
        ));
    }

    #[test]
    fn digest_parser_is_byte_safe_and_rejects_unicode_without_panicking() {
        assert_eq!(parse_digest(&"Aa".repeat(32)).unwrap(), [0xaa; 32]);
        for hostile in [
            "€".repeat(21) + "a",
            "😀".repeat(16),
            "é".repeat(32),
            "a".repeat(63),
            "g".repeat(64),
        ] {
            assert!(parse_digest(&hostile).is_err(), "accepted {hostile:?}");
        }
    }

    #[tokio::test]
    async fn resolved_fake_driver_crosses_real_process_boundary_without_shell_expansion() {
        use navigator_domain::{
            FencingEpoch, HostId, InstanceId, LaunchAttemptId, ParticipantId, RequestId, SessionId,
        };
        use navigator_supervisor::{LaunchPlan, ProcessBackend, UnixProcessBackend};

        let (directory, catalog, driver_id) = fixture();
        let entry = catalog
            .resolve(
                Some("fake"),
                DriverSelectionSource::TrustedConfiguration,
                &requirement(driver_id, "driver.fake"),
            )
            .unwrap();
        let config = entry.supervised_config(directory.path().join("control"));
        let id = |value| Uuid::from_u128(value);
        let plan = LaunchPlan {
            session_id: SessionId::from_uuid(id(1)).unwrap(),
            participant_id: ParticipantId::from_uuid(id(2)).unwrap(),
            driver_id,
            driver_configuration_digest: [9; 32],
            attempt_id: LaunchAttemptId::from_uuid(id(3)).unwrap(),
            instance_id: InstanceId::from_uuid(id(4)).unwrap(),
            host_id: HostId::from_uuid(id(5)).unwrap(),
            ownership_epoch: FencingEpoch::new(1).unwrap(),
            prepare_request_id: RequestId::from_uuid(id(6)).unwrap(),
            attach_request_id: RequestId::from_uuid(id(7)).unwrap(),
            compensation_request_id: RequestId::from_uuid(id(8)).unwrap(),
            compensation_terminal_request_id: RequestId::from_uuid(id(9)).unwrap(),
            program: config.program,
            expected_executable_identity: config.expected_executable_identity,
            arguments: config.arguments,
            working_directory: config.working_directory,
            environment: config.environment,
            environment_allowlist: config.environment_allowlist,
            ownership_channel: config.ownership_channel,
            process_io_mode: config.process_io_mode,
            bootstrap_configuration: config.bootstrap_configuration,
        };
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let backend = UnixProcessBackend::new(directory.path().join("credentials")).unwrap();
        backend
            .spawn(&plan, b"scoped-test-credential")
            .await
            .unwrap();
        let output = directory.path().join("driver-output");
        tokio::time::timeout(Duration::from_secs(5), async {
            while std::fs::metadata(&output).map_or(0, |value| value.len()) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(output).unwrap(),
            "; touch should-not-exist"
        );
        assert!(!directory.path().join("should-not-exist").exists());
    }

    #[tokio::test]
    async fn executable_replacement_after_resolution_is_rejected_before_spawn() {
        use navigator_domain::{
            FencingEpoch, HostId, InstanceId, LaunchAttemptId, ParticipantId, RequestId, SessionId,
        };
        use navigator_supervisor::{
            LaunchPlan, ProcessBackend, SupervisorError, UnixProcessBackend,
        };

        let (directory, catalog, driver_id) = fixture();
        let config = catalog
            .resolve_requirement(None, &requirement(driver_id, "driver.fake"))
            .unwrap()
            .supervised_config(directory.path().join("control"));
        std::fs::write(&config.program, b"#!/bin/sh\ntouch replacement-ran\n").unwrap();
        let id = |value| Uuid::from_u128(value);
        let plan = LaunchPlan {
            session_id: SessionId::from_uuid(id(11)).unwrap(),
            participant_id: ParticipantId::from_uuid(id(12)).unwrap(),
            driver_id,
            driver_configuration_digest: [9; 32],
            attempt_id: LaunchAttemptId::from_uuid(id(13)).unwrap(),
            instance_id: InstanceId::from_uuid(id(14)).unwrap(),
            host_id: HostId::from_uuid(id(15)).unwrap(),
            ownership_epoch: FencingEpoch::new(1).unwrap(),
            prepare_request_id: RequestId::from_uuid(id(16)).unwrap(),
            attach_request_id: RequestId::from_uuid(id(17)).unwrap(),
            compensation_request_id: RequestId::from_uuid(id(18)).unwrap(),
            compensation_terminal_request_id: RequestId::from_uuid(id(19)).unwrap(),
            program: config.program,
            expected_executable_identity: config.expected_executable_identity,
            arguments: config.arguments,
            working_directory: config.working_directory,
            environment: config.environment,
            environment_allowlist: config.environment_allowlist,
            ownership_channel: config.ownership_channel,
            process_io_mode: config.process_io_mode,
            bootstrap_configuration: config.bootstrap_configuration,
        };
        let backend = UnixProcessBackend::new(directory.path().join("credentials")).unwrap();
        assert!(matches!(
            backend.spawn(&plan, b"credential").await,
            Err(SupervisorError::IdentityMismatch)
        ));
        assert!(!directory.path().join("replacement-ran").exists());
        assert!(
            !directory
                .path()
                .join("credentials")
                .join(format!("{}.credential", plan.attempt_id))
                .exists()
        );
    }

    #[test]
    fn trusted_artifact_digest_mismatch_is_rejected_before_selection() {
        let (directory, _, _) = fixture();
        let path = directory.path().join("drivers.json");
        let mut document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let artifact = directory.path().join("adapter.js");
        std::fs::write(&artifact, b"trusted adapter").unwrap();
        document["entries"]["fake"]["trusted_artifacts"] = serde_json::json!([{
            "path": artifact,
            "sha256": "00".repeat(32),
        }]);
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(matches!(
            TrustedDriverCatalog::from_path(Some(&path)),
            Err(DriverCatalogError::InvalidCatalog)
        ));
        assert!(!directory.path().join("driver-output").exists());
    }

    #[test]
    fn missing_unknown_untrusted_and_capability_mismatch_fail_before_process_launch() {
        assert!(matches!(
            TrustedDriverCatalog::from_path(None),
            Err(DriverCatalogError::MissingCatalog)
        ));
        let (directory, catalog, driver_id) = fixture();
        let valid = requirement(driver_id, "driver.fake");
        assert!(matches!(
            catalog.resolve(None, DriverSelectionSource::TrustedConfiguration, &valid),
            Err(DriverCatalogError::UnknownEntry)
        ));
        assert!(matches!(
            catalog.resolve(
                Some("missing"),
                DriverSelectionSource::TrustedConfiguration,
                &valid
            ),
            Err(DriverCatalogError::UnknownEntry)
        ));
        assert!(matches!(
            catalog.resolve(
                Some("fake"),
                DriverSelectionSource::UntrustedTaskInput,
                &valid
            ),
            Err(DriverCatalogError::UntrustedSelection)
        ));
        assert!(matches!(
            catalog.resolve(
                Some("fake"),
                DriverSelectionSource::TrustedConfiguration,
                &requirement(driver_id, "driver.missing")
            ),
            Err(DriverCatalogError::CapabilityMismatch)
        ));
        assert!(!directory.path().join("should-not-exist").exists());
    }

    #[test]
    fn catalog_bounds_accept_maximum_and_reject_max_plus_one_before_allocation_growth() {
        let (directory, _, _) = fixture();
        let path = directory.path().join("drivers.json");
        let base: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for (field, maximum) in [
            ("arguments", MAX_ARGUMENTS),
            ("environment", MAX_ENVIRONMENT),
        ] {
            let mut document = base.clone();
            if field == "arguments" {
                document["entries"]["fake"][field] = serde_json::Value::Array(
                    (0..maximum)
                        .map(|_| serde_json::Value::String("safe".into()))
                        .collect(),
                );
            } else {
                document["entries"]["fake"][field] = serde_json::Value::Object(
                    (0..maximum)
                        .map(|index| {
                            (
                                format!("SAFE_{index}"),
                                serde_json::Value::String("value".into()),
                            )
                        })
                        .collect(),
                );
            }
            std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
            assert!(TrustedDriverCatalog::from_path(Some(&path)).is_ok());
            if field == "arguments" {
                document["entries"]["fake"][field]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::Value::String("extra".into()));
            } else {
                document["entries"]["fake"][field]
                    .as_object_mut()
                    .unwrap()
                    .insert(
                        "SAFE_EXTRA".into(),
                        serde_json::Value::String("value".into()),
                    );
            }
            std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
            assert!(matches!(
                TrustedDriverCatalog::from_path(Some(&path)),
                Err(DriverCatalogError::InvalidCatalog)
            ));
        }
        let mut capabilities = base.clone();
        capabilities["entries"]["fake"]["capabilities"] = serde_json::Value::Array(
            (0..navigator_domain::MAX_DRIVER_CAPABILITIES)
                .map(|index| serde_json::json!({"name":format!("driver.capability.{index}"),"version":1}))
                .collect(),
        );
        std::fs::write(&path, serde_json::to_vec(&capabilities).unwrap()).unwrap();
        assert!(TrustedDriverCatalog::from_path(Some(&path)).is_ok());
        capabilities["entries"]["fake"]["capabilities"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"name":"driver.capability.extra","version":1}));
        std::fs::write(&path, serde_json::to_vec(&capabilities).unwrap()).unwrap();
        assert!(TrustedDriverCatalog::from_path(Some(&path)).is_err());

        let template_entry = base["entries"]["fake"].clone();
        let entries = (0..MAX_CATALOG_ENTRIES)
            .map(|index| {
                let mut entry = template_entry.clone();
                entry["driver_id"] =
                    serde_json::Value::String(Uuid::from_u128(10_000 + index as u128).to_string());
                (format!("fake-{index}"), entry)
            })
            .collect::<serde_json::Map<_, _>>();
        let mut entry_document = serde_json::json!({"entries":entries});
        std::fs::write(&path, serde_json::to_vec(&entry_document).unwrap()).unwrap();
        assert!(TrustedDriverCatalog::from_path(Some(&path)).is_ok());
        entry_document["entries"]
            .as_object_mut()
            .unwrap()
            .insert("fake-extra".into(), template_entry);
        std::fs::write(&path, serde_json::to_vec(&entry_document).unwrap()).unwrap();
        assert!(TrustedDriverCatalog::from_path(Some(&path)).is_err());
        std::fs::write(&path, vec![b' '; MAX_CATALOG_BYTES + 1]).unwrap();
        assert!(matches!(
            TrustedDriverCatalog::from_path(Some(&path)),
            Err(DriverCatalogError::InvalidCatalog)
        ));
    }

    #[test]
    fn unsafe_permissions_symlinks_reserved_environment_and_secret_arguments_are_rejected() {
        use std::os::unix::fs::symlink;
        let (directory, _, _) = fixture();
        let path = directory.path().join("drivers.json");
        let original = std::fs::read(&path).unwrap();
        let mut document: serde_json::Value = serde_json::from_slice(&original).unwrap();
        document["entries"]["fake"]["environment"] =
            serde_json::json!({"NAVIGATOR_CREDENTIAL_FILE":"stolen"});
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(TrustedDriverCatalog::from_path(Some(&path)).is_err());
        document = serde_json::from_slice(&original).unwrap();
        document["entries"]["fake"]["arguments"] = serde_json::json!(["--api-key=secret"]);
        std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert!(TrustedDriverCatalog::from_path(Some(&path)).is_err());
        std::fs::write(&path, &original).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(TrustedDriverCatalog::from_path(Some(&path)).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("catalog-link.json");
        symlink(&path, &link).unwrap();
        assert!(TrustedDriverCatalog::from_path(Some(&link)).is_err());
        let executable = directory.path().join("fake-driver");
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(TrustedDriverCatalog::from_path(Some(&path)).is_err());
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable_link = directory.path().join("fake-driver-link");
        symlink(&executable, &executable_link).unwrap();
        let mut linked: serde_json::Value = serde_json::from_slice(&original).unwrap();
        linked["entries"]["fake"]["executable"] =
            serde_json::Value::String(executable_link.to_string_lossy().into_owned());
        std::fs::write(&path, serde_json::to_vec(&linked).unwrap()).unwrap();
        assert!(TrustedDriverCatalog::from_path(Some(&path)).is_err());
    }
}
