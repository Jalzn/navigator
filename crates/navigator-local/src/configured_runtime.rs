use std::{
    collections::BTreeSet, fs, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc,
    time::Duration,
};

use navigator_core::{FirstOperationConfig, FirstOperationService};
use navigator_domain::HostId;
use navigator_store_sqlite::SqliteStore;
use navigator_supervisor::{
    InstanceSupervisor, OsCredentialSource, SupervisorConfig, SupervisorError, UnixProcessBackend,
};
use thiserror::Error;

use crate::{
    ApprovalSinkInstaller, BoundedSessionMailboxDispatcher, CatalogDriverConfigResolver,
    DriverTransitionContexts, ExistingOperationScheduler, HierarchySinkInstaller,
    MailboxBackedOperationExecutor, OperationController, PermitOnlyMailboxScheduler,
    RecoveryInstanceInspector, SessionMailboxDispatcher, ShutdownObserver, StoreTrustedToolCatalog,
    SupervisedDriverExecutor, ToolSinkInstaller, TrustedDriverCatalog,
};

#[derive(Debug, Error)]
pub enum ConfiguredRuntimeError {
    #[error("configured Driver runtime settings are invalid")]
    InvalidSettings,
    #[error("configured Driver runtime could not be prepared")]
    Io(#[from] std::io::Error),
    #[error("configured Driver supervisor could not be prepared")]
    Supervisor(#[from] SupervisorError),
}

pub struct ConfiguredRuntimeComponents {
    pub controller: Arc<dyn OperationController>,
    pub permit_scheduler: Arc<dyn ExistingOperationScheduler>,
    pub hierarchy_installer: Arc<dyn HierarchySinkInstaller>,
    pub approval_installer: Arc<dyn ApprovalSinkInstaller>,
    pub tool_installer: Arc<dyn ToolSinkInstaller>,
    pub mailbox_dispatcher: Arc<dyn SessionMailboxDispatcher>,
    pub process_backend: Arc<UnixProcessBackend>,
    pub recovery_inspector: Arc<dyn RecoveryInstanceInspector>,
    pub configuration_identity: [u8; 32],
}

#[derive(Clone, Copy, Debug)]
pub struct ConfiguredRuntimeSettings {
    operation_capacity: usize,
    report_deadline: Duration,
    mailbox_lease: Duration,
    driver_call_timeout: Duration,
    delivery_budget: Duration,
}

impl Default for ConfiguredRuntimeSettings {
    fn default() -> Self {
        Self {
            operation_capacity: 4,
            report_deadline: Duration::from_secs(90),
            mailbox_lease: Duration::from_secs(10),
            driver_call_timeout: Duration::from_secs(5),
            delivery_budget: Duration::from_secs(30),
        }
    }
}

impl ConfiguredRuntimeSettings {
    pub fn new(
        operation_capacity: usize,
        report_deadline: Duration,
    ) -> Result<Self, ConfiguredRuntimeError> {
        if !(1..=4_096).contains(&operation_capacity)
            || report_deadline.is_zero()
            || report_deadline > Duration::from_secs(86_400)
        {
            return Err(ConfiguredRuntimeError::InvalidSettings);
        }
        Ok(Self {
            operation_capacity,
            report_deadline,
            ..Self::default()
        })
    }

    pub fn with_delivery_budgets(
        mut self,
        mailbox_lease: Duration,
        driver_call_timeout: Duration,
        delivery_budget: Duration,
    ) -> Result<Self, ConfiguredRuntimeError> {
        if driver_call_timeout.is_zero()
            || driver_call_timeout >= mailbox_lease
            || delivery_budget < driver_call_timeout
            || delivery_budget > Duration::from_secs(86_400)
        {
            return Err(ConfiguredRuntimeError::InvalidSettings);
        }
        self.mailbox_lease = mailbox_lease;
        self.driver_call_timeout = driver_call_timeout;
        self.delivery_budget = delivery_budget;
        Ok(self)
    }

    #[must_use]
    pub fn operation_capacity(self) -> usize {
        self.operation_capacity
    }

    #[must_use]
    pub fn report_deadline(self) -> Duration {
        self.report_deadline
    }
}

pub fn build_catalog_operation_controller(
    store: Arc<SqliteStore>,
    host_id: HostId,
    catalog: TrustedDriverCatalog,
    allowed_profiles: BTreeSet<String>,
    runtime_root: PathBuf,
) -> Result<Arc<dyn OperationController>, ConfiguredRuntimeError> {
    Ok(
        build_catalog_runtime_components(store, host_id, catalog, allowed_profiles, runtime_root)?
            .controller,
    )
}

pub fn build_catalog_runtime_components(
    store: Arc<SqliteStore>,
    host_id: HostId,
    catalog: TrustedDriverCatalog,
    allowed_profiles: BTreeSet<String>,
    runtime_root: PathBuf,
) -> Result<ConfiguredRuntimeComponents, ConfiguredRuntimeError> {
    build_catalog_runtime_components_with_settings(
        store,
        host_id,
        catalog,
        allowed_profiles,
        runtime_root,
        ConfiguredRuntimeSettings::default(),
    )
}

pub fn build_catalog_runtime_components_with_settings(
    store: Arc<SqliteStore>,
    host_id: HostId,
    catalog: TrustedDriverCatalog,
    allowed_profiles: BTreeSet<String>,
    runtime_root: PathBuf,
    settings: ConfiguredRuntimeSettings,
) -> Result<ConfiguredRuntimeComponents, ConfiguredRuntimeError> {
    build_catalog_runtime_components_with_settings_and_shutdown_observer(
        store,
        host_id,
        catalog,
        allowed_profiles,
        runtime_root,
        settings,
        None,
    )
}

pub fn build_catalog_runtime_components_with_settings_and_shutdown_observer(
    store: Arc<SqliteStore>,
    host_id: HostId,
    catalog: TrustedDriverCatalog,
    allowed_profiles: BTreeSet<String>,
    runtime_root: PathBuf,
    settings: ConfiguredRuntimeSettings,
    shutdown_observer: Option<Arc<dyn ShutdownObserver>>,
) -> Result<ConfiguredRuntimeComponents, ConfiguredRuntimeError> {
    let configuration_identity = catalog.configuration_identity(&allowed_profiles);
    match fs::create_dir(&runtime_root) {
        Ok(()) => fs::set_permissions(&runtime_root, fs::Permissions::from_mode(0o700))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let backend = Arc::new(UnixProcessBackend::new(runtime_root.join("credentials"))?);
    let supervisor = Arc::new(InstanceSupervisor::new(
        store.clone(),
        backend.clone(),
        OsCredentialSource,
        SupervisorConfig {
            graceful_timeout: Duration::from_secs(2),
            forced_timeout: Duration::from_secs(2),
            ownership_loss_timeout: Duration::from_secs(5),
        },
    ));
    let recovery_inspector: Arc<dyn RecoveryInstanceInspector> = supervisor.clone();
    let resolver = Arc::new(CatalogDriverConfigResolver::new(
        catalog,
        Some(allowed_profiles),
        runtime_root,
    ));
    let driver_executor =
        SupervisedDriverExecutor::new_with_resolver(store.clone(), supervisor, host_id, resolver);
    let driver_executor = match shutdown_observer {
        Some(observer) => driver_executor.with_shutdown_observer(observer),
        None => driver_executor,
    };
    let driver_executor = Arc::new(driver_executor);
    driver_executor
        .install_trusted_tool_catalog(Arc::new(StoreTrustedToolCatalog::new(store.clone())))
        .map_err(|_| ConfiguredRuntimeError::InvalidSettings)?;
    let operation_executor = Arc::new(MailboxBackedOperationExecutor::new(
        store.clone(),
        driver_executor.clone(),
        host_id,
        settings.mailbox_lease,
        Duration::from_millis(50),
        settings.driver_call_timeout,
        settings.delivery_budget,
        128,
    )?);
    let mailbox_dispatcher: Arc<dyn SessionMailboxDispatcher> =
        Arc::new(BoundedSessionMailboxDispatcher::new(
            Arc::clone(&store),
            Arc::clone(&operation_executor),
            32,
        ));
    let service = Arc::new(FirstOperationService::new(
        store,
        operation_executor.clone(),
        Arc::new(DriverTransitionContexts { host_id }),
        settings.operation_capacity,
        FirstOperationConfig {
            capacity_wait: Duration::from_secs(2),
            // This is the absolute bound for a whole Driver operation, including
            // bounded child launches and their causally-routed outcomes. It is
            // deliberately not refreshed by hierarchy progress.
            report_deadline: settings.report_deadline,
        },
    ));
    let controller: Arc<dyn OperationController> = service.clone();
    let permit_scheduler: Arc<dyn ExistingOperationScheduler> =
        Arc::new(PermitOnlyMailboxScheduler::new(service, operation_executor));
    let hierarchy_installer: Arc<dyn HierarchySinkInstaller> = driver_executor.clone();
    let approval_installer: Arc<dyn ApprovalSinkInstaller> = driver_executor.clone();
    let tool_installer: Arc<dyn ToolSinkInstaller> = driver_executor;
    Ok(ConfiguredRuntimeComponents {
        controller,
        permit_scheduler,
        hierarchy_installer,
        approval_installer,
        tool_installer,
        mailbox_dispatcher,
        process_backend: backend,
        recovery_inspector,
        configuration_identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_runtime_settings_preserve_the_bounded_production_budget() {
        let settings = ConfiguredRuntimeSettings::default();
        assert_eq!(settings.operation_capacity(), 4);
        assert_eq!(settings.report_deadline(), Duration::from_secs(90));
    }

    #[test]
    fn invalid_runtime_settings_fail_before_a_runtime_can_be_built() {
        for invalid in [
            ConfiguredRuntimeSettings::new(0, Duration::from_secs(1)),
            ConfiguredRuntimeSettings::new(4_097, Duration::from_secs(1)),
            ConfiguredRuntimeSettings::new(1, Duration::ZERO),
            ConfiguredRuntimeSettings::new(1, Duration::from_secs(86_401)),
        ] {
            assert!(matches!(
                invalid,
                Err(ConfiguredRuntimeError::InvalidSettings)
            ));
        }
    }
}
