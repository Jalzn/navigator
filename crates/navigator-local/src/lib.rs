//! Authenticated local Consumer service over Unix domain sockets.

mod artifact_store;
mod background_tasks;
mod client;
mod configured_runtime;
mod fault_matrix;
pub use artifact_store::{ArtifactWrite, LocalArtifactError, LocalArtifactStore};
mod driver_catalog;
mod driver_executor;
mod recovery_backend;
mod service;
mod shutdown;
mod tool_broker;
mod trusted_tool_catalog;

pub use background_tasks::{
    BackgroundShutdownOutcome, BackgroundTaskClosed, BackgroundTaskRegistry,
};
pub use client::{ClientError, LocalClient, SessionManifestSpecification};
pub use configured_runtime::{
    ConfiguredRuntimeComponents, ConfiguredRuntimeError, ConfiguredRuntimeSettings,
    build_catalog_operation_controller, build_catalog_runtime_components,
    build_catalog_runtime_components_with_settings,
    build_catalog_runtime_components_with_settings_and_shutdown_observer,
};
pub use driver_catalog::{
    CatalogDriverConfigResolver, DriverCatalogError, DriverSelectionSource, TrustedDriverCatalog,
    TrustedDriverEntry,
};
pub use driver_executor::{
    ApprovalCommandSink, ApprovalSinkInstaller, AuthenticatedApprovalRequest, AuthenticatedDriver,
    BoundedSessionMailboxDispatcher, DriverConfigResolver, DriverDeliveryContexts,
    DriverTransitionContexts, ExistingOperationScheduler, FirstOperationScheduler,
    HierarchyCommandSink, HierarchySinkInstaller, LocalApprovalSink, LocalHierarchySink,
    MailboxBackedOperationExecutor, MailboxFirstOperationScheduler, PermitOnlyMailboxScheduler,
    SessionAdmissionProvider, SessionMailboxDispatcher, SessionScopedExistingScheduler,
    ShutdownAttemptEvidence, ShutdownAttemptOutcome, ShutdownObserver, SupervisedDriverConfig,
    SupervisedDriverExecutor, SupervisedMailboxWorker, ToolCommandSink, ToolSinkInstaller,
    TrustedToolCatalog, TrustedToolCatalogInstaller, TrustedToolCatalogProvider,
    resolved_launch_attempt_for_config,
};
pub use recovery_backend::{
    RecoveryInstanceInspector, RecoveryOwnershipInstaller, StoreRecoveryBackend,
};
pub use service::{
    AUTHENTICATION_HEADER, ArtifactControlError, ArtifactController, AuthorizedResolutionStore,
    BootstrapCredential, CommittedAuthorizedResolution, LocalError, LocalNavigator,
    LocalRecoveryController, MAX_SUBSCRIPTIONS, OperationControlError, OperationController,
    RecoveryController, ServerConfig, StoreAuthorizedResolution, UnverifiedRecoveryAuthorityClaim,
    current_metadata, load_or_create_host_id, serve, validate_socket_directory,
};
pub use tool_broker::{LocalToolBroker, ToolBrokerControl, ToolProviderResponseStream};
pub use trusted_tool_catalog::StoreTrustedToolCatalog;
