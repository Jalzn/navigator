use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsString,
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use navigator_core::{
    AcceptanceObservation, AdmissionGate, AdmissionPermit, AuthenticatedHierarchyCaller,
    ChildStatusRequest, DeliveryAcceptance, DeliveryContextFactory, DeliveryDriverError,
    DeliveryLoop, DeliveryLoopError, DeliveryPhase, DeliveryStep, ExecutorError, ExecutorReport,
    ExecutorTerminalOutcome, FirstOperationService, HierarchyService, MailboxDriver,
    OperationExecutor, SpawnChildRequest, TransitionContextFactory,
};
use navigator_domain::{
    ApprovalResource, ApprovalStatus, ApprovalSummary, Capability, DeliveryAttemptId,
    DriverCapabilityRequirement, DriverId, FencingEpoch, HostId, InstanceId, LaunchAttemptId,
    LiveObservation, MessageBody, MessageId, OperationAction, OperationId, OwnershipSnapshot,
    ParticipantId, RequestId, SemanticDigest, SessionId, Template, Timestamp,
    ValidatedMessageEnvelope,
};
use navigator_driver_client::{ClientError, DriverClient, Observation};
use navigator_driver_protocol::{ToolCorrelationDisposition, ToolCorrelationGuard, v1};
use navigator_store_api::{
    ApprovalStore, AuthorityStore, AuthorizedChildOutcome, DeliveryLease, HierarchyStore,
    InstanceStore, LaunchSnapshot, LaunchState, MailboxStore, MessageDeliveryState,
    MessageSnapshot, Mutation, OperationSnapshot, OperationStore, RequestApproval, RequestContext,
    StoreError, TemplateRecord,
};
use navigator_supervisor::{
    CredentialSource, DriverBootstrapRequest, InstanceSupervisor, LaunchPlan, LifecycleFence,
    NoFaults, ReconcileRequestIds, StopRequestIds, UnixProcessBackend,
};
use sha2::{Digest, Sha256};
use tokio::task::spawn_blocking;
use uuid::Uuid;

pub struct DriverDeliveryContexts {
    host_id: HostId,
    seed: [u8; 16],
    sequence: std::sync::atomic::AtomicU64,
}

impl DriverDeliveryContexts {
    pub fn new(host_id: HostId) -> Result<Self, std::io::Error> {
        use std::io::Read;
        let mut seed = [0_u8; 16];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
        Ok(Self {
            host_id,
            seed,
            sequence: std::sync::atomic::AtomicU64::new(0),
        })
    }

    fn next_uuid(&self, domain: &[u8], extra: &[u8]) -> Uuid {
        use std::sync::atomic::Ordering;
        let mut digest = Sha256::new();
        digest.update(domain);
        digest.update(self.seed);
        digest.update(self.sequence.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        digest.update(extra);
        let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().expect("fixed digest");
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Uuid::from_bytes(bytes)
    }
}

impl DeliveryContextFactory for DriverDeliveryContexts {
    fn context(&self, message_id: Option<MessageId>, phase: DeliveryPhase) -> RequestContext {
        let mut extra = vec![phase as u8];
        if let Some(message_id) = message_id {
            extra.extend_from_slice(message_id.as_uuid().as_bytes());
        }
        RequestContext::new(
            RequestId::from_uuid(self.next_uuid(b"navigator.mailbox.command.v1", &extra))
                .expect("derived request is non-nil"),
            self.host_id,
        )
    }

    fn attempt_id(&self, destination: ParticipantId) -> DeliveryAttemptId {
        DeliveryAttemptId::from_uuid(self.next_uuid(
            b"navigator.mailbox.attempt.v1",
            destination.as_uuid().as_bytes(),
        ))
        .expect("derived attempt is non-nil")
    }
}

pub struct SupervisedMailboxWorker<S, C> {
    delivery: DeliveryLoop<S, SupervisedDriverExecutor<S, C>, DriverDeliveryContexts>,
}

pub struct MailboxBackedOperationExecutor<S, C> {
    store: Arc<S>,
    inner: Arc<SupervisedDriverExecutor<S, C>>,
    worker: SupervisedMailboxWorker<S, C>,
    max_delivery_steps: usize,
    delivery_budget: Duration,
}

impl<S, C> MailboxBackedOperationExecutor<S, C>
where
    S: MailboxStore + InstanceStore + OperationStore + HierarchyStore + ApprovalStore + 'static,
    C: CredentialSource + Sync,
{
    #[expect(
        clippy::too_many_arguments,
        reason = "delivery safety budgets are explicit"
    )]
    pub fn new(
        store: Arc<S>,
        inner: Arc<SupervisedDriverExecutor<S, C>>,
        host_id: HostId,
        lease_duration: Duration,
        retry_backoff: Duration,
        driver_call_timeout: Duration,
        delivery_budget: Duration,
        max_delivery_steps: usize,
    ) -> Result<Self, std::io::Error> {
        let worker = SupervisedMailboxWorker::new(
            store.clone(),
            inner.clone(),
            host_id,
            lease_duration,
            retry_backoff,
            driver_call_timeout,
        )?;
        Ok(Self {
            store,
            inner,
            worker,
            max_delivery_steps: max_delivery_steps.clamp(1, 4_096),
            delivery_budget,
        })
    }

    pub async fn dispatch_message(
        &self,
        permit: &AdmissionPermit,
        operation_id: OperationId,
        message_id: MessageId,
        epoch: FencingEpoch,
    ) -> Result<(), ExecutorError> {
        let operation = self
            .store
            .load_operation(operation_id)
            .await
            .map_err(executor_error)?;
        let instance = self.inner.ensure_operation_ready(&operation).await?;
        let instance_id = domain_id(&instance.identity.instance_id, InstanceId::from_uuid)?;
        let launch_attempt_id = domain_id(
            &instance.identity.launch_attempt_id,
            LaunchAttemptId::from_uuid,
        )?;
        let deadline = tokio::time::Instant::now() + self.delivery_budget;
        for _ in 0..self.max_delivery_steps {
            permit.check().map_err(executor_error)?;
            match self
                .worker
                .drive_once(
                    permit,
                    operation.session_id,
                    epoch,
                    operation.participant_id,
                    instance_id,
                    launch_attempt_id,
                )
                .await
                .map_err(executor_error)?
            {
                DeliveryStep::Accepted(id) if id == message_id => return Ok(()),
                DeliveryStep::DeadLetter(id) | DeliveryStep::Uncertain(id) if id == message_id => {
                    return Err(boundary_error());
                }
                _ if tokio::time::Instant::now() >= deadline => return Err(boundary_error()),
                _ => tokio::task::yield_now().await,
            }
        }
        Err(boundary_error())
    }

    async fn accepted_causal_message(
        &self,
        operation: &OperationSnapshot,
        operation_id: OperationId,
        message_id: MessageId,
        delivery_attempt_id: DeliveryAttemptId,
        instance: &AuthenticatedDriver,
    ) -> Result<(), ExecutorError> {
        let deadline = tokio::time::Instant::now() + self.delivery_budget;
        loop {
            let message = self
                .store
                .load_message(message_id)
                .await
                .map_err(executor_error)?;
            if operation_id != operation.operation_id
                || message.session_id != operation.session_id
                || message.destination != operation.participant_id
                || message.correlation.operation_id != Some(operation.operation_id)
            {
                return Err(boundary_error());
            }
            let epoch =
                FencingEpoch::new(instance.identity.ownership_epoch).map_err(executor_error)?;
            self.store
                .validate_launch_authority(operation.session_id, self.inner.host_id, epoch)
                .await
                .map_err(executor_error)?;
            match causal_acceptance_state(
                &message.state,
                delivery_attempt_id,
                self.inner.host_id,
                &instance.identity,
                current_timestamp()?,
            ) {
                CausalAcceptanceState::Accepted => return Ok(()),
                CausalAcceptanceState::Pending if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                _ => return Err(boundary_error()),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CausalAcceptanceState {
    Accepted,
    Pending,
    Rejected,
}

fn causal_acceptance_state(
    state: &MessageDeliveryState,
    report_attempt: DeliveryAttemptId,
    host_id: HostId,
    identity: &v1::InstanceIdentity,
    now: Timestamp,
) -> CausalAcceptanceState {
    match state {
        MessageDeliveryState::Accepted { attempt_id, .. } if *attempt_id == report_attempt => {
            CausalAcceptanceState::Accepted
        }
        MessageDeliveryState::AcceptancePending { lease }
            if lease.attempt_id == report_attempt
                && lease.owner == host_id
                && lease.ownership_epoch.get() == identity.ownership_epoch
                && lease.driver_ownership_epoch.get() == identity.ownership_epoch
                && identity.launch_attempt_id
                    == lease.driver_launch_attempt_id.as_uuid().as_bytes()
                && identity.instance_id == lease.instance_id.as_uuid().as_bytes()
                && now < lease.expires_at =>
        {
            CausalAcceptanceState::Pending
        }
        _ => CausalAcceptanceState::Rejected,
    }
}

fn current_timestamp() -> Result<Timestamp, ExecutorError> {
    let now = time::OffsetDateTime::now_utc();
    Timestamp::new(now.unix_timestamp(), now.nanosecond()).map_err(executor_error)
}

impl<S, C> SupervisedMailboxWorker<S, C>
where
    S: MailboxStore + InstanceStore + OperationStore + HierarchyStore + ApprovalStore + 'static,
    C: CredentialSource + Sync,
{
    pub fn new(
        store: Arc<S>,
        executor: Arc<SupervisedDriverExecutor<S, C>>,
        host_id: HostId,
        lease_duration: Duration,
        retry_backoff: Duration,
        driver_call_timeout: Duration,
    ) -> Result<Self, std::io::Error> {
        Ok(Self {
            delivery: DeliveryLoop::new(
                store,
                executor,
                Arc::new(DriverDeliveryContexts::new(host_id)?),
                lease_duration,
                retry_backoff,
                driver_call_timeout,
            )
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?,
        })
    }

    pub async fn drive_once(
        &self,
        permit: &AdmissionPermit,
        session_id: SessionId,
        epoch: FencingEpoch,
        destination: ParticipantId,
        instance_id: InstanceId,
        driver_launch_attempt_id: LaunchAttemptId,
    ) -> Result<DeliveryStep, DeliveryLoopError> {
        self.delivery
            .drive_once(
                permit,
                session_id,
                epoch,
                destination,
                instance_id,
                driver_launch_attempt_id,
            )
            .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "exact Driver binding is explicit"
    )]
    pub async fn drive_until_idle(
        &self,
        permit: &AdmissionPermit,
        session_id: SessionId,
        epoch: FencingEpoch,
        destination: ParticipantId,
        instance_id: InstanceId,
        driver_launch_attempt_id: LaunchAttemptId,
        max_steps: usize,
    ) -> Result<Vec<DeliveryStep>, DeliveryLoopError> {
        let mut steps = Vec::with_capacity(max_steps.min(64));
        for _ in 0..max_steps.min(4_096) {
            permit.check()?;
            let step = self
                .drive_once(
                    permit,
                    session_id,
                    epoch,
                    destination,
                    instance_id,
                    driver_launch_attempt_id,
                )
                .await?;
            steps.push(step);
            if step == DeliveryStep::Empty {
                break;
            }
        }
        Ok(steps)
    }
}

pub(crate) struct DriverExecutor {
    channels: Arc<RwLock<Arc<DriverChannels>>>,
    identity: v1::InstanceIdentity,
    sequence: Arc<Mutex<u64>>,
    pending_report: Arc<Mutex<Option<PendingReport>>>,
    control_socket: ControlSocketEvidence,
    watchdog: tokio::sync::Mutex<
        Option<
            tokio::task::JoinHandle<
                Result<navigator_supervisor::StopOutcome, navigator_supervisor::SupervisorError>,
            >,
        >,
    >,
    hierarchy_sink: Option<Arc<dyn HierarchyCommandSink>>,
    tool_sink: Option<Arc<dyn ToolCommandSink>>,
    tool_correlations: Arc<Mutex<ToolRuntimeCorrelations>>,
    host_id: HostId,
    config_identity: [u8; 32],
    stopping: Arc<LifecycleFence>,
}

struct DriverChannels {
    control: Arc<Mutex<DriverClient>>,
    observe: Arc<Mutex<DriverClient>>,
}

struct CloseLifecycleOnDrop(Arc<LifecycleFence>);

impl Drop for CloseLifecycleOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

fn publish_if_current<T>(
    registry: &RwLock<Arc<T>>,
    origin: &Arc<T>,
    replacement: Arc<T>,
    lifecycle: &LifecycleFence,
) -> Result<bool, ExecutorError> {
    lifecycle
        .while_open(|| {
            let mut current = registry.write().map_err(|_| boundary_error())?;
            if !Arc::ptr_eq(&current, origin) {
                return Ok(false);
            }
            *current = replacement;
            Ok(true)
        })
        .unwrap_or(Ok(false))
}

fn valid_reconnect_inspection(state: i32, last_sequence: u64, after: u64) -> bool {
    v1::InstanceState::try_from(state) == Ok(v1::InstanceState::Ready) && last_sequence >= after
}

struct SupervisedDriverMetadata {
    hierarchy_sink: Option<Arc<dyn HierarchyCommandSink>>,
    tool_sink: Option<Arc<dyn ToolCommandSink>>,
    host_id: HostId,
    config_identity: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct TrustedToolCatalog {
    entries: serde_json::Value,
    identity: [u8; 32],
}
impl TrustedToolCatalog {
    pub fn new(entries: serde_json::Value) -> Result<Self, ExecutorError> {
        Self::new_with_identity(entries, None)
    }

    pub(crate) fn new_bound(
        entries: serde_json::Value,
        binding: &serde_json::Value,
    ) -> Result<Self, ExecutorError> {
        Self::new_with_identity(entries, Some(binding))
    }

    fn new_with_identity(
        entries: serde_json::Value,
        binding: Option<&serde_json::Value>,
    ) -> Result<Self, ExecutorError> {
        let Some(array) = entries.as_array() else {
            return Err(boundary_error_at("driver.tool_catalog.invalid"));
        };
        if array.len() > 64 {
            return Err(boundary_error_at("driver.tool_catalog.capacity"));
        }
        for entry in array {
            validate_trusted_tool_entry(entry)?;
        }
        let identity_value = serde_json::json!({
            "binding": binding,
            "entries": entries.clone(),
        });
        let bytes = serde_json::to_vec(&identity_value).map_err(executor_error)?;
        let digest = SemanticDigest::v1(
            &Capability::new("driver.trusted_tool_catalog.v1").expect("static"),
            &bytes,
        );
        Ok(Self {
            entries,
            identity: *digest.as_bytes(),
        })
    }

    #[must_use]
    pub(crate) const fn identity(&self) -> [u8; 32] {
        self.identity
    }
}

fn validate_trusted_tool_entry(entry: &serde_json::Value) -> Result<(), ExecutorError> {
    let object = entry
        .as_object()
        .ok_or_else(|| boundary_error_at("driver.tool_catalog.entry.invalid"))?;
    if object.len() != 4
        || !object.contains_key("registration_id")
        || !object.contains_key("name")
        || !object.contains_key("version")
        || !object.contains_key("input_schema")
    {
        return Err(boundary_error_at("driver.tool_catalog.entry.invalid"));
    }
    let registration = object
        .get("registration_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| boundary_error_at("driver.tool_catalog.registration.invalid"))?;
    let parsed = Uuid::parse_str(registration)
        .map_err(|_| boundary_error_at("driver.tool_catalog.registration.invalid"))?;
    if parsed.is_nil() || registration.len() != 32 {
        return Err(boundary_error_at(
            "driver.tool_catalog.registration.invalid",
        ));
    }
    for (field, maximum) in [("name", 128), ("version", 64)] {
        let value = object
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| boundary_error_at("driver.tool_catalog.identifier.invalid"))?;
        if value.is_empty()
            || value.len() > maximum
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || value.starts_with(['.', '-', '_'])
            || value.ends_with(['.', '-', '_'])
        {
            return Err(boundary_error_at("driver.tool_catalog.identifier.invalid"));
        }
    }
    if !object
        .get("input_schema")
        .is_some_and(serde_json::Value::is_object)
    {
        return Err(boundary_error_at("driver.tool_catalog.schema.invalid"));
    }
    Ok(())
}
pub trait TrustedToolCatalogProvider: Send + Sync {
    fn catalog(
        &self,
        session_id: SessionId,
        participant_id: ParticipantId,
        operation_id: Option<OperationId>,
    ) -> Pin<Box<dyn Future<Output = Result<TrustedToolCatalog, ExecutorError>> + Send + '_>>;
}
pub trait TrustedToolCatalogInstaller: Send + Sync {
    fn install_trusted_tool_catalog(
        &self,
        provider: Arc<dyn TrustedToolCatalogProvider>,
    ) -> Result<(), ExecutorError>;
}
struct EmptyTrustedToolCatalog;
impl TrustedToolCatalogProvider for EmptyTrustedToolCatalog {
    fn catalog(
        &self,
        _: SessionId,
        _: ParticipantId,
        _: Option<OperationId>,
    ) -> Pin<Box<dyn Future<Output = Result<TrustedToolCatalog, ExecutorError>> + Send + '_>> {
        Box::pin(async { TrustedToolCatalog::new(serde_json::Value::Array(Vec::new())) })
    }
}

#[derive(Debug, Default)]
struct ToolRuntimeCorrelations {
    guard: ToolCorrelationGuard,
    results: HashMap<Vec<u8>, v1::tool_result_request::Result>,
}

pub trait HierarchyCommandSink: Send + Sync {
    fn handle(
        &self,
        caller: AuthenticatedHierarchyCaller,
        command: v1::HierarchyCommand,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<v1::hierarchy_result_request::Result, ExecutorError>>
                + Send
                + '_,
        >,
    >;

    fn question(
        &self,
        caller: AuthenticatedHierarchyCaller,
        event_id: Vec<u8>,
        operation_id: OperationId,
        delivered_message_id: MessageId,
        code: Capability,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>>;
}

pub trait HierarchySinkInstaller: Send + Sync {
    fn install(&self, sink: Arc<dyn HierarchyCommandSink>) -> Result<(), ExecutorError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedApprovalRequest {
    pub capability: Capability,
    pub resource: ApprovalResource,
    pub summary: ApprovalSummary,
    pub expires_at: Timestamp,
}

pub trait ApprovalCommandSink: Send + Sync {
    fn request(
        &self,
        caller: AuthenticatedHierarchyCaller,
        event_id: Vec<u8>,
        operation_id: OperationId,
        delivered_message_id: MessageId,
        delivery_attempt_id: DeliveryAttemptId,
        request: AuthenticatedApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>>;
}

pub trait ApprovalSinkInstaller: Send + Sync {
    fn install_approval_sink(
        &self,
        sink: Arc<dyn ApprovalCommandSink>,
    ) -> Result<(), ExecutorError>;
}

pub struct LocalApprovalSink<S> {
    store: Arc<S>,
}

impl<S> LocalApprovalSink<S> {
    #[must_use]
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

impl<S: ApprovalStore> ApprovalCommandSink for LocalApprovalSink<S> {
    fn request(
        &self,
        caller: AuthenticatedHierarchyCaller,
        event_id: Vec<u8>,
        operation_id: OperationId,
        delivered_message_id: MessageId,
        delivery_attempt_id: DeliveryAttemptId,
        request: AuthenticatedApprovalRequest,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            let event_uuid = Uuid::from_slice(&event_id).map_err(|_| boundary_error())?;
            self.store
                .request_approval(RequestApproval {
                    context: RequestContext::new(
                        RequestId::from_uuid(event_uuid).map_err(|_| boundary_error())?,
                        caller.host_id,
                    ),
                    session_id: caller.session_id,
                    owner_epoch: caller.ownership_epoch,
                    approval_id: navigator_domain::ApprovalRequestId::from_uuid(event_uuid)
                        .map_err(|_| boundary_error())?,
                    requester_id: caller.participant_id,
                    operation_id,
                    source_message_id: delivered_message_id,
                    source_delivery_attempt_id: delivery_attempt_id,
                    capability: request.capability,
                    resource: request.resource,
                    summary: request.summary,
                    expires_at: request.expires_at,
                })
                .await
                .map(|_| ())
                .map_err(executor_error)
        })
    }
}

async fn dispatch_approval_request(
    sink: Option<Arc<dyn ApprovalCommandSink>>,
    caller: AuthenticatedHierarchyCaller,
    pending: &PendingReport,
    request: AuthenticatedApprovalRequest,
) -> Result<(), ExecutorError> {
    let sink = sink.ok_or_else(|| boundary_error_at("driver.approval_sink.missing"))?;
    sink.request(
        caller,
        pending.event_id.clone(),
        pending.operation_id,
        pending.message_id,
        pending.delivery_attempt_id,
        request,
    )
    .await
}

pub trait ToolCommandSink: Send + Sync {
    fn handle(
        &self,
        caller: AuthenticatedHierarchyCaller,
        command: v1::ToolCommand,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<v1::tool_result_request::Result, ExecutorError>> + Send + '_,
        >,
    >;
}

pub trait ToolSinkInstaller: Send + Sync {
    fn install_tool_sink(&self, sink: Arc<dyn ToolCommandSink>) -> Result<(), ExecutorError>;
}

pub trait ExistingOperationScheduler: Send + Sync {
    fn redeliver_recovery_with_permit(
        &self,
        _permit: AdmissionPermit,
        _operation_id: OperationId,
        _message_id: MessageId,
        _epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ExecutorError>> + Send + '_>> {
        Box::pin(async { Ok(false) })
    }

    fn schedule_recovery_with_permit(
        &self,
        permit: AdmissionPermit,
        operation_id: OperationId,
        _input_message_id: MessageId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        self.schedule_with_permit(permit, operation_id, epoch)
    }

    fn schedule_with_permit(
        &self,
        permit: AdmissionPermit,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>>;

    fn schedule(
        &self,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>>;

    fn schedule_feedback(
        &self,
        operation_id: OperationId,
        _message_id: MessageId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        self.schedule(operation_id, epoch)
    }
}

pub trait SessionAdmissionProvider: Send + Sync {
    fn admit_current(
        &self,
        session_id: SessionId,
        expected_epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<AdmissionPermit, ExecutorError>> + Send + '_>>;
}

pub trait SessionMailboxDispatcher: Send + Sync {
    fn sweep_with_permit(
        &self,
        permit: AdmissionPermit,
        session_id: SessionId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<usize, ExecutorError>> + Send + '_>>;
}

pub struct BoundedSessionMailboxDispatcher<S, C> {
    store: Arc<S>,
    executor: Arc<MailboxBackedOperationExecutor<S, C>>,
    limit: usize,
}

impl<S, C> BoundedSessionMailboxDispatcher<S, C> {
    #[must_use]
    pub fn new(
        store: Arc<S>,
        executor: Arc<MailboxBackedOperationExecutor<S, C>>,
        limit: usize,
    ) -> Self {
        Self {
            store,
            executor,
            limit: limit.clamp(1, navigator_store_api::MAX_SESSION_DELIVERY_WORK),
        }
    }
}

impl<S, C> SessionMailboxDispatcher for BoundedSessionMailboxDispatcher<S, C>
where
    S: MailboxStore + InstanceStore + OperationStore + HierarchyStore + ApprovalStore + 'static,
    C: CredentialSource + Sync + 'static,
{
    fn sweep_with_permit(
        &self,
        permit: AdmissionPermit,
        session_id: SessionId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<usize, ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            permit.check().map_err(executor_error)?;
            let work = self
                .store
                .load_due_session_delivery_work(session_id, self.limit)
                .await
                .map_err(executor_error)?;
            let count = work.len();
            for item in work {
                permit.check().map_err(executor_error)?;
                self.executor
                    .dispatch_message(
                        &permit,
                        item.operation.operation_id,
                        item.message.message_id,
                        epoch,
                    )
                    .await?;
            }
            Ok(count)
        })
    }
}

pub struct SessionScopedExistingScheduler<S> {
    store: Arc<S>,
    admissions: Arc<dyn SessionAdmissionProvider>,
    inner: Arc<dyn ExistingOperationScheduler>,
}

impl<S> SessionScopedExistingScheduler<S> {
    #[must_use]
    pub fn new(
        store: Arc<S>,
        admissions: Arc<dyn SessionAdmissionProvider>,
        inner: Arc<dyn ExistingOperationScheduler>,
    ) -> Self {
        Self {
            store,
            admissions,
            inner,
        }
    }
}

impl<S> ExistingOperationScheduler for SessionScopedExistingScheduler<S>
where
    S: OperationStore + 'static,
{
    fn schedule_with_permit(
        &self,
        permit: AdmissionPermit,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        self.inner.schedule_with_permit(permit, operation_id, epoch)
    }

    fn schedule(
        &self,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            let operation = self
                .store
                .load_operation(operation_id)
                .await
                .map_err(executor_error)?;
            let permit = self
                .admissions
                .admit_current(operation.session_id, epoch)
                .await?;
            permit.check().map_err(executor_error)?;
            self.inner
                .schedule_with_permit(permit, operation_id, epoch)
                .await
        })
    }
}

pub struct FirstOperationScheduler<S, E, F> {
    service: Arc<FirstOperationService<S, E, F>>,
    admission: AdmissionGate,
}

impl<S, E, F> FirstOperationScheduler<S, E, F> {
    #[must_use]
    pub fn new(service: Arc<FirstOperationService<S, E, F>>, admission: AdmissionGate) -> Self {
        Self { service, admission }
    }
}

impl<S, E, F> ExistingOperationScheduler for FirstOperationScheduler<S, E, F>
where
    S: navigator_core::OperationPersistence,
    E: OperationExecutor,
    F: TransitionContextFactory,
{
    fn schedule(
        &self,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            let permit = self.admission.admit().map_err(executor_error)?;
            self.schedule_with_permit(permit, operation_id, epoch).await
        })
    }

    fn schedule_with_permit(
        &self,
        permit: AdmissionPermit,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            self.service
                .resume_existing(permit, operation_id, epoch)
                .await
                .map(|_| ())
                .map_err(executor_error)
        })
    }
}

pub struct MailboxFirstOperationScheduler<S, C, F> {
    service: Arc<FirstOperationService<S, MailboxBackedOperationExecutor<S, C>, F>>,
    executor: Arc<MailboxBackedOperationExecutor<S, C>>,
    admission: AdmissionGate,
}

pub struct PermitOnlyMailboxScheduler<S, C, F> {
    service: Arc<FirstOperationService<S, MailboxBackedOperationExecutor<S, C>, F>>,
    executor: Arc<MailboxBackedOperationExecutor<S, C>>,
}

impl<S, C, F> PermitOnlyMailboxScheduler<S, C, F> {
    #[must_use]
    pub fn new(
        service: Arc<FirstOperationService<S, MailboxBackedOperationExecutor<S, C>, F>>,
        executor: Arc<MailboxBackedOperationExecutor<S, C>>,
    ) -> Self {
        Self { service, executor }
    }
}

impl<S, C, F> ExistingOperationScheduler for PermitOnlyMailboxScheduler<S, C, F>
where
    S: MailboxStore + InstanceStore + OperationStore + HierarchyStore + ApprovalStore + 'static,
    C: CredentialSource + Sync,
    F: TransitionContextFactory,
{
    fn redeliver_recovery_with_permit(
        &self,
        permit: AdmissionPermit,
        operation_id: OperationId,
        message_id: MessageId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            self.executor
                .dispatch_message(&permit, operation_id, message_id, epoch)
                .await?;
            Ok(true)
        })
    }

    fn schedule_with_permit(
        &self,
        permit: AdmissionPermit,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            self.service
                .resume_existing(permit, operation_id, epoch)
                .await
                .map(|_| ())
                .map_err(executor_error)
        })
    }

    fn schedule(
        &self,
        _operation_id: OperationId,
        _epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        Box::pin(async { Err(boundary_error()) })
    }
}

impl<S, C, F> MailboxFirstOperationScheduler<S, C, F> {
    #[must_use]
    pub fn new(
        service: Arc<FirstOperationService<S, MailboxBackedOperationExecutor<S, C>, F>>,
        executor: Arc<MailboxBackedOperationExecutor<S, C>>,
        admission: AdmissionGate,
    ) -> Self {
        Self {
            service,
            executor,
            admission,
        }
    }
}

impl<S, C, F> ExistingOperationScheduler for MailboxFirstOperationScheduler<S, C, F>
where
    S: MailboxStore + InstanceStore + OperationStore + HierarchyStore + ApprovalStore + 'static,
    C: CredentialSource + Sync,
    F: TransitionContextFactory,
{
    fn redeliver_recovery_with_permit(
        &self,
        permit: AdmissionPermit,
        operation_id: OperationId,
        message_id: MessageId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<bool, ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            self.executor
                .dispatch_message(&permit, operation_id, message_id, epoch)
                .await?;
            Ok(true)
        })
    }

    fn schedule(
        &self,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            let permit = self.admission.admit().map_err(executor_error)?;
            self.schedule_with_permit(permit, operation_id, epoch).await
        })
    }

    fn schedule_with_permit(
        &self,
        permit: AdmissionPermit,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            self.service
                .resume_existing(permit, operation_id, epoch)
                .await
                .map(|_| ())
                .map_err(executor_error)
        })
    }

    fn schedule_feedback(
        &self,
        operation_id: OperationId,
        message_id: MessageId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            let permit = self.admission.admit().map_err(executor_error)?;
            self.executor
                .dispatch_message(&permit, operation_id, message_id, epoch)
                .await?;
            self.service
                .resume_existing(permit, operation_id, epoch)
                .await
                .map(|_| ())
                .map_err(executor_error)
        })
    }
}

pub struct LocalHierarchySink<S> {
    service: Arc<HierarchyService<S>>,
    store: Arc<S>,
    host_id: HostId,
    scheduler: Option<Arc<dyn ExistingOperationScheduler>>,
}

impl<S> LocalHierarchySink<S>
where
    S: AuthorityStore + navigator_store_api::HierarchyStore + InstanceStore + OperationStore,
{
    #[must_use]
    pub fn new(store: Arc<S>, host_id: HostId) -> Self {
        Self {
            service: Arc::new(HierarchyService::new(Arc::clone(&store))),
            store,
            host_id,
            scheduler: None,
        }
    }

    #[must_use]
    pub fn with_scheduler(mut self, scheduler: Arc<dyn ExistingOperationScheduler>) -> Self {
        self.scheduler = Some(scheduler);
        self
    }
}

impl<S> HierarchyCommandSink for LocalHierarchySink<S>
where
    S: AuthorityStore
        + navigator_store_api::HierarchyStore
        + InstanceStore
        + OperationStore
        + 'static,
{
    #[expect(clippy::too_many_lines, reason = "closed hierarchy command dispatch")]
    fn handle(
        &self,
        caller: AuthenticatedHierarchyCaller,
        command: v1::HierarchyCommand,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<v1::hierarchy_result_request::Result, ExecutorError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            self.service
                .verify_caller(caller)
                .await
                .map_err(|_| boundary_error_at("hierarchy.caller.invalid"))?;
            let request_id = parse_request(&command.request_id)?;
            match command.command.ok_or_else(boundary_error)? {
                v1::hierarchy_command::Command::SpawnChild(spawn) => {
                    let ownership_epoch = caller.ownership_epoch;
                    let template_id = navigator_domain::TemplateId::from_uuid(
                        Uuid::from_slice(&spawn.template_id).map_err(|_| boundary_error())?,
                    )
                    .map_err(|_| boundary_error())?;
                    let registered = self
                        .store
                        .load_template(template_id)
                        .await
                        .map_err(|_| boundary_error())?;
                    let template = Template::try_from(registered).map_err(|_| boundary_error())?;
                    let input = template
                        .validate_input(&spawn.task_input)
                        .map_err(|_| boundary_error())?;
                    let grant_id = parse_optional_grant(&spawn.grant_id)?;
                    let participant_id = derived_participant(&command.request_id)?;
                    let operation_id = derived_operation(&command.request_id)?;
                    let input_message_id = derived_message(&command.request_id)?;
                    let mutation = self
                        .service
                        .spawn_child(
                            caller,
                            SpawnChildRequest {
                                context: RequestContext::new(request_id, self.host_id),
                                participant_id,
                                template_id,
                                grant_id,
                                operation_id,
                                input_message_id,
                                input,
                            },
                        )
                        .await
                        .map_err(|error| {
                            boundary_error_at(match error {
                                navigator_core::HierarchyServiceError::UnauthenticatedInstance => {
                                    "hierarchy.spawn.caller_invalid"
                                }
                                navigator_core::HierarchyServiceError::Denied => {
                                    "hierarchy.spawn.denied"
                                }
                                navigator_core::HierarchyServiceError::Store => {
                                    "hierarchy.spawn.store_failed"
                                }
                                navigator_core::HierarchyServiceError::StoreConflict => {
                                    "hierarchy.spawn.request_conflict"
                                }
                                navigator_core::HierarchyServiceError::StoreCorrupt => {
                                    "hierarchy.spawn.store_corrupt"
                                }
                            })
                        })?;
                    match mutation.value() {
                        AuthorizedChildOutcome::Allowed {
                            participant,
                            operation,
                            ..
                        } => {
                            // Exact hierarchy replay is also a recovery signal: the durable
                            // child may exist while its first worker attempt died pre-start.
                            if authorized_child_requires_schedule()
                                && let Some(scheduler) = &self.scheduler
                            {
                                scheduler
                                    .schedule(operation.operation_id, ownership_epoch)
                                    .await
                                    .map_err(|_| {
                                        boundary_error_at("hierarchy.spawn.schedule_failed")
                                    })?;
                            }
                            Ok(v1::hierarchy_result_request::Result::Spawned(
                                v1::SpawnChildResult {
                                    participant_id: participant
                                        .participant_id
                                        .as_uuid()
                                        .as_bytes()
                                        .to_vec(),
                                    operation_id: operation
                                        .operation_id
                                        .as_uuid()
                                        .as_bytes()
                                        .to_vec(),
                                    input_message_id: operation
                                        .input_message_id
                                        .as_uuid()
                                        .as_bytes()
                                        .to_vec(),
                                },
                            ))
                        }
                        AuthorizedChildOutcome::Denied => Ok(hierarchy_failure(
                            v1::FailureCode::Authorization,
                            "hierarchy command denied",
                        )),
                    }
                }
                v1::hierarchy_command::Command::Status(status) => {
                    let participant_id = ParticipantId::from_uuid(
                        Uuid::from_slice(&status.participant_id).map_err(|_| boundary_error())?,
                    )
                    .map_err(|_| boundary_error())?;
                    let operation_id = if status.operation_id.is_empty() {
                        None
                    } else {
                        Some(parse_operation(&status.operation_id)?)
                    };
                    let status_result = self
                        .service
                        .child_status(
                            caller,
                            ChildStatusRequest {
                                context: RequestContext::new(request_id, self.host_id),
                                participant_id,
                                operation_id,
                            },
                        )
                        .await;
                    let (participant, operation) = match status_result {
                        Ok(value) => value,
                        Err(navigator_core::HierarchyServiceError::Denied) => {
                            return Ok(hierarchy_failure(
                                v1::FailureCode::Authorization,
                                "hierarchy command denied",
                            ));
                        }
                        Err(_) => return Err(boundary_error()),
                    };
                    Ok(v1::hierarchy_result_request::Result::Status(
                        v1::ParticipantStatusResult {
                            participant_id: participant
                                .participant_id
                                .as_uuid()
                                .as_bytes()
                                .to_vec(),
                            operation_id: operation.as_ref().map_or_else(Vec::new, |value| {
                                value.operation_id.as_uuid().as_bytes().to_vec()
                            }),
                            state: operation
                                .as_ref()
                                .map_or("registered", |value| operation_state_name(value.state))
                                .to_owned(),
                        },
                    ))
                }
                v1::hierarchy_command::Command::Send(send) => {
                    let destination = parse_participant(&send.destination_participant_id)?;
                    let envelope: ValidatedMessageEnvelope =
                        serde_json::from_slice(&send.validated_envelope)
                            .map_err(|_| boundary_error())?;
                    let message_id = derived_message(&command.request_id)?;
                    let effect = match envelope.body() {
                        MessageBody::CorrelatedFeedback {
                            operation_id,
                            in_reply_to,
                            feedback,
                        } => navigator_store_api::HierarchyEffect::ResumeChild {
                            message_id,
                            child_id: destination,
                            operation_id: *operation_id,
                            in_reply_to: *in_reply_to,
                            feedback: *feedback,
                            grant_id: None,
                        },
                        MessageBody::Control { .. } => navigator_store_api::HierarchyEffect::Send {
                            message_id,
                            destination,
                            envelope,
                            grant_id: None,
                        },
                        _ => {
                            return Ok(hierarchy_failure(
                                v1::FailureCode::Authorization,
                                "hierarchy message denied",
                            ));
                        }
                    };
                    let outcome = self
                        .store
                        .apply_hierarchy_effect(navigator_store_api::ApplyHierarchyEffect {
                            context: RequestContext::new(request_id, self.host_id),
                            session_id: caller.session_id,
                            epoch: caller.ownership_epoch,
                            caller_participant_id: caller.participant_id,
                            effect,
                        })
                        .await
                        .map_err(|_| boundary_error())?;
                    match outcome.value() {
                        navigator_store_api::HierarchyEffectOutcome::Allowed {
                            message,
                            operation,
                        } => {
                            if !matches!(&outcome, Mutation::Unchanged(_))
                                && let (Some(scheduler), Some(operation)) =
                                    (&self.scheduler, operation.as_ref())
                            {
                                scheduler
                                    .schedule_feedback(
                                        operation.operation_id,
                                        message.message_id,
                                        caller.ownership_epoch,
                                    )
                                    .await
                                    .map_err(|_| {
                                        boundary_error_at("hierarchy.send.schedule_failed")
                                    })?;
                            }
                            Ok(v1::hierarchy_result_request::Result::Sent(
                                v1::MessageAcceptedResult {
                                    message_id: message.message_id.as_uuid().as_bytes().to_vec(),
                                },
                            ))
                        }
                        navigator_store_api::HierarchyEffectOutcome::Denied => {
                            Ok(hierarchy_failure(
                                v1::FailureCode::Authorization,
                                "hierarchy message denied",
                            ))
                        }
                    }
                }
                v1::hierarchy_command::Command::Cancel(cancel) => {
                    let child_id = parse_participant(&cancel.participant_id)?;
                    let operation_id = parse_operation(&cancel.operation_id)?;
                    let outcome = self
                        .store
                        .apply_hierarchy_effect(navigator_store_api::ApplyHierarchyEffect {
                            context: RequestContext::new(request_id, self.host_id),
                            session_id: caller.session_id,
                            epoch: caller.ownership_epoch,
                            caller_participant_id: caller.participant_id,
                            effect: navigator_store_api::HierarchyEffect::CancelChild {
                                message_id: derived_message(&command.request_id)?,
                                child_id,
                                operation_id,
                                grant_id: None,
                            },
                        })
                        .await
                        .map_err(|_| boundary_error())?;
                    match outcome.value() {
                        navigator_store_api::HierarchyEffectOutcome::Allowed {
                            message,
                            operation,
                        } => {
                            if !matches!(&outcome, Mutation::Unchanged(_))
                                && let (Some(scheduler), Some(operation)) =
                                    (&self.scheduler, operation.as_ref())
                            {
                                scheduler
                                    .schedule_feedback(
                                        operation.operation_id,
                                        message.message_id,
                                        caller.ownership_epoch,
                                    )
                                    .await
                                    .map_err(|_| {
                                        boundary_error_at("hierarchy.cancel.schedule_failed")
                                    })?;
                            }
                            Ok(v1::hierarchy_result_request::Result::Cancelled(
                                v1::CancelAcceptedResult {
                                    operation_id: operation_id.as_uuid().as_bytes().to_vec(),
                                },
                            ))
                        }
                        navigator_store_api::HierarchyEffectOutcome::Denied => {
                            Ok(hierarchy_failure(
                                v1::FailureCode::Authorization,
                                "hierarchy cancellation denied",
                            ))
                        }
                    }
                }
            }
        })
    }

    fn question(
        &self,
        caller: AuthenticatedHierarchyCaller,
        event_id: Vec<u8>,
        operation_id: OperationId,
        delivered_message_id: MessageId,
        code: Capability,
    ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
        Box::pin(async move {
            self.service
                .verify_caller(caller)
                .await
                .map_err(|_| boundary_error_at("hierarchy.caller.invalid"))?;
            let request_id = parse_request(&event_id)?;
            let message_id = derived_message(&event_id)?;
            let result = self
                .store
                .apply_hierarchy_effect(navigator_store_api::ApplyHierarchyEffect {
                    context: RequestContext::new(request_id, self.host_id),
                    session_id: caller.session_id,
                    epoch: caller.ownership_epoch,
                    caller_participant_id: caller.participant_id,
                    effect: navigator_store_api::HierarchyEffect::QuestionUpward {
                        message_id,
                        operation_id,
                        delivered_message_id,
                        code,
                        grant_id: None,
                    },
                })
                .await
                .map_err(|_| boundary_error())?;
            matches!(
                result.value(),
                navigator_store_api::HierarchyEffectOutcome::Allowed { .. }
            )
            .then_some(())
            .ok_or_else(boundary_error)
        })
    }
}

const fn authorized_child_requires_schedule() -> bool {
    true
}

#[derive(Clone)]
struct ControlSocketEvidence {
    path: PathBuf,
    device: u64,
    inode: u64,
}

#[derive(Clone)]
pub struct SupervisedDriverConfig {
    pub driver_id: DriverId,
    pub program: PathBuf,
    pub expected_executable_identity: [u8; 32],
    pub arguments: Vec<OsString>,
    pub working_directory: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub environment_allowlist: BTreeSet<OsString>,
    pub control_directory: PathBuf,
    pub control_socket_environment: OsString,
    pub connect_timeout: Duration,
    pub offered_capabilities: Vec<DriverCapabilityRequirement>,
    pub ownership_channel: navigator_supervisor::OwnershipChannel,
    pub process_io_mode: navigator_supervisor::ProcessIoMode,
    pub bootstrap_configuration: Vec<u8>,
    pub trusted_artifacts: Vec<(PathBuf, [u8; 32])>,
}

/// Resolves operator-trusted process configuration from persisted Template metadata.
/// Implementations must never consult operation input or model output.
pub trait DriverConfigResolver: Send + Sync {
    fn resolve(&self, template: &TemplateRecord) -> Result<SupervisedDriverConfig, ExecutorError>;
}

struct FixedDriverConfigResolver(SupervisedDriverConfig);

impl DriverConfigResolver for FixedDriverConfigResolver {
    fn resolve(&self, _template: &TemplateRecord) -> Result<SupervisedDriverConfig, ExecutorError> {
        Ok(self.0.clone())
    }
}

impl std::fmt::Debug for SupervisedDriverConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SupervisedDriverConfig")
            .field("driver_id", &self.driver_id)
            .field("program", &self.program)
            .field(
                "expected_executable_identity",
                &self.expected_executable_identity,
            )
            .field("working_directory", &self.working_directory)
            .field("control_directory", &self.control_directory)
            .field("connect_timeout", &self.connect_timeout)
            .field("offered_capabilities", &self.offered_capabilities)
            .field("ownership_channel", &self.ownership_channel)
            .field("process_io_mode", &self.process_io_mode)
            .field("arguments", &"[redacted]")
            .field("environment", &"[redacted]")
            .finish_non_exhaustive()
    }
}

fn config_identity(config: &SupervisedDriverConfig) -> [u8; 32] {
    use std::os::unix::ffi::OsStrExt as _;
    let mut digest = Sha256::new();
    digest.update(b"navigator.driver.profile.v1\0");
    digest.update(config.driver_id.as_uuid().as_bytes());
    digest.update(config.expected_executable_identity);
    digest.update(config.program.as_os_str().as_bytes());
    digest.update(config.working_directory.as_os_str().as_bytes());
    digest.update(&config.bootstrap_configuration);
    digest.update([match config.ownership_channel {
        navigator_supervisor::OwnershipChannel::Stdin => 0,
        navigator_supervisor::OwnershipChannel::DedicatedFd => 1,
    }]);
    digest.update([match config.process_io_mode {
        navigator_supervisor::ProcessIoMode::Headless => 0,
        navigator_supervisor::ProcessIoMode::TerminalPty => 1,
    }]);
    for argument in &config.arguments {
        digest.update((argument.as_bytes().len() as u64).to_be_bytes());
        digest.update(argument.as_bytes());
    }
    for (key, value) in &config.environment {
        digest.update((key.as_bytes().len() as u64).to_be_bytes());
        digest.update(key.as_bytes());
        digest.update((value.as_bytes().len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    for capability in &config.offered_capabilities {
        digest.update(capability.capability().as_str().as_bytes());
        digest.update(capability.minimum_version().to_be_bytes());
        for (key, value) in capability.parameters() {
            digest.update(key.as_str().as_bytes());
            digest.update([0]);
            digest.update(value.as_str().as_bytes());
            digest.update([0]);
        }
    }
    for (path, artifact_digest) in &config.trusted_artifacts {
        digest.update(path.as_os_str().as_bytes());
        digest.update([0]);
        digest.update(artifact_digest);
    }
    digest.finalize().into()
}

fn resolved_driver_identity(base: [u8; 32], catalog: [u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"navigator.driver.config-with-tools.v1\0");
    digest.update(base);
    digest.update(catalog);
    digest.finalize().into()
}

fn active_identity_matches(active: [u8; 32], resolved: [u8; 32]) -> bool {
    active == resolved
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CatalogLifecycleAction {
    Launch,
    Reuse,
    Replace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostLaunchFailure {
    Bootstrap,
    Digest,
    HierarchySink,
    ToolSink,
    DriverConstruction,
    ActiveCache,
}

async fn run_post_launch_cleanup<Abort, Remove, Stop, StopFuture>(
    _failure: PostLaunchFailure,
    abort: Abort,
    remove_socket: Remove,
    stop: Stop,
) -> Result<(), ExecutorError>
where
    Abort: FnOnce(),
    Remove: FnOnce() -> Result<(), ExecutorError>,
    Stop: FnOnce() -> StopFuture,
    StopFuture: Future<Output = Result<(), ExecutorError>>,
{
    abort();
    let socket_result = remove_socket();
    let stop_result = stop().await;
    socket_result?;
    stop_result
}

fn catalog_lifecycle_action(
    active: Option<[u8; 32]>,
    resolved: [u8; 32],
) -> CatalogLifecycleAction {
    match active {
        None => CatalogLifecycleAction::Launch,
        Some(identity) if active_identity_matches(identity, resolved) => {
            CatalogLifecycleAction::Reuse
        }
        Some(_) => CatalogLifecycleAction::Replace,
    }
}

fn active_cache_has_capacity(size: usize) -> bool {
    size < MAX_ACTIVE_DRIVER_CACHE
}

fn remaining_connect_budget(
    deadline: tokio::time::Instant,
    now: tokio::time::Instant,
) -> Option<Duration> {
    let remaining = deadline.saturating_duration_since(now);
    (!remaining.is_zero()).then_some(remaining)
}

async fn wait_for_pending_launch_cancellation(cancellation: Arc<std::sync::atomic::AtomicBool>) {
    while !cancellation.load(std::sync::atomic::Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn remove_active_if_same<K, V>(cache: &mut HashMap<K, Arc<V>>, key: &K, expected: &Arc<V>) -> bool
where
    K: Eq + std::hash::Hash,
{
    if cache
        .get(key)
        .is_some_and(|current| Arc::ptr_eq(current, expected))
    {
        cache.remove(key);
        true
    } else {
        false
    }
}

#[cfg(test)]
fn cache_bootstrapped<K, V, E>(
    cache: &mut HashMap<K, V>,
    key: K,
    bootstrap: Result<V, E>,
) -> Result<V, E>
where
    K: Eq + std::hash::Hash,
    V: Clone,
{
    let value = bootstrap?;
    cache.insert(key, value.clone());
    Ok(value)
}

fn resolved_launch_attempt_id(
    participant_id: ParticipantId,
    epoch: FencingEpoch,
    resolved: [u8; 32],
) -> Result<LaunchAttemptId, ExecutorError> {
    let mut input = participant_id.as_uuid().as_bytes().to_vec();
    input.extend_from_slice(&epoch.get().to_be_bytes());
    input.extend_from_slice(&resolved);
    LaunchAttemptId::from_uuid(derived_uuid(b"navigator.driver.attempt.v1", &input))
        .map_err(executor_error)
}

/// Derives the exact launch identity used by the supervised runtime.
///
/// This is public for integration fixtures that must prepare attempt-bound
/// process inputs; callers must not reimplement the identity grammar.
pub fn resolved_launch_attempt_for_config(
    participant_id: ParticipantId,
    epoch: FencingEpoch,
    config: &SupervisedDriverConfig,
    catalog: &TrustedToolCatalog,
) -> Result<LaunchAttemptId, ExecutorError> {
    resolved_launch_attempt_id(
        participant_id,
        epoch,
        resolved_driver_identity(config_identity(config), catalog.identity()),
    )
}

pub struct SupervisedDriverExecutor<S, C> {
    store: Arc<S>,
    supervisor: Arc<InstanceSupervisor<S, UnixProcessBackend, C, NoFaults>>,
    host_id: HostId,
    config_resolver: Arc<dyn DriverConfigResolver>,
    active:
        tokio::sync::Mutex<HashMap<(navigator_domain::ParticipantId, u64), Arc<DriverExecutor>>>,
    pending_launches: tokio::sync::Mutex<HashMap<LaunchAttemptId, PendingLaunch>>,
    launch_lock: tokio::sync::Mutex<()>,
    hierarchy_sink: RwLock<Option<Arc<dyn HierarchyCommandSink>>>,
    approval_sink: RwLock<Option<Arc<dyn ApprovalCommandSink>>>,
    tool_sink: RwLock<Option<Arc<dyn ToolCommandSink>>>,
    trusted_tool_catalog: RwLock<Arc<dyn TrustedToolCatalogProvider>>,
    shutdown_observer: Arc<dyn ShutdownObserver>,
}

#[derive(Clone)]
struct PendingLaunch {
    session_id: SessionId,
    participant_id: ParticipantId,
    epoch: FencingEpoch,
    cancellation: Arc<std::sync::atomic::AtomicBool>,
}

fn finish_pending_reconcile(
    pending: &mut HashMap<LaunchAttemptId, PendingLaunch>,
    attempt_id: LaunchAttemptId,
    result: &Result<(), ExecutorError>,
) {
    if result.is_ok() {
        pending.remove(&attempt_id);
    }
}

fn classify_pending_reconcile(
    outcome: navigator_supervisor::StopOutcome,
) -> Result<(), ExecutorError> {
    match outcome {
        navigator_supervisor::StopOutcome::Stopped
        | navigator_supervisor::StopOutcome::AlreadyStopped => Ok(()),
        navigator_supervisor::StopOutcome::CleanupRequired => {
            Err(boundary_error_at("driver.pending_launch.cleanup_required"))
        }
    }
}

fn pending_launch_was_never_prepared(
    loaded: Result<LaunchSnapshot, StoreError>,
) -> Result<bool, ExecutorError> {
    match loaded {
        Ok(_) => Ok(false),
        Err(StoreError::LaunchNotFound { .. }) => Ok(true),
        Err(error) => Err(executor_error(error)),
    }
}

const MAX_ACTIVE_DRIVER_CACHE: usize = 1024;
// Observe is a long-lived operation poll, not a mailbox delivery call.  Give
// it an explicit bound so a prior short delivery deadline cannot leak through
// the stateful Unix stream. The operation worker still owns the tighter
// absolute report/reminder deadline and cancels this task at that boundary.
const DRIVER_OBSERVE_IO_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownAttemptOutcome {
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownAttemptEvidence {
    pub participant_id: ParticipantId,
    pub attempt_id: LaunchAttemptId,
    pub outcome: ShutdownAttemptOutcome,
}

pub trait ShutdownObserver: Send + Sync {
    fn level_completed(&self, depth: u32, attempts: &[ShutdownAttemptEvidence]);
}

struct NoopShutdownObserver;
impl ShutdownObserver for NoopShutdownObserver {
    fn level_completed(&self, _: u32, _: &[ShutdownAttemptEvidence]) {}
}

type DepthRead<'a> = Pin<
    Box<
        dyn Future<
                Output = (
                    ParticipantId,
                    Result<
                        navigator_store_api::ParticipantSnapshot,
                        navigator_store_api::StoreError,
                    >,
                ),
            > + Send
            + 'a,
    >,
>;

type ShutdownLevelResult = (
    (ParticipantId, u64),
    Arc<DriverExecutor>,
    Result<(), ExecutorError>,
);

fn observe_shutdown_level(
    observer: &dyn ShutdownObserver,
    depth: u32,
    results: &[ShutdownLevelResult],
) {
    let evidence = results
        .iter()
        .map(|((participant_id, _), driver, result)| {
            let attempt_id = Uuid::from_slice(&driver.identity.launch_attempt_id)
                .ok()
                .and_then(|id| LaunchAttemptId::from_uuid(id).ok())
                .expect("authenticated Driver attempt identity is valid");
            ShutdownAttemptEvidence {
                participant_id: *participant_id,
                attempt_id,
                outcome: if result.is_ok() {
                    ShutdownAttemptOutcome::Stopped
                } else {
                    ShutdownAttemptOutcome::Failed
                },
            }
        })
        .collect::<Vec<_>>();
    observer.level_completed(depth, &evidence);
}

impl<S, C> SupervisedDriverExecutor<S, C> {
    pub fn new(
        store: Arc<S>,
        supervisor: Arc<InstanceSupervisor<S, UnixProcessBackend, C, NoFaults>>,
        host_id: HostId,
        config: SupervisedDriverConfig,
    ) -> Self {
        Self::new_with_resolver(
            store,
            supervisor,
            host_id,
            Arc::new(FixedDriverConfigResolver(config)),
        )
    }

    pub fn new_with_resolver(
        store: Arc<S>,
        supervisor: Arc<InstanceSupervisor<S, UnixProcessBackend, C, NoFaults>>,
        host_id: HostId,
        config_resolver: Arc<dyn DriverConfigResolver>,
    ) -> Self {
        Self {
            store,
            supervisor,
            host_id,
            config_resolver,
            active: tokio::sync::Mutex::new(HashMap::new()),
            pending_launches: tokio::sync::Mutex::new(HashMap::new()),
            launch_lock: tokio::sync::Mutex::new(()),
            hierarchy_sink: RwLock::new(None),
            approval_sink: RwLock::new(None),
            tool_sink: RwLock::new(None),
            trusted_tool_catalog: RwLock::new(Arc::new(EmptyTrustedToolCatalog)),
            shutdown_observer: Arc::new(NoopShutdownObserver),
        }
    }

    #[must_use]
    pub fn with_shutdown_observer(mut self, observer: Arc<dyn ShutdownObserver>) -> Self {
        self.shutdown_observer = observer;
        self
    }

    #[must_use]
    pub fn with_hierarchy_sink(mut self, sink: Arc<dyn HierarchyCommandSink>) -> Self {
        *self
            .hierarchy_sink
            .get_mut()
            .expect("new lock is available") = Some(sink);
        self
    }

    pub fn install_hierarchy_sink(
        &self,
        sink: Arc<dyn HierarchyCommandSink>,
    ) -> Result<(), ExecutorError> {
        *self.hierarchy_sink.write().map_err(|_| boundary_error())? = Some(sink);
        Ok(())
    }

    pub fn install_tool_sink(&self, sink: Arc<dyn ToolCommandSink>) -> Result<(), ExecutorError> {
        *self.tool_sink.write().map_err(|_| boundary_error())? = Some(sink);
        Ok(())
    }
    pub fn install_approval_sink(
        &self,
        sink: Arc<dyn ApprovalCommandSink>,
    ) -> Result<(), ExecutorError> {
        *self.approval_sink.write().map_err(|_| boundary_error())? = Some(sink);
        Ok(())
    }
    pub fn install_trusted_tool_catalog(
        &self,
        provider: Arc<dyn TrustedToolCatalogProvider>,
    ) -> Result<(), ExecutorError> {
        *self
            .trusted_tool_catalog
            .write()
            .map_err(|_| boundary_error())? = provider;
        Ok(())
    }
}

impl<S, C> HierarchySinkInstaller for SupervisedDriverExecutor<S, C>
where
    S: Send + Sync,
    C: Send + Sync,
{
    fn install(&self, sink: Arc<dyn HierarchyCommandSink>) -> Result<(), ExecutorError> {
        self.install_hierarchy_sink(sink)
    }
}

impl<S, C> ToolSinkInstaller for SupervisedDriverExecutor<S, C>
where
    S: Send + Sync,
    C: Send + Sync,
{
    fn install_tool_sink(&self, sink: Arc<dyn ToolCommandSink>) -> Result<(), ExecutorError> {
        self.install_tool_sink(sink)
    }
}
impl<S, C> ApprovalSinkInstaller for SupervisedDriverExecutor<S, C>
where
    S: Send + Sync,
    C: Send + Sync,
{
    fn install_approval_sink(
        &self,
        sink: Arc<dyn ApprovalCommandSink>,
    ) -> Result<(), ExecutorError> {
        self.install_approval_sink(sink)
    }
}
impl<S: Send + Sync, C: Send + Sync> TrustedToolCatalogInstaller
    for SupervisedDriverExecutor<S, C>
{
    fn install_trusted_tool_catalog(
        &self,
        provider: Arc<dyn TrustedToolCatalogProvider>,
    ) -> Result<(), ExecutorError> {
        self.install_trusted_tool_catalog(provider)
    }
}

impl<S, C> SupervisedDriverExecutor<S, C>
where
    S: MailboxStore + InstanceStore + OperationStore + HierarchyStore + 'static,
    C: CredentialSource,
{
    pub async fn shutdown(&self) -> Result<(), ExecutorError> {
        // Descendant levels are deliberately stopped before their parents.  A
        // single-process budget cannot cover that sequential dependency chain;
        // use the active count as a finite conservative upper bound (siblings
        // at one level still stop concurrently). Explicit-deadline entry points
        // below continue to honor the caller's exact global bound.
        let active_count =
            self.active.lock().await.len() + self.pending_launches.lock().await.len();
        let deadline = tokio::time::Instant::now()
            + bounded_hierarchy_shutdown_budget(
                self.supervisor.configured_stop_budget(),
                active_count,
            );
        self.shutdown_with_deadline(deadline).await
    }

    pub async fn shutdown_with_deadline(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), ExecutorError> {
        self.shutdown_matching(deadline, None).await
    }

    pub async fn shutdown_session_with_deadline(
        &self,
        session_id: SessionId,
        deadline: tokio::time::Instant,
    ) -> Result<(), ExecutorError> {
        self.shutdown_matching(deadline, Some(session_id)).await
    }

    async fn shutdown_matching(
        &self,
        deadline: tokio::time::Instant,
        session_filter: Option<SessionId>,
    ) -> Result<(), ExecutorError> {
        // Interrupt socket/bootstrap waits before waiting for the launch lock;
        // otherwise a normal shutdown could spend its whole cleanup budget
        // behind the larger trusted cold-start budget.
        for pending in self.pending_launches.lock().await.values() {
            if session_filter.is_none_or(|id| id == pending.session_id) {
                pending
                    .cancellation
                    .store(true, std::sync::atomic::Ordering::Release);
            }
        }
        // Serialize with the whole launch boundary. A cancelled caller leaves
        // its durable attempt in `pending_launches`; once this guard is held no
        // launch can move from Prepared to an untracked live process while the
        // shutdown inventory is being drained.
        let launch_guard = tokio::time::timeout_at(deadline, self.launch_lock.lock())
            .await
            .map_err(|_| boundary_error_at("driver.pending_launch.deadline"))?;
        let pending_cleanup_failed = self
            .drain_pending_launches(&launch_guard, deadline, session_filter)
            .await;
        let drivers = {
            let active = self.active.lock().await;
            active
                .iter()
                .filter(|(_, driver)| {
                    session_filter.is_none_or(|session_id| {
                        driver.identity.session_id == session_id.as_uuid().as_bytes()
                    })
                })
                .map(|(key, driver)| (*key, Arc::clone(driver)))
                .collect::<Vec<_>>()
        };
        let depth_reads: Vec<DepthRead<'_>> = drivers
            .iter()
            .map(|((participant_id, _), _)| {
                Box::pin(async move {
                    (
                        *participant_id,
                        self.store.load_participant(*participant_id).await,
                    )
                }) as DepthRead<'_>
            })
            .collect();
        let depths = tokio::time::timeout_at(deadline, join_all(depth_reads)).await;
        let participant_by_id = depths.map_or_else(
            |_| HashMap::new(),
            |values| {
                values
                    .into_iter()
                    .filter_map(|(participant, snapshot)| {
                        snapshot.ok().map(|snapshot| (participant, snapshot))
                    })
                    .collect()
            },
        );
        let topology_failed = participant_by_id.len() != drivers.len();
        if topology_failed {
            return Err(boundary_error());
        }
        let drivers = drivers.into_iter();
        let levels = group_by_depth(
            drivers.map(|(key, driver)| (participant_by_id[&key.0].depth, (key, driver))),
        );
        let level_results = execute_descendants_first(
            levels,
            |(key, driver)| {
                Box::pin(async move {
                    (
                        key,
                        driver.clone(),
                        self.shutdown_driver(driver, deadline).await,
                    )
                }) as Pin<Box<dyn Future<Output = ShutdownLevelResult> + Send>>
            },
            |depth, results| {
                observe_shutdown_level(self.shutdown_observer.as_ref(), depth, results);
            },
        )
        .await;
        let mut cleanup_required = pending_cleanup_failed;
        for (_, results) in level_results {
            for (key, driver, result) in results {
                if result.is_ok() {
                    let mut active = self.active.lock().await;
                    remove_active_if_same(&mut active, &key, &driver);
                } else {
                    cleanup_required = true;
                }
            }
        }
        cleanup_required
            .then_some(())
            .map_or(Ok(()), |()| Err(boundary_error()))
    }

    async fn drain_pending_launches(
        &self,
        launch_guard: &tokio::sync::MutexGuard<'_, ()>,
        deadline: tokio::time::Instant,
        session_filter: Option<SessionId>,
    ) -> bool {
        let pending = self
            .pending_launches
            .lock()
            .await
            .iter()
            .filter(|(_, pending)| session_filter.is_none_or(|id| id == pending.session_id))
            .map(|(attempt, pending)| (*attempt, pending.clone()))
            .collect::<Vec<_>>();
        let mut cleanup_failed = false;
        for (attempt_id, pending) in pending {
            let result = if tokio::time::Instant::now() >= deadline {
                Err(boundary_error_at("driver.pending_launch.deadline"))
            } else {
                match tokio::time::timeout_at(
                    deadline,
                    self.reconcile_pending_launch_locked(launch_guard, attempt_id, pending.epoch),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(boundary_error_at("driver.pending_launch.deadline")),
                }
            };
            let mut registry = self.pending_launches.lock().await;
            finish_pending_reconcile(&mut registry, attempt_id, &result);
            cleanup_failed |= result.is_err();
        }
        cleanup_failed
    }

    async fn shutdown_driver(
        &self,
        driver: Arc<DriverExecutor>,
        deadline: tokio::time::Instant,
    ) -> Result<(), ExecutorError> {
        driver.stopping.close();
        let attempt_id = Uuid::from_slice(&driver.identity.launch_attempt_id)
            .ok()
            .and_then(|id| LaunchAttemptId::from_uuid(id).ok());
        let epoch = navigator_domain::FencingEpoch::new(driver.identity.ownership_epoch).ok();
        let Some((attempt_id, epoch)) = attempt_id.zip(epoch) else {
            return Err(boundary_error());
        };
        let initial_launch = self
            .store
            .load_launch(attempt_id)
            .await
            .map_err(executor_error)?;
        let current_epoch = match self
            .store
            .read_ownership(initial_launch.session_id)
            .await
            .map_err(executor_error)?
        {
            OwnershipSnapshot::Owned { host_id, epoch, .. } if host_id == self.host_id => {
                Some(epoch)
            }
            _ => None,
        };
        let still_authoritative = current_epoch == Some(epoch);
        let watchdog_result = finish_driver_watchdog(
            &driver,
            still_authoritative,
            self.supervisor.ownership_cleanup_budget(),
        )
        .await;
        let stopping = request(b"shutdown-stop", attempt_id);
        let terminal = request(b"shutdown-terminal", attempt_id);
        let completed_watchdog = watchdog_result
            .and_then(Result::ok)
            .and_then(|outcome| completed_watchdog_shutdown(&outcome));
        let durable_cleanup = self
            .store
            .load_launch(attempt_id)
            .await
            .map_err(executor_error)?;
        let stale_identity_gone = stale_watchdog_proves_identity_gone(
            still_authoritative,
            current_epoch,
            completed_watchdog.as_ref(),
            |current_epoch| async move {
                self.supervisor
                    .inspect_for_recovery(attempt_id, self.host_id, current_epoch)
                    .await
                    .map_err(executor_error)
            },
        )
        .await?;
        let result = if stale_identity_gone {
            Ok(())
        } else if let Some(result) = completed_watchdog {
            result
        } else if durable_cleanup.state == navigator_store_api::LaunchState::Stopped {
            Ok(())
        } else if tokio::time::Instant::now() >= deadline {
            Err(boundary_error())
        } else {
            match (stopping, terminal) {
                (Ok(stopping), Ok(terminal)) => {
                    // The Driver RPC is advisory; the Supervisor is the
                    // authoritative, identity-checked cleanup path. Running
                    // them serially consumed part of the caller's deadline
                    // before SIGTERM/SIGKILL even began. A slow Pi stop RPC
                    // could therefore leave less than the configured process
                    // stop budget and persist CleanupRequired although the
                    // exact process exited immediately afterwards.
                    let graceful_driver = Arc::clone(&driver);
                    let graceful =
                        tokio::spawn(async move { graceful_driver.request_stop(attempt_id).await });
                    let result = self
                        .shutdown_attempt(
                            attempt_id,
                            epoch,
                            StopRequestIds { stopping, terminal },
                            deadline,
                        )
                        .await;
                    graceful.abort();
                    let _ = graceful.await;
                    result
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
            }
        };
        if result.is_ok() {
            driver
                .control_socket
                .remove_if_same()
                .map_err(executor_error)?;
        }
        result
    }

    pub async fn disconnect_controls_for_recovery(&self) {
        self.active.lock().await.clear();
    }

    #[expect(
        clippy::too_many_lines,
        reason = "launch admission, durable attach, and authenticated bootstrap form one boundary"
    )]
    async fn driver_for(
        &self,
        session_id: SessionId,
        participant_id: ParticipantId,
        operation_id: Option<OperationId>,
    ) -> Result<Arc<DriverExecutor>, ExecutorError> {
        let epoch = match self
            .store
            .read_ownership(session_id)
            .await
            .map_err(executor_error)?
        {
            OwnershipSnapshot::Owned { host_id, epoch, .. } if host_id == self.host_id => epoch,
            _ => return Err(boundary_error()),
        };
        self.store
            .validate_launch_authority(session_id, self.host_id, epoch)
            .await
            .map_err(executor_error)?;
        let participant = self
            .store
            .load_participant(participant_id)
            .await
            .map_err(executor_error)?;
        let registered = self
            .store
            .load_template(participant.template_id)
            .await
            .map_err(executor_error)?;
        let config = self.config_resolver.resolve(&registered)?;
        let catalog_provider = self
            .trusted_tool_catalog
            .read()
            .map_err(|_| boundary_error())?
            .clone();
        let catalog = catalog_provider
            .catalog(session_id, participant_id, operation_id)
            .await?;
        let base_config_identity = config_identity(&config);
        let resolved_config_identity =
            resolved_driver_identity(base_config_identity, catalog.identity());
        let attempt_id =
            resolved_launch_attempt_for_config(participant_id, epoch, &config, &catalog)?;
        let template = Template::try_from(registered.clone()).map_err(executor_error)?;
        if !template
            .driver_requirement()
            .is_satisfied_by(config.driver_id, &config.offered_capabilities)
        {
            return Err(boundary_error());
        }
        let trusted_configuration = trusted_configuration_with_catalog(
            serde_json::to_value(&registered.trusted_configuration).map_err(executor_error)?,
            catalog.entries,
        )?;
        if let Some(driver) = self
            .active
            .lock()
            .await
            .get(&(participant_id, epoch.get()))
            .cloned()
        {
            if catalog_lifecycle_action(Some(driver.config_identity), resolved_config_identity)
                == CatalogLifecycleAction::Reuse
            {
                return Ok(driver);
            }
        }
        let launch_guard = self.launch_lock.lock().await;
        // A cancelled readiness future may have crossed the durable launch
        // boundary without reaching the active cache. Reconcile that exact
        // attempt before admitting any later launch; an unproven cleanup is a
        // global launch fence, not something a new epoch or catalog may bypass.
        let pending = self
            .pending_launches
            .lock()
            .await
            .iter()
            .map(|(attempt, pending)| (*attempt, pending.clone()))
            .collect::<Vec<_>>();
        for (pending_attempt, pending_launch) in pending {
            self.reconcile_pending_launch_locked(
                &launch_guard,
                pending_attempt,
                pending_launch.epoch,
            )
            .await?;
            self.pending_launches.lock().await.remove(&pending_attempt);
            self.active
                .lock()
                .await
                .remove(&(pending_launch.participant_id, pending_launch.epoch.get()));
        }
        // Everything above this point may have waited behind another launch or
        // reconciled durable cleanup. Re-read every value that determines the
        // launch identity while still holding the admission lock; a stale
        // catalog, template, configuration, or ownership snapshot must never
        // cross the durable launch boundary.
        let current_epoch = match self
            .store
            .read_ownership(session_id)
            .await
            .map_err(executor_error)?
        {
            OwnershipSnapshot::Owned {
                host_id,
                epoch: current,
                ..
            } if host_id == self.host_id && current == epoch => current,
            _ => return Err(boundary_error_at("driver.launch.fenced")),
        };
        self.store
            .validate_launch_authority(session_id, self.host_id, current_epoch)
            .await
            .map_err(executor_error)?;
        let current_participant = self
            .store
            .load_participant(participant_id)
            .await
            .map_err(executor_error)?;
        let current_registered = self
            .store
            .load_template(current_participant.template_id)
            .await
            .map_err(executor_error)?;
        let current_config = self.config_resolver.resolve(&current_registered)?;
        let current_catalog = catalog_provider
            .catalog(session_id, participant_id, operation_id)
            .await?;
        let current_resolved_identity =
            resolved_driver_identity(config_identity(&current_config), current_catalog.identity());
        let current_attempt = resolved_launch_attempt_for_config(
            participant_id,
            current_epoch,
            &current_config,
            &current_catalog,
        )?;
        if current_participant.template_id != participant.template_id
            || current_registered != registered
            || current_resolved_identity != resolved_config_identity
            || current_attempt != attempt_id
        {
            return Err(boundary_error_at("driver.launch.snapshot_changed"));
        }
        let stale_epochs = self
            .active
            .lock()
            .await
            .iter()
            .filter(|((active_participant, active_epoch), _)| {
                active_participant == &participant_id && active_epoch != &epoch.get()
            })
            .map(|(key, driver)| (*key, Arc::clone(driver)))
            .collect::<Vec<_>>();
        for (key, stale) in stale_epochs {
            let deadline = tokio::time::Instant::now() + self.supervisor.configured_stop_budget();
            self.shutdown_driver(Arc::clone(&stale), deadline)
                .await
                .map_err(|_| boundary_error_at("driver.stale.shutdown"))?;
            let mut active = self.active.lock().await;
            remove_active_if_same(&mut active, &key, &stale);
        }
        if let Some(driver) = self
            .active
            .lock()
            .await
            .get(&(participant_id, epoch.get()))
            .cloned()
        {
            if catalog_lifecycle_action(Some(driver.config_identity), resolved_config_identity)
                == CatalogLifecycleAction::Reuse
            {
                return Ok(driver);
            }
            let deadline = tokio::time::Instant::now() + self.supervisor.configured_stop_budget();
            self.shutdown_driver(Arc::clone(&driver), deadline).await?;
            let mut active = self.active.lock().await;
            remove_active_if_same(&mut active, &(participant_id, epoch.get()), &driver);
        }
        if self
            .store
            .cancellation_requested(participant_id)
            .await
            .map_err(executor_error)?
        {
            return Err(boundary_error());
        }
        if !active_cache_has_capacity(self.active.lock().await.len()) {
            return Err(boundary_error_at("driver.active.capacity"));
        }
        for (path, expected) in &config.trusted_artifacts {
            let actual: [u8; 32] =
                Sha256::digest(std::fs::read(path).map_err(executor_error)?).into();
            if &actual != expected {
                return Err(boundary_error());
            }
        }
        let instance_id = InstanceId::from_uuid(derived_uuid(
            b"navigator.driver.instance.v1",
            attempt_id.as_uuid().as_bytes(),
        ))
        .map_err(executor_error)?;
        let control_socket = self.supervisor.managed_control_socket_path(attempt_id);
        if std::os::unix::ffi::OsStrExt::as_bytes(control_socket.as_os_str()).len() > 100 {
            return Err(boundary_error());
        }
        let mut environment = config.environment.clone();
        environment.insert(
            config.control_socket_environment.clone(),
            control_socket.clone().into_os_string(),
        );
        let mut environment_allowlist = config.environment_allowlist.clone();
        environment_allowlist.insert(config.control_socket_environment.clone());
        let plan = LaunchPlan {
            session_id,
            participant_id,
            driver_id: config.driver_id,
            driver_configuration_digest: resolved_config_identity,
            attempt_id,
            instance_id,
            host_id: self.host_id,
            ownership_epoch: epoch,
            prepare_request_id: request(b"prepare", attempt_id)?,
            attach_request_id: request(b"attach", attempt_id)?,
            compensation_request_id: request(b"compensate", attempt_id)?,
            compensation_terminal_request_id: request(b"compensate-terminal", attempt_id)?,
            program: config.program.clone(),
            expected_executable_identity: config.expected_executable_identity,
            arguments: config.arguments.clone(),
            working_directory: config.working_directory.clone(),
            environment,
            environment_allowlist,
            ownership_channel: config.ownership_channel,
            process_io_mode: config.process_io_mode,
            bootstrap_configuration: config.bootstrap_configuration.clone(),
        };
        let pending_cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.pending_launches.lock().await.insert(
            attempt_id,
            PendingLaunch {
                session_id,
                participant_id,
                epoch,
                cancellation: Arc::clone(&pending_cancellation),
            },
        );
        crate::fault_matrix::external_fault_at("launch.external.before_call");
        if let Err(error) = self.supervisor.launch(plan).await {
            // `launch` persists intent before spawning. Its error is therefore
            // ambiguous until the durable attempt has been reconciled; retain
            // the registry entry if reconciliation itself cannot be proven.
            if self
                .reconcile_pending_launch_locked(&launch_guard, attempt_id, epoch)
                .await
                .is_ok()
            {
                self.pending_launches.lock().await.remove(&attempt_id);
            }
            return Err(executor_error(error));
        }
        crate::fault_matrix::external_fault_at("launch.external.after_call");
        let cleanup_ids = StopRequestIds {
            stopping: request(b"bootstrap-stop", attempt_id)?,
            terminal: request(b"bootstrap-terminal", attempt_id)?,
        };
        let deadline = tokio::time::Instant::now() + config.connect_timeout;
        let socket_evidence = loop {
            if pending_cancellation.load(std::sync::atomic::Ordering::Acquire) {
                self.stop_failed_bootstrap(attempt_id, epoch, cleanup_ids)
                    .await?;
                return Err(boundary_error_at("driver.launch.cancelled"));
            }
            match std::fs::symlink_metadata(&control_socket) {
                Ok(metadata) if metadata.file_type().is_socket() => {
                    break ControlSocketEvidence {
                        path: control_socket.clone(),
                        device: metadata.dev(),
                        inode: metadata.ino(),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) | Err(_) => {
                    self.stop_failed_bootstrap(attempt_id, epoch, cleanup_ids)
                        .await?;
                    return Err(boundary_error());
                }
            }
            if tokio::time::Instant::now() >= deadline {
                self.stop_failed_bootstrap(attempt_id, epoch, cleanup_ids)
                    .await?;
                return Err(boundary_error());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        let Some(remaining) = remaining_connect_budget(deadline, tokio::time::Instant::now())
        else {
            self.stop_failed_bootstrap(attempt_id, epoch, cleanup_ids)
                .await?;
            self.pending_launches.lock().await.remove(&attempt_id);
            return Err(boundary_error());
        };
        let bootstrap_request = DriverBootstrapRequest {
            attempt_id,
            host_id: self.host_id,
            epoch,
            socket: control_socket,
            timeout: remaining,
            start_request_id: request(b"driver-start", attempt_id)?,
            ready_request_id: request(b"driver-ready", attempt_id)?,
            trusted_configuration,
            required_capabilities: template
                .driver_requirement()
                .capabilities()
                .iter()
                .map(capability_wire)
                .collect(),
            expected_capabilities: config
                .offered_capabilities
                .iter()
                .map(capability_offer_wire)
                .collect(),
            cleanup_ids,
        };
        crate::fault_matrix::external_fault_at("launch.external.before_identity_proof");
        let bootstrap = tokio::select! {
            result = self.supervisor.connect_start_ready(bootstrap_request) => result,
            () = wait_for_pending_launch_cancellation(Arc::clone(&pending_cancellation)) => {
                self.stop_failed_bootstrap(attempt_id, epoch, cleanup_ids).await?;
                return Err(boundary_error_at("driver.launch.cancelled"));
            }
        };
        let (launch, client, identity) = match bootstrap {
            Ok(value) => value,
            Err(error) => {
                self.cleanup_launched_driver(
                    PostLaunchFailure::Bootstrap,
                    attempt_id,
                    epoch,
                    cleanup_ids,
                    &socket_evidence,
                    None,
                )
                .await?;
                return Err(executor_error(error));
            }
        };
        crate::fault_matrix::external_fault_at("launch.external.after_identity_proof");
        if pending_cancellation.load(std::sync::atomic::Ordering::Acquire) {
            self.cleanup_launched_driver(
                PostLaunchFailure::Bootstrap,
                attempt_id,
                epoch,
                cleanup_ids,
                &socket_evidence,
                None,
            )
            .await?;
            return Err(boundary_error_at("driver.launch.cancelled"));
        }
        if launch.driver_configuration_digest != resolved_config_identity {
            self.cleanup_launched_driver(
                PostLaunchFailure::Digest,
                attempt_id,
                epoch,
                cleanup_ids,
                &socket_evidence,
                None,
            )
            .await?;
            return Err(boundary_error());
        }
        let hierarchy_sink = self
            .hierarchy_sink
            .read()
            .map(|sink| sink.clone())
            .map_err(|_| boundary_error());
        let Ok(hierarchy_sink) = hierarchy_sink else {
            self.cleanup_launched_driver(
                PostLaunchFailure::HierarchySink,
                attempt_id,
                epoch,
                cleanup_ids,
                &socket_evidence,
                None,
            )
            .await?;
            return Err(boundary_error());
        };
        let tool_sink = self
            .tool_sink
            .read()
            .map(|sink| sink.clone())
            .map_err(|_| boundary_error());
        let Ok(tool_sink) = tool_sink else {
            self.cleanup_launched_driver(
                PostLaunchFailure::ToolSink,
                attempt_id,
                epoch,
                cleanup_ids,
                &socket_evidence,
                None,
            )
            .await?;
            return Err(boundary_error());
        };
        let lifecycle_fence = Arc::new(LifecycleFence::default());
        let watchdog_fence = Arc::clone(&lifecycle_fence);
        let watchdog_supervisor = Arc::clone(&self.supervisor);
        let watchdog_host = self.host_id;
        let watchdog = tokio::spawn(async move {
            let _close_on_exit = CloseLifecycleOnDrop(Arc::clone(&watchdog_fence));
            watchdog_supervisor
                .watch_ownership_with_fence(
                    attempt_id,
                    watchdog_host,
                    epoch,
                    StopRequestIds {
                        stopping: request(b"ownership-lost-stop", attempt_id)
                            .expect("derived request is valid"),
                        terminal: request(b"ownership-lost-terminal", attempt_id)
                            .expect("derived request is valid"),
                    },
                    Duration::from_millis(25),
                    Some(&watchdog_fence),
                )
                .await
        });
        let watchdog_abort = watchdog.abort_handle();
        let driver = DriverExecutor::from_supervised(
            client,
            identity,
            &launch,
            socket_evidence.clone(),
            watchdog,
            lifecycle_fence,
            SupervisedDriverMetadata {
                hierarchy_sink,
                tool_sink,
                host_id: self.host_id,
                config_identity: resolved_config_identity,
            },
        );
        let driver = match driver {
            Ok(driver) => Arc::new(driver),
            Err(error) => {
                self.cleanup_launched_driver(
                    PostLaunchFailure::DriverConstruction,
                    attempt_id,
                    epoch,
                    cleanup_ids,
                    &socket_evidence,
                    Some(&watchdog_abort),
                )
                .await?;
                return Err(error);
            }
        };
        let cache_key = (participant_id, epoch.get());
        let cache_collision = {
            let mut active = self.active.lock().await;
            if let std::collections::hash_map::Entry::Vacant(entry) = active.entry(cache_key) {
                entry.insert(Arc::clone(&driver));
                false
            } else {
                true
            }
        };
        if cache_collision {
            self.cleanup_launched_driver(
                PostLaunchFailure::ActiveCache,
                attempt_id,
                epoch,
                cleanup_ids,
                &socket_evidence,
                Some(&watchdog_abort),
            )
            .await?;
            return Err(boundary_error());
        }
        self.pending_launches.lock().await.remove(&attempt_id);
        Ok(driver)
    }

    async fn active_driver_for(
        &self,
        session_id: SessionId,
        participant_id: ParticipantId,
    ) -> Result<Option<Arc<DriverExecutor>>, ExecutorError> {
        let epoch = match self
            .store
            .read_ownership(session_id)
            .await
            .map_err(executor_error)?
        {
            OwnershipSnapshot::Owned { host_id, epoch, .. } if host_id == self.host_id => epoch,
            _ => return Err(boundary_error()),
        };
        self.store
            .validate_launch_authority(session_id, self.host_id, epoch)
            .await
            .map_err(executor_error)?;
        Ok(self
            .active
            .lock()
            .await
            .get(&(participant_id, epoch.get()))
            .cloned())
    }

    async fn driver(
        &self,
        operation: &OperationSnapshot,
    ) -> Result<Arc<DriverExecutor>, ExecutorError> {
        self.driver_for(
            operation.session_id,
            operation.participant_id,
            Some(operation.operation_id),
        )
        .await
    }

    async fn origin_driver(&self, lease: &DeliveryLease) -> Option<Arc<DriverExecutor>> {
        let expected = *lease.instance_id.as_uuid().as_bytes();
        self.active
            .lock()
            .await
            .values()
            .find(|driver| driver.identity.instance_id == expected)
            .cloned()
    }

    async fn reconnect_origin(
        &self,
        lease: &DeliveryLease,
        operation_id: OperationId,
    ) -> Result<(DriverClient, v1::InstanceIdentity), ExecutorError> {
        let launch = self
            .store
            .load_launch(lease.driver_launch_attempt_id)
            .await
            .map_err(executor_error)?;
        if launch.instance_id != Some(lease.instance_id) {
            return Err(boundary_error());
        }
        let registered = self
            .store
            .load_template(
                self.store
                    .load_participant(launch.participant_id)
                    .await
                    .map_err(executor_error)?
                    .template_id,
            )
            .await
            .map_err(executor_error)?;
        let config = self.config_resolver.resolve(&registered)?;
        let operation = self
            .store
            .load_operation(operation_id)
            .await
            .map_err(executor_error)?;
        if operation.session_id != launch.session_id
            || operation.participant_id != launch.participant_id
        {
            return Err(boundary_error());
        }
        let catalog_provider = self
            .trusted_tool_catalog
            .read()
            .map_err(|_| boundary_error())?
            .clone();
        let catalog = catalog_provider
            .catalog(
                operation.session_id,
                operation.participant_id,
                Some(operation.operation_id),
            )
            .await?;
        let resolved_config_identity =
            resolved_driver_identity(config_identity(&config), catalog.identity());
        if launch.driver_configuration_digest != resolved_config_identity {
            return Err(boundary_error());
        }
        let trusted_configuration = trusted_configuration_with_catalog(
            serde_json::to_value(&registered.trusted_configuration).map_err(executor_error)?,
            catalog.entries,
        )?;
        let socket = self
            .supervisor
            .managed_control_socket_path(lease.driver_launch_attempt_id);
        let (_, client, identity) = self
            .supervisor
            .reconnect_ready(DriverBootstrapRequest {
                attempt_id: lease.driver_launch_attempt_id,
                host_id: self.host_id,
                epoch: lease.driver_ownership_epoch,
                socket,
                timeout: config.connect_timeout,
                start_request_id: request(b"driver-start", lease.driver_launch_attempt_id)?,
                ready_request_id: request(b"driver-ready", lease.driver_launch_attempt_id)?,
                trusted_configuration,
                required_capabilities: Template::try_from(registered)
                    .map_err(executor_error)?
                    .driver_requirement()
                    .capabilities()
                    .iter()
                    .map(capability_wire)
                    .collect(),
                expected_capabilities: config
                    .offered_capabilities
                    .iter()
                    .map(capability_offer_wire)
                    .collect(),
                cleanup_ids: StopRequestIds {
                    stopping: request(b"bootstrap-stop", lease.driver_launch_attempt_id)?,
                    terminal: request(b"bootstrap-terminal", lease.driver_launch_attempt_id)?,
                },
            })
            .await
            .map_err(executor_error)?;
        Ok((client, identity))
    }

    async fn stop_failed_bootstrap(
        &self,
        attempt_id: LaunchAttemptId,
        epoch: navigator_domain::FencingEpoch,
        ids: StopRequestIds,
    ) -> Result<(), ExecutorError> {
        let result = match self
            .supervisor
            .stop(attempt_id, self.host_id, epoch, ids)
            .await
            .map_err(executor_error)?
        {
            navigator_supervisor::StopOutcome::Stopped
            | navigator_supervisor::StopOutcome::AlreadyStopped => Ok(()),
            navigator_supervisor::StopOutcome::CleanupRequired => Err(boundary_error()),
        };
        if result.is_ok() {
            self.pending_launches.lock().await.remove(&attempt_id);
        }
        result
    }

    async fn cleanup_launched_driver(
        &self,
        failure: PostLaunchFailure,
        attempt_id: LaunchAttemptId,
        epoch: navigator_domain::FencingEpoch,
        ids: StopRequestIds,
        socket: &ControlSocketEvidence,
        watchdog: Option<&tokio::task::AbortHandle>,
    ) -> Result<(), ExecutorError> {
        let result = run_post_launch_cleanup(
            failure,
            || {
                if let Some(watchdog) = watchdog {
                    watchdog.abort();
                }
            },
            || socket.remove_if_same().map_err(executor_error),
            || {
                self.shutdown_attempt(
                    attempt_id,
                    epoch,
                    ids,
                    tokio::time::Instant::now() + Duration::from_secs(5),
                )
            },
        )
        .await;
        if result.is_ok() {
            self.pending_launches.lock().await.remove(&attempt_id);
        }
        result
    }

    async fn reconcile_pending_launch_locked(
        &self,
        _launch_guard: &tokio::sync::MutexGuard<'_, ()>,
        attempt_id: LaunchAttemptId,
        epoch: FencingEpoch,
    ) -> Result<(), ExecutorError> {
        // While holding the global launch boundary, durable absence proves this
        // pending entry was cancelled before prepare persisted: no concurrent
        // launch can cross into an untracked process here.
        if pending_launch_was_never_prepared(self.store.load_launch(attempt_id).await)? {
            return Ok(());
        }
        let ids = ReconcileRequestIds {
            cleanup: request(b"pending-cleanup", attempt_id)?,
            stop: StopRequestIds {
                stopping: request(b"pending-stop", attempt_id)?,
                terminal: request(b"pending-terminal", attempt_id)?,
            },
        };
        classify_pending_reconcile(
            self.supervisor
                .reconcile_launch(attempt_id, self.host_id, epoch, ids)
                .await
                .map_err(executor_error)?,
        )
    }

    async fn shutdown_attempt(
        &self,
        attempt_id: LaunchAttemptId,
        epoch: navigator_domain::FencingEpoch,
        ids: StopRequestIds,
        deadline: tokio::time::Instant,
    ) -> Result<(), ExecutorError> {
        match self
            .supervisor
            .stop_with_deadline(attempt_id, self.host_id, epoch, ids, deadline)
            .await
            .map_err(executor_error)?
        {
            navigator_supervisor::StopOutcome::Stopped
            | navigator_supervisor::StopOutcome::AlreadyStopped => Ok(()),
            navigator_supervisor::StopOutcome::CleanupRequired => Err(boundary_error()),
        }
    }

    async fn validate_current(
        &self,
        operation: &OperationSnapshot,
        instance: &AuthenticatedDriver,
    ) -> Result<(), ExecutorError> {
        match self
            .store
            .read_ownership(operation.session_id)
            .await
            .map_err(executor_error)?
        {
            OwnershipSnapshot::Owned { host_id, epoch, .. }
                if host_id == self.host_id && instance.identity.ownership_epoch == epoch.get() =>
            {
                self.store
                    .validate_launch_authority(operation.session_id, self.host_id, epoch)
                    .await
                    .map_err(executor_error)
            }
            _ => Err(boundary_error()),
        }
    }
}

/// Converts only a proven terminal watchdog outcome into a shutdown result.
///
/// A watchdog error (including a transient Store outage) is inconclusive: the
/// caller must continue through the explicit, deadline-bounded stop path.  In
/// contrast, `CleanupRequired` is a durable fail-closed outcome and must not be
/// hidden by another stop attempt.
fn completed_watchdog_shutdown(
    outcome: &Result<navigator_supervisor::StopOutcome, navigator_supervisor::SupervisorError>,
) -> Option<Result<(), ExecutorError>> {
    match outcome {
        Ok(
            navigator_supervisor::StopOutcome::Stopped
            | navigator_supervisor::StopOutcome::AlreadyStopped,
        ) => Some(Ok(())),
        Ok(navigator_supervisor::StopOutcome::CleanupRequired) => Some(Err(boundary_error())),
        Err(_) => None,
    }
}

/// Accepts a stale watchdog cleanup obligation only when a fresh owner can
/// inspect the exact old launch evidence and prove that identity is gone.
async fn stale_watchdog_proves_identity_gone<F, Fut>(
    still_authoritative: bool,
    current_epoch: Option<FencingEpoch>,
    completed_watchdog: Option<&Result<(), ExecutorError>>,
    inspect_old_evidence: F,
) -> Result<bool, ExecutorError>
where
    F: FnOnce(FencingEpoch) -> Fut,
    Fut: Future<Output = Result<LiveObservation, ExecutorError>>,
{
    if still_authoritative || !completed_watchdog.is_some_and(Result::is_err) {
        return Ok(false);
    }
    let Some(current_epoch) = current_epoch else {
        return Ok(false);
    };
    Ok(matches!(
        inspect_old_evidence(current_epoch).await?,
        LiveObservation::Absent | LiveObservation::DifferentInstance
    ))
}

async fn finish_driver_watchdog(
    driver: &DriverExecutor,
    still_authoritative: bool,
    stale_cleanup_budget: Duration,
) -> Option<
    Result<
        Result<navigator_supervisor::StopOutcome, navigator_supervisor::SupervisorError>,
        tokio::task::JoinError,
    >,
> {
    let watchdog = driver.watchdog.lock().await.take()?;
    Some(finish_watchdog_handle(watchdog, still_authoritative, stale_cleanup_budget).await)
}

async fn finish_watchdog_handle(
    mut watchdog: tokio::task::JoinHandle<
        Result<navigator_supervisor::StopOutcome, navigator_supervisor::SupervisorError>,
    >,
    still_authoritative: bool,
    stale_cleanup_budget: Duration,
) -> Result<
    Result<navigator_supervisor::StopOutcome, navigator_supervisor::SupervisorError>,
    tokio::task::JoinError,
> {
    if still_authoritative {
        watchdog.abort();
        return watchdog.await;
    }
    let deadline = tokio::time::Instant::now() + stale_cleanup_budget;
    if let Ok(result) = tokio::time::timeout_at(deadline, &mut watchdog).await {
        result
    } else {
        watchdog.abort();
        watchdog.await
    }
}

fn bounded_hierarchy_shutdown_budget(per_attempt: Duration, active_count: usize) -> Duration {
    let attempts = u32::try_from(active_count).unwrap_or(u32::MAX).max(1);
    per_attempt.saturating_mul(attempts)
}

pub struct DriverTransitionContexts {
    pub host_id: HostId,
}

impl TransitionContextFactory for DriverTransitionContexts {
    fn context(
        &self,
        operation_id: OperationId,
        action: OperationAction,
        ordinal: u32,
    ) -> navigator_store_api::RequestContext {
        let mut digest = Sha256::new();
        digest.update(b"navigator.operation-transition.v1");
        digest.update(operation_id.as_uuid().as_bytes());
        digest.update((action as u32).to_be_bytes());
        digest.update(ordinal.to_be_bytes());
        let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().expect("fixed digest");
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        navigator_store_api::RequestContext::new(
            RequestId::from_uuid(Uuid::from_bytes(bytes)).expect("derived identity is non-nil"),
            self.host_id,
        )
    }
}

#[derive(Clone)]
pub struct AuthenticatedDriver {
    channels: Arc<RwLock<Arc<DriverChannels>>>,
    identity: v1::InstanceIdentity,
    sequence: Arc<Mutex<u64>>,
    pending_report: Arc<Mutex<Option<PendingReport>>>,
}

#[derive(Clone)]
struct PendingReport {
    event_id: Vec<u8>,
    sequence: u64,
    operation_id: OperationId,
    message_id: MessageId,
    delivery_attempt_id: DeliveryAttemptId,
    request: Option<PendingRequest>,
}

#[derive(Clone)]
enum PendingRequest {
    Question(Capability),
    Approval(AuthenticatedApprovalRequest),
}

impl AuthenticatedDriver {
    #[must_use]
    pub fn ownership_epoch(&self) -> u64 {
        self.identity.ownership_epoch
    }
}

impl<S, C> SupervisedDriverExecutor<S, C>
where
    S: MailboxStore + InstanceStore + OperationStore + HierarchyStore + 'static,
    C: CredentialSource + Sync,
{
    async fn ensure_operation_ready(
        &self,
        operation: &OperationSnapshot,
    ) -> Result<AuthenticatedDriver, ExecutorError> {
        let instance = self
            .driver(operation)
            .await?
            .ensure_ready(operation)
            .await?;
        self.validate_current(operation, &instance).await?;
        Ok(instance)
    }
    async fn next_operation_report(
        &self,
        instance: &AuthenticatedDriver,
        operation: &OperationSnapshot,
    ) -> Result<ExecutorReport, ExecutorError> {
        self.validate_current(operation, instance).await?;
        let driver = self.driver(operation).await?;
        if instance.identity != driver.identity {
            return Err(boundary_error());
        }
        crate::fault_matrix::external_fault_at("report.external.before_call");
        let report = driver.next_report(instance, operation).await;
        crate::fault_matrix::external_fault_at("report.external.after_call");
        crate::fault_matrix::external_fault_at("report.external.before_correlation_proof");
        match report {
            Ok(report) => {
                crate::fault_matrix::external_fault_at("report.external.after_correlation_proof");
                Ok(report)
            }
            Err(error) if error.message == "driver.observe.io_failed" => {
                self.validate_current(operation, instance).await?;
                let current = self
                    .active
                    .lock()
                    .await
                    .get(&(operation.participant_id, instance.identity.ownership_epoch))
                    .cloned()
                    .ok_or_else(boundary_error)?;
                if !Arc::ptr_eq(&current, &driver) || current.identity != instance.identity {
                    return Err(boundary_error_at("driver.observe.reconnect_fenced"));
                }
                let (origin_channels, replacement_channels) =
                    driver.prepare_reconnected_channels(instance).await?;
                self.validate_current(operation, instance).await?;
                let launch_attempt = domain_id(
                    &instance.identity.launch_attempt_id,
                    LaunchAttemptId::from_uuid,
                )?;
                let launch = self
                    .store
                    .load_launch(launch_attempt)
                    .await
                    .map_err(executor_error)?;
                validate_supervised_identity(&instance.identity, &launch)?;
                let current = self
                    .active
                    .lock()
                    .await
                    .get(&(operation.participant_id, instance.identity.ownership_epoch))
                    .cloned()
                    .ok_or_else(boundary_error)?;
                if !Arc::ptr_eq(&current, &driver) || current.identity != instance.identity {
                    return Err(boundary_error_at("driver.observe.reconnect_fenced"));
                }
                if !publish_if_current(
                    &driver.channels,
                    &origin_channels,
                    replacement_channels,
                    &driver.stopping,
                )? {
                    return Err(boundary_error_at("driver.observe.reconnect_fenced"));
                }
                driver.next_report(instance, operation).await
            }
            Err(error) => Err(error),
        }
    }

    async fn commit_pending_request(
        &self,
        instance: &AuthenticatedDriver,
        operation_id: OperationId,
        message_id: MessageId,
    ) -> Result<(), ExecutorError> {
        let pending = instance
            .pending_report
            .lock()
            .map_err(|_| boundary_error())?
            .as_ref()
            .filter(|pending| {
                pending.operation_id == operation_id && pending.message_id == message_id
            })
            .cloned()
            .ok_or_else(boundary_error)?;
        match pending.request.clone().ok_or_else(boundary_error)? {
            PendingRequest::Question(code) => {
                let sink = self
                    .hierarchy_sink
                    .read()
                    .map_err(|_| boundary_error())?
                    .clone()
                    .ok_or_else(boundary_error)?;
                sink.question(
                    hierarchy_caller(&instance.identity, self.host_id)?,
                    pending.event_id,
                    operation_id,
                    message_id,
                    code,
                )
                .await
            }
            PendingRequest::Approval(request) => {
                let sink = self
                    .approval_sink
                    .read()
                    .map_err(|_| boundary_error())?
                    .clone();
                dispatch_approval_request(
                    sink,
                    hierarchy_caller(&instance.identity, self.host_id)?,
                    &pending,
                    request,
                )
                .await
            }
        }
    }
    async fn remind_operation(
        &self,
        instance: &AuthenticatedDriver,
        operation: &OperationSnapshot,
    ) -> Result<(), ExecutorError> {
        self.validate_current(operation, instance).await?;
        let driver = self.driver(operation).await?;
        if instance.identity != driver.identity {
            return Err(boundary_error());
        }
        driver.remind(instance, operation).await
    }
}

impl<S, C> OperationExecutor for MailboxBackedOperationExecutor<S, C>
where
    S: MailboxStore + InstanceStore + OperationStore + HierarchyStore + ApprovalStore + 'static,
    C: CredentialSource + Sync,
{
    type AuthenticatedInstance = AuthenticatedDriver;

    async fn ensure_ready(
        &self,
        operation: &OperationSnapshot,
    ) -> Result<AuthenticatedDriver, ExecutorError> {
        self.inner.ensure_operation_ready(operation).await
    }

    async fn deliver(
        &self,
        permit: &AdmissionPermit,
        instance: &AuthenticatedDriver,
        operation: &OperationSnapshot,
        input: &[u8],
    ) -> Result<DeliveryAcceptance, ExecutorError> {
        permit.check().map_err(executor_error)?;
        let persisted = self
            .store
            .load_operation_input(operation.operation_id)
            .await
            .map_err(executor_error)?;
        if persisted.as_slice() != input {
            return Err(boundary_error());
        }
        self.inner.validate_current(operation, instance).await?;
        let instance_id = domain_id(&instance.identity.instance_id, InstanceId::from_uuid)?;
        let launch_attempt_id = domain_id(
            &instance.identity.launch_attempt_id,
            LaunchAttemptId::from_uuid,
        )?;
        let epoch = FencingEpoch::new(instance.identity.ownership_epoch).map_err(executor_error)?;
        let deadline = tokio::time::Instant::now() + self.delivery_budget;
        for _ in 0..self.max_delivery_steps {
            let delivery_message = self
                .store
                .load_message(operation.input_message_id)
                .await
                .map_err(executor_error)?;
            if delivery_message.session_id != operation.session_id
                || delivery_message.destination != operation.participant_id
                || delivery_message.source != operation.participant_id
                || delivery_message.correlation.operation_id != Some(operation.operation_id)
                || !matches!(
                    delivery_message.envelope.body(),
                    MessageBody::OperationInput { operation_id, input_digest }
                        if *operation_id == operation.operation_id
                            && *input_digest == operation.input_digest
                )
            {
                return Err(boundary_error());
            }
            match delivery_message.state {
                MessageDeliveryState::Accepted { .. } => {
                    return Ok(DeliveryAcceptance::Accepted);
                }
                MessageDeliveryState::DeadLetter { .. } => {
                    return Ok(DeliveryAcceptance::NotAccepted);
                }
                MessageDeliveryState::Uncertain { .. } => {
                    return Ok(DeliveryAcceptance::Unknown);
                }
                MessageDeliveryState::Queued
                | MessageDeliveryState::RetryScheduled { .. }
                | MessageDeliveryState::Leased { .. }
                | MessageDeliveryState::AcceptancePending { .. }
                | MessageDeliveryState::AcceptanceUnknown { .. } => {}
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(boundary_error());
            }
            let step = self
                .worker
                .drive_once(
                    permit,
                    operation.session_id,
                    epoch,
                    operation.participant_id,
                    instance_id,
                    launch_attempt_id,
                )
                .await
                .map_err(executor_error)?;
            match step {
                DeliveryStep::Accepted(id) if id == operation.input_message_id => {
                    return Ok(DeliveryAcceptance::Accepted);
                }
                DeliveryStep::DeadLetter(id) if id == operation.input_message_id => {
                    return Ok(DeliveryAcceptance::NotAccepted);
                }
                DeliveryStep::Uncertain(id) if id == operation.input_message_id => {
                    return Ok(DeliveryAcceptance::Unknown);
                }
                DeliveryStep::Empty | DeliveryStep::RetryScheduled(_) => {
                    permit.check().map_err(executor_error)?;
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    tokio::time::sleep(remaining.min(Duration::from_millis(10))).await;
                }
                DeliveryStep::Accepted(_)
                | DeliveryStep::DeadLetter(_)
                | DeliveryStep::Uncertain(_)
                | DeliveryStep::ReconciliationRequired(_) => {}
            }
        }
        Err(boundary_error())
    }

    async fn next_report(
        &self,
        instance: &AuthenticatedDriver,
        operation: &OperationSnapshot,
    ) -> Result<ExecutorReport, ExecutorError> {
        let report = self
            .inner
            .next_operation_report(instance, operation)
            .await?;
        if let Some((operation_id, message_id)) = report_identity(&report) {
            let delivery_attempt_id = instance
                .pending_report
                .lock()
                .map_err(|_| boundary_error())?
                .as_ref()
                .filter(|pending| {
                    pending.operation_id == operation_id && pending.message_id == message_id
                })
                .map(|pending| pending.delivery_attempt_id)
                .ok_or_else(boundary_error)?;
            if let Err(error) = self
                .accepted_causal_message(
                    operation,
                    operation_id,
                    message_id,
                    delivery_attempt_id,
                    instance,
                )
                .await
            {
                discard_pending_report(instance, operation_id, message_id, delivery_attempt_id)?;
                return Err(error);
            }
            if matches!(report, ExecutorReport::Waiting { .. }) {
                if let Err(error) = self
                    .inner
                    .commit_pending_request(instance, operation_id, message_id)
                    .await
                {
                    discard_pending_report(
                        instance,
                        operation_id,
                        message_id,
                        delivery_attempt_id,
                    )?;
                    return Err(error);
                }
            }
        }
        Ok(report)
    }

    async fn acknowledge_report(
        &self,
        instance: &AuthenticatedDriver,
        operation_id: OperationId,
        message_id: MessageId,
    ) -> Result<(), ExecutorError> {
        acknowledge_pending_report(instance, operation_id, message_id)
    }

    async fn remind(
        &self,
        instance: &AuthenticatedDriver,
        operation: &OperationSnapshot,
    ) -> Result<(), ExecutorError> {
        self.inner.remind_operation(instance, operation).await
    }

    async fn drive_cancellation(
        &self,
        permit: &AdmissionPermit,
        operation: &OperationSnapshot,
        notification: &MessageSnapshot,
    ) -> Result<(), ExecutorError> {
        permit.check().map_err(executor_error)?;
        let driver = self
            .inner
            .active_driver_for(operation.session_id, operation.participant_id)
            .await?
            .ok_or_else(boundary_error)?;
        let instance_id = domain_id(&driver.identity.instance_id, InstanceId::from_uuid)?;
        let launch_attempt_id = domain_id(
            &driver.identity.launch_attempt_id,
            LaunchAttemptId::from_uuid,
        )?;
        let epoch = FencingEpoch::new(driver.identity.ownership_epoch).map_err(executor_error)?;
        for _ in 0..self.max_delivery_steps {
            let current = self
                .store
                .load_message(notification.message_id)
                .await
                .map_err(executor_error)?;
            if current.state.is_terminal() {
                return Ok(());
            }
            match self
                .worker
                .drive_once(
                    permit,
                    operation.session_id,
                    epoch,
                    operation.participant_id,
                    instance_id,
                    launch_attempt_id,
                )
                .await
                .map_err(executor_error)?
            {
                DeliveryStep::Accepted(id)
                | DeliveryStep::DeadLetter(id)
                | DeliveryStep::Uncertain(id)
                    if id == notification.message_id =>
                {
                    return Ok(());
                }
                DeliveryStep::Empty | DeliveryStep::RetryScheduled(_) => {
                    tokio::task::yield_now().await;
                }
                _ => {}
            }
        }
        Err(boundary_error())
    }

    async fn shutdown_until(&self, deadline: tokio::time::Instant) -> Result<(), ExecutorError> {
        self.inner.shutdown_with_deadline(deadline).await
    }

    async fn shutdown_session_until(
        &self,
        session_id: SessionId,
        deadline: tokio::time::Instant,
    ) -> Result<(), ExecutorError> {
        self.inner
            .shutdown_session_with_deadline(session_id, deadline)
            .await
    }
}

fn domain_id<T>(
    value: &[u8],
    make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
) -> Result<T, ExecutorError> {
    let uuid = Uuid::from_slice(value).map_err(executor_error)?;
    make(uuid).map_err(executor_error)
}

async fn join_all<T>(futures: Vec<Pin<Box<dyn Future<Output = T> + Send + '_>>>) -> Vec<T> {
    let mut futures = futures.into_iter().map(Some).collect::<Vec<_>>();
    let mut results = (0..futures.len()).map(|_| None).collect::<Vec<_>>();
    std::future::poll_fn(|context| {
        let mut pending = false;
        for (index, slot) in futures.iter_mut().enumerate() {
            let Some(future) = slot.as_mut() else {
                continue;
            };
            match future.as_mut().poll(context) {
                std::task::Poll::Ready(value) => {
                    results[index] = Some(value);
                    *slot = None;
                }
                std::task::Poll::Pending => pending = true,
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(
                results
                    .iter_mut()
                    .map(|value| value.take().expect("completed future has a result"))
                    .collect(),
            )
        }
    })
    .await
}

fn group_by_depth<T>(entries: impl IntoIterator<Item = (u32, T)>) -> BTreeMap<u32, Vec<T>> {
    let mut levels = BTreeMap::new();
    for (depth, value) in entries {
        levels.entry(depth).or_insert_with(Vec::new).push(value);
    }
    levels
}

async fn execute_descendants_first<'a, T, R, F, H>(
    levels: BTreeMap<u32, Vec<T>>,
    mut execute: F,
    mut level_completed: H,
) -> Vec<(u32, Vec<R>)>
where
    T: 'a,
    R: 'a,
    F: FnMut(T) -> Pin<Box<dyn Future<Output = R> + Send + 'a>>,
    H: FnMut(u32, &[R]),
{
    let mut results = Vec::new();
    for (depth, level) in levels.into_iter().rev() {
        let completed = join_all(level.into_iter().map(&mut execute).collect()).await;
        level_completed(depth, &completed);
        results.push((depth, completed));
    }
    results
}

#[cfg(test)]
fn participant_matches_session(
    participants: &HashMap<ParticipantId, navigator_store_api::ParticipantSnapshot>,
    participant_id: ParticipantId,
    session_filter: Option<SessionId>,
) -> bool {
    session_filter.is_none_or(|session_id| {
        participants
            .get(&participant_id)
            .is_some_and(|participant| participant.session_id == session_id)
    })
}

impl<S, C> MailboxDriver for SupervisedDriverExecutor<S, C>
where
    S: MailboxStore + InstanceStore + OperationStore + HierarchyStore + ApprovalStore + 'static,
    C: CredentialSource + Sync,
{
    #[expect(
        clippy::too_many_lines,
        reason = "delivery validates the complete causal envelope around one external call"
    )]
    async fn deliver(
        &self,
        message: &MessageSnapshot,
        lease: &DeliveryLease,
        call_timeout: Duration,
    ) -> Result<AcceptanceObservation, DeliveryDriverError> {
        let driver = self
            .driver_for(
                message.session_id,
                message.destination,
                message.correlation.operation_id,
            )
            .await
            .map_err(|_| DeliveryDriverError)?;
        validate_mailbox_binding(&driver.identity, message, lease)?;
        let client = driver.delivery_control()?;
        let identity = driver.identity.clone();
        let request_id = derived_id(
            b"navigator.driver.mailbox-deliver.v1",
            &lease.attempt_id.as_uuid(),
        );
        let message_id = message.message_id.as_uuid().as_bytes().to_vec();
        let attempt_id = lease.attempt_id.as_uuid().as_bytes().to_vec();
        let operation_id = message
            .correlation
            .operation_id
            .map_or_else(Vec::new, |value| value.as_uuid().as_bytes().to_vec());
        if matches!(
            message.envelope.body(),
            MessageBody::Control {
                command: navigator_domain::ControlMessageKind::Cancel,
                operation_id: control_operation,
            } if message.correlation.operation_id == Some(*control_operation)
        ) {
            let proof_digest =
                mailbox_acceptance_proof(message.message_id, lease, &driver.identity);
            return deliver_driver_cancel(
                client,
                identity,
                request_id,
                operation_id,
                call_timeout,
                proof_digest,
            )
            .await;
        }
        let payload = match message.envelope.body() {
            MessageBody::OperationInput {
                operation_id,
                input_digest,
            } => {
                let operation = self
                    .store
                    .load_operation(*operation_id)
                    .await
                    .map_err(|_| DeliveryDriverError)?;
                let input = self
                    .store
                    .load_operation_input(*operation_id)
                    .await
                    .map_err(|_| DeliveryDriverError)?;
                let actual_digest = *SemanticDigest::v1(
                    &Capability::new("operation.input.v1").expect("static capability"),
                    input.as_slice(),
                )
                .as_bytes();
                if message.correlation.operation_id != Some(*operation_id)
                    || operation.session_id != message.session_id
                    || operation.participant_id != message.destination
                    || operation.input_message_id != message.message_id
                    || operation.input_digest != *input_digest
                    || &actual_digest != input_digest
                {
                    return Err(DeliveryDriverError);
                }
                input.as_slice().to_vec()
            }
            MessageBody::Question { .. }
            | MessageBody::OperationOutcome { .. }
            | MessageBody::CorrelatedFeedback { .. }
            | MessageBody::Control { .. } => message.envelope.as_bytes().to_vec(),
            MessageBody::ApprovalDecision { .. } => {
                approval_decision_payload(self.store.as_ref(), message).await?
            }
        };
        crate::fault_matrix::external_fault_at("delivery.external.before_call");
        let acceptance = spawn_blocking(move || {
            let mut client = client.lock().map_err(|_| DeliveryDriverError)?;
            client
                .set_io_timeout(driver_io_timeout(call_timeout))
                .map_err(|_| DeliveryDriverError)?;
            client
                .deliver_attempt(
                    request_id,
                    identity,
                    message_id,
                    attempt_id,
                    operation_id,
                    payload,
                )
                .map_err(|_| DeliveryDriverError)
        })
        .await
        .map_err(|_| DeliveryDriverError)??;
        crate::fault_matrix::external_fault_at("delivery.external.after_call");
        crate::fault_matrix::external_fault_at("delivery.external.before_acceptance_proof");
        let observation = acceptance_observation(acceptance, message, lease, &driver.identity);
        crate::fault_matrix::external_fault_at("delivery.external.after_acceptance_proof");
        observation
    }

    async fn query_acceptance(
        &self,
        message_id: MessageId,
        lease: &DeliveryLease,
        call_timeout: Duration,
    ) -> Result<AcceptanceObservation, DeliveryDriverError> {
        let operation_id = self
            .store
            .load_message(message_id)
            .await
            .map_err(|_| DeliveryDriverError)?
            .correlation
            .operation_id
            .ok_or(DeliveryDriverError)?;
        let origin = self.origin_driver(lease).await;
        let (client, identity, attached) = if let Some(driver) = origin.as_ref() {
            (driver.delivery_control()?, driver.identity.clone(), true)
        } else {
            let (client, identity) = self
                .reconnect_origin(lease, operation_id)
                .await
                .map_err(|_| DeliveryDriverError)?;
            (Arc::new(Mutex::new(client)), identity, false)
        };
        if identity.instance_id != lease.instance_id.as_uuid().as_bytes()
            || identity.launch_attempt_id != lease.driver_launch_attempt_id.as_uuid().as_bytes()
            || identity.ownership_epoch != lease.driver_ownership_epoch.get()
        {
            return Err(DeliveryDriverError);
        }
        let mut proof_identity = identity.clone();
        let message = message_id.as_uuid().as_bytes().to_vec();
        let attempt = lease.attempt_id.as_uuid().as_bytes().to_vec();
        let first_message = message.clone();
        let first_attempt = attempt.clone();
        let first_identity = identity.clone();
        let first = query_driver_acceptance(
            client,
            first_identity,
            first_message,
            first_attempt,
            if attached {
                call_timeout.min(Duration::from_millis(50))
            } else {
                call_timeout
            },
        )
        .await;
        let acceptance = match first {
            Ok(value) => value,
            Err(_) if attached => {
                let reconnect_deadline = tokio::time::Instant::now()
                    + call_timeout.saturating_sub(Duration::from_millis(20));
                let (client, identity) = loop {
                    match self.reconnect_origin(lease, operation_id).await {
                        Ok(connected) => break connected,
                        Err(_) if tokio::time::Instant::now() < reconnect_deadline => {
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                        Err(_) => return Err(DeliveryDriverError),
                    }
                };
                proof_identity = identity.clone();
                let replacement = if let Some(origin) = origin.as_ref() {
                    origin
                        .publish_reconnected_pair(client, &identity)
                        .map_err(|_| DeliveryDriverError)?
                } else {
                    Arc::new(Mutex::new(client))
                };
                query_driver_acceptance(replacement, identity, message, attempt, call_timeout)
                    .await?
            }
            Err(error) => return Err(error),
        };
        Ok(match acceptance {
            v1::Acceptance::Accepted => AcceptanceObservation::Accepted {
                proof_digest: mailbox_acceptance_proof(message_id, lease, &proof_identity),
            },
            v1::Acceptance::NotAccepted => AcceptanceObservation::NotAccepted,
            v1::Acceptance::Unknown => AcceptanceObservation::Unknown,
            v1::Acceptance::Unspecified => return Err(DeliveryDriverError),
        })
    }
}

async fn query_driver_acceptance(
    client: Arc<Mutex<DriverClient>>,
    identity: v1::InstanceIdentity,
    message: Vec<u8>,
    attempt: Vec<u8>,
    call_timeout: Duration,
) -> Result<v1::Acceptance, DeliveryDriverError> {
    spawn_blocking(move || {
        let mut client = client.lock().map_err(|_| DeliveryDriverError)?;
        client
            .set_io_timeout(driver_io_timeout(call_timeout))
            .map_err(|_| DeliveryDriverError)?;
        client
            .query_acceptance(identity, message, &attempt)
            .map_err(|_| DeliveryDriverError)
    })
    .await
    .map_err(|_| DeliveryDriverError)?
}

fn driver_io_timeout(call_timeout: Duration) -> Duration {
    call_timeout
        .saturating_sub(Duration::from_millis(10))
        .max(Duration::from_millis(1))
}

fn validate_mailbox_binding(
    identity: &v1::InstanceIdentity,
    message: &MessageSnapshot,
    lease: &DeliveryLease,
) -> Result<(), DeliveryDriverError> {
    if identity.session_id != message.session_id.as_uuid().as_bytes()
        || identity.participant_id != message.destination.as_uuid().as_bytes()
        || identity.instance_id != lease.instance_id.as_uuid().as_bytes()
        || identity.launch_attempt_id != lease.driver_launch_attempt_id.as_uuid().as_bytes()
        || identity.ownership_epoch != lease.driver_ownership_epoch.get()
        || lease.ownership_epoch != lease.driver_ownership_epoch
    {
        return Err(DeliveryDriverError);
    }
    Ok(())
}

fn approval_decision_matches(
    message: &MessageSnapshot,
    request: &navigator_domain::ApprovalRequest,
    grant: Option<&navigator_domain::ApprovalGrant>,
) -> bool {
    let MessageBody::ApprovalDecision {
        approval_id,
        operation_id,
        status,
        grant_id,
    } = message.envelope.body()
    else {
        return false;
    };
    let status_is_exact = match status {
        ApprovalStatus::Granted => match (grant_id, grant) {
            (Some(grant_id), Some(grant)) => {
                request.grant_id == Some(*grant_id)
                    && grant.id == *grant_id
                    && grant.request_id == *approval_id
                    && grant.session_id == message.session_id
                    && grant.subject_id == message.destination
                    && grant.operation_id == *operation_id
                    && grant.capability == request.capability
                    && grant.resource_hash == request.resource.digest()
            }
            _ => false,
        },
        ApprovalStatus::Denied => {
            grant_id.is_none() && grant.is_none() && request.grant_id.is_none()
        }
        ApprovalStatus::Pending
        | ApprovalStatus::Consumed
        | ApprovalStatus::Expired
        | ApprovalStatus::Revoked => false,
    };
    status_is_exact
        && request.id == *approval_id
        && request.status == *status
        && request.session_id == message.session_id
        && request.requester_id == message.destination
        && request.coordinator_id == message.source
        && request.operation_id == *operation_id
        && message.correlation.operation_id == Some(*operation_id)
        && message.correlation.in_reply_to == Some(request.source_message_id)
}

async fn approval_decision_payload<S: ApprovalStore>(
    store: &S,
    message: &MessageSnapshot,
) -> Result<Vec<u8>, DeliveryDriverError> {
    let MessageBody::ApprovalDecision {
        approval_id,
        status,
        grant_id,
        ..
    } = message.envelope.body()
    else {
        return Err(DeliveryDriverError);
    };
    let request = store
        .load_approval_request(*approval_id)
        .await
        .map_err(|_| DeliveryDriverError)?;
    let grant = if *status == ApprovalStatus::Granted {
        Some(
            store
                .load_approval_grant((*grant_id).ok_or(DeliveryDriverError)?)
                .await
                .map_err(|_| DeliveryDriverError)?,
        )
    } else {
        None
    };
    if !approval_decision_matches(message, &request, grant.as_ref()) {
        return Err(DeliveryDriverError);
    }
    Ok(message.envelope.as_bytes().to_vec())
}

fn acceptance_observation(
    acceptance: v1::Acceptance,
    message: &MessageSnapshot,
    lease: &DeliveryLease,
    identity: &v1::InstanceIdentity,
) -> Result<AcceptanceObservation, DeliveryDriverError> {
    Ok(match acceptance {
        v1::Acceptance::Accepted => AcceptanceObservation::Accepted {
            proof_digest: mailbox_acceptance_proof(message.message_id, lease, identity),
        },
        v1::Acceptance::NotAccepted => AcceptanceObservation::NotAccepted,
        v1::Acceptance::Unknown => AcceptanceObservation::Unknown,
        v1::Acceptance::Unspecified => return Err(DeliveryDriverError),
    })
}

async fn deliver_driver_cancel(
    client: Arc<std::sync::Mutex<DriverClient>>,
    identity: v1::InstanceIdentity,
    request_id: Vec<u8>,
    operation_id: Vec<u8>,
    call_timeout: Duration,
    proof_digest: [u8; 32],
) -> Result<AcceptanceObservation, DeliveryDriverError> {
    crate::fault_matrix::external_fault_at("cancellation.external.before_call");
    let disposition = spawn_blocking(move || {
        let mut client = client.lock().map_err(|_| DeliveryDriverError)?;
        client
            .set_io_timeout(driver_io_timeout(call_timeout))
            .map_err(|_| DeliveryDriverError)?;
        client
            .cancel(request_id, identity, operation_id)
            .map_err(|_| DeliveryDriverError)
    })
    .await
    .map_err(|_| DeliveryDriverError)??;
    crate::fault_matrix::external_fault_at("cancellation.external.after_call");
    crate::fault_matrix::external_fault_at("cancellation.external.before_stop_proof");
    let observation = match disposition {
        v1::CancelDisposition::CancelRequested | v1::CancelDisposition::AlreadyTerminal => {
            Ok(AcceptanceObservation::Accepted { proof_digest })
        }
        v1::CancelDisposition::CancelUnknown => Ok(AcceptanceObservation::Unknown),
        v1::CancelDisposition::Unspecified => Err(DeliveryDriverError),
    };
    crate::fault_matrix::external_fault_at("cancellation.external.after_stop_proof");
    observation
}

fn mailbox_acceptance_proof(
    message_id: MessageId,
    lease: &DeliveryLease,
    identity: &v1::InstanceIdentity,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"navigator.mailbox.acceptance-proof.v1");
    digest.update(message_id.as_uuid().as_bytes());
    digest.update(lease.attempt_id.as_uuid().as_bytes());
    digest.update(lease.driver_launch_attempt_id.as_uuid().as_bytes());
    digest.update(&identity.instance_id);
    digest.update(lease.driver_ownership_epoch.get().to_be_bytes());
    digest.finalize().into()
}

impl DriverExecutor {
    fn channel_pair(&self) -> Result<Arc<DriverChannels>, ExecutorError> {
        self.channels
            .read()
            .map(|channels| Arc::clone(&channels))
            .map_err(|_| boundary_error())
    }

    fn delivery_control(&self) -> Result<Arc<Mutex<DriverClient>>, DeliveryDriverError> {
        self.channel_pair()
            .map(|channels| Arc::clone(&channels.control))
            .map_err(|_| DeliveryDriverError)
    }

    fn publish_reconnected_pair(
        &self,
        control: DriverClient,
        identity: &v1::InstanceIdentity,
    ) -> Result<Arc<Mutex<DriverClient>>, ExecutorError> {
        if self.stopping.is_closed() || identity != &self.identity {
            return Err(boundary_error_at("driver.reconnect.fenced"));
        }
        let origin = self.channel_pair()?;
        let observe = control
            .connect_peer(&self.control_socket.path, DRIVER_OBSERVE_IO_TIMEOUT)
            .map_err(executor_error)?;
        let control = Arc::new(Mutex::new(control));
        let replacement = Arc::new(DriverChannels {
            control: Arc::clone(&control),
            observe: Arc::new(Mutex::new(observe)),
        });
        if publish_if_current(&self.channels, &origin, replacement, &self.stopping)? {
            Ok(control)
        } else {
            Ok(Arc::clone(&self.channel_pair()?.control))
        }
    }

    async fn prepare_reconnected_channels(
        &self,
        instance: &AuthenticatedDriver,
    ) -> Result<(Arc<DriverChannels>, Arc<DriverChannels>), ExecutorError> {
        if self.stopping.is_closed() || instance.identity != self.identity {
            return Err(boundary_error_at("driver.observe.reconnect_fenced"));
        }
        let origin = self.channel_pair()?;
        let control = Arc::clone(&origin.control);
        let socket = self.control_socket.path.clone();
        let identity = self.identity.clone();
        let after = *instance.sequence.lock().map_err(|_| boundary_error())?;
        let replacement = spawn_blocking(move || {
            let mut next_control = control
                .lock()
                .map_err(|_| boundary_error())?
                .connect_peer(&socket, DRIVER_OBSERVE_IO_TIMEOUT)
                .map_err(|error| observe_reconnect_error(&error))?;
            let described = next_control
                .describe()
                .map_err(|error| observe_reconnect_error(&error))?;
            if described.driver_id != identity.driver_id {
                return Err(boundary_error_at("driver.observe.reconnect_identity"));
            }
            let inspected = next_control
                .inspect(identity)
                .map_err(|error| observe_reconnect_error(&error))?;
            if !valid_reconnect_inspection(inspected.state, inspected.last_event_sequence, after) {
                return Err(boundary_error_at("driver.observe.reconnect_state"));
            }
            let next_observe = next_control
                .connect_peer(&socket, DRIVER_OBSERVE_IO_TIMEOUT)
                .map_err(|error| observe_reconnect_error(&error))?;
            Ok(Arc::new(DriverChannels {
                control: Arc::new(Mutex::new(next_control)),
                observe: Arc::new(Mutex::new(next_observe)),
            }))
        })
        .await
        .map_err(|_| boundary_error_at("driver.observe.reconnect_join"))??;
        if self.stopping.is_closed() {
            return Err(boundary_error_at("driver.observe.reconnect_fenced"));
        }
        Ok((origin, replacement))
    }

    async fn request_stop(&self, attempt_id: LaunchAttemptId) -> Result<(), ExecutorError> {
        self.stopping.close();
        let client = Arc::clone(&self.channel_pair()?.control);
        let identity = self.identity.clone();
        let request_id = request(b"driver-graceful-stop", attempt_id)?;
        let disposition = spawn_blocking(move || {
            client
                .lock()
                .map_err(|_| boundary_error())?
                .stop(request_id.as_uuid().as_bytes().to_vec(), identity)
                .map_err(executor_error)
        })
        .await
        .map_err(|_| boundary_error())??;
        match disposition {
            v1::StopDisposition::StoppedConfirmed | v1::StopDisposition::AlreadyStopped => Ok(()),
            v1::StopDisposition::StopUncertain | v1::StopDisposition::StopCleanupRequired => {
                Err(boundary_error())
            }
            v1::StopDisposition::Unspecified => Err(boundary_error()),
        }
    }

    fn from_supervised(
        client: DriverClient,
        identity: v1::InstanceIdentity,
        launch: &LaunchSnapshot,
        control_socket: ControlSocketEvidence,
        watchdog: tokio::task::JoinHandle<
            Result<navigator_supervisor::StopOutcome, navigator_supervisor::SupervisorError>,
        >,
        lifecycle_fence: Arc<LifecycleFence>,
        metadata: SupervisedDriverMetadata,
    ) -> Result<Self, ExecutorError> {
        validate_supervised_identity(&identity, launch)?;
        validate_identity(&identity)?;
        let observe_client = client
            .connect_peer(&control_socket.path, DRIVER_OBSERVE_IO_TIMEOUT)
            .map_err(executor_error)?;
        let channels = Arc::new(DriverChannels {
            control: Arc::new(Mutex::new(client)),
            observe: Arc::new(Mutex::new(observe_client)),
        });
        Ok(Self {
            channels: Arc::new(RwLock::new(channels)),
            identity,
            sequence: Arc::new(Mutex::new(0)),
            pending_report: Arc::new(Mutex::new(None)),
            control_socket,
            watchdog: tokio::sync::Mutex::new(Some(watchdog)),
            hierarchy_sink: metadata.hierarchy_sink,
            tool_sink: metadata.tool_sink,
            tool_correlations: Arc::new(Mutex::new(ToolRuntimeCorrelations::default())),
            host_id: metadata.host_id,
            config_identity: metadata.config_identity,
            stopping: lifecycle_fence,
        })
    }

    async fn ensure_ready(
        &self,
        operation: &OperationSnapshot,
    ) -> Result<AuthenticatedDriver, ExecutorError> {
        validate_binding(&self.identity, operation)?;
        let client = Arc::clone(&self.channel_pair()?.control);
        spawn_blocking(move || {
            client
                .lock()
                .map_err(|_| boundary_error())?
                .describe()
                .map_err(executor_error)
        })
        .await
        .map_err(|_| boundary_error())??;
        Ok(AuthenticatedDriver {
            channels: Arc::clone(&self.channels),
            identity: self.identity.clone(),
            sequence: Arc::clone(&self.sequence),
            pending_report: Arc::clone(&self.pending_report),
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "authenticated event dispatch is closed"
    )]
    async fn next_report(
        &self,
        instance: &AuthenticatedDriver,
        operation: &OperationSnapshot,
    ) -> Result<ExecutorReport, ExecutorError> {
        validate_binding(&instance.identity, operation)?;
        loop {
            let after = *instance.sequence.lock().map_err(|_| boundary_error())?;
            let client = Arc::clone(
                &instance
                    .channels
                    .read()
                    .map_err(|_| boundary_error())?
                    .observe,
            );
            let identity = instance.identity.clone();
            let observation = spawn_blocking(move || {
                client
                    .lock()
                    .map_err(|_| boundary_error())?
                    .observe_with_timeout(identity, after, DRIVER_OBSERVE_IO_TIMEOUT)
                    .map_err(|error| observe_error(&error))
            })
            .await
            .map_err(|_| boundary_error_at("driver.observe.join_failed"))??;
            let Observation::Event(event) = observation else {
                // An empty Observe response is a completed bounded poll, not a
                // readiness signal. Back off outside the client mutex so
                // Remind, Cancel, and Stop calls can acquire the control
                // channel and so an always-empty Driver cannot busy-spin.
                tokio::time::sleep(Duration::from_millis(1)).await;
                continue;
            };
            if event.instance.as_ref() != Some(&instance.identity)
                || !is_exact_next_sequence(after, event.sequence)
            {
                return Err(boundary_error_at("driver.observe.identity_failed"));
            }
            let event_id = event.event_id.clone();
            match event.event.ok_or_else(boundary_error)? {
                v1::driver_event::Event::Ready(_) | v1::driver_event::Event::Acceptance(_) => {
                    *instance.sequence.lock().map_err(|_| boundary_error())? = event.sequence;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                v1::driver_event::Event::Disconnected(_) | v1::driver_event::Event::Stopped(_) => {
                    *instance.sequence.lock().map_err(|_| boundary_error())? = event.sequence;
                    return Ok(ExecutorReport::Disconnected);
                }
                v1::driver_event::Event::Report(report) => {
                    let delivery_attempt_id =
                        domain_id(&report.delivery_attempt_id, DeliveryAttemptId::from_uuid)?;
                    if let Some(v1::report::Result::Outcome(outcome)) = report.result.as_ref()
                        && outcome.kind == v1::ReportKind::Question as i32
                    {
                        let operation_id = parse_operation(&report.operation_id)?;
                        let delivered_message_id = parse_message(&report.message_id)?;
                        if operation_id != operation.operation_id {
                            return Err(boundary_error());
                        }
                        let code = Capability::new(
                            std::str::from_utf8(&outcome.payload)
                                .map_err(|_| boundary_error())?
                                .to_owned(),
                        )
                        .map_err(|_| boundary_error())?;
                        *instance
                            .pending_report
                            .lock()
                            .map_err(|_| boundary_error())? = Some(PendingReport {
                            event_id,
                            sequence: event.sequence,
                            operation_id,
                            message_id: delivered_message_id,
                            delivery_attempt_id,
                            request: Some(PendingRequest::Question(code)),
                        });
                        return Ok(ExecutorReport::Waiting {
                            operation_id,
                            message_id: delivered_message_id,
                        });
                    }
                    if let Some(v1::report::Result::ApprovalRequest(request)) =
                        report.result.as_ref()
                    {
                        let operation_id = parse_operation(&report.operation_id)?;
                        let delivered_message_id = parse_message(&report.message_id)?;
                        if operation_id != operation.operation_id {
                            return Err(boundary_error());
                        }
                        let expires_at = request.expires_at.as_ref().ok_or_else(boundary_error)?;
                        let approval = AuthenticatedApprovalRequest {
                            capability: Capability::new(request.capability.clone())
                                .map_err(|_| boundary_error())?,
                            resource: ApprovalResource::new(&request.resource)
                                .map_err(|_| boundary_error())?,
                            summary: ApprovalSummary::new(request.summary.clone())
                                .map_err(|_| boundary_error())?,
                            expires_at: Timestamp::new(
                                expires_at.unix_seconds,
                                expires_at.nanoseconds,
                            )
                            .map_err(|_| boundary_error())?,
                        };
                        *instance
                            .pending_report
                            .lock()
                            .map_err(|_| boundary_error())? = Some(PendingReport {
                            event_id,
                            sequence: event.sequence,
                            operation_id,
                            message_id: delivered_message_id,
                            delivery_attempt_id,
                            request: Some(PendingRequest::Approval(approval)),
                        });
                        return Ok(ExecutorReport::Waiting {
                            operation_id,
                            message_id: delivered_message_id,
                        });
                    }
                    let mapped = map_report(report)?;
                    if !report_matches(&mapped, operation) {
                        return Err(boundary_error());
                    }
                    let (operation_id, message_id) =
                        report_identity(&mapped).ok_or_else(boundary_error)?;
                    *instance
                        .pending_report
                        .lock()
                        .map_err(|_| boundary_error())? = Some(PendingReport {
                        event_id,
                        sequence: event.sequence,
                        operation_id,
                        message_id,
                        delivery_attempt_id,
                        request: None,
                    });
                    return Ok(mapped);
                }
                v1::driver_event::Event::HierarchyCommand(command) => {
                    let sink = self.hierarchy_sink.as_ref().ok_or_else(boundary_error)?;
                    let hierarchy_request_id = command.request_id.clone();
                    let result = sink
                        .handle(hierarchy_caller(&instance.identity, self.host_id)?, command)
                        .await
                        .map_err(hierarchy_apply_error)?;
                    let client = Arc::clone(
                        &instance
                            .channels
                            .read()
                            .map_err(|_| boundary_error())?
                            .control,
                    );
                    let identity = instance.identity.clone();
                    let response_request_id =
                        derived_bytes(b"navigator.hierarchy.result.v1", &hierarchy_request_id);
                    spawn_blocking(move || {
                        client
                            .lock()
                            .map_err(|_| boundary_error())?
                            .hierarchy_result(
                                response_request_id,
                                identity,
                                hierarchy_request_id,
                                result,
                            )
                            .map_err(executor_error)
                    })
                    .await
                    .map_err(|_| boundary_error_at("driver.hierarchy.ack_join_failed"))?
                    .map_err(|_| boundary_error_at("driver.hierarchy.ack_failed"))?;
                    *instance.sequence.lock().map_err(|_| boundary_error())? = event.sequence;
                }
                v1::driver_event::Event::ToolCommand(command) => {
                    if parse_operation(&command.operation_id)? != operation.operation_id {
                        return Err(boundary_error_at("tool.operation.invalid"));
                    }
                    let tool_request_id = command.request_id.clone();
                    let result = resolve_tool_command(
                        &self.tool_correlations,
                        self.tool_sink.as_ref(),
                        &instance.identity,
                        self.host_id,
                        operation.operation_id,
                        command,
                    )
                    .await?;
                    let client = Arc::clone(
                        &instance
                            .channels
                            .read()
                            .map_err(|_| boundary_error())?
                            .control,
                    );
                    let identity = instance.identity.clone();
                    let completed_tool_request_id = tool_request_id.clone();
                    let response_request_id =
                        derived_bytes(b"navigator.tool.result.v1", &tool_request_id);
                    spawn_blocking(move || {
                        client
                            .lock()
                            .map_err(|_| boundary_error())?
                            .tool_result(response_request_id, identity, tool_request_id, result)
                            .map_err(executor_error)
                    })
                    .await
                    .map_err(|_| boundary_error_at("driver.tool.ack_join_failed"))?
                    .map_err(|_| boundary_error_at("driver.tool.ack_failed"))?;
                    let mut correlations = self
                        .tool_correlations
                        .lock()
                        .map_err(|_| boundary_error())?;
                    correlations.guard.forget(&completed_tool_request_id);
                    correlations.results.remove(&completed_tool_request_id);
                    *instance.sequence.lock().map_err(|_| boundary_error())? = event.sequence;
                }
            }
        }
    }

    async fn remind(
        &self,
        instance: &AuthenticatedDriver,
        operation: &OperationSnapshot,
    ) -> Result<(), ExecutorError> {
        validate_binding(&instance.identity, operation)?;
        let client = Arc::clone(&self.channel_pair()?.control);
        let identity = instance.identity.clone();
        let request_id = derived_id(
            b"navigator.driver.remind.v1",
            &operation.operation_id.as_uuid(),
        );
        let operation_id = operation.operation_id.as_uuid().as_bytes().to_vec();
        let message_id = operation.input_message_id.as_uuid().as_bytes().to_vec();
        spawn_blocking(move || {
            client
                .lock()
                .map_err(|_| boundary_error())?
                .reminder(identity, request_id, operation_id, message_id)
                .map_err(executor_error)
        })
        .await
        .map_err(|_| boundary_error())??;
        Ok(())
    }
}

impl ControlSocketEvidence {
    fn remove_if_same(&self) -> std::io::Result<()> {
        match std::fs::symlink_metadata(&self.path) {
            Ok(metadata)
                if metadata.file_type().is_socket()
                    && metadata.dev() == self.device
                    && metadata.ino() == self.inode =>
            {
                std::fs::remove_file(&self.path)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err(std::io::Error::other("control socket identity changed")),
            Err(error) => Err(error),
        }
    }
}

fn validate_supervised_identity(
    identity: &v1::InstanceIdentity,
    launch: &LaunchSnapshot,
) -> Result<(), ExecutorError> {
    if launch.state != LaunchState::Ready
        || identity.session_id != launch.session_id.as_uuid().as_bytes()
        || identity.participant_id != launch.participant_id.as_uuid().as_bytes()
        || identity.driver_id != launch.driver_id.as_uuid().as_bytes()
        || identity.launch_attempt_id != launch.attempt_id.as_uuid().as_bytes()
        || identity.instance_id
            != launch
                .instance_id
                .ok_or_else(boundary_error)?
                .as_uuid()
                .as_bytes()
    {
        return Err(boundary_error());
    }
    Ok(())
}

fn map_report(report: v1::Report) -> Result<ExecutorReport, ExecutorError> {
    let operation_id = parse_operation(&report.operation_id)?;
    let message_id = parse_message(&report.message_id)?;
    match report.result.ok_or_else(boundary_error)? {
        // Approval requests are handled by the authenticated pending-report
        // path and must never be interpreted as an ordinary outcome.
        v1::report::Result::ApprovalRequest(_) => Err(boundary_error()),
        v1::report::Result::Failure(_) => Ok(ExecutorReport::Terminal {
            operation_id,
            message_id,
            outcome: ExecutorTerminalOutcome::Failed {
                code: "driver_failure".into(),
                detail: "Driver reported failure".into(),
            },
        }),
        v1::report::Result::Outcome(outcome) => {
            match v1::ReportKind::try_from(outcome.kind).map_err(|_| boundary_error())? {
                v1::ReportKind::Progress => Ok(ExecutorReport::Progress {
                    operation_id,
                    message_id,
                    payload: outcome.payload,
                }),
                v1::ReportKind::Question | v1::ReportKind::Unspecified => Err(boundary_error()),
                v1::ReportKind::Succeeded => Ok(ExecutorReport::Terminal {
                    operation_id,
                    message_id,
                    outcome: ExecutorTerminalOutcome::Succeeded(outcome.payload),
                }),
                v1::ReportKind::ReportFailed => Ok(ExecutorReport::Terminal {
                    operation_id,
                    message_id,
                    outcome: ExecutorTerminalOutcome::Failed {
                        code: "driver_failure".into(),
                        detail: String::from_utf8_lossy(&outcome.payload).into_owned(),
                    },
                }),
                v1::ReportKind::ReportCancelled => Ok(ExecutorReport::Terminal {
                    operation_id,
                    message_id,
                    outcome: ExecutorTerminalOutcome::Cancelled,
                }),
                v1::ReportKind::Blocked => Ok(ExecutorReport::Terminal {
                    operation_id,
                    message_id,
                    outcome: ExecutorTerminalOutcome::Blocked(
                        String::from_utf8_lossy(&outcome.payload).into_owned(),
                    ),
                }),
                v1::ReportKind::ReportUncertain => Ok(ExecutorReport::Terminal {
                    operation_id,
                    message_id,
                    outcome: ExecutorTerminalOutcome::Uncertain(
                        String::from_utf8_lossy(&outcome.payload).into_owned(),
                    ),
                }),
            }
        }
    }
}

fn report_matches(report: &ExecutorReport, operation: &OperationSnapshot) -> bool {
    match report {
        ExecutorReport::Progress {
            operation_id,
            message_id,
            ..
        }
        | ExecutorReport::Waiting {
            operation_id,
            message_id,
        }
        | ExecutorReport::Terminal {
            operation_id,
            message_id,
            ..
        } => *operation_id == operation.operation_id && !message_id.as_uuid().is_nil(),
        ExecutorReport::Idle | ExecutorReport::Disconnected => true,
    }
}

fn report_identity(report: &ExecutorReport) -> Option<(OperationId, MessageId)> {
    match report {
        ExecutorReport::Progress {
            operation_id,
            message_id,
            ..
        }
        | ExecutorReport::Waiting {
            operation_id,
            message_id,
        }
        | ExecutorReport::Terminal {
            operation_id,
            message_id,
            ..
        } => Some((*operation_id, *message_id)),
        ExecutorReport::Idle | ExecutorReport::Disconnected => None,
    }
}

fn acknowledge_pending_report(
    instance: &AuthenticatedDriver,
    operation_id: OperationId,
    message_id: MessageId,
) -> Result<(), ExecutorError> {
    let mut pending = instance
        .pending_report
        .lock()
        .map_err(|_| boundary_error())?;
    let mut sequence = instance.sequence.lock().map_err(|_| boundary_error())?;
    commit_pending_report(&mut pending, &mut sequence, operation_id, message_id)
}

fn discard_pending_report(
    instance: &AuthenticatedDriver,
    operation_id: OperationId,
    message_id: MessageId,
    delivery_attempt_id: DeliveryAttemptId,
) -> Result<(), ExecutorError> {
    let mut pending = instance
        .pending_report
        .lock()
        .map_err(|_| boundary_error())?;
    if pending.as_ref().is_some_and(|value| {
        value.operation_id == operation_id
            && value.message_id == message_id
            && value.delivery_attempt_id == delivery_attempt_id
    }) {
        *pending = None;
    }
    Ok(())
}

fn commit_pending_report(
    pending: &mut Option<PendingReport>,
    sequence: &mut u64,
    operation_id: OperationId,
    message_id: MessageId,
) -> Result<(), ExecutorError> {
    let Some(value) = pending.as_ref() else {
        return Ok(());
    };
    if value.operation_id != operation_id
        || value.message_id != message_id
        || value.event_id.len() != 16
        || value.sequence < *sequence
    {
        return Err(boundary_error());
    }
    *sequence = value.sequence;
    *pending = None;
    Ok(())
}

fn validate_binding(
    identity: &v1::InstanceIdentity,
    operation: &OperationSnapshot,
) -> Result<(), ExecutorError> {
    validate_identity(identity)?;
    if identity.session_id == operation.session_id.as_uuid().as_bytes()
        && identity.participant_id == operation.participant_id.as_uuid().as_bytes()
    {
        Ok(())
    } else {
        Err(boundary_error())
    }
}

fn validate_identity(identity: &v1::InstanceIdentity) -> Result<(), ExecutorError> {
    for value in [
        &identity.driver_id,
        &identity.participant_id,
        &identity.launch_attempt_id,
        &identity.instance_id,
        &identity.session_id,
    ] {
        if value.len() != 16 || value.iter().all(|byte| *byte == 0) {
            return Err(boundary_error());
        }
    }
    if identity.ownership_epoch == 0 {
        return Err(boundary_error());
    }
    Ok(())
}

fn hierarchy_caller(
    identity: &v1::InstanceIdentity,
    host_id: HostId,
) -> Result<AuthenticatedHierarchyCaller, ExecutorError> {
    validate_identity(identity)?;
    Ok(AuthenticatedHierarchyCaller {
        host_id,
        session_id: SessionId::from_uuid(
            Uuid::from_slice(&identity.session_id).map_err(|_| boundary_error())?,
        )
        .map_err(|_| boundary_error())?,
        participant_id: ParticipantId::from_uuid(
            Uuid::from_slice(&identity.participant_id).map_err(|_| boundary_error())?,
        )
        .map_err(|_| boundary_error())?,
        launch_attempt_id: LaunchAttemptId::from_uuid(
            Uuid::from_slice(&identity.launch_attempt_id).map_err(|_| boundary_error())?,
        )
        .map_err(|_| boundary_error())?,
        instance_id: InstanceId::from_uuid(
            Uuid::from_slice(&identity.instance_id).map_err(|_| boundary_error())?,
        )
        .map_err(|_| boundary_error())?,
        ownership_epoch: FencingEpoch::new(identity.ownership_epoch)
            .map_err(|_| boundary_error())?,
    })
}

fn tool_caller(
    identity: &v1::InstanceIdentity,
    host_id: HostId,
    command: &v1::ToolCommand,
) -> Result<AuthenticatedHierarchyCaller, ExecutorError> {
    if command.session_id != identity.session_id
        || command.participant_id != identity.participant_id
    {
        return Err(boundary_error_at("tool.caller.invalid"));
    }
    hierarchy_caller(identity, host_id)
}

async fn apply_tool_command(
    sink: Option<&Arc<dyn ToolCommandSink>>,
    identity: &v1::InstanceIdentity,
    host_id: HostId,
    command: v1::ToolCommand,
) -> Result<v1::tool_result_request::Result, ExecutorError> {
    let caller = tool_caller(identity, host_id, &command)?;
    Ok(match sink {
        Some(sink) => sink.handle(caller, command).await.unwrap_or_else(|_| {
            v1::tool_result_request::Result::Failure(v1::Failure {
                code: v1::FailureCode::Internal.into(),
                message: "Tool command sink failed".into(),
                retryable: false,
            })
        }),
        None => v1::tool_result_request::Result::Failure(v1::Failure {
            code: v1::FailureCode::Unavailable.into(),
            message: "Tool command sink is not configured".into(),
            retryable: true,
        }),
    })
}

async fn resolve_tool_command(
    correlations: &Mutex<ToolRuntimeCorrelations>,
    sink: Option<&Arc<dyn ToolCommandSink>>,
    identity: &v1::InstanceIdentity,
    host_id: HostId,
    operation_id: OperationId,
    command: v1::ToolCommand,
) -> Result<v1::tool_result_request::Result, ExecutorError> {
    if parse_operation(&command.operation_id)? != operation_id {
        return Err(boundary_error_at("tool.operation.invalid"));
    }
    let request_id = command.request_id.clone();
    let disposition = correlations
        .lock()
        .map_err(|_| boundary_error())?
        .guard
        .observe_scoped_command(identity, &command)
        .map_err(|_| boundary_error_at("tool.correlation.invalid"))?;
    if disposition == ToolCorrelationDisposition::Duplicate {
        return correlations
            .lock()
            .map_err(|_| boundary_error())?
            .results
            .get(&request_id)
            .cloned()
            .ok_or_else(|| boundary_error_at("tool.result.missing"));
    }
    let result = apply_tool_command(sink, identity, host_id, command).await?;
    let semantic = v1::ToolResultRequest {
        metadata: None,
        instance: Some(identity.clone()),
        tool_request_id: request_id.clone(),
        result: Some(result.clone()),
    };
    let mut state = correlations.lock().map_err(|_| boundary_error())?;
    state
        .guard
        .observe_scoped_result(operation_id.as_uuid().as_bytes(), &semantic)
        .map_err(|_| boundary_error_at("tool.result.correlation.invalid"))?;
    state.results.insert(request_id, result.clone());
    Ok(result)
}

fn parse_operation(bytes: &[u8]) -> Result<OperationId, ExecutorError> {
    OperationId::from_uuid(Uuid::from_slice(bytes).map_err(|_| boundary_error())?)
        .map_err(|_| boundary_error())
}

fn parse_message(bytes: &[u8]) -> Result<MessageId, ExecutorError> {
    MessageId::from_uuid(Uuid::from_slice(bytes).map_err(|_| boundary_error())?)
        .map_err(|_| boundary_error())
}

fn parse_participant(bytes: &[u8]) -> Result<ParticipantId, ExecutorError> {
    ParticipantId::from_uuid(Uuid::from_slice(bytes).map_err(|_| boundary_error())?)
        .map_err(|_| boundary_error())
}

fn parse_request(bytes: &[u8]) -> Result<RequestId, ExecutorError> {
    RequestId::from_uuid(Uuid::from_slice(bytes).map_err(|_| boundary_error())?)
        .map_err(|_| boundary_error())
}

fn parse_optional_grant(bytes: &[u8]) -> Result<Option<navigator_domain::GrantId>, ExecutorError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        navigator_domain::GrantId::from_uuid(Uuid::from_slice(bytes).map_err(|_| boundary_error())?)
            .map(Some)
            .map_err(|_| boundary_error())
    }
}

fn derived_participant(bytes: &[u8]) -> Result<ParticipantId, ExecutorError> {
    ParticipantId::from_uuid(derived_uuid(b"navigator.hierarchy.child.v1", bytes))
        .map_err(|_| boundary_error())
}

fn derived_operation(bytes: &[u8]) -> Result<OperationId, ExecutorError> {
    OperationId::from_uuid(derived_uuid(b"navigator.hierarchy.operation.v1", bytes))
        .map_err(|_| boundary_error())
}

fn derived_message(bytes: &[u8]) -> Result<MessageId, ExecutorError> {
    MessageId::from_uuid(derived_uuid(b"navigator.hierarchy.message.v1", bytes))
        .map_err(|_| boundary_error())
}

fn hierarchy_failure(
    code: v1::FailureCode,
    message: &'static str,
) -> v1::hierarchy_result_request::Result {
    v1::hierarchy_result_request::Result::Failure(v1::Failure {
        code: code as i32,
        message: message.into(),
        retryable: false,
    })
}

fn operation_state_name(state: navigator_domain::OperationState) -> &'static str {
    use navigator_domain::OperationState;
    match state {
        OperationState::Queued => "queued",
        OperationState::Starting => "starting",
        OperationState::Running => "running",
        OperationState::Waiting => "waiting",
        OperationState::Cancelling => "cancelling",
        OperationState::Succeeded => "succeeded",
        OperationState::Failed => "failed",
        OperationState::Cancelled => "cancelled",
        OperationState::Blocked => "blocked",
        OperationState::Uncertain => "uncertain",
    }
}

fn derived_id(domain: &[u8], identity: &Uuid) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(identity.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().expect("fixed digest");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes.to_vec()
}

fn is_exact_next_sequence(after: u64, observed: u64) -> bool {
    after.checked_add(1) == Some(observed)
}

fn trusted_configuration_with_catalog(
    mut configuration: serde_json::Value,
    catalog: serde_json::Value,
) -> Result<Vec<u8>, ExecutorError> {
    let object = configuration.as_object_mut().ok_or_else(boundary_error)?;
    if object.contains_key("navigator_tool_catalog") || !catalog.is_array() {
        return Err(boundary_error_at("driver.tool_catalog.override"));
    }
    object.insert("navigator_tool_catalog".into(), catalog);
    serde_json::to_vec(&configuration).map_err(executor_error)
}

fn derived_bytes(domain: &[u8], identity: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(identity);
    let mut bytes = digest.finalize()[..16].to_vec();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

fn derived_uuid(domain: &[u8], input: &[u8]) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(input);
    let mut bytes: [u8; 16] = digest.finalize()[..16].try_into().expect("fixed digest");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn request(domain: &[u8], attempt: LaunchAttemptId) -> Result<RequestId, ExecutorError> {
    RequestId::from_uuid(derived_uuid(domain, attempt.as_uuid().as_bytes())).map_err(executor_error)
}

fn capability_wire(value: &DriverCapabilityRequirement) -> v1::CapabilityRequirement {
    v1::CapabilityRequirement {
        id: value.capability().as_str().to_owned(),
        minimum_version: value.minimum_version(),
        parameters: value
            .parameters()
            .iter()
            .map(|(key, value)| v1::CapabilityParameter {
                key: key.as_str().to_owned(),
                value: value.as_str().to_owned(),
            })
            .collect(),
    }
}

fn capability_offer_wire(value: &DriverCapabilityRequirement) -> v1::Capability {
    v1::Capability {
        id: value.capability().as_str().to_owned(),
        version: value.minimum_version(),
        parameters: value
            .parameters()
            .iter()
            .map(|(key, value)| v1::CapabilityParameter {
                key: key.as_str().to_owned(),
                value: value.as_str().to_owned(),
            })
            .collect(),
    }
}

fn executor_error(_: impl std::fmt::Debug) -> ExecutorError {
    boundary_error()
}

fn observe_error(error: &ClientError) -> ExecutorError {
    boundary_error_at(match error {
        ClientError::Io(_) => "driver.observe.io_failed",
        ClientError::Protocol => "driver.observe.protocol_failed",
        ClientError::ProtocolDetail(stage) => stage,
        ClientError::Correlation => "driver.observe.correlation_failed",
        ClientError::Credential => "driver.observe.credential_failed",
        ClientError::Failure(_) => "driver.observe.remote_failure",
    })
}

fn observe_reconnect_error(error: &ClientError) -> ExecutorError {
    boundary_error_at(match error {
        ClientError::Io(_) => "driver.observe.reconnect_io",
        ClientError::Credential => "driver.observe.reconnect_credential",
        ClientError::Protocol | ClientError::ProtocolDetail(_) => {
            "driver.observe.reconnect_protocol"
        }
        ClientError::Correlation => "driver.observe.reconnect_correlation",
        ClientError::Failure(_) => "driver.observe.reconnect_remote",
    })
}

fn hierarchy_apply_error(error: ExecutorError) -> ExecutorError {
    match error.message.as_str() {
        "hierarchy.caller.invalid"
        | "hierarchy.spawn.caller_invalid"
        | "hierarchy.spawn.denied"
        | "hierarchy.spawn.store_failed"
        | "hierarchy.spawn.request_conflict"
        | "hierarchy.spawn.store_corrupt"
        | "hierarchy.spawn.schedule_failed"
        | "hierarchy.send.schedule_failed"
        | "hierarchy.cancel.schedule_failed" => error,
        _ => boundary_error_at("driver.hierarchy.apply_failed"),
    }
}
fn boundary_error() -> ExecutorError {
    ExecutorError {
        message: "authenticated Driver boundary failed".into(),
    }
}

fn boundary_error_at(code: &'static str) -> ExecutorError {
    ExecutorError {
        message: code.to_owned(),
    }
}

#[cfg(test)]
mod report_cursor_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use navigator_store_sqlite::SqliteStore;
    use tokio::sync::Notify;

    use super::*;

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ApprovalSinkCall {
        caller: AuthenticatedHierarchyCaller,
        event_id: Vec<u8>,
        operation_id: OperationId,
        message_id: MessageId,
        delivery_attempt_id: DeliveryAttemptId,
        request: AuthenticatedApprovalRequest,
    }

    #[derive(Default)]
    struct RecordingApprovalSink(Mutex<Vec<ApprovalSinkCall>>);

    impl ApprovalCommandSink for RecordingApprovalSink {
        fn request(
            &self,
            caller: AuthenticatedHierarchyCaller,
            event_id: Vec<u8>,
            operation_id: OperationId,
            delivered_message_id: MessageId,
            delivery_attempt_id: DeliveryAttemptId,
            request: AuthenticatedApprovalRequest,
        ) -> Pin<Box<dyn Future<Output = Result<(), ExecutorError>> + Send + '_>> {
            Box::pin(async move {
                self.0
                    .lock()
                    .map_err(|_| boundary_error())?
                    .push(ApprovalSinkCall {
                        caller,
                        event_id,
                        operation_id,
                        message_id: delivered_message_id,
                        delivery_attempt_id,
                        request,
                    });
                Ok(())
            })
        }
    }

    struct PendingTestCredentials;

    impl CredentialSource for PendingTestCredentials {
        fn next_credential(&mut self) -> Result<Vec<u8>, navigator_supervisor::SupervisorError> {
            Ok(b"pending-test-credential".to_vec())
        }
    }

    #[test]
    fn socket_wait_and_bootstrap_share_one_absolute_connect_budget() {
        let start = tokio::time::Instant::now();
        let deadline = start + Duration::from_secs(15);
        assert_eq!(
            remaining_connect_budget(deadline, start + Duration::from_secs(6)),
            Some(Duration::from_secs(9))
        );
        assert_eq!(remaining_connect_budget(deadline, deadline), None);
        assert_eq!(
            remaining_connect_budget(deadline, deadline + Duration::from_millis(1)),
            None
        );
    }

    #[test]
    fn reconnected_pair_is_atomic_fenced_and_visible_to_old_holders() {
        let original = Arc::new(1_u8);
        let registry = RwLock::new(Arc::clone(&original));
        let stopping = LifecycleFence::default();
        let replacement = Arc::new(2_u8);
        assert!(
            publish_if_current(&registry, &original, Arc::clone(&replacement), &stopping,).unwrap()
        );
        assert_eq!(
            *original, 1,
            "an in-flight holder remains internally coherent"
        );
        assert!(Arc::ptr_eq(&registry.read().unwrap(), &replacement));
        assert!(
            !publish_if_current(&registry, &original, Arc::new(3), &stopping).unwrap(),
            "a stale reconnect overwrote the atomically published pair"
        );
        stopping.close();
        assert!(
            !publish_if_current(&registry, &replacement, Arc::new(4), &stopping).unwrap(),
            "a reconnect published after Stop began"
        );
    }

    #[tokio::test]
    async fn watchdog_fence_wins_when_reconnect_is_paused_before_publish() {
        let original = Arc::new(1_u8);
        let registry = Arc::new(RwLock::new(Arc::clone(&original)));
        let lifecycle_fence = Arc::new(LifecycleFence::default());
        let at_publish = Arc::new(Notify::new());
        let resume_publish = Arc::new(Notify::new());
        let publisher = {
            let registry = Arc::clone(&registry);
            let lifecycle_fence = Arc::clone(&lifecycle_fence);
            let at_publish = Arc::clone(&at_publish);
            let resume_publish = Arc::clone(&resume_publish);
            let origin = Arc::clone(&original);
            tokio::spawn(async move {
                let replacement = Arc::new(2_u8);
                at_publish.notify_one();
                resume_publish.notified().await;
                publish_if_current(&registry, &origin, replacement, &lifecycle_fence).unwrap()
            })
        };
        at_publish.notified().await;
        lifecycle_fence.close();
        resume_publish.notify_one();
        assert!(!publisher.await.unwrap());
        assert!(Arc::ptr_eq(&registry.read().unwrap(), &original));
    }

    #[tokio::test]
    async fn production_watchdog_drop_guard_fences_panic_and_abort() {
        let panic_fence = Arc::new(LifecycleFence::default());
        let panic_guard = Arc::clone(&panic_fence);
        let panicked = tokio::spawn(async move {
            let _close_on_exit = CloseLifecycleOnDrop(panic_guard);
            panic!("watchdog mutant");
        });
        assert!(panicked.await.is_err());
        assert!(panic_fence.is_closed());

        let abort_fence = Arc::new(LifecycleFence::default());
        let abort_guard = Arc::clone(&abort_fence);
        let entered = Arc::new(Notify::new());
        let task_entered = Arc::clone(&entered);
        let aborted = tokio::spawn(async move {
            let _close_on_exit = CloseLifecycleOnDrop(abort_guard);
            task_entered.notify_one();
            std::future::pending::<()>().await;
        });
        entered.notified().await;
        aborted.abort();
        assert!(aborted.await.is_err());
        assert!(abort_fence.is_closed());
    }

    #[test]
    fn reconnect_requires_exact_ready_state_and_non_regressing_sequence() {
        assert!(valid_reconnect_inspection(
            v1::InstanceState::Ready as i32,
            7,
            7
        ));
        assert!(!valid_reconnect_inspection(
            v1::InstanceState::Stopped as i32,
            7,
            7
        ));
        assert!(!valid_reconnect_inspection(
            v1::InstanceState::Ready as i32,
            6,
            7
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn pending_launch_cancellation_interrupts_the_connect_wait() {
        let cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waiter = tokio::spawn(wait_for_pending_launch_cancellation(Arc::clone(
            &cancellation,
        )));
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        cancellation.store(true, std::sync::atomic::Ordering::Release);
        tokio::time::advance(Duration::from_millis(10)).await;
        waiter.await.unwrap();
    }

    #[test]
    fn cancelled_pending_launch_is_retained_until_absence_is_proven() {
        let session_id = SessionId::from_uuid(Uuid::from_u128(7_001)).unwrap();
        let attempt_id = LaunchAttemptId::from_uuid(Uuid::from_u128(7_002)).unwrap();
        let pending = PendingLaunch {
            session_id,
            participant_id: ParticipantId::from_uuid(Uuid::from_u128(7_003)).unwrap(),
            epoch: FencingEpoch::new(3).unwrap(),
            cancellation: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let mut registry = HashMap::from([(attempt_id, pending)]);

        let cleanup_required =
            classify_pending_reconcile(navigator_supervisor::StopOutcome::CleanupRequired);
        assert_eq!(
            cleanup_required.as_ref().unwrap_err().message,
            "driver.pending_launch.cleanup_required"
        );
        finish_pending_reconcile(&mut registry, attempt_id, &cleanup_required);
        assert_eq!(
            registry.get(&attempt_id).map(|value| value.session_id),
            Some(session_id)
        );

        let stopped = classify_pending_reconcile(navigator_supervisor::StopOutcome::Stopped);
        finish_pending_reconcile(&mut registry, attempt_id, &stopped);
        assert!(!registry.contains_key(&attempt_id));
    }

    #[tokio::test]
    async fn shutdown_clears_only_pre_prepare_pending_launch_under_launch_lock() {
        let directory = tempfile::Builder::new()
            .prefix("nav-pending")
            .tempdir_in("/tmp")
            .unwrap();
        std::fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("pending-pre-prepare.db"))
                .await
                .unwrap(),
        );
        let backend =
            Arc::new(UnixProcessBackend::new(directory.path().join("credentials")).unwrap());
        let supervisor = Arc::new(InstanceSupervisor::new(
            store.clone(),
            backend,
            PendingTestCredentials,
            navigator_supervisor::SupervisorConfig {
                graceful_timeout: Duration::from_millis(10),
                forced_timeout: Duration::from_millis(10),
                ownership_loss_timeout: Duration::from_millis(10),
            },
        ));
        let host = HostId::from_uuid(Uuid::from_u128(7_010)).unwrap();
        let session = SessionId::from_uuid(Uuid::from_u128(7_011)).unwrap();
        let attempt = LaunchAttemptId::from_uuid(Uuid::from_u128(7_012)).unwrap();
        let executor = SupervisedDriverExecutor::new(
            store,
            supervisor,
            host,
            SupervisedDriverConfig {
                driver_id: DriverId::from_uuid(Uuid::from_u128(7_013)).unwrap(),
                program: PathBuf::from("/never/launched"),
                expected_executable_identity: [0; 32],
                arguments: Vec::new(),
                working_directory: directory.path().to_path_buf(),
                environment: BTreeMap::new(),
                environment_allowlist: BTreeSet::new(),
                control_directory: directory.path().to_path_buf(),
                control_socket_environment: OsString::from("NAVIGATOR_CONTROL_SOCKET"),
                connect_timeout: Duration::from_secs(1),
                offered_capabilities: Vec::new(),
                ownership_channel: navigator_supervisor::OwnershipChannel::Stdin,
                process_io_mode: navigator_supervisor::ProcessIoMode::Headless,
                bootstrap_configuration: Vec::new(),
                trusted_artifacts: Vec::new(),
            },
        );
        executor.pending_launches.lock().await.insert(
            attempt,
            PendingLaunch {
                session_id: session,
                participant_id: ParticipantId::from_uuid(Uuid::from_u128(7_014)).unwrap(),
                epoch: FencingEpoch::new(1).unwrap(),
                cancellation: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            },
        );

        executor
            .shutdown_session_with_deadline(
                session,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert!(executor.pending_launches.lock().await.is_empty());

        for error in [
            StoreError::Unavailable,
            StoreError::Corrupt,
            StoreError::Invalid,
        ] {
            assert!(pending_launch_was_never_prepared(Err(error)).is_err());
        }
    }

    #[test]
    fn unchanged_authorized_child_replay_still_requires_scheduling() {
        assert!(
            authorized_child_requires_schedule(),
            "an exact Spawn replay must recover a child stranded before BeginStart"
        );
    }

    #[test]
    fn resolved_attempt_changes_with_configuration_and_catalog_identity() {
        let participant = ParticipantId::from_uuid(Uuid::from_u128(9_001)).unwrap();
        let epoch = FencingEpoch::new(7).unwrap();
        let mut config = SupervisedDriverConfig {
            bootstrap_configuration: vec![],
            trusted_artifacts: vec![],
            ownership_channel: navigator_supervisor::OwnershipChannel::Stdin,
            process_io_mode: navigator_supervisor::ProcessIoMode::Headless,
            driver_id: DriverId::from_uuid(Uuid::from_u128(9_002)).unwrap(),
            program: PathBuf::from("/trusted/driver"),
            expected_executable_identity: [3; 32],
            arguments: vec![],
            working_directory: PathBuf::from("/trusted"),
            environment: BTreeMap::new(),
            environment_allowlist: BTreeSet::new(),
            control_directory: PathBuf::from("/trusted/control"),
            control_socket_environment: OsString::from("NAV_CONTROL"),
            connect_timeout: Duration::from_secs(1),
            offered_capabilities: vec![],
        };
        let catalog_a = TrustedToolCatalog::new_bound(
            serde_json::json!([]),
            &serde_json::json!({"policy":"a"}),
        )
        .unwrap();
        let catalog_b = TrustedToolCatalog::new_bound(
            serde_json::json!([]),
            &serde_json::json!({"policy":"b"}),
        )
        .unwrap();
        let attempt_a =
            resolved_launch_attempt_for_config(participant, epoch, &config, &catalog_a).unwrap();
        assert_ne!(
            attempt_a,
            resolved_launch_attempt_for_config(participant, epoch, &config, &catalog_b).unwrap()
        );
        config.arguments.push(OsString::from("--changed"));
        assert_ne!(
            attempt_a,
            resolved_launch_attempt_for_config(participant, epoch, &config, &catalog_a).unwrap()
        );
    }

    #[tokio::test]
    async fn every_post_launch_failure_runs_exactly_once_cleanup_before_cache() {
        for failure in [
            PostLaunchFailure::Bootstrap,
            PostLaunchFailure::Digest,
            PostLaunchFailure::HierarchySink,
            PostLaunchFailure::ToolSink,
            PostLaunchFailure::DriverConstruction,
            PostLaunchFailure::ActiveCache,
        ] {
            let aborted = Arc::new(AtomicUsize::new(0));
            let removed = Arc::new(AtomicUsize::new(0));
            let stopped = Arc::new(AtomicUsize::new(0));
            let active = HashMap::<u8, u8>::new();
            run_post_launch_cleanup(
                failure,
                {
                    let aborted = Arc::clone(&aborted);
                    move || {
                        aborted.fetch_add(1, Ordering::Relaxed);
                    }
                },
                {
                    let removed = Arc::clone(&removed);
                    move || {
                        removed.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    }
                },
                {
                    let stopped = Arc::clone(&stopped);
                    move || async move {
                        stopped.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    }
                },
            )
            .await
            .unwrap();
            assert_eq!(aborted.load(Ordering::Relaxed), 1, "{failure:?}");
            assert_eq!(removed.load(Ordering::Relaxed), 1, "{failure:?}");
            assert_eq!(stopped.load(Ordering::Relaxed), 1, "{failure:?}");
            assert!(active.is_empty(), "{failure:?}");
        }
    }

    #[test]
    fn successful_post_launch_cache_does_not_run_cleanup() {
        let mut active = HashMap::new();
        let value = cache_bootstrapped::<_, _, ExecutorError>(&mut active, 1_u8, Ok(2_u8)).unwrap();
        assert_eq!(value, 2);
        assert_eq!(active.get(&1), Some(&2));
    }

    fn delivery_lease(attempt_id: DeliveryAttemptId) -> DeliveryLease {
        DeliveryLease {
            attempt_id,
            owner: HostId::from_uuid(Uuid::from_u128(601)).unwrap(),
            ownership_epoch: FencingEpoch::new(3).unwrap(),
            driver_ownership_epoch: FencingEpoch::new(3).unwrap(),
            driver_launch_attempt_id: LaunchAttemptId::from_uuid(Uuid::from_u128(602)).unwrap(),
            instance_id: InstanceId::from_uuid(Uuid::from_u128(603)).unwrap(),
            expires_at: navigator_domain::Timestamp::new(100, 0).unwrap(),
        }
    }

    fn report_identity_for(lease: &DeliveryLease) -> v1::InstanceIdentity {
        v1::InstanceIdentity {
            driver_id: Uuid::from_u128(607).as_bytes().to_vec(),
            participant_id: Uuid::from_u128(608).as_bytes().to_vec(),
            launch_attempt_id: lease.driver_launch_attempt_id.as_uuid().as_bytes().to_vec(),
            instance_id: lease.instance_id.as_uuid().as_bytes().to_vec(),
            session_id: Uuid::from_u128(609).as_bytes().to_vec(),
            ownership_epoch: lease.driver_ownership_epoch.get(),
        }
    }

    struct SuccessfulToolSink(AtomicUsize);

    impl ToolCommandSink for SuccessfulToolSink {
        fn handle(
            &self,
            _: AuthenticatedHierarchyCaller,
            _: v1::ToolCommand,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<v1::tool_result_request::Result, ExecutorError>>
                    + Send
                    + '_,
            >,
        > {
            self.0.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {
                Ok(v1::tool_result_request::Result::Success(
                    v1::ToolCallResult {
                        output: br#"{"ok":true}"#.to_vec(),
                        artifacts: vec![],
                    },
                ))
            })
        }
    }

    fn tool_command(identity: &v1::InstanceIdentity) -> v1::ToolCommand {
        v1::ToolCommand {
            request_id: Uuid::from_u128(620).as_bytes().to_vec(),
            session_id: identity.session_id.clone(),
            participant_id: identity.participant_id.clone(),
            operation_id: Uuid::from_u128(621).as_bytes().to_vec(),
            tool_name: "records.lookup".into(),
            tool_version: "v1".into(),
            input: b"{}".to_vec(),
            authority_grant_id: Vec::new(),
            approval_grant_id: Vec::new(),
        }
    }

    #[tokio::test]
    async fn uninstalled_tool_sink_fails_typed_and_effect_free() {
        let lease = delivery_lease(DeliveryAttemptId::from_uuid(Uuid::from_u128(622)).unwrap());
        let identity = report_identity_for(&lease);
        let result = apply_tool_command(None, &identity, lease.owner, tool_command(&identity))
            .await
            .unwrap();
        let v1::tool_result_request::Result::Failure(failure) = result else {
            panic!("uninstalled sink unexpectedly succeeded")
        };
        assert_eq!(failure.code, v1::FailureCode::Unavailable as i32);
    }

    #[tokio::test]
    async fn tool_sink_result_and_caller_context_are_exact() {
        let lease = delivery_lease(DeliveryAttemptId::from_uuid(Uuid::from_u128(623)).unwrap());
        let identity = report_identity_for(&lease);
        let sink: Arc<dyn ToolCommandSink> = Arc::new(SuccessfulToolSink(AtomicUsize::new(0)));
        assert!(matches!(
            apply_tool_command(Some(&sink), &identity, lease.owner, tool_command(&identity))
                .await
                .unwrap(),
            v1::tool_result_request::Result::Success(_)
        ));
        let mut mutant = tool_command(&identity);
        mutant.participant_id = Uuid::from_u128(624).as_bytes().to_vec();
        assert!(
            apply_tool_command(Some(&sink), &identity, lease.owner, mutant)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn reobserved_tool_event_reuses_terminal_without_reapplying_sink() {
        let lease = delivery_lease(DeliveryAttemptId::from_uuid(Uuid::from_u128(625)).unwrap());
        let identity = report_identity_for(&lease);
        let operation_id = OperationId::from_uuid(Uuid::from_u128(621)).unwrap();
        let sink = Arc::new(SuccessfulToolSink(AtomicUsize::new(0)));
        let erased: Arc<dyn ToolCommandSink> = sink.clone();
        let correlations = Mutex::new(ToolRuntimeCorrelations::default());
        let command = tool_command(&identity);
        let first = resolve_tool_command(
            &correlations,
            Some(&erased),
            &identity,
            lease.owner,
            operation_id,
            command.clone(),
        )
        .await
        .unwrap();
        let replay = resolve_tool_command(
            &correlations,
            Some(&erased),
            &identity,
            lease.owner,
            operation_id,
            command,
        )
        .await
        .unwrap();
        assert_eq!(first, replay);
        assert_eq!(sink.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn driver_event_sequence_rejects_gap_duplicate_and_overflow() {
        assert!(is_exact_next_sequence(7, 8));
        assert!(!is_exact_next_sequence(7, 7));
        assert!(!is_exact_next_sequence(7, 9));
        assert!(!is_exact_next_sequence(u64::MAX, 0));
    }

    #[test]
    fn trusted_tool_catalog_is_reserved_and_changes_launch_bytes() {
        let base = serde_json::json!({"base_instructions":"fixed","secret_names":[]});
        let empty =
            trusted_configuration_with_catalog(base.clone(), serde_json::json!([])).unwrap();
        let registered = trusted_configuration_with_catalog(
            base.clone(),
            serde_json::json!([{"registration_id":"00000000000000000000000000000001","name":"Records.Lookup","version":"V1","input_schema":{"type":"object"}}]),
        ).unwrap();
        assert_ne!(Sha256::digest(empty), Sha256::digest(registered));
        assert!(
            trusted_configuration_with_catalog(
                serde_json::json!({"navigator_tool_catalog":[]}),
                serde_json::json!([])
            )
            .is_err()
        );
        assert!(trusted_configuration_with_catalog(base, serde_json::json!({})).is_err());
        let entry = serde_json::json!({
            "registration_id":"00000000000000000000000000000001",
            "name":"Records.Lookup","version":"V1","input_schema":{"type":"object"}
        });
        assert!(TrustedToolCatalog::new(serde_json::json!(vec![entry.clone(); 64])).is_ok());
        assert!(TrustedToolCatalog::new(serde_json::json!(vec![entry; 65])).is_err());
        assert!(TrustedToolCatalog::new(serde_json::json!([{}])).is_err());
        assert!(
            TrustedToolCatalog::new(serde_json::json!([{
                "registration_id":"00000000000000000000000000000000",
                "name":"Records.Lookup","version":"V1","input_schema":{"type":"object"}
            }]))
            .is_err()
        );
    }

    #[test]
    fn active_lifecycle_is_bound_to_operation_policy_and_registration_catalog_identity() {
        let base = [7_u8; 32];
        let participant = ParticipantId::from_uuid(Uuid::from_u128(710)).unwrap();
        let epoch = FencingEpoch::new(3).unwrap();
        let entries = serde_json::json!([{
            "registration_id":"00000000000000000000000000000711",
            "name":"records.lookup","version":"v1","input_schema":{"type":"object"}
        }]);
        let operation_a = TrustedToolCatalog::new_bound(
            entries.clone(),
            &serde_json::json!({
                "operation_id":"00000000000000000000000000000712","policy":"a","registrations":"a"
            }),
        )
        .unwrap();
        let operation_b = TrustedToolCatalog::new_bound(
            entries.clone(),
            &serde_json::json!({
                "operation_id":"00000000000000000000000000000713","policy":"a","registrations":"a"
            }),
        )
        .unwrap();
        let policy_revoked = TrustedToolCatalog::new_bound(entries.clone(), &serde_json::json!({
            "operation_id":"00000000000000000000000000000712","policy":"revoked","registrations":"a"
        })).unwrap();
        let registration_changed = TrustedToolCatalog::new_bound(
            entries,
            &serde_json::json!({
                "operation_id":"00000000000000000000000000000712","policy":"a","registrations":"b"
            }),
        )
        .unwrap();
        let identity_a = resolved_driver_identity(base, operation_a.identity);
        let variants = [operation_b, policy_revoked, registration_changed];
        let attempt_a = resolved_launch_attempt_id(participant, epoch, identity_a).unwrap();
        for variant in variants {
            let identity_b = resolved_driver_identity(base, variant.identity);
            // Rejects the old bug: comparing only `base` would reuse A here.
            assert!(!active_identity_matches(identity_a, identity_b));
            let attempt_b = resolved_launch_attempt_id(participant, epoch, identity_b).unwrap();
            // A stopped Instance cannot be mistaken for, or reconnect as, B.
            assert_ne!(attempt_a, attempt_b);
            assert_ne!(identity_a, identity_b);
        }
        assert!(active_identity_matches(identity_a, identity_a));
        assert_eq!(
            attempt_a,
            resolved_launch_attempt_id(participant, epoch, identity_a).unwrap(),
            "exact replay retains the same durable attempt identity"
        );
    }

    #[test]
    fn executable_catalog_lifecycle_reuses_or_drains_and_fences_exactly() {
        #[derive(Default)]
        struct FakeLifecycle {
            active: Option<([u8; 32], LaunchAttemptId)>,
            stopped: Vec<LaunchAttemptId>,
            launched: Vec<LaunchAttemptId>,
        }
        impl FakeLifecycle {
            fn reconcile(
                &mut self,
                participant: ParticipantId,
                epoch: FencingEpoch,
                resolved: [u8; 32],
                stop_succeeds: bool,
            ) -> Result<LaunchAttemptId, ()> {
                match catalog_lifecycle_action(self.active.map(|value| value.0), resolved) {
                    CatalogLifecycleAction::Reuse => return Ok(self.active.expect("active").1),
                    CatalogLifecycleAction::Replace => {
                        if !stop_succeeds {
                            return Err(());
                        }
                        self.stopped.push(self.active.take().expect("active").1);
                    }
                    CatalogLifecycleAction::Launch => {}
                }
                let attempt = resolved_launch_attempt_id(participant, epoch, resolved).unwrap();
                self.launched.push(attempt);
                self.active = Some((resolved, attempt));
                Ok(attempt)
            }
        }

        let participant = ParticipantId::from_uuid(Uuid::from_u128(720)).unwrap();
        let epoch = FencingEpoch::new(7).unwrap();
        let first_identity = [1; 32];
        let changed_identity = [2; 32];
        let mut lifecycle = FakeLifecycle::default();
        let first = lifecycle
            .reconcile(participant, epoch, first_identity, true)
            .unwrap();
        assert_eq!(
            lifecycle
                .reconcile(participant, epoch, first_identity, true)
                .unwrap(),
            first
        );
        assert_eq!(lifecycle.launched, vec![first]);

        assert!(
            lifecycle
                .reconcile(participant, epoch, changed_identity, false)
                .is_err()
        );
        assert!(lifecycle.stopped.is_empty());
        assert_eq!(lifecycle.launched, vec![first]);

        let replacement = lifecycle
            .reconcile(participant, epoch, changed_identity, true)
            .unwrap();
        assert_eq!(lifecycle.stopped, vec![first]);
        assert_eq!(lifecycle.launched, vec![first, replacement]);
        assert_ne!(first, replacement);
        let next_epoch = resolved_launch_attempt_id(
            participant,
            FencingEpoch::new(8).unwrap(),
            changed_identity,
        )
        .unwrap();
        assert_ne!(replacement, next_epoch, "stale attempt is fenced by epoch");

        assert!(active_cache_has_capacity(MAX_ACTIVE_DRIVER_CACHE - 1));
        assert!(!active_cache_has_capacity(MAX_ACTIVE_DRIVER_CACHE));
        let mut failed_bootstrap_cache = HashMap::new();
        assert!(
            cache_bootstrapped(
                &mut failed_bootstrap_cache,
                1_u8,
                Err::<u8, _>("bootstrap failed")
            )
            .is_err()
        );
        assert!(
            failed_bootstrap_cache.is_empty(),
            "failed bootstrap must never become active"
        );
        let mut epochs = std::collections::BTreeMap::new();
        for value in 1..=128_u64 {
            epochs.retain(|existing, _| existing == &value);
            epochs.insert(value, value);
            assert_eq!(
                epochs.len(),
                1,
                "epoch churn retains only the current attempt"
            );
        }
    }

    #[test]
    fn report_acceptance_is_bound_to_the_exact_delivery_attempt() {
        let exact = DeliveryAttemptId::from_uuid(Uuid::from_u128(604)).unwrap();
        let competing = DeliveryAttemptId::from_uuid(Uuid::from_u128(605)).unwrap();
        let lease = delivery_lease(exact);
        let identity = report_identity_for(&lease);
        let host = lease.owner;
        let pending = MessageDeliveryState::AcceptancePending { lease };
        let accepted = MessageDeliveryState::Accepted {
            attempt_id: exact,
            proof_digest: [7; 32],
            accepted_at: navigator_domain::Timestamp::new(101, 0).unwrap(),
        };

        assert_eq!(
            causal_acceptance_state(
                &pending,
                exact,
                host,
                &identity,
                Timestamp::new(99, 0).unwrap(),
            ),
            CausalAcceptanceState::Pending
        );
        assert_eq!(
            causal_acceptance_state(
                &accepted,
                exact,
                host,
                &identity,
                Timestamp::new(101, 0).unwrap(),
            ),
            CausalAcceptanceState::Accepted
        );
        assert_eq!(
            causal_acceptance_state(
                &pending,
                competing,
                host,
                &identity,
                Timestamp::new(99, 0).unwrap(),
            ),
            CausalAcceptanceState::Rejected
        );
        assert_eq!(
            causal_acceptance_state(
                &accepted,
                competing,
                host,
                &identity,
                Timestamp::new(101, 0).unwrap(),
            ),
            CausalAcceptanceState::Rejected
        );
    }

    #[test]
    fn report_acceptance_rejects_every_noncausal_delivery_state() {
        let attempt = DeliveryAttemptId::from_uuid(Uuid::from_u128(606)).unwrap();
        let lease = delivery_lease(attempt);
        let identity = report_identity_for(&lease);
        let host = lease.owner;
        let states = [
            MessageDeliveryState::Queued,
            MessageDeliveryState::AcceptanceUnknown { lease },
            MessageDeliveryState::DeadLetter {
                reason: navigator_domain::BoundedText::new("dead").unwrap(),
            },
            MessageDeliveryState::Uncertain {
                attempt_id: attempt,
                reason: navigator_domain::BoundedText::new("unknown").unwrap(),
            },
        ];
        for state in states {
            assert_eq!(
                causal_acceptance_state(
                    &state,
                    attempt,
                    host,
                    &identity,
                    Timestamp::new(99, 0).unwrap(),
                ),
                CausalAcceptanceState::Rejected,
                "state must not legitimize a Report: {state:?}"
            );
        }
    }

    #[test]
    fn pending_report_rejects_each_mismatched_fencing_dimension() {
        let attempt = DeliveryAttemptId::from_uuid(Uuid::from_u128(610)).unwrap();
        let lease = delivery_lease(attempt);
        let identity = report_identity_for(&lease);
        let host = lease.owner;
        let mut leases = Vec::new();

        let mut wrong_owner = lease.clone();
        wrong_owner.owner = HostId::from_uuid(Uuid::from_u128(611)).unwrap();
        leases.push(wrong_owner);
        let mut wrong_owner_epoch = lease.clone();
        wrong_owner_epoch.ownership_epoch = FencingEpoch::new(4).unwrap();
        leases.push(wrong_owner_epoch);
        let mut wrong_driver_epoch = lease.clone();
        wrong_driver_epoch.driver_ownership_epoch = FencingEpoch::new(4).unwrap();
        leases.push(wrong_driver_epoch);
        let mut wrong_launch = lease.clone();
        wrong_launch.driver_launch_attempt_id =
            LaunchAttemptId::from_uuid(Uuid::from_u128(612)).unwrap();
        leases.push(wrong_launch);
        let mut wrong_instance = lease;
        wrong_instance.instance_id = InstanceId::from_uuid(Uuid::from_u128(613)).unwrap();
        leases.push(wrong_instance);

        for lease in leases {
            assert_eq!(
                causal_acceptance_state(
                    &MessageDeliveryState::AcceptancePending { lease },
                    attempt,
                    host,
                    &identity,
                    Timestamp::new(99, 0).unwrap(),
                ),
                CausalAcceptanceState::Rejected
            );
        }
    }

    #[test]
    fn pending_report_rejects_expired_and_boundary_expired_leases() {
        let attempt = DeliveryAttemptId::from_uuid(Uuid::from_u128(614)).unwrap();
        let lease = delivery_lease(attempt);
        let identity = report_identity_for(&lease);
        let host = lease.owner;
        for now in [
            Timestamp::new(100, 0).unwrap(),
            Timestamp::new(101, 0).unwrap(),
        ] {
            assert_eq!(
                causal_acceptance_state(
                    &MessageDeliveryState::AcceptancePending {
                        lease: lease.clone(),
                    },
                    attempt,
                    host,
                    &identity,
                    now,
                ),
                CausalAcceptanceState::Rejected
            );
        }
    }

    #[test]
    fn pending_report_requires_exact_identity_and_commit_is_idempotent() {
        let operation = OperationId::from_uuid(Uuid::from_u128(501)).unwrap();
        let message = MessageId::from_uuid(Uuid::from_u128(502)).unwrap();
        let mut pending = Some(PendingReport {
            event_id: Uuid::from_u128(503).as_bytes().to_vec(),
            sequence: 7,
            operation_id: operation,
            message_id: message,
            delivery_attempt_id: DeliveryAttemptId::from_uuid(Uuid::from_u128(505)).unwrap(),
            request: None,
        });
        let mut sequence = 3;
        assert!(
            commit_pending_report(
                &mut pending,
                &mut sequence,
                OperationId::from_uuid(Uuid::from_u128(504)).unwrap(),
                message,
            )
            .is_err()
        );
        assert_eq!(sequence, 3);
        assert!(pending.is_some());
        commit_pending_report(&mut pending, &mut sequence, operation, message).unwrap();
        assert_eq!(sequence, 7);
        assert!(pending.is_none());
        commit_pending_report(&mut pending, &mut sequence, operation, message).unwrap();
    }

    #[test]
    fn shutdown_plan_orders_descendants_before_parents_and_keeps_siblings_together() {
        let levels = group_by_depth([(1, "root"), (2, "child"), (3, "grandchild"), (2, "sibling")]);
        let ordered = levels.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(ordered[0], (3, vec!["grandchild"]));
        assert_eq!(ordered[1], (2, vec!["child", "sibling"]));
        assert_eq!(ordered[2], (1, vec!["root"]));
    }

    #[test]
    fn default_shutdown_budget_is_finite_and_covers_each_active_hierarchy_member() {
        let per_attempt = Duration::from_millis(500);
        assert_eq!(
            bounded_hierarchy_shutdown_budget(per_attempt, 3),
            Duration::from_millis(1_500)
        );
        assert_eq!(
            bounded_hierarchy_shutdown_budget(per_attempt, 0),
            per_attempt
        );
    }

    #[test]
    fn watchdog_store_failure_requires_explicit_shutdown_reconciliation() {
        let result =
            completed_watchdog_shutdown(&Err(navigator_supervisor::SupervisorError::Store(
                navigator_store_api::StoreError::Unavailable,
            )));

        assert!(
            result.is_none(),
            "a transient watchdog failure must not suppress the explicit stop path"
        );
    }

    #[test]
    fn watchdog_terminal_outcomes_are_not_reinterpreted() {
        assert!(
            completed_watchdog_shutdown(&Ok(navigator_supervisor::StopOutcome::Stopped))
                .expect("stopped is terminal")
                .is_ok()
        );
        assert!(
            completed_watchdog_shutdown(&Ok(navigator_supervisor::StopOutcome::CleanupRequired))
                .expect("cleanup-required is terminal")
                .is_err(),
            "a proven cleanup obligation must remain fail-closed"
        );
    }

    #[tokio::test]
    async fn stale_watchdog_relaunch_requires_exact_gone_evidence() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let current = FencingEpoch::new(2).unwrap();
        for (observation, expected) in [
            (LiveObservation::Absent, true),
            (LiveObservation::DifferentInstance, true),
            (LiveObservation::SameUnauthenticatedInstance, false),
            (LiveObservation::Unreachable, false),
        ] {
            let inspections = Arc::new(AtomicUsize::new(0));
            let observed_inspections = Arc::clone(&inspections);
            let cleanup_required = Err(boundary_error());
            let gone = stale_watchdog_proves_identity_gone(
                false,
                Some(current),
                Some(&cleanup_required),
                |epoch| async move {
                    assert_eq!(epoch, current, "inspection must use the fresh epoch");
                    observed_inspections.fetch_add(1, Ordering::Relaxed);
                    Ok(observation)
                },
            )
            .await
            .unwrap();
            assert_eq!(gone, expected);
            assert_eq!(inspections.load(Ordering::Relaxed), 1);
        }

        let cleanup_required = Err(boundary_error());
        assert!(
            stale_watchdog_proves_identity_gone(
                false,
                Some(current),
                Some(&cleanup_required),
                |_| async { Err(boundary_error()) },
            )
            .await
            .is_err(),
            "an unreachable inspector must fail closed"
        );
    }

    #[tokio::test]
    async fn stale_watchdog_timeout_panic_success_and_missing_owner_never_inspect() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for (authoritative, epoch, watchdog) in [
            (true, FencingEpoch::new(1).ok(), Some(Ok(()))),
            (false, FencingEpoch::new(2).ok(), Some(Ok(()))),
            (false, FencingEpoch::new(2).ok(), None),
            (false, None, Some(Err(boundary_error()))),
        ] {
            let inspections = Arc::new(AtomicUsize::new(0));
            let observed_inspections = Arc::clone(&inspections);
            let gone = stale_watchdog_proves_identity_gone(
                authoritative,
                epoch,
                watchdog.as_ref(),
                |_| async move {
                    observed_inspections.fetch_add(1, Ordering::Relaxed);
                    Ok(LiveObservation::Absent)
                },
            )
            .await
            .unwrap();
            assert!(!gone);
            assert_eq!(inspections.load(Ordering::Relaxed), 0);
        }

        let stopped = tokio::spawn(async { Ok(navigator_supervisor::StopOutcome::Stopped) });
        assert!(
            finish_watchdog_handle(stopped, false, Duration::from_secs(1))
                .await
                .is_ok_and(|result| {
                    matches!(result, Ok(navigator_supervisor::StopOutcome::Stopped))
                })
        );
        let panicked = tokio::spawn(async {
            panic!("watchdog mutant");
            #[allow(unreachable_code)]
            Ok(navigator_supervisor::StopOutcome::Stopped)
        });
        assert!(
            finish_watchdog_handle(panicked, false, Duration::from_secs(1))
                .await
                .is_err(),
            "watchdog panic must remain inconclusive"
        );
        let timed_out = tokio::spawn(async {
            std::future::pending::<()>().await;
            Ok(navigator_supervisor::StopOutcome::Stopped)
        });
        assert!(
            finish_watchdog_handle(timed_out, false, Duration::from_millis(1))
                .await
                .is_err(),
            "watchdog timeout must abort and remain inconclusive"
        );
    }

    #[test]
    fn active_replacement_and_socket_replacement_are_never_removed() {
        let old = Arc::new(1_u8);
        let replacement = Arc::new(2_u8);
        let mut active = HashMap::from([(7_u8, Arc::clone(&replacement))]);
        assert!(!remove_active_if_same(&mut active, &7, &old));
        assert!(Arc::ptr_eq(active.get(&7).unwrap(), &replacement));
        assert!(remove_active_if_same(&mut active, &7, &replacement));
        assert!(!active.contains_key(&7));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.sock");
        let old_socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        let evidence = ControlSocketEvidence {
            path: path.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        drop(old_socket);
        std::fs::remove_file(&path).unwrap();
        let replacement_socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(evidence.remove_if_same().is_err());
        assert!(
            path.exists(),
            "replacement socket must survive stale cleanup"
        );
        drop(replacement_socket);
    }

    #[tokio::test]
    async fn shutdown_execution_waits_for_descendants_and_runs_siblings_in_parallel() {
        let started = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let worker_release = Arc::new(tokio::sync::Notify::new());
        let campaign_release = Arc::new(tokio::sync::Notify::new());
        let sibling_release = Arc::new(tokio::sync::Notify::new());
        let root_release = Arc::new(tokio::sync::Notify::new());
        let completed_levels = Arc::new(std::sync::Mutex::new(Vec::new()));
        let levels = group_by_depth([
            (1, ("root", Arc::clone(&root_release))),
            (2, ("campaign", Arc::clone(&campaign_release))),
            (2, ("sibling", Arc::clone(&sibling_release))),
            (3, ("worker", Arc::clone(&worker_release))),
        ]);
        let observed = Arc::clone(&started);
        let barriers = Arc::clone(&completed_levels);
        let shutdown = tokio::spawn(async move {
            let execution_barriers = Arc::clone(&barriers);
            execute_descendants_first(
                levels,
                move |(name, release)| {
                    let observed = Arc::clone(&observed);
                    let barriers = Arc::clone(&execution_barriers);
                    Box::pin(async move {
                        let completed = barriers.lock().unwrap().clone();
                        if matches!(name, "campaign" | "sibling") {
                            assert!(completed.contains(&3));
                        }
                        if name == "root" {
                            assert!(completed.contains(&2));
                        }
                        observed.lock().await.push(name);
                        release.notified().await;
                        name
                    })
                },
                move |depth, _| barriers.lock().unwrap().push(depth),
            )
            .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while started.lock().await.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(*started.lock().await, ["worker"]);
        worker_release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while started.lock().await.len() < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let second_level = started.lock().await.clone();
        assert_eq!(second_level.len(), 3);
        assert!(second_level[1..].contains(&"campaign"));
        assert!(second_level[1..].contains(&"sibling"));
        assert!(!second_level.contains(&"root"));

        campaign_release.notify_one();
        tokio::task::yield_now().await;
        assert!(!started.lock().await.contains(&"root"));
        sibling_release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while started.lock().await.len() < 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(started.lock().await.last(), Some(&"root"));
        root_release.notify_one();
        shutdown.await.unwrap();
    }

    #[test]
    fn session_shutdown_never_selects_an_instance_from_another_session() {
        let session_a = SessionId::from_uuid(Uuid::from_u128(610)).unwrap();
        let session_b = SessionId::from_uuid(Uuid::from_u128(611)).unwrap();
        let participant_a = ParticipantId::from_uuid(Uuid::from_u128(612)).unwrap();
        let participant_b = ParticipantId::from_uuid(Uuid::from_u128(613)).unwrap();
        let template = navigator_domain::TemplateId::from_uuid(Uuid::from_u128(614)).unwrap();
        let compatibility = navigator_domain::CompatibilityIdentity::from_bytes([7; 32]);
        let snapshot = |session_id, participant_id| navigator_store_api::ParticipantSnapshot {
            session_id,
            participant_id,
            parent_participant_id: None,
            depth: 1,
            template_id: template,
            template_compatibility: compatibility,
            revision: navigator_domain::Revision::initial(),
        };
        let participants = HashMap::from([
            (participant_a, snapshot(session_a, participant_a)),
            (participant_b, snapshot(session_b, participant_b)),
        ]);
        assert!(participant_matches_session(
            &participants,
            participant_a,
            Some(session_a)
        ));
        assert!(!participant_matches_session(
            &participants,
            participant_b,
            Some(session_a)
        ));
        assert!(participant_matches_session(
            &participants,
            participant_b,
            None
        ));
    }

    #[tokio::test]
    async fn same_depth_attempts_all_cleanup_futures_concurrently() {
        let release = Arc::new(Notify::new());
        let sibling_attempted = Arc::new(AtomicBool::new(false));
        let blocked = {
            let release = Arc::clone(&release);
            Box::pin(async move {
                release.notified().await;
                Err::<(), ()>(())
            }) as Pin<Box<dyn Future<Output = Result<(), ()>> + Send>>
        };
        let sibling = {
            let attempted = Arc::clone(&sibling_attempted);
            let release = Arc::clone(&release);
            Box::pin(async move {
                attempted.store(true, Ordering::Release);
                release.notify_waiters();
                Ok(())
            }) as Pin<Box<dyn Future<Output = Result<(), ()>> + Send>>
        };
        let results = join_all(vec![blocked, sibling]).await;
        assert!(sibling_attempted.load(Ordering::Acquire));
        assert_eq!(results, vec![Err(()), Ok(())]);
    }

    #[tokio::test]
    async fn approval_sink_is_pre_ack_exact_and_replay_preserves_correlation() {
        let caller = AuthenticatedHierarchyCaller {
            host_id: HostId::from_uuid(Uuid::from_u128(701)).unwrap(),
            session_id: SessionId::from_uuid(Uuid::from_u128(702)).unwrap(),
            participant_id: ParticipantId::from_uuid(Uuid::from_u128(703)).unwrap(),
            launch_attempt_id: LaunchAttemptId::from_uuid(Uuid::from_u128(704)).unwrap(),
            instance_id: InstanceId::from_uuid(Uuid::from_u128(705)).unwrap(),
            ownership_epoch: FencingEpoch::new(6).unwrap(),
        };
        let pending = PendingReport {
            event_id: Uuid::from_u128(706).as_bytes().to_vec(),
            sequence: 9,
            operation_id: OperationId::from_uuid(Uuid::from_u128(707)).unwrap(),
            message_id: MessageId::from_uuid(Uuid::from_u128(708)).unwrap(),
            delivery_attempt_id: DeliveryAttemptId::from_uuid(Uuid::from_u128(709)).unwrap(),
            request: None,
        };
        let request = AuthenticatedApprovalRequest {
            capability: Capability::new("repo.publish").unwrap(),
            resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
            summary: ApprovalSummary::new("publish main").unwrap(),
            expires_at: Timestamp::new(200, 0).unwrap(),
        };
        let sink = Arc::new(RecordingApprovalSink::default());
        let erased: Arc<dyn ApprovalCommandSink> = sink.clone();

        dispatch_approval_request(Some(erased.clone()), caller, &pending, request.clone())
            .await
            .unwrap();
        assert_eq!(
            pending.sequence, 9,
            "sink completion must precede cursor ACK"
        );
        dispatch_approval_request(Some(erased), caller, &pending, request.clone())
            .await
            .unwrap();
        let calls = sink.0.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0], calls[1],
            "replay must preserve every causal dimension"
        );
        assert_eq!(calls[0].caller, caller);
        assert_eq!(calls[0].event_id, pending.event_id);
        assert_eq!(calls[0].operation_id, pending.operation_id);
        assert_eq!(calls[0].message_id, pending.message_id);
        assert_eq!(calls[0].delivery_attempt_id, pending.delivery_attempt_id);
        assert_eq!(calls[0].request, request);
    }

    #[tokio::test]
    async fn missing_approval_sink_has_zero_calls_and_cannot_advance_ack_state() {
        let pending = PendingReport {
            event_id: Uuid::from_u128(710).as_bytes().to_vec(),
            sequence: 11,
            operation_id: OperationId::from_uuid(Uuid::from_u128(711)).unwrap(),
            message_id: MessageId::from_uuid(Uuid::from_u128(712)).unwrap(),
            delivery_attempt_id: DeliveryAttemptId::from_uuid(Uuid::from_u128(713)).unwrap(),
            request: None,
        };
        let caller = AuthenticatedHierarchyCaller {
            host_id: HostId::from_uuid(Uuid::from_u128(714)).unwrap(),
            session_id: SessionId::from_uuid(Uuid::from_u128(715)).unwrap(),
            participant_id: ParticipantId::from_uuid(Uuid::from_u128(716)).unwrap(),
            launch_attempt_id: LaunchAttemptId::from_uuid(Uuid::from_u128(717)).unwrap(),
            instance_id: InstanceId::from_uuid(Uuid::from_u128(718)).unwrap(),
            ownership_epoch: FencingEpoch::new(8).unwrap(),
        };
        let request = AuthenticatedApprovalRequest {
            capability: Capability::new("repo.publish").unwrap(),
            resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
            summary: ApprovalSummary::new("publish main").unwrap(),
            expires_at: Timestamp::new(200, 0).unwrap(),
        };
        assert!(
            dispatch_approval_request(None, caller, &pending, request)
                .await
                .is_err()
        );
        assert_eq!(pending.sequence, 11);
    }

    fn denied_approval_relay_fixture() -> (MessageSnapshot, navigator_domain::ApprovalRequest) {
        let session_id = SessionId::from_uuid(Uuid::from_u128(801)).unwrap();
        let requester_id = ParticipantId::from_uuid(Uuid::from_u128(802)).unwrap();
        let coordinator_id = ParticipantId::from_uuid(Uuid::from_u128(803)).unwrap();
        let operation_id = OperationId::from_uuid(Uuid::from_u128(804)).unwrap();
        let source_message_id = MessageId::from_uuid(Uuid::from_u128(805)).unwrap();
        let approval_id =
            navigator_domain::ApprovalRequestId::from_uuid(Uuid::from_u128(806)).unwrap();
        let now = Timestamp::new(100, 0).unwrap();
        let request = navigator_domain::ApprovalRequest {
            id: approval_id,
            session_id,
            requester_id,
            operation_id,
            source_message_id,
            source_delivery_attempt_id: DeliveryAttemptId::from_uuid(Uuid::from_u128(807)).unwrap(),
            coordinator_id,
            capability: Capability::new("repo.publish").unwrap(),
            resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
            summary: ApprovalSummary::new("publish main").unwrap(),
            status: ApprovalStatus::Denied,
            expires_at: Timestamp::new(200, 0).unwrap(),
            grant_id: None,
            decision_source: Some(navigator_domain::ApprovalDecisionSource::TrustedConsumer),
            created_at: now,
            decided_at: Some(Timestamp::new(110, 0).unwrap()),
            revision: navigator_domain::Revision::new(2).unwrap(),
        };
        let message = MessageSnapshot {
            session_id,
            message_id: MessageId::from_uuid(Uuid::from_u128(808)).unwrap(),
            source: coordinator_id,
            destination: requester_id,
            mailbox_sequence: 1,
            priority: navigator_store_api::MessagePriority::Control,
            correlation: navigator_store_api::MessageCorrelation {
                operation_id: Some(operation_id),
                in_reply_to: Some(source_message_id),
            },
            envelope: ValidatedMessageEnvelope::approval_decision(
                approval_id,
                operation_id,
                ApprovalStatus::Denied,
                None,
            ),
            attempt_count: 0,
            state: MessageDeliveryState::Queued,
            revision: navigator_domain::Revision::initial(),
            created_at: now,
            updated_at: now,
        };
        (message, request)
    }

    #[test]
    fn approval_decision_relay_is_exact_replayable_and_rejects_cross_scope() {
        let (message, request) = denied_approval_relay_fixture();
        assert!(approval_decision_matches(&message, &request, None));
        assert!(
            approval_decision_matches(&message, &request, None),
            "exact replay is idempotent"
        );

        let mut mutant = message.clone();
        mutant.destination = ParticipantId::from_uuid(Uuid::from_u128(809)).unwrap();
        assert!(!approval_decision_matches(&mutant, &request, None));
        let mut mutant = message.clone();
        mutant.source = ParticipantId::from_uuid(Uuid::from_u128(810)).unwrap();
        assert!(!approval_decision_matches(&mutant, &request, None));
        let mut mutant = message.clone();
        mutant.correlation.operation_id =
            Some(OperationId::from_uuid(Uuid::from_u128(811)).unwrap());
        assert!(!approval_decision_matches(&mutant, &request, None));
        let mut mutant = message.clone();
        mutant.correlation.in_reply_to = Some(MessageId::from_uuid(Uuid::from_u128(812)).unwrap());
        assert!(!approval_decision_matches(&mutant, &request, None));
        let mut mutant = message.clone();
        mutant.envelope = ValidatedMessageEnvelope::approval_decision(
            request.id,
            request.operation_id,
            ApprovalStatus::Granted,
            None,
        );
        assert!(!approval_decision_matches(&mutant, &request, None));
        let mut mutant = message;
        mutant.envelope = ValidatedMessageEnvelope::approval_decision(
            navigator_domain::ApprovalRequestId::from_uuid(Uuid::from_u128(813)).unwrap(),
            request.operation_id,
            ApprovalStatus::Denied,
            None,
        );
        assert!(!approval_decision_matches(&mutant, &request, None));
    }
}
