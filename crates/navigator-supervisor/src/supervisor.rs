use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use hmac::{Hmac, Mac};
use navigator_domain::{
    BoundedText, DriverId, FencingEpoch, HostId, InstanceId, LaunchAttemptId, LiveObservation,
    ParticipantId, RequestId, SessionId,
};
use navigator_driver_client::{DriverClient, DriverCredential, StartParameters};
use navigator_driver_protocol::{PROTOCOL_V1, v1};
use navigator_store_api::{
    AttachLaunch, InstanceStore, LaunchSnapshot, LaunchState, PrepareLaunch, ProcessEvidence,
    RequestContext, StoreError, TransitionLaunch,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Clone)]
pub struct LaunchPlan {
    pub session_id: SessionId,
    pub participant_id: ParticipantId,
    pub driver_id: DriverId,
    pub driver_configuration_digest: [u8; 32],
    pub attempt_id: LaunchAttemptId,
    pub instance_id: InstanceId,
    pub host_id: HostId,
    pub ownership_epoch: FencingEpoch,
    pub prepare_request_id: RequestId,
    pub attach_request_id: RequestId,
    pub compensation_request_id: RequestId,
    pub compensation_terminal_request_id: RequestId,
    pub program: PathBuf,
    pub expected_executable_identity: [u8; 32],
    pub arguments: Vec<OsString>,
    pub working_directory: PathBuf,
    pub environment: BTreeMap<OsString, OsString>,
    pub environment_allowlist: BTreeSet<OsString>,
    pub ownership_channel: OwnershipChannel,
    pub process_io_mode: ProcessIoMode,
    pub bootstrap_configuration: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OwnershipChannel {
    #[default]
    Stdin,
    DedicatedFd,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ProcessIoMode {
    #[default]
    Headless,
    TerminalPty,
}

impl std::fmt::Debug for LaunchPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LaunchPlan")
            .field("session_id", &self.session_id)
            .field("participant_id", &self.participant_id)
            .field("driver_id", &self.driver_id)
            .field("attempt_id", &self.attempt_id)
            .field("instance_id", &self.instance_id)
            .field("host_id", &self.host_id)
            .field("ownership_epoch", &self.ownership_epoch)
            .field("process_io_mode", &self.process_io_mode)
            .field("program", &self.program)
            .field(
                "expected_executable_identity",
                &self.expected_executable_identity,
            )
            .field("working_directory", &self.working_directory)
            .field("arguments", &"[redacted]")
            .field("environment", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StopRequestIds {
    pub stopping: RequestId,
    pub terminal: RequestId,
}

#[derive(Clone, Copy, Debug)]
pub struct ReconcileRequestIds {
    pub cleanup: RequestId,
    pub stop: StopRequestIds,
}

#[derive(Clone, Copy, Debug)]
pub struct ReadyRequest {
    pub request_id: RequestId,
    pub attempt_id: LaunchAttemptId,
    pub host_id: HostId,
    pub ownership_epoch: FencingEpoch,
    pub nonce: [u8; 32],
}

pub struct DriverBootstrapRequest {
    pub attempt_id: LaunchAttemptId,
    pub host_id: HostId,
    pub epoch: FencingEpoch,
    pub socket: PathBuf,
    pub timeout: Duration,
    pub start_request_id: RequestId,
    pub ready_request_id: RequestId,
    pub trusted_configuration: Vec<u8>,
    pub required_capabilities: Vec<v1::CapabilityRequirement>,
    /// Catalog capabilities the authenticated Driver must advertise exactly.
    pub expected_capabilities: Vec<v1::Capability>,
    pub cleanup_ids: StopRequestIds,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FaultPoint {
    BeforeSpawn,
    AfterSpawn,
    AfterAttach,
    BeforeReady,
}

pub trait FaultInjector: Send + Sync + 'static {
    fn hit(&self, point: FaultPoint) -> Result<(), SupervisorError>;
}

#[derive(Default)]
pub struct NoFaults;

impl FaultInjector for NoFaults {
    fn hit(&self, _point: FaultPoint) -> Result<(), SupervisorError> {
        Ok(())
    }
}

pub trait CredentialSource: Send + 'static {
    fn next_credential(&mut self) -> Result<Vec<u8>, SupervisorError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityObservation {
    Same,
    Exited,
    Mismatch,
}

pub trait ProcessBackend: Send + Sync + 'static {
    fn spawn(
        &self,
        plan: &LaunchPlan,
        credential: &[u8],
    ) -> impl Future<Output = Result<ProcessEvidence, SupervisorError>> + Send;

    fn inspect(
        &self,
        attempt_id: LaunchAttemptId,
        expected: &ProcessEvidence,
    ) -> impl Future<Output = Result<IdentityObservation, SupervisorError>> + Send;

    fn graceful_stop(
        &self,
        attempt_id: LaunchAttemptId,
        expected: &ProcessEvidence,
    ) -> impl Future<Output = Result<(), SupervisorError>> + Send;

    fn force_stop_group(
        &self,
        attempt_id: LaunchAttemptId,
        expected: &ProcessEvidence,
    ) -> impl Future<Output = Result<(), SupervisorError>> + Send;

    fn wait_for_exit(
        &self,
        attempt_id: LaunchAttemptId,
        timeout: Duration,
    ) -> impl Future<Output = Result<bool, SupervisorError>> + Send;

    fn revoke_ownership(
        &self,
        attempt_id: LaunchAttemptId,
    ) -> impl Future<Output = Result<(), SupervisorError>> + Send;

    fn cleanup(
        &self,
        attempt_id: LaunchAttemptId,
    ) -> impl Future<Output = Result<(), SupervisorError>> + Send;
}

#[derive(Clone, Copy, Debug)]
pub struct SupervisorConfig {
    pub graceful_timeout: Duration,
    pub forced_timeout: Duration,
    pub ownership_loss_timeout: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopOutcome {
    Stopped,
    AlreadyStopped,
    CleanupRequired,
}

#[derive(Default)]
pub struct LifecycleFence {
    terminal: std::sync::atomic::AtomicBool,
    boundary: Mutex<()>,
}

impl LifecycleFence {
    pub fn close(&self) {
        let _boundary = self
            .boundary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.terminal
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub fn while_open<T>(&self, action: impl FnOnce() -> T) -> Option<T> {
        let _boundary = self
            .boundary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (!self.terminal.load(std::sync::atomic::Ordering::Acquire)).then(action)
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.terminal.load(std::sync::atomic::Ordering::Acquire)
    }
}

fn set_terminal_fence(fence: Option<&LifecycleFence>) {
    if let Some(fence) = fence {
        fence.close();
    }
}

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("launch Store rejected the operation")]
    Store(#[from] StoreError),
    #[error("environment contains a key outside the explicit allowlist")]
    EnvironmentDenied,
    #[error("bootstrap credential is invalid")]
    InvalidCredential,
    #[error("Instance ready proof is invalid")]
    Authentication,
    #[error("Instance identity cannot be verified")]
    IdentityMismatch,
    #[error("Instance is not attached")]
    NotAttached,
    #[error("Instance is not ready")]
    NotReady,
    #[error("durable launch state requires explicit reconciliation")]
    ReconciliationRequired,
    #[error("process backend failed")]
    Process,
    #[error("bounded process I/O deadline elapsed")]
    Timeout,
    #[error("process cleanup could not be verified")]
    CleanupRequired,
    #[error("fault injected at {0:?}")]
    Injected(FaultPoint),
}

struct RuntimeBinding {
    evidence: ProcessEvidence,
    credential: Vec<u8>,
}

pub struct InstanceSupervisor<S, B, C, F = NoFaults> {
    store: Arc<S>,
    backend: Arc<B>,
    credentials: Mutex<C>,
    faults: Arc<F>,
    config: SupervisorConfig,
    launch_lock: tokio::sync::Mutex<()>,
    active: tokio::sync::Mutex<HashMap<LaunchAttemptId, RuntimeBinding>>,
}

impl<S, C, F> InstanceSupervisor<S, crate::UnixProcessBackend, C, F> {
    /// Returns the control endpoint inside the backend-owned attempt directory.
    #[must_use]
    pub fn managed_control_socket_path(&self, attempt_id: LaunchAttemptId) -> PathBuf {
        self.backend.managed_control_socket_path(attempt_id)
    }
}

impl<S, B, C> InstanceSupervisor<S, B, C, NoFaults> {
    #[must_use]
    pub fn new(store: Arc<S>, backend: Arc<B>, credentials: C, config: SupervisorConfig) -> Self {
        Self::with_faults(store, backend, credentials, Arc::new(NoFaults), config)
    }
}

impl<S, B, C, F> InstanceSupervisor<S, B, C, F> {
    #[must_use]
    pub fn with_faults(
        store: Arc<S>,
        backend: Arc<B>,
        credentials: C,
        faults: Arc<F>,
        config: SupervisorConfig,
    ) -> Self {
        Self {
            store,
            backend,
            credentials: Mutex::new(credentials),
            faults,
            config,
            launch_lock: tokio::sync::Mutex::new(()),
            active: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
}

impl<S, B, C, F> InstanceSupervisor<S, B, C, F>
where
    S: InstanceStore + 'static,
    B: ProcessBackend,
    C: CredentialSource,
    F: FaultInjector,
{
    /// Inspects durable process identity only after validating the fresh owner.
    /// A matching process is deliberately *not* called authenticated: recovery
    /// must complete the Driver handshake under `epoch` before that claim.
    pub async fn inspect_for_recovery(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: HostId,
        epoch: FencingEpoch,
    ) -> Result<LiveObservation, SupervisorError> {
        let snapshot = self.store.load_launch(attempt_id).await?;
        self.store
            .validate_launch_authority(snapshot.session_id, host_id, epoch)
            .await?;
        if snapshot.state == LaunchState::Stopped {
            return Ok(LiveObservation::Absent);
        }
        let Some(evidence) = snapshot.evidence.as_ref() else {
            return Ok(if snapshot.state == LaunchState::Prepared {
                LiveObservation::Absent
            } else {
                LiveObservation::Unreachable
            });
        };
        Ok(match self.backend.inspect(attempt_id, evidence).await? {
            IdentityObservation::Exited => LiveObservation::Absent,
            IdentityObservation::Mismatch => LiveObservation::DifferentInstance,
            IdentityObservation::Same => LiveObservation::SameUnauthenticatedInstance,
        })
    }

    #[must_use]
    pub fn configured_stop_budget(&self) -> Duration {
        self.config
            .graceful_timeout
            .saturating_add(self.config.forced_timeout)
            .saturating_add(Duration::from_millis(100))
    }

    #[must_use]
    pub fn process_stop_budget(&self) -> Duration {
        self.config
            .graceful_timeout
            .saturating_add(self.config.forced_timeout)
    }

    /// Maximum time for ownership revocation followed by verified escalation.
    #[must_use]
    pub fn ownership_cleanup_budget(&self) -> Duration {
        self.config
            .ownership_loss_timeout
            .saturating_add(self.configured_stop_budget())
    }
    pub async fn reconnect_ready(
        &self,
        request: DriverBootstrapRequest,
    ) -> Result<(LaunchSnapshot, DriverClient, v1::InstanceIdentity), SupervisorError> {
        let snapshot = self.store.load_launch(request.attempt_id).await?;
        if snapshot.state != LaunchState::Ready {
            return Err(SupervisorError::NotReady);
        }
        self.store
            .validate_launch_authority(snapshot.session_id, request.host_id, request.epoch)
            .await?;
        let credential = self
            .active
            .lock()
            .await
            .get(&request.attempt_id)
            .map(|binding| binding.credential.clone())
            .ok_or(SupervisorError::NotAttached)?;
        let expected_instance = snapshot.instance_id.ok_or(SupervisorError::NotReady)?;
        let channel = OpenDriverRequest {
            socket: request.socket,
            timeout: request.timeout,
            credential,
            expected_driver: snapshot.driver_id,
            required_capabilities: request.required_capabilities,
            expected_capabilities: request.expected_capabilities,
            start_request_id: request.start_request_id,
            participant_id: snapshot.participant_id,
            attempt_id: snapshot.attempt_id,
            expected_instance,
            session_id: snapshot.session_id,
            epoch: request.epoch,
            trusted_configuration: request.trusted_configuration,
        };
        let (client, identity) =
            tokio::task::spawn_blocking(move || open_authenticated_driver(channel))
                .await
                .map_err(|_| SupervisorError::Process)??;
        if identity.driver_id != snapshot.driver_id.as_uuid().as_bytes()
            || identity.session_id != snapshot.session_id.as_uuid().as_bytes()
            || identity.participant_id != snapshot.participant_id.as_uuid().as_bytes()
            || identity.launch_attempt_id != snapshot.attempt_id.as_uuid().as_bytes()
            || identity.instance_id != expected_instance.as_uuid().as_bytes()
            || identity.ownership_epoch != request.epoch.get()
        {
            return Err(SupervisorError::IdentityMismatch);
        }
        Ok((snapshot, client, identity))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "authenticated bootstrap compensation remains one auditable transaction boundary"
    )]
    pub async fn connect_start_ready(
        &self,
        request: DriverBootstrapRequest,
    ) -> Result<(LaunchSnapshot, DriverClient, v1::InstanceIdentity), SupervisorError> {
        let DriverBootstrapRequest {
            attempt_id,
            host_id,
            epoch,
            socket,
            timeout,
            start_request_id,
            ready_request_id,
            trusted_configuration,
            required_capabilities,
            expected_capabilities,
            cleanup_ids,
        } = request;
        let snapshot = self.store.load_launch(attempt_id).await?;
        if snapshot.state != LaunchState::Attached {
            return Err(SupervisorError::NotAttached);
        }
        self.store
            .validate_launch_authority(snapshot.session_id, host_id, epoch)
            .await?;
        let credential = self
            .active
            .lock()
            .await
            .get(&attempt_id)
            .map(|binding| binding.credential.clone())
            .ok_or(SupervisorError::NotAttached)?;
        let participant_id = snapshot.participant_id;
        let session_id = snapshot.session_id;
        let expected_instance = snapshot.instance_id.ok_or(SupervisorError::NotAttached)?;
        let channel = OpenDriverRequest {
            socket,
            timeout,
            credential,
            expected_driver: snapshot.driver_id,
            required_capabilities,
            expected_capabilities,
            start_request_id,
            participant_id,
            attempt_id,
            expected_instance,
            session_id,
            epoch,
            trusted_configuration,
        };
        let opened = tokio::task::spawn_blocking(move || open_authenticated_driver(channel)).await;
        let (client, identity) = match opened {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                return Err(self
                    .compensate_bootstrap(attempt_id, host_id, epoch, cleanup_ids, error)
                    .await);
            }
            Err(_) => {
                return Err(self
                    .compensate_bootstrap(
                        attempt_id,
                        host_id,
                        epoch,
                        cleanup_ids,
                        SupervisorError::Process,
                    )
                    .await);
            }
        };
        if identity.driver_id != snapshot.driver_id.as_uuid().as_bytes()
            || identity.session_id != session_id.as_uuid().as_bytes()
            || identity.participant_id != participant_id.as_uuid().as_bytes()
            || identity.launch_attempt_id != attempt_id.as_uuid().as_bytes()
            || identity.instance_id != expected_instance.as_uuid().as_bytes()
            || identity.ownership_epoch != epoch.get()
        {
            return Err(self
                .compensate_bootstrap(
                    attempt_id,
                    host_id,
                    epoch,
                    cleanup_ids,
                    SupervisorError::IdentityMismatch,
                )
                .await);
        }
        let nonce = Sha256::digest(ready_request_id.as_uuid().as_bytes()).into();
        let ready_credential = self
            .active
            .lock()
            .await
            .get(&attempt_id)
            .map(|binding| binding.credential.clone());
        let proof = match ready_credential {
            Some(credential) => ready_proof(
                &credential,
                session_id,
                expected_instance,
                attempt_id,
                epoch,
                nonce,
            ),
            None => Err(SupervisorError::NotAttached),
        };
        let proof = match proof {
            Ok(value) => value,
            Err(error) => {
                return Err(self
                    .compensate_bootstrap(attempt_id, host_id, epoch, cleanup_ids, error)
                    .await);
            }
        };
        let ready = match self
            .ready(
                ReadyRequest {
                    request_id: ready_request_id,
                    attempt_id,
                    host_id,
                    ownership_epoch: epoch,
                    nonce,
                },
                &proof,
            )
            .await
        {
            Ok(value) => value,
            Err(error) => {
                return Err(self
                    .compensate_bootstrap(attempt_id, host_id, epoch, cleanup_ids, error)
                    .await);
            }
        };
        Ok((ready, client, identity))
    }

    async fn compensate_bootstrap(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: HostId,
        epoch: FencingEpoch,
        ids: StopRequestIds,
        error: SupervisorError,
    ) -> SupervisorError {
        match self.stop(attempt_id, host_id, epoch, ids).await {
            Ok(StopOutcome::Stopped | StopOutcome::AlreadyStopped) => error,
            Ok(StopOutcome::CleanupRequired) | Err(_) => SupervisorError::CleanupRequired,
        }
    }

    pub async fn launch(&self, plan: LaunchPlan) -> Result<LaunchSnapshot, SupervisorError> {
        let _launch_guard = self.launch_lock.lock().await;
        validate_environment(&plan)?;
        let credential = self
            .credentials
            .lock()
            .expect("credential source poisoned")
            .next_credential()?;
        if credential.len() < 32 || credential.len() > 4096 {
            return Err(SupervisorError::InvalidCredential);
        }
        let credential_digest = credential_digest(&credential);
        let prepared_mutation = self
            .store
            .prepare_launch(PrepareLaunch {
                context: RequestContext::new(plan.prepare_request_id, plan.host_id),
                epoch: plan.ownership_epoch,
                session_id: plan.session_id,
                participant_id: plan.participant_id,
                driver_id: plan.driver_id,
                driver_configuration_digest: plan.driver_configuration_digest,
                attempt_id: plan.attempt_id,
                credential_digest,
            })
            .await?;
        let prepared = prepared_mutation.value().clone();
        if !matches!(prepared_mutation, navigator_store_api::Mutation::Applied(_)) {
            return if prepared.state == LaunchState::Prepared {
                Err(SupervisorError::ReconciliationRequired)
            } else {
                Ok(prepared)
            };
        }
        if let Err(error) = self.faults.hit(FaultPoint::BeforeSpawn) {
            self.classify_without_process(&plan, prepared).await;
            return Err(error);
        }
        let evidence = self.backend.spawn(&plan, &credential).await?;
        self.active.lock().await.insert(
            plan.attempt_id,
            RuntimeBinding {
                evidence: evidence.clone(),
                credential,
            },
        );
        if let Err(error) = self.faults.hit(FaultPoint::AfterSpawn) {
            self.compensate_launch(&plan, &evidence).await;
            return Err(error);
        }
        let attached = match self
            .store
            .attach_launch(AttachLaunch {
                context: RequestContext::new(plan.attach_request_id, plan.host_id),
                session_id: plan.session_id,
                epoch: plan.ownership_epoch,
                attempt_id: plan.attempt_id,
                expected_revision: prepared.revision,
                instance_id: plan.instance_id,
                evidence: evidence.clone(),
            })
            .await
        {
            Ok(mutation) => mutation.value().clone(),
            Err(error) => {
                self.compensate_launch(&plan, &evidence).await;
                return Err(error.into());
            }
        };
        if let Err(error) = self.faults.hit(FaultPoint::AfterAttach) {
            self.compensate_launch(&plan, &evidence).await;
            return Err(error);
        }
        Ok(attached)
    }

    pub async fn ready(
        &self,
        request: ReadyRequest,
        proof: &[u8],
    ) -> Result<LaunchSnapshot, SupervisorError> {
        self.faults.hit(FaultPoint::BeforeReady)?;
        let snapshot = self.store.load_launch(request.attempt_id).await?;
        let (evidence, expected_proof) = {
            let bindings = self.active.lock().await;
            let binding = bindings
                .get(&request.attempt_id)
                .ok_or(SupervisorError::NotAttached)?;
            (
                binding.evidence.clone(),
                ready_proof(
                    &binding.credential,
                    snapshot.session_id,
                    snapshot.instance_id.ok_or(SupervisorError::NotAttached)?,
                    request.attempt_id,
                    request.ownership_epoch,
                    request.nonce,
                )?,
            )
        };
        if !constant_time_eq(proof, &expected_proof) {
            return Err(SupervisorError::Authentication);
        }
        if self.backend.inspect(request.attempt_id, &evidence).await? != IdentityObservation::Same {
            return Err(SupervisorError::IdentityMismatch);
        }
        Ok(self
            .store
            .transition_launch(TransitionLaunch {
                context: RequestContext::new(request.request_id, request.host_id),
                session_id: snapshot.session_id,
                epoch: request.ownership_epoch,
                attempt_id: request.attempt_id,
                expected_revision: snapshot.revision,
                target: LaunchState::Ready,
                cleanup_reason: None,
            })
            .await?
            .value()
            .clone())
    }

    pub async fn require_ready(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: HostId,
        epoch: FencingEpoch,
    ) -> Result<LaunchSnapshot, SupervisorError> {
        let snapshot = self.store.load_launch(attempt_id).await?;
        if snapshot.state != LaunchState::Ready {
            return Err(SupervisorError::NotReady);
        }
        self.store
            .validate_launch_authority(snapshot.session_id, host_id, epoch)
            .await?;
        Ok(snapshot)
    }

    pub async fn stop(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: HostId,
        epoch: FencingEpoch,
        ids: StopRequestIds,
    ) -> Result<StopOutcome, SupervisorError> {
        let budget = self
            .config
            .graceful_timeout
            .saturating_add(self.config.forced_timeout);
        self.stop_with_deadline(
            attempt_id,
            host_id,
            epoch,
            ids,
            tokio::time::Instant::now() + budget + Duration::from_millis(100),
        )
        .await
    }

    pub async fn stop_with_deadline(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: HostId,
        epoch: FencingEpoch,
        ids: StopRequestIds,
        deadline: tokio::time::Instant,
    ) -> Result<StopOutcome, SupervisorError> {
        let snapshot = self.store.load_launch(attempt_id).await?;
        if snapshot.state == LaunchState::Stopped {
            return Ok(StopOutcome::AlreadyStopped);
        }
        if snapshot.state == LaunchState::CleanupRequired && tokio::time::Instant::now() >= deadline
        {
            return Ok(StopOutcome::CleanupRequired);
        }
        // Fencing is checked before process identity inspection as well as
        // before every possible signal. Persisted `Stopping` and
        // `CleanupRequired` states must not let a superseded host bypass the
        // transition-time authority check.
        self.store
            .validate_launch_authority(snapshot.session_id, host_id, epoch)
            .await?;
        let evidence = snapshot
            .evidence
            .clone()
            .ok_or(SupervisorError::NotAttached)?;
        if tokio::time::Instant::now() >= deadline {
            let reason = BoundedText::new(
                "process identity or termination could not be proven before the shutdown deadline",
            )
            .map_err(|_| SupervisorError::Process)?;
            self.transition_terminal_with_retry(
                TransitionLaunch {
                    context: RequestContext::new(ids.terminal, host_id),
                    session_id: snapshot.session_id,
                    epoch,
                    attempt_id,
                    expected_revision: snapshot.revision,
                    target: LaunchState::CleanupRequired,
                    cleanup_reason: Some(reason),
                },
                tokio::time::Instant::now() + Duration::from_millis(100),
            )
            .await?;
            return Ok(StopOutcome::CleanupRequired);
        }
        let stopping = if matches!(
            snapshot.state,
            LaunchState::Stopping | LaunchState::CleanupRequired
        ) {
            snapshot
        } else {
            self.store
                .transition_launch(TransitionLaunch {
                    context: RequestContext::new(ids.stopping, host_id),
                    session_id: snapshot.session_id,
                    epoch,
                    attempt_id,
                    expected_revision: snapshot.revision,
                    target: LaunchState::Stopping,
                    cleanup_reason: None,
                })
                .await?
                .value()
                .clone()
        };
        let mut stopped = self
            .stop_verified_until(attempt_id, &evidence, deadline)
            .await
            .unwrap_or(false);
        stopped = stopped || self.exact_process_exited(attempt_id, &evidence).await;
        if stopped && self.backend.cleanup(attempt_id).await.is_err() {
            stopped = false;
        }
        if !stopped && stopping.state == LaunchState::CleanupRequired {
            return Ok(StopOutcome::CleanupRequired);
        }
        let target = if stopped {
            LaunchState::Stopped
        } else {
            LaunchState::CleanupRequired
        };
        let reason = (!stopped)
            .then(|| BoundedText::new("process identity or termination could not be proven"))
            .transpose()
            .map_err(|_| SupervisorError::Process)?;
        let terminal = TransitionLaunch {
            context: RequestContext::new(ids.terminal, host_id),
            session_id: stopping.session_id,
            epoch,
            attempt_id,
            expected_revision: stopping.revision,
            target,
            cleanup_reason: reason,
        };
        // Leave a small, bounded durability budget after process work consumes
        // the host deadline. This cannot start a new signal sequence; it only
        // records the fail-closed terminal classification.
        let terminal_deadline = deadline.max(
            tokio::time::Instant::now()
                .checked_add(Duration::from_millis(100))
                .unwrap_or(deadline),
        );
        self.transition_terminal_with_retry(terminal, terminal_deadline)
            .await?;
        if stopped {
            self.active.lock().await.remove(&attempt_id);
            Ok(StopOutcome::Stopped)
        } else {
            Ok(StopOutcome::CleanupRequired)
        }
    }

    async fn transition_terminal_with_retry(
        &self,
        command: TransitionLaunch,
        deadline: tokio::time::Instant,
    ) -> Result<(), SupervisorError> {
        // Process termination and backend cleanup precede a `Stopped` commit.
        // Retrying the same request identity is safe because Store mutations
        // are idempotent by request id.
        loop {
            match tokio::time::timeout_at(deadline, self.store.transition_launch(command.clone()))
                .await
            {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(error)) if error.retryable() && tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep_until(
                        deadline.min(tokio::time::Instant::now() + Duration::from_millis(10)),
                    )
                    .await;
                }
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => return Err(SupervisorError::Process),
            }
        }
    }

    pub async fn ownership_lost(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: HostId,
        epoch: FencingEpoch,
        ids: StopRequestIds,
    ) -> Result<StopOutcome, SupervisorError> {
        self.backend.revoke_ownership(attempt_id).await?;
        if self
            .backend
            .wait_for_exit(attempt_id, self.config.ownership_loss_timeout)
            .await?
        {
            let result = self
                .finish_already_exited(attempt_id, host_id, epoch, ids)
                .await;
            if result.is_err() {
                let _ = self.backend.cleanup(attempt_id).await;
                self.active.lock().await.remove(&attempt_id);
                return Ok(StopOutcome::CleanupRequired);
            }
            return result;
        }
        let result = self.stop(attempt_id, host_id, epoch, ids).await;
        if result.is_err() {
            let evidence = self
                .active
                .lock()
                .await
                .get(&attempt_id)
                .map(|binding| binding.evidence.clone());
            if let Some(evidence) = evidence {
                let _ = self.stop_verified(attempt_id, &evidence).await;
            }
            let _ = self.backend.cleanup(attempt_id).await;
            self.active.lock().await.remove(&attempt_id);
            return Ok(StopOutcome::CleanupRequired);
        }
        result
    }

    pub async fn watch_ownership(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: HostId,
        epoch: FencingEpoch,
        ids: StopRequestIds,
        poll_interval: Duration,
    ) -> Result<StopOutcome, SupervisorError> {
        self.watch_ownership_with_fence(attempt_id, host_id, epoch, ids, poll_interval, None)
            .await
    }

    pub async fn watch_ownership_with_fence(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: HostId,
        epoch: FencingEpoch,
        ids: StopRequestIds,
        poll_interval: Duration,
        terminal_fence: Option<&LifecycleFence>,
    ) -> Result<StopOutcome, SupervisorError> {
        // `ownership_loss_timeout` is also the maximum continuous interval in
        // which the watchdog may be unable to validate durable authority. It
        // keeps transient Store contention non-destructive without permitting
        // an unbounded unfenced process when the Store remains unavailable.
        let mut authority_uncertainty_deadline = None;
        loop {
            let snapshot = match self.store.load_launch(attempt_id).await {
                Ok(snapshot) => snapshot,
                Err(error) if error.retryable() => {
                    if authority_uncertainty_requires_revocation(
                        AuthorityObservation::RetryableFailure,
                        &mut authority_uncertainty_deadline,
                        tokio::time::Instant::now(),
                        self.config.ownership_loss_timeout,
                    ) {
                        set_terminal_fence(terminal_fence);
                        return self.ownership_lost(attempt_id, host_id, epoch, ids).await;
                    }
                    tokio::time::sleep(poll_interval).await;
                    continue;
                }
                Err(error) => {
                    // The launch cannot be safely related to durable authority.
                    // Fence through the authenticated local binding without
                    // trusting another Store read. A non-conforming Driver is
                    // escalated before the binding may be forgotten.
                    set_terminal_fence(terminal_fence);
                    let evidence = self
                        .active
                        .lock()
                        .await
                        .get(&attempt_id)
                        .map(|binding| binding.evidence.clone())
                        .ok_or(SupervisorError::NotAttached)?;
                    self.backend.revoke_ownership(attempt_id).await?;
                    let exited_after_revoke = self
                        .backend
                        .wait_for_exit(attempt_id, self.config.ownership_loss_timeout)
                        .await
                        .unwrap_or(false);
                    let stopped = if exited_after_revoke {
                        true
                    } else {
                        let Some(stop_deadline) =
                            tokio::time::Instant::now().checked_add(self.configured_stop_budget())
                        else {
                            // The escalation bound is not representable. Keep
                            // the authenticated binding for reconciliation;
                            // never panic or forget a possibly live process.
                            return Err(SupervisorError::CleanupRequired);
                        };
                        self.stop_verified_until(attempt_id, &evidence, stop_deadline)
                            .await
                            .unwrap_or(false)
                    };
                    if !stopped || self.backend.cleanup(attempt_id).await.is_err() {
                        return Err(SupervisorError::CleanupRequired);
                    }
                    self.active.lock().await.remove(&attempt_id);
                    return Err(error.into());
                }
            };
            let _ = authority_uncertainty_requires_revocation(
                AuthorityObservation::LaunchLoaded,
                &mut authority_uncertainty_deadline,
                tokio::time::Instant::now(),
                self.config.ownership_loss_timeout,
            );
            if matches!(
                snapshot.state,
                LaunchState::Stopped | LaunchState::CleanupRequired
            ) {
                set_terminal_fence(terminal_fence);
                return Ok(if snapshot.state == LaunchState::Stopped {
                    StopOutcome::Stopped
                } else {
                    StopOutcome::CleanupRequired
                });
            }
            let validation = self
                .store
                .validate_launch_authority(snapshot.session_id, host_id, epoch)
                .await;
            let observation = match &validation {
                Ok(()) => AuthorityObservation::AuthorityValidated,
                Err(error) if error.retryable() => AuthorityObservation::RetryableFailure,
                Err(_) => AuthorityObservation::AuthoritativeLoss,
            };
            if authority_uncertainty_requires_revocation(
                observation,
                &mut authority_uncertainty_deadline,
                tokio::time::Instant::now(),
                self.config.ownership_loss_timeout,
            ) {
                set_terminal_fence(terminal_fence);
                return self.ownership_lost(attempt_id, host_id, epoch, ids).await;
            }
            tokio::time::sleep(poll_interval).await;
        }
    }

    pub async fn reconcile_launch(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: HostId,
        epoch: FencingEpoch,
        ids: ReconcileRequestIds,
    ) -> Result<StopOutcome, SupervisorError> {
        let snapshot = self.store.load_launch(attempt_id).await?;
        match snapshot.state {
            LaunchState::Stopped => Ok(StopOutcome::AlreadyStopped),
            LaunchState::Prepared => {
                let reason = BoundedText::new(
                    "process identity is unavailable after a Prepared recovery boundary",
                )
                .expect("static cleanup reason is bounded");
                self.store
                    .transition_launch(TransitionLaunch {
                        context: RequestContext::new(ids.cleanup, host_id),
                        session_id: snapshot.session_id,
                        epoch,
                        attempt_id,
                        expected_revision: snapshot.revision,
                        target: LaunchState::CleanupRequired,
                        cleanup_reason: Some(reason),
                    })
                    .await?;
                Ok(StopOutcome::CleanupRequired)
            }
            LaunchState::Attached
            | LaunchState::Ready
            | LaunchState::Stopping
            | LaunchState::CleanupRequired => self.stop(attempt_id, host_id, epoch, ids.stop).await,
        }
    }

    async fn finish_already_exited(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: HostId,
        epoch: FencingEpoch,
        ids: StopRequestIds,
    ) -> Result<StopOutcome, SupervisorError> {
        let snapshot = self.store.load_launch(attempt_id).await?;
        let stopping = self
            .store
            .transition_launch(TransitionLaunch {
                context: RequestContext::new(ids.stopping, host_id),
                session_id: snapshot.session_id,
                epoch,
                attempt_id,
                expected_revision: snapshot.revision,
                target: LaunchState::Stopping,
                cleanup_reason: None,
            })
            .await?
            .value()
            .clone();
        self.store
            .transition_launch(TransitionLaunch {
                context: RequestContext::new(ids.terminal, host_id),
                session_id: snapshot.session_id,
                epoch,
                attempt_id,
                expected_revision: stopping.revision,
                target: LaunchState::Stopped,
                cleanup_reason: None,
            })
            .await?;
        self.backend.cleanup(attempt_id).await?;
        self.active.lock().await.remove(&attempt_id);
        Ok(StopOutcome::Stopped)
    }

    async fn stop_verified(
        &self,
        attempt_id: LaunchAttemptId,
        evidence: &ProcessEvidence,
    ) -> Result<bool, SupervisorError> {
        let budget = self
            .config
            .graceful_timeout
            .saturating_add(self.config.forced_timeout);
        self.stop_verified_until(attempt_id, evidence, tokio::time::Instant::now() + budget)
            .await
    }

    async fn stop_verified_until(
        &self,
        attempt_id: LaunchAttemptId,
        evidence: &ProcessEvidence,
        deadline: tokio::time::Instant,
    ) -> Result<bool, SupervisorError> {
        match self.backend.inspect(attempt_id, evidence).await? {
            IdentityObservation::Exited => return Ok(true),
            IdentityObservation::Mismatch => return Ok(false),
            IdentityObservation::Same => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        if let Err(error) = self.backend.graceful_stop(attempt_id, evidence).await {
            return match self.backend.inspect(attempt_id, evidence).await? {
                // The exact owned child may exit between the pre-signal
                // inspection and the signal attempt. That is a proven stop,
                // not an identity failure.
                IdentityObservation::Exited => Ok(true),
                IdentityObservation::Mismatch => Ok(false),
                IdentityObservation::Same => Err(error),
            };
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        if self
            .backend
            .wait_for_exit(attempt_id, self.config.graceful_timeout.min(remaining))
            .await?
        {
            return Ok(true);
        }
        match self.backend.inspect(attempt_id, evidence).await? {
            IdentityObservation::Exited => return Ok(true),
            IdentityObservation::Mismatch => return Ok(false),
            IdentityObservation::Same => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        if let Err(error) = self.backend.force_stop_group(attempt_id, evidence).await {
            return match self.backend.inspect(attempt_id, evidence).await? {
                IdentityObservation::Exited => Ok(true),
                IdentityObservation::Mismatch => Ok(false),
                IdentityObservation::Same => Err(error),
            };
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        self.backend
            .wait_for_exit(attempt_id, self.config.forced_timeout.min(remaining))
            .await
    }

    /// Closes a final observation race without issuing another signal. Only
    /// the exact retained Child/evidence pair can prove successful exit.
    async fn exact_process_exited(
        &self,
        attempt_id: LaunchAttemptId,
        evidence: &ProcessEvidence,
    ) -> bool {
        matches!(
            self.backend.inspect(attempt_id, evidence).await,
            Ok(IdentityObservation::Exited)
        )
    }

    async fn compensate_launch(&self, plan: &LaunchPlan, evidence: &ProcessEvidence) {
        let stopped = self
            .stop_verified(plan.attempt_id, evidence)
            .await
            .unwrap_or(false);
        if stopped {
            let _ = self.backend.cleanup(plan.attempt_id).await;
            self.active.lock().await.remove(&plan.attempt_id);
        }
        let Ok(snapshot) = self.store.load_launch(plan.attempt_id).await else {
            return;
        };
        let reason = BoundedText::new(if stopped {
            "launch failed after spawn; process termination verified"
        } else {
            "launch failed after spawn; process termination is uncertain"
        })
        .expect("static cleanup reason is bounded");
        let Ok(cleanup) = self
            .store
            .transition_launch(TransitionLaunch {
                context: RequestContext::new(plan.compensation_request_id, plan.host_id),
                session_id: snapshot.session_id,
                epoch: plan.ownership_epoch,
                attempt_id: plan.attempt_id,
                expected_revision: snapshot.revision,
                target: LaunchState::CleanupRequired,
                cleanup_reason: Some(reason),
            })
            .await
        else {
            return;
        };
        if stopped {
            let _ = self
                .store
                .transition_launch(TransitionLaunch {
                    context: RequestContext::new(
                        plan.compensation_terminal_request_id,
                        plan.host_id,
                    ),
                    session_id: snapshot.session_id,
                    epoch: plan.ownership_epoch,
                    attempt_id: plan.attempt_id,
                    expected_revision: cleanup.value().revision,
                    target: LaunchState::Stopped,
                    cleanup_reason: None,
                })
                .await;
        }
    }

    async fn classify_without_process(&self, plan: &LaunchPlan, snapshot: LaunchSnapshot) {
        let reason = BoundedText::new("launch stopped before process creation")
            .expect("static cleanup reason is bounded");
        let Ok(cleanup) = self
            .store
            .transition_launch(TransitionLaunch {
                context: RequestContext::new(plan.compensation_request_id, plan.host_id),
                session_id: snapshot.session_id,
                epoch: plan.ownership_epoch,
                attempt_id: plan.attempt_id,
                expected_revision: snapshot.revision,
                target: LaunchState::CleanupRequired,
                cleanup_reason: Some(reason),
            })
            .await
        else {
            return;
        };
        let _ = self
            .store
            .transition_launch(TransitionLaunch {
                context: RequestContext::new(plan.compensation_terminal_request_id, plan.host_id),
                session_id: snapshot.session_id,
                epoch: plan.ownership_epoch,
                attempt_id: plan.attempt_id,
                expected_revision: cleanup.value().revision,
                target: LaunchState::Stopped,
                cleanup_reason: None,
            })
            .await;
    }
}

struct OpenDriverRequest {
    socket: PathBuf,
    timeout: Duration,
    credential: Vec<u8>,
    expected_driver: DriverId,
    required_capabilities: Vec<v1::CapabilityRequirement>,
    expected_capabilities: Vec<v1::Capability>,
    start_request_id: RequestId,
    participant_id: ParticipantId,
    attempt_id: LaunchAttemptId,
    expected_instance: InstanceId,
    session_id: SessionId,
    epoch: FencingEpoch,
    trusted_configuration: Vec<u8>,
}

fn open_authenticated_driver(
    request: OpenDriverRequest,
) -> Result<(DriverClient, v1::InstanceIdentity), SupervisorError> {
    let mut client = DriverClient::connect(
        &request.socket,
        DriverCredential::new(request.credential).map_err(|_| SupervisorError::Authentication)?,
        request.timeout,
    )
    .map_err(|_| SupervisorError::Authentication)?;
    let described = client
        .describe()
        .map_err(|_| SupervisorError::Authentication)?;
    if !describe_matches(
        &described,
        request.expected_driver,
        &request.expected_capabilities,
        &request.required_capabilities,
    ) {
        return Err(SupervisorError::IdentityMismatch);
    }
    let started = client
        .start_requiring(
            StartParameters {
                request_id: request.start_request_id.as_uuid().as_bytes().to_vec(),
                participant_id: request.participant_id.as_uuid().as_bytes().to_vec(),
                launch_attempt_id: request.attempt_id.as_uuid().as_bytes().to_vec(),
                instance_id: request.expected_instance.as_uuid().as_bytes().to_vec(),
                session_id: request.session_id.as_uuid().as_bytes().to_vec(),
                ownership_epoch: request.epoch.get(),
                trusted_configuration: request.trusted_configuration,
            },
            request.required_capabilities,
        )
        .map_err(|_| SupervisorError::Authentication)?;
    if v1::StartDisposition::try_from(started.disposition).ok()
        != Some(v1::StartDisposition::Started)
    {
        return Err(SupervisorError::Authentication);
    }
    Ok((
        client,
        started.instance.ok_or(SupervisorError::Authentication)?,
    ))
}

fn describe_matches(
    described: &v1::DescribeResult,
    expected_driver: DriverId,
    expected_capabilities: &[v1::Capability],
    required_capabilities: &[v1::CapabilityRequirement],
) -> bool {
    let Some(protocol) = described.protocol.as_ref() else {
        return false;
    };
    described.driver_id == expected_driver.as_uuid().as_bytes()
        && protocol.minimum <= PROTOCOL_V1
        && protocol.maximum >= PROTOCOL_V1
        && same_capabilities(&described.capabilities, expected_capabilities)
        && required_capabilities.iter().all(|required| {
            described.capabilities.iter().any(|actual| {
                actual.id == required.id
                    && actual.version >= required.minimum_version
                    && required
                        .parameters
                        .iter()
                        .all(|parameter| actual.parameters.contains(parameter))
            })
        })
}

fn same_capabilities(actual: &[v1::Capability], expected: &[v1::Capability]) -> bool {
    actual.len() == expected.len()
        && expected.iter().all(|expected| {
            actual.iter().any(|actual| {
                actual.id == expected.id
                    && actual.version == expected.version
                    && actual.parameters.len() == expected.parameters.len()
                    && expected
                        .parameters
                        .iter()
                        .all(|parameter| actual.parameters.contains(parameter))
            })
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityObservation {
    LaunchLoaded,
    AuthorityValidated,
    RetryableFailure,
    AuthoritativeLoss,
}

fn authority_uncertainty_requires_revocation(
    observation: AuthorityObservation,
    transient_deadline: &mut Option<tokio::time::Instant>,
    now: tokio::time::Instant,
    transient_budget: Duration,
) -> bool {
    match observation {
        AuthorityObservation::LaunchLoaded => false,
        AuthorityObservation::AuthorityValidated => {
            *transient_deadline = None;
            false
        }
        AuthorityObservation::RetryableFailure => {
            if transient_budget.is_zero() {
                return true;
            }
            let deadline = if let Some(deadline) = *transient_deadline {
                deadline
            } else {
                let Some(deadline) = now.checked_add(transient_budget) else {
                    return true;
                };
                *transient_deadline = Some(deadline);
                deadline
            };
            now >= deadline
        }
        AuthorityObservation::AuthoritativeLoss => true,
    }
}

fn validate_environment(plan: &LaunchPlan) -> Result<(), SupervisorError> {
    if plan
        .environment
        .keys()
        .all(|key| plan.environment_allowlist.contains(key))
    {
        Ok(())
    } else {
        Err(SupervisorError::EnvironmentDenied)
    }
}

fn credential_digest(credential: &[u8]) -> [u8; 32] {
    Sha256::digest(credential).into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let length = left.len().ct_eq(&right.len());
    let maximum = left.len().max(right.len());
    let mut difference = 0_u8;
    for index in 0..maximum {
        difference |= left.get(index).copied().unwrap_or_default()
            ^ right.get(index).copied().unwrap_or_default();
    }
    bool::from(length & difference.ct_eq(&0))
}

pub fn ready_proof(
    credential: &[u8],
    session_id: SessionId,
    instance_id: InstanceId,
    attempt_id: LaunchAttemptId,
    epoch: FencingEpoch,
    nonce: [u8; 32],
) -> Result<[u8; 32], SupervisorError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(credential)
        .map_err(|_| SupervisorError::InvalidCredential)?;
    mac.update(b"navigator.ready.v1\0");
    mac.update(session_id.as_uuid().as_bytes());
    mac.update(instance_id.as_uuid().as_bytes());
    mac.update(attempt_id.as_uuid().as_bytes());
    mac.update(&epoch.get().to_be_bytes());
    mac.update(&nonce);
    Ok(mac.finalize().into_bytes().into())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet, VecDeque},
        ffi::OsString,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use navigator_domain::{
        CompatibilityIdentity, ConsumerKey, DriverId, FencingEpoch, HostId, InstanceId,
        LaunchAttemptId, OwnershipSnapshot, ParticipantId, RequestId, SessionId, SessionSnapshot,
    };
    use navigator_store_api::{
        AcquireOwnership, AttachLaunch, CloseSession, EventPage, InstanceStore, LaunchSnapshot,
        LeaseDuration, Mutation, OpenSession, OwnershipLease, PrepareLaunch, ReadEvents,
        ReleaseOwnership, RenewOwnership, RequestContext, SessionStore, StoredRequest,
        TransitionLaunch,
    };

    #[test]
    fn describe_identity_protocol_and_capabilities_are_exact_and_required() {
        let driver = DriverId::from_uuid(uuid::Uuid::from_u128(77)).unwrap();
        let parameter = v1::CapabilityParameter {
            key: "mode".into(),
            value: "durable".into(),
        };
        let capability = v1::Capability {
            id: "delivery".into(),
            version: 2,
            parameters: vec![parameter.clone()],
        };
        let required = v1::CapabilityRequirement {
            id: "delivery".into(),
            minimum_version: 2,
            parameters: vec![parameter.clone()],
        };
        let baseline = v1::DescribeResult {
            driver_id: driver.as_uuid().as_bytes().to_vec(),
            implementation: "fixture".into(),
            implementation_version: "1".into(),
            protocol: Some(v1::ProtocolRange {
                minimum: PROTOCOL_V1,
                maximum: PROTOCOL_V1,
            }),
            capabilities: vec![capability.clone()],
        };
        assert!(describe_matches(
            &baseline,
            driver,
            std::slice::from_ref(&capability),
            std::slice::from_ref(&required)
        ));

        let mut mutants = Vec::new();
        let mut wrong_driver = baseline.clone();
        wrong_driver.driver_id[0] ^= 1;
        mutants.push(wrong_driver);
        let mut wrong_protocol = baseline.clone();
        wrong_protocol.protocol.as_mut().unwrap().minimum = PROTOCOL_V1 + 1;
        mutants.push(wrong_protocol);
        let mut under_version = baseline.clone();
        under_version.capabilities[0].version = 1;
        mutants.push(under_version);
        let mut wrong_parameter = baseline.clone();
        wrong_parameter.capabilities[0].parameters[0].value = "volatile".into();
        mutants.push(wrong_parameter);
        let mut omitted = baseline.clone();
        omitted.capabilities.clear();
        mutants.push(omitted);
        let mut over_advertised = baseline.clone();
        over_advertised.capabilities.push(v1::Capability {
            id: "untrusted-extra".into(),
            version: 1,
            parameters: Vec::new(),
        });
        mutants.push(over_advertised);
        for mutant in mutants {
            assert!(!describe_matches(
                &mutant,
                driver,
                std::slice::from_ref(&capability),
                std::slice::from_ref(&required)
            ));
        }
    }
    use navigator_store_sqlite::SqliteStore;
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;

    #[test]
    fn sustained_retryable_authority_uncertainty_is_bounded_and_alternating_errors_share_budget() {
        let now = tokio::time::Instant::now();
        let budget = Duration::from_millis(10);
        let mut deadline = None;
        assert!(!authority_uncertainty_requires_revocation(
            AuthorityObservation::RetryableFailure,
            &mut deadline,
            now,
            budget,
        ));
        assert!(!authority_uncertainty_requires_revocation(
            AuthorityObservation::RetryableFailure,
            &mut deadline,
            now + Duration::from_millis(9),
            budget,
        ));
        assert!(authority_uncertainty_requires_revocation(
            AuthorityObservation::RetryableFailure,
            &mut deadline,
            now + budget,
            budget,
        ));
    }

    #[test]
    fn successful_authority_validation_resets_uncertainty_and_authoritative_loss_is_immediate() {
        let now = tokio::time::Instant::now();
        let budget = Duration::from_millis(10);
        let mut deadline = None;
        assert!(!authority_uncertainty_requires_revocation(
            AuthorityObservation::RetryableFailure,
            &mut deadline,
            now,
            budget,
        ));
        assert!(!authority_uncertainty_requires_revocation(
            AuthorityObservation::AuthorityValidated,
            &mut deadline,
            now + budget,
            budget,
        ));
        assert_eq!(deadline, None);
        assert!(!authority_uncertainty_requires_revocation(
            AuthorityObservation::RetryableFailure,
            &mut deadline,
            now + budget,
            budget,
        ));
        assert!(authority_uncertainty_requires_revocation(
            AuthorityObservation::AuthoritativeLoss,
            &mut deadline,
            now + budget,
            budget,
        ));
    }

    #[test]
    fn zero_or_unrepresentable_authority_uncertainty_budget_is_fail_closed() {
        let now = tokio::time::Instant::now();
        let mut deadline = None;
        assert!(authority_uncertainty_requires_revocation(
            AuthorityObservation::RetryableFailure,
            &mut deadline,
            now,
            Duration::ZERO,
        ));
        assert_eq!(deadline, None);
        assert!(authority_uncertainty_requires_revocation(
            AuthorityObservation::RetryableFailure,
            &mut deadline,
            now,
            Duration::MAX,
        ));
        assert_eq!(deadline, None);
    }

    #[test]
    fn successful_launch_read_does_not_reset_uncertainty_before_authority_validation() {
        let now = tokio::time::Instant::now();
        let budget = Duration::from_millis(10);
        let mut deadline = None;
        assert!(!authority_uncertainty_requires_revocation(
            AuthorityObservation::RetryableFailure,
            &mut deadline,
            now,
            budget,
        ));
        let established = deadline;
        assert!(!authority_uncertainty_requires_revocation(
            AuthorityObservation::LaunchLoaded,
            &mut deadline,
            now + budget,
            budget,
        ));
        assert_eq!(deadline, established);
        assert!(authority_uncertainty_requires_revocation(
            AuthorityObservation::RetryableFailure,
            &mut deadline,
            now + budget,
            budget,
        ));
    }

    #[test]
    fn ready_proof_is_bound_to_identity_epoch_and_fresh_challenge() {
        let session = SessionId::from_uuid(Uuid::from_u128(1)).unwrap();
        let instance = InstanceId::from_uuid(Uuid::from_u128(2)).unwrap();
        let attempt = LaunchAttemptId::from_uuid(Uuid::from_u128(3)).unwrap();
        let epoch = FencingEpoch::new(4).unwrap();
        let baseline = ready_proof(&[7; 32], session, instance, attempt, epoch, [5; 32]).unwrap();

        assert_eq!(
            baseline,
            ready_proof(&[7; 32], session, instance, attempt, epoch, [5; 32]).unwrap()
        );
        assert_ne!(
            baseline,
            ready_proof(&[7; 32], session, instance, attempt, epoch, [6; 32]).unwrap()
        );
        assert_ne!(
            baseline,
            ready_proof(
                &[7; 32],
                session,
                instance,
                attempt,
                FencingEpoch::new(5).unwrap(),
                [5; 32],
            )
            .unwrap()
        );
    }

    #[derive(Clone, Copy, Default)]
    enum RevokeBehavior {
        #[default]
        Exit,
        Ignore,
    }

    #[derive(Clone, Copy, Default)]
    enum ForceBehavior {
        #[default]
        Remain,
        Exit,
    }

    #[derive(Clone, Copy, Default)]
    enum ExitRace {
        #[default]
        None,
        GracefulSignal,
        FirstWait,
        ForceSignal,
        SecondWait,
    }

    #[derive(Default)]
    struct BackendState {
        spawns: usize,
        inspected: usize,
        graceful: usize,
        forced: usize,
        revoked: usize,
        revoke_fence: Option<Arc<LifecycleFence>>,
        revoke_fence_observation: Option<bool>,
        cleaned: usize,
        observation: Option<IdentityObservation>,
        exits_on_wait: bool,
        revoke_behavior: RevokeBehavior,
        force_behavior: ForceBehavior,
        fail_graceful: bool,
        exit_race: ExitRace,
        wait_calls: usize,
        fail_cleanup: bool,
    }

    #[derive(Default)]
    struct FakeBackend(Mutex<BackendState>);

    impl ProcessBackend for FakeBackend {
        async fn spawn(
            &self,
            _plan: &LaunchPlan,
            _credential: &[u8],
        ) -> Result<ProcessEvidence, SupervisorError> {
            self.0.lock().unwrap().spawns += 1;
            Ok(evidence())
        }

        async fn inspect(
            &self,
            _attempt_id: LaunchAttemptId,
            _expected: &ProcessEvidence,
        ) -> Result<IdentityObservation, SupervisorError> {
            let mut state = self.0.lock().unwrap();
            state.inspected += 1;
            Ok(state.observation.unwrap_or(IdentityObservation::Same))
        }

        async fn graceful_stop(
            &self,
            _attempt_id: LaunchAttemptId,
            _expected: &ProcessEvidence,
        ) -> Result<(), SupervisorError> {
            let mut state = self.0.lock().unwrap();
            state.graceful += 1;
            if matches!(state.exit_race, ExitRace::GracefulSignal) {
                state.observation = Some(IdentityObservation::Exited);
                return Err(SupervisorError::Process);
            }
            if state.fail_graceful {
                return Err(SupervisorError::Process);
            }
            Ok(())
        }

        async fn force_stop_group(
            &self,
            _attempt_id: LaunchAttemptId,
            _expected: &ProcessEvidence,
        ) -> Result<(), SupervisorError> {
            let mut state = self.0.lock().unwrap();
            state.forced += 1;
            if matches!(state.exit_race, ExitRace::ForceSignal) {
                state.observation = Some(IdentityObservation::Exited);
                return Err(SupervisorError::Process);
            }
            if matches!(state.force_behavior, ForceBehavior::Exit) {
                state.exits_on_wait = true;
            }
            Ok(())
        }

        async fn wait_for_exit(
            &self,
            _attempt_id: LaunchAttemptId,
            _timeout: Duration,
        ) -> Result<bool, SupervisorError> {
            let mut state = self.0.lock().unwrap();
            state.wait_calls += 1;
            if matches!(state.exit_race, ExitRace::FirstWait) {
                state.exit_race = ExitRace::None;
                state.observation = Some(IdentityObservation::Exited);
                return Ok(false);
            }
            if matches!(state.exit_race, ExitRace::SecondWait) && state.wait_calls == 2 {
                state.observation = Some(IdentityObservation::Exited);
                return Ok(false);
            }
            Ok(state.exits_on_wait)
        }

        async fn revoke_ownership(
            &self,
            _attempt_id: LaunchAttemptId,
        ) -> Result<(), SupervisorError> {
            let mut state = self.0.lock().unwrap();
            state.revoked += 1;
            state.revoke_fence_observation =
                state.revoke_fence.as_ref().map(|fence| fence.is_closed());
            if matches!(state.revoke_behavior, RevokeBehavior::Exit) {
                state.exits_on_wait = true;
            }
            Ok(())
        }

        async fn cleanup(&self, _attempt_id: LaunchAttemptId) -> Result<(), SupervisorError> {
            let mut state = self.0.lock().unwrap();
            state.cleaned += 1;
            if state.fail_cleanup {
                return Err(SupervisorError::Process);
            }
            Ok(())
        }
    }

    struct Credential;

    impl CredentialSource for Credential {
        fn next_credential(&mut self) -> Result<Vec<u8>, SupervisorError> {
            Ok(vec![7; 32])
        }
    }

    struct ValidationFaultStore {
        inner: Arc<SqliteStore>,
        load_faults: Mutex<VecDeque<StoreError>>,
        validation_faults: Mutex<VecDeque<StoreError>>,
        observed_faults: Mutex<Vec<(&'static str, StoreError)>>,
        fault_observed: tokio::sync::Notify,
        validation_successes: AtomicUsize,
        validation_succeeded: tokio::sync::Notify,
    }

    impl ValidationFaultStore {
        fn new(inner: Arc<SqliteStore>) -> Self {
            Self {
                inner,
                load_faults: Mutex::new(VecDeque::new()),
                validation_faults: Mutex::new(VecDeque::new()),
                observed_faults: Mutex::new(Vec::new()),
                fault_observed: tokio::sync::Notify::new(),
                validation_successes: AtomicUsize::new(0),
                validation_succeeded: tokio::sync::Notify::new(),
            }
        }

        fn inject_load(&self, faults: impl IntoIterator<Item = StoreError>) {
            self.load_faults.lock().unwrap().extend(faults);
        }

        fn inject_validation(&self, faults: impl IntoIterator<Item = StoreError>) {
            self.validation_faults.lock().unwrap().extend(faults);
        }

        async fn wait_for_faults(&self, count: usize) -> Vec<(&'static str, StoreError)> {
            loop {
                let notified = self.fault_observed.notified();
                let observed = self.observed_faults.lock().unwrap().clone();
                if observed.len() >= count {
                    return observed;
                }
                notified.await;
            }
        }

        fn record_fault(&self, site: &'static str, error: &StoreError) {
            self.observed_faults
                .lock()
                .unwrap()
                .push((site, error.clone()));
            self.fault_observed.notify_waiters();
        }

        async fn wait_for_validation_successes(&self, count: usize) {
            loop {
                let notified = self.validation_succeeded.notified();
                if self.validation_successes.load(Ordering::Acquire) >= count {
                    return;
                }
                notified.await;
            }
        }
    }

    impl SessionStore for ValidationFaultStore {
        async fn open_session(
            &self,
            command: OpenSession,
        ) -> Result<Mutation<SessionSnapshot>, StoreError> {
            self.inner.open_session(command).await
        }
        async fn close_session(
            &self,
            command: CloseSession,
        ) -> Result<Mutation<SessionSnapshot>, StoreError> {
            self.inner.close_session(command).await
        }
        async fn acquire_ownership(
            &self,
            command: AcquireOwnership,
        ) -> Result<Mutation<OwnershipLease>, StoreError> {
            self.inner.acquire_ownership(command).await
        }
        async fn renew_ownership(
            &self,
            command: RenewOwnership,
        ) -> Result<Mutation<OwnershipLease>, StoreError> {
            self.inner.renew_ownership(command).await
        }
        async fn release_ownership(
            &self,
            command: ReleaseOwnership,
        ) -> Result<Mutation<OwnershipSnapshot>, StoreError> {
            self.inner.release_ownership(command).await
        }
        async fn load_session(&self, session_id: SessionId) -> Result<SessionSnapshot, StoreError> {
            self.inner.load_session(session_id).await
        }
        async fn read_ownership(
            &self,
            session_id: SessionId,
        ) -> Result<OwnershipSnapshot, StoreError> {
            self.inner.read_ownership(session_id).await
        }
        async fn read_request(
            &self,
            request_id: RequestId,
        ) -> Result<Option<StoredRequest>, StoreError> {
            self.inner.read_request(request_id).await
        }
        async fn read_events(&self, query: ReadEvents) -> Result<EventPage, StoreError> {
            self.inner.read_events(query).await
        }
    }

    impl InstanceStore for ValidationFaultStore {
        async fn validate_launch_authority(
            &self,
            session_id: SessionId,
            host_id: HostId,
            epoch: FencingEpoch,
        ) -> Result<(), StoreError> {
            if let Some(error) = self.validation_faults.lock().unwrap().pop_front() {
                self.record_fault("validate", &error);
                return Err(error);
            }
            let result = self
                .inner
                .validate_launch_authority(session_id, host_id, epoch)
                .await;
            if result.is_ok() {
                self.validation_successes.fetch_add(1, Ordering::AcqRel);
                self.validation_succeeded.notify_waiters();
            }
            result
        }
        async fn prepare_launch(
            &self,
            command: PrepareLaunch,
        ) -> Result<Mutation<LaunchSnapshot>, StoreError> {
            self.inner.prepare_launch(command).await
        }
        async fn attach_launch(
            &self,
            command: AttachLaunch,
        ) -> Result<Mutation<LaunchSnapshot>, StoreError> {
            self.inner.attach_launch(command).await
        }
        async fn transition_launch(
            &self,
            command: TransitionLaunch,
        ) -> Result<Mutation<LaunchSnapshot>, StoreError> {
            self.inner.transition_launch(command).await
        }
        async fn load_launch(
            &self,
            attempt_id: LaunchAttemptId,
        ) -> Result<LaunchSnapshot, StoreError> {
            if let Some(error) = self.load_faults.lock().unwrap().pop_front() {
                self.record_fault("load", &error);
                return Err(error);
            }
            self.inner.load_launch(attempt_id).await
        }
        async fn session_has_launches(&self, session_id: SessionId) -> Result<bool, StoreError> {
            self.inner.session_has_launches(session_id).await
        }
        async fn session_has_unresolved_launches(
            &self,
            session_id: SessionId,
        ) -> Result<bool, StoreError> {
            self.inner.session_has_unresolved_launches(session_id).await
        }
    }

    struct OneFault(FaultPoint);

    impl FaultInjector for OneFault {
        fn hit(&self, point: FaultPoint) -> Result<(), SupervisorError> {
            if point == self.0 {
                Err(SupervisorError::Injected(point))
            } else {
                Ok(())
            }
        }
    }

    fn identity<T>(
        value: u128,
        make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
    ) -> T {
        make(Uuid::from_u128(value)).unwrap()
    }

    fn evidence() -> ProcessEvidence {
        ProcessEvidence {
            process_id: 11,
            process_group_id: 11,
            parent_process_id: 10,
            creation_marker: 1,
            executable_identity: [9; 32],
        }
    }

    fn plan(epoch: FencingEpoch) -> LaunchPlan {
        LaunchPlan {
            session_id: identity(20, SessionId::from_uuid),
            participant_id: identity(21, ParticipantId::from_uuid),
            driver_id: identity(22, DriverId::from_uuid),
            driver_configuration_digest: [15; 32],
            attempt_id: identity(23, LaunchAttemptId::from_uuid),
            instance_id: identity(24, InstanceId::from_uuid),
            host_id: identity(25, HostId::from_uuid),
            ownership_epoch: epoch,
            prepare_request_id: identity(26, RequestId::from_uuid),
            attach_request_id: identity(27, RequestId::from_uuid),
            compensation_request_id: identity(28, RequestId::from_uuid),
            compensation_terminal_request_id: identity(29, RequestId::from_uuid),
            program: "/bin/false".into(),
            expected_executable_identity: [9; 32],
            arguments: Vec::new(),
            working_directory: "/".into(),
            environment: BTreeMap::from([(OsString::from("SAFE"), OsString::from("1"))]),
            environment_allowlist: BTreeSet::from([OsString::from("SAFE")]),
            ownership_channel: OwnershipChannel::Stdin,
            process_io_mode: ProcessIoMode::Headless,
            bootstrap_configuration: Vec::new(),
        }
    }

    async fn fixture() -> (TempDir, Arc<SqliteStore>, LaunchPlan) {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("store.db"))
                .await
                .unwrap(),
        );
        let draft = plan(FencingEpoch::new(1).unwrap());
        store
            .open_session(OpenSession::new(
                RequestContext::new(identity(30, RequestId::from_uuid), draft.host_id),
                draft.session_id,
                ConsumerKey::new("supervisor-test").unwrap(),
                CompatibilityIdentity::from_bytes([3; 32]),
            ))
            .await
            .unwrap();
        let lease = store
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(identity(31, RequestId::from_uuid), draft.host_id),
                draft.session_id,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await
            .unwrap()
            .value()
            .clone();
        (directory, store, plan(lease.epoch()))
    }

    fn config() -> SupervisorConfig {
        SupervisorConfig {
            graceful_timeout: Duration::from_millis(1),
            forced_timeout: Duration::from_millis(1),
            ownership_loss_timeout: Duration::from_millis(1),
        }
    }

    async fn assert_exit_race_is_a_proven_stop(configure: fn(&mut BackendState), id: u128) {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        configure(&mut backend.0.lock().unwrap());
        let outcome = supervisor
            .stop(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(id, RequestId::from_uuid),
                    terminal: identity(id + 1, RequestId::from_uuid),
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome, StopOutcome::Stopped);
        assert_eq!(
            store.load_launch(plan.attempt_id).await.unwrap().state,
            LaunchState::Stopped
        );
    }

    #[tokio::test]
    async fn dual_supervisors_spawn_a_durable_attempt_only_once() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let first = InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        let second = InstanceSupervisor::new(store, backend.clone(), Credential, config());
        let (left, right) = tokio::join!(first.launch(plan.clone()), second.launch(plan));
        assert!(left.is_ok() || right.is_ok());
        assert!(matches!(
            (&left, &right),
            (Ok(_) | Err(SupervisorError::ReconciliationRequired), Ok(_))
                | (Ok(_), Err(SupervisorError::ReconciliationRequired))
        ));
        assert_eq!(backend.0.lock().unwrap().spawns, 1);
    }

    #[tokio::test]
    async fn reconcile_prepared_and_unadoptable_attached_attempts_without_respawn() {
        let (_directory, store, plan) = fixture().await;
        store
            .prepare_launch(PrepareLaunch {
                context: RequestContext::new(plan.prepare_request_id, plan.host_id),
                epoch: plan.ownership_epoch,
                session_id: plan.session_id,
                participant_id: plan.participant_id,
                driver_id: plan.driver_id,
                attempt_id: plan.attempt_id,
                credential_digest: [7; 32],
                driver_configuration_digest: [17; 32],
            })
            .await
            .unwrap();
        let backend = Arc::new(FakeBackend::default());
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        let outcome = supervisor
            .reconcile_launch(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                ReconcileRequestIds {
                    cleanup: identity(66, RequestId::from_uuid),
                    stop: StopRequestIds {
                        stopping: identity(67, RequestId::from_uuid),
                        terminal: identity(68, RequestId::from_uuid),
                    },
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome, StopOutcome::CleanupRequired);
        assert_eq!(backend.0.lock().unwrap().spawns, 0);

        let (_other_directory, other_store, other_plan) = fixture().await;
        let original_backend = Arc::new(FakeBackend::default());
        InstanceSupervisor::new(other_store.clone(), original_backend, Credential, config())
            .launch(other_plan.clone())
            .await
            .unwrap();
        let restarted_backend = Arc::new(FakeBackend::default());
        restarted_backend.0.lock().unwrap().observation = Some(IdentityObservation::Mismatch);
        let restarted = InstanceSupervisor::new(
            other_store.clone(),
            restarted_backend.clone(),
            Credential,
            config(),
        );
        let outcome = restarted
            .reconcile_launch(
                other_plan.attempt_id,
                other_plan.host_id,
                other_plan.ownership_epoch,
                ReconcileRequestIds {
                    cleanup: identity(69, RequestId::from_uuid),
                    stop: StopRequestIds {
                        stopping: identity(70, RequestId::from_uuid),
                        terminal: identity(71, RequestId::from_uuid),
                    },
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome, StopOutcome::CleanupRequired);
        assert_eq!(restarted_backend.0.lock().unwrap().spawns, 0);
        assert_eq!(
            other_store
                .load_launch(other_plan.attempt_id)
                .await
                .unwrap()
                .state,
            LaunchState::CleanupRequired
        );
    }

    #[tokio::test]
    async fn matching_process_identity_is_not_mistaken_for_authentication() {
        let (_directory, store, plan) = fixture().await;
        let original_backend = Arc::new(FakeBackend::default());
        InstanceSupervisor::new(store.clone(), original_backend, Credential, config())
            .launch(plan.clone())
            .await
            .unwrap();
        let restarted = InstanceSupervisor::new(
            store,
            Arc::new(FakeBackend::default()),
            Credential,
            config(),
        );
        assert_eq!(
            restarted
                .inspect_for_recovery(plan.attempt_id, plan.host_id, plan.ownership_epoch)
                .await
                .unwrap(),
            LiveObservation::SameUnauthenticatedInstance
        );
    }

    #[tokio::test]
    async fn after_spawn_fault_is_bounded_and_durably_classified() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        backend.0.lock().unwrap().exits_on_wait = true;
        let supervisor = InstanceSupervisor::with_faults(
            store.clone(),
            backend.clone(),
            Credential,
            Arc::new(OneFault(FaultPoint::AfterSpawn)),
            config(),
        );
        assert!(matches!(
            supervisor.launch(plan.clone()).await,
            Err(SupervisorError::Injected(FaultPoint::AfterSpawn))
        ));
        assert_eq!(
            store.load_launch(plan.attempt_id).await.unwrap().state,
            LaunchState::Stopped
        );
        let state = backend.0.lock().unwrap();
        assert_eq!((state.spawns, state.graceful, state.cleaned), (1, 1, 1));
    }

    #[tokio::test]
    async fn before_spawn_fault_never_creates_a_process() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor = InstanceSupervisor::with_faults(
            store.clone(),
            backend.clone(),
            Credential,
            Arc::new(OneFault(FaultPoint::BeforeSpawn)),
            config(),
        );
        assert!(matches!(
            supervisor.launch(plan.clone()).await,
            Err(SupervisorError::Injected(FaultPoint::BeforeSpawn))
        ));
        assert_eq!(backend.0.lock().unwrap().spawns, 0);
        assert_eq!(
            store.load_launch(plan.attempt_id).await.unwrap().state,
            LaunchState::Stopped
        );
    }

    #[tokio::test]
    async fn denied_environment_has_no_store_or_process_effect() {
        let (_directory, store, mut plan) = fixture().await;
        plan.environment
            .insert(OsString::from("UNREVIEWED"), OsString::from("secret"));
        let backend = Arc::new(FakeBackend::default());
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        assert!(matches!(
            supervisor.launch(plan.clone()).await,
            Err(SupervisorError::EnvironmentDenied)
        ));
        assert_eq!(backend.0.lock().unwrap().spawns, 0);
        assert!(store.load_launch(plan.attempt_id).await.is_err());
    }

    #[tokio::test]
    async fn after_attach_fault_compensates_the_attached_process() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        backend.0.lock().unwrap().exits_on_wait = true;
        let supervisor = InstanceSupervisor::with_faults(
            store.clone(),
            backend.clone(),
            Credential,
            Arc::new(OneFault(FaultPoint::AfterAttach)),
            config(),
        );
        assert!(matches!(
            supervisor.launch(plan.clone()).await,
            Err(SupervisorError::Injected(FaultPoint::AfterAttach))
        ));
        assert_eq!(
            store.load_launch(plan.attempt_id).await.unwrap().state,
            LaunchState::Stopped
        );
    }

    #[tokio::test]
    async fn before_ready_fault_keeps_admission_closed() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor = InstanceSupervisor::with_faults(
            store,
            backend,
            Credential,
            Arc::new(OneFault(FaultPoint::BeforeReady)),
            config(),
        );
        supervisor.launch(plan.clone()).await.unwrap();
        let nonce = [6; 32];
        let proof = ready_proof(
            &[7; 32],
            plan.session_id,
            plan.instance_id,
            plan.attempt_id,
            plan.ownership_epoch,
            nonce,
        )
        .unwrap();
        assert!(matches!(
            supervisor
                .ready(
                    ReadyRequest {
                        request_id: identity(44, RequestId::from_uuid),
                        attempt_id: plan.attempt_id,
                        host_id: plan.host_id,
                        ownership_epoch: plan.ownership_epoch,
                        nonce,
                    },
                    &proof,
                )
                .await,
            Err(SupervisorError::Injected(FaultPoint::BeforeReady))
        ));
        assert!(matches!(
            supervisor
                .require_ready(plan.attempt_id, plan.host_id, plan.ownership_epoch)
                .await,
            Err(SupervisorError::NotReady)
        ));
    }

    #[tokio::test]
    async fn ready_requires_challenge_bound_authentication_before_admission() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor = InstanceSupervisor::new(store, backend, Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        let request = ReadyRequest {
            request_id: identity(50, RequestId::from_uuid),
            attempt_id: plan.attempt_id,
            host_id: plan.host_id,
            ownership_epoch: plan.ownership_epoch,
            nonce: [8; 32],
        };
        assert!(matches!(
            supervisor.ready(request, &[0; 32]).await,
            Err(SupervisorError::Authentication)
        ));
        assert!(matches!(
            supervisor
                .require_ready(plan.attempt_id, plan.host_id, plan.ownership_epoch)
                .await,
            Err(SupervisorError::NotReady)
        ));
        let proof = ready_proof(
            &[7; 32],
            plan.session_id,
            plan.instance_id,
            plan.attempt_id,
            plan.ownership_epoch,
            request.nonce,
        )
        .unwrap();
        supervisor.ready(request, &proof).await.unwrap();
        supervisor
            .require_ready(plan.attempt_id, plan.host_id, plan.ownership_epoch)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn identity_mismatch_never_signals_and_records_cleanup_required() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        backend.0.lock().unwrap().observation = Some(IdentityObservation::Mismatch);
        let outcome = supervisor
            .stop(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(40, RequestId::from_uuid),
                    terminal: identity(41, RequestId::from_uuid),
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome, StopOutcome::CleanupRequired);
        {
            let state = backend.0.lock().unwrap();
            assert_eq!((state.graceful, state.forced), (0, 0));
        }
        assert_eq!(
            store.load_launch(plan.attempt_id).await.unwrap().state,
            LaunchState::CleanupRequired,
            "an identity mismatch must be durably classified without signalling"
        );
    }

    #[tokio::test]
    async fn bounded_escalation_is_classified_when_group_does_not_exit() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        let outcome = supervisor
            .stop(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(45, RequestId::from_uuid),
                    terminal: identity(46, RequestId::from_uuid),
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome, StopOutcome::CleanupRequired);
        let state = backend.0.lock().unwrap();
        assert_eq!((state.graceful, state.forced), (1, 1));
    }

    #[tokio::test]
    async fn exact_child_exit_races_never_become_cleanup_required() {
        assert_exit_race_is_a_proven_stop(
            |state| state.exit_race = ExitRace::GracefulSignal,
            1_000,
        )
        .await;
        assert_exit_race_is_a_proven_stop(|state| state.exit_race = ExitRace::FirstWait, 1_010)
            .await;
        assert_exit_race_is_a_proven_stop(|state| state.exit_race = ExitRace::ForceSignal, 1_020)
            .await;
        assert_exit_race_is_a_proven_stop(|state| state.exit_race = ExitRace::SecondWait, 1_030)
            .await;
    }

    #[tokio::test]
    async fn exhausted_host_deadline_never_starts_a_signal_sequence() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        let outcome = supervisor
            .stop_with_deadline(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(47, RequestId::from_uuid),
                    terminal: identity(48, RequestId::from_uuid),
                },
                tokio::time::Instant::now(),
            )
            .await
            .unwrap();
        assert_eq!(outcome, StopOutcome::CleanupRequired);
        {
            let state = backend.0.lock().unwrap();
            assert_eq!((state.graceful, state.forced), (0, 0));
        }
        assert_eq!(
            store.load_launch(plan.attempt_id).await.unwrap().state,
            LaunchState::CleanupRequired,
            "an exhausted deadline must be durably classified without signalling"
        );
        let classified = store.load_launch(plan.attempt_id).await.unwrap();
        let repeated = supervisor
            .stop_with_deadline(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(147, RequestId::from_uuid),
                    terminal: identity(148, RequestId::from_uuid),
                },
                tokio::time::Instant::now(),
            )
            .await
            .unwrap();
        assert_eq!(repeated, StopOutcome::CleanupRequired);
        assert_eq!(
            store.load_launch(plan.attempt_id).await.unwrap().revision,
            classified.revision,
            "an already-classified exhausted stop must be mutation-free"
        );
    }

    #[tokio::test]
    async fn stale_owner_cannot_inspect_or_signal_existing_terminalizing_launches() {
        for target in [LaunchState::Stopping, LaunchState::CleanupRequired] {
            let (_directory, store, plan) = fixture().await;
            let backend = Arc::new(FakeBackend::default());
            let stale_supervisor =
                InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
            stale_supervisor.launch(plan.clone()).await.unwrap();
            let ready = store.load_launch(plan.attempt_id).await.unwrap();
            store
                .transition_launch(TransitionLaunch {
                    context: RequestContext::new(identity(149, RequestId::from_uuid), plan.host_id),
                    session_id: plan.session_id,
                    epoch: plan.ownership_epoch,
                    attempt_id: plan.attempt_id,
                    expected_revision: ready.revision,
                    target,
                    cleanup_reason: (target == LaunchState::CleanupRequired)
                        .then(|| BoundedText::new("adversarial fixture").unwrap()),
                })
                .await
                .unwrap();
            store
                .release_ownership(ReleaseOwnership::new(
                    RequestContext::new(identity(150, RequestId::from_uuid), plan.host_id),
                    plan.session_id,
                    plan.ownership_epoch,
                ))
                .await
                .unwrap();
            let successor_host = identity(151, HostId::from_uuid);
            let successor = store
                .acquire_ownership(AcquireOwnership::new(
                    RequestContext::new(identity(152, RequestId::from_uuid), successor_host),
                    plan.session_id,
                    LeaseDuration::from_millis(60_000).unwrap(),
                ))
                .await
                .unwrap()
                .value()
                .clone();
            let _successor_supervisor =
                InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
            assert!(successor.epoch() > plan.ownership_epoch);
            let before = store.load_launch(plan.attempt_id).await.unwrap();

            let result = stale_supervisor
                .stop_with_deadline(
                    plan.attempt_id,
                    plan.host_id,
                    plan.ownership_epoch,
                    StopRequestIds {
                        stopping: identity(153, RequestId::from_uuid),
                        terminal: identity(154, RequestId::from_uuid),
                    },
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await;

            assert!(matches!(
                result,
                Err(SupervisorError::Store(
                    StoreError::StaleOwnership { .. } | StoreError::OwnershipHeld { .. }
                ))
            ));
            {
                let state = backend.0.lock().unwrap();
                assert_eq!(
                    (state.inspected, state.graceful, state.forced, state.cleaned),
                    (0, 0, 0, 0)
                );
            }
            assert_eq!(store.load_launch(plan.attempt_id).await.unwrap(), before);
        }
    }

    #[tokio::test]
    async fn signal_and_cleanup_failures_are_durably_cleanup_required() {
        for cleanup_failure in [false, true] {
            let (_directory, store, plan) = fixture().await;
            let backend = Arc::new(FakeBackend::default());
            {
                let mut state = backend.0.lock().unwrap();
                state.exits_on_wait = cleanup_failure;
                state.fail_graceful = !cleanup_failure;
                state.fail_cleanup = cleanup_failure;
            }
            let supervisor = InstanceSupervisor::new(store.clone(), backend, Credential, config());
            supervisor.launch(plan.clone()).await.unwrap();
            let outcome = supervisor
                .stop(
                    plan.attempt_id,
                    plan.host_id,
                    plan.ownership_epoch,
                    StopRequestIds {
                        stopping: identity(51 + u128::from(cleanup_failure), RequestId::from_uuid),
                        terminal: identity(53 + u128::from(cleanup_failure), RequestId::from_uuid),
                    },
                )
                .await
                .unwrap();
            assert_eq!(outcome, StopOutcome::CleanupRequired);
            assert_eq!(
                store.load_launch(plan.attempt_id).await.unwrap().state,
                LaunchState::CleanupRequired
            );
        }
    }

    #[tokio::test]
    async fn cleanup_required_retry_is_stable_then_can_confirm_stopped() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        let first = supervisor
            .stop(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(60, RequestId::from_uuid),
                    terminal: identity(61, RequestId::from_uuid),
                },
            )
            .await
            .unwrap();
        assert_eq!(first, StopOutcome::CleanupRequired);
        let second = supervisor
            .stop(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(62, RequestId::from_uuid),
                    terminal: identity(63, RequestId::from_uuid),
                },
            )
            .await
            .unwrap();
        assert_eq!(second, StopOutcome::CleanupRequired);
        backend.0.lock().unwrap().exits_on_wait = true;
        let final_outcome = supervisor
            .stop(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(64, RequestId::from_uuid),
                    terminal: identity(65, RequestId::from_uuid),
                },
            )
            .await
            .unwrap();
        assert_eq!(final_outcome, StopOutcome::Stopped);
        assert_eq!(
            store.load_launch(plan.attempt_id).await.unwrap().state,
            LaunchState::Stopped
        );
    }

    #[tokio::test]
    async fn ownership_loss_revokes_channel_before_waiting_or_signalling() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor = InstanceSupervisor::new(store, backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        let outcome = supervisor
            .ownership_lost(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(42, RequestId::from_uuid),
                    terminal: identity(43, RequestId::from_uuid),
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome, StopOutcome::Stopped);
        let state = backend.0.lock().unwrap();
        assert_eq!((state.revoked, state.graceful, state.forced), (1, 0, 0));
    }

    #[tokio::test]
    async fn ownership_loss_cleans_local_process_when_stale_epoch_blocks_durable_transition() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        store
            .release_ownership(ReleaseOwnership::new(
                RequestContext::new(identity(47, RequestId::from_uuid), plan.host_id),
                plan.session_id,
                plan.ownership_epoch,
            ))
            .await
            .unwrap();
        let outcome = supervisor
            .ownership_lost(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(48, RequestId::from_uuid),
                    terminal: identity(49, RequestId::from_uuid),
                },
            )
            .await
            .unwrap();
        assert_eq!(outcome, StopOutcome::CleanupRequired);
        let state = backend.0.lock().unwrap();
        assert_eq!((state.revoked, state.cleaned), (1, 1));
    }

    #[tokio::test]
    async fn watchdog_revokes_and_cleans_when_ownership_channel_is_lost() {
        let (_directory, store, plan) = fixture().await;
        let backend = Arc::new(FakeBackend::default());
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        store
            .release_ownership(ReleaseOwnership::new(
                RequestContext::new(identity(56, RequestId::from_uuid), plan.host_id),
                plan.session_id,
                plan.ownership_epoch,
            ))
            .await
            .unwrap();
        let terminal_fence = Arc::new(LifecycleFence::default());
        let published = Arc::new(Mutex::new(1_u8));
        let at_publish = Arc::new(tokio::sync::Notify::new());
        let resume_publish = Arc::new(tokio::sync::Notify::new());
        let publish_task = {
            let terminal_fence = Arc::clone(&terminal_fence);
            let published = Arc::clone(&published);
            let at_publish = Arc::clone(&at_publish);
            let resume_publish = Arc::clone(&resume_publish);
            tokio::spawn(async move {
                at_publish.notify_one();
                resume_publish.notified().await;
                terminal_fence.while_open(|| *published.lock().unwrap() = 2)
            })
        };
        at_publish.notified().await;
        let outcome = supervisor
            .watch_ownership_with_fence(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(57, RequestId::from_uuid),
                    terminal: identity(58, RequestId::from_uuid),
                },
                Duration::from_millis(1),
                Some(&terminal_fence),
            )
            .await
            .unwrap();
        assert_eq!(outcome, StopOutcome::CleanupRequired);
        assert!(terminal_fence.is_closed());
        resume_publish.notify_one();
        assert!(publish_task.await.unwrap().is_none());
        assert_eq!(*published.lock().unwrap(), 1);
        assert_eq!(backend.0.lock().unwrap().revoked, 1);
    }

    #[tokio::test]
    async fn watchdog_fences_every_preexisting_terminal_launch_state() {
        for (force_behavior, expected) in [
            (ForceBehavior::Exit, StopOutcome::Stopped),
            (ForceBehavior::Remain, StopOutcome::CleanupRequired),
        ] {
            let (_directory, store, plan) = fixture().await;
            let backend = Arc::new(FakeBackend::default());
            backend.0.lock().unwrap().force_behavior = force_behavior;
            let supervisor = InstanceSupervisor::new(store, backend, Credential, config());
            supervisor.launch(plan.clone()).await.unwrap();
            let stopped = supervisor
                .stop(
                    plan.attempt_id,
                    plan.host_id,
                    plan.ownership_epoch,
                    StopRequestIds {
                        stopping: identity(170, RequestId::from_uuid),
                        terminal: identity(171, RequestId::from_uuid),
                    },
                )
                .await
                .unwrap();
            assert_eq!(stopped, expected);
            let fence = LifecycleFence::default();
            let observed = supervisor
                .watch_ownership_with_fence(
                    plan.attempt_id,
                    plan.host_id,
                    plan.ownership_epoch,
                    StopRequestIds {
                        stopping: identity(172, RequestId::from_uuid),
                        terminal: identity(173, RequestId::from_uuid),
                    },
                    Duration::from_millis(1),
                    Some(&fence),
                )
                .await
                .unwrap();
            assert_eq!(observed, expected);
            assert!(fence.is_closed());
        }
    }

    #[tokio::test]
    async fn watchdog_tolerates_isolated_retryable_validation_faults_then_revokes_stale_owner() {
        let (_directory, sqlite, plan) = fixture().await;
        let store = Arc::new(ValidationFaultStore::new(sqlite.clone()));
        let backend = Arc::new(FakeBackend::default());
        let mut watchdog_config = config();
        watchdog_config.ownership_loss_timeout = Duration::from_millis(100);
        let supervisor = Arc::new(InstanceSupervisor::new(
            store.clone(),
            backend.clone(),
            Credential,
            watchdog_config,
        ));
        supervisor.launch(plan.clone()).await.unwrap();
        store.inject_load([StoreError::Busy, StoreError::Unavailable]);
        store.inject_validation([StoreError::Busy, StoreError::Unavailable]);
        let watcher = {
            let supervisor = supervisor.clone();
            let plan = plan.clone();
            tokio::spawn(async move {
                supervisor
                    .watch_ownership(
                        plan.attempt_id,
                        plan.host_id,
                        plan.ownership_epoch,
                        StopRequestIds {
                            stopping: identity(155, RequestId::from_uuid),
                            terminal: identity(156, RequestId::from_uuid),
                        },
                        Duration::from_millis(1),
                    )
                    .await
            })
        };
        let observed = tokio::time::timeout(Duration::from_secs(1), store.wait_for_faults(4))
            .await
            .expect("watchdog did not consume injected retryable faults");
        assert_eq!(
            observed,
            vec![
                ("load", StoreError::Busy),
                ("load", StoreError::Unavailable),
                ("validate", StoreError::Busy),
                ("validate", StoreError::Unavailable),
            ]
        );
        tokio::time::timeout(
            Duration::from_secs(1),
            store.wait_for_validation_successes(2),
        )
        .await
        .expect("watchdog did not recover after isolated retryable faults");
        assert!(!watcher.is_finished());
        assert_eq!(backend.0.lock().unwrap().revoked, 0);

        sqlite
            .release_ownership(ReleaseOwnership::new(
                RequestContext::new(identity(157, RequestId::from_uuid), plan.host_id),
                plan.session_id,
                plan.ownership_epoch,
            ))
            .await
            .unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(1), watcher)
            .await
            .expect("watchdog did not react to authoritative ownership loss")
            .unwrap()
            .unwrap();
        assert_eq!(outcome, StopOutcome::CleanupRequired);
        let state = backend.0.lock().unwrap();
        assert_eq!(state.revoked, 1);
        assert_eq!(state.cleaned, 1);
    }

    #[tokio::test]
    async fn watchdog_retryable_authority_expiry_closes_terminal_fence() {
        let (_directory, sqlite, plan) = fixture().await;
        let store = Arc::new(ValidationFaultStore::new(sqlite));
        let backend = Arc::new(FakeBackend::default());
        let mut watchdog_config = config();
        watchdog_config.ownership_loss_timeout = Duration::ZERO;
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, watchdog_config);
        supervisor.launch(plan.clone()).await.unwrap();
        store.inject_load([StoreError::Unavailable]);
        let fence = Arc::new(LifecycleFence::default());
        backend.0.lock().unwrap().revoke_fence = Some(Arc::clone(&fence));
        let outcome = supervisor
            .watch_ownership_with_fence(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(174, RequestId::from_uuid),
                    terminal: identity(175, RequestId::from_uuid),
                },
                Duration::from_millis(1),
                Some(&fence),
            )
            .await
            .unwrap();
        assert_eq!(outcome, StopOutcome::Stopped);
        assert!(fence.is_closed());
        let faults = store.wait_for_faults(1).await;
        assert!(faults.iter().all(|(site, _)| *site == "load"));
        let state = backend.0.lock().unwrap();
        assert_eq!(state.revoke_fence_observation, Some(true));
    }

    #[tokio::test]
    async fn watchdog_revokes_before_returning_a_nonretryable_launch_read_failure() {
        let (_directory, sqlite, plan) = fixture().await;
        let store = Arc::new(ValidationFaultStore::new(sqlite));
        let backend = Arc::new(FakeBackend::default());
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        store.inject_load([StoreError::Corrupt]);
        let terminal_fence = LifecycleFence::default();

        let result = supervisor
            .watch_ownership_with_fence(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(158, RequestId::from_uuid),
                    terminal: identity(159, RequestId::from_uuid),
                },
                Duration::from_millis(1),
                Some(&terminal_fence),
            )
            .await;

        assert!(matches!(
            result,
            Err(SupervisorError::Store(StoreError::Corrupt))
        ));
        assert!(terminal_fence.is_closed());
        assert_eq!(
            store.wait_for_faults(1).await,
            vec![("load", StoreError::Corrupt)]
        );
        let state = backend.0.lock().unwrap();
        assert_eq!((state.revoked, state.cleaned), (1, 1));
    }

    #[tokio::test]
    async fn corrupt_launch_read_escalates_a_driver_that_ignores_ownership_revocation() {
        let (_directory, sqlite, plan) = fixture().await;
        let store = Arc::new(ValidationFaultStore::new(sqlite));
        let backend = Arc::new(FakeBackend::default());
        {
            let mut state = backend.0.lock().unwrap();
            state.revoke_behavior = RevokeBehavior::Ignore;
            state.force_behavior = ForceBehavior::Exit;
        }
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        store.inject_load([StoreError::Corrupt]);

        let result = supervisor
            .watch_ownership(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(160, RequestId::from_uuid),
                    terminal: identity(161, RequestId::from_uuid),
                },
                Duration::from_millis(1),
            )
            .await;

        assert!(matches!(
            result,
            Err(SupervisorError::Store(StoreError::Corrupt))
        ));
        {
            let state = backend.0.lock().unwrap();
            assert_eq!(
                (state.revoked, state.graceful, state.forced, state.cleaned),
                (1, 1, 1, 1)
            );
        }
        assert!(
            !supervisor
                .active
                .lock()
                .await
                .contains_key(&plan.attempt_id)
        );
    }

    #[tokio::test]
    async fn unproven_exit_after_corrupt_read_retains_binding_for_reconciliation() {
        let (_directory, sqlite, plan) = fixture().await;
        let store = Arc::new(ValidationFaultStore::new(sqlite));
        let backend = Arc::new(FakeBackend::default());
        backend.0.lock().unwrap().revoke_behavior = RevokeBehavior::Ignore;
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, config());
        supervisor.launch(plan.clone()).await.unwrap();
        store.inject_load([StoreError::Corrupt]);

        let result = supervisor
            .watch_ownership(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(162, RequestId::from_uuid),
                    terminal: identity(163, RequestId::from_uuid),
                },
                Duration::from_millis(1),
            )
            .await;

        assert!(matches!(result, Err(SupervisorError::CleanupRequired)));
        {
            let state = backend.0.lock().unwrap();
            assert_eq!(
                (state.revoked, state.graceful, state.forced, state.cleaned),
                (1, 1, 1, 0)
            );
        }
        assert!(
            supervisor
                .active
                .lock()
                .await
                .contains_key(&plan.attempt_id)
        );
    }

    #[tokio::test]
    async fn unrepresentable_escalation_deadline_is_fail_closed_and_retains_binding() {
        let (_directory, sqlite, plan) = fixture().await;
        let store = Arc::new(ValidationFaultStore::new(sqlite));
        let backend = Arc::new(FakeBackend::default());
        backend.0.lock().unwrap().revoke_behavior = RevokeBehavior::Ignore;
        let overflow_config = SupervisorConfig {
            graceful_timeout: Duration::MAX,
            forced_timeout: Duration::MAX,
            ownership_loss_timeout: Duration::from_millis(1),
        };
        let supervisor =
            InstanceSupervisor::new(store.clone(), backend.clone(), Credential, overflow_config);
        supervisor.launch(plan.clone()).await.unwrap();
        store.inject_load([StoreError::Corrupt]);

        let result = supervisor
            .watch_ownership(
                plan.attempt_id,
                plan.host_id,
                plan.ownership_epoch,
                StopRequestIds {
                    stopping: identity(164, RequestId::from_uuid),
                    terminal: identity(165, RequestId::from_uuid),
                },
                Duration::from_millis(1),
            )
            .await;

        assert!(matches!(result, Err(SupervisorError::CleanupRequired)));
        {
            let state = backend.0.lock().unwrap();
            assert_eq!(
                (state.revoked, state.graceful, state.forced, state.cleaned),
                (1, 0, 0, 0)
            );
        }
        assert!(
            supervisor
                .active
                .lock()
                .await
                .contains_key(&plan.attempt_id)
        );
    }
}
