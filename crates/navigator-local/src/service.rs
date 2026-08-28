use std::{
    collections::HashMap,
    fs::File,
    future::Future,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, RwLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use navigator_consumer_protocol::{
    ArtifactWriteStreamValidator, CAPABILITY_APPROVALS_V1, CAPABILITY_ARTIFACTS_V1,
    CAPABILITY_CONSUMER_TOOLS_V1, CAPABILITY_OPERATIONAL_PROJECTIONS_V1, CURRENT_MAJOR,
    CURRENT_MINOR, MAX_ARTIFACT_CHUNK_BYTES, MAX_REQUEST_BYTES, ValidateRequest, ValidationError,
    negotiate,
    v1::{
        self, Failure, FailureCode, RetryClass, close_session_response,
        navigator_consumer_server::NavigatorConsumer, negotiate_response, open_session_response,
        snapshot_response, subscribe_events_response,
    },
    validate_artifact_snapshot_response, validate_begin_artifact_write,
    validate_delete_artifact_response, validate_negotiated_capabilities,
    validate_write_artifact_response, validated_session_templates,
};
use navigator_core::{
    AdmissionPermit, FirstOperationService, OperationExecutor, OperationPersistence,
    OwnershipConfig, OwnershipStatus, OwnershipSupervisor, Reconciler, RecoveryBackend,
    RecoveryEntity, RecoveryRunIds, ReleaseCommandError, ReleaseCommandFactory, ReleaseOutcome,
    RenewalCommandError, RenewalCommandFactory, TransitionContextFactory, WallClock,
};
use navigator_domain::{
    ApprovalGrant, ApprovalRequest, ApprovalRequestId, ApprovalStatus, ArtifactDigest, ArtifactId,
    ArtifactMediaType, ArtifactSnapshot, ArtifactState, BoundedBytes, BoundedText, Capability,
    CompatibilityIdentity, ConsumerKey, EffectProof, EffectProofKind, EventPosition, FencingEpoch,
    GrantId, HostId, MAX_EFFECT_PROOF_BYTES, MAX_RESOLUTION_REASON_BYTES, MessageId, OperationId,
    OperationState, OwnershipSnapshot, ParticipantId, RequestId, ResolveUncertaintyDecision,
    ResourceScope, Revision, ScopedCapability, SessionCompatibilityManifest, SessionEvent,
    SessionId, SessionSnapshot, SessionStatus, Template, Timestamp, UncertaintyResolution,
};
use navigator_store_api::{
    AcquireOwnership, ApprovalStore, ApproveRequest, ArtifactAccess, ArtifactStore,
    AuthorityPolicySnapshot, AuthorityStore, AuthorityTemplatePolicy, CancelSubtree,
    CapacityResource, CloseSession, CreateRootParticipant, DeleteArtifact, DenyRequest,
    EffectJournalStore, EventReadLimit, HierarchyStore, InstanceStore, LeaseDuration, LimitProfile,
    MailboxStore, MessageDeliveryState, MessagePriority, MessageSnapshot, MutableRequest,
    OpenSession, OperationSnapshot, OperationStore, OperationTerminalOutcome, OwnershipLease,
    ParticipantSnapshot, ProjectionPage, ProjectionPageSize, ProjectionPageToken, ProjectionStore,
    ProjectionView, PutAuthorityPolicy, ReadEvents, ReadProjection,
    RegisterAuthorityTemplatePolicy, RegisterTemplatesAndOpenSession, ReleaseOwnership,
    RenewOwnership, RequestContext, ResolveAuthorizedEffect, RevokeApprovalGrant, SessionStore,
    StartOperation, StoreAction, StoreError, StoredRequestOutcome, StoredResult,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::{Mutex, Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    time::{MissedTickBehavior, interval},
};

use crate::{BackgroundShutdownOutcome, BackgroundTaskRegistry, shutdown::ShutdownDeadline};
use tokio_stream::{
    Stream,
    wrappers::{ReceiverStream, UnixListenerStream},
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub const AUTHENTICATION_HEADER: &str = "x-navigator-bootstrap";
pub const MAX_SUBSCRIPTIONS: usize = 32;
const EVENT_STREAM_QUEUE_CAPACITY: usize = 32;
const EVENT_STREAM_SEND_TIMEOUT: Duration = Duration::from_millis(250);
const CAPABILITIES: &[&str] = &[
    "events.replay.v1",
    "operation.execution.v1",
    "operation.cancellation.v1",
    "resource.snapshots.v1",
    "session.lifecycle.v1",
    "session.open-modes.v1",
];
#[derive(Clone)]
pub(crate) struct NegotiationEntry {
    pub(crate) capabilities: Vec<String>,
    pub(crate) consumer_key: Option<ConsumerKey>,
    pub(crate) reservation_id: Option<RequestId>,
}

/// Transport proof inserted only after bootstrap authentication. It is private
/// so an in-process untrusted controller cannot manufacture approval authority.
#[derive(Clone, Copy)]
struct AuthenticatedTrustedConsumer;

#[derive(Clone, Copy)]
struct TrustedConsumerAuthority(AuthenticatedTrustedConsumer);

#[derive(Clone)]
struct ApprovalView {
    request: ApprovalRequest,
    grant: Option<ApprovalGrant>,
}

#[tonic::async_trait]
trait ApprovalController: Send + Sync {
    async fn snapshot(
        &self,
        session_id: SessionId,
        approval_id: ApprovalRequestId,
    ) -> Result<ApprovalView, StoreError>;
    async fn approve(
        &self,
        authority: TrustedConsumerAuthority,
        command: ApproveRequest,
    ) -> Result<ApprovalView, StoreError>;
    async fn deny(
        &self,
        authority: TrustedConsumerAuthority,
        command: DenyRequest,
    ) -> Result<ApprovalView, StoreError>;
    async fn revoke(
        &self,
        authority: TrustedConsumerAuthority,
        command: RevokeApprovalGrant,
    ) -> Result<ApprovalView, StoreError>;
}

struct StoreApprovalController<S> {
    store: Arc<S>,
}

#[tonic::async_trait]
impl<S: ApprovalStore + 'static> ApprovalController for StoreApprovalController<S> {
    async fn snapshot(
        &self,
        session_id: SessionId,
        approval_id: ApprovalRequestId,
    ) -> Result<ApprovalView, StoreError> {
        let request = self.store.load_approval_request(approval_id).await?;
        if request.session_id != session_id {
            return Err(StoreError::Invalid);
        }
        let grant = match request.grant_id {
            Some(id) => Some(self.store.load_approval_grant(id).await?),
            None => None,
        };
        Ok(ApprovalView { request, grant })
    }

    async fn approve(
        &self,
        _: TrustedConsumerAuthority,
        command: ApproveRequest,
    ) -> Result<ApprovalView, StoreError> {
        let value = self.store.approve_request(command).await?;
        Ok(ApprovalView {
            request: value.value().request.clone(),
            grant: Some(value.value().grant.clone()),
        })
    }

    async fn deny(
        &self,
        _: TrustedConsumerAuthority,
        command: DenyRequest,
    ) -> Result<ApprovalView, StoreError> {
        let value = self.store.deny_request(command).await?;
        Ok(ApprovalView {
            request: value.value().clone(),
            grant: None,
        })
    }

    async fn revoke(
        &self,
        _: TrustedConsumerAuthority,
        command: RevokeApprovalGrant,
    ) -> Result<ApprovalView, StoreError> {
        let value = self.store.revoke_approval_grant(command).await?;
        let grant = value.value().clone();
        let request = self.store.load_approval_request(grant.request_id).await?;
        Ok(ApprovalView {
            request,
            grant: Some(grant),
        })
    }
}
type EventStream = Pin<Box<dyn Stream<Item = Result<v1::SubscribeEventsResponse, Status>> + Send>>;
type ArtifactReadStream =
    Pin<Box<dyn Stream<Item = Result<v1::ReadArtifactResponse, Status>> + Send>>;
type ToolProviderStream =
    Pin<Box<dyn Stream<Item = Result<v1::ToolProviderResponse, Status>> + Send>>;
type ArtifactContent = Pin<Box<dyn AsyncRead + Send + Unpin + 'static>>;

#[derive(Debug, Error)]
pub enum LocalError {
    #[error("invalid bootstrap credential")]
    InvalidCredential,
    #[error("local I/O failed")]
    Io(#[from] io::Error),
    #[error("local transport failed")]
    Transport(#[from] tonic::transport::Error),
    #[error("invalid persisted host identity")]
    InvalidHostIdentity,
    #[error("socket path exists and is not a socket")]
    UnsafeSocketPath,
    #[error("socket path is already in use")]
    SocketInUse,
    #[error("socket parent directory is not private")]
    UnsafeSocketDirectory,
    #[error("ownership cleanup did not complete")]
    CleanupRequired,
}

#[derive(Clone)]
pub struct BootstrapCredential(Arc<[u8]>);

impl BootstrapCredential {
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Result<Self, LocalError> {
        let bytes = bytes.into();
        if bytes.is_empty()
            || bytes.len() > 4096
            || !bytes.is_ascii()
            || bytes.contains(&b'\n')
            || bytes.contains(&b'\r')
        {
            return Err(LocalError::InvalidCredential);
        }
        Ok(Self(bytes.into()))
    }

    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, LocalError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if std::fs::metadata(path.as_ref())?.permissions().mode() & 0o077 != 0 {
                return Err(LocalError::InvalidCredential);
            }
        }
        let mut bytes = std::fs::read(path)?;
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        Self::from_bytes(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn authenticate(&self, request: &Request<()>) -> Result<(), Status> {
        let supplied = request
            .metadata()
            .get(AUTHENTICATION_HEADER)
            .map(tonic::metadata::MetadataValue::as_encoded_bytes)
            .unwrap_or_default();
        let mut expected = vec![0_u8; 4096];
        expected[..self.0.len()].copy_from_slice(&self.0);
        let mut candidate = vec![0_u8; 4096];
        let copied = supplied.len().min(candidate.len());
        candidate[..copied].copy_from_slice(&supplied[..copied]);
        let same_length = u64::try_from(supplied.len())
            .unwrap_or(u64::MAX)
            .ct_eq(&u64::try_from(self.0.len()).expect("credential bound fits u64"));
        if bool::from(same_length & candidate.ct_eq(&expected)) {
            Ok(())
        } else {
            Err(Status::unauthenticated("authentication failed"))
        }
    }
}

pub fn load_or_create_host_id(path: impl AsRef<Path>) -> Result<HostId, LocalError> {
    let path = path.as_ref();
    if path.exists() {
        return read_host_id(path);
    }
    let uuid = random_uuid()?;
    let id = HostId::from_uuid(uuid).map_err(|_| LocalError::InvalidHostIdentity)?;
    let temporary = path.with_extension(format!("{}.tmp", random_uuid()?));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(uuid.to_string().as_bytes())?;
    file.sync_all()?;
    match std::fs::hard_link(&temporary, path) {
        Ok(()) => {
            std::fs::remove_file(temporary)?;
            Ok(id)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(temporary)?;
            read_host_id(path)
        }
        Err(error) => {
            let _ = std::fs::remove_file(temporary);
            Err(error.into())
        }
    }
}

fn read_host_id(path: &Path) -> Result<HostId, LocalError> {
    let text = std::fs::read_to_string(path)?;
    let uuid = Uuid::parse_str(text.trim()).map_err(|_| LocalError::InvalidHostIdentity)?;
    HostId::from_uuid(uuid).map_err(|_| LocalError::InvalidHostIdentity)
}

struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }
}

struct CommandFactory {
    host_id: HostId,
}

impl RenewalCommandFactory for CommandFactory {
    fn create(
        &self,
        lease: &OwnershipLease,
        duration: LeaseDuration,
    ) -> Result<RenewOwnership, RenewalCommandError> {
        let request_id = RequestId::from_uuid(random_uuid().map_err(|_| RenewalCommandError)?)
            .map_err(|_| RenewalCommandError)?;
        Ok(RenewOwnership::new(
            RequestContext::new(request_id, self.host_id),
            lease.session_id(),
            lease.epoch(),
            duration,
        ))
    }
}

impl ReleaseCommandFactory for CommandFactory {
    fn create(&self, lease: &OwnershipLease) -> Result<ReleaseOwnership, ReleaseCommandError> {
        let request_id = RequestId::from_uuid(random_uuid().map_err(|_| ReleaseCommandError)?)
            .map_err(|_| ReleaseCommandError)?;
        Ok(ReleaseOwnership::new(
            RequestContext::new(request_id, self.host_id),
            lease.session_id(),
            lease.epoch(),
        ))
    }
}

pub struct LocalNavigator<S> {
    store: Arc<S>,
    host_id: HostId,
    lease_duration: LeaseDuration,
    negotiations: Arc<RwLock<HashMap<Uuid, NegotiationEntry>>>,
    supervisors: Arc<Mutex<HashMap<SessionId, SessionSupervisor<S>>>>,
    close_locks: Arc<Mutex<HashMap<SessionId, Weak<Mutex<()>>>>>,
    stopping: Arc<AtomicBool>,
    subscriptions: Arc<Semaphore>,
    subscription_sessions: Arc<std::sync::Mutex<HashMap<SessionId, usize>>>,
    limits: Arc<LimitProfile>,
    cleanup_failed: Arc<AtomicBool>,
    operations: Arc<dyn OperationController>,
    recovery: Arc<dyn RecoveryController>,
    recovery_configured: bool,
    runtime_configuration_identity: [u8; 32],
    mailbox_dispatcher: Option<Arc<dyn crate::SessionMailboxDispatcher>>,
    mailbox_pumps: Arc<Mutex<HashMap<SessionId, FencingEpoch>>>,
    mailbox_wakes: Arc<Mutex<HashMap<SessionId, Arc<Notify>>>>,
    mailbox_pump_stopped: Arc<Notify>,
    ownership_shutdown_millis: Arc<AtomicU64>,
    session_close_timeout_millis: Arc<AtomicU64>,
    background_tasks: BackgroundTaskRegistry,
    artifacts: Arc<dyn ArtifactController>,
    artifacts_configured: bool,
    tools: Option<Arc<dyn crate::ToolBrokerControl>>,
    approvals: Option<Arc<dyn ApprovalController>>,
    projections: Option<Arc<dyn ProjectionController>>,
}

trait ProjectionController: Send + Sync {
    fn read(
        &self,
        query: ReadProjection,
    ) -> Pin<Box<dyn Future<Output = Result<ProjectionPage, StoreError>> + Send + '_>>;
}

struct StoreProjectionController<S>(Arc<S>);

impl<S: ProjectionStore + 'static> ProjectionController for StoreProjectionController<S> {
    fn read(
        &self,
        query: ReadProjection,
    ) -> Pin<Box<dyn Future<Output = Result<ProjectionPage, StoreError>> + Send + '_>> {
        Box::pin(self.0.read_projection(query))
    }
}

#[derive(Debug, Error)]
pub enum ArtifactControlError {
    #[error("artifact service is unavailable")]
    Unavailable,
    #[error("artifact request is invalid")]
    Invalid,
    #[error("artifact exceeds its bound")]
    Oversize,
    #[error("artifact integrity check failed")]
    Integrity,
    #[error("artifact metadata store failed")]
    Store(#[from] StoreError),
    #[error("artifact filesystem failed")]
    Io(#[from] io::Error),
}

#[tonic::async_trait]
pub trait ArtifactController: Send + Sync {
    async fn write(
        &self,
        request: crate::ArtifactWrite,
        content: ArtifactContent,
    ) -> Result<ArtifactSnapshot, ArtifactControlError>;
    async fn read(
        &self,
        access: ArtifactAccess,
    ) -> Result<(ArtifactSnapshot, ArtifactContent), ArtifactControlError>;
    async fn snapshot(
        &self,
        access: ArtifactAccess,
    ) -> Result<ArtifactSnapshot, ArtifactControlError>;
    async fn logically_delete(
        &self,
        request: DeleteArtifact,
    ) -> Result<ArtifactSnapshot, ArtifactControlError>;
}

struct UnavailableArtifactController;

#[tonic::async_trait]
impl ArtifactController for UnavailableArtifactController {
    async fn write(
        &self,
        _: crate::ArtifactWrite,
        _: ArtifactContent,
    ) -> Result<ArtifactSnapshot, ArtifactControlError> {
        Err(ArtifactControlError::Unavailable)
    }
    async fn read(
        &self,
        _: ArtifactAccess,
    ) -> Result<(ArtifactSnapshot, ArtifactContent), ArtifactControlError> {
        Err(ArtifactControlError::Unavailable)
    }
    async fn snapshot(&self, _: ArtifactAccess) -> Result<ArtifactSnapshot, ArtifactControlError> {
        Err(ArtifactControlError::Unavailable)
    }
    async fn logically_delete(
        &self,
        _: DeleteArtifact,
    ) -> Result<ArtifactSnapshot, ArtifactControlError> {
        Err(ArtifactControlError::Unavailable)
    }
}

#[tonic::async_trait]
impl<S> ArtifactController for crate::LocalArtifactStore<S>
where
    S: ArtifactStore + navigator_store_api::CapacityStore + 'static,
{
    async fn write(
        &self,
        request: crate::ArtifactWrite,
        content: ArtifactContent,
    ) -> Result<ArtifactSnapshot, ArtifactControlError> {
        crate::LocalArtifactStore::write(self, request, content)
            .await
            .map_err(artifact_local_error)
    }
    async fn read(
        &self,
        access: ArtifactAccess,
    ) -> Result<(ArtifactSnapshot, ArtifactContent), ArtifactControlError> {
        self.open_verified(access)
            .await
            .map(|(snapshot, file)| (snapshot, Box::pin(file) as ArtifactContent))
            .map_err(artifact_local_error)
    }
    async fn snapshot(
        &self,
        access: ArtifactAccess,
    ) -> Result<ArtifactSnapshot, ArtifactControlError> {
        crate::LocalArtifactStore::snapshot(self, access)
            .await
            .map_err(artifact_local_error)
    }
    async fn logically_delete(
        &self,
        request: DeleteArtifact,
    ) -> Result<ArtifactSnapshot, ArtifactControlError> {
        crate::LocalArtifactStore::logically_delete(self, request)
            .await
            .map_err(artifact_local_error)
    }
}

fn artifact_local_error(error: crate::LocalArtifactError) -> ArtifactControlError {
    match error {
        crate::LocalArtifactError::Invalid => ArtifactControlError::Invalid,
        crate::LocalArtifactError::Oversize => ArtifactControlError::Oversize,
        crate::LocalArtifactError::Integrity => ArtifactControlError::Integrity,
        crate::LocalArtifactError::Store(value) => ArtifactControlError::Store(value),
        crate::LocalArtifactError::Io(value) => ArtifactControlError::Io(value),
    }
}

#[derive(Debug, Error)]
pub enum OperationControlError {
    #[error("operation execution is unavailable")]
    Unavailable,
    #[error("operation cleanup could not be verified")]
    CleanupRequired,
    #[error("operation persistence failed")]
    Store(#[from] StoreError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnverifiedRecoveryAuthorityClaim {
    pub grant_id: GrantId,
}

#[tonic::async_trait]
pub trait RecoveryController: Send + Sync {
    /// Acquires fresh fenced ownership, reconciles, and resumes only safe classifications.
    async fn resume_session(
        &self,
        recovery_request_id: RequestId,
        session_id: SessionId,
    ) -> Result<v1::RecoveryReport, OperationControlError>;

    /// Validates the untrusted Grant claim effect-time and atomically audits the resolution.
    async fn resolve_uncertainty(
        &self,
        authority_claim: UnverifiedRecoveryAuthorityClaim,
        request: v1::ResolveUncertaintyRequest,
    ) -> Result<v1::ResolutionSnapshot, OperationControlError>;
}

struct UnavailableRecoveryController;

#[tonic::async_trait]
pub trait AuthorizedResolutionStore: Send + Sync {
    async fn allowed_actions(
        &self,
        effect_id: RequestId,
    ) -> Result<Vec<v1::ResolutionAction>, OperationControlError>;

    async fn preflight_authorized(
        &self,
        authority_claim: UnverifiedRecoveryAuthorityClaim,
        request: &v1::ResolveUncertaintyRequest,
    ) -> Result<(), OperationControlError>;

    async fn resolve_authorized(
        &self,
        epoch: FencingEpoch,
        authority_claim: UnverifiedRecoveryAuthorityClaim,
        request: v1::ResolveUncertaintyRequest,
    ) -> Result<CommittedAuthorizedResolution, OperationControlError>;
}

pub struct CommittedAuthorizedResolution {
    pub wire: v1::ResolutionSnapshot,
    pub operation: OperationSnapshot,
}

pub struct LocalRecoveryController<B, R> {
    reconciler: Reconciler<B>,
    resolutions: Arc<R>,
}

pub struct StoreAuthorizedResolution<S> {
    store: Arc<S>,
    host_id: HostId,
}

impl<S> StoreAuthorizedResolution<S> {
    #[must_use]
    pub const fn new(store: Arc<S>, host_id: HostId) -> Self {
        Self { store, host_id }
    }
}

#[tonic::async_trait]
impl<S> AuthorizedResolutionStore for StoreAuthorizedResolution<S>
where
    S: AuthorityStore + EffectJournalStore + OperationStore + 'static,
{
    async fn allowed_actions(
        &self,
        effect_id: RequestId,
    ) -> Result<Vec<v1::ResolutionAction>, OperationControlError> {
        let effect = self
            .store
            .read_effect(effect_id)
            .await?
            .ok_or(StoreError::Invalid)?;
        if effect.phase != navigator_store_api::EffectJournalPhase::Uncertain {
            return Ok(Vec::new());
        }
        let contract = effect.resolution_contract;
        let mut actions = Vec::with_capacity(3);
        if contract.allows_completion_proof(navigator_domain::EffectProofKind::ExternalCommit)
            || contract
                .allows_completion_proof(navigator_domain::EffectProofKind::IdempotencyReceipt)
        {
            actions.push(v1::ResolutionAction::ConfirmCompleted);
        }
        if contract.allow_do_not_retry {
            actions.push(v1::ResolutionAction::DoNotRetry);
        }
        if contract.allows_retry_proof(navigator_domain::EffectProofKind::EffectAbsent) {
            actions.push(v1::ResolutionAction::RetryWithEffectProof);
        }
        Ok(actions)
    }

    async fn preflight_authorized(
        &self,
        authority_claim: UnverifiedRecoveryAuthorityClaim,
        request: &v1::ResolveUncertaintyRequest,
    ) -> Result<(), OperationControlError> {
        let session_id = session_id(&request.session_id).map_err(|_| StoreError::Invalid)?;
        let operation_id = operation_id(&request.operation_id).map_err(|_| StoreError::Invalid)?;
        let effect_id = request_id(&request.effect_id).map_err(|_| StoreError::Invalid)?;
        let effect = self
            .store
            .read_effect(effect_id)
            .await?
            .ok_or(StoreError::Invalid)?;
        let grant = self.store.load_grant(authority_claim.grant_id).await?;
        let now = time::OffsetDateTime::now_utc();
        let now = Timestamp::new(now.unix_timestamp(), now.nanosecond())
            .map_err(|_| StoreError::Invalid)?;
        let expected = ScopedCapability::new(
            Capability::new("effect.resolve_uncertainty").expect("static capability"),
            ResourceScope::Operation(operation_id),
        );
        if effect.session_id != session_id
            || effect.operation_id != operation_id
            || grant.grant.session_id != session_id
            || grant.grant.subject != effect.participant_id
            || grant.grant.authority != expected
            || (!grant.grant.is_active(now) && grant.consumed_at.is_none())
        {
            return Err(StoreError::Invalid.into());
        }
        Ok(())
    }

    async fn resolve_authorized(
        &self,
        epoch: FencingEpoch,
        authority_claim: UnverifiedRecoveryAuthorityClaim,
        request: v1::ResolveUncertaintyRequest,
    ) -> Result<CommittedAuthorizedResolution, OperationControlError> {
        let resolution_request_id =
            request_id(&request.request_id).map_err(|_| OperationControlError::Unavailable)?;
        let session_id =
            session_id(&request.session_id).map_err(|_| OperationControlError::Unavailable)?;
        let operation_id =
            operation_id(&request.operation_id).map_err(|_| OperationControlError::Unavailable)?;
        let effect_id =
            request_id(&request.effect_id).map_err(|_| OperationControlError::Unavailable)?;
        let effect = self
            .store
            .read_effect(effect_id)
            .await?
            .ok_or(StoreError::Invalid)?;
        if effect.session_id != session_id || effect.operation_id != operation_id {
            return Err(StoreError::Invalid.into());
        }
        let reason = BoundedText::<MAX_RESOLUTION_REASON_BYTES>::new(request.reason)
            .map_err(|_| StoreError::Invalid)?;
        let resolution = wire_resolution(request.resolution.ok_or(StoreError::Invalid)?)?;
        let action = wire_resolution_action(&resolution);
        let decision =
            ResolveUncertaintyDecision::new(session_id, operation_id, reason, resolution)
                .map_err(|_| StoreError::Invalid)?;
        let outcome = self
            .store
            .resolve_authorized_effect(ResolveAuthorizedEffect {
                context: RequestContext::new(resolution_request_id, self.host_id),
                session_id,
                owner_epoch: epoch,
                participant_id: effect.participant_id,
                grant_id: authority_claim.grant_id,
                effect_request_id: effect_id,
                expected_effect_revision: effect.revision,
                decision,
                tool_terminal: None,
            })
            .await?;
        let value = outcome.value();
        let wire = v1::ResolutionSnapshot {
            operation: Some(operation_wire(&value.current_operation)),
            action: action.into(),
            authority_grant_id: authority_claim.grant_id.as_uuid().as_bytes().to_vec(),
            reason: "authorized uncertainty resolution committed".to_owned(),
            request_id: resolution_request_id.as_uuid().as_bytes().to_vec(),
            session_id: session_id.as_uuid().as_bytes().to_vec(),
            effect_id: effect_id.as_uuid().as_bytes().to_vec(),
            revision: value.effect_entry.revision.get(),
            audit_event_position: value.audit_event_position.get(),
            action_status: if action == v1::ResolutionAction::RetryWithEffectProof {
                v1::RecoveryActionStatus::Pending.into()
            } else {
                v1::RecoveryActionStatus::Executed.into()
            },
        };
        Ok(CommittedAuthorizedResolution {
            wire,
            operation: value.current_operation.clone(),
        })
    }
}

impl<B: RecoveryBackend, R> LocalRecoveryController<B, R> {
    #[must_use]
    pub fn new(backend: B, resolutions: Arc<R>) -> Self {
        Self {
            reconciler: Reconciler::new(backend),
            resolutions,
        }
    }
}

#[tonic::async_trait]
impl<B, R> RecoveryController for LocalRecoveryController<B, R>
where
    B: RecoveryBackend<Error = StoreError> + Send + Sync,
    R: AuthorizedResolutionStore + 'static,
{
    async fn resume_session(
        &self,
        recovery_request_id: RequestId,
        session_id: SessionId,
    ) -> Result<v1::RecoveryReport, OperationControlError> {
        let reconciliation = self
            .reconciler
            .reconcile(
                session_id,
                RecoveryRunIds {
                    ownership_request_id: recovery_internal_id(
                        b"navigator.resume.ownership.v1",
                        recovery_request_id,
                        session_id,
                    ),
                    classification_request_id: recovery_request_id,
                },
            )
            .await
            .map_err(|_| OperationControlError::CleanupRequired)?;
        let mut report = recovery_report(session_id, &reconciliation);
        for classification in &mut report.classifications {
            let Some(v1::recovery_classification::Entity::EffectId(effect_id)) =
                classification.entity.as_ref()
            else {
                continue;
            };
            if classification.disposition != i32::from(v1::RecoveryDisposition::EffectUncertain) {
                classification.allowed_actions.clear();
                continue;
            }
            let effect_id =
                request_id(effect_id).map_err(|_| OperationControlError::CleanupRequired)?;
            classification.allowed_actions = self
                .resolutions
                .allowed_actions(effect_id)
                .await?
                .into_iter()
                .map(i32::from)
                .collect();
        }
        Ok(report)
    }

    async fn resolve_uncertainty(
        &self,
        authority_claim: UnverifiedRecoveryAuthorityClaim,
        request: v1::ResolveUncertaintyRequest,
    ) -> Result<v1::ResolutionSnapshot, OperationControlError> {
        let session_id =
            session_id(&request.session_id).map_err(|_| OperationControlError::Unavailable)?;
        let recovery_request_id =
            request_id(&request.request_id).map_err(|_| OperationControlError::Unavailable)?;
        self.resolutions
            .preflight_authorized(authority_claim, &request)
            .await?;
        let ownership_request_id = recovery_internal_id(
            b"navigator.resolve.ownership.v1",
            recovery_request_id,
            session_id,
        );
        let classification_request_id = recovery_internal_id(
            b"navigator.resolve.classification.v1",
            recovery_request_id,
            session_id,
        );
        let epoch = self
            .reconciler
            .acquire_only(session_id, ownership_request_id)
            .await
            .map_err(|_| OperationControlError::CleanupRequired)?;
        let committed = self
            .resolutions
            .resolve_authorized(epoch, authority_claim, request)
            .await?;
        self.reconciler
            .classify_only(
                session_id,
                RecoveryRunIds {
                    ownership_request_id,
                    classification_request_id,
                },
            )
            .await
            .map_err(|_| OperationControlError::CleanupRequired)?;
        Ok(committed.wire)
    }
}

#[tonic::async_trait]
impl RecoveryController for UnavailableRecoveryController {
    async fn resume_session(
        &self,
        _: RequestId,
        _: SessionId,
    ) -> Result<v1::RecoveryReport, OperationControlError> {
        Err(OperationControlError::Unavailable)
    }

    async fn resolve_uncertainty(
        &self,
        _: UnverifiedRecoveryAuthorityClaim,
        _: v1::ResolveUncertaintyRequest,
    ) -> Result<v1::ResolutionSnapshot, OperationControlError> {
        Err(OperationControlError::Unavailable)
    }
}

#[tonic::async_trait]
pub trait OperationController: Send + Sync {
    async fn start(
        &self,
        permit: AdmissionPermit,
        command: StartOperation,
    ) -> Result<OperationSnapshot, OperationControlError>;

    async fn cancel_subtree(
        &self,
        permit: AdmissionPermit,
        command: CancelSubtree,
    ) -> Result<navigator_store_api::CancelSubtreeOutcome, OperationControlError>;

    async fn cancel_session_until(
        &self,
        permit: AdmissionPermit,
        command: CancelSubtree,
        deadline: tokio::time::Instant,
    ) -> Result<navigator_store_api::CancelSubtreeOutcome, OperationControlError>;

    async fn shutdown_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), OperationControlError>;
}

struct UnavailableOperationController;

#[tonic::async_trait]
impl OperationController for UnavailableOperationController {
    async fn start(
        &self,
        _permit: AdmissionPermit,
        _command: StartOperation,
    ) -> Result<OperationSnapshot, OperationControlError> {
        Err(OperationControlError::Unavailable)
    }

    async fn cancel_subtree(
        &self,
        _permit: AdmissionPermit,
        _command: CancelSubtree,
    ) -> Result<navigator_store_api::CancelSubtreeOutcome, OperationControlError> {
        Err(OperationControlError::Unavailable)
    }

    async fn cancel_session_until(
        &self,
        _permit: AdmissionPermit,
        _command: CancelSubtree,
        _deadline: tokio::time::Instant,
    ) -> Result<navigator_store_api::CancelSubtreeOutcome, OperationControlError> {
        Err(OperationControlError::Unavailable)
    }

    async fn shutdown_until(
        &self,
        _deadline: tokio::time::Instant,
    ) -> Result<(), OperationControlError> {
        Ok(())
    }
}

#[tonic::async_trait]
impl<S, E, F> OperationController for FirstOperationService<S, E, F>
where
    S: OperationPersistence + HierarchyStore,
    E: OperationExecutor,
    F: TransitionContextFactory,
{
    async fn start(
        &self,
        permit: AdmissionPermit,
        command: StartOperation,
    ) -> Result<OperationSnapshot, OperationControlError> {
        let handle = FirstOperationService::start(self, permit, command)
            .await
            .map_err(|error| match error {
                navigator_core::FirstOperationError::Store(error) => {
                    OperationControlError::Store(error)
                }
                navigator_core::FirstOperationError::Service(_)
                | navigator_core::FirstOperationError::WorkerStopped => {
                    OperationControlError::Unavailable
                }
            })?;
        Ok(handle.admitted().value().clone())
    }

    async fn cancel_subtree(
        &self,
        permit: AdmissionPermit,
        command: CancelSubtree,
    ) -> Result<navigator_store_api::CancelSubtreeOutcome, OperationControlError> {
        FirstOperationService::cancel_subtree(self, permit, command)
            .await
            .map_err(|error| match error {
                navigator_core::FirstOperationError::Store(error) => {
                    OperationControlError::Store(error)
                }
                navigator_core::FirstOperationError::Service(_)
                | navigator_core::FirstOperationError::WorkerStopped => {
                    OperationControlError::Unavailable
                }
            })
    }

    async fn cancel_session_until(
        &self,
        permit: AdmissionPermit,
        command: CancelSubtree,
        deadline: tokio::time::Instant,
    ) -> Result<navigator_store_api::CancelSubtreeOutcome, OperationControlError> {
        FirstOperationService::cancel_session_until(self, permit, command, deadline)
            .await
            .map_err(|error| match error {
                navigator_core::FirstOperationError::Store(error) => {
                    OperationControlError::Store(error)
                }
                navigator_core::FirstOperationError::Service(_) => {
                    OperationControlError::Unavailable
                }
                navigator_core::FirstOperationError::WorkerStopped => {
                    OperationControlError::CleanupRequired
                }
            })
    }

    async fn shutdown_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), OperationControlError> {
        FirstOperationService::shutdown_until(self, deadline)
            .await
            .map_err(|_| OperationControlError::Unavailable)
    }
}

type SessionSupervisor<S> = OwnershipSupervisor<S, SystemWallClock, CommandFactory>;

struct LocalSessionAdmissions<S> {
    supervisors: std::sync::Weak<Mutex<HashMap<SessionId, SessionSupervisor<S>>>>,
}

struct NotifyingExistingScheduler<S> {
    store: Arc<S>,
    inner: Arc<dyn crate::ExistingOperationScheduler>,
    wakes: Arc<Mutex<HashMap<SessionId, Arc<Notify>>>>,
}

impl<S> crate::ExistingOperationScheduler for NotifyingExistingScheduler<S>
where
    S: OperationStore + 'static,
{
    fn schedule_with_permit(
        &self,
        permit: AdmissionPermit,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<(), navigator_core::ExecutorError>> + Send + '_,
        >,
    > {
        Box::pin(async move {
            let session_id = self
                .store
                .load_operation(operation_id)
                .await
                .map_err(|_| admission_error())?
                .session_id;
            let result = self
                .inner
                .schedule_with_permit(permit, operation_id, epoch)
                .await;
            if let Some(wake) = self.wakes.lock().await.get(&session_id).cloned() {
                wake.notify_one();
            }
            result
        })
    }

    fn schedule(
        &self,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<(), navigator_core::ExecutorError>> + Send + '_,
        >,
    > {
        Box::pin(async move {
            let session_id = self
                .store
                .load_operation(operation_id)
                .await
                .map_err(|_| admission_error())?
                .session_id;
            let result = self.inner.schedule(operation_id, epoch).await;
            if let Some(wake) = self.wakes.lock().await.get(&session_id).cloned() {
                wake.notify_one();
            }
            result
        })
    }
}

impl<S> crate::SessionAdmissionProvider for LocalSessionAdmissions<S>
where
    S: OperationStore + 'static,
{
    fn admit_current(
        &self,
        session_id: SessionId,
        expected_epoch: FencingEpoch,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<AdmissionPermit, navigator_core::ExecutorError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let supervisors = self.supervisors.upgrade().ok_or_else(admission_error)?;
            let locked = supervisors.lock().await;
            let supervisor = locked.get(&session_id).ok_or_else(admission_error)?;
            let OwnershipStatus::Active { epoch, .. } = supervisor.status() else {
                return Err(admission_error());
            };
            if epoch != expected_epoch {
                return Err(admission_error());
            }
            let permit = supervisor
                .admission()
                .admit()
                .map_err(|_| admission_error())?;
            permit.check().map_err(|_| admission_error())?;
            Ok(permit)
        })
    }
}

fn admission_error() -> navigator_core::ExecutorError {
    navigator_core::ExecutorError {
        message: "current Session admission is unavailable".into(),
    }
}

impl<S> Clone for LocalNavigator<S> {
    fn clone(&self) -> Self {
        Self {
            store: Arc::clone(&self.store),
            host_id: self.host_id,
            lease_duration: self.lease_duration,
            negotiations: Arc::clone(&self.negotiations),
            supervisors: Arc::clone(&self.supervisors),
            close_locks: Arc::clone(&self.close_locks),
            stopping: Arc::clone(&self.stopping),
            subscriptions: Arc::clone(&self.subscriptions),
            subscription_sessions: Arc::clone(&self.subscription_sessions),
            limits: Arc::clone(&self.limits),
            cleanup_failed: Arc::clone(&self.cleanup_failed),
            operations: Arc::clone(&self.operations),
            recovery: Arc::clone(&self.recovery),
            recovery_configured: self.recovery_configured,
            runtime_configuration_identity: self.runtime_configuration_identity,
            mailbox_dispatcher: self.mailbox_dispatcher.clone(),
            mailbox_pumps: Arc::clone(&self.mailbox_pumps),
            mailbox_wakes: Arc::clone(&self.mailbox_wakes),
            mailbox_pump_stopped: Arc::clone(&self.mailbox_pump_stopped),
            ownership_shutdown_millis: Arc::clone(&self.ownership_shutdown_millis),
            session_close_timeout_millis: Arc::clone(&self.session_close_timeout_millis),
            background_tasks: self.background_tasks.clone(),
            artifacts: Arc::clone(&self.artifacts),
            artifacts_configured: self.artifacts_configured,
            tools: self.tools.clone(),
            approvals: self.approvals.clone(),
            projections: self.projections.clone(),
        }
    }
}

impl<S> LocalNavigator<S> {
    #[must_use]
    pub fn new(store: Arc<S>, host_id: HostId, lease_duration: LeaseDuration) -> Self {
        Self::new_with_limits(store, host_id, lease_duration, LimitProfile::default())
    }

    #[must_use]
    pub fn new_with_limits(
        store: Arc<S>,
        host_id: HostId,
        lease_duration: LeaseDuration,
        limits: LimitProfile,
    ) -> Self {
        let subscription_limit =
            usize::try_from(limits.get(CapacityResource::Subscriptions).global)
                .expect("hard subscription ceiling fits usize");
        Self {
            store,
            host_id,
            lease_duration,
            negotiations: Arc::new(RwLock::new(HashMap::new())),
            supervisors: Arc::new(Mutex::new(HashMap::new())),
            close_locks: Arc::new(Mutex::new(HashMap::new())),
            stopping: Arc::new(AtomicBool::new(false)),
            subscriptions: Arc::new(Semaphore::new(subscription_limit)),
            subscription_sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
            limits: Arc::new(limits),
            cleanup_failed: Arc::new(AtomicBool::new(false)),
            operations: Arc::new(UnavailableOperationController),
            recovery: Arc::new(UnavailableRecoveryController),
            recovery_configured: false,
            runtime_configuration_identity: [0; 32],
            mailbox_dispatcher: None,
            mailbox_pumps: Arc::new(Mutex::new(HashMap::new())),
            mailbox_wakes: Arc::new(Mutex::new(HashMap::new())),
            mailbox_pump_stopped: Arc::new(Notify::new()),
            ownership_shutdown_millis: Arc::new(AtomicU64::new(1_000)),
            session_close_timeout_millis: Arc::new(AtomicU64::new(1_000)),
            background_tasks: BackgroundTaskRegistry::new(),
            artifacts: Arc::new(UnavailableArtifactController),
            artifacts_configured: false,
            tools: None,
            approvals: None,
            projections: None,
        }
    }

    #[must_use]
    pub fn with_operation_controller(mut self, operations: Arc<dyn OperationController>) -> Self {
        self.operations = operations;
        self
    }

    #[must_use]
    pub fn with_recovery_controller(mut self, recovery: Arc<dyn RecoveryController>) -> Self {
        self.recovery = recovery;
        self.recovery_configured = true;
        self
    }

    #[must_use]
    pub fn with_artifact_controller(mut self, artifacts: Arc<dyn ArtifactController>) -> Self {
        self.artifacts = artifacts;
        self.artifacts_configured = true;
        self
    }

    #[must_use]
    pub fn with_tool_controller(mut self, tools: Arc<dyn crate::ToolBrokerControl>) -> Self {
        self.tools = Some(tools);
        self
    }

    #[cfg(test)]
    pub(crate) fn tool_test_context(
        &self,
    ) -> (
        Arc<RwLock<HashMap<Uuid, NegotiationEntry>>>,
        BackgroundTaskRegistry,
    ) {
        (
            Arc::clone(&self.negotiations),
            self.background_tasks.clone(),
        )
    }

    #[must_use]
    pub fn with_runtime_configuration_identity(mut self, identity: [u8; 32]) -> Self {
        self.runtime_configuration_identity = identity;
        self
    }

    fn configuration_identity(&self) -> [u8; 32] {
        let mut capabilities = CAPABILITIES.to_vec();
        if self.recovery_configured {
            capabilities.push("recovery.resolution.v1");
        }
        if self.artifacts_configured {
            capabilities.push(CAPABILITY_ARTIFACTS_V1);
        }
        if self.tools.is_some() {
            capabilities.push(CAPABILITY_CONSUMER_TOOLS_V1);
        }
        if self.approvals.is_some() {
            capabilities.push(CAPABILITY_APPROVALS_V1);
        }
        if self.projections.is_some() {
            capabilities.push(CAPABILITY_OPERATIONAL_PROJECTIONS_V1);
        }
        capabilities.sort_unstable();
        let mut digest = Sha256::new();
        digest.update(b"navigator.consumer.configuration.v1\0");
        digest.update(CURRENT_MAJOR.to_be_bytes());
        digest.update(CURRENT_MINOR.to_be_bytes());
        for capability in capabilities {
            digest.update(capability.len().to_be_bytes());
            digest.update(capability.as_bytes());
        }
        digest.update(self.runtime_configuration_identity);
        digest.finalize().into()
    }
}

impl LocalNavigator<navigator_store_sqlite::SqliteStore> {
    #[must_use]
    pub fn with_operational_projections(mut self) -> Self {
        self.projections = Some(Arc::new(StoreProjectionController(Arc::clone(&self.store))));
        self
    }

    pub fn with_configured_runtime(
        mut self,
        components: crate::ConfiguredRuntimeComponents,
    ) -> Result<Self, navigator_core::ExecutorError> {
        self.runtime_configuration_identity = components.configuration_identity;
        let admissions: Arc<dyn crate::SessionAdmissionProvider> =
            Arc::new(LocalSessionAdmissions {
                supervisors: Arc::downgrade(&self.supervisors),
            });
        let notifying: Arc<dyn crate::ExistingOperationScheduler> =
            Arc::new(NotifyingExistingScheduler {
                store: Arc::clone(&self.store),
                inner: components.permit_scheduler,
                wakes: Arc::clone(&self.mailbox_wakes),
            });
        let scheduler: Arc<dyn crate::ExistingOperationScheduler> =
            Arc::new(crate::SessionScopedExistingScheduler::new(
                Arc::clone(&self.store),
                admissions,
                notifying,
            ));
        let sink = Arc::new(
            crate::LocalHierarchySink::new(Arc::clone(&self.store), self.host_id)
                .with_scheduler(scheduler),
        );
        components.hierarchy_installer.install(sink)?;
        components
            .approval_installer
            .install_approval_sink(Arc::new(crate::LocalApprovalSink::new(Arc::clone(
                &self.store,
            ))))?;
        let broker = Arc::new(crate::LocalToolBroker::new(
            Arc::clone(&self.store),
            self.host_id,
            Duration::from_millis(self.lease_duration.as_millis()),
            Arc::clone(&self.negotiations),
            self.background_tasks.clone(),
        ));
        let tool_sink: Arc<dyn crate::ToolCommandSink> = broker.clone();
        components.tool_installer.install_tool_sink(tool_sink)?;
        self.tools = Some(broker);
        self.approvals = Some(Arc::new(StoreApprovalController {
            store: Arc::clone(&self.store),
        }));
        self.projections = Some(Arc::new(StoreProjectionController(Arc::clone(&self.store))));
        self.operations = components.controller;
        self.mailbox_dispatcher = Some(components.mailbox_dispatcher);
        Ok(self)
    }
}

impl<S> LocalNavigator<S>
where
    S: navigator_store_api::RecoveryStore
        + AuthorityStore
        + navigator_store_api::MailboxStore
        + EffectJournalStore
        + OperationStore
        + 'static,
{
    #[must_use]
    pub fn with_recovery_runtime(
        mut self,
        inspector: Arc<dyn crate::RecoveryInstanceInspector>,
        scheduler: Arc<dyn crate::ExistingOperationScheduler>,
    ) -> Self {
        let ownership: Arc<dyn crate::RecoveryOwnershipInstaller> = Arc::new(self.clone());
        let backend = crate::StoreRecoveryBackend::new(
            Arc::clone(&self.store),
            self.host_id,
            ownership,
            inspector,
            scheduler,
        );
        let resolutions = Arc::new(StoreAuthorizedResolution::new(
            Arc::clone(&self.store),
            self.host_id,
        ));
        self.recovery = Arc::new(LocalRecoveryController::new(backend, resolutions));
        self.recovery_configured = true;
        self
    }
}

impl<S> crate::RecoveryOwnershipInstaller for LocalNavigator<S>
where
    S: OperationStore + 'static,
{
    fn acquire_and_install(
        &self,
        session_id: SessionId,
        recovery_request_id: RequestId,
    ) -> crate::recovery_backend::InstalledOwnershipFuture<'_> {
        Box::pin(async move {
            let lease = self
                .store
                .acquire_ownership(AcquireOwnership::new(
                    RequestContext::new(recovery_request_id, self.host_id),
                    session_id,
                    self.lease_duration,
                ))
                .await?
                .value()
                .clone();
            if lease.owner() != self.host_id || lease.session_id() != session_id {
                return Err(StoreError::Corrupt);
            }
            let epoch = lease.epoch();
            let mut supervisors = self.supervisors.lock().await;
            if let Some(existing) = supervisors.get(&session_id)
                && matches!(existing.status(), OwnershipStatus::Active { epoch: active, .. } if active == epoch)
            {
                return existing
                    .admission()
                    .admit()
                    .map(|permit| (epoch, permit))
                    .map_err(|_| StoreError::Invalid);
            }
            let supervisor = self.supervisor(lease).map_err(|_| StoreError::Invalid)?;
            let permit = supervisor
                .admission()
                .admit()
                .map_err(|_| StoreError::Invalid)?;
            let replaced = supervisors.insert(session_id, supervisor);
            drop(supervisors);
            if let Some(previous) = replaced {
                // Its epoch was fenced by the acquisition above. Stop its worker
                // without releasing the newly installed ownership.
                let _ = previous.shutdown_after_ownership_cleared().await;
            }
            self.start_mailbox_pump(session_id, epoch).await;
            Ok((epoch, permit))
        })
    }
}

trait HasMetadata {
    fn metadata(&self) -> Option<&v1::RequestMetadata>;
    fn required_capability() -> &'static str;
}
macro_rules! has_metadata { ($($ty:ty => $capability:literal),+) => {$(
    impl HasMetadata for $ty {
        fn metadata(&self) -> Option<&v1::RequestMetadata> { self.metadata.as_ref() }
        fn required_capability() -> &'static str { $capability }
    }
)+}; }
has_metadata!(
    v1::OpenSessionRequest => "session.lifecycle.v1",
    v1::SnapshotRequest => "session.lifecycle.v1",
    v1::CloseSessionRequest => "session.lifecycle.v1",
    v1::SubscribeEventsRequest => "events.replay.v1",
    v1::ReadEventsRequest => "events.replay.v1",
    v1::StartOperationRequest => "operation.execution.v1",
    v1::OperationSnapshotRequest => "operation.execution.v1",
    v1::ParticipantSnapshotRequest => "resource.snapshots.v1",
    v1::MessageSnapshotRequest => "resource.snapshots.v1",
    v1::CancelSubtreeRequest => "operation.cancellation.v1",
    v1::ResumeSessionRequest => "recovery.resolution.v1",
    v1::ResolveUncertaintyRequest => "recovery.resolution.v1",
    v1::RegisterToolRequest => "consumer.tools.v1",
    v1::ReadArtifactRequest => "artifacts.v1",
    v1::ArtifactSnapshotRequest => "artifacts.v1",
    v1::DeleteArtifactRequest => "artifacts.v1",
    v1::ApprovalSnapshotRequest => "approvals.v1",
    v1::ApproveApprovalRequest => "approvals.v1",
    v1::DenyApprovalRequest => "approvals.v1",
    v1::RevokeApprovalGrantRequest => "approvals.v1"
    ,v1::ReadProjectionRequest => "operational.projections.v1"
);

impl<S: OperationStore + 'static> LocalNavigator<S> {
    fn validate<T: ValidateRequest + HasMetadata>(&self, value: &T) -> Result<(), Failure> {
        value.validate_request().map_err(validation_failure)?;
        if self.stopping.load(Ordering::Acquire) {
            return Err(failure(
                FailureCode::Unavailable,
                "daemon is shutting down",
                RetryClass::Safe,
            ));
        }
        let metadata = value
            .metadata()
            .ok_or_else(|| validation_failure(ValidationError::MissingField))?;
        self.validate_selected_metadata(metadata, T::required_capability())
    }

    fn validate_selected_metadata(
        &self,
        metadata: &v1::RequestMetadata,
        required_capability: &str,
    ) -> Result<(), Failure> {
        let id = Uuid::from_slice(&metadata.negotiation_id)
            .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
        let negotiated = self
            .negotiations
            .read()
            .expect("negotiation registry poisoned")
            .get(&id)
            .map(|entry| entry.capabilities.clone())
            .ok_or_else(|| {
                failure(
                    FailureCode::UnsupportedVersion,
                    "unknown negotiation",
                    RetryClass::Safe,
                )
            })?;
        validate_negotiated_capabilities(metadata, &negotiated).map_err(validation_failure)?;
        if metadata
            .capabilities
            .iter()
            .any(|value| value == required_capability)
        {
            Ok(())
        } else {
            Err(failure(
                FailureCode::UnsupportedCapability,
                "required capability was not selected",
                RetryClass::Never,
            ))
        }
    }

    async fn bind_negotiated_consumer(
        &self,
        metadata: &v1::RequestMetadata,
        consumer_key: &ConsumerKey,
    ) -> Result<(), Failure>
    where
        S: navigator_store_api::CapacityStore,
    {
        let id = Uuid::from_slice(&metadata.negotiation_id)
            .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
        let reservation_id = {
            let mut registry = self
                .negotiations
                .write()
                .expect("negotiation registry poisoned");
            let entry = registry.get_mut(&id).ok_or_else(|| {
                failure(
                    FailureCode::UnsupportedVersion,
                    "unknown negotiation",
                    RetryClass::Safe,
                )
            })?;
            match entry.consumer_key.as_ref() {
                Some(existing) if existing != consumer_key => {
                    return Err(failure(
                        FailureCode::Authentication,
                        "negotiation is bound to another Consumer",
                        RetryClass::Never,
                    ));
                }
                Some(_) => None,
                None => {
                    entry.consumer_key = Some(consumer_key.clone());
                    entry.reservation_id.take()
                }
            }
        };
        if let Some(reservation_id) = reservation_id {
            self.store
                .release_global_capacity(reservation_id)
                .await
                .map_err(|_| {
                    failure(
                        FailureCode::Unavailable,
                        "negotiation capacity release failed",
                        RetryClass::Safe,
                    )
                })?;
        }
        Ok(())
    }

    async fn trusted_approval_authority<T: HasMetadata>(
        &self,
        request: &Request<T>,
        session_id: SessionId,
    ) -> Result<TrustedConsumerAuthority, Failure> {
        let marker = request
            .extensions()
            .get::<AuthenticatedTrustedConsumer>()
            .copied()
            .ok_or_else(|| {
                failure(
                    FailureCode::Authentication,
                    "trusted Consumer authentication is required",
                    RetryClass::Never,
                )
            })?;
        let metadata = request
            .get_ref()
            .metadata()
            .ok_or_else(|| validation_failure(ValidationError::MissingField))?;
        self.validate_selected_metadata(metadata, CAPABILITY_APPROVALS_V1)?;
        let negotiation_id = Uuid::from_slice(&metadata.negotiation_id)
            .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
        let bound = self
            .negotiations
            .read()
            .expect("negotiation registry poisoned")
            .get(&negotiation_id)
            .and_then(|entry| entry.consumer_key.clone())
            .ok_or_else(|| {
                failure(
                    FailureCode::Authentication,
                    "negotiation is not bound to a Consumer",
                    RetryClass::Never,
                )
            })?;
        let session = self
            .store
            .load_session(session_id)
            .await
            .map_err(|error| store_failure(&error))?;
        if session.consumer_key() != &bound {
            return Err(failure(
                FailureCode::Authorization,
                "Consumer is not bound to this Session",
                RetryClass::Never,
            ));
        }
        Ok(TrustedConsumerAuthority(marker))
    }

    async fn bound_session_consumer(
        &self,
        metadata: &v1::RequestMetadata,
        session_id: SessionId,
    ) -> Result<ConsumerKey, Failure> {
        let negotiation_id = Uuid::from_slice(&metadata.negotiation_id)
            .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
        let consumer = self
            .negotiations
            .read()
            .expect("negotiation registry poisoned")
            .get(&negotiation_id)
            .and_then(|entry| entry.consumer_key.clone())
            .ok_or_else(|| {
                failure(
                    FailureCode::Authentication,
                    "negotiation is not bound to a Consumer",
                    RetryClass::Never,
                )
            })?;
        let session_matches = self
            .store
            .load_session(session_id)
            .await
            .is_ok_and(|snapshot| snapshot.consumer_key() == &consumer);
        if !session_matches {
            return Err(failure(
                FailureCode::Authentication,
                "Consumer does not own Session",
                RetryClass::Never,
            ));
        }
        Ok(consumer)
    }

    async fn release_all(&self) -> Result<(), LocalError> {
        let supervisors = self
            .supervisors
            .lock()
            .await
            .drain()
            .map(|(_, supervisor)| supervisor)
            .collect::<Vec<_>>();
        let mut tasks = tokio::task::JoinSet::new();
        for supervisor in supervisors {
            tasks.spawn(async move {
                crate::fault_matrix::external_fault_at("shutdown.external.before_call");
                let outcome = supervisor.shutdown().await;
                crate::fault_matrix::external_fault_at("shutdown.external.after_call");
                outcome
            });
        }
        let mut complete = true;
        while let Some(result) = tasks.join_next().await {
            crate::fault_matrix::external_fault_at("shutdown.external.before_identity_proof");
            complete &= result.is_ok_and(|outcome| {
                outcome.task_terminated() && outcome.release() == ReleaseOutcome::Released
            });
            crate::fault_matrix::external_fault_at("shutdown.external.after_identity_proof");
        }
        if complete {
            Ok(())
        } else {
            Err(LocalError::CleanupRequired)
        }
    }

    async fn wake_all_mailbox_pumps(&self) {
        for wake in self.mailbox_wakes.lock().await.values() {
            wake.notify_one();
        }
    }

    fn supervisor(&self, lease: OwnershipLease) -> Result<SessionSupervisor<S>, Failure> {
        let renewal_millis = (self.lease_duration.as_millis() / 3).max(1);
        let factory = Arc::new(CommandFactory {
            host_id: self.host_id,
        });
        OwnershipSupervisor::start(
            Arc::clone(&self.store),
            Arc::new(SystemWallClock),
            Arc::clone(&factory),
            factory,
            lease,
            OwnershipConfig {
                renewal_period: Duration::from_millis(renewal_millis),
                lease_duration: self.lease_duration,
                shutdown_timeout: Duration::from_millis(
                    self.ownership_shutdown_millis.load(Ordering::Acquire),
                ),
            },
        )
        .map_err(|_| {
            failure(
                FailureCode::Internal,
                "ownership supervision failed",
                RetryClass::Never,
            )
        })
    }

    async fn has_active_supervisor(&self, session_id: SessionId) -> bool {
        let mut supervisors = self.supervisors.lock().await;
        let active = supervisors.get(&session_id).is_some_and(|supervisor| {
            matches!(supervisor.status(), OwnershipStatus::Active { .. })
                && supervisor.admission().is_open()
        });
        if !active {
            supervisors.remove(&session_id);
        }
        active
    }

    async fn install_reconciled_supervisor(&self, session_id: SessionId) -> Result<(), Failure> {
        let ownership = self
            .store
            .read_ownership(session_id)
            .await
            .map_err(|error| store_failure(&error))?;
        let OwnershipSnapshot::Owned {
            host_id,
            epoch,
            expires_at,
        } = ownership
        else {
            return Err(failure(
                FailureCode::StaleOwnership,
                "reconciliation did not retain ownership",
                RetryClass::AfterReconciliation,
            ));
        };
        if host_id != self.host_id {
            return Err(failure(
                FailureCode::StaleOwnership,
                "reconciliation ownership belongs to another host",
                RetryClass::AfterReconciliation,
            ));
        }
        let supervisor = self.supervisor(OwnershipLease::restored(
            session_id, host_id, epoch, expires_at,
        ))?;
        {
            let mut supervisors = self.supervisors.lock().await;
            if let Some(existing) = supervisors.get(&session_id)
                && matches!(existing.status(), OwnershipStatus::Active { epoch: current, .. } if current == epoch)
            {
                // Exact replay: keep the already-running renewal worker.
                drop(supervisor);
            } else {
                if supervisors.get(&session_id).is_some_and(|existing| {
                    matches!(existing.status(), OwnershipStatus::Active { .. })
                }) {
                    return Err(stale_ownership_failure());
                }
                supervisors.insert(session_id, supervisor);
            }
        }
        self.start_mailbox_pump(session_id, epoch).await;
        Ok(())
    }

    async fn reconciled_open_snapshot(
        &self,
        session_id: SessionId,
        template: &Template,
    ) -> Result<v1::SessionSnapshot, Failure>
    where
        S: AuthorityStore,
    {
        self.install_reconciled_supervisor(session_id).await?;
        let (_permit, epoch) = self.active_operation_context(session_id).await?;
        let root = self.ensure_root(session_id, epoch, template).await?;
        self.ensure_root_authority(session_id, root, epoch, template)
            .await?;
        self.start_mailbox_pump(session_id, epoch).await;
        let snapshot = self
            .store
            .load_session(session_id)
            .await
            .map_err(|error| store_failure(&error))?;
        Ok(snapshot_wire(&snapshot, root))
    }

    async fn start_mailbox_pump(&self, session_id: SessionId, epoch: FencingEpoch) {
        let Some(dispatcher) = self.mailbox_dispatcher.clone() else {
            return;
        };
        {
            let mut pumps = self.mailbox_pumps.lock().await;
            if pumps.get(&session_id) == Some(&epoch) {
                return;
            }
            pumps.insert(session_id, epoch);
        }
        let wake = {
            let mut wakes = self.mailbox_wakes.lock().await;
            Arc::clone(
                wakes
                    .entry(session_id)
                    .or_insert_with(|| Arc::new(Notify::new())),
            )
        };
        let admissions: Arc<dyn crate::SessionAdmissionProvider> =
            Arc::new(LocalSessionAdmissions {
                supervisors: Arc::downgrade(&self.supervisors),
            });
        let pumps = Arc::clone(&self.mailbox_pumps);
        let wakes = Arc::clone(&self.mailbox_wakes);
        let task_wake = Arc::clone(&wake);
        let failed_pumps = Arc::clone(&self.mailbox_pumps);
        let failed_wakes = Arc::clone(&self.mailbox_wakes);
        let failed_wake = Arc::clone(&wake);
        let stopped = Arc::clone(&self.mailbox_pump_stopped);
        let spawned = self
            .background_tasks
            .spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(1));
                ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {}
                        () = wake.notified() => {}
                    }
                    let Ok(permit) = admissions.admit_current(session_id, epoch).await else {
                        break;
                    };
                    // Discovery and delivery are both revalidated atomically by
                    // the Store. A process may still be starting, so a failed
                    // bounded sweep is retried on the next delayed tick; only
                    // loss of the epoch/admission above terminates this pump.
                    let _ = dispatcher
                        .sweep_with_permit(permit, session_id, epoch)
                        .await;
                }
                let mut active = pumps.lock().await;
                if active.get(&session_id) == Some(&epoch) {
                    active.remove(&session_id);
                    drop(active);
                    let mut registered = wakes.lock().await;
                    if registered
                        .get(&session_id)
                        .is_some_and(|value| Arc::ptr_eq(value, &task_wake))
                    {
                        registered.remove(&session_id);
                    }
                }
                stopped.notify_waiters();
            })
            .await;
        if spawned.is_err() {
            let mut active = failed_pumps.lock().await;
            if active.get(&session_id) == Some(&epoch) {
                active.remove(&session_id);
                drop(active);
                let mut registered = failed_wakes.lock().await;
                if registered
                    .get(&session_id)
                    .is_some_and(|value| Arc::ptr_eq(value, &failed_wake))
                {
                    registered.remove(&session_id);
                }
            }
        }
    }

    async fn release_lease(&self, lease: &OwnershipLease) {
        let factory = CommandFactory {
            host_id: self.host_id,
        };
        if let Ok(command) = ReleaseCommandFactory::create(&factory, lease) {
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                self.store.release_ownership(command),
            )
            .await;
        }
    }

    async fn replayed_close(
        &self,
        request_id: RequestId,
        session_id: SessionId,
    ) -> Result<Option<SessionSnapshot>, Failure> {
        let Some(stored) = self
            .store
            .read_request(request_id)
            .await
            .map_err(|error| store_failure(&error))?
        else {
            return Ok(None);
        };
        if stored.caller() != self.host_id || stored.action() != StoreAction::CloseSession {
            return Err(failure(
                FailureCode::Conflict,
                "request identity conflicts with durable request",
                RetryClass::Never,
            ));
        }
        match stored.outcome() {
            StoredRequestOutcome::Succeeded {
                result: StoredResult::Session(snapshot),
                ..
            } if snapshot.id() == session_id && snapshot.status() == SessionStatus::Closed => {
                Ok(Some(snapshot.clone()))
            }
            StoredRequestOutcome::Failed(error)
                if error_session_id(error).is_some_and(|id| id == session_id) =>
            {
                Err(store_failure(error))
            }
            _ => Err(failure(
                FailureCode::Conflict,
                "request identity conflicts with Session",
                RetryClass::Never,
            )),
        }
    }

    async fn close_owned(
        &self,
        request_id: RequestId,
        session_id: SessionId,
    ) -> close_session_response::Outcome
    where
        S: HierarchyStore + InstanceStore,
    {
        let deadline = tokio::time::Instant::now()
            + Duration::from_millis(self.session_close_timeout_millis.load(Ordering::Acquire));
        let (root_id, replayed) = match self
            .initial_close_context(request_id, session_id, deadline)
            .await
        {
            Ok(context) => context,
            Err(error) => return close_session_response::Outcome::Failure(error),
        };
        if let Some(snapshot) = replayed {
            return close_session_response::Outcome::Snapshot(snapshot_wire(&snapshot, root_id));
        }
        // Serialize only this Session's close lifecycle.  The supervisor stays
        // discoverable while cancellation, process cleanup, and the durable
        // Close are awaited, so cancellation of the RPC cannot strand a valid
        // lease outside the registry.  The global maps are never held across
        // an external await.
        let (_closing, permit, epoch) =
            match tokio::time::timeout_at(deadline, self.begin_close(session_id)).await {
                Ok(Ok(context)) => context,
                Ok(Err(error)) => return close_session_response::Outcome::Failure(error),
                Err(_) => return close_session_response::Outcome::Failure(close_deadline_failure()),
            };
        match tokio::time::timeout_at(deadline, self.replayed_close(request_id, session_id)).await {
            Ok(Ok(Some(snapshot))) => {
                return close_session_response::Outcome::Snapshot(snapshot_wire(
                    &snapshot, root_id,
                ));
            }
            Ok(Err(error)) => return close_session_response::Outcome::Failure(error),
            Ok(Ok(None)) => {}
            Err(_) => return close_session_response::Outcome::Failure(close_deadline_failure()),
        }
        let cancelled = tokio::time::timeout_at(
            deadline,
            self.cancel_before_close(
                permit.clone(),
                request_id,
                session_id,
                root_id,
                epoch,
                deadline,
            ),
        )
        .await;
        if !matches!(cancelled, Ok(true)) {
            return close_session_response::Outcome::Failure(failure(
                FailureCode::CleanupRequired,
                "Session cancellation did not reach a verified terminal state",
                RetryClass::AfterReconciliation,
            ));
        }
        if tokio::time::Instant::now() >= deadline {
            return close_session_response::Outcome::Failure(close_deadline_failure());
        }
        let unresolved = tokio::time::timeout_at(
            deadline,
            self.store.session_has_unresolved_launches(session_id),
        )
        .await;
        if !matches!(unresolved, Ok(Ok(false))) {
            return close_session_response::Outcome::Failure(failure(
                FailureCode::CleanupRequired,
                "Session process cleanup is not durably verified",
                RetryClass::AfterReconciliation,
            ));
        }
        let result = tokio::time::timeout_at(
            deadline,
            self.store.close_session(CloseSession::new(
                RequestContext::new(request_id, self.host_id),
                session_id,
                epoch,
            )),
        )
        .await;
        drop(permit);
        match result {
            Ok(Ok(value)) => {
                let supervisor = {
                    let mut supervisors = self.supervisors.lock().await;
                    let exact = supervisors.get(&session_id).is_some_and(|supervisor| {
                        matches!(supervisor.status(), OwnershipStatus::Active { epoch: current, .. } if current == epoch)
                    });
                    exact.then(|| supervisors.remove(&session_id)).flatten()
                };
                if let Some(supervisor) = supervisor {
                    let _ = supervisor.shutdown_after_ownership_cleared().await;
                }
                close_session_response::Outcome::Snapshot(snapshot_wire(value.value(), root_id))
            }
            Ok(Err(error)) => close_session_response::Outcome::Failure(store_failure(&error)),
            Err(_) => close_session_response::Outcome::Failure(close_deadline_failure()),
        }
    }

    async fn initial_close_context(
        &self,
        request_id: RequestId,
        session_id: SessionId,
        deadline: tokio::time::Instant,
    ) -> Result<(ParticipantId, Option<SessionSnapshot>), Failure> {
        let root = tokio::time::timeout_at(deadline, self.store.load_root_participant(session_id))
            .await
            .map_err(|_| close_deadline_failure())?
            .map_err(|error| store_failure(&error))?;
        let replayed =
            tokio::time::timeout_at(deadline, self.replayed_close(request_id, session_id))
                .await
                .map_err(|_| close_deadline_failure())??;
        Ok((root.participant_id, replayed))
    }

    async fn serialize_close(&self, session_id: SessionId) -> tokio::sync::OwnedMutexGuard<()> {
        let close_lock = {
            let mut locks = self.close_locks.lock().await;
            locks.retain(|_, lock| lock.strong_count() != 0);
            if let Some(lock) = locks.get(&session_id).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(Mutex::new(()));
                locks.insert(session_id, Arc::downgrade(&lock));
                lock
            }
        };
        close_lock.lock_owned().await
    }

    async fn begin_close(
        &self,
        session_id: SessionId,
    ) -> Result<
        (
            tokio::sync::OwnedMutexGuard<()>,
            AdmissionPermit,
            FencingEpoch,
        ),
        Failure,
    > {
        let guard = self.serialize_close(session_id).await;
        let (permit, epoch) = self.close_permit(session_id).await?;
        Ok((guard, permit, epoch))
    }

    async fn close_permit(
        &self,
        session_id: SessionId,
    ) -> Result<(AdmissionPermit, FencingEpoch), Failure> {
        let (status, permit) = {
            let supervisors = self.supervisors.lock().await;
            let Some(supervisor) = supervisors.get(&session_id) else {
                return Err(stale_ownership_failure());
            };
            (supervisor.status(), supervisor.admission().admit())
        };
        match (permit, status) {
            (Ok(permit), OwnershipStatus::Active { epoch, .. }) if permit.check().is_ok() => {
                Ok((permit, epoch))
            }
            _ => Err(stale_ownership_failure()),
        }
    }

    async fn cancel_before_close(
        &self,
        permit: AdmissionPermit,
        request_id: RequestId,
        session_id: SessionId,
        root_id: ParticipantId,
        epoch: navigator_domain::FencingEpoch,
        deadline: tokio::time::Instant,
    ) -> bool
    where
        S: HierarchyStore + InstanceStore,
    {
        let cancel_request_id = RequestId::from_uuid(derived_uuid(
            b"navigator.close.cancel-session.v1",
            &[
                request_id.as_uuid().as_bytes(),
                session_id.as_uuid().as_bytes(),
            ],
        ))
        .expect("derived cancellation request identity is non-nil");
        let command = CancelSubtree {
            context: RequestContext::new(cancel_request_id, self.host_id),
            session_id,
            epoch,
            root_participant_id: root_id,
        };
        let prior = self
            .store
            .inspect_subtree_cancellation(session_id, root_id)
            .await;
        let prior_launches = self.store.session_has_unresolved_launches(session_id).await;
        if durable_cancellation_is_confirmed(&prior, &prior_launches) {
            return true;
        }
        match self
            .operations
            .cancel_session_until(permit, command.clone(), deadline)
            .await
        {
            Ok(outcome) => cancellation_is_confirmed(&outcome),
            Err(
                OperationControlError::Unavailable
                | OperationControlError::Store(_)
                | OperationControlError::CleanupRequired,
            ) => {
                // A prior explicit cancellation may already have completed the
                // driver lifecycle.  In that case a fresh close-scoped request
                // cannot necessarily contact the now-absent driver.  Accept
                // only the durable proof left behind by that cancellation:
                // every operation has confirmed cleanup and every launch is
                // durably stopped.  Either missing proof remains fail-closed.
                let outcome = self
                    .store
                    .inspect_subtree_cancellation(session_id, root_id)
                    .await;
                let unresolved = self.store.session_has_unresolved_launches(session_id).await;
                durable_cancellation_is_confirmed(&outcome, &unresolved)
            }
        }
    }
}

impl<S> crate::SessionAdmissionProvider for LocalNavigator<S>
where
    S: OperationStore + 'static,
{
    fn admit_current(
        &self,
        session_id: SessionId,
        expected_epoch: FencingEpoch,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<AdmissionPermit, navigator_core::ExecutorError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            let (permit, current_epoch) =
                self.active_operation_context(session_id)
                    .await
                    .map_err(|_| navigator_core::ExecutorError {
                        message: "current Session admission is unavailable".into(),
                    })?;
            if current_epoch != expected_epoch {
                return Err(navigator_core::ExecutorError {
                    message: "stale Session ownership epoch".into(),
                });
            }
            permit.check().map_err(|_| navigator_core::ExecutorError {
                message: "Session admission is closed".into(),
            })?;
            Ok(permit)
        })
    }
}

fn cancellation_is_confirmed(outcome: &navigator_store_api::CancelSubtreeOutcome) -> bool {
    outcome
        .records
        .iter()
        .all(|record| record.operation.state.is_terminal() && record.cleanup_confirmed())
}

fn durable_cancellation_is_confirmed(
    outcome: &Result<navigator_store_api::CancelSubtreeOutcome, StoreError>,
    unresolved_launches: &Result<bool, StoreError>,
) -> bool {
    matches!((outcome, unresolved_launches), (Ok(outcome), Ok(false)) if cancellation_is_confirmed(outcome))
}

fn close_deadline_failure() -> Failure {
    failure(
        FailureCode::CleanupRequired,
        "Session close deadline elapsed before durable Close",
        RetryClass::AfterReconciliation,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResetOwnershipPath {
    RestoreLocal,
    Recover,
}

fn reset_ownership_path(ownership: &OwnershipSnapshot, local_host: HostId) -> ResetOwnershipPath {
    match ownership {
        OwnershipSnapshot::Owned { host_id, .. } if *host_id == local_host => {
            ResetOwnershipPath::RestoreLocal
        }
        OwnershipSnapshot::Unowned | OwnershipSnapshot::Owned { .. } => ResetOwnershipPath::Recover,
    }
}

impl<S: OperationStore + 'static> LocalNavigator<S> {
    async fn ensure_root(
        &self,
        session_id: SessionId,
        epoch: navigator_domain::FencingEpoch,
        template: &Template,
    ) -> Result<ParticipantId, Failure> {
        match self.store.load_root_participant(session_id).await {
            Ok(root)
                if root.template_id == template.template_id()
                    && root.template_compatibility == template.compatibility() =>
            {
                return Ok(root.participant_id);
            }
            Ok(_) => {
                return Err(failure(
                    FailureCode::Conflict,
                    "Session root Template conflicts with the request",
                    RetryClass::Never,
                ));
            }
            Err(StoreError::RootParticipantNotFound {
                session_id: missing,
            }) if missing == session_id => {}
            Err(error) => return Err(store_failure(&error)),
        }
        let participant_id = ParticipantId::from_uuid(derived_uuid(
            b"navigator.root-participant.v1",
            &[
                session_id.as_uuid().as_bytes(),
                template.template_id().as_uuid().as_bytes(),
            ],
        ))
        .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
        let create_request_id = RequestId::from_uuid(derived_uuid(
            b"navigator.create-root.v1",
            &[
                session_id.as_uuid().as_bytes(),
                template.template_id().as_uuid().as_bytes(),
            ],
        ))
        .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
        let root = self
            .store
            .create_root_participant(CreateRootParticipant {
                context: RequestContext::new(create_request_id, self.host_id),
                session_id,
                epoch,
                participant_id,
                template_id: template.template_id(),
                expected_compatibility: template.compatibility(),
            })
            .await
            .map_err(|error| store_failure(&error))?;
        Ok(root.value().participant_id)
    }

    async fn ensure_root_authority(
        &self,
        session_id: SessionId,
        participant_id: ParticipantId,
        epoch: FencingEpoch,
        template: &Template,
    ) -> Result<(), Failure>
    where
        S: AuthorityStore,
    {
        let profile = template.authority().clone();
        let template_request = RequestId::from_uuid(derived_uuid(
            b"navigator.root-authority-template.v1",
            &[
                session_id.as_uuid().as_bytes(),
                template.template_id().as_uuid().as_bytes(),
                template.compatibility().as_bytes(),
            ],
        ))
        .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
        self.store
            .register_authority_template_policy(RegisterAuthorityTemplatePolicy {
                context: RequestContext::new(template_request, self.host_id),
                session_id,
                epoch,
                policy: AuthorityTemplatePolicy {
                    template_id: template.template_id(),
                    allowed_parent_templates: std::collections::BTreeSet::from([
                        template.template_id()
                    ]),
                    template: profile.clone(),
                    relationship: profile.clone(),
                    subject: profile.clone(),
                },
            })
            .await
            .map_err(|error| store_failure(&error))?;
        let policy_request = RequestId::from_uuid(derived_uuid(
            b"navigator.root-authority-policy.v1",
            &[
                session_id.as_uuid().as_bytes(),
                participant_id.as_uuid().as_bytes(),
                template.compatibility().as_bytes(),
            ],
        ))
        .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
        self.store
            .put_authority_policy(PutAuthorityPolicy {
                context: RequestContext::new(policy_request, self.host_id),
                session_id,
                epoch,
                policy: AuthorityPolicySnapshot {
                    session_id,
                    participant_id,
                    session: profile.clone(),
                    parent: profile.clone(),
                    template: profile.clone(),
                    relationship: profile.clone(),
                    subject: profile,
                },
            })
            .await
            .map_err(|error| store_failure(&error))?;
        Ok(())
    }

    async fn session_wire(
        &self,
        snapshot: &SessionSnapshot,
    ) -> Result<v1::SessionSnapshot, Failure> {
        let root = self
            .store
            .load_root_participant(snapshot.id())
            .await
            .map_err(|error| store_failure(&error))?;
        Ok(snapshot_wire(snapshot, root.participant_id))
    }

    async fn active_operation_context(
        &self,
        session_id: SessionId,
    ) -> Result<(AdmissionPermit, navigator_domain::FencingEpoch), Failure> {
        let supervisors = self.supervisors.lock().await;
        let supervisor = supervisors
            .get(&session_id)
            .ok_or_else(stale_ownership_failure)?;
        let OwnershipStatus::Active { epoch, .. } = supervisor.status() else {
            return Err(stale_ownership_failure());
        };
        let permit = supervisor
            .admission()
            .admit()
            .map_err(|_| stale_ownership_failure())?;
        permit.check().map_err(|_| stale_ownership_failure())?;
        Ok((permit, epoch))
    }

    async fn prepare_operation(
        &self,
        request: &v1::StartOperationRequest,
        request_id: RequestId,
        session_id: SessionId,
        participant_id: ParticipantId,
    ) -> Result<(AdmissionPermit, StartOperation), Failure> {
        let root = self
            .store
            .load_root_participant(session_id)
            .await
            .map_err(|error| store_failure(&error))?;
        if root.participant_id != participant_id {
            return Err(failure(
                FailureCode::NotFound,
                "Participant is not the Session root",
                RetryClass::Never,
            ));
        }
        let registered = self
            .store
            .load_template(root.template_id)
            .await
            .map_err(|error| store_failure(&error))?;
        let template = Template::try_from(registered).map_err(|_| {
            failure(
                FailureCode::CorruptedState,
                "persisted Template registration is invalid",
                RetryClass::Never,
            )
        })?;
        if template.compatibility() != root.template_compatibility {
            return Err(failure(
                FailureCode::CorruptedState,
                "Participant Template binding is invalid",
                RetryClass::Never,
            ));
        }
        let validated = template.validate_input(&request.input).map_err(|error| {
            failure(
                FailureCode::InvalidRequest,
                &error.to_string(),
                RetryClass::Never,
            )
        })?;
        let (permit, epoch) = self.active_operation_context(session_id).await?;
        let operation_id = OperationId::from_uuid(derived_uuid(
            b"navigator.operation.v1",
            &[
                session_id.as_uuid().as_bytes(),
                request_id.as_uuid().as_bytes(),
            ],
        ))
        .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
        let input_message_id = MessageId::from_uuid(derived_uuid(
            b"navigator.operation-input.v1",
            &[
                session_id.as_uuid().as_bytes(),
                request_id.as_uuid().as_bytes(),
            ],
        ))
        .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
        Ok((
            permit,
            StartOperation {
                context: RequestContext::new(request_id, self.host_id),
                session_id,
                epoch,
                operation_id,
                participant_id,
                input_message_id,
                input: validated,
            },
        ))
    }
}

impl<S> LocalNavigator<S>
where
    S: OperationStore + HierarchyStore + 'static,
{
    async fn prepare_artifact_write(
        &self,
        begin: &v1::BeginArtifactWrite,
    ) -> Result<(AdmissionPermit, crate::ArtifactWrite), Failure> {
        validate_begin_artifact_write(begin).map_err(validation_failure)?;
        self.validate_selected_metadata(
            begin
                .metadata
                .as_ref()
                .ok_or_else(|| validation_failure(ValidationError::MissingField))?,
            CAPABILITY_ARTIFACTS_V1,
        )?;
        if !begin.authority_grant_id.is_empty() {
            return Err(unsupported_artifact_grant());
        }
        let session_id = session_id(&begin.session_id)?;
        let creator = participant_id(&begin.creator_participant_id)?;
        let operation_id = operation_id(&begin.creator_operation_id)?;
        let participant = self
            .store
            .load_participant(creator)
            .await
            .map_err(|error| store_failure(&error))?;
        let operation = self
            .store
            .load_operation(operation_id)
            .await
            .map_err(|error| store_failure(&error))?;
        if participant.session_id != session_id
            || operation.session_id != session_id
            || operation.participant_id != creator
        {
            return Err(failure(
                FailureCode::Authorization,
                "Artifact creator scope does not match Session/Participant/Operation",
                RetryClass::Never,
            ));
        }
        let (permit, epoch) = self.active_operation_context(session_id).await?;
        let digest: [u8; 32] = begin
            .declared_sha256
            .as_slice()
            .try_into()
            .map_err(|_| validation_failure(ValidationError::InvalidBound))?;
        let retention = begin
            .retain_until
            .as_ref()
            .ok_or_else(|| validation_failure(ValidationError::MissingField))?;
        let retention_until = Timestamp::new(retention.unix_seconds, retention.nanoseconds)
            .map_err(|_| validation_failure(ValidationError::InvalidTimestamp))?;
        let media_type = ArtifactMediaType::new(begin.media_type.clone())
            .map_err(|_| validation_failure(ValidationError::InvalidBound))?;
        Ok((
            permit,
            crate::ArtifactWrite {
                request_id: request_id(&begin.request_id)?,
                caller: self.host_id,
                session_id,
                epoch,
                artifact_id: artifact_id(&begin.artifact_id)?,
                media_type,
                creator_participant_id: creator,
                creator_operation_id: operation_id,
                expected_size: begin.declared_size,
                expected_digest: ArtifactDigest::from_bytes(digest),
                retention_until,
            },
        ))
    }
}

#[tonic::async_trait]
#[allow(clippy::too_many_lines)]
impl<
    S: OperationStore
        + MailboxStore
        + HierarchyStore
        + InstanceStore
        + AuthorityStore
        + navigator_store_api::CapacityStore
        + 'static,
> NavigatorConsumer for LocalNavigator<S>
{
    async fn negotiate(
        &self,
        request: Request<v1::NegotiateRequest>,
    ) -> Result<Response<v1::NegotiateResponse>, Status> {
        if let Err(error) = request.get_ref().validate_request() {
            return Ok(Response::new(v1::NegotiateResponse {
                outcome: Some(negotiate_response::Outcome::Failure(validation_failure(
                    error,
                ))),
            }));
        }
        let token = random_uuid()
            .map_err(|_| Status::internal("identity generation failed"))?
            .as_bytes()
            .to_vec();
        let mut supported = CAPABILITIES.to_vec();
        if self.recovery_configured {
            supported.push("recovery.resolution.v1");
        }
        if self.artifacts_configured
            && request
                .get_ref()
                .maximum_version
                .as_ref()
                .is_some_and(|version| version.minor >= 1)
        {
            supported.push(CAPABILITY_ARTIFACTS_V1);
        }
        if self.tools.is_some()
            && request
                .get_ref()
                .maximum_version
                .as_ref()
                .is_some_and(|version| version.minor >= 1)
        {
            supported.push(CAPABILITY_CONSUMER_TOOLS_V1);
        }
        if self.approvals.is_some()
            && request
                .get_ref()
                .maximum_version
                .as_ref()
                .is_some_and(|version| version.minor >= 2)
        {
            supported.push(CAPABILITY_APPROVALS_V1);
        }
        if self.projections.is_some()
            && request
                .get_ref()
                .maximum_version
                .as_ref()
                .is_some_and(|version| version.minor >= 2)
        {
            supported.push(CAPABILITY_OPERATIONAL_PROJECTIONS_V1);
        }
        let outcome = match negotiate(request.get_ref(), &supported, token) {
            Ok(mut value) => {
                value.configuration_identity = self.configuration_identity().to_vec();
                let id = Uuid::from_slice(&value.negotiation_id)
                    .map_err(|_| Status::internal("invalid negotiation identity"))?;
                value.capabilities.sort();
                let existing = self
                    .negotiations
                    .read()
                    .expect("negotiation registry poisoned")
                    .iter()
                    .find_map(|(token, entry)| {
                        (entry.capabilities == value.capabilities && entry.consumer_key.is_none())
                            .then_some(*token)
                    });
                if let Some(existing) = existing {
                    value.negotiation_id = existing.as_bytes().to_vec();
                    negotiate_response::Outcome::Negotiated(value)
                } else {
                    let reservation_id = RequestId::from_uuid(id)
                        .map_err(|_| Status::internal("invalid negotiation identity"))?;
                    if self
                        .store
                        .reserve_global_capacity(navigator_store_api::ReserveGlobalCapacity {
                            reservation_id,
                            resource: CapacityResource::PendingRequests,
                            amount: 1,
                        })
                        .await
                        .is_err()
                    {
                        return Ok(Response::new(v1::NegotiateResponse {
                            outcome: Some(negotiate_response::Outcome::Failure(failure(
                                FailureCode::Capacity,
                                "negotiation capacity reached",
                                RetryClass::Safe,
                            ))),
                        }));
                    }
                    let raced_existing = {
                        let mut registry = self
                            .negotiations
                            .write()
                            .expect("negotiation registry poisoned");
                        if let Some(existing) = registry.iter().find_map(|(token, entry)| {
                            (entry.capabilities == value.capabilities
                                && entry.consumer_key.is_none())
                            .then_some(*token)
                        }) {
                            Some(existing)
                        } else {
                            registry.insert(
                                id,
                                NegotiationEntry {
                                    capabilities: value.capabilities.clone(),
                                    consumer_key: None,
                                    reservation_id: None,
                                },
                            );
                            None
                        }
                    };
                    self.store
                        .release_global_capacity(reservation_id)
                        .await
                        .map_err(|_| Status::unavailable("negotiation capacity release failed"))?;
                    if let Some(existing) = raced_existing {
                        value.negotiation_id = existing.as_bytes().to_vec();
                    }
                    negotiate_response::Outcome::Negotiated(value)
                }
            }
            Err(error) => negotiate_response::Outcome::Failure(validation_failure(error)),
        };
        Ok(Response::new(v1::NegotiateResponse {
            outcome: Some(outcome),
        }))
    }

    #[allow(clippy::single_match_else)]
    async fn open_session(
        &self,
        request: Request<v1::OpenSessionRequest>,
    ) -> Result<Response<v1::OpenSessionResponse>, Status> {
        let request = request.into_inner();
        let prepared = self.validate(&request).and_then(|()| {
            validate_configuration_identity(&request, &self.configuration_identity())?;
            let (template, compatible, manifest) =
                validated_session_templates(&request).map_err(validation_failure)?;
            let compatibility = manifest.as_ref().map_or_else(
                || template.compatibility(),
                SessionCompatibilityManifest::compatibility,
            );
            let commands = self.open_commands(&request, compatibility, manifest)?;
            let metadata = request
                .metadata
                .as_ref()
                .ok_or_else(|| validation_failure(ValidationError::MissingField))?;
            Ok((commands, template, compatible, metadata.clone()))
        });
        let prepared = match prepared {
            Ok((commands, template, compatible, metadata)) => self
                .bind_negotiated_consumer(&metadata, commands.1.consumer_key())
                .await
                .map(|()| (commands, template, compatible)),
            Err(error) => Err(error),
        };
        let outcome = match prepared {
            Err(error) => open_session_response::Outcome::Failure(error),
            Ok(((_candidate_session_id, open, acquire), template, compatible)) => {
                let mut registrations = Vec::with_capacity(compatible.len() + 1);
                registrations.push(template.registration_snapshot());
                registrations.extend(
                    compatible
                        .into_iter()
                        .map(|value| value.registration_snapshot()),
                );
                let command = match RegisterTemplatesAndOpenSession::new(open, registrations) {
                    Ok(command) => command,
                    Err(error) => {
                        return Ok(Response::new(v1::OpenSessionResponse {
                            outcome: Some(open_session_response::Outcome::Failure(store_failure(
                                &error,
                            ))),
                        }));
                    }
                };
                let mut reset_replay = false;
                if command.open().mode() == navigator_store_api::SessionOpenMode::Reset {
                    match self
                        .store
                        .read_request(command.context().request_id())
                        .await
                    {
                        Err(error) => {
                            return Ok(Response::new(v1::OpenSessionResponse {
                                outcome: Some(open_session_response::Outcome::Failure(
                                    store_failure(&error),
                                )),
                            }));
                        }
                        Ok(Some(stored))
                            if stored.caller() != command.context().caller()
                                || stored.action() != command.action()
                                || stored.digest() != command.digest() =>
                        {
                            return Ok(Response::new(v1::OpenSessionResponse {
                                outcome: Some(open_session_response::Outcome::Failure(
                                    store_failure(&StoreError::RequestConflict {
                                        request_id: command.context().request_id(),
                                    }),
                                )),
                            }));
                        }
                        Ok(Some(stored)) => match stored.outcome() {
                            StoredRequestOutcome::Succeeded {
                                result: StoredResult::Session(_),
                                ..
                            } => reset_replay = true,
                            StoredRequestOutcome::Succeeded { .. } => {
                                return Ok(Response::new(v1::OpenSessionResponse {
                                    outcome: Some(open_session_response::Outcome::Failure(
                                        store_failure(&StoreError::Corrupt),
                                    )),
                                }));
                            }
                            StoredRequestOutcome::Failed(error) => {
                                return Ok(Response::new(v1::OpenSessionResponse {
                                    outcome: Some(open_session_response::Outcome::Failure(
                                        store_failure(error),
                                    )),
                                }));
                            }
                        },
                        Ok(None) => {}
                    }
                }
                if command.open().mode() == navigator_store_api::SessionOpenMode::Reset
                    && !reset_replay
                {
                    match self
                        .store
                        .find_open_session(command.open().consumer_key().clone())
                        .await
                    {
                        Err(error) => {
                            return Ok(Response::new(v1::OpenSessionResponse {
                                outcome: Some(open_session_response::Outcome::Failure(
                                    store_failure(&error),
                                )),
                            }));
                        }
                        Ok(Some(previous)) => {
                            if !self.has_active_supervisor(previous.id()).await {
                                let ownership = match self.store.read_ownership(previous.id()).await
                                {
                                    Ok(ownership) => ownership,
                                    Err(error) => {
                                        return Ok(Response::new(v1::OpenSessionResponse {
                                            outcome: Some(open_session_response::Outcome::Failure(
                                                store_failure(&error),
                                            )),
                                        }));
                                    }
                                };
                                if reset_ownership_path(&ownership, self.host_id)
                                    == ResetOwnershipPath::Recover
                                {
                                    let recovery_id = recovery_internal_id(
                                        b"navigator.reset.reconcile.v1",
                                        command.context().request_id(),
                                        previous.id(),
                                    );
                                    if let Err(error) = self
                                        .recovery
                                        .resume_session(recovery_id, previous.id())
                                        .await
                                    {
                                        return Ok(Response::new(v1::OpenSessionResponse {
                                            outcome: Some(open_session_response::Outcome::Failure(
                                                operation_control_failure(error),
                                            )),
                                        }));
                                    }
                                }
                                if let Err(error) =
                                    self.install_reconciled_supervisor(previous.id()).await
                                {
                                    return Ok(Response::new(v1::OpenSessionResponse {
                                        outcome: Some(open_session_response::Outcome::Failure(
                                            error,
                                        )),
                                    }));
                                }
                            }
                            let close_id = recovery_internal_id(
                                b"navigator.reset.close.v1",
                                command.context().request_id(),
                                previous.id(),
                            );
                            if let close_session_response::Outcome::Failure(error) =
                                self.close_owned(close_id, previous.id()).await
                            {
                                return Ok(Response::new(v1::OpenSessionResponse {
                                    outcome: Some(open_session_response::Outcome::Failure(error)),
                                }));
                            }
                        }
                        Ok(None) => {}
                    }
                }
                match self
                    .store
                    .register_templates_and_open_session(command)
                    .await
                {
                    Err(error) => open_session_response::Outcome::Failure(store_failure(&error)),
                    Ok(opened) if self.has_active_supervisor(opened.value().id()).await => {
                        let session_id = opened.value().id();
                        if request.mode == i32::from(v1::SessionOpenMode::Resume) {
                            let recovery_id = request_id(&request.request_id).map_err(|_| {
                                Status::internal("validated request identity became invalid")
                            })?;
                            if let Err(error) =
                                self.recovery.resume_session(recovery_id, session_id).await
                            {
                                return Ok(Response::new(v1::OpenSessionResponse {
                                    outcome: Some(open_session_response::Outcome::Failure(
                                        operation_control_failure(error),
                                    )),
                                }));
                            }
                            let outcome = match self
                                .reconciled_open_snapshot(session_id, &template)
                                .await
                            {
                                Ok(snapshot) => open_session_response::Outcome::Snapshot(snapshot),
                                Err(error) => open_session_response::Outcome::Failure(error),
                            };
                            return Ok(Response::new(v1::OpenSessionResponse {
                                outcome: Some(outcome),
                            }));
                        }
                        let context = self.active_operation_context(session_id).await;
                        match context {
                            Ok((_permit, epoch)) => {
                                match self.ensure_root(session_id, epoch, &template).await {
                                    Ok(root) => match self
                                        .ensure_root_authority(session_id, root, epoch, &template)
                                        .await
                                    {
                                        Err(error) => {
                                            open_session_response::Outcome::Failure(error)
                                        }
                                        Ok(()) => {
                                            self.start_mailbox_pump(session_id, epoch).await;
                                            match self.store.load_session(session_id).await {
                                                Ok(value) => {
                                                    open_session_response::Outcome::Snapshot(
                                                        snapshot_wire(&value, root),
                                                    )
                                                }
                                                Err(error) => {
                                                    open_session_response::Outcome::Failure(
                                                        store_failure(&error),
                                                    )
                                                }
                                            }
                                        }
                                    },
                                    Err(error) => open_session_response::Outcome::Failure(error),
                                }
                            }
                            Err(error) => open_session_response::Outcome::Failure(error),
                        }
                    }
                    Ok(opened) => {
                        let session_id = opened.value().id();
                        if request.mode == i32::from(v1::SessionOpenMode::Resume) {
                            let recovery_id = request_id(&request.request_id).map_err(|_| {
                                Status::internal("validated request identity became invalid")
                            })?;
                            if let Err(error) =
                                self.recovery.resume_session(recovery_id, session_id).await
                            {
                                return Ok(Response::new(v1::OpenSessionResponse {
                                    outcome: Some(open_session_response::Outcome::Failure(
                                        operation_control_failure(error),
                                    )),
                                }));
                            }
                            let outcome = match self
                                .reconciled_open_snapshot(session_id, &template)
                                .await
                            {
                                Ok(snapshot) => open_session_response::Outcome::Snapshot(snapshot),
                                Err(error) => open_session_response::Outcome::Failure(error),
                            };
                            return Ok(Response::new(v1::OpenSessionResponse {
                                outcome: Some(outcome),
                            }));
                        }
                        let acquire = AcquireOwnership::new(
                            RequestContext::new(acquire.context().request_id(), self.host_id),
                            session_id,
                            self.lease_duration,
                        );
                        match self.store.acquire_ownership(acquire).await {
                            Err(error) => {
                                open_session_response::Outcome::Failure(store_failure(&error))
                            }
                            Ok(lease) => {
                                let supervisor = match self.supervisor(lease.value().clone()) {
                                    Ok(value) => value,
                                    Err(error) => {
                                        self.release_lease(lease.value()).await;
                                        return Ok(Response::new(v1::OpenSessionResponse {
                                            outcome: Some(open_session_response::Outcome::Failure(
                                                error,
                                            )),
                                        }));
                                    }
                                };
                                let epoch = lease.value().epoch();
                                self.supervisors.lock().await.insert(session_id, supervisor);
                                match self.ensure_root(session_id, epoch, &template).await {
                                    Ok(root) => match self
                                        .ensure_root_authority(session_id, root, epoch, &template)
                                        .await
                                    {
                                        Err(error) => {
                                            open_session_response::Outcome::Failure(error)
                                        }
                                        Ok(()) => {
                                            self.start_mailbox_pump(session_id, epoch).await;
                                            match self.store.load_session(session_id).await {
                                                Ok(value) => {
                                                    open_session_response::Outcome::Snapshot(
                                                        snapshot_wire(&value, root),
                                                    )
                                                }
                                                Err(error) => {
                                                    open_session_response::Outcome::Failure(
                                                        store_failure(&error),
                                                    )
                                                }
                                            }
                                        }
                                    },
                                    Err(error) => open_session_response::Outcome::Failure(error),
                                }
                            }
                        }
                    }
                }
            }
        };
        Ok(Response::new(v1::OpenSessionResponse {
            outcome: Some(outcome),
        }))
    }

    async fn snapshot(
        &self,
        request: Request<v1::SnapshotRequest>,
    ) -> Result<Response<v1::SnapshotResponse>, Status> {
        let request = request.into_inner();
        let outcome = match self
            .validate(&request)
            .and_then(|()| session_id(&request.session_id))
        {
            Err(error) => snapshot_response::Outcome::Failure(error),
            Ok(id) => match self.store.load_session(id).await {
                Ok(value) => match self.session_wire(&value).await {
                    Ok(snapshot) => snapshot_response::Outcome::Snapshot(snapshot),
                    Err(error) => snapshot_response::Outcome::Failure(error),
                },
                Err(error) => snapshot_response::Outcome::Failure(store_failure(&error)),
            },
        };
        Ok(Response::new(v1::SnapshotResponse {
            outcome: Some(outcome),
        }))
    }

    async fn close_session(
        &self,
        request: Request<v1::CloseSessionRequest>,
    ) -> Result<Response<v1::CloseSessionResponse>, Status> {
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            Ok((
                request_id(&request.request_id)?,
                session_id(&request.session_id)?,
            ))
        });
        let outcome = match parsed {
            Err(error) => close_session_response::Outcome::Failure(error),
            Ok((request_id, session_id)) => self.close_owned(request_id, session_id).await,
        };
        Ok(Response::new(v1::CloseSessionResponse {
            outcome: Some(outcome),
        }))
    }

    async fn start_operation(
        &self,
        request: Request<v1::StartOperationRequest>,
    ) -> Result<Response<v1::StartOperationResponse>, Status> {
        use v1::start_operation_response::Outcome;
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            Ok((
                request_id(&request.request_id)?,
                session_id(&request.session_id)?,
                participant_id(&request.participant_id)?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((request_id, session_id, participant_id)) => match self
                .prepare_operation(&request, request_id, session_id, participant_id)
                .await
            {
                Err(error) => Outcome::Failure(error),
                Ok((permit, command)) => match self.operations.start(permit, command).await {
                    Ok(snapshot) => Outcome::Snapshot(operation_wire(&snapshot)),
                    Err(OperationControlError::Unavailable) => Outcome::Failure(failure(
                        FailureCode::Unavailable,
                        "no matching Driver is configured",
                        RetryClass::Safe,
                    )),
                    Err(OperationControlError::CleanupRequired) => Outcome::Failure(failure(
                        FailureCode::CleanupRequired,
                        "operation cleanup requires reconciliation",
                        RetryClass::AfterReconciliation,
                    )),
                    Err(OperationControlError::Store(error)) => {
                        Outcome::Failure(store_failure(&error))
                    }
                },
            },
        };
        Ok(Response::new(v1::StartOperationResponse {
            outcome: Some(outcome),
        }))
    }

    async fn operation_snapshot(
        &self,
        request: Request<v1::OperationSnapshotRequest>,
    ) -> Result<Response<v1::OperationSnapshotResponse>, Status> {
        use v1::operation_snapshot_response::Outcome;
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            Ok((
                session_id(&request.session_id)?,
                operation_id(&request.operation_id)?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((session_id, operation_id)) => match self.store.load_operation(operation_id).await {
                Ok(snapshot) if snapshot.session_id == session_id => {
                    Outcome::Snapshot(operation_wire(&snapshot))
                }
                Ok(_) => Outcome::Failure(failure(
                    FailureCode::NotFound,
                    "Operation does not belong to Session",
                    RetryClass::Never,
                )),
                Err(error) => Outcome::Failure(store_failure(&error)),
            },
        };
        Ok(Response::new(v1::OperationSnapshotResponse {
            outcome: Some(outcome),
        }))
    }

    async fn participant_snapshot(
        &self,
        request: Request<v1::ParticipantSnapshotRequest>,
    ) -> Result<Response<v1::ParticipantSnapshotResponse>, Status> {
        use v1::participant_snapshot_response::Outcome;
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            Ok((
                session_id(&request.session_id)?,
                participant_id(&request.participant_id)?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((session_id, participant_id)) => {
                match self.store.load_participant(participant_id).await {
                    Ok(snapshot) if snapshot.session_id == session_id => {
                        Outcome::Snapshot(participant_wire(&snapshot))
                    }
                    Ok(_) => Outcome::Failure(failure(
                        FailureCode::NotFound,
                        "Participant does not belong to Session",
                        RetryClass::Never,
                    )),
                    Err(error) => Outcome::Failure(store_failure(&error)),
                }
            }
        };
        Ok(Response::new(v1::ParticipantSnapshotResponse {
            outcome: Some(outcome),
        }))
    }

    async fn message_snapshot(
        &self,
        request: Request<v1::MessageSnapshotRequest>,
    ) -> Result<Response<v1::MessageSnapshotResponse>, Status> {
        use v1::message_snapshot_response::Outcome;
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            Ok((
                session_id(&request.session_id)?,
                message_id(&request.message_id)?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((session_id, message_id)) => match self.store.load_message(message_id).await {
                Ok(snapshot) if snapshot.session_id == session_id => {
                    Outcome::Snapshot(message_wire(&snapshot))
                }
                Ok(_) => Outcome::Failure(failure(
                    FailureCode::NotFound,
                    "Message does not belong to Session",
                    RetryClass::Never,
                )),
                Err(error) => Outcome::Failure(store_failure(&error)),
            },
        };
        Ok(Response::new(v1::MessageSnapshotResponse {
            outcome: Some(outcome),
        }))
    }

    async fn cancel_subtree(
        &self,
        request: Request<v1::CancelSubtreeRequest>,
    ) -> Result<Response<v1::CancelSubtreeResponse>, Status> {
        use v1::cancel_subtree_response::Outcome;
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            Ok((
                request_id(&request.request_id)?,
                session_id(&request.session_id)?,
                participant_id(&request.root_participant_id)?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((request_id, session_id, root_participant_id)) => {
                let (permit, epoch) = match self.active_operation_context(session_id).await {
                    Ok(value) => value,
                    Err(error) => {
                        return Ok(Response::new(v1::CancelSubtreeResponse {
                            outcome: Some(Outcome::Failure(error)),
                        }));
                    }
                };
                match self
                    .operations
                    .cancel_subtree(
                        permit,
                        CancelSubtree {
                            context: RequestContext::new(request_id, self.host_id),
                            session_id,
                            epoch,
                            root_participant_id,
                        },
                    )
                    .await
                {
                    Ok(result) => {
                        if let Some(tools) = self.tools.as_ref() {
                            let operation_ids = result
                                .records
                                .iter()
                                .map(|record| record.operation.operation_id)
                                .collect();
                            if tools
                                .cancel_operations(request_id, session_id, operation_ids)
                                .await
                                .is_err()
                            {
                                return Ok(Response::new(v1::CancelSubtreeResponse {
                                    outcome: Some(Outcome::Failure(failure(
                                        FailureCode::CleanupRequired,
                                        "Tool cancellation requires reconciliation",
                                        RetryClass::AfterReconciliation,
                                    ))),
                                }));
                            }
                        }
                        Outcome::Cancellation(v1::CancellationSnapshot {
                            root_participant_id: result
                                .root_participant_id
                                .as_uuid()
                                .as_bytes()
                                .to_vec(),
                            operations: result
                                .records
                                .iter()
                                .map(|record| v1::CancellationOperation {
                                    operation: Some(operation_wire(&record.operation)),
                                    notification_message_id: record
                                        .notification
                                        .as_ref()
                                        .map_or_else(Vec::new, |message| {
                                            message.message_id.as_uuid().as_bytes().to_vec()
                                        }),
                                    cleanup_confirmed: record.cleanup_confirmed(),
                                })
                                .collect(),
                        })
                    }
                    Err(OperationControlError::Store(error)) => {
                        Outcome::Failure(store_failure(&error))
                    }
                    Err(OperationControlError::Unavailable) => Outcome::Failure(failure(
                        FailureCode::Unavailable,
                        "cancellation delivery is unavailable",
                        RetryClass::Safe,
                    )),
                    Err(OperationControlError::CleanupRequired) => Outcome::Failure(failure(
                        FailureCode::CleanupRequired,
                        "cancellation cleanup requires reconciliation",
                        RetryClass::AfterReconciliation,
                    )),
                }
            }
        };
        Ok(Response::new(v1::CancelSubtreeResponse {
            outcome: Some(outcome),
        }))
    }

    async fn resume_session(
        &self,
        request: Request<v1::ResumeSessionRequest>,
    ) -> Result<Response<v1::ResumeSessionResponse>, Status> {
        use v1::resume_session_response::Outcome;
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            Ok((
                request_id(&request.request_id)?,
                session_id(&request.session_id)?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((request_id, session_id)) => {
                // Resume is a crash/recovery ownership boundary.  A locally
                // supervised active Session is already owned and must not
                // issue a competing Acquire request (which also creates
                // unbounded failed ledger entries under polling callers).
                if self.has_active_supervisor(session_id).await {
                    return Ok(Response::new(v1::ResumeSessionResponse {
                        outcome: Some(Outcome::Failure(failure(
                            FailureCode::CleanupRequired,
                            "Session is already actively supervised",
                            RetryClass::AfterReconciliation,
                        ))),
                    }));
                }
                match self.recovery.resume_session(request_id, session_id).await {
                    Ok(report) => Outcome::Report(report),
                    Err(error) => Outcome::Failure(operation_control_failure(error)),
                }
            }
        };
        Ok(Response::new(v1::ResumeSessionResponse {
            outcome: Some(outcome),
        }))
    }

    async fn resolve_uncertainty(
        &self,
        request: Request<v1::ResolveUncertaintyRequest>,
    ) -> Result<Response<v1::ResolveUncertaintyResponse>, Status> {
        use v1::resolve_uncertainty_response::Outcome;
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            Ok((
                session_id(&request.session_id)?,
                UnverifiedRecoveryAuthorityClaim {
                    grant_id: grant_id(&request.authority_grant_id)?,
                },
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((_session_id, authority_claim)) => {
                match self
                    .recovery
                    .resolve_uncertainty(authority_claim, request)
                    .await
                {
                    Ok(resolution) => Outcome::Resolution(resolution),
                    Err(error) => Outcome::Failure(operation_control_failure(error)),
                }
            }
        };
        Ok(Response::new(v1::ResolveUncertaintyResponse {
            outcome: Some(outcome),
        }))
    }

    async fn register_tool(
        &self,
        request: Request<v1::RegisterToolRequest>,
    ) -> Result<Response<v1::RegisterToolResponse>, Status> {
        use v1::register_tool_response::Outcome;
        let parsed = self
            .validate(request.get_ref())
            .and_then(|()| session_id(&request.get_ref().session_id));
        let session_id = match parsed {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::new(v1::RegisterToolResponse {
                    outcome: Some(Outcome::Failure(error)),
                }));
            }
        };
        let Some(tools) = self.tools.as_ref() else {
            return Ok(Response::new(v1::RegisterToolResponse {
                outcome: Some(Outcome::Failure(failure(
                    FailureCode::Unavailable,
                    "durable Consumer Tool registration is not configured",
                    RetryClass::Safe,
                ))),
            }));
        };
        let (_, epoch) = match self.active_operation_context(session_id).await {
            Ok(value) => value,
            Err(error) => {
                return Ok(Response::new(v1::RegisterToolResponse {
                    outcome: Some(Outcome::Failure(error)),
                }));
            }
        };
        Ok(Response::new(
            tools.register(request.into_inner(), epoch).await,
        ))
    }

    type ProvideToolsStream = ToolProviderStream;
    async fn provide_tools(
        &self,
        request: Request<tonic::Streaming<v1::ToolProviderRequest>>,
    ) -> Result<Response<Self::ProvideToolsStream>, Status> {
        let Some(tools) = self.tools.as_ref() else {
            let response = v1::ToolProviderResponse {
                frame: Some(v1::tool_provider_response::Frame::Failure(failure(
                    FailureCode::Unavailable,
                    "durable Consumer Tool provider is not configured",
                    RetryClass::Safe,
                ))),
            };
            return Ok(Response::new(Box::pin(tokio_stream::once(Ok(response)))));
        };
        tools.provide(request.into_inner()).await.map(Response::new)
    }

    async fn write_artifact(
        &self,
        request: Request<tonic::Streaming<v1::WriteArtifactRequest>>,
    ) -> Result<Response<v1::WriteArtifactResponse>, Status> {
        use v1::write_artifact_response::Outcome;
        if !self.artifacts_configured {
            return Ok(Response::new(v1::WriteArtifactResponse {
                outcome: Some(Outcome::Failure(artifact_unavailable())),
            }));
        }
        let mut input = request.into_inner();
        let mut validator = ArtifactWriteStreamValidator::default();
        let first = match input.message().await {
            Ok(Some(value)) => value,
            Ok(None) => {
                return Ok(Response::new(v1::WriteArtifactResponse {
                    outcome: Some(Outcome::Failure(validation_failure(
                        ValidationError::MissingField,
                    ))),
                }));
            }
            Err(_) => {
                return Ok(Response::new(v1::WriteArtifactResponse {
                    outcome: Some(Outcome::Failure(malformed_artifact_stream())),
                }));
            }
        };
        if let Err(error) = validator.accept(&first) {
            return Ok(Response::new(v1::WriteArtifactResponse {
                outcome: Some(Outcome::Failure(validation_failure(error))),
            }));
        }
        let Some(v1::write_artifact_request::Frame::Begin(begin)) = first.frame else {
            return Ok(Response::new(v1::WriteArtifactResponse {
                outcome: Some(Outcome::Failure(validation_failure(
                    ValidationError::MissingField,
                ))),
            }));
        };
        let parsed = self.prepare_artifact_write(&begin).await;
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((permit, command)) => {
                let (mut writer, reader) = tokio::io::duplex(MAX_ARTIFACT_CHUNK_BYTES * 2);
                let producer = async move {
                    loop {
                        let frame = match input.message().await {
                            Ok(Some(value)) => value,
                            Ok(None) => break,
                            Err(_) => return Err(malformed_artifact_stream()),
                        };
                        validator.accept(&frame).map_err(validation_failure)?;
                        let Some(v1::write_artifact_request::Frame::Chunk(chunk)) = frame.frame
                        else {
                            return Err(validation_failure(ValidationError::MalformedRequest));
                        };
                        writer.write_all(&chunk.content).await.map_err(|_| {
                            failure(
                                FailureCode::Unavailable,
                                "artifact upload reader closed",
                                RetryClass::Safe,
                            )
                        })?;
                    }
                    validator.finish().map_err(validation_failure)?;
                    writer.shutdown().await.map_err(|_| {
                        failure(
                            FailureCode::Unavailable,
                            "artifact upload reader closed",
                            RetryClass::Safe,
                        )
                    })
                };
                let (upload_result, result) = tokio::join!(
                    producer,
                    self.artifacts
                        .write(command, Box::pin(reader) as ArtifactContent)
                );
                drop(permit);
                match (upload_result, result) {
                    (Err(error), _) => Outcome::Failure(error),
                    (Ok(()), Ok(snapshot)) => Outcome::Artifact(artifact_wire(&snapshot)),
                    (Ok(()), Err(error)) => Outcome::Failure(artifact_control_failure(error)),
                }
            }
        };
        let response = v1::WriteArtifactResponse {
            outcome: Some(outcome),
        };
        debug_assert!(validate_write_artifact_response(&response).is_ok());
        Ok(Response::new(response))
    }

    type ReadArtifactStream = ArtifactReadStream;
    async fn read_artifact(
        &self,
        request: Request<v1::ReadArtifactRequest>,
    ) -> Result<Response<Self::ReadArtifactStream>, Status> {
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            if !request.authority_grant_id.is_empty() {
                return Err(unsupported_artifact_grant());
            }
            Ok((
                session_id(&request.session_id)?,
                artifact_id(&request.artifact_id)?,
            ))
        });
        let (session_id, artifact_id) = match parsed {
            Ok(value) if self.artifacts_configured => value,
            Ok(_) => return Ok(artifact_failure_stream(artifact_unavailable())),
            Err(error) => return Ok(artifact_failure_stream(error)),
        };
        let (permit, epoch) = match self.active_operation_context(session_id).await {
            Ok(value) => value,
            Err(error) => return Ok(artifact_failure_stream(error)),
        };
        let result = self
            .artifacts
            .read(ArtifactAccess {
                session_id,
                owner: self.host_id,
                epoch,
                artifact_id,
            })
            .await;
        drop(permit);
        let (snapshot, mut reader) = match result {
            Ok(value) => value,
            Err(error) => return Ok(artifact_failure_stream(artifact_control_failure(error))),
        };
        if request.offset > snapshot.size {
            return Ok(artifact_failure_stream(failure(
                FailureCode::InvalidRequest,
                "artifact range starts beyond content",
                RetryClass::Never,
            )));
        }
        let available = snapshot.size - request.offset;
        let length = match request.length {
            Some(value) => value,
            None => available,
        };
        if length > available {
            return Ok(artifact_failure_stream(failure(
                FailureCode::InvalidRequest,
                "artifact range exceeds content",
                RetryClass::Never,
            )));
        }
        let header = v1::ReadArtifactResponse {
            outcome: Some(v1::read_artifact_response::Outcome::Header(
                v1::ArtifactReadHeader {
                    artifact: Some(artifact_wire(&snapshot)),
                    range_offset: request.offset,
                    range_length: length,
                },
            )),
        };
        let artifact_bytes = request.artifact_id.clone();
        let range_offset = request.offset;
        let range_end = range_offset + length;
        let expected_size = snapshot.size;
        let expected_digest = snapshot.digest.as_bytes();
        let (sender, receiver) = mpsc::channel(4);
        if self
            .background_tasks
            .spawn(async move {
                if sender.send(Ok(header)).await.is_err() {
                    return;
                }
                let mut buffer = vec![0_u8; MAX_ARTIFACT_CHUNK_BYTES].into_boxed_slice();
                let mut digest = Sha256::new();
                let mut position = 0_u64;
                while position != expected_size {
                    let wanted = usize::try_from(
                        (expected_size - position).min(MAX_ARTIFACT_CHUNK_BYTES as u64),
                    )
                    .expect("chunk bound fits usize");
                    let count = match reader.read(&mut buffer[..wanted]).await {
                        Ok(0) | Err(_) => {
                            let _ = sender
                                .send(Ok(artifact_read_failure(artifact_control_failure(
                                    ArtifactControlError::Integrity,
                                ))))
                                .await;
                            return;
                        }
                        Ok(count) => count,
                    };
                    digest.update(&buffer[..count]);
                    let chunk_end = position + count as u64;
                    let emit_start = position.max(range_offset);
                    let emit_end = chunk_end.min(range_end);
                    if emit_start < emit_end {
                        let start = usize::try_from(emit_start - position)
                            .expect("chunk-relative offset fits usize");
                        let end = usize::try_from(emit_end - position)
                            .expect("chunk-relative offset fits usize");
                        let response = v1::ReadArtifactResponse {
                            outcome: Some(v1::read_artifact_response::Outcome::Chunk(
                                v1::ArtifactChunk {
                                    artifact_id: artifact_bytes.clone(),
                                    offset: emit_start,
                                    content: buffer[start..end].to_vec(),
                                },
                            )),
                        };
                        if sender.send(Ok(response)).await.is_err() {
                            return;
                        }
                    }
                    position = chunk_end;
                }
                let trailing = reader.read(&mut buffer[..1]).await.unwrap_or(1);
                let actual_digest: [u8; 32] = digest.finalize().into();
                if trailing != 0 || actual_digest != expected_digest {
                    let _ = sender
                        .send(Ok(artifact_read_failure(artifact_control_failure(
                            ArtifactControlError::Integrity,
                        ))))
                        .await;
                }
            })
            .await
            .is_err()
        {
            return Ok(artifact_failure_stream(failure(
                FailureCode::Unavailable,
                "daemon is shutting down",
                RetryClass::Safe,
            )));
        }
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn artifact_snapshot(
        &self,
        request: Request<v1::ArtifactSnapshotRequest>,
    ) -> Result<Response<v1::ArtifactSnapshotResponse>, Status> {
        use v1::artifact_snapshot_response::Outcome;
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            Ok((
                session_id(&request.session_id)?,
                artifact_id(&request.artifact_id)?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok(_) if !self.artifacts_configured => Outcome::Failure(artifact_unavailable()),
            Ok((session_id, artifact_id)) => {
                match self.active_operation_context(session_id).await {
                    Err(error) => Outcome::Failure(error),
                    Ok((permit, epoch)) => {
                        let result = self
                            .artifacts
                            .snapshot(ArtifactAccess {
                                session_id,
                                owner: self.host_id,
                                epoch,
                                artifact_id,
                            })
                            .await;
                        drop(permit);
                        match result {
                            Ok(snapshot) => Outcome::Artifact(artifact_wire(&snapshot)),
                            Err(error) => Outcome::Failure(artifact_control_failure(error)),
                        }
                    }
                }
            }
        };
        let response = v1::ArtifactSnapshotResponse {
            outcome: Some(outcome),
        };
        debug_assert!(validate_artifact_snapshot_response(&response).is_ok());
        Ok(Response::new(response))
    }

    async fn delete_artifact(
        &self,
        request: Request<v1::DeleteArtifactRequest>,
    ) -> Result<Response<v1::DeleteArtifactResponse>, Status> {
        use v1::delete_artifact_response::Outcome;
        let request = request.into_inner();
        let parsed = self.validate(&request).and_then(|()| {
            if !request.authority_grant_id.is_empty() {
                return Err(unsupported_artifact_grant());
            }
            Ok((
                request_id(&request.request_id)?,
                session_id(&request.session_id)?,
                artifact_id(&request.artifact_id)?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok(_) if !self.artifacts_configured => Outcome::Failure(artifact_unavailable()),
            Ok((request_id, session_id, artifact_id)) => {
                match self.active_operation_context(session_id).await {
                    Err(error) => Outcome::Failure(error),
                    Ok((permit, epoch)) => {
                        let result = self
                            .artifacts
                            .logically_delete(DeleteArtifact {
                                context: RequestContext::new(request_id, self.host_id),
                                session_id,
                                owner: self.host_id,
                                epoch,
                                artifact_id,
                            })
                            .await;
                        drop(permit);
                        match result {
                            Ok(snapshot) => Outcome::Artifact(artifact_wire(&snapshot)),
                            Err(error) => Outcome::Failure(artifact_control_failure(error)),
                        }
                    }
                }
            }
        };
        let response = v1::DeleteArtifactResponse {
            outcome: Some(outcome),
        };
        debug_assert!(validate_delete_artifact_response(&response).is_ok());
        Ok(Response::new(response))
    }

    async fn approval_snapshot(
        &self,
        request: Request<v1::ApprovalSnapshotRequest>,
    ) -> Result<Response<v1::ApprovalSnapshotResponse>, Status> {
        use v1::approval_snapshot_response::Outcome;
        let parsed = self.validate(request.get_ref()).and_then(|()| {
            Ok((
                session_id(&request.get_ref().session_id)?,
                approval_request_id(&request.get_ref().approval_id)?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((session_id, approval_id)) => {
                match self.trusted_approval_authority(&request, session_id).await {
                    Err(error) => Outcome::Failure(error),
                    Ok(_) => match self.approvals.as_ref() {
                        None => Outcome::Failure(approval_unavailable()),
                        Some(controller) => {
                            match controller.snapshot(session_id, approval_id).await {
                                Ok(value) => Outcome::Approval(approval_wire(&value)),
                                Err(error) => Outcome::Failure(store_failure(&error)),
                            }
                        }
                    },
                }
            }
        };
        Ok(Response::new(v1::ApprovalSnapshotResponse {
            outcome: Some(outcome),
        }))
    }

    async fn approve_approval(
        &self,
        request: Request<v1::ApproveApprovalRequest>,
    ) -> Result<Response<v1::ApproveApprovalResponse>, Status> {
        use v1::approve_approval_response::Outcome;
        let parsed = self.validate(request.get_ref()).and_then(|()| {
            let value = request.get_ref();
            Ok((
                request_id(&value.request_id)?,
                session_id(&value.session_id)?,
                approval_request_id(&value.approval_id)?,
                Revision::new(value.expected_revision)
                    .map_err(|_| validation_failure(ValidationError::InvalidBound))?,
                grant_id(&value.grant_id)?,
                timestamp_domain(value.grant_expires_at.as_ref())?,
                value.max_uses,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((
                request_id,
                session_id,
                approval_id,
                expected_revision,
                grant_id,
                expires_at,
                max_uses,
            )) => match self.trusted_approval_authority(&request, session_id).await {
                Err(error) => Outcome::Failure(error),
                Ok(authority) => match (
                    self.approvals.as_ref(),
                    self.active_operation_context(session_id).await,
                ) {
                    (None, _) => Outcome::Failure(approval_unavailable()),
                    (_, Err(error)) => Outcome::Failure(error),
                    (Some(controller), Ok((permit, epoch))) => {
                        let result = controller
                            .approve(
                                authority,
                                ApproveRequest {
                                    context: RequestContext::new(request_id, self.host_id),
                                    session_id,
                                    owner_epoch: epoch,
                                    approval_id,
                                    expected_revision,
                                    grant_id,
                                    grant_expires_at: expires_at,
                                    max_uses,
                                },
                            )
                            .await;
                        drop(permit);
                        match result {
                            Ok(value) => Outcome::Approval(approval_wire(&value)),
                            Err(error) => Outcome::Failure(store_failure(&error)),
                        }
                    }
                },
            },
        };
        Ok(Response::new(v1::ApproveApprovalResponse {
            outcome: Some(outcome),
        }))
    }

    async fn deny_approval(
        &self,
        request: Request<v1::DenyApprovalRequest>,
    ) -> Result<Response<v1::DenyApprovalResponse>, Status> {
        use v1::deny_approval_response::Outcome;
        let parsed = self.validate(request.get_ref()).and_then(|()| {
            let value = request.get_ref();
            Ok((
                request_id(&value.request_id)?,
                session_id(&value.session_id)?,
                approval_request_id(&value.approval_id)?,
                Revision::new(value.expected_revision)
                    .map_err(|_| validation_failure(ValidationError::InvalidBound))?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((request_id, session_id, approval_id, expected_revision)) => {
                match self.trusted_approval_authority(&request, session_id).await {
                    Err(error) => Outcome::Failure(error),
                    Ok(authority) => match (
                        self.approvals.as_ref(),
                        self.active_operation_context(session_id).await,
                    ) {
                        (None, _) => Outcome::Failure(approval_unavailable()),
                        (_, Err(error)) => Outcome::Failure(error),
                        (Some(controller), Ok((permit, epoch))) => {
                            let result = controller
                                .deny(
                                    authority,
                                    DenyRequest {
                                        context: RequestContext::new(request_id, self.host_id),
                                        session_id,
                                        owner_epoch: epoch,
                                        approval_id,
                                        expected_revision,
                                    },
                                )
                                .await;
                            drop(permit);
                            match result {
                                Ok(value) => Outcome::Approval(approval_wire(&value)),
                                Err(error) => Outcome::Failure(store_failure(&error)),
                            }
                        }
                    },
                }
            }
        };
        Ok(Response::new(v1::DenyApprovalResponse {
            outcome: Some(outcome),
        }))
    }

    async fn revoke_approval_grant(
        &self,
        request: Request<v1::RevokeApprovalGrantRequest>,
    ) -> Result<Response<v1::RevokeApprovalGrantResponse>, Status> {
        use v1::revoke_approval_grant_response::Outcome;
        let parsed = self.validate(request.get_ref()).and_then(|()| {
            let value = request.get_ref();
            Ok((
                request_id(&value.request_id)?,
                session_id(&value.session_id)?,
                grant_id(&value.grant_id)?,
                Revision::new(value.expected_revision)
                    .map_err(|_| validation_failure(ValidationError::InvalidBound))?,
            ))
        });
        let outcome = match parsed {
            Err(error) => Outcome::Failure(error),
            Ok((request_id, session_id, grant_id, expected_revision)) => {
                match self.trusted_approval_authority(&request, session_id).await {
                    Err(error) => Outcome::Failure(error),
                    Ok(authority) => match (
                        self.approvals.as_ref(),
                        self.active_operation_context(session_id).await,
                    ) {
                        (None, _) => Outcome::Failure(approval_unavailable()),
                        (_, Err(error)) => Outcome::Failure(error),
                        (Some(controller), Ok((permit, epoch))) => {
                            let result = controller
                                .revoke(
                                    authority,
                                    RevokeApprovalGrant {
                                        context: RequestContext::new(request_id, self.host_id),
                                        session_id,
                                        owner_epoch: epoch,
                                        grant_id,
                                        expected_revision,
                                    },
                                )
                                .await;
                            drop(permit);
                            match result {
                                Ok(value) => Outcome::Approval(approval_wire(&value)),
                                Err(error) => Outcome::Failure(store_failure(&error)),
                            }
                        }
                    },
                }
            }
        };
        Ok(Response::new(v1::RevokeApprovalGrantResponse {
            outcome: Some(outcome),
        }))
    }

    async fn read_projection(
        &self,
        request: Request<v1::ReadProjectionRequest>,
    ) -> Result<Response<v1::ReadProjectionResponse>, Status> {
        use v1::read_projection_response::Outcome;
        let outcome = if let Err(error) = self.validate(request.get_ref()) {
            Outcome::Failure(error)
        } else {
            let value = request.get_ref();
            let parsed = (|| {
                let session_id = session_id(&value.session_id)?;
                let claimed_consumer = ConsumerKey::new(value.consumer_key.clone())
                    .map_err(|_| validation_failure(ValidationError::InvalidBound))?;
                let metadata = value
                    .metadata
                    .as_ref()
                    .ok_or_else(|| validation_failure(ValidationError::MissingField))?;
                let negotiation_id = Uuid::from_slice(&metadata.negotiation_id)
                    .map_err(|_| validation_failure(ValidationError::InvalidIdentity))?;
                let consumer = self
                    .negotiations
                    .read()
                    .expect("negotiation registry poisoned")
                    .get(&negotiation_id)
                    .and_then(|entry| entry.consumer_key.clone())
                    .ok_or_else(|| {
                        failure(
                            FailureCode::Authentication,
                            "negotiation is not bound to a Consumer",
                            RetryClass::Never,
                        )
                    })?;
                if claimed_consumer != consumer {
                    return Err(failure(
                        FailureCode::Authentication,
                        "Consumer binding does not match negotiation",
                        RetryClass::Never,
                    ));
                }
                let view = projection_view(value.view)?;
                let page_size = ProjectionPageSize::new(
                    u16::try_from(value.page_size)
                        .map_err(|_| validation_failure(ValidationError::InvalidBound))?,
                )
                .map_err(|_| validation_failure(ValidationError::InvalidBound))?;
                let page_token = if value.page_token.is_empty() {
                    None
                } else {
                    Some(
                        ProjectionPageToken::new(value.page_token.clone())
                            .map_err(|_| validation_failure(ValidationError::InvalidBound))?,
                    )
                };
                Ok::<_, Failure>((session_id, consumer, view, page_size, page_token))
            })();
            match parsed {
                Err(error) => Outcome::Failure(error),
                Ok((session_id, consumer, view, page_size, page_token)) => {
                    let session_matches = self
                        .store
                        .load_session(session_id)
                        .await
                        .is_ok_and(|snapshot| snapshot.consumer_key() == &consumer);
                    if !session_matches {
                        Outcome::Failure(failure(
                            FailureCode::Authentication,
                            "Consumer does not own Session",
                            RetryClass::Never,
                        ))
                    } else if let Some(controller) = &self.projections {
                        match controller
                            .read(ReadProjection {
                                session_id,
                                consumer,
                                view,
                                page_size,
                                page_token,
                            })
                            .await
                        {
                            Ok(page) => Outcome::Page(projection_page_wire(page)),
                            Err(error) => Outcome::Failure(store_failure(&error)),
                        }
                    } else {
                        Outcome::Failure(failure(
                            FailureCode::Unavailable,
                            "operational projections are unavailable",
                            RetryClass::Safe,
                        ))
                    }
                }
            }
        };
        Ok(Response::new(v1::ReadProjectionResponse {
            outcome: Some(outcome),
        }))
    }

    type SubscribeEventsStream = EventStream;
    async fn subscribe_events(
        &self,
        request: Request<v1::SubscribeEventsRequest>,
    ) -> Result<Response<Self::SubscribeEventsStream>, Status> {
        let request = request.into_inner();
        let (id, consumer, after) = match self.subscription_setup(&request).await {
            Ok(value) => value,
            Err(error) => return Ok(failure_stream(error)),
        };
        let ownership = match self.store.read_ownership(id).await {
            Ok(OwnershipSnapshot::Owned {
                host_id,
                epoch,
                expires_at,
            }) if host_id == self.host_id => (epoch, expires_at),
            _ => {
                return Ok(failure_stream(failure(
                    FailureCode::StaleOwnership,
                    "subscription requires current durable ownership",
                    RetryClass::Safe,
                )));
            }
        };
        let Ok(permit) = Arc::clone(&self.subscriptions).try_acquire_owned() else {
            return Ok(failure_stream(failure(
                FailureCode::Capacity,
                "subscription capacity reached",
                RetryClass::Safe,
            )));
        };
        let session_permit = {
            let limit =
                usize::try_from(self.limits.get(CapacityResource::Subscriptions).per_session)
                    .expect("hard subscription ceiling fits usize");
            let mut usage = self
                .subscription_sessions
                .lock()
                .expect("subscription capacity lock poisoned");
            let used = usage.entry(id).or_default();
            if *used >= limit {
                return Ok(failure_stream(failure(
                    FailureCode::Capacity,
                    "Session subscription capacity reached",
                    RetryClass::Safe,
                )));
            }
            *used += 1;
            SessionSubscriptionPermit {
                session_id: id,
                usage: Arc::clone(&self.subscription_sessions),
            }
        };
        let Ok(root) = self.store.load_root_participant(id).await else {
            return Ok(failure_stream(failure(
                FailureCode::Capacity,
                "subscription capacity identity unavailable",
                RetryClass::Safe,
            )));
        };
        let reservation_id = RequestId::from_uuid(
            random_uuid().map_err(|_| Status::internal("identity generation failed"))?,
        )
        .map_err(|_| Status::internal("identity generation failed"))?;
        if self
            .store
            .reserve_subscription_lease(navigator_store_api::ReserveSubscriptionLease {
                reservation_id,
                session_id: id,
                campaign_id: root.participant_id,
                owner_host_id: self.host_id,
                owner_epoch: ownership.0,
                expires_at: ownership.1,
            })
            .await
            .is_err()
        {
            if self.store.release_capacity(reservation_id).await.is_err() {
                self.background_tasks.mark_cleanup_required().await;
            }
            return Ok(failure_stream(failure(
                FailureCode::Capacity,
                "durable subscription capacity reached",
                RetryClass::Safe,
            )));
        }
        let (sender, receiver) = mpsc::channel(EVENT_STREAM_QUEUE_CAPACITY);
        let store = Arc::clone(&self.store);
        let stopping = Arc::clone(&self.stopping);
        let background_tasks = self.background_tasks.clone();
        let lease = navigator_store_api::ReserveSubscriptionLease {
            reservation_id,
            session_id: id,
            campaign_id: root.participant_id,
            owner_host_id: self.host_id,
            owner_epoch: ownership.0,
            expires_at: ownership.1,
        };
        if self
            .background_tasks
            .spawn(async move {
                event_loop(
                    Arc::clone(&store),
                    sender,
                    id,
                    consumer,
                    after,
                    stopping,
                    Some(lease),
                    SubscriptionPermits {
                        _global: permit,
                        _session: Some(session_permit),
                    },
                )
                .await;
                // The task owns the durable reservation and synchronously closes
                // it before completing. A process crash is reclaimed on store
                // reopen by the SQLite startup reconciliation.
                if store.release_capacity(reservation_id).await.is_err() {
                    background_tasks.mark_cleanup_required().await;
                }
            })
            .await
            .is_err()
        {
            return Ok(failure_stream(failure(
                FailureCode::Unavailable,
                "daemon is shutting down",
                RetryClass::Safe,
            )));
        }
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn read_events(
        &self,
        request: Request<v1::ReadEventsRequest>,
    ) -> Result<Response<v1::ReadEventsResponse>, Status> {
        let request = request.into_inner();
        let outcome = if let Err(error) = self.validate(&request) {
            v1::read_events_response::Outcome::Failure(error)
        } else {
            let result = async {
                let session_id = session_id(&request.session_id)?;
                let metadata = request
                    .metadata
                    .as_ref()
                    .ok_or_else(|| validation_failure(ValidationError::MissingField))?;
                let consumer = self.bound_session_consumer(metadata, session_id).await?;
                let after = if request.after_position == 0 {
                    None
                } else {
                    Some(
                        EventPosition::new(request.after_position)
                            .map_err(|_| validation_failure(ValidationError::ZeroValue))?,
                    )
                };
                let page = self
                    .store
                    .read_events(ReadEvents {
                        session_id,
                        consumer,
                        after,
                        limit: EventReadLimit::new(request.page_size)
                            .map_err(|_| validation_failure(ValidationError::InvalidBound))?,
                    })
                    .await
                    .map_err(|error| store_failure(&error))?;
                Ok::<_, Failure>(v1::EventPage {
                    events: page.events.iter().map(event_wire).collect(),
                    has_more: page.has_more,
                })
            }
            .await;
            match result {
                Ok(page) => v1::read_events_response::Outcome::Page(page),
                Err(error) => v1::read_events_response::Outcome::Failure(error),
            }
        };
        Ok(Response::new(v1::ReadEventsResponse {
            outcome: Some(outcome),
        }))
    }
}

impl<S: OperationStore + 'static> LocalNavigator<S> {
    async fn subscription_setup(
        &self,
        request: &v1::SubscribeEventsRequest,
    ) -> Result<(SessionId, ConsumerKey, Option<EventPosition>), Failure> {
        self.validate(request)?;
        let id = session_id(&request.session_id)?;
        let metadata = request
            .metadata
            .as_ref()
            .ok_or_else(|| validation_failure(ValidationError::MissingField))?;
        let consumer = self.bound_session_consumer(metadata, id).await?;
        let after = if request.after_position == 0 {
            None
        } else {
            Some(
                EventPosition::new(request.after_position)
                    .map_err(|_| validation_failure(ValidationError::ZeroValue))?,
            )
        };
        Ok((id, consumer, after))
    }
}

impl<S> LocalNavigator<S> {
    fn open_commands(
        &self,
        request: &v1::OpenSessionRequest,
        compatibility: CompatibilityIdentity,
        manifest: Option<SessionCompatibilityManifest>,
    ) -> Result<(SessionId, OpenSession, AcquireOwnership), Failure> {
        let session_id = session_id(&request.session_id)?;
        let context = RequestContext::new(request_id(&request.request_id)?, self.host_id);
        let ownership_id = RequestId::from_uuid(random_uuid().map_err(|_| {
            failure(
                FailureCode::Internal,
                "identity generation failed",
                RetryClass::Never,
            )
        })?)
        .map_err(|_| {
            failure(
                FailureCode::Internal,
                "identity generation failed",
                RetryClass::Never,
            )
        })?;
        let ownership = RequestContext::new(ownership_id, self.host_id);
        let consumer = ConsumerKey::new(request.consumer_key.clone())
            .map_err(|_| validation_failure(ValidationError::InvalidBound))?;
        let mode = match v1::SessionOpenMode::try_from(request.mode) {
            Ok(v1::SessionOpenMode::Unspecified) => navigator_store_api::SessionOpenMode::Exact,
            Ok(v1::SessionOpenMode::Open) => navigator_store_api::SessionOpenMode::Open,
            Ok(v1::SessionOpenMode::Resume) => navigator_store_api::SessionOpenMode::Resume,
            Ok(v1::SessionOpenMode::Reset) => navigator_store_api::SessionOpenMode::Reset,
            Err(_) => return Err(validation_failure(ValidationError::InvalidEnum)),
        };
        Ok((
            session_id,
            match manifest {
                Some(manifest) => {
                    OpenSession::with_manifest(context, session_id, consumer, manifest)
                }
                None => OpenSession::new(context, session_id, consumer, compatibility),
            }
            .with_mode(mode),
            AcquireOwnership::new(ownership, session_id, self.lease_duration),
        ))
    }
}

fn validate_configuration_identity(
    request: &v1::OpenSessionRequest,
    expected: &[u8; 32],
) -> Result<(), Failure> {
    if request.configuration_identity.is_empty()
        || bool::from(request.configuration_identity.as_slice().ct_eq(expected))
    {
        Ok(())
    } else {
        Err(validation_failure(ValidationError::CompatibilityMismatch))
    }
}

pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub shutdown_timeout: Duration,
}

pub async fn serve<
    S: OperationStore
        + MailboxStore
        + HierarchyStore
        + InstanceStore
        + AuthorityStore
        + navigator_store_api::CapacityStore
        + 'static,
>(
    service: LocalNavigator<S>,
    credential: BootstrapCredential,
    config: ServerConfig,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), LocalError> {
    let inner_shutdown = config.shutdown_timeout.as_millis().saturating_div(2).max(1);
    service.ownership_shutdown_millis.store(
        u64::try_from(inner_shutdown).unwrap_or(u64::MAX),
        Ordering::Release,
    );
    service.session_close_timeout_millis.store(
        u64::try_from(config.shutdown_timeout.as_millis()).unwrap_or(u64::MAX),
        Ordering::Release,
    );
    let listener = bind_private_socket(&config.socket_path)?;
    let cleanup = Cleanup {
        path: config.socket_path.clone(),
        identity: socket_identity(&config.socket_path)?,
    };
    let bounded = v1::navigator_consumer_server::NavigatorConsumerServer::new(service.clone())
        .max_decoding_message_size(MAX_REQUEST_BYTES);
    let server = tonic::service::interceptor::InterceptedService::new(
        bounded,
        move |mut request: Request<()>| {
            credential.authenticate(&request)?;
            request
                .extensions_mut()
                .insert(AuthenticatedTrustedConsumer);
            Ok(request)
        },
    );
    let shutdown_service = service.clone();
    let cleanup_failed = Arc::clone(&service.cleanup_failed);
    let mut transport_shutdown = shutdown.clone();
    let transport = tonic::transport::Server::builder().serve_with_incoming_shutdown(
        server,
        UnixListenerStream::new(listener),
        async move {
            while !*transport_shutdown.borrow() && transport_shutdown.changed().await.is_ok() {}
            shutdown_service.stopping.store(true, Ordering::Release);
        },
    );
    tokio::pin!(transport);
    let transport_result = tokio::select! {
        result = &mut transport => {
            service.stopping.store(true, Ordering::Release);
            let deadline = ShutdownDeadline::after(config.shutdown_timeout);
            let operations = deadline
                .run(service.operations.shutdown_until(deadline.instant()))
                .await;
            let ownership = deadline.run(service.release_all()).await;
            service.wake_all_mailbox_pumps().await;
            let background = service
                .background_tasks
                .shutdown_until(deadline.instant())
                .await;
            if !matches!(operations, Ok(Ok(())))
                || background != BackgroundShutdownOutcome::Complete
                || !matches!(ownership, Ok(Ok(())))
            {
                cleanup_failed.store(true, Ordering::Release);
            }
            result
        }
        () = async {
            while !*shutdown.borrow() && shutdown.changed().await.is_ok() {}
        } => {
            service.stopping.store(true, Ordering::Release);
            let deadline = ShutdownDeadline::after(config.shutdown_timeout);
            let operations = deadline
                .run(service.operations.shutdown_until(deadline.instant()))
                .await;
            let ownership = deadline.run(service.release_all()).await;
            service.wake_all_mailbox_pumps().await;
            let background = service
                .background_tasks
                .shutdown_until(deadline.instant())
                .await;
            let drained = deadline.run(&mut transport).await;
            if !matches!(operations, Ok(Ok(())))
                || background != BackgroundShutdownOutcome::Complete
                || !matches!(drained, Ok(Ok(())))
                || !matches!(ownership, Ok(Ok(())))
            {
                cleanup_failed.store(true, Ordering::Release);
            }
            drained.map_or(Ok(()), |result| result)
        }
    };
    drop(cleanup);
    if cleanup_failed.load(Ordering::Acquire) {
        return Err(LocalError::CleanupRequired);
    }
    transport_result?;
    Ok(())
}

struct SessionSubscriptionPermit {
    session_id: SessionId,
    usage: Arc<std::sync::Mutex<HashMap<SessionId, usize>>>,
}

struct SubscriptionPermits {
    _global: OwnedSemaphorePermit,
    _session: Option<SessionSubscriptionPermit>,
}

impl Drop for SessionSubscriptionPermit {
    fn drop(&mut self) {
        let mut usage = self
            .usage
            .lock()
            .expect("subscription capacity lock poisoned");
        if let Some(used) = usage.get_mut(&self.session_id) {
            *used = used.saturating_sub(1);
            if *used == 0 {
                usage.remove(&self.session_id);
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "stream task owns explicit authentication, cursor, lease, shutdown, and capacity guards"
)]
async fn event_loop<S: SessionStore + navigator_store_api::CapacityStore + 'static>(
    store: Arc<S>,
    sender: mpsc::Sender<Result<v1::SubscribeEventsResponse, Status>>,
    session_id: SessionId,
    consumer: ConsumerKey,
    mut after: Option<EventPosition>,
    stopping: Arc<AtomicBool>,
    lease: Option<navigator_store_api::ReserveSubscriptionLease>,
    _permits: SubscriptionPermits,
) {
    let limit = EventReadLimit::new(128).expect("valid page size");
    let mut tick = interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = sender.closed() => return,
            _ = tick.tick() => {}
        }
        if stopping.load(Ordering::Acquire) {
            return;
        }
        if let Some(mut lease) = lease.clone() {
            let Ok(OwnershipSnapshot::Owned {
                host_id,
                epoch,
                expires_at,
            }) = store.read_ownership(session_id).await
            else {
                return;
            };
            if host_id != lease.owner_host_id || epoch != lease.owner_epoch {
                return;
            }
            lease.expires_at = expires_at;
            if store.renew_subscription_lease(lease).await.is_err() {
                return;
            }
        }
        loop {
            let page = match store
                .read_events(ReadEvents {
                    session_id,
                    consumer: consumer.clone(),
                    after,
                    limit,
                })
                .await
            {
                Ok(page) => page,
                Err(error) => {
                    let response = Ok(v1::SubscribeEventsResponse {
                        outcome: Some(subscribe_events_response::Outcome::Failure(store_failure(
                            &error,
                        ))),
                    });
                    let _ = tokio::time::timeout(EVENT_STREAM_SEND_TIMEOUT, sender.send(response))
                        .await;
                    return;
                }
            };
            for event in page.events {
                after = Some(event.position());
                let response = Ok(v1::SubscribeEventsResponse {
                    outcome: Some(subscribe_events_response::Outcome::Event(event_wire(
                        &event,
                    ))),
                });
                if !matches!(
                    tokio::time::timeout(EVENT_STREAM_SEND_TIMEOUT, sender.send(response)).await,
                    Ok(Ok(()))
                ) {
                    return;
                }
            }
            if !page.has_more {
                break;
            }
        }
    }
}

fn request_id(bytes: &[u8]) -> Result<RequestId, Failure> {
    Uuid::from_slice(bytes)
        .ok()
        .and_then(|id| RequestId::from_uuid(id).ok())
        .ok_or_else(|| validation_failure(ValidationError::InvalidIdentity))
}
fn session_id(bytes: &[u8]) -> Result<SessionId, Failure> {
    Uuid::from_slice(bytes)
        .ok()
        .and_then(|id| SessionId::from_uuid(id).ok())
        .ok_or_else(|| validation_failure(ValidationError::InvalidIdentity))
}
fn participant_id(bytes: &[u8]) -> Result<ParticipantId, Failure> {
    Uuid::from_slice(bytes)
        .ok()
        .and_then(|id| ParticipantId::from_uuid(id).ok())
        .ok_or_else(|| validation_failure(ValidationError::InvalidIdentity))
}
fn operation_id(bytes: &[u8]) -> Result<OperationId, Failure> {
    Uuid::from_slice(bytes)
        .ok()
        .and_then(|id| OperationId::from_uuid(id).ok())
        .ok_or_else(|| validation_failure(ValidationError::InvalidIdentity))
}
fn message_id(bytes: &[u8]) -> Result<MessageId, Failure> {
    Uuid::from_slice(bytes)
        .ok()
        .and_then(|id| MessageId::from_uuid(id).ok())
        .ok_or_else(|| validation_failure(ValidationError::InvalidIdentity))
}
fn artifact_id(bytes: &[u8]) -> Result<ArtifactId, Failure> {
    Uuid::from_slice(bytes)
        .ok()
        .and_then(|id| ArtifactId::from_uuid(id).ok())
        .ok_or_else(|| validation_failure(ValidationError::InvalidIdentity))
}

fn grant_id(bytes: &[u8]) -> Result<GrantId, Failure> {
    Uuid::from_slice(bytes)
        .ok()
        .and_then(|value| GrantId::from_uuid(value).ok())
        .ok_or_else(|| validation_failure(ValidationError::InvalidIdentity))
}

fn approval_request_id(bytes: &[u8]) -> Result<ApprovalRequestId, Failure> {
    Uuid::from_slice(bytes)
        .ok()
        .and_then(|value| ApprovalRequestId::from_uuid(value).ok())
        .ok_or_else(|| validation_failure(ValidationError::InvalidIdentity))
}

fn timestamp_domain(value: Option<&v1::Timestamp>) -> Result<Timestamp, Failure> {
    let value = value.ok_or_else(|| validation_failure(ValidationError::MissingField))?;
    Timestamp::new(value.unix_seconds, value.nanoseconds)
        .map_err(|_| validation_failure(ValidationError::InvalidTimestamp))
}

fn operation_control_failure(error: OperationControlError) -> Failure {
    match error {
        OperationControlError::Unavailable => failure(
            FailureCode::Unavailable,
            "recovery controller is unavailable",
            RetryClass::Safe,
        ),
        OperationControlError::CleanupRequired => failure(
            FailureCode::CleanupRequired,
            "recovery requires reconciliation",
            RetryClass::AfterReconciliation,
        ),
        OperationControlError::Store(error) => store_failure(&error),
    }
}

fn artifact_control_failure(error: ArtifactControlError) -> Failure {
    match error {
        ArtifactControlError::Unavailable => artifact_unavailable(),
        ArtifactControlError::Invalid => failure(
            FailureCode::InvalidRequest,
            "artifact request violates its storage boundary",
            RetryClass::Never,
        ),
        ArtifactControlError::Oversize => failure(
            FailureCode::Capacity,
            "artifact exceeds the content limit",
            RetryClass::Never,
        ),
        ArtifactControlError::Integrity => failure(
            FailureCode::CorruptedState,
            "artifact content failed integrity verification",
            RetryClass::Never,
        ),
        ArtifactControlError::Store(error) => store_failure(&error),
        ArtifactControlError::Io(_) => failure(
            FailureCode::Unavailable,
            "artifact filesystem is unavailable",
            RetryClass::Safe,
        ),
    }
}

fn artifact_unavailable() -> Failure {
    failure(
        FailureCode::Unavailable,
        "Artifact controller is not configured",
        RetryClass::Safe,
    )
}

fn approval_unavailable() -> Failure {
    failure(
        FailureCode::Unavailable,
        "Approval controller is not configured",
        RetryClass::Safe,
    )
}

fn unsupported_artifact_grant() -> Failure {
    failure(
        FailureCode::Authorization,
        "Artifact Grant authority is not configured",
        RetryClass::Never,
    )
}

fn artifact_failure_stream(error: Failure) -> Response<ArtifactReadStream> {
    Response::new(Box::pin(tokio_stream::once(Ok(artifact_read_failure(
        error,
    )))))
}

fn artifact_read_failure(error: Failure) -> v1::ReadArtifactResponse {
    v1::ReadArtifactResponse {
        outcome: Some(v1::read_artifact_response::Outcome::Failure(error)),
    }
}

fn malformed_artifact_stream() -> Failure {
    failure(
        FailureCode::InvalidRequest,
        "artifact upload stream is malformed",
        RetryClass::Never,
    )
}

fn recovery_report(
    session_id: SessionId,
    reconciliation: &navigator_core::Reconciliation,
) -> v1::RecoveryReport {
    v1::RecoveryReport {
        session_id: session_id.as_uuid().as_bytes().to_vec(),
        classifications: reconciliation
            .executions
            .iter()
            .map(|execution| {
                let item = execution.classification;
                let blocked_by_uncertainty = matches!(
                    execution.status,
                    navigator_core::RecoveryExecutionStatus::BlockedByUncertainty
                );
                let action_pending = matches!(
                    execution.status,
                    navigator_core::RecoveryExecutionStatus::Pending
                        | navigator_core::RecoveryExecutionStatus::BlockedByCleanup
                ) && !matches!(
                    item.decision.action,
                    navigator_domain::RecoveryAction::AwaitResolution
                );
                v1::RecoveryClassification {
                    entity: Some(match item.entity {
                        RecoveryEntity::Session(id) => {
                            v1::recovery_classification::Entity::SessionId(
                                id.as_uuid().as_bytes().to_vec(),
                            )
                        }
                        RecoveryEntity::Participant(id) => {
                            v1::recovery_classification::Entity::ParticipantId(
                                id.as_uuid().as_bytes().to_vec(),
                            )
                        }
                        RecoveryEntity::Instance(id) => {
                            v1::recovery_classification::Entity::LaunchAttemptId(
                                id.as_uuid().as_bytes().to_vec(),
                            )
                        }
                        RecoveryEntity::Operation { operation_id, .. } => {
                            v1::recovery_classification::Entity::OperationId(
                                operation_id.as_uuid().as_bytes().to_vec(),
                            )
                        }
                        RecoveryEntity::Message(id) => {
                            v1::recovery_classification::Entity::MessageId(
                                id.as_uuid().as_bytes().to_vec(),
                            )
                        }
                        RecoveryEntity::Effect(id) => {
                            v1::recovery_classification::Entity::EffectId(
                                id.as_uuid().as_bytes().to_vec(),
                            )
                        }
                    }),
                    disposition: if blocked_by_uncertainty {
                        v1::RecoveryDisposition::EffectUncertain.into()
                    } else if action_pending {
                        v1::RecoveryDisposition::CleanupRequired.into()
                    } else {
                        recovery_disposition(item.decision.class).into()
                    },
                    allowed_actions: Vec::new(),
                    reason: if blocked_by_uncertainty {
                        "blocked_by_session_uncertainty".to_owned()
                    } else if action_pending {
                        "recovery_action_pending".to_owned()
                    } else {
                        item.decision.reason.as_str().to_owned()
                    },
                    action_status: recovery_action_status(execution.status).into(),
                }
            })
            .collect(),
    }
}

const fn recovery_action_status(
    status: navigator_core::RecoveryExecutionStatus,
) -> v1::RecoveryActionStatus {
    match status {
        navigator_core::RecoveryExecutionStatus::Executed => v1::RecoveryActionStatus::Executed,
        navigator_core::RecoveryExecutionStatus::NoOp => v1::RecoveryActionStatus::NoOp,
        navigator_core::RecoveryExecutionStatus::Pending => v1::RecoveryActionStatus::Pending,
        navigator_core::RecoveryExecutionStatus::BlockedByUncertainty => {
            v1::RecoveryActionStatus::BlockedByUncertainty
        }
        navigator_core::RecoveryExecutionStatus::BlockedByCleanup => {
            v1::RecoveryActionStatus::BlockedByCleanup
        }
    }
}

const fn recovery_disposition(class: navigator_domain::RecoveryClass) -> v1::RecoveryDisposition {
    match class {
        navigator_domain::RecoveryClass::SafeToContinue => v1::RecoveryDisposition::SafeToContinue,
        navigator_domain::RecoveryClass::SafeToRedeliver => {
            v1::RecoveryDisposition::SafeToRedeliver
        }
        navigator_domain::RecoveryClass::ExternallyAlive => {
            v1::RecoveryDisposition::ExternallyAlive
        }
        navigator_domain::RecoveryClass::EffectUncertain => {
            v1::RecoveryDisposition::EffectUncertain
        }
        navigator_domain::RecoveryClass::CleanupRequired => {
            v1::RecoveryDisposition::CleanupRequired
        }
        navigator_domain::RecoveryClass::Terminal => v1::RecoveryDisposition::Terminal,
    }
}

fn wire_resolution(
    resolution: v1::resolve_uncertainty_request::Resolution,
) -> Result<UncertaintyResolution, StoreError> {
    match resolution {
        v1::resolve_uncertainty_request::Resolution::ConfirmCompleted(proof) => {
            Ok(UncertaintyResolution::ConfirmCompleted {
                proof: domain_effect_proof(proof)?,
            })
        }
        v1::resolve_uncertainty_request::Resolution::DoNotRetry(_) => {
            Ok(UncertaintyResolution::DoNotRetry)
        }
        v1::resolve_uncertainty_request::Resolution::RetryWithEffectProof(proof) => {
            Ok(UncertaintyResolution::RetryWithEffectProof {
                proof: domain_effect_proof(proof)?,
            })
        }
    }
}

fn domain_effect_proof(proof: v1::EffectProof) -> Result<EffectProof, StoreError> {
    let kind = match v1::EffectProofKind::try_from(proof.kind).map_err(|_| StoreError::Invalid)? {
        v1::EffectProofKind::ExternalCommit => EffectProofKind::ExternalCommit,
        v1::EffectProofKind::IdempotencyReceipt => EffectProofKind::IdempotencyReceipt,
        v1::EffectProofKind::EffectAbsent => EffectProofKind::EffectAbsent,
        v1::EffectProofKind::Unspecified => return Err(StoreError::Invalid),
    };
    let digest: [u8; 32] = proof.digest.try_into().map_err(|_| StoreError::Invalid)?;
    let evidence = BoundedBytes::<MAX_EFFECT_PROOF_BYTES>::new(proof.evidence)
        .map_err(|_| StoreError::Invalid)?;
    EffectProof::new(kind, digest, evidence).map_err(|_| StoreError::Invalid)
}

const fn wire_resolution_action(resolution: &UncertaintyResolution) -> v1::ResolutionAction {
    match resolution {
        UncertaintyResolution::ConfirmCompleted { .. } => v1::ResolutionAction::ConfirmCompleted,
        UncertaintyResolution::DoNotRetry => v1::ResolutionAction::DoNotRetry,
        UncertaintyResolution::RetryWithEffectProof { .. } => {
            v1::ResolutionAction::RetryWithEffectProof
        }
    }
}

fn derived_uuid(domain: &[u8], parts: &[&[u8]]) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update(
            u64::try_from(part.len())
                .expect("identity component fits u64")
                .to_be_bytes(),
        );
        digest.update(part);
    }
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .expect("SHA-256 prefix has fixed size");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn recovery_internal_id(
    domain: &[u8],
    public_request_id: RequestId,
    session_id: SessionId,
) -> RequestId {
    RequestId::from_uuid(derived_uuid(
        domain,
        &[
            public_request_id.as_uuid().as_bytes(),
            session_id.as_uuid().as_bytes(),
        ],
    ))
    .expect("domain-separated recovery identity is non-nil")
}

fn snapshot_wire(
    value: &SessionSnapshot,
    root_participant_id: ParticipantId,
) -> v1::SessionSnapshot {
    v1::SessionSnapshot {
        session_id: value.id().as_uuid().as_bytes().to_vec(),
        consumer_key: value.consumer_key().as_str().to_owned(),
        compatibility_identity: value.compatibility().as_bytes().to_vec(),
        status: match value.status() {
            SessionStatus::Open => v1::SessionStatus::Open as i32,
            SessionStatus::Closed => v1::SessionStatus::Closed as i32,
        },
        revision: value.revision().get(),
        created_at: Some(timestamp_wire(value.created_at())),
        updated_at: Some(timestamp_wire(value.updated_at())),
        root_participant_id: root_participant_id.as_uuid().as_bytes().to_vec(),
    }
}

fn artifact_wire(value: &ArtifactSnapshot) -> v1::ArtifactSnapshot {
    let status = match value.state {
        ArtifactState::Available => v1::ArtifactStatus::Available,
        ArtifactState::LogicallyDeleted => v1::ArtifactStatus::LogicallyDeleted,
        ArtifactState::PhysicallyErased => v1::ArtifactStatus::Erased,
    };
    v1::ArtifactSnapshot {
        artifact_id: value.artifact_id.as_uuid().as_bytes().to_vec(),
        session_id: value.session_id.as_uuid().as_bytes().to_vec(),
        creator_participant_id: value.creator_participant_id.as_uuid().as_bytes().to_vec(),
        creator_operation_id: value.creator_operation_id.as_uuid().as_bytes().to_vec(),
        media_type: value.media_type.as_str().to_owned(),
        size: value.size,
        sha256: value.digest.as_bytes().to_vec(),
        storage_relative_locator: value.locator.clone(),
        status: status.into(),
        retain_until: Some(timestamp_wire(value.retention_until)),
        created_at: Some(timestamp_wire(value.created_at)),
        updated_at: Some(timestamp_wire(value.deleted_at.unwrap_or(value.created_at))),
        revision: value.revision.get(),
    }
}

fn operation_wire(value: &OperationSnapshot) -> v1::OperationSnapshot {
    let (result, terminal_failure) = public_terminal(value.terminal_outcome.as_ref());
    v1::OperationSnapshot {
        operation_id: value.operation_id.as_uuid().as_bytes().to_vec(),
        session_id: value.session_id.as_uuid().as_bytes().to_vec(),
        participant_id: value.participant_id.as_uuid().as_bytes().to_vec(),
        request_id: value.start_request_id.as_uuid().as_bytes().to_vec(),
        status: match value.state {
            OperationState::Queued => v1::OperationStatus::Queued,
            OperationState::Starting => v1::OperationStatus::Starting,
            OperationState::Running => v1::OperationStatus::Running,
            OperationState::Waiting => v1::OperationStatus::Waiting,
            OperationState::Cancelling => v1::OperationStatus::Cancelling,
            OperationState::Succeeded => v1::OperationStatus::Succeeded,
            OperationState::Failed => v1::OperationStatus::Failed,
            OperationState::Cancelled => v1::OperationStatus::Cancelled,
            OperationState::Blocked => v1::OperationStatus::Blocked,
            OperationState::Uncertain => v1::OperationStatus::Uncertain,
        } as i32,
        result,
        terminal_failure,
        revision: value.revision.get(),
        created_at: Some(timestamp_wire(value.created_at)),
        updated_at: Some(timestamp_wire(value.updated_at)),
    }
}

fn participant_wire(value: &ParticipantSnapshot) -> v1::ParticipantSnapshot {
    v1::ParticipantSnapshot {
        session_id: value.session_id.as_uuid().as_bytes().to_vec(),
        participant_id: value.participant_id.as_uuid().as_bytes().to_vec(),
        parent_participant_id: value
            .parent_participant_id
            .map(|id| id.as_uuid().as_bytes().to_vec()),
        depth: value.depth,
        template_id: value.template_id.as_uuid().as_bytes().to_vec(),
        template_compatibility: value.template_compatibility.as_bytes().to_vec(),
        revision: value.revision.get(),
    }
}

fn message_wire(value: &MessageSnapshot) -> v1::MessageSnapshot {
    let delivery_status = match &value.state {
        MessageDeliveryState::Queued => v1::MessageDeliveryStatus::Queued,
        MessageDeliveryState::RetryScheduled { .. } => v1::MessageDeliveryStatus::RetryScheduled,
        MessageDeliveryState::Leased { .. } => v1::MessageDeliveryStatus::Leased,
        MessageDeliveryState::AcceptancePending { .. } => {
            v1::MessageDeliveryStatus::AcceptancePending
        }
        MessageDeliveryState::AcceptanceUnknown { .. } => {
            v1::MessageDeliveryStatus::AcceptanceUnknown
        }
        MessageDeliveryState::Accepted { .. } => v1::MessageDeliveryStatus::Accepted,
        MessageDeliveryState::Uncertain { .. } => v1::MessageDeliveryStatus::Uncertain,
        MessageDeliveryState::DeadLetter { .. } => v1::MessageDeliveryStatus::DeadLetter,
    };
    v1::MessageSnapshot {
        session_id: value.session_id.as_uuid().as_bytes().to_vec(),
        message_id: value.message_id.as_uuid().as_bytes().to_vec(),
        source_participant_id: value.source.as_uuid().as_bytes().to_vec(),
        destination_participant_id: value.destination.as_uuid().as_bytes().to_vec(),
        mailbox_sequence: value.mailbox_sequence,
        priority: match value.priority {
            MessagePriority::Control => v1::MessagePriority::Control,
            MessagePriority::Ordinary => v1::MessagePriority::Ordinary,
        } as i32,
        operation_id: value
            .correlation
            .operation_id
            .map(|id| id.as_uuid().as_bytes().to_vec()),
        in_reply_to: value
            .correlation
            .in_reply_to
            .map(|id| id.as_uuid().as_bytes().to_vec()),
        envelope: value.envelope.as_bytes().to_vec(),
        attempt_count: value.attempt_count,
        delivery_status: delivery_status as i32,
        revision: value.revision.get(),
        created_at: Some(timestamp_wire(value.created_at)),
        updated_at: Some(timestamp_wire(value.updated_at)),
    }
}

fn public_terminal(
    outcome: Option<&OperationTerminalOutcome>,
) -> (Option<Vec<u8>>, Option<Failure>) {
    match outcome {
        Some(OperationTerminalOutcome::Succeeded { result }) => {
            (Some(result.as_slice().to_vec()), None)
        }
        Some(OperationTerminalOutcome::Failed { .. }) => (
            None,
            Some(failure(
                FailureCode::Internal,
                "Operation failed",
                RetryClass::Never,
            )),
        ),
        Some(OperationTerminalOutcome::Cancelled) => (
            None,
            Some(failure(
                FailureCode::Cancelled,
                "Operation was cancelled",
                RetryClass::Never,
            )),
        ),
        Some(OperationTerminalOutcome::Blocked { .. }) => (
            None,
            Some(failure(
                FailureCode::Unavailable,
                "Operation is blocked",
                RetryClass::AfterReconciliation,
            )),
        ),
        Some(OperationTerminalOutcome::Uncertain { .. }) => (
            None,
            Some(failure(
                FailureCode::UncertainEffect,
                "Operation outcome requires reconciliation",
                RetryClass::AfterReconciliation,
            )),
        ),
        None => (None, None),
    }
}

#[cfg(test)]
mod operation_visibility_tests {
    use super::*;

    #[test]
    fn executor_private_terminal_text_is_never_public() {
        let sentinel = "PRIVATE_EXECUTOR_SENTINEL";
        for outcome in [
            OperationTerminalOutcome::Failed {
                code: navigator_domain::BoundedText::new(sentinel).unwrap(),
                detail: navigator_domain::BoundedText::new(sentinel).unwrap(),
            },
            OperationTerminalOutcome::Blocked {
                reason: navigator_domain::BoundedText::new(sentinel).unwrap(),
            },
            OperationTerminalOutcome::Uncertain {
                reason: navigator_domain::BoundedText::new(sentinel).unwrap(),
            },
        ] {
            assert!(!format!("{:?}", public_terminal(Some(&outcome))).contains(sentinel));
        }
    }
}

#[cfg(test)]
mod durable_subscription_tests {
    use super::*;
    use navigator_domain::{CompatibilityIdentity, RequestId};
    use navigator_store_api::{ReleaseOwnership, RequestContext};
    use navigator_store_sqlite::SqliteStore;
    use tempfile::TempDir;
    use tokio_stream::StreamExt;

    fn id<T>(
        value: u128,
        make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
    ) -> T {
        make(Uuid::from_u128(value)).unwrap()
    }

    fn context(value: u128, host: HostId) -> RequestContext {
        RequestContext::new(id(value, RequestId::from_uuid), host)
    }

    fn replay_metadata(negotiation_id: Uuid) -> v1::RequestMetadata {
        v1::RequestMetadata {
            protocol_version: Some(v1::ProtocolVersion { major: 1, minor: 2 }),
            capabilities: vec!["events.replay.v1".into()],
            negotiation_id: negotiation_id.as_bytes().to_vec(),
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one fixture compares the complete negative and positive authorization boundary"
    )]
    async fn event_reads_require_exact_bound_consumer_before_store_access() {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("event-auth.db"))
                .await
                .unwrap(),
        );
        let host = id(201, HostId::from_uuid);
        let session = id(202, SessionId::from_uuid);
        store
            .open_session(OpenSession::new(
                context(203, host),
                session,
                ConsumerKey::new("consumer-a").unwrap(),
                CompatibilityIdentity::from_bytes([4; 32]),
            ))
            .await
            .unwrap();
        let service = LocalNavigator::new(
            Arc::clone(&store),
            host,
            LeaseDuration::from_millis(30_000).unwrap(),
        );
        let bound = Uuid::from_u128(204);
        let unbound = Uuid::from_u128(205);
        let crossed = Uuid::from_u128(206);
        service.negotiations.write().unwrap().extend([
            (
                bound,
                NegotiationEntry {
                    capabilities: vec!["events.replay.v1".into()],
                    consumer_key: Some(ConsumerKey::new("consumer-a").unwrap()),
                    reservation_id: None,
                },
            ),
            (
                unbound,
                NegotiationEntry {
                    capabilities: vec!["events.replay.v1".into()],
                    consumer_key: None,
                    reservation_id: None,
                },
            ),
            (
                crossed,
                NegotiationEntry {
                    capabilities: vec!["events.replay.v1".into()],
                    consumer_key: Some(ConsumerKey::new("consumer-b").unwrap()),
                    reservation_id: None,
                },
            ),
        ]);
        let before_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let before_ledger: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
            .fetch_one(store.pool())
            .await
            .unwrap();

        let mut hidden_failures = Vec::new();
        for (token, candidate_session) in [
            (unbound, session),
            (crossed, session),
            (bound, id(207, SessionId::from_uuid)),
        ] {
            let response = NavigatorConsumer::read_events(
                &service,
                Request::new(v1::ReadEventsRequest {
                    metadata: Some(replay_metadata(token)),
                    session_id: candidate_session.as_uuid().as_bytes().to_vec(),
                    after_position: 0,
                    page_size: 1,
                }),
            )
            .await
            .unwrap()
            .into_inner();
            let Some(v1::read_events_response::Outcome::Failure(value)) = response.outcome else {
                panic!("unauthorized event read reached the Store")
            };
            assert_eq!(value.code, FailureCode::Authentication as i32);
            if token != unbound {
                hidden_failures.push(value);
            }
        }
        assert_eq!(hidden_failures.len(), 2);
        assert_eq!(hidden_failures[0], hidden_failures[1]);
        let response = NavigatorConsumer::read_events(
            &service,
            Request::new(v1::ReadEventsRequest {
                metadata: Some(replay_metadata(bound)),
                session_id: session.as_uuid().as_bytes().to_vec(),
                after_position: 0,
                page_size: 1,
            }),
        )
        .await
        .unwrap()
        .into_inner();
        assert!(matches!(
            response.outcome,
            Some(v1::read_events_response::Outcome::Page(_))
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            before_events
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM request_ledger")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            before_ledger
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one fixture compares authorization, no-oracle behavior, and ownership fencing"
    )]
    async fn subscription_auth_precedes_and_preserves_ownership_fencing() {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("subscription-auth.db"))
                .await
                .unwrap(),
        );
        let host = id(211, HostId::from_uuid);
        let session = id(212, SessionId::from_uuid);
        store
            .open_session(OpenSession::new(
                context(213, host),
                session,
                ConsumerKey::new("consumer-a").unwrap(),
                CompatibilityIdentity::from_bytes([5; 32]),
            ))
            .await
            .unwrap();
        let service = LocalNavigator::new(
            Arc::clone(&store),
            host,
            LeaseDuration::from_millis(30_000).unwrap(),
        );
        let bound = Uuid::from_u128(214);
        let unbound = Uuid::from_u128(215);
        let crossed = Uuid::from_u128(216);
        service.negotiations.write().unwrap().extend([
            (
                bound,
                NegotiationEntry {
                    capabilities: vec!["events.replay.v1".into()],
                    consumer_key: Some(ConsumerKey::new("consumer-a").unwrap()),
                    reservation_id: None,
                },
            ),
            (
                unbound,
                NegotiationEntry {
                    capabilities: vec!["events.replay.v1".into()],
                    consumer_key: None,
                    reservation_id: None,
                },
            ),
            (
                crossed,
                NegotiationEntry {
                    capabilities: vec!["events.replay.v1".into()],
                    consumer_key: Some(ConsumerKey::new("consumer-b").unwrap()),
                    reservation_id: None,
                },
            ),
        ]);
        let request = |token, candidate_session: SessionId| {
            Request::new(v1::SubscribeEventsRequest {
                metadata: Some(replay_metadata(token)),
                session_id: candidate_session.as_uuid().as_bytes().to_vec(),
                after_position: 0,
            })
        };

        let before_reservations: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM capacity_reservations")
                .fetch_one(store.pool())
                .await
                .unwrap();
        let mut hidden_failures = Vec::new();
        for (token, candidate_session) in [
            (unbound, session),
            (crossed, session),
            (bound, id(217, SessionId::from_uuid)),
        ] {
            let mut rejected =
                NavigatorConsumer::subscribe_events(&service, request(token, candidate_session))
                    .await
                    .unwrap()
                    .into_inner();
            let Some(v1::subscribe_events_response::Outcome::Failure(value)) =
                rejected.next().await.unwrap().unwrap().outcome
            else {
                panic!("unauthorized subscription passed admission")
            };
            assert_eq!(value.code, FailureCode::Authentication as i32);
            if token != unbound {
                hidden_failures.push(value);
            }
        }
        assert_eq!(hidden_failures.len(), 2);
        assert_eq!(hidden_failures[0], hidden_failures[1]);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM capacity_reservations")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            before_reservations
        );
        let mut fenced_stream =
            NavigatorConsumer::subscribe_events(&service, request(bound, session))
                .await
                .unwrap()
                .into_inner();
        assert!(matches!(
            fenced_stream.next().await.unwrap().unwrap().outcome,
            Some(v1::subscribe_events_response::Outcome::Failure(Failure { code, .. }))
                if code == FailureCode::StaleOwnership as i32
        ));
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one fixture preserves subscription disconnect and cursor ordering"
    )]
    async fn slow_subscription_disconnects_and_every_cursor_resumes_exclusively() {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("events.db"))
                .await
                .unwrap(),
        );
        let host = id(1, HostId::from_uuid);
        let session = id(2, SessionId::from_uuid);
        let consumer = ConsumerKey::new("durable-subscription").unwrap();
        store
            .open_session(OpenSession::new(
                context(3, host),
                session,
                consumer.clone(),
                CompatibilityIdentity::from_bytes([4; 32]),
            ))
            .await
            .unwrap();
        for ordinal in 0_u128..20 {
            let lease = store
                .acquire_ownership(AcquireOwnership::new(
                    context(10 + ordinal * 2, host),
                    session,
                    LeaseDuration::from_millis(1_000).unwrap(),
                ))
                .await
                .unwrap()
                .value()
                .clone();
            store
                .release_ownership(ReleaseOwnership::new(
                    context(11 + ordinal * 2, host),
                    session,
                    lease.epoch(),
                ))
                .await
                .unwrap();
        }

        let (sender, mut receiver) = mpsc::channel(EVENT_STREAM_QUEUE_CAPACITY);
        let subscriptions = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&subscriptions).try_acquire_owned().unwrap();
        let event_task = tokio::spawn(event_loop(
            store.clone(),
            sender,
            session,
            consumer.clone(),
            None,
            Arc::new(AtomicBool::new(false)),
            None,
            SubscriptionPermits {
                _global: permit,
                _session: None,
            },
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while receiver.capacity() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("subscription queue never reached its deterministic capacity barrier");
        let commit = store.acquire_ownership(AcquireOwnership::new(
            context(100, host),
            session,
            LeaseDuration::from_millis(1_000).unwrap(),
        ));
        tokio::time::timeout(Duration::from_secs(1), commit)
            .await
            .expect("full subscriber queue blocked an independent Store commit")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), event_task)
            .await
            .expect("slow subscriber retained its task and capacity permit")
            .unwrap();
        assert_eq!(subscriptions.available_permits(), 1);

        let mut buffered = Vec::new();
        while let Ok(response) = receiver.try_recv() {
            let Some(subscribe_events_response::Outcome::Event(event)) = response.unwrap().outcome
            else {
                panic!("slow subscriber received a non-Event item")
            };
            buffered.push(event);
        }
        assert!(
            receiver.recv().await.is_none(),
            "slow stream did not end with EOF"
        );
        assert_eq!(buffered.len(), EVENT_STREAM_QUEUE_CAPACITY);
        for (index, event) in buffered.iter().enumerate() {
            assert_eq!(event.position, u64::try_from(index + 1).unwrap());
        }
        assert_eq!(
            buffered
                .iter()
                .map(|event| event.event_id.clone())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            buffered.len(),
            "distinct durable facts shared an Event identity"
        );

        let all = store
            .read_events(ReadEvents {
                session_id: session,
                consumer: consumer.clone(),
                after: None,
                limit: EventReadLimit::new(EventReadLimit::MAX).unwrap(),
            })
            .await
            .unwrap();
        for boundary in 0..all.events.len() {
            let after = (boundary != 0).then(|| all.events[boundary - 1].position());
            let resumed = store
                .read_events(ReadEvents {
                    session_id: session,
                    consumer: consumer.clone(),
                    after,
                    limit: EventReadLimit::new(1).unwrap(),
                })
                .await
                .unwrap();
            assert_eq!(resumed.events.as_slice(), &all.events[boundary..=boundary]);
        }
        let at_head = store
            .read_events(ReadEvents {
                session_id: session,
                consumer: consumer.clone(),
                after: all.events.last().map(SessionEvent::position),
                limit: EventReadLimit::new(1).unwrap(),
            })
            .await
            .unwrap();
        assert!(at_head.events.is_empty());
        assert!(!at_head.has_more);
        let duplicate = store
            .read_events(ReadEvents {
                session_id: session,
                consumer,
                after: Some(all.events[30].position()),
                limit: EventReadLimit::new(1).unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(duplicate.events[0].id(), all.events[31].id());
    }
}

#[cfg(test)]
mod host_shutdown_tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use navigator_store_sqlite::SqliteStore;
    use tempfile::TempDir;
    use tokio::sync::{Notify, watch};

    use crate::SessionAdmissionProvider;

    use super::*;

    struct PumpDispatcher {
        calls: AtomicUsize,
        swept: Notify,
    }

    impl crate::SessionMailboxDispatcher for PumpDispatcher {
        fn sweep_with_permit(
            &self,
            permit: AdmissionPermit,
            _session_id: SessionId,
            _epoch: FencingEpoch,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<usize, navigator_core::ExecutorError>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                permit.check().map_err(|_| admission_error())?;
                self.calls.fetch_add(1, Ordering::AcqRel);
                self.swept.notify_one();
                Ok(0)
            })
        }
    }

    async fn pump_fixture(
        request: u128,
    ) -> (
        LocalNavigator<SqliteStore>,
        SessionId,
        FencingEpoch,
        Arc<PumpDispatcher>,
        TempDir,
    ) {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("pump.db"))
                .await
                .unwrap(),
        );
        let host = HostId::from_uuid(Uuid::from_u128(request)).unwrap();
        let session = SessionId::from_uuid(Uuid::from_u128(request + 1)).unwrap();
        open_recovery_session(&store, host, session, request + 2, "pump").await;
        let dispatcher = Arc::new(PumpDispatcher {
            calls: AtomicUsize::new(0),
            swept: Notify::new(),
        });
        let mut service =
            LocalNavigator::new(store, host, LeaseDuration::from_millis(30_000).unwrap());
        service.mailbox_dispatcher = Some(dispatcher.clone());
        let (epoch, _) = crate::RecoveryOwnershipInstaller::acquire_and_install(
            &service,
            session,
            RequestId::from_uuid(Uuid::from_u128(request + 3)).unwrap(),
        )
        .await
        .unwrap();
        (service, session, epoch, dispatcher, directory)
    }

    async fn wait_for_calls(dispatcher: &PumpDispatcher, expected: usize) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while dispatcher.calls.load(Ordering::Acquire) < expected {
                dispatcher.swept.notified().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mailbox_pump_wakes_immediately_and_periodic_sweep_recovers_missed_signal() {
        let (service, session, epoch, dispatcher, _directory) = pump_fixture(93_000).await;
        tokio::time::pause();
        service.start_mailbox_pump(session, epoch).await;
        wait_for_calls(&dispatcher, 1).await;
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert_eq!(dispatcher.calls.load(Ordering::Acquire), 1);

        service
            .mailbox_wakes
            .lock()
            .await
            .get(&session)
            .unwrap()
            .notify_one();
        wait_for_calls(&dispatcher, 2).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        wait_for_calls(&dispatcher, 3).await;
    }

    #[tokio::test]
    async fn mailbox_pump_spawn_failure_and_epoch_churn_leave_no_registry_entries() {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("spawn-failure.db"))
                .await
                .unwrap(),
        );
        let session = SessionId::from_uuid(Uuid::from_u128(94_001)).unwrap();
        let epoch = FencingEpoch::new(1).unwrap();
        let mut service = LocalNavigator::new(
            store,
            HostId::from_uuid(Uuid::from_u128(94_000)).unwrap(),
            LeaseDuration::from_millis(30_000).unwrap(),
        );
        service.mailbox_dispatcher = Some(Arc::new(PumpDispatcher {
            calls: AtomicUsize::new(0),
            swept: Notify::new(),
        }));
        service.background_tasks.close_admission().await;
        service.start_mailbox_pump(session, epoch).await;
        assert!(service.mailbox_pumps.lock().await.is_empty());
        assert!(service.mailbox_wakes.lock().await.is_empty());

        for ordinal in 0..8_u128 {
            let (churn, churn_session, churn_epoch, dispatcher, _directory) =
                pump_fixture(95_000 + ordinal * 10).await;
            churn.start_mailbox_pump(churn_session, churn_epoch).await;
            wait_for_calls(&dispatcher, 1).await;
            let stopped = churn.mailbox_pump_stopped.notified();
            tokio::pin!(stopped);
            stopped.as_mut().enable();
            let supervisor = churn
                .supervisors
                .lock()
                .await
                .remove(&churn_session)
                .unwrap();
            let _ = supervisor.shutdown_after_ownership_cleared().await;
            churn
                .mailbox_wakes
                .lock()
                .await
                .get(&churn_session)
                .unwrap()
                .notify_one();
            stopped.await;
            assert!(churn.mailbox_pumps.lock().await.is_empty());
            assert!(churn.mailbox_wakes.lock().await.is_empty());
        }
    }

    async fn open_recovery_session(
        store: &SqliteStore,
        host: HostId,
        session: SessionId,
        request: u128,
        consumer: &str,
    ) {
        store
            .open_session(OpenSession::new(
                RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
                    host,
                ),
                session,
                ConsumerKey::new(consumer).unwrap(),
                CompatibilityIdentity::from_bytes([7; 32]),
            ))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn recovery_ownership_isolated_by_session_and_request_replay_is_stable() {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("recovery-ownership.db"))
                .await
                .unwrap(),
        );
        let host = HostId::from_uuid(Uuid::from_u128(91_000)).unwrap();
        let first = SessionId::from_uuid(Uuid::from_u128(91_001)).unwrap();
        let second = SessionId::from_uuid(Uuid::from_u128(91_002)).unwrap();
        open_recovery_session(&store, host, first, 91_010, "recovery-first").await;
        open_recovery_session(&store, host, second, 91_011, "recovery-second").await;
        let service = LocalNavigator::new(store, host, LeaseDuration::from_millis(30_000).unwrap());
        let request_a = RequestId::from_uuid(Uuid::from_u128(91_020)).unwrap();
        let request_b = RequestId::from_uuid(Uuid::from_u128(91_021)).unwrap();
        let (left, right) = tokio::join!(
            crate::RecoveryOwnershipInstaller::acquire_and_install(&service, first, request_a),
            crate::RecoveryOwnershipInstaller::acquire_and_install(&service, second, request_b),
        );
        let (epoch_a, permit_a) = left.unwrap();
        let (epoch_b, permit_b) = right.unwrap();
        permit_a.check().unwrap();
        permit_b.check().unwrap();
        assert_eq!(service.supervisors.lock().await.len(), 2);
        let (replayed, replay_permit) =
            crate::RecoveryOwnershipInstaller::acquire_and_install(&service, first, request_a)
                .await
                .unwrap();
        assert_eq!(replayed, epoch_a);
        replay_permit.check().unwrap();
        assert_eq!(service.supervisors.lock().await.len(), 2);
        assert!(matches!(
            crate::RecoveryOwnershipInstaller::acquire_and_install(
                &service,
                first,
                RequestId::from_uuid(Uuid::from_u128(91_022)).unwrap(),
            )
            .await,
            Err(StoreError::OwnershipHeld { .. })
        ));
        assert_eq!(epoch_b.get(), 1);
    }

    #[tokio::test]
    async fn session_admission_is_exact_epoch_isolated_and_closed_fail_closed() {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("session-admission.db"))
                .await
                .unwrap(),
        );
        let host = HostId::from_uuid(Uuid::from_u128(92_000)).unwrap();
        let first = SessionId::from_uuid(Uuid::from_u128(92_001)).unwrap();
        let second = SessionId::from_uuid(Uuid::from_u128(92_002)).unwrap();
        open_recovery_session(&store, host, first, 92_010, "admission-first").await;
        open_recovery_session(&store, host, second, 92_011, "admission-second").await;
        let service = LocalNavigator::new(store, host, LeaseDuration::from_millis(30_000).unwrap());
        let (first_epoch, _) = crate::RecoveryOwnershipInstaller::acquire_and_install(
            &service,
            first,
            RequestId::from_uuid(Uuid::from_u128(92_020)).unwrap(),
        )
        .await
        .unwrap();
        let (second_epoch, _) = crate::RecoveryOwnershipInstaller::acquire_and_install(
            &service,
            second,
            RequestId::from_uuid(Uuid::from_u128(92_021)).unwrap(),
        )
        .await
        .unwrap();
        let provider = LocalSessionAdmissions {
            supervisors: Arc::downgrade(&service.supervisors),
        };
        provider
            .admit_current(first, first_epoch)
            .await
            .unwrap()
            .check()
            .unwrap();
        provider
            .admit_current(second, second_epoch)
            .await
            .unwrap()
            .check()
            .unwrap();
        assert!(
            provider
                .admit_current(first, FencingEpoch::new(first_epoch.get() + 1).unwrap())
                .await
                .is_err()
        );
        let first_supervisor = service.supervisors.lock().await.remove(&first).unwrap();
        let _ = first_supervisor.shutdown_after_ownership_cleared().await;
        assert!(provider.admit_current(first, first_epoch).await.is_err());
        provider
            .admit_current(second, second_epoch)
            .await
            .unwrap()
            .check()
            .unwrap();
    }

    #[test]
    fn close_fallback_requires_durable_cancellation_and_stopped_launches() {
        let confirmed = Ok(navigator_store_api::CancelSubtreeOutcome {
            root_participant_id: ParticipantId::from_uuid(Uuid::from_u128(92_100)).unwrap(),
            records: Vec::new(),
        });
        assert!(durable_cancellation_is_confirmed(&confirmed, &Ok(false)));
        assert!(!durable_cancellation_is_confirmed(&confirmed, &Ok(true)));
        assert!(!durable_cancellation_is_confirmed(
            &confirmed,
            &Err(StoreError::Unavailable)
        ));
        assert!(!durable_cancellation_is_confirmed(
            &Err(StoreError::Unavailable),
            &Ok(false)
        ));
    }

    #[test]
    fn reset_restores_only_the_exact_local_durable_owner() {
        let local = HostId::from_uuid(Uuid::from_u128(96_001)).unwrap();
        let foreign = HostId::from_uuid(Uuid::from_u128(96_002)).unwrap();
        let owned = |host_id| OwnershipSnapshot::Owned {
            host_id,
            epoch: FencingEpoch::new(7).unwrap(),
            expires_at: Timestamp::new(10_000, 0).unwrap(),
        };
        assert_eq!(
            reset_ownership_path(&owned(local), local),
            ResetOwnershipPath::RestoreLocal
        );
        assert_eq!(
            reset_ownership_path(&owned(foreign), local),
            ResetOwnershipPath::Recover
        );
        assert_eq!(
            reset_ownership_path(&OwnershipSnapshot::Unowned, local),
            ResetOwnershipPath::Recover
        );
    }

    struct BlockingCloseController {
        calls: AtomicUsize,
        entered: Notify,
    }

    #[tonic::async_trait]
    impl OperationController for BlockingCloseController {
        async fn start(
            &self,
            _permit: AdmissionPermit,
            _command: StartOperation,
        ) -> Result<OperationSnapshot, OperationControlError> {
            Err(OperationControlError::Unavailable)
        }

        async fn cancel_subtree(
            &self,
            _permit: AdmissionPermit,
            _command: CancelSubtree,
        ) -> Result<navigator_store_api::CancelSubtreeOutcome, OperationControlError> {
            Err(OperationControlError::Unavailable)
        }

        async fn cancel_session_until(
            &self,
            _permit: AdmissionPermit,
            command: CancelSubtree,
            _deadline: tokio::time::Instant,
        ) -> Result<navigator_store_api::CancelSubtreeOutcome, OperationControlError> {
            if self.calls.fetch_add(1, Ordering::AcqRel) == 0 {
                self.entered.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(navigator_store_api::CancelSubtreeOutcome {
                root_participant_id: command.root_participant_id,
                records: Vec::new(),
            })
        }

        async fn shutdown_until(
            &self,
            _deadline: tokio::time::Instant,
        ) -> Result<(), OperationControlError> {
            Ok(())
        }
    }

    fn close_test_template() -> v1::RootTemplateSpecification {
        v1::RootTemplateSpecification {
            template_id: Uuid::from_u128(96_020).as_bytes().to_vec(),
            role: "close-worker".into(),
            driver_id: Uuid::from_u128(96_021).as_bytes().to_vec(),
            required_capabilities: Vec::new(),
            trusted_configuration: Some(v1::TrustedTemplateConfiguration {
                base_instructions: "close deterministically".into(),
                secret_names: Vec::new(),
            }),
            resources: Some(v1::ParticipantResourceBounds {
                memory_bytes: 1 << 20,
                cpu_millis: 1_000,
                max_concurrent_operations: 1,
            }),
            input_schema: Some(v1::InputSchema { fields: Vec::new() }),
            authority_profile: None,
        }
    }

    #[tokio::test]
    async fn cancelled_close_remains_discoverable_and_exact_retry_closes() {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("close-serialization.db"))
                .await
                .unwrap(),
        );
        let host = HostId::from_uuid(Uuid::from_u128(96_010)).unwrap();
        let session = SessionId::from_uuid(Uuid::from_u128(96_011)).unwrap();
        let controller = Arc::new(BlockingCloseController {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
        });
        let service = LocalNavigator::new(
            Arc::clone(&store),
            host,
            LeaseDuration::from_millis(30_000).unwrap(),
        )
        .with_operation_controller(controller.clone());
        let negotiation = Uuid::from_u128(96_012);
        service.negotiations.write().unwrap().insert(
            negotiation,
            NegotiationEntry {
                capabilities: vec!["session.lifecycle.v1".into()],
                consumer_key: Some(ConsumerKey::new("close-cancellation").unwrap()),
                reservation_id: None,
            },
        );
        NavigatorConsumer::open_session(
            &service,
            Request::new(v1::OpenSessionRequest {
                metadata: Some(current_metadata(
                    negotiation.as_bytes().to_vec(),
                    &["session.lifecycle.v1"],
                )),
                request_id: Uuid::from_u128(96_013).as_bytes().to_vec(),
                session_id: session.as_uuid().as_bytes().to_vec(),
                consumer_key: "close-cancellation".into(),
                compatibility_identity: Vec::new(),
                root_template: Some(close_test_template()),
                compatible_templates: Vec::new(),
                configuration_identity: Vec::new(),
                mode: v1::SessionOpenMode::Unspecified.into(),
            }),
        )
        .await
        .unwrap();
        let close_request = RequestId::from_uuid(Uuid::from_u128(96_014)).unwrap();
        service
            .session_close_timeout_millis
            .store(1_000, Ordering::Release);
        let holder_service = service.clone();
        let holder =
            tokio::spawn(async move { holder_service.close_owned(close_request, session).await });
        controller.entered.notified().await;
        service
            .session_close_timeout_millis
            .store(10, Ordering::Release);
        let timed_out = service.close_owned(close_request, session).await;
        assert!(matches!(
            timed_out,
            close_session_response::Outcome::Failure(Failure {
                code,
                retry,
                ..
            }) if code == v1::FailureCode::CleanupRequired as i32
                && retry == v1::RetryClass::AfterReconciliation as i32
        ));
        holder.abort();
        let _ = holder.await;
        assert!(
            service.supervisors.lock().await.contains_key(&session),
            "cancellation made the exact ownership supervisor undiscoverable"
        );
        assert!(service.close_locks.lock().await.contains_key(&session));
        assert!(matches!(
            store.read_ownership(session).await.unwrap(),
            OwnershipSnapshot::Owned { host_id, .. } if host_id == host
        ));
        service
            .session_close_timeout_millis
            .store(1_000, Ordering::Release);
        let retried = service.close_owned(close_request, session).await;
        assert!(matches!(
            retried,
            close_session_response::Outcome::Snapshot(ref snapshot)
                if snapshot.status == v1::SessionStatus::Closed as i32
        ));
        assert_eq!(
            store.load_session(session).await.unwrap().status(),
            SessionStatus::Closed
        );
        assert!(!service.supervisors.lock().await.contains_key(&session));

        let unrelated = SessionId::from_uuid(Uuid::from_u128(96_015)).unwrap();
        drop(service.serialize_close(unrelated).await);
        assert!(
            !service.close_locks.lock().await.contains_key(&session),
            "dead per-Session lock was not pruned opportunistically"
        );
    }

    #[test]
    fn recovery_orchestration_ids_are_stable_and_action_separated() {
        let public = RequestId::from_uuid(Uuid::from_u128(92_001)).unwrap();
        let session = SessionId::from_uuid(Uuid::from_u128(92_002)).unwrap();
        let ownership = recovery_internal_id(b"navigator.resolve.ownership.v1", public, session);
        let classification =
            recovery_internal_id(b"navigator.resolve.classification.v1", public, session);
        assert_ne!(ownership, public);
        assert_ne!(classification, public);
        assert_ne!(ownership, classification);
        assert_eq!(
            ownership,
            recovery_internal_id(b"navigator.resolve.ownership.v1", public, session)
        );
        assert_ne!(
            ownership,
            recovery_internal_id(
                b"navigator.resolve.ownership.v1",
                RequestId::from_uuid(Uuid::from_u128(92_003)).unwrap(),
                session,
            )
        );
    }

    #[tokio::test]
    async fn unavailable_recovery_is_not_negotiated() {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("no-recovery.db"))
                .await
                .unwrap(),
        );
        let service = LocalNavigator::new(
            store,
            HostId::from_uuid(Uuid::from_u128(92_010)).unwrap(),
            LeaseDuration::from_millis(1_000).unwrap(),
        );
        let response = NavigatorConsumer::negotiate(
            &service,
            Request::new(v1::NegotiateRequest {
                minimum_version: Some(v1::ProtocolVersion { major: 1, minor: 0 }),
                maximum_version: Some(v1::ProtocolVersion { major: 1, minor: 0 }),
                capabilities: vec!["recovery.resolution.v1".into()],
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let Some(negotiate_response::Outcome::Negotiated(negotiated)) = response.outcome else {
            panic!("base daemon negotiation failed")
        };
        assert!(negotiated.capabilities.is_empty());
        assert_eq!(negotiated.configuration_identity.len(), 32);
        let configured = service.clone().with_runtime_configuration_identity([7; 32]);
        assert_ne!(
            service.configuration_identity(),
            configured.configuration_identity()
        );
    }

    struct Controller {
        calls: AtomicUsize,
        entered: Notify,
        block: bool,
    }

    #[tonic::async_trait]
    impl OperationController for Controller {
        async fn start(
            &self,
            _permit: AdmissionPermit,
            _command: StartOperation,
        ) -> Result<OperationSnapshot, OperationControlError> {
            Err(OperationControlError::Unavailable)
        }

        async fn cancel_subtree(
            &self,
            _permit: AdmissionPermit,
            _command: CancelSubtree,
        ) -> Result<navigator_store_api::CancelSubtreeOutcome, OperationControlError> {
            Err(OperationControlError::Unavailable)
        }

        async fn cancel_session_until(
            &self,
            _permit: AdmissionPermit,
            _command: CancelSubtree,
            _deadline: tokio::time::Instant,
        ) -> Result<navigator_store_api::CancelSubtreeOutcome, OperationControlError> {
            Err(OperationControlError::Unavailable)
        }

        async fn shutdown_until(
            &self,
            _deadline: tokio::time::Instant,
        ) -> Result<(), OperationControlError> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.entered.notify_one();
            if self.block {
                std::future::pending().await
            } else {
                Ok(())
            }
        }
    }

    struct Dropped(Arc<AtomicBool>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    async fn fixture(
        directory: &TempDir,
        controller: Arc<Controller>,
    ) -> (LocalNavigator<SqliteStore>, PathBuf, BootstrapCredential) {
        let store = Arc::new(
            SqliteStore::open(directory.path().join("shutdown.db"))
                .await
                .unwrap(),
        );
        let host = HostId::from_uuid(Uuid::from_u128(90_001)).unwrap();
        let service = LocalNavigator::new(store, host, LeaseDuration::from_millis(1_000).unwrap())
            .with_operation_controller(controller);
        (
            service,
            directory.path().join("navigator.sock"),
            BootstrapCredential::from_bytes(b"shutdown-test".to_vec()).unwrap(),
        )
    }

    async fn wait_for_socket(path: &Path) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn normal_host_shutdown_calls_hook_once_and_removes_owned_socket() {
        let directory = TempDir::new().unwrap();
        let controller = Arc::new(Controller {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            block: false,
        });
        let (service, socket, credential) = fixture(&directory, controller.clone()).await;
        let registry = service.background_tasks.clone();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve(
            service,
            credential,
            ServerConfig {
                socket_path: socket.clone(),
                shutdown_timeout: Duration::from_secs(1),
            },
            shutdown_rx,
        ));
        wait_for_socket(&socket).await;
        shutdown_tx.send(true).unwrap();
        shutdown_tx.send(true).unwrap();
        assert!(server.await.unwrap().is_ok());
        assert_eq!(controller.calls.load(Ordering::Acquire), 1);
        assert_eq!(registry.task_count().await, 0);
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn deadline_aborts_background_task_and_never_unlinks_replacement_inode() {
        let directory = TempDir::new().unwrap();
        let controller = Arc::new(Controller {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            block: true,
        });
        let (service, socket, credential) = fixture(&directory, controller.clone()).await;
        let registry = service.background_tasks.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let drop_observer = Arc::clone(&dropped);
        registry
            .spawn(async move {
                let _guard = Dropped(drop_observer);
                std::future::pending::<()>().await;
            })
            .await
            .unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve(
            service,
            credential,
            ServerConfig {
                socket_path: socket.clone(),
                shutdown_timeout: Duration::from_millis(50),
            },
            shutdown_rx,
        ));
        wait_for_socket(&socket).await;
        shutdown_tx.send(true).unwrap();
        controller.entered.notified().await;
        std::fs::remove_file(&socket).unwrap();
        std::fs::write(&socket, b"replacement").unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("host shutdown exceeded its bounded budget")
            .unwrap();
        assert!(matches!(result, Err(LocalError::CleanupRequired)));
        assert_eq!(controller.calls.load(Ordering::Acquire), 1);
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(registry.task_count().await, 0);
        assert_eq!(std::fs::read(&socket).unwrap(), b"replacement");
    }

    #[tokio::test]
    async fn stuck_transport_is_bounded_and_cannot_report_clean_shutdown() {
        let directory = TempDir::new().unwrap();
        let controller = Arc::new(Controller {
            calls: AtomicUsize::new(0),
            entered: Notify::new(),
            block: false,
        });
        let (service, socket, credential) = fixture(&directory, controller.clone()).await;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let server = tokio::spawn(serve(
            service,
            credential,
            ServerConfig {
                socket_path: socket.clone(),
                shutdown_timeout: Duration::from_millis(50),
            },
            shutdown_rx,
        ));
        wait_for_socket(&socket).await;
        let _connection = tokio::net::UnixStream::connect(&socket).await.unwrap();
        tokio::task::yield_now().await;
        shutdown_tx.send(true).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .expect("stuck transport escaped the host deadline")
            .unwrap();
        assert!(matches!(result, Err(LocalError::CleanupRequired)));
        assert_eq!(controller.calls.load(Ordering::Acquire), 1);
        assert!(!socket.exists());
    }
}
fn event_wire(value: &SessionEvent) -> v1::SessionEvent {
    v1::SessionEvent {
        event_id: value.id().as_uuid().as_bytes().to_vec(),
        session_id: value.session_id().as_uuid().as_bytes().to_vec(),
        position: value.position().get(),
        revision: value.revision().get(),
        event_type: value.event_type().as_str().to_owned(),
        schema_version: u32::from(value.schema_version().get()),
        related_request_id: value
            .related_request_id()
            .map(|id| id.as_uuid().as_bytes().to_vec()),
        data: value.data().as_slice().to_vec(),
        occurred_at: Some(timestamp_wire(value.occurred_at())),
    }
}

fn projection_view(value: i32) -> Result<ProjectionView, Failure> {
    match v1::ProjectionView::try_from(value) {
        Ok(v1::ProjectionView::SessionTree) => Ok(ProjectionView::SessionTree),
        Ok(v1::ProjectionView::ActiveWork) => Ok(ProjectionView::ActiveWork),
        Ok(v1::ProjectionView::Delivery) => Ok(ProjectionView::Delivery),
        Ok(v1::ProjectionView::Approval) => Ok(ProjectionView::Approval),
        Ok(v1::ProjectionView::Recovery) => Ok(ProjectionView::Recovery),
        Ok(v1::ProjectionView::Capacity) => Ok(ProjectionView::Capacity),
        Ok(v1::ProjectionView::Failure) => Ok(ProjectionView::Failure),
        _ => Err(validation_failure(ValidationError::InvalidEnum)),
    }
}

fn projection_page_wire(value: ProjectionPage) -> v1::ProjectionPage {
    v1::ProjectionPage {
        session_id: value.session_id.as_uuid().as_bytes().to_vec(),
        view: match value.view {
            ProjectionView::SessionTree => v1::ProjectionView::SessionTree,
            ProjectionView::ActiveWork => v1::ProjectionView::ActiveWork,
            ProjectionView::Delivery => v1::ProjectionView::Delivery,
            ProjectionView::Approval => v1::ProjectionView::Approval,
            ProjectionView::Recovery => v1::ProjectionView::Recovery,
            ProjectionView::Capacity => v1::ProjectionView::Capacity,
            ProjectionView::Failure => v1::ProjectionView::Failure,
        }
        .into(),
        generation: value.generation,
        checkpoint_position: value.checkpoint_position.map(EventPosition::get),
        source_head_position: value.source_head_position.map(EventPosition::get),
        items: value
            .items
            .into_iter()
            .map(|item| v1::ProjectionItem {
                key: item.key.as_str().to_owned(),
                redacted_json: item.data.as_slice().to_vec(),
            })
            .collect(),
        next_page_token: value
            .next_page_token
            .map_or_else(String::new, |token| token.as_str().to_owned()),
    }
}
fn timestamp_wire(value: navigator_domain::Timestamp) -> v1::Timestamp {
    v1::Timestamp {
        unix_seconds: value.unix_seconds(),
        nanoseconds: value.nanoseconds(),
    }
}

fn approval_wire(value: &ApprovalView) -> v1::ApprovalSnapshot {
    let request = &value.request;
    v1::ApprovalSnapshot {
        request: Some(v1::ApprovalRequestSnapshot {
            approval_id: request.id.as_uuid().as_bytes().to_vec(),
            session_id: request.session_id.as_uuid().as_bytes().to_vec(),
            requester_participant_id: request.requester_id.as_uuid().as_bytes().to_vec(),
            operation_id: request.operation_id.as_uuid().as_bytes().to_vec(),
            capability: request.capability.as_str().to_owned(),
            resource: request.resource.as_bytes().to_vec(),
            summary: request.summary.as_str().to_owned(),
            status: match request.status {
                ApprovalStatus::Pending => v1::ApprovalStatus::Pending as i32,
                ApprovalStatus::Granted => v1::ApprovalStatus::Granted as i32,
                ApprovalStatus::Consumed => v1::ApprovalStatus::Consumed as i32,
                ApprovalStatus::Denied => v1::ApprovalStatus::Denied as i32,
                ApprovalStatus::Expired => v1::ApprovalStatus::Expired as i32,
                ApprovalStatus::Revoked => v1::ApprovalStatus::Revoked as i32,
            },
            expires_at: Some(timestamp_wire(request.expires_at)),
            grant_id: request.grant_id.map(|id| id.as_uuid().as_bytes().to_vec()),
            decision_source: request
                .decision_source
                .map_or(v1::ApprovalDecisionSource::Unspecified as i32, |_| {
                    v1::ApprovalDecisionSource::TrustedConsumer as i32
                }),
            created_at: Some(timestamp_wire(request.created_at)),
            decided_at: request.decided_at.map(timestamp_wire),
            revision: request.revision.get(),
        }),
        grant: value.grant.as_ref().map(|grant| v1::ApprovalGrantSnapshot {
            grant_id: grant.id.as_uuid().as_bytes().to_vec(),
            approval_id: grant.request_id.as_uuid().as_bytes().to_vec(),
            session_id: grant.session_id.as_uuid().as_bytes().to_vec(),
            subject_participant_id: grant.subject_id.as_uuid().as_bytes().to_vec(),
            operation_id: grant.operation_id.as_uuid().as_bytes().to_vec(),
            capability: grant.capability.as_str().to_owned(),
            resource_hash: grant.resource_hash.as_bytes().to_vec(),
            issued_by: v1::ApprovalDecisionSource::TrustedConsumer as i32,
            max_uses: grant.max_uses,
            used_count: grant.used_count,
            expires_at: Some(timestamp_wire(grant.expires_at)),
            revoked_at: grant.revoked_at.map(timestamp_wire),
            created_at: Some(timestamp_wire(grant.created_at)),
            revision: grant.revision.get(),
        }),
    }
}

fn validation_failure(error: ValidationError) -> Failure {
    let code = match error {
        ValidationError::UnsupportedVersion | ValidationError::InvalidVersionRange => {
            FailureCode::UnsupportedVersion
        }
        ValidationError::InvalidCapability => FailureCode::UnsupportedCapability,
        _ => FailureCode::InvalidRequest,
    };
    failure(code, &error.to_string(), RetryClass::Never)
}
fn store_failure(error: &StoreError) -> Failure {
    let (code, retry) = match &error {
        StoreError::SessionNotFound { .. }
        | StoreError::TemplateNotFound { .. }
        | StoreError::ParticipantNotFound { .. }
        | StoreError::RootParticipantNotFound { .. }
        | StoreError::OperationNotFound { .. }
        | StoreError::ArtifactNotFound { .. } => (FailureCode::NotFound, RetryClass::Never),
        StoreError::StaleOwnership { .. } | StoreError::OwnershipExpired { .. } => {
            (FailureCode::StaleOwnership, RetryClass::AfterReconciliation)
        }
        StoreError::Busy | StoreError::Unavailable => (FailureCode::Unavailable, RetryClass::Safe),
        StoreError::Corrupt => (FailureCode::CorruptedState, RetryClass::Never),
        StoreError::SchemaTooNew { .. } => (FailureCode::Incompatible, RetryClass::Never),
        _ => (FailureCode::Conflict, RetryClass::Never),
    };
    failure(code, &error.to_string(), retry)
}

fn error_session_id(error: &StoreError) -> Option<SessionId> {
    match error {
        StoreError::SessionNotFound { session_id }
        | StoreError::SessionClosed { session_id }
        | StoreError::AlreadyClosed { session_id }
        | StoreError::CompatibilityConflict { session_id, .. }
        | StoreError::InterruptedSession { session_id }
        | StoreError::ConsumerConflict { session_id, .. }
        | StoreError::OwnershipExpired { session_id, .. }
        | StoreError::StaleOwnership { session_id, .. }
        | StoreError::RootParticipantNotFound { session_id } => Some(*session_id),
        StoreError::OwnershipHeld { ownership } => match ownership {
            navigator_domain::OwnershipSnapshot::Unowned
            | navigator_domain::OwnershipSnapshot::Owned { .. } => None,
        },
        _ => None,
    }
}
fn failure(code: FailureCode, message: &str, retry: RetryClass) -> Failure {
    Failure {
        code: code as i32,
        message: message.to_owned(),
        retry: retry as i32,
        related_id: None,
        details: Vec::new(),
    }
}

fn stale_ownership_failure() -> Failure {
    failure(
        FailureCode::StaleOwnership,
        "daemon does not own Session",
        RetryClass::AfterReconciliation,
    )
}

fn failure_stream(error: Failure) -> Response<EventStream> {
    let response = v1::SubscribeEventsResponse {
        outcome: Some(subscribe_events_response::Outcome::Failure(error)),
    };
    Response::new(Box::pin(tokio_stream::once(Ok(response))))
}

/// Rejects a socket pathname whose immediate directory is not an existing,
/// private directory. Daemon entry points can call this before opening any
/// durable state; [`serve`] checks it again at the bind boundary.
pub fn validate_socket_directory(path: &Path) -> Result<(), LocalError> {
    use std::os::unix::fs::PermissionsExt;

    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent_metadata = std::fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir() || parent_metadata.permissions().mode() & 0o022 != 0 {
        return Err(LocalError::UnsafeSocketDirectory);
    }
    Ok(())
}

fn prepare_socket(path: &Path) -> Result<(), LocalError> {
    use std::os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixStream,
    };

    validate_socket_directory(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if !metadata.file_type().is_socket() => Err(LocalError::UnsafeSocketPath),
        Ok(metadata) => match UnixStream::connect(path) {
            Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                let expected = (metadata.dev(), metadata.ino());
                let current = std::fs::symlink_metadata(path)?;
                if current.file_type().is_socket() && (current.dev(), current.ino()) == expected {
                    std::fs::remove_file(path)?;
                    Ok(())
                } else {
                    Err(LocalError::SocketInUse)
                }
            }
            Ok(_) | Err(_) => Err(LocalError::SocketInUse),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Binds and hardens a Unix socket before atomically publishing its public
/// pathname.  Consumers must never be able to observe the process umask's
/// transient mode between `bind(2)` and `chmod(2)`.
fn bind_private_socket(path: &Path) -> Result<UnixListener, LocalError> {
    prepare_socket(path)?;
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let nonce = random_uuid()?;
    let suffix = u32::from_be_bytes(nonce.as_bytes()[..4].try_into().expect("fixed UUID prefix"));
    let temporary = parent.join(format!(".n-{suffix:08x}"));
    let listener = UnixListener::bind(&temporary)?;
    if let Err(error) = private_permissions(&temporary) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error);
    }
    // `link(2)` is an atomic no-clobber publication: unlike rename, it cannot
    // replace a socket another daemon published after `prepare_socket`.
    if let Err(error) = std::fs::hard_link(&temporary, path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Err(error) = std::fs::remove_file(&temporary) {
        let _ = std::fs::remove_file(path);
        return Err(error.into());
    }
    Ok(listener)
}

fn private_permissions(path: &Path) -> Result<(), LocalError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(test)]
mod trusted_approval_boundary_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use navigator_store_sqlite::SqliteStore;
    use tempfile::TempDir;

    use super::*;

    struct CountingController(AtomicUsize);

    #[tonic::async_trait]
    impl ApprovalController for CountingController {
        async fn snapshot(
            &self,
            _: SessionId,
            _: ApprovalRequestId,
        ) -> Result<ApprovalView, StoreError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(StoreError::Unavailable)
        }
        async fn approve(
            &self,
            _: TrustedConsumerAuthority,
            _: ApproveRequest,
        ) -> Result<ApprovalView, StoreError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(StoreError::Unavailable)
        }
        async fn deny(
            &self,
            _: TrustedConsumerAuthority,
            _: DenyRequest,
        ) -> Result<ApprovalView, StoreError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(StoreError::Unavailable)
        }
        async fn revoke(
            &self,
            _: TrustedConsumerAuthority,
            _: RevokeApprovalGrant,
        ) -> Result<ApprovalView, StoreError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(StoreError::Unavailable)
        }
    }

    fn approval_request(
        negotiation: Uuid,
        session: SessionId,
        include_capability: bool,
    ) -> Request<v1::ApprovalSnapshotRequest> {
        let mut request = Request::new(v1::ApprovalSnapshotRequest {
            metadata: Some(current_metadata(
                negotiation.as_bytes().to_vec(),
                if include_capability {
                    &[CAPABILITY_APPROVALS_V1]
                } else {
                    &[]
                },
            )),
            session_id: session.as_uuid().as_bytes().to_vec(),
            approval_id: Uuid::from_u128(98_100).as_bytes().to_vec(),
        });
        request
            .extensions_mut()
            .insert(AuthenticatedTrustedConsumer);
        request
    }

    fn failure_code(response: v1::ApprovalSnapshotResponse) -> FailureCode {
        let Some(v1::approval_snapshot_response::Outcome::Failure(value)) = response.outcome else {
            panic!("negative Approval request unexpectedly reached controller")
        };
        FailureCode::try_from(value.code).unwrap()
    }

    #[tokio::test]
    async fn every_untrusted_or_misbound_approval_request_stops_before_controller_or_mutation() {
        let directory = TempDir::new().unwrap();
        let store = Arc::new(
            SqliteStore::open(directory.path().join("approval-boundary.db"))
                .await
                .unwrap(),
        );
        let host = HostId::from_uuid(Uuid::from_u128(98_001)).unwrap();
        let session = SessionId::from_uuid(Uuid::from_u128(98_002)).unwrap();
        store
            .open_session(OpenSession::new(
                RequestContext::new(RequestId::from_uuid(Uuid::from_u128(98_003)).unwrap(), host),
                session,
                ConsumerKey::new("trusted-a").unwrap(),
                CompatibilityIdentity::from_bytes([8; 32]),
            ))
            .await
            .unwrap();
        let calls = Arc::new(CountingController(AtomicUsize::new(0)));
        let mut service = LocalNavigator::new(
            Arc::clone(&store),
            host,
            LeaseDuration::from_millis(30_000).unwrap(),
        );
        service.approvals = Some(calls.clone());
        let bound = Uuid::from_u128(98_010);
        let unbound = Uuid::from_u128(98_011);
        let crossed = Uuid::from_u128(98_012);
        service.negotiations.write().unwrap().extend([
            (
                bound,
                NegotiationEntry {
                    capabilities: vec![CAPABILITY_APPROVALS_V1.into()],
                    consumer_key: Some(ConsumerKey::new("trusted-a").unwrap()),
                    reservation_id: None,
                },
            ),
            (
                unbound,
                NegotiationEntry {
                    capabilities: vec![CAPABILITY_APPROVALS_V1.into()],
                    consumer_key: None,
                    reservation_id: None,
                },
            ),
            (
                crossed,
                NegotiationEntry {
                    capabilities: vec![CAPABILITY_APPROVALS_V1.into()],
                    consumer_key: Some(ConsumerKey::new("trusted-b").unwrap()),
                    reservation_id: None,
                },
            ),
        ]);

        let mut no_marker = approval_request(bound, session, true);
        no_marker
            .extensions_mut()
            .remove::<AuthenticatedTrustedConsumer>();
        let cases = [
            (no_marker, FailureCode::Authentication),
            (
                approval_request(bound, session, false),
                FailureCode::UnsupportedCapability,
            ),
            (
                approval_request(unbound, session, true),
                FailureCode::Authentication,
            ),
            (
                approval_request(crossed, session, true),
                FailureCode::Authorization,
            ),
            (
                approval_request(Uuid::from_u128(98_099), session, true),
                FailureCode::UnsupportedVersion,
            ),
        ];
        for (request, expected) in cases {
            let response = NavigatorConsumer::approval_snapshot(&service, request)
                .await
                .unwrap()
                .into_inner();
            assert_eq!(failure_code(response), expected);
        }
        assert_eq!(calls.0.load(Ordering::SeqCst), 0);
        let mutations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM approval_mutations")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(mutations, 0);
    }
}

#[cfg(test)]
mod private_socket_tests {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    use tempfile::TempDir;

    use super::*;

    #[tokio::test]
    async fn socket_is_private_at_its_first_publicly_observable_path() {
        let directory = TempDir::new().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("navigator.sock");

        let listener = bind_private_socket(&path).unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        std::os::unix::net::UnixStream::connect(&path).unwrap();

        drop(listener);
        std::fs::remove_file(path).unwrap();
    }
}

#[derive(Clone, Copy)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

fn socket_identity(path: &Path) -> Result<SocketIdentity, LocalError> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(LocalError::UnsafeSocketPath);
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

struct Cleanup {
    path: PathBuf,
    identity: SocketIdentity,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if socket_identity(&self.path).is_ok_and(|current| {
            current.device == self.identity.device && current.inode == self.identity.inode
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
fn random_uuid() -> io::Result<Uuid> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

#[cfg(test)]
mod artifact_rpc_tests {
    use std::{
        os::unix::fs::PermissionsExt,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use navigator_consumer_protocol::{ArtifactReadStreamValidator, CAPABILITY_ARTIFACTS_V1, v1};
    use navigator_domain::{InputSchema, MessageId, OperationId, RequestId};
    use navigator_store_api::{LeaseDuration, OperationStore, RequestContext, StartOperation};
    use navigator_store_sqlite::SqliteStore;
    use sha2::{Digest, Sha256};
    use sqlx::{AssertSqlSafe, Row};
    use tempfile::TempDir;
    use tokio::sync::watch;
    use tonic::{Request, metadata::MetadataValue, transport::Endpoint};

    use super::*;

    struct SnapshotReadGuard {
        inner: Arc<crate::LocalArtifactStore<SqliteStore>>,
        reject_read: Arc<AtomicBool>,
        mutate_read: Arc<AtomicBool>,
    }

    #[tonic::async_trait]
    impl ArtifactController for SnapshotReadGuard {
        async fn write(
            &self,
            request: crate::ArtifactWrite,
            content: ArtifactContent,
        ) -> Result<ArtifactSnapshot, ArtifactControlError> {
            self.inner
                .write(request, content)
                .await
                .map_err(artifact_local_error)
        }

        async fn read(
            &self,
            access: ArtifactAccess,
        ) -> Result<(ArtifactSnapshot, ArtifactContent), ArtifactControlError> {
            assert!(
                !self.reject_read.load(Ordering::SeqCst),
                "snapshot RPC must not open artifact content"
            );
            if self.mutate_read.load(Ordering::SeqCst) {
                let snapshot = self
                    .inner
                    .snapshot(access)
                    .await
                    .map_err(artifact_local_error)?;
                let mut content = vec![0x5a; usize::try_from(snapshot.size).unwrap()];
                *content.last_mut().unwrap() ^= 1;
                return Ok((snapshot, Box::pin(std::io::Cursor::new(content))));
            }
            self.inner
                .open_verified(access)
                .await
                .map(|(snapshot, file)| (snapshot, Box::pin(file) as ArtifactContent))
                .map_err(artifact_local_error)
        }

        async fn snapshot(
            &self,
            access: ArtifactAccess,
        ) -> Result<ArtifactSnapshot, ArtifactControlError> {
            self.inner
                .snapshot(access)
                .await
                .map_err(artifact_local_error)
        }

        async fn logically_delete(
            &self,
            request: DeleteArtifact,
        ) -> Result<ArtifactSnapshot, ArtifactControlError> {
            self.inner
                .logically_delete(request)
                .await
                .map_err(artifact_local_error)
        }
    }

    fn wire_id(value: u128) -> Vec<u8> {
        Uuid::from_u128(value).as_bytes().to_vec()
    }

    fn root_template() -> v1::RootTemplateSpecification {
        v1::RootTemplateSpecification {
            template_id: wire_id(70_010),
            role: "artifact-worker".into(),
            driver_id: wire_id(70_011),
            required_capabilities: vec![v1::DriverCapabilityRequirement {
                capability: "durable.acceptance".into(),
                minimum_version: 1,
                parameters: Vec::new(),
            }],
            trusted_configuration: Some(v1::TrustedTemplateConfiguration {
                base_instructions: "produce an artifact".into(),
                secret_names: Vec::new(),
            }),
            resources: Some(v1::ParticipantResourceBounds {
                memory_bytes: 1 << 20,
                cpu_millis: 1_000,
                max_concurrent_operations: 1,
            }),
            input_schema: Some(v1::InputSchema { fields: Vec::new() }),
            authority_profile: None,
        }
    }

    fn authenticated<T>(value: T) -> Request<T> {
        let mut request = Request::new(value);
        request.metadata_mut().insert(
            AUTHENTICATION_HEADER,
            MetadataValue::try_from("artifact-rpc-test").unwrap(),
        );
        request
    }

    fn metadata(negotiation: Uuid, capability: &str) -> v1::RequestMetadata {
        current_metadata(negotiation.as_bytes().to_vec(), &[capability])
    }

    async fn wait_for_socket(path: &Path) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !path.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[expect(
        clippy::too_many_lines,
        reason = "real RPC fixture is intentionally explicit"
    )]
    async fn fixture() -> (
        TempDir,
        Arc<SqliteStore>,
        PathBuf,
        PathBuf,
        watch::Sender<bool>,
        tokio::task::JoinHandle<Result<(), LocalError>>,
        Uuid,
        Uuid,
        Uuid,
        Uuid,
        Arc<AtomicBool>,
        Arc<AtomicBool>,
    ) {
        let directory = TempDir::new().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let database = directory.path().join("artifact-rpc.db");
        let artifact_root = directory.path().join("artifacts");
        let socket = directory.path().join("navigator.sock");
        let store = Arc::new(SqliteStore::open(database).await.unwrap());
        let host = HostId::from_uuid(Uuid::from_u128(70_001)).unwrap();
        let artifacts =
            Arc::new(crate::LocalArtifactStore::new(store.clone(), &artifact_root).unwrap());
        let reject_read = Arc::new(AtomicBool::new(false));
        let mutate_read = Arc::new(AtomicBool::new(false));
        let mut service = LocalNavigator::new(
            store.clone(),
            host,
            LeaseDuration::from_millis(60_000).unwrap(),
        )
        .with_artifact_controller(Arc::new(SnapshotReadGuard {
            inner: artifacts,
            reject_read: reject_read.clone(),
            mutate_read: mutate_read.clone(),
        }));
        service.projections = Some(Arc::new(StoreProjectionController(store.clone())));
        let negotiation = Uuid::from_u128(70_002);
        service.negotiations.write().unwrap().insert(
            negotiation,
            NegotiationEntry {
                capabilities: vec![
                    "session.lifecycle.v1".into(),
                    "events.replay.v1".into(),
                    CAPABILITY_ARTIFACTS_V1.into(),
                    CAPABILITY_OPERATIONAL_PROJECTIONS_V1.into(),
                ],
                consumer_key: Some(ConsumerKey::new("artifact-rpc").unwrap()),
                reservation_id: None,
            },
        );
        service.negotiations.write().unwrap().insert(
            Uuid::from_u128(70_202),
            NegotiationEntry {
                capabilities: vec![CAPABILITY_OPERATIONAL_PROJECTIONS_V1.into()],
                consumer_key: Some(ConsumerKey::new("foreign-consumer").unwrap()),
                reservation_id: None,
            },
        );
        let session = Uuid::from_u128(70_003);
        let open = NavigatorConsumer::open_session(
            &service,
            Request::new(v1::OpenSessionRequest {
                metadata: Some(metadata(negotiation, "session.lifecycle.v1")),
                request_id: wire_id(70_004),
                session_id: session.as_bytes().to_vec(),
                consumer_key: "artifact-rpc".into(),
                compatibility_identity: Vec::new(),
                root_template: Some(root_template()),
                compatible_templates: Vec::new(),
                configuration_identity: Vec::new(),
                mode: v1::SessionOpenMode::Unspecified.into(),
            }),
        )
        .await
        .unwrap()
        .into_inner();
        let Some(v1::open_session_response::Outcome::Snapshot(snapshot)) = open.outcome else {
            panic!("artifact fixture Session did not open")
        };
        let participant = Uuid::from_slice(&snapshot.root_participant_id).unwrap();
        let session_id = SessionId::from_uuid(session).unwrap();
        let OwnershipStatus::Active { epoch, .. } = service
            .supervisors
            .lock()
            .await
            .get(&session_id)
            .unwrap()
            .status()
        else {
            panic!("fixture ownership inactive");
        };
        let operation = Uuid::from_u128(70_005);
        store
            .start_operation(StartOperation {
                context: RequestContext::new(
                    RequestId::from_uuid(Uuid::from_u128(70_006)).unwrap(),
                    host,
                ),
                session_id,
                epoch,
                operation_id: OperationId::from_uuid(operation).unwrap(),
                participant_id: ParticipantId::from_uuid(participant).unwrap(),
                input_message_id: MessageId::from_uuid(Uuid::from_u128(70_007)).unwrap(),
                input: InputSchema::new(Vec::new())
                    .unwrap()
                    .validate(b"{}")
                    .unwrap(),
            })
            .await
            .unwrap();
        let (shutdown, receiver) = watch::channel(false);
        let server = tokio::spawn(serve(
            service,
            BootstrapCredential::from_bytes(b"artifact-rpc-test".to_vec()).unwrap(),
            ServerConfig {
                socket_path: socket.clone(),
                shutdown_timeout: Duration::from_secs(2),
            },
            receiver,
        ));
        wait_for_socket(&socket).await;
        (
            directory,
            store,
            artifact_root,
            socket,
            shutdown,
            server,
            negotiation,
            session,
            participant,
            operation,
            reject_read,
            mutate_read,
        )
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one end-to-end stream lifecycle keeps the causal fixture visible"
    )]
    async fn real_rpc_streams_artifact_and_reports_corruption_delete_partial_and_oversize() {
        let (
            _directory,
            _store,
            root,
            socket,
            shutdown,
            server,
            negotiation,
            session,
            participant,
            operation,
            reject_read,
            mutate_read,
        ) = fixture().await;
        let channel = Endpoint::from_shared(format!("unix:{}", socket.display()))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = v1::navigator_consumer_client::NavigatorConsumerClient::new(channel)
            .max_decoding_message_size(MAX_REQUEST_BYTES)
            .max_encoding_message_size(MAX_REQUEST_BYTES);
        let artifact = Uuid::from_u128(70_020);
        let content = vec![0x5a; MAX_ARTIFACT_CHUNK_BYTES * 10 + 17];
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let begin = v1::WriteArtifactRequest {
            frame: Some(v1::write_artifact_request::Frame::Begin(
                v1::BeginArtifactWrite {
                    metadata: Some(metadata(negotiation, CAPABILITY_ARTIFACTS_V1)),
                    request_id: wire_id(70_021),
                    session_id: session.as_bytes().to_vec(),
                    artifact_id: artifact.as_bytes().to_vec(),
                    media_type: "application/octet-stream".into(),
                    declared_size: content.len() as u64,
                    declared_sha256: digest.to_vec(),
                    retain_until: Some(v1::Timestamp {
                        unix_seconds: 4_000_000_000,
                        nanoseconds: 0,
                    }),
                    authority_grant_id: Vec::new(),
                    creator_participant_id: participant.as_bytes().to_vec(),
                    creator_operation_id: operation.as_bytes().to_vec(),
                },
            )),
        };
        let mut frames = vec![begin];
        for (index, chunk) in content.chunks(MAX_ARTIFACT_CHUNK_BYTES).enumerate() {
            frames.push(v1::WriteArtifactRequest {
                frame: Some(v1::write_artifact_request::Frame::Chunk(
                    v1::ArtifactChunk {
                        artifact_id: artifact.as_bytes().to_vec(),
                        offset: (index * MAX_ARTIFACT_CHUNK_BYTES) as u64,
                        content: chunk.to_vec(),
                    },
                )),
            });
        }
        let written = client
            .write_artifact(authenticated(tokio_stream::iter(frames)))
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(
            written.outcome,
            Some(v1::write_artifact_response::Outcome::Artifact(_))
        ));

        let read_request = v1::ReadArtifactRequest {
            metadata: Some(metadata(negotiation, CAPABILITY_ARTIFACTS_V1)),
            session_id: session.as_bytes().to_vec(),
            artifact_id: artifact.as_bytes().to_vec(),
            offset: 0,
            length: None,
            authority_grant_id: Vec::new(),
        };
        let mut stream = client
            .read_artifact(authenticated(read_request.clone()))
            .await
            .unwrap()
            .into_inner();
        let mut received = Vec::new();
        while let Some(frame) = stream.message().await.unwrap() {
            if let Some(v1::read_artifact_response::Outcome::Chunk(chunk)) = frame.outcome {
                received.extend(chunk.content);
            }
        }
        assert_eq!(received, content);

        mutate_read.store(true, Ordering::SeqCst);
        let mut changed = client
            .read_artifact(authenticated(read_request.clone()))
            .await
            .unwrap()
            .into_inner();
        let mut validator = ArtifactReadStreamValidator::default();
        let mut saw_chunk = false;
        while let Some(frame) = changed.message().await.unwrap() {
            saw_chunk |= matches!(
                &frame.outcome,
                Some(v1::read_artifact_response::Outcome::Chunk(_))
            );
            validator.accept(&frame).unwrap();
        }
        validator.finish().unwrap();
        assert!(saw_chunk);
        assert!(!validator.completed_successfully());
        mutate_read.store(false, Ordering::SeqCst);

        reject_read.store(true, Ordering::SeqCst);
        let snapshot = client
            .artifact_snapshot(authenticated(v1::ArtifactSnapshotRequest {
                metadata: Some(metadata(negotiation, CAPABILITY_ARTIFACTS_V1)),
                session_id: session.as_bytes().to_vec(),
                artifact_id: artifact.as_bytes().to_vec(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            matches!(snapshot.outcome, Some(v1::artifact_snapshot_response::Outcome::Artifact(v1::ArtifactSnapshot { size, .. })) if size == content.len() as u64)
        );
        reject_read.store(false, Ordering::SeqCst);

        let path = root
            .join(session.to_string())
            .join(format!("{artifact}.blob"));
        std::fs::write(&path, b"corrupt").unwrap();
        let mut corrupt = client
            .read_artifact(authenticated(read_request.clone()))
            .await
            .unwrap()
            .into_inner();
        let first = corrupt.message().await.unwrap().unwrap();
        assert!(
            matches!(first.outcome, Some(v1::read_artifact_response::Outcome::Failure(Failure { code, .. })) if code == FailureCode::CorruptedState as i32)
        );
        std::fs::write(&path, &content).unwrap();

        std::fs::remove_file(&path).unwrap();
        let mut removed = client
            .read_artifact(authenticated(read_request.clone()))
            .await
            .unwrap()
            .into_inner();
        let first = removed.message().await.unwrap().unwrap();
        assert!(matches!(
            first.outcome,
            Some(v1::read_artifact_response::Outcome::Failure(_))
        ));
        std::fs::write(&path, &content).unwrap();

        let deleted = client
            .delete_artifact(authenticated(v1::DeleteArtifactRequest {
                metadata: Some(metadata(negotiation, CAPABILITY_ARTIFACTS_V1)),
                request_id: wire_id(70_022),
                session_id: session.as_bytes().to_vec(),
                artifact_id: artifact.as_bytes().to_vec(),
                authority_grant_id: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            matches!(deleted.outcome, Some(v1::delete_artifact_response::Outcome::Artifact(v1::ArtifactSnapshot { status, .. })) if status == v1::ArtifactStatus::LogicallyDeleted as i32)
        );

        let partial_id = Uuid::from_u128(70_030);
        let partial = vec![
            v1::WriteArtifactRequest {
                frame: Some(v1::write_artifact_request::Frame::Begin(
                    v1::BeginArtifactWrite {
                        metadata: Some(metadata(negotiation, CAPABILITY_ARTIFACTS_V1)),
                        request_id: wire_id(70_031),
                        session_id: session.as_bytes().to_vec(),
                        artifact_id: partial_id.as_bytes().to_vec(),
                        media_type: "text/plain".into(),
                        declared_size: 3,
                        declared_sha256: Sha256::digest(b"abc").to_vec(),
                        retain_until: Some(v1::Timestamp {
                            unix_seconds: 4_000_000_000,
                            nanoseconds: 0,
                        }),
                        authority_grant_id: Vec::new(),
                        creator_participant_id: participant.as_bytes().to_vec(),
                        creator_operation_id: operation.as_bytes().to_vec(),
                    },
                )),
            },
            v1::WriteArtifactRequest {
                frame: Some(v1::write_artifact_request::Frame::Chunk(
                    v1::ArtifactChunk {
                        artifact_id: partial_id.as_bytes().to_vec(),
                        offset: 0,
                        content: b"ab".to_vec(),
                    },
                )),
            },
        ];
        let partial = client
            .write_artifact(authenticated(tokio_stream::iter(partial)))
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(
            partial.outcome,
            Some(v1::write_artifact_response::Outcome::Failure(_))
        ));

        let oversize = v1::WriteArtifactRequest {
            frame: Some(v1::write_artifact_request::Frame::Begin(
                v1::BeginArtifactWrite {
                    metadata: Some(metadata(negotiation, CAPABILITY_ARTIFACTS_V1)),
                    request_id: wire_id(70_041),
                    session_id: session.as_bytes().to_vec(),
                    artifact_id: wire_id(70_040),
                    media_type: "text/plain".into(),
                    declared_size: navigator_domain::MAX_ARTIFACT_BYTES + 1,
                    declared_sha256: vec![1; 32],
                    retain_until: Some(v1::Timestamp {
                        unix_seconds: 4_000_000_000,
                        nanoseconds: 0,
                    }),
                    authority_grant_id: Vec::new(),
                    creator_participant_id: participant.as_bytes().to_vec(),
                    creator_operation_id: operation.as_bytes().to_vec(),
                },
            )),
        };
        let oversize = client
            .write_artifact(authenticated(tokio_stream::iter([oversize])))
            .await
            .unwrap()
            .into_inner();
        assert!(
            matches!(oversize.outcome, Some(v1::write_artifact_response::Outcome::Failure(Failure { code, .. })) if code == FailureCode::InvalidRequest as i32)
        );

        shutdown.send(true).unwrap();
        assert!(server.await.unwrap().is_ok());
    }

    async fn inspector_domain_fingerprint(store: &SqliteStore) -> Vec<(String, [u8; 32])> {
        let tables: Vec<(String, String)> = sqlx::query_as(
            "SELECT name,sql FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='_sqlx_migrations' ORDER BY name",
        )
        .fetch_all(store.pool())
        .await
        .unwrap();
        let mut result = Vec::with_capacity(tables.len());
        for (table, schema) in tables {
            assert!(
                table
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "sqlite_schema supplied an unsafe table identifier"
            );
            let columns = sqlx::query("SELECT name FROM pragma_table_info(?) ORDER BY cid")
                .bind(&table)
                .fetch_all(store.pool())
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.try_get::<String, _>("name").unwrap())
                .collect::<Vec<_>>();
            assert!(!columns.is_empty(), "mutable table has no columns");
            assert!(columns.iter().all(|column| {
                column
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            }));
            let quoted = columns
                .iter()
                .map(|column| format!("quote(\"{column}\")"))
                .collect::<Vec<_>>()
                .join("||x'1f'||");
            let ordering = columns
                .iter()
                .map(|column| format!("\"{column}\""))
                .collect::<Vec<_>>()
                .join(",");
            let query = format!("SELECT {quoted} FROM \"{table}\" ORDER BY {ordering}");
            let rows: Vec<String> = sqlx::query_scalar(AssertSqlSafe(query.as_str()))
                .fetch_all(store.pool())
                .await
                .unwrap();
            let mut digest = Sha256::new();
            digest.update(schema.as_bytes());
            for row in rows {
                digest.update(row.len().to_be_bytes());
                digest.update(row.as_bytes());
            }
            result.push((table, digest.finalize().into()));
        }
        result
    }

    #[tokio::test]
    async fn inspector_fingerprint_detects_a_mutant_in_every_mutable_table() {
        let directory = TempDir::new().unwrap();
        let store = SqliteStore::open(directory.path().join("fingerprint-mutants.db"))
            .await
            .unwrap();
        let baseline = inspector_domain_fingerprint(&store).await;

        for (table, _) in &baseline {
            let add =
                format!("ALTER TABLE \"{table}\" ADD COLUMN inspector_fingerprint_mutant INTEGER");
            sqlx::query(AssertSqlSafe(add.as_str()))
                .execute(store.pool())
                .await
                .unwrap_or_else(|error| panic!("failed to mutate {table}: {error}"));
            let mutated = inspector_domain_fingerprint(&store).await;
            let changed = baseline
                .iter()
                .zip(&mutated)
                .filter(|(before, after)| before != after)
                .map(|((name, _), _)| name.as_str())
                .collect::<Vec<_>>();
            assert_eq!(changed, [table.as_str()], "mutant coverage drifted");

            let drop = format!("ALTER TABLE \"{table}\" DROP COLUMN inspector_fingerprint_mutant");
            sqlx::query(AssertSqlSafe(drop.as_str()))
                .execute(store.pool())
                .await
                .unwrap_or_else(|error| panic!("failed to restore {table}: {error}"));
            assert_eq!(inspector_domain_fingerprint(&store).await, baseline);
        }
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "the real RPC mutation oracle is intentionally explicit"
    )]
    async fn inspector_rpc_is_read_only_bounded_and_resumes_after_reconnect() {
        use navigator_store_api::ProjectionStore;

        let (
            _directory,
            store,
            _root,
            socket,
            shutdown,
            server,
            bound_negotiation,
            session,
            participant,
            _operation,
            _reject_read,
            _mutate_read,
        ) = fixture().await;
        let _ = participant;
        store
            .rebuild_projection(SessionId::from_uuid(session).unwrap())
            .await
            .unwrap();
        let generation: i64 =
            sqlx::query_scalar("SELECT generation FROM projection_heads WHERE session_id=?")
                .bind(session.to_string())
                .fetch_one(store.pool())
                .await
                .unwrap();
        // A second valid, redacted row makes the opaque pagination cursor
        // observable without creating additional domain state after baseline.
        sqlx::query("INSERT INTO projection_rows(session_id,generation,view,item_key,sort_key,data) VALUES(?,?,'session_tree','test-resume-row','zz-test-resume-row',?)")
            .bind(session.to_string())
            .bind(generation)
            .bind(br#"{\"kind\":\"test_resume\"}"#.as_slice())
            .execute(store.pool())
            .await
            .unwrap();
        let before_ledger: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let before_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let before_head: (i64, i64, i64) = sqlx::query_as(
            "SELECT generation,checkpoint_position,source_head_position FROM projection_heads WHERE session_id=?",
        )
        .bind(session.to_string())
        .fetch_one(store.pool())
        .await
        .unwrap();
        let before_counts: (i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM sessions),(SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM request_ledger),(SELECT COUNT(*) FROM messages),(SELECT COUNT(*) FROM mailbox_counters),(SELECT COUNT(*) FROM projection_generations),(SELECT COUNT(*) FROM projection_rows),(SELECT COUNT(*) FROM projection_heads),(SELECT COUNT(*) FROM projection_progress)",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        let before_persisted = inspector_domain_fingerprint(&store).await;

        let connect = || async {
            let channel = Endpoint::from_shared(format!("unix:{}", socket.display()))
                .unwrap()
                .connect()
                .await
                .unwrap();
            v1::navigator_consumer_client::NavigatorConsumerClient::new(channel)
        };
        let mut client = connect().await;
        let negotiated = client
            .negotiate(authenticated(v1::NegotiateRequest {
                minimum_version: Some(v1::ProtocolVersion { major: 1, minor: 2 }),
                maximum_version: Some(v1::ProtocolVersion { major: 1, minor: 2 }),
                capabilities: vec![CAPABILITY_OPERATIONAL_PROJECTIONS_V1.into()],
            }))
            .await
            .unwrap()
            .into_inner();
        let Some(negotiate_response::Outcome::Negotiated(negotiated)) = negotiated.outcome else {
            panic!("inspector capability did not negotiate");
        };
        let inspector_negotiation = Uuid::from_slice(&negotiated.negotiation_id).unwrap();
        let unbound = client
            .read_projection(authenticated(v1::ReadProjectionRequest {
                metadata: Some(metadata(
                    inspector_negotiation,
                    CAPABILITY_OPERATIONAL_PROJECTIONS_V1,
                )),
                session_id: session.as_bytes().to_vec(),
                view: v1::ProjectionView::SessionTree.into(),
                page_size: 1,
                page_token: String::new(),
                consumer_key: "artifact-rpc".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            matches!(unbound.outcome, Some(v1::read_projection_response::Outcome::Failure(Failure { code, .. })) if code == FailureCode::Authentication as i32)
        );
        let views = [
            v1::ProjectionView::SessionTree,
            v1::ProjectionView::ActiveWork,
            v1::ProjectionView::Delivery,
            v1::ProjectionView::Approval,
            v1::ProjectionView::Recovery,
            v1::ProjectionView::Capacity,
            v1::ProjectionView::Failure,
        ];
        let mut resumed = false;
        for view in views {
            let first = tokio::time::timeout(
                Duration::from_secs(1),
                client.read_projection(authenticated(v1::ReadProjectionRequest {
                    metadata: Some(metadata(
                        bound_negotiation,
                        CAPABILITY_OPERATIONAL_PROJECTIONS_V1,
                    )),
                    session_id: session.as_bytes().to_vec(),
                    view: view.into(),
                    page_size: 1,
                    page_token: String::new(),
                    consumer_key: "artifact-rpc".into(),
                })),
            )
            .await
            .expect("bounded projection read timed out")
            .unwrap()
            .into_inner();
            let Some(v1::read_projection_response::Outcome::Page(first)) = first.outcome else {
                panic!("projection read failed");
            };
            assert!(first.items.len() <= 1);
            if !first.next_page_token.is_empty() && !resumed {
                drop(client);
                client = connect().await;
                let resumed_page = client
                    .read_projection(authenticated(v1::ReadProjectionRequest {
                        metadata: Some(metadata(
                            bound_negotiation,
                            CAPABILITY_OPERATIONAL_PROJECTIONS_V1,
                        )),
                        session_id: session.as_bytes().to_vec(),
                        view: view.into(),
                        page_size: 1,
                        page_token: first.next_page_token,
                        consumer_key: "artifact-rpc".into(),
                    }))
                    .await
                    .unwrap()
                    .into_inner();
                assert!(matches!(
                    resumed_page.outcome,
                    Some(v1::read_projection_response::Outcome::Page(_))
                ));
                resumed = true;
            }
        }
        assert!(resumed, "fixture must exercise an opaque resume token");

        let omitted = client
            .read_projection(authenticated(v1::ReadProjectionRequest {
                metadata: Some(metadata(bound_negotiation, "session.lifecycle.v1")),
                session_id: session.as_bytes().to_vec(),
                view: v1::ProjectionView::SessionTree.into(),
                page_size: 1,
                page_token: String::new(),
                consumer_key: "artifact-rpc".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            matches!(omitted.outcome, Some(v1::read_projection_response::Outcome::Failure(Failure { code, .. })) if code == FailureCode::UnsupportedCapability as i32)
        );
        let mut forged = Request::new(v1::ReadProjectionRequest {
            metadata: Some(metadata(
                bound_negotiation,
                CAPABILITY_OPERATIONAL_PROJECTIONS_V1,
            )),
            session_id: session.as_bytes().to_vec(),
            view: v1::ProjectionView::SessionTree.into(),
            page_size: 1,
            page_token: String::new(),
            consumer_key: "artifact-rpc".into(),
        });
        forged.metadata_mut().insert(
            AUTHENTICATION_HEADER,
            MetadataValue::try_from("forged-bootstrap").unwrap(),
        );
        assert_eq!(
            client.read_projection(forged).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        for (candidate_session, consumer) in [
            (session, "foreign-consumer"),
            (Uuid::from_u128(70_999), "artifact-rpc"),
        ] {
            let response = client
                .read_projection(authenticated(v1::ReadProjectionRequest {
                    metadata: Some(metadata(
                        bound_negotiation,
                        CAPABILITY_OPERATIONAL_PROJECTIONS_V1,
                    )),
                    session_id: candidate_session.as_bytes().to_vec(),
                    view: v1::ProjectionView::SessionTree.into(),
                    page_size: 1,
                    page_token: String::new(),
                    consumer_key: consumer.into(),
                }))
                .await
                .unwrap()
                .into_inner();
            assert!(
                matches!(response.outcome, Some(v1::read_projection_response::Outcome::Failure(Failure { code, .. })) if code == FailureCode::Authentication as i32)
            );
        }
        let cross_token = client
            .read_projection(authenticated(v1::ReadProjectionRequest {
                metadata: Some(metadata(
                    Uuid::from_u128(70_202),
                    CAPABILITY_OPERATIONAL_PROJECTIONS_V1,
                )),
                session_id: session.as_bytes().to_vec(),
                view: v1::ProjectionView::SessionTree.into(),
                page_size: 1,
                page_token: String::new(),
                consumer_key: "foreign-consumer".into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            matches!(cross_token.outcome, Some(v1::read_projection_response::Outcome::Failure(Failure { code, .. })) if code == FailureCode::Authentication as i32)
        );

        let events = client
            .read_events(authenticated(v1::ReadEventsRequest {
                metadata: Some(metadata(bound_negotiation, "events.replay.v1")),
                session_id: session.as_bytes().to_vec(),
                after_position: 0,
                page_size: 1,
            }))
            .await
            .unwrap()
            .into_inner();
        let Some(v1::read_events_response::Outcome::Page(first_page)) = events.outcome else {
            panic!("missing first event page");
        };
        let first_event = first_page.events.first().expect("missing first event");
        drop(client);
        let mut client = connect().await;
        let resumed_events = client
            .read_events(authenticated(v1::ReadEventsRequest {
                metadata: Some(metadata(bound_negotiation, "events.replay.v1")),
                session_id: session.as_bytes().to_vec(),
                after_position: first_event.position,
                page_size: 1,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(
            matches!(resumed_events.outcome, Some(v1::read_events_response::Outcome::Page(page)) if page.events.first().is_some_and(|event| event.position > first_event.position))
        );

        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM request_ledger")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            before_ledger
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events")
                .fetch_one(store.pool())
                .await
                .unwrap(),
            before_events
        );
        let after_head: (i64, i64, i64) = sqlx::query_as(
            "SELECT generation,checkpoint_position,source_head_position FROM projection_heads WHERE session_id=?",
        )
        .bind(session.to_string())
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(after_head, before_head);
        let after_counts: (i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM sessions),(SELECT COUNT(*) FROM events),(SELECT COUNT(*) FROM request_ledger),(SELECT COUNT(*) FROM messages),(SELECT COUNT(*) FROM mailbox_counters),(SELECT COUNT(*) FROM projection_generations),(SELECT COUNT(*) FROM projection_rows),(SELECT COUNT(*) FROM projection_heads),(SELECT COUNT(*) FROM projection_progress)",
        )
        .fetch_one(store.pool())
        .await
        .unwrap();
        assert_eq!(after_counts, before_counts);
        assert_eq!(inspector_domain_fingerprint(&store).await, before_persisted);

        shutdown.send(true).unwrap();
        assert!(server.await.unwrap().is_ok());
    }
}

#[must_use]
pub fn current_metadata(negotiation_id: Vec<u8>, capabilities: &[&str]) -> v1::RequestMetadata {
    v1::RequestMetadata {
        protocol_version: Some(v1::ProtocolVersion {
            major: CURRENT_MAJOR,
            minor: CURRENT_MINOR,
        }),
        capabilities: capabilities.iter().map(ToString::to_string).collect(),
        negotiation_id,
    }
}
