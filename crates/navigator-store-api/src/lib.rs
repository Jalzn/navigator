//! Semantic persistence boundary for Navigator.

use navigator_domain::{
    ArtifactId, ArtifactSnapshot, BoundedBytes, BoundedText, Capability, CompatibilityIdentity,
    ConsumerKey, EventPosition, FencingEpoch, HostId, LaunchAttemptId, MessageId, OperationAction,
    OperationId, OperationState, OwnershipSnapshot, ParticipantId, RequestId, SemanticDigest,
    SessionCompatibilityManifest, SessionEvent, SessionId, SessionSnapshot, TemplateId, Timestamp,
};
use std::future::Future;
use thiserror::Error;

mod mailbox;
pub use mailbox::*;
mod projection;
pub use projection::*;
mod resource_limits;
pub use resource_limits::*;
mod approval;
pub use approval::*;
mod artifact;
pub use artifact::*;
mod authority;
pub use authority::*;
mod hierarchy;
pub use hierarchy::*;
mod effect_journal;
pub use effect_journal::*;
mod recovery;
pub use recovery::*;
mod tool;
pub use tool::*;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StoreAction {
    OpenSession,
    CloseSession,
    AcquireOwnership,
    RenewOwnership,
    ReleaseOwnership,
    PrepareLaunch,
    AttachLaunch,
    TransitionLaunch,
    CreateRootParticipant,
    CreateChildParticipant,
    StartOperation,
    TransitionOperation,
    EnqueueMessage,
    LeaseNextMessage,
    TransitionMessageDelivery,
    PutAuthorityPolicy,
    IssueGrant,
    RevokeGrant,
    CheckAuthorityEffect,
    CreateAuthorizedChild,
    ApplyHierarchyEffect,
    CancelSubtree,
    RegisterAuthorityTemplatePolicy,
    ReserveEffect,
    StartEffect,
    ResolveEffect,
    TakeoverEffect,
    ResolveAuthorizedEffect,
    PublishArtifact,
    DeleteArtifact,
    EraseArtifact,
    RegisterTool,
    ReserveToolInvocation,
    TransitionToolInvocation,
    ConnectToolProvider,
}

impl StoreAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenSession => "session.open",
            Self::CloseSession => "session.close",
            Self::AcquireOwnership => "ownership.acquire",
            Self::RenewOwnership => "ownership.renew",
            Self::ReleaseOwnership => "ownership.release",
            Self::PrepareLaunch => "instance.prepare_launch",
            Self::AttachLaunch => "instance.attach_launch",
            Self::TransitionLaunch => "instance.transition_launch",
            Self::CreateRootParticipant => "participant.create_root",
            Self::CreateChildParticipant => "participant.create_child",
            Self::StartOperation => "operation.start",
            Self::TransitionOperation => "operation.transition",
            Self::EnqueueMessage => "message.enqueue",
            Self::LeaseNextMessage => "message.lease_next",
            Self::TransitionMessageDelivery => "message.transition_delivery",
            Self::PutAuthorityPolicy => "authority.put_policy",
            Self::IssueGrant => "authority.issue_grant",
            Self::RevokeGrant => "authority.revoke_grant",
            Self::CheckAuthorityEffect => "authority.check_effect",
            Self::CreateAuthorizedChild => "authority.create_child",
            Self::ApplyHierarchyEffect => "hierarchy.apply_effect",
            Self::CancelSubtree => "operation.cancel_subtree",
            Self::RegisterAuthorityTemplatePolicy => "authority.register_template_policy",
            Self::ReserveEffect => "effect.reserve",
            Self::StartEffect => "effect.start",
            Self::ResolveEffect => "effect.resolve",
            Self::TakeoverEffect => "effect.takeover",
            Self::ResolveAuthorizedEffect => "effect.resolve_authorized",
            Self::PublishArtifact => "artifact.publish",
            Self::DeleteArtifact => "artifact.delete",
            Self::EraseArtifact => "artifact.erase",
            Self::RegisterTool => "tool.register",
            Self::ReserveToolInvocation => "tool.invoke.reserve",
            Self::TransitionToolInvocation => "tool.invoke.transition",
            Self::ConnectToolProvider => "tool.provider.connect",
        }
    }

    fn capability(self) -> Capability {
        Capability::new(self.as_str()).expect("Store action names are valid capabilities")
    }
}

/// `RequestId` identifies one mutation globally, not merely within a Session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestContext {
    request_id: RequestId,
    caller: HostId,
}

impl RequestContext {
    #[must_use]
    pub const fn new(request_id: RequestId, caller: HostId) -> Self {
        Self { request_id, caller }
    }

    #[must_use]
    pub const fn request_id(self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn caller(self) -> HostId {
        self.caller
    }
}

pub trait MutableRequest {
    fn context(&self) -> RequestContext;
    fn action(&self) -> StoreAction;
    fn digest(&self) -> SemanticDigest;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenSession {
    context: RequestContext,
    session_id: SessionId,
    consumer_key: ConsumerKey,
    compatibility: CompatibilityIdentity,
    manifest: Option<SessionCompatibilityManifest>,
    mode: SessionOpenMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionOpenMode {
    Exact,
    Open,
    Resume,
    Reset,
}

impl OpenSession {
    #[must_use]
    pub const fn context(&self) -> RequestContext {
        self.context
    }

    #[must_use]
    pub fn new(
        context: RequestContext,
        session_id: SessionId,
        consumer_key: ConsumerKey,
        compatibility: CompatibilityIdentity,
    ) -> Self {
        Self {
            context,
            session_id,
            consumer_key,
            compatibility,
            manifest: None,
            mode: SessionOpenMode::Exact,
        }
    }

    #[must_use]
    pub fn with_manifest(
        context: RequestContext,
        session_id: SessionId,
        consumer_key: ConsumerKey,
        manifest: SessionCompatibilityManifest,
    ) -> Self {
        Self {
            context,
            session_id,
            consumer_key,
            compatibility: manifest.compatibility(),
            manifest: Some(manifest),
            mode: SessionOpenMode::Exact,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn consumer_key(&self) -> &ConsumerKey {
        &self.consumer_key
    }

    #[must_use]
    pub const fn compatibility(&self) -> CompatibilityIdentity {
        self.compatibility
    }

    #[must_use]
    pub const fn manifest(&self) -> Option<&SessionCompatibilityManifest> {
        self.manifest.as_ref()
    }

    #[must_use]
    pub const fn with_mode(mut self, mode: SessionOpenMode) -> Self {
        self.mode = mode;
        self
    }

    #[must_use]
    pub const fn mode(&self) -> SessionOpenMode {
        self.mode
    }

    #[must_use]
    pub const fn with_session_id(mut self, session_id: SessionId) -> Self {
        self.session_id = session_id;
        self
    }
}

impl MutableRequest for OpenSession {
    fn context(&self) -> RequestContext {
        self.context
    }

    fn action(&self) -> StoreAction {
        StoreAction::OpenSession
    }

    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        // Candidate identity is not part of consumer-key mode semantics.
        if self.mode == SessionOpenMode::Exact {
            input.identity(*self.session_id.as_uuid().as_bytes());
        }
        input.bytes(self.consumer_key.as_str().as_bytes());
        input.fixed(self.compatibility.as_bytes());
        input.fixed(&[match self.mode {
            SessionOpenMode::Exact => 0,
            SessionOpenMode::Open => 1,
            SessionOpenMode::Resume => 2,
            SessionOpenMode::Reset => 3,
        }]);
        match &self.manifest {
            Some(manifest) => {
                input.fixed(&[1]);
                input.fixed(manifest.configuration_identity().as_bytes());
                input.u64(manifest.templates().len() as u64);
                for binding in manifest.templates() {
                    input.identity(*binding.template_id.as_uuid().as_bytes());
                    input.fixed(binding.compatibility.as_bytes());
                }
            }
            None => input.fixed(&[0]),
        }
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterTemplatesAndOpenSession {
    open: OpenSession,
    templates: Vec<TemplateRecord>,
}

impl RegisterTemplatesAndOpenSession {
    pub fn new(open: OpenSession, mut templates: Vec<TemplateRecord>) -> Result<Self, StoreError> {
        templates.sort_unstable_by_key(|template| template.identity);
        if templates.is_empty()
            || templates
                .windows(2)
                .any(|pair| pair[0].identity == pair[1].identity)
            || templates
                .iter()
                .any(|template| navigator_domain::Template::try_from(template.clone()).is_err())
        {
            return Err(StoreError::Invalid);
        }
        let exact = match open.manifest() {
            Some(manifest) => {
                manifest.templates().len() == templates.len()
                    && manifest
                        .templates()
                        .iter()
                        .zip(&templates)
                        .all(|(binding, template)| {
                            binding.template_id == template.identity
                                && binding.compatibility == template.compatibility
                        })
            }
            None => templates.len() == 1 && templates[0].compatibility == open.compatibility(),
        };
        if !exact {
            return Err(StoreError::Invalid);
        }
        Ok(Self { open, templates })
    }

    #[must_use]
    pub const fn open(&self) -> &OpenSession {
        &self.open
    }

    #[must_use]
    pub fn templates(&self) -> &[TemplateRecord] {
        &self.templates
    }
}

impl MutableRequest for RegisterTemplatesAndOpenSession {
    fn context(&self) -> RequestContext {
        self.open.context()
    }

    fn action(&self) -> StoreAction {
        StoreAction::OpenSession
    }

    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        if self.open.mode() == SessionOpenMode::Exact {
            input.identity(*self.open.session_id().as_uuid().as_bytes());
        }
        input.bytes(self.open.consumer_key().as_str().as_bytes());
        input.fixed(self.open.compatibility().as_bytes());
        input.fixed(self.open.digest().as_bytes());
        input.u64(self.templates.len() as u64);
        for template in &self.templates {
            input.identity(*template.identity.as_uuid().as_bytes());
            input.fixed(template.compatibility.as_bytes());
        }
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CloseSession {
    context: RequestContext,
    session_id: SessionId,
    epoch: FencingEpoch,
}

impl CloseSession {
    #[must_use]
    pub const fn new(context: RequestContext, session_id: SessionId, epoch: FencingEpoch) -> Self {
        Self {
            context,
            session_id,
            epoch,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn epoch(&self) -> FencingEpoch {
        self.epoch
    }
}

impl MutableRequest for CloseSession {
    fn context(&self) -> RequestContext {
        self.context
    }

    fn action(&self) -> StoreAction {
        StoreAction::CloseSession
    }

    fn digest(&self) -> SemanticDigest {
        session_epoch_digest(self.action(), self.session_id, self.epoch)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LeaseDurationError {
    #[error("lease duration must be positive and representable")]
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LeaseDuration(u64);

impl LeaseDuration {
    pub const fn from_millis(milliseconds: u64) -> Result<Self, LeaseDurationError> {
        if milliseconds == 0 || milliseconds > i64::MAX as u64 {
            Err(LeaseDurationError::Invalid)
        } else {
            Ok(Self(milliseconds))
        }
    }

    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireOwnership {
    context: RequestContext,
    session_id: SessionId,
    duration: LeaseDuration,
}

impl AcquireOwnership {
    #[must_use]
    pub const fn new(
        context: RequestContext,
        session_id: SessionId,
        duration: LeaseDuration,
    ) -> Self {
        Self {
            context,
            session_id,
            duration,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn context(&self) -> RequestContext {
        self.context
    }

    #[must_use]
    pub const fn duration(&self) -> LeaseDuration {
        self.duration
    }
}

impl MutableRequest for AcquireOwnership {
    fn context(&self) -> RequestContext {
        self.context
    }

    fn action(&self) -> StoreAction {
        StoreAction::AcquireOwnership
    }

    fn digest(&self) -> SemanticDigest {
        session_duration_digest(self.action(), self.session_id, self.duration)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewOwnership {
    context: RequestContext,
    session_id: SessionId,
    epoch: FencingEpoch,
    duration: LeaseDuration,
}

impl RenewOwnership {
    #[must_use]
    pub const fn new(
        context: RequestContext,
        session_id: SessionId,
        epoch: FencingEpoch,
        duration: LeaseDuration,
    ) -> Self {
        Self {
            context,
            session_id,
            epoch,
            duration,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn epoch(&self) -> FencingEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn duration(&self) -> LeaseDuration {
        self.duration
    }
}

impl MutableRequest for RenewOwnership {
    fn context(&self) -> RequestContext {
        self.context
    }

    fn action(&self) -> StoreAction {
        StoreAction::RenewOwnership
    }

    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.u64(self.duration.as_millis());
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseOwnership {
    context: RequestContext,
    session_id: SessionId,
    epoch: FencingEpoch,
}

impl ReleaseOwnership {
    #[must_use]
    pub const fn new(context: RequestContext, session_id: SessionId, epoch: FencingEpoch) -> Self {
        Self {
            context,
            session_id,
            epoch,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn epoch(&self) -> FencingEpoch {
        self.epoch
    }
}

impl MutableRequest for ReleaseOwnership {
    fn context(&self) -> RequestContext {
        self.context
    }

    fn action(&self) -> StoreAction {
        StoreAction::ReleaseOwnership
    }

    fn digest(&self) -> SemanticDigest {
        session_epoch_digest(self.action(), self.session_id, self.epoch)
    }
}

pub(crate) struct CanonicalInput(Vec<u8>);

impl CanonicalInput {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn identity(&mut self, value: [u8; 16]) {
        self.fixed(&value);
    }

    pub(crate) fn fixed(&mut self, value: &[u8]) {
        self.0.extend_from_slice(value);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.u64(u64::try_from(value.len()).expect("bounded input length fits u64"));
        self.fixed(value);
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.fixed(&value.to_be_bytes());
    }

    pub(crate) fn finish(self, action: StoreAction) -> SemanticDigest {
        SemanticDigest::v1(&action.capability(), &self.0)
    }
}

fn session_epoch_digest(
    action: StoreAction,
    session_id: SessionId,
    epoch: FencingEpoch,
) -> SemanticDigest {
    let mut input = CanonicalInput::new();
    input.identity(*session_id.as_uuid().as_bytes());
    input.u64(epoch.get());
    input.finish(action)
}

fn session_duration_digest(
    action: StoreAction,
    session_id: SessionId,
    duration: LeaseDuration,
) -> SemanticDigest {
    let mut input = CanonicalInput::new();
    input.identity(*session_id.as_uuid().as_bytes());
    input.u64(duration.as_millis());
    input.finish(action)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Mutation<T> {
    Applied(T),
    Replayed(T),
    Unchanged(T),
}

impl<T> Mutation<T> {
    #[must_use]
    pub const fn value(&self) -> &T {
        match self {
            Self::Applied(value) | Self::Replayed(value) | Self::Unchanged(value) => value,
        }
    }

    #[must_use]
    pub const fn was_replayed(&self) -> bool {
        matches!(self, Self::Replayed(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnershipLease {
    session_id: SessionId,
    owner: HostId,
    epoch: FencingEpoch,
    expires_at: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OwnershipLeaseError {
    #[error("ownership lease expiry must be later than its issuance time")]
    ExpiryNotFuture,
}

impl OwnershipLease {
    pub fn new(
        session_id: SessionId,
        owner: HostId,
        epoch: FencingEpoch,
        issued_at: Timestamp,
        expires_at: Timestamp,
    ) -> Result<Self, OwnershipLeaseError> {
        if expires_at <= issued_at {
            return Err(OwnershipLeaseError::ExpiryNotFuture);
        }
        Ok(Self {
            session_id,
            owner,
            epoch,
            expires_at,
        })
    }

    /// Restores a lease already validated and persisted by a Store.
    #[must_use]
    pub const fn restored(
        session_id: SessionId,
        owner: HostId,
        epoch: FencingEpoch,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            session_id,
            owner,
            epoch,
            expires_at,
        }
    }

    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub const fn owner(&self) -> HostId {
        self.owner
    }

    #[must_use]
    pub const fn epoch(&self) -> FencingEpoch {
        self.epoch
    }

    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    #[must_use]
    pub fn is_effective_at(&self, observed_at: Timestamp) -> bool {
        observed_at < self.expires_at
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestPhase {
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoredEffect {
    Applied,
    Unchanged,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredResult {
    Session(SessionSnapshot),
    OwnershipLease(OwnershipLease),
    Ownership(OwnershipSnapshot),
    Launch(LaunchSnapshot),
    Participant(ParticipantSnapshot),
    Operation(OperationSnapshot),
    Message(Box<Option<MessageSnapshot>>),
    AuthorityPolicy(Box<AuthorityPolicySnapshot>),
    AuthorityTemplatePolicy(Box<AuthorityTemplatePolicy>),
    Grant(GrantSnapshot),
    AuthorityEffect(AuthorityEffectOutcome),
    AuthorizedChild(Box<AuthorizedChildOutcome>),
    HierarchyEffect(Box<HierarchyEffectOutcome>),
    Cancellation(Box<CancelSubtreeOutcome>),
    Artifact(ArtifactSnapshot),
    ToolRegistration(Box<ToolRegistrationSnapshot>),
    ToolProviderConnection(Box<ToolProviderConnectionSnapshot>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoredRequestOutcome {
    Succeeded {
        effect: StoredEffect,
        result: StoredResult,
    },
    Failed(StoreError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRequest {
    request_id: RequestId,
    caller: HostId,
    action: StoreAction,
    digest: SemanticDigest,
    outcome: StoredRequestOutcome,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StoredRequestError {
    #[error("stored outcome does not match request action")]
    OutcomeMismatch,
}

impl StoredRequest {
    pub fn new(
        request_id: RequestId,
        caller: HostId,
        action: StoreAction,
        digest: SemanticDigest,
        outcome: StoredRequestOutcome,
    ) -> Result<Self, StoredRequestError> {
        let valid = match &outcome {
            StoredRequestOutcome::Failed(_) => true,
            StoredRequestOutcome::Succeeded { effect, result } => {
                let result_matches = matches!(
                    (action, result),
                    (
                        StoreAction::OpenSession | StoreAction::CloseSession,
                        StoredResult::Session(_)
                    ) | (
                        StoreAction::AcquireOwnership | StoreAction::RenewOwnership,
                        StoredResult::OwnershipLease(_)
                    ) | (StoreAction::ReleaseOwnership, StoredResult::Ownership(_))
                        | (
                            StoreAction::PrepareLaunch
                                | StoreAction::AttachLaunch
                                | StoreAction::TransitionLaunch,
                            StoredResult::Launch(_),
                        )
                        | (
                            StoreAction::CreateRootParticipant
                                | StoreAction::CreateChildParticipant,
                            StoredResult::Participant(_)
                        )
                        | (
                            StoreAction::StartOperation | StoreAction::TransitionOperation,
                            StoredResult::Operation(_),
                        )
                        | (
                            StoreAction::EnqueueMessage
                                | StoreAction::LeaseNextMessage
                                | StoreAction::TransitionMessageDelivery,
                            StoredResult::Message(_),
                        )
                        | (
                            StoreAction::PutAuthorityPolicy,
                            StoredResult::AuthorityPolicy(_)
                        )
                        | (
                            StoreAction::IssueGrant | StoreAction::RevokeGrant,
                            StoredResult::Grant(_)
                        )
                        | (
                            StoreAction::CheckAuthorityEffect,
                            StoredResult::AuthorityEffect(_)
                        )
                        | (
                            StoreAction::CreateAuthorizedChild,
                            StoredResult::AuthorizedChild(_)
                        )
                        | (
                            StoreAction::ApplyHierarchyEffect,
                            StoredResult::HierarchyEffect(_)
                        )
                        | (StoreAction::CancelSubtree, StoredResult::Cancellation(_))
                        | (
                            StoreAction::PublishArtifact
                                | StoreAction::DeleteArtifact
                                | StoreAction::EraseArtifact,
                            StoredResult::Artifact(_)
                        )
                        | (
                            StoreAction::RegisterAuthorityTemplatePolicy,
                            StoredResult::AuthorityTemplatePolicy(_)
                        )
                        | (StoreAction::RegisterTool, StoredResult::ToolRegistration(_))
                        | (
                            StoreAction::ConnectToolProvider,
                            StoredResult::ToolProviderConnection(_)
                        )
                );
                result_matches
                    && (*effect != StoredEffect::Unchanged
                        || matches!(
                            action,
                            StoreAction::OpenSession
                                | StoreAction::PrepareLaunch
                                | StoreAction::CreateRootParticipant
                                | StoreAction::CreateChildParticipant
                                | StoreAction::StartOperation
                        ))
            }
        };
        if !valid {
            return Err(StoredRequestError::OutcomeMismatch);
        }
        Ok(Self {
            request_id,
            caller,
            action,
            digest,
            outcome,
        })
    }

    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    #[must_use]
    pub const fn caller(&self) -> HostId {
        self.caller
    }

    #[must_use]
    pub const fn action(&self) -> StoreAction {
        self.action
    }

    #[must_use]
    pub const fn digest(&self) -> SemanticDigest {
        self.digest
    }

    #[must_use]
    pub const fn outcome(&self) -> &StoredRequestOutcome {
        &self.outcome
    }

    #[must_use]
    pub const fn phase(&self) -> RequestPhase {
        match &self.outcome {
            StoredRequestOutcome::Succeeded { .. } => RequestPhase::Succeeded,
            StoredRequestOutcome::Failed(_) => RequestPhase::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EventReadError {
    #[error("event page limit must be between 1 and {maximum}")]
    OutOfRange { maximum: u32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventReadLimit(u32);

impl EventReadLimit {
    pub const MAX: u32 = 1_000;

    pub const fn new(value: u32) -> Result<Self, EventReadError> {
        if value == 0 || value > Self::MAX {
            Err(EventReadError::OutOfRange { maximum: Self::MAX })
        } else {
            Ok(Self(value))
        }
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadEvents {
    pub session_id: SessionId,
    pub consumer: ConsumerKey,
    pub after: Option<EventPosition>,
    pub limit: EventReadLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPage {
    pub events: Vec<SessionEvent>,
    pub last_position: Option<EventPosition>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StoreError {
    #[error("session does not exist")]
    SessionNotFound { session_id: SessionId },
    #[error("template does not exist")]
    TemplateNotFound { template_id: TemplateId },
    #[error("participant does not exist")]
    ParticipantNotFound { participant_id: ParticipantId },
    #[error("session root participant does not exist")]
    RootParticipantNotFound { session_id: SessionId },
    #[error("operation does not exist")]
    OperationNotFound { operation_id: OperationId },
    #[error("message does not exist")]
    MessageNotFound { message_id: MessageId },
    #[error("artifact does not exist")]
    ArtifactNotFound { artifact_id: ArtifactId },
    #[error("launch attempt does not exist")]
    LaunchNotFound { attempt_id: LaunchAttemptId },
    #[error("message payload exceeds the durable envelope limit")]
    MessageOversize,
    #[error("mailbox queued-byte quota is exhausted")]
    MailboxQuotaExceeded,
    #[error("capacity exhausted: {reason}")]
    CapacityExceeded { reason: CapacityReason },
    #[error("session is closed and cannot accept this mutation")]
    SessionClosed { session_id: SessionId },
    #[error("a different request already closed the session")]
    AlreadyClosed { session_id: SessionId },
    #[error("session compatibility identity conflicts with persisted identity")]
    CompatibilityConflict {
        session_id: SessionId,
        persisted: CompatibilityIdentity,
        requested: CompatibilityIdentity,
    },
    #[error("session has interrupted work; use resume or reset explicitly")]
    InterruptedSession { session_id: SessionId },
    #[error("session consumer identity conflicts with persisted identity")]
    ConsumerConflict {
        session_id: SessionId,
        persisted: ConsumerKey,
        requested: ConsumerKey,
    },
    #[error("global request identity was reused with different semantics")]
    RequestConflict { request_id: RequestId },
    #[error("session ownership is held by another live owner")]
    OwnershipHeld { ownership: OwnershipSnapshot },
    #[error("ownership lease is expired")]
    OwnershipExpired {
        session_id: SessionId,
        epoch: FencingEpoch,
    },
    #[error("ownership epoch is stale")]
    StaleOwnership {
        session_id: SessionId,
        attempted: FencingEpoch,
        current: Option<FencingEpoch>,
    },
    #[error("requested lease duration exceeds the Store maximum")]
    LeaseTooLong,
    #[error("store schema {found} is newer than supported schema {supported}")]
    SchemaTooNew { found: u32, supported: u32 },
    #[error("durable state is corrupt")]
    Corrupt,
    #[error("store is busy")]
    Busy,
    #[error("store input violates its semantic contract")]
    Invalid,
    #[error("projection page token is stale or its bounded lease expired")]
    ProjectionStale,
    #[error("store is temporarily unavailable")]
    Unavailable,
}

impl StoreError {
    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(self, Self::Busy | Self::Unavailable)
    }
}

pub trait SessionStore: Send + Sync {
    fn open_session(
        &self,
        command: OpenSession,
    ) -> impl Future<Output = Result<Mutation<SessionSnapshot>, StoreError>> + Send;

    fn close_session(
        &self,
        command: CloseSession,
    ) -> impl Future<Output = Result<Mutation<SessionSnapshot>, StoreError>> + Send;

    fn acquire_ownership(
        &self,
        command: AcquireOwnership,
    ) -> impl Future<Output = Result<Mutation<OwnershipLease>, StoreError>> + Send;

    fn renew_ownership(
        &self,
        command: RenewOwnership,
    ) -> impl Future<Output = Result<Mutation<OwnershipLease>, StoreError>> + Send;

    fn release_ownership(
        &self,
        command: ReleaseOwnership,
    ) -> impl Future<Output = Result<Mutation<OwnershipSnapshot>, StoreError>> + Send;

    fn load_session(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<SessionSnapshot, StoreError>> + Send;

    fn read_ownership(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<OwnershipSnapshot, StoreError>> + Send;

    fn read_request(
        &self,
        request_id: RequestId,
    ) -> impl Future<Output = Result<Option<StoredRequest>, StoreError>> + Send;

    fn read_events(
        &self,
        query: ReadEvents,
    ) -> impl Future<Output = Result<EventPage, StoreError>> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchState {
    Prepared,
    Attached,
    Ready,
    Stopping,
    Stopped,
    CleanupRequired,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ProcessEvidence {
    pub process_id: u32,
    pub process_group_id: u32,
    pub parent_process_id: u32,
    pub creation_marker: u64,
    pub executable_identity: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LaunchSnapshot {
    pub session_id: SessionId,
    pub ownership_epoch: Option<FencingEpoch>,
    pub participant_id: navigator_domain::ParticipantId,
    pub driver_id: navigator_domain::DriverId,
    pub driver_configuration_digest: [u8; 32],
    pub attempt_id: navigator_domain::LaunchAttemptId,
    pub instance_id: Option<navigator_domain::InstanceId>,
    pub state: LaunchState,
    pub revision: navigator_domain::Revision,
    pub credential_digest: [u8; 32],
    pub evidence: Option<ProcessEvidence>,
    pub cleanup_reason: Option<navigator_domain::BoundedText<1024>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareLaunch {
    pub context: RequestContext,
    pub epoch: FencingEpoch,
    pub session_id: SessionId,
    pub participant_id: navigator_domain::ParticipantId,
    pub driver_id: navigator_domain::DriverId,
    pub driver_configuration_digest: [u8; 32],
    pub attempt_id: navigator_domain::LaunchAttemptId,
    pub credential_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachLaunch {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub attempt_id: navigator_domain::LaunchAttemptId,
    pub expected_revision: navigator_domain::Revision,
    pub instance_id: navigator_domain::InstanceId,
    pub evidence: ProcessEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionLaunch {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub attempt_id: navigator_domain::LaunchAttemptId,
    pub expected_revision: navigator_domain::Revision,
    pub target: LaunchState,
    pub cleanup_reason: Option<navigator_domain::BoundedText<1024>>,
}

impl MutableRequest for PrepareLaunch {
    fn context(&self) -> RequestContext {
        self.context
    }

    fn action(&self) -> StoreAction {
        StoreAction::PrepareLaunch
    }

    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.participant_id.as_uuid().as_bytes());
        input.identity(*self.driver_id.as_uuid().as_bytes());
        input.fixed(&self.driver_configuration_digest);
        input.identity(*self.attempt_id.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.fixed(&self.credential_digest);
        input.finish(self.action())
    }
}

impl MutableRequest for AttachLaunch {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::AttachLaunch
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.attempt_id.as_uuid().as_bytes());
        input.identity(*self.instance_id.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.u64(self.expected_revision.get());
        input.u64(u64::from(self.evidence.process_id));
        input.u64(u64::from(self.evidence.process_group_id));
        input.u64(u64::from(self.evidence.parent_process_id));
        input.u64(self.evidence.creation_marker);
        input.fixed(&self.evidence.executable_identity);
        input.finish(self.action())
    }
}

impl MutableRequest for TransitionLaunch {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::TransitionLaunch
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.attempt_id.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.u64(self.expected_revision.get());
        input.bytes(state_name(self.target).as_bytes());
        if let Some(reason) = &self.cleanup_reason {
            input.bytes(reason.as_str().as_bytes());
        }
        input.finish(self.action())
    }
}

fn state_name(state: LaunchState) -> &'static str {
    match state {
        LaunchState::Prepared => "prepared",
        LaunchState::Attached => "attached",
        LaunchState::Ready => "ready",
        LaunchState::Stopping => "stopping",
        LaunchState::Stopped => "stopped",
        LaunchState::CleanupRequired => "cleanup_required",
    }
}

pub trait InstanceStore: SessionStore + Send + Sync {
    fn validate_launch_authority(
        &self,
        session_id: SessionId,
        host_id: HostId,
        epoch: FencingEpoch,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    fn prepare_launch(
        &self,
        command: PrepareLaunch,
    ) -> impl Future<Output = Result<Mutation<LaunchSnapshot>, StoreError>> + Send;

    fn attach_launch(
        &self,
        command: AttachLaunch,
    ) -> impl Future<Output = Result<Mutation<LaunchSnapshot>, StoreError>> + Send;

    fn transition_launch(
        &self,
        command: TransitionLaunch,
    ) -> impl Future<Output = Result<Mutation<LaunchSnapshot>, StoreError>> + Send;

    fn load_launch(
        &self,
        attempt_id: navigator_domain::LaunchAttemptId,
    ) -> impl Future<Output = Result<LaunchSnapshot, StoreError>> + Send;

    fn session_has_launches(
        &self,
        _session_id: SessionId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        async { Err(StoreError::Unavailable) }
    }

    fn session_has_unresolved_launches(
        &self,
        _session_id: SessionId,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send {
        async { Err(StoreError::Unavailable) }
    }
}

pub type TemplateRecord = navigator_domain::RegisteredTemplateSnapshot;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ParticipantSnapshot {
    pub session_id: SessionId,
    pub participant_id: ParticipantId,
    pub parent_participant_id: Option<ParticipantId>,
    pub depth: u32,
    pub template_id: TemplateId,
    pub template_compatibility: CompatibilityIdentity,
    pub revision: navigator_domain::Revision,
}

pub const MAX_PARTICIPANT_DEPTH: u32 = 8;
pub const MAX_DIRECT_CHILDREN: u32 = 64;
pub const MAX_SESSION_PARTICIPANTS: u32 = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRootParticipant {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub participant_id: ParticipantId,
    pub template_id: TemplateId,
    pub expected_compatibility: CompatibilityIdentity,
}

impl MutableRequest for CreateRootParticipant {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::CreateRootParticipant
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.template_id.as_uuid().as_bytes());
        input.fixed(self.expected_compatibility.as_bytes());
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateChildParticipant {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub participant_id: ParticipantId,
    pub parent_participant_id: ParticipantId,
    pub template_id: TemplateId,
    pub expected_compatibility: CompatibilityIdentity,
}

impl MutableRequest for CreateChildParticipant {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::CreateChildParticipant
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.parent_participant_id.as_uuid().as_bytes());
        input.identity(*self.template_id.as_uuid().as_bytes());
        input.fixed(self.expected_compatibility.as_bytes());
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OperationSnapshot {
    pub session_id: SessionId,
    pub operation_id: OperationId,
    pub participant_id: ParticipantId,
    pub start_request_id: RequestId,
    pub input_message_id: MessageId,
    #[serde(default)]
    pub waiting_on_message_id: Option<MessageId>,
    pub input_digest: [u8; 32],
    pub state: OperationState,
    pub revision: navigator_domain::Revision,
    pub terminal_outcome: Option<OperationTerminalOutcome>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

pub const MAX_OPERATION_INPUT_BYTES: usize = 65_536;
pub const MAX_OPERATION_OUTCOME_BYTES: usize = 65_536;
pub const MAX_OPERATION_REASON_BYTES: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperationTerminalOutcome {
    Succeeded {
        result: BoundedBytes<MAX_OPERATION_OUTCOME_BYTES>,
    },
    Failed {
        code: BoundedText<128>,
        detail: BoundedText<MAX_OPERATION_REASON_BYTES>,
    },
    Cancelled,
    Blocked {
        reason: BoundedText<MAX_OPERATION_REASON_BYTES>,
    },
    Uncertain {
        reason: BoundedText<MAX_OPERATION_REASON_BYTES>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartOperation {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub operation_id: OperationId,
    pub participant_id: ParticipantId,
    pub input_message_id: MessageId,
    pub input: navigator_domain::ValidatedTaskInput,
}

impl MutableRequest for StartOperation {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::StartOperation
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.participant_id.as_uuid().as_bytes());
        input.bytes(self.input.as_bytes());
        input.finish(self.action())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionOperation {
    pub context: RequestContext,
    pub session_id: SessionId,
    pub epoch: FencingEpoch,
    pub operation_id: OperationId,
    pub expected_revision: navigator_domain::Revision,
    pub action: OperationAction,
    pub report_message_id: Option<MessageId>,
    pub terminal_outcome: Option<OperationTerminalOutcome>,
}

impl MutableRequest for TransitionOperation {
    fn context(&self) -> RequestContext {
        self.context
    }
    fn action(&self) -> StoreAction {
        StoreAction::TransitionOperation
    }
    fn digest(&self) -> SemanticDigest {
        let mut input = CanonicalInput::new();
        input.identity(*self.session_id.as_uuid().as_bytes());
        input.identity(*self.operation_id.as_uuid().as_bytes());
        input.u64(self.epoch.get());
        input.u64(self.expected_revision.get());
        input.bytes(operation_action_name(self.action).as_bytes());
        if let Some(message_id) = self.report_message_id {
            input.identity(*message_id.as_uuid().as_bytes());
        }
        if let Some(outcome) = &self.terminal_outcome {
            match outcome {
                OperationTerminalOutcome::Succeeded { result } => {
                    input.bytes(b"succeeded");
                    input.bytes(result.as_slice());
                }
                OperationTerminalOutcome::Failed { code, detail } => {
                    input.bytes(b"failed");
                    input.bytes(code.as_str().as_bytes());
                    input.bytes(detail.as_str().as_bytes());
                }
                OperationTerminalOutcome::Cancelled => input.bytes(b"cancelled"),
                OperationTerminalOutcome::Blocked { reason } => {
                    input.bytes(b"blocked");
                    input.bytes(reason.as_str().as_bytes());
                }
                OperationTerminalOutcome::Uncertain { reason } => {
                    input.bytes(b"uncertain");
                    input.bytes(reason.as_str().as_bytes());
                }
            }
        }
        input.finish(self.action())
    }
}

fn operation_action_name(action: OperationAction) -> &'static str {
    match action {
        OperationAction::BeginStart => "begin_start",
        OperationAction::ReportRunning => "report_running",
        OperationAction::Wait => "wait",
        OperationAction::Resume => "resume",
        OperationAction::RequestCancel => "request_cancel",
        OperationAction::ReportSuccess => "report_success",
        OperationAction::ReportFailure => "report_failure",
        OperationAction::ReportCancelled => "report_cancelled",
        OperationAction::ReportBlocked => "report_blocked",
        OperationAction::ReportUncertain => "report_uncertain",
        OperationAction::ObserveIdle => "observe_idle",
    }
}

pub trait OperationStore: SessionStore + Send + Sync {
    fn find_open_session(
        &self,
        _consumer_key: ConsumerKey,
    ) -> impl Future<Output = Result<Option<SessionSnapshot>, StoreError>> + Send {
        async { Err(StoreError::Unavailable) }
    }

    fn register_templates_and_open_session(
        &self,
        command: RegisterTemplatesAndOpenSession,
    ) -> impl Future<Output = Result<Mutation<SessionSnapshot>, StoreError>> + Send;

    fn register_template(
        &self,
        template: TemplateRecord,
    ) -> impl Future<Output = Result<Mutation<TemplateRecord>, StoreError>> + Send;

    fn create_root_participant(
        &self,
        command: CreateRootParticipant,
    ) -> impl Future<Output = Result<Mutation<ParticipantSnapshot>, StoreError>> + Send;

    fn create_child_participant(
        &self,
        command: CreateChildParticipant,
    ) -> impl Future<Output = Result<Mutation<ParticipantSnapshot>, StoreError>> + Send;

    fn start_operation(
        &self,
        command: StartOperation,
    ) -> impl Future<Output = Result<Mutation<OperationSnapshot>, StoreError>> + Send;

    fn transition_operation(
        &self,
        command: TransitionOperation,
    ) -> impl Future<Output = Result<Mutation<OperationSnapshot>, StoreError>> + Send;

    fn load_participant(
        &self,
        participant_id: ParticipantId,
    ) -> impl Future<Output = Result<ParticipantSnapshot, StoreError>> + Send;

    fn load_root_participant(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<ParticipantSnapshot, StoreError>> + Send;

    fn load_direct_children(
        &self,
        parent_id: ParticipantId,
    ) -> impl Future<Output = Result<Vec<ParticipantSnapshot>, StoreError>> + Send;

    fn load_template(
        &self,
        template_id: TemplateId,
    ) -> impl Future<Output = Result<TemplateRecord, StoreError>> + Send;

    fn load_operation(
        &self,
        operation_id: OperationId,
    ) -> impl Future<Output = Result<OperationSnapshot, StoreError>> + Send;

    fn load_operation_input(
        &self,
        operation_id: OperationId,
    ) -> impl Future<Output = Result<BoundedBytes<MAX_OPERATION_INPUT_BYTES>, StoreError>> + Send;
}

#[cfg(test)]
mod tests;
