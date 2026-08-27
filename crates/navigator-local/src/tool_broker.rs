//! Durable bridge between authenticated Driver Tool commands and reconnectable
//! Consumer providers.  The `SQLite` ledger is the source of truth; the maps in
//! this module are bounded routing hints only.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use navigator_consumer_protocol::{
    CAPABILITY_CONSUMER_TOOLS_V1, ToolProviderStreamValidator, v1, validate_negotiated_capabilities,
};
use navigator_core::{AuthenticatedHierarchyCaller, ExecutorError};
use navigator_domain::{
    ApprovalResource, ArtifactDigest, ArtifactId, ArtifactMediaType, ArtifactRef, ArtifactState,
    BoundedText, CanonicalJson, ConsumerKey, EffectClass, FencingEpoch, GrantId, HostId,
    IdempotencyContract, MAX_TOOL_FAILURE_MESSAGE_BYTES, MAX_TOOL_INLINE_BYTES,
    MAX_TOOL_SCHEMA_BYTES, OperationId, ParticipantId, RequestId, SessionId,
    TerminalApprovalEffectPhase, Timestamp, ToolCancellation, ToolConnectionId, ToolDefinition,
    ToolDispatchId, ToolFailure, ToolFailureKind, ToolInvocation, ToolInvocationId, ToolName,
    ToolProviderId, ToolRegistrationId, ToolResult, ToolTimeout, ToolVersion,
};
use navigator_driver_protocol::v1 as driver_v1;
use navigator_store_api::{
    ApprovalStore, ArtifactAccess, ArtifactStore, ConnectToolProvider, ConsumeApprovalGrant,
    FinishApprovalEffect, Mutation, RegisterTool, RequestContext, ReserveToolInvocation,
    StoreError, ToolInvocationPhase, ToolInvocationSnapshot, ToolStore, ToolTerminal,
    ToolTransition, TransitionToolInvocation,
};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio_stream::{Stream, StreamExt, wrappers::ReceiverStream};
use tonic::Status;
use uuid::Uuid;

pub type ToolProviderResponseStream =
    Pin<Box<dyn Stream<Item = Result<v1::ToolProviderResponse, Status>> + Send>>;

const PROVIDER_QUEUE: usize = 32;
const MAX_ACTIVE_PROVIDERS: usize = 256;
const SEND_BUDGET: Duration = Duration::from_millis(250);
const CANCELLATION_GRACE: Duration = Duration::from_millis(250);

#[cfg(test)]
static APPROVAL_FINISH_PAUSE: std::sync::Mutex<Option<RequestId>> = std::sync::Mutex::new(None);
#[cfg(test)]
static APPROVAL_FINISH_ENTERED: std::sync::OnceLock<Notify> = std::sync::OnceLock::new();
#[cfg(test)]
static APPROVAL_FINISH_RELEASE: std::sync::OnceLock<Notify> = std::sync::OnceLock::new();

#[cfg(test)]
fn set_approval_finish_pause(effect_id: Option<RequestId>) {
    *APPROVAL_FINISH_PAUSE.lock().expect("finish pause lock") = effect_id;
    if effect_id.is_none() {
        APPROVAL_FINISH_RELEASE
            .get_or_init(Notify::new)
            .notify_waiters();
    }
}

#[cfg(test)]
async fn wait_approval_finish_entered() {
    APPROVAL_FINISH_ENTERED
        .get_or_init(Notify::new)
        .notified()
        .await;
}

#[allow(clippy::unused_async)]
async fn approval_finish_pause(effect_id: RequestId) {
    #[cfg(test)]
    if APPROVAL_FINISH_PAUSE
        .lock()
        .expect("finish pause lock")
        .is_some_and(|value| value == effect_id)
    {
        APPROVAL_FINISH_ENTERED
            .get_or_init(Notify::new)
            .notify_one();
        APPROVAL_FINISH_RELEASE
            .get_or_init(Notify::new)
            .notified()
            .await;
    }
    #[cfg(not(test))]
    let _ = effect_id;
}

fn approval_reconcile_crash_injected(effect_id: RequestId) -> bool {
    #[cfg(test)]
    {
        return APPROVAL_FINISH_PAUSE
            .lock()
            .expect("finish pause lock")
            .is_some_and(|value| value == effect_id);
    }
    #[cfg(not(test))]
    {
        let _ = effect_id;
        false
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum ToolCancelError {
    #[error("Tool cancellation persistence failed")]
    Store,
    #[error("Tool cancellation requires reconciliation")]
    CleanupRequired,
}

pub trait ToolBrokerControl: Send + Sync {
    fn register(
        &self,
        request: v1::RegisterToolRequest,
        owner_epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = v1::RegisterToolResponse> + Send + '_>>;

    fn provide(
        &self,
        input: tonic::Streaming<v1::ToolProviderRequest>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolProviderResponseStream, Status>> + Send + '_>>;

    fn cancel_operations(
        &self,
        request_id: RequestId,
        session_id: SessionId,
        operation_ids: Vec<OperationId>,
    ) -> Pin<Box<dyn Future<Output = Result<(), ToolCancelError>> + Send + '_>>;
}

#[derive(Clone)]
struct ActiveProvider {
    session_id: SessionId,
    provider_id: ToolProviderId,
    connection_id: ToolConnectionId,
    generation: u64,
    host_id: HostId,
    owner_epoch: FencingEpoch,
    registrations: HashSet<ToolRegistrationId>,
    sender: mpsc::Sender<Result<v1::ToolProviderResponse, Status>>,
}

pub struct LocalToolBroker<S> {
    store: Arc<S>,
    host_id: HostId,
    lease_duration: Duration,
    providers: Arc<Mutex<HashMap<(SessionId, ToolProviderId), ActiveProvider>>>,
    changed: Arc<Notify>,
    negotiations: Arc<std::sync::RwLock<HashMap<Uuid, crate::service::NegotiationEntry>>>,
    background_tasks: crate::BackgroundTaskRegistry,
}

impl<S> LocalToolBroker<S> {
    #[must_use]
    pub(crate) fn new(
        store: Arc<S>,
        host_id: HostId,
        lease_duration: Duration,
        negotiations: Arc<std::sync::RwLock<HashMap<Uuid, crate::service::NegotiationEntry>>>,
        background_tasks: crate::BackgroundTaskRegistry,
    ) -> Self {
        Self {
            store,
            host_id,
            lease_duration,
            providers: Arc::new(Mutex::new(HashMap::new())),
            changed: Arc::new(Notify::new()),
            negotiations,
            background_tasks,
        }
    }
}

impl<S: ToolStore + ArtifactStore + ApprovalStore + SessionConsumerKey + 'static> ToolBrokerControl
    for LocalToolBroker<S>
{
    fn register(
        &self,
        request: v1::RegisterToolRequest,
        owner_epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = v1::RegisterToolResponse> + Send + '_>> {
        Box::pin(async move { self.register_inner(request, owner_epoch).await })
    }

    fn provide(
        &self,
        input: tonic::Streaming<v1::ToolProviderRequest>,
    ) -> Pin<Box<dyn Future<Output = Result<ToolProviderResponseStream, Status>> + Send + '_>> {
        Box::pin(async move { self.provide_inner(input).await })
    }

    fn cancel_operations(
        &self,
        request_id: RequestId,
        session_id: SessionId,
        operation_ids: Vec<OperationId>,
    ) -> Pin<Box<dyn Future<Output = Result<(), ToolCancelError>> + Send + '_>> {
        Box::pin(async move {
            self.cancel_operations_inner(request_id, session_id, &operation_ids)
                .await
        })
    }
}

impl<S: ToolStore + ArtifactStore + SessionConsumerKey + 'static> LocalToolBroker<S> {
    async fn register_inner(
        &self,
        request: v1::RegisterToolRequest,
        owner_epoch: FencingEpoch,
    ) -> v1::RegisterToolResponse {
        use v1::register_tool_response::Outcome;
        let parsed = (|| {
            let request_id = parse_id(&request.request_id, RequestId::from_uuid)?;
            let session_id = parse_id(&request.session_id, SessionId::from_uuid)?;
            let definition =
                definition_from_wire(request.tool.as_ref().ok_or(BrokerError::Invalid)?)?;
            let metadata = request.metadata.as_ref().ok_or(BrokerError::Invalid)?;
            Ok::<_, BrokerError>((request_id, session_id, definition, metadata.clone()))
        })();
        let (request_id, session_id, definition, metadata) = match parsed {
            Ok(value) => value,
            Err(error) => return register_failure(&error),
        };
        let consumer_key = match self.authenticated_consumer(&metadata, session_id).await {
            Ok(value) => value,
            Err(error) => return register_failure(&error),
        };
        let registration_id = stable_registration_id(session_id, &definition);
        let command = RegisterTool {
            context: RequestContext::new(request_id, self.host_id),
            session_id,
            owner_epoch,
            registration_id,
            consumer_key,
            definition,
        };
        match self.store.register_tool(command).await {
            Ok(value) => {
                let snapshot = match value {
                    Mutation::Applied(value)
                    | Mutation::Unchanged(value)
                    | Mutation::Replayed(value) => value,
                };
                v1::RegisterToolResponse {
                    outcome: Some(Outcome::Registration(registration_wire(
                        &snapshot, request_id,
                    ))),
                }
            }
            Err(error) => register_failure(&BrokerError::Store(error)),
        }
    }

    // ToolStore deliberately does not expose Session metadata. SQLite is the
    // production store, while tests can override this through the blanket
    // `SessionConsumerKey` implementation below.
    async fn authenticated_consumer(
        &self,
        metadata: &v1::RequestMetadata,
        session_id: SessionId,
    ) -> Result<ConsumerKey, BrokerError> {
        let negotiation_id =
            Uuid::from_slice(&metadata.negotiation_id).map_err(|_| BrokerError::Unauthorized)?;
        let bound = self
            .negotiations
            .read()
            .map_err(|_| BrokerError::Corrupt)?
            .get(&negotiation_id)
            .and_then(|entry| entry.consumer_key.clone())
            .ok_or(BrokerError::Unauthorized)?;
        let durable = self
            .store
            .consumer_key(session_id)
            .await
            .map_err(BrokerError::Store)?;
        if bound != durable {
            return Err(BrokerError::Unauthorized);
        }
        Ok(bound)
    }

    #[allow(clippy::too_many_lines)]
    async fn provide_inner(
        &self,
        mut input: tonic::Streaming<v1::ToolProviderRequest>,
    ) -> Result<ToolProviderResponseStream, Status>
    where
        S: ApprovalStore,
    {
        let first = input
            .message()
            .await
            .map_err(|_| Status::invalid_argument("malformed Tool provider stream"))?
            .ok_or_else(|| Status::invalid_argument("missing Tool provider connect frame"))?;
        let mut stream_validator = ToolProviderStreamValidator::default();
        stream_validator
            .accept(&first)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let Some(v1::tool_provider_request::Frame::Connect(connect)) = first.frame else {
            return Err(Status::invalid_argument(
                "first Tool provider frame must connect",
            ));
        };
        let metadata = connect
            .metadata
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing negotiation metadata"))?;
        let negotiation_id = Uuid::from_slice(&metadata.negotiation_id)
            .map_err(|_| Status::invalid_argument("invalid negotiation identity"))?;
        let negotiated = self
            .negotiations
            .read()
            .map_err(|_| Status::internal("negotiation registry unavailable"))?
            .get(&negotiation_id)
            .map(|entry| entry.capabilities.clone())
            .ok_or_else(|| Status::failed_precondition("unknown negotiation"))?;
        validate_negotiated_capabilities(metadata, &negotiated)
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        if !metadata
            .capabilities
            .iter()
            .any(|value| value == CAPABILITY_CONSUMER_TOOLS_V1)
        {
            return Err(Status::failed_precondition(
                "Consumer Tools capability was not selected",
            ));
        }
        let session_id = parse_id(&connect.session_id, SessionId::from_uuid)
            .map_err(|_| Status::invalid_argument("invalid Session identity"))?;
        let provider_id = parse_id(&connect.provider_id, ToolProviderId::from_uuid)
            .map_err(|_| Status::invalid_argument("invalid provider identity"))?;
        let connection_id = parse_id(&connect.connection_id, ToolConnectionId::from_uuid)
            .map_err(|_| Status::invalid_argument("invalid connection identity"))?;
        let owner_epoch = self
            .store
            .owner_epoch(session_id, self.host_id)
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let consumer_key = self
            .authenticated_consumer(metadata, session_id)
            .await
            .map_err(|_| Status::unauthenticated("Consumer negotiation does not own Session"))?;
        let mut registrations = Vec::with_capacity(connect.registration_ids.len());
        for value in &connect.registration_ids {
            registrations.push(
                parse_id(value, ToolRegistrationId::from_uuid)
                    .map_err(|_| Status::invalid_argument("invalid registration identity"))?,
            );
        }
        let request_id = derived_id(
            b"navigator.tool.provider.connect.v1",
            &[
                session_id.as_uuid().as_bytes(),
                provider_id.as_uuid().as_bytes(),
                connection_id.as_uuid().as_bytes(),
            ],
            RequestId::from_uuid,
        );
        let (sender, receiver) = mpsc::channel(PROVIDER_QUEUE);
        let (start_sender, start_receiver) = oneshot::channel();
        let store = Arc::clone(&self.store);
        let providers = Arc::clone(&self.providers);
        let changed = Arc::clone(&self.changed);
        let task_sender = sender.clone();
        self.background_tasks
            .spawn(async move {
                let Ok((active, replay, after)) = start_receiver.await else {
                    return;
                };
                if replay_provider_reconnect(&*store, &active, replay, after, &task_sender)
                    .await
                    .is_ok()
                {
                    while let Some(frame) = input.next().await {
                        let Ok(frame) = frame else { break };
                        if stream_validator.accept(&frame).is_err() {
                            break;
                        }
                        if process_provider_frame(&*store, &active, frame, &task_sender)
                            .await
                            .is_err()
                        {
                            break;
                        }
                        let _ = reconcile_reserved_approval_effects_in(
                            &*store,
                            active.session_id,
                            active.host_id,
                            active.owner_epoch,
                        )
                        .await;
                        changed.notify_waiters();
                    }
                }
                if let Ok(recoverable) = store
                    .list_provider_replay(active.session_id, active.provider_id, 0)
                    .await
                {
                    for snapshot in recoverable {
                        if matches!(
                            recovery_disposition(&snapshot),
                            RecoveryDisposition::MarkUncertain
                        ) {
                            let _ = store
                                .transition_tool_invocation(transition_command(
                                    active.host_id,
                                    &active,
                                    &snapshot,
                                    ToolTransition::MarkUncertain,
                                ))
                                .await;
                        }
                    }
                }
                let _ = reconcile_reserved_approval_effects_in(
                    &*store,
                    active.session_id,
                    active.host_id,
                    active.owner_epoch,
                )
                .await;
                let mut routes = providers.lock().await;
                if routes
                    .get(&(active.session_id, active.provider_id))
                    .is_some_and(|current| {
                        current.connection_id == active.connection_id
                            && current.generation == active.generation
                    })
                {
                    routes.remove(&(active.session_id, active.provider_id));
                }
                drop(routes);
                changed.notify_waiters();
            })
            .await
            .map_err(|_| Status::unavailable("Tool provider admission is closed"))?;
        let connection = self
            .store
            .connect_tool_provider(ConnectToolProvider {
                context: RequestContext::new(request_id, self.host_id),
                session_id,
                owner_epoch,
                consumer_key: consumer_key.clone(),
                provider_id,
                connection_id,
                after_server_sequence: connect.after_server_sequence,
                registration_ids: registrations.clone(),
            })
            .await
            .map_err(|error| Status::failed_precondition(error.to_string()))?;
        let active = ActiveProvider {
            session_id,
            provider_id,
            connection_id,
            generation: connection.generation,
            host_id: self.host_id,
            owner_epoch,
            registrations: registrations.into_iter().collect(),
            sender: sender.clone(),
        };
        {
            let mut providers = self.providers.lock().await;
            providers.retain(|_, value| !value.sender.is_closed());
            if providers.len() >= MAX_ACTIVE_PROVIDERS
                && !providers.contains_key(&(session_id, provider_id))
            {
                return Err(Status::resource_exhausted("Tool provider capacity reached"));
            }
            install_provider_route(&mut providers, active.clone())?;
        }
        let connected = provider_connected_wire(&connection);

        let replay = self
            .store
            .list_provider_replay(session_id, provider_id, connect.after_server_sequence)
            .await
            .map_err(|error| Status::internal(error.to_string()))?;
        start_sender
            .send((active, replay, connect.after_server_sequence))
            .map_err(|_| Status::unavailable("Tool provider task stopped before replay"))?;
        Ok(Box::pin(
            tokio_stream::once(Ok(connected)).chain(ReceiverStream::new(receiver)),
        ))
    }

    async fn transition(
        &self,
        provider: &ActiveProvider,
        snapshot: &ToolInvocationSnapshot,
        transition: ToolTransition,
    ) -> Result<ToolInvocationSnapshot, StoreError> {
        self.store
            .transition_tool_invocation(transition_command(
                self.host_id,
                provider,
                snapshot,
                transition,
            ))
            .await
    }

    async fn cancel_operations_inner(
        &self,
        cancellation_request_id: RequestId,
        session_id: SessionId,
        operation_ids: &[OperationId],
    ) -> Result<(), ToolCancelError>
    where
        S: ApprovalStore,
    {
        let operations: HashSet<_> = operation_ids.iter().copied().collect();
        let owner_epoch = self
            .store
            .owner_epoch(session_id, self.host_id)
            .await
            .map_err(|_| ToolCancelError::Store)?;
        let invocations = self
            .store
            .list_recoverable_tool_invocations(session_id)
            .await
            .map_err(|_| ToolCancelError::Store)?;
        for snapshot in invocations {
            if !operations.contains(&snapshot.invocation().operation_id()) {
                continue;
            }
            self.cancel_one(cancellation_request_id, snapshot).await?;
            self.reconcile_reserved_approval_effects(session_id, owner_epoch)
                .await
                .map_err(|_| ToolCancelError::Store)?;
        }
        Ok(())
    }

    async fn cancel_one(
        &self,
        cancellation_request_id: RequestId,
        snapshot: ToolInvocationSnapshot,
    ) -> Result<(), ToolCancelError> {
        let provider = self
            .providers
            .lock()
            .await
            .get(&(
                snapshot.invocation().session_id(),
                snapshot.dispatch().provider_id,
            ))
            .cloned();
        let provider = match provider {
            Some(value) => value,
            None => self
                .recovery_provider(&snapshot)
                .await
                .map_err(|_| ToolCancelError::Store)?
                .ok_or(ToolCancelError::CleanupRequired)?,
        };
        if snapshot.phase() == ToolInvocationPhase::Reserved
            && snapshot.definition().cancellation() == ToolCancellation::Unsupported
        {
            let terminal = cancelled_failure(snapshot.invocation().invocation_id())?;
            self.transition(&provider, &snapshot, ToolTransition::Fail(terminal))
                .await
                .map_err(|_| ToolCancelError::Store)?;
            self.changed.notify_waiters();
            return Ok(());
        }
        if snapshot.definition().cancellation() == ToolCancellation::Unsupported {
            if matches!(
                snapshot.definition().effect_class(),
                EffectClass::Transactional | EffectClass::NonIdempotent | EffectClass::Unknown
            ) {
                self.transition(&provider, &snapshot, ToolTransition::MarkUncertain)
                    .await
                    .map_err(|_| ToolCancelError::Store)?;
                self.changed.notify_waiters();
            }
            // Read-only/idempotent handlers cannot be truthfully reported as
            // cancelled without a cooperative boundary. Their existing
            // deadline task will durably settle them.
            return Ok(());
        }
        let cancellation_id = derived_id(
            b"navigator.tool.cancellation.v1",
            &[
                cancellation_request_id.as_uuid().as_bytes(),
                snapshot.invocation().invocation_id().as_uuid().as_bytes(),
            ],
            navigator_domain::ToolCancellationId::from_uuid,
        );
        let updated = if snapshot.dispatch().cancellation_id == Some(cancellation_id) {
            snapshot
        } else if snapshot.dispatch().cancellation_id.is_some() {
            return Err(ToolCancelError::CleanupRequired);
        } else {
            self.transition(
                &provider,
                &snapshot,
                ToolTransition::RequestCancel { cancellation_id },
            )
            .await
            .map_err(|_| ToolCancelError::Store)?
        };
        if !matches!(
            tokio::time::timeout(
                SEND_BUDGET,
                provider.sender.send(Ok(cancellation_wire(&updated))),
            )
            .await,
            Ok(Ok(()))
        ) {
            return self.classify_after_cancel(&provider, updated).await;
        }
        tokio::time::sleep(CANCELLATION_GRACE).await;
        let current = self
            .store
            .load_tool_invocation(updated.invocation().invocation_id())
            .await
            .map_err(|_| ToolCancelError::Store)?
            .ok_or(ToolCancelError::Store)?;
        if current.terminal().is_some() || current.phase() == ToolInvocationPhase::Uncertain {
            return Ok(());
        }
        self.classify_after_cancel(&provider, current).await
    }

    async fn classify_after_cancel(
        &self,
        provider: &ActiveProvider,
        snapshot: ToolInvocationSnapshot,
    ) -> Result<(), ToolCancelError> {
        let transition = if snapshot.phase() == ToolInvocationPhase::Started
            && matches!(
                snapshot.definition().effect_class(),
                EffectClass::Transactional | EffectClass::NonIdempotent | EffectClass::Unknown
            ) {
            ToolTransition::MarkUncertain
        } else {
            ToolTransition::Fail(cancelled_failure(snapshot.invocation().invocation_id())?)
        };
        let terminal = self
            .transition(provider, &snapshot, transition)
            .await
            .map_err(|_| ToolCancelError::Store)?;
        if terminal.terminal().is_some() {
            let _ = tokio::time::timeout(
                SEND_BUDGET,
                provider.sender.send(Ok(ack_wire(
                    &terminal,
                    v1::ToolProviderAckKind::Terminal,
                    false,
                ))),
            )
            .await;
        }
        self.changed.notify_waiters();
        Ok(())
    }

    async fn handle_command(
        &self,
        caller: AuthenticatedHierarchyCaller,
        command: driver_v1::ToolCommand,
    ) -> Result<driver_v1::tool_result_request::Result, ExecutorError>
    where
        S: ApprovalStore,
    {
        let result = self.handle_command_inner(caller, command).await;
        Ok(match result {
            Ok(value) => {
                driver_v1::tool_result_request::Result::Success(driver_v1::ToolCallResult {
                    output: value.output().to_vec(),
                    artifacts: value.artifacts().iter().map(driver_artifact_wire).collect(),
                })
            }
            Err(error) => driver_v1::tool_result_request::Result::Failure(driver_v1::Failure {
                code: error.driver_code().into(),
                message: error.public_message().into(),
                retryable: error.retryable(),
            }),
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn handle_command_inner(
        &self,
        caller: AuthenticatedHierarchyCaller,
        command: driver_v1::ToolCommand,
    ) -> Result<ToolResult, BrokerError>
    where
        S: ApprovalStore,
    {
        let request_id = parse_id(&command.request_id, RequestId::from_uuid)?;
        let session_id = parse_id(&command.session_id, SessionId::from_uuid)?;
        let participant_id = parse_id(&command.participant_id, ParticipantId::from_uuid)?;
        let operation_id = parse_id(&command.operation_id, OperationId::from_uuid)?;
        if session_id != caller.session_id || participant_id != caller.participant_id {
            return Err(BrokerError::Unauthorized);
        }
        let invocation_id = derived_id(
            b"navigator.tool.invocation.v1",
            &[
                session_id.as_uuid().as_bytes(),
                request_id.as_uuid().as_bytes(),
            ],
            ToolInvocationId::from_uuid,
        );
        let input = CanonicalJson::<MAX_TOOL_INLINE_BYTES>::new(&command.input)
            .map_err(|_| BrokerError::Invalid)?;
        let mut invocation = ToolInvocation::new(
            invocation_id,
            request_id,
            session_id,
            participant_id,
            operation_id,
            ToolName::new(&command.tool_name).map_err(|_| BrokerError::Invalid)?,
            ToolVersion::new(&command.tool_version).map_err(|_| BrokerError::Invalid)?,
            input,
        )
        .map_err(|_| BrokerError::Invalid)?;
        if !command.authority_grant_id.is_empty() {
            invocation = invocation
                .with_authority_grant(parse_id(&command.authority_grant_id, GrantId::from_uuid)?);
        }
        if !command.approval_grant_id.is_empty() {
            let approval_grant_id = parse_id(&command.approval_grant_id, GrantId::from_uuid)?;
            let approval_effect_id = derived_id(
                b"navigator.tool.approval-effect.v1",
                &[
                    session_id.as_uuid().as_bytes(),
                    request_id.as_uuid().as_bytes(),
                ],
                RequestId::from_uuid,
            );
            invocation = invocation.with_approval_grant(approval_grant_id, approval_effect_id);
        }
        let existing_invocation = self
            .store
            .load_tool_invocation(invocation_id)
            .await
            .map_err(BrokerError::Store)?;
        if existing_invocation
            .as_ref()
            .is_some_and(|existing| existing.invocation() != &invocation)
        {
            return Err(BrokerError::Store(StoreError::RequestConflict {
                request_id,
            }));
        }
        let approval_effect_id = if command.approval_grant_id.is_empty() {
            None
        } else {
            // Reject an invalid or currently undispatchable Tool before
            // spending the narrow approval use. The authoritative lookup is
            // repeated below when reserving the Tool invocation.
            let approval_registration = self
                .store
                .list_tool_registrations(session_id)
                .await
                .map_err(BrokerError::Store)?
                .into_iter()
                .find(|value| {
                    value.definition.name() == command.tool_name
                        && value.definition.version() == command.tool_version
                })
                .ok_or(BrokerError::Unavailable)?;
            approval_registration
                .definition
                .validate_input(invocation.input())
                .map_err(|_| BrokerError::Invalid)?;
            if !self.providers.lock().await.values().any(|value| {
                value.session_id == session_id
                    && value
                        .registrations
                        .contains(&approval_registration.registration_id)
                    && !value.sender.is_closed()
            }) {
                return Err(BrokerError::Unavailable);
            }
            let grant_id = parse_id(&command.approval_grant_id, GrantId::from_uuid)?;
            let capability = navigator_domain::Capability::new("tool.invoke")
                .map_err(|_| BrokerError::Corrupt)?;
            let input_value: serde_json::Value =
                serde_json::from_slice(&command.input).map_err(|_| BrokerError::Invalid)?;
            let resource_bytes = serde_json::to_vec(&serde_json::json!({
                "tool_name": command.tool_name,
                "tool_version": command.tool_version,
                "input": input_value,
            }))
            .map_err(|_| BrokerError::Invalid)?;
            let resource =
                ApprovalResource::new(&resource_bytes).map_err(|_| BrokerError::Invalid)?;
            let effect_id = derived_id(
                b"navigator.tool.approval-effect.v1",
                &[
                    session_id.as_uuid().as_bytes(),
                    request_id.as_uuid().as_bytes(),
                ],
                RequestId::from_uuid,
            );
            if let Ok(existing) = self.store.load_approval_effect(effect_id).await {
                if existing.session_id != session_id
                    || existing.grant_id != grant_id
                    || existing.subject_id != participant_id
                    || existing.operation_id != operation_id
                    || existing.capability != capability
                    || existing.resource_hash != resource.digest()
                {
                    return Err(BrokerError::Unauthorized);
                }
            } else {
                let grant = self
                    .store
                    .load_approval_grant(grant_id)
                    .await
                    .map_err(|_| BrokerError::Unauthorized)?;
                let consume_request_id = derived_id(
                    b"navigator.tool.approval-consume.v1",
                    &[
                        session_id.as_uuid().as_bytes(),
                        request_id.as_uuid().as_bytes(),
                    ],
                    RequestId::from_uuid,
                );
                crate::fault_matrix::external_fault_at("approval.external.before_call");
                self.store
                    .consume_approval_grant(ConsumeApprovalGrant {
                        context: RequestContext::new(consume_request_id, caller.host_id),
                        session_id,
                        owner_epoch: caller.ownership_epoch,
                        grant_id,
                        expected_revision: grant.revision,
                        effect_id,
                        subject_id: participant_id,
                        operation_id,
                        capability,
                        resource_hash: resource.digest(),
                    })
                    .await
                    .map_err(|_| BrokerError::Unauthorized)?;
                crate::fault_matrix::external_fault_at("approval.external.after_call");
                crate::fault_matrix::external_fault_at("approval.external.before_effect_proof");
                self.store
                    .load_approval_effect(effect_id)
                    .await
                    .map_err(|_| BrokerError::Unauthorized)?;
                crate::fault_matrix::external_fault_at("approval.external.after_effect_proof");
            }
            Some(effect_id)
        };
        if let Some(existing) = existing_invocation {
            self.schedule_deadline(existing.clone()).await?;
            let result = self.await_terminal(existing).await;
            self.finish_approval_effect(approval_effect_id, caller, &result)
                .await?;
            return result;
        }
        let registration = self
            .store
            .list_tool_registrations(session_id)
            .await
            .map_err(BrokerError::Store)?
            .into_iter()
            .find(|value| {
                value.definition.name() == command.tool_name
                    && value.definition.version() == command.tool_version
            })
            .ok_or(BrokerError::Unavailable)?;
        if registration.definition.requires_approval() && approval_effect_id.is_none() {
            return Err(BrokerError::Unauthorized);
        }
        let provider = {
            let providers = self.providers.lock().await;
            providers
                .values()
                .filter(|value| {
                    value.session_id == session_id
                        && value.registrations.contains(&registration.registration_id)
                        && !value.sender.is_closed()
                })
                .min_by_key(|value| value.provider_id)
                .cloned()
                .ok_or(BrokerError::Unavailable)?
        };
        registration
            .definition
            .validate_input(invocation.input())
            .map_err(|_| BrokerError::Invalid)?;
        let dispatch_id = random_id(ToolDispatchId::from_uuid)?;
        let deadline = deadline_after(registration.definition.timeout().as_millis())?;
        let snapshot = self
            .store
            .reserve_tool_invocation(ReserveToolInvocation {
                context: RequestContext::new(request_id, caller.host_id),
                owner_epoch: caller.ownership_epoch,
                invocation,
                dispatch_id,
                provider_id: provider.provider_id,
                registration_id: registration.registration_id,
                deadline,
                lease_duration: self.lease_duration,
            })
            .await
            .map_err(map_reserve_error)?;
        self.schedule_deadline(snapshot.clone()).await?;
        // Persistence is complete before the handler can observe the frame.
        crate::fault_matrix::external_fault_at("tool.external.before_call");
        let sent = matches!(
            tokio::time::timeout(
                SEND_BUDGET,
                provider
                    .sender
                    .send(Ok(invocation_wire(&snapshot, registration.registration_id))),
            )
            .await,
            Ok(Ok(()))
        );
        crate::fault_matrix::external_fault_at("tool.external.after_call");
        if !sent {
            let terminal = ToolFailure {
                invocation_id,
                kind: ToolFailureKind::ProviderUnavailable,
                message: BoundedText::new("Tool provider could not accept durable dispatch")
                    .map_err(|_| BrokerError::Corrupt)?,
                retryable: true,
            };
            let _ = self
                .transition(&provider, &snapshot, ToolTransition::Fail(terminal))
                .await;
            let result = Err(BrokerError::Capacity);
            self.finish_approval_effect(approval_effect_id, caller, &result)
                .await?;
            return result;
        }
        crate::fault_matrix::external_fault_at("tool.external.before_result_proof");
        let result = self.await_terminal(snapshot).await;
        crate::fault_matrix::external_fault_at("tool.external.after_result_proof");
        self.finish_approval_effect(approval_effect_id, caller, &result)
            .await?;
        result
    }

    async fn finish_approval_effect(
        &self,
        effect_id: Option<RequestId>,
        caller: AuthenticatedHierarchyCaller,
        result: &Result<ToolResult, BrokerError>,
    ) -> Result<(), BrokerError>
    where
        S: ApprovalStore,
    {
        let Some(effect_id) = effect_id else {
            return Ok(());
        };
        let effect = self.store.load_approval_effect(effect_id).await?;
        if effect.phase != navigator_domain::ApprovalEffectPhase::Reserved {
            return Ok(());
        }
        let phase = match result {
            Ok(_) => TerminalApprovalEffectPhase::Succeeded,
            Err(BrokerError::Tool(failure)) if failure.kind != ToolFailureKind::EffectUncertain => {
                TerminalApprovalEffectPhase::Failed
            }
            Err(BrokerError::Capacity) => TerminalApprovalEffectPhase::Failed,
            Err(_) => TerminalApprovalEffectPhase::Uncertain,
        };
        let finish_id = derived_id(
            b"navigator.tool.approval-finish.v1",
            &[effect_id.as_uuid().as_bytes()],
            RequestId::from_uuid,
        );
        approval_finish_pause(effect_id).await;
        self.store
            .finish_approval_effect(FinishApprovalEffect {
                context: RequestContext::new(finish_id, caller.host_id),
                session_id: caller.session_id,
                owner_epoch: caller.ownership_epoch,
                effect_id,
                expected_revision: effect.revision,
                phase,
            })
            .await?;
        Ok(())
    }

    async fn reconcile_reserved_approval_effects(
        &self,
        session_id: SessionId,
        owner_epoch: FencingEpoch,
    ) -> Result<(), BrokerError>
    where
        S: ApprovalStore,
    {
        reconcile_reserved_approval_effects_in(&*self.store, session_id, self.host_id, owner_epoch)
            .await
    }

    async fn await_terminal(
        &self,
        mut snapshot: ToolInvocationSnapshot,
    ) -> Result<ToolResult, BrokerError> {
        loop {
            match snapshot.terminal() {
                Some(ToolTerminal::Completed(result)) => return Ok(result.clone()),
                Some(ToolTerminal::Failed(failure)) => {
                    return Err(BrokerError::Tool(failure.clone()));
                }
                None if snapshot.phase() == ToolInvocationPhase::Uncertain => {
                    return Err(BrokerError::Uncertain);
                }
                None => {}
            }
            let now = now_timestamp()?;
            if timestamp_nanos(now) >= timestamp_nanos(snapshot.dispatch().deadline) {
                let provider = self
                    .providers
                    .lock()
                    .await
                    .get(&(
                        snapshot.invocation().session_id(),
                        snapshot.dispatch().provider_id,
                    ))
                    .cloned();
                let provider = match provider {
                    Some(value) => Some(value),
                    None => self.recovery_provider(&snapshot).await?,
                };
                if let Some(provider) = provider {
                    let transition = if snapshot.phase() == ToolInvocationPhase::Started
                        && matches!(
                            snapshot.definition().effect_class(),
                            EffectClass::Transactional
                                | EffectClass::NonIdempotent
                                | EffectClass::Unknown
                        ) {
                        ToolTransition::MarkUncertain
                    } else {
                        ToolTransition::Fail(ToolFailure {
                            invocation_id: snapshot.invocation().invocation_id(),
                            kind: ToolFailureKind::TimedOut,
                            message: BoundedText::new("Tool invocation exceeded its deadline")
                                .map_err(|_| BrokerError::Corrupt)?,
                            retryable: false,
                        })
                    };
                    if let Ok(updated) = self.transition(&provider, &snapshot, transition).await {
                        snapshot = updated;
                        continue;
                    }
                }
                return Err(BrokerError::TimedOut);
            }
            let remaining = (timestamp_nanos(snapshot.dispatch().deadline) - timestamp_nanos(now))
                .min(250_000_000);
            let notified = self.changed.notified();
            let duration =
                Duration::from_nanos(u64::try_from(remaining).map_err(|_| BrokerError::Corrupt)?);
            let _ = tokio::time::timeout(duration, notified).await;
            snapshot = self
                .store
                .load_tool_invocation(snapshot.invocation().invocation_id())
                .await
                .map_err(BrokerError::Store)?
                .ok_or(BrokerError::Corrupt)?;
        }
    }

    async fn recovery_provider(
        &self,
        snapshot: &ToolInvocationSnapshot,
    ) -> Result<Option<ActiveProvider>, BrokerError> {
        let (Some(connection_id), Some(generation)) = (
            snapshot.dispatch().connection_id,
            snapshot.dispatch().connection_generation,
        ) else {
            return Ok(None);
        };
        let owner_epoch = self
            .store
            .owner_epoch(snapshot.invocation().session_id(), self.host_id)
            .await
            .map_err(BrokerError::Store)?;
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        Ok(Some(ActiveProvider {
            session_id: snapshot.invocation().session_id(),
            provider_id: snapshot.dispatch().provider_id,
            connection_id,
            generation,
            host_id: self.host_id,
            owner_epoch,
            registrations: HashSet::from([snapshot.registration_id()]),
            sender,
        }))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "deadline recovery matrix is kept together so every durable phase is explicit"
    )]
    async fn schedule_deadline(&self, snapshot: ToolInvocationSnapshot) -> Result<(), BrokerError>
    where
        S: ApprovalStore,
    {
        if snapshot.terminal().is_some() || snapshot.phase() == ToolInvocationPhase::Uncertain {
            return Ok(());
        }
        let store = Arc::clone(&self.store);
        let providers = Arc::clone(&self.providers);
        let changed = Arc::clone(&self.changed);
        let host_id = self.host_id;
        self.background_tasks
            .spawn(async move {
                let now = now_timestamp().ok();
                let delay = now
                    .and_then(|value| {
                        let nanos = timestamp_nanos(snapshot.dispatch().deadline)
                            .saturating_sub(timestamp_nanos(value));
                        u64::try_from(nanos).ok()
                    })
                    .map_or(Duration::ZERO, Duration::from_nanos);
                tokio::time::sleep(delay).await;
                let Ok(Some(mut current)) = store
                    .load_tool_invocation(snapshot.invocation().invocation_id())
                    .await
                else {
                    return;
                };
                if current.terminal().is_some() || current.phase() == ToolInvocationPhase::Uncertain
                {
                    return;
                }
                let active = providers
                    .lock()
                    .await
                    .get(&(
                        current.invocation().session_id(),
                        current.dispatch().provider_id,
                    ))
                    .cloned();
                let provider = if let Some(value) = active {
                    value
                } else {
                    let (Some(connection_id), Some(generation)) = (
                        current.dispatch().connection_id,
                        current.dispatch().connection_generation,
                    ) else {
                        return;
                    };
                    let Ok(owner_epoch) = store
                        .owner_epoch(current.invocation().session_id(), host_id)
                        .await
                    else {
                        return;
                    };
                    let (sender, receiver) = mpsc::channel(1);
                    drop(receiver);
                    ActiveProvider {
                        session_id: current.invocation().session_id(),
                        provider_id: current.dispatch().provider_id,
                        connection_id,
                        generation,
                        host_id,
                        owner_epoch,
                        registrations: HashSet::from([current.registration_id()]),
                        sender,
                    }
                };
                if current.definition().cancellation() == ToolCancellation::Cooperative
                    && current.dispatch().cancellation_id.is_none()
                {
                    let cancellation_id = derived_id(
                        b"navigator.tool.deadline.cancellation.v1",
                        &[current.invocation().invocation_id().as_uuid().as_bytes()],
                        navigator_domain::ToolCancellationId::from_uuid,
                    );
                    if let Ok(cancelled) = store
                        .transition_tool_invocation(transition_command(
                            host_id,
                            &provider,
                            &current,
                            ToolTransition::RequestCancel { cancellation_id },
                        ))
                        .await
                    {
                        current = cancelled;
                        let _ = tokio::time::timeout(
                            SEND_BUDGET,
                            provider.sender.send(Ok(cancellation_wire(&current))),
                        )
                        .await;
                        tokio::time::sleep(CANCELLATION_GRACE).await;
                        let Ok(Some(reloaded)) = store
                            .load_tool_invocation(current.invocation().invocation_id())
                            .await
                        else {
                            return;
                        };
                        current = reloaded;
                        if current.terminal().is_some()
                            || current.phase() == ToolInvocationPhase::Uncertain
                        {
                            let _ = reconcile_reserved_approval_effects_in(
                                &*store,
                                current.invocation().session_id(),
                                host_id,
                                provider.owner_epoch,
                            )
                            .await;
                            changed.notify_waiters();
                            return;
                        }
                    }
                }
                let transition = if current.phase() == ToolInvocationPhase::Started
                    && matches!(
                        current.definition().effect_class(),
                        EffectClass::Transactional
                            | EffectClass::NonIdempotent
                            | EffectClass::Unknown
                    ) {
                    ToolTransition::MarkUncertain
                } else {
                    let Ok(message) = BoundedText::new("Tool invocation exceeded its deadline")
                    else {
                        return;
                    };
                    ToolTransition::Fail(ToolFailure {
                        invocation_id: current.invocation().invocation_id(),
                        kind: ToolFailureKind::TimedOut,
                        message,
                        retryable: false,
                    })
                };
                let _ = store
                    .transition_tool_invocation(transition_command(
                        host_id, &provider, &current, transition,
                    ))
                    .await;
                let _ = reconcile_reserved_approval_effects_in(
                    &*store,
                    current.invocation().session_id(),
                    host_id,
                    provider.owner_epoch,
                )
                .await;
                changed.notify_waiters();
            })
            .await
            .map_err(|_| BrokerError::Unavailable)
    }
}

impl<S: ToolStore + ArtifactStore + ApprovalStore + SessionConsumerKey + 'static>
    crate::ToolCommandSink for LocalToolBroker<S>
{
    fn handle(
        &self,
        caller: AuthenticatedHierarchyCaller,
        command: driver_v1::ToolCommand,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<driver_v1::tool_result_request::Result, ExecutorError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move { self.handle_command(caller, command).await })
    }
}

/// Small adapter kept separate from `ToolStore` so the durable Tool API remains
/// infrastructure-neutral.
pub trait SessionConsumerKey: Send + Sync {
    fn consumer_key(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<ConsumerKey, StoreError>> + Send;
    fn owner_epoch(
        &self,
        session_id: SessionId,
        host_id: HostId,
    ) -> impl Future<Output = Result<FencingEpoch, StoreError>> + Send;
}

impl SessionConsumerKey for navigator_store_sqlite::SqliteStore {
    async fn consumer_key(&self, session_id: SessionId) -> Result<ConsumerKey, StoreError> {
        use navigator_store_api::SessionStore;
        Ok(self.load_session(session_id).await?.consumer_key().clone())
    }

    async fn owner_epoch(
        &self,
        session_id: SessionId,
        host_id: HostId,
    ) -> Result<FencingEpoch, StoreError> {
        use navigator_store_api::SessionStore;
        match self.read_ownership(session_id).await? {
            navigator_domain::OwnershipSnapshot::Owned {
                host_id: owner,
                epoch,
                expires_at,
            } if owner == host_id
                && timestamp_nanos(expires_at)
                    > timestamp_nanos(now_timestamp().map_err(|_| StoreError::Unavailable)?) =>
            {
                Ok(epoch)
            }
            _ => Err(StoreError::Invalid),
        }
    }
}

async fn send_provider_frame(
    sender: &mpsc::Sender<Result<v1::ToolProviderResponse, Status>>,
    frame: v1::ToolProviderResponse,
) -> Result<(), BrokerError> {
    match tokio::time::timeout(SEND_BUDGET, sender.send(Ok(frame))).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(BrokerError::Capacity),
    }
}

async fn replay_provider_frames<S: ToolStore>(
    store: &S,
    provider: &ActiveProvider,
    replay: Vec<ToolInvocationSnapshot>,
    after: u64,
    sender: &mpsc::Sender<Result<v1::ToolProviderResponse, Status>>,
) -> Result<(), BrokerError> {
    let mut frames = Vec::new();
    for snapshot in replay {
        match recovery_disposition(&snapshot) {
            RecoveryDisposition::Dispatch => frames.push((
                snapshot.dispatch().server_sequence,
                0,
                invocation_wire(&snapshot, snapshot.registration_id()),
            )),
            RecoveryDisposition::MarkUncertain => {
                store
                    .transition_tool_invocation(transition_command(
                        provider.host_id,
                        provider,
                        &snapshot,
                        ToolTransition::MarkUncertain,
                    ))
                    .await?;
                // Once an unsafe Started invocation becomes Uncertain, ordinary
                // reconnect must emit no executable or cancellation frame.
                continue;
            }
            RecoveryDisposition::SuppressUncertain => continue,
            RecoveryDisposition::TerminalOrUncertain => {
                if snapshot.terminal().is_some() && snapshot.dispatch().server_sequence > after {
                    let cancellation_sequence = snapshot.dispatch().cancellation_server_sequence;
                    frames.push((
                        cancellation_sequence.unwrap_or(snapshot.dispatch().server_sequence),
                        u8::from(cancellation_sequence.is_some()),
                        ack_wire(&snapshot, v1::ToolProviderAckKind::Terminal, true),
                    ));
                }
            }
        }
        if let Some(sequence) = snapshot.dispatch().cancellation_server_sequence
            && sequence > after
        {
            frames.push((sequence, 0, cancellation_wire(&snapshot)));
        }
    }
    frames.sort_by_key(|(sequence, causal_order, _)| (*sequence, *causal_order));
    for (_, _, frame) in frames {
        send_provider_frame(sender, frame).await?;
    }
    Ok(())
}

async fn replay_provider_reconnect<S: ToolStore + ApprovalStore>(
    store: &S,
    provider: &ActiveProvider,
    replay: Vec<ToolInvocationSnapshot>,
    after: u64,
    sender: &mpsc::Sender<Result<v1::ToolProviderResponse, Status>>,
) -> Result<(), BrokerError> {
    replay_provider_frames(store, provider, replay, after, sender).await?;
    reconcile_reserved_approval_effects_in(
        store,
        provider.session_id,
        provider.host_id,
        provider.owner_epoch,
    )
    .await
}

#[allow(clippy::too_many_lines)]
async fn process_provider_frame<S: ToolStore + ArtifactStore>(
    store: &S,
    provider: &ActiveProvider,
    frame: v1::ToolProviderRequest,
    sender: &mpsc::Sender<Result<v1::ToolProviderResponse, Status>>,
) -> Result<(), BrokerError> {
    let transition = match frame.frame.ok_or(BrokerError::Invalid)? {
        v1::tool_provider_request::Frame::Connect(_) => return Err(BrokerError::Invalid),
        v1::tool_provider_request::Frame::Started(value) => {
            correlated(
                provider,
                &value.session_id,
                &value.provider_id,
                &value.connection_id,
            )?;
            let invocation_id = parse_id(&value.invocation_id, ToolInvocationId::from_uuid)?;
            let snapshot = store
                .load_tool_invocation(invocation_id)
                .await?
                .ok_or(BrokerError::Invalid)?;
            exact_provider_dispatch(provider, &snapshot)?;
            exact_dispatch(&snapshot, &value.dispatch_id, value.server_sequence)?;
            if snapshot.phase() == ToolInvocationPhase::Started {
                send_provider_frame(
                    sender,
                    ack_wire(&snapshot, v1::ToolProviderAckKind::Started, true),
                )
                .await?;
                return Ok(());
            }
            (
                snapshot,
                ToolTransition::Start,
                v1::ToolProviderAckKind::Started,
            )
        }
        v1::tool_provider_request::Frame::Result(value) => {
            correlated(
                provider,
                &value.session_id,
                &value.provider_id,
                &value.connection_id,
            )?;
            let invocation_id = parse_id(&value.invocation_id, ToolInvocationId::from_uuid)?;
            let snapshot = store
                .load_tool_invocation(invocation_id)
                .await?
                .ok_or(BrokerError::Invalid)?;
            exact_provider_dispatch(provider, &snapshot)?;
            exact_dispatch(&snapshot, &value.dispatch_id, value.server_sequence)?;
            snapshot
                .definition()
                .validate_output(&value.output)
                .map_err(|_| BrokerError::Invalid)?;
            let artifacts = value
                .artifacts
                .iter()
                .map(artifact_from_wire)
                .collect::<Result<Vec<_>, _>>()?;
            for artifact in &artifacts {
                let durable = store
                    .load_artifact(ArtifactAccess {
                        session_id: snapshot.invocation().session_id(),
                        owner: provider.host_id,
                        epoch: provider.owner_epoch,
                        artifact_id: artifact.artifact_id(),
                    })
                    .await?;
                if durable.state != ArtifactState::Available
                    || durable.artifact_id != artifact.artifact_id()
                    || durable.session_id != artifact.session_id()
                    || durable.creator_participant_id != artifact.creator_participant_id()
                    || durable.creator_operation_id != artifact.creator_operation_id()
                    || durable.media_type != *artifact.media_type()
                    || durable.size != artifact.size()
                    || durable.digest != artifact.digest()
                {
                    return Err(BrokerError::Invalid);
                }
            }
            let result = ToolResult::new(
                invocation_id,
                CanonicalJson::new(&value.output).map_err(|_| BrokerError::Invalid)?,
                artifacts,
            )
            .map_err(|_| BrokerError::Invalid)?;
            if snapshot.terminal() == Some(&ToolTerminal::Completed(result.clone())) {
                send_provider_frame(
                    sender,
                    ack_wire(&snapshot, v1::ToolProviderAckKind::Terminal, true),
                )
                .await?;
                return Ok(());
            }
            if snapshot.terminal().is_some() {
                return Err(BrokerError::Invalid);
            }
            (
                snapshot,
                ToolTransition::Complete(result),
                v1::ToolProviderAckKind::Terminal,
            )
        }
        v1::tool_provider_request::Frame::Failure(value) => {
            correlated(
                provider,
                &value.session_id,
                &value.provider_id,
                &value.connection_id,
            )?;
            let invocation_id = parse_id(&value.invocation_id, ToolInvocationId::from_uuid)?;
            let snapshot = store
                .load_tool_invocation(invocation_id)
                .await?
                .ok_or(BrokerError::Invalid)?;
            exact_provider_dispatch(provider, &snapshot)?;
            exact_dispatch(&snapshot, &value.dispatch_id, value.server_sequence)?;
            let failure = value.failure.ok_or(BrokerError::Invalid)?;
            let terminal = ToolFailure {
                invocation_id,
                kind: failure_kind(failure.code),
                message: BoundedText::<MAX_TOOL_FAILURE_MESSAGE_BYTES>::new(failure.message)
                    .map_err(|_| BrokerError::Invalid)?,
                retryable: failure.retry == v1::RetryClass::Safe as i32,
            };
            if snapshot.terminal() == Some(&ToolTerminal::Failed(terminal.clone())) {
                send_provider_frame(
                    sender,
                    ack_wire(&snapshot, v1::ToolProviderAckKind::Terminal, true),
                )
                .await?;
                return Ok(());
            }
            if snapshot.terminal().is_some() {
                return Err(BrokerError::Invalid);
            }
            (
                snapshot,
                ToolTransition::Fail(terminal),
                v1::ToolProviderAckKind::Terminal,
            )
        }
    };
    let (snapshot, transition, kind) = transition;
    let request_id = derived_id(
        match kind {
            v1::ToolProviderAckKind::Started => b"navigator.tool.started.v1".as_slice(),
            _ => b"navigator.tool.terminal.v1".as_slice(),
        },
        &[
            snapshot.invocation().invocation_id().as_uuid().as_bytes(),
            provider.connection_id.as_uuid().as_bytes(),
        ],
        RequestId::from_uuid,
    );
    let prior_phase = snapshot.phase();
    let updated = store
        .transition_tool_invocation(TransitionToolInvocation {
            context: RequestContext::new(request_id, provider.host_id),
            invocation_id: snapshot.invocation().invocation_id(),
            owner_epoch: provider.owner_epoch,
            expected_revision: snapshot.revision(),
            transition,
            provider_id: provider.provider_id,
            connection_id: provider.connection_id,
            connection_generation: provider.generation,
            dispatch_id: snapshot.dispatch().dispatch_id,
            server_sequence: snapshot.dispatch().server_sequence,
        })
        .await?;
    let duplicate = updated.revision() == snapshot.revision() || prior_phase == updated.phase();
    send_provider_frame(sender, ack_wire(&updated, kind, duplicate)).await?;
    Ok(())
}

fn transition_command(
    host_id: HostId,
    provider: &ActiveProvider,
    snapshot: &ToolInvocationSnapshot,
    transition: ToolTransition,
) -> TransitionToolInvocation {
    let request_domain: &[u8] = match &transition {
        ToolTransition::Start => b"navigator.tool.recovery.start.v1",
        ToolTransition::Complete(_) => b"navigator.tool.recovery.complete.v1",
        ToolTransition::Fail(_) => b"navigator.tool.recovery.fail.v1",
        ToolTransition::MarkUncertain => b"navigator.tool.recovery.uncertain.v1",
        ToolTransition::RequestCancel { .. } => b"navigator.tool.recovery.cancel.v1",
    };
    let request_id = derived_id(
        request_domain,
        &[
            snapshot.invocation().invocation_id().as_uuid().as_bytes(),
            provider.connection_id.as_uuid().as_bytes(),
        ],
        RequestId::from_uuid,
    );
    TransitionToolInvocation {
        context: RequestContext::new(request_id, host_id),
        invocation_id: snapshot.invocation().invocation_id(),
        owner_epoch: provider.owner_epoch,
        expected_revision: snapshot.revision(),
        transition,
        provider_id: provider.provider_id,
        connection_id: provider.connection_id,
        connection_generation: provider.generation,
        dispatch_id: snapshot.dispatch().dispatch_id,
        server_sequence: snapshot.dispatch().server_sequence,
    }
}

fn cancellation_wire(value: &ToolInvocationSnapshot) -> v1::ToolProviderResponse {
    v1::ToolProviderResponse {
        frame: Some(v1::tool_provider_response::Frame::Cancellation(
            v1::ToolInvocationCancel {
                session_id: value
                    .invocation()
                    .session_id()
                    .as_uuid()
                    .as_bytes()
                    .to_vec(),
                invocation_id: value
                    .invocation()
                    .invocation_id()
                    .as_uuid()
                    .as_bytes()
                    .to_vec(),
                dispatch_id: value.dispatch().dispatch_id.as_uuid().as_bytes().to_vec(),
                server_sequence: value
                    .dispatch()
                    .cancellation_server_sequence
                    .expect("persisted cancellation has a sequence"),
                cancellation_id: value
                    .dispatch()
                    .cancellation_id
                    .expect("persisted cancellation has an identity")
                    .as_uuid()
                    .as_bytes()
                    .to_vec(),
                requested_at: Some(timestamp_wire(
                    now_timestamp().unwrap_or(value.dispatch().deadline),
                )),
            },
        )),
    }
}

fn cancelled_failure(invocation_id: ToolInvocationId) -> Result<ToolFailure, ToolCancelError> {
    Ok(ToolFailure {
        invocation_id,
        kind: ToolFailureKind::Cancelled,
        message: BoundedText::new("Tool invocation was cancelled")
            .map_err(|_| ToolCancelError::Store)?,
        retryable: false,
    })
}

#[derive(Clone, Copy)]
enum RecoveryDisposition {
    Dispatch,
    MarkUncertain,
    /// An uncertain external effect requires explicit reconciliation. Ordinary
    /// provider reconnect must not re-emit Invocation or cancellation frames.
    SuppressUncertain,
    TerminalOrUncertain,
}

fn approval_terminal_phase(
    invocation: &ToolInvocationSnapshot,
) -> Option<TerminalApprovalEffectPhase> {
    match (invocation.phase(), invocation.terminal()) {
        (ToolInvocationPhase::Completed, Some(ToolTerminal::Completed(_))) => {
            Some(TerminalApprovalEffectPhase::Succeeded)
        }
        (ToolInvocationPhase::Failed, Some(ToolTerminal::Failed(failure))) => {
            Some(if failure.kind == ToolFailureKind::EffectUncertain {
                TerminalApprovalEffectPhase::Uncertain
            } else {
                TerminalApprovalEffectPhase::Failed
            })
        }
        (ToolInvocationPhase::Uncertain, _) => Some(TerminalApprovalEffectPhase::Uncertain),
        _ => None,
    }
}

async fn reconcile_reserved_approval_effects_in<S: ToolStore + ApprovalStore>(
    store: &S,
    session_id: SessionId,
    host_id: HostId,
    owner_epoch: FencingEpoch,
) -> Result<(), BrokerError> {
    for effect in store.list_reserved_approval_effects(session_id).await? {
        let Some(invocation) = store
            .load_tool_invocation_by_approval_effect(effect.effect_id)
            .await?
        else {
            continue;
        };
        if invocation.invocation().approval_effect_id() != Some(effect.effect_id)
            || invocation.invocation().approval_grant_id() != Some(effect.grant_id)
            || invocation.invocation().session_id() != effect.session_id
            || invocation.invocation().participant_id() != effect.subject_id
            || invocation.invocation().operation_id() != effect.operation_id
        {
            return Err(BrokerError::Corrupt);
        }
        let Some(phase) = approval_terminal_phase(&invocation) else {
            continue;
        };
        let finish_id = derived_id(
            b"navigator.tool.approval-finish.v1",
            &[effect.effect_id.as_uuid().as_bytes()],
            RequestId::from_uuid,
        );
        if approval_reconcile_crash_injected(effect.effect_id) {
            continue;
        }
        store
            .finish_approval_effect(FinishApprovalEffect {
                context: RequestContext::new(finish_id, host_id),
                session_id,
                owner_epoch,
                effect_id: effect.effect_id,
                expected_revision: effect.revision,
                phase,
            })
            .await?;
    }
    Ok(())
}

fn recovery_disposition(value: &ToolInvocationSnapshot) -> RecoveryDisposition {
    match value.phase() {
        ToolInvocationPhase::Reserved
            if matches!(
                value.definition().effect_class(),
                EffectClass::ReadOnly | EffectClass::Idempotent
            ) =>
        {
            RecoveryDisposition::Dispatch
        }
        ToolInvocationPhase::Reserved | ToolInvocationPhase::Uncertain => {
            RecoveryDisposition::SuppressUncertain
        }
        ToolInvocationPhase::Started
            if matches!(
                value.definition().effect_class(),
                EffectClass::ReadOnly | EffectClass::Idempotent
            ) =>
        {
            RecoveryDisposition::Dispatch
        }
        ToolInvocationPhase::Started => RecoveryDisposition::MarkUncertain,
        ToolInvocationPhase::Completed | ToolInvocationPhase::Failed => {
            RecoveryDisposition::TerminalOrUncertain
        }
    }
}

#[derive(Debug)]
enum BrokerError {
    Invalid,
    Unauthorized,
    Unavailable,
    Capacity,
    TimedOut,
    Uncertain,
    Corrupt,
    Tool(ToolFailure),
    Store(StoreError),
}
impl From<StoreError> for BrokerError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}
impl BrokerError {
    fn public_message(&self) -> &'static str {
        match self {
            Self::Invalid => "invalid Tool request",
            Self::Unauthorized => "Tool authority denied",
            Self::Unavailable => "Tool provider unavailable",
            Self::Capacity => "Tool provider backpressure",
            Self::TimedOut => "Tool invocation timed out",
            Self::Uncertain => "Tool effect is uncertain",
            Self::Corrupt => "Tool state is corrupt",
            Self::Tool(_) => "Tool handler failed",
            Self::Store(_) => "Tool persistence failed",
        }
    }
    fn retryable(&self) -> bool {
        matches!(self, Self::Unavailable | Self::Capacity)
            || matches!(
                self,
                Self::Store(StoreError::Busy | StoreError::Unavailable)
            )
    }
    fn driver_code(&self) -> driver_v1::FailureCode {
        match self {
            Self::Invalid => driver_v1::FailureCode::Validation,
            Self::Unauthorized => driver_v1::FailureCode::Authorization,
            Self::Unavailable | Self::Capacity => driver_v1::FailureCode::Unavailable,
            Self::TimedOut => driver_v1::FailureCode::Timeout,
            Self::Uncertain => driver_v1::FailureCode::UncertainEffect,
            Self::Tool(value) => match value.kind {
                ToolFailureKind::Unauthorized => driver_v1::FailureCode::Authorization,
                ToolFailureKind::TimedOut => driver_v1::FailureCode::Timeout,
                ToolFailureKind::Cancelled => driver_v1::FailureCode::Cancelled,
                ToolFailureKind::EffectUncertain => driver_v1::FailureCode::UncertainEffect,
                _ => driver_v1::FailureCode::Internal,
            },
            Self::Store(StoreError::Busy | StoreError::Unavailable) => {
                driver_v1::FailureCode::Unavailable
            }
            Self::Store(StoreError::Corrupt) | Self::Corrupt => {
                driver_v1::FailureCode::CorruptedState
            }
            Self::Store(_) => driver_v1::FailureCode::Internal,
        }
    }
}

fn definition_from_wire(value: &v1::ToolSpecification) -> Result<ToolDefinition, BrokerError> {
    let definition = ToolDefinition::new(
        ToolName::new(&value.name).map_err(|_| BrokerError::Invalid)?,
        ToolVersion::new(&value.version).map_err(|_| BrokerError::Invalid)?,
        CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(&value.input_schema)
            .map_err(|_| BrokerError::Invalid)?,
        CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(&value.output_schema)
            .map_err(|_| BrokerError::Invalid)?,
        navigator_domain::Capability::new(&value.required_authority)
            .map_err(|_| BrokerError::Invalid)?,
        ToolTimeout::from_millis(value.timeout_millis).map_err(|_| BrokerError::Invalid)?,
        match v1::ToolCancellationBehavior::try_from(value.cancellation_behavior)
            .map_err(|_| BrokerError::Invalid)?
        {
            v1::ToolCancellationBehavior::Cooperative => ToolCancellation::Cooperative,
            v1::ToolCancellationBehavior::Unsupported => ToolCancellation::Unsupported,
            v1::ToolCancellationBehavior::Unspecified => return Err(BrokerError::Invalid),
        },
        match v1::ToolEffectClass::try_from(value.effect_class).map_err(|_| BrokerError::Invalid)? {
            v1::ToolEffectClass::ReadOnly => EffectClass::ReadOnly,
            v1::ToolEffectClass::Idempotent => EffectClass::Idempotent,
            v1::ToolEffectClass::Transactional => EffectClass::Transactional,
            v1::ToolEffectClass::NonIdempotent => EffectClass::NonIdempotent,
            v1::ToolEffectClass::Unknown => EffectClass::Unknown,
            v1::ToolEffectClass::Unspecified => return Err(BrokerError::Invalid),
        },
        match v1::ToolIdempotencyContract::try_from(value.idempotency_contract)
            .map_err(|_| BrokerError::Invalid)?
        {
            v1::ToolIdempotencyContract::NoExternalEffect => IdempotencyContract::NoExternalEffect,
            v1::ToolIdempotencyContract::InvocationIdentity => {
                IdempotencyContract::InvocationIdentity
            }
            v1::ToolIdempotencyContract::ExternalTransactionProof => {
                IdempotencyContract::ExternalTransactionProof
            }
            v1::ToolIdempotencyContract::NeverReplay => IdempotencyContract::NeverReplay,
            v1::ToolIdempotencyContract::Unspecified => return Err(BrokerError::Invalid),
        },
    )
    .map_err(|_| BrokerError::Invalid)?;
    Ok(if value.requires_approval {
        definition.with_required_approval()
    } else {
        definition
    })
}

fn registration_wire(
    value: &navigator_store_api::ToolRegistrationSnapshot,
    request_id: RequestId,
) -> v1::ToolRegistrationSnapshot {
    v1::ToolRegistrationSnapshot {
        registration_id: value.registration_id.as_uuid().as_bytes().to_vec(),
        session_id: value.session_id.as_uuid().as_bytes().to_vec(),
        tool: Some(definition_wire(&value.definition)),
        revision: value.revision.get(),
        created_at: Some(timestamp_wire(value.registered_at)),
        updated_at: Some(timestamp_wire(value.registered_at)),
        active: true,
        request_id: request_id.as_uuid().as_bytes().to_vec(),
    }
}

fn definition_wire(value: &ToolDefinition) -> v1::ToolSpecification {
    v1::ToolSpecification {
        name: value.name().into(),
        version: value.version().into(),
        input_schema: value.input_schema().to_vec(),
        output_schema: value.output_schema().to_vec(),
        required_authority: value.required_authority().as_str().into(),
        timeout_millis: value.timeout().as_millis(),
        cancellation_behavior: match value.cancellation() {
            ToolCancellation::Cooperative => v1::ToolCancellationBehavior::Cooperative,
            ToolCancellation::Unsupported => v1::ToolCancellationBehavior::Unsupported,
        }
        .into(),
        effect_class: match value.effect_class() {
            EffectClass::ReadOnly => v1::ToolEffectClass::ReadOnly,
            EffectClass::Idempotent => v1::ToolEffectClass::Idempotent,
            EffectClass::Transactional => v1::ToolEffectClass::Transactional,
            EffectClass::NonIdempotent => v1::ToolEffectClass::NonIdempotent,
            EffectClass::Unknown => v1::ToolEffectClass::Unknown,
        }
        .into(),
        idempotency_contract: match value.idempotency() {
            IdempotencyContract::NoExternalEffect => v1::ToolIdempotencyContract::NoExternalEffect,
            IdempotencyContract::InvocationIdentity => {
                v1::ToolIdempotencyContract::InvocationIdentity
            }
            IdempotencyContract::ExternalTransactionProof => {
                v1::ToolIdempotencyContract::ExternalTransactionProof
            }
            IdempotencyContract::NeverReplay => v1::ToolIdempotencyContract::NeverReplay,
        }
        .into(),
        requires_approval: value.requires_approval(),
    }
}

fn provider_connected_wire(
    value: &navigator_store_api::ToolProviderConnectionSnapshot,
) -> v1::ToolProviderResponse {
    v1::ToolProviderResponse {
        frame: Some(v1::tool_provider_response::Frame::Connected(
            v1::ToolProviderConnected {
                session_id: value.session_id.as_uuid().as_bytes().to_vec(),
                provider_id: value.provider_id.as_uuid().as_bytes().to_vec(),
                connection_id: value.connection_id.as_uuid().as_bytes().to_vec(),
                next_server_sequence: value.next_server_sequence,
                accepted_after_server_sequence: value.acknowledged_server_sequence,
                high_water_server_sequence: value.next_server_sequence.saturating_sub(1),
            },
        )),
    }
}

fn invocation_wire(
    value: &ToolInvocationSnapshot,
    registration_id: ToolRegistrationId,
) -> v1::ToolProviderResponse {
    v1::ToolProviderResponse {
        frame: Some(v1::tool_provider_response::Frame::Invocation(
            v1::ToolInvocation {
                session_id: value
                    .invocation()
                    .session_id()
                    .as_uuid()
                    .as_bytes()
                    .to_vec(),
                registration_id: registration_id.as_uuid().as_bytes().to_vec(),
                invocation_id: value
                    .invocation()
                    .invocation_id()
                    .as_uuid()
                    .as_bytes()
                    .to_vec(),
                dispatch_id: value.dispatch().dispatch_id.as_uuid().as_bytes().to_vec(),
                operation_id: value
                    .invocation()
                    .operation_id()
                    .as_uuid()
                    .as_bytes()
                    .to_vec(),
                participant_id: value
                    .invocation()
                    .participant_id()
                    .as_uuid()
                    .as_bytes()
                    .to_vec(),
                server_sequence: value.dispatch().server_sequence,
                tool_name: value.invocation().tool_name().into(),
                tool_version: value.invocation().tool_version().into(),
                input: value.invocation().input().to_vec(),
                deadline: Some(timestamp_wire(value.dispatch().deadline)),
            },
        )),
    }
}

fn ack_wire(
    value: &ToolInvocationSnapshot,
    kind: v1::ToolProviderAckKind,
    duplicate: bool,
) -> v1::ToolProviderResponse {
    v1::ToolProviderResponse {
        frame: Some(v1::tool_provider_response::Frame::Acknowledgement(
            v1::ToolProviderAck {
                session_id: value
                    .invocation()
                    .session_id()
                    .as_uuid()
                    .as_bytes()
                    .to_vec(),
                invocation_id: value
                    .invocation()
                    .invocation_id()
                    .as_uuid()
                    .as_bytes()
                    .to_vec(),
                dispatch_id: value.dispatch().dispatch_id.as_uuid().as_bytes().to_vec(),
                server_sequence: value.dispatch().server_sequence,
                kind: kind.into(),
                duplicate,
            },
        )),
    }
}

fn artifact_from_wire(value: &v1::ArtifactReference) -> Result<ArtifactRef, BrokerError> {
    let digest: [u8; 32] = value
        .sha256
        .as_slice()
        .try_into()
        .map_err(|_| BrokerError::Invalid)?;
    ArtifactRef::new(
        parse_id(&value.artifact_id, ArtifactId::from_uuid)?,
        parse_id(&value.session_id, SessionId::from_uuid)?,
        parse_id(&value.creator_participant_id, ParticipantId::from_uuid)?,
        parse_id(&value.creator_operation_id, OperationId::from_uuid)?,
        ArtifactMediaType::new(&value.media_type).map_err(|_| BrokerError::Invalid)?,
        value.size,
        ArtifactDigest::from_bytes(digest),
    )
    .map_err(|_| BrokerError::Invalid)
}

fn driver_artifact_wire(value: &ArtifactRef) -> driver_v1::ToolArtifactReference {
    driver_v1::ToolArtifactReference {
        artifact_id: value.artifact_id().as_uuid().as_bytes().to_vec(),
        session_id: value.session_id().as_uuid().as_bytes().to_vec(),
        creator_participant_id: value.creator_participant_id().as_uuid().as_bytes().to_vec(),
        creator_operation_id: value.creator_operation_id().as_uuid().as_bytes().to_vec(),
        media_type: value.media_type().as_str().into(),
        size: value.size(),
        sha256: value.digest().as_bytes().to_vec(),
    }
}

fn correlated(
    provider: &ActiveProvider,
    session: &[u8],
    provider_id: &[u8],
    connection: &[u8],
) -> Result<(), BrokerError> {
    if parse_id(session, SessionId::from_uuid)? != provider.session_id
        || parse_id(provider_id, ToolProviderId::from_uuid)? != provider.provider_id
        || parse_id(connection, ToolConnectionId::from_uuid)? != provider.connection_id
    {
        return Err(BrokerError::Invalid);
    }
    Ok(())
}
fn exact_dispatch(
    value: &ToolInvocationSnapshot,
    dispatch: &[u8],
    sequence: u64,
) -> Result<(), BrokerError> {
    if parse_id(dispatch, ToolDispatchId::from_uuid)? != value.dispatch().dispatch_id
        || sequence != value.dispatch().server_sequence
    {
        return Err(BrokerError::Invalid);
    }
    Ok(())
}
fn exact_provider_dispatch(
    provider: &ActiveProvider,
    value: &ToolInvocationSnapshot,
) -> Result<(), BrokerError> {
    if value.dispatch().provider_id != provider.provider_id
        || value.dispatch().connection_id != Some(provider.connection_id)
        || value.dispatch().connection_generation != Some(provider.generation)
    {
        return Err(BrokerError::Invalid);
    }
    Ok(())
}

fn install_provider_route(
    routes: &mut HashMap<(SessionId, ToolProviderId), ActiveProvider>,
    candidate: ActiveProvider,
) -> Result<(), Status> {
    let key = (candidate.session_id, candidate.provider_id);
    if routes.get(&key).is_some_and(|current| {
        current.generation > candidate.generation
            || (current.generation == candidate.generation
                && current.connection_id != candidate.connection_id)
    }) {
        return Err(Status::failed_precondition(
            "Tool provider connection was superseded during admission",
        ));
    }
    routes.insert(key, candidate);
    Ok(())
}
fn failure_kind(code: i32) -> ToolFailureKind {
    match v1::FailureCode::try_from(code).unwrap_or(v1::FailureCode::Internal) {
        v1::FailureCode::Authorization => ToolFailureKind::Unauthorized,
        v1::FailureCode::Timeout => ToolFailureKind::TimedOut,
        v1::FailureCode::Cancelled => ToolFailureKind::Cancelled,
        v1::FailureCode::UncertainEffect => ToolFailureKind::EffectUncertain,
        v1::FailureCode::InvalidRequest => ToolFailureKind::InvalidOutput,
        _ => ToolFailureKind::HandlerFailed,
    }
}
fn map_reserve_error(value: StoreError) -> BrokerError {
    if matches!(value, StoreError::Invalid) {
        BrokerError::Unauthorized
    } else {
        BrokerError::Store(value)
    }
}
fn register_failure(error: &BrokerError) -> v1::RegisterToolResponse {
    v1::RegisterToolResponse {
        outcome: Some(v1::register_tool_response::Outcome::Failure(v1::Failure {
            code: match error {
                BrokerError::Invalid => v1::FailureCode::InvalidRequest,
                BrokerError::Unauthorized => v1::FailureCode::Authentication,
                BrokerError::Unavailable | BrokerError::Capacity => v1::FailureCode::Unavailable,
                BrokerError::TimedOut => v1::FailureCode::Timeout,
                BrokerError::Uncertain => v1::FailureCode::UncertainEffect,
                BrokerError::Corrupt => v1::FailureCode::CorruptedState,
                BrokerError::Store(StoreError::RequestConflict { .. }) => v1::FailureCode::Conflict,
                BrokerError::Tool(_) | BrokerError::Store(_) => v1::FailureCode::Internal,
            }
            .into(),
            message: error.public_message().into(),
            retry: if error.retryable() {
                v1::RetryClass::Safe
            } else {
                v1::RetryClass::Never
            }
            .into(),
            related_id: None,
            details: vec![],
        })),
    }
}

fn timestamp_wire(value: Timestamp) -> v1::Timestamp {
    v1::Timestamp {
        unix_seconds: value.unix_seconds(),
        nanoseconds: value.nanoseconds(),
    }
}
fn now_timestamp() -> Result<Timestamp, BrokerError> {
    let now = time::OffsetDateTime::now_utc();
    Timestamp::new(now.unix_timestamp(), now.nanosecond()).map_err(|_| BrokerError::Corrupt)
}
fn deadline_after(millis: u64) -> Result<Timestamp, BrokerError> {
    let now = now_timestamp()?;
    let nanos = timestamp_nanos(now)
        .checked_add(i128::from(millis) * 1_000_000)
        .ok_or(BrokerError::Corrupt)?;
    let seconds = i64::try_from(nanos / 1_000_000_000).map_err(|_| BrokerError::Corrupt)?;
    let subsecond =
        u32::try_from(nanos.rem_euclid(1_000_000_000)).map_err(|_| BrokerError::Corrupt)?;
    Timestamp::new(seconds, subsecond).map_err(|_| BrokerError::Corrupt)
}
fn timestamp_nanos(value: Timestamp) -> i128 {
    i128::from(value.unix_seconds()) * 1_000_000_000 + i128::from(value.nanoseconds())
}
fn parse_id<T>(
    bytes: &[u8],
    make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
) -> Result<T, BrokerError> {
    make(Uuid::from_slice(bytes).map_err(|_| BrokerError::Invalid)?)
        .map_err(|_| BrokerError::Invalid)
}
fn derived_uuid(domain: &[u8], parts: &[&[u8]]) -> Uuid {
    let mut h = Sha256::new();
    h.update(domain);
    for p in parts {
        h.update(p.len().to_be_bytes());
        h.update(p);
    }
    let mut bytes: [u8; 16] = h.finalize()[..16].try_into().expect("fixed digest");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
fn derived_id<T>(
    domain: &[u8],
    parts: &[&[u8]],
    make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
) -> T {
    make(derived_uuid(domain, parts)).expect("derived UUID is non-nil")
}
fn random_id<T>(
    make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
) -> Result<T, BrokerError> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| BrokerError::Unavailable)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    make(Uuid::from_bytes(bytes)).map_err(|_| BrokerError::Corrupt)
}

fn stable_registration_id(
    session_id: SessionId,
    definition: &ToolDefinition,
) -> ToolRegistrationId {
    derived_id(
        b"navigator.tool.registration.v1",
        &[
            session_id.as_uuid().as_bytes(),
            definition.name().as_bytes(),
            definition.version().as_bytes(),
        ],
        ToolRegistrationId::from_uuid,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use navigator_domain::{
        ApprovalResource, ApprovalSummary, AuthorityProfile, InputSchema, LaunchAttemptId,
        MessageId, ResourceScope, ScopedCapability,
    };
    use navigator_domain::{DeliveryAttemptId, DriverId, InstanceId, OperationAction, Revision};
    use navigator_store_api::{
        AcquireOwnership, ApprovalStore, ApproveRequest, AttachLaunch, AuthorityPolicySnapshot,
        AuthorityStore, DeliveryTransition, EventReadLimit, InstanceStore, LaunchState,
        LeaseDuration, LeaseNextMessage, MailboxStore, OperationStore, PrepareLaunch,
        ProcessEvidence, PutAuthorityPolicy, ReadEvents, ReleaseOwnership, RenewOwnership,
        RequestApproval, SessionStore, StartOperation, TransitionLaunch, TransitionMessageDelivery,
        TransitionOperation,
    };
    use navigator_store_api::{
        ConnectToolProvider, RegisterTool, ReserveToolInvocation, ToolDispatchSnapshot,
        ToolProviderConnectionSnapshot, ToolRegistrationSnapshot, TransitionToolInvocation,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::{
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::Command,
    };
    use tempfile::TempDir;
    use tokio::sync::watch;
    use tonic::{Request, metadata::MetadataValue, transport::Endpoint};

    fn id<T>(
        value: u128,
        make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
    ) -> T {
        make(Uuid::from_u128(value)).unwrap()
    }

    async fn stale_owner_rejected_without_mutation(
        store: &navigator_store_sqlite::SqliteStore,
        session: SessionId,
    ) -> bool {
        let navigator_domain::OwnershipSnapshot::Owned {
            host_id,
            epoch,
            expires_at: _,
        } = store.read_ownership(session).await.unwrap()
        else {
            return false;
        };
        store
            .release_ownership(ReleaseOwnership::new(
                RequestContext::new(id(99_801, RequestId::from_uuid), host_id),
                session,
                epoch,
            ))
            .await
            .unwrap();
        let successor = id(99_802, HostId::from_uuid);
        store
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(id(99_803, RequestId::from_uuid), successor),
                session,
                LeaseDuration::from_millis(60_000).unwrap(),
            ))
            .await
            .unwrap();
        let before = store.load_session(session).await.unwrap();
        let before_events = store
            .read_events(ReadEvents {
                session_id: session,
                consumer: before.consumer_key().clone(),
                after: None,
                limit: EventReadLimit::new(128).unwrap(),
            })
            .await
            .unwrap()
            .events
            .len();
        let rejected = matches!(
            store
                .renew_ownership(RenewOwnership::new(
                    RequestContext::new(id(99_804, RequestId::from_uuid), host_id),
                    session,
                    epoch,
                    LeaseDuration::from_millis(60_000).unwrap(),
                ))
                .await,
            Err(StoreError::StaleOwnership { .. })
        );
        let after = store.load_session(session).await.unwrap();
        let after_events = store
            .read_events(ReadEvents {
                session_id: session,
                consumer: after.consumer_key().clone(),
                after: None,
                limit: EventReadLimit::new(128).unwrap(),
            })
            .await
            .unwrap()
            .events
            .len();
        rejected && before == after && before_events == after_events
    }

    fn definition(class: EffectClass) -> ToolDefinition {
        definition_with_cancellation(class, ToolCancellation::Cooperative)
    }

    fn definition_with_cancellation(
        class: EffectClass,
        cancellation: ToolCancellation,
    ) -> ToolDefinition {
        let contract = match class {
            EffectClass::ReadOnly => IdempotencyContract::NoExternalEffect,
            EffectClass::Idempotent => IdempotencyContract::InvocationIdentity,
            EffectClass::Transactional => IdempotencyContract::ExternalTransactionProof,
            EffectClass::NonIdempotent | EffectClass::Unknown => IdempotencyContract::NeverReplay,
        };
        ToolDefinition::new(
            ToolName::new("records.lookup").unwrap(),
            ToolVersion::new("v1").unwrap(),
            CanonicalJson::new(r#"{"type":"object"}"#).unwrap(),
            CanonicalJson::new(r#"{"type":"object"}"#).unwrap(),
            navigator_domain::Capability::new("tool.records.lookup").unwrap(),
            ToolTimeout::from_millis(1_000).unwrap(),
            cancellation,
            class,
            contract,
        )
        .unwrap()
    }

    fn snapshot(class: EffectClass, phase: ToolInvocationPhase) -> ToolInvocationSnapshot {
        snapshot_with_cancellation(class, phase, ToolCancellation::Cooperative)
    }

    fn snapshot_with_cancellation(
        class: EffectClass,
        phase: ToolInvocationPhase,
        cancellation: ToolCancellation,
    ) -> ToolInvocationSnapshot {
        let invocation = ToolInvocation::new(
            id(1, ToolInvocationId::from_uuid),
            id(2, RequestId::from_uuid),
            id(3, SessionId::from_uuid),
            id(4, ParticipantId::from_uuid),
            id(5, OperationId::from_uuid),
            ToolName::new("records.lookup").unwrap(),
            ToolVersion::new("v1").unwrap(),
            CanonicalJson::new("{}").unwrap(),
        )
        .unwrap();
        ToolInvocationSnapshot::new(
            id(6, ToolRegistrationId::from_uuid),
            definition_with_cancellation(class, cancellation),
            invocation,
            phase,
            None,
            Revision::initial(),
            ToolDispatchSnapshot {
                dispatch_id: id(7, ToolDispatchId::from_uuid),
                provider_id: id(8, ToolProviderId::from_uuid),
                server_sequence: 1,
                deadline: Timestamp::new(100, 0).unwrap(),
                connection_id: Some(id(9, ToolConnectionId::from_uuid)),
                connection_generation: Some(1),
                cancellation_id: None,
                cancellation_server_sequence: None,
                terminal_digest: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn disconnect_recovery_matrix_never_replays_an_unsafe_started_effect() {
        for class in [EffectClass::ReadOnly, EffectClass::Idempotent] {
            assert!(matches!(
                recovery_disposition(&snapshot(class, ToolInvocationPhase::Started)),
                RecoveryDisposition::Dispatch
            ));
        }
        for class in [
            EffectClass::Transactional,
            EffectClass::NonIdempotent,
            EffectClass::Unknown,
        ] {
            assert!(matches!(
                recovery_disposition(&snapshot(class, ToolInvocationPhase::Started)),
                RecoveryDisposition::MarkUncertain
            ));
        }
        assert!(matches!(
            recovery_disposition(&snapshot(
                EffectClass::NonIdempotent,
                ToolInvocationPhase::Reserved
            )),
            RecoveryDisposition::SuppressUncertain
        ));
        assert!(matches!(
            recovery_disposition(&snapshot(
                EffectClass::NonIdempotent,
                ToolInvocationPhase::Uncertain
            )),
            RecoveryDisposition::SuppressUncertain
        ));
    }

    #[test]
    fn approval_reconciler_maps_pending_and_terminal_tool_states_closed() {
        assert_eq!(
            approval_terminal_phase(&snapshot(
                EffectClass::NonIdempotent,
                ToolInvocationPhase::Reserved
            )),
            None
        );
        assert_eq!(
            approval_terminal_phase(&snapshot(
                EffectClass::NonIdempotent,
                ToolInvocationPhase::Started
            )),
            None
        );
        assert_eq!(
            approval_terminal_phase(&snapshot(
                EffectClass::NonIdempotent,
                ToolInvocationPhase::Uncertain
            )),
            Some(TerminalApprovalEffectPhase::Uncertain)
        );

        let base = snapshot(EffectClass::NonIdempotent, ToolInvocationPhase::Reserved);
        let terminal_snapshot = |terminal: ToolTerminal, phase| {
            ToolInvocationSnapshot::new(
                base.registration_id(),
                base.definition().clone(),
                base.invocation().clone(),
                phase,
                Some(terminal),
                base.revision(),
                base.dispatch().clone(),
            )
            .unwrap()
        };
        let completed = terminal_snapshot(
            ToolTerminal::Completed(
                ToolResult::new(
                    base.invocation().invocation_id(),
                    CanonicalJson::new(r#"{"ok":true}"#).unwrap(),
                    vec![],
                )
                .unwrap(),
            ),
            ToolInvocationPhase::Completed,
        );
        assert_eq!(
            approval_terminal_phase(&completed),
            Some(TerminalApprovalEffectPhase::Succeeded)
        );
        for (kind, expected) in [
            (
                ToolFailureKind::ProviderUnavailable,
                TerminalApprovalEffectPhase::Failed,
            ),
            (
                ToolFailureKind::EffectUncertain,
                TerminalApprovalEffectPhase::Uncertain,
            ),
        ] {
            let failed = terminal_snapshot(
                ToolTerminal::Failed(ToolFailure {
                    invocation_id: base.invocation().invocation_id(),
                    kind,
                    message: BoundedText::new("terminal").unwrap(),
                    retryable: false,
                }),
                ToolInvocationPhase::Failed,
            );
            assert_eq!(approval_terminal_phase(&failed), Some(expected));
        }
    }

    #[test]
    fn exact_dispatch_rejects_stale_connection_sequence_mutants() {
        let value = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Reserved);
        assert!(
            exact_dispatch(&value, value.dispatch().dispatch_id.as_uuid().as_bytes(), 1).is_ok()
        );
        assert!(
            exact_dispatch(
                &value,
                id(10, ToolDispatchId::from_uuid).as_uuid().as_bytes(),
                1
            )
            .is_err()
        );
        assert!(
            exact_dispatch(&value, value.dispatch().dispatch_id.as_uuid().as_bytes(), 2).is_err()
        );
    }

    #[test]
    fn wire_definition_is_executable_schema_not_descriptive_metadata() {
        let mut wire = definition_wire(&definition(EffectClass::ReadOnly));
        assert!(definition_from_wire(&wire).is_ok());
        wire.input_schema = br#"{"type":"object","required":["key"]}"#.to_vec();
        let parsed = definition_from_wire(&wire).unwrap();
        assert!(parsed.validate_input(br#"{"key":1}"#).is_ok());
        assert!(parsed.validate_input(b"{}").is_err());
        wire.input_schema = b"[]".to_vec();
        assert!(definition_from_wire(&wire).is_err());
    }

    #[test]
    fn driver_artifact_reference_preserves_every_authority_and_integrity_field() {
        let reference = ArtifactRef::new(
            id(40, ArtifactId::from_uuid),
            id(41, SessionId::from_uuid),
            id(42, ParticipantId::from_uuid),
            id(43, OperationId::from_uuid),
            ArtifactMediaType::new("application/octet-stream").unwrap(),
            17,
            ArtifactDigest::from_bytes([44; 32]),
        )
        .unwrap();
        let wire = driver_artifact_wire(&reference);
        assert_eq!(
            wire.artifact_id,
            reference.artifact_id().as_uuid().as_bytes()
        );
        assert_eq!(wire.session_id, reference.session_id().as_uuid().as_bytes());
        assert_eq!(
            wire.creator_participant_id,
            reference.creator_participant_id().as_uuid().as_bytes()
        );
        assert_eq!(
            wire.creator_operation_id,
            reference.creator_operation_id().as_uuid().as_bytes()
        );
        assert_eq!(wire.media_type, reference.media_type().as_str());
        assert_eq!(wire.size, 17);
        assert_eq!(wire.sha256, vec![44; 32]);
    }

    #[test]
    fn request_scoped_identities_are_stable_and_semantically_separated() {
        let session = id(20, SessionId::from_uuid);
        let request = id(21, RequestId::from_uuid);
        let first = derived_id(
            b"navigator.tool.invocation.v1",
            &[session.as_uuid().as_bytes(), request.as_uuid().as_bytes()],
            ToolInvocationId::from_uuid,
        );
        let replay = derived_id(
            b"navigator.tool.invocation.v1",
            &[session.as_uuid().as_bytes(), request.as_uuid().as_bytes()],
            ToolInvocationId::from_uuid,
        );
        let other = derived_id(
            b"navigator.tool.invocation.v1",
            &[
                session.as_uuid().as_bytes(),
                id(22, RequestId::from_uuid).as_uuid().as_bytes(),
            ],
            ToolInvocationId::from_uuid,
        );
        assert_eq!(first, replay);
        assert_ne!(first, other);
    }

    #[test]
    fn registration_identity_is_stable_across_fresh_request_ids() {
        let session = id(23, SessionId::from_uuid);
        let definition = definition(EffectClass::ReadOnly);
        let first = stable_registration_id(session, &definition);
        // Rejects the old request-scoped derivation: a semantically identical
        // re-registration must converge even when its mutation RequestId is new.
        let _fresh_request = id(24, RequestId::from_uuid);
        assert_eq!(first, stable_registration_id(session, &definition));
        let other_session = id(25, SessionId::from_uuid);
        assert_ne!(first, stable_registration_id(other_session, &definition));
    }

    #[test]
    fn duplicate_ack_shortcuts_are_fenced_to_current_connection_generation() {
        let value = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Started);
        let exact = ActiveProvider {
            session_id: value.invocation().session_id(),
            provider_id: value.dispatch().provider_id,
            connection_id: value.dispatch().connection_id.unwrap(),
            generation: value.dispatch().connection_generation.unwrap(),
            host_id: id(26, HostId::from_uuid),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            registrations: HashSet::from([value.registration_id()]),
            sender: mpsc::channel(1).0,
        };
        assert!(exact_provider_dispatch(&exact, &value).is_ok());
        let mut stale = exact;
        stale.connection_id = id(27, ToolConnectionId::from_uuid);
        assert!(exact_provider_dispatch(&stale, &value).is_err());
        stale.connection_id = value.dispatch().connection_id.unwrap();
        stale.generation += 1;
        assert!(exact_provider_dispatch(&stale, &value).is_err());
    }

    #[test]
    fn provider_admission_never_reinstalls_an_older_generation() {
        let value = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Reserved);
        let mut older = active_for(&value);
        older.generation = 1;
        older.connection_id = id(27, ToolConnectionId::from_uuid);
        let mut newer = older.clone();
        newer.generation = 2;
        newer.connection_id = id(28, ToolConnectionId::from_uuid);
        let key = (newer.session_id, newer.provider_id);
        let mut routes = HashMap::new();

        // Models the dangerous completion order: generation two finishes its
        // durable connect and installs before generation one returns.
        install_provider_route(&mut routes, newer.clone()).unwrap();
        assert!(install_provider_route(&mut routes, older).is_err());
        let current = routes.get(&key).unwrap();
        assert_eq!(current.generation, 2);
        assert_eq!(current.connection_id, newer.connection_id);
    }

    fn active_for(value: &ToolInvocationSnapshot) -> ActiveProvider {
        ActiveProvider {
            session_id: value.invocation().session_id(),
            provider_id: value.dispatch().provider_id,
            connection_id: value.dispatch().connection_id.unwrap(),
            generation: value.dispatch().connection_generation.unwrap(),
            host_id: id(28, HostId::from_uuid),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            registrations: HashSet::from([value.registration_id()]),
            sender: mpsc::channel(1).0,
        }
    }

    #[tokio::test]
    async fn reconnect_replays_terminal_ack_and_cancellation_in_durable_sequence_order() {
        let reserved = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Reserved);
        let store = FrameStore::new(reserved.clone());
        let cancelled = store
            .transition_tool_invocation(TransitionToolInvocation {
                context: RequestContext::new(
                    id(29, RequestId::from_uuid),
                    id(28, HostId::from_uuid),
                ),
                invocation_id: reserved.invocation().invocation_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                expected_revision: reserved.revision(),
                transition: ToolTransition::RequestCancel {
                    cancellation_id: id(30, navigator_domain::ToolCancellationId::from_uuid),
                },
                provider_id: reserved.dispatch().provider_id,
                connection_id: reserved.dispatch().connection_id.unwrap(),
                connection_generation: 1,
                dispatch_id: reserved.dispatch().dispatch_id,
                server_sequence: 1,
            })
            .await
            .unwrap();
        let (sender, mut receiver) = mpsc::channel(4);
        replay_provider_frames(&store, &active_for(&cancelled), vec![cancelled], 0, &sender)
            .await
            .unwrap();
        assert!(
            matches!(receiver.recv().await.unwrap().unwrap().frame, Some(v1::tool_provider_response::Frame::Invocation(value)) if value.server_sequence == 1)
        );
        assert!(
            matches!(receiver.recv().await.unwrap().unwrap().frame, Some(v1::tool_provider_response::Frame::Cancellation(value)) if value.server_sequence == 2)
        );

        let started = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Started);
        let terminal_store = FrameStore::new(started.clone());
        let failed = terminal_store
            .transition_tool_invocation(TransitionToolInvocation {
                context: RequestContext::new(
                    id(31, RequestId::from_uuid),
                    id(28, HostId::from_uuid),
                ),
                invocation_id: started.invocation().invocation_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                expected_revision: started.revision(),
                transition: ToolTransition::Fail(ToolFailure {
                    invocation_id: started.invocation().invocation_id(),
                    kind: ToolFailureKind::HandlerFailed,
                    message: BoundedText::new("failed").unwrap(),
                    retryable: false,
                }),
                provider_id: started.dispatch().provider_id,
                connection_id: started.dispatch().connection_id.unwrap(),
                connection_generation: 1,
                dispatch_id: started.dispatch().dispatch_id,
                server_sequence: 1,
            })
            .await
            .unwrap();
        let (sender, mut receiver) = mpsc::channel(2);
        replay_provider_frames(
            &terminal_store,
            &active_for(&failed),
            vec![failed],
            0,
            &sender,
        )
        .await
        .unwrap();
        assert!(
            matches!(receiver.recv().await.unwrap().unwrap().frame, Some(v1::tool_provider_response::Frame::Acknowledgement(v1::ToolProviderAck { kind, server_sequence: 1, duplicate: true, .. })) if kind == v1::ToolProviderAckKind::Terminal as i32)
        );
    }

    #[tokio::test]
    async fn reconnect_replays_cancel_before_later_terminal_ack_for_same_snapshot() {
        let reserved = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Reserved);
        let store = FrameStore::new(reserved.clone());
        let cancelled = store
            .transition_tool_invocation(TransitionToolInvocation {
                context: RequestContext::new(
                    id(32, RequestId::from_uuid),
                    id(28, HostId::from_uuid),
                ),
                invocation_id: reserved.invocation().invocation_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                expected_revision: reserved.revision(),
                transition: ToolTransition::RequestCancel {
                    cancellation_id: id(33, navigator_domain::ToolCancellationId::from_uuid),
                },
                provider_id: reserved.dispatch().provider_id,
                connection_id: reserved.dispatch().connection_id.unwrap(),
                connection_generation: 1,
                dispatch_id: reserved.dispatch().dispatch_id,
                server_sequence: 1,
            })
            .await
            .unwrap();
        let terminal = store
            .transition_tool_invocation(TransitionToolInvocation {
                context: RequestContext::new(
                    id(34, RequestId::from_uuid),
                    id(28, HostId::from_uuid),
                ),
                invocation_id: cancelled.invocation().invocation_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                expected_revision: cancelled.revision(),
                transition: ToolTransition::Fail(
                    cancelled_failure(cancelled.invocation().invocation_id()).unwrap(),
                ),
                provider_id: cancelled.dispatch().provider_id,
                connection_id: cancelled.dispatch().connection_id.unwrap(),
                connection_generation: 1,
                dispatch_id: cancelled.dispatch().dispatch_id,
                server_sequence: 1,
            })
            .await
            .unwrap();
        let (sender, mut receiver) = mpsc::channel(2);
        replay_provider_frames(&store, &active_for(&terminal), vec![terminal], 0, &sender)
            .await
            .unwrap();
        assert!(matches!(receiver.recv().await.unwrap().unwrap().frame,
            Some(v1::tool_provider_response::Frame::Cancellation(value)) if value.server_sequence == 2));
        assert!(matches!(receiver.recv().await.unwrap().unwrap().frame,
            Some(v1::tool_provider_response::Frame::Acknowledgement(v1::ToolProviderAck { kind, server_sequence: 1, .. }))
                if kind == v1::ToolProviderAckKind::Terminal as i32));
    }

    #[tokio::test]
    async fn unpublished_artifact_reference_is_rejected_before_terminal_commit() {
        let value = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Started);
        let store = FrameStore::new(value.clone());
        let provider = active_for(&value);
        let (sender, _receiver) = mpsc::channel(2);
        let frame = v1::ToolProviderRequest {
            frame: Some(v1::tool_provider_request::Frame::Result(
                v1::ToolHandlerResult {
                    session_id: value
                        .invocation()
                        .session_id()
                        .as_uuid()
                        .as_bytes()
                        .to_vec(),
                    provider_id: provider.provider_id.as_uuid().as_bytes().to_vec(),
                    connection_id: provider.connection_id.as_uuid().as_bytes().to_vec(),
                    invocation_id: value
                        .invocation()
                        .invocation_id()
                        .as_uuid()
                        .as_bytes()
                        .to_vec(),
                    dispatch_id: value.dispatch().dispatch_id.as_uuid().as_bytes().to_vec(),
                    server_sequence: value.dispatch().server_sequence,
                    output: b"{}".to_vec(),
                    artifacts: vec![v1::ArtifactReference {
                        artifact_id: id(45, ArtifactId::from_uuid).as_uuid().as_bytes().to_vec(),
                        session_id: value
                            .invocation()
                            .session_id()
                            .as_uuid()
                            .as_bytes()
                            .to_vec(),
                        creator_participant_id: value
                            .invocation()
                            .participant_id()
                            .as_uuid()
                            .as_bytes()
                            .to_vec(),
                        creator_operation_id: value
                            .invocation()
                            .operation_id()
                            .as_uuid()
                            .as_bytes()
                            .to_vec(),
                        media_type: "application/octet-stream".into(),
                        size: 1,
                        sha256: vec![46; 32],
                    }],
                },
            )),
        };
        assert!(matches!(
            process_provider_frame(&store, &provider, frame, &sender).await,
            Err(BrokerError::Store(StoreError::Unavailable))
        ));
        assert_eq!(store.transitions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn provider_output_backpressure_is_bounded_when_peer_does_not_read() {
        let (sender, _receiver) = mpsc::channel(1);
        let frame = v1::ToolProviderResponse { frame: None };
        send_provider_frame(&sender, frame.clone()).await.unwrap();
        let result = tokio::time::timeout(
            SEND_BUDGET + Duration::from_millis(100),
            send_provider_frame(&sender, frame),
        )
        .await
        .expect("provider send ignored its finite budget");
        assert!(matches!(result, Err(BrokerError::Capacity)));
    }

    #[tokio::test]
    async fn replay_larger_than_queue_progresses_only_in_independent_producer() {
        let value = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Reserved);
        let store = Arc::new(FrameStore::new(value.clone()));
        let provider = active_for(&value);
        let replay = vec![value; PROVIDER_QUEUE + 1];
        let (sender, mut receiver) = mpsc::channel(PROVIDER_QUEUE);
        let producer = tokio::spawn({
            let store = Arc::clone(&store);
            async move { replay_provider_frames(&*store, &provider, replay, 0, &sender).await }
        });
        // This receiver represents the already-returned response stream. The
        // old synchronous prefill implementation could never reach this loop.
        for _ in 0..=PROVIDER_QUEUE {
            assert!(matches!(
                receiver.recv().await.unwrap().unwrap().frame,
                Some(v1::tool_provider_response::Frame::Invocation(_))
            ));
        }
        producer.await.unwrap().unwrap();
    }

    struct FrameStore {
        snapshot: Mutex<Option<ToolInvocationSnapshot>>,
        transitions: AtomicUsize,
    }

    impl FrameStore {
        fn new(snapshot: ToolInvocationSnapshot) -> Self {
            Self {
                snapshot: Mutex::new(Some(snapshot)),
                transitions: AtomicUsize::new(0),
            }
        }
    }

    impl ToolStore for FrameStore {
        async fn connect_tool_provider(
            &self,
            _: ConnectToolProvider,
        ) -> Result<ToolProviderConnectionSnapshot, StoreError> {
            Err(StoreError::Unavailable)
        }
        async fn register_tool(
            &self,
            _: RegisterTool,
        ) -> Result<Mutation<ToolRegistrationSnapshot>, StoreError> {
            Err(StoreError::Unavailable)
        }
        async fn reserve_tool_invocation(
            &self,
            _: ReserveToolInvocation,
        ) -> Result<ToolInvocationSnapshot, StoreError> {
            Err(StoreError::Unavailable)
        }
        async fn transition_tool_invocation(
            &self,
            command: TransitionToolInvocation,
        ) -> Result<ToolInvocationSnapshot, StoreError> {
            self.transitions.fetch_add(1, Ordering::SeqCst);
            let current = self
                .snapshot
                .lock()
                .await
                .clone()
                .ok_or(StoreError::Corrupt)?;
            if command.expected_revision != current.revision() {
                return Err(StoreError::Invalid);
            }
            let mut dispatch = current.dispatch().clone();
            let (phase, terminal) = match command.transition {
                ToolTransition::Start => (ToolInvocationPhase::Started, None),
                ToolTransition::Complete(value) => (
                    ToolInvocationPhase::Completed,
                    Some(ToolTerminal::Completed(value)),
                ),
                ToolTransition::Fail(value) => (
                    ToolInvocationPhase::Failed,
                    Some(ToolTerminal::Failed(value)),
                ),
                ToolTransition::MarkUncertain => (ToolInvocationPhase::Uncertain, None),
                ToolTransition::RequestCancel { cancellation_id } => {
                    dispatch.cancellation_id = Some(cancellation_id);
                    dispatch.cancellation_server_sequence = Some(
                        dispatch
                            .server_sequence
                            .checked_add(1)
                            .ok_or(StoreError::Corrupt)?,
                    );
                    (current.phase(), None)
                }
            };
            let updated = ToolInvocationSnapshot::new(
                current.registration_id(),
                current.definition().clone(),
                current.invocation().clone(),
                phase,
                terminal,
                current.revision().next().ok_or(StoreError::Corrupt)?,
                dispatch,
            )
            .map_err(|_| StoreError::Invalid)?;
            *self.snapshot.lock().await = Some(updated.clone());
            Ok(updated)
        }
        async fn load_tool_invocation(
            &self,
            _: ToolInvocationId,
        ) -> Result<Option<ToolInvocationSnapshot>, StoreError> {
            Ok(self.snapshot.lock().await.clone())
        }
        async fn list_recoverable_tool_invocations(
            &self,
            _: SessionId,
        ) -> Result<Vec<ToolInvocationSnapshot>, StoreError> {
            Ok(vec![])
        }
        async fn load_tool_registration(
            &self,
            _: SessionId,
            _: ToolRegistrationId,
        ) -> Result<Option<ToolRegistrationSnapshot>, StoreError> {
            Ok(None)
        }
        async fn list_tool_registrations(
            &self,
            _: SessionId,
        ) -> Result<Vec<ToolRegistrationSnapshot>, StoreError> {
            Ok(vec![])
        }
        async fn list_provider_replay(
            &self,
            _: SessionId,
            _: ToolProviderId,
            _: u64,
        ) -> Result<Vec<ToolInvocationSnapshot>, StoreError> {
            Ok(vec![])
        }
    }

    impl ArtifactStore for FrameStore {
        async fn publish_artifact(
            &self,
            _: navigator_store_api::PublishArtifact,
        ) -> Result<Mutation<navigator_domain::ArtifactSnapshot>, StoreError> {
            Err(StoreError::Unavailable)
        }
        async fn load_artifact(
            &self,
            _: ArtifactAccess,
        ) -> Result<navigator_domain::ArtifactSnapshot, StoreError> {
            Err(StoreError::Unavailable)
        }
        async fn logically_delete_artifact(
            &self,
            _: navigator_store_api::DeleteArtifact,
        ) -> Result<Mutation<navigator_domain::ArtifactSnapshot>, StoreError> {
            Err(StoreError::Unavailable)
        }
        async fn retention_eligible_artifacts(
            &self,
            _: Timestamp,
            _: usize,
        ) -> Result<Vec<navigator_domain::ArtifactSnapshot>, StoreError> {
            Ok(vec![])
        }
        async fn authorize_physical_erasure(
            &self,
            _: &navigator_store_api::EraseArtifact,
        ) -> Result<navigator_domain::ArtifactSnapshot, StoreError> {
            Err(StoreError::Unavailable)
        }
        async fn record_physical_erasure(
            &self,
            _: navigator_store_api::EraseArtifact,
        ) -> Result<navigator_domain::ArtifactSnapshot, StoreError> {
            Err(StoreError::Unavailable)
        }
    }

    impl SessionConsumerKey for FrameStore {
        async fn consumer_key(&self, _: SessionId) -> Result<ConsumerKey, StoreError> {
            Ok(ConsumerKey::new("test-consumer").unwrap())
        }
        async fn owner_epoch(&self, _: SessionId, _: HostId) -> Result<FencingEpoch, StoreError> {
            Ok(FencingEpoch::new(1).unwrap())
        }
    }

    fn active(
        value: &ToolInvocationSnapshot,
    ) -> (
        ActiveProvider,
        mpsc::Receiver<Result<v1::ToolProviderResponse, Status>>,
    ) {
        let (sender, receiver) = mpsc::channel(4);
        (
            ActiveProvider {
                session_id: value.invocation().session_id(),
                provider_id: value.dispatch().provider_id,
                connection_id: value.dispatch().connection_id.unwrap(),
                generation: value.dispatch().connection_generation.unwrap(),
                host_id: id(30, HostId::from_uuid),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                registrations: HashSet::from([value.registration_id()]),
                sender,
            },
            receiver,
        )
    }

    fn started_frame(
        value: &ToolInvocationSnapshot,
        connection_id: ToolConnectionId,
    ) -> v1::ToolProviderRequest {
        v1::ToolProviderRequest {
            frame: Some(v1::tool_provider_request::Frame::Started(
                v1::ToolHandlerStarted {
                    session_id: value
                        .invocation()
                        .session_id()
                        .as_uuid()
                        .as_bytes()
                        .to_vec(),
                    provider_id: value.dispatch().provider_id.as_uuid().as_bytes().to_vec(),
                    connection_id: connection_id.as_uuid().as_bytes().to_vec(),
                    invocation_id: value
                        .invocation()
                        .invocation_id()
                        .as_uuid()
                        .as_bytes()
                        .to_vec(),
                    dispatch_id: value.dispatch().dispatch_id.as_uuid().as_bytes().to_vec(),
                    server_sequence: value.dispatch().server_sequence,
                    started_at: Some(v1::Timestamp {
                        unix_seconds: 50,
                        nanoseconds: 0,
                    }),
                },
            )),
        }
    }

    #[tokio::test]
    async fn started_ack_loss_replays_ack_without_reentering_the_durable_boundary() {
        let initial = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Reserved);
        let store = FrameStore::new(initial.clone());
        let (provider, mut receiver) = active(&initial);
        let frame = started_frame(&initial, provider.connection_id);
        process_provider_frame(&store, &provider, frame.clone(), &provider.sender)
            .await
            .unwrap();
        let first = receiver.recv().await.unwrap().unwrap();
        let Some(v1::tool_provider_response::Frame::Acknowledgement(first)) = first.frame else {
            panic!("expected Started acknowledgement");
        };
        assert!(!first.duplicate);
        process_provider_frame(&store, &provider, frame, &provider.sender)
            .await
            .unwrap();
        let replay = receiver.recv().await.unwrap().unwrap();
        let Some(v1::tool_provider_response::Frame::Acknowledgement(replay)) = replay.frame else {
            panic!("expected duplicate Started acknowledgement");
        };
        assert!(replay.duplicate);
        assert_eq!(store.transitions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stale_connection_is_fenced_before_any_effect_transition() {
        let initial = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Reserved);
        let store = FrameStore::new(initial.clone());
        let (provider, _) = active(&initial);
        let stale = started_frame(&initial, id(31, ToolConnectionId::from_uuid));
        assert!(
            process_provider_frame(&store, &provider, stale, &provider.sender)
                .await
                .is_err()
        );
        assert_eq!(store.transitions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn expired_reserved_work_is_durably_failed_even_after_memory_state_is_lost() {
        let initial = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Reserved);
        let store = Arc::new(FrameStore::new(initial.clone()));
        let broker = LocalToolBroker::new(
            Arc::clone(&store),
            id(30, HostId::from_uuid),
            Duration::from_secs(1),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
            crate::BackgroundTaskRegistry::new(),
        );
        assert!(matches!(
            broker.await_terminal(initial).await,
            Err(BrokerError::Tool(ToolFailure {
                kind: ToolFailureKind::TimedOut,
                ..
            }))
        ));
        assert_eq!(store.transitions.load(Ordering::SeqCst), 1);
        assert_eq!(
            store.snapshot.lock().await.as_ref().unwrap().phase(),
            ToolInvocationPhase::Failed
        );
    }

    #[tokio::test]
    async fn expired_started_non_idempotent_work_becomes_uncertain_never_failed_or_replayed() {
        let initial = snapshot(EffectClass::NonIdempotent, ToolInvocationPhase::Started);
        let store = Arc::new(FrameStore::new(initial.clone()));
        let broker = LocalToolBroker::new(
            Arc::clone(&store),
            id(30, HostId::from_uuid),
            Duration::from_secs(1),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
            crate::BackgroundTaskRegistry::new(),
        );
        assert!(matches!(
            broker.await_terminal(initial).await,
            Err(BrokerError::Uncertain)
        ));
        assert_eq!(store.transitions.load(Ordering::SeqCst), 1);
        assert_eq!(
            store.snapshot.lock().await.as_ref().unwrap().phase(),
            ToolInvocationPhase::Uncertain
        );
    }

    #[tokio::test]
    async fn cooperative_cancel_is_persisted_before_frame_and_terminal_ack() {
        let initial = snapshot(EffectClass::Idempotent, ToolInvocationPhase::Reserved);
        let store = Arc::new(FrameStore::new(initial.clone()));
        let broker = Arc::new(LocalToolBroker::new(
            Arc::clone(&store),
            id(30, HostId::from_uuid),
            Duration::from_secs(1),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
            crate::BackgroundTaskRegistry::new(),
        ));
        let (provider, mut receiver) = active(&initial);
        broker.providers.lock().await.insert(
            (
                initial.invocation().session_id(),
                initial.dispatch().provider_id,
            ),
            provider,
        );
        let task = {
            let broker = Arc::clone(&broker);
            tokio::spawn(async move {
                broker
                    .cancel_one(id(40, RequestId::from_uuid), initial)
                    .await
            })
        };
        let cancel = receiver.recv().await.unwrap().unwrap();
        let Some(v1::tool_provider_response::Frame::Cancellation(cancel)) = cancel.frame else {
            panic!("expected cancellation frame");
        };
        let persisted = store.snapshot.lock().await.clone().unwrap();
        assert_eq!(
            persisted
                .dispatch()
                .cancellation_id
                .unwrap()
                .as_uuid()
                .as_bytes()
                .as_slice(),
            cancel.cancellation_id.as_slice()
        );
        task.await.unwrap().unwrap();
        let ack = receiver.recv().await.unwrap().unwrap();
        assert!(matches!(
            ack.frame,
            Some(v1::tool_provider_response::Frame::Acknowledgement(
                v1::ToolProviderAck {
                    kind,
                    ..
                }
            )) if kind == v1::ToolProviderAckKind::Terminal as i32
        ));
        assert_eq!(
            store.snapshot.lock().await.as_ref().unwrap().phase(),
            ToolInvocationPhase::Failed
        );
    }

    #[tokio::test]
    async fn unsupported_cancel_never_emits_a_false_cancel_frame() {
        let initial = snapshot_with_cancellation(
            EffectClass::Idempotent,
            ToolInvocationPhase::Reserved,
            ToolCancellation::Unsupported,
        );
        let store = Arc::new(FrameStore::new(initial.clone()));
        let broker = LocalToolBroker::new(
            Arc::clone(&store),
            id(30, HostId::from_uuid),
            Duration::from_secs(1),
            Arc::new(std::sync::RwLock::new(HashMap::new())),
            crate::BackgroundTaskRegistry::new(),
        );
        let (provider, mut receiver) = active(&initial);
        broker.providers.lock().await.insert(
            (
                initial.invocation().session_id(),
                initial.dispatch().provider_id,
            ),
            provider,
        );
        broker
            .cancel_one(id(41, RequestId::from_uuid), initial)
            .await
            .unwrap();
        assert!(receiver.try_recv().is_err());
        assert_eq!(
            store.snapshot.lock().await.as_ref().unwrap().phase(),
            ToolInvocationPhase::Failed
        );
    }

    #[tokio::test]
    async fn negotiation_auth_rejects_unknown_unbound_and_cross_consumer_without_effect() {
        let store = Arc::new(FrameStore::new(snapshot(
            EffectClass::Idempotent,
            ToolInvocationPhase::Reserved,
        )));
        let bound_id = Uuid::from_u128(50);
        let unbound_id = Uuid::from_u128(51);
        let mut entries = HashMap::new();
        entries.insert(
            bound_id,
            crate::service::NegotiationEntry {
                capabilities: vec![CAPABILITY_CONSUMER_TOOLS_V1.into()],
                consumer_key: Some(ConsumerKey::new("other-consumer").unwrap()),
                reservation_id: None,
            },
        );
        entries.insert(
            unbound_id,
            crate::service::NegotiationEntry {
                capabilities: vec![CAPABILITY_CONSUMER_TOOLS_V1.into()],
                consumer_key: None,
                reservation_id: None,
            },
        );
        let broker = LocalToolBroker::new(
            Arc::clone(&store),
            id(30, HostId::from_uuid),
            Duration::from_secs(1),
            Arc::new(std::sync::RwLock::new(entries)),
            crate::BackgroundTaskRegistry::new(),
        );
        for negotiation_id in [Uuid::from_u128(52), unbound_id, bound_id] {
            let metadata = rpc_metadata(negotiation_id.as_bytes(), CAPABILITY_CONSUMER_TOOLS_V1);
            assert!(matches!(
                broker
                    .authenticated_consumer(&metadata, id(3, SessionId::from_uuid))
                    .await,
                Err(BrokerError::Unauthorized)
            ));
        }
        assert_eq!(store.transitions.load(Ordering::SeqCst), 0);
    }

    fn rpc_metadata(negotiation: &[u8], capability: &str) -> v1::RequestMetadata {
        crate::current_metadata(negotiation.to_vec(), &[capability])
    }

    fn authenticated<T>(value: T) -> Request<T> {
        let mut request = Request::new(value);
        request.metadata_mut().insert(
            crate::AUTHENTICATION_HEADER,
            MetadataValue::try_from("tool-rpc-test").unwrap(),
        );
        request
    }

    fn rpc_root_template() -> v1::RootTemplateSpecification {
        v1::RootTemplateSpecification {
            template_id: Uuid::from_u128(91_010).as_bytes().to_vec(),
            role: "tool-worker".into(),
            driver_id: Uuid::from_u128(91_011).as_bytes().to_vec(),
            required_capabilities: vec![v1::DriverCapabilityRequirement {
                capability: "durable.acceptance".into(),
                minimum_version: 1,
                parameters: vec![],
            }],
            trusted_configuration: Some(v1::TrustedTemplateConfiguration {
                base_instructions: "use a trusted tool".into(),
                secret_names: vec![],
            }),
            resources: Some(v1::ParticipantResourceBounds {
                memory_bytes: 1 << 20,
                cpu_millis: 1_000,
                max_concurrent_operations: 1,
            }),
            input_schema: Some(v1::InputSchema { fields: vec![] }),
            authority_profile: Some(v1::AuthorityProfileSpecification {
                active: vec![v1::ScopedCapabilitySpecification {
                    capability: "tool.records.lookup".into(),
                    resource: Some(v1::scoped_capability_specification::Resource::OperationId(
                        Uuid::from_u128(91_004).as_bytes().to_vec(),
                    )),
                }],
                delegable: vec![v1::ScopedCapabilitySpecification {
                    capability: "tool.records.lookup".into(),
                    resource: Some(v1::scoped_capability_specification::Resource::OperationId(
                        Uuid::from_u128(91_004).as_bytes().to_vec(),
                    )),
                }],
            }),
        }
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

    async fn rpc_next(
        stream: &mut tonic::Streaming<v1::ToolProviderResponse>,
        phase: &str,
    ) -> v1::ToolProviderResponse {
        tokio::time::timeout(Duration::from_secs(3), stream.message())
            .await
            .unwrap_or_else(|_| panic!("Tool RPC response timed out at {phase}"))
            .unwrap()
            .expect("Tool RPC stream closed")
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one real RPC lifecycle keeps causal order visible"
    )]
    async fn real_bidi_rpc_consumes_approval_before_handler_and_finishes_terminal() {
        let directory = TempDir::new().unwrap();
        let directory_path = std::env::var_os("NAVIGATOR_TOOL_FAULT_ROOT")
            .map_or_else(|| directory.path().to_path_buf(), PathBuf::from);
        std::fs::create_dir_all(&directory_path).unwrap();
        std::fs::set_permissions(&directory_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let database_path = directory_path.join("tool-rpc.db");
        let store = Arc::new(
            navigator_store_sqlite::SqliteStore::open(&database_path)
                .await
                .unwrap(),
        );
        let host_id = id(91_001, HostId::from_uuid);
        let mut service = crate::LocalNavigator::new(
            Arc::clone(&store),
            host_id,
            LeaseDuration::from_millis(60_000).unwrap(),
        );
        let (negotiations, background) = service.tool_test_context();
        let broker = Arc::new(LocalToolBroker::new(
            Arc::clone(&store),
            host_id,
            Duration::from_secs(60),
            negotiations,
            background,
        ));
        let controller: Arc<dyn ToolBrokerControl> = broker.clone();
        service = service.with_tool_controller(controller);
        let socket = directory_path.join("navigator.sock");
        let (shutdown, receiver) = watch::channel(false);
        let server = tokio::spawn(crate::serve(
            service,
            crate::BootstrapCredential::from_bytes(b"tool-rpc-test".to_vec()).unwrap(),
            crate::ServerConfig {
                socket_path: socket.clone(),
                shutdown_timeout: Duration::from_secs(2),
            },
            receiver,
        ));
        wait_for_socket(&socket).await;
        let channel = Endpoint::from_shared(format!("unix:{}", socket.display()))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = v1::navigator_consumer_client::NavigatorConsumerClient::new(channel);
        let negotiated = client
            .negotiate(authenticated(v1::NegotiateRequest {
                minimum_version: Some(v1::ProtocolVersion { major: 1, minor: 1 }),
                maximum_version: Some(v1::ProtocolVersion { major: 1, minor: 1 }),
                capabilities: vec![
                    "session.lifecycle.v1".into(),
                    CAPABILITY_CONSUMER_TOOLS_V1.into(),
                ],
            }))
            .await
            .unwrap()
            .into_inner();
        let Some(v1::negotiate_response::Outcome::Negotiated(negotiated)) = negotiated.outcome
        else {
            panic!("Tool capability did not negotiate");
        };
        let configuration_identity = negotiated.configuration_identity.clone();
        let session_uuid = Uuid::from_u128(91_002);
        let opened = client
            .open_session(authenticated(v1::OpenSessionRequest {
                metadata: Some(rpc_metadata(
                    &negotiated.negotiation_id,
                    "session.lifecycle.v1",
                )),
                request_id: Uuid::from_u128(91_003).as_bytes().to_vec(),
                session_id: session_uuid.as_bytes().to_vec(),
                consumer_key: "tool-rpc".into(),
                compatibility_identity: Vec::new(),
                root_template: Some(rpc_root_template()),
                compatible_templates: vec![],
                configuration_identity: configuration_identity.clone(),
                mode: v1::SessionOpenMode::Unspecified.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        let Some(v1::open_session_response::Outcome::Snapshot(opened)) = opened.outcome else {
            panic!("Tool Session did not open");
        };
        let hijack = client
            .open_session(authenticated(v1::OpenSessionRequest {
                metadata: Some(rpc_metadata(
                    &negotiated.negotiation_id,
                    "session.lifecycle.v1",
                )),
                request_id: Uuid::from_u128(91_103).as_bytes().to_vec(),
                session_id: Uuid::from_u128(91_102).as_bytes().to_vec(),
                consumer_key: "other-consumer".into(),
                compatibility_identity: Vec::new(),
                root_template: Some(rpc_root_template()),
                compatible_templates: vec![],
                configuration_identity,
                mode: v1::SessionOpenMode::Unspecified.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(
            hijack.outcome,
            Some(v1::open_session_response::Outcome::Failure(v1::Failure { code, .. }))
                if code == v1::FailureCode::Authentication as i32
        ));
        let session_id = id(91_002, SessionId::from_uuid);
        let participant_id =
            parse_id(&opened.root_participant_id, ParticipantId::from_uuid).unwrap();
        let navigator_domain::OwnershipSnapshot::Owned { epoch, .. } =
            store.read_ownership(session_id).await.unwrap()
        else {
            panic!("Session ownership missing");
        };
        let operation_id = id(91_004, OperationId::from_uuid);
        store
            .start_operation(StartOperation {
                context: RequestContext::new(id(91_005, RequestId::from_uuid), host_id),
                session_id,
                epoch,
                operation_id,
                participant_id,
                input_message_id: id(91_006, MessageId::from_uuid),
                input: InputSchema::new(vec![]).unwrap().validate(b"{}").unwrap(),
            })
            .await
            .unwrap();
        // Drive the same durable launch, delivery-acceptance, and Operation
        // transitions used in production before admitting an effect.
        let launch_attempt_id = id(91_020, LaunchAttemptId::from_uuid);
        let instance_id = id(91_021, InstanceId::from_uuid);
        store
            .prepare_launch(PrepareLaunch {
                context: RequestContext::new(id(91_022, RequestId::from_uuid), host_id),
                epoch,
                session_id,
                participant_id,
                driver_id: id(91_011, DriverId::from_uuid),
                driver_configuration_digest: [11; 32],
                attempt_id: launch_attempt_id,
                credential_digest: [12; 32],
            })
            .await
            .unwrap();
        store
            .attach_launch(AttachLaunch {
                context: RequestContext::new(id(91_023, RequestId::from_uuid), host_id),
                session_id,
                epoch,
                attempt_id: launch_attempt_id,
                expected_revision: Revision::initial(),
                instance_id,
                evidence: ProcessEvidence {
                    process_id: 101,
                    process_group_id: 101,
                    parent_process_id: 100,
                    creation_marker: 1,
                    executable_identity: [13; 32],
                },
            })
            .await
            .unwrap();
        store
            .transition_launch(TransitionLaunch {
                context: RequestContext::new(id(91_024, RequestId::from_uuid), host_id),
                session_id,
                epoch,
                attempt_id: launch_attempt_id,
                expected_revision: Revision::new(2).unwrap(),
                target: LaunchState::Ready,
                cleanup_reason: None,
            })
            .await
            .unwrap();
        let delivery_attempt_id = id(91_025, DeliveryAttemptId::from_uuid);
        let leased = store
            .lease_next_message(LeaseNextMessage {
                context: RequestContext::new(id(91_026, RequestId::from_uuid), host_id),
                session_id,
                epoch,
                destination: participant_id,
                instance_id,
                driver_launch_attempt_id: launch_attempt_id,
                proposed_attempt_id: delivery_attempt_id,
                lease_duration: Duration::from_secs(30),
            })
            .await
            .unwrap()
            .value()
            .clone()
            .expect("Operation input message is available");
        let pending = store
            .transition_message_delivery(TransitionMessageDelivery {
                context: RequestContext::new(id(91_027, RequestId::from_uuid), host_id),
                session_id,
                epoch,
                message_id: leased.message_id,
                attempt_id: delivery_attempt_id,
                expected_revision: leased.revision,
                transition: DeliveryTransition::AcceptancePending,
            })
            .await
            .unwrap()
            .value()
            .clone();
        store
            .transition_message_delivery(TransitionMessageDelivery {
                context: RequestContext::new(id(91_028, RequestId::from_uuid), host_id),
                session_id,
                epoch,
                message_id: pending.message_id,
                attempt_id: delivery_attempt_id,
                expected_revision: pending.revision,
                transition: DeliveryTransition::Accepted {
                    proof_digest: [14; 32],
                },
            })
            .await
            .unwrap();
        for (request, revision, action, report_message_id) in [
            (91_029, 1, OperationAction::BeginStart, None),
            (
                91_030,
                2,
                OperationAction::ReportRunning,
                Some(id(91_006, MessageId::from_uuid)),
            ),
        ] {
            store
                .transition_operation(TransitionOperation {
                    context: RequestContext::new(id(request, RequestId::from_uuid), host_id),
                    session_id,
                    epoch,
                    operation_id,
                    expected_revision: Revision::new(revision).unwrap(),
                    action,
                    report_message_id,
                    terminal_outcome: None,
                })
                .await
                .unwrap();
        }
        let scope = ScopedCapability::new(
            navigator_domain::Capability::new("tool.records.lookup").unwrap(),
            ResourceScope::Operation(operation_id),
        );
        let profile = AuthorityProfile::new([scope.clone()], [scope]).unwrap();
        store
            .put_authority_policy(PutAuthorityPolicy {
                context: RequestContext::new(id(91_007, RequestId::from_uuid), host_id),
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
            .unwrap();
        let registered = client
            .register_tool(authenticated(v1::RegisterToolRequest {
                metadata: Some(rpc_metadata(
                    &negotiated.negotiation_id,
                    CAPABILITY_CONSUMER_TOOLS_V1,
                )),
                request_id: Uuid::from_u128(91_008).as_bytes().to_vec(),
                session_id: session_uuid.as_bytes().to_vec(),
                tool: Some(definition_wire(
                    &definition(EffectClass::NonIdempotent).with_required_approval(),
                )),
            }))
            .await
            .unwrap()
            .into_inner();
        let Some(v1::register_tool_response::Outcome::Registration(registration)) =
            registered.outcome
        else {
            panic!("Tool registration failed");
        };
        let definition_mutant = client
            .register_tool(authenticated(v1::RegisterToolRequest {
                metadata: Some(rpc_metadata(
                    &negotiated.negotiation_id,
                    CAPABILITY_CONSUMER_TOOLS_V1,
                )),
                request_id: Uuid::from_u128(91_108).as_bytes().to_vec(),
                session_id: session_uuid.as_bytes().to_vec(),
                tool: Some(definition_wire(&definition(EffectClass::ReadOnly))),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(
            definition_mutant.outcome,
            Some(v1::register_tool_response::Outcome::Failure(v1::Failure { code, .. }))
                if code == v1::FailureCode::Conflict as i32
        ));
        let attacker_negotiated = client
            .negotiate(authenticated(v1::NegotiateRequest {
                minimum_version: Some(v1::ProtocolVersion { major: 1, minor: 1 }),
                maximum_version: Some(v1::ProtocolVersion { major: 1, minor: 1 }),
                capabilities: vec![
                    "session.lifecycle.v1".into(),
                    CAPABILITY_CONSUMER_TOOLS_V1.into(),
                ],
            }))
            .await
            .unwrap()
            .into_inner();
        let Some(v1::negotiate_response::Outcome::Negotiated(attacker_negotiated)) =
            attacker_negotiated.outcome
        else {
            panic!("attacker negotiation failed");
        };
        let attacker_session = Uuid::from_u128(91_202);
        let attacker_open = client
            .open_session(authenticated(v1::OpenSessionRequest {
                metadata: Some(rpc_metadata(
                    &attacker_negotiated.negotiation_id,
                    "session.lifecycle.v1",
                )),
                request_id: Uuid::from_u128(91_203).as_bytes().to_vec(),
                session_id: attacker_session.as_bytes().to_vec(),
                consumer_key: "attacker".into(),
                compatibility_identity: Vec::new(),
                root_template: Some(rpc_root_template()),
                compatible_templates: vec![],
                configuration_identity: attacker_negotiated.configuration_identity,
                mode: v1::SessionOpenMode::Unspecified.into(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(
            attacker_open.outcome,
            Some(v1::open_session_response::Outcome::Snapshot(_))
        ));
        let cross_register = client
            .register_tool(authenticated(v1::RegisterToolRequest {
                metadata: Some(rpc_metadata(
                    &attacker_negotiated.negotiation_id,
                    CAPABILITY_CONSUMER_TOOLS_V1,
                )),
                request_id: Uuid::from_u128(91_208).as_bytes().to_vec(),
                session_id: session_uuid.as_bytes().to_vec(),
                tool: Some(definition_wire(&definition(EffectClass::NonIdempotent))),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(
            cross_register.outcome,
            Some(v1::register_tool_response::Outcome::Failure(v1::Failure { code, .. }))
                if code == v1::FailureCode::Authentication as i32
        ));
        let (hijack_tx, hijack_rx) = mpsc::channel(1);
        hijack_tx
            .send(v1::ToolProviderRequest {
                frame: Some(v1::tool_provider_request::Frame::Connect(
                    v1::ConnectToolProvider {
                        metadata: Some(rpc_metadata(
                            &attacker_negotiated.negotiation_id,
                            CAPABILITY_CONSUMER_TOOLS_V1,
                        )),
                        session_id: session_uuid.as_bytes().to_vec(),
                        provider_id: Uuid::from_u128(91_220).as_bytes().to_vec(),
                        connection_id: Uuid::from_u128(91_221).as_bytes().to_vec(),
                        after_server_sequence: 0,
                        registration_ids: vec![registration.registration_id.clone()],
                    },
                )),
            })
            .await
            .unwrap();
        let Err(hijack_status) = client
            .provide_tools(authenticated(ReceiverStream::new(hijack_rx)))
            .await
        else {
            panic!("cross-Consumer provider hijack connected");
        };
        assert_eq!(hijack_status.code(), tonic::Code::Unauthenticated);
        drop(hijack_tx);
        let provider_id = Uuid::from_u128(91_020);
        let connection_id = Uuid::from_u128(91_021);
        let (provider_tx, provider_rx) = mpsc::channel(8);
        provider_tx
            .send(v1::ToolProviderRequest {
                frame: Some(v1::tool_provider_request::Frame::Connect(
                    v1::ConnectToolProvider {
                        metadata: Some(rpc_metadata(
                            &negotiated.negotiation_id,
                            CAPABILITY_CONSUMER_TOOLS_V1,
                        )),
                        session_id: session_uuid.as_bytes().to_vec(),
                        provider_id: provider_id.as_bytes().to_vec(),
                        connection_id: connection_id.as_bytes().to_vec(),
                        after_server_sequence: 0,
                        registration_ids: vec![registration.registration_id.clone()],
                    },
                )),
            })
            .await
            .unwrap();
        let mut provider_stream = client
            .provide_tools(authenticated(ReceiverStream::new(provider_rx)))
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(
            rpc_next(&mut provider_stream, "connect").await.frame,
            Some(v1::tool_provider_response::Frame::Connected(_))
        ));
        let (reconnect_tx, reconnect_rx) = mpsc::channel(1);
        reconnect_tx
            .send(v1::ToolProviderRequest {
                frame: Some(v1::tool_provider_request::Frame::Connect(
                    v1::ConnectToolProvider {
                        metadata: Some(rpc_metadata(
                            &attacker_negotiated.negotiation_id,
                            CAPABILITY_CONSUMER_TOOLS_V1,
                        )),
                        session_id: session_uuid.as_bytes().to_vec(),
                        provider_id: provider_id.as_bytes().to_vec(),
                        connection_id: Uuid::from_u128(91_222).as_bytes().to_vec(),
                        after_server_sequence: 0,
                        registration_ids: vec![registration.registration_id.clone()],
                    },
                )),
            })
            .await
            .unwrap();
        let Err(reconnect_status) = client
            .provide_tools(authenticated(ReceiverStream::new(reconnect_rx)))
            .await
        else {
            panic!("cross-Consumer reconnect replaced the authenticated provider");
        };
        assert_eq!(reconnect_status.code(), tonic::Code::Unauthenticated);
        drop(reconnect_tx);
        let denied = Box::pin(broker.handle_command(
            AuthenticatedHierarchyCaller {
                host_id,
                session_id,
                participant_id,
                launch_attempt_id: id(91_030, LaunchAttemptId::from_uuid),
                instance_id: id(91_031, navigator_domain::InstanceId::from_uuid),
                ownership_epoch: epoch,
            },
            driver_v1::ToolCommand {
                request_id: Uuid::from_u128(91_299).as_bytes().to_vec(),
                session_id: session_uuid.as_bytes().to_vec(),
                participant_id: participant_id.as_uuid().as_bytes().to_vec(),
                operation_id: operation_id.as_uuid().as_bytes().to_vec(),
                tool_name: "records.lookup".into(),
                tool_version: "v1".into(),
                input: br#"{"key":"a"}"#.to_vec(),
                authority_grant_id: vec![],
                approval_grant_id: vec![],
            },
        ))
        .await
        .unwrap();
        assert!(matches!(
            denied,
            driver_v1::tool_result_request::Result::Failure(driver_v1::Failure { code, .. })
                if code == driver_v1::FailureCode::Authorization as i32
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), provider_stream.message())
                .await
                .is_err(),
            "required approval rejection must emit no provider frame"
        );
        let approval_id = id(91_300, navigator_domain::ApprovalRequestId::from_uuid);
        let approval_grant_id = id(91_301, GrantId::from_uuid);
        let approval_expiry = deadline_after(60_000).unwrap();
        let approval_resource = ApprovalResource::new(
            &serde_json::to_vec(&serde_json::json!({
                "tool_name": "records.lookup",
                "tool_version": "v1",
                "input": {"key": "a"},
            }))
            .unwrap(),
        )
        .unwrap();
        let pending_approval = store
            .request_approval(RequestApproval {
                context: RequestContext::new(id(91_302, RequestId::from_uuid), host_id),
                session_id,
                owner_epoch: epoch,
                approval_id,
                requester_id: participant_id,
                operation_id,
                source_message_id: id(91_006, MessageId::from_uuid),
                source_delivery_attempt_id: delivery_attempt_id,
                capability: navigator_domain::Capability::new("tool.invoke").unwrap(),
                resource: approval_resource,
                summary: ApprovalSummary::new("invoke records lookup").unwrap(),
                expires_at: approval_expiry,
            })
            .await
            .unwrap()
            .value()
            .clone();
        store
            .approve_request(ApproveRequest {
                context: RequestContext::new(id(91_303, RequestId::from_uuid), host_id),
                session_id,
                owner_epoch: epoch,
                approval_id,
                expected_revision: pending_approval.revision,
                grant_id: approval_grant_id,
                grant_expires_at: approval_expiry,
                max_uses: 1,
            })
            .await
            .unwrap();
        let caller = AuthenticatedHierarchyCaller {
            host_id,
            session_id,
            participant_id,
            launch_attempt_id: id(91_030, LaunchAttemptId::from_uuid),
            instance_id: id(91_031, navigator_domain::InstanceId::from_uuid),
            ownership_epoch: epoch,
        };
        let sink = Arc::clone(&broker);
        let invocation_task = tokio::spawn(async move {
            Box::pin(sink.handle_command(
                caller,
                driver_v1::ToolCommand {
                    request_id: Uuid::from_u128(91_032).as_bytes().to_vec(),
                    session_id: session_uuid.as_bytes().to_vec(),
                    participant_id: participant_id.as_uuid().as_bytes().to_vec(),
                    operation_id: operation_id.as_uuid().as_bytes().to_vec(),
                    tool_name: "records.lookup".into(),
                    tool_version: "v1".into(),
                    input: br#"{"key":"a"}"#.to_vec(),
                    authority_grant_id: vec![],
                    approval_grant_id: approval_grant_id.as_uuid().as_bytes().to_vec(),
                },
            ))
            .await
            .unwrap()
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !invocation_task.is_finished(),
            "Tool sink failed before provider dispatch"
        );
        let invocation = rpc_next(&mut provider_stream, "invocation").await;
        let Some(v1::tool_provider_response::Frame::Invocation(invocation)) = invocation.frame
        else {
            panic!("missing invocation");
        };
        provider_tx
            .send(v1::ToolProviderRequest {
                frame: Some(v1::tool_provider_request::Frame::Started(
                    v1::ToolHandlerStarted {
                        session_id: invocation.session_id.clone(),
                        provider_id: provider_id.as_bytes().to_vec(),
                        connection_id: connection_id.as_bytes().to_vec(),
                        invocation_id: invocation.invocation_id.clone(),
                        dispatch_id: invocation.dispatch_id.clone(),
                        server_sequence: invocation.server_sequence,
                        started_at: Some(v1::Timestamp {
                            unix_seconds: 1,
                            nanoseconds: 0,
                        }),
                    },
                )),
            })
            .await
            .unwrap();
        let started_ack = rpc_next(&mut provider_stream, "started ack").await;
        assert!(
            matches!(started_ack.frame, Some(v1::tool_provider_response::Frame::Acknowledgement(v1::ToolProviderAck { kind, .. })) if kind == v1::ToolProviderAckKind::Started as i32)
        );
        assert!(
            !invocation_task.is_finished(),
            "handler result crossed before durable Started ACK"
        );
        let approval_effect_id = derived_id(
            b"navigator.tool.approval-effect.v1",
            &[
                session_id.as_uuid().as_bytes(),
                Uuid::from_u128(91_032).as_bytes(),
            ],
            RequestId::from_uuid,
        );
        set_approval_finish_pause(Some(approval_effect_id));
        provider_tx
            .send(v1::ToolProviderRequest {
                frame: Some(v1::tool_provider_request::Frame::Result(
                    v1::ToolHandlerResult {
                        session_id: invocation.session_id,
                        provider_id: provider_id.as_bytes().to_vec(),
                        connection_id: connection_id.as_bytes().to_vec(),
                        invocation_id: invocation.invocation_id,
                        dispatch_id: invocation.dispatch_id,
                        server_sequence: invocation.server_sequence,
                        output: br#"{"found":true}"#.to_vec(),
                        artifacts: vec![],
                    },
                )),
            })
            .await
            .unwrap();
        let terminal_ack = rpc_next(&mut provider_stream, "terminal ack").await;
        assert!(
            matches!(terminal_ack.frame, Some(v1::tool_provider_response::Frame::Acknowledgement(v1::ToolProviderAck { kind, .. })) if kind == v1::ToolProviderAckKind::Terminal as i32)
        );
        tokio::time::timeout(Duration::from_secs(3), wait_approval_finish_entered())
            .await
            .expect("success finish hook was not reached");
        assert_eq!(
            store
                .load_approval_effect(approval_effect_id)
                .await
                .unwrap()
                .phase,
            navigator_domain::ApprovalEffectPhase::Reserved,
            "Tool terminal is durable while the pre-finish crash window remains Reserved"
        );
        invocation_task.abort();
        assert!(invocation_task.await.unwrap_err().is_cancelled());
        set_approval_finish_pause(None);
        let reopened_store = Arc::new(
            navigator_store_sqlite::SqliteStore::open(&database_path)
                .await
                .unwrap(),
        );
        let success_replay = reopened_store
            .list_provider_replay(session_id, id(91_020, ToolProviderId::from_uuid), 0)
            .await
            .unwrap();
        let mut recovered_provider = active_for(&success_replay[0]);
        recovered_provider.host_id = host_id;
        recovered_provider.owner_epoch = epoch;
        let (recovery_tx, mut recovery_rx) = mpsc::channel(32);
        replay_provider_reconnect(
            &*reopened_store,
            &recovered_provider,
            success_replay,
            0,
            &recovery_tx,
        )
        .await
        .unwrap();
        assert!(
            recovery_rx.recv().await.is_some(),
            "reconnect replayed terminal ACK"
        );
        assert_eq!(
            reopened_store
                .load_approval_effect(approval_effect_id)
                .await
                .unwrap()
                .phase,
            navigator_domain::ApprovalEffectPhase::Succeeded
        );
        replay_provider_reconnect(
            &*reopened_store,
            &recovered_provider,
            Vec::new(),
            u64::MAX,
            &recovery_tx,
        )
        .await
        .unwrap();
        assert_eq!(
            store
                .load_approval_grant(approval_grant_id)
                .await
                .unwrap()
                .used_count,
            1
        );

        let failed_approval_id = id(91_320, navigator_domain::ApprovalRequestId::from_uuid);
        let failed_grant_id = id(91_321, GrantId::from_uuid);
        let failed_resource = ApprovalResource::new(
            &serde_json::to_vec(&serde_json::json!({
                "tool_name": "records.lookup",
                "tool_version": "v1",
                "input": {"key": "failed"},
            }))
            .unwrap(),
        )
        .unwrap();
        let failed_pending = store
            .request_approval(RequestApproval {
                context: RequestContext::new(id(91_322, RequestId::from_uuid), host_id),
                session_id,
                owner_epoch: epoch,
                approval_id: failed_approval_id,
                requester_id: participant_id,
                operation_id,
                source_message_id: id(91_006, MessageId::from_uuid),
                source_delivery_attempt_id: delivery_attempt_id,
                capability: navigator_domain::Capability::new("tool.invoke").unwrap(),
                resource: failed_resource,
                summary: ApprovalSummary::new("invoke failing lookup").unwrap(),
                expires_at: approval_expiry,
            })
            .await
            .unwrap()
            .value()
            .clone();
        store
            .approve_request(ApproveRequest {
                context: RequestContext::new(id(91_323, RequestId::from_uuid), host_id),
                session_id,
                owner_epoch: epoch,
                approval_id: failed_approval_id,
                expected_revision: failed_pending.revision,
                grant_id: failed_grant_id,
                grant_expires_at: approval_expiry,
                max_uses: 1,
            })
            .await
            .unwrap();
        let failed_sink = Arc::clone(&broker);
        let failed_task = tokio::spawn(async move {
            Box::pin(failed_sink.handle_command(
                AuthenticatedHierarchyCaller {
                    host_id,
                    session_id,
                    participant_id,
                    launch_attempt_id: id(91_030, LaunchAttemptId::from_uuid),
                    instance_id: id(91_031, navigator_domain::InstanceId::from_uuid),
                    ownership_epoch: epoch,
                },
                driver_v1::ToolCommand {
                    request_id: Uuid::from_u128(91_232).as_bytes().to_vec(),
                    session_id: session_uuid.as_bytes().to_vec(),
                    participant_id: participant_id.as_uuid().as_bytes().to_vec(),
                    operation_id: operation_id.as_uuid().as_bytes().to_vec(),
                    tool_name: "records.lookup".into(),
                    tool_version: "v1".into(),
                    input: br#"{"key":"failed"}"#.to_vec(),
                    authority_grant_id: vec![],
                    approval_grant_id: failed_grant_id.as_uuid().as_bytes().to_vec(),
                },
            ))
            .await
        });
        let failed_invocation = rpc_next(&mut provider_stream, "failed invocation").await;
        let Some(v1::tool_provider_response::Frame::Invocation(failed_invocation)) =
            failed_invocation.frame
        else {
            panic!("missing failed invocation");
        };
        provider_tx
            .send(v1::ToolProviderRequest {
                frame: Some(v1::tool_provider_request::Frame::Started(
                    v1::ToolHandlerStarted {
                        session_id: failed_invocation.session_id.clone(),
                        provider_id: provider_id.as_bytes().to_vec(),
                        connection_id: connection_id.as_bytes().to_vec(),
                        invocation_id: failed_invocation.invocation_id.clone(),
                        dispatch_id: failed_invocation.dispatch_id.clone(),
                        server_sequence: failed_invocation.server_sequence,
                        started_at: Some(v1::Timestamp {
                            unix_seconds: 3,
                            nanoseconds: 0,
                        }),
                    },
                )),
            })
            .await
            .unwrap();
        assert!(matches!(
            rpc_next(&mut provider_stream, "failed started ack").await.frame,
            Some(v1::tool_provider_response::Frame::Acknowledgement(v1::ToolProviderAck { kind, .. }))
                if kind == v1::ToolProviderAckKind::Started as i32
        ));
        let failed_effect_id = derived_id(
            b"navigator.tool.approval-effect.v1",
            &[
                session_id.as_uuid().as_bytes(),
                Uuid::from_u128(91_232).as_bytes(),
            ],
            RequestId::from_uuid,
        );
        set_approval_finish_pause(Some(failed_effect_id));
        provider_tx
            .send(v1::ToolProviderRequest {
                frame: Some(v1::tool_provider_request::Frame::Failure(
                    v1::ToolHandlerFailure {
                        session_id: failed_invocation.session_id,
                        provider_id: provider_id.as_bytes().to_vec(),
                        connection_id: connection_id.as_bytes().to_vec(),
                        invocation_id: failed_invocation.invocation_id,
                        dispatch_id: failed_invocation.dispatch_id,
                        server_sequence: failed_invocation.server_sequence,
                        failure: Some(v1::Failure {
                            code: v1::FailureCode::Internal as i32,
                            message: "handler failed".into(),
                            retry: v1::RetryClass::Never as i32,
                            details: vec![],
                            related_id: None,
                        }),
                    },
                )),
            })
            .await
            .unwrap();
        assert!(matches!(
            rpc_next(&mut provider_stream, "failed terminal ack").await.frame,
            Some(v1::tool_provider_response::Frame::Acknowledgement(v1::ToolProviderAck { kind, .. }))
                if kind == v1::ToolProviderAckKind::Terminal as i32
        ));
        tokio::time::timeout(Duration::from_secs(3), wait_approval_finish_entered())
            .await
            .expect("failed finish hook was not reached");
        assert_eq!(
            store
                .load_approval_effect(failed_effect_id)
                .await
                .unwrap()
                .phase,
            navigator_domain::ApprovalEffectPhase::Reserved
        );
        failed_task.abort();
        assert!(failed_task.await.unwrap_err().is_cancelled());
        set_approval_finish_pause(None);
        let failed_reopened_store = navigator_store_sqlite::SqliteStore::open(&database_path)
            .await
            .unwrap();
        let failed_replay = failed_reopened_store
            .list_provider_replay(session_id, id(91_020, ToolProviderId::from_uuid), 0)
            .await
            .unwrap();
        replay_provider_reconnect(
            &failed_reopened_store,
            &recovered_provider,
            failed_replay,
            0,
            &recovery_tx,
        )
        .await
        .unwrap();
        assert_eq!(
            failed_reopened_store
                .load_approval_effect(failed_effect_id)
                .await
                .unwrap()
                .phase,
            navigator_domain::ApprovalEffectPhase::Failed
        );
        let replay_without_grant = Box::pin(broker.handle_command(
            AuthenticatedHierarchyCaller {
                host_id,
                session_id,
                participant_id,
                launch_attempt_id: id(91_030, LaunchAttemptId::from_uuid),
                instance_id: id(91_031, navigator_domain::InstanceId::from_uuid),
                ownership_epoch: epoch,
            },
            driver_v1::ToolCommand {
                request_id: Uuid::from_u128(91_032).as_bytes().to_vec(),
                session_id: session_uuid.as_bytes().to_vec(),
                participant_id: participant_id.as_uuid().as_bytes().to_vec(),
                operation_id: operation_id.as_uuid().as_bytes().to_vec(),
                tool_name: "records.lookup".into(),
                tool_version: "v1".into(),
                input: br#"{"key":"a"}"#.to_vec(),
                authority_grant_id: vec![],
                approval_grant_id: vec![],
            },
        ))
        .await
        .unwrap();
        assert!(matches!(
            replay_without_grant,
            driver_v1::tool_result_request::Result::Failure(_)
        ));
        assert_eq!(
            store
                .load_approval_grant(approval_grant_id)
                .await
                .unwrap()
                .used_count,
            1,
            "conflicting replay cannot consume or refund the approval"
        );
        let unsafe_approval_id = id(91_310, navigator_domain::ApprovalRequestId::from_uuid);
        let unsafe_approval_grant_id = id(91_311, GrantId::from_uuid);
        let unsafe_resource = ApprovalResource::new(
            &serde_json::to_vec(&serde_json::json!({
                "tool_name": "records.lookup",
                "tool_version": "v1",
                "input": {"key": "unsafe"},
            }))
            .unwrap(),
        )
        .unwrap();
        let unsafe_pending = store
            .request_approval(RequestApproval {
                context: RequestContext::new(id(91_312, RequestId::from_uuid), host_id),
                session_id,
                owner_epoch: epoch,
                approval_id: unsafe_approval_id,
                requester_id: participant_id,
                operation_id,
                source_message_id: id(91_006, MessageId::from_uuid),
                source_delivery_attempt_id: delivery_attempt_id,
                capability: navigator_domain::Capability::new("tool.invoke").unwrap(),
                resource: unsafe_resource,
                summary: ApprovalSummary::new("invoke unsafe lookup").unwrap(),
                expires_at: approval_expiry,
            })
            .await
            .unwrap()
            .value()
            .clone();
        store
            .approve_request(ApproveRequest {
                context: RequestContext::new(id(91_313, RequestId::from_uuid), host_id),
                session_id,
                owner_epoch: epoch,
                approval_id: unsafe_approval_id,
                expected_revision: unsafe_pending.revision,
                grant_id: unsafe_approval_grant_id,
                grant_expires_at: approval_expiry,
                max_uses: 1,
            })
            .await
            .unwrap();
        let second_caller = AuthenticatedHierarchyCaller {
            host_id,
            session_id,
            participant_id,
            launch_attempt_id: id(91_030, LaunchAttemptId::from_uuid),
            instance_id: id(91_031, navigator_domain::InstanceId::from_uuid),
            ownership_epoch: epoch,
        };
        let second_sink = Arc::clone(&broker);
        let second_task = tokio::spawn(async move {
            Box::pin(second_sink.handle_command(
                second_caller,
                driver_v1::ToolCommand {
                    request_id: Uuid::from_u128(91_132).as_bytes().to_vec(),
                    session_id: session_uuid.as_bytes().to_vec(),
                    participant_id: participant_id.as_uuid().as_bytes().to_vec(),
                    operation_id: operation_id.as_uuid().as_bytes().to_vec(),
                    tool_name: "records.lookup".into(),
                    tool_version: "v1".into(),
                    input: br#"{"key":"unsafe"}"#.to_vec(),
                    authority_grant_id: vec![],
                    approval_grant_id: unsafe_approval_grant_id.as_uuid().as_bytes().to_vec(),
                },
            ))
            .await
        });
        let unsafe_invocation = rpc_next(&mut provider_stream, "unsafe invocation").await;
        let Some(v1::tool_provider_response::Frame::Invocation(unsafe_invocation)) =
            unsafe_invocation.frame
        else {
            panic!("missing unsafe invocation");
        };
        provider_tx
            .send(v1::ToolProviderRequest {
                frame: Some(v1::tool_provider_request::Frame::Started(
                    v1::ToolHandlerStarted {
                        session_id: unsafe_invocation.session_id,
                        provider_id: provider_id.as_bytes().to_vec(),
                        connection_id: connection_id.as_bytes().to_vec(),
                        invocation_id: unsafe_invocation.invocation_id.clone(),
                        dispatch_id: unsafe_invocation.dispatch_id,
                        server_sequence: unsafe_invocation.server_sequence,
                        started_at: Some(v1::Timestamp {
                            unix_seconds: 2,
                            nanoseconds: 0,
                        }),
                    },
                )),
            })
            .await
            .unwrap();
        assert!(matches!(
            rpc_next(&mut provider_stream, "unsafe started ack").await.frame,
            Some(v1::tool_provider_response::Frame::Acknowledgement(v1::ToolProviderAck { kind, .. }))
                if kind == v1::ToolProviderAckKind::Started as i32
        ));
        let unsafe_invocation_id = parse_id(
            &unsafe_invocation.invocation_id,
            ToolInvocationId::from_uuid,
        )
        .unwrap();
        let unsafe_effect_id = derived_id(
            b"navigator.tool.approval-effect.v1",
            &[
                session_id.as_uuid().as_bytes(),
                Uuid::from_u128(91_132).as_bytes(),
            ],
            RequestId::from_uuid,
        );
        set_approval_finish_pause(Some(unsafe_effect_id));
        drop(provider_tx);
        drop(provider_stream);
        tokio::time::timeout(Duration::from_secs(3), wait_approval_finish_entered())
            .await
            .expect("uncertain finish hook was not reached");
        assert_eq!(
            store
                .load_approval_effect(unsafe_effect_id)
                .await
                .unwrap()
                .phase,
            navigator_domain::ApprovalEffectPhase::Reserved
        );
        second_task.abort();
        assert!(second_task.await.unwrap_err().is_cancelled());
        set_approval_finish_pause(None);
        assert_eq!(
            store
                .load_tool_invocation(unsafe_invocation_id)
                .await
                .unwrap()
                .unwrap()
                .phase(),
            ToolInvocationPhase::Uncertain
        );
        let unsafe_replay = reopened_store
            .list_provider_replay(session_id, id(91_020, ToolProviderId::from_uuid), 0)
            .await
            .unwrap();
        replay_provider_reconnect(
            &*reopened_store,
            &recovered_provider,
            unsafe_replay,
            0,
            &recovery_tx,
        )
        .await
        .unwrap();
        assert_eq!(
            reopened_store
                .load_approval_effect(unsafe_effect_id)
                .await
                .unwrap()
                .phase,
            navigator_domain::ApprovalEffectPhase::Uncertain
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if broker.providers.lock().await.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("disconnected provider route remained selectable");
        drop(client);
        shutdown.send(true).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .expect("Tool RPC server shutdown timed out")
                .unwrap()
                .is_ok()
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "cross-store fault matrix is clearer as one end-to-end crash/reopen oracle"
    )]
    async fn external_tool_and_approval_fault_matrix_reopens_observed_state() {
        for point in [
            "approval.external.before_call",
            "approval.external.after_call",
            "approval.external.before_effect_proof",
            "approval.external.after_effect_proof",
            "tool.external.before_call",
            "tool.external.after_call",
            "tool.external.before_result_proof",
            "tool.external.after_result_proof",
        ] {
            if std::env::var("NAVIGATOR_FAULT_MATRIX_ONLY").is_ok_and(|only| only != point) {
                continue;
            }
            let directory = TempDir::new().unwrap();
            let root = directory.path().join("fixture");
            let observation = directory.path().join("observed");
            let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let status = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(
                    "tool_broker::tests::real_bidi_rpc_consumes_approval_before_handler_and_finishes_terminal",
                )
                .env("NAVIGATOR_TOOL_FAULT_ROOT", &root)
                .env("NAVIGATOR_EXTERNAL_FAULT_POINT", point)
                .env("NAVIGATOR_EXTERNAL_FAULT_OBSERVATION", &observation)
                .status()
                .unwrap();
            assert!(!status.success(), "worker did not abort at {point}");
            assert_eq!(std::fs::read_to_string(&observation).unwrap(), point);

            // Reopening the exact persistent fixture is part of the oracle:
            // WAL recovery and schema validation must succeed before the
            // production reconnect/replay path is allowed to run.
            let reopened = navigator_store_sqlite::SqliteStore::open(root.join("tool-rpc.db"))
                .await
                .unwrap();
            let duplicate_roots: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM (SELECT session_id FROM participants WHERE parent_participant_id IS NULL GROUP BY session_id HAVING COUNT(*)>1)",
            )
            .fetch_one(reopened.pool())
            .await
            .unwrap();
            let duplicate_unfinished_operations: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM (SELECT participant_id FROM operations WHERE terminal_outcome IS NULL GROUP BY participant_id HAVING COUNT(*)>1)",
            )
            .fetch_one(reopened.pool())
            .await
            .unwrap();
            let foreign_key_violations = sqlx::query("PRAGMA foreign_key_check")
                .fetch_all(reopened.pool())
                .await
                .unwrap()
                .len();
            let session_id = id(91_002, SessionId::from_uuid);
            let provider_id = id(91_020, ToolProviderId::from_uuid);
            let provider_calls_before: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tool_invocations WHERE session_id=? AND provider_id=?",
            )
            .bind(session_id.to_string())
            .bind(provider_id.to_string())
            .fetch_one(reopened.pool())
            .await
            .unwrap();
            let provider_receipts_before: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tool_invocations WHERE session_id=? AND provider_id=? AND terminal_digest IS NOT NULL",
            ).bind(session_id.to_string()).bind(provider_id.to_string())
                .fetch_one(reopened.pool()).await.unwrap();
            let provider_replay = reopened
                .list_provider_replay(session_id, provider_id, 0)
                .await
                .unwrap();
            let ordinary_reconnect_attempted = !provider_replay.is_empty();
            let mut replay_frames_emitted = 0_u64;
            if let (
                Some(first),
                navigator_domain::OwnershipSnapshot::Owned { host_id, epoch, .. },
            ) = (
                provider_replay.first(),
                reopened.read_ownership(session_id).await.unwrap(),
            ) {
                let mut active = active_for(first);
                active.host_id = host_id;
                active.owner_epoch = epoch;
                let (sender, mut receiver) = mpsc::channel(128);
                replay_provider_reconnect(&reopened, &active, provider_replay.clone(), 0, &sender)
                    .await
                    .unwrap();
                drop(sender);
                while receiver.recv().await.is_some() {
                    replay_frames_emitted += 1;
                }
            }
            let provider_calls_after: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tool_invocations WHERE session_id=? AND provider_id=?",
            )
            .bind(session_id.to_string())
            .bind(provider_id.to_string())
            .fetch_one(reopened.pool())
            .await
            .unwrap();
            let provider_receipts_after: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tool_invocations WHERE session_id=? AND provider_id=? AND terminal_digest IS NOT NULL",
            ).bind(session_id.to_string()).bind(provider_id.to_string())
                .fetch_one(reopened.pool()).await.unwrap();
            let effects_before_reconcile = reopened
                .list_reserved_approval_effects(session_id)
                .await
                .unwrap();
            let mut invocation_before_reconcile = provider_calls_before > 0;
            let mut terminal_invocation_before_reconcile = provider_receipts_before > 0;
            for effect in &effects_before_reconcile {
                if let Some(invocation) = reopened
                    .load_tool_invocation_by_approval_effect(effect.effect_id)
                    .await
                    .unwrap()
                {
                    invocation_before_reconcile = true;
                    terminal_invocation_before_reconcile |=
                        approval_terminal_phase(&invocation).is_some();
                }
            }
            reconcile_reserved_approval_effects_in(
                &reopened,
                session_id,
                id(91_001, HostId::from_uuid),
                FencingEpoch::new(1).unwrap(),
            )
            .await
            .unwrap();
            let reserved_effects = reopened
                .list_reserved_approval_effects(session_id)
                .await
                .unwrap();
            let mut terminal_effect_left_reserved = false;
            for effect in &reserved_effects {
                if let Some(invocation) = reopened
                    .load_tool_invocation_by_approval_effect(effect.effect_id)
                    .await
                    .unwrap()
                {
                    terminal_effect_left_reserved |= approval_terminal_phase(&invocation).is_some();
                }
            }
            assert!(
                !terminal_effect_left_reserved,
                "terminal Tool left a recoverable Approval effect at {point}"
            );
            let stale_owner_cannot_commit =
                stale_owner_rejected_without_mutation(&reopened, session_id).await;
            drop(reopened);
            let unrelated_process_survived = unrelated.try_wait().unwrap().is_none();
            assert!(
                unrelated_process_survived,
                "Tool recovery at {point} terminated an unrelated process"
            );
            unrelated.kill().unwrap();
            unrelated.wait().unwrap();
            if let Some(result_path) = std::env::var_os("NAVIGATOR_FAULT_CASE_RESULT") {
                let actual = if terminal_invocation_before_reconcile {
                    "terminal"
                } else if invocation_before_reconcile {
                    "uncertain"
                } else {
                    "recoverable"
                };
                let classified_final_state = match actual {
                    "terminal" => {
                        terminal_invocation_before_reconcile || reserved_effects.is_empty()
                    }
                    "uncertain" => {
                        invocation_before_reconcile && !terminal_invocation_before_reconcile
                    }
                    "recoverable" => !invocation_before_reconcile,
                    _ => false,
                };
                let no_orphan_reservation =
                    !terminal_effect_left_reserved && foreign_key_violations == 0;
                let uncertain_effect_not_ordinarily_replayed = actual != "uncertain"
                    || (ordinary_reconnect_attempted
                        && replay_frames_emitted == 0
                        && provider_calls_before == provider_calls_after
                        && provider_receipts_before == provider_receipts_after);
                std::fs::write(
                    result_path,
                    serde_json::to_vec(&serde_json::json!({
                        "schema_version": 1,
                        "seed": std::env::var("NAVIGATOR_FAULT_CASE_SEED").unwrap().parse::<u64>().unwrap(),
                        "fault_point": point,
                        "actual_classification": actual,
                        "facts": {
                            "no_duplicate_unfinished_participant": duplicate_roots == 0,
                            "no_duplicate_unfinished_operation": duplicate_unfinished_operations == 0,
                            "no_orphan_reservation": no_orphan_reservation,
                            "uncertain_effect_not_ordinarily_replayed": uncertain_effect_not_ordinarily_replayed,
                            "stale_owner_cannot_commit": stale_owner_cannot_commit,
                            "unrelated_process_not_terminated": unrelated_process_survived,
                            "classified_final_state": classified_final_state
                        },
                        "diagnostics": {
                            "observation_schema": "external-tool-v2",
                            "reconciler_completed": !terminal_effect_left_reserved,
                            "reserved_effects_before_reconcile": effects_before_reconcile.len(),
                            "invocation_before_reconcile": invocation_before_reconcile,
                            "terminal_invocation_before_reconcile": terminal_invocation_before_reconcile,
                            "ordinary_reconnect_attempted": ordinary_reconnect_attempted,
                            "replay_frames_emitted": replay_frames_emitted,
                            "provider_calls_before": provider_calls_before,
                            "provider_calls_after": provider_calls_after,
                            "provider_receipts_before": provider_receipts_before,
                            "provider_receipts_after": provider_receipts_after,
                            "reserved_effect_count": reserved_effects.len(),
                            "duplicate_roots": duplicate_roots,
                            "duplicate_unfinished_operations": duplicate_unfinished_operations,
                            "foreign_key_violations": foreign_key_violations,
                            "stale_predecessor_rejected_without_mutation": stale_owner_cannot_commit,
                            "unrelated_process_survived": unrelated_process_survived
                        }
                    }))
                    .unwrap(),
                )
                .unwrap();
            }
        }
    }
}
