use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    future::Future,
    sync::Arc,
    time::Duration,
};

use navigator_domain::{
    BoundedBytes, BoundedText, FencingEpoch, MessageId, OperationAction, OperationId,
    OperationState, ParticipantId,
};
use navigator_store_api::{
    CancelSubtree, CancelSubtreeOutcome, HierarchyStore, MAX_OPERATION_INPUT_BYTES,
    MessageSnapshot, Mutation, OperationSnapshot, OperationStore, OperationTerminalOutcome,
    RequestContext, StartOperation, StoreError, TransitionOperation,
};
use thiserror::Error;
use tokio::sync::{Mutex, oneshot, watch};

use crate::{AdmissionPermit, ServiceError};

pub const MAX_REPORTS_PER_OPERATION: usize = 1_024;
pub const MAX_PROGRESS_BYTES: usize = 65_536;
const MAX_WORKER_FAILURE_RECORDS: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryAcceptance {
    Accepted,
    NotAccepted,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutorReport {
    Progress {
        operation_id: OperationId,
        message_id: MessageId,
        payload: Vec<u8>,
    },
    Waiting {
        operation_id: OperationId,
        message_id: MessageId,
    },
    Idle,
    Disconnected,
    Terminal {
        operation_id: OperationId,
        message_id: MessageId,
        outcome: ExecutorTerminalOutcome,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutorTerminalOutcome {
    Succeeded(Vec<u8>),
    Failed { code: String, detail: String },
    Cancelled,
    Blocked(String),
    Uncertain(String),
}

pub trait OperationExecutor: Send + Sync + 'static {
    type AuthenticatedInstance: Clone + Send + Sync;

    fn ensure_ready(
        &self,
        operation: &OperationSnapshot,
    ) -> impl Future<Output = Result<Self::AuthenticatedInstance, ExecutorError>> + Send;

    fn deliver(
        &self,
        permit: &AdmissionPermit,
        instance: &Self::AuthenticatedInstance,
        operation: &OperationSnapshot,
        input: &[u8],
    ) -> impl Future<Output = Result<DeliveryAcceptance, ExecutorError>> + Send;

    fn next_report(
        &self,
        instance: &Self::AuthenticatedInstance,
        operation: &OperationSnapshot,
    ) -> impl Future<Output = Result<ExecutorReport, ExecutorError>> + Send;

    fn acknowledge_report(
        &self,
        _instance: &Self::AuthenticatedInstance,
        _operation_id: OperationId,
        _message_id: MessageId,
    ) -> impl Future<Output = Result<(), ExecutorError>> + Send {
        async { Ok(()) }
    }

    fn remind(
        &self,
        instance: &Self::AuthenticatedInstance,
        operation: &OperationSnapshot,
    ) -> impl Future<Output = Result<(), ExecutorError>> + Send;

    fn drive_cancellation(
        &self,
        permit: &AdmissionPermit,
        operation: &OperationSnapshot,
        notification: &MessageSnapshot,
    ) -> impl Future<Output = Result<(), ExecutorError>> + Send;

    fn shutdown_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> impl Future<Output = Result<(), ExecutorError>> + Send;

    fn shutdown_session_until(
        &self,
        session_id: navigator_domain::SessionId,
        deadline: tokio::time::Instant,
    ) -> impl Future<Output = Result<(), ExecutorError>> + Send;
}

pub trait OperationPersistence: Send + Sync + 'static {
    fn campaign(
        &self,
        participant_id: ParticipantId,
    ) -> impl Future<Output = Result<ParticipantId, StoreError>> + Send;
    fn load(
        &self,
        operation_id: OperationId,
    ) -> impl Future<Output = Result<OperationSnapshot, StoreError>> + Send;
    fn start(
        &self,
        command: StartOperation,
    ) -> impl Future<Output = Result<Mutation<OperationSnapshot>, StoreError>> + Send;
    fn transition(
        &self,
        command: TransitionOperation,
    ) -> impl Future<Output = Result<Mutation<OperationSnapshot>, StoreError>> + Send;
    fn input(
        &self,
        operation_id: OperationId,
    ) -> impl Future<Output = Result<BoundedBytes<MAX_OPERATION_INPUT_BYTES>, StoreError>> + Send;
}

impl<T: OperationStore + HierarchyStore + 'static> OperationPersistence for T {
    async fn campaign(&self, participant_id: ParticipantId) -> Result<ParticipantId, StoreError> {
        let mut participant = self.load_participant(participant_id).await?;
        while let Some(parent_id) = participant.parent_participant_id {
            participant = self.load_participant(parent_id).await?;
        }
        Ok(participant.participant_id)
    }
    async fn load(&self, operation_id: OperationId) -> Result<OperationSnapshot, StoreError> {
        self.load_operation(operation_id).await
    }
    async fn start(
        &self,
        command: StartOperation,
    ) -> Result<Mutation<OperationSnapshot>, StoreError> {
        self.start_operation(command).await
    }

    async fn transition(
        &self,
        command: TransitionOperation,
    ) -> Result<Mutation<OperationSnapshot>, StoreError> {
        self.transition_operation(command).await
    }

    async fn input(
        &self,
        operation_id: OperationId,
    ) -> Result<BoundedBytes<MAX_OPERATION_INPUT_BYTES>, StoreError> {
        self.load_operation_input(operation_id).await
    }
}

pub trait TransitionContextFactory: Send + Sync + 'static {
    fn context(
        &self,
        operation_id: OperationId,
        action: OperationAction,
        ordinal: u32,
    ) -> RequestContext;
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("Executor boundary failed: {message}")]
pub struct ExecutorError {
    pub message: String,
}

#[derive(Debug, Error)]
pub enum FirstOperationError {
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("operation worker stopped before durable admission")]
    WorkerStopped,
}

#[derive(Clone, Copy, Debug)]
pub struct FirstOperationConfig {
    pub capacity_wait: Duration,
    pub report_deadline: Duration,
}

pub struct OperationHandle {
    admitted: Mutation<OperationSnapshot>,
    completion: watch::Receiver<Option<Result<OperationSnapshot, String>>>,
}

impl OperationHandle {
    #[must_use]
    pub const fn admitted(&self) -> &Mutation<OperationSnapshot> {
        &self.admitted
    }

    pub async fn completion(mut self) -> Result<OperationSnapshot, String> {
        loop {
            if let Some(result) = self.completion.borrow().clone() {
                return result;
            }
            if self.completion.changed().await.is_err() {
                return Err("operation worker stopped without a terminal snapshot".into());
            }
        }
    }
}

pub struct FirstOperationService<S, E, F> {
    store: Arc<S>,
    executor: Arc<E>,
    contexts: Arc<F>,
    capacity: Arc<FairCapacity>,
    registry: Arc<Mutex<WorkerRegistry>>,
    config: FirstOperationConfig,
}

struct FairCapacity {
    state: std::sync::Mutex<FairCapacityState>,
}

struct FairCapacityState {
    capacity: usize,
    active: usize,
    last_served: Option<ParticipantId>,
    waiting: BTreeMap<ParticipantId, VecDeque<oneshot::Sender<()>>>,
}

impl FairCapacity {
    fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "operation capacity must be positive");
        Self {
            state: std::sync::Mutex::new(FairCapacityState {
                capacity,
                active: 0,
                last_served: None,
                waiting: BTreeMap::new(),
            }),
        }
    }

    async fn acquire(self: &Arc<Self>, campaign: ParticipantId) -> FairCapacityPermit {
        let receiver = {
            let mut state = self.state.lock().expect("fair capacity lock poisoned");
            if state.active < state.capacity && state.waiting.is_empty() {
                state.active += 1;
                return FairCapacityPermit {
                    capacity: Arc::clone(self),
                };
            }
            let (sender, receiver) = oneshot::channel();
            state.waiting.entry(campaign).or_default().push_back(sender);
            receiver
        };
        let _ = receiver.await;
        FairCapacityPermit {
            capacity: Arc::clone(self),
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("fair capacity lock poisoned");
        state.active = state.active.saturating_sub(1);
        while state.active < state.capacity && !state.waiting.is_empty() {
            let next = state
                .waiting
                .keys()
                .copied()
                .find(|key| state.last_served.is_none_or(|last| *key > last))
                .or_else(|| state.waiting.keys().next().copied())
                .expect("non-empty fair queue has a key");
            let sender = state.waiting.get_mut(&next).and_then(VecDeque::pop_front);
            if state.waiting.get(&next).is_some_and(VecDeque::is_empty) {
                state.waiting.remove(&next);
            }
            if sender.is_some_and(|sender| sender.send(()).is_ok()) {
                state.last_served = Some(next);
                state.active += 1;
            }
        }
    }
}

struct FairCapacityPermit {
    capacity: Arc<FairCapacity>,
}

impl Drop for FairCapacityPermit {
    fn drop(&mut self) {
        self.capacity.release();
    }
}

struct WorkerRegistry {
    accepting: bool,
    active: HashSet<OperationId>,
    wake_requested: HashSet<OperationId>,
    handles: HashMap<OperationId, tokio::task::JoinHandle<()>>,
    failures: HashMap<OperationId, String>,
}

impl<S, E, F> FirstOperationService<S, E, F>
where
    S: OperationPersistence,
    E: OperationExecutor,
    F: TransitionContextFactory,
{
    #[must_use]
    pub fn new(
        store: Arc<S>,
        executor: Arc<E>,
        contexts: Arc<F>,
        capacity: usize,
        config: FirstOperationConfig,
    ) -> Self {
        Self {
            store,
            executor,
            contexts,
            capacity: Arc::new(FairCapacity::new(capacity)),
            registry: Arc::new(Mutex::new(WorkerRegistry {
                accepting: true,
                active: HashSet::new(),
                wake_requested: HashSet::new(),
                handles: HashMap::new(),
                failures: HashMap::new(),
            })),
            config,
        }
    }

    pub async fn start(
        &self,
        permit: AdmissionPermit,
        command: StartOperation,
    ) -> Result<OperationHandle, FirstOperationError> {
        permit.check()?;
        let operation_id = command.operation_id;
        let mut registry = self.registry.lock().await;
        if !registry.accepting || !registry.active.insert(operation_id) {
            return Err(FirstOperationError::WorkerStopped);
        }
        let (admitted_tx, admitted_rx) = oneshot::channel();
        let (completion_tx, completion_rx) = watch::channel(None);
        let worker = Worker {
            store: Arc::clone(&self.store),
            executor: Arc::clone(&self.executor),
            contexts: Arc::clone(&self.contexts),
            capacity: Arc::clone(&self.capacity),
            config: self.config,
            permit,
            epoch: command.epoch,
        };
        let workers = Arc::clone(&self.registry);
        let (run_tx, run_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            if run_rx.await.is_err() {
                return;
            }
            worker.run(command, admitted_tx, completion_tx).await;
            loop {
                let rerun = {
                    let mut registry = workers.lock().await;
                    if registry.wake_requested.remove(&operation_id) {
                        true
                    } else {
                        registry.active.remove(&operation_id);
                        registry.handles.remove(&operation_id);
                        false
                    }
                };
                if !rerun {
                    break;
                }
                let Ok(mut operation) = worker.store.load(operation_id).await else {
                    continue;
                };
                let result = worker.execute(&mut operation).await;
                record_worker_result(&workers, operation_id, &result).await;
            }
        });
        registry.handles.insert(operation_id, handle);
        let _ = run_tx.send(());
        drop(registry);
        let admitted = admitted_rx
            .await
            .map_err(|_| FirstOperationError::WorkerStopped)??;
        Ok(OperationHandle {
            admitted,
            completion: completion_rx,
        })
    }

    pub async fn resume_existing(
        &self,
        permit: AdmissionPermit,
        operation_id: OperationId,
        epoch: FencingEpoch,
    ) -> Result<bool, FirstOperationError> {
        permit.check()?;
        let operation = self.store.load(operation_id).await?;
        if operation.state.is_terminal() {
            self.registry.lock().await.failures.remove(&operation_id);
            return Ok(false);
        }
        self.store.input(operation_id).await?;
        let mut registry = self.registry.lock().await;
        if !registry.accepting {
            return Err(FirstOperationError::WorkerStopped);
        }
        if !registry.active.insert(operation_id) {
            registry.wake_requested.insert(operation_id);
            return Ok(false);
        }
        let workers = Arc::clone(&self.registry);
        let worker = Worker {
            store: Arc::clone(&self.store),
            executor: Arc::clone(&self.executor),
            contexts: Arc::clone(&self.contexts),
            capacity: Arc::clone(&self.capacity),
            config: self.config,
            permit,
            epoch,
        };
        let (run_tx, run_rx) = oneshot::channel();
        let handle = tokio::spawn(async move {
            if run_rx.await.is_err() {
                return;
            }
            let mut operation = operation;
            loop {
                let result = execute_existing_with_retry(&worker, &mut operation).await;
                record_worker_result(&workers, operation_id, &result).await;
                let rerun = {
                    let mut registry = workers.lock().await;
                    if registry.wake_requested.remove(&operation_id) {
                        true
                    } else {
                        registry.active.remove(&operation_id);
                        registry.handles.remove(&operation_id);
                        false
                    }
                };
                if !rerun {
                    break;
                }
                let Ok(reloaded) = worker.store.load(operation_id).await else {
                    continue;
                };
                operation = reloaded;
            }
        });
        registry.handles.insert(operation_id, handle);
        let _ = run_tx.send(());
        Ok(true)
    }

    pub async fn shutdown_until(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), FirstOperationError> {
        let handles = {
            let mut registry = self.registry.lock().await;
            registry.accepting = false;
            registry.active.clear();
            registry.wake_requested.clear();
            registry.failures.clear();
            registry
                .handles
                .drain()
                .map(|(_, handle)| handle)
                .collect::<Vec<_>>()
        };
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let _ = handle.await;
        }
        if self.executor.shutdown_until(deadline).await.is_err() {
            Err(FirstOperationError::WorkerStopped)
        } else {
            Ok(())
        }
    }

    pub async fn cancel_subtree(
        &self,
        permit: AdmissionPermit,
        command: CancelSubtree,
    ) -> Result<CancelSubtreeOutcome, FirstOperationError>
    where
        S: HierarchyStore,
    {
        permit.check()?;
        let committed = self.store.cancel_subtree(command.clone()).await?;
        let mut interrupted = Vec::new();
        {
            let mut registry = self.registry.lock().await;
            for record in &committed.value().records {
                registry.active.remove(&record.operation.operation_id);
                registry.failures.remove(&record.operation.operation_id);
                if let Some(handle) = registry.handles.remove(&record.operation.operation_id) {
                    interrupted.push(handle);
                }
            }
        }
        for handle in interrupted {
            handle.abort();
            let _ = handle.await;
        }
        for record in &committed.value().records {
            if let Some(notification) = &record.notification {
                permit.check()?;
                self.executor
                    .drive_cancellation(&permit, &record.operation, notification)
                    .await
                    .map_err(|_| FirstOperationError::WorkerStopped)?;
            }
        }
        let current = self
            .store
            .cancel_subtree(command.clone())
            .await?
            .value()
            .clone();
        for record in &current.records {
            if record.operation.state == OperationState::Cancelling {
                let _ = self
                    .resume_existing(permit.clone(), record.operation.operation_id, command.epoch)
                    .await?;
            }
        }
        Ok(current)
    }

    pub async fn cancel_session_until(
        &self,
        permit: AdmissionPermit,
        command: CancelSubtree,
        deadline: tokio::time::Instant,
    ) -> Result<CancelSubtreeOutcome, FirstOperationError>
    where
        S: HierarchyStore,
    {
        let current = match tokio::time::timeout_at(
            deadline,
            self.cancel_subtree(permit.clone(), command.clone()),
        )
        .await
        .map_err(|_| FirstOperationError::WorkerStopped)?
        {
            Ok(current) => current,
            Err(delivery_error @ FirstOperationError::WorkerStopped) => {
                // A cancellation notification can race a launch that never
                // crossed its effect boundary. The Store may already have
                // terminalized the operation while there is no Driver to ACK
                // that now-vacuous notification. Re-read durable truth before
                // continuing, and still require the session-wide shutdown
                // below to reconcile every pending or active launch.
                let replay =
                    tokio::time::timeout_at(deadline, self.store.cancel_subtree(command.clone()))
                        .await
                        .map_err(|_| FirstOperationError::WorkerStopped)??
                        .value()
                        .clone();
                if replay
                    .records
                    .iter()
                    .any(|record| !record.operation.state.is_terminal())
                {
                    return Err(delivery_error);
                }
                replay
            }
            Err(error) => return Err(error),
        };
        loop {
            permit.check()?;
            let mut terminal = true;
            for record in &current.records {
                let operation = tokio::time::timeout_at(
                    deadline,
                    self.store.load(record.operation.operation_id),
                )
                .await
                .map_err(|_| FirstOperationError::WorkerStopped)??;
                terminal &= operation.state.is_terminal();
            }
            if terminal {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(FirstOperationError::WorkerStopped);
            }
            tokio::task::yield_now().await;
        }
        tokio::time::timeout_at(
            deadline,
            self.executor
                .shutdown_session_until(command.session_id, deadline),
        )
        .await
        .map_err(|_| FirstOperationError::WorkerStopped)?
        .map_err(|_| FirstOperationError::WorkerStopped)?;
        Ok(
            tokio::time::timeout_at(deadline, self.store.cancel_subtree(command))
                .await
                .map_err(|_| FirstOperationError::WorkerStopped)??
                .value()
                .clone(),
        )
    }
}

struct Worker<S, E, F> {
    store: Arc<S>,
    executor: Arc<E>,
    contexts: Arc<F>,
    capacity: Arc<FairCapacity>,
    config: FirstOperationConfig,
    permit: AdmissionPermit,
    epoch: FencingEpoch,
}

impl<S, E, F> Worker<S, E, F>
where
    S: OperationPersistence,
    E: OperationExecutor,
    F: TransitionContextFactory,
{
    async fn run(
        &self,
        command: StartOperation,
        admitted: oneshot::Sender<Result<Mutation<OperationSnapshot>, FirstOperationError>>,
        completion: watch::Sender<Option<Result<OperationSnapshot, String>>>,
    ) {
        let started = match self.store.start(command).await {
            Ok(value) => value,
            Err(error) => {
                let _ = admitted.send(Err(error.into()));
                return;
            }
        };
        let mut operation = started.value().clone();
        if admitted.send(Ok(started)).is_err() {
            // The durable worker deliberately continues after Consumer cancellation.
        }
        let result = self.execute(&mut operation).await;
        let _ = completion.send(Some(result.map_err(|error| error.to_string())));
    }

    async fn execute(
        &self,
        operation: &mut OperationSnapshot,
    ) -> Result<OperationSnapshot, WorkerError> {
        if operation.state.is_terminal() {
            return Ok(operation.clone());
        }
        let campaign = self.store.campaign(operation.participant_id).await?;
        let Ok(capacity_permit) =
            tokio::time::timeout(self.config.capacity_wait, self.capacity.acquire(campaign)).await
        else {
            return self
                .fail(
                    operation,
                    "capacity",
                    "execution capacity deadline elapsed",
                    1,
                )
                .await;
        };
        if operation.state == OperationState::Queued {
            *operation = self
                .transition(operation, OperationAction::BeginStart, None, None, 1)
                .await?;
        }
        *operation = self.store.load(operation.operation_id).await?;
        if operation.state == OperationState::Cancelled {
            return Ok(operation.clone());
        }
        let Ok(instance) = self.executor.ensure_ready(operation).await else {
            return self
                .fail(
                    operation,
                    "executor_unavailable",
                    "Executor could not become ready",
                    2,
                )
                .await;
        };
        if matches!(
            operation.state,
            OperationState::Running | OperationState::Waiting | OperationState::Cancelling
        ) {
            return self.observe(operation, &instance, capacity_permit).await;
        }
        self.permit.check()?;
        let input = self.store.input(operation.operation_id).await?;
        self.permit.check()?;
        let Ok(acceptance) = self
            .executor
            .deliver(&self.permit, &instance, operation, input.as_slice())
            .await
        else {
            return self
                .uncertain(operation, "Driver delivery failed after durable intent", 2)
                .await;
        };
        match acceptance {
            DeliveryAcceptance::Accepted => {}
            DeliveryAcceptance::NotAccepted => {
                return self
                    .fail(
                        operation,
                        "delivery_rejected",
                        "Driver did not accept the durable Message",
                        2,
                    )
                    .await;
            }
            DeliveryAcceptance::Unknown => {
                return self
                    .uncertain(operation, "delivery acceptance is unknown", 2)
                    .await;
            }
        }
        *operation = self
            .transition(
                operation,
                OperationAction::ReportRunning,
                Some(operation.input_message_id),
                None,
                2,
            )
            .await?;
        self.observe(operation, &instance, capacity_permit).await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "closed report state machine stays auditable"
    )]
    async fn observe(
        &self,
        operation: &mut OperationSnapshot,
        instance: &E::AuthenticatedInstance,
        capacity_permit: FairCapacityPermit,
    ) -> Result<OperationSnapshot, WorkerError> {
        let mut reminded = false;
        let mut reports_seen = 0usize;
        let started = tokio::time::Instant::now();
        let deadline = started + self.config.report_deadline;
        let reminder_at = started + self.config.report_deadline / 2;
        loop {
            let poll_deadline = if reminded { deadline } else { reminder_at };
            let report = tokio::time::timeout_at(
                poll_deadline,
                self.executor.next_report(instance, operation),
            )
            .await;
            let report = match report {
                Ok(Ok(value)) => value,
                Ok(Err(error)) => {
                    if operation.state == OperationState::Cancelling {
                        return Err(cancellation_pending());
                    }
                    return self.uncertain(operation, &error.message, 3).await;
                }
                Err(_) if !reminded => {
                    if self.executor.remind(instance, operation).await.is_err() {
                        if operation.state == OperationState::Cancelling {
                            return Err(cancellation_pending());
                        }
                        return self
                            .uncertain(operation, "Driver reminder delivery failed", 3)
                            .await;
                    }
                    reminded = true;
                    continue;
                }
                Err(_) => {
                    if operation.state == OperationState::Cancelling {
                        return Err(cancellation_pending());
                    }
                    return self
                        .fail(
                            operation,
                            "result_deadline",
                            "Executor produced no explicit terminal report",
                            3,
                        )
                        .await;
                }
            };
            reports_seen += 1;
            if reports_seen > MAX_REPORTS_PER_OPERATION {
                return self
                    .fail(
                        operation,
                        "report_capacity",
                        "Driver report budget was exhausted",
                        3,
                    )
                    .await;
            }
            match report {
                ExecutorReport::Waiting {
                    operation_id,
                    message_id,
                } => {
                    if Self::correlate(operation, operation_id, message_id).is_err() {
                        return self.fail(operation, "invalid_correlation", "Driver question does not identify the delivered Operation and Message", 3).await;
                    }
                    let waiting = self.store.load(operation.operation_id).await?;
                    if waiting.state != OperationState::Waiting
                        || waiting.waiting_on_message_id.is_none()
                    {
                        return self
                            .fail(
                                operation,
                                "invalid_question",
                                "Question was not committed atomically",
                                3,
                            )
                            .await;
                    }
                    self.executor
                        .acknowledge_report(instance, operation_id, message_id)
                        .await?;
                    return Ok(waiting);
                }
                ExecutorReport::Progress {
                    operation_id,
                    message_id,
                    payload,
                } => {
                    if Self::correlate(operation, operation_id, message_id).is_err() {
                        return self.fail(operation, "invalid_correlation", "Driver report does not identify the delivered Operation and Message", 3).await;
                    }
                    if payload.len() > MAX_PROGRESS_BYTES {
                        return self
                            .fail(operation, "invalid_report", "Progress exceeds bound", 3)
                            .await;
                    }
                    self.executor
                        .acknowledge_report(instance, operation_id, message_id)
                        .await?;
                }
                ExecutorReport::Idle if !reminded => {
                    if self.executor.remind(instance, operation).await.is_err() {
                        if operation.state == OperationState::Cancelling {
                            return Err(cancellation_pending());
                        }
                        return self
                            .uncertain(operation, "Driver reminder delivery failed", 3)
                            .await;
                    }
                    reminded = true;
                }
                ExecutorReport::Idle => {
                    if operation.state == OperationState::Cancelling {
                        return Err(cancellation_pending());
                    }
                    return self
                        .fail(
                            operation,
                            "result_deadline",
                            "Executor settled without an explicit terminal report",
                            3,
                        )
                        .await;
                }
                ExecutorReport::Disconnected => {}
                ExecutorReport::Terminal {
                    operation_id,
                    message_id,
                    outcome,
                } => {
                    if Self::correlate(operation, operation_id, message_id).is_err() {
                        return self.fail(operation, "invalid_correlation", "Driver terminal report does not identify the delivered Operation and Message", 3).await;
                    }
                    *operation = self.store.load(operation.operation_id).await?;
                    let terminal = self.commit_terminal(operation, outcome, 3).await;
                    if terminal.is_ok() {
                        self.executor
                            .acknowledge_report(instance, operation_id, message_id)
                            .await?;
                    }
                    drop(capacity_permit);
                    return terminal;
                }
            }
        }
    }

    fn correlate(
        operation: &OperationSnapshot,
        operation_id: OperationId,
        message_id: MessageId,
    ) -> Result<(), WorkerError> {
        // The authenticated executor validates that this is an Accepted
        // delivery correlated to this operation; it need not be the original
        // input (for example, a child outcome delivered to its parent).
        if operation.operation_id == operation_id && !message_id.as_uuid().is_nil() {
            Ok(())
        } else {
            Err(WorkerError::Correlation)
        }
    }

    async fn transition(
        &self,
        operation: &OperationSnapshot,
        action: OperationAction,
        report_message_id: Option<MessageId>,
        terminal_outcome: Option<OperationTerminalOutcome>,
        ordinal: u32,
    ) -> Result<OperationSnapshot, WorkerError> {
        self.permit.check()?;
        let mutation = self
            .store
            .transition(TransitionOperation {
                context: self
                    .contexts
                    .context(operation.operation_id, action, ordinal),
                session_id: operation.session_id,
                epoch: self.epoch,
                operation_id: operation.operation_id,
                expected_revision: operation.revision,
                action,
                report_message_id,
                terminal_outcome,
            })
            .await?;
        Ok(mutation.value().clone())
    }

    async fn commit_terminal(
        &self,
        operation: &OperationSnapshot,
        outcome: ExecutorTerminalOutcome,
        ordinal: u32,
    ) -> Result<OperationSnapshot, WorkerError> {
        let (action, outcome) = match terminal(outcome) {
            Ok(value) => value,
            Err(WorkerError::Bound) => (
                OperationAction::ReportFailure,
                OperationTerminalOutcome::Failed {
                    code: BoundedText::new("invalid_report").expect("static code is bounded"),
                    detail: BoundedText::new("Executor terminal report exceeded its bound")
                        .expect("static detail is bounded"),
                },
            ),
            Err(error) => return Err(error),
        };
        self.transition(
            operation,
            action,
            Some(operation.input_message_id),
            Some(outcome),
            ordinal,
        )
        .await
    }

    async fn fail(
        &self,
        operation: &OperationSnapshot,
        code: &str,
        detail: &str,
        ordinal: u32,
    ) -> Result<OperationSnapshot, WorkerError> {
        self.transition(
            operation,
            OperationAction::ReportFailure,
            system_report_message(operation),
            Some(OperationTerminalOutcome::Failed {
                code: BoundedText::new(code).map_err(|_| WorkerError::Bound)?,
                detail: BoundedText::new(detail).map_err(|_| WorkerError::Bound)?,
            }),
            ordinal,
        )
        .await
    }

    async fn uncertain(
        &self,
        operation: &OperationSnapshot,
        reason: &str,
        ordinal: u32,
    ) -> Result<OperationSnapshot, WorkerError> {
        self.transition(
            operation,
            OperationAction::ReportUncertain,
            system_report_message(operation),
            Some(OperationTerminalOutcome::Uncertain {
                reason: BoundedText::new(reason).map_err(|_| WorkerError::Bound)?,
            }),
            ordinal,
        )
        .await
    }
}

const MAX_PRE_START_RETRIES: usize = 3;
const PRE_START_RETRY_BACKOFF: Duration = Duration::from_millis(10);

async fn execute_existing_with_retry<S, E, F>(
    worker: &Worker<S, E, F>,
    operation: &mut OperationSnapshot,
) -> Result<OperationSnapshot, WorkerError>
where
    S: OperationPersistence,
    E: OperationExecutor,
    F: TransitionContextFactory,
{
    for attempt in 0..MAX_PRE_START_RETRIES {
        match worker.execute(operation).await {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) => {
                let Ok(reloaded) = worker.store.load(operation.operation_id).await else {
                    if attempt + 1 == MAX_PRE_START_RETRIES {
                        return Err(error);
                    }
                    worker.permit.check()?;
                    tokio::time::sleep(PRE_START_RETRY_BACKOFF).await;
                    continue;
                };
                if reloaded.state != OperationState::Queued {
                    return Err(error);
                }
                *operation = reloaded;
                if attempt + 1 == MAX_PRE_START_RETRIES {
                    return Err(error);
                }
                worker.permit.check()?;
                tokio::time::sleep(PRE_START_RETRY_BACKOFF).await;
            }
        }
    }
    unreachable!("the bounded retry loop always returns")
}

async fn record_worker_result(
    workers: &Mutex<WorkerRegistry>,
    operation_id: OperationId,
    result: &Result<OperationSnapshot, WorkerError>,
) {
    let mut registry = workers.lock().await;
    match result {
        Ok(_) => {
            registry.failures.remove(&operation_id);
        }
        Err(error) => {
            if !registry.failures.contains_key(&operation_id)
                && registry.failures.len() == MAX_WORKER_FAILURE_RECORDS
                && let Some(oldest) = registry.failures.keys().next().copied()
            {
                registry.failures.remove(&oldest);
            }
            registry.failures.insert(operation_id, error.to_string());
        }
    }
}

fn system_report_message(operation: &OperationSnapshot) -> Option<MessageId> {
    matches!(
        operation.state,
        OperationState::Running | OperationState::Waiting | OperationState::Cancelling
    )
    .then_some(operation.input_message_id)
}

fn terminal(
    value: ExecutorTerminalOutcome,
) -> Result<(OperationAction, OperationTerminalOutcome), WorkerError> {
    Ok(match value {
        ExecutorTerminalOutcome::Succeeded(result) => (
            OperationAction::ReportSuccess,
            OperationTerminalOutcome::Succeeded {
                result: BoundedBytes::new(result).map_err(|_| WorkerError::Bound)?,
            },
        ),
        ExecutorTerminalOutcome::Failed { code, detail } => (
            OperationAction::ReportFailure,
            OperationTerminalOutcome::Failed {
                code: BoundedText::new(code).map_err(|_| WorkerError::Bound)?,
                detail: BoundedText::new(detail).map_err(|_| WorkerError::Bound)?,
            },
        ),
        ExecutorTerminalOutcome::Cancelled => (
            OperationAction::ReportCancelled,
            OperationTerminalOutcome::Cancelled,
        ),
        ExecutorTerminalOutcome::Blocked(reason) => (
            OperationAction::ReportBlocked,
            OperationTerminalOutcome::Blocked {
                reason: BoundedText::new(reason).map_err(|_| WorkerError::Bound)?,
            },
        ),
        ExecutorTerminalOutcome::Uncertain(reason) => (
            OperationAction::ReportUncertain,
            OperationTerminalOutcome::Uncertain {
                reason: BoundedText::new(reason).map_err(|_| WorkerError::Bound)?,
            },
        ),
    })
}

fn cancellation_pending() -> WorkerError {
    ExecutorError {
        message: "cancellation remains pending without an authenticated terminal report".into(),
    }
    .into()
}

#[derive(Debug, Error)]
enum WorkerError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Executor(#[from] ExecutorError),
    #[error("Driver report correlation is invalid")]
    Correlation,
    #[error("terminal report exceeds its bound")]
    Bound,
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicU32, Ordering},
        },
    };

    use navigator_domain::{
        ControlMessageKind, FencingEpoch, HostId, InputSchema, MessageId, OperationId,
        OperationState, ParticipantId, RequestId, Revision, SessionId, Timestamp,
        ValidatedMessageEnvelope,
    };
    use navigator_store_api::{MessageCorrelation, MessageDeliveryState, MessagePriority};
    use uuid::Uuid;

    use super::*;
    use crate::AdmissionGate;

    fn identity<T>(
        value: u128,
        make: fn(Uuid) -> Result<T, navigator_domain::InvalidIdentity>,
    ) -> T {
        make(Uuid::from_u128(value)).unwrap()
    }

    #[tokio::test]
    async fn fair_capacity_rotates_subtrees_and_skips_cancelled_waiters() {
        let capacity = Arc::new(FairCapacity::new(1));
        let campaign_a = identity(90, ParticipantId::from_uuid);
        let campaign_b = identity(91, ParticipantId::from_uuid);
        let held = capacity.acquire(campaign_a).await;
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

        let cancelled_capacity = Arc::clone(&capacity);
        let cancelled = tokio::spawn(async move {
            let _permit = cancelled_capacity.acquire(campaign_a).await;
        });
        tokio::task::yield_now().await;
        cancelled.abort();
        assert!(cancelled.await.unwrap_err().is_cancelled());

        for (campaign, label) in [(campaign_a, "a"), (campaign_b, "b")] {
            let capacity = Arc::clone(&capacity);
            let sender = sender.clone();
            tokio::spawn(async move {
                let permit = capacity.acquire(campaign).await;
                sender.send((label, permit)).unwrap();
            });
            tokio::task::yield_now().await;
        }
        drop(held);
        let (first, first_permit) = receiver.recv().await.unwrap();
        assert_eq!(first, "a");
        drop(first_permit);
        let (second, second_permit) = receiver.recv().await.unwrap();
        assert_eq!(second, "b");
        drop(second_permit);
    }

    #[tokio::test]
    async fn hot_campaign_subtree_cannot_starve_a_peer_campaign() {
        let capacity = Arc::new(FairCapacity::new(1));
        let hot_campaign = identity(92, ParticipantId::from_uuid);
        let peer_campaign = identity(93, ParticipantId::from_uuid);
        let held = capacity.acquire(hot_campaign).await;
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        for (campaign, label) in [
            (hot_campaign, "hot-1"),
            (hot_campaign, "hot-2"),
            (hot_campaign, "hot-3"),
            (peer_campaign, "peer"),
        ] {
            let capacity = Arc::clone(&capacity);
            let sender = sender.clone();
            tokio::spawn(async move {
                let permit = capacity.acquire(campaign).await;
                sender.send((label, permit)).unwrap();
            });
            tokio::task::yield_now().await;
        }
        drop(held);
        let mut order = Vec::new();
        for _ in 0..4 {
            let (label, permit) = receiver.recv().await.unwrap();
            order.push(label);
            drop(permit);
        }
        assert_eq!(order, ["hot-1", "peer", "hot-2", "hot-3"]);
    }

    struct Store {
        snapshot: Mutex<OperationSnapshot>,
        input: BoundedBytes<65_536>,
        revoke_on_load: Mutex<Option<AdmissionGate>>,
        cancellation_notification: Option<MessageSnapshot>,
    }

    struct FlakyBeginStartStore {
        inner: Store,
        failures_remaining: AtomicU32,
        attempts: AtomicU32,
    }

    impl OperationPersistence for FlakyBeginStartStore {
        async fn campaign(
            &self,
            participant_id: ParticipantId,
        ) -> Result<ParticipantId, StoreError> {
            Ok(participant_id)
        }
        async fn load(&self, operation_id: OperationId) -> Result<OperationSnapshot, StoreError> {
            self.inner.load(operation_id).await
        }

        async fn start(
            &self,
            command: StartOperation,
        ) -> Result<Mutation<OperationSnapshot>, StoreError> {
            self.inner.start(command).await
        }

        async fn transition(
            &self,
            command: TransitionOperation,
        ) -> Result<Mutation<OperationSnapshot>, StoreError> {
            if command.action == OperationAction::BeginStart {
                self.attempts.fetch_add(1, Ordering::SeqCst);
                if self
                    .failures_remaining
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                        value.checked_sub(1)
                    })
                    .is_ok()
                {
                    return Err(StoreError::Unavailable);
                }
            }
            self.inner.transition(command).await
        }

        async fn input(
            &self,
            operation_id: OperationId,
        ) -> Result<BoundedBytes<MAX_OPERATION_INPUT_BYTES>, StoreError> {
            self.inner.input(operation_id).await
        }
    }

    impl OperationPersistence for Store {
        async fn campaign(
            &self,
            participant_id: ParticipantId,
        ) -> Result<ParticipantId, StoreError> {
            Ok(participant_id)
        }
        async fn load(&self, _: OperationId) -> Result<OperationSnapshot, StoreError> {
            if let Some(gate) = self.revoke_on_load.lock().unwrap().take() {
                gate.close();
            }
            Ok(self.snapshot.lock().unwrap().clone())
        }
        async fn start(
            &self,
            _: StartOperation,
        ) -> Result<Mutation<OperationSnapshot>, StoreError> {
            Ok(Mutation::Applied(self.snapshot.lock().unwrap().clone()))
        }

        async fn transition(
            &self,
            command: TransitionOperation,
        ) -> Result<Mutation<OperationSnapshot>, StoreError> {
            let mut value = self.snapshot.lock().unwrap();
            assert_eq!(command.epoch, FencingEpoch::new(7).unwrap());
            assert_eq!(command.expected_revision, value.revision);
            value.state = match command.action {
                OperationAction::BeginStart => OperationState::Starting,
                OperationAction::ReportRunning => OperationState::Running,
                OperationAction::ReportSuccess => OperationState::Succeeded,
                OperationAction::ReportFailure => OperationState::Failed,
                OperationAction::ReportCancelled => OperationState::Cancelled,
                OperationAction::ReportBlocked => OperationState::Blocked,
                OperationAction::ReportUncertain => OperationState::Uncertain,
                _ => return Err(StoreError::Invalid),
            };
            value.revision = value.revision.next().unwrap();
            value.terminal_outcome = command.terminal_outcome;
            Ok(Mutation::Applied(value.clone()))
        }

        async fn input(
            &self,
            _: OperationId,
        ) -> Result<BoundedBytes<MAX_OPERATION_INPUT_BYTES>, StoreError> {
            Ok(self.input.clone())
        }
    }

    impl HierarchyStore for Store {
        async fn apply_hierarchy_effect(
            &self,
            _: navigator_store_api::ApplyHierarchyEffect,
        ) -> Result<Mutation<navigator_store_api::HierarchyEffectOutcome>, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn authorized_status(
            &self,
            _: navigator_store_api::AuthorizedStatus,
        ) -> Result<Mutation<navigator_store_api::AuthorizedStatusOutcome>, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn cancel_subtree(
            &self,
            command: CancelSubtree,
        ) -> Result<Mutation<CancelSubtreeOutcome>, StoreError> {
            let operation = self.snapshot.lock().unwrap().clone();
            Ok(Mutation::Applied(CancelSubtreeOutcome {
                root_participant_id: command.root_participant_id,
                records: vec![navigator_store_api::CancellationRecord {
                    operation,
                    notification: self.cancellation_notification.clone(),
                }],
            }))
        }

        async fn cancellation_requested(&self, _: ParticipantId) -> Result<bool, StoreError> {
            Ok(false)
        }
    }

    struct Executor {
        reports: Mutex<VecDeque<ExecutorReport>>,
        reminders: Mutex<u32>,
        terminal_at: Mutex<Option<tokio::time::Instant>>,
        repeat_disconnect: bool,
        deliveries: AtomicU32,
        shutdown_calls: AtomicU32,
    }

    struct BlockingDeliverExecutor {
        entered: tokio::sync::Notify,
        shutdown_calls: AtomicU32,
    }

    impl OperationExecutor for BlockingDeliverExecutor {
        type AuthenticatedInstance = ();

        async fn ensure_ready(
            &self,
            _: &OperationSnapshot,
        ) -> Result<Self::AuthenticatedInstance, ExecutorError> {
            Ok(())
        }

        async fn deliver(
            &self,
            _: &AdmissionPermit,
            (): &(),
            _: &OperationSnapshot,
            _: &[u8],
        ) -> Result<DeliveryAcceptance, ExecutorError> {
            self.entered.notify_one();
            std::future::pending().await
        }

        async fn next_report(
            &self,
            (): &(),
            _: &OperationSnapshot,
        ) -> Result<ExecutorReport, ExecutorError> {
            unreachable!()
        }

        async fn remind(&self, (): &(), _: &OperationSnapshot) -> Result<(), ExecutorError> {
            unreachable!()
        }

        async fn drive_cancellation(
            &self,
            _: &AdmissionPermit,
            _: &OperationSnapshot,
            _: &MessageSnapshot,
        ) -> Result<(), ExecutorError> {
            unreachable!()
        }

        async fn shutdown_until(&self, _: tokio::time::Instant) -> Result<(), ExecutorError> {
            self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn shutdown_session_until(
            &self,
            _: SessionId,
            _: tokio::time::Instant,
        ) -> Result<(), ExecutorError> {
            self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl OperationExecutor for Executor {
        type AuthenticatedInstance = ();

        async fn ensure_ready(
            &self,
            _: &OperationSnapshot,
        ) -> Result<Self::AuthenticatedInstance, ExecutorError> {
            Ok(())
        }
        async fn deliver(
            &self,
            _: &AdmissionPermit,
            (): &Self::AuthenticatedInstance,
            operation: &OperationSnapshot,
            input: &[u8],
        ) -> Result<DeliveryAcceptance, ExecutorError> {
            self.deliveries.fetch_add(1, Ordering::SeqCst);
            assert_eq!(operation.operation_id, identity(3, OperationId::from_uuid));
            assert_eq!(input, b"work");
            Ok(DeliveryAcceptance::Accepted)
        }
        async fn next_report(
            &self,
            (): &Self::AuthenticatedInstance,
            _: &OperationSnapshot,
        ) -> Result<ExecutorReport, ExecutorError> {
            let terminal_at = *self.terminal_at.lock().unwrap();
            if let Some(terminal_at) = terminal_at {
                tokio::time::sleep_until(terminal_at).await;
                return Ok(ExecutorReport::Terminal {
                    operation_id: identity(3, OperationId::from_uuid),
                    message_id: identity(6, MessageId::from_uuid),
                    outcome: ExecutorTerminalOutcome::Succeeded(b"late".to_vec()),
                });
            }
            if let Some(report) = self.reports.lock().unwrap().pop_front() {
                return Ok(report);
            }
            if self.repeat_disconnect {
                tokio::task::yield_now().await;
                Ok(ExecutorReport::Disconnected)
            } else {
                Ok(ExecutorReport::Idle)
            }
        }
        async fn remind(
            &self,
            (): &Self::AuthenticatedInstance,
            _: &OperationSnapshot,
        ) -> Result<(), ExecutorError> {
            *self.reminders.lock().unwrap() += 1;
            Ok(())
        }
        async fn drive_cancellation(
            &self,
            _: &AdmissionPermit,
            _: &OperationSnapshot,
            _: &MessageSnapshot,
        ) -> Result<(), ExecutorError> {
            Ok(())
        }
        async fn shutdown_until(&self, _: tokio::time::Instant) -> Result<(), ExecutorError> {
            self.shutdown_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn shutdown_session_until(
            &self,
            _: SessionId,
            _: tokio::time::Instant,
        ) -> Result<(), ExecutorError> {
            Ok(())
        }
    }

    struct Contexts;
    impl TransitionContextFactory for Contexts {
        fn context(&self, _: OperationId, action: OperationAction, ordinal: u32) -> RequestContext {
            RequestContext::new(
                identity(
                    100 + u128::from(ordinal) * 20 + action as u128,
                    RequestId::from_uuid,
                ),
                identity(2, HostId::from_uuid),
            )
        }
    }

    struct RevokingExecutor {
        gate: AdmissionGate,
        delivered: AtomicBool,
    }

    enum SessionShutdownBehavior {
        Error,
        Pending,
        DeliveryErrorThenSuccess,
    }

    struct SessionShutdownExecutor(SessionShutdownBehavior);

    impl OperationExecutor for SessionShutdownExecutor {
        type AuthenticatedInstance = ();

        async fn ensure_ready(&self, _: &OperationSnapshot) -> Result<(), ExecutorError> {
            unreachable!("terminal cancellation must not launch a Driver")
        }
        async fn deliver(
            &self,
            _: &AdmissionPermit,
            (): &(),
            _: &OperationSnapshot,
            _: &[u8],
        ) -> Result<DeliveryAcceptance, ExecutorError> {
            unreachable!("terminal cancellation must not deliver")
        }
        async fn next_report(
            &self,
            (): &(),
            _: &OperationSnapshot,
        ) -> Result<ExecutorReport, ExecutorError> {
            unreachable!("terminal cancellation must not observe")
        }
        async fn remind(&self, (): &(), _: &OperationSnapshot) -> Result<(), ExecutorError> {
            unreachable!("terminal cancellation must not remind")
        }
        async fn drive_cancellation(
            &self,
            _: &AdmissionPermit,
            _: &OperationSnapshot,
            _: &MessageSnapshot,
        ) -> Result<(), ExecutorError> {
            if matches!(self.0, SessionShutdownBehavior::DeliveryErrorThenSuccess) {
                Err(ExecutorError {
                    message: "injected cancellation delivery failure".into(),
                })
            } else {
                Ok(())
            }
        }
        async fn shutdown_until(&self, _: tokio::time::Instant) -> Result<(), ExecutorError> {
            Ok(())
        }
        async fn shutdown_session_until(
            &self,
            _: SessionId,
            _: tokio::time::Instant,
        ) -> Result<(), ExecutorError> {
            match self.0 {
                SessionShutdownBehavior::Error => Err(ExecutorError {
                    message: "injected session cleanup failure".into(),
                }),
                SessionShutdownBehavior::Pending => std::future::pending().await,
                SessionShutdownBehavior::DeliveryErrorThenSuccess => Ok(()),
            }
        }
    }

    impl OperationExecutor for RevokingExecutor {
        type AuthenticatedInstance = ();
        async fn ensure_ready(&self, _: &OperationSnapshot) -> Result<(), ExecutorError> {
            self.gate.close();
            Ok(())
        }
        async fn deliver(
            &self,
            _: &AdmissionPermit,
            (): &(),
            _: &OperationSnapshot,
            _: &[u8],
        ) -> Result<DeliveryAcceptance, ExecutorError> {
            self.delivered.store(true, Ordering::SeqCst);
            Ok(DeliveryAcceptance::Accepted)
        }
        async fn next_report(
            &self,
            (): &(),
            _: &OperationSnapshot,
        ) -> Result<ExecutorReport, ExecutorError> {
            unreachable!("revoked ownership must prevent observation")
        }
        async fn remind(&self, (): &(), _: &OperationSnapshot) -> Result<(), ExecutorError> {
            unreachable!("revoked ownership must prevent reminders")
        }
        async fn drive_cancellation(
            &self,
            _: &AdmissionPermit,
            _: &OperationSnapshot,
            _: &MessageSnapshot,
        ) -> Result<(), ExecutorError> {
            Ok(())
        }
        async fn shutdown_until(&self, _: tokio::time::Instant) -> Result<(), ExecutorError> {
            Ok(())
        }
        async fn shutdown_session_until(
            &self,
            _: SessionId,
            _: tokio::time::Instant,
        ) -> Result<(), ExecutorError> {
            Ok(())
        }
    }

    fn snapshot() -> OperationSnapshot {
        OperationSnapshot {
            session_id: identity(1, SessionId::from_uuid),
            operation_id: identity(3, OperationId::from_uuid),
            participant_id: identity(4, ParticipantId::from_uuid),
            start_request_id: identity(5, RequestId::from_uuid),
            input_message_id: identity(6, MessageId::from_uuid),
            waiting_on_message_id: None,
            input_digest: [9; 32],
            state: OperationState::Queued,
            revision: Revision::initial(),
            terminal_outcome: None,
            created_at: navigator_domain::Timestamp::new(1, 0).unwrap(),
            updated_at: navigator_domain::Timestamp::new(1, 0).unwrap(),
        }
    }

    fn cancellation_message() -> MessageSnapshot {
        let operation_id = identity(3, OperationId::from_uuid);
        MessageSnapshot {
            session_id: identity(1, SessionId::from_uuid),
            message_id: identity(7, MessageId::from_uuid),
            source: identity(4, ParticipantId::from_uuid),
            destination: identity(4, ParticipantId::from_uuid),
            mailbox_sequence: 1,
            priority: MessagePriority::Control,
            correlation: MessageCorrelation {
                operation_id: Some(operation_id),
                in_reply_to: None,
            },
            envelope: ValidatedMessageEnvelope::control(operation_id, ControlMessageKind::Cancel),
            attempt_count: 0,
            state: MessageDeliveryState::Queued,
            revision: Revision::initial(),
            created_at: Timestamp::new(1, 0).unwrap(),
            updated_at: Timestamp::new(1, 0).unwrap(),
        }
    }

    fn command() -> StartOperation {
        StartOperation {
            context: RequestContext::new(
                identity(5, RequestId::from_uuid),
                identity(2, HostId::from_uuid),
            ),
            session_id: identity(1, SessionId::from_uuid),
            epoch: FencingEpoch::new(7).unwrap(),
            operation_id: identity(3, OperationId::from_uuid),
            participant_id: identity(4, ParticipantId::from_uuid),
            input_message_id: identity(6, MessageId::from_uuid),
            input: InputSchema::new(vec![]).unwrap().validate(b"{}").unwrap(),
        }
    }

    fn cancel_command() -> CancelSubtree {
        CancelSubtree {
            context: RequestContext::new(
                identity(700, RequestId::from_uuid),
                identity(2, HostId::from_uuid),
            ),
            session_id: identity(1, SessionId::from_uuid),
            epoch: FencingEpoch::new(7).unwrap(),
            root_participant_id: identity(4, ParticipantId::from_uuid),
        }
    }

    fn service(
        reports: Vec<ExecutorReport>,
    ) -> (
        Arc<Store>,
        Arc<Executor>,
        FirstOperationService<Store, Executor, Contexts>,
    ) {
        let store = Arc::new(Store {
            snapshot: Mutex::new(snapshot()),
            input: BoundedBytes::new(b"work".to_vec()).unwrap(),
            revoke_on_load: Mutex::new(None),
            cancellation_notification: None,
        });
        let executor = Arc::new(Executor {
            reports: Mutex::new(reports.into()),
            reminders: Mutex::new(0),
            terminal_at: Mutex::new(None),
            repeat_disconnect: false,
            deliveries: AtomicU32::new(0),
            shutdown_calls: AtomicU32::new(0),
        });
        let service = FirstOperationService::new(
            store.clone(),
            executor.clone(),
            Arc::new(Contexts),
            1,
            FirstOperationConfig {
                capacity_wait: Duration::from_secs(1),
                report_deadline: Duration::from_secs(1),
            },
        );
        (store, executor, service)
    }

    #[tokio::test]
    async fn idle_never_becomes_success_and_only_one_reminder_is_sent() {
        let (store, executor, service) = service(vec![ExecutorReport::Idle, ExecutorReport::Idle]);
        let handle = service
            .start(AdmissionGate::open().admit().unwrap(), command())
            .await
            .unwrap();
        let terminal = handle.completion().await.unwrap();
        assert_eq!(terminal.state, OperationState::Failed);
        assert_eq!(*executor.reminders.lock().unwrap(), 1);
        assert!(matches!(
            store.snapshot.lock().unwrap().terminal_outcome,
            Some(OperationTerminalOutcome::Failed { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn reminder_never_refreshes_the_absolute_report_deadline() {
        let (store, executor, service) = service(Vec::new());
        *executor.terminal_at.lock().unwrap() =
            Some(tokio::time::Instant::now() + Duration::from_millis(1_500));
        let handle = service
            .start(AdmissionGate::open().admit().unwrap(), command())
            .await
            .unwrap();
        let terminal = handle.completion().await.unwrap();
        assert_eq!(terminal.state, OperationState::Failed);
        assert_eq!(*executor.reminders.lock().unwrap(), 1);
        assert!(matches!(
            store.snapshot.lock().unwrap().terminal_outcome,
            Some(OperationTerminalOutcome::Failed { .. })
        ));
        assert!(tokio::time::Instant::now() < terminal_at(&executor));
    }

    fn terminal_at(executor: &Executor) -> tokio::time::Instant {
        executor.terminal_at.lock().unwrap().unwrap()
    }

    #[tokio::test]
    async fn wrong_terminal_correlation_is_committed_as_failure() {
        let (_, _, service) = service(vec![ExecutorReport::Terminal {
            operation_id: identity(99, OperationId::from_uuid),
            message_id: identity(6, MessageId::from_uuid),
            outcome: ExecutorTerminalOutcome::Succeeded(b"forged".to_vec()),
        }]);
        let terminal = service
            .start(AdmissionGate::open().admit().unwrap(), command())
            .await
            .unwrap()
            .completion()
            .await
            .unwrap();
        assert_eq!(terminal.state, OperationState::Failed);
    }

    #[tokio::test]
    async fn dropping_consumer_handle_does_not_cancel_durable_background_work() {
        let (store, _, service) = service(vec![ExecutorReport::Terminal {
            operation_id: identity(3, OperationId::from_uuid),
            message_id: identity(6, MessageId::from_uuid),
            outcome: ExecutorTerminalOutcome::Succeeded(b"done".to_vec()),
        }]);
        let handle = service
            .start(AdmissionGate::open().admit().unwrap(), command())
            .await
            .unwrap();
        drop(handle);
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert_eq!(
            store.snapshot.lock().unwrap().state,
            OperationState::Succeeded
        );
    }

    #[tokio::test]
    async fn oversized_untrusted_terminal_is_a_bounded_typed_failure() {
        let (_, _, service) = service(vec![ExecutorReport::Terminal {
            operation_id: identity(3, OperationId::from_uuid),
            message_id: identity(6, MessageId::from_uuid),
            outcome: ExecutorTerminalOutcome::Succeeded(vec![0; 65_537]),
        }]);
        let terminal = service
            .start(AdmissionGate::open().admit().unwrap(), command())
            .await
            .unwrap()
            .completion()
            .await
            .unwrap();
        assert_eq!(terminal.state, OperationState::Failed);
        let Some(OperationTerminalOutcome::Failed { code, detail }) = terminal.terminal_outcome
        else {
            panic!("invalid report did not become a typed failure")
        };
        assert_eq!(code.as_str(), "invalid_report");
        assert!(!detail.as_str().contains('\0'));
    }

    #[tokio::test]
    async fn oversized_progress_is_a_bounded_typed_failure() {
        let (_, _, service) = service(vec![ExecutorReport::Progress {
            operation_id: identity(3, OperationId::from_uuid),
            message_id: identity(6, MessageId::from_uuid),
            payload: vec![0; MAX_PROGRESS_BYTES + 1],
        }]);
        let terminal = service
            .start(AdmissionGate::open().admit().unwrap(), command())
            .await
            .unwrap()
            .completion()
            .await
            .unwrap();
        assert_eq!(terminal.state, OperationState::Failed);
        let Some(OperationTerminalOutcome::Failed { code, .. }) = terminal.terminal_outcome else {
            panic!("oversized progress did not become a typed failure")
        };
        assert_eq!(code.as_str(), "invalid_report");
    }

    #[tokio::test]
    async fn ownership_loss_before_delivery_prevents_the_external_effect() {
        let gate = AdmissionGate::open();
        let executor = Arc::new(RevokingExecutor {
            gate: gate.clone(),
            delivered: AtomicBool::new(false),
        });
        let store = Arc::new(Store {
            snapshot: Mutex::new(snapshot()),
            input: BoundedBytes::new(b"work".to_vec()).unwrap(),
            revoke_on_load: Mutex::new(None),
            cancellation_notification: None,
        });
        let service = FirstOperationService::new(
            store,
            executor.clone(),
            Arc::new(Contexts),
            1,
            FirstOperationConfig {
                capacity_wait: Duration::from_secs(1),
                report_deadline: Duration::from_secs(1),
            },
        );
        let result = service
            .start(gate.admit().unwrap(), command())
            .await
            .unwrap()
            .completion()
            .await;
        assert!(result.is_err());
        assert!(!executor.delivered.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn repeated_disconnects_cannot_reset_the_absolute_report_budget() {
        let store = Arc::new(Store {
            snapshot: Mutex::new(snapshot()),
            input: BoundedBytes::new(b"work".to_vec()).unwrap(),
            revoke_on_load: Mutex::new(None),
            cancellation_notification: None,
        });
        let executor = Arc::new(Executor {
            reports: Mutex::new(VecDeque::new()),
            reminders: Mutex::new(0),
            terminal_at: Mutex::new(None),
            repeat_disconnect: true,
            deliveries: AtomicU32::new(0),
            shutdown_calls: AtomicU32::new(0),
        });
        let service = FirstOperationService::new(
            store,
            executor.clone(),
            Arc::new(Contexts),
            1,
            FirstOperationConfig {
                capacity_wait: Duration::from_secs(1),
                report_deadline: Duration::from_secs(1),
            },
        );
        let handle = service
            .start(AdmissionGate::open().admit().unwrap(), command())
            .await
            .unwrap();
        let terminal = handle.completion().await.unwrap();
        assert_eq!(terminal.state, OperationState::Failed);
        assert!(*executor.reminders.lock().unwrap() <= 1);
    }

    async fn terminal_session_with_shutdown_behavior(
        behavior: SessionShutdownBehavior,
        cancellation_notification: Option<MessageSnapshot>,
    ) -> Result<CancelSubtreeOutcome, FirstOperationError> {
        let mut terminal = snapshot();
        terminal.state = OperationState::Succeeded;
        terminal.terminal_outcome = Some(OperationTerminalOutcome::Succeeded {
            result: BoundedBytes::new(b"done".to_vec()).unwrap(),
        });
        let store = Arc::new(Store {
            snapshot: Mutex::new(terminal),
            input: BoundedBytes::new(b"work".to_vec()).unwrap(),
            revoke_on_load: Mutex::new(None),
            cancellation_notification,
        });
        let service = FirstOperationService::new(
            store,
            Arc::new(SessionShutdownExecutor(behavior)),
            Arc::new(Contexts),
            1,
            FirstOperationConfig {
                capacity_wait: Duration::from_secs(1),
                report_deadline: Duration::from_secs(1),
            },
        );
        service
            .cancel_session_until(
                AdmissionGate::open().admit().unwrap(),
                cancel_command(),
                tokio::time::Instant::now() + Duration::from_millis(10),
            )
            .await
    }

    #[tokio::test]
    async fn terminal_operations_do_not_hide_session_cleanup_failure() {
        assert!(matches!(
            terminal_session_with_shutdown_behavior(SessionShutdownBehavior::Error, None).await,
            Err(FirstOperationError::WorkerStopped)
        ));
    }

    #[tokio::test]
    async fn terminal_operations_do_not_hide_session_cleanup_timeout() {
        assert!(matches!(
            terminal_session_with_shutdown_behavior(SessionShutdownBehavior::Pending, None).await,
            Err(FirstOperationError::WorkerStopped)
        ));
    }

    #[tokio::test]
    async fn terminal_cancellation_delivery_failure_still_runs_verified_session_shutdown() {
        let outcome = terminal_session_with_shutdown_behavior(
            SessionShutdownBehavior::DeliveryErrorThenSuccess,
            Some(cancellation_message()),
        )
        .await
        .unwrap();
        assert!(
            outcome
                .records
                .iter()
                .all(|record| record.operation.state.is_terminal())
        );
    }

    #[tokio::test]
    async fn nonterminal_cancellation_delivery_failure_remains_fail_closed() {
        let mut cancelling = snapshot();
        cancelling.state = OperationState::Cancelling;
        let store = Arc::new(Store {
            snapshot: Mutex::new(cancelling),
            input: BoundedBytes::new(b"work".to_vec()).unwrap(),
            revoke_on_load: Mutex::new(None),
            cancellation_notification: Some(cancellation_message()),
        });
        let service = FirstOperationService::new(
            store,
            Arc::new(SessionShutdownExecutor(
                SessionShutdownBehavior::DeliveryErrorThenSuccess,
            )),
            Arc::new(Contexts),
            1,
            FirstOperationConfig {
                capacity_wait: Duration::from_secs(1),
                report_deadline: Duration::from_secs(1),
            },
        );
        assert!(matches!(
            service
                .cancel_session_until(
                    AdmissionGate::open().admit().unwrap(),
                    cancel_command(),
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await,
            Err(FirstOperationError::WorkerStopped)
        ));
    }

    #[tokio::test]
    async fn ownership_loss_during_terminal_wait_fails_closed_before_cleanup() {
        let gate = AdmissionGate::open();
        let mut running = snapshot();
        running.state = OperationState::Running;
        let store = Arc::new(Store {
            snapshot: Mutex::new(running),
            input: BoundedBytes::new(b"work".to_vec()).unwrap(),
            revoke_on_load: Mutex::new(Some(gate.clone())),
            cancellation_notification: None,
        });
        let service = FirstOperationService::new(
            store,
            Arc::new(SessionShutdownExecutor(SessionShutdownBehavior::Error)),
            Arc::new(Contexts),
            1,
            FirstOperationConfig {
                capacity_wait: Duration::from_secs(1),
                report_deadline: Duration::from_secs(1),
            },
        );
        let result = service
            .cancel_session_until(
                gate.admit().unwrap(),
                cancel_command(),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert!(matches!(result, Err(FirstOperationError::Service(_))));
    }

    #[tokio::test]
    async fn replayed_terminal_start_returns_without_reexecuting_the_effect() {
        let (store, _, service) = service(Vec::new());
        {
            let mut value = store.snapshot.lock().unwrap();
            value.state = OperationState::Succeeded;
            value.terminal_outcome = Some(OperationTerminalOutcome::Succeeded {
                result: BoundedBytes::new(b"already committed".to_vec()).unwrap(),
            });
        }
        let terminal = service
            .start(AdmissionGate::open().admit().unwrap(), command())
            .await
            .unwrap()
            .completion()
            .await
            .unwrap();
        assert_eq!(terminal.state, OperationState::Succeeded);
        assert_eq!(terminal.revision, Revision::initial());
        let operation_id = identity(3, OperationId::from_uuid);
        service
            .registry
            .lock()
            .await
            .failures
            .insert(operation_id, "stale".into());
        assert!(
            !service
                .resume_existing(
                    AdmissionGate::open().admit().unwrap(),
                    operation_id,
                    FencingEpoch::new(7).unwrap(),
                )
                .await
                .unwrap()
        );
        assert!(service.registry.lock().await.failures.is_empty());
    }

    fn flaky_resume_service(
        failures: u32,
    ) -> (
        Arc<FlakyBeginStartStore>,
        FirstOperationService<FlakyBeginStartStore, Executor, Contexts>,
    ) {
        let store = Arc::new(FlakyBeginStartStore {
            inner: Store {
                snapshot: Mutex::new(snapshot()),
                input: BoundedBytes::new(b"work".to_vec()).unwrap(),
                revoke_on_load: Mutex::new(None),
                cancellation_notification: None,
            },
            failures_remaining: AtomicU32::new(failures),
            attempts: AtomicU32::new(0),
        });
        let executor = Arc::new(Executor {
            reports: Mutex::new(VecDeque::from([ExecutorReport::Terminal {
                operation_id: identity(3, OperationId::from_uuid),
                message_id: identity(6, MessageId::from_uuid),
                outcome: ExecutorTerminalOutcome::Succeeded(b"done".to_vec()),
            }])),
            reminders: Mutex::new(0),
            terminal_at: Mutex::new(None),
            repeat_disconnect: false,
            deliveries: AtomicU32::new(0),
            shutdown_calls: AtomicU32::new(0),
        });
        let service = FirstOperationService::new(
            store.clone(),
            executor,
            Arc::new(Contexts),
            1,
            FirstOperationConfig {
                capacity_wait: Duration::from_secs(1),
                report_deadline: Duration::from_secs(1),
            },
        );
        (store, service)
    }

    #[tokio::test]
    async fn resumed_worker_retries_a_transient_pre_start_store_failure() {
        let (store, service) = flaky_resume_service(1);
        assert!(
            service
                .resume_existing(
                    AdmissionGate::open().admit().unwrap(),
                    identity(3, OperationId::from_uuid),
                    FencingEpoch::new(7).unwrap(),
                )
                .await
                .unwrap()
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if store.inner.snapshot.lock().unwrap().state == OperationState::Succeeded {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(store.attempts.load(Ordering::SeqCst), 2);
        let registry = service.registry.lock().await;
        assert!(registry.active.is_empty());
        assert!(registry.handles.is_empty());
        assert!(registry.failures.is_empty());
    }

    #[tokio::test]
    async fn persistent_pre_start_failure_is_bounded_and_observable() {
        let (store, service) = flaky_resume_service(u32::MAX);
        let operation_id = identity(3, OperationId::from_uuid);
        assert!(
            service
                .resume_existing(
                    AdmissionGate::open().admit().unwrap(),
                    operation_id,
                    FencingEpoch::new(7).unwrap(),
                )
                .await
                .unwrap()
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let registry = service.registry.lock().await;
                if !registry.active.contains(&operation_id) {
                    break;
                }
                drop(registry);
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(store.attempts.load(Ordering::SeqCst), 3);
        assert_eq!(
            store.inner.snapshot.lock().unwrap().state,
            OperationState::Queued
        );
        let registry = service.registry.lock().await;
        assert!(registry.handles.is_empty());
        assert!(registry.failures.contains_key(&operation_id));
        drop(registry);

        store.failures_remaining.store(0, Ordering::SeqCst);
        assert!(
            service
                .resume_existing(
                    AdmissionGate::open().admit().unwrap(),
                    operation_id,
                    FencingEpoch::new(7).unwrap(),
                )
                .await
                .unwrap(),
            "an exact durable replay must schedule the stranded operation again"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if store.inner.snapshot.lock().unwrap().state == OperationState::Succeeded {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn replayed_wake_for_an_active_operation_is_an_idempotent_noop() {
        let (_, _, service) = service(Vec::new());
        let operation_id = identity(3, OperationId::from_uuid);
        service.registry.lock().await.active.insert(operation_id);

        let scheduled = service
            .resume_existing(
                AdmissionGate::open().admit().unwrap(),
                operation_id,
                FencingEpoch::new(1).unwrap(),
            )
            .await
            .unwrap();

        assert!(!scheduled);
        let registry = service.registry.lock().await;
        assert_eq!(registry.active, HashSet::from([operation_id]));
        assert_eq!(registry.wake_requested, HashSet::from([operation_id]));
        assert!(registry.handles.is_empty());
    }

    #[tokio::test]
    async fn shutdown_aborts_every_worker_before_executor_cleanup() {
        let (_, executor, service) = service(Vec::new());
        {
            let mut registry = service.registry.lock().await;
            registry
                .failures
                .insert(identity(19, OperationId::from_uuid), "old".into());
            for ordinal in 20..22 {
                let operation_id = identity(ordinal, OperationId::from_uuid);
                registry.active.insert(operation_id);
                registry
                    .handles
                    .insert(operation_id, tokio::spawn(std::future::pending::<()>()));
            }
        }

        let result = service.shutdown_until(tokio::time::Instant::now()).await;

        assert!(result.is_ok());
        let registry = service.registry.lock().await;
        assert!(!registry.accepting);
        assert!(registry.active.is_empty());
        assert!(registry.handles.is_empty());
        assert!(registry.failures.is_empty());
        assert_eq!(executor.shutdown_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shutdown_during_observe_does_not_commit_a_spurious_terminal_state() {
        let (store, executor, service) = service(Vec::new());
        *executor.terminal_at.lock().unwrap() =
            Some(tokio::time::Instant::now() + Duration::from_secs(60));
        let handle = service
            .start(AdmissionGate::open().admit().unwrap(), command())
            .await
            .unwrap();
        assert_eq!(handle.admitted().value().state, OperationState::Queued);
        while store.snapshot.lock().unwrap().state != OperationState::Running {
            tokio::task::yield_now().await;
        }

        service
            .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();

        let snapshot = store.snapshot.lock().unwrap().clone();
        assert_eq!(snapshot.state, OperationState::Running);
        assert_eq!(snapshot.terminal_outcome, None);
        assert_eq!(executor.shutdown_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shutdown_during_deliver_does_not_commit_a_spurious_terminal_state() {
        let store = Arc::new(Store {
            snapshot: Mutex::new(snapshot()),
            input: BoundedBytes::new(b"work".to_vec()).unwrap(),
            revoke_on_load: Mutex::new(None),
            cancellation_notification: None,
        });
        let executor = Arc::new(BlockingDeliverExecutor {
            entered: tokio::sync::Notify::new(),
            shutdown_calls: AtomicU32::new(0),
        });
        let service = FirstOperationService::new(
            store.clone(),
            executor.clone(),
            Arc::new(Contexts),
            1,
            FirstOperationConfig {
                capacity_wait: Duration::from_secs(1),
                report_deadline: Duration::from_secs(1),
            },
        );
        let _handle = service
            .start(AdmissionGate::open().admit().unwrap(), command())
            .await
            .unwrap();
        executor.entered.notified().await;

        service
            .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();

        let snapshot = store.snapshot.lock().unwrap().clone();
        assert_eq!(snapshot.state, OperationState::Starting);
        assert_eq!(snapshot.terminal_outcome, None);
        assert_eq!(executor.shutdown_calls.load(Ordering::SeqCst), 1);
    }
}
