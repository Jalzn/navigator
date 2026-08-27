use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc};

use navigator_core::{
    AdmissionPermit, ClassifiedRecovery, RecoveryBackend, RecoveryCandidate, RecoveryEntity,
};
use navigator_domain::{
    EffectClass, FencingEpoch, LaunchAttemptId, LiveObservation, MessageId, OperationState,
    RecoveryState, RequestId, SessionId,
};
use navigator_store_api::{
    EffectJournalPhase, LaunchState, MailboxStore, MessageDeliveryState,
    RecordRecoveryClassifications, RecoveryEventClassification, RecoveryEventEntity, RecoveryStore,
    RequestContext, StoreError,
};
use navigator_supervisor::{CredentialSource, FaultInjector, InstanceSupervisor, ProcessBackend};
use tokio::sync::Mutex;

use crate::ExistingOperationScheduler;

pub type InstalledOwnershipFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(FencingEpoch, AdmissionPermit), StoreError>> + Send + 'a>>;

pub trait RecoveryOwnershipInstaller: Send + Sync {
    fn acquire_and_install(
        &self,
        session_id: SessionId,
        recovery_request_id: RequestId,
    ) -> InstalledOwnershipFuture<'_>;
}

pub trait RecoveryInstanceInspector: Send + Sync {
    fn inspect(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: navigator_domain::HostId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<LiveObservation, StoreError>> + Send + '_>>;
}

impl<S, B, C, F> RecoveryInstanceInspector for InstanceSupervisor<S, B, C, F>
where
    S: navigator_store_api::InstanceStore + 'static,
    B: ProcessBackend,
    C: CredentialSource,
    F: FaultInjector,
{
    fn inspect(
        &self,
        attempt_id: LaunchAttemptId,
        host_id: navigator_domain::HostId,
        epoch: FencingEpoch,
    ) -> Pin<Box<dyn Future<Output = Result<LiveObservation, StoreError>> + Send + '_>> {
        Box::pin(async move {
            self.inspect_for_recovery(attempt_id, host_id, epoch)
                .await
                .map_err(|_| StoreError::Unavailable)
        })
    }
}

pub struct StoreRecoveryBackend<S> {
    store: Arc<S>,
    host_id: navigator_domain::HostId,
    ownership: Arc<dyn RecoveryOwnershipInstaller>,
    inspector: Arc<dyn RecoveryInstanceInspector>,
    scheduler: Arc<dyn ExistingOperationScheduler>,
    installed: Mutex<HashMap<SessionId, InstalledRecovery>>,
    attempts: Mutex<HashMap<LaunchAttemptId, SessionId>>,
}

#[derive(Clone)]
struct InstalledRecovery {
    epoch: FencingEpoch,
    permit: AdmissionPermit,
}

impl<S> StoreRecoveryBackend<S> {
    #[must_use]
    pub fn new(
        store: Arc<S>,
        host_id: navigator_domain::HostId,
        ownership: Arc<dyn RecoveryOwnershipInstaller>,
        inspector: Arc<dyn RecoveryInstanceInspector>,
        scheduler: Arc<dyn ExistingOperationScheduler>,
    ) -> Self {
        Self {
            store,
            host_id,
            ownership,
            inspector,
            scheduler,
            installed: Mutex::new(HashMap::new()),
            attempts: Mutex::new(HashMap::new()),
        }
    }
}

impl<S> RecoveryBackend for StoreRecoveryBackend<S>
where
    S: RecoveryStore + navigator_store_api::OperationStore + MailboxStore + 'static,
{
    type Error = StoreError;

    async fn acquire_epoch(
        &self,
        session_id: SessionId,
        recovery_request_id: RequestId,
    ) -> Result<FencingEpoch, StoreError> {
        if let Some(installed) = self.installed.lock().await.get(&session_id).cloned() {
            if installed.permit.check().is_ok() {
                return Ok(installed.epoch);
            }
        }
        let (epoch, permit) = self
            .ownership
            .acquire_and_install(session_id, recovery_request_id)
            .await?;
        let mut recoveries = self.installed.lock().await;
        if !recoveries.contains_key(&session_id) && recoveries.len() >= 1_024 {
            return Err(StoreError::Invalid);
        }
        recoveries.insert(session_id, InstalledRecovery { epoch, permit });
        drop(recoveries);
        Ok(epoch)
    }

    async fn unfinished(
        &self,
        session_id: SessionId,
        epoch: FencingEpoch,
    ) -> Result<Vec<RecoveryCandidate>, StoreError> {
        let inventory = self
            .store
            .load_recovery_inventory(session_id, self.host_id, epoch)
            .await?;
        self.attempts
            .lock()
            .await
            .retain(|_, owner_session| *owner_session != session_id);
        let mut result = Vec::new();
        result.push(candidate(
            session_id,
            RecoveryEntity::Session(session_id),
            RecoveryState::SessionOpen,
        ));
        for participant in inventory.participants {
            result.push(candidate(
                session_id,
                RecoveryEntity::Participant(participant.participant_id),
                RecoveryState::ParticipantRegistered,
            ));
        }
        for launch in inventory.launches {
            self.attempts
                .lock()
                .await
                .insert(launch.attempt_id, session_id);
            result.push(candidate(
                session_id,
                RecoveryEntity::Instance(launch.attempt_id),
                launch_state(launch.state),
            ));
        }
        for operation in inventory.operations {
            result.push(candidate(
                session_id,
                RecoveryEntity::Operation {
                    operation_id: operation.operation_id,
                    input_message_id: operation.input_message_id,
                },
                operation_state(operation.state),
            ));
        }
        for message in inventory.messages {
            let state = message_state(&message.state, inventory.snapshot_at);
            if matches!(
                state,
                RecoveryState::MessageQueued
                    | RecoveryState::MessageRetryScheduled
                    | RecoveryState::MessageLeased
            ) && message.correlation.operation_id.is_none()
            {
                return Err(StoreError::Corrupt);
            }
            result.push(candidate(
                session_id,
                RecoveryEntity::Message(message.message_id),
                state,
            ));
        }
        for effect in inventory.effects {
            result.push(candidate(
                session_id,
                RecoveryEntity::Effect(effect.request_id),
                effect_state(effect.phase, effect.effect_class),
            ));
        }
        for (index, item) in result.iter_mut().enumerate() {
            item.ordinal = u64::try_from(index + 1).map_err(|_| StoreError::Corrupt)?;
        }
        Ok(result)
    }

    async fn inspect_instance(
        &self,
        attempt_id: LaunchAttemptId,
        epoch: FencingEpoch,
    ) -> Result<LiveObservation, StoreError> {
        let session_id = self
            .attempts
            .lock()
            .await
            .get(&attempt_id)
            .copied()
            .ok_or(StoreError::Invalid)?;
        let installed = self
            .installed
            .lock()
            .await
            .get(&session_id)
            .cloned()
            .ok_or(StoreError::Invalid)?;
        if installed.epoch != epoch {
            return Err(StoreError::Invalid);
        }
        self.inspector
            .inspect(attempt_id, self.host_id, epoch)
            .await
    }

    async fn record_classifications(
        &self,
        epoch: FencingEpoch,
        recovery_request_id: RequestId,
        classifications: &[ClassifiedRecovery],
    ) -> Result<(), StoreError> {
        let session_id = self
            .installed
            .lock()
            .await
            .iter()
            .find_map(|(session_id, value)| (value.epoch == epoch).then_some(*session_id))
            .ok_or(StoreError::Invalid)?;
        let rows = classifications
            .iter()
            .map(|item| RecoveryEventClassification {
                entity: event_entity(item.entity),
                state: item.state,
                observation: item.observation,
                decision: item.decision,
            })
            .collect();
        self.store
            .record_recovery_classifications(RecordRecoveryClassifications {
                context: RequestContext::new(recovery_request_id, self.host_id),
                session_id,
                epoch,
                classifications: rows,
            })
            .await
    }

    async fn schedule_existing_operation(
        &self,
        epoch: FencingEpoch,
        operation_id: navigator_domain::OperationId,
        input_message_id: navigator_domain::MessageId,
    ) -> Result<(), StoreError> {
        let operation = self.store.load_operation(operation_id).await?;
        if operation.input_message_id != input_message_id
            || operation.state != OperationState::Queued
        {
            return Err(StoreError::Corrupt);
        }
        let installed = self
            .installed
            .lock()
            .await
            .get(&operation.session_id)
            .cloned()
            .ok_or(StoreError::Invalid)?;
        if installed.epoch != epoch {
            return Err(StoreError::Invalid);
        }
        self.scheduler
            .schedule_recovery_with_permit(installed.permit, operation_id, input_message_id, epoch)
            .await
            .map_err(|_| StoreError::Unavailable)
    }

    async fn redeliver_exact_message(
        &self,
        epoch: FencingEpoch,
        message_id: MessageId,
    ) -> Result<bool, StoreError> {
        let message = self.store.load_message(message_id).await?;
        let operation_id = message
            .correlation
            .operation_id
            .ok_or(StoreError::Corrupt)?;
        let installed = self
            .installed
            .lock()
            .await
            .get(&message.session_id)
            .cloned()
            .ok_or(StoreError::Invalid)?;
        if installed.epoch != epoch {
            return Err(StoreError::Invalid);
        }
        self.scheduler
            .redeliver_recovery_with_permit(installed.permit, operation_id, message_id, epoch)
            .await
            .map_err(|_| StoreError::Unavailable)
    }
}

fn candidate(
    session_id: SessionId,
    entity: RecoveryEntity,
    state: RecoveryState,
) -> RecoveryCandidate {
    RecoveryCandidate {
        ordinal: 1,
        session_id,
        entity,
        state,
    }
}

fn event_entity(entity: RecoveryEntity) -> RecoveryEventEntity {
    match entity {
        RecoveryEntity::Session(id) => RecoveryEventEntity::Session(id),
        RecoveryEntity::Participant(id) => RecoveryEventEntity::Participant(id),
        RecoveryEntity::Instance(id) => RecoveryEventEntity::Instance(id),
        RecoveryEntity::Operation { operation_id, .. } => {
            RecoveryEventEntity::Operation(operation_id)
        }
        RecoveryEntity::Message(id) => RecoveryEventEntity::Message(id),
        RecoveryEntity::Effect(id) => RecoveryEventEntity::Effect(id),
    }
}

fn launch_state(value: LaunchState) -> RecoveryState {
    match value {
        LaunchState::Prepared => RecoveryState::InstancePrepared,
        LaunchState::Attached => RecoveryState::InstanceAttached,
        LaunchState::Ready => RecoveryState::InstanceReady,
        LaunchState::Stopping => RecoveryState::InstanceStopping,
        LaunchState::CleanupRequired => RecoveryState::InstanceCleanupRequired,
        LaunchState::Stopped => RecoveryState::InstanceStopped,
    }
}
fn operation_state(value: OperationState) -> RecoveryState {
    match value {
        OperationState::Queued => RecoveryState::OperationQueued,
        OperationState::Starting => RecoveryState::OperationStarting,
        OperationState::Running => RecoveryState::OperationRunning,
        OperationState::Waiting => RecoveryState::OperationWaiting,
        OperationState::Cancelling => RecoveryState::OperationCancelling,
        _ => RecoveryState::OperationTerminal,
    }
}
fn message_state(value: &MessageDeliveryState, now: navigator_domain::Timestamp) -> RecoveryState {
    match value {
        MessageDeliveryState::Queued => RecoveryState::MessageQueued,
        MessageDeliveryState::RetryScheduled { not_before } if *not_before <= now => {
            RecoveryState::MessageRetryScheduled
        }
        MessageDeliveryState::RetryScheduled { .. } => RecoveryState::MessageRetryDeferred,
        MessageDeliveryState::Leased { lease } if lease.expires_at <= now => {
            RecoveryState::MessageLeased
        }
        MessageDeliveryState::Leased { .. } => RecoveryState::MessageLeaseActive,
        MessageDeliveryState::AcceptancePending { .. } => RecoveryState::MessageAcceptancePending,
        MessageDeliveryState::AcceptanceUnknown { .. } => RecoveryState::MessageAcceptanceUnknown,
        MessageDeliveryState::Accepted { .. } => RecoveryState::MessageAccepted,
        MessageDeliveryState::Uncertain { .. } => RecoveryState::MessageUncertain,
        MessageDeliveryState::DeadLetter { .. } => RecoveryState::MessageDeadLetter,
    }
}
fn effect_state(phase: EffectJournalPhase, class: EffectClass) -> RecoveryState {
    match phase {
        EffectJournalPhase::Reserved => RecoveryState::EffectReserved,
        EffectJournalPhase::RetryAuthorized => RecoveryState::EffectStartedRetryable,
        EffectJournalPhase::Started
            if matches!(class, EffectClass::ReadOnly | EffectClass::Idempotent) =>
        {
            RecoveryState::EffectStartedRetryable
        }
        EffectJournalPhase::Started | EffectJournalPhase::Uncertain => {
            RecoveryState::EffectStartedUnsafe
        }
        EffectJournalPhase::Completed | EffectJournalPhase::Failed => {
            RecoveryState::EffectCompleted
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        sync::{
            Arc, Mutex,
            atomic::{AtomicI64, Ordering},
        },
    };

    use navigator_consumer_protocol::v1;
    use navigator_core::AdmissionPermit;
    use navigator_domain::{
        AuthorityProfile, BoundedText, Capability, Clock, ConsumerKey, DeliveryAttemptId, DriverId,
        DriverRequirement, EffectClass, EffectProofKind, Grant, GrantId, HostId, InputSchema,
        InstanceId, LaunchAttemptId, MessageId, MonotonicInstant, OperationAction, OperationId,
        ParticipantId, ResourceBounds, ResourceScope, Revision, ScopedCapability, Template,
        TemplateId, Timestamp, TrustedConfiguration,
    };
    use navigator_store_api::{
        AcquireOwnership, AttachLaunch, AuthorityPolicySnapshot, AuthorityStore,
        CreateRootParticipant, DeliveryTransition, EffectJournalStore, EffectResolutionContract,
        EffectTransition, InstanceStore, IssueGrant, LaunchState, LeaseDuration, LeaseNextMessage,
        MailboxStore, OpenSession, OperationStore, PrepareLaunch, ProcessEvidence,
        PutAuthorityPolicy, RequestContext, ReserveEffect, RevokeGrant, SessionStore,
        StartOperation, TransitionLaunch, TransitionMessageDelivery, TransitionOperation,
    };
    use navigator_store_sqlite::SqliteStore;
    use sha2::Digest;
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;
    use crate::{
        BootstrapCredential, ExistingOperationScheduler, LocalClient, LocalNavigator, ServerConfig,
        serve,
    };

    struct TestClock(AtomicI64);
    impl Clock for TestClock {
        fn wall_now(&self) -> time::OffsetDateTime {
            time::OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).unwrap()
        }
        fn monotonic_now(&self) -> MonotonicInstant {
            MonotonicInstant::from_ticks(0)
        }
    }

    struct NoInstances;
    impl RecoveryInstanceInspector for NoInstances {
        fn inspect(
            &self,
            _: LaunchAttemptId,
            _: HostId,
            _: FencingEpoch,
        ) -> Pin<Box<dyn Future<Output = Result<LiveObservation, StoreError>> + Send + '_>>
        {
            Box::pin(async { Err(StoreError::Corrupt) })
        }
    }

    #[derive(Default)]
    struct SchedulerSpy {
        attempts: Mutex<Vec<(OperationId, MessageId)>>,
        effects: Mutex<HashSet<(OperationId, MessageId)>>,
        redelivery_attempts: Mutex<Vec<(OperationId, MessageId)>>,
        redelivery_effects: Mutex<HashSet<(OperationId, MessageId)>>,
    }
    impl ExistingOperationScheduler for SchedulerSpy {
        fn redeliver_recovery_with_permit(
            &self,
            permit: AdmissionPermit,
            operation_id: OperationId,
            message_id: MessageId,
            _: FencingEpoch,
        ) -> Pin<Box<dyn Future<Output = Result<bool, navigator_core::ExecutorError>> + Send + '_>>
        {
            Box::pin(async move {
                permit
                    .check()
                    .map_err(|error| navigator_core::ExecutorError {
                        message: error.to_string(),
                    })?;
                self.redelivery_attempts
                    .lock()
                    .unwrap()
                    .push((operation_id, message_id));
                self.redelivery_effects
                    .lock()
                    .unwrap()
                    .insert((operation_id, message_id));
                Ok(true)
            })
        }

        fn schedule_recovery_with_permit(
            &self,
            permit: AdmissionPermit,
            operation_id: OperationId,
            input_message_id: MessageId,
            _: FencingEpoch,
        ) -> Pin<Box<dyn Future<Output = Result<(), navigator_core::ExecutorError>> + Send + '_>>
        {
            Box::pin(async move {
                permit
                    .check()
                    .map_err(|error| navigator_core::ExecutorError {
                        message: error.to_string(),
                    })?;
                self.attempts
                    .lock()
                    .unwrap()
                    .push((operation_id, input_message_id));
                self.effects
                    .lock()
                    .unwrap()
                    .insert((operation_id, input_message_id));
                Ok(())
            })
        }
        fn schedule_with_permit(
            &self,
            permit: AdmissionPermit,
            operation_id: OperationId,
            _: FencingEpoch,
        ) -> Pin<Box<dyn Future<Output = Result<(), navigator_core::ExecutorError>> + Send + '_>>
        {
            Box::pin(async move {
                permit
                    .check()
                    .map_err(|error| navigator_core::ExecutorError {
                        message: error.to_string(),
                    })?;
                Err(navigator_core::ExecutorError {
                    message: format!("missing recovery Message identity for {operation_id}"),
                })
            })
        }
        fn schedule(
            &self,
            operation_id: OperationId,
            epoch: FencingEpoch,
        ) -> Pin<Box<dyn Future<Output = Result<(), navigator_core::ExecutorError>> + Send + '_>>
        {
            Box::pin(async move {
                let _ = (operation_id, epoch);
                Err(navigator_core::ExecutorError {
                    message: "fresh permit required".into(),
                })
            })
        }
    }

    fn id<T>(value: u128, make: fn(Uuid) -> Result<T, navigator_domain::InvalidIdentity>) -> T {
        make(Uuid::from_u128(value)).unwrap()
    }

    #[test]
    fn retry_schedule_is_not_redeliverable_before_store_snapshot_time() {
        let now = navigator_domain::Timestamp::new(100, 0).unwrap();
        assert_eq!(
            message_state(
                &MessageDeliveryState::RetryScheduled {
                    not_before: navigator_domain::Timestamp::new(101, 0).unwrap(),
                },
                now,
            ),
            RecoveryState::MessageRetryDeferred
        );
        assert_eq!(
            message_state(
                &MessageDeliveryState::RetryScheduled {
                    not_before: navigator_domain::Timestamp::new(100, 0).unwrap(),
                },
                now,
            ),
            RecoveryState::MessageRetryScheduled
        );
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one composed restart scenario keeps every durable identity and effect boundary visible"
    )]
    async fn reopened_store_reconciles_exact_committed_pair_once_without_replacement_rows() {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("composed-recovery.db");
        let base = time::OffsetDateTime::now_utc().unix_timestamp();
        let clock = Arc::new(TestClock(AtomicI64::new(base)));
        let store = Arc::new(
            SqliteStore::open_with_clock(
                &path,
                clock.clone(),
                LeaseDuration::from_millis(60_000).unwrap(),
            )
            .await
            .unwrap(),
        );
        let host = id(1, HostId::from_uuid);
        let session = id(2, SessionId::from_uuid);
        let participant = id(3, ParticipantId::from_uuid);
        let operation = id(4, OperationId::from_uuid);
        let message = id(5, MessageId::from_uuid);
        let template = Template::register(
            id(6, TemplateId::from_uuid),
            BoundedText::new("recovery".to_owned()).unwrap(),
            DriverRequirement::new(id(7, DriverId::from_uuid), vec![]).unwrap(),
            TrustedConfiguration::new(BoundedText::new("trusted".to_owned()).unwrap(), []).unwrap(),
            ResourceBounds::new(1024, 1000, 1).unwrap(),
            InputSchema::new(vec![]).unwrap(),
        )
        .unwrap();
        let registration = template.registration_snapshot();
        store
            .open_session(OpenSession::new(
                RequestContext::new(id(10, RequestId::from_uuid), host),
                session,
                ConsumerKey::new("composed-recovery").unwrap(),
                registration.compatibility,
            ))
            .await
            .unwrap();
        let lease = store
            .acquire_ownership(AcquireOwnership::new(
                RequestContext::new(id(11, RequestId::from_uuid), host),
                session,
                LeaseDuration::from_millis(1_000).unwrap(),
            ))
            .await
            .unwrap()
            .value()
            .clone();
        store.register_template(registration.clone()).await.unwrap();
        store
            .create_root_participant(CreateRootParticipant {
                context: RequestContext::new(id(12, RequestId::from_uuid), host),
                session_id: session,
                epoch: lease.epoch(),
                participant_id: participant,
                template_id: registration.identity,
                expected_compatibility: registration.compatibility,
            })
            .await
            .unwrap();
        store
            .start_operation(StartOperation {
                context: RequestContext::new(id(13, RequestId::from_uuid), host),
                session_id: session,
                epoch: lease.epoch(),
                operation_id: operation,
                participant_id: participant,
                input_message_id: message,
                input: template.validate_input(br"{}").unwrap(),
            })
            .await
            .unwrap();
        let before_operations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operations")
            .fetch_one(store.pool())
            .await
            .unwrap();
        let before_messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
            .fetch_one(store.pool())
            .await
            .unwrap();
        store.pool().close().await;
        drop(store);
        clock.0.store(base + 2, Ordering::SeqCst);
        let reopened = Arc::new(
            SqliteStore::open_with_clock(
                &path,
                clock.clone(),
                LeaseDuration::from_millis(60_000).unwrap(),
            )
            .await
            .unwrap(),
        );
        let spy = Arc::new(SchedulerSpy::default());
        let service = LocalNavigator::new(
            reopened.clone(),
            host,
            LeaseDuration::from_millis(30_000).unwrap(),
        )
        .with_recovery_runtime(Arc::new(NoInstances), spy.clone());
        let socket = directory.path().join("recovery.sock");
        let credential = BootstrapCredential::from_bytes(b"recovery-e2e".to_vec()).unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve(
            service,
            credential.clone(),
            ServerConfig {
                socket_path: socket.clone(),
                shutdown_timeout: std::time::Duration::from_secs(1),
            },
            shutdown_rx,
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !socket.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut client = LocalClient::connect(&socket, &credential).await.unwrap();
        let response = client
            .resume_session(Uuid::from_u128(20), session.as_uuid())
            .await
            .unwrap();
        let Some(v1::resume_session_response::Outcome::Report(report)) = response.outcome else {
            panic!(
                "Resume did not return a typed recovery report: {:?}",
                response.outcome
            )
        };
        assert!(report.classifications.iter().any(|item| matches!(
            item.entity,
            Some(v1::recovery_classification::Entity::OperationId(ref value))
                if value.as_slice() == operation.as_uuid().as_bytes()
        )));
        let events_after_resume: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        let requests_after_resume: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        let scheduling_after_resume = spy.attempts.lock().unwrap().clone();
        assert_eq!(
            scheduling_after_resume.as_slice(),
            &[(operation, message)],
            "the first recovery boundary must schedule the exact committed pair"
        );
        assert_eq!(
            *spy.effects.lock().unwrap(),
            HashSet::from([(operation, message)])
        );
        assert_eq!(
            spy.redelivery_attempts.lock().unwrap().as_slice(),
            &[(operation, message)]
        );
        assert_eq!(
            *spy.redelivery_effects.lock().unwrap(),
            HashSet::from([(operation, message)])
        );
        let replay = client
            .resume_session(Uuid::from_u128(20), session.as_uuid())
            .await
            .unwrap();
        assert!(matches!(
            replay.outcome,
            Some(v1::resume_session_response::Outcome::Failure(ref failure))
                if failure.code == i32::from(v1::FailureCode::CleanupRequired)
                    && failure.retry == i32::from(v1::RetryClass::AfterReconciliation)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events")
                .fetch_one(reopened.pool())
                .await
                .unwrap(),
            events_after_resume
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM request_ledger")
                .fetch_one(reopened.pool())
                .await
                .unwrap(),
            requests_after_resume
        );
        assert_eq!(*spy.attempts.lock().unwrap(), scheduling_after_resume);
        let navigator_domain::OwnershipSnapshot::Owned { epoch, .. } =
            reopened.read_ownership(session).await.unwrap()
        else {
            panic!("Resume did not install ownership")
        };
        accept_recovered_input(RecoveredInput {
            store: &reopened,
            host,
            session,
            participant,
            driver_id: registration.driver.driver_id(),
            operation,
            message,
            epoch,
            seed: 400,
        })
        .await;
        for (request, revision, action) in [
            (30_u128, 1_u64, OperationAction::BeginStart),
            (31, 2, OperationAction::ReportRunning),
        ] {
            reopened
                .transition_operation(TransitionOperation {
                    context: RequestContext::new(id(request, RequestId::from_uuid), host),
                    session_id: session,
                    epoch,
                    operation_id: operation,
                    expected_revision: navigator_domain::Revision::new(revision).unwrap(),
                    action,
                    report_message_id: (action == OperationAction::ReportRunning)
                        .then_some(message),
                    terminal_outcome: None,
                })
                .await
                .unwrap();
        }
        let reserve = ReserveEffect::new(
            RequestContext::new(id(32, RequestId::from_uuid), host),
            session,
            participant,
            operation,
            epoch,
            Capability::new("tool.external").unwrap(),
            b"effect",
            EffectClass::NonIdempotent,
            EffectResolutionContract {
                allow_confirm_completed: true,
                allow_do_not_retry: true,
                allow_retry_with_proof: true,
                allowed_proof_kinds: vec![
                    EffectProofKind::ExternalCommit,
                    EffectProofKind::EffectAbsent,
                ],
            },
            std::time::Duration::from_secs(1),
        );
        let reserved = reopened.reserve_effect(reserve.clone()).await.unwrap();
        reopened
            .start_effect(EffectTransition::start(
                RequestContext::new(id(33, RequestId::from_uuid), host),
                reserved.request_id,
                epoch,
                reserved.revision,
            ))
            .await
            .unwrap();
        clock.0.store(base + 4, Ordering::SeqCst);
        let uncertain = reopened.reserve_effect(reserve).await.unwrap();
        reopened
            .transition_operation(TransitionOperation {
                context: RequestContext::new(id(34, RequestId::from_uuid), host),
                session_id: session,
                epoch,
                operation_id: operation,
                expected_revision: navigator_domain::Revision::new(3).unwrap(),
                action: OperationAction::ReportUncertain,
                report_message_id: Some(message),
                terminal_outcome: Some(navigator_store_api::OperationTerminalOutcome::Uncertain {
                    reason: BoundedText::new("effect uncertain").unwrap(),
                }),
            })
            .await
            .unwrap();
        drop(client);
        shutdown_tx.send(true).unwrap();
        assert!(server.await.unwrap().is_ok());
        clock.0.store(base + 40, Ordering::SeqCst);
        let service = LocalNavigator::new(
            reopened.clone(),
            host,
            LeaseDuration::from_millis(30_000).unwrap(),
        )
        .with_recovery_runtime(Arc::new(NoInstances), spy.clone());
        let socket = directory.path().join("recovery-second.sock");
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(serve(
            service,
            credential.clone(),
            ServerConfig {
                socket_path: socket.clone(),
                shutdown_timeout: std::time::Duration::from_secs(1),
            },
            shutdown_rx,
        ));
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !socket.exists() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut client = LocalClient::connect(&socket, &credential).await.unwrap();
        let contract_report = client
            .resume_session(Uuid::from_u128(45), session.as_uuid())
            .await
            .unwrap();
        let Some(v1::resume_session_response::Outcome::Report(contract_report)) =
            contract_report.outcome
        else {
            panic!(
                "contract recovery did not return a report: {:?}",
                contract_report.outcome
            )
        };
        let effect_classification = contract_report
            .classifications
            .iter()
            .find(|item| {
                matches!(
                    item.entity,
                    Some(v1::recovery_classification::Entity::EffectId(ref value))
                        if value.as_slice() == uncertain.request_id.as_uuid().as_bytes()
                )
            })
            .unwrap();
        assert_eq!(
            effect_classification.allowed_actions,
            vec![
                i32::from(v1::ResolutionAction::ConfirmCompleted),
                i32::from(v1::ResolutionAction::DoNotRetry),
                i32::from(v1::ResolutionAction::RetryWithEffectProof),
            ]
        );
        assert!(contract_report.classifications.iter().all(|item| {
            matches!(
                item.entity,
                Some(v1::recovery_classification::Entity::EffectId(_))
            ) || item.allowed_actions.is_empty()
        }));
        let navigator_domain::OwnershipSnapshot::Owned { epoch, .. } =
            reopened.read_ownership(session).await.unwrap()
        else {
            panic!("contract Resume did not install ownership")
        };
        let resolution_scope = ScopedCapability::new(
            Capability::new("effect.resolve_uncertainty").unwrap(),
            ResourceScope::Operation(operation),
        );
        let policy_scopes = [
            operation,
            id(50, OperationId::from_uuid),
            id(60, OperationId::from_uuid),
        ]
        .map(|operation_id| {
            ScopedCapability::new(
                Capability::new("effect.resolve_uncertainty").unwrap(),
                ResourceScope::Operation(operation_id),
            )
        });
        let full = AuthorityProfile::new(policy_scopes.clone(), policy_scopes).unwrap();
        reopened
            .put_authority_policy(PutAuthorityPolicy {
                context: RequestContext::new(id(35, RequestId::from_uuid), host),
                session_id: session,
                epoch,
                policy: AuthorityPolicySnapshot {
                    session_id: session,
                    participant_id: participant,
                    session: full.clone(),
                    parent: full.clone(),
                    template: full.clone(),
                    relationship: full.clone(),
                    subject: full,
                },
            })
            .await
            .unwrap();
        let expired_grant_id = id(40, GrantId::from_uuid);
        reopened
            .issue_grant(IssueGrant {
                context: RequestContext::new(id(41, RequestId::from_uuid), host),
                session_id: session,
                epoch,
                grant: Grant {
                    id: expired_grant_id,
                    session_id: session,
                    subject: participant,
                    authority: resolution_scope.clone(),
                    expires_at: Timestamp::new(base + 1_000, 0).unwrap(),
                    revoked: false,
                },
                single_use: true,
            })
            .await
            .unwrap();
        let mut expired_snapshot = reopened.load_grant(expired_grant_id).await.unwrap();
        expired_snapshot.grant.expires_at = Timestamp::new(base - 1, 0).unwrap();
        sqlx::query("UPDATE authority_grants SET snapshot=? WHERE grant_id=?")
            .bind(serde_json::to_vec(&expired_snapshot).unwrap())
            .bind(expired_grant_id.to_string())
            .execute(reopened.pool())
            .await
            .unwrap();
        clock.0.store(base + 42, Ordering::SeqCst);
        let revoked_grant_id = id(42, GrantId::from_uuid);
        reopened
            .issue_grant(IssueGrant {
                context: RequestContext::new(id(43, RequestId::from_uuid), host),
                session_id: session,
                epoch,
                grant: Grant {
                    id: revoked_grant_id,
                    session_id: session,
                    subject: participant,
                    authority: resolution_scope.clone(),
                    expires_at: Timestamp::new(base + 1_000, 0).unwrap(),
                    revoked: false,
                },
                single_use: true,
            })
            .await
            .unwrap();
        reopened
            .revoke_grant(RevokeGrant {
                context: RequestContext::new(id(44, RequestId::from_uuid), host),
                session_id: session,
                epoch,
                grant_id: revoked_grant_id,
            })
            .await
            .unwrap();
        let grant_id = id(36, GrantId::from_uuid);
        reopened
            .issue_grant(IssueGrant {
                context: RequestContext::new(id(37, RequestId::from_uuid), host),
                session_id: session,
                epoch,
                grant: Grant {
                    id: grant_id,
                    session_id: session,
                    subject: participant,
                    authority: resolution_scope,
                    expires_at: Timestamp::new(base + 1_000, 0).unwrap(),
                    revoked: false,
                },
                single_use: true,
            })
            .await
            .unwrap();
        let proof = b"PRIVATE_PROOF_SENTINEL".to_vec();
        let resolve_request = v1::ResolveUncertaintyRequest {
            metadata: None,
            request_id: Uuid::from_u128(38).as_bytes().to_vec(),
            session_id: session.as_uuid().as_bytes().to_vec(),
            operation_id: operation.as_uuid().as_bytes().to_vec(),
            authority_grant_id: grant_id.as_uuid().as_bytes().to_vec(),
            reason: "verified external receipt".into(),
            resolution: Some(
                v1::resolve_uncertainty_request::Resolution::ConfirmCompleted(v1::EffectProof {
                    kind: v1::EffectProofKind::ExternalCommit.into(),
                    digest: sha2::Sha256::digest(&proof).to_vec(),
                    evidence: proof.clone(),
                }),
            ),
            effect_id: uncertain.request_id.as_uuid().as_bytes().to_vec(),
        };
        let before_denial_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        let before_denial_ownership = reopened.read_ownership(session).await.unwrap();
        let before_denial_effect = reopened.read_effect(uncertain.request_id).await.unwrap();
        let before_denial_operation = reopened.load_operation(operation).await.unwrap();
        let before_denial_grant = reopened.load_grant(grant_id).await.unwrap();
        for denied_grant in [
            id(39, GrantId::from_uuid),
            expired_grant_id,
            revoked_grant_id,
        ] {
            let mut denied_request = resolve_request.clone();
            denied_request.authority_grant_id = denied_grant.as_uuid().as_bytes().to_vec();
            let denied = client.resolve_uncertainty(denied_request).await.unwrap();
            assert!(matches!(
                denied.outcome,
                Some(v1::resolve_uncertainty_response::Outcome::Failure(_))
            ));
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events")
                .fetch_one(reopened.pool())
                .await
                .unwrap(),
            before_denial_events
        );
        assert_eq!(
            reopened.read_ownership(session).await.unwrap(),
            before_denial_ownership
        );
        assert_eq!(
            reopened.read_effect(uncertain.request_id).await.unwrap(),
            before_denial_effect
        );
        assert_eq!(
            reopened.load_operation(operation).await.unwrap(),
            before_denial_operation
        );
        assert_eq!(
            reopened.load_grant(grant_id).await.unwrap(),
            before_denial_grant
        );
        let response = client
            .resolve_uncertainty(resolve_request.clone())
            .await
            .unwrap();
        assert!(
            matches!(
                response.outcome,
                Some(v1::resolve_uncertainty_response::Outcome::Resolution(_))
            ),
            "unexpected resolution outcome: {:?}",
            response.outcome
        );
        let replay = client
            .resolve_uncertainty(resolve_request.clone())
            .await
            .unwrap();
        assert_eq!(response, replay);
        let events_after_resolution: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        let effect_after_resolution = reopened.read_effect(uncertain.request_id).await.unwrap();
        let grant_after_resolution = reopened.load_grant(grant_id).await.unwrap();
        let mut changed = resolve_request;
        changed.reason = "different semantic reason".into();
        let conflict = client.resolve_uncertainty(changed).await.unwrap();
        assert!(matches!(
            conflict.outcome,
            Some(v1::resolve_uncertainty_response::Outcome::Failure(ref failure))
                if failure.code == i32::from(v1::FailureCode::Conflict)
        ));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events")
                .fetch_one(reopened.pool())
                .await
                .unwrap(),
            events_after_resolution
        );
        assert_eq!(
            reopened.read_effect(uncertain.request_id).await.unwrap(),
            effect_after_resolution
        );
        assert_eq!(
            reopened.load_grant(grant_id).await.unwrap(),
            grant_after_resolution
        );
        assert_eq!(
            reopened.load_operation(operation).await.unwrap().state,
            OperationState::Uncertain
        );
        for (offset, resolution, expected_phase) in [
            (
                50_u128,
                v1::resolve_uncertainty_request::Resolution::DoNotRetry(v1::DoNotRetry {}),
                navigator_store_api::EffectJournalPhase::Failed,
            ),
            (
                60,
                v1::resolve_uncertainty_request::Resolution::RetryWithEffectProof(
                    v1::EffectProof {
                        kind: v1::EffectProofKind::EffectAbsent.into(),
                        digest: sha2::Sha256::digest(b"RETRY_PROOF_SENTINEL_60").to_vec(),
                        evidence: b"RETRY_PROOF_SENTINEL_60".to_vec(),
                    },
                ),
                navigator_store_api::EffectJournalPhase::RetryAuthorized,
            ),
        ] {
            let extra_operation = id(offset, OperationId::from_uuid);
            let extra_message = id(offset + 1, MessageId::from_uuid);
            reopened
                .start_operation(StartOperation {
                    context: RequestContext::new(id(offset + 2, RequestId::from_uuid), host),
                    session_id: session,
                    epoch,
                    operation_id: extra_operation,
                    participant_id: participant,
                    input_message_id: extra_message,
                    input: template.validate_input(br"{}").unwrap(),
                })
                .await
                .unwrap();
            accept_recovered_input(RecoveredInput {
                store: &reopened,
                host,
                session,
                participant,
                driver_id: registration.driver.driver_id(),
                operation: extra_operation,
                message: extra_message,
                epoch,
                seed: offset + 1_000,
            })
            .await;
            for (request, revision, action) in [
                (offset + 3, 1_u64, OperationAction::BeginStart),
                (offset + 4, 2, OperationAction::ReportRunning),
            ] {
                reopened
                    .transition_operation(TransitionOperation {
                        context: RequestContext::new(id(request, RequestId::from_uuid), host),
                        session_id: session,
                        epoch,
                        operation_id: extra_operation,
                        expected_revision: navigator_domain::Revision::new(revision).unwrap(),
                        action,
                        report_message_id: (action == OperationAction::ReportRunning)
                            .then_some(extra_message),
                        terminal_outcome: None,
                    })
                    .await
                    .unwrap();
            }
            let effect_request = id(offset + 5, RequestId::from_uuid);
            let reserve = ReserveEffect::new(
                RequestContext::new(effect_request, host),
                session,
                participant,
                extra_operation,
                epoch,
                Capability::new("tool.external").unwrap(),
                format!("effect-{offset}").as_bytes(),
                EffectClass::NonIdempotent,
                EffectResolutionContract {
                    allow_confirm_completed: true,
                    allow_do_not_retry: true,
                    allow_retry_with_proof: true,
                    allowed_proof_kinds: vec![
                        EffectProofKind::ExternalCommit,
                        EffectProofKind::EffectAbsent,
                    ],
                },
                std::time::Duration::from_secs(1),
            );
            let extra_effect = reopened.reserve_effect(reserve.clone()).await.unwrap();
            reopened
                .start_effect(EffectTransition::start(
                    RequestContext::new(id(offset + 6, RequestId::from_uuid), host),
                    effect_request,
                    epoch,
                    extra_effect.revision,
                ))
                .await
                .unwrap();
            clock.0.fetch_add(2, Ordering::SeqCst);
            let extra_effect = reopened.reserve_effect(reserve).await.unwrap();
            reopened
                .transition_operation(TransitionOperation {
                    context: RequestContext::new(id(offset + 7, RequestId::from_uuid), host),
                    session_id: session,
                    epoch,
                    operation_id: extra_operation,
                    expected_revision: navigator_domain::Revision::new(3).unwrap(),
                    action: OperationAction::ReportUncertain,
                    report_message_id: Some(extra_message),
                    terminal_outcome: Some(
                        navigator_store_api::OperationTerminalOutcome::Uncertain {
                            reason: BoundedText::new("effect uncertain").unwrap(),
                        },
                    ),
                })
                .await
                .unwrap();
            let extra_grant_id = id(offset + 8, GrantId::from_uuid);
            reopened
                .issue_grant(IssueGrant {
                    context: RequestContext::new(id(offset + 9, RequestId::from_uuid), host),
                    session_id: session,
                    epoch,
                    grant: Grant {
                        id: extra_grant_id,
                        session_id: session,
                        subject: participant,
                        authority: ScopedCapability::new(
                            Capability::new("effect.resolve_uncertainty").unwrap(),
                            ResourceScope::Operation(extra_operation),
                        ),
                        expires_at: Timestamp::new(base + 1_000, 0).unwrap(),
                        revoked: false,
                    },
                    single_use: true,
                })
                .await
                .unwrap();
            let request = v1::ResolveUncertaintyRequest {
                metadata: None,
                request_id: Uuid::from_u128(offset + 10).as_bytes().to_vec(),
                session_id: session.as_uuid().as_bytes().to_vec(),
                operation_id: extra_operation.as_uuid().as_bytes().to_vec(),
                authority_grant_id: extra_grant_id.as_uuid().as_bytes().to_vec(),
                reason: format!("resolution-{offset}"),
                resolution: Some(resolution),
                effect_id: extra_effect.request_id.as_uuid().as_bytes().to_vec(),
            };
            let scheduled_before_resolution = spy.attempts.lock().unwrap().clone();
            let operation_before_resolution =
                reopened.load_operation(extra_operation).await.unwrap();
            let messages_before_resolution: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM messages")
                    .fetch_one(reopened.pool())
                    .await
                    .unwrap();
            let resolved = client.resolve_uncertainty(request.clone()).await.unwrap();
            assert!(
                matches!(
                    resolved.outcome,
                    Some(v1::resolve_uncertainty_response::Outcome::Resolution(_))
                ),
                "unexpected {offset} resolution: {:?}",
                resolved.outcome
            );
            if expected_phase == navigator_store_api::EffectJournalPhase::RetryAuthorized {
                let Some(v1::resolve_uncertainty_response::Outcome::Resolution(snapshot)) =
                    resolved.outcome.as_ref()
                else {
                    unreachable!("checked above")
                };
                assert_eq!(
                    snapshot.action_status,
                    i32::from(v1::RecoveryActionStatus::Pending)
                );
            }
            assert_eq!(client.resolve_uncertainty(request).await.unwrap(), resolved);
            assert_eq!(
                reopened
                    .read_effect(effect_request)
                    .await
                    .unwrap()
                    .unwrap()
                    .phase,
                expected_phase
            );
            assert!(
                reopened
                    .load_grant(extra_grant_id)
                    .await
                    .unwrap()
                    .consumed_at
                    .is_some()
            );
            assert_eq!(
                reopened.load_operation(extra_operation).await.unwrap(),
                operation_before_resolution
            );
            assert_eq!(*spy.attempts.lock().unwrap(), scheduled_before_resolution);
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM messages")
                    .fetch_one(reopened.pool())
                    .await
                    .unwrap(),
                messages_before_resolution
            );
        }
        let public_response = format!("{response:?}");
        assert!(!public_response.contains("PRIVATE_PROOF_SENTINEL"));
        let event_data: Vec<Vec<u8>> = sqlx::query_scalar("SELECT data FROM events")
            .fetch_all(reopened.pool())
            .await
            .unwrap();
        assert!(
            event_data
                .iter()
                .all(|data| !data.windows(proof.len()).any(|window| window == proof))
        );
        for durable_path in [
            &path,
            &std::path::PathBuf::from(format!("{}-wal", path.display())),
        ] {
            if durable_path.exists() {
                let bytes = std::fs::read(durable_path).unwrap();
                assert!(!bytes.windows(proof.len()).any(|window| window == proof));
            }
        }
        assert_eq!(
            spy.attempts.lock().unwrap().as_slice(),
            &[(operation, message)]
        );
        assert_eq!(
            *spy.effects.lock().unwrap(),
            HashSet::from([(operation, message)])
        );
        assert_eq!(
            spy.redelivery_attempts.lock().unwrap().as_slice(),
            &[(operation, message)]
        );
        assert_eq!(
            *spy.redelivery_effects.lock().unwrap(),
            HashSet::from([(operation, message)])
        );
        assert_eq!(
            reopened
                .load_operation(operation)
                .await
                .unwrap()
                .input_message_id,
            message
        );
        let after_operations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operations")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        let after_messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        assert_eq!(
            (after_operations, after_messages),
            (before_operations + 2, before_messages + 2)
        );
        let classified_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events WHERE event_type='recovery.classified'",
        )
        .fetch_one(reopened.pool())
        .await
        .unwrap();
        assert_eq!(classified_events, 5);
        shutdown_tx.send(true).unwrap();
        assert!(server.await.unwrap().is_ok());
    }

    #[derive(Clone, Copy)]
    struct RecoveredInput<'a> {
        store: &'a SqliteStore,
        host: HostId,
        session: SessionId,
        participant: ParticipantId,
        driver_id: DriverId,
        operation: OperationId,
        message: MessageId,
        epoch: FencingEpoch,
        seed: u128,
    }

    async fn prepare_recovered_launch(input: RecoveredInput<'_>) -> (LaunchAttemptId, InstanceId) {
        let launch = id(input.seed, LaunchAttemptId::from_uuid);
        let instance = id(input.seed + 1, InstanceId::from_uuid);
        input
            .store
            .prepare_launch(PrepareLaunch {
                context: RequestContext::new(id(input.seed + 2, RequestId::from_uuid), input.host),
                epoch: input.epoch,
                session_id: input.session,
                participant_id: input.participant,
                driver_id: input.driver_id,
                attempt_id: launch,
                credential_digest: [4; 32],
                driver_configuration_digest: [5; 32],
            })
            .await
            .unwrap();
        input
            .store
            .attach_launch(AttachLaunch {
                context: RequestContext::new(id(input.seed + 3, RequestId::from_uuid), input.host),
                session_id: input.session,
                epoch: input.epoch,
                attempt_id: launch,
                expected_revision: Revision::initial(),
                instance_id: instance,
                evidence: ProcessEvidence {
                    process_id: 4,
                    process_group_id: 4,
                    parent_process_id: 3,
                    creation_marker: 1,
                    executable_identity: [6; 32],
                },
            })
            .await
            .unwrap();
        input
            .store
            .transition_launch(TransitionLaunch {
                context: RequestContext::new(id(input.seed + 4, RequestId::from_uuid), input.host),
                session_id: input.session,
                epoch: input.epoch,
                attempt_id: launch,
                expected_revision: Revision::new(2).unwrap(),
                target: LaunchState::Ready,
                cleanup_reason: None,
            })
            .await
            .unwrap();
        (launch, instance)
    }

    async fn accept_recovered_input(input: RecoveredInput<'_>) {
        let (launch, instance) = prepare_recovered_launch(input).await;
        let delivery = id(input.seed + 5, DeliveryAttemptId::from_uuid);
        let leased = input
            .store
            .lease_next_message(LeaseNextMessage {
                context: RequestContext::new(id(input.seed + 6, RequestId::from_uuid), input.host),
                session_id: input.session,
                epoch: input.epoch,
                destination: input.participant,
                instance_id: instance,
                driver_launch_attempt_id: launch,
                proposed_attempt_id: delivery,
                lease_duration: std::time::Duration::from_secs(2),
            })
            .await
            .unwrap()
            .value()
            .clone()
            .unwrap();
        assert_eq!(leased.message_id, input.message);
        let pending = input
            .store
            .transition_message_delivery(TransitionMessageDelivery {
                context: RequestContext::new(id(input.seed + 7, RequestId::from_uuid), input.host),
                session_id: input.session,
                epoch: input.epoch,
                message_id: input.message,
                attempt_id: delivery,
                expected_revision: leased.revision,
                transition: DeliveryTransition::AcceptancePending,
            })
            .await
            .unwrap()
            .value()
            .clone();
        input
            .store
            .transition_message_delivery(TransitionMessageDelivery {
                context: RequestContext::new(id(input.seed + 8, RequestId::from_uuid), input.host),
                session_id: input.session,
                epoch: input.epoch,
                message_id: input.message,
                attempt_id: delivery,
                expected_revision: pending.revision,
                transition: DeliveryTransition::Accepted {
                    proof_digest: [7; 32],
                },
            })
            .await
            .unwrap();
        for (request_id, revision, target) in [
            (
                input.seed + 9,
                Revision::new(3).unwrap(),
                LaunchState::Stopping,
            ),
            (
                input.seed + 10,
                Revision::new(4).unwrap(),
                LaunchState::Stopped,
            ),
        ] {
            input
                .store
                .transition_launch(TransitionLaunch {
                    context: RequestContext::new(id(request_id, RequestId::from_uuid), input.host),
                    session_id: input.session,
                    epoch: input.epoch,
                    attempt_id: launch,
                    expected_revision: revision,
                    target,
                    cleanup_reason: None,
                })
                .await
                .unwrap();
        }
        assert_eq!(
            input
                .store
                .load_operation(input.operation)
                .await
                .unwrap()
                .state,
            OperationState::Queued
        );
    }
}
