use std::future::Future;

use navigator_domain::{
    FencingEpoch, LaunchAttemptId, LiveObservation, MessageId, OperationId, ParticipantId,
    RecoveryAction, RecoveryContradiction, RecoveryDecision, RecoveryState, RequestId, SessionId,
    classify_recovery,
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RecoveryEntity {
    Session(SessionId),
    Participant(ParticipantId),
    Instance(LaunchAttemptId),
    Operation {
        operation_id: OperationId,
        input_message_id: MessageId,
    },
    Message(MessageId),
    Effect(RequestId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryCandidate {
    pub ordinal: u64,
    pub session_id: SessionId,
    pub entity: RecoveryEntity,
    pub state: RecoveryState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClassifiedRecovery {
    pub entity: RecoveryEntity,
    pub state: RecoveryState,
    pub observation: LiveObservation,
    pub decision: RecoveryDecision,
}

/// Store/Driver boundary for reconciliation. `acquire_epoch` is deliberately a
/// single operation so no inspection can occur under an inherited epoch.
pub trait RecoveryBackend: Send + Sync {
    type Error;

    /// Acquires a new epoch once. Repeating the same `recovery_request_id`
    /// returns that same acquisition instead of advancing ownership again.
    fn acquire_epoch(
        &self,
        session_id: SessionId,
        recovery_request_id: RequestId,
    ) -> impl Future<Output = Result<FencingEpoch, Self::Error>> + Send;

    fn unfinished(
        &self,
        session_id: SessionId,
        epoch: FencingEpoch,
    ) -> impl Future<Output = Result<Vec<RecoveryCandidate>, Self::Error>> + Send;

    fn inspect_instance(
        &self,
        attempt_id: LaunchAttemptId,
        epoch: FencingEpoch,
    ) -> impl Future<Output = Result<LiveObservation, Self::Error>> + Send;

    /// Must append one classification Event idempotently for
    /// `(epoch, entity, state, observation, decision)`.
    /// Atomically records the whole classification set. Repetition with the
    /// same recovery request and semantic input is an idempotent replay.
    fn record_classifications(
        &self,
        epoch: FencingEpoch,
        recovery_request_id: RequestId,
        classifications: &[ClassifiedRecovery],
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Schedules the already committed pair. Implementations must never mint a
    /// replacement Operation or Message.
    fn schedule_existing_operation(
        &self,
        epoch: FencingEpoch,
        operation_id: OperationId,
        input_message_id: MessageId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Redelivers the exact persisted Message through receiver deduplication.
    /// `false` means this runtime has no concrete handler and the action remains pending.
    fn redeliver_exact_message(
        &self,
        _epoch: FencingEpoch,
        _message_id: MessageId,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }

    fn reconnect_exact_instance(
        &self,
        _epoch: FencingEpoch,
        _attempt_id: LaunchAttemptId,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }

    fn cleanup_verified_instance(
        &self,
        _epoch: FencingEpoch,
        _attempt_id: LaunchAttemptId,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(false) }
    }
}

#[derive(Debug, Error)]
pub enum ReconcileError<E> {
    #[error("recovery backend failed")]
    Backend(E),
    #[error("durable recovery state contradicts its live observation: {0:?}")]
    Contradiction(RecoveryContradiction),
    #[error("recovery action does not match the persisted entity")]
    ActionEntityMismatch,
    #[error("recovery inventory is not in stable order")]
    InventoryOrder,
    #[error("recovery inventory contains a duplicate entity")]
    DuplicateEntity,
    #[error("recovery inventory contains an entity from another Session")]
    CrossSessionEntity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reconciliation {
    pub epoch: FencingEpoch,
    pub classifications: Vec<ClassifiedRecovery>,
    /// Ordered semantic actions, including actions blocked at the Session
    /// safety barrier. `executions` is authoritative for whether each action
    /// ran, remains pending, or was blocked.
    pub actions: Vec<ClassifiedRecovery>,
    pub executions: Vec<RecoveryExecution>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryExecutionStatus {
    Executed,
    NoOp,
    Pending,
    BlockedByUncertainty,
    BlockedByCleanup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryExecution {
    pub classification: ClassifiedRecovery,
    pub status: RecoveryExecutionStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryRunIds {
    pub ownership_request_id: RequestId,
    pub classification_request_id: RequestId,
}

pub struct Reconciler<B> {
    backend: B,
}

#[cfg(test)]
#[expect(
    clippy::items_after_test_module,
    reason = "semantic fakes stay adjacent to the recovery boundary they exercise"
)]
mod tests {
    use std::{collections::HashSet, sync::Mutex};

    use super::*;

    fn id<T>(value: u128) -> T
    where
        T: FromUuid,
    {
        T::from_uuid(uuid::Uuid::from_u128(value))
    }

    trait FromUuid: Sized {
        fn from_uuid(value: uuid::Uuid) -> Self;
    }

    macro_rules! from_uuid {
        ($($type:ty),+ $(,)?) => {$(
            impl FromUuid for $type {
                fn from_uuid(value: uuid::Uuid) -> Self {
                    <$type>::from_uuid(value).unwrap()
                }
            }
        )+};
    }
    from_uuid!(
        SessionId,
        OperationId,
        MessageId,
        LaunchAttemptId,
        RequestId
    );

    fn run_ids(value: u128) -> RecoveryRunIds {
        RecoveryRunIds {
            ownership_request_id: id(value),
            classification_request_id: id(value + 100),
        }
    }

    #[derive(Default)]
    struct Fake {
        calls: Mutex<Vec<&'static str>>,
        candidates: Mutex<Vec<RecoveryCandidate>>,
        scheduled: Mutex<HashSet<(OperationId, MessageId)>>,
        redelivered: Mutex<HashSet<MessageId>>,
        reconnected: Mutex<HashSet<LaunchAttemptId>>,
        cleaned: Mutex<HashSet<LaunchAttemptId>>,
        supported: Mutex<Vec<RecoveryAction>>,
        fail_redelivery_once: Mutex<bool>,
        events: Mutex<HashSet<(u64, RecoveryEntity, RecoveryState)>>,
        observation: Mutex<Option<LiveObservation>>,
    }

    impl RecoveryBackend for Fake {
        type Error = ();

        async fn acquire_epoch(
            &self,
            _session_id: SessionId,
            _recovery_request_id: RequestId,
        ) -> Result<FencingEpoch, ()> {
            self.calls.lock().unwrap().push("acquire");
            Ok(FencingEpoch::new(7).unwrap())
        }

        async fn unfinished(
            &self,
            _session_id: SessionId,
            _epoch: FencingEpoch,
        ) -> Result<Vec<RecoveryCandidate>, ()> {
            self.calls.lock().unwrap().push("inventory");
            Ok(self.candidates.lock().unwrap().clone())
        }

        async fn inspect_instance(
            &self,
            _attempt_id: LaunchAttemptId,
            _epoch: FencingEpoch,
        ) -> Result<LiveObservation, ()> {
            self.calls.lock().unwrap().push("inspect");
            Ok(self
                .observation
                .lock()
                .unwrap()
                .unwrap_or(LiveObservation::SameAuthenticatedInstance))
        }

        async fn record_classifications(
            &self,
            epoch: FencingEpoch,
            _recovery_request_id: RequestId,
            items: &[ClassifiedRecovery],
        ) -> Result<(), ()> {
            self.calls.lock().unwrap().push("record");
            for item in items {
                self.events
                    .lock()
                    .unwrap()
                    .insert((epoch.get(), item.entity, item.state));
            }
            Ok(())
        }

        async fn schedule_existing_operation(
            &self,
            _epoch: FencingEpoch,
            operation_id: OperationId,
            input_message_id: MessageId,
        ) -> Result<(), ()> {
            self.calls.lock().unwrap().push("schedule");
            self.scheduled
                .lock()
                .unwrap()
                .insert((operation_id, input_message_id));
            Ok(())
        }

        async fn redeliver_exact_message(
            &self,
            _epoch: FencingEpoch,
            message_id: MessageId,
        ) -> Result<bool, ()> {
            self.calls.lock().unwrap().push("redeliver");
            let mut fail_once = self.fail_redelivery_once.lock().unwrap();
            if *fail_once {
                *fail_once = false;
                return Err(());
            }
            drop(fail_once);
            let supported = self
                .supported
                .lock()
                .unwrap()
                .contains(&RecoveryAction::RedeliverExactMessage);
            if supported {
                self.redelivered.lock().unwrap().insert(message_id);
            }
            Ok(supported)
        }

        async fn reconnect_exact_instance(
            &self,
            _epoch: FencingEpoch,
            attempt_id: LaunchAttemptId,
        ) -> Result<bool, ()> {
            self.calls.lock().unwrap().push("reconnect");
            let supported = self
                .supported
                .lock()
                .unwrap()
                .contains(&RecoveryAction::ReconnectExactInstance);
            if supported {
                self.reconnected.lock().unwrap().insert(attempt_id);
            }
            Ok(supported)
        }

        async fn cleanup_verified_instance(
            &self,
            _epoch: FencingEpoch,
            attempt_id: LaunchAttemptId,
        ) -> Result<bool, ()> {
            self.calls.lock().unwrap().push("cleanup");
            let supported = self
                .supported
                .lock()
                .unwrap()
                .contains(&RecoveryAction::CleanupVerifiedResource);
            if supported {
                self.cleaned.lock().unwrap().insert(attempt_id);
            }
            Ok(supported)
        }
    }

    #[tokio::test]
    async fn crash_after_spawn_commit_schedules_exact_existing_identities_once() {
        let operation_id = id(2);
        let message_id = id(3);
        let fake = Fake::default();
        fake.candidates.lock().unwrap().push(RecoveryCandidate {
            ordinal: 1,
            session_id: id(1),
            entity: RecoveryEntity::Operation {
                operation_id,
                input_message_id: message_id,
            },
            state: RecoveryState::OperationQueued,
        });
        let reconciler = Reconciler::new(fake);

        reconciler.reconcile(id(1), run_ids(9)).await.unwrap();
        reconciler.reconcile(id(1), run_ids(9)).await.unwrap();

        assert_eq!(
            reconciler.backend.calls.lock().unwrap()[..3],
            ["acquire", "inventory", "record"]
        );
        let scheduled = reconciler.backend.scheduled.lock().unwrap();
        assert_eq!(scheduled.len(), 1);
        assert!(scheduled.contains(&(operation_id, message_id)));
        assert_eq!(reconciler.backend.events.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn classify_only_never_executes_a_resume_action() {
        let fake = Fake::default();
        fake.candidates.lock().unwrap().push(RecoveryCandidate {
            ordinal: 1,
            session_id: id(1),
            entity: RecoveryEntity::Operation {
                operation_id: id(2),
                input_message_id: id(3),
            },
            state: RecoveryState::OperationQueued,
        });
        let reconciler = Reconciler::new(fake);
        let report = reconciler.classify_only(id(1), run_ids(9)).await.unwrap();
        assert_eq!(report.actions.len(), 1);
        assert!(reconciler.backend.scheduled.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn ownership_is_acquired_before_driver_inspection() {
        let fake = Fake::default();
        fake.candidates.lock().unwrap().push(RecoveryCandidate {
            ordinal: 1,
            session_id: id(1),
            entity: RecoveryEntity::Instance(id(4)),
            state: RecoveryState::InstanceReady,
        });
        let reconciler = Reconciler::new(fake);
        reconciler.reconcile(id(1), run_ids(9)).await.unwrap();
        assert_eq!(
            *reconciler.backend.calls.lock().unwrap(),
            ["acquire", "inventory", "inspect", "record", "reconnect"]
        );
    }

    #[tokio::test]
    async fn uncertain_instance_blocks_otherwise_safe_queued_resume() {
        let fake = Fake::default();
        *fake.observation.lock().unwrap() = Some(LiveObservation::SameUnauthenticatedInstance);
        fake.supported
            .lock()
            .unwrap()
            .push(RecoveryAction::RedeliverExactMessage);
        fake.candidates.lock().unwrap().extend([
            RecoveryCandidate {
                ordinal: 1,
                session_id: id(1),
                entity: RecoveryEntity::Instance(id(4)),
                state: RecoveryState::InstanceReady,
            },
            RecoveryCandidate {
                ordinal: 2,
                session_id: id(1),
                entity: RecoveryEntity::Operation {
                    operation_id: id(2),
                    input_message_id: id(3),
                },
                state: RecoveryState::OperationQueued,
            },
            RecoveryCandidate {
                ordinal: 3,
                session_id: id(1),
                entity: RecoveryEntity::Message(id(5)),
                state: RecoveryState::MessageQueued,
            },
        ]);
        let reconciler = Reconciler::new(fake);
        let report = reconciler.reconcile(id(1), run_ids(9)).await.unwrap();
        assert!(report.executions.iter().any(|execution| {
            execution.classification.decision.action == RecoveryAction::ScheduleExistingOperation
                && execution.status == RecoveryExecutionStatus::BlockedByUncertainty
        }));
        assert!(reconciler.backend.scheduled.lock().unwrap().is_empty());
        assert!(reconciler.backend.redelivered.lock().unwrap().is_empty());
        assert!(report.executions.iter().any(|execution| matches!(
            execution.status,
            RecoveryExecutionStatus::BlockedByUncertainty
        )));
    }

    #[tokio::test]
    async fn redelivery_uses_exact_message_and_is_idempotent_at_receiver() {
        let message_id = id(3);
        let fake = Fake::default();
        fake.supported
            .lock()
            .unwrap()
            .push(RecoveryAction::RedeliverExactMessage);
        fake.candidates.lock().unwrap().push(RecoveryCandidate {
            ordinal: 1,
            session_id: id(1),
            entity: RecoveryEntity::Message(message_id),
            state: RecoveryState::MessageQueued,
        });
        let reconciler = Reconciler::new(fake);

        let first = reconciler.reconcile(id(1), run_ids(9)).await.unwrap();
        let second = reconciler.reconcile(id(1), run_ids(9)).await.unwrap();

        assert_eq!(
            first.executions[0].status,
            RecoveryExecutionStatus::Executed
        );
        assert_eq!(
            second.executions[0].status,
            RecoveryExecutionStatus::Executed
        );
        assert_eq!(reconciler.backend.redelivered.lock().unwrap().len(), 1);
        assert_eq!(
            reconciler
                .backend
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| **call == "redeliver")
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn missing_reconnect_and_cleanup_handlers_remain_pending() {
        for (state, observation) in [
            (
                RecoveryState::InstanceReady,
                LiveObservation::SameAuthenticatedInstance,
            ),
            (RecoveryState::InstanceStopping, LiveObservation::Absent),
        ] {
            let fake = Fake::default();
            *fake.observation.lock().unwrap() = Some(observation);
            fake.candidates.lock().unwrap().push(RecoveryCandidate {
                ordinal: 1,
                session_id: id(1),
                entity: RecoveryEntity::Instance(id(4)),
                state,
            });
            let report = Reconciler::new(fake)
                .reconcile(id(1), run_ids(9))
                .await
                .unwrap();
            assert_eq!(
                report.executions[0].status,
                RecoveryExecutionStatus::Pending
            );
        }
    }

    #[tokio::test]
    async fn partial_action_failure_retries_idempotently_without_new_identities() {
        let operation_id = id(2);
        let message_id = id(3);
        let redelivery_id = id(5);
        let fake = Fake::default();
        fake.supported
            .lock()
            .unwrap()
            .push(RecoveryAction::RedeliverExactMessage);
        *fake.fail_redelivery_once.lock().unwrap() = true;
        fake.candidates.lock().unwrap().extend([
            RecoveryCandidate {
                ordinal: 1,
                session_id: id(1),
                entity: RecoveryEntity::Operation {
                    operation_id,
                    input_message_id: message_id,
                },
                state: RecoveryState::OperationQueued,
            },
            RecoveryCandidate {
                ordinal: 2,
                session_id: id(1),
                entity: RecoveryEntity::Message(redelivery_id),
                state: RecoveryState::MessageRetryScheduled,
            },
        ]);
        let reconciler = Reconciler::new(fake);

        assert!(reconciler.reconcile(id(1), run_ids(9)).await.is_err());
        let retry = reconciler.reconcile(id(1), run_ids(9)).await.unwrap();

        assert_eq!(reconciler.backend.scheduled.lock().unwrap().len(), 1);
        assert!(
            reconciler
                .backend
                .scheduled
                .lock()
                .unwrap()
                .contains(&(operation_id, message_id))
        );
        assert_eq!(reconciler.backend.redelivered.lock().unwrap().len(), 1);
        assert!(
            retry
                .executions
                .iter()
                .all(|execution| execution.status == RecoveryExecutionStatus::Executed)
        );
    }

    #[tokio::test]
    async fn cleanup_barrier_only_allows_the_verified_cleanup() {
        let fake = Fake::default();
        *fake.observation.lock().unwrap() = Some(LiveObservation::Absent);
        fake.supported
            .lock()
            .unwrap()
            .push(RecoveryAction::CleanupVerifiedResource);
        fake.supported
            .lock()
            .unwrap()
            .push(RecoveryAction::RedeliverExactMessage);
        fake.candidates.lock().unwrap().extend([
            RecoveryCandidate {
                ordinal: 1,
                session_id: id(1),
                entity: RecoveryEntity::Instance(id(4)),
                state: RecoveryState::InstanceStopping,
            },
            RecoveryCandidate {
                ordinal: 2,
                session_id: id(1),
                entity: RecoveryEntity::Operation {
                    operation_id: id(2),
                    input_message_id: id(3),
                },
                state: RecoveryState::OperationQueued,
            },
            RecoveryCandidate {
                ordinal: 3,
                session_id: id(1),
                entity: RecoveryEntity::Message(id(5)),
                state: RecoveryState::MessageQueued,
            },
        ]);
        let reconciler = Reconciler::new(fake);
        let report = reconciler.reconcile(id(1), run_ids(9)).await.unwrap();
        assert_eq!(reconciler.backend.cleaned.lock().unwrap().len(), 1);
        assert!(reconciler.backend.scheduled.lock().unwrap().is_empty());
        assert!(reconciler.backend.redelivered.lock().unwrap().is_empty());
        assert_eq!(
            report
                .executions
                .iter()
                .filter(|value| value.status == RecoveryExecutionStatus::BlockedByCleanup)
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn uncertainty_takes_precedence_and_blocks_cleanup() {
        let fake = Fake::default();
        *fake.observation.lock().unwrap() = Some(LiveObservation::Absent);
        fake.supported
            .lock()
            .unwrap()
            .push(RecoveryAction::CleanupVerifiedResource);
        fake.candidates.lock().unwrap().extend([
            RecoveryCandidate {
                ordinal: 1,
                session_id: id(1),
                entity: RecoveryEntity::Instance(id(4)),
                state: RecoveryState::InstanceStopping,
            },
            RecoveryCandidate {
                ordinal: 2,
                session_id: id(1),
                entity: RecoveryEntity::Operation {
                    operation_id: id(2),
                    input_message_id: id(3),
                },
                state: RecoveryState::OperationRunning,
            },
        ]);
        let reconciler = Reconciler::new(fake);
        let report = reconciler.reconcile(id(1), run_ids(9)).await.unwrap();
        assert!(reconciler.backend.cleaned.lock().unwrap().is_empty());
        assert!(report.executions.iter().all(|value| matches!(
            value.status,
            RecoveryExecutionStatus::BlockedByUncertainty | RecoveryExecutionStatus::Pending
        )));
    }

    #[tokio::test]
    async fn malformed_inventory_fails_before_record_or_action() {
        for candidates in [
            vec![RecoveryCandidate {
                ordinal: 0,
                session_id: id(1),
                entity: RecoveryEntity::Message(id(2)),
                state: RecoveryState::MessageQueued,
            }],
            vec![
                RecoveryCandidate {
                    ordinal: 1,
                    session_id: id(1),
                    entity: RecoveryEntity::Message(id(2)),
                    state: RecoveryState::MessageQueued,
                },
                RecoveryCandidate {
                    ordinal: 2,
                    session_id: id(1),
                    entity: RecoveryEntity::Message(id(2)),
                    state: RecoveryState::MessageLeased,
                },
            ],
            vec![RecoveryCandidate {
                ordinal: 1,
                session_id: id(9),
                entity: RecoveryEntity::Message(id(2)),
                state: RecoveryState::MessageQueued,
            }],
        ] {
            let fake = Fake::default();
            *fake.candidates.lock().unwrap() = candidates;
            let reconciler = Reconciler::new(fake);
            assert!(reconciler.reconcile(id(1), run_ids(9)).await.is_err());
            let calls = reconciler.backend.calls.lock().unwrap();
            assert_eq!(calls.as_slice(), &["acquire", "inventory"]);
        }
    }
}

impl<B> Reconciler<B>
where
    B: RecoveryBackend,
{
    #[must_use]
    pub const fn new(backend: B) -> Self {
        Self { backend }
    }

    pub async fn acquire_only(
        &self,
        session_id: SessionId,
        ownership_request_id: RequestId,
    ) -> Result<FencingEpoch, ReconcileError<B::Error>> {
        self.backend
            .acquire_epoch(session_id, ownership_request_id)
            .await
            .map_err(ReconcileError::Backend)
    }

    pub async fn reconcile(
        &self,
        session_id: SessionId,
        ids: RecoveryRunIds,
    ) -> Result<Reconciliation, ReconcileError<B::Error>> {
        let mut reconciliation = self.classify_only(session_id, ids).await?;
        self.execute_actions(&mut reconciliation).await?;
        Ok(reconciliation)
    }

    pub async fn classify_only(
        &self,
        session_id: SessionId,
        ids: RecoveryRunIds,
    ) -> Result<Reconciliation, ReconcileError<B::Error>> {
        // Fencing is intentionally the first observable backend operation.
        let epoch = self
            .backend
            .acquire_epoch(session_id, ids.ownership_request_id)
            .await
            .map_err(ReconcileError::Backend)?;
        let candidates = self
            .backend
            .unfinished(session_id, epoch)
            .await
            .map_err(ReconcileError::Backend)?;
        let mut seen = std::collections::HashSet::with_capacity(candidates.len());
        let mut previous = 0;
        for candidate in &candidates {
            if candidate.session_id != session_id {
                return Err(ReconcileError::CrossSessionEntity);
            }
            if candidate.ordinal == 0 || candidate.ordinal <= previous {
                return Err(ReconcileError::InventoryOrder);
            }
            previous = candidate.ordinal;
            if !seen.insert(candidate.entity) {
                return Err(ReconcileError::DuplicateEntity);
            }
        }
        let mut classified = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let observation = match candidate.entity {
                RecoveryEntity::Instance(attempt_id) => self
                    .backend
                    .inspect_instance(attempt_id, epoch)
                    .await
                    .map_err(ReconcileError::Backend)?,
                _ => LiveObservation::NotApplicable,
            };
            let decision = classify_recovery(candidate.state, observation)
                .map_err(ReconcileError::Contradiction)?;
            classified.push(ClassifiedRecovery {
                entity: candidate.entity,
                state: candidate.state,
                observation,
                decision,
            });
        }

        // Classification is complete before any resume action. A contradiction
        // therefore fails closed without partially continuing work.
        self.backend
            .record_classifications(epoch, ids.classification_request_id, &classified)
            .await
            .map_err(ReconcileError::Backend)?;
        let has_uncertainty = classified
            .iter()
            .any(|item| item.decision.class == navigator_domain::RecoveryClass::EffectUncertain);
        let has_cleanup = classified
            .iter()
            .any(|item| item.decision.class == navigator_domain::RecoveryClass::CleanupRequired);
        let actions = classified
            .iter()
            .copied()
            .filter(|item| {
                !matches!(
                    item.decision.action,
                    RecoveryAction::None | RecoveryAction::AwaitResolution
                )
            })
            .collect::<Vec<_>>();
        let executions = classified
            .iter()
            .copied()
            .map(|classification| RecoveryExecution {
                classification,
                status: planned_status(classification, has_uncertainty, has_cleanup),
            })
            .collect();
        Ok(Reconciliation {
            epoch,
            classifications: classified,
            actions,
            executions,
        })
    }

    pub async fn execute_actions(
        &self,
        reconciliation: &mut Reconciliation,
    ) -> Result<(), ReconcileError<B::Error>> {
        for execution in &mut reconciliation.executions {
            if execution.status != RecoveryExecutionStatus::Pending {
                continue;
            }
            let item = execution.classification;
            let executed = match (item.decision.action, item.entity) {
                (
                    RecoveryAction::ScheduleExistingOperation,
                    RecoveryEntity::Operation {
                        operation_id,
                        input_message_id,
                    },
                ) => {
                    self.backend
                        .schedule_existing_operation(
                            reconciliation.epoch,
                            operation_id,
                            input_message_id,
                        )
                        .await
                        .map_err(ReconcileError::Backend)?;
                    true
                }
                (RecoveryAction::RedeliverExactMessage, RecoveryEntity::Message(message_id)) => {
                    self.backend
                        .redeliver_exact_message(reconciliation.epoch, message_id)
                        .await
                        .map_err(ReconcileError::Backend)?
                }
                (RecoveryAction::ReconnectExactInstance, RecoveryEntity::Instance(attempt_id)) => {
                    self.backend
                        .reconnect_exact_instance(reconciliation.epoch, attempt_id)
                        .await
                        .map_err(ReconcileError::Backend)?
                }
                (RecoveryAction::CleanupVerifiedResource, RecoveryEntity::Instance(attempt_id)) => {
                    self.backend
                        .cleanup_verified_instance(reconciliation.epoch, attempt_id)
                        .await
                        .map_err(ReconcileError::Backend)?
                }
                (RecoveryAction::Continue | RecoveryAction::None, _) => true,
                (RecoveryAction::AwaitResolution, _) => false,
                _ => return Err(ReconcileError::ActionEntityMismatch),
            };
            execution.status = if executed {
                RecoveryExecutionStatus::Executed
            } else {
                RecoveryExecutionStatus::Pending
            };
        }
        Ok(())
    }

    pub async fn schedule_exact_operation(
        &self,
        epoch: FencingEpoch,
        operation_id: OperationId,
        input_message_id: MessageId,
    ) -> Result<(), ReconcileError<B::Error>> {
        self.backend
            .schedule_existing_operation(epoch, operation_id, input_message_id)
            .await
            .map_err(ReconcileError::Backend)
    }
}

fn planned_status(
    item: ClassifiedRecovery,
    has_uncertainty: bool,
    has_cleanup: bool,
) -> RecoveryExecutionStatus {
    match item.decision.action {
        RecoveryAction::None | RecoveryAction::Continue => RecoveryExecutionStatus::NoOp,
        RecoveryAction::AwaitResolution => RecoveryExecutionStatus::Pending,
        _ if has_uncertainty => RecoveryExecutionStatus::BlockedByUncertainty,
        RecoveryAction::ScheduleExistingOperation
        | RecoveryAction::RedeliverExactMessage
        | RecoveryAction::ReconnectExactInstance
            if has_cleanup =>
        {
            RecoveryExecutionStatus::BlockedByCleanup
        }
        _ => RecoveryExecutionStatus::Pending,
    }
}
