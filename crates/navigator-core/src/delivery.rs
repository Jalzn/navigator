use std::{future::Future, sync::Arc, time::Duration};

use navigator_domain::{
    BoundedText, DeliveryAttemptId, FencingEpoch, InstanceId, LaunchAttemptId, MessageId,
    ParticipantId, SessionId,
};
use navigator_store_api::{
    DeliveryLease, DeliveryTransition, LeaseNextMessage, MAX_DELIVERY_REASON_BYTES, MailboxStore,
    MessageDeliveryState, MessageSnapshot, RequestContext, StoreError, TransitionMessageDelivery,
};
use thiserror::Error;

use crate::{AdmissionPermit, ServiceError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcceptanceObservation {
    Accepted { proof_digest: [u8; 32] },
    NotAccepted,
    Unknown,
}

pub trait MailboxDriver: Send + Sync + 'static {
    fn deliver(
        &self,
        message: &MessageSnapshot,
        lease: &DeliveryLease,
        call_timeout: Duration,
    ) -> impl Future<Output = Result<AcceptanceObservation, DeliveryDriverError>> + Send;

    fn query_acceptance(
        &self,
        message_id: MessageId,
        lease: &DeliveryLease,
        call_timeout: Duration,
    ) -> impl Future<Output = Result<AcceptanceObservation, DeliveryDriverError>> + Send;
}

pub trait DeliveryContextFactory: Send + Sync + 'static {
    fn context(&self, message_id: Option<MessageId>, phase: DeliveryPhase) -> RequestContext;
    fn attempt_id(&self, destination: ParticipantId) -> DeliveryAttemptId;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryPhase {
    Lease,
    AcceptancePending,
    AcceptanceUnknown,
    Retry,
    Accepted,
    Uncertain,
    DeadLetter,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("Driver delivery boundary failed")]
pub struct DeliveryDriverError;

#[derive(Debug, Error)]
pub enum DeliveryLoopError {
    #[error(transparent)]
    Service(#[from] ServiceError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("delivery call deadline must end before lease expiry")]
pub struct DeliveryConfigError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryStep {
    Empty,
    Accepted(MessageId),
    DeadLetter(MessageId),
    Uncertain(MessageId),
    ReconciliationRequired(MessageId),
    RetryScheduled(MessageId),
}

pub struct DeliveryLoop<S, D, F> {
    store: Arc<S>,
    driver: Arc<D>,
    contexts: Arc<F>,
    lease_duration: Duration,
    retry_backoff: Duration,
    driver_call_timeout: Duration,
    participant_locks: [tokio::sync::Mutex<()>; 64],
}

impl<S, D, F> DeliveryLoop<S, D, F>
where
    S: MailboxStore,
    D: MailboxDriver,
    F: DeliveryContextFactory,
{
    pub fn new(
        store: Arc<S>,
        driver: Arc<D>,
        contexts: Arc<F>,
        lease_duration: Duration,
        retry_backoff: Duration,
        driver_call_timeout: Duration,
    ) -> Result<Self, DeliveryConfigError> {
        if !delivery_deadlines_are_valid(lease_duration, driver_call_timeout) {
            return Err(DeliveryConfigError);
        }
        Ok(Self {
            store,
            driver,
            contexts,
            lease_duration,
            retry_backoff,
            driver_call_timeout,
            participant_locks: std::array::from_fn(|_| tokio::sync::Mutex::new(())),
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
        let participant_bytes = destination.as_uuid().into_bytes();
        let stripe = usize::from(participant_bytes[0]) % self.participant_locks.len();
        let _participant = self.participant_locks[stripe].lock().await;
        permit.check()?;
        let leased = self
            .store
            .lease_next_message(LeaseNextMessage {
                context: self.contexts.context(None, DeliveryPhase::Lease),
                session_id,
                epoch,
                destination,
                instance_id,
                driver_launch_attempt_id,
                proposed_attempt_id: self.contexts.attempt_id(destination),
                lease_duration: self.lease_duration,
            })
            .await?;
        let Some(message) = leased.value().clone() else {
            return Ok(DeliveryStep::Empty);
        };
        self.reconcile(permit, epoch, message).await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "all delivery outcomes share one fenced decision boundary"
    )]
    async fn reconcile(
        &self,
        permit: &AdmissionPermit,
        epoch: FencingEpoch,
        mut message: MessageSnapshot,
    ) -> Result<DeliveryStep, DeliveryLoopError> {
        let lease = match &message.state {
            MessageDeliveryState::Leased { lease }
            | MessageDeliveryState::AcceptancePending { lease }
            | MessageDeliveryState::AcceptanceUnknown { lease } => lease.clone(),
            MessageDeliveryState::Accepted { .. } => {
                return Ok(DeliveryStep::Accepted(message.message_id));
            }
            MessageDeliveryState::Uncertain { .. } => {
                return Ok(DeliveryStep::Uncertain(message.message_id));
            }
            MessageDeliveryState::DeadLetter { .. } => {
                return Ok(DeliveryStep::DeadLetter(message.message_id));
            }
            MessageDeliveryState::Queued | MessageDeliveryState::RetryScheduled { .. } => {
                return Ok(DeliveryStep::Empty);
            }
        };
        let was_reconciliation = matches!(
            message.state,
            MessageDeliveryState::AcceptancePending { .. }
                | MessageDeliveryState::AcceptanceUnknown { .. }
        );
        let observation = match message.state {
            MessageDeliveryState::AcceptancePending { .. }
            | MessageDeliveryState::AcceptanceUnknown { .. } => {
                match tokio::time::timeout(
                    self.driver_call_timeout,
                    self.driver.query_acceptance(
                        message.message_id,
                        &lease,
                        self.driver_call_timeout,
                    ),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(DeliveryDriverError),
                }
            }
            MessageDeliveryState::Leased { .. } => {
                permit.check()?;
                message = self
                    .transition(
                        permit,
                        epoch,
                        &message,
                        lease.attempt_id,
                        DeliveryPhase::AcceptancePending,
                        DeliveryTransition::AcceptancePending,
                    )
                    .await?;
                permit.check()?;
                match tokio::time::timeout(
                    self.driver_call_timeout,
                    self.driver
                        .deliver(&message, &lease, self.driver_call_timeout),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(DeliveryDriverError),
                }
            }
            _ => unreachable!(),
        };
        match observation {
            Ok(AcceptanceObservation::Accepted { proof_digest }) => {
                self.transition(
                    permit,
                    epoch,
                    &message,
                    lease.attempt_id,
                    DeliveryPhase::Accepted,
                    DeliveryTransition::Accepted { proof_digest },
                )
                .await?;
                Ok(DeliveryStep::Accepted(message.message_id))
            }
            Ok(AcceptanceObservation::NotAccepted) => {
                if message.attempt_count >= navigator_store_api::MAX_DELIVERY_ATTEMPTS {
                    let reason = BoundedText::<MAX_DELIVERY_REASON_BYTES>::new(
                        "Delivery attempt budget exhausted",
                    )
                    .expect("static reason is bounded");
                    self.transition(
                        permit,
                        epoch,
                        &message,
                        lease.attempt_id,
                        DeliveryPhase::DeadLetter,
                        DeliveryTransition::DeadLetter { reason },
                    )
                    .await?;
                    return Ok(DeliveryStep::DeadLetter(message.message_id));
                }
                self.transition(
                    permit,
                    epoch,
                    &message,
                    lease.attempt_id,
                    DeliveryPhase::Retry,
                    DeliveryTransition::RetryAfter {
                        delay: self.retry_backoff,
                    },
                )
                .await?;
                Ok(DeliveryStep::RetryScheduled(message.message_id))
            }
            Ok(AcceptanceObservation::Unknown) | Err(_) if !was_reconciliation => {
                let pending = self
                    .transition(
                        permit,
                        epoch,
                        &message,
                        lease.attempt_id,
                        DeliveryPhase::AcceptanceUnknown,
                        DeliveryTransition::AcceptanceUnknown,
                    )
                    .await?;
                permit.check()?;
                let MessageDeliveryState::AcceptanceUnknown {
                    lease: pending_lease,
                } = &pending.state
                else {
                    unreachable!()
                };
                let query = tokio::time::timeout(
                    self.driver_call_timeout,
                    self.driver.query_acceptance(
                        pending.message_id,
                        pending_lease,
                        self.driver_call_timeout,
                    ),
                )
                .await;
                match query {
                    Ok(Ok(AcceptanceObservation::Accepted { proof_digest })) => {
                        self.transition(
                            permit,
                            epoch,
                            &pending,
                            pending_lease.attempt_id,
                            DeliveryPhase::Accepted,
                            DeliveryTransition::Accepted { proof_digest },
                        )
                        .await?;
                        Ok(DeliveryStep::Accepted(pending.message_id))
                    }
                    Ok(Ok(AcceptanceObservation::NotAccepted)) => {
                        self.transition(
                            permit,
                            epoch,
                            &pending,
                            pending_lease.attempt_id,
                            DeliveryPhase::Retry,
                            DeliveryTransition::RetryAfter {
                                delay: self.retry_backoff,
                            },
                        )
                        .await?;
                        Ok(DeliveryStep::RetryScheduled(pending.message_id))
                    }
                    Ok(Ok(AcceptanceObservation::Unknown) | Err(_)) | Err(_) => {
                        Ok(DeliveryStep::ReconciliationRequired(pending.message_id))
                    }
                }
            }
            Ok(AcceptanceObservation::Unknown) | Err(_) => {
                self.uncertain(permit, epoch, &message, lease.attempt_id)
                    .await
            }
        }
    }

    async fn uncertain(
        &self,
        permit: &AdmissionPermit,
        epoch: FencingEpoch,
        message: &MessageSnapshot,
        attempt_id: DeliveryAttemptId,
    ) -> Result<DeliveryStep, DeliveryLoopError> {
        let reason = BoundedText::<MAX_DELIVERY_REASON_BYTES>::new(
            "Driver cannot prove delivery acceptance",
        )
        .expect("static reason is bounded");
        self.transition(
            permit,
            epoch,
            message,
            attempt_id,
            DeliveryPhase::Uncertain,
            DeliveryTransition::Uncertain { reason },
        )
        .await?;
        Ok(DeliveryStep::Uncertain(message.message_id))
    }

    async fn transition(
        &self,
        permit: &AdmissionPermit,
        epoch: FencingEpoch,
        message: &MessageSnapshot,
        attempt_id: DeliveryAttemptId,
        phase: DeliveryPhase,
        transition: DeliveryTransition,
    ) -> Result<MessageSnapshot, DeliveryLoopError> {
        permit.check()?;
        Ok(self
            .store
            .transition_message_delivery(TransitionMessageDelivery {
                context: self.contexts.context(Some(message.message_id), phase),
                session_id: message.session_id,
                epoch,
                message_id: message.message_id,
                attempt_id,
                expected_revision: message.revision,
                transition,
            })
            .await?
            .value()
            .clone())
    }
}

fn delivery_deadlines_are_valid(lease_duration: Duration, call_timeout: Duration) -> bool {
    !call_timeout.is_zero()
        && lease_duration > call_timeout.saturating_add(Duration::from_millis(10))
}

#[cfg(test)]
mod deadline_tests {
    use super::delivery_deadlines_are_valid;
    use std::time::Duration;

    #[test]
    fn driver_deadline_must_end_before_lease_expiry() {
        assert!(delivery_deadlines_are_valid(
            Duration::from_millis(21),
            Duration::from_millis(10)
        ));
        assert!(!delivery_deadlines_are_valid(
            Duration::from_millis(20),
            Duration::from_millis(10)
        ));
        assert!(!delivery_deadlines_are_valid(
            Duration::from_secs(1),
            Duration::ZERO
        ));
    }
}
