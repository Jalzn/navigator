//! Runtime-neutral Navigator orchestration services.

use std::{
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration as StdDuration,
};

use navigator_domain::{FencingEpoch, SessionId, SessionSnapshot, Timestamp};
use navigator_store_api::{
    AcquireOwnership, CloseSession, EventPage, LeaseDuration, Mutation, OpenSession,
    OwnershipLease, ReadEvents, ReleaseOwnership, RenewOwnership, SessionStore, StoreError,
};
use thiserror::Error;
use tokio::{sync::watch, task::JoinHandle};

mod first_operation;
pub use first_operation::*;
mod delivery;
pub use delivery::*;
mod hierarchy;
mod recovery;
pub use hierarchy::*;
pub use recovery::*;

#[derive(Clone)]
pub struct SessionService<S> {
    store: Arc<S>,
}

impl<S: SessionStore> SessionService<S> {
    #[must_use]
    pub const fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    pub async fn open(
        &self,
        command: OpenSession,
    ) -> Result<Mutation<SessionSnapshot>, StoreError> {
        self.store.open_session(command).await
    }

    pub async fn snapshot(&self, session_id: SessionId) -> Result<SessionSnapshot, StoreError> {
        self.store.load_session(session_id).await
    }

    pub async fn close(
        &self,
        permit: &AdmissionPermit,
        command: CloseSession,
    ) -> Result<Mutation<SessionSnapshot>, ServiceError> {
        permit.check()?;
        self.store.close_session(command).await.map_err(Into::into)
    }

    pub async fn events(&self, query: ReadEvents) -> Result<EventPage, StoreError> {
        self.store.read_events(query).await
    }
}

#[derive(Debug)]
struct AdmissionState {
    open: AtomicBool,
    generation: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct AdmissionGate(Arc<AdmissionState>);

#[derive(Clone, Debug)]
pub struct AdmissionPermit {
    state: Arc<AdmissionState>,
    generation: u64,
}

impl AdmissionGate {
    fn open() -> Self {
        Self(Arc::new(AdmissionState {
            open: AtomicBool::new(true),
            generation: AtomicU64::new(1),
        }))
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        self.0.open.load(Ordering::Acquire)
    }

    pub fn admit(&self) -> Result<AdmissionPermit, ServiceError> {
        let generation = self.0.generation.load(Ordering::Acquire);
        let permit = AdmissionPermit {
            state: Arc::clone(&self.0),
            generation,
        };
        permit.check()?;
        Ok(permit)
    }

    fn close(&self) {
        self.0.open.store(false, Ordering::Release);
        self.0.generation.fetch_add(1, Ordering::AcqRel);
    }
}

impl AdmissionPermit {
    pub fn check(&self) -> Result<(), ServiceError> {
        if self.state.open.load(Ordering::Acquire)
            && self.state.generation.load(Ordering::Acquire) == self.generation
        {
            Ok(())
        } else {
            Err(ServiceError::AdmissionClosed)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipLoss {
    Expired,
    RenewalFailed,
    Stale,
    Shutdown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnershipStatus {
    Active {
        session_id: SessionId,
        epoch: FencingEpoch,
        expires_at: Timestamp,
    },
    Lost {
        session_id: SessionId,
        epoch: FencingEpoch,
        reason: OwnershipLoss,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct OwnershipConfig {
    pub renewal_period: StdDuration,
    pub lease_duration: LeaseDuration,
    pub shutdown_timeout: StdDuration,
}

pub trait WallClock: Send + Sync + 'static {
    fn now(&self) -> time::OffsetDateTime;
}

pub trait RenewalCommandFactory: Send + Sync + 'static {
    fn create(
        &self,
        lease: &OwnershipLease,
        duration: LeaseDuration,
    ) -> Result<RenewOwnership, RenewalCommandError>;
}

pub trait ReleaseCommandFactory: Send + Sync + 'static {
    fn create(&self, lease: &OwnershipLease) -> Result<ReleaseOwnership, ReleaseCommandError>;
}

#[derive(Clone, Copy, Debug, Error)]
#[error("renewal command construction failed")]
pub struct RenewalCommandError;

#[derive(Clone, Copy, Debug, Error)]
#[error("release command construction failed")]
pub struct ReleaseCommandError;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("session admission is closed")]
    AdmissionClosed,
    #[error("ownership configuration is invalid")]
    InvalidOwnershipConfiguration,
    #[error("ownership renewal command could not be created")]
    RenewalCommand,
    #[error("ownership release command could not be created")]
    ReleaseCommand,
    #[error("store returned an invalid renewed lease")]
    InvalidRenewedLease,
    #[error(transparent)]
    Store(#[from] StoreError),
}

struct OwnershipState<S, C, F> {
    store: Arc<S>,
    clock: Arc<C>,
    factory: Arc<F>,
    release_factory: Arc<dyn ReleaseCommandFactory>,
    config: OwnershipConfig,
    lease: Mutex<OwnershipLease>,
    admission: AdmissionGate,
    status: Arc<RwLock<OwnershipStatus>>,
    worker_running: Arc<AtomicBool>,
}

struct WorkerGuard {
    running: Arc<AtomicBool>,
    admission: AdmissionGate,
    status: Arc<RwLock<OwnershipStatus>>,
    session_id: SessionId,
    epoch: FencingEpoch,
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if self.admission.is_open() {
            self.admission.close();
            *self.status.write().expect("ownership status poisoned") = OwnershipStatus::Lost {
                session_id: self.session_id,
                epoch: self.epoch,
                reason: OwnershipLoss::RenewalFailed,
            };
        }
    }
}

impl<S: SessionStore, C: WallClock, F: RenewalCommandFactory> OwnershipState<S, C, F> {
    async fn tick(&self) -> Result<(), ServiceError> {
        if !self.admission.is_open() {
            return Err(ServiceError::AdmissionClosed);
        }
        let now = self.clock.now();
        let lease = self.lease.lock().expect("ownership lease poisoned").clone();
        let observed_at = Timestamp::from_datetime(now);
        if observed_at >= lease.expires_at() {
            self.lose(&lease, OwnershipLoss::Expired);
            return Err(ServiceError::AdmissionClosed);
        }
        let command = self
            .factory
            .create(&lease, self.config.lease_duration)
            .map_err(|_| {
                self.lose(&lease, OwnershipLoss::RenewalFailed);
                ServiceError::RenewalCommand
            })?;
        match self.store.renew_ownership(command).await {
            Ok(mutation) => {
                let renewed = mutation.value().clone();
                let valid = renewed.session_id() == lease.session_id()
                    && renewed.owner() == lease.owner()
                    && renewed.epoch() == lease.epoch()
                    && renewed.expires_at() > Timestamp::from_datetime(self.clock.now());
                if !valid {
                    self.lose(&lease, OwnershipLoss::RenewalFailed);
                    return Err(ServiceError::InvalidRenewedLease);
                }
                *self.lease.lock().expect("ownership lease poisoned") = renewed.clone();
                *self.status.write().expect("ownership status poisoned") =
                    OwnershipStatus::Active {
                        session_id: renewed.session_id(),
                        epoch: renewed.epoch(),
                        expires_at: renewed.expires_at(),
                    };
                Ok(())
            }
            Err(error) => {
                let reason = if matches!(error, StoreError::StaleOwnership { .. }) {
                    OwnershipLoss::Stale
                } else {
                    OwnershipLoss::RenewalFailed
                };
                self.lose(&lease, reason);
                Err(ServiceError::Store(error))
            }
        }
    }

    fn lose(&self, lease: &OwnershipLease, reason: OwnershipLoss) {
        self.admission.close();
        *self.status.write().expect("ownership status poisoned") = OwnershipStatus::Lost {
            session_id: lease.session_id(),
            epoch: lease.epoch(),
            reason,
        };
    }
}

pub struct OwnershipSupervisor<S, C, F> {
    state: Arc<OwnershipState<S, C, F>>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl<S, C, F> OwnershipSupervisor<S, C, F>
where
    S: SessionStore + 'static,
    C: WallClock,
    F: RenewalCommandFactory,
{
    pub fn start(
        store: Arc<S>,
        clock: Arc<C>,
        factory: Arc<F>,
        release_factory: Arc<dyn ReleaseCommandFactory>,
        lease: OwnershipLease,
        config: OwnershipConfig,
    ) -> Result<Self, ServiceError> {
        if config.renewal_period.is_zero() || config.shutdown_timeout.is_zero() {
            return Err(ServiceError::InvalidOwnershipConfiguration);
        }
        let now = clock.now();
        let expiry = lease
            .expires_at()
            .to_datetime()
            .map_err(|_| ServiceError::InvalidOwnershipConfiguration)?;
        let remaining = expiry - now;
        let remaining = StdDuration::try_from(remaining)
            .map_err(|_| ServiceError::InvalidOwnershipConfiguration)?;
        if config.renewal_period >= remaining {
            return Err(ServiceError::InvalidOwnershipConfiguration);
        }
        let admission = AdmissionGate::open();
        let status = OwnershipStatus::Active {
            session_id: lease.session_id(),
            epoch: lease.epoch(),
            expires_at: lease.expires_at(),
        };
        let session_id = lease.session_id();
        let epoch = lease.epoch();
        let state = Arc::new(OwnershipState {
            store,
            clock,
            factory,
            release_factory,
            config,
            lease: Mutex::new(lease),
            admission,
            status: Arc::new(RwLock::new(status)),
            worker_running: Arc::new(AtomicBool::new(true)),
        });
        let (stop, mut stopped) = watch::channel(false);
        let worker = Arc::clone(&state);
        let running = WorkerGuard {
            running: Arc::clone(&state.worker_running),
            admission: state.admission.clone(),
            status: Arc::clone(&state.status),
            session_id,
            epoch,
        };
        let task = tokio::spawn(async move {
            let _running = running;
            loop {
                tokio::select! {
                    changed = stopped.changed() => { if changed.is_err() || *stopped.borrow() { break; } }
                    () = tokio::time::sleep(worker.config.renewal_period) => { if worker.tick().await.is_err() { break; } }
                }
            }
        });
        Ok(Self {
            state,
            stop,
            task: Some(task),
        })
    }

    #[must_use]
    pub fn admission(&self) -> AdmissionGate {
        self.state.admission.clone()
    }

    #[must_use]
    pub fn status(&self) -> OwnershipStatus {
        *self.state.status.read().expect("ownership status poisoned")
    }

    #[must_use]
    pub fn is_worker_running(&self) -> bool {
        self.state.worker_running.load(Ordering::Acquire)
    }

    pub async fn tick(&self) -> Result<(), ServiceError> {
        self.state.tick().await
    }

    pub async fn shutdown(mut self) -> ShutdownOutcome {
        let lease = self
            .state
            .lease
            .lock()
            .expect("ownership lease poisoned")
            .clone();
        self.state.lose(&lease, OwnershipLoss::Shutdown);
        let _ = self.stop.send(true);
        if let Some(mut task) = self.task.take() {
            if tokio::time::timeout(self.state.config.shutdown_timeout, &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
        let release = match self.state.release_factory.create(&lease) {
            Ok(command) => match tokio::time::timeout(
                self.state.config.shutdown_timeout,
                self.state.store.release_ownership(command),
            )
            .await
            {
                Ok(Ok(_)) => ReleaseOutcome::Released,
                Ok(Err(_)) => ReleaseOutcome::Failed,
                Err(_) => ReleaseOutcome::TimedOut,
            },
            Err(_) => ReleaseOutcome::CommandFailed,
        };
        ShutdownOutcome {
            task_terminated: !self.state.worker_running.load(Ordering::Acquire),
            release,
        }
    }

    /// Stops supervision without releasing; the Store must already have cleared ownership.
    pub async fn shutdown_after_ownership_cleared(mut self) -> bool {
        let lease = self
            .state
            .lease
            .lock()
            .expect("ownership lease poisoned")
            .clone();
        self.state.lose(&lease, OwnershipLoss::Shutdown);
        let _ = self.stop.send(true);
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(self.state.config.shutdown_timeout, &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ = task.await;
        }
        !self.state.worker_running.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownOutcome {
    task_terminated: bool,
    release: ReleaseOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseOutcome {
    Released,
    Failed,
    TimedOut,
    CommandFailed,
}

impl ShutdownOutcome {
    #[must_use]
    pub const fn task_terminated(self) -> bool {
        self.task_terminated
    }

    #[must_use]
    pub const fn release(self) -> ReleaseOutcome {
        self.release
    }
}

impl<S, C, F> Drop for OwnershipSupervisor<S, C, F> {
    fn drop(&mut self) {
        self.state.admission.close();
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

pub struct OwnershipManager<S> {
    store: Arc<S>,
}

impl<S: SessionStore> OwnershipManager<S> {
    #[must_use]
    pub const fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    pub async fn acquire(&self, command: AcquireOwnership) -> Result<OwnershipLease, StoreError> {
        self.store
            .acquire_ownership(command)
            .await
            .map(|mutation| mutation.value().clone())
    }

    pub async fn release(
        &self,
        command: ReleaseOwnership,
    ) -> Result<navigator_domain::OwnershipSnapshot, StoreError> {
        self.store
            .release_ownership(command)
            .await
            .map(|mutation| mutation.value().clone())
    }
}

#[cfg(test)]
mod tests;
