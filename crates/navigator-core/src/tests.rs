use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use navigator_domain::{
    FencingEpoch, HostId, OwnershipSnapshot, RequestId, SessionId, SessionSnapshot, Timestamp,
};
use navigator_store_api::{
    AcquireOwnership, CloseSession, EventPage, LeaseDuration, Mutation, OpenSession,
    OwnershipLease, ReadEvents, ReleaseOwnership, RenewOwnership, RequestContext, SessionStore,
    StoreError, StoredRequest,
};
use time::{Duration, OffsetDateTime, macros::datetime};
use uuid::Uuid;

use super::*;

struct FakeClock(Mutex<OffsetDateTime>);

impl WallClock for FakeClock {
    fn now(&self) -> OffsetDateTime {
        *self.0.lock().unwrap()
    }
}

struct Factory {
    host: HostId,
}

struct ReleaseFactory {
    host: HostId,
}

impl ReleaseCommandFactory for ReleaseFactory {
    fn create(&self, lease: &OwnershipLease) -> Result<ReleaseOwnership, ReleaseCommandError> {
        Ok(ReleaseOwnership::new(
            RequestContext::new(request(32), self.host),
            lease.session_id(),
            lease.epoch(),
        ))
    }
}

fn release_factory() -> Arc<dyn ReleaseCommandFactory> {
    Arc::new(ReleaseFactory { host: host(2) })
}

impl RenewalCommandFactory for Factory {
    fn create(
        &self,
        lease: &OwnershipLease,
        duration: LeaseDuration,
    ) -> Result<RenewOwnership, RenewalCommandError> {
        let context = RequestContext::new(request(31), self.host);
        Ok(RenewOwnership::new(
            context,
            lease.session_id(),
            lease.epoch(),
            duration,
        ))
    }
}

struct FakeStore {
    renewal: Mutex<Result<OwnershipLease, StoreError>>,
    close_calls: AtomicUsize,
    release_calls: AtomicUsize,
    panic_renewal: bool,
    block_renewal: bool,
    renewal_entered: AtomicBool,
}

impl FakeStore {
    fn new(renewal: Result<OwnershipLease, StoreError>) -> Self {
        Self {
            renewal: Mutex::new(renewal),
            close_calls: AtomicUsize::new(0),
            release_calls: AtomicUsize::new(0),
            panic_renewal: false,
            block_renewal: false,
            renewal_entered: AtomicBool::new(false),
        }
    }

    fn panic_on_renewal(renewal: OwnershipLease) -> Self {
        Self {
            panic_renewal: true,
            ..Self::new(Ok(renewal))
        }
    }

    fn block_on_renewal(renewal: OwnershipLease) -> Self {
        Self {
            block_renewal: true,
            ..Self::new(Ok(renewal))
        }
    }
}

impl SessionStore for FakeStore {
    async fn open_session(&self, _: OpenSession) -> Result<Mutation<SessionSnapshot>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn close_session(
        &self,
        _: CloseSession,
    ) -> Result<Mutation<SessionSnapshot>, StoreError> {
        self.close_calls.fetch_add(1, Ordering::SeqCst);
        Err(StoreError::Unavailable)
    }
    async fn acquire_ownership(
        &self,
        _: AcquireOwnership,
    ) -> Result<Mutation<OwnershipLease>, StoreError> {
        Err(StoreError::Unavailable)
    }
    async fn renew_ownership(
        &self,
        _: RenewOwnership,
    ) -> Result<Mutation<OwnershipLease>, StoreError> {
        self.renewal_entered.store(true, Ordering::Release);
        assert!(!self.panic_renewal, "injected renewal panic");
        if self.block_renewal {
            std::future::pending::<()>().await;
        }
        self.renewal.lock().unwrap().clone().map(Mutation::Applied)
    }
    async fn release_ownership(
        &self,
        _: ReleaseOwnership,
    ) -> Result<Mutation<OwnershipSnapshot>, StoreError> {
        self.release_calls.fetch_add(1, Ordering::SeqCst);
        Err(StoreError::Unavailable)
    }
    async fn load_session(&self, session_id: SessionId) -> Result<SessionSnapshot, StoreError> {
        Err(StoreError::SessionNotFound { session_id })
    }
    async fn read_ownership(&self, _: SessionId) -> Result<OwnershipSnapshot, StoreError> {
        Ok(OwnershipSnapshot::Unowned)
    }
    async fn read_events(&self, _: ReadEvents) -> Result<EventPage, StoreError> {
        Ok(EventPage {
            events: vec![],
            last_position: None,
            has_more: false,
        })
    }
    async fn read_request(&self, _: RequestId) -> Result<Option<StoredRequest>, StoreError> {
        Ok(None)
    }
}

fn id<T>(n: u128, make: impl FnOnce(Uuid) -> Result<T, navigator_domain::InvalidIdentity>) -> T {
    make(Uuid::from_u128(n)).unwrap()
}

fn session(n: u128) -> SessionId {
    id(n, SessionId::from_uuid)
}
fn host(n: u128) -> HostId {
    id(n, HostId::from_uuid)
}
fn request(n: u128) -> RequestId {
    id(n, RequestId::from_uuid)
}

fn lease(expires_at: OffsetDateTime) -> OwnershipLease {
    lease_for(host(2), expires_at)
}

fn lease_for(owner: HostId, expires_at: OffsetDateTime) -> OwnershipLease {
    OwnershipLease::new(
        session(1),
        owner,
        FencingEpoch::new(1).unwrap(),
        Timestamp::from_datetime(expires_at - Duration::seconds(60)),
        Timestamp::from_datetime(expires_at),
    )
    .unwrap()
}

fn config() -> OwnershipConfig {
    OwnershipConfig {
        renewal_period: StdDuration::from_secs(10),
        lease_duration: LeaseDuration::from_millis(30_000).unwrap(),
        shutdown_timeout: StdDuration::from_secs(1),
    }
}

fn close_command() -> CloseSession {
    CloseSession::new(
        RequestContext::new(request(41), host(2)),
        session(1),
        FencingEpoch::new(1).unwrap(),
    )
}

#[tokio::test]
async fn renewal_failure_closes_admission_before_a_protected_write() {
    let now = datetime!(2026-01-01 0:00 UTC);
    let failed = StoreError::Unavailable;
    let store = Arc::new(FakeStore::new(Err(failed)));
    let supervisor = OwnershipSupervisor::start(
        Arc::clone(&store),
        Arc::new(FakeClock(Mutex::new(now))),
        Arc::new(Factory { host: host(2) }),
        release_factory(),
        lease(now + Duration::seconds(20)),
        config(),
    )
    .unwrap();

    let permit = supervisor.admission().admit().unwrap();
    assert!(supervisor.tick().await.is_err());
    assert!(!supervisor.admission().is_open());
    let service = SessionService::new(Arc::clone(&store));
    assert!(matches!(
        service.close(&permit, close_command()).await,
        Err(ServiceError::AdmissionClosed)
    ));
    assert_eq!(store.close_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn equality_at_expiry_revokes_without_calling_renewal() {
    let now = datetime!(2026-01-01 0:00 UTC);
    let renewed = lease(now + Duration::seconds(30));
    let store = Arc::new(FakeStore::new(Ok(renewed)));
    let clock = Arc::new(FakeClock(Mutex::new(now - Duration::seconds(11))));
    let supervisor = OwnershipSupervisor::start(
        Arc::clone(&store),
        Arc::clone(&clock),
        Arc::new(Factory { host: host(2) }),
        release_factory(),
        lease(now),
        config(),
    )
    .unwrap();
    *clock.0.lock().unwrap() = now;

    assert!(matches!(
        supervisor.tick().await,
        Err(ServiceError::AdmissionClosed)
    ));
    assert_eq!(
        supervisor.status(),
        OwnershipStatus::Lost {
            session_id: session(1),
            epoch: FencingEpoch::new(1).unwrap(),
            reason: OwnershipLoss::Expired
        }
    );
}

#[tokio::test]
async fn stale_epoch_is_reported_without_store_details() {
    let now = datetime!(2026-01-01 0:00 UTC);
    let store = Arc::new(FakeStore::new(Err(StoreError::StaleOwnership {
        session_id: session(1),
        attempted: FencingEpoch::new(1).unwrap(),
        current: Some(FencingEpoch::new(2).unwrap()),
    })));
    let supervisor = OwnershipSupervisor::start(
        store,
        Arc::new(FakeClock(Mutex::new(now))),
        Arc::new(Factory { host: host(2) }),
        release_factory(),
        lease(now + Duration::seconds(20)),
        config(),
    )
    .unwrap();

    assert!(supervisor.tick().await.is_err());
    assert_eq!(
        supervisor.status(),
        OwnershipStatus::Lost {
            session_id: session(1),
            epoch: FencingEpoch::new(1).unwrap(),
            reason: OwnershipLoss::Stale,
        }
    );
    assert!(!format!("{:?}", supervisor.status()).contains("current"));
}

#[tokio::test]
async fn clean_shutdown_closes_admission_and_joins_worker() {
    let now = datetime!(2026-01-01 0:00 UTC);
    let store = Arc::new(FakeStore::new(Ok(lease(now + Duration::seconds(40)))));
    let supervisor = OwnershipSupervisor::start(
        Arc::clone(&store),
        Arc::new(FakeClock(Mutex::new(now))),
        Arc::new(Factory { host: host(2) }),
        release_factory(),
        lease(now + Duration::seconds(20)),
        config(),
    )
    .unwrap();
    let admission = supervisor.admission();
    assert!(supervisor.is_worker_running());

    let outcome = supervisor.shutdown().await;
    assert!(outcome.task_terminated());
    assert_eq!(outcome.release(), ReleaseOutcome::Failed);
    assert_eq!(store.release_calls.load(Ordering::SeqCst), 1);
    assert!(!admission.is_open());
}

#[tokio::test]
async fn shutdown_after_store_cleared_ownership_does_not_release_twice() {
    let now = datetime!(2026-01-01 0:00 UTC);
    let store = Arc::new(FakeStore::new(Ok(lease(now + Duration::seconds(40)))));
    let supervisor = OwnershipSupervisor::start(
        Arc::clone(&store),
        Arc::new(FakeClock(Mutex::new(now))),
        Arc::new(Factory { host: host(2) }),
        release_factory(),
        lease(now + Duration::seconds(20)),
        config(),
    )
    .unwrap();
    let admission = supervisor.admission();

    assert!(supervisor.shutdown_after_ownership_cleared().await);
    assert_eq!(store.release_calls.load(Ordering::SeqCst), 0);
    assert!(!admission.is_open());
}

#[tokio::test]
async fn expired_initial_lease_and_late_renewal_schedule_are_rejected() {
    let now = datetime!(2026-01-01 0:00 UTC);
    let store = Arc::new(FakeStore::new(Ok(lease(now + Duration::seconds(30)))));
    let clock = Arc::new(FakeClock(Mutex::new(now)));
    let factory = Arc::new(Factory { host: host(2) });

    let expired = OwnershipSupervisor::start(
        Arc::clone(&store),
        Arc::clone(&clock),
        Arc::clone(&factory),
        release_factory(),
        lease(now),
        config(),
    );
    assert!(matches!(
        expired,
        Err(ServiceError::InvalidOwnershipConfiguration)
    ));

    let mut late = config();
    late.renewal_period = StdDuration::from_secs(20);
    let result = OwnershipSupervisor::start(
        store,
        clock,
        factory,
        release_factory(),
        lease(now + Duration::seconds(20)),
        late,
    );
    assert!(matches!(
        result,
        Err(ServiceError::InvalidOwnershipConfiguration)
    ));
}

#[tokio::test]
async fn renewed_lease_cannot_change_fencing_identity() {
    let now = datetime!(2026-01-01 0:00 UTC);
    let bad = lease_for(host(99), now + Duration::seconds(40));
    let store = Arc::new(FakeStore::new(Ok(bad)));
    let supervisor = OwnershipSupervisor::start(
        store,
        Arc::new(FakeClock(Mutex::new(now))),
        Arc::new(Factory { host: host(2) }),
        release_factory(),
        lease(now + Duration::seconds(20)),
        config(),
    )
    .unwrap();

    assert!(matches!(
        supervisor.tick().await,
        Err(ServiceError::InvalidRenewedLease)
    ));
    assert!(!supervisor.admission().is_open());
}

#[tokio::test]
async fn panic_in_critical_worker_fails_closed() {
    let now = datetime!(2026-01-01 0:00 UTC);
    let store = Arc::new(FakeStore::panic_on_renewal(lease(
        now + Duration::seconds(40),
    )));
    let mut fast = config();
    fast.renewal_period = StdDuration::from_nanos(1);
    let supervisor = OwnershipSupervisor::start(
        store,
        Arc::new(FakeClock(Mutex::new(now))),
        Arc::new(Factory { host: host(2) }),
        release_factory(),
        lease(now + Duration::seconds(20)),
        fast,
    )
    .unwrap();

    for _ in 0..1_000 {
        if !supervisor.is_worker_running() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(!supervisor.is_worker_running());
    assert!(!supervisor.admission().is_open());
    assert!(matches!(
        supervisor.status(),
        OwnershipStatus::Lost {
            reason: OwnershipLoss::RenewalFailed,
            ..
        }
    ));
}

#[tokio::test]
async fn stuck_worker_is_aborted_and_joined_within_shutdown_bound() {
    let now = datetime!(2026-01-01 0:00 UTC);
    let store = Arc::new(FakeStore::block_on_renewal(lease(
        now + Duration::seconds(40),
    )));
    let mut fast = config();
    fast.renewal_period = StdDuration::from_nanos(1);
    fast.shutdown_timeout = StdDuration::from_nanos(1);
    let supervisor = OwnershipSupervisor::start(
        Arc::clone(&store),
        Arc::new(FakeClock(Mutex::new(now))),
        Arc::new(Factory { host: host(2) }),
        release_factory(),
        lease(now + Duration::seconds(20)),
        fast,
    )
    .unwrap();

    for _ in 0..1_000 {
        if store.renewal_entered.load(Ordering::Acquire) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(store.renewal_entered.load(Ordering::Acquire));
    assert!(supervisor.shutdown().await.task_terminated());
}
