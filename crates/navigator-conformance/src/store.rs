use std::future::Future;

use navigator_domain::{
    CompatibilityIdentity, ConsumerKey, EventPosition, FencingEpoch, HostId, OwnershipSnapshot,
    RequestId, SessionId, SessionStatus,
};
use navigator_store_api::{
    AcquireOwnership, CloseSession, EventReadLimit, LeaseDuration, Mutation, OpenSession,
    ReadEvents, ReleaseOwnership, RenewOwnership, RequestContext, SessionStore, StoreError,
};
use uuid::Uuid;

pub const STORE_CONTRACT_SPECIFICATIONS: &[&str] = &[
    "NAV-SESSION-001",
    "NAV-IDEMPOTENCY-001",
    "NAV-LEASE-001",
    "NAV-EVENT-001",
    "NAV-TIME-001",
];

pub trait SessionStoreFixture {
    type Store: SessionStore;

    fn store(&self) -> &Self::Store;
    fn set_wall_seconds(&self, seconds: i64);
    fn reopen(&mut self) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[derive(Clone, Copy)]
struct ContractIds {
    session: SessionId,
    owner_a: HostId,
    owner_b: HostId,
}

impl ContractIds {
    fn new() -> Self {
        Self {
            session: session(1),
            owner_a: host(10),
            owner_b: host(11),
        }
    }
}

pub async fn assert_session_store_contract<F: SessionStoreFixture>(
    fixture: &mut F,
) -> Result<(), String> {
    let ids = ContractIds::new();
    fixture.set_wall_seconds(100);
    assert_lifecycle_and_idempotency(fixture.store(), ids).await?;
    assert_global_request_identity(fixture.store(), ids).await?;
    let first_epoch = assert_lease_semantics(fixture, ids).await?;
    assert_event_stream(fixture.store(), ids).await?;
    assert_time_floor_and_takeover(fixture, ids, first_epoch).await?;
    assert_close_is_permanent(fixture, ids).await
}

async fn assert_lifecycle_and_idempotency<S: SessionStore>(
    store: &S,
    ids: ContractIds,
) -> Result<(), String> {
    let command = open(100, ids.owner_a, ids.session, "consumer-a", 7);
    let created = store.open_session(command.clone()).await.map_err(display)?;
    ensure(
        matches!(created, Mutation::Applied(_)),
        "NAV-SESSION-001 create was not applied",
    )?;
    let snapshot = created.value();
    ensure(
        snapshot.status() == SessionStatus::Open,
        "NAV-SESSION-001 new Session is not open",
    )?;
    ensure(
        snapshot.revision().get() == 1,
        "NAV-SESSION-001 create revision is not one",
    )?;

    let replay = store.open_session(command).await.map_err(display)?;
    ensure(
        matches!(replay, Mutation::Replayed(_)),
        "NAV-IDEMPOTENCY-001 exact replay was not identified",
    )?;
    ensure(
        replay.value() == snapshot,
        "NAV-IDEMPOTENCY-001 replay changed the result",
    )?;

    let unchanged = store
        .open_session(open(101, ids.owner_a, ids.session, "consumer-a", 7))
        .await
        .map_err(display)?;
    ensure(
        matches!(unchanged, Mutation::Unchanged(_)),
        "NAV-SESSION-001 equivalent reopen should be unchanged",
    )?;
    ensure(
        unchanged.value().revision().get() == 1,
        "NAV-IDEMPOTENCY-001 unchanged reopen advanced revision",
    )?;

    ensure(
        matches!(
            store
                .open_session(open(102, ids.owner_a, ids.session, "consumer-b", 7))
                .await,
            Err(StoreError::ConsumerConflict { .. })
        ),
        "NAV-SESSION-001 conflicting Consumer identity was accepted",
    )?;
    ensure(
        matches!(
            store
                .open_session(open(103, ids.owner_a, ids.session, "consumer-a", 8))
                .await,
            Err(StoreError::CompatibilityConflict { .. })
        ),
        "NAV-SESSION-001 conflicting compatibility identity was accepted",
    )?;

    let events = all_events(store, ids.session).await?;
    ensure(
        events.len() == 1,
        "NAV-IDEMPOTENCY-001 replay or unchanged open emitted an Event",
    )?;
    ensure(
        events[0].event_type().as_str() == "session.created",
        "NAV-EVENT-001 first Event is not session.created",
    )
}

async fn assert_global_request_identity<S: SessionStore>(
    store: &S,
    ids: ContractIds,
) -> Result<(), String> {
    ensure(
        matches!(
            store
                .open_session(open(100, ids.owner_a, session(2), "consumer-a", 7))
                .await,
            Err(StoreError::RequestConflict { .. })
        ),
        "NAV-IDEMPOTENCY-001 Request identity was scoped by Session",
    )?;
    ensure(
        matches!(
            store
                .acquire_ownership(acquire(100, ids.owner_a, ids.session, 10_000))
                .await,
            Err(StoreError::RequestConflict { .. })
        ),
        "NAV-IDEMPOTENCY-001 Request identity was scoped by action",
    )?;
    ensure(
        matches!(
            store
                .open_session(open(100, ids.owner_b, ids.session, "consumer-a", 7))
                .await,
            Err(StoreError::RequestConflict { .. })
        ),
        "NAV-IDEMPOTENCY-001 Request identity ignored caller",
    )?;
    ensure(
        matches!(
            store
                .open_session(open(100, ids.owner_a, ids.session, "consumer-a", 9))
                .await,
            Err(StoreError::RequestConflict { .. })
        ),
        "NAV-IDEMPOTENCY-001 Request identity ignored semantic digest",
    )
}

async fn assert_lease_semantics<F: SessionStoreFixture>(
    fixture: &F,
    ids: ContractIds,
) -> Result<FencingEpoch, String> {
    let store = fixture.store();
    let acquired = store
        .acquire_ownership(acquire(200, ids.owner_a, ids.session, 20_000))
        .await
        .map_err(display)?;
    ensure(
        matches!(acquired, Mutation::Applied(_)),
        "NAV-LEASE-001 acquisition was not applied",
    )?;
    let lease = acquired.value();
    ensure(
        lease.owner() == ids.owner_a,
        "NAV-LEASE-001 acquisition recorded the wrong owner",
    )?;
    ensure(
        lease.epoch().get() == 1,
        "NAV-LEASE-001 first epoch is not one",
    )?;
    ensure(
        lease.expires_at().unix_seconds() == 120,
        "NAV-LEASE-001 lease expiry is not based on trusted time",
    )?;

    let before = store.load_session(ids.session).await.map_err(display)?;
    let before_events = all_events(store, ids.session).await?.len();
    let replay = store
        .acquire_ownership(acquire(200, ids.owner_a, ids.session, 20_000))
        .await
        .map_err(display)?;
    ensure(
        matches!(replay, Mutation::Replayed(_)),
        "NAV-IDEMPOTENCY-001 lease replay was not identified",
    )?;
    ensure(
        store
            .load_session(ids.session)
            .await
            .map_err(display)?
            .revision()
            == before.revision(),
        "NAV-IDEMPOTENCY-001 lease replay advanced revision",
    )?;
    ensure(
        all_events(store, ids.session).await?.len() == before_events,
        "NAV-IDEMPOTENCY-001 lease replay emitted an Event",
    )?;

    ensure(
        matches!(
            store
                .acquire_ownership(acquire(201, ids.owner_b, ids.session, 20_000))
                .await,
            Err(StoreError::OwnershipHeld { .. })
        ),
        "NAV-LEASE-001 a second live owner acquired the Session",
    )?;

    let renewed = store
        .renew_ownership(renew(202, ids.owner_a, ids.session, lease.epoch(), 60_000))
        .await
        .map_err(display)?;
    ensure(
        renewed.value().expires_at().unix_seconds() == 160,
        "NAV-LEASE-001 maximum lease was not accepted",
    )?;
    ensure(
        store
            .load_session(ids.session)
            .await
            .map_err(display)?
            .revision()
            == before.revision(),
        "NAV-LEASE-001 renewal advanced Session revision",
    )?;
    ensure(
        all_events(store, ids.session).await?.len() == before_events,
        "NAV-LEASE-001 renewal emitted an Event",
    )?;
    ensure(
        matches!(
            store
                .renew_ownership(renew(203, ids.owner_a, ids.session, lease.epoch(), 60_001))
                .await,
            Err(StoreError::LeaseTooLong)
        ),
        "NAV-LEASE-001 a lease above the configured maximum was accepted",
    )?;

    assert_release_and_reacquire(store, ids, lease.epoch()).await
}

async fn assert_release_and_reacquire<S: SessionStore>(
    store: &S,
    ids: ContractIds,
    epoch: FencingEpoch,
) -> Result<FencingEpoch, String> {
    let released = store
        .release_ownership(release(208, ids.owner_a, ids.session, epoch))
        .await
        .map_err(display)?;
    ensure(
        matches!(released, Mutation::Applied(OwnershipSnapshot::Unowned)),
        "NAV-LEASE-001 release did not make the Session unowned",
    )?;
    let released_revision = store
        .load_session(ids.session)
        .await
        .map_err(display)?
        .revision();
    let released_events = all_events(store, ids.session).await?.len();
    ensure(
        matches!(
            store
                .release_ownership(release(208, ids.owner_a, ids.session, epoch))
                .await
                .map_err(display)?,
            Mutation::Replayed(OwnershipSnapshot::Unowned)
        ),
        "NAV-IDEMPOTENCY-001 release replay was not identified",
    )?;
    ensure(
        store
            .load_session(ids.session)
            .await
            .map_err(display)?
            .revision()
            == released_revision,
        "NAV-IDEMPOTENCY-001 release replay advanced revision",
    )?;
    ensure(
        all_events(store, ids.session).await?.len() == released_events,
        "NAV-IDEMPOTENCY-001 release replay emitted an Event",
    )?;

    let reacquired = store
        .acquire_ownership(acquire(209, ids.owner_a, ids.session, 60_000))
        .await
        .map_err(display)?;
    ensure(
        reacquired.value().epoch().get() == epoch.get() + 1,
        "NAV-LEASE-001 reacquisition reused a fencing epoch",
    )?;
    Ok(reacquired.value().epoch())
}

async fn assert_event_stream<S: SessionStore>(store: &S, ids: ContractIds) -> Result<(), String> {
    let first = store
        .read_events(ReadEvents {
            session_id: ids.session,
            consumer: consumer(),
            after: None,
            limit: EventReadLimit::new(2).expect("valid fixture limit"),
        })
        .await
        .map_err(display)?;
    ensure(
        first.events.len() == 2 && first.has_more,
        "NAV-EVENT-001 first page metadata is incorrect",
    )?;
    ensure(
        first.last_position == Some(EventPosition::new(2).expect("valid fixture cursor")),
        "NAV-EVENT-001 first page cursor is incorrect",
    )?;
    ensure(
        first.events[0].event_type().as_str() == "session.created"
            && first.events[1].event_type().as_str() == "ownership.acquired",
        "NAV-EVENT-001 initial Event order is incorrect",
    )?;
    let second = store
        .read_events(ReadEvents {
            session_id: ids.session,
            consumer: consumer(),
            after: first.last_position,
            limit: EventReadLimit::new(2).expect("valid fixture limit"),
        })
        .await
        .map_err(display)?;
    ensure(
        second.events.len() == 2 && !second.has_more,
        "NAV-EVENT-001 second page metadata is incorrect",
    )?;
    ensure(
        second.events[0].position().get() == 3 && second.events[1].position().get() == 4,
        "NAV-EVENT-001 positions are not contiguous",
    )?;
    ensure(
        second.events[0].event_type().as_str() == "ownership.released"
            && second.events[1].event_type().as_str() == "ownership.acquired",
        "NAV-EVENT-001 release/reacquisition Event order is incorrect",
    )?;
    ensure(
        second.events[0].revision().get() == 3 && second.events[1].revision().get() == 4,
        "NAV-EVENT-001 Event revision does not match committed state",
    )?;
    let beyond = store
        .read_events(ReadEvents {
            session_id: ids.session,
            consumer: consumer(),
            after: Some(EventPosition::new(999).expect("valid fixture cursor")),
            limit: EventReadLimit::new(3).expect("valid fixture limit"),
        })
        .await
        .map_err(display)?;
    ensure(
        beyond.events.is_empty() && beyond.last_position.is_none() && !beyond.has_more,
        "NAV-EVENT-001 read beyond head was not empty",
    )
}

async fn assert_time_floor_and_takeover<F: SessionStoreFixture>(
    fixture: &mut F,
    ids: ContractIds,
    old_epoch: FencingEpoch,
) -> Result<(), String> {
    fixture.set_wall_seconds(159);
    ensure(
        matches!(
            fixture
                .store()
                .acquire_ownership(acquire(204, ids.owner_b, ids.session, 5_000))
                .await,
            Err(StoreError::OwnershipHeld { .. })
        ),
        "NAV-LEASE-001 live lease was treated as expired",
    )?;
    fixture.reopen().await.map_err(display)?;
    fixture.set_wall_seconds(90);
    let renewed = fixture
        .store()
        .renew_ownership(renew(205, ids.owner_a, ids.session, old_epoch, 10_000))
        .await
        .map_err(display)?;
    ensure(
        renewed.value().expires_at().unix_seconds() == 169,
        "NAV-TIME-001 clock regression crossed durable time floor",
    )?;

    fixture.set_wall_seconds(169);
    let takeover = fixture
        .store()
        .acquire_ownership(acquire(206, ids.owner_b, ids.session, 10_000))
        .await
        .map_err(display)?;
    ensure(
        takeover.value().epoch().get() == old_epoch.get() + 1,
        "NAV-LEASE-001 takeover did not advance fencing epoch",
    )?;
    ensure(
        matches!(
            fixture
                .store()
                .release_ownership(release(207, ids.owner_a, ids.session, old_epoch))
                .await,
            Err(StoreError::StaleOwnership { .. })
        ),
        "NAV-LEASE-001 stale owner committed after takeover",
    )?;
    ensure(
        matches!(
            fixture.store().read_ownership(ids.session).await.map_err(display)?,
            OwnershipSnapshot::Owned { host_id, epoch, .. }
                if host_id == ids.owner_b && epoch == takeover.value().epoch()
        ),
        "NAV-LEASE-001 rejected stale write changed ownership",
    )?;
    Ok(())
}

async fn assert_close_is_permanent<F: SessionStoreFixture>(
    fixture: &mut F,
    ids: ContractIds,
) -> Result<(), String> {
    let epoch = match fixture
        .store()
        .read_ownership(ids.session)
        .await
        .map_err(display)?
    {
        OwnershipSnapshot::Owned { epoch, .. } => epoch,
        OwnershipSnapshot::Unowned => {
            return Err("NAV-LEASE-001 owner disappeared before close".into());
        }
    };
    let close = close(300, ids.owner_b, ids.session, epoch);
    let closed = fixture
        .store()
        .close_session(close.clone())
        .await
        .map_err(display)?;
    ensure(
        closed.value().status() == SessionStatus::Closed,
        "NAV-SESSION-001 close did not persist closed status",
    )?;
    ensure(
        matches!(
            fixture
                .store()
                .read_ownership(ids.session)
                .await
                .map_err(display)?,
            OwnershipSnapshot::Unowned
        ),
        "NAV-SESSION-001 close did not release ownership",
    )?;
    let revision = closed.value().revision();
    let event_count = all_events(fixture.store(), ids.session).await?.len();
    ensure(
        matches!(
            fixture
                .store()
                .close_session(close)
                .await
                .map_err(display)?,
            Mutation::Replayed(_)
        ),
        "NAV-IDEMPOTENCY-001 close replay was not identified",
    )?;
    ensure(
        fixture
            .store()
            .load_session(ids.session)
            .await
            .map_err(display)?
            .revision()
            == revision,
        "NAV-IDEMPOTENCY-001 close replay advanced revision",
    )?;
    ensure(
        all_events(fixture.store(), ids.session).await?.len() == event_count,
        "NAV-IDEMPOTENCY-001 close replay emitted an Event",
    )?;
    ensure(
        matches!(
            fixture
                .store()
                .acquire_ownership(acquire(301, ids.owner_a, ids.session, 1_000))
                .await,
            Err(StoreError::SessionClosed { .. })
        ),
        "NAV-SESSION-001 closed Session accepted ownership",
    )?;
    fixture.reopen().await.map_err(display)?;
    ensure(
        fixture
            .store()
            .load_session(ids.session)
            .await
            .map_err(display)?
            .status()
            == SessionStatus::Closed,
        "NAV-SESSION-001 logical close did not survive reopen",
    )?;
    ensure(
        all_events(fixture.store(), ids.session).await?.len() == event_count,
        "NAV-SESSION-001 history changed across reopen",
    )
}

async fn all_events<S: SessionStore>(
    store: &S,
    session_id: SessionId,
) -> Result<Vec<navigator_domain::SessionEvent>, String> {
    store
        .read_events(ReadEvents {
            session_id,
            consumer: consumer(),
            after: None,
            limit: EventReadLimit::new(EventReadLimit::MAX).expect("maximum is valid"),
        })
        .await
        .map(|page| page.events)
        .map_err(display)
}

fn open(request: u128, caller: HostId, id: SessionId, key: &str, compatibility: u8) -> OpenSession {
    OpenSession::new(
        context(request, caller),
        id,
        ConsumerKey::new(key).expect("valid fixture Consumer key"),
        CompatibilityIdentity::from_bytes([compatibility; 32]),
    )
}

fn acquire(request: u128, caller: HostId, id: SessionId, millis: u64) -> AcquireOwnership {
    AcquireOwnership::new(context(request, caller), id, duration(millis))
}

fn renew(
    request: u128,
    caller: HostId,
    id: SessionId,
    epoch: FencingEpoch,
    millis: u64,
) -> RenewOwnership {
    RenewOwnership::new(context(request, caller), id, epoch, duration(millis))
}

fn release(request: u128, caller: HostId, id: SessionId, epoch: FencingEpoch) -> ReleaseOwnership {
    ReleaseOwnership::new(context(request, caller), id, epoch)
}

fn close(request: u128, caller: HostId, id: SessionId, epoch: FencingEpoch) -> CloseSession {
    CloseSession::new(context(request, caller), id, epoch)
}

fn duration(millis: u64) -> LeaseDuration {
    LeaseDuration::from_millis(millis).expect("positive fixture lease duration")
}

fn context(request: u128, caller: HostId) -> RequestContext {
    RequestContext::new(request_id(request), caller)
}

fn request_id(value: u128) -> RequestId {
    RequestId::from_uuid(Uuid::from_u128(value)).expect("non-nil fixture Request identity")
}

fn session(value: u128) -> SessionId {
    SessionId::from_uuid(Uuid::from_u128(value)).expect("non-nil fixture Session identity")
}

fn host(value: u128) -> HostId {
    HostId::from_uuid(Uuid::from_u128(value)).expect("non-nil fixture Host identity")
}

fn consumer() -> ConsumerKey {
    ConsumerKey::new("consumer-a").expect("valid fixture Consumer key")
}

fn ensure(condition: bool, message: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn display(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
    struct Attempt {
        session: u8,
        request: u8,
        semantics: u8,
    }

    trait LedgerSubject {
        fn execute(&mut self, attempt: Attempt) -> bool;
    }

    #[derive(Default)]
    struct GlobalLedger(BTreeMap<u8, u8>);

    impl LedgerSubject for GlobalLedger {
        fn execute(&mut self, attempt: Attempt) -> bool {
            if let Some(semantics) = self.0.get(&attempt.request) {
                *semantics == attempt.semantics
            } else {
                self.0.insert(attempt.request, attempt.semantics);
                true
            }
        }
    }

    #[derive(Default)]
    struct SessionScopedLedger(BTreeMap<(u8, u8), u8>);

    impl LedgerSubject for SessionScopedLedger {
        fn execute(&mut self, attempt: Attempt) -> bool {
            if let Some(semantics) = self.0.get(&(attempt.session, attempt.request)) {
                *semantics == attempt.semantics
            } else {
                self.0
                    .insert((attempt.session, attempt.request), attempt.semantics);
                true
            }
        }
    }

    fn global_identity_oracle(subject: &mut impl LedgerSubject) -> Result<(), &'static str> {
        let first = Attempt {
            session: 1,
            request: 7,
            semantics: 10,
        };
        let conflict = Attempt {
            session: 2,
            request: 7,
            semantics: 11,
        };
        if !subject.execute(first) || subject.execute(conflict) {
            return Err("NAV-IDEMPOTENCY-001 global conflict was not preserved");
        }
        Ok(())
    }

    #[test]
    fn global_request_oracle_accepts_correct_ledger_and_rejects_session_scoped_mutant() {
        global_identity_oracle(&mut GlobalLedger::default()).expect("reference ledger conforms");
        assert!(global_identity_oracle(&mut SessionScopedLedger::default()).is_err());
    }
}
