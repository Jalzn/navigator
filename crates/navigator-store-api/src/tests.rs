use super::{
    AcquireOwnership, CloseSession, EventReadLimit, LeaseDuration, MutableRequest, Mutation,
    OpenSession, OwnershipLease, ReleaseOwnership, RequestContext, StoreAction, StoredEffect,
    StoredRequest, StoredRequestOutcome, StoredResult,
};
use navigator_domain::{
    CompatibilityIdentity, ConsumerKey, FencingEpoch, HostId, IdentitySource, RequestId,
    SemanticDigest, SessionId, Timestamp,
};
use std::collections::HashMap;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lifecycle {
    Open,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReferenceModel {
    lifecycle: Lifecycle,
    ownership: Option<OwnershipLease>,
    next_epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelError {
    Closed,
    Held,
    Expired,
    Stale,
}

impl ReferenceModel {
    fn open() -> Self {
        Self {
            lifecycle: Lifecycle::Open,
            ownership: None,
            next_epoch: 1,
        }
    }

    fn close(
        &mut self,
        owner: HostId,
        epoch: FencingEpoch,
        now: Timestamp,
    ) -> Result<(), ModelError> {
        self.require_owner(owner, epoch, now)?;
        self.lifecycle = Lifecycle::Closed;
        Ok(())
    }

    fn acquire(
        &mut self,
        session_id: SessionId,
        owner: HostId,
        now: Timestamp,
        expires_at: Timestamp,
    ) -> Result<OwnershipLease, ModelError> {
        if self.lifecycle == Lifecycle::Closed {
            return Err(ModelError::Closed);
        }
        if self
            .ownership
            .as_ref()
            .is_some_and(|lease| lease.is_effective_at(now))
        {
            return Err(ModelError::Held);
        }
        let epoch = FencingEpoch::new(self.next_epoch).unwrap();
        self.next_epoch += 1;
        let lease = OwnershipLease::new(session_id, owner, epoch, now, expires_at).unwrap();
        self.ownership = Some(lease.clone());
        Ok(lease)
    }

    fn renew(
        &mut self,
        owner: HostId,
        epoch: FencingEpoch,
        now: Timestamp,
        expires_at: Timestamp,
    ) -> Result<OwnershipLease, ModelError> {
        self.require_owner(owner, epoch, now)?;
        let current = self.ownership.as_ref().unwrap();
        let lease = OwnershipLease::new(
            current.session_id(),
            current.owner(),
            current.epoch(),
            now,
            expires_at,
        )
        .unwrap();
        self.ownership = Some(lease.clone());
        Ok(lease)
    }

    fn require_owner(
        &self,
        owner: HostId,
        epoch: FencingEpoch,
        now: Timestamp,
    ) -> Result<(), ModelError> {
        let Some(lease) = &self.ownership else {
            return Err(ModelError::Stale);
        };
        if lease.epoch() != epoch || lease.owner() != owner {
            return Err(ModelError::Stale);
        }
        if !lease.is_effective_at(now) {
            return Err(ModelError::Expired);
        }
        Ok(())
    }
}

struct ReopensClosed(ReferenceModel);

impl ReopensClosed {
    fn acquire(
        &mut self,
        session_id: SessionId,
        owner: HostId,
        now: Timestamp,
        expires_at: Timestamp,
    ) -> Result<OwnershipLease, ModelError> {
        self.0.lifecycle = Lifecycle::Open;
        self.0.acquire(session_id, owner, now, expires_at)
    }
}

struct InclusiveExpiry(ReferenceModel);

impl InclusiveExpiry {
    fn require_owner(
        &self,
        owner: HostId,
        epoch: FencingEpoch,
        now: Timestamp,
    ) -> Result<(), ModelError> {
        let lease = self.0.ownership.as_ref().ok_or(ModelError::Stale)?;
        if lease.epoch() != epoch || lease.owner() != owner {
            return Err(ModelError::Stale);
        }
        if now > lease.expires_at() {
            return Err(ModelError::Expired);
        }
        Ok(())
    }
}

struct IgnoresFence(ReferenceModel);

impl IgnoresFence {
    fn renew(
        &mut self,
        owner: HostId,
        _epoch: FencingEpoch,
        now: Timestamp,
        expires_at: Timestamp,
    ) -> Result<OwnershipLease, ModelError> {
        let current = self.0.ownership.as_ref().ok_or(ModelError::Stale)?.epoch();
        self.0.renew(owner, current, now, expires_at)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RecordedRequest {
    caller: HostId,
    action: StoreAction,
    digest: SemanticDigest,
    result: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestError {
    Conflict,
}

#[derive(Default)]
struct IdempotentCounter {
    value: u64,
    requests: HashMap<RequestId, RecordedRequest>,
}

impl IdempotentCounter {
    fn apply(&mut self, request: &impl MutableRequest) -> Result<Mutation<u64>, RequestError> {
        let context = request.context();
        if let Some(persisted) = self.requests.get(&context.request_id()) {
            return if persisted.caller == context.caller()
                && persisted.action == request.action()
                && persisted.digest == request.digest()
            {
                Ok(Mutation::Replayed(persisted.result))
            } else {
                Err(RequestError::Conflict)
            };
        }
        self.value += 1;
        self.requests.insert(
            context.request_id(),
            RecordedRequest {
                caller: context.caller(),
                action: request.action(),
                digest: request.digest(),
                result: self.value,
            },
        );
        Ok(Mutation::Applied(self.value))
    }
}

struct ReappliesDuplicate(IdempotentCounter);

impl ReappliesDuplicate {
    fn apply(&mut self) -> Mutation<u64> {
        self.0.value += 1;
        Mutation::Applied(self.0.value)
    }
}

struct LeaseClock {
    floor: Timestamp,
    expires_at: Timestamp,
}

impl LeaseClock {
    fn effective(&mut self, observed_at: Timestamp) -> bool {
        self.floor = self.floor.max(observed_at);
        self.floor < self.expires_at
    }
}

struct AllowsClockResurrection {
    expires_at: Timestamp,
}

impl AllowsClockResurrection {
    fn effective(&self, observed_at: Timestamp) -> bool {
        observed_at < self.expires_at
    }
}

struct SequentialIds(u128);

impl IdentitySource for SequentialIds {
    fn next_uuid(&mut self) -> Uuid {
        self.0 += 1;
        Uuid::from_u128(self.0)
    }
}

fn identities() -> (SessionId, HostId, HostId, RequestId) {
    let mut source = SequentialIds(0);
    (
        SessionId::generate(&mut source).unwrap(),
        HostId::generate(&mut source).unwrap(),
        HostId::generate(&mut source).unwrap(),
        RequestId::generate(&mut source).unwrap(),
    )
}

fn at(seconds: i64) -> Timestamp {
    Timestamp::from_datetime(OffsetDateTime::from_unix_timestamp(seconds).unwrap())
}

fn open_command(context: RequestContext, session: SessionId, consumer: &str) -> OpenSession {
    OpenSession::new(
        context,
        session,
        ConsumerKey::new(consumer).unwrap(),
        CompatibilityIdentity::digest(b"compatibility"),
    )
}

#[test]
fn command_digest_is_derived_from_action_and_every_semantic_field() {
    let (session, host, _, request) = identities();
    let context = RequestContext::new(request, host);
    let original = open_command(context, session, "consumer-a");
    let changed = open_command(context, session, "consumer-b");
    assert_ne!(original.digest(), changed.digest());

    let epoch = FencingEpoch::new(1).unwrap();
    let close = CloseSession::new(context, session, epoch);
    let release = ReleaseOwnership::new(context, session, epoch);
    assert_ne!(close.digest(), release.digest());

    let short = AcquireOwnership::new(context, session, LeaseDuration::from_millis(1_000).unwrap());
    let long = AcquireOwnership::new(context, session, LeaseDuration::from_millis(2_000).unwrap());
    assert_ne!(short.digest(), long.digest());
}

#[test]
fn repeated_request_replays_once_and_global_identity_conflicts_across_callers() {
    let (session, first_host, second_host, request_id) = identities();
    let first = open_command(
        RequestContext::new(request_id, first_host),
        session,
        "consumer",
    );
    let other_caller = open_command(
        RequestContext::new(request_id, second_host),
        session,
        "consumer",
    );
    let mut model = IdempotentCounter::default();

    assert_eq!(model.apply(&first), Ok(Mutation::Applied(1)));
    assert_eq!(model.apply(&first), Ok(Mutation::Replayed(1)));
    assert_eq!(model.apply(&other_caller), Err(RequestError::Conflict));
    assert_eq!(model.value, 1);

    let mut mutant = ReappliesDuplicate(model);
    assert_eq!(mutant.apply(), Mutation::Applied(2));
}

#[test]
fn expiry_is_exclusive_and_equality_fences_the_owner() {
    let (session, owner, _, _) = identities();
    let now = at(1_800_000_000);
    let expires = at(1_800_000_010);
    let later = at(1_800_000_020);
    let mut model = ReferenceModel::open();
    let lease = model.acquire(session, owner, now, expires).unwrap();

    assert_eq!(
        model.renew(owner, lease.epoch(), expires, later),
        Err(ModelError::Expired)
    );
    assert!(
        InclusiveExpiry(model)
            .require_owner(owner, lease.epoch(), expires)
            .is_ok()
    );
}

#[test]
fn takeover_fences_the_previous_epoch_even_for_the_same_host() {
    let (session, owner, _, _) = identities();
    let mut model = ReferenceModel::open();
    let first = model.acquire(session, owner, at(100), at(101)).unwrap();
    let second = model.acquire(session, owner, at(101), at(111)).unwrap();

    assert_ne!(first.epoch(), second.epoch());
    assert_eq!(
        model.renew(owner, first.epoch(), at(101), at(120)),
        Err(ModelError::Stale)
    );
    assert!(
        IgnoresFence(model)
            .renew(owner, first.epoch(), at(101), at(120))
            .is_ok()
    );
}

#[test]
fn closed_is_permanent_and_cannot_be_reopened_by_acquire() {
    let (session, owner, _, _) = identities();
    let mut model = ReferenceModel::open();
    let lease = model.acquire(session, owner, at(100), at(110)).unwrap();
    model.close(owner, lease.epoch(), at(100)).unwrap();

    assert_eq!(
        model.acquire(session, owner, at(110), at(120)),
        Err(ModelError::Closed)
    );
    assert!(
        ReopensClosed(model)
            .acquire(session, owner, at(110), at(120))
            .is_ok()
    );
}

#[test]
fn persisted_time_floor_prevents_clock_regression_from_restoring_a_lease() {
    let before_expiry = at(109);
    let expiry = at(110);
    let mut clock = LeaseClock {
        floor: before_expiry,
        expires_at: expiry,
    };
    assert!(!clock.effective(expiry));
    assert!(!clock.effective(before_expiry));
    assert!(AllowsClockResurrection { expires_at: expiry }.effective(before_expiry));
}

#[test]
fn bounded_values_reject_invalid_edges() {
    assert!(LeaseDuration::from_millis(1).is_ok());
    assert!(LeaseDuration::from_millis(0).is_err());
    assert!(LeaseDuration::from_millis(i64::MAX as u64).is_ok());
    assert!(LeaseDuration::from_millis(i64::MAX as u64 + 1).is_err());
    assert!(EventReadLimit::new(1).is_ok());
    assert!(EventReadLimit::new(EventReadLimit::MAX).is_ok());
    assert!(EventReadLimit::new(0).is_err());
    assert!(EventReadLimit::new(EventReadLimit::MAX + 1).is_err());
}

#[test]
fn public_durable_records_reject_impossible_states() {
    let (session, host, _, request_id) = identities();
    let epoch = FencingEpoch::new(1).unwrap();
    assert!(OwnershipLease::new(session, host, epoch, at(100), at(100)).is_err());
    let lease = OwnershipLease::new(session, host, epoch, at(100), at(110)).unwrap();
    let command = ReleaseOwnership::new(RequestContext::new(request_id, host), session, epoch);

    assert!(
        StoredRequest::new(
            request_id,
            host,
            command.action(),
            command.digest(),
            StoredRequestOutcome::Succeeded {
                effect: StoredEffect::Applied,
                result: StoredResult::OwnershipLease(lease),
            },
        )
        .is_err()
    );
}
