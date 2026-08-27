use navigator_domain::{
    BoundedBytes, Capability, EffectClass, HostId, OperationId, ParticipantId, RequestId, SessionId,
};
use navigator_store_api::{
    AcquireOwnership, EffectJournalPhase, EffectJournalStore, EffectResolution,
    EffectResolutionContract, EffectTransition, LeaseDuration, RequestContext, ReserveEffect,
    SessionStore, StoreError, TakeoverEffect,
};
use std::future::Future;
use uuid::Uuid;

pub trait EffectJournalFixture {
    type Store: EffectJournalStore + SessionStore;
    fn store(&self) -> &Self::Store;
    fn set_wall_seconds(&self, seconds: i64);
    fn reopen(&mut self) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn prepare_linkage(
        &mut self,
    ) -> impl Future<Output = Result<(SessionId, HostId, ParticipantId, OperationId), String>> + Send;
}

#[allow(clippy::too_many_lines)]
pub async fn assert_effect_journal_contract<F: EffectJournalFixture>(
    f: &mut F,
) -> Result<(), String> {
    let (session, owner, participant, operation) = f.prepare_linkage().await?;
    let owner_b = id::<HostId>(906);
    f.set_wall_seconds(201);
    let lease = f
        .store()
        .acquire_ownership(AcquireOwnership::new(
            ctx(9903, owner),
            session,
            LeaseDuration::from_millis(10_000).unwrap(),
        ))
        .await
        .map_err(show)?
        .value()
        .clone();
    let action = Capability::new("tool.send").unwrap();
    let reserve = ReserveEffect::new(
        ctx(904, owner),
        session,
        participant,
        operation,
        lease.epoch(),
        action.clone(),
        br#"{"a":1}"#,
        EffectClass::NonIdempotent,
        EffectResolutionContract::conservative(),
        std::time::Duration::from_secs(10),
    );
    let first = f
        .store()
        .reserve_effect(reserve.clone())
        .await
        .map_err(show)?;
    f.reopen().await.map_err(|e| format!("reopen: {e}"))?;
    let replay = f
        .store()
        .reserve_effect(reserve)
        .await
        .map_err(|e| format!("replay: {e}"))?;
    if first != replay {
        return Err("NAV-RECOVERY-001 reservation did not survive replay".into());
    }
    let conflicting = ReserveEffect::new(
        ctx(904, owner),
        session,
        participant,
        operation,
        lease.epoch(),
        action.clone(),
        br#"{"a":2}"#,
        EffectClass::NonIdempotent,
        EffectResolutionContract::conservative(),
        std::time::Duration::from_secs(10),
    );
    if !matches!(
        f.store().reserve_effect(conflicting).await,
        Err(StoreError::RequestConflict { .. })
    ) {
        return Err("NAV-IDEMPOTENCY-001 semantic input reuse was accepted".into());
    }
    f.set_wall_seconds(211);
    let lease_b = f
        .store()
        .acquire_ownership(AcquireOwnership::new(
            ctx(907, owner_b),
            session,
            LeaseDuration::from_millis(60_000).unwrap(),
        ))
        .await
        .map_err(show)?
        .value()
        .clone();
    let taken = f
        .store()
        .takeover_effect(TakeoverEffect::new(
            ctx(908, owner_b),
            first.request_id,
            lease_b.epoch(),
            first.revision,
            std::time::Duration::from_secs(10),
        ))
        .await
        .map_err(show)?;
    if taken.owner_host != owner_b || taken.caller != owner {
        return Err("NAV-RECOVERY-001 takeover corrupted immutable caller/owner identity".into());
    }
    if !matches!(
        f.store()
            .start_effect(EffectTransition::start(
                ctx(909, owner),
                first.request_id,
                lease.epoch(),
                taken.revision
            ))
            .await,
        Err(StoreError::StaleOwnership { .. })
    ) {
        return Err("NAV-LEASE-001 old owner started taken-over effect".into());
    }
    let started = f
        .store()
        .start_effect(EffectTransition::start(
            ctx(910, owner_b),
            first.request_id,
            lease_b.epoch(),
            taken.revision,
        ))
        .await
        .map_err(show)?;
    f.set_wall_seconds(221);
    let observed = f
        .store()
        .takeover_effect(TakeoverEffect::new(
            ctx(911, owner_b),
            first.request_id,
            lease_b.epoch(),
            started.revision,
            std::time::Duration::from_secs(10),
        ))
        .await
        .map_err(show)?;
    if observed.phase != EffectJournalPhase::Uncertain || observed.revision == started.revision {
        return Err("NAV-RECOVERY-001 expired started effect was replayable".into());
    }
    let completed_command = EffectTransition::resolve(
        ctx(912, owner_b),
        first.request_id,
        lease_b.epoch(),
        observed.revision,
        EffectResolution::Completed(BoundedBytes::new(b"proof".to_vec()).unwrap()),
    );
    if !matches!(
        f.store().resolve_effect(completed_command).await,
        Err(StoreError::Invalid)
    ) || f
        .store()
        .read_effect(first.request_id)
        .await
        .map_err(show)?
        != Some(observed.clone())
    {
        return Err("NAV-AUTHORITY-001 uncertain effect bypassed authorized resolution".into());
    }
    let listed = f.store().list_effects(session).await.map_err(show)?;
    if listed.len() != 1 || listed[0].session_id != session {
        return Err("NAV-RECOVERY-001 deterministic effect inventory failed".into());
    }
    Ok(())
}
fn ctx(n: u128, h: HostId) -> RequestContext {
    RequestContext::new(id::<RequestId>(n), h)
}
trait FromUuid: Sized {
    fn make(u: Uuid) -> Self;
}
macro_rules! impl_id {
    ($t:ty) => {
        impl FromUuid for $t {
            fn make(u: Uuid) -> Self {
                <$t>::from_uuid(u).unwrap()
            }
        }
    };
}
impl_id!(SessionId);
impl_id!(HostId);
impl_id!(RequestId);
impl_id!(ParticipantId);
impl_id!(OperationId);
fn id<T: FromUuid>(n: u128) -> T {
    T::make(Uuid::from_u128(n))
}
#[allow(clippy::needless_pass_by_value)]
fn show(e: StoreError) -> String {
    e.to_string()
}
