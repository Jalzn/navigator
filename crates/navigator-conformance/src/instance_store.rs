use navigator_domain::{
    CompatibilityIdentity, ConsumerKey, DriverId, FencingEpoch, HostId, InstanceId,
    LaunchAttemptId, ParticipantId, RequestId, Revision, SessionId,
};
use navigator_store_api::{
    AcquireOwnership, AttachLaunch, InstanceStore, LaunchState, LeaseDuration, Mutation,
    OpenSession, PrepareLaunch, ProcessEvidence, RequestContext, SessionStore, StoreError,
    TransitionLaunch,
};
use uuid::Uuid;

pub trait InstanceStoreFixture {
    type Store: InstanceStore;

    fn store(&self) -> &Self::Store;
    fn set_wall_seconds(&self, seconds: i64);
    fn reopen(&mut self) -> impl Future<Output = Result<(), StoreError>> + Send;
}

pub async fn assert_instance_store_contract<F: InstanceStoreFixture>(
    fixture: &mut F,
) -> Result<(), String> {
    let store = fixture.store();
    let session = session(700);
    let owner = host(701);
    store
        .open_session(OpenSession::new(
            context(702, owner),
            session,
            ConsumerKey::new("instance-contract").map_err(debug)?,
            CompatibilityIdentity::from_bytes([4; 32]),
        ))
        .await
        .map_err(debug)?;
    let lease = store
        .acquire_ownership(AcquireOwnership::new(
            context(703, owner),
            session,
            LeaseDuration::from_millis(20_000).map_err(debug)?,
        ))
        .await
        .map_err(debug)?
        .value()
        .clone();
    let attempt = LaunchAttemptId::from_uuid(Uuid::from_u128(704)).map_err(debug)?;
    assert_prepare_and_attach(store, session, owner, lease.epoch(), attempt).await?;
    assert_transitions(store, session, owner, lease.epoch(), attempt).await?;
    fixture.set_wall_seconds(120);
    assert_fencing(fixture.store(), session, owner, lease.epoch()).await?;
    assert_cross_identity_conflicts(fixture.store(), session, attempt).await?;
    fixture.reopen().await.map_err(debug)?;
    let persisted = fixture.store().load_launch(attempt).await.map_err(debug)?;
    if persisted.state != LaunchState::Stopped
        || persisted.instance_id
            != Some(InstanceId::from_uuid(Uuid::from_u128(709)).map_err(debug)?)
    {
        return Err("terminal launch snapshot did not survive reopen".into());
    }
    Ok(())
}

async fn assert_prepare_and_attach<S: InstanceStore>(
    store: &S,
    session: SessionId,
    owner: HostId,
    epoch: FencingEpoch,
    attempt: LaunchAttemptId,
) -> Result<(), String> {
    let prepare = PrepareLaunch {
        context: context(705, owner),
        epoch,
        session_id: session,
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(706)).map_err(debug)?,
        driver_id: DriverId::from_uuid(Uuid::from_u128(707)).map_err(debug)?,
        attempt_id: attempt,
        credential_digest: [8; 32],
        driver_configuration_digest: [18; 32],
    };
    if !matches!(
        store.prepare_launch(prepare.clone()).await,
        Ok(Mutation::Applied(_))
    ) {
        return Err("prepare did not atomically apply".into());
    }
    if !matches!(
        store.prepare_launch(prepare.clone()).await,
        Ok(Mutation::Replayed(_))
    ) {
        return Err("prepare was not globally replayable".into());
    }
    let mut changed_configuration = prepare;
    changed_configuration.driver_configuration_digest = [19; 32];
    if !matches!(
        store.prepare_launch(changed_configuration).await,
        Err(StoreError::RequestConflict { .. })
    ) {
        return Err("prepare replay accepted a changed Driver configuration".into());
    }
    let mut attach = AttachLaunch {
        context: context(708, owner),
        session_id: session,
        epoch,
        attempt_id: attempt,
        expected_revision: Revision::initial(),
        instance_id: InstanceId::from_uuid(Uuid::from_u128(709)).map_err(debug)?,
        evidence: ProcessEvidence {
            process_id: 0,
            process_group_id: 1,
            parent_process_id: 1,
            creation_marker: 1,
            executable_identity: [1; 32],
        },
    };
    if store.attach_launch(attach.clone()).await != Err(StoreError::Invalid) {
        return Err("invalid process evidence was accepted".into());
    }
    attach.context = context(710, owner);
    attach.evidence.process_id = 10;
    attach.evidence.process_group_id = 10;
    attach.evidence.parent_process_id = 9;
    if !matches!(
        store.attach_launch(attach.clone()).await,
        Ok(Mutation::Applied(_))
    ) {
        return Err("attach CAS did not apply".into());
    }
    if !matches!(
        store.attach_launch(attach.clone()).await,
        Ok(Mutation::Replayed(_))
    ) {
        return Err("attach was not replayable".into());
    }
    let mut conflicting_attach = attach;
    conflicting_attach.instance_id = InstanceId::from_uuid(Uuid::from_u128(711)).map_err(debug)?;
    if !matches!(
        store.attach_launch(conflicting_attach).await,
        Err(StoreError::RequestConflict { .. })
    ) {
        return Err("attach request digest conflict was not rejected".into());
    }
    Ok(())
}

async fn assert_transitions<S: InstanceStore>(
    store: &S,
    session: SessionId,
    owner: HostId,
    epoch: FencingEpoch,
    attempt: LaunchAttemptId,
) -> Result<(), String> {
    let ready = transition(712, owner, session, epoch, attempt, 2, LaunchState::Ready);
    if !matches!(
        store.transition_launch(ready.clone()).await,
        Ok(Mutation::Applied(_))
    ) || !matches!(
        store.transition_launch(ready).await,
        Ok(Mutation::Replayed(_))
    ) {
        return Err("Ready transition was not applied and replayed".into());
    }
    store
        .transition_launch(transition(
            713,
            owner,
            session,
            epoch,
            attempt,
            3,
            LaunchState::Stopping,
        ))
        .await
        .map_err(debug)?;
    store
        .transition_launch(transition(
            714,
            owner,
            session,
            epoch,
            attempt,
            4,
            LaunchState::Stopped,
        ))
        .await
        .map_err(debug)?;
    if store
        .transition_launch(transition(
            715,
            owner,
            session,
            epoch,
            attempt,
            5,
            LaunchState::Ready,
        ))
        .await
        != Err(StoreError::Invalid)
    {
        return Err("terminal launch state was mutable".into());
    }
    Ok(())
}

async fn assert_fencing<S: InstanceStore>(
    store: &S,
    session: SessionId,
    owner: HostId,
    epoch: FencingEpoch,
) -> Result<(), String> {
    if !matches!(
        store.validate_launch_authority(session, owner, epoch).await,
        Err(StoreError::OwnershipExpired { .. })
    ) {
        return Err("authority remained effective at exact expiry".into());
    }
    let next_owner = host(720);
    store
        .acquire_ownership(AcquireOwnership::new(
            context(721, next_owner),
            session,
            LeaseDuration::from_millis(20_000).map_err(debug)?,
        ))
        .await
        .map_err(debug)?;
    let stale = PrepareLaunch {
        context: context(722, owner),
        epoch,
        session_id: session,
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(723)).map_err(debug)?,
        driver_id: DriverId::from_uuid(Uuid::from_u128(724)).map_err(debug)?,
        attempt_id: LaunchAttemptId::from_uuid(Uuid::from_u128(725)).map_err(debug)?,
        credential_digest: [2; 32],
        driver_configuration_digest: [12; 32],
    };
    if !matches!(
        store.prepare_launch(stale).await,
        Err(StoreError::StaleOwnership { .. })
    ) {
        return Err("stale owner prepared a launch after takeover".into());
    }
    Ok(())
}

async fn assert_cross_identity_conflicts<S: InstanceStore>(
    store: &S,
    _session: SessionId,
    attempt: LaunchAttemptId,
) -> Result<(), String> {
    let next_owner = host(720);
    let other_session = SessionId::from_uuid(Uuid::from_u128(730)).map_err(debug)?;
    store
        .open_session(OpenSession::new(
            context(731, next_owner),
            other_session,
            ConsumerKey::new("instance-contract-other").map_err(debug)?,
            CompatibilityIdentity::from_bytes([5; 32]),
        ))
        .await
        .map_err(debug)?;
    let other_lease = store
        .acquire_ownership(AcquireOwnership::new(
            context(732, next_owner),
            other_session,
            LeaseDuration::from_millis(20_000).map_err(debug)?,
        ))
        .await
        .map_err(debug)?
        .value()
        .clone();
    let session_scoped_ledger_mutant = PrepareLaunch {
        context: context(705, next_owner),
        epoch: other_lease.epoch(),
        session_id: other_session,
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(734)).map_err(debug)?,
        driver_id: DriverId::from_uuid(Uuid::from_u128(735)).map_err(debug)?,
        attempt_id: LaunchAttemptId::from_uuid(Uuid::from_u128(739)).map_err(debug)?,
        credential_digest: [6; 32],
        driver_configuration_digest: [16; 32],
    };
    if !matches!(
        store.prepare_launch(session_scoped_ledger_mutant).await,
        Err(StoreError::RequestConflict { .. })
    ) {
        return Err("request ledger was scoped per Session instead of globally".into());
    }
    let cross_session = PrepareLaunch {
        context: context(733, next_owner),
        epoch: other_lease.epoch(),
        session_id: other_session,
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(734)).map_err(debug)?,
        driver_id: DriverId::from_uuid(Uuid::from_u128(735)).map_err(debug)?,
        attempt_id: attempt,
        credential_digest: [6; 32],
        driver_configuration_digest: [16; 32],
    };
    if store.prepare_launch(cross_session).await != Err(StoreError::Invalid) {
        return Err("launch attempt identity was accepted across Sessions".into());
    }
    let other_attempt = LaunchAttemptId::from_uuid(Uuid::from_u128(736)).map_err(debug)?;
    store
        .prepare_launch(PrepareLaunch {
            context: context(737, next_owner),
            epoch: other_lease.epoch(),
            session_id: other_session,
            participant_id: ParticipantId::from_uuid(Uuid::from_u128(734)).map_err(debug)?,
            driver_id: DriverId::from_uuid(Uuid::from_u128(735)).map_err(debug)?,
            attempt_id: other_attempt,
            credential_digest: [6; 32],
            driver_configuration_digest: [16; 32],
        })
        .await
        .map_err(debug)?;
    let duplicate_instance = AttachLaunch {
        context: context(738, next_owner),
        session_id: other_session,
        epoch: other_lease.epoch(),
        attempt_id: other_attempt,
        expected_revision: Revision::initial(),
        instance_id: InstanceId::from_uuid(Uuid::from_u128(709)).map_err(debug)?,
        evidence: ProcessEvidence {
            process_id: 12,
            process_group_id: 12,
            parent_process_id: 9,
            creation_marker: 2,
            executable_identity: [2; 32],
        },
    };
    if store.attach_launch(duplicate_instance).await != Err(StoreError::Invalid) {
        return Err("Instance identity was attached to multiple attempts".into());
    }
    Ok(())
}

fn transition(
    request: u128,
    caller: HostId,
    session_id: SessionId,
    epoch: FencingEpoch,
    attempt_id: LaunchAttemptId,
    revision: u64,
    target: LaunchState,
) -> TransitionLaunch {
    TransitionLaunch {
        context: context(request, caller),
        session_id,
        epoch,
        attempt_id,
        expected_revision: Revision::new(revision).expect("positive revision"),
        target,
        cleanup_reason: None,
    }
}

fn context(request: u128, caller: HostId) -> RequestContext {
    RequestContext::new(
        RequestId::from_uuid(Uuid::from_u128(request)).expect("non-nil request"),
        caller,
    )
}

fn session(value: u128) -> SessionId {
    SessionId::from_uuid(Uuid::from_u128(value)).expect("non-nil session")
}

fn host(value: u128) -> HostId {
    HostId::from_uuid(Uuid::from_u128(value)).expect("non-nil host")
}

fn debug(error: impl core::fmt::Debug) -> String {
    format!("{error:?}")
}
