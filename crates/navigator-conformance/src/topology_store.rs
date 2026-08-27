use navigator_domain::{FencingEpoch, HostId, ParticipantId, RequestId, SessionId, TemplateId};
use navigator_store_api::{
    CreateChildParticipant, MAX_DIRECT_CHILDREN, MAX_PARTICIPANT_DEPTH, MAX_SESSION_PARTICIPANTS,
    Mutation, OperationStore, RequestContext, StoreError,
};
use uuid::Uuid;

#[derive(Clone, Copy)]
pub struct TopologyScope {
    pub session_id: SessionId,
    pub owner: HostId,
    pub epoch: FencingEpoch,
    pub root: ParticipantId,
    pub template_id: TemplateId,
    pub compatibility: navigator_domain::CompatibilityIdentity,
}

pub trait TopologyStoreFixture {
    type Store: OperationStore;
    fn store(&self) -> &Self::Store;
    fn prepare_scope(
        &self,
        seed: u128,
    ) -> impl Future<Output = Result<TopologyScope, StoreError>> + Send;
    fn reopen(&mut self) -> impl Future<Output = Result<(), StoreError>> + Send;
}

#[expect(
    clippy::too_many_lines,
    reason = "one complete topology semantic contract"
)]
pub async fn assert_topology_store_contract<F: TopologyStoreFixture>(
    fixture: &mut F,
) -> Result<(), String> {
    let scope = fixture.prepare_scope(20_000).await.map_err(debug)?;
    let first = child(scope, 1, 101, scope.root);
    let created = fixture
        .store()
        .create_child_participant(first.clone())
        .await
        .map_err(debug)?
        .value()
        .clone();
    if created.parent_participant_id != Some(scope.root) || created.depth != 2 {
        return Err("child relationship was not persisted".into());
    }
    let mut replay = first;
    replay.participant_id = participant(102);
    let replayed = fixture
        .store()
        .create_child_participant(replay)
        .await
        .map_err(debug)?;
    if !replayed.was_replayed() || replayed.value() != &created {
        return Err("retry regenerated child identity".into());
    }
    let moved = child(scope, 2, 101, created.participant_id);
    if fixture.store().create_child_participant(moved).await != Err(StoreError::Invalid) {
        return Err("existing Participant was reparented".into());
    }
    let children = fixture
        .store()
        .load_direct_children(scope.root)
        .await
        .map_err(debug)?;
    if children != [created.clone()] {
        return Err("direct-child snapshot is not queryable or stable".into());
    }

    let other = fixture.prepare_scope(30_000).await.map_err(debug)?;
    let mut cross = child(scope, 3, 103, other.root);
    cross.session_id = scope.session_id;
    if fixture.store().create_child_participant(cross).await != Err(StoreError::Invalid) {
        return Err("cross-Session parent was accepted".into());
    }

    let depth_scope = fixture.prepare_scope(40_000).await.map_err(debug)?;
    let mut parent = depth_scope.root;
    for depth in 2..=MAX_PARTICIPANT_DEPTH {
        let command = child(
            depth_scope,
            u128::from(depth),
            400 + u128::from(depth),
            parent,
        );
        let snapshot = fixture
            .store()
            .create_child_participant(command)
            .await
            .map_err(debug)?
            .value()
            .clone();
        if snapshot.depth != depth {
            return Err("depth was not derived from durable parent".into());
        }
        parent = snapshot.participant_id;
    }
    if fixture
        .store()
        .create_child_participant(child(depth_scope, 99, 499, parent))
        .await
        != Err(StoreError::Invalid)
    {
        return Err("maximum depth was exceeded".into());
    }

    let count_scope = fixture.prepare_scope(50_000).await.map_err(debug)?;
    for ordinal in 0..MAX_DIRECT_CHILDREN - 1 {
        fixture
            .store()
            .create_child_participant(child(
                count_scope,
                1_000 + u128::from(ordinal),
                2_000 + u128::from(ordinal),
                count_scope.root,
            ))
            .await
            .map_err(debug)?;
    }
    let left = child(count_scope, 8_000, 8_100, count_scope.root);
    let right = child(count_scope, 8_001, 8_101, count_scope.root);
    let (left, right) = tokio::join!(
        fixture.store().create_child_participant(left),
        fixture.store().create_child_participant(right)
    );
    if [left, right]
        .iter()
        .filter(|result| matches!(result, Ok(Mutation::Applied(_))))
        .count()
        != 1
        || fixture
            .store()
            .load_direct_children(count_scope.root)
            .await
            .map_err(debug)?
            .len()
            != usize::try_from(MAX_DIRECT_CHILDREN).map_err(debug)?
    {
        return Err("concurrent direct-child capacity was not exact".into());
    }

    let total_scope = fixture.prepare_scope(60_000).await.map_err(debug)?;
    let mut parents = vec![total_scope.root];
    let mut total = 1_u32;
    let mut ordinal = 0_u128;
    let mut cursor = 0_usize;
    while total < MAX_SESSION_PARTICIPANTS {
        let parent = parents[cursor];
        let parent_depth = fixture
            .store()
            .load_participant(parent)
            .await
            .map_err(debug)?
            .depth;
        let capacity = MAX_DIRECT_CHILDREN.min(MAX_SESSION_PARTICIPANTS - total);
        for _ in 0..capacity {
            ordinal += 1;
            let snapshot = fixture
                .store()
                .create_child_participant(child(
                    total_scope,
                    70_000 + ordinal,
                    80_000 + ordinal,
                    parent,
                ))
                .await
                .map_err(debug)?
                .value()
                .clone();
            parents.push(snapshot.participant_id);
            total += 1;
            if total == MAX_SESSION_PARTICIPANTS {
                break;
            }
        }
        cursor += 1;
        if parent_depth >= MAX_PARTICIPANT_DEPTH || cursor >= parents.len() {
            return Err("test topology could not reach total boundary".into());
        }
    }
    if fixture
        .store()
        .create_child_participant(child(total_scope, 99_998, 99_999, parents[cursor]))
        .await
        != Err(StoreError::Invalid)
    {
        return Err("Session Participant total was exceeded".into());
    }
    fixture.reopen().await.map_err(debug)?;
    if fixture
        .store()
        .load_participant(created.participant_id)
        .await
        .map_err(debug)?
        != created
    {
        return Err("reopen changed immutable topology".into());
    }
    Ok(())
}

fn child(
    scope: TopologyScope,
    request: u128,
    id: u128,
    parent: ParticipantId,
) -> CreateChildParticipant {
    CreateChildParticipant {
        context: RequestContext::new(
            request_id(scope.session_id.as_uuid().as_u128() + request),
            scope.owner,
        ),
        session_id: scope.session_id,
        epoch: scope.epoch,
        participant_id: participant(scope.session_id.as_uuid().as_u128() + id),
        parent_participant_id: parent,
        template_id: scope.template_id,
        expected_compatibility: scope.compatibility,
    }
}
fn participant(value: u128) -> ParticipantId {
    ParticipantId::from_uuid(Uuid::from_u128(value)).unwrap()
}
fn request_id(value: u128) -> RequestId {
    RequestId::from_uuid(Uuid::from_u128(value)).unwrap()
}
fn debug(error: impl std::fmt::Debug) -> String {
    format!("{error:?}")
}
