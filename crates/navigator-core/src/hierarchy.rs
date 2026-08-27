use std::collections::{BTreeMap, BTreeSet};

use std::sync::Arc;

use navigator_domain::{
    Capability, FencingEpoch, GrantId, HostId, InstanceId, LaunchAttemptId, MessageId, OperationId,
    ParticipantId, ResourceScope, ScopedCapability, SessionId, TemplateId, ValidatedTaskInput,
};
use navigator_store_api::{
    AuthorityStore, AuthorizedChildOutcome, AuthorizedStatus, AuthorizedStatusOutcome,
    CreateAuthorizedChild, HierarchyStore, InstanceStore, LaunchState, Mutation, OperationSnapshot,
    OperationStore, ParticipantSnapshot, RequestContext,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedHierarchyCaller {
    pub host_id: HostId,
    pub session_id: SessionId,
    pub participant_id: ParticipantId,
    pub launch_attempt_id: LaunchAttemptId,
    pub instance_id: InstanceId,
    pub ownership_epoch: FencingEpoch,
}

#[derive(Clone)]
pub struct HierarchyService<S> {
    store: Arc<S>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpawnChildRequest {
    pub context: RequestContext,
    pub participant_id: ParticipantId,
    pub template_id: TemplateId,
    pub grant_id: Option<GrantId>,
    pub operation_id: OperationId,
    pub input_message_id: MessageId,
    pub input: ValidatedTaskInput,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildStatusRequest {
    pub context: RequestContext,
    pub participant_id: ParticipantId,
    pub operation_id: Option<OperationId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HierarchyServiceError {
    #[error("authenticated Instance is not the current ready identity")]
    UnauthenticatedInstance,
    #[error("hierarchy command is denied by topology or policy")]
    Denied,
    #[error("hierarchy Store boundary failed")]
    Store,
    #[error("hierarchy request identity conflicts with prior semantics")]
    StoreConflict,
    #[error("hierarchy durable state failed integrity validation")]
    StoreCorrupt,
}

impl<S> HierarchyService<S>
where
    S: AuthorityStore + HierarchyStore + InstanceStore + OperationStore,
{
    #[must_use]
    pub const fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    pub async fn spawn_child(
        &self,
        caller: AuthenticatedHierarchyCaller,
        request: SpawnChildRequest,
    ) -> Result<Mutation<AuthorizedChildOutcome>, HierarchyServiceError> {
        self.verify_caller(caller).await?;
        let template = self
            .store
            .load_template(request.template_id)
            .await
            .map_err(|error| classify_store_error(&error))?;
        let command = CreateAuthorizedChild {
            context: request.context,
            session_id: caller.session_id,
            epoch: caller.ownership_epoch,
            parent_participant_id: caller.participant_id,
            participant_id: request.participant_id,
            template_id: request.template_id,
            expected_compatibility: template.compatibility,
            requested: ScopedCapability::new(
                Capability::new("participant.spawn").expect("static capability"),
                ResourceScope::Participant(caller.participant_id),
            ),
            grant_id: request.grant_id,
            operation_id: request.operation_id,
            input_message_id: request.input_message_id,
            input: request.input,
        };
        self.store
            .create_authorized_child(command)
            .await
            .map_err(|error| classify_store_error(&error))
    }

    pub async fn verify_caller(
        &self,
        caller: AuthenticatedHierarchyCaller,
    ) -> Result<(), HierarchyServiceError> {
        self.store
            .validate_launch_authority(caller.session_id, caller.host_id, caller.ownership_epoch)
            .await
            .map_err(|_| HierarchyServiceError::UnauthenticatedInstance)?;
        let launch = self
            .store
            .load_launch(caller.launch_attempt_id)
            .await
            .map_err(|_| HierarchyServiceError::UnauthenticatedInstance)?;
        if launch.session_id != caller.session_id
            || launch.participant_id != caller.participant_id
            || launch.ownership_epoch != Some(caller.ownership_epoch)
            || launch.instance_id != Some(caller.instance_id)
            || launch.state != LaunchState::Ready
        {
            return Err(HierarchyServiceError::UnauthenticatedInstance);
        }
        Ok(())
    }

    pub async fn child_status(
        &self,
        caller: AuthenticatedHierarchyCaller,
        request: ChildStatusRequest,
    ) -> Result<(ParticipantSnapshot, Option<OperationSnapshot>), HierarchyServiceError> {
        self.verify_caller(caller).await?;
        match self
            .store
            .authorized_status(AuthorizedStatus {
                context: request.context,
                session_id: caller.session_id,
                epoch: caller.ownership_epoch,
                caller_participant_id: caller.participant_id,
                target_participant_id: request.participant_id,
                operation_id: request.operation_id,
            })
            .await
            .map_err(|error| classify_store_error(&error))?
            .value()
        {
            AuthorizedStatusOutcome::Allowed {
                participant,
                operation,
            } => Ok((participant.as_ref().clone(), operation.as_deref().cloned())),
            AuthorizedStatusOutcome::Denied => Err(HierarchyServiceError::Denied),
        }
    }
}

fn classify_store_error(error: &navigator_store_api::StoreError) -> HierarchyServiceError {
    match error {
        navigator_store_api::StoreError::RequestConflict { .. } => {
            HierarchyServiceError::StoreConflict
        }
        navigator_store_api::StoreError::Corrupt => HierarchyServiceError::StoreCorrupt,
        _ => HierarchyServiceError::Store,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HierarchyRoute {
    SelfTarget,
    DirectParent,
    DirectChild,
    ViaCommonAncestor(ParticipantId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HierarchyRouteError {
    #[error("participant is outside the authenticated Session")]
    CrossSession,
    #[error("participant topology is incomplete or corrupt")]
    InvalidTopology,
    #[error("direct cross-tree delivery is forbidden")]
    DirectCrossTreeForbidden,
}

pub fn direct_route(
    caller: &ParticipantSnapshot,
    target: &ParticipantSnapshot,
) -> Result<HierarchyRoute, HierarchyRouteError> {
    ensure_same_session(caller.session_id, target.session_id)?;
    if caller.participant_id == target.participant_id {
        return Ok(HierarchyRoute::SelfTarget);
    }
    if caller.parent_participant_id == Some(target.participant_id) {
        return Ok(HierarchyRoute::DirectParent);
    }
    if target.parent_participant_id == Some(caller.participant_id) {
        return Ok(HierarchyRoute::DirectChild);
    }
    Err(HierarchyRouteError::DirectCrossTreeForbidden)
}

pub fn policy_route(
    caller: ParticipantId,
    target: ParticipantId,
    participants: &[ParticipantSnapshot],
) -> Result<HierarchyRoute, HierarchyRouteError> {
    let by_id: BTreeMap<_, _> = participants
        .iter()
        .map(|participant| (participant.participant_id, participant))
        .collect();
    let caller = by_id
        .get(&caller)
        .ok_or(HierarchyRouteError::InvalidTopology)?;
    let target = by_id
        .get(&target)
        .ok_or(HierarchyRouteError::InvalidTopology)?;
    let caller_ancestors = ancestor_set(caller.participant_id, &by_id)?;
    let _target_ancestors = ancestor_set(target.participant_id, &by_id)?;
    if let Ok(route) = direct_route(caller, target) {
        return Ok(route);
    }
    ensure_same_session(caller.session_id, target.session_id)?;
    let mut cursor = target.participant_id;
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(cursor) {
            return Err(HierarchyRouteError::InvalidTopology);
        }
        if caller_ancestors.contains(&cursor) {
            return Ok(HierarchyRoute::ViaCommonAncestor(cursor));
        }
        let participant = by_id
            .get(&cursor)
            .ok_or(HierarchyRouteError::InvalidTopology)?;
        cursor = participant
            .parent_participant_id
            .ok_or(HierarchyRouteError::InvalidTopology)?;
    }
}

fn ancestor_set(
    participant: ParticipantId,
    by_id: &BTreeMap<ParticipantId, &ParticipantSnapshot>,
) -> Result<BTreeSet<ParticipantId>, HierarchyRouteError> {
    let mut result = BTreeSet::new();
    let mut cursor = participant;
    loop {
        if !result.insert(cursor) {
            return Err(HierarchyRouteError::InvalidTopology);
        }
        let snapshot = by_id
            .get(&cursor)
            .ok_or(HierarchyRouteError::InvalidTopology)?;
        let Some(parent) = snapshot.parent_participant_id else {
            return Ok(result);
        };
        cursor = parent;
    }
}

fn ensure_same_session(left: SessionId, right: SessionId) -> Result<(), HierarchyRouteError> {
    if left == right {
        Ok(())
    } else {
        Err(HierarchyRouteError::CrossSession)
    }
}

#[cfg(test)]
mod tests {
    use navigator_domain::{CompatibilityIdentity, Revision, TemplateId};
    use uuid::Uuid;

    use super::*;

    fn id(value: u128) -> ParticipantId {
        ParticipantId::from_uuid(Uuid::from_u128(value)).unwrap()
    }

    fn participant(value: u128, parent: Option<u128>, depth: u32) -> ParticipantSnapshot {
        ParticipantSnapshot {
            session_id: SessionId::from_uuid(Uuid::from_u128(1)).unwrap(),
            participant_id: id(value),
            parent_participant_id: parent.map(id),
            depth,
            template_id: TemplateId::from_uuid(Uuid::from_u128(100 + value)).unwrap(),
            template_compatibility: CompatibilityIdentity::from_bytes([7; 32]),
            revision: Revision::initial(),
        }
    }

    #[test]
    fn direct_delivery_never_skips_a_relationship_boundary() {
        let root = participant(1, None, 1);
        let left = participant(2, Some(1), 2);
        let right = participant(3, Some(1), 2);
        let leaf = participant(4, Some(2), 3);
        assert_eq!(direct_route(&root, &left), Ok(HierarchyRoute::DirectChild));
        assert_eq!(direct_route(&left, &root), Ok(HierarchyRoute::DirectParent));
        assert_eq!(
            direct_route(&left, &right),
            Err(HierarchyRouteError::DirectCrossTreeForbidden)
        );
        assert_eq!(
            direct_route(&root, &leaf),
            Err(HierarchyRouteError::DirectCrossTreeForbidden)
        );
    }

    #[test]
    fn sibling_route_names_the_common_ancestor_without_direct_delivery() {
        let topology = [
            participant(1, None, 1),
            participant(2, Some(1), 2),
            participant(3, Some(1), 2),
            participant(4, Some(2), 3),
            participant(5, Some(3), 3),
        ];
        assert_eq!(
            policy_route(id(4), id(5), &topology),
            Ok(HierarchyRoute::ViaCommonAncestor(id(1)))
        );
        assert_eq!(
            direct_route(&topology[3], &topology[4]),
            Err(HierarchyRouteError::DirectCrossTreeForbidden)
        );
    }

    #[test]
    fn malformed_cycle_and_cross_session_fail_closed() {
        let cyclic = [participant(2, Some(3), 2), participant(3, Some(2), 2)];
        assert_eq!(
            policy_route(id(2), id(3), &cyclic),
            Err(HierarchyRouteError::InvalidTopology)
        );
        let mut foreign = participant(9, None, 1);
        foreign.session_id = SessionId::from_uuid(Uuid::from_u128(2)).unwrap();
        assert_eq!(
            direct_route(&participant(1, None, 1), &foreign),
            Err(HierarchyRouteError::CrossSession)
        );
    }
}
