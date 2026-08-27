use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
};

use navigator_domain::{FencingEpoch, HostId, ParticipantId, RequestId, SessionId, Timestamp};

use crate::StoreError;

#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CapacityResource {
    Participants,
    ActiveOperations,
    QueuedOperations,
    Messages,
    MessageBytes,
    Artifacts,
    ArtifactBytes,
    PendingRequests,
    Subscriptions,
    Retries,
    RetainedEvents,
}

impl CapacityResource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Participants => "participants",
            Self::ActiveOperations => "active_operations",
            Self::QueuedOperations => "queued_operations",
            Self::Messages => "messages",
            Self::MessageBytes => "message_bytes",
            Self::Artifacts => "artifacts",
            Self::ArtifactBytes => "artifact_bytes",
            Self::PendingRequests => "pending_requests",
            Self::Subscriptions => "subscriptions",
            Self::Retries => "retries",
            Self::RetainedEvents => "retained_events",
        }
    }

    pub const ALL: [Self; 11] = [
        Self::Participants,
        Self::ActiveOperations,
        Self::QueuedOperations,
        Self::Messages,
        Self::MessageBytes,
        Self::Artifacts,
        Self::ArtifactBytes,
        Self::PendingRequests,
        Self::Subscriptions,
        Self::Retries,
        Self::RetainedEvents,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LimitProfileError {
    #[error("a resource limit must be non-zero and no greater than its immutable safety ceiling")]
    OutOfRange,
    #[error("a per-session limit cannot exceed its global limit")]
    SessionExceedsGlobal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ResourceLimit {
    pub per_session: u64,
    pub global: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct LimitProfile {
    limits: BTreeMap<CapacityResource, ResourceLimit>,
}

impl Default for LimitProfile {
    fn default() -> Self {
        let mut limits = BTreeMap::new();
        for resource in CapacityResource::ALL {
            let ceiling = Self::hard_ceiling(resource);
            limits.insert(
                resource,
                ResourceLimit {
                    per_session: Self::default_session(resource),
                    global: Self::default_global(resource).min(ceiling.global),
                },
            );
        }
        Self { limits }
    }
}

impl LimitProfile {
    #[must_use]
    pub const fn hard_ceiling(resource: CapacityResource) -> ResourceLimit {
        match resource {
            CapacityResource::Participants | CapacityResource::ActiveOperations => ResourceLimit {
                per_session: 4_096,
                global: 65_536,
            },
            CapacityResource::QueuedOperations
            | CapacityResource::Artifacts
            | CapacityResource::PendingRequests
            | CapacityResource::Retries => ResourceLimit {
                per_session: 65_536,
                global: 1_048_576,
            },
            CapacityResource::Messages => ResourceLimit {
                per_session: 262_144,
                global: 4_194_304,
            },
            CapacityResource::MessageBytes => ResourceLimit {
                per_session: 1 << 34,
                global: 1 << 38,
            },
            CapacityResource::ArtifactBytes => ResourceLimit {
                per_session: 1 << 40,
                global: 1 << 44,
            },
            CapacityResource::Subscriptions => ResourceLimit {
                per_session: 1_024,
                global: 16_384,
            },
            CapacityResource::RetainedEvents => ResourceLimit {
                per_session: 4_194_304,
                global: 67_108_864,
            },
        }
    }

    const fn default_session(resource: CapacityResource) -> u64 {
        match resource {
            CapacityResource::Participants => 1_024,
            CapacityResource::ActiveOperations => 256,
            CapacityResource::QueuedOperations
            | CapacityResource::Artifacts
            | CapacityResource::PendingRequests
            | CapacityResource::Retries => 4_096,
            CapacityResource::Messages => 65_536,
            CapacityResource::MessageBytes => 256 * 1024 * 1024,
            CapacityResource::ArtifactBytes => 4 * 1024 * 1024 * 1024,
            CapacityResource::Subscriptions => 32,
            CapacityResource::RetainedEvents => 262_144,
        }
    }

    const fn default_global(resource: CapacityResource) -> u64 {
        Self::default_session(resource) * 16
    }

    pub fn new(
        limits: impl IntoIterator<Item = (CapacityResource, ResourceLimit)>,
    ) -> Result<Self, LimitProfileError> {
        let mut profile = Self::default();
        for (resource, limit) in limits {
            let ceiling = Self::hard_ceiling(resource);
            if limit.per_session == 0
                || limit.global == 0
                || limit.per_session > limit.global
                || limit.per_session > ceiling.per_session
                || limit.global > ceiling.global
            {
                return Err(if limit.per_session > limit.global {
                    LimitProfileError::SessionExceedsGlobal
                } else {
                    LimitProfileError::OutOfRange
                });
            }
            profile.limits.insert(resource, limit);
        }
        Ok(profile)
    }

    #[must_use]
    pub fn get(&self, resource: CapacityResource) -> ResourceLimit {
        self.limits[&resource]
    }
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize, thiserror::Error,
)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum CapacityReason {
    #[error("session {resource:?} limit reached")]
    SessionLimit { resource: CapacityResource },
    #[error("global {resource:?} limit reached")]
    GlobalLimit { resource: CapacityResource },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReserveCapacity {
    pub reservation_id: RequestId,
    pub session_id: SessionId,
    pub campaign_id: ParticipantId,
    pub resource: CapacityResource,
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapacityReservation {
    pub reservation_id: RequestId,
    pub session_id: SessionId,
    pub campaign_id: ParticipantId,
    pub resource: CapacityResource,
    pub amount: u64,
    pub released: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReserveSubscriptionLease {
    pub reservation_id: RequestId,
    pub session_id: SessionId,
    pub campaign_id: ParticipantId,
    pub owner_host_id: HostId,
    pub owner_epoch: FencingEpoch,
    pub expires_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscriptionLease {
    pub reservation_id: RequestId,
    pub session_id: SessionId,
    pub campaign_id: ParticipantId,
    pub owner_host_id: HostId,
    pub owner_epoch: FencingEpoch,
    pub expires_at: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReserveGlobalCapacity {
    pub reservation_id: RequestId,
    pub resource: CapacityResource,
    pub amount: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlobalCapacityReservation {
    pub reservation_id: RequestId,
    pub resource: CapacityResource,
    pub amount: u64,
    pub released: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct CapacityMetric {
    pub resource: CapacityResource,
    pub session_used: u64,
    pub session_limit: u64,
    pub global_used: u64,
    pub global_limit: u64,
}

pub trait CapacityStore: Send + Sync {
    fn reserve_subscription_lease(
        &self,
        _command: ReserveSubscriptionLease,
    ) -> impl Future<Output = Result<SubscriptionLease, StoreError>> + Send {
        async { Err(StoreError::Unavailable) }
    }

    fn renew_subscription_lease(
        &self,
        _command: ReserveSubscriptionLease,
    ) -> impl Future<Output = Result<SubscriptionLease, StoreError>> + Send {
        async { Err(StoreError::Unavailable) }
    }

    fn reserve_global_capacity(
        &self,
        command: ReserveGlobalCapacity,
    ) -> impl Future<Output = Result<GlobalCapacityReservation, StoreError>> + Send;

    fn release_global_capacity(
        &self,
        reservation_id: RequestId,
    ) -> impl Future<Output = Result<GlobalCapacityReservation, StoreError>> + Send;

    fn reserve_capacity(
        &self,
        command: ReserveCapacity,
    ) -> impl Future<Output = Result<CapacityReservation, StoreError>> + Send;

    fn release_capacity(
        &self,
        reservation_id: RequestId,
    ) -> impl Future<Output = Result<CapacityReservation, StoreError>> + Send;

    fn capacity_metrics(
        &self,
        session_id: SessionId,
    ) -> impl Future<Output = Result<Vec<CapacityMetric>, StoreError>> + Send;
}

/// Deterministic deficit round-robin. A caller supplies one queue head per Campaign/subtree;
/// each successful selection rotates that Campaign behind all currently eligible peers.
#[derive(Clone, Debug, Default)]
pub struct FairScheduler {
    cursor: Option<ParticipantId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FairQueueError {
    #[error("fair queue capacity reached")]
    Capacity,
}

/// Bounded deterministic queue which gives each Campaign/subtree at most one item per round.
#[derive(Clone, Debug)]
pub struct FairQueue<T> {
    queues: BTreeMap<ParticipantId, VecDeque<T>>,
    scheduler: FairScheduler,
    len: usize,
    limit: usize,
}

impl<T> FairQueue<T> {
    pub const fn new(limit: usize) -> Result<Self, FairQueueError> {
        if limit == 0 {
            return Err(FairQueueError::Capacity);
        }
        Ok(Self {
            queues: BTreeMap::new(),
            scheduler: FairScheduler { cursor: None },
            len: 0,
            limit,
        })
    }

    pub fn push(&mut self, campaign: ParticipantId, value: T) -> Result<(), FairQueueError> {
        if self.len == self.limit {
            return Err(FairQueueError::Capacity);
        }
        self.queues.entry(campaign).or_default().push_back(value);
        self.len += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<(ParticipantId, T)> {
        let campaign = self.scheduler.select(self.queues.keys().copied())?;
        let queue = self.queues.get_mut(&campaign)?;
        let value = queue.pop_front()?;
        self.len -= 1;
        if queue.is_empty() {
            self.queues.remove(&campaign);
        }
        Some((campaign, value))
    }

    pub fn cancel_campaign(&mut self, campaign: ParticipantId) -> usize {
        let released = self.queues.remove(&campaign).map_or(0, |queue| queue.len());
        self.len -= released;
        released
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl FairScheduler {
    pub fn select(
        &mut self,
        eligible: impl IntoIterator<Item = ParticipantId>,
    ) -> Option<ParticipantId> {
        let mut campaigns: Vec<_> = eligible.into_iter().collect();
        campaigns.sort_unstable();
        campaigns.dedup();
        let selected = match self.cursor {
            None => campaigns.first().copied(),
            Some(cursor) => campaigns
                .iter()
                .copied()
                .find(|candidate| *candidate > cursor)
                .or_else(|| campaigns.first().copied()),
        };
        self.cursor = selected;
        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn participant(value: u128) -> ParticipantId {
        ParticipantId::from_uuid(Uuid::from_u128(value)).unwrap()
    }

    #[test]
    fn profile_accepts_exact_ceiling_and_rejects_plus_one_and_session_over_global() {
        for resource in CapacityResource::ALL {
            let ceiling = LimitProfile::hard_ceiling(resource);
            assert!(LimitProfile::new([(resource, ceiling)]).is_ok());
            assert_eq!(
                LimitProfile::new([(
                    resource,
                    ResourceLimit {
                        global: ceiling.global + 1,
                        ..ceiling
                    },
                )]),
                Err(LimitProfileError::OutOfRange)
            );
        }
        assert_eq!(
            LimitProfile::new([(
                CapacityResource::Participants,
                ResourceLimit {
                    per_session: 2,
                    global: 1
                },
            )]),
            Err(LimitProfileError::SessionExceedsGlobal)
        );
    }

    #[test]
    fn scheduler_rotates_campaigns_deterministically_without_time() {
        let a = participant(1);
        let b = participant(2);
        let c = participant(3);
        let mut scheduler = FairScheduler::default();
        assert_eq!(scheduler.select([c, a, b]), Some(a));
        assert_eq!(scheduler.select([a, b, c]), Some(b));
        assert_eq!(scheduler.select([c, a, b]), Some(c));
        assert_eq!(scheduler.select([a, c]), Some(a));
    }

    #[test]
    fn fair_queue_barrier_prevents_a_hot_subtree_from_starving_peers_and_is_bounded() {
        let a = participant(1);
        let b = participant(2);
        let c = participant(3);
        let mut queue = FairQueue::new(6).unwrap();
        for value in 0..4 {
            queue.push(a, value).unwrap();
        }
        queue.push(b, 10).unwrap();
        queue.push(c, 20).unwrap();
        assert_eq!(queue.push(c, 21), Err(FairQueueError::Capacity));
        assert_eq!(queue.pop(), Some((a, 0)));
        assert_eq!(queue.pop(), Some((b, 10)));
        assert_eq!(queue.pop(), Some((c, 20)));
        assert_eq!(queue.pop(), Some((a, 1)));
        assert_eq!(queue.cancel_campaign(a), 2);
        assert_eq!(queue.len(), 0);
    }
}
