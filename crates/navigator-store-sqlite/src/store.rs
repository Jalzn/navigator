use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
    sync::{Arc, Mutex},
};

use hmac::{Hmac, Mac};
use navigator_domain::{
    ApprovalDecisionSource, ApprovalEffectIntent, ApprovalEffectPhase, ApprovalGrant,
    ApprovalRequest, ApprovalRequestId, ApprovalStatus, ArtifactDigest, ArtifactId,
    ArtifactMediaType, ArtifactSnapshot, ArtifactState, BoundedBytes, BoundedText, Capability,
    Clock, CompatibilityIdentity, ConsumerKey, DriverId, EffectClass, EventId, EventPosition,
    EventSchemaVersion, EventType, FencingEpoch, GrantId, HostId, InstanceId, LaunchAttemptId,
    MessageId, MonotonicInstant, OperationAction, OperationId, OperationState, OwnershipSnapshot,
    ParticipantId, RedactedEventData, RequestId, ResourceScope, Revision, ScopedCapability,
    SemanticDigest, SessionCompatibilityManifest, SessionEvent, SessionId, SessionSnapshot,
    SessionStatus, TemplateCompatibilityBinding, TemplateId, Timestamp, ToolInvocationId,
    UncertaintyResolution, ValidatedMessageEnvelope,
};
use navigator_store_api::{
    AcquireOwnership, ApplyHierarchyEffect, ApprovalStore, ApproveRequest, ApprovedRequest,
    ArtifactAccess, ArtifactStore, AttachLaunch, AuthorityEffectOutcome, AuthorityPolicySnapshot,
    AuthorityStore, AuthorityTemplatePolicy, AuthorizedChildOutcome, AuthorizedEffectResolution,
    AuthorizedStatus, AuthorizedStatusOutcome, CancelSubtree, CancelSubtreeOutcome,
    CancellationRecord, CapacityMetric, CapacityReason, CapacityReservation, CapacityResource,
    CapacityStore, CheckAuthorityEffect, CloseSession, ConnectToolProvider, ConsumeApprovalGrant,
    ConsumedApprovalGrant, CreateAuthorizedChild, CreateChildParticipant, CreateRootParticipant,
    DeleteArtifact, DeliveryLease, DeliveryTransition, DenyRequest, EffectJournalEntry,
    EffectJournalPhase, EffectJournalStore, EffectResolution, EffectTerminal, EffectTransition,
    EnqueueMessage, EraseArtifact, EventPage, ExpireApproval, FinishApprovalEffect,
    GlobalCapacityReservation, GrantSnapshot, HierarchyEffect, HierarchyEffectOutcome,
    HierarchyStore, InstanceStore, IssueGrant, LaunchSnapshot, LaunchState, LeaseDuration,
    LeaseNextMessage, LimitProfile, MAX_DELIVERY_ATTEMPTS, MAX_DIRECT_CHILDREN,
    MAX_MAILBOX_QUEUED_BYTES, MAX_MAILBOX_QUEUED_MESSAGES, MAX_MAILBOX_RESERVED_OUTCOME_BYTES,
    MAX_MAILBOX_RESERVED_OUTCOMES, MAX_OPERATION_INPUT_BYTES, MAX_PARTICIPANT_DEPTH,
    MAX_SESSION_DELIVERY_WORK, MAX_SESSION_PARTICIPANTS, MAX_TOOL_REGISTRATIONS, MailboxStore,
    MessageCorrelation, MessageDeliveryState, MessagePriority, MessageSnapshot, MutableRequest,
    Mutation, OpenSession, OperationSnapshot, OperationStore, OperationTerminalOutcome,
    OwnershipLease, ParticipantSnapshot, PrepareLaunch, ProcessEvidence, ProjectionItem,
    ProjectionItemKey, ProjectionPage, ProjectionPageToken, ProjectionRebuild, ProjectionStore,
    ProjectionView, PublishArtifact, PutAuthorityPolicy, ReadEvents, ReadProjection,
    RecordRecoveryClassifications, RecoveryInventory, RecoveryStore,
    RegisterAuthorityTemplatePolicy, RegisterTemplatesAndOpenSession, RegisterTool,
    ReleaseOwnership, RenewOwnership, RequestApproval, ReserveCapacity, ReserveEffect,
    ReserveGlobalCapacity, ReserveSubscriptionLease, ReserveToolInvocation,
    ResolveAuthorizedEffect, RevokeApprovalGrant, RevokeGrant, SessionDeliveryWork, SessionStore,
    StartOperation, StoreAction, StoreError, StoredEffect, StoredRequest, StoredRequestOutcome,
    StoredResult, SubscriptionLease, TakeoverEffect, TemplateRecord, ToolDispatchSnapshot,
    ToolInvocationPhase, ToolInvocationSnapshot, ToolProviderConnectionSnapshot,
    ToolRegistrationSnapshot, ToolStore, ToolTerminal, ToolTransition, TransitionLaunch,
    TransitionMessageDelivery, TransitionOperation, TransitionToolInvocation, priority_for,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use sqlx::{Row, Sqlite, SqlitePool, Transaction, sqlite::SqliteRow};
use uuid::Uuid;

use crate::crash_at;

#[cfg(test)]
static APPROVAL_CONSUME_PAUSE: std::sync::Mutex<Option<RequestId>> = std::sync::Mutex::new(None);
#[cfg(test)]
static APPROVAL_CONSUME_ENTERED: tokio::sync::Notify = tokio::sync::Notify::const_new();
#[cfg(test)]
static APPROVAL_CONSUME_RELEASE: tokio::sync::Notify = tokio::sync::Notify::const_new();
#[cfg(test)]
static CAPACITY_RESERVE_PAUSE: std::sync::Mutex<Option<RequestId>> = std::sync::Mutex::new(None);
#[cfg(test)]
static CAPACITY_RESERVE_ENTERED: tokio::sync::Notify = tokio::sync::Notify::const_new();
#[cfg(test)]
static CAPACITY_RESERVE_RELEASE: tokio::sync::Notify = tokio::sync::Notify::const_new();

#[cfg(test)]
pub(crate) fn set_capacity_reserve_pause(request_id: Option<RequestId>) {
    *CAPACITY_RESERVE_PAUSE.lock().expect("capacity pause lock") = request_id;
    if request_id.is_none() {
        CAPACITY_RESERVE_RELEASE.notify_waiters();
    }
}

#[cfg(test)]
pub(crate) async fn wait_capacity_reserve_entered() {
    CAPACITY_RESERVE_ENTERED.notified().await;
}

#[cfg(test)]
async fn capacity_reserve_pause(request_id: RequestId) {
    if *CAPACITY_RESERVE_PAUSE.lock().expect("capacity pause lock") == Some(request_id) {
        CAPACITY_RESERVE_ENTERED.notify_waiters();
        CAPACITY_RESERVE_RELEASE.notified().await;
    }
}

#[cfg(not(test))]
#[expect(
    clippy::unused_async,
    reason = "matches the awaited fault-injection hook in test builds"
)]
async fn capacity_reserve_pause(_: RequestId) {}

impl CapacityStore for SqliteStore {
    async fn reserve_subscription_lease(
        &self,
        command: ReserveSubscriptionLease,
    ) -> Result<SubscriptionLease, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        validate_subscription_owner(&mut tx, &command).await?;
        reclaim_stale_subscription_leases(&mut tx, command.session_id).await?;
        let existing: Option<(String, String, String, i64, i64, i64)> = sqlx::query_as(
            "SELECT session_id,campaign_id,owner_host_id,owner_epoch,expires_at_seconds,expires_at_nanos FROM subscription_leases WHERE reservation_id=?",
        )
        .bind(command.reservation_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if let Some((session, campaign, host, epoch, seconds, nanos)) = existing {
            let exact = session == command.session_id.to_string()
                && campaign == command.campaign_id.to_string()
                && host == command.owner_host_id.to_string()
                && to_u64(epoch).ok() == Some(command.owner_epoch.get())
                && decode_timestamp(seconds, nanos).ok() == Some(command.expires_at);
            if !exact {
                return Err(StoreError::RequestConflict {
                    request_id: command.reservation_id,
                });
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(subscription_lease(&command));
        }
        let (session_used, global_used): (i64, i64) = sqlx::query_as(
            "SELECT COALESCE((SELECT used FROM capacity_session_usage WHERE session_id=? AND resource='subscriptions'),0),COALESCE((SELECT used FROM capacity_global_usage WHERE resource='subscriptions'),0)",
        )
        .bind(command.session_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let (session_limit, global_limit): (i64, i64) = sqlx::query_as(
            "SELECT per_session,global_limit FROM capacity_limits WHERE resource='subscriptions'",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if session_used >= session_limit {
            return Err(StoreError::CapacityExceeded {
                reason: CapacityReason::SessionLimit {
                    resource: CapacityResource::Subscriptions,
                },
            });
        }
        if global_used >= global_limit {
            return Err(StoreError::CapacityExceeded {
                reason: CapacityReason::GlobalLimit {
                    resource: CapacityResource::Subscriptions,
                },
            });
        }
        let now = self.now();
        sqlx::query("INSERT INTO capacity_reservations(reservation_id,session_id,campaign_id,resource,amount,released,created_at_seconds,created_at_nanos,released_at_seconds,released_at_nanos) VALUES(?,?,?,'subscriptions',1,0,?,?,NULL,NULL)")
            .bind(command.reservation_id.to_string()).bind(command.session_id.to_string()).bind(command.campaign_id.to_string())
            .bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).execute(&mut *tx).await.map_err(map_sqlx)?;
        sqlx::query("INSERT INTO subscription_leases(reservation_id,session_id,campaign_id,owner_host_id,owner_epoch,expires_at_seconds,expires_at_nanos) VALUES(?,?,?,?,?,?,?)")
            .bind(command.reservation_id.to_string()).bind(command.session_id.to_string()).bind(command.campaign_id.to_string()).bind(command.owner_host_id.to_string())
            .bind(to_i64(command.owner_epoch.get())?).bind(command.expires_at.unix_seconds()).bind(i64::from(command.expires_at.nanoseconds())).execute(&mut *tx).await.map_err(map_sqlx)?;
        increment_capacity_counter(
            &mut tx,
            command.session_id,
            CapacityResource::Subscriptions,
            1,
        )
        .await?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(subscription_lease(&command))
    }

    async fn renew_subscription_lease(
        &self,
        command: ReserveSubscriptionLease,
    ) -> Result<SubscriptionLease, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        validate_subscription_owner(&mut tx, &command).await?;
        let changed = sqlx::query("UPDATE subscription_leases SET expires_at_seconds=?,expires_at_nanos=? WHERE reservation_id=? AND session_id=? AND campaign_id=? AND owner_host_id=? AND owner_epoch=? AND (expires_at_seconds<? OR (expires_at_seconds=? AND expires_at_nanos<=?))")
            .bind(command.expires_at.unix_seconds()).bind(i64::from(command.expires_at.nanoseconds())).bind(command.reservation_id.to_string())
            .bind(command.session_id.to_string()).bind(command.campaign_id.to_string()).bind(command.owner_host_id.to_string()).bind(to_i64(command.owner_epoch.get())?)
            .bind(command.expires_at.unix_seconds()).bind(command.expires_at.unix_seconds()).bind(i64::from(command.expires_at.nanoseconds())).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected();
        if changed != 1 {
            return Err(StoreError::RequestConflict {
                request_id: command.reservation_id,
            });
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(subscription_lease(&command))
    }

    async fn reserve_global_capacity(
        &self,
        command: ReserveGlobalCapacity,
    ) -> Result<GlobalCapacityReservation, StoreError> {
        if command.amount == 0 {
            return Err(StoreError::Invalid);
        }
        let mut tx = begin_immediate(&self.pool).await?;
        let existing: Option<(String, i64, i64)> = sqlx::query_as(
            "SELECT resource,amount,released FROM capacity_global_reservations WHERE reservation_id=?",
        ).bind(command.reservation_id.to_string()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?;
        if let Some((resource, amount, released)) = existing {
            if resource != command.resource.as_str()
                || u64::try_from(amount).map_err(|_| StoreError::Corrupt)? != command.amount
            {
                return Err(StoreError::RequestConflict {
                    request_id: command.reservation_id,
                });
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(GlobalCapacityReservation {
                reservation_id: command.reservation_id,
                resource: command.resource,
                amount: command.amount,
                released: released != 0,
            });
        }
        let used: i64 = sqlx::query_scalar(
            "SELECT COALESCE((SELECT used FROM capacity_global_usage WHERE resource=?),0)",
        )
        .bind(command.resource.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let after = u64::try_from(used)
            .map_err(|_| StoreError::Corrupt)?
            .checked_add(command.amount)
            .ok_or(StoreError::CapacityExceeded {
                reason: CapacityReason::GlobalLimit {
                    resource: command.resource,
                },
            })?;
        if after > self.limit_profile.get(command.resource).global {
            return Err(StoreError::CapacityExceeded {
                reason: CapacityReason::GlobalLimit {
                    resource: command.resource,
                },
            });
        }
        let now = self.now();
        sqlx::query("INSERT INTO capacity_global_reservations(reservation_id,resource,amount,released,created_at_seconds,created_at_nanos,released_at_seconds,released_at_nanos) VALUES(?,?,?,0,?,?,NULL,NULL)")
            .bind(command.reservation_id.to_string()).bind(command.resource.as_str()).bind(i64::try_from(command.amount).map_err(|_|StoreError::Invalid)?).bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).execute(&mut *tx).await.map_err(map_sqlx)?;
        sqlx::query("INSERT INTO capacity_global_usage(resource,used) VALUES(?,?) ON CONFLICT(resource) DO UPDATE SET used=excluded.used")
            .bind(command.resource.as_str()).bind(i64::try_from(after).map_err(|_|StoreError::Corrupt)?).execute(&mut *tx).await.map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(GlobalCapacityReservation {
            reservation_id: command.reservation_id,
            resource: command.resource,
            amount: command.amount,
            released: false,
        })
    }

    async fn release_global_capacity(
        &self,
        reservation_id: RequestId,
    ) -> Result<GlobalCapacityReservation, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        let row:Option<(String,i64,i64)>=sqlx::query_as("SELECT resource,amount,released FROM capacity_global_reservations WHERE reservation_id=?")
            .bind(reservation_id.to_string()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?;
        let (resource, amount, released) = row.ok_or(StoreError::Invalid)?;
        let resource = parse_capacity_resource(&resource)?;
        if released == 0 {
            let now = self.now();
            if sqlx::query("UPDATE capacity_global_reservations SET released=1,released_at_seconds=?,released_at_nanos=? WHERE reservation_id=? AND released=0")
                .bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).bind(reservation_id.to_string()).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected()!=1
                || sqlx::query("UPDATE capacity_global_usage SET used=used-? WHERE resource=? AND used>=?")
                    .bind(amount).bind(resource.as_str()).bind(amount).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected()!=1 { return Err(StoreError::Corrupt); }
        }
        if resource == CapacityResource::PendingRequests {
            sqlx::query(
                "DELETE FROM capacity_global_reservations WHERE reservation_id=? AND released=1",
            )
            .bind(reservation_id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
            sqlx::query("DELETE FROM capacity_global_usage WHERE resource=? AND used=0")
                .bind(resource.as_str())
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(GlobalCapacityReservation {
            reservation_id,
            resource,
            amount: u64::try_from(amount).map_err(|_| StoreError::Corrupt)?,
            released: true,
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one atomic reservation transaction keeps replay and both counters inseparable"
    )]
    async fn reserve_capacity(
        &self,
        command: ReserveCapacity,
    ) -> Result<CapacityReservation, StoreError> {
        if command.resource == CapacityResource::Subscriptions {
            return Err(StoreError::Invalid);
        }
        if command.amount == 0 {
            return Err(StoreError::Invalid);
        }
        let mut tx = begin_immediate(&self.pool).await?;
        let existing: Option<(String, String, String, i64, i64)> = sqlx::query_as(
            "SELECT session_id,campaign_id,resource,amount,released FROM capacity_reservations WHERE reservation_id=?",
        )
        .bind(command.reservation_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if let Some((session, campaign, resource, amount, released)) = existing {
            let exact = session == command.session_id.to_string()
                && campaign == command.campaign_id.to_string()
                && resource == command.resource.as_str()
                && u64::try_from(amount).ok() == Some(command.amount);
            if !exact {
                return Err(StoreError::RequestConflict {
                    request_id: command.reservation_id,
                });
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(CapacityReservation {
                reservation_id: command.reservation_id,
                session_id: command.session_id,
                campaign_id: command.campaign_id,
                resource: command.resource,
                amount: command.amount,
                released: released != 0,
            });
        }
        let campaign_session: Option<String> =
            sqlx::query_scalar("SELECT session_id FROM participants WHERE participant_id=?")
                .bind(command.campaign_id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        if campaign_session.as_deref() != Some(command.session_id.to_string().as_str()) {
            return Err(StoreError::ParticipantNotFound {
                participant_id: command.campaign_id,
            });
        }
        let session_used: i64 = sqlx::query_scalar(
            "SELECT COALESCE((SELECT used FROM capacity_session_usage WHERE session_id=? AND resource=?),0)",
        )
        .bind(command.session_id.to_string())
        .bind(command.resource.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let global_used: i64 = sqlx::query_scalar(
            "SELECT COALESCE((SELECT used FROM capacity_global_usage WHERE resource=?),0)",
        )
        .bind(command.resource.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let (derived_session, derived_global) =
            derived_capacity_usage(&mut tx, command.session_id, command.resource).await?;
        let session_after = derived_session
            .checked_add(u64::try_from(session_used).map_err(|_| StoreError::Corrupt)?)
            .and_then(|used| used.checked_add(command.amount))
            .ok_or(StoreError::CapacityExceeded {
                reason: CapacityReason::SessionLimit {
                    resource: command.resource,
                },
            })?;
        let global_after = derived_global
            .checked_add(u64::try_from(global_used).map_err(|_| StoreError::Corrupt)?)
            .and_then(|used| used.checked_add(command.amount))
            .ok_or(StoreError::CapacityExceeded {
                reason: CapacityReason::GlobalLimit {
                    resource: command.resource,
                },
            })?;
        let limits = self.limit_profile.get(command.resource);
        if session_after > limits.per_session {
            return Err(StoreError::CapacityExceeded {
                reason: CapacityReason::SessionLimit {
                    resource: command.resource,
                },
            });
        }
        if global_after > limits.global {
            return Err(StoreError::CapacityExceeded {
                reason: CapacityReason::GlobalLimit {
                    resource: command.resource,
                },
            });
        }
        let now = self.now();
        sqlx::query("INSERT INTO capacity_reservations(reservation_id,session_id,campaign_id,resource,amount,released,created_at_seconds,created_at_nanos,released_at_seconds,released_at_nanos) VALUES(?,?,?,?,?,0,?,?,NULL,NULL)")
            .bind(command.reservation_id.to_string()).bind(command.session_id.to_string()).bind(command.campaign_id.to_string()).bind(command.resource.as_str()).bind(i64::try_from(command.amount).map_err(|_|StoreError::Invalid)?).bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).execute(&mut *tx).await.map_err(map_sqlx)?;
        capacity_reserve_pause(command.reservation_id).await;
        crash_at("capacity.reserve.after_reservation");
        sqlx::query("INSERT INTO capacity_session_usage(session_id,resource,used) VALUES(?,?,?) ON CONFLICT(session_id,resource) DO UPDATE SET used=excluded.used")
            .bind(command.session_id.to_string()).bind(command.resource.as_str()).bind(i64::try_from(session_after-derived_session).map_err(|_|StoreError::Corrupt)?).execute(&mut *tx).await.map_err(map_sqlx)?;
        sqlx::query("INSERT INTO capacity_global_usage(resource,used) VALUES(?,?) ON CONFLICT(resource) DO UPDATE SET used=excluded.used")
            .bind(command.resource.as_str()).bind(i64::try_from(global_after-derived_global).map_err(|_|StoreError::Corrupt)?).execute(&mut *tx).await.map_err(map_sqlx)?;
        crash_at("capacity.reserve.after_accounting");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("capacity.reserve.after_commit");
        Ok(CapacityReservation {
            reservation_id: command.reservation_id,
            session_id: command.session_id,
            campaign_id: command.campaign_id,
            resource: command.resource,
            amount: command.amount,
            released: false,
        })
    }

    async fn release_capacity(
        &self,
        reservation_id: RequestId,
    ) -> Result<CapacityReservation, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        let row: Option<(String, String, String, i64, i64)> = sqlx::query_as(
            "SELECT session_id,campaign_id,resource,amount,released FROM capacity_reservations WHERE reservation_id=?",
        ).bind(reservation_id.to_string()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?;
        let (session, campaign, resource, amount, released) = row.ok_or(StoreError::Invalid)?;
        let session_id = parse_session_id(&session)?;
        let campaign_id = parse_participant_id(&campaign)?;
        let resource = parse_capacity_resource(&resource)?;
        let amount = u64::try_from(amount).map_err(|_| StoreError::Corrupt)?;
        if released == 0 {
            let now = self.now();
            let changed = sqlx::query("UPDATE capacity_reservations SET released=1,released_at_seconds=?,released_at_nanos=? WHERE reservation_id=? AND released=0")
                .bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).bind(reservation_id.to_string()).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected();
            if changed != 1 {
                return Err(StoreError::Corrupt);
            }
            crash_at("capacity.release.after_reservation");
            let amount_i64 = i64::try_from(amount).map_err(|_| StoreError::Corrupt)?;
            if sqlx::query("UPDATE capacity_session_usage SET used=used-? WHERE session_id=? AND resource=? AND used>=?")
                .bind(amount_i64).bind(&session).bind(resource.as_str()).bind(amount_i64).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected() != 1
                || sqlx::query("UPDATE capacity_global_usage SET used=used-? WHERE resource=? AND used>=?")
                .bind(amount_i64).bind(resource.as_str()).bind(amount_i64).execute(&mut *tx).await.map_err(map_sqlx)?.rows_affected() != 1 { return Err(StoreError::Corrupt); }
            crash_at("capacity.release.after_accounting");
        }
        if resource == CapacityResource::Subscriptions {
            sqlx::query("DELETE FROM capacity_reservations WHERE reservation_id=? AND released=1")
                .bind(reservation_id.to_string())
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx)?;
            sqlx::query(
                "DELETE FROM capacity_session_usage WHERE session_id=? AND resource=? AND used=0",
            )
            .bind(&session)
            .bind(resource.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
            sqlx::query("DELETE FROM capacity_global_usage WHERE resource=? AND used=0")
                .bind(resource.as_str())
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        }
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("capacity.release.after_commit");
        Ok(CapacityReservation {
            reservation_id,
            session_id,
            campaign_id,
            resource,
            amount,
            released: true,
        })
    }

    async fn capacity_metrics(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<CapacityMetric>, StoreError> {
        let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM sessions WHERE session_id=?")
            .bind(session_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx)?;
        if exists.is_none() {
            return Err(StoreError::SessionNotFound { session_id });
        }
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let mut result = Vec::with_capacity(CapacityResource::ALL.len());
        for resource in CapacityResource::ALL {
            let (derived_session, derived_global) =
                derived_capacity_usage(&mut tx, session_id, resource).await?;
            let session_reserved: i64 = sqlx::query_scalar("SELECT COALESCE((SELECT used FROM capacity_session_usage WHERE session_id=? AND resource=?),0)").bind(session_id.to_string()).bind(resource.as_str()).fetch_one(&mut *tx).await.map_err(map_sqlx)?;
            let global_reserved: i64 = sqlx::query_scalar(
                "SELECT COALESCE((SELECT used FROM capacity_global_usage WHERE resource=?),0)",
            )
            .bind(resource.as_str())
            .fetch_one(&mut *tx)
            .await
            .map_err(map_sqlx)?;
            let limits = self.limit_profile.get(resource);
            result.push(CapacityMetric {
                resource,
                session_used: derived_session
                    .checked_add(u64::try_from(session_reserved).map_err(|_| StoreError::Corrupt)?)
                    .ok_or(StoreError::Corrupt)?,
                session_limit: limits.per_session,
                global_used: derived_global
                    .checked_add(u64::try_from(global_reserved).map_err(|_| StoreError::Corrupt)?)
                    .ok_or(StoreError::Corrupt)?,
                global_limit: limits.global,
            });
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(result)
    }
}

fn parse_capacity_resource(value: &str) -> Result<CapacityResource, StoreError> {
    CapacityResource::ALL
        .into_iter()
        .find(|resource| resource.as_str() == value)
        .ok_or(StoreError::Corrupt)
}

#[cfg(test)]
pub(crate) fn set_approval_consume_pause(effect_id: Option<RequestId>) {
    *APPROVAL_CONSUME_PAUSE.lock().expect("test pause mutex") = effect_id;
    if effect_id.is_none() {
        APPROVAL_CONSUME_RELEASE.notify_waiters();
    }
}

#[cfg(test)]
pub(crate) async fn wait_approval_consume_entered() {
    APPROVAL_CONSUME_ENTERED.notified().await;
}

#[cfg(test)]
async fn approval_consume_pause(effect_id: RequestId) {
    let enabled = APPROVAL_CONSUME_PAUSE
        .lock()
        .expect("test pause mutex")
        .is_some_and(|target| target == effect_id);
    if enabled {
        APPROVAL_CONSUME_ENTERED.notify_one();
        APPROVAL_CONSUME_RELEASE.notified().await;
    }
}

#[cfg(not(test))]
fn approval_consume_pause(_effect_id: RequestId) -> std::future::Ready<()> {
    std::future::ready(())
}

pub(crate) const DUE_SESSION_DELIVERY_WORK_SQL: &str =
    include_str!("../queries/due_session_delivery_work.sql");

macro_rules! approval_try_prewrite {
    ($tx:ident, $value:expr) => {
        match $value {
            Ok(value) => value,
            Err(error) => {
                $tx.commit().await.map_err(map_sqlx)?;
                return Err(error);
            }
        }
    };
}
macro_rules! approval_require_prewrite {
    ($tx:ident, $condition:expr) => {
        if !$condition {
            $tx.commit().await.map_err(map_sqlx)?;
            return Err(StoreError::Invalid);
        }
    };
}

impl ApprovalStore for SqliteStore {
    async fn list_reserved_approval_effects(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<ApprovalEffectIntent>, StoreError> {
        const RECOVERY_BATCH_LIMIT: usize = 128;
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        validate_approval_schema(&mut tx)
            .await
            .map_err(map_database_error)?;
        let rows = sqlx::query("SELECT effect_id FROM approval_effect_intents WHERE session_id=? AND phase='reserved' ORDER BY effect_id LIMIT 129")
            .bind(session_id.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        if rows.len() > RECOVERY_BATCH_LIMIT {
            return Err(StoreError::Unavailable);
        }
        let mut effects = Vec::with_capacity(rows.len());
        for row in rows {
            let raw: String = row.try_get("effect_id").map_err(map_sqlx)?;
            let id = RequestId::from_uuid(Uuid::parse_str(&raw).map_err(|_| StoreError::Corrupt)?)
                .map_err(|_| StoreError::Corrupt)?;
            let effect = approval_effect_in(&mut tx, id).await?;
            if effect.session_id != session_id
                || effect.phase != ApprovalEffectPhase::Reserved
                || effect.finished_at.is_some()
            {
                return Err(StoreError::Corrupt);
            }
            effects.push(effect);
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(effects)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "causal Approval request validation is intentionally atomic"
    )]
    async fn request_approval(
        &self,
        c: RequestApproval,
    ) -> Result<Mutation<ApprovalRequest>, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(v) = approval_replay(&mut tx, c.context, "approval.request", c.digest()).await?
        {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(v));
        }
        let now = approval_try_prewrite!(
            tx,
            approval_authorize(
                &mut tx,
                c.session_id,
                c.context.caller(),
                c.owner_epoch,
                self.now(),
            )
            .await
        );
        approval_require_prewrite!(tx, c.expires_at > now);
        let approval_exists: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM approval_requests WHERE approval_id=? LIMIT 1")
                .bind(c.approval_id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        approval_require_prewrite!(tx, approval_exists.is_none());
        let valid:Option<i64>=sqlx::query_scalar("SELECT 1 FROM participants p JOIN operations o ON o.operation_id=? AND o.participant_id=p.participant_id WHERE p.participant_id=? AND p.session_id=? AND o.session_id=? AND o.state IN ('running','waiting')")
            .bind(c.operation_id.to_string()).bind(c.requester_id.to_string()).bind(c.session_id.to_string()).bind(c.session_id.to_string()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?;
        approval_require_prewrite!(tx, valid.is_some());
        let causal_bytes: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT snapshot FROM messages WHERE message_id=?")
                .bind(c.source_message_id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        let causal: MessageSnapshot = approval_try_prewrite!(
            tx,
            serde_json::from_slice(&causal_bytes.ok_or(StoreError::Invalid)?)
                .map_err(|_| StoreError::Corrupt)
        );
        let operation = approval_try_prewrite!(
            tx,
            load_operation_in(&mut tx, c.operation_id)
                .await?
                .ok_or(StoreError::Invalid)
        );
        let requester = approval_try_prewrite!(
            tx,
            load_participant_in(&mut tx, c.requester_id)
                .await?
                .ok_or(StoreError::Invalid)
        );
        let coordinator = requester.parent_participant_id.unwrap_or(c.requester_id);
        approval_require_prewrite!(
            tx,
            causal.session_id == c.session_id
                && causal.destination == c.requester_id
                && causal.source == coordinator
                && causal.message_id == operation.input_message_id
                && causal.correlation.operation_id == Some(c.operation_id)
                && matches!(causal.envelope.body(), navigator_domain::MessageBody::OperationInput { operation_id, input_digest } if *operation_id == c.operation_id && *input_digest == operation.input_digest)
                && matches!(causal.state, MessageDeliveryState::Accepted { attempt_id, .. } if attempt_id == c.source_delivery_attempt_id)
        );
        let command_digest = c.digest();
        let v = ApprovalRequest {
            id: c.approval_id,
            session_id: c.session_id,
            requester_id: c.requester_id,
            operation_id: c.operation_id,
            source_message_id: c.source_message_id,
            source_delivery_attempt_id: c.source_delivery_attempt_id,
            coordinator_id: coordinator,
            capability: c.capability,
            resource: c.resource,
            summary: c.summary,
            status: ApprovalStatus::Pending,
            expires_at: c.expires_at,
            grant_id: None,
            decision_source: None,
            created_at: now,
            decided_at: None,
            revision: Revision::initial(),
        }
        .validate()
        .map_err(|_| StoreError::Invalid)?;
        sqlx::query("INSERT INTO approval_requests(approval_id,session_id,requester_id,operation_id,capability,resource_hash,status,expires_seconds,expires_nanos,revision,snapshot) VALUES(?,?,?,?,?,?,'pending',?,?,1,?)")
            .bind(v.id.to_string()).bind(v.session_id.to_string()).bind(v.requester_id.to_string()).bind(v.operation_id.to_string()).bind(v.capability.as_str()).bind(v.resource.digest().as_bytes().as_slice()).bind(v.expires_at.unix_seconds()).bind(i64::from(v.expires_at.nanoseconds())).bind(serde_json::to_vec(&v).map_err(|_|StoreError::Invalid)?).execute(&mut *tx).await.map_err(map_sqlx)?;
        crash_at("approval.after_row_write");
        approval_record(&mut tx, c.context, "approval.request", command_digest, &v).await?;
        approval_event(
            &mut tx,
            c.context.request_id(),
            c.session_id,
            v.revision,
            "approval.requested",
            &v,
            now,
        )
        .await?;
        crash_at("approval.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("approval.after_commit");
        Ok(Mutation::Applied(v))
    }
    async fn approve_request(
        &self,
        c: ApproveRequest,
    ) -> Result<Mutation<ApprovedRequest>, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(v) = approval_replay(&mut tx, c.context, "approval.approve", c.digest()).await?
        {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(v));
        }
        let now = approval_try_prewrite!(
            tx,
            approval_authorize(
                &mut tx,
                c.session_id,
                c.context.caller(),
                c.owner_epoch,
                self.now(),
            )
            .await
        );
        let mut r = approval_try_prewrite!(tx, approval_request_in(&mut tx, c.approval_id).await);
        approval_try_prewrite!(tx, c.validate_against(&r, now));
        approval_try_prewrite!(tx, approval_operation_live(&mut tx, &r).await);
        let grant_exists: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM approval_grants WHERE grant_id=? LIMIT 1")
                .bind(c.grant_id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        approval_require_prewrite!(tx, grant_exists.is_none());
        let grant = ApprovalGrant {
            id: c.grant_id,
            request_id: r.id,
            session_id: r.session_id,
            subject_id: r.requester_id,
            operation_id: r.operation_id,
            capability: r.capability.clone(),
            resource_hash: r.resource.digest(),
            issued_by: ApprovalDecisionSource::TrustedConsumer,
            max_uses: c.max_uses,
            used_count: 0,
            expires_at: c.grant_expires_at,
            revoked_at: None,
            created_at: now,
            revision: Revision::initial(),
        }
        .validate()
        .map_err(|_| StoreError::Invalid)?;
        r.status = ApprovalStatus::Granted;
        r.grant_id = Some(grant.id);
        r.decision_source = Some(ApprovalDecisionSource::TrustedConsumer);
        r.decided_at = Some(now);
        r.revision = r.revision.next().ok_or(StoreError::Invalid)?;
        let out = ApprovedRequest {
            request: r.clone(),
            grant: grant.clone(),
        }
        .validate()?;
        approval_update_request(&mut tx, &r).await?;
        sqlx::query("INSERT INTO approval_grants(grant_id,approval_id,session_id,subject_id,operation_id,capability,resource_hash,max_uses,used_count,expires_seconds,expires_nanos,revoked,revision,snapshot) VALUES(?,?,?,?,?,?,?,?,0,?,?,0,1,?)").bind(grant.id.to_string()).bind(grant.request_id.to_string()).bind(grant.session_id.to_string()).bind(grant.subject_id.to_string()).bind(grant.operation_id.to_string()).bind(grant.capability.as_str()).bind(grant.resource_hash.as_bytes().as_slice()).bind(i64::from(grant.max_uses)).bind(grant.expires_at.unix_seconds()).bind(i64::from(grant.expires_at.nanoseconds())).bind(serde_json::to_vec(&grant).map_err(|_|StoreError::Invalid)?).execute(&mut *tx).await.map_err(map_sqlx)?;
        crash_at("approval.after_row_write");
        approval_insert_decision_relay(&mut tx, c.context.request_id(), &r, now).await?;
        approval_record(&mut tx, c.context, "approval.approve", c.digest(), &out).await?;
        approval_event(
            &mut tx,
            c.context.request_id(),
            c.session_id,
            r.revision,
            "approval.granted",
            &r,
            now,
        )
        .await?;
        crash_at("approval.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("approval.after_commit");
        Ok(Mutation::Applied(out))
    }
    async fn deny_request(&self, c: DenyRequest) -> Result<Mutation<ApprovalRequest>, StoreError> {
        approval_decide_terminal(
            self,
            c.context,
            c.session_id,
            c.owner_epoch,
            c.approval_id,
            c.expected_revision,
            c.digest(),
            "approval.deny",
            ApprovalStatus::Denied,
        )
        .await
    }
    async fn expire_approval(
        &self,
        c: ExpireApproval,
    ) -> Result<Mutation<ApprovalRequest>, StoreError> {
        approval_decide_terminal(
            self,
            c.context,
            c.session_id,
            c.owner_epoch,
            c.approval_id,
            c.expected_revision,
            c.digest(),
            "approval.expire",
            ApprovalStatus::Expired,
        )
        .await
    }
    async fn revoke_approval_grant(
        &self,
        c: RevokeApprovalGrant,
    ) -> Result<Mutation<ApprovalGrant>, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(v) = approval_replay(&mut tx, c.context, "approval.revoke", c.digest()).await? {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(v));
        }
        let now = approval_try_prewrite!(
            tx,
            approval_authorize(
                &mut tx,
                c.session_id,
                c.context.caller(),
                c.owner_epoch,
                self.now(),
            )
            .await
        );
        let mut g = approval_try_prewrite!(tx, approval_grant_in(&mut tx, c.grant_id).await);
        let mut r = approval_try_prewrite!(tx, approval_request_in(&mut tx, g.request_id).await);
        approval_try_prewrite!(tx, c.validate_against(&r, &g, now));
        g.revoked_at = Some(now);
        g.revision = g.revision.next().ok_or(StoreError::Invalid)?;
        r.status = ApprovalStatus::Revoked;
        r.revision = r.revision.next().ok_or(StoreError::Invalid)?;
        approval_update_grant(&mut tx, &g).await?;
        approval_update_request(&mut tx, &r).await?;
        approval_record(&mut tx, c.context, "approval.revoke", c.digest(), &g).await?;
        approval_event(
            &mut tx,
            c.context.request_id(),
            c.session_id,
            g.revision,
            "approval.revoked",
            &g,
            now,
        )
        .await?;
        crash_at("approval.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("approval.after_commit");
        Ok(Mutation::Applied(g))
    }
    async fn consume_approval_grant(
        &self,
        c: ConsumeApprovalGrant,
    ) -> Result<Mutation<ConsumedApprovalGrant>, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(v) = approval_replay(&mut tx, c.context, "approval.consume", c.digest()).await?
        {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(v));
        }
        let now = approval_try_prewrite!(
            tx,
            approval_authorize(
                &mut tx,
                c.session_id,
                c.context.caller(),
                c.owner_epoch,
                self.now(),
            )
            .await
        );
        let mut g = approval_try_prewrite!(tx, approval_grant_in(&mut tx, c.grant_id).await);
        let mut r = approval_try_prewrite!(tx, approval_request_in(&mut tx, g.request_id).await);
        let next = approval_try_prewrite!(tx, c.validate_against(&g, &r, now));
        approval_try_prewrite!(tx, approval_operation_live(&mut tx, &r).await);
        approval_try_prewrite!(
            tx,
            approval_effect_identity_available(&mut tx, c.context.request_id(), c.effect_id).await
        );
        g.used_count = g.used_count.checked_add(1).ok_or(StoreError::Invalid)?;
        g.revision = g.revision.next().ok_or(StoreError::Invalid)?;
        r.status = next;
        if next == ApprovalStatus::Consumed {
            r.revision = r.revision.next().ok_or(StoreError::Invalid)?;
            approval_update_request(&mut tx, &r).await?;
        }
        let command_digest = c.digest();
        let e = ApprovalEffectIntent {
            effect_id: c.effect_id,
            session_id: c.session_id,
            grant_id: g.id,
            subject_id: c.subject_id,
            operation_id: c.operation_id,
            capability: c.capability,
            resource_hash: c.resource_hash,
            phase: ApprovalEffectPhase::Reserved,
            created_at: now,
            finished_at: None,
            revision: Revision::initial(),
        }
        .validate()
        .map_err(|_| StoreError::Invalid)?;
        approval_update_grant(&mut tx, &g).await?;
        sqlx::query("INSERT INTO approval_effect_intents(effect_id,session_id,grant_id,operation_id,phase,revision,snapshot) VALUES(?,?,?,?,'reserved',1,?)").bind(e.effect_id.to_string()).bind(e.session_id.to_string()).bind(e.grant_id.to_string()).bind(e.operation_id.to_string()).bind(serde_json::to_vec(&e).map_err(|_|StoreError::Invalid)?).execute(&mut *tx).await.map_err(map_sqlx)?;
        crash_at("approval.after_row_write");
        approval_consume_pause(c.effect_id).await;
        let out = ConsumedApprovalGrant {
            grant: g,
            effect: e,
        }
        .validate()?;
        approval_record(&mut tx, c.context, "approval.consume", command_digest, &out).await?;
        approval_event(
            &mut tx,
            c.context.request_id(),
            c.session_id,
            out.effect.revision,
            "approval.consumed",
            &out.effect,
            now,
        )
        .await?;
        crash_at("approval.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("approval.after_commit");
        Ok(Mutation::Applied(out))
    }
    async fn finish_approval_effect(
        &self,
        c: FinishApprovalEffect,
    ) -> Result<Mutation<ApprovalEffectIntent>, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(v) =
            approval_replay(&mut tx, c.context, "approval.effect.finish", c.digest()).await?
        {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(v));
        }
        let now = approval_try_prewrite!(
            tx,
            approval_authorize(
                &mut tx,
                c.session_id,
                c.context.caller(),
                c.owner_epoch,
                self.now(),
            )
            .await
        );
        let mut e = approval_try_prewrite!(tx, approval_effect_in(&mut tx, c.effect_id).await);
        approval_try_prewrite!(tx, c.validate_against(&e));
        e.phase = c.phase.into();
        e.finished_at = Some(now);
        e.revision = e.revision.next().ok_or(StoreError::Invalid)?;
        e = e.validate().map_err(|_| StoreError::Invalid)?;
        sqlx::query(
            "UPDATE approval_effect_intents SET phase=?,revision=?,snapshot=? WHERE effect_id=?",
        )
        .bind(approval_effect_phase(e.phase))
        .bind(i64::try_from(e.revision.get()).map_err(|_| StoreError::Invalid)?)
        .bind(serde_json::to_vec(&e).map_err(|_| StoreError::Invalid)?)
        .bind(e.effect_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        crash_at("approval.after_row_write");
        approval_record(&mut tx, c.context, "approval.effect.finish", c.digest(), &e).await?;
        approval_event(
            &mut tx,
            c.context.request_id(),
            c.session_id,
            e.revision,
            "approval.effect.finished",
            &e,
            now,
        )
        .await?;
        crash_at("approval.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("approval.after_commit");
        Ok(Mutation::Applied(e))
    }
    async fn load_approval_request(
        &self,
        id: ApprovalRequestId,
    ) -> Result<ApprovalRequest, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(map_sqlx)?;
        validate_approval_schema(&mut connection)
            .await
            .map_err(map_database_error)?;
        let b: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT snapshot FROM approval_requests WHERE approval_id=?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx)?;
        serde_json::from_slice(&b.ok_or(StoreError::Invalid)?).map_err(|_| StoreError::Corrupt)
    }
    async fn load_approval_grant(&self, id: GrantId) -> Result<ApprovalGrant, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(map_sqlx)?;
        validate_approval_schema(&mut connection)
            .await
            .map_err(map_database_error)?;
        let b: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT snapshot FROM approval_grants WHERE grant_id=?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx)?;
        serde_json::from_slice(&b.ok_or(StoreError::Invalid)?).map_err(|_| StoreError::Corrupt)
    }
    async fn load_approval_effect(
        &self,
        id: RequestId,
    ) -> Result<ApprovalEffectIntent, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(map_sqlx)?;
        validate_approval_schema(&mut connection)
            .await
            .map_err(map_database_error)?;
        let b: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT snapshot FROM approval_effect_intents WHERE effect_id=?")
                .bind(id.to_string())
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx)?;
        serde_json::from_slice(&b.ok_or(StoreError::Invalid)?).map_err(|_| StoreError::Corrupt)
    }
}

async fn approval_authorize(
    tx: &mut Transaction<'_, Sqlite>,
    session: SessionId,
    caller: HostId,
    epoch: FencingEpoch,
    observed: Timestamp,
) -> Result<Timestamp, StoreError> {
    let row = require_open_session(tx, session, StoreAction::StartOperation).await?;
    let now = advance_time_floor(tx, session, row.time_floor, observed).await?;
    require_owner(&row, caller, epoch, now)?;
    Ok(now)
}
async fn approval_request_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: ApprovalRequestId,
) -> Result<ApprovalRequest, StoreError> {
    validate_approval_schema(tx)
        .await
        .map_err(map_database_error)?;
    let b: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT snapshot FROM approval_requests WHERE approval_id=?")
            .bind(id.to_string())
            .fetch_optional(&mut **tx)
            .await
            .map_err(map_sqlx)?;
    serde_json::from_slice(&b.ok_or(StoreError::Invalid)?).map_err(|_| StoreError::Corrupt)
}
async fn approval_grant_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: GrantId,
) -> Result<ApprovalGrant, StoreError> {
    validate_approval_schema(tx)
        .await
        .map_err(map_database_error)?;
    let b: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT snapshot FROM approval_grants WHERE grant_id=?")
            .bind(id.to_string())
            .fetch_optional(&mut **tx)
            .await
            .map_err(map_sqlx)?;
    serde_json::from_slice(&b.ok_or(StoreError::Invalid)?).map_err(|_| StoreError::Corrupt)
}
async fn approval_effect_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: RequestId,
) -> Result<ApprovalEffectIntent, StoreError> {
    validate_approval_schema(tx)
        .await
        .map_err(map_database_error)?;
    let b: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT snapshot FROM approval_effect_intents WHERE effect_id=?")
            .bind(id.to_string())
            .fetch_optional(&mut **tx)
            .await
            .map_err(map_sqlx)?;
    serde_json::from_slice(&b.ok_or(StoreError::Invalid)?).map_err(|_| StoreError::Corrupt)
}
async fn approval_operation_live(
    tx: &mut Transaction<'_, Sqlite>,
    r: &ApprovalRequest,
) -> Result<(), StoreError> {
    let ok:Option<i64>=sqlx::query_scalar("SELECT 1 FROM operations WHERE operation_id=? AND session_id=? AND participant_id=? AND state IN ('running','waiting')").bind(r.operation_id.to_string()).bind(r.session_id.to_string()).bind(r.requester_id.to_string()).fetch_optional(&mut **tx).await.map_err(map_sqlx)?;
    if ok.is_some() {
        Ok(())
    } else {
        Err(StoreError::Invalid)
    }
}

pub(crate) async fn approval_insert_decision_relay(
    tx: &mut Transaction<'_, Sqlite>,
    request_id: RequestId,
    approval: &ApprovalRequest,
    now: Timestamp,
) -> Result<(), StoreError> {
    let tag: &[u8] = match approval.status {
        ApprovalStatus::Granted => b"granted",
        ApprovalStatus::Denied => b"denied",
        _ => return Err(StoreError::Invalid),
    };
    let mut identity = approval.id.as_uuid().as_bytes().to_vec();
    identity.extend_from_slice(tag);
    let mut raw: [u8; 16] = SemanticDigest::v1(
        &Capability::new("approval.decision.relay.v1").expect("static capability"),
        &identity,
    )
    .as_bytes()[..16]
        .try_into()
        .map_err(|_| StoreError::Corrupt)?;
    raw[6] = (raw[6] & 0x0f) | 0x40;
    raw[8] = (raw[8] & 0x3f) | 0x80;
    let message_id =
        MessageId::from_uuid(Uuid::from_bytes(raw)).map_err(|_| StoreError::Corrupt)?;
    let envelope = ValidatedMessageEnvelope::approval_decision(
        approval.id,
        approval.operation_id,
        approval.status,
        approval.grant_id,
    );
    let counter: Option<(i64, i64, i64)> = sqlx::query_as("SELECT next_sequence,queued_bytes,queued_messages FROM mailbox_counters WHERE destination_participant_id=?")
        .bind(approval.requester_id.to_string()).fetch_optional(&mut **tx).await.map_err(map_sqlx)?;
    let (sequence, queued, count) = counter.unwrap_or((1, 0, 0));
    let queued_bytes = u64::try_from(queued)
        .map_err(|_| StoreError::Corrupt)?
        .checked_add(u64::try_from(envelope.as_bytes().len()).map_err(|_| StoreError::Corrupt)?)
        .ok_or(StoreError::MailboxQuotaExceeded)?;
    let queued_messages = u64::try_from(count)
        .map_err(|_| StoreError::Corrupt)?
        .checked_add(1)
        .ok_or(StoreError::MailboxQuotaExceeded)?;
    if queued_bytes > MAX_MAILBOX_QUEUED_BYTES || queued_messages > MAX_MAILBOX_QUEUED_MESSAGES {
        return Err(StoreError::MailboxQuotaExceeded);
    }
    let snapshot = MessageSnapshot {
        session_id: approval.session_id,
        message_id,
        source: approval.coordinator_id,
        destination: approval.requester_id,
        mailbox_sequence: u64::try_from(sequence).map_err(|_| StoreError::Corrupt)?,
        priority: MessagePriority::Control,
        correlation: MessageCorrelation {
            operation_id: Some(approval.operation_id),
            in_reply_to: Some(approval.source_message_id),
        },
        envelope,
        attempt_count: 0,
        state: MessageDeliveryState::Queued,
        revision: Revision::initial(),
        created_at: now,
        updated_at: now,
    };
    sqlx::query("INSERT INTO messages(message_id,session_id,source_participant_id,destination_participant_id,mailbox_sequence,priority,snapshot) VALUES(?,?,?,?,?,0,?)")
        .bind(snapshot.message_id.to_string()).bind(snapshot.session_id.to_string()).bind(snapshot.source.to_string()).bind(snapshot.destination.to_string()).bind(sequence).bind(serde_json::to_vec(&snapshot).map_err(|_| StoreError::Corrupt)?).execute(&mut **tx).await.map_err(map_sqlx)?;
    crash_at("approval.after_relay_message");
    sqlx::query("INSERT INTO mailbox_counters(destination_participant_id,next_sequence,queued_bytes,queued_messages) VALUES(?,?,?,?) ON CONFLICT(destination_participant_id) DO UPDATE SET next_sequence=excluded.next_sequence,queued_bytes=excluded.queued_bytes,queued_messages=excluded.queued_messages")
        .bind(snapshot.destination.to_string()).bind(sequence.checked_add(1).ok_or(StoreError::Corrupt)?).bind(i64::try_from(queued_bytes).map_err(|_| StoreError::Corrupt)?).bind(i64::try_from(queued_messages).map_err(|_| StoreError::Corrupt)?).execute(&mut **tx).await.map_err(map_sqlx)?;
    crash_at("approval.after_relay_counter");
    append_message_event(tx, request_id, &snapshot, now).await
}
async fn approval_update_request(
    tx: &mut Transaction<'_, Sqlite>,
    v: &ApprovalRequest,
) -> Result<(), StoreError> {
    let changed = sqlx::query(
        "UPDATE approval_requests SET status=?,revision=?,snapshot=? WHERE approval_id=?",
    )
    .bind(format!("{:?}", v.status).to_ascii_lowercase())
    .bind(i64::try_from(v.revision.get()).map_err(|_| StoreError::Invalid)?)
    .bind(serde_json::to_vec(v).map_err(|_| StoreError::Invalid)?)
    .bind(v.id.to_string())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx)?
    .rows_affected();
    if changed == 1 {
        crash_at("approval.after_row_write");
        Ok(())
    } else {
        Err(StoreError::Invalid)
    }
}
async fn approval_update_grant(
    tx: &mut Transaction<'_, Sqlite>,
    v: &ApprovalGrant,
) -> Result<(), StoreError> {
    let changed = sqlx::query(
        "UPDATE approval_grants SET used_count=?,revoked=?,revision=?,snapshot=? WHERE grant_id=?",
    )
    .bind(i64::from(v.used_count))
    .bind(i64::from(v.revoked_at.is_some()))
    .bind(i64::try_from(v.revision.get()).map_err(|_| StoreError::Invalid)?)
    .bind(serde_json::to_vec(v).map_err(|_| StoreError::Invalid)?)
    .bind(v.id.to_string())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx)?
    .rows_affected();
    if changed == 1 {
        crash_at("approval.after_row_write");
        Ok(())
    } else {
        Err(StoreError::Invalid)
    }
}
async fn approval_replay<T: DeserializeOwned>(
    tx: &mut Transaction<'_, Sqlite>,
    ctx: navigator_store_api::RequestContext,
    action: &str,
    digest: SemanticDigest,
) -> Result<Option<T>, StoreError> {
    let row=sqlx::query("SELECT caller_host_id,action,semantic_digest,result FROM approval_mutations WHERE request_id=?").bind(ctx.request_id().to_string()).fetch_optional(&mut **tx).await.map_err(map_sqlx)?;
    let Some(row) = row else {
        let collision: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM request_ledger WHERE request_id=?
            UNION ALL SELECT 1 FROM effect_journal WHERE request_id=?
            UNION ALL SELECT 1 FROM effect_journal_mutations WHERE request_id=?
            UNION ALL SELECT 1 FROM recovery_classifications WHERE request_id=?
            UNION ALL SELECT 1 FROM tool_invocation_mutations WHERE request_id=?
            UNION ALL SELECT 1 FROM approval_effect_intents WHERE effect_id=? LIMIT 1",
        )
        .bind(ctx.request_id().to_string())
        .bind(ctx.request_id().to_string())
        .bind(ctx.request_id().to_string())
        .bind(ctx.request_id().to_string())
        .bind(ctx.request_id().to_string())
        .bind(ctx.request_id().to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx)?;
        if collision.is_some() {
            return Err(StoreError::RequestConflict {
                request_id: ctx.request_id(),
            });
        }
        return Ok(None);
    };
    validate_approval_schema(tx)
        .await
        .map_err(map_database_error)?;
    if row
        .try_get::<String, _>("caller_host_id")
        .map_err(map_sqlx)?
        != ctx.caller().to_string()
        || row.try_get::<String, _>("action").map_err(map_sqlx)? != action
        || row
            .try_get::<Vec<u8>, _>("semantic_digest")
            .map_err(map_sqlx)?
            .as_slice()
            != digest.as_bytes()
    {
        return Err(StoreError::RequestConflict {
            request_id: ctx.request_id(),
        });
    }
    serde_json::from_slice(&row.try_get::<Vec<u8>, _>("result").map_err(map_sqlx)?)
        .map(Some)
        .map_err(|_| StoreError::Corrupt)
}
async fn approval_record<T: Serialize>(
    tx: &mut Transaction<'_, Sqlite>,
    ctx: navigator_store_api::RequestContext,
    action: &str,
    digest: SemanticDigest,
    value: &T,
) -> Result<(), StoreError> {
    crash_at("approval.before_ledger_write");
    reject_global_request_collision(tx, ctx.request_id()).await?;
    reject_effect_request_collision(tx, ctx.request_id()).await?;
    sqlx::query("INSERT INTO approval_mutations(request_id,session_id,caller_host_id,action,semantic_digest,result) VALUES(?,?,?,?,?,?)").bind(ctx.request_id().to_string()).bind(approval_result_session(value)?).bind(ctx.caller().to_string()).bind(action).bind(digest.as_bytes().as_slice()).bind(serde_json::to_vec(value).map_err(|_|StoreError::Invalid)?).execute(&mut **tx).await.map_err(map_sqlx)?;
    crash_at("approval.after_ledger_write");
    Ok(())
}
fn approval_result_session<T: Serialize>(value: &T) -> Result<String, StoreError> {
    let v = serde_json::to_value(value).map_err(|_| StoreError::Invalid)?;
    v.get("session_id")
        .or_else(|| v.get("request").and_then(|r| r.get("session_id")))
        .or_else(|| v.get("effect").and_then(|r| r.get("session_id")))
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or(StoreError::Invalid)
}
async fn approval_event<T: Serialize>(
    tx: &mut Transaction<'_, Sqlite>,
    request: RequestId,
    session: SessionId,
    revision: Revision,
    event: &str,
    value: &T,
    now: Timestamp,
) -> Result<(), StoreError> {
    let v = serde_json::to_value(value).map_err(|_| StoreError::Invalid)?;
    let is_request = v.get("requester_id").is_some();
    let is_grant = v.get("max_uses").is_some();
    let approval_id = if is_request {
        v.get("id").cloned().unwrap_or(serde_json::Value::Null)
    } else if is_grant {
        v.get("request_id")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    } else if let Some(grant_id) = v.get("grant_id").and_then(|id| id.as_str()) {
        let id: Option<String> =
            sqlx::query_scalar("SELECT approval_id FROM approval_grants WHERE grant_id=?")
                .bind(grant_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(map_sqlx)?;
        id.map_or(serde_json::Value::Null, serde_json::Value::String)
    } else {
        serde_json::Value::Null
    };
    let resource_hash = if is_request {
        let digest = serde_json::from_value::<ApprovalRequest>(v.clone())
            .map_err(|_| StoreError::Invalid)?
            .resource
            .digest();
        serde_json::to_value(digest).map_err(|_| StoreError::Invalid)?
    } else {
        v.get("resource_hash")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };
    let summary_digest = v
        .get("summary")
        .and_then(|summary| summary.as_str())
        .map(|summary| {
            serde_json::to_value(SemanticDigest::v1(
                &Capability::new("approval.summary.v1").expect("static capability"),
                summary.as_bytes(),
            ))
            .expect("semantic digest serializes")
        });
    let request_state: Option<(String, i64)> = if let Some(approval_id) = approval_id.as_str() {
        sqlx::query_as("SELECT status,revision FROM approval_requests WHERE approval_id=?")
            .bind(approval_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(map_sqlx)?
    } else {
        None
    };
    let grant_revision: Option<i64> = if let Some(grant_id) =
        v.get("grant_id").and_then(|id| id.as_str()).or_else(|| {
            is_grant
                .then(|| v.get("id").and_then(|id| id.as_str()))
                .flatten()
        }) {
        sqlx::query_scalar("SELECT revision FROM approval_grants WHERE grant_id=?")
            .bind(grant_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(map_sqlx)?
    } else {
        None
    };
    let data=serde_json::to_vec(&serde_json::json!({
        "schema_version":1,
        "session_id":session,
        "approval_id":approval_id,
        "grant_id":if is_request{v.get("grant_id")}else if is_grant{v.get("id")}else{v.get("grant_id")},
        "effect_id":v.get("effect_id"),"subject_id":v.get("subject_id").or_else(||v.get("requester_id")),
        "operation_id":v.get("operation_id"),"capability":v.get("capability"),"resource_hash":resource_hash,
        "requester_id":v.get("requester_id"),"coordinator_id":v.get("coordinator_id"),
        "source_message_id":v.get("source_message_id"),"summary_digest":summary_digest,
        "status":request_state.as_ref().map(|state|state.0.as_str()).or_else(||v.get("status").and_then(|value|value.as_str())),
        "request_revision":request_state.as_ref().map(|state|state.1),
        "grant_revision":grant_revision,
        "effect_revision":(!is_request && !is_grant).then_some(revision.get()),
        "phase":v.get("phase"),"max_uses":v.get("max_uses"),"used_count":v.get("used_count"),
        "expires_at":v.get("expires_at"),"revoked_at":v.get("revoked_at"),"created_at":v.get("created_at"),
        "decided_at":v.get("decided_at"),"finished_at":v.get("finished_at"),"revision":revision.get()
    })).map_err(|_|StoreError::Invalid)?;
    let result = append_event_data(tx, request, session, revision, event, &data, now).await;
    if result.is_ok() {
        crash_at("approval.after_audit_write");
    }
    result
}
fn approval_effect_phase(v: ApprovalEffectPhase) -> &'static str {
    match v {
        ApprovalEffectPhase::Reserved => "reserved",
        ApprovalEffectPhase::Succeeded => "succeeded",
        ApprovalEffectPhase::Failed => "failed",
        ApprovalEffectPhase::Uncertain => "uncertain",
    }
}
#[expect(
    clippy::too_many_arguments,
    reason = "shared deny/expire transaction binds the full mutation identity"
)]
async fn approval_decide_terminal(
    store: &SqliteStore,
    ctx: navigator_store_api::RequestContext,
    session: SessionId,
    epoch: FencingEpoch,
    id: ApprovalRequestId,
    expected: Revision,
    digest: SemanticDigest,
    action: &str,
    status: ApprovalStatus,
) -> Result<Mutation<ApprovalRequest>, StoreError> {
    let mut tx = begin_immediate(&store.pool).await?;
    if let Some(v) = approval_replay(&mut tx, ctx, action, digest).await? {
        tx.commit().await.map_err(map_sqlx)?;
        return Ok(Mutation::Replayed(v));
    }
    let now = approval_try_prewrite!(
        tx,
        approval_authorize(&mut tx, session, ctx.caller(), epoch, store.now()).await
    );
    let mut r = approval_try_prewrite!(tx, approval_request_in(&mut tx, id).await);
    approval_require_prewrite!(
        tx,
        r.session_id == session && r.revision == expected && r.status == ApprovalStatus::Pending
    );
    if status == ApprovalStatus::Expired {
        approval_require_prewrite!(tx, now >= r.expires_at);
    } else {
        approval_require_prewrite!(tx, now < r.expires_at);
        approval_try_prewrite!(tx, approval_operation_live(&mut tx, &r).await);
        r.decision_source = Some(ApprovalDecisionSource::TrustedConsumer);
        r.decided_at = Some(now);
    }
    r.status = status;
    r.revision = r.revision.next().ok_or(StoreError::Invalid)?;
    r = r.validate().map_err(|_| StoreError::Invalid)?;
    approval_update_request(&mut tx, &r).await?;
    if status == ApprovalStatus::Denied {
        approval_insert_decision_relay(&mut tx, ctx.request_id(), &r, now).await?;
    }
    approval_record(&mut tx, ctx, action, digest, &r).await?;
    approval_event(
        &mut tx,
        ctx.request_id(),
        session,
        r.revision,
        if status == ApprovalStatus::Denied {
            "approval.denied"
        } else {
            "approval.expired"
        },
        &r,
        now,
    )
    .await?;
    crash_at("approval.before_commit");
    tx.commit().await.map_err(map_sqlx)?;
    crash_at("approval.after_commit");
    Ok(Mutation::Applied(r))
}

#[derive(Serialize, Deserialize)]
struct ProjectionTokenWire {
    session_id: SessionId,
    view: ProjectionView,
    generation: u64,
    checkpoint: u64,
    expires_seconds: i64,
    page_size: u16,
    last_sort_key: String,
    last_item_key: String,
    signature: [u8; 32],
}

// Every cursor coordinate is intentionally authenticated; grouping them would only hide the
// security-relevant binding from call sites.
#[allow(clippy::too_many_arguments)]
pub(crate) fn projection_signature(
    key: &[u8; 32],
    consumer: &ConsumerKey,
    session: SessionId,
    view: ProjectionView,
    generation: u64,
    checkpoint: u64,
    expires_seconds: i64,
    page_size: u16,
    last_sort: &str,
    last_item: &str,
) -> [u8; 32] {
    let bytes = serde_json::to_vec(&(
        consumer,
        session,
        view,
        generation,
        checkpoint,
        expires_seconds,
        page_size,
        last_sort,
        last_item,
    ))
    .expect("closed projection token input serializes");
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed-size projection MAC key");
    mac.update(b"navigator.projection.page-token.v1\0");
    mac.update(&bytes);
    mac.finalize().into_bytes().into()
}

#[allow(clippy::too_many_arguments)]
fn verify_projection_signature(
    key: &[u8; 32],
    consumer: &ConsumerKey,
    wire: &ProjectionTokenWire,
) -> bool {
    let bytes = serde_json::to_vec(&(
        consumer,
        wire.session_id,
        wire.view,
        wire.generation,
        wire.checkpoint,
        wire.expires_seconds,
        wire.page_size,
        &wire.last_sort_key,
        &wire.last_item_key,
    ))
    .expect("closed projection token input serializes");
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed-size projection MAC key");
    mac.update(b"navigator.projection.page-token.v1\0");
    mac.update(&bytes);
    mac.verify_slice(&wire.signature).is_ok()
}

#[allow(clippy::too_many_arguments)]
fn projection_token(
    key: &[u8; 32],
    consumer: &ConsumerKey,
    session: SessionId,
    view: ProjectionView,
    generation: u64,
    checkpoint: u64,
    expires_seconds: i64,
    page_size: u16,
    last_sort: String,
    last_item: String,
) -> Result<ProjectionPageToken, StoreError> {
    let signature = projection_signature(
        key,
        consumer,
        session,
        view,
        generation,
        checkpoint,
        expires_seconds,
        page_size,
        &last_sort,
        &last_item,
    );
    let wire = ProjectionTokenWire {
        session_id: session,
        view,
        generation,
        checkpoint,
        expires_seconds,
        page_size,
        last_sort_key: last_sort,
        last_item_key: last_item,
        signature,
    };
    ProjectionPageToken::new(serde_json::to_string(&wire).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Invalid)
}

struct ProjectionTarget {
    view: ProjectionView,
    key: String,
    sort: String,
    data: Vec<u8>,
    revision: u64,
    terminal: bool,
    kind: String,
}

#[expect(
    clippy::too_many_lines,
    reason = "one closed decoder keeps required event fields fail-closed"
)]
fn projection_event_targets(
    session_id: SessionId,
    event_revision: u64,
    event_type: &str,
    event_id: &str,
    data: &[u8],
) -> Result<Vec<ProjectionTarget>, StoreError> {
    let recognized = [
        "participant.",
        "operation.",
        "message.",
        "approval.",
        "recovery.",
        "capacity.",
        "failure.",
    ]
    .iter()
    .any(|prefix| event_type.starts_with(prefix));
    if !recognized {
        // Optional event families do not affect a projection, but still advance its checkpoint.
        return Ok(Vec::new());
    }
    if matches!(
        event_type,
        "participant.create_root" | "participant.create_child"
    ) {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_slice(data).map_err(|_| StoreError::Corrupt)?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        return Err(StoreError::Corrupt);
    }
    if value.get("session_id").and_then(serde_json::Value::as_str)
        != Some(session_id.to_string().as_str())
    {
        return Err(StoreError::Corrupt);
    }
    let id = |names: &[&str]| -> Result<String, StoreError> {
        names
            .iter()
            .find_map(|name| value.get(*name).and_then(serde_json::Value::as_str))
            .filter(|id| !id.is_empty())
            .map(str::to_owned)
            .ok_or(StoreError::Corrupt)
    };
    let uuid_id = |names: &[&str]| -> Result<String, StoreError> {
        let id = id(names)?;
        Uuid::parse_str(&id).map_err(|_| StoreError::Corrupt)?;
        Ok(id)
    };
    let required = |names: &[&str]| -> Result<(), StoreError> {
        if names
            .iter()
            .all(|name| value.get(*name).is_some_and(|v| !v.is_null()))
        {
            Ok(())
        } else {
            Err(StoreError::Corrupt)
        }
    };
    let target = if event_type.starts_with("participant.") {
        required(&[
            "participant_id",
            "template_id",
            "depth",
            "revision",
            "lifecycle",
        ])?;
        if event_type != "participant.created"
            || value.get("lifecycle").and_then(serde_json::Value::as_str) != Some("registered")
        {
            return Err(StoreError::Corrupt);
        }
        Some((ProjectionView::SessionTree, uuid_id(&["participant_id"])?))
    } else if event_type.starts_with("operation.") {
        required(&["operation_id", "participant_id", "state", "revision"])?;
        if value.get("state").and_then(serde_json::Value::as_str)
            != event_type.strip_prefix("operation.")
        {
            return Err(StoreError::Corrupt);
        }
        uuid_id(&["participant_id"])?;
        Some((ProjectionView::ActiveWork, uuid_id(&["operation_id"])?))
    } else if event_type.starts_with("message.") {
        required(&["message_id", "source", "destination", "state", "revision"])?;
        let expected_state = if event_type == "message.enqueued" {
            Some("queued")
        } else {
            event_type.strip_prefix("message.")
        };
        if value.get("state").and_then(serde_json::Value::as_str) != expected_state {
            return Err(StoreError::Corrupt);
        }
        uuid_id(&["source"])?;
        uuid_id(&["destination"])?;
        Some((ProjectionView::Delivery, uuid_id(&["message_id"])?))
    } else if event_type.starts_with("approval.") {
        // Every approval transition folds into one lifecycle row. Grant/effect identifiers are
        // causal links, never alternative projection identities.
        let status = value.get("status").and_then(serde_json::Value::as_str);
        let coherent = match event_type {
            "approval.requested" => status == Some("pending"),
            "approval.granted" => status == Some("granted"),
            "approval.denied" => status == Some("denied"),
            "approval.expired" => status == Some("expired"),
            "approval.revoked" => status == Some("revoked"),
            "approval.consumed" => matches!(status, Some("granted" | "consumed")),
            "approval.effect.finished" => matches!(
                value.get("phase").and_then(serde_json::Value::as_str),
                Some("succeeded" | "failed" | "uncertain")
            ),
            _ => false,
        };
        if !coherent {
            return Err(StoreError::Corrupt);
        }
        Some((ProjectionView::Approval, uuid_id(&["approval_id"])?))
    } else if event_type.starts_with("recovery.") {
        required(&["request_id", "classifications"])?;
        if event_type != "recovery.classified"
            || !value
                .get("classifications")
                .is_some_and(serde_json::Value::is_array)
        {
            return Err(StoreError::Corrupt);
        }
        Some((
            ProjectionView::Recovery,
            uuid_id(&["entity_id", "request_id"])?,
        ))
    } else if event_type.starts_with("capacity.") {
        if event_type != "capacity.observed" {
            return Err(StoreError::Corrupt);
        }
        required(&["scope_id", "resource", "available", "total", "revision"])?;
        if value
            .get("available")
            .and_then(serde_json::Value::as_u64)
            .zip(value.get("total").and_then(serde_json::Value::as_u64))
            .is_none_or(|(available, total)| available > total)
        {
            return Err(StoreError::Corrupt);
        }
        Some((ProjectionView::Capacity, id(&["scope_id", "resource"])?))
    } else if event_type.starts_with("failure.") {
        if event_type != "failure.recorded" {
            return Err(StoreError::Corrupt);
        }
        required(&["failure_id", "code", "entity_id", "revision"])?;
        if value
            .get("code")
            .and_then(serde_json::Value::as_str)
            .is_none()
            || value
                .get("entity_id")
                .and_then(serde_json::Value::as_str)
                .is_none()
        {
            return Err(StoreError::Corrupt);
        }
        Some((ProjectionView::Failure, uuid_id(&["failure_id"])?))
    } else {
        None
    };
    if value.get("revision").and_then(serde_json::Value::as_u64) != Some(event_revision) {
        return Err(StoreError::Corrupt);
    }
    let state = ["state", "status", "phase", "delivery_state", "lifecycle"]
        .iter()
        .find_map(|field| value.get(*field).and_then(serde_json::Value::as_str));
    let terminal = matches!(
        state,
        Some(
            "succeeded"
                | "failed"
                | "cancelled"
                | "consumed"
                | "denied"
                | "expired"
                | "revoked"
                | "accepted"
                | "dead_lettered"
        )
    );
    let derived_failure_key = target
        .as_ref()
        .map(|(_, key)| format!("{event_type}:{key}"));
    let mut targets = target.into_iter().collect::<Vec<_>>();
    if event_type.ends_with(".failed")
        || event_type.ends_with(".dead_lettered")
        || event_type.ends_with(".uncertain")
    {
        let failure_key = derived_failure_key.ok_or(StoreError::Corrupt)?;
        targets.push((ProjectionView::Failure, failure_key));
    }
    Ok(targets
        .into_iter()
        .map(|(view, key)| ProjectionTarget {
            view,
            key,
            sort: event_id.to_owned(),
            data: data.to_vec(),
            revision: event_revision,
            terminal,
            kind: event_type.to_owned(),
        })
        .collect())
}

#[expect(
    clippy::unnested_or_patterns,
    reason = "explicit predecessor rows are easier to audit as a transition table"
)]
fn projection_transition_allowed(view: ProjectionView, previous: &str, next: &str) -> bool {
    match view {
        ProjectionView::ActiveWork => matches!(
            (previous, next),
            (
                "operation.queued",
                "operation.starting" | "operation.cancelling"
            ) | (
                "operation.starting",
                "operation.running" | "operation.failed" | "operation.uncertain"
            ) | (
                "operation.running",
                "operation.waiting" | "operation.cancelling"
            ) | (
                "operation.running",
                "operation.succeeded"
                    | "operation.failed"
                    | "operation.blocked"
                    | "operation.uncertain"
            ) | (
                "operation.waiting",
                "operation.running" | "operation.cancelling"
            ) | (
                "operation.waiting",
                "operation.failed" | "operation.blocked" | "operation.uncertain"
            ) | (
                "operation.cancelling",
                "operation.cancelled" | "operation.failed" | "operation.uncertain"
            )
        ),
        ProjectionView::Delivery => matches!(
            (previous, next),
            (
                "message.enqueued" | "message.retry_scheduled",
                "message.leased"
            ) | (
                "message.leased",
                "message.retry_scheduled" | "message.acceptance_pending" | "message.dead_lettered"
            ) | (
                "message.acceptance_pending",
                "message.accepted" | "message.acceptance_unknown" | "message.uncertain"
            ) | (
                "message.acceptance_unknown",
                "message.accepted" | "message.uncertain"
            )
        ),
        ProjectionView::SessionTree => previous == next && previous == "participant.created",
        ProjectionView::Recovery | ProjectionView::Capacity | ProjectionView::Failure => false,
        ProjectionView::Approval => true,
    }
}

fn projection_initial_event(view: ProjectionView, kind: &str) -> bool {
    match view {
        ProjectionView::SessionTree => kind == "participant.created",
        ProjectionView::ActiveWork => kind == "operation.queued",
        ProjectionView::Delivery => kind == "message.enqueued",
        ProjectionView::Recovery => kind == "recovery.classified",
        ProjectionView::Capacity => kind == "capacity.observed",
        ProjectionView::Failure => {
            kind == "failure.recorded"
                || kind.contains("failed")
                || kind.ends_with(".uncertain")
                || kind.ends_with(".dead_lettered")
        }
        ProjectionView::Approval => false,
    }
}

impl ProjectionStore for SqliteStore {
    // The rebuild keeps source capture, pure ordered fold, and atomic generation publication
    // together so no intermediate representation can escape with a mismatched checkpoint.
    #[allow(clippy::too_many_lines)]
    async fn rebuild_projection(
        &self,
        session_id: SessionId,
    ) -> Result<ProjectionRebuild, StoreError> {
        tracing::debug!(session_id = %session_id, "starting projection rebuild");
        let source_head: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(position),0) FROM events WHERE session_id=?")
                .bind(session_id.to_string())
                .fetch_one(&self.pool)
                .await
                .map_err(map_sqlx)?;
        let current: Option<(i64, i64)> = sqlx::query_as(
            "SELECT generation,source_head_position FROM projection_heads WHERE session_id=?",
        )
        .bind(session_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        if let Some((generation, checkpoint)) = current
            && checkpoint == source_head
        {
            let now = self.now();
            sqlx::query("UPDATE projection_generations SET observed_time_floor_seconds=?,observed_time_floor_nanos=? WHERE session_id=? AND (observed_time_floor_seconds<? OR (observed_time_floor_seconds=? AND observed_time_floor_nanos<?))")
                .bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).bind(session_id.to_string()).bind(now.unix_seconds()).bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).execute(&self.pool).await.map_err(map_sqlx)?;
            return Ok(ProjectionRebuild {
                session_id,
                generation: u64::try_from(generation).map_err(|_| StoreError::Corrupt)?,
                checkpoint_position: if checkpoint == 0 {
                    None
                } else {
                    Some(
                        EventPosition::new(
                            u64::try_from(checkpoint).map_err(|_| StoreError::Corrupt)?,
                        )
                        .map_err(|_| StoreError::Corrupt)?,
                    )
                },
            });
        }
        let events = sqlx::query("SELECT event_id,position,revision,event_type,schema_version,data FROM events WHERE session_id=? ORDER BY position")
            .bind(session_id.to_string()).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        let mut expected = 1_i64;
        let mut rows = BTreeMap::<(String, String), (String, Vec<u8>)>::new();
        let mut histories = BTreeMap::<(String, String), (u64, bool, String)>::new();
        let mut tree = BTreeMap::<String, (Option<String>, u64)>::new();
        let mut approval_requests = BTreeSet::<String>::new();
        let mut approval_grants = BTreeMap::<String, String>::new();
        let mut approval_states = BTreeMap::<String, &'static str>::new();
        let mut approval_request_revisions = BTreeMap::<String, u64>::new();
        let mut approval_grant_revisions = BTreeMap::<String, u64>::new();
        let mut approval_effect_revisions = BTreeMap::<String, u64>::new();
        let mut completed_approval_effects = BTreeSet::<String>::new();
        for event in &events {
            let position: i64 = event.try_get("position").map_err(map_sqlx)?;
            if position != expected {
                return Err(StoreError::Corrupt);
            }
            expected = expected.checked_add(1).ok_or(StoreError::Corrupt)?;
            let schema: i64 = event.try_get("schema_version").map_err(map_sqlx)?;
            let event_type: String = event.try_get("event_type").map_err(map_sqlx)?;
            if schema != 1 {
                return Err(StoreError::Corrupt);
            }
            let event_id: String = event.try_get("event_id").map_err(map_sqlx)?;
            let data: Vec<u8> = event.try_get("data").map_err(map_sqlx)?;
            let revision = u64::try_from(event.try_get::<i64, _>("revision").map_err(map_sqlx)?)
                .map_err(|_| StoreError::Corrupt)?;
            let decoded =
                projection_event_targets(session_id, revision, &event_type, &event_id, &data);
            for target in decoded? {
                let identity = (target.view.as_str().to_owned(), target.key.clone());
                if target.view == ProjectionView::SessionTree {
                    let value: serde_json::Value =
                        serde_json::from_slice(&target.data).map_err(|_| StoreError::Corrupt)?;
                    let parent = value
                        .get("parent_participant_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let depth = value.get("depth").and_then(serde_json::Value::as_u64);
                    if let Some((prior_parent, prior_depth)) = tree.get(&target.key) {
                        if parent
                            .as_ref()
                            .is_some_and(|value| Some(value) != prior_parent.as_ref())
                            || depth.is_some_and(|value| value != *prior_depth)
                        {
                            return Err(StoreError::Corrupt);
                        }
                    } else {
                        let depth = depth.ok_or(StoreError::Corrupt)?;
                        match parent.as_ref() {
                            None if depth == 1
                                && tree.values().all(|(parent, _)| parent.is_some()) => {}
                            Some(parent)
                                if tree
                                    .get(parent)
                                    .is_some_and(|(_, parent_depth)| depth == parent_depth + 1) => {
                            }
                            _ => return Err(StoreError::Corrupt),
                        }
                        tree.insert(target.key.clone(), (parent, depth));
                    }
                }
                if target.view == ProjectionView::Approval {
                    let value: serde_json::Value =
                        serde_json::from_slice(&target.data).map_err(|_| StoreError::Corrupt)?;
                    let approval_id = value
                        .get("approval_id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(StoreError::Corrupt)?
                        .to_owned();
                    let grant_id = value
                        .get("grant_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let request_revision = value
                        .get("request_revision")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or(StoreError::Corrupt)?;
                    match target.kind.as_str() {
                        "approval.requested" if grant_id.is_none() => {
                            if request_revision != 1
                                || !approval_requests.insert(approval_id.clone())
                                || approval_states.insert(approval_id, "requested").is_some()
                            {
                                return Err(StoreError::Corrupt);
                            }
                            approval_request_revisions.insert(target.key.clone(), 1);
                        }
                        "approval.granted" => {
                            let grant_id = grant_id.ok_or(StoreError::Corrupt)?;
                            let grant_revision = value
                                .get("grant_revision")
                                .and_then(serde_json::Value::as_u64)
                                .ok_or(StoreError::Corrupt)?;
                            if approval_states.get(&approval_id) != Some(&"requested")
                                || request_revision
                                    != approval_request_revisions
                                        .get(&approval_id)
                                        .copied()
                                        .and_then(|revision| revision.checked_add(1))
                                        .ok_or(StoreError::Corrupt)?
                                || grant_revision != 1
                                || approval_grants
                                    .insert(grant_id, approval_id.clone())
                                    .is_some()
                            {
                                return Err(StoreError::Corrupt);
                            }
                            approval_request_revisions
                                .insert(approval_id.clone(), request_revision);
                            let grant_id = value
                                .get("grant_id")
                                .and_then(serde_json::Value::as_str)
                                .ok_or(StoreError::Corrupt)?
                                .to_owned();
                            approval_grant_revisions.insert(grant_id, grant_revision);
                            approval_states.insert(approval_id, "granted");
                        }
                        "approval.denied" | "approval.expired" => {
                            if approval_states.get(&approval_id) != Some(&"requested")
                                || request_revision
                                    != approval_request_revisions
                                        .get(&approval_id)
                                        .copied()
                                        .and_then(|revision| revision.checked_add(1))
                                        .ok_or(StoreError::Corrupt)?
                                || grant_id.is_some()
                            {
                                return Err(StoreError::Corrupt);
                            }
                            approval_request_revisions
                                .insert(approval_id.clone(), request_revision);
                            approval_states.insert(
                                approval_id,
                                if target.kind == "approval.denied" {
                                    "denied"
                                } else {
                                    "expired"
                                },
                            );
                        }
                        "approval.revoked" | "approval.consumed" => {
                            let grant_id = grant_id.ok_or(StoreError::Corrupt)?;
                            let grant_revision = value
                                .get("grant_revision")
                                .and_then(serde_json::Value::as_u64)
                                .ok_or(StoreError::Corrupt)?;
                            let prior_grant_revision = approval_grant_revisions
                                .get(&grant_id)
                                .copied()
                                .ok_or(StoreError::Corrupt)?;
                            if approval_states.get(&approval_id) != Some(&"granted")
                                || approval_grants.get(&grant_id) != Some(&approval_id)
                                || grant_revision != prior_grant_revision + 1
                            {
                                return Err(StoreError::Corrupt);
                            }
                            approval_grant_revisions.insert(grant_id.clone(), grant_revision);
                            if target.kind == "approval.consumed" {
                                let effect_id = value
                                    .get("effect_id")
                                    .and_then(serde_json::Value::as_str)
                                    .ok_or(StoreError::Corrupt)?
                                    .to_owned();
                                let effect_revision = value
                                    .get("effect_revision")
                                    .and_then(serde_json::Value::as_u64)
                                    .ok_or(StoreError::Corrupt)?;
                                if effect_revision != 1
                                    || approval_effect_revisions
                                        .insert(effect_id, effect_revision)
                                        .is_some()
                                {
                                    return Err(StoreError::Corrupt);
                                }
                            }
                            let value: serde_json::Value = serde_json::from_slice(&target.data)
                                .map_err(|_| StoreError::Corrupt)?;
                            let next = if target.kind == "approval.revoked" {
                                "revoked"
                            } else if value.get("status").and_then(serde_json::Value::as_str)
                                == Some("consumed")
                            {
                                "consumed"
                            } else {
                                "granted"
                            };
                            approval_states.insert(approval_id, next);
                            let prior_request = approval_request_revisions
                                .get(&target.key)
                                .copied()
                                .ok_or(StoreError::Corrupt)?;
                            if request_revision != prior_request
                                && request_revision != prior_request + 1
                            {
                                return Err(StoreError::Corrupt);
                            }
                            approval_request_revisions.insert(target.key.clone(), request_revision);
                        }
                        "approval.effect.finished" => {
                            let grant_id = grant_id.ok_or(StoreError::Corrupt)?;
                            let effect_id = value
                                .get("effect_id")
                                .and_then(serde_json::Value::as_str)
                                .ok_or(StoreError::Corrupt)?;
                            let effect_revision = value
                                .get("effect_revision")
                                .and_then(serde_json::Value::as_u64)
                                .ok_or(StoreError::Corrupt)?;
                            if completed_approval_effects.contains(effect_id)
                                || !matches!(
                                    approval_states.get(&approval_id),
                                    Some(&"granted" | &"consumed")
                                )
                                || approval_grants.get(&grant_id) != Some(&approval_id)
                                || approval_effect_revisions.get(effect_id).copied()
                                    != effect_revision.checked_sub(1)
                            {
                                return Err(StoreError::Corrupt);
                            }
                            approval_effect_revisions.insert(effect_id.to_owned(), effect_revision);
                            completed_approval_effects.insert(effect_id.to_owned());
                        }
                        _ => return Err(StoreError::Corrupt),
                    }
                }
                if target.view != ProjectionView::Approval {
                    if let Some((prior, terminal, prior_kind)) = histories.get(&identity) {
                        if *terminal
                            || target.revision != prior.saturating_add(1)
                            || !projection_transition_allowed(target.view, prior_kind, &target.kind)
                        {
                            return Err(StoreError::Corrupt);
                        }
                    } else if target.revision != 1
                        || !projection_initial_event(target.view, &target.kind)
                    {
                        return Err(StoreError::Corrupt);
                    }
                    histories.insert(
                        identity.clone(),
                        (target.revision, target.terminal, target.kind.clone()),
                    );
                }
                if target.view == ProjectionView::ActiveWork && target.terminal {
                    rows.remove(&identity);
                } else {
                    rows.insert(identity, (target.sort, target.data));
                }
            }
        }
        let tree_count = rows
            .keys()
            .filter(|(view, _)| view == "session_tree")
            .count();
        let work_count = rows
            .keys()
            .filter(|(view, _)| view == "active_work")
            .count();
        let delivery_count = rows.keys().filter(|(view, _)| view == "delivery").count();
        let capacity_metrics = self.capacity_metrics(session_id).await?;
        let capacity = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "session_id": session_id,
            "participants": tree_count,
            "active_work": work_count,
            "deliveries": delivery_count,
            "resources": capacity_metrics,
        }))
        .map_err(|_| StoreError::Corrupt)?;
        rows.insert(
            (
                ProjectionView::Capacity.as_str().to_owned(),
                "session".to_owned(),
            ),
            ("capacity".to_owned(), capacity),
        );
        let checkpoint = u64::try_from(expected - 1).map_err(|_| StoreError::Corrupt)?;
        let mut tx = begin_immediate(&self.pool).await?;
        let generation: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(generation),0)+1 FROM projection_generations WHERE session_id=?",
        )
        .bind(session_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        sqlx::query("INSERT INTO projection_generations(session_id,generation,state,checkpoint_position,source_head_position,observed_time_floor_seconds,observed_time_floor_nanos,created_at_seconds,created_at_nanos) VALUES(?,?,'building',?,?,?,?,?,?)")
            .bind(session_id.to_string()).bind(generation).bind(i64::try_from(checkpoint).map_err(|_|StoreError::Corrupt)?).bind(i64::try_from(checkpoint).map_err(|_|StoreError::Corrupt)?).bind(self.now().unix_seconds()).bind(i64::from(self.now().nanoseconds())).bind(self.now().unix_seconds()).bind(i64::from(self.now().nanoseconds())).execute(&mut *tx).await.map_err(map_sqlx)?;
        for ((view, key), (sort, data)) in rows {
            sqlx::query("INSERT INTO projection_rows(session_id,generation,view,item_key,sort_key,data) VALUES(?,?,?,?,?,?)")
                .bind(session_id.to_string()).bind(generation).bind(view).bind(key).bind(sort).bind(data).execute(&mut *tx).await.map_err(map_sqlx)?;
        }
        crash_at("projection.before_generation_swap");
        sqlx::query("UPDATE projection_generations SET state='retired' WHERE session_id=? AND state='published'").bind(session_id.to_string()).execute(&mut *tx).await.map_err(map_sqlx)?;
        sqlx::query("UPDATE projection_generations SET state='published' WHERE session_id=? AND generation=?").bind(session_id.to_string()).bind(generation).execute(&mut *tx).await.map_err(map_sqlx)?;
        sqlx::query("INSERT INTO projection_heads(session_id,generation,checkpoint_position,source_head_position) VALUES(?,?,?,?) ON CONFLICT(session_id) DO UPDATE SET generation=excluded.generation,checkpoint_position=excluded.checkpoint_position,source_head_position=excluded.source_head_position")
            .bind(session_id.to_string()).bind(generation).bind(i64::try_from(checkpoint).map_err(|_|StoreError::Corrupt)?).bind(i64::try_from(checkpoint).map_err(|_|StoreError::Corrupt)?).execute(&mut *tx).await.map_err(map_sqlx)?;
        sqlx::query("INSERT INTO projection_progress(session_id,generation,ordinal,checkpoint_position,dropped_updates,recorded_at_seconds,recorded_at_nanos) VALUES(?,?,1,?,0,?,?)")
            .bind(session_id.to_string()).bind(generation).bind(i64::try_from(checkpoint).map_err(|_|StoreError::Corrupt)?).bind(self.now().unix_seconds()).bind(i64::from(self.now().nanoseconds())).execute(&mut *tx).await.map_err(map_sqlx)?;
        sqlx::query("DELETE FROM projection_progress WHERE session_id=? AND generation NOT IN (SELECT generation FROM projection_generations WHERE session_id=? ORDER BY generation DESC LIMIT 8)")
            .bind(session_id.to_string()).bind(session_id.to_string()).execute(&mut *tx).await.map_err(map_sqlx)?;
        let gc_before = self
            .now()
            .unix_seconds()
            .checked_sub(60)
            .ok_or(StoreError::Corrupt)?;
        sqlx::query("DELETE FROM projection_generations WHERE session_id=? AND state='retired' AND created_at_seconds<=? AND generation NOT IN (SELECT generation FROM projection_generations WHERE session_id=? ORDER BY generation DESC LIMIT 8)")
            .bind(session_id.to_string()).bind(gc_before).bind(session_id.to_string()).execute(&mut *tx).await.map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("projection.after_generation_swap");
        tracing::info!(session_id = %session_id, generation, checkpoint, "published projection generation");
        Ok(ProjectionRebuild {
            session_id,
            generation: u64::try_from(generation).map_err(|_| StoreError::Corrupt)?,
            checkpoint_position: if checkpoint == 0 {
                None
            } else {
                Some(EventPosition::new(checkpoint).map_err(|_| StoreError::Corrupt)?)
            },
        })
    }

    // Token authentication, generation pinning, and the bounded row read intentionally stay in
    // one routine so no branch can accidentally serve a page from a different generation.
    #[allow(clippy::too_many_lines)]
    async fn read_projection(&self, query: ReadProjection) -> Result<ProjectionPage, StoreError> {
        let session = self.load_session(query.session_id).await?;
        if session.consumer_key() != &query.consumer {
            return Err(StoreError::Invalid);
        }
        let (generation, checkpoint, last_sort, last_item, token_expiry) =
            if let Some(token) = &query.page_token {
                let wire: ProjectionTokenWire =
                    serde_json::from_str(token.as_str()).map_err(|_| StoreError::Invalid)?;
                if wire.session_id != query.session_id
                    || wire.view != query.view
                    || wire.page_size != query.page_size.get()
                    || !verify_projection_signature(
                        &self.projection_token_secret,
                        &query.consumer,
                        &wire,
                    )
                {
                    return Err(StoreError::Invalid);
                }
                (
                    wire.generation,
                    wire.checkpoint,
                    wire.last_sort_key,
                    wire.last_item_key,
                    Some(wire.expires_seconds),
                )
            } else {
                let head: (i64, i64) = sqlx::query_as(
                "SELECT generation,checkpoint_position FROM projection_heads WHERE session_id=?",
            )
            .bind(query.session_id.to_string())
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx)?;
                (
                    u64::try_from(head.0).map_err(|_| StoreError::Corrupt)?,
                    u64::try_from(head.1).map_err(|_| StoreError::Corrupt)?,
                    String::new(),
                    String::new(),
                    None,
                )
            };
        let pinned: Option<(i64,i64,i64)> = sqlx::query_as("SELECT checkpoint_position,observed_time_floor_seconds,observed_time_floor_nanos FROM projection_generations WHERE session_id=? AND generation=? AND state IN ('published','retired')")
            .bind(query.session_id.to_string()).bind(i64::try_from(generation).map_err(|_|StoreError::Invalid)?).fetch_optional(&self.pool).await.map_err(map_sqlx)?;
        let Some((pinned_checkpoint, floor_seconds, floor_nanos)) = pinned else {
            return Err(StoreError::ProjectionStale);
        };
        if pinned_checkpoint != i64::try_from(checkpoint).map_err(|_| StoreError::Invalid)? {
            return Err(StoreError::ProjectionStale);
        }
        let floor = Timestamp::new(
            floor_seconds,
            u32::try_from(floor_nanos).map_err(|_| StoreError::Corrupt)?,
        )
        .map_err(|_| StoreError::Corrupt)?;
        if token_expiry.is_some_and(|expires| self.now().max(floor).unix_seconds() >= expires) {
            return Err(StoreError::ProjectionStale);
        }
        let limit = i64::from(query.page_size.get()) + 1;
        let rows = sqlx::query("SELECT item_key,sort_key,data FROM projection_rows WHERE session_id=? AND generation=? AND view=? AND (sort_key>? OR (sort_key=? AND item_key>?)) ORDER BY sort_key,item_key LIMIT ?")
            .bind(query.session_id.to_string()).bind(i64::try_from(generation).map_err(|_|StoreError::Invalid)?).bind(query.view.as_str()).bind(&last_sort).bind(&last_sort).bind(&last_item).bind(limit).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        let has_more = rows.len() > usize::from(query.page_size.get());
        let selected = rows
            .into_iter()
            .take(usize::from(query.page_size.get()))
            .collect::<Vec<_>>();
        let last_sort = selected
            .last()
            .map(|row| row.try_get::<String, _>("sort_key"))
            .transpose()
            .map_err(map_sqlx)?;
        let last_item = selected
            .last()
            .map(|row| row.try_get::<String, _>("item_key"))
            .transpose()
            .map_err(map_sqlx)?;
        let mut items = Vec::with_capacity(selected.len());
        for row in selected {
            items.push(ProjectionItem {
                key: ProjectionItemKey::new(
                    row.try_get::<String, _>("item_key").map_err(map_sqlx)?,
                )
                .map_err(|_| StoreError::Corrupt)?,
                data: RedactedEventData::new(row.try_get::<Vec<u8>, _>("data").map_err(map_sqlx)?)
                    .map_err(|_| StoreError::Corrupt)?,
            });
        }
        let next_page_token = if has_more {
            let token = projection_token(
                &self.projection_token_secret,
                &query.consumer,
                query.session_id,
                query.view,
                generation,
                checkpoint,
                self.now()
                    .max(floor)
                    .unix_seconds()
                    .checked_add(60)
                    .ok_or(StoreError::Corrupt)?,
                query.page_size.get(),
                last_sort.ok_or(StoreError::Corrupt)?,
                last_item.ok_or(StoreError::Corrupt)?,
            )?;
            Some(token)
        } else {
            None
        };
        let source_head: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(position),0) FROM events WHERE session_id=?")
                .bind(query.session_id.to_string())
                .fetch_one(&self.pool)
                .await
                .map_err(map_sqlx)?;
        Ok(ProjectionPage {
            session_id: query.session_id,
            view: query.view,
            generation,
            checkpoint_position: if checkpoint == 0 {
                None
            } else {
                Some(EventPosition::new(checkpoint).map_err(|_| StoreError::Corrupt)?)
            },
            source_head_position: if source_head == 0 {
                None
            } else {
                Some(
                    EventPosition::new(
                        u64::try_from(source_head).map_err(|_| StoreError::Corrupt)?,
                    )
                    .map_err(|_| StoreError::Corrupt)?,
                )
            },
            items,
            next_page_token,
        })
    }
}

impl ArtifactStore for SqliteStore {
    #[expect(
        clippy::too_many_lines,
        reason = "artifact publication atomically converts both durable quota reservations"
    )]
    async fn publish_artifact(
        &self,
        request: PublishArtifact,
    ) -> Result<Mutation<ArtifactSnapshot>, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(snapshot) = replay_json::<ArtifactSnapshot>(&mut tx, &request).await? {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(snapshot));
        }
        authorize_artifact(
            &mut tx,
            request.session_id,
            request.owner,
            request.epoch,
            self.now(),
        )
        .await?;
        let creator = load_participant_in(&mut tx, request.creator_participant_id)
            .await?
            .ok_or(StoreError::ParticipantNotFound {
                participant_id: request.creator_participant_id,
            })?;
        let operation = load_operation_in(&mut tx, request.creator_operation_id)
            .await?
            .ok_or(StoreError::OperationNotFound {
                operation_id: request.creator_operation_id,
            })?;
        if creator.session_id != request.session_id
            || operation.session_id != request.session_id
            || operation.participant_id != request.creator_participant_id
        {
            return Err(StoreError::Invalid);
        }
        let locator = format!("{}/{}.blob", request.session_id, request.artifact_id);
        if request.locator != locator || request.size > navigator_domain::MAX_ARTIFACT_BYTES {
            return Err(StoreError::Invalid);
        }
        let now = self.now();
        let snapshot = ArtifactSnapshot {
            artifact_id: request.artifact_id,
            session_id: request.session_id,
            creator_participant_id: request.creator_participant_id,
            creator_operation_id: request.creator_operation_id,
            media_type: request.media_type.clone(),
            size: request.size,
            digest: request.digest,
            locator: request.locator.clone(),
            state: ArtifactState::Available,
            revision: Revision::initial(),
            retention_until: request.retention_until,
            created_at: now,
            deleted_at: None,
        };
        if !snapshot.structurally_valid() {
            return Err(StoreError::Invalid);
        }
        consume_capacity_reservation(
            &mut tx,
            request.artifact_reservation_id,
            request.session_id,
            request.creator_participant_id,
            CapacityResource::Artifacts,
            1,
            now,
        )
        .await?;
        match (request.size, request.byte_reservation_id) {
            (0, None) => {}
            (0, Some(_)) | (1.., None) => return Err(StoreError::Invalid),
            (size, Some(reservation_id)) => {
                consume_capacity_reservation(
                    &mut tx,
                    reservation_id,
                    request.session_id,
                    request.creator_participant_id,
                    CapacityResource::ArtifactBytes,
                    size,
                    now,
                )
                .await?;
            }
        }
        ensure_derived_capacity(
            &mut tx,
            &self.limit_profile,
            request.session_id,
            CapacityResource::Artifacts,
            1,
        )
        .await?;
        ensure_derived_capacity(
            &mut tx,
            &self.limit_profile,
            request.session_id,
            CapacityResource::ArtifactBytes,
            request.size,
        )
        .await?;
        sqlx::query("INSERT INTO artifacts (artifact_id,session_id,creator_participant_id,creator_operation_id,media_type,size,digest,locator,state,revision,retention_seconds,retention_nanos,created_seconds,created_nanos) VALUES (?,?,?,?,?,?,?,?,'available',1,?,?,?,?)")
            .bind(request.artifact_id.to_string()).bind(request.session_id.to_string())
            .bind(request.creator_participant_id.to_string()).bind(request.creator_operation_id.to_string())
            .bind(request.media_type.as_str()).bind(to_i64(request.size)?).bind(request.digest.as_bytes().to_vec())
            .bind(&request.locator).bind(request.retention_until.unix_seconds()).bind(i64::from(request.retention_until.nanoseconds()))
            .bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).execute(&mut *tx).await.map_err(map_sqlx)?;
        append_event(
            &mut tx,
            request.context.request_id(),
            request.session_id,
            snapshot.revision,
            "artifact.published",
            now,
        )
        .await?;
        record_json(&mut tx, request.session_id, &request, &snapshot).await?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(Mutation::Applied(snapshot))
    }

    async fn load_artifact(&self, access: ArtifactAccess) -> Result<ArtifactSnapshot, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        authorize_artifact(
            &mut tx,
            access.session_id,
            access.owner,
            access.epoch,
            self.now(),
        )
        .await?;
        let snapshot = load_artifact_in(&mut tx, access.artifact_id)
            .await?
            .filter(|value| {
                value.session_id == access.session_id && value.state == ArtifactState::Available
            })
            .ok_or(StoreError::ArtifactNotFound {
                artifact_id: access.artifact_id,
            })?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(snapshot)
    }

    async fn logically_delete_artifact(
        &self,
        request: DeleteArtifact,
    ) -> Result<Mutation<ArtifactSnapshot>, StoreError> {
        transition_artifact(self, request, false).await
    }

    async fn retention_eligible_artifacts(
        &self,
        now: Timestamp,
        limit: usize,
    ) -> Result<Vec<ArtifactSnapshot>, StoreError> {
        if limit == 0 || limit > 1024 {
            return Err(StoreError::Invalid);
        }
        let rows = sqlx::query("SELECT * FROM artifacts WHERE state='logically_deleted' AND (retention_seconds < ? OR (retention_seconds = ? AND retention_nanos <= ?)) ORDER BY retention_seconds,retention_nanos,artifact_id LIMIT ?")
            .bind(now.unix_seconds()).bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).bind(i64::try_from(limit).map_err(|_| StoreError::Invalid)?)
            .fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.iter().map(decode_artifact).collect()
    }

    async fn authorize_physical_erasure(
        &self,
        request: &EraseArtifact,
    ) -> Result<ArtifactSnapshot, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        // Physical deletion happens between this authorization and the durable
        // transition.  Authenticate an exact replay (and reject a colliding
        // request id) before the caller is allowed to touch the filesystem.
        // This also makes a retry after a committed erase a no-op at the
        // physical boundary instead of rejecting the already-erased state.
        if let Some(snapshot) = replay_json::<ArtifactSnapshot>(&mut tx, request).await? {
            if snapshot.state != ArtifactState::PhysicallyErased {
                return Err(StoreError::Corrupt);
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(snapshot);
        }
        authorize_artifact(
            &mut tx,
            request.session_id,
            request.owner,
            request.epoch,
            self.now(),
        )
        .await?;
        let snapshot = load_artifact_in(&mut tx, request.artifact_id)
            .await?
            .ok_or(StoreError::ArtifactNotFound {
                artifact_id: request.artifact_id,
            })?;
        if snapshot.session_id != request.session_id
            || snapshot.state != ArtifactState::LogicallyDeleted
            || snapshot.retention_until > self.now()
        {
            return Err(StoreError::Invalid);
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(snapshot)
    }

    async fn record_physical_erasure(
        &self,
        request: EraseArtifact,
    ) -> Result<ArtifactSnapshot, StoreError> {
        Ok(transition_erased(self, request).await?.value().clone())
    }
}

impl RecoveryStore for SqliteStore {
    async fn load_recovery_inventory(
        &self,
        session_id: SessionId,
        owner: HostId,
        epoch: FencingEpoch,
    ) -> Result<RecoveryInventory, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        let session =
            require_open_session(&mut tx, session_id, StoreAction::AcquireOwnership).await?;
        let now = advance_time_floor(&mut tx, session_id, session.time_floor, self.now()).await?;
        require_owner(&session, owner, epoch, now)?;

        let launch_ids: Vec<String> = sqlx::query_scalar("SELECT attempt_id FROM launch_attempts WHERE session_id=? AND state!='stopped' ORDER BY attempt_id LIMIT 16385")
            .bind(session_id.to_string()).fetch_all(&mut *tx).await.map_err(map_sqlx)?;
        let participant_ids: Vec<String> = sqlx::query_scalar(
            "SELECT participant_id FROM participants WHERE session_id=? ORDER BY participant_id LIMIT 16385",
        )
        .bind(session_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let operation_ids: Vec<String> = sqlx::query_scalar("SELECT operation_id FROM operations WHERE session_id=? AND terminal_outcome IS NULL ORDER BY operation_id LIMIT 16385")
            .bind(session_id.to_string()).fetch_all(&mut *tx).await.map_err(map_sqlx)?;
        let message_rows: Vec<SqliteRow> = sqlx::query("SELECT message_id, session_id, source_participant_id, destination_participant_id, mailbox_sequence, priority, snapshot FROM messages WHERE session_id=? ORDER BY message_id LIMIT 16385")
            .bind(session_id.to_string()).fetch_all(&mut *tx).await.map_err(map_sqlx)?;
        let effect_ids: Vec<String> = sqlx::query_scalar("SELECT request_id FROM effect_journal WHERE session_id=? AND phase NOT IN ('completed','failed') ORDER BY request_id LIMIT 16385")
            .bind(session_id.to_string()).fetch_all(&mut *tx).await.map_err(map_sqlx)?;

        if 1 + launch_ids.len()
            + participant_ids.len()
            + operation_ids.len()
            + message_rows.len()
            + effect_ids.len()
            > navigator_store_api::MAX_RECOVERY_CLASSIFICATIONS
        {
            return Err(StoreError::Invalid);
        }

        let mut launches = Vec::with_capacity(launch_ids.len());
        for value in launch_ids {
            launches.push(
                load_launch_in(&mut tx, parse_launch_attempt(&value)?)
                    .await?
                    .ok_or(StoreError::Corrupt)?,
            );
        }
        let mut participants = Vec::with_capacity(participant_ids.len());
        for value in participant_ids {
            participants.push(
                load_participant_in(&mut tx, parse_participant_id(&value)?)
                    .await?
                    .ok_or(StoreError::Corrupt)?,
            );
        }
        let mut operations = Vec::with_capacity(operation_ids.len());
        for value in operation_ids {
            operations.push(
                load_operation_in(&mut tx, parse_operation_id(&value)?)
                    .await?
                    .ok_or(StoreError::Corrupt)?,
            );
        }
        let messages = message_rows
            .iter()
            .map(decode_message_row)
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|message| !message.state.is_terminal())
            .collect();
        let mut effects = Vec::with_capacity(effect_ids.len());
        for value in effect_ids {
            effects.push(
                load_effect_in(&mut tx, parse_request_id(&value)?)
                    .await?
                    .ok_or(StoreError::Corrupt)?,
            );
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(RecoveryInventory {
            session_id,
            snapshot_at: now,
            launches,
            participants,
            operations,
            messages,
            effects,
        })
    }

    async fn record_recovery_classifications(
        &self,
        command: RecordRecoveryClassifications,
    ) -> Result<(), StoreError> {
        if !command.is_structurally_valid() {
            return Err(StoreError::Invalid);
        }
        let payload =
            serde_json::to_vec(&command.classifications).map_err(|_| StoreError::Corrupt)?;
        let digest = SemanticDigest::v1(
            &Capability::new("recovery.classify").expect("static capability"),
            &payload,
        );
        let mut tx = begin_immediate(&self.pool).await?;
        reject_global_request_collision(&mut tx, command.context.request_id()).await?;
        let journal_collision: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM effect_journal WHERE request_id = ? UNION ALL SELECT 1 FROM effect_journal_mutations WHERE request_id = ? LIMIT 1",
        )
        .bind(command.context.request_id().to_string())
        .bind(command.context.request_id().to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if journal_collision.is_some() {
            return Err(StoreError::RequestConflict {
                request_id: command.context.request_id(),
            });
        }
        let session =
            require_open_session(&mut tx, command.session_id, StoreAction::AcquireOwnership)
                .await?;
        let now =
            advance_time_floor(&mut tx, command.session_id, session.time_floor, self.now()).await?;
        require_owner(&session, command.context.caller(), command.epoch, now)?;
        if let Some(existing) = sqlx::query(
            "SELECT session_id,caller_host_id,owner_epoch,semantic_digest FROM recovery_classifications WHERE request_id=?",
        )
                .bind(command.context.request_id().to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx)?
        {
            let stored: Vec<u8> = existing.try_get("semantic_digest").map_err(map_sqlx)?;
            if stored.as_slice() != digest.as_bytes()
                || existing.try_get::<String, _>("session_id").map_err(map_sqlx)?
                    != command.session_id.to_string()
                || existing.try_get::<String, _>("caller_host_id").map_err(map_sqlx)?
                    != command.context.caller().to_string()
                || existing.try_get::<i64, _>("owner_epoch").map_err(map_sqlx)?
                    != to_i64(command.epoch.get())?
            {
                return Err(StoreError::RequestConflict {
                    request_id: command.context.request_id(),
                });
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(());
        }
        validate_recovery_classifications(
            &mut tx,
            command.session_id,
            now,
            &command.classifications,
        )
        .await?;
        sqlx::query("INSERT INTO recovery_classifications(request_id,session_id,caller_host_id,owner_epoch,semantic_digest,payload) VALUES(?,?,?,?,?,?)")
            .bind(command.context.request_id().to_string()).bind(command.session_id.to_string())
            .bind(command.context.caller().to_string()).bind(to_i64(command.epoch.get())?)
            .bind(digest.as_bytes().as_slice()).bind(&payload).execute(&mut *tx).await.map_err(map_sqlx)?;
        let event_payload = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "session_id": command.session_id,
            "request_id": command.context.request_id(),
            "revision": session.snapshot.revision().get(),
            "classifications": command.classifications,
        }))
        .map_err(|_| StoreError::Corrupt)?;
        append_event_data(
            &mut tx,
            command.context.request_id(),
            command.session_id,
            session.snapshot.revision(),
            "recovery.classified",
            &event_payload,
            now,
        )
        .await?;
        crash_at("recovery.classifications.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("recovery.classifications.after_commit");
        Ok(())
    }
}

async fn validate_recovery_classifications(
    tx: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    now: navigator_domain::Timestamp,
    rows: &[navigator_store_api::RecoveryEventClassification],
) -> Result<(), StoreError> {
    use navigator_domain::RecoveryState as R;
    use navigator_store_api::RecoveryEventEntity as E;
    for row in rows {
        let valid = match row.entity {
            E::Session(id) => id == session_id && row.state == R::SessionOpen,
            E::Participant(id) => load_participant_in(tx, id).await?.is_some_and(|v| {
                v.session_id == session_id && row.state == R::ParticipantRegistered
            }),
            E::Instance(id) => load_launch_in(tx, id).await?.is_some_and(|v| {
                v.session_id == session_id && row.state == recovery_launch_state(v.state)
            }),
            E::Operation(id) => load_operation_in(tx, id).await?.is_some_and(|v| {
                v.session_id == session_id && row.state == recovery_operation_state(v.state)
            }),
            E::Message(id) => load_message_in(tx, id).await?.is_some_and(|v| {
                v.session_id == session_id && row.state == recovery_message_state(&v.state, now)
            }),
            E::Effect(id) => load_effect_in(tx, id).await?.is_some_and(|v| {
                v.session_id == session_id
                    && row.state == recovery_effect_state(v.phase, v.effect_class)
            }),
        };
        if !valid {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}

fn recovery_launch_state(value: LaunchState) -> navigator_domain::RecoveryState {
    use navigator_domain::RecoveryState as R;
    match value {
        LaunchState::Prepared => R::InstancePrepared,
        LaunchState::Attached => R::InstanceAttached,
        LaunchState::Ready => R::InstanceReady,
        LaunchState::Stopping => R::InstanceStopping,
        LaunchState::Stopped => R::InstanceStopped,
        LaunchState::CleanupRequired => R::InstanceCleanupRequired,
    }
}

fn recovery_operation_state(value: OperationState) -> navigator_domain::RecoveryState {
    use navigator_domain::RecoveryState as R;
    match value {
        OperationState::Queued => R::OperationQueued,
        OperationState::Starting => R::OperationStarting,
        OperationState::Running => R::OperationRunning,
        OperationState::Waiting => R::OperationWaiting,
        OperationState::Cancelling => R::OperationCancelling,
        _ => R::OperationTerminal,
    }
}

fn recovery_message_state(
    value: &MessageDeliveryState,
    now: navigator_domain::Timestamp,
) -> navigator_domain::RecoveryState {
    use navigator_domain::RecoveryState as R;
    match value {
        MessageDeliveryState::Queued => R::MessageQueued,
        MessageDeliveryState::RetryScheduled { not_before } if *not_before <= now => {
            R::MessageRetryScheduled
        }
        MessageDeliveryState::RetryScheduled { .. } => R::MessageRetryDeferred,
        MessageDeliveryState::Leased { lease } if lease.expires_at <= now => R::MessageLeased,
        MessageDeliveryState::Leased { .. } => R::MessageLeaseActive,
        MessageDeliveryState::AcceptancePending { .. } => R::MessageAcceptancePending,
        MessageDeliveryState::AcceptanceUnknown { .. } => R::MessageAcceptanceUnknown,
        MessageDeliveryState::Accepted { .. } => R::MessageAccepted,
        MessageDeliveryState::Uncertain { .. } => R::MessageUncertain,
        MessageDeliveryState::DeadLetter { .. } => R::MessageDeadLetter,
    }
}

fn recovery_effect_state(
    value: EffectJournalPhase,
    class: EffectClass,
) -> navigator_domain::RecoveryState {
    use navigator_domain::RecoveryState as R;
    match value {
        EffectJournalPhase::Reserved => R::EffectReserved,
        EffectJournalPhase::RetryAuthorized => R::EffectStartedRetryable,
        EffectJournalPhase::Started
            if matches!(class, EffectClass::ReadOnly | EffectClass::Idempotent) =>
        {
            R::EffectStartedRetryable
        }
        EffectJournalPhase::Started | EffectJournalPhase::Uncertain => R::EffectStartedUnsafe,
        EffectJournalPhase::Completed | EffectJournalPhase::Failed => R::EffectCompleted,
    }
}
use crate::database::{DatabaseError, SCHEMA_VERSION, open_pool, validate_approval_schema};

const DEFAULT_MAX_LEASE_MILLIS: u64 = 300_000;

#[derive(Clone)]
pub struct SqliteStore {
    pool: SqlitePool,
    clock: Arc<dyn Clock + Send + Sync>,
    max_lease_millis: u64,
    authority_time_floors: Arc<Mutex<BTreeMap<SessionId, Timestamp>>>,
    projection_token_secret: [u8; 32],
    limit_profile: Arc<LimitProfile>,
}

impl SqliteStore {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::open_with_clock(
            path,
            Arc::new(SystemClock),
            LeaseDuration::from_millis(DEFAULT_MAX_LEASE_MILLIS)
                .expect("default lease duration is valid"),
        )
        .await
    }

    pub async fn open_with_limits(
        path: impl AsRef<Path>,
        limits: LimitProfile,
    ) -> Result<Self, StoreError> {
        Self::open_with_clock_and_limits(
            path,
            Arc::new(SystemClock),
            LeaseDuration::from_millis(DEFAULT_MAX_LEASE_MILLIS)
                .expect("default lease duration is valid"),
            limits,
        )
        .await
    }

    pub async fn open_with_clock(
        path: impl AsRef<Path>,
        clock: Arc<dyn Clock + Send + Sync>,
        max_lease: LeaseDuration,
    ) -> Result<Self, StoreError> {
        Self::open_with_clock_and_limits(path, clock, max_lease, LimitProfile::default()).await
    }

    pub async fn open_with_clock_and_limits(
        path: impl AsRef<Path>,
        clock: Arc<dyn Clock + Send + Sync>,
        max_lease: LeaseDuration,
        limits: LimitProfile,
    ) -> Result<Self, StoreError> {
        let pool = open_pool(path.as_ref()).await.map_err(map_database_error)?;
        reconcile_abandoned_subscriptions(&pool).await?;
        configure_capacity_limits(&pool, &limits).await?;
        validate_compatibility_manifests(&pool).await?;
        let projection_token_secret: [u8; 32] = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT token_secret FROM projection_metadata WHERE singleton=1",
        )
        .fetch_one(&pool)
        .await
        .map_err(map_sqlx)?
        .try_into()
        .map_err(|_| StoreError::Corrupt)?;
        Ok(Self {
            pool,
            clock,
            max_lease_millis: max_lease.as_millis(),
            authority_time_floors: Arc::new(Mutex::new(BTreeMap::new())),
            projection_token_secret,
            limit_profile: Arc::new(limits),
        })
    }

    #[must_use]
    pub const fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub(crate) fn now(&self) -> Timestamp {
        Timestamp::from_datetime(self.clock.wall_now())
    }

    #[cfg(test)]
    pub(crate) async fn append_capacity_test_event(
        &self,
        request_id: RequestId,
        session_id: SessionId,
    ) -> Result<(), StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        let replay: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM events WHERE session_id=? AND related_request_id=? AND event_type='capacity.test'",
        )
        .bind(session_id.to_string())
        .bind(request_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if replay.is_some() {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(());
        }
        let position: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(revision),0)+1 FROM events WHERE session_id=?")
                .bind(session_id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        append_event(
            &mut tx,
            request_id,
            session_id,
            Revision::new(u64::try_from(position).map_err(|_| StoreError::Corrupt)?)
                .map_err(|_| StoreError::Corrupt)?,
            "capacity.test",
            self.now(),
        )
        .await?;
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("event.append.after_commit");
        Ok(())
    }

    fn expiry(&self, now: Timestamp, duration: LeaseDuration) -> Result<Timestamp, StoreError> {
        if duration.as_millis() > self.max_lease_millis {
            return Err(StoreError::LeaseTooLong);
        }
        let millis = i64::try_from(duration.as_millis()).map_err(|_| StoreError::LeaseTooLong)?;
        let value = now
            .to_datetime()
            .map_err(|_| StoreError::Corrupt)?
            .checked_add(time::Duration::milliseconds(millis))
            .ok_or(StoreError::Invalid)?;
        Ok(Timestamp::from_datetime(value))
    }
}

/// Reclaims only leases proven expired or fenced by durable Session ownership.
/// Opening another pool must not disturb a live owner in another process.
async fn reconcile_abandoned_subscriptions(pool: &SqlitePool) -> Result<(), StoreError> {
    let mut tx = begin_immediate(pool).await?;
    sqlx::query(
        "DELETE FROM capacity_reservations WHERE reservation_id IN (
            SELECT l.reservation_id FROM subscription_leases l JOIN sessions s ON s.session_id=l.session_id
            WHERE s.owner_host_id IS NULL OR l.owner_host_id<>s.owner_host_id OR l.owner_epoch<>s.owner_epoch
               OR l.expires_at_seconds<s.observed_time_floor_seconds
               OR (l.expires_at_seconds=s.observed_time_floor_seconds AND l.expires_at_nanos<=s.observed_time_floor_nanos)
        )",
    )
    .execute(&mut *tx)
    .await
    .map_err(map_sqlx)?;
    sqlx::query(
        "UPDATE capacity_session_usage SET used=COALESCE((SELECT SUM(amount) FROM capacity_reservations r WHERE r.session_id=capacity_session_usage.session_id AND r.resource='subscriptions' AND r.released=0),0) WHERE resource='subscriptions'",
    )
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    sqlx::query("DELETE FROM capacity_session_usage WHERE resource='subscriptions' AND used=0")
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount),0) FROM capacity_reservations WHERE resource='subscriptions' AND released=0",
    )
    .fetch_one(&mut *tx)
    .await
    .map_err(map_sqlx)?;
    sqlx::query("UPDATE capacity_global_usage SET used=? WHERE resource='subscriptions'")
        .bind(remaining)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    sqlx::query("DELETE FROM capacity_global_usage WHERE resource='subscriptions' AND used=0")
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    tx.commit().await.map_err(map_sqlx)
}

fn subscription_lease(command: &ReserveSubscriptionLease) -> SubscriptionLease {
    SubscriptionLease {
        reservation_id: command.reservation_id,
        session_id: command.session_id,
        campaign_id: command.campaign_id,
        owner_host_id: command.owner_host_id,
        owner_epoch: command.owner_epoch,
        expires_at: command.expires_at,
    }
}

async fn validate_subscription_owner(
    tx: &mut Transaction<'_, Sqlite>,
    command: &ReserveSubscriptionLease,
) -> Result<(), StoreError> {
    let row: Option<(String, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT owner_host_id,owner_epoch,owner_expires_at_seconds,owner_expires_at_nanos,observed_time_floor_seconds,observed_time_floor_nanos FROM sessions WHERE session_id=? AND closed=0",
    )
    .bind(command.session_id.to_string())
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx)?;
    let Some((host, epoch, expiry_s, expiry_n, floor_s, floor_n)) = row else {
        return Err(StoreError::SessionNotFound {
            session_id: command.session_id,
        });
    };
    let owner_expiry = decode_timestamp(expiry_s, expiry_n)?;
    let floor = decode_timestamp(floor_s, floor_n)?;
    if host != command.owner_host_id.to_string()
        || to_u64(epoch)? != command.owner_epoch.get()
        || command.expires_at <= floor
        || command.expires_at > owner_expiry
    {
        return Err(StoreError::StaleOwnership {
            session_id: command.session_id,
            attempted: command.owner_epoch,
            current: FencingEpoch::new(to_u64(epoch)?).ok(),
        });
    }
    let campaign_session: Option<String> =
        sqlx::query_scalar("SELECT session_id FROM participants WHERE participant_id=?")
            .bind(command.campaign_id.to_string())
            .fetch_optional(&mut **tx)
            .await
            .map_err(map_sqlx)?;
    if campaign_session.as_deref() != Some(command.session_id.to_string().as_str()) {
        return Err(StoreError::ParticipantNotFound {
            participant_id: command.campaign_id,
        });
    }
    Ok(())
}

async fn increment_capacity_counter(
    tx: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    resource: CapacityResource,
    amount: i64,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO capacity_session_usage(session_id,resource,used) VALUES(?,?,?) ON CONFLICT(session_id,resource) DO UPDATE SET used=used+excluded.used")
        .bind(session_id.to_string()).bind(resource.as_str()).bind(amount).execute(&mut **tx).await.map_err(map_sqlx)?;
    sqlx::query("INSERT INTO capacity_global_usage(resource,used) VALUES(?,?) ON CONFLICT(resource) DO UPDATE SET used=used+excluded.used")
        .bind(resource.as_str()).bind(amount).execute(&mut **tx).await.map_err(map_sqlx)?;
    Ok(())
}

async fn reclaim_stale_subscription_leases(
    tx: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
) -> Result<(), StoreError> {
    sqlx::query(
        "DELETE FROM capacity_reservations WHERE reservation_id IN (
            SELECT l.reservation_id FROM subscription_leases l JOIN sessions s ON s.session_id=l.session_id
            WHERE l.session_id=? AND (
                s.owner_host_id IS NULL OR l.owner_host_id<>s.owner_host_id OR l.owner_epoch<>s.owner_epoch
                OR l.expires_at_seconds<s.observed_time_floor_seconds
                OR (l.expires_at_seconds=s.observed_time_floor_seconds AND l.expires_at_nanos<=s.observed_time_floor_nanos)
            )
        )",
    )
    .bind(session_id.to_string())
    .execute(&mut **tx)
    .await
    .map_err(map_sqlx)?;
    let session_used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount),0) FROM capacity_reservations WHERE session_id=? AND resource='subscriptions' AND released=0",
    )
    .bind(session_id.to_string())
    .fetch_one(&mut **tx)
    .await
    .map_err(map_sqlx)?;
    if session_used == 0 {
        sqlx::query(
            "DELETE FROM capacity_session_usage WHERE session_id=? AND resource='subscriptions'",
        )
        .bind(session_id.to_string())
        .execute(&mut **tx)
        .await
        .map_err(map_sqlx)?;
    } else {
        sqlx::query("UPDATE capacity_session_usage SET used=? WHERE session_id=? AND resource='subscriptions'")
            .bind(session_used).bind(session_id.to_string()).execute(&mut **tx).await.map_err(map_sqlx)?;
    }
    let global_used: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount),0) FROM capacity_reservations WHERE resource='subscriptions' AND released=0",
    )
    .fetch_one(&mut **tx)
    .await
    .map_err(map_sqlx)?;
    if global_used == 0 {
        sqlx::query("DELETE FROM capacity_global_usage WHERE resource='subscriptions'")
            .execute(&mut **tx)
            .await
            .map_err(map_sqlx)?;
    } else {
        sqlx::query("UPDATE capacity_global_usage SET used=? WHERE resource='subscriptions'")
            .bind(global_used)
            .execute(&mut **tx)
            .await
            .map_err(map_sqlx)?;
    }
    Ok(())
}

async fn validate_compatibility_manifests(pool: &SqlitePool) -> Result<(), StoreError> {
    let sessions = sqlx::query(
        "SELECT session_id, compatibility_identity, compatibility_configuration_identity
         FROM sessions WHERE compatibility_manifest_complete = 1",
    )
    .fetch_all(pool)
    .await
    .map_err(map_sqlx)?;
    for session in sessions {
        let session_id = session
            .try_get::<String, _>("session_id")
            .map_err(map_sqlx)?;
        let compatibility = CompatibilityIdentity::from_bytes(
            session
                .try_get::<Vec<u8>, _>("compatibility_identity")
                .map_err(map_sqlx)?
                .try_into()
                .map_err(|_| StoreError::Corrupt)?,
        );
        let configuration = CompatibilityIdentity::from_bytes(
            session
                .try_get::<Vec<u8>, _>("compatibility_configuration_identity")
                .map_err(map_sqlx)?
                .try_into()
                .map_err(|_| StoreError::Corrupt)?,
        );
        let rows = sqlx::query(
            "SELECT m.template_id, m.template_compatibility,
                    t.compatibility_identity AS registered_compatibility
             FROM session_template_manifest m JOIN templates t ON t.template_id = m.template_id
             WHERE m.session_id = ? ORDER BY m.template_id",
        )
        .bind(session_id)
        .fetch_all(pool)
        .await
        .map_err(map_sqlx)?;
        let mut bindings = Vec::with_capacity(rows.len());
        for row in rows {
            let value: Vec<u8> = row.try_get("template_compatibility").map_err(map_sqlx)?;
            if value
                != row
                    .try_get::<Vec<u8>, _>("registered_compatibility")
                    .map_err(map_sqlx)?
            {
                return Err(StoreError::Corrupt);
            }
            bindings.push(TemplateCompatibilityBinding {
                template_id: parse_template_id(
                    &row.try_get::<String, _>("template_id").map_err(map_sqlx)?,
                )?,
                compatibility: CompatibilityIdentity::from_bytes(
                    value.try_into().map_err(|_| StoreError::Corrupt)?,
                ),
            });
        }
        if SessionCompatibilityManifest::new(configuration, bindings)
            .map_err(|_| StoreError::Corrupt)?
            .compatibility()
            != compatibility
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(())
}

impl fmt::Debug for SqliteStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteStore")
            .field("max_lease_millis", &self.max_lease_millis)
            .finish_non_exhaustive()
    }
}

impl EffectJournalStore for SqliteStore {
    async fn reserve_effect(
        &self,
        command: ReserveEffect,
    ) -> Result<EffectJournalEntry, StoreError> {
        if !command.resolution_contract.is_valid() {
            return Err(StoreError::Invalid);
        }
        if command.lease_duration.is_zero()
            || command.lease_duration.as_millis() > u128::from(self.max_lease_millis)
        {
            return Err(StoreError::LeaseTooLong);
        }
        let observed = self.now();
        let mut tx = begin_immediate(&self.pool).await?;
        reject_global_request_collision(&mut tx, command.context.request_id()).await?;
        reject_recovery_request_collision(&mut tx, command.context.request_id()).await?;
        let mutation_collision: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM effect_journal_mutations WHERE request_id = ? LIMIT 1",
        )
        .bind(command.context.request_id().to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if mutation_collision.is_some() {
            return Err(StoreError::RequestConflict {
                request_id: command.context.request_id(),
            });
        }
        let row =
            require_open_session(&mut tx, command.session_id, StoreAction::ReserveEffect).await?;
        let now = advance_time_floor(&mut tx, command.session_id, row.time_floor, observed).await?;
        require_owner(&row, command.context.caller(), command.owner_epoch, now)?;
        let participant = load_participant_in(&mut tx, command.participant_id)
            .await?
            .ok_or(StoreError::ParticipantNotFound {
                participant_id: command.participant_id,
            })?;
        let operation = load_operation_in(&mut tx, command.operation_id)
            .await?
            .ok_or(StoreError::OperationNotFound {
                operation_id: command.operation_id,
            })?;
        if participant.session_id != command.session_id
            || operation.session_id != command.session_id
            || operation.participant_id != command.participant_id
            || !matches!(
                operation.state,
                OperationState::Running | OperationState::Waiting
            )
        {
            return Err(StoreError::Invalid);
        }
        if let Some(mut existing) = load_effect_in(&mut tx, command.context.request_id()).await? {
            if existing.session_id != command.session_id
                || existing.caller != command.context.caller()
                || existing.action != command.action
                || existing.semantic_digest != command.semantic_digest
                || existing.effect_class != command.effect_class
                || existing.participant_id != command.participant_id
                || existing.operation_id != command.operation_id
                || existing.resolution_contract != command.resolution_contract
            {
                return Err(StoreError::RequestConflict {
                    request_id: command.context.request_id(),
                });
            }
            if existing.phase == EffectJournalPhase::Started && existing.lease_expires_at <= now {
                existing.phase = EffectJournalPhase::Uncertain;
                existing.revision = existing.revision.next().ok_or(StoreError::Corrupt)?;
                update_effect(&mut tx, &existing).await?;
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(existing);
        }
        let entry = EffectJournalEntry {
            request_id: command.context.request_id(),
            session_id: command.session_id,
            participant_id: command.participant_id,
            operation_id: command.operation_id,
            caller: command.context.caller(),
            action: command.action,
            semantic_digest: command.semantic_digest,
            effect_class: command.effect_class,
            resolution_contract: command.resolution_contract,
            phase: EffectJournalPhase::Reserved,
            owner_host: command.context.caller(),
            owner_epoch: command.owner_epoch,
            lease_expires_at: effect_expiry(now, command.lease_duration)?,
            terminal: None,
            revision: Revision::initial(),
        };
        insert_effect(&mut tx, &entry).await?;
        crash_at("effect.reserve.after_write");
        crash_at("effect.reserve.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("effect.reserve.after_commit");
        Ok(entry)
    }

    async fn start_effect(
        &self,
        command: EffectTransition,
    ) -> Result<EffectJournalEntry, StoreError> {
        transition_effect(self, command).await
    }
    async fn resolve_effect(
        &self,
        command: EffectTransition,
    ) -> Result<EffectJournalEntry, StoreError> {
        transition_effect(self, command).await
    }
    async fn takeover_effect(
        &self,
        command: TakeoverEffect,
    ) -> Result<EffectJournalEntry, StoreError> {
        takeover_effect(self, command).await
    }
    async fn resolve_authorized_effect(
        &self,
        command: ResolveAuthorizedEffect,
    ) -> Result<Mutation<AuthorizedEffectResolution>, StoreError> {
        resolve_authorized_effect(self, command).await
    }
    async fn read_effect(
        &self,
        request_id: RequestId,
    ) -> Result<Option<EffectJournalEntry>, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        let value = load_effect_in(&mut tx, request_id).await?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(value)
    }
    async fn list_effects(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<EffectJournalEntry>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let rows = sqlx::query(
            "SELECT * FROM effect_journal WHERE session_id = ? ORDER BY request_id COLLATE BINARY",
        )
        .bind(session_id.to_string())
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let values = rows.iter().map(decode_effect).collect();
        transaction.commit().await.map_err(map_sqlx)?;
        values
    }
}

impl ToolStore for SqliteStore {
    async fn load_tool_invocation_by_approval_effect(
        &self,
        effect_id: RequestId,
    ) -> Result<Option<ToolInvocationSnapshot>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let rows = sqlx::query("SELECT invocation_id FROM tool_invocations WHERE json_extract(CAST(snapshot AS TEXT),'$.invocation.approval_effect_id')=? LIMIT 2")
            .bind(effect_id.to_string())
            .fetch_all(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        if rows.len() > 1 {
            return Err(StoreError::Corrupt);
        }
        let Some(row) = rows.first() else {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(None);
        };
        let raw: String = row.try_get("invocation_id").map_err(map_sqlx)?;
        let id =
            ToolInvocationId::from_uuid(Uuid::parse_str(&raw).map_err(|_| StoreError::Corrupt)?)
                .map_err(|_| StoreError::Corrupt)?;
        let snapshot = load_tool_invocation_in(&mut tx, id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        if snapshot.invocation().approval_effect_id() != Some(effect_id) {
            return Err(StoreError::Corrupt);
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(Some(snapshot))
    }

    #[allow(clippy::too_many_lines)]
    async fn connect_tool_provider(
        &self,
        command: ConnectToolProvider,
    ) -> Result<ToolProviderConnectionSnapshot, StoreError> {
        if command.registration_ids.is_empty()
            || command.registration_ids.len() > MAX_TOOL_REGISTRATIONS
        {
            return Err(StoreError::Invalid);
        }
        let mut ids = command.registration_ids.clone();
        ids.sort();
        ids.dedup();
        if ids.len() != command.registration_ids.len() {
            return Err(StoreError::Invalid);
        }
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(value) =
            replay_json::<ToolProviderConnectionSnapshot>(&mut tx, &command).await?
        {
            let event = sqlx::query("SELECT occurred_at_seconds,occurred_at_nanos FROM events WHERE related_request_id=? AND event_type='tool.provider_connected'")
                .bind(command.context.request_id().to_string())
                .fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StoreError::Corrupt)?;
            let durable = sqlx::query("SELECT connection_id,consumer_key,generation,acknowledged_server_sequence,next_server_sequence FROM tool_provider_connections WHERE session_id=? AND provider_id=?")
                .bind(command.session_id.to_string()).bind(command.provider_id.to_string())
                .fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StoreError::Corrupt)?;
            if !value.is_structurally_valid()
                || value.connected_at.unix_seconds()
                    != event
                        .try_get::<i64, _>("occurred_at_seconds")
                        .map_err(map_sqlx)?
                || i64::from(value.connected_at.nanoseconds())
                    != event
                        .try_get::<i64, _>("occurred_at_nanos")
                        .map_err(map_sqlx)?
                || value.session_id != command.session_id
                || value.consumer_key != command.consumer_key
                || value.provider_id != command.provider_id
                || value.connection_id != command.connection_id
                || value.registration_ids != ids
                || value.generation
                    > u64::try_from(durable.try_get::<i64, _>("generation").map_err(map_sqlx)?)
                        .map_err(|_| StoreError::Corrupt)?
                || value.acknowledged_server_sequence != command.after_server_sequence
                || durable
                    .try_get::<String, _>("consumer_key")
                    .map_err(map_sqlx)?
                    != command.consumer_key.as_str()
                || value.acknowledged_server_sequence
                    > u64::try_from(
                        durable
                            .try_get::<i64, _>("acknowledged_server_sequence")
                            .map_err(map_sqlx)?,
                    )
                    .map_err(|_| StoreError::Corrupt)?
                || value.next_server_sequence
                    > u64::try_from(
                        durable
                            .try_get::<i64, _>("next_server_sequence")
                            .map_err(map_sqlx)?,
                    )
                    .map_err(|_| StoreError::Corrupt)?
            {
                return Err(StoreError::Corrupt);
            }
            for registration_id in &value.registration_ids {
                let registration = sqlx::query(
                    "SELECT consumer_key,snapshot FROM tool_registrations WHERE session_id=? AND registration_id=?",
                )
                .bind(value.session_id.to_string())
                .bind(registration_id.to_string())
                .fetch_optional(&mut *tx)
                .await
                .map_err(map_sqlx)?
                .ok_or(StoreError::Corrupt)?;
                let snapshot: ToolRegistrationSnapshot = serde_json::from_slice(
                    &registration
                        .try_get::<Vec<u8>, _>("snapshot")
                        .map_err(map_sqlx)?,
                )
                .map_err(|_| StoreError::Corrupt)?;
                if snapshot.session_id != value.session_id
                    || snapshot.consumer_key != value.consumer_key
                    || snapshot.registration_id != *registration_id
                    || registration
                        .try_get::<String, _>("consumer_key")
                        .map_err(map_sqlx)?
                        != value.consumer_key.as_str()
                {
                    return Err(StoreError::Corrupt);
                }
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(value);
        }
        let row = require_open_session(&mut tx, command.session_id, command.action()).await?;
        let now =
            advance_time_floor(&mut tx, command.session_id, row.time_floor, self.now()).await?;
        require_owner(&row, command.context.caller(), command.owner_epoch, now)?;
        if command.consumer_key != *row.snapshot.consumer_key() {
            return Err(StoreError::Invalid);
        }
        for id in &command.registration_ids {
            let consumer: Option<String> = sqlx::query_scalar(
                "SELECT consumer_key FROM tool_registrations WHERE session_id=? AND registration_id=?",
            )
            .bind(command.session_id.to_string())
            .bind(id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx)?;
            if consumer.as_deref() != Some(row.snapshot.consumer_key().as_str()) {
                return Err(StoreError::Invalid);
            }
        }
        let alias = sqlx::query(
            "SELECT session_id,provider_id FROM tool_provider_connections WHERE connection_id=?",
        )
        .bind(command.connection_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if alias.is_some_and(|v| {
            v.try_get::<String, _>("session_id").ok().as_deref()
                != Some(command.session_id.to_string().as_str())
                || v.try_get::<String, _>("provider_id").ok().as_deref()
                    != Some(command.provider_id.to_string().as_str())
        }) {
            return Err(StoreError::RequestConflict {
                request_id: command.context.request_id(),
            });
        }
        let previous=sqlx::query("SELECT consumer_key,generation,acknowledged_server_sequence,next_server_sequence FROM tool_provider_connections WHERE session_id=? AND provider_id=?")
            .bind(command.session_id.to_string()).bind(command.provider_id.to_string()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?;
        let (generation, next, prior_ack) = if let Some(row) = previous {
            if row.try_get::<String, _>("consumer_key").map_err(map_sqlx)?
                != command.consumer_key.as_str()
            {
                return Err(StoreError::Invalid);
            }
            (
                u64::try_from(row.try_get::<i64, _>("generation").map_err(map_sqlx)?)
                    .map_err(|_| StoreError::Corrupt)?
                    .checked_add(1)
                    .ok_or(StoreError::Corrupt)?,
                u64::try_from(
                    row.try_get::<i64, _>("next_server_sequence")
                        .map_err(map_sqlx)?,
                )
                .map_err(|_| StoreError::Corrupt)?,
                u64::try_from(
                    row.try_get::<i64, _>("acknowledged_server_sequence")
                        .map_err(map_sqlx)?,
                )
                .map_err(|_| StoreError::Corrupt)?,
            )
        } else {
            (1, 1, 0)
        };
        if command.after_server_sequence < prior_ack || command.after_server_sequence >= next {
            return Err(StoreError::Invalid);
        }
        if command.after_server_sequence > prior_ack {
            let rows = sqlx::query("SELECT server_sequence,cancellation_server_sequence,snapshot FROM tool_invocations WHERE session_id=? AND provider_id=? AND (server_sequence<=? OR cancellation_server_sequence<=?)")
                .bind(command.session_id.to_string())
                .bind(command.provider_id.to_string())
                .bind(to_i64(command.after_server_sequence)?)
                .bind(to_i64(command.after_server_sequence)?)
                .fetch_all(&mut *tx)
                .await
                .map_err(map_sqlx)?;
            let mut durable_prefix = BTreeSet::new();
            for row in rows {
                let value: ToolInvocationSnapshot = serde_json::from_slice(
                    &row.try_get::<Vec<u8>, _>("snapshot").map_err(map_sqlx)?,
                )
                .map_err(|_| StoreError::Corrupt)?;
                let sequence =
                    u64::try_from(row.try_get::<i64, _>("server_sequence").map_err(map_sqlx)?)
                        .map_err(|_| StoreError::Corrupt)?;
                if sequence <= command.after_server_sequence
                    && (matches!(
                        value.phase(),
                        ToolInvocationPhase::Completed | ToolInvocationPhase::Failed
                    ) || value.dispatch().cancellation_id.is_some())
                {
                    durable_prefix.insert(sequence);
                }
                if let Some(sequence) = row
                    .try_get::<Option<i64>, _>("cancellation_server_sequence")
                    .map_err(map_sqlx)?
                {
                    let sequence = u64::try_from(sequence).map_err(|_| StoreError::Corrupt)?;
                    if sequence <= command.after_server_sequence {
                        durable_prefix.insert(sequence);
                    }
                }
            }
            if durable_prefix.len()
                != usize::try_from(command.after_server_sequence)
                    .map_err(|_| StoreError::Invalid)?
                || durable_prefix.first().copied() != Some(1)
                || durable_prefix.last().copied() != Some(command.after_server_sequence)
            {
                return Err(StoreError::Invalid);
            }
        }
        let snapshot = ToolProviderConnectionSnapshot {
            session_id: command.session_id,
            consumer_key: command.consumer_key.clone(),
            provider_id: command.provider_id,
            connection_id: command.connection_id,
            registration_ids: ids.clone(),
            generation,
            acknowledged_server_sequence: command.after_server_sequence,
            next_server_sequence: next,
            connected_at: now,
        };
        sqlx::query("INSERT INTO tool_provider_connections(session_id,provider_id,connection_id,consumer_key,generation,acknowledged_server_sequence,next_server_sequence,connected_at_seconds,connected_at_nanos,registrations) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(session_id,provider_id) DO UPDATE SET connection_id=excluded.connection_id,generation=excluded.generation,acknowledged_server_sequence=excluded.acknowledged_server_sequence,connected_at_seconds=excluded.connected_at_seconds,connected_at_nanos=excluded.connected_at_nanos,registrations=excluded.registrations")
            .bind(command.session_id.to_string()).bind(command.provider_id.to_string()).bind(command.connection_id.to_string())
            .bind(command.consumer_key.as_str())
            .bind(to_i64(generation)?).bind(to_i64(command.after_server_sequence)?).bind(to_i64(next)?)
            .bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).bind(serde_json::to_vec(&ids).map_err(|_|StoreError::Corrupt)?)
            .execute(&mut *tx).await.map_err(map_sqlx)?;
        let pending = sqlx::query("SELECT invocation_id,snapshot FROM tool_invocations WHERE session_id=? AND provider_id=? AND json_extract(CAST(snapshot AS TEXT),'$.phase') IN ('reserved','started','uncertain')")
            .bind(command.session_id.to_string()).bind(command.provider_id.to_string())
            .fetch_all(&mut *tx).await.map_err(map_sqlx)?;
        for pending in pending {
            let mut value: ToolInvocationSnapshot = serde_json::from_slice(
                &pending
                    .try_get::<Vec<u8>, _>("snapshot")
                    .map_err(map_sqlx)?,
            )
            .map_err(|_| StoreError::Corrupt)?;
            let mut dispatch = value.dispatch().clone();
            dispatch.connection_id = Some(command.connection_id);
            dispatch.connection_generation = Some(generation);
            value = ToolInvocationSnapshot::new(
                value.registration_id(),
                value.definition().clone(),
                value.invocation().clone(),
                value.phase(),
                value.terminal().cloned(),
                value.revision(),
                dispatch,
            )
            .map_err(|_| StoreError::Corrupt)?;
            sqlx::query("UPDATE tool_invocations SET snapshot=?,connection_generation=? WHERE invocation_id=?")
                .bind(serde_json::to_vec(&value).map_err(|_| StoreError::Corrupt)?)
                .bind(to_i64(generation)?)
                .bind(pending.try_get::<String, _>("invocation_id").map_err(map_sqlx)?)
                .execute(&mut *tx).await.map_err(map_sqlx)?;
        }
        append_event(
            &mut tx,
            command.context.request_id(),
            command.session_id,
            Revision::new(generation).map_err(|_| StoreError::Corrupt)?,
            "tool.provider_connected",
            now,
        )
        .await?;
        record_json(&mut tx, command.session_id, &command, &snapshot).await?;
        crash_at("tool.connect.after_write");
        crash_at("tool.connect.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("tool.connect.after_commit");
        Ok(snapshot)
    }

    async fn register_tool(
        &self,
        command: RegisterTool,
    ) -> Result<Mutation<ToolRegistrationSnapshot>, StoreError> {
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(value) = replay_json::<ToolRegistrationSnapshot>(&mut tx, &command).await? {
            let session = load_session_in(&mut tx, command.session_id)
                .await?
                .ok_or(StoreError::Corrupt)?;
            let current = load_tool_registration_in(
                &mut tx,
                command.session_id,
                command.definition.name(),
                command.definition.version(),
            )
            .await?
            .ok_or(StoreError::Corrupt)?;
            if value != current
                || value.session_id != command.session_id
                || value.registration_id != command.registration_id
                || value.consumer_key != command.consumer_key
                || value.consumer_key != *session.snapshot.consumer_key()
                || value.definition != command.definition
            {
                return Err(StoreError::Corrupt);
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(value));
        }
        let row = require_open_session(&mut tx, command.session_id, command.action()).await?;
        let now =
            advance_time_floor(&mut tx, command.session_id, row.time_floor, self.now()).await?;
        require_owner(&row, command.context.caller(), command.owner_epoch, now)?;
        if row.snapshot.consumer_key() != &command.consumer_key {
            return Err(StoreError::Invalid);
        }
        reject_aliased_tool_registration(&mut tx, &command).await?;
        let existing: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT snapshot FROM tool_registrations WHERE session_id=? AND tool_name=? AND tool_version=?",
        ).bind(command.session_id.to_string()).bind(command.definition.name())
            .bind(command.definition.version()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?;
        if let Some(bytes) = existing {
            let snapshot: ToolRegistrationSnapshot =
                serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
            if snapshot.consumer_key != command.consumer_key
                || snapshot.definition != command.definition
                || snapshot.registration_id != command.registration_id
            {
                return Err(StoreError::RequestConflict {
                    request_id: command.context.request_id(),
                });
            }
            record_json(&mut tx, command.session_id, &command, &snapshot).await?;
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Unchanged(snapshot));
        }
        if tool_registration_capacity_reached(&mut tx, command.session_id).await? {
            return Err(StoreError::Invalid);
        }
        let snapshot = ToolRegistrationSnapshot {
            registration_id: command.registration_id,
            session_id: command.session_id,
            consumer_key: command.consumer_key.clone(),
            definition: command.definition.clone(),
            revision: Revision::initial(),
            registered_at: now,
        };
        sqlx::query("INSERT INTO tool_registrations(session_id,registration_id,tool_name,tool_version,consumer_key,snapshot) VALUES(?,?,?,?,?,?)")
            .bind(command.session_id.to_string()).bind(command.registration_id.to_string()).bind(command.definition.name()).bind(command.definition.version())
            .bind(command.consumer_key.as_str()).bind(serde_json::to_vec(&snapshot).map_err(|_|StoreError::Corrupt)?)
            .execute(&mut *tx).await.map_err(map_sqlx)?;
        append_event(
            &mut tx,
            command.context.request_id(),
            command.session_id,
            snapshot.revision,
            "tool.registered",
            now,
        )
        .await?;
        record_json(&mut tx, command.session_id, &command, &snapshot).await?;
        crash_at("tool.register.after_write");
        crash_at("tool.register.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("tool.register.after_commit");
        Ok(Mutation::Applied(snapshot))
    }

    #[allow(clippy::too_many_lines)]
    async fn reserve_tool_invocation(
        &self,
        command: ReserveToolInvocation,
    ) -> Result<ToolInvocationSnapshot, StoreError> {
        if command.context.request_id() != command.invocation.request_id()
            || command.lease_duration.is_zero()
            || command.lease_duration.as_millis() > u128::from(self.max_lease_millis)
        {
            return Err(StoreError::Invalid);
        }
        let mut tx = begin_immediate(&self.pool).await?;
        reject_global_request_collision(&mut tx, command.context.request_id()).await?;
        reject_recovery_request_collision(&mut tx, command.context.request_id()).await?;
        let mutation_collision: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM tool_invocation_mutations WHERE request_id=? LIMIT 1",
        )
        .bind(command.context.request_id().to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if mutation_collision.is_some() {
            return Err(StoreError::RequestConflict {
                request_id: command.context.request_id(),
            });
        }
        let request_invocation: Option<String> = sqlx::query_scalar(
            "SELECT invocation_id FROM tool_invocations WHERE effect_request_id=?",
        )
        .bind(command.context.request_id().to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if request_invocation
            .as_deref()
            .is_some_and(|value| value != command.invocation.invocation_id().to_string())
        {
            return Err(StoreError::RequestConflict {
                request_id: command.context.request_id(),
            });
        }
        if let Some(existing) =
            load_tool_invocation_in(&mut tx, command.invocation.invocation_id()).await?
        {
            let effect = load_effect_in(&mut tx, existing.invocation().request_id())
                .await?
                .ok_or(StoreError::Corrupt)?;
            if existing.invocation() != &command.invocation
                || effect.caller != command.context.caller()
                || effect.owner_epoch != command.owner_epoch
                || effect.semantic_digest != command.digest()
            {
                return Err(StoreError::RequestConflict {
                    request_id: command.context.request_id(),
                });
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(existing);
        }
        let row = require_open_session(&mut tx, command.invocation.session_id(), command.action())
            .await?;
        let now = advance_time_floor(
            &mut tx,
            command.invocation.session_id(),
            row.time_floor,
            self.now(),
        )
        .await?;
        require_owner(&row, command.context.caller(), command.owner_epoch, now)?;
        let registration = load_tool_registration_in(
            &mut tx,
            command.invocation.session_id(),
            command.invocation.tool_name(),
            command.invocation.tool_version(),
        )
        .await?
        .ok_or(StoreError::Invalid)?;
        if registration.registration_id != command.registration_id {
            return Err(StoreError::Invalid);
        }
        registration
            .definition
            .validate_input(command.invocation.input())
            .map_err(|_| StoreError::Invalid)?;
        let provider=sqlx::query("SELECT connection_id,generation,next_server_sequence,registrations FROM tool_provider_connections WHERE session_id=? AND provider_id=?")
            .bind(command.invocation.session_id().to_string()).bind(command.provider_id.to_string()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?
            .ok_or(StoreError::Invalid)?;
        let registration_ids: Vec<navigator_domain::ToolRegistrationId> = serde_json::from_slice(
            &provider
                .try_get::<Vec<u8>, _>("registrations")
                .map_err(map_sqlx)?,
        )
        .map_err(|_| StoreError::Corrupt)?;
        if !registration_ids.contains(&registration.registration_id) {
            return Err(StoreError::Invalid);
        }
        let server_sequence = u64::try_from(
            provider
                .try_get::<i64, _>("next_server_sequence")
                .map_err(map_sqlx)?,
        )
        .map_err(|_| StoreError::Corrupt)?;
        let generation = u64::try_from(provider.try_get::<i64, _>("generation").map_err(map_sqlx)?)
            .map_err(|_| StoreError::Corrupt)?;
        let connection_id = navigator_domain::ToolConnectionId::from_uuid(
            Uuid::parse_str(
                &provider
                    .try_get::<String, _>("connection_id")
                    .map_err(map_sqlx)?,
            )
            .map_err(|_| StoreError::Corrupt)?,
        )
        .map_err(|_| StoreError::Corrupt)?;
        let now_nanos =
            i128::from(now.unix_seconds()) * 1_000_000_000 + i128::from(now.nanoseconds());
        let deadline_nanos = i128::from(command.deadline.unix_seconds()) * 1_000_000_000
            + i128::from(command.deadline.nanoseconds());
        if deadline_nanos <= now_nanos
            || deadline_nanos - now_nanos
                > i128::from(registration.definition.timeout().as_millis()) * 1_000_000
        {
            return Err(StoreError::Invalid);
        }
        sqlx::query("UPDATE tool_provider_connections SET next_server_sequence=? WHERE session_id=? AND provider_id=? AND next_server_sequence=?")
            .bind(to_i64(server_sequence.checked_add(1).ok_or(StoreError::Corrupt)?)?).bind(command.invocation.session_id().to_string())
            .bind(command.provider_id.to_string()).bind(to_i64(server_sequence)?).execute(&mut *tx).await.map_err(map_sqlx)?;
        let participant = load_participant_in(&mut tx, command.invocation.participant_id())
            .await?
            .ok_or(StoreError::Invalid)?;
        let operation = load_operation_in(&mut tx, command.invocation.operation_id())
            .await?
            .ok_or(StoreError::Invalid)?;
        if participant.session_id != command.invocation.session_id()
            || operation.session_id != command.invocation.session_id()
            || operation.participant_id != command.invocation.participant_id()
            || !matches!(
                operation.state,
                OperationState::Running | OperationState::Waiting
            )
        {
            return Err(StoreError::Invalid);
        }
        let requested = ScopedCapability::new(
            registration.definition.required_authority().clone(),
            ResourceScope::Operation(operation.operation_id),
        );
        let grant = match command.invocation.authority_grant_id() {
            Some(id) => load_grant_in(&mut tx, id).await?,
            None => None,
        };
        let authorized = load_authority_policy_in(&mut tx, participant.participant_id)
            .await?
            .as_ref()
            .and_then(|policy| {
                policy_ceilings(policy)
                    .authorize_effect(
                        participant.participant_id,
                        command.invocation.session_id(),
                        &requested,
                        grant.as_ref().map(|value| &value.grant),
                        now,
                    )
                    .ok()
            })
            .is_some()
            && grant
                .as_ref()
                .is_none_or(|value| value.consumed_at.is_none());
        if !authorized {
            return Err(StoreError::Invalid);
        }
        let contract = navigator_store_api::EffectResolutionContract::conservative();
        let effect = EffectJournalEntry {
            request_id: command.context.request_id(),
            session_id: command.invocation.session_id(),
            participant_id: command.invocation.participant_id(),
            operation_id: command.invocation.operation_id(),
            caller: command.context.caller(),
            action: registration.definition.required_authority().clone(),
            semantic_digest: command.digest(),
            effect_class: registration.definition.effect_class(),
            resolution_contract: contract,
            phase: EffectJournalPhase::Reserved,
            owner_host: command.context.caller(),
            owner_epoch: command.owner_epoch,
            lease_expires_at: effect_expiry(now, command.lease_duration)?,
            terminal: None,
            revision: Revision::initial(),
        };
        insert_effect(&mut tx, &effect).await?;
        let snapshot = ToolInvocationSnapshot::new(
            command.registration_id,
            registration.definition.clone(),
            command.invocation.clone(),
            ToolInvocationPhase::Reserved,
            None,
            Revision::initial(),
            ToolDispatchSnapshot {
                dispatch_id: command.dispatch_id,
                provider_id: command.provider_id,
                server_sequence,
                deadline: command.deadline,
                connection_id: Some(connection_id),
                connection_generation: Some(generation),
                cancellation_id: None,
                cancellation_server_sequence: None,
                terminal_digest: None,
            },
        )
        .map_err(|_| StoreError::Invalid)?;
        sqlx::query("INSERT INTO tool_invocations(invocation_id,effect_request_id,registration_id,dispatch_id,provider_id,server_sequence,deadline_seconds,deadline_nanos,connection_generation,session_id,participant_id,operation_id,tool_name,tool_version,snapshot) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(command.invocation.invocation_id().to_string()).bind(command.context.request_id().to_string())
            .bind(registration.registration_id.to_string())
            .bind(command.dispatch_id.to_string()).bind(command.provider_id.to_string()).bind(to_i64(server_sequence)?)
            .bind(command.deadline.unix_seconds()).bind(i64::from(command.deadline.nanoseconds())).bind(to_i64(generation)?)
            .bind(command.invocation.session_id().to_string()).bind(command.invocation.participant_id().to_string())
            .bind(command.invocation.operation_id().to_string()).bind(command.invocation.tool_name())
            .bind(command.invocation.tool_version()).bind(serde_json::to_vec(&snapshot).map_err(|_|StoreError::Corrupt)?)
            .execute(&mut *tx).await.map_err(map_sqlx)?;
        append_event(
            &mut tx,
            command.context.request_id(),
            command.invocation.session_id(),
            snapshot.revision(),
            "tool.invocation_reserved",
            now,
        )
        .await?;
        crash_at("tool.reserve.after_write");
        crash_at("tool.reserve.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("tool.reserve.after_commit");
        Ok(snapshot)
    }

    async fn transition_tool_invocation(
        &self,
        command: TransitionToolInvocation,
    ) -> Result<ToolInvocationSnapshot, StoreError> {
        transition_tool(self, command).await
    }

    async fn load_tool_invocation(
        &self,
        id: ToolInvocationId,
    ) -> Result<Option<ToolInvocationSnapshot>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let value = load_tool_invocation_in(&mut tx, id).await?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(value)
    }

    async fn list_recoverable_tool_invocations(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<ToolInvocationSnapshot>, StoreError> {
        let rows=sqlx::query_scalar::<_,String>("SELECT invocation_id FROM tool_invocations WHERE session_id=? AND json_extract(CAST(snapshot AS TEXT),'$.phase') IN ('reserved','started','uncertain') ORDER BY invocation_id COLLATE BINARY LIMIT 16385")
            .bind(session_id.to_string()).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        if rows.len() > 16384 {
            return Err(StoreError::Invalid);
        }
        let mut values = Vec::with_capacity(rows.len());
        for value in rows {
            let id = ToolInvocationId::from_uuid(
                Uuid::parse_str(&value).map_err(|_| StoreError::Corrupt)?,
            )
            .map_err(|_| StoreError::Corrupt)?;
            values.push(
                self.load_tool_invocation(id)
                    .await?
                    .ok_or(StoreError::Corrupt)?,
            );
        }
        Ok(values)
    }

    async fn load_tool_registration(
        &self,
        session_id: SessionId,
        registration_id: navigator_domain::ToolRegistrationId,
    ) -> Result<Option<ToolRegistrationSnapshot>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let identity = sqlx::query(
            "SELECT tool_name,tool_version FROM tool_registrations WHERE session_id=? AND registration_id=?",
        )
        .bind(session_id.to_string())
        .bind(registration_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let value = if let Some(identity) = identity {
            let value = load_tool_registration_in(
                &mut tx,
                session_id,
                &identity
                    .try_get::<String, _>("tool_name")
                    .map_err(map_sqlx)?,
                &identity
                    .try_get::<String, _>("tool_version")
                    .map_err(map_sqlx)?,
            )
            .await?
            .ok_or(StoreError::Corrupt)?;
            if value.registration_id != registration_id {
                return Err(StoreError::Corrupt);
            }
            Some(value)
        } else {
            None
        };
        tx.commit().await.map_err(map_sqlx)?;
        Ok(value)
    }
    async fn list_tool_registrations(
        &self,
        session_id: SessionId,
    ) -> Result<Vec<ToolRegistrationSnapshot>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let rows=sqlx::query("SELECT tool_name,tool_version FROM tool_registrations WHERE session_id=? ORDER BY tool_name COLLATE BINARY,tool_version COLLATE BINARY LIMIT 65")
            .bind(session_id.to_string()).fetch_all(&mut *tx).await.map_err(map_sqlx)?;
        if rows.len() > 64 {
            return Err(StoreError::Invalid);
        }
        let mut values = Vec::with_capacity(rows.len());
        for row in rows {
            values.push(
                load_tool_registration_in(
                    &mut tx,
                    session_id,
                    &row.try_get::<String, _>("tool_name").map_err(map_sqlx)?,
                    &row.try_get::<String, _>("tool_version").map_err(map_sqlx)?,
                )
                .await?
                .ok_or(StoreError::Corrupt)?,
            );
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(values)
    }
    async fn list_provider_replay(
        &self,
        session_id: SessionId,
        provider_id: navigator_domain::ToolProviderId,
        after: u64,
    ) -> Result<Vec<ToolInvocationSnapshot>, StoreError> {
        let rows=sqlx::query_scalar::<_,String>("SELECT invocation_id FROM tool_invocations WHERE session_id=? AND provider_id=? AND (json_extract(CAST(snapshot AS TEXT),'$.phase') IN ('reserved','started','uncertain') OR server_sequence>?) ORDER BY server_sequence LIMIT 16385")
            .bind(session_id.to_string()).bind(provider_id.to_string()).bind(to_i64(after)?).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        if rows.len() > 16384 {
            return Err(StoreError::Invalid);
        }
        let mut values = Vec::with_capacity(rows.len());
        for value in rows {
            let id = ToolInvocationId::from_uuid(
                Uuid::parse_str(&value).map_err(|_| StoreError::Corrupt)?,
            )
            .map_err(|_| StoreError::Corrupt)?;
            let snapshot = self
                .load_tool_invocation(id)
                .await?
                .ok_or(StoreError::Corrupt)?;
            if snapshot.invocation().session_id() != session_id
                || snapshot.dispatch().provider_id != provider_id
            {
                return Err(StoreError::Corrupt);
            }
            values.push(snapshot);
        }
        Ok(values)
    }
}

async fn load_tool_registration_in(
    tx: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    name: &str,
    version: &str,
) -> Result<Option<ToolRegistrationSnapshot>, StoreError> {
    let row=sqlx::query("SELECT session_id,registration_id,tool_name,tool_version,consumer_key,snapshot FROM tool_registrations WHERE session_id=? AND tool_name=? AND tool_version=?")
        .bind(session_id.to_string()).bind(name).bind(version).fetch_optional(&mut **tx).await.map_err(map_sqlx)?;
    let value = row
        .as_ref()
        .map(|row| {
            serde_json::from_slice::<ToolRegistrationSnapshot>(
                &row.try_get::<Vec<u8>, _>("snapshot").map_err(map_sqlx)?,
            )
            .map_err(|_| StoreError::Corrupt)
        })
        .transpose()?;
    if let Some(v) = &value {
        let row = row.as_ref().ok_or(StoreError::Corrupt)?;
        let session = load_session_in(tx, session_id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        if v.session_id != session_id
            || v.consumer_key != *session.snapshot.consumer_key()
            || v.definition.name() != name
            || v.definition.version() != version
            || row.try_get::<String, _>("session_id").map_err(map_sqlx)? != v.session_id.to_string()
            || row
                .try_get::<String, _>("registration_id")
                .map_err(map_sqlx)?
                != v.registration_id.to_string()
            || row.try_get::<String, _>("tool_name").map_err(map_sqlx)? != v.definition.name()
            || row.try_get::<String, _>("tool_version").map_err(map_sqlx)? != v.definition.version()
            || row.try_get::<String, _>("consumer_key").map_err(map_sqlx)?
                != v.consumer_key.as_str()
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(value)
}

async fn tool_registration_capacity_reached(
    tx: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
) -> Result<bool, StoreError> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tool_registrations WHERE session_id=?")
            .bind(session_id.to_string())
            .fetch_one(&mut **tx)
            .await
            .map_err(map_sqlx)?;
    Ok(count >= i64::try_from(MAX_TOOL_REGISTRATIONS).map_err(|_| StoreError::Corrupt)?)
}

async fn reject_aliased_tool_registration(
    tx: &mut Transaction<'_, Sqlite>,
    command: &RegisterTool,
) -> Result<(), StoreError> {
    let aliased: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT snapshot FROM tool_registrations WHERE registration_id=?")
            .bind(command.registration_id.to_string())
            .fetch_optional(&mut **tx)
            .await
            .map_err(map_sqlx)?;
    let Some(bytes) = aliased else { return Ok(()) };
    let snapshot: ToolRegistrationSnapshot =
        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
    if snapshot.session_id != command.session_id
        || snapshot.definition.name() != command.definition.name()
        || snapshot.definition.version() != command.definition.version()
    {
        return Err(StoreError::RequestConflict {
            request_id: command.context.request_id(),
        });
    }
    Ok(())
}

fn tool_invocation_projection_matches(
    row: &SqliteRow,
    value: &ToolInvocationSnapshot,
) -> Result<bool, StoreError> {
    let dispatch = value.dispatch();
    Ok(dispatch.dispatch_id.to_string()
        == row.try_get::<String, _>("dispatch_id").map_err(map_sqlx)?
        && dispatch.provider_id.to_string()
            == row.try_get::<String, _>("provider_id").map_err(map_sqlx)?
        && i64::try_from(dispatch.server_sequence).ok()
            == Some(row.try_get::<i64, _>("server_sequence").map_err(map_sqlx)?)
        && dispatch.deadline.unix_seconds()
            == row
                .try_get::<i64, _>("deadline_seconds")
                .map_err(map_sqlx)?
        && i64::from(dispatch.deadline.nanoseconds())
            == row.try_get::<i64, _>("deadline_nanos").map_err(map_sqlx)?
        && dispatch
            .connection_generation
            .and_then(|item| i64::try_from(item).ok())
            == row
                .try_get::<Option<i64>, _>("connection_generation")
                .map_err(map_sqlx)?
        && dispatch.cancellation_id.map(|item| item.to_string())
            == row
                .try_get::<Option<String>, _>("cancellation_id")
                .map_err(map_sqlx)?
        && dispatch
            .cancellation_server_sequence
            .and_then(|item| i64::try_from(item).ok())
            == row
                .try_get::<Option<i64>, _>("cancellation_server_sequence")
                .map_err(map_sqlx)?
        && dispatch
            .terminal_digest
            .map(|item| item.as_bytes().to_vec())
            == row
                .try_get::<Option<Vec<u8>>, _>("terminal_digest")
                .map_err(map_sqlx)?)
}

async fn load_tool_invocation_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: ToolInvocationId,
) -> Result<Option<ToolInvocationSnapshot>, StoreError> {
    let row=sqlx::query("SELECT effect_request_id,registration_id,dispatch_id,provider_id,server_sequence,deadline_seconds,deadline_nanos,connection_generation,cancellation_id,cancellation_server_sequence,terminal_digest,session_id,participant_id,operation_id,tool_name,tool_version,snapshot FROM tool_invocations WHERE invocation_id=?")
        .bind(id.to_string()).fetch_optional(&mut **tx).await.map_err(map_sqlx)?;
    let Some(row) = row else { return Ok(None) };
    let bytes: Vec<u8> = row.try_get("snapshot").map_err(map_sqlx)?;
    let value: ToolInvocationSnapshot =
        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
    if value.invocation().invocation_id() != id
        || value.invocation().request_id().to_string()
            != row
                .try_get::<String, _>("effect_request_id")
                .map_err(map_sqlx)?
        || value.invocation().session_id().to_string()
            != row.try_get::<String, _>("session_id").map_err(map_sqlx)?
        || value.invocation().participant_id().to_string()
            != row
                .try_get::<String, _>("participant_id")
                .map_err(map_sqlx)?
        || value.invocation().operation_id().to_string()
            != row.try_get::<String, _>("operation_id").map_err(map_sqlx)?
        || value.invocation().tool_name()
            != row.try_get::<String, _>("tool_name").map_err(map_sqlx)?
        || value.invocation().tool_version()
            != row.try_get::<String, _>("tool_version").map_err(map_sqlx)?
        || !tool_invocation_projection_matches(&row, &value)?
    {
        return Err(StoreError::Corrupt);
    }
    let effect = load_effect_in(tx, value.invocation().request_id())
        .await?
        .ok_or(StoreError::Corrupt)?;
    let phase_matches = matches!(
        (value.phase(), effect.phase),
        (
            ToolInvocationPhase::Reserved,
            EffectJournalPhase::Reserved | EffectJournalPhase::RetryAuthorized,
        ) | (ToolInvocationPhase::Started, EffectJournalPhase::Started)
            | (
                ToolInvocationPhase::Uncertain,
                EffectJournalPhase::Uncertain
            )
            | (
                ToolInvocationPhase::Completed | ToolInvocationPhase::Failed,
                EffectJournalPhase::Completed,
            )
            | (ToolInvocationPhase::Failed, EffectJournalPhase::Failed)
    );
    if !phase_matches || effect.revision != value.revision() {
        return Err(StoreError::Corrupt);
    }
    let participant = load_participant_in(tx, value.invocation().participant_id())
        .await?
        .ok_or(StoreError::Corrupt)?;
    let operation = load_operation_in(tx, value.invocation().operation_id())
        .await?
        .ok_or(StoreError::Corrupt)?;
    if participant.session_id != value.invocation().session_id()
        || operation.session_id != value.invocation().session_id()
        || operation.participant_id != value.invocation().participant_id()
        || effect.session_id != value.invocation().session_id()
        || effect.participant_id != value.invocation().participant_id()
        || effect.operation_id != value.invocation().operation_id()
        || effect.action != *value.definition().required_authority()
        || effect.effect_class != value.definition().effect_class()
    {
        return Err(StoreError::Corrupt);
    }
    let registration = load_tool_registration_in(
        tx,
        value.invocation().session_id(),
        value.invocation().tool_name(),
        value.invocation().tool_version(),
    )
    .await?
    .ok_or(StoreError::Corrupt)?;
    if value.registration_id() != registration.registration_id
        || registration.registration_id.to_string()
            != row
                .try_get::<String, _>("registration_id")
                .map_err(map_sqlx)?
        || registration.definition != *value.definition()
    {
        return Err(StoreError::Corrupt);
    }
    Ok(Some(value))
}

#[allow(clippy::too_many_lines)]
async fn transition_tool(
    store: &SqliteStore,
    command: TransitionToolInvocation,
) -> Result<ToolInvocationSnapshot, StoreError> {
    let mut tx = begin_immediate(&store.pool).await?;
    if let Some(row)=sqlx::query("SELECT invocation_id,caller_host_id,semantic_digest,result FROM tool_invocation_mutations WHERE request_id=?")
        .bind(command.context.request_id().to_string()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?{
        let digest:Vec<u8>=row.try_get("semantic_digest").map_err(map_sqlx)?;
        if row.try_get::<String,_>("invocation_id").map_err(map_sqlx)?!=command.invocation_id.to_string()
            || row.try_get::<String,_>("caller_host_id").map_err(map_sqlx)?!=command.context.caller().to_string()
            || digest.as_slice()!=command.digest().as_bytes(){return Err(StoreError::RequestConflict{request_id:command.context.request_id()});}
        let bytes:Vec<u8>=row.try_get("result").map_err(map_sqlx)?;
        let snapshot: ToolInvocationSnapshot = serde_json::from_slice(&bytes).map_err(|_|StoreError::Corrupt)?;
        let current = load_tool_invocation_in(&mut tx, command.invocation_id)
            .await?.ok_or(StoreError::Corrupt)?;
        validate_tool_transition_replay(&command, &snapshot, &current)?;
        tx.commit().await.map_err(map_sqlx)?;return Ok(snapshot)
    }
    reject_global_request_collision(&mut tx, command.context.request_id()).await?;
    reject_effect_request_collision(&mut tx, command.context.request_id()).await?;
    reject_recovery_request_collision(&mut tx, command.context.request_id()).await?;
    let current = load_tool_invocation_in(&mut tx, command.invocation_id)
        .await?
        .ok_or(StoreError::Invalid)?;
    let row =
        require_open_session(&mut tx, current.invocation().session_id(), command.action()).await?;
    let now = advance_time_floor(
        &mut tx,
        current.invocation().session_id(),
        row.time_floor,
        store.now(),
    )
    .await?;
    require_owner(&row, command.context.caller(), command.owner_epoch, now)?;
    if current.revision() != command.expected_revision {
        return Err(StoreError::Invalid);
    }
    let effect = load_effect_in(&mut tx, current.invocation().request_id())
        .await?
        .ok_or(StoreError::Corrupt)?;
    if effect.owner_epoch != command.owner_epoch {
        return Err(StoreError::Invalid);
    }
    let connection=sqlx::query("SELECT connection_id,generation,next_server_sequence FROM tool_provider_connections WHERE session_id=? AND provider_id=?")
        .bind(current.invocation().session_id().to_string()).bind(command.provider_id.to_string())
        .fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StoreError::Invalid)?;
    if command.provider_id != current.dispatch().provider_id
        || current.dispatch().connection_id != Some(command.connection_id)
        || command.dispatch_id != current.dispatch().dispatch_id
        || command.server_sequence != current.dispatch().server_sequence
        || command.connection_generation == 0
        || connection
            .try_get::<String, _>("connection_id")
            .map_err(map_sqlx)?
            != command.connection_id.to_string()
        || u64::try_from(
            connection
                .try_get::<i64, _>("generation")
                .map_err(map_sqlx)?,
        )
        .map_err(|_| StoreError::Corrupt)?
            != command.connection_generation
    {
        return Err(StoreError::Invalid);
    }
    if matches!(command.transition, ToolTransition::Start) {
        if current.dispatch().cancellation_id.is_some() {
            return Err(StoreError::Invalid);
        }
        let participant = load_participant_in(&mut tx, current.invocation().participant_id())
            .await?
            .ok_or(StoreError::Invalid)?;
        let operation = load_operation_in(&mut tx, current.invocation().operation_id())
            .await?
            .ok_or(StoreError::Invalid)?;
        if participant.session_id != current.invocation().session_id()
            || operation.session_id != current.invocation().session_id()
            || operation.participant_id != participant.participant_id
            || operation.state != OperationState::Running
        {
            return Err(StoreError::Invalid);
        }
        let requested = ScopedCapability::new(
            current.definition().required_authority().clone(),
            ResourceScope::Operation(current.invocation().operation_id()),
        );
        let mut grant = match current.invocation().authority_grant_id() {
            Some(id) => load_grant_in(&mut tx, id).await?,
            None => None,
        };
        let allowed = load_authority_policy_in(&mut tx, current.invocation().participant_id())
            .await?
            .as_ref()
            .and_then(|policy| {
                policy_ceilings(policy)
                    .authorize_effect(
                        current.invocation().participant_id(),
                        current.invocation().session_id(),
                        &requested,
                        grant.as_ref().map(|value| &value.grant),
                        now,
                    )
                    .ok()
            })
            .is_some()
            && grant
                .as_ref()
                .is_none_or(|value| value.consumed_at.is_none());
        if !allowed {
            return Err(StoreError::Invalid);
        }
        if let Some(value) = grant.as_mut().filter(|value| value.single_use) {
            value.consumed_at = Some(now);
            update_grant_in(&mut tx, value).await?;
        }
    }
    if matches!(command.transition, ToolTransition::RequestCancel { .. })
        && current.definition().cancellation() == navigator_domain::ToolCancellation::Unsupported
    {
        return Err(StoreError::Invalid);
    }
    let requested_terminal = match &command.transition {
        ToolTransition::Complete(v) => Some(ToolTerminal::Completed(v.clone())),
        ToolTransition::Fail(v) => Some(ToolTerminal::Failed(v.clone())),
        _ => None,
    };
    if matches!(
        current.phase(),
        ToolInvocationPhase::Completed | ToolInvocationPhase::Failed
    ) {
        if requested_terminal.as_ref() != current.terminal() {
            return Err(StoreError::RequestConflict {
                request_id: command.context.request_id(),
            });
        }
        record_tool_mutation(&mut tx, &command, &current).await?;
        tx.commit().await.map_err(map_sqlx)?;
        return Ok(current);
    }
    let (phase, terminal, effect_phase, effect_terminal, event) = match &command.transition {
        ToolTransition::Start if current.phase() == ToolInvocationPhase::Reserved => (
            ToolInvocationPhase::Started,
            None,
            EffectJournalPhase::Started,
            None,
            "tool.invocation_started",
        ),
        ToolTransition::Complete(result) if current.phase() == ToolInvocationPhase::Started => {
            current
                .definition()
                .validate_output(result.output())
                .map_err(|_| StoreError::Invalid)?;
            let bytes = serde_json::to_vec(result).map_err(|_| StoreError::Corrupt)?;
            let bounded = BoundedBytes::new(bytes).map_err(|_| StoreError::Invalid)?;
            (
                ToolInvocationPhase::Completed,
                Some(ToolTerminal::Completed(result.clone())),
                EffectJournalPhase::Completed,
                Some(EffectTerminal::Completed(bounded)),
                "tool.invocation_completed",
            )
        }
        ToolTransition::Fail(failure)
            if current.phase() == ToolInvocationPhase::Started
                || (current.phase() == ToolInvocationPhase::Reserved
                    && matches!(
                        failure.kind,
                        navigator_domain::ToolFailureKind::TimedOut
                            | navigator_domain::ToolFailureKind::Cancelled
                            | navigator_domain::ToolFailureKind::ProviderUnavailable
                    )) =>
        {
            let id = BoundedText::new(format!("{:?}", failure.kind).to_ascii_lowercase())
                .map_err(|_| StoreError::Invalid)?;
            (
                ToolInvocationPhase::Failed,
                Some(ToolTerminal::Failed(failure.clone())),
                EffectJournalPhase::Failed,
                Some(EffectTerminal::Failed(id)),
                "tool.invocation_failed",
            )
        }
        ToolTransition::MarkUncertain
            if current.phase() == ToolInvocationPhase::Started
                && matches!(
                    effect.effect_class,
                    EffectClass::Transactional | EffectClass::NonIdempotent | EffectClass::Unknown
                ) =>
        {
            (
                ToolInvocationPhase::Uncertain,
                None,
                EffectJournalPhase::Uncertain,
                None,
                "tool.invocation_uncertain",
            )
        }
        ToolTransition::RequestCancel { .. }
            if matches!(
                current.phase(),
                ToolInvocationPhase::Reserved | ToolInvocationPhase::Started
            ) =>
        {
            (
                current.phase(),
                current.terminal().cloned(),
                effect.phase,
                effect.terminal.clone(),
                "tool.invocation_cancel_requested",
            )
        }
        _ => return Err(StoreError::Invalid),
    };
    let revision = current.revision().next().ok_or(StoreError::Corrupt)?;
    let mut dispatch = current.dispatch().clone();
    dispatch.connection_generation = Some(command.connection_generation);
    match &command.transition {
        ToolTransition::Complete(result) => {
            dispatch.terminal_digest = Some(SemanticDigest::v1(
                &Capability::new("tool.result").expect("static capability"),
                &serde_json::to_vec(result).map_err(|_| StoreError::Corrupt)?,
            ));
        }
        ToolTransition::Fail(failure) => {
            dispatch.terminal_digest = Some(SemanticDigest::v1(
                &Capability::new("tool.failure").expect("static capability"),
                &serde_json::to_vec(failure).map_err(|_| StoreError::Corrupt)?,
            ));
        }
        ToolTransition::RequestCancel { cancellation_id } => {
            if dispatch.cancellation_id.is_some() {
                return Err(StoreError::RequestConflict {
                    request_id: command.context.request_id(),
                });
            }
            let next = u64::try_from(
                connection
                    .try_get::<i64, _>("next_server_sequence")
                    .map_err(map_sqlx)?,
            )
            .map_err(|_| StoreError::Corrupt)?;
            let following = next.checked_add(1).ok_or(StoreError::Corrupt)?;
            let changed = sqlx::query("UPDATE tool_provider_connections SET next_server_sequence=? WHERE session_id=? AND provider_id=? AND connection_id=? AND generation=? AND next_server_sequence=?")
                .bind(to_i64(following)?)
                .bind(current.invocation().session_id().to_string())
                .bind(command.provider_id.to_string())
                .bind(command.connection_id.to_string())
                .bind(to_i64(command.connection_generation)?)
                .bind(to_i64(next)?)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx)?;
            if changed.rows_affected() != 1 {
                return Err(StoreError::Invalid);
            }
            dispatch.cancellation_id = Some(*cancellation_id);
            dispatch.cancellation_server_sequence = Some(next);
        }
        _ => {}
    }
    let updated = ToolInvocationSnapshot::new(
        current.registration_id(),
        current.definition().clone(),
        current.invocation().clone(),
        phase,
        terminal,
        revision,
        dispatch.clone(),
    )
    .map_err(|_| StoreError::Corrupt)?;
    let mut updated_effect = effect;
    updated_effect.phase = effect_phase;
    updated_effect.terminal = effect_terminal;
    updated_effect.revision = revision;
    update_effect(&mut tx, &updated_effect).await?;
    let changed = sqlx::query("UPDATE tool_invocations SET snapshot=?,connection_generation=?,cancellation_id=?,cancellation_server_sequence=?,terminal_digest=? WHERE invocation_id=?")
        .bind(serde_json::to_vec(&updated).map_err(|_| StoreError::Corrupt)?)
        .bind(dispatch.connection_generation.map(to_i64).transpose()?)
        .bind(dispatch.cancellation_id.map(|v|v.to_string()))
        .bind(dispatch.cancellation_server_sequence.map(to_i64).transpose()?)
        .bind(dispatch.terminal_digest.map(|v|v.as_bytes().to_vec()))
        .bind(command.invocation_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    if changed.rows_affected() != 1 {
        return Err(StoreError::Corrupt);
    }
    let event_data = tool_invocation_event_payload(&updated)?;
    append_event_data(
        &mut tx,
        command.context.request_id(),
        current.invocation().session_id(),
        revision,
        event,
        &event_data,
        now,
    )
    .await?;
    record_tool_mutation(&mut tx, &command, &updated).await?;
    crash_at("tool.transition.after_write");
    crash_at("tool.transition.before_commit");
    tx.commit().await.map_err(map_sqlx)?;
    crash_at("tool.transition.after_commit");
    Ok(updated)
}

fn validate_tool_transition_replay(
    command: &TransitionToolInvocation,
    recorded: &ToolInvocationSnapshot,
    current: &ToolInvocationSnapshot,
) -> Result<(), StoreError> {
    let same_identity = recorded.invocation().invocation_id() == command.invocation_id
        && recorded.invocation() == current.invocation()
        && recorded.definition() == current.definition()
        && recorded.registration_id() == current.registration_id()
        && recorded.dispatch().dispatch_id == command.dispatch_id
        && recorded.dispatch().dispatch_id == current.dispatch().dispatch_id
        && recorded.dispatch().provider_id == command.provider_id
        && recorded.dispatch().provider_id == current.dispatch().provider_id
        && recorded.dispatch().server_sequence == command.server_sequence
        && recorded.dispatch().server_sequence == current.dispatch().server_sequence
        && recorded.dispatch().deadline == current.dispatch().deadline;
    let next_revision = command
        .expected_revision
        .next()
        .ok_or(StoreError::Corrupt)?;
    let valid_result = match &command.transition {
        ToolTransition::Start => {
            recorded.phase() == ToolInvocationPhase::Started
                && recorded.terminal().is_none()
                && recorded.revision() == next_revision
        }
        ToolTransition::Complete(result) => {
            recorded.phase() == ToolInvocationPhase::Completed
                && recorded.terminal() == Some(&ToolTerminal::Completed(result.clone()))
                && matches!(recorded.revision(), value if value == command.expected_revision || value == next_revision)
        }
        ToolTransition::Fail(failure) => {
            recorded.phase() == ToolInvocationPhase::Failed
                && recorded.terminal() == Some(&ToolTerminal::Failed(failure.clone()))
                && matches!(recorded.revision(), value if value == command.expected_revision || value == next_revision)
        }
        ToolTransition::MarkUncertain => {
            recorded.phase() == ToolInvocationPhase::Uncertain
                && recorded.terminal().is_none()
                && recorded.revision() == next_revision
        }
        ToolTransition::RequestCancel { cancellation_id } => {
            recorded.dispatch().cancellation_id == Some(*cancellation_id)
                && recorded.revision() == next_revision
                && recorded.terminal().is_none()
        }
    };
    let terminal_is_authoritative = recorded.terminal().is_none()
        || (recorded.terminal() == current.terminal() && recorded.phase() == current.phase());
    if !same_identity || !valid_result || !terminal_is_authoritative {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

async fn record_tool_mutation(
    tx: &mut Transaction<'_, Sqlite>,
    command: &TransitionToolInvocation,
    value: &ToolInvocationSnapshot,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO tool_invocation_mutations(request_id,invocation_id,caller_host_id,semantic_digest,result) VALUES(?,?,?,?,?)")
        .bind(command.context.request_id().to_string()).bind(command.invocation_id.to_string()).bind(command.context.caller().to_string())
        .bind(command.digest().as_bytes().as_slice()).bind(serde_json::to_vec(value).map_err(|_|StoreError::Corrupt)?)
        .execute(&mut **tx).await.map_err(map_sqlx)?;
    Ok(())
}

struct SystemClock;

impl Clock for SystemClock {
    fn wall_now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::now_utc()
    }

    fn monotonic_now(&self) -> MonotonicInstant {
        MonotonicInstant::from_ticks(0)
    }
}

#[derive(Debug)]
struct SessionRow {
    snapshot: SessionSnapshot,
    owner: Option<OwnershipLease>,
    epoch_high_water: u64,
    time_floor: Timestamp,
}

#[derive(Serialize, Deserialize)]
struct LeaseWire {
    session_id: Uuid,
    owner: Uuid,
    epoch: u64,
    issued_seconds: i64,
    issued_nanos: u32,
    expires_seconds: i64,
    expires_nanos: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
enum FailureWire {
    SessionNotFound {
        session_id: SessionId,
    },
    TemplateNotFound {
        template_id: TemplateId,
    },
    ParticipantNotFound {
        participant_id: ParticipantId,
    },
    RootParticipantNotFound {
        session_id: SessionId,
    },
    OperationNotFound {
        operation_id: OperationId,
    },
    SessionClosed {
        session_id: SessionId,
    },
    AlreadyClosed {
        session_id: SessionId,
    },
    CompatibilityConflict {
        session_id: SessionId,
        persisted: CompatibilityIdentity,
        requested: CompatibilityIdentity,
    },
    InterruptedSession {
        session_id: SessionId,
    },
    ConsumerConflict {
        session_id: SessionId,
        persisted: ConsumerKey,
        requested: ConsumerKey,
    },
    RequestConflict {
        request_id: RequestId,
    },
    OwnershipHeld {
        ownership: OwnershipSnapshot,
    },
    OwnershipExpired {
        session_id: SessionId,
        epoch: FencingEpoch,
    },
    StaleOwnership {
        session_id: SessionId,
        attempted: FencingEpoch,
        current: Option<FencingEpoch>,
    },
    LeaseTooLong,
    SchemaTooNew {
        found: u32,
        supported: u32,
    },
    Corrupt,
    Busy,
    Invalid,
    MessageNotFound {
        message_id: MessageId,
    },
    ArtifactNotFound {
        artifact_id: ArtifactId,
    },
    LaunchNotFound {
        attempt_id: LaunchAttemptId,
    },
    MessageOversize,
    MailboxQuotaExceeded,
    CapacityExceeded {
        reason: CapacityReason,
    },
    ProjectionStale,
    Unavailable,
}

impl From<&StoreError> for FailureWire {
    fn from(error: &StoreError) -> Self {
        match error {
            StoreError::SessionNotFound { session_id } => Self::SessionNotFound {
                session_id: *session_id,
            },
            StoreError::TemplateNotFound { template_id } => Self::TemplateNotFound {
                template_id: *template_id,
            },
            StoreError::ParticipantNotFound { participant_id } => Self::ParticipantNotFound {
                participant_id: *participant_id,
            },
            StoreError::RootParticipantNotFound { session_id } => Self::RootParticipantNotFound {
                session_id: *session_id,
            },
            StoreError::MessageNotFound { message_id } => Self::MessageNotFound {
                message_id: *message_id,
            },
            StoreError::ArtifactNotFound { artifact_id } => Self::ArtifactNotFound {
                artifact_id: *artifact_id,
            },
            StoreError::LaunchNotFound { attempt_id } => Self::LaunchNotFound {
                attempt_id: *attempt_id,
            },
            StoreError::MessageOversize => Self::MessageOversize,
            StoreError::MailboxQuotaExceeded => Self::MailboxQuotaExceeded,
            StoreError::CapacityExceeded { reason } => Self::CapacityExceeded { reason: *reason },
            StoreError::OperationNotFound { operation_id } => Self::OperationNotFound {
                operation_id: *operation_id,
            },
            StoreError::SessionClosed { session_id } => Self::SessionClosed {
                session_id: *session_id,
            },
            StoreError::AlreadyClosed { session_id } => Self::AlreadyClosed {
                session_id: *session_id,
            },
            StoreError::CompatibilityConflict {
                session_id,
                persisted,
                requested,
            } => Self::CompatibilityConflict {
                session_id: *session_id,
                persisted: *persisted,
                requested: *requested,
            },
            StoreError::InterruptedSession { session_id } => Self::InterruptedSession {
                session_id: *session_id,
            },
            StoreError::ConsumerConflict {
                session_id,
                persisted,
                requested,
            } => Self::ConsumerConflict {
                session_id: *session_id,
                persisted: persisted.clone(),
                requested: requested.clone(),
            },
            StoreError::RequestConflict { request_id } => Self::RequestConflict {
                request_id: *request_id,
            },
            StoreError::OwnershipHeld { ownership } => Self::OwnershipHeld {
                ownership: ownership.clone(),
            },
            StoreError::OwnershipExpired { session_id, epoch } => Self::OwnershipExpired {
                session_id: *session_id,
                epoch: *epoch,
            },
            StoreError::StaleOwnership {
                session_id,
                attempted,
                current,
            } => Self::StaleOwnership {
                session_id: *session_id,
                attempted: *attempted,
                current: *current,
            },
            StoreError::LeaseTooLong => Self::LeaseTooLong,
            StoreError::SchemaTooNew { found, supported } => Self::SchemaTooNew {
                found: *found,
                supported: *supported,
            },
            StoreError::Corrupt => Self::Corrupt,
            StoreError::Busy => Self::Busy,
            StoreError::Invalid => Self::Invalid,
            StoreError::ProjectionStale => Self::ProjectionStale,
            StoreError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<FailureWire> for StoreError {
    fn from(error: FailureWire) -> Self {
        match error {
            FailureWire::SessionNotFound { session_id } => Self::SessionNotFound { session_id },
            FailureWire::TemplateNotFound { template_id } => Self::TemplateNotFound { template_id },
            FailureWire::ParticipantNotFound { participant_id } => {
                Self::ParticipantNotFound { participant_id }
            }
            FailureWire::RootParticipantNotFound { session_id } => {
                Self::RootParticipantNotFound { session_id }
            }
            FailureWire::OperationNotFound { operation_id } => {
                Self::OperationNotFound { operation_id }
            }
            FailureWire::MessageNotFound { message_id } => Self::MessageNotFound { message_id },
            FailureWire::ArtifactNotFound { artifact_id } => Self::ArtifactNotFound { artifact_id },
            FailureWire::LaunchNotFound { attempt_id } => Self::LaunchNotFound { attempt_id },
            FailureWire::MessageOversize => Self::MessageOversize,
            FailureWire::MailboxQuotaExceeded => Self::MailboxQuotaExceeded,
            FailureWire::CapacityExceeded { reason } => Self::CapacityExceeded { reason },
            FailureWire::SessionClosed { session_id } => Self::SessionClosed { session_id },
            FailureWire::AlreadyClosed { session_id } => Self::AlreadyClosed { session_id },
            FailureWire::CompatibilityConflict {
                session_id,
                persisted,
                requested,
            } => Self::CompatibilityConflict {
                session_id,
                persisted,
                requested,
            },
            FailureWire::InterruptedSession { session_id } => {
                Self::InterruptedSession { session_id }
            }
            FailureWire::ConsumerConflict {
                session_id,
                persisted,
                requested,
            } => Self::ConsumerConflict {
                session_id,
                persisted,
                requested,
            },
            FailureWire::RequestConflict { request_id } => Self::RequestConflict { request_id },
            FailureWire::OwnershipHeld { ownership } => Self::OwnershipHeld { ownership },
            FailureWire::OwnershipExpired { session_id, epoch } => {
                Self::OwnershipExpired { session_id, epoch }
            }
            FailureWire::StaleOwnership {
                session_id,
                attempted,
                current,
            } => Self::StaleOwnership {
                session_id,
                attempted,
                current,
            },
            FailureWire::LeaseTooLong => Self::LeaseTooLong,
            FailureWire::SchemaTooNew { found, supported } => {
                Self::SchemaTooNew { found, supported }
            }
            FailureWire::Corrupt => Self::Corrupt,
            FailureWire::Busy => Self::Busy,
            FailureWire::Invalid => Self::Invalid,
            FailureWire::ProjectionStale => Self::ProjectionStale,
            FailureWire::Unavailable => Self::Unavailable,
        }
    }
}

impl LeaseWire {
    fn from_lease(lease: &OwnershipLease, issued_at: Timestamp) -> Self {
        Self {
            session_id: lease.session_id().as_uuid(),
            owner: lease.owner().as_uuid(),
            epoch: lease.epoch().get(),
            issued_seconds: issued_at.unix_seconds(),
            issued_nanos: issued_at.nanoseconds(),
            expires_seconds: lease.expires_at().unix_seconds(),
            expires_nanos: lease.expires_at().nanoseconds(),
        }
    }

    fn into_lease(self) -> Result<OwnershipLease, StoreError> {
        OwnershipLease::new(
            SessionId::from_uuid(self.session_id).map_err(|_| StoreError::Corrupt)?,
            HostId::from_uuid(self.owner).map_err(|_| StoreError::Corrupt)?,
            FencingEpoch::new(self.epoch).map_err(|_| StoreError::Corrupt)?,
            Timestamp::new(self.issued_seconds, self.issued_nanos)
                .map_err(|_| StoreError::Corrupt)?,
            Timestamp::new(self.expires_seconds, self.expires_nanos)
                .map_err(|_| StoreError::Corrupt)?,
        )
        .map_err(|_| StoreError::Corrupt)
    }
}

impl SessionStore for SqliteStore {
    async fn open_session(
        &self,
        command: OpenSession,
    ) -> Result<Mutation<SessionSnapshot>, StoreError> {
        let observed_at = self.now();
        let now = observed_at;
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(snapshot) = replay_json::<SessionSnapshot>(&mut transaction, &command).await? {
            validate_open_replay(&snapshot, &command)?;
            validate_session_manifest_in(&mut transaction, &command).await?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(snapshot));
        }

        if let Some(row) = load_session_in(&mut transaction, command.session_id()).await? {
            if row.snapshot.compatibility() != command.compatibility() {
                let error = StoreError::CompatibilityConflict {
                    session_id: command.session_id(),
                    persisted: row.snapshot.compatibility(),
                    requested: command.compatibility(),
                };
                return Err(
                    finish_failure(transaction, command.session_id(), &command, error).await?,
                );
            }
            if row.snapshot.consumer_key() != command.consumer_key() {
                let error = StoreError::ConsumerConflict {
                    session_id: command.session_id(),
                    persisted: row.snapshot.consumer_key().clone(),
                    requested: command.consumer_key().clone(),
                };
                return Err(
                    finish_failure(transaction, command.session_id(), &command, error).await?,
                );
            }
            if let Err(error) = validate_session_manifest_in(&mut transaction, &command).await {
                return Err(
                    finish_failure(transaction, command.session_id(), &command, error).await?,
                );
            }
            record_json_with_effect(
                &mut transaction,
                command.session_id(),
                &command,
                StoredEffect::Unchanged,
                &row.snapshot,
            )
            .await?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Unchanged(row.snapshot));
        }

        if !new_session_manifest_is_registered(&mut transaction, &command).await? {
            return Err(finish_failure(
                transaction,
                command.session_id(),
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let snapshot = SessionSnapshot::new(
            command.session_id(),
            command.consumer_key().clone(),
            command.compatibility(),
            SessionStatus::Open,
            Revision::initial(),
            observed_at,
            now,
        )
        .map_err(|_| StoreError::Invalid)?;
        insert_session_row(&mut transaction, &command, now).await?;
        insert_session_manifest(&mut transaction, &command).await?;
        crash_at("open.after_session_insert");
        let event_data = session_event_payload(&snapshot)?;
        append_event_data(
            &mut transaction,
            command.context().request_id(),
            command.session_id(),
            Revision::initial(),
            "session.created",
            &event_data,
            now,
        )
        .await?;
        crash_at("open.after_event_insert");
        record_json(&mut transaction, command.session_id(), &command, &snapshot).await?;
        crash_at("open.after_ledger_insert");
        crash_at("open.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("open.after_commit");
        Ok(Mutation::Applied(snapshot))
    }

    async fn close_session(
        &self,
        command: CloseSession,
    ) -> Result<Mutation<SessionSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(snapshot) = replay_json::<SessionSnapshot>(&mut transaction, &command).await? {
            if snapshot.id() != command.session_id() || snapshot.status() != SessionStatus::Closed {
                return Err(StoreError::Corrupt);
            }
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(snapshot));
        }
        let mut row =
            match require_open_session(&mut transaction, command.session_id(), command.action())
                .await
            {
                Ok(row) => row,
                Err(error) => {
                    return Err(
                        finish_failure(transaction, command.session_id(), &command, error).await?,
                    );
                }
            };
        let now = advance_time_floor(
            &mut transaction,
            command.session_id(),
            row.time_floor,
            observed_at,
        )
        .await?;
        if let Err(error) = require_owner(&row, command.context().caller(), command.epoch(), now) {
            return Err(finish_failure(transaction, command.session_id(), &command, error).await?);
        }
        row.snapshot.close(now).map_err(|_| StoreError::Invalid)?;
        let result = sqlx::query(
            "UPDATE sessions SET closed = 1, revision = ?, updated_at_seconds = ?,
             updated_at_nanos = ?, owner_host_id = NULL, owner_expires_at_seconds = NULL,
             owner_expires_at_nanos = NULL WHERE session_id = ? AND owner_host_id = ?
             AND owner_epoch = ? AND closed = 0",
        )
        .bind(to_i64(row.snapshot.revision().get())?)
        .bind(now.unix_seconds())
        .bind(i64::from(now.nanoseconds()))
        .bind(command.session_id().to_string())
        .bind(command.context().caller().to_string())
        .bind(to_i64(command.epoch().get())?)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Corrupt);
        }
        crash_at("close.after_session_update");
        let event_data = session_event_payload(&row.snapshot)?;
        append_event_data(
            &mut transaction,
            command.context().request_id(),
            command.session_id(),
            row.snapshot.revision(),
            "session.closed",
            &event_data,
            now,
        )
        .await?;
        crash_at("close.after_event_insert");
        record_json(
            &mut transaction,
            command.session_id(),
            &command,
            &row.snapshot,
        )
        .await?;
        crash_at("close.after_ledger_insert");
        crash_at("close.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("close.after_commit");
        Ok(Mutation::Applied(row.snapshot))
    }

    #[allow(clippy::too_many_lines)]
    async fn acquire_ownership(
        &self,
        command: AcquireOwnership,
    ) -> Result<Mutation<OwnershipLease>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(bytes) = replay_bytes(&mut transaction, &command).await? {
            let lease = decode_lease(&bytes)?;
            validate_lease_replay(
                &lease,
                &bytes,
                command.session_id(),
                command.context().caller(),
                None,
                command.duration(),
            )?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(lease));
        }
        let row =
            match require_open_session(&mut transaction, command.session_id(), command.action())
                .await
            {
                Ok(row) => row,
                Err(error) => {
                    return Err(
                        finish_failure(transaction, command.session_id(), &command, error).await?,
                    );
                }
            };
        let now = advance_time_floor(
            &mut transaction,
            command.session_id(),
            row.time_floor,
            observed_at,
        )
        .await?;
        crash_at("acquire.after_time_floor");
        let expires_at = match self.expiry(now, command.duration()) {
            Ok(value) => value,
            Err(error) => {
                return Err(
                    finish_failure(transaction, command.session_id(), &command, error).await?,
                );
            }
        };
        if expires_at <= now {
            return Err(finish_failure(
                transaction,
                command.session_id(),
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        if let Some(owner) = row.owner
            && owner.is_effective_at(now)
        {
            let error = StoreError::OwnershipHeld {
                ownership: ownership_snapshot(&owner),
            };
            return Err(finish_failure(transaction, command.session_id(), &command, error).await?);
        }
        let epoch = row
            .epoch_high_water
            .checked_add(1)
            .and_then(|value| FencingEpoch::new(value).ok())
            .ok_or(StoreError::Corrupt)?;
        let revision = row.snapshot.revision().next().ok_or(StoreError::Corrupt)?;
        let lease = OwnershipLease::new(
            command.session_id(),
            command.context().caller(),
            epoch,
            now,
            expires_at,
        )
        .map_err(|_| StoreError::Invalid)?;
        let result = sqlx::query(
            "UPDATE sessions SET owner_host_id = ?, owner_epoch = ?,
             owner_expires_at_seconds = ?, owner_expires_at_nanos = ?, epoch_high_water = ?,
             revision = ?, updated_at_seconds = ?, updated_at_nanos = ? WHERE session_id = ?",
        )
        .bind(lease.owner().to_string())
        .bind(to_i64(epoch.get())?)
        .bind(expires_at.unix_seconds())
        .bind(i64::from(expires_at.nanoseconds()))
        .bind(to_i64(epoch.get())?)
        .bind(to_i64(revision.get())?)
        .bind(now.unix_seconds())
        .bind(i64::from(now.nanoseconds()))
        .bind(command.session_id().to_string())
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Corrupt);
        }
        crash_at("acquire.after_session_update");
        append_event(
            &mut transaction,
            command.context().request_id(),
            command.session_id(),
            revision,
            "ownership.acquired",
            now,
        )
        .await?;
        crash_at("acquire.after_event_insert");
        record_bytes(
            &mut transaction,
            command.session_id(),
            &command,
            StoredEffect::Applied,
            &encode_lease(&lease, now)?,
        )
        .await?;
        crash_at("acquire.after_ledger_insert");
        crash_at("acquire.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("acquire.after_commit");
        Ok(Mutation::Applied(lease))
    }

    async fn renew_ownership(
        &self,
        command: RenewOwnership,
    ) -> Result<Mutation<OwnershipLease>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(bytes) = replay_bytes(&mut transaction, &command).await? {
            let lease = decode_lease(&bytes)?;
            validate_lease_replay(
                &lease,
                &bytes,
                command.session_id(),
                command.context().caller(),
                Some(command.epoch()),
                command.duration(),
            )?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(lease));
        }
        let row =
            match require_open_session(&mut transaction, command.session_id(), command.action())
                .await
            {
                Ok(row) => row,
                Err(error) => {
                    return Err(
                        finish_failure(transaction, command.session_id(), &command, error).await?,
                    );
                }
            };
        let now = advance_time_floor(
            &mut transaction,
            command.session_id(),
            row.time_floor,
            observed_at,
        )
        .await?;
        crash_at("renew.after_time_floor");
        if let Err(error) = require_owner(&row, command.context().caller(), command.epoch(), now) {
            return Err(finish_failure(transaction, command.session_id(), &command, error).await?);
        }
        let expires_at = match self.expiry(now, command.duration()) {
            Ok(value) => value,
            Err(error) => {
                return Err(
                    finish_failure(transaction, command.session_id(), &command, error).await?,
                );
            }
        };
        if expires_at <= now {
            return Err(finish_failure(
                transaction,
                command.session_id(),
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let lease = OwnershipLease::new(
            command.session_id(),
            command.context().caller(),
            command.epoch(),
            now,
            expires_at,
        )
        .map_err(|_| StoreError::Invalid)?;
        let result = sqlx::query(
            "UPDATE sessions SET owner_expires_at_seconds = ?, owner_expires_at_nanos = ?
             WHERE session_id = ? AND owner_host_id = ? AND owner_epoch = ?",
        )
        .bind(expires_at.unix_seconds())
        .bind(i64::from(expires_at.nanoseconds()))
        .bind(command.session_id().to_string())
        .bind(command.context().caller().to_string())
        .bind(to_i64(command.epoch().get())?)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Corrupt);
        }
        crash_at("renew.after_session_update");
        record_bytes(
            &mut transaction,
            command.session_id(),
            &command,
            StoredEffect::Applied,
            &encode_lease(&lease, now)?,
        )
        .await?;
        crash_at("renew.after_ledger_insert");
        crash_at("renew.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("renew.after_commit");
        Ok(Mutation::Applied(lease))
    }

    async fn release_ownership(
        &self,
        command: ReleaseOwnership,
    ) -> Result<Mutation<OwnershipSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(bytes) = replay_bytes(&mut transaction, &command).await? {
            if bytes != b"unowned" {
                return Err(StoreError::Corrupt);
            }
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(OwnershipSnapshot::Unowned));
        }
        let row =
            match require_open_session(&mut transaction, command.session_id(), command.action())
                .await
            {
                Ok(row) => row,
                Err(error) => {
                    return Err(
                        finish_failure(transaction, command.session_id(), &command, error).await?,
                    );
                }
            };
        let now = advance_time_floor(
            &mut transaction,
            command.session_id(),
            row.time_floor,
            observed_at,
        )
        .await?;
        crash_at("release.after_time_floor");
        if let Err(error) = require_owner(&row, command.context().caller(), command.epoch(), now) {
            return Err(finish_failure(transaction, command.session_id(), &command, error).await?);
        }
        let revision = row.snapshot.revision().next().ok_or(StoreError::Corrupt)?;
        let result = sqlx::query(
            "UPDATE sessions SET owner_host_id = NULL, owner_expires_at_seconds = NULL,
             owner_expires_at_nanos = NULL, revision = ?, updated_at_seconds = ?,
             updated_at_nanos = ? WHERE session_id = ? AND owner_host_id = ? AND owner_epoch = ?",
        )
        .bind(to_i64(revision.get())?)
        .bind(now.unix_seconds())
        .bind(i64::from(now.nanoseconds()))
        .bind(command.session_id().to_string())
        .bind(command.context().caller().to_string())
        .bind(to_i64(command.epoch().get())?)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Corrupt);
        }
        crash_at("release.after_session_update");
        append_event(
            &mut transaction,
            command.context().request_id(),
            command.session_id(),
            revision,
            "ownership.released",
            now,
        )
        .await?;
        crash_at("release.after_event_insert");
        record_bytes(
            &mut transaction,
            command.session_id(),
            &command,
            StoredEffect::Applied,
            b"unowned",
        )
        .await?;
        crash_at("release.after_ledger_insert");
        crash_at("release.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("release.after_commit");
        Ok(Mutation::Applied(OwnershipSnapshot::Unowned))
    }

    async fn load_session(&self, session_id: SessionId) -> Result<SessionSnapshot, StoreError> {
        load_session_from_pool(&self.pool, session_id)
            .await?
            .map(|row| row.snapshot)
            .ok_or(StoreError::SessionNotFound { session_id })
    }

    async fn read_ownership(&self, session_id: SessionId) -> Result<OwnershipSnapshot, StoreError> {
        let row = load_session_from_pool(&self.pool, session_id)
            .await?
            .ok_or(StoreError::SessionNotFound { session_id })?;
        let observed_at = row.time_floor.max(self.now());
        Ok(row
            .owner
            .as_ref()
            .map_or(OwnershipSnapshot::Unowned, |lease| {
                if lease.is_effective_at(observed_at) {
                    ownership_snapshot(lease)
                } else {
                    OwnershipSnapshot::Unowned
                }
            }))
    }

    async fn read_request(
        &self,
        request_id: RequestId,
    ) -> Result<Option<StoredRequest>, StoreError> {
        let row = sqlx::query(
            "SELECT caller_host_id, action, semantic_digest, outcome, effect, result
             FROM request_ledger WHERE request_id = ?",
        )
        .bind(request_id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        row.map(|row| decode_stored_request(&row, request_id))
            .transpose()
    }

    async fn read_events(&self, query: ReadEvents) -> Result<EventPage, StoreError> {
        let row = load_session_from_pool(&self.pool, query.session_id)
            .await?
            .ok_or(StoreError::SessionNotFound {
                session_id: query.session_id,
            })?;
        if row.snapshot.consumer_key() != &query.consumer {
            return Err(StoreError::Invalid);
        }
        let after = query.after.map_or(0, EventPosition::get);
        let rows = sqlx::query(
            "SELECT event_id, position, revision, event_type, schema_version,
             related_request_id, data,
             occurred_at_seconds, occurred_at_nanos FROM events
             WHERE session_id = ? AND position > ? ORDER BY position LIMIT ?",
        )
        .bind(query.session_id.to_string())
        .bind(to_i64(after)?)
        .bind(i64::from(query.limit.get()) + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        let has_more = rows.len() > query.limit.get() as usize;
        let mut events = Vec::with_capacity(rows.len().min(query.limit.get() as usize));
        for row in rows.into_iter().take(query.limit.get() as usize) {
            events.push(decode_event(&row, query.session_id)?);
        }
        Ok(EventPage {
            last_position: events.last().map(SessionEvent::position),
            events,
            has_more,
        })
    }
}

impl InstanceStore for SqliteStore {
    async fn validate_launch_authority(
        &self,
        session_id: SessionId,
        host_id: HostId,
        epoch: FencingEpoch,
    ) -> Result<(), StoreError> {
        // Watchdogs call this frequently and concurrently. Authority
        // validation must not contend for SQLite's single writer merely to
        // observe the already durable lease. Mutations persist the time floor;
        // readers combine that floor with their current observation exactly as
        // `read_ownership` does, so wall-clock regression cannot move behind
        // durable time.
        let row = load_session_from_pool(&self.pool, session_id)
            .await?
            .ok_or(StoreError::SessionNotFound { session_id })?;
        if row.snapshot.status() == SessionStatus::Closed {
            return Err(StoreError::SessionClosed { session_id });
        }
        let observed_at = row.time_floor.max(self.now());
        let effective = {
            let mut floors = self
                .authority_time_floors
                .lock()
                .map_err(|_| StoreError::Unavailable)?;
            let floor = floors.entry(session_id).or_insert(observed_at);
            *floor = (*floor).max(observed_at);
            *floor
        };
        match require_owner(&row, host_id, epoch, effective) {
            Ok(()) => Ok(()),
            Err(StoreError::OwnershipExpired { .. }) => {
                // Expiry is a one-way fencing observation. Seal that rare
                // transition durably so neither wall-clock regression nor a
                // process restart can resurrect the same lease. Healthy
                // watchdog polls remain read-only.
                let mut transaction = begin_immediate(&self.pool).await?;
                let current =
                    require_open_session(&mut transaction, session_id, StoreAction::PrepareLaunch)
                        .await?;
                let sealed =
                    advance_time_floor(&mut transaction, session_id, current.time_floor, effective)
                        .await?;
                let result = require_owner(&current, host_id, epoch, sealed);
                transaction.commit().await.map_err(map_sqlx)?;
                result
            }
            Err(error) => Err(error),
        }
    }

    async fn prepare_launch(
        &self,
        command: PrepareLaunch,
    ) -> Result<Mutation<LaunchSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(snapshot) = replay_json::<LaunchSnapshot>(&mut transaction, &command).await? {
            if participant_cancellation_requested(&mut transaction, command.participant_id).await? {
                return Err(StoreError::Invalid);
            }
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(snapshot));
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        if participant_cancellation_requested(&mut transaction, command.participant_id).await? {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        if let Some(existing) = load_launch_in(&mut transaction, command.attempt_id).await? {
            if existing.session_id != command.session_id
                || existing.participant_id != command.participant_id
                || existing.driver_id != command.driver_id
                || existing.driver_configuration_digest != command.driver_configuration_digest
                || existing.credential_digest != command.credential_digest
            {
                return Err(finish_failure(
                    transaction,
                    command.session_id,
                    &command,
                    StoreError::Invalid,
                )
                .await?);
            }
            record_json_with_effect(
                &mut transaction,
                command.session_id,
                &command,
                StoredEffect::Unchanged,
                &existing,
            )
            .await?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Unchanged(existing));
        }
        let snapshot = LaunchSnapshot {
            session_id: command.session_id,
            ownership_epoch: Some(command.epoch),
            participant_id: command.participant_id,
            driver_id: command.driver_id,
            driver_configuration_digest: command.driver_configuration_digest,
            attempt_id: command.attempt_id,
            instance_id: None,
            state: LaunchState::Prepared,
            revision: Revision::initial(),
            credential_digest: command.credential_digest,
            evidence: None,
            cleanup_reason: None,
        };
        insert_launch(&mut transaction, &snapshot).await?;
        crash_at("launch.prepare.after_insert");
        record_json(&mut transaction, command.session_id, &command, &snapshot).await?;
        crash_at("launch.prepare.after_ledger");
        crash_at("launch.prepare.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("launch.prepare.after_commit");
        Ok(Mutation::Applied(snapshot))
    }

    async fn attach_launch(
        &self,
        command: AttachLaunch,
    ) -> Result<Mutation<LaunchSnapshot>, StoreError> {
        mutate_launch(
            self,
            command.session_id,
            command.context,
            command.epoch,
            command.attempt_id,
            command.expected_revision,
            &command,
            |snapshot| {
                if snapshot.state != LaunchState::Prepared
                    || snapshot.instance_id.is_some()
                    || command.evidence.process_id == 0
                    || command.evidence.process_group_id == 0
                    || command.evidence.parent_process_id == 0
                    || command.evidence.creation_marker == 0
                    || command.evidence.executable_identity == [0; 32]
                {
                    return Err(StoreError::Invalid);
                }
                snapshot.instance_id = Some(command.instance_id);
                snapshot.evidence = Some(command.evidence.clone());
                snapshot.state = LaunchState::Attached;
                Ok(())
            },
        )
        .await
    }

    async fn transition_launch(
        &self,
        command: TransitionLaunch,
    ) -> Result<Mutation<LaunchSnapshot>, StoreError> {
        mutate_launch(
            self,
            command.session_id,
            command.context,
            command.epoch,
            command.attempt_id,
            command.expected_revision,
            &command,
            |snapshot| {
                if !valid_launch_transition(snapshot.state, command.target)
                    || (command.target == LaunchState::CleanupRequired)
                        != command.cleanup_reason.is_some()
                {
                    return Err(StoreError::Invalid);
                }
                snapshot.state = command.target;
                snapshot.cleanup_reason.clone_from(&command.cleanup_reason);
                Ok(())
            },
        )
        .await
    }

    async fn load_launch(&self, attempt_id: LaunchAttemptId) -> Result<LaunchSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let snapshot = load_launch_in(&mut transaction, attempt_id)
            .await?
            .ok_or(StoreError::LaunchNotFound { attempt_id })?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(snapshot)
    }

    async fn session_has_launches(&self, session_id: SessionId) -> Result<bool, StoreError> {
        let value: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM launch_attempts WHERE session_id = ? LIMIT 1)",
        )
        .bind(session_id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StoreError::Corrupt),
        }
    }

    async fn session_has_unresolved_launches(
        &self,
        session_id: SessionId,
    ) -> Result<bool, StoreError> {
        let value: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM launch_attempts WHERE session_id = ? AND state != 'stopped' LIMIT 1)",
        )
        .bind(session_id.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(StoreError::Corrupt),
        }
    }
}

impl OperationStore for SqliteStore {
    async fn find_open_session(
        &self,
        consumer_key: ConsumerKey,
    ) -> Result<Option<SessionSnapshot>, StoreError> {
        let id: Option<String> = sqlx::query_scalar(
            "SELECT session_id FROM sessions WHERE public_consumer_key = ? AND closed = 0 LIMIT 1",
        )
        .bind(consumer_key.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        match id {
            Some(id) => self.load_session(parse_session_id(&id)?).await.map(Some),
            None => Ok(None),
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn register_templates_and_open_session(
        &self,
        command: RegisterTemplatesAndOpenSession,
    ) -> Result<Mutation<SessionSnapshot>, StoreError> {
        let requested_open = command.open();
        let now = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(snapshot) = replay_json::<SessionSnapshot>(&mut transaction, &command).await? {
            // A mode request may resolve to an identity other than its fresh
            // candidate, so its replay is authenticated by the request ledger.
            if requested_open.mode() == navigator_store_api::SessionOpenMode::Exact {
                validate_open_replay(&snapshot, requested_open)?;
            }
            validate_registered_templates(&mut transaction, command.templates()).await?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(snapshot));
        }
        let mut open = requested_open.clone();
        if requested_open.mode() != navigator_store_api::SessionOpenMode::Exact {
            let existing_id: Option<String> = sqlx::query_scalar(
                "SELECT session_id FROM sessions WHERE public_consumer_key = ? AND closed = 0 LIMIT 1",
            )
            .bind(requested_open.consumer_key().as_str())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
            if let Some(existing_id) = existing_id {
                let existing_id = parse_session_id(&existing_id)?;
                let row = load_session_in(&mut transaction, existing_id)
                    .await?
                    .ok_or(StoreError::Corrupt)?;
                if requested_open.mode() == navigator_store_api::SessionOpenMode::Reset {
                    let error = StoreError::InterruptedSession {
                        session_id: existing_id,
                    };
                    return Err(finish_failure(transaction, existing_id, &command, error).await?);
                }
                if requested_open.mode() != navigator_store_api::SessionOpenMode::Reset
                    && row.snapshot.compatibility() != requested_open.compatibility()
                {
                    let error = StoreError::CompatibilityConflict {
                        session_id: existing_id,
                        persisted: row.snapshot.compatibility(),
                        requested: requested_open.compatibility(),
                    };
                    return Err(finish_failure(transaction, existing_id, &command, error).await?);
                }
                let unfinished: i64 = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM operations WHERE session_id = ? AND state NOT IN ('succeeded','failed','cancelled') LIMIT 1)",
                )
                .bind(existing_id.to_string())
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
                match requested_open.mode() {
                    navigator_store_api::SessionOpenMode::Open if unfinished != 0 => {
                        let error = StoreError::InterruptedSession {
                            session_id: existing_id,
                        };
                        return Err(
                            finish_failure(transaction, existing_id, &command, error).await?
                        );
                    }
                    navigator_store_api::SessionOpenMode::Resume
                    | navigator_store_api::SessionOpenMode::Open => {}
                    navigator_store_api::SessionOpenMode::Reset
                    | navigator_store_api::SessionOpenMode::Exact => unreachable!(),
                }
                open = requested_open.clone().with_session_id(existing_id);
            } else if requested_open.mode() == navigator_store_api::SessionOpenMode::Reset {
                let unresolved: i64 = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM launch_attempts l JOIN sessions s ON s.session_id = l.session_id WHERE s.public_consumer_key = ? AND l.state != 'stopped' LIMIT 1)",
                )
                .bind(requested_open.consumer_key().as_str())
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
                if unresolved != 0 {
                    transaction.rollback().await.map_err(map_sqlx)?;
                    return Err(StoreError::Invalid);
                }
            }
        }
        validate_template_set_before_open(&mut transaction, command.templates()).await?;
        let existing = load_session_in(&mut transaction, open.session_id()).await?;
        if let Some(row) = &existing {
            if row.snapshot.consumer_key() != open.consumer_key()
                || row.snapshot.compatibility() != open.compatibility()
                || validate_session_manifest_in(&mut transaction, &open)
                    .await
                    .is_err()
            {
                transaction.rollback().await.map_err(map_sqlx)?;
                return Err(StoreError::Invalid);
            }
        }
        insert_missing_templates(&mut transaction, command.templates()).await?;
        crash_at("open_with_templates.after_templates");
        let was_existing = existing.is_some();
        let snapshot = if let Some(row) = existing {
            row.snapshot
        } else {
            let snapshot = SessionSnapshot::new(
                open.session_id(),
                open.consumer_key().clone(),
                open.compatibility(),
                SessionStatus::Open,
                Revision::initial(),
                now,
                now,
            )
            .map_err(|_| StoreError::Invalid)?;
            insert_session_row(&mut transaction, &open, now).await?;
            insert_session_manifest(&mut transaction, &open).await?;
            append_event(
                &mut transaction,
                open.context().request_id(),
                open.session_id(),
                Revision::initial(),
                "session.created",
                now,
            )
            .await?;
            snapshot
        };
        record_json_with_effect(
            &mut transaction,
            open.session_id(),
            &command,
            if was_existing {
                StoredEffect::Unchanged
            } else {
                StoredEffect::Applied
            },
            &snapshot,
        )
        .await?;
        crash_at("open_with_templates.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("open_with_templates.after_commit");
        Ok(if was_existing {
            Mutation::Unchanged(snapshot)
        } else {
            Mutation::Applied(snapshot)
        })
    }

    async fn register_template(
        &self,
        template: TemplateRecord,
    ) -> Result<Mutation<TemplateRecord>, StoreError> {
        let mut transaction = begin_immediate(&self.pool).await?;
        navigator_domain::Template::try_from(template.clone()).map_err(|_| StoreError::Invalid)?;
        if let Some(existing) = load_template_in(&mut transaction, template.identity).await? {
            transaction.commit().await.map_err(map_sqlx)?;
            return if existing == template {
                Ok(Mutation::Unchanged(existing))
            } else {
                Err(StoreError::Invalid)
            };
        }
        sqlx::query(
            "INSERT INTO templates (template_id, compatibility_identity, registration)
             VALUES (?, ?, ?)",
        )
        .bind(template.identity.to_string())
        .bind(template.compatibility.as_bytes().as_slice())
        .bind(serde_json::to_vec(&template).map_err(|_| StoreError::Invalid)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(Mutation::Applied(template))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "single atomic root creation transaction"
    )]
    async fn create_root_participant(
        &self,
        command: CreateRootParticipant,
    ) -> Result<Mutation<ParticipantSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(snapshot) =
            replay_json::<ParticipantSnapshot>(&mut transaction, &command).await?
        {
            let current = load_participant_in(&mut transaction, snapshot.participant_id)
                .await?
                .ok_or(StoreError::Corrupt)?;
            if current != snapshot {
                return Err(StoreError::Corrupt);
            }
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(current));
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        let Some(template) = load_template_in(&mut transaction, command.template_id).await? else {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        };
        if template.compatibility != command.expected_compatibility {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        if !session_allows_template(&mut transaction, command.session_id, &template).await? {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        if let Some(existing) =
            load_participant_in(&mut transaction, command.participant_id).await?
        {
            if existing.session_id != command.session_id
                || existing.template_id != command.template_id
            {
                return Err(finish_failure(
                    transaction,
                    command.session_id,
                    &command,
                    StoreError::Invalid,
                )
                .await?);
            }
            record_json_with_effect(
                &mut transaction,
                command.session_id,
                &command,
                StoredEffect::Unchanged,
                &existing,
            )
            .await?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Unchanged(existing));
        }
        let root_exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM participants WHERE session_id = ? AND parent_participant_id IS NULL LIMIT 1")
            .bind(command.session_id.to_string()).fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        if root_exists.is_some() {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        ensure_derived_capacity(
            &mut transaction,
            &self.limit_profile,
            command.session_id,
            CapacityResource::Participants,
            1,
        )
        .await?;
        let snapshot = ParticipantSnapshot {
            session_id: command.session_id,
            participant_id: command.participant_id,
            parent_participant_id: None,
            depth: 1,
            template_id: command.template_id,
            template_compatibility: template.compatibility,
            revision: Revision::initial(),
        };
        commit_root_participant(transaction, &command, snapshot, observed_at).await
    }

    #[expect(clippy::too_many_lines, reason = "single atomic topology transaction")]
    async fn create_child_participant(
        &self,
        command: CreateChildParticipant,
    ) -> Result<Mutation<ParticipantSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(snapshot) =
            replay_json::<ParticipantSnapshot>(&mut transaction, &command).await?
        {
            let current = load_participant_in(&mut transaction, snapshot.participant_id)
                .await?
                .ok_or(StoreError::Corrupt)?;
            if current != snapshot {
                return Err(StoreError::Corrupt);
            }
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(current));
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        let Some(parent) =
            load_participant_in(&mut transaction, command.parent_participant_id).await?
        else {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        };
        if participant_cancellation_requested(&mut transaction, command.parent_participant_id)
            .await?
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let Some(template) = load_template_in(&mut transaction, command.template_id).await? else {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        };
        if parent.session_id != command.session_id
            || template.compatibility != command.expected_compatibility
            || command.participant_id == command.parent_participant_id
            || parent.depth >= MAX_PARTICIPANT_DEPTH
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        if !session_allows_template(&mut transaction, command.session_id, &template).await? {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        if load_participant_in(&mut transaction, command.participant_id)
            .await?
            .is_some()
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let direct: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM participants WHERE session_id = ? AND parent_participant_id = ?",
        )
        .bind(command.session_id.to_string())
        .bind(command.parent_participant_id.to_string())
        .fetch_one(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM participants WHERE session_id = ?")
                .bind(command.session_id.to_string())
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        if direct >= i64::from(MAX_DIRECT_CHILDREN) || total >= i64::from(MAX_SESSION_PARTICIPANTS)
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        ensure_derived_capacity(
            &mut transaction,
            &self.limit_profile,
            command.session_id,
            CapacityResource::Participants,
            1,
        )
        .await?;
        let snapshot = ParticipantSnapshot {
            session_id: command.session_id,
            participant_id: command.participant_id,
            parent_participant_id: Some(command.parent_participant_id),
            depth: parent.depth.checked_add(1).ok_or(StoreError::Corrupt)?,
            template_id: command.template_id,
            template_compatibility: template.compatibility,
            revision: Revision::initial(),
        };
        sqlx::query("INSERT INTO participants (participant_id, session_id, parent_participant_id, template_id, template_compatibility, revision, depth) VALUES (?, ?, ?, ?, ?, 1, ?)")
            .bind(snapshot.participant_id.to_string()).bind(snapshot.session_id.to_string())
            .bind(command.parent_participant_id.to_string()).bind(snapshot.template_id.to_string())
            .bind(snapshot.template_compatibility.as_bytes().as_slice()).bind(i64::from(snapshot.depth))
            .execute(&mut *transaction).await.map_err(map_sqlx)?;
        crash_at("participant.child.after_insert");
        let data = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1, "session_id": snapshot.session_id,
            "participant_id": snapshot.participant_id,
            "parent_participant_id": command.parent_participant_id,
            "template_id": snapshot.template_id, "depth": snapshot.depth,
            "revision": snapshot.revision.get(), "lifecycle":"registered",
        }))
        .map_err(|_| StoreError::Corrupt)?;
        append_event_data(
            &mut transaction,
            command.context.request_id(),
            command.session_id,
            snapshot.revision,
            "participant.created",
            &data,
            observed_at,
        )
        .await?;
        crash_at("participant.child.after_event");
        record_json(&mut transaction, command.session_id, &command, &snapshot).await?;
        crash_at("participant.child.after_ledger");
        crash_at("participant.child.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("participant.child.after_commit");
        Ok(Mutation::Applied(snapshot))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "single atomic operation admission transaction"
    )]
    async fn start_operation(
        &self,
        command: StartOperation,
    ) -> Result<Mutation<OperationSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(recorded) = replay_json::<OperationSnapshot>(&mut transaction, &command).await?
        {
            let snapshot = load_operation_in(&mut transaction, recorded.operation_id)
                .await?
                .ok_or(StoreError::Corrupt)?;
            if snapshot.session_id != recorded.session_id
                || snapshot.participant_id != recorded.participant_id
                || snapshot.start_request_id != recorded.start_request_id
                || snapshot.input_message_id != recorded.input_message_id
            {
                return Err(StoreError::Corrupt);
            }
            let message = load_message_in(&mut transaction, snapshot.input_message_id)
                .await?
                .ok_or(StoreError::Corrupt)?;
            if message.session_id != snapshot.session_id
                || message.source != snapshot.participant_id
                || message.destination != snapshot.participant_id
                || message.correlation.operation_id != Some(snapshot.operation_id)
                || message.correlation.in_reply_to.is_some()
                || message.envelope
                    != navigator_domain::ValidatedMessageEnvelope::operation_input(
                        snapshot.operation_id,
                        snapshot.input_digest,
                    )
            {
                return Err(StoreError::Corrupt);
            }
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(snapshot));
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        let observed_at = load_session_in(&mut transaction, command.session_id)
            .await?
            .ok_or(StoreError::Corrupt)?
            .time_floor;
        let participant = load_participant_in(&mut transaction, command.participant_id).await?;
        let Some(participant) = participant.filter(|value| value.session_id == command.session_id)
        else {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        };
        if participant_cancellation_requested(&mut transaction, command.participant_id).await? {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let template = load_template_in(&mut transaction, participant.template_id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        if participant.template_compatibility != template.compatibility {
            return Err(StoreError::Corrupt);
        }
        let registered =
            navigator_domain::Template::try_from(template).map_err(|_| StoreError::Corrupt)?;
        if registered.validate_input(command.input.as_bytes()).is_err() {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let unfinished: Option<i64> = sqlx::query_scalar("SELECT 1 FROM operations WHERE participant_id = ? AND terminal_outcome IS NULL LIMIT 1")
            .bind(command.participant_id.to_string()).fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        if unfinished.is_some()
            || load_operation_in(&mut transaction, command.operation_id)
                .await?
                .is_some()
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        ensure_derived_capacity(
            &mut transaction,
            &self.limit_profile,
            command.session_id,
            CapacityResource::QueuedOperations,
            1,
        )
        .await?;
        let input_digest = *SemanticDigest::v1(
            &Capability::new("operation.input.v1").expect("static capability"),
            command.input.as_bytes(),
        )
        .as_bytes();
        let message_collision: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM messages WHERE message_id = ? LIMIT 1")
                .bind(command.input_message_id.to_string())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        if message_collision.is_some() {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let queued: Option<(i64, i64)> = sqlx::query_as(
            "SELECT queued_bytes, queued_messages FROM mailbox_counters WHERE destination_participant_id = ?",
        )
        .bind(command.participant_id.to_string())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        let (queued_bytes, queued_messages) = queued.unwrap_or((0, 0));
        let envelope_bytes = navigator_domain::ValidatedMessageEnvelope::operation_input(
            command.operation_id,
            input_digest,
        )
        .as_bytes()
        .len();
        ensure_derived_capacity(
            &mut transaction,
            &self.limit_profile,
            command.session_id,
            CapacityResource::Messages,
            1,
        )
        .await?;
        ensure_derived_capacity(
            &mut transaction,
            &self.limit_profile,
            command.session_id,
            CapacityResource::MessageBytes,
            u64::try_from(envelope_bytes).map_err(|_| StoreError::Invalid)?,
        )
        .await?;
        if u64::try_from(queued_bytes)
            .map_err(|_| StoreError::Corrupt)?
            .saturating_add(u64::try_from(envelope_bytes).map_err(|_| StoreError::Corrupt)?)
            > MAX_MAILBOX_QUEUED_BYTES
            || u64::try_from(queued_messages)
                .map_err(|_| StoreError::Corrupt)?
                .saturating_add(1)
                > MAX_MAILBOX_QUEUED_MESSAGES
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::MailboxQuotaExceeded,
            )
            .await?);
        }
        let snapshot = OperationSnapshot {
            session_id: command.session_id,
            operation_id: command.operation_id,
            participant_id: command.participant_id,
            start_request_id: command.context.request_id(),
            input_message_id: command.input_message_id,
            waiting_on_message_id: None,
            input_digest,
            state: OperationState::Queued,
            revision: Revision::initial(),
            terminal_outcome: None,
            created_at: observed_at,
            updated_at: observed_at,
        };
        commit_operation_start(transaction, &command, snapshot, observed_at).await
    }

    #[expect(
        clippy::too_many_lines,
        reason = "operation transition and upward outcome share one transaction"
    )]
    async fn transition_operation(
        &self,
        command: TransitionOperation,
    ) -> Result<Mutation<OperationSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(snapshot) = replay_json::<OperationSnapshot>(&mut transaction, &command).await?
        {
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(snapshot));
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        let Some(mut snapshot) = load_operation_in(&mut transaction, command.operation_id).await?
        else {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        };
        if snapshot.session_id != command.session_id
            || snapshot.revision != command.expected_revision
            || !valid_report_correlation(&mut transaction, &snapshot, &command).await?
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let Some(next) = next_operation_state(snapshot.state, command.action) else {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        };
        if !valid_terminal_outcome(next, command.terminal_outcome.as_ref()) {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        if snapshot.state == OperationState::Queued
            && !next.is_terminal()
            && next != OperationState::Queued
        {
            ensure_derived_capacity(
                &mut transaction,
                &self.limit_profile,
                command.session_id,
                CapacityResource::ActiveOperations,
                1,
            )
            .await?;
        }
        ensure_derived_capacity(
            &mut transaction,
            &self.limit_profile,
            command.session_id,
            CapacityResource::RetainedEvents,
            1,
        )
        .await?;
        snapshot.state = next;
        if command.action == OperationAction::Wait {
            snapshot.waiting_on_message_id = command.report_message_id;
        } else if snapshot.state != OperationState::Waiting {
            snapshot.waiting_on_message_id = None;
        }
        snapshot.revision = snapshot.revision.next().ok_or(StoreError::Corrupt)?;
        snapshot.updated_at = observed_at.max(snapshot.updated_at);
        snapshot
            .terminal_outcome
            .clone_from(&command.terminal_outcome);
        let terminal_name = snapshot
            .terminal_outcome
            .as_ref()
            .map(terminal_outcome_name);
        let terminal_payload = snapshot
            .terminal_outcome
            .as_ref()
            .map(|value| serde_json::to_vec(value).map_err(|_| StoreError::Corrupt))
            .transpose()?;
        let result = sqlx::query("UPDATE operations SET state = ?, waiting_on_message_id = ?, terminal_outcome = ?, terminal_payload = ?, revision = ?, updated_at_seconds = ?, updated_at_nanos = ? WHERE operation_id = ? AND revision = ?")
            .bind(operation_state_name(next)).bind(snapshot.waiting_on_message_id.map(|id| id.to_string())).bind(terminal_name).bind(terminal_payload).bind(to_i64(snapshot.revision.get())?).bind(snapshot.updated_at.unix_seconds()).bind(i64::from(snapshot.updated_at.nanoseconds()))
            .bind(snapshot.operation_id.to_string()).bind(to_i64(command.expected_revision.get())?).execute(&mut *transaction).await.map_err(map_sqlx)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Corrupt);
        }
        if let Some(outcome) = snapshot.terminal_outcome.as_ref() {
            retire_correlated_messages(
                &mut transaction,
                command.context.request_id(),
                &snapshot,
                observed_at,
            )
            .await?;
            let participant = load_participant_in(&mut transaction, snapshot.participant_id)
                .await?
                .ok_or(StoreError::Corrupt)?;
            if let Some(parent_id) = participant.parent_participant_id {
                let message_id = derived_store_message_id(
                    command.context.request_id(),
                    b"navigator.operation.outcome.v1",
                )?;
                let policy =
                    load_authority_policy_in(&mut transaction, snapshot.participant_id).await?;
                let parent_operation: Option<String> = sqlx::query_scalar(
                    "SELECT operation_id FROM operations WHERE session_id = ? AND participant_id = ? AND terminal_outcome IS NULL LIMIT 2",
                )
                .bind(command.session_id.to_string())
                .bind(parent_id.to_string())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
                let parent_operation = parent_operation
                    .as_deref()
                    .map(parse_operation_id)
                    .transpose()?;
                let now = load_session_in(&mut transaction, command.session_id)
                    .await?
                    .ok_or(StoreError::Corrupt)?
                    .time_floor;
                let requested = ScopedCapability::new(
                    Capability::new("message.outcome").expect("static capability"),
                    navigator_domain::ResourceScope::Operation(snapshot.operation_id),
                );
                let authorized = parent_operation.is_some()
                    && policy.as_ref().is_some_and(|policy| {
                        policy_ceilings(policy)
                            .authorize_effect(
                                snapshot.participant_id,
                                command.session_id,
                                &requested,
                                None,
                                now,
                            )
                            .is_ok()
                    });
                let delivered = if authorized {
                    insert_hierarchy_message(
                        &mut transaction,
                        command.session_id,
                        command.context.request_id(),
                        message_id,
                        snapshot.participant_id,
                        parent_id,
                        MessageCorrelation {
                            operation_id: parent_operation,
                            in_reply_to: None,
                        },
                        navigator_domain::ValidatedMessageEnvelope::operation_outcome(
                            snapshot.operation_id,
                            public_terminal_outcome(outcome),
                            terminal_public_digest(outcome),
                        ),
                        snapshot.updated_at,
                    )
                    .await
                    .map_or_else(
                        |error| match error {
                            StoreError::Invalid
                            | StoreError::MailboxQuotaExceeded
                            | StoreError::MessageOversize => Ok(false),
                            other => Err(other),
                        },
                        |_| Ok(true),
                    )?
                } else {
                    false
                };
                append_authority_event(
                    &mut transaction,
                    command.session_id,
                    &command,
                    if delivered {
                        "authority.allowed"
                    } else {
                        "authority.denied"
                    },
                    snapshot.participant_id,
                    snapshot.updated_at,
                )
                .await?;
            }
        }
        crash_at("operation.transition.after_state");
        append_operation_event(&mut transaction, &command, &snapshot, observed_at).await?;
        crash_at("operation.transition.after_event");
        record_json(&mut transaction, command.session_id, &command, &snapshot).await?;
        crash_at("operation.transition.after_ledger");
        crash_at("operation.transition.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("operation.transition.after_commit");
        Ok(Mutation::Applied(snapshot))
    }

    async fn load_participant(
        &self,
        participant_id: ParticipantId,
    ) -> Result<ParticipantSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let value = load_participant_in(&mut transaction, participant_id)
            .await?
            .ok_or(StoreError::ParticipantNotFound { participant_id })?;
        let template = load_template_in(&mut transaction, value.template_id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        if value.template_compatibility != template.compatibility {
            return Err(StoreError::Corrupt);
        }
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(value)
    }

    async fn load_root_participant(
        &self,
        session_id: SessionId,
    ) -> Result<ParticipantSnapshot, StoreError> {
        let participant_id: String = sqlx::query_scalar("SELECT participant_id FROM participants WHERE session_id = ? AND parent_participant_id IS NULL")
            .bind(session_id.to_string()).fetch_optional(&self.pool).await.map_err(map_sqlx)?.ok_or(StoreError::RootParticipantNotFound { session_id })?;
        self.load_participant(parse_participant_id(&participant_id)?)
            .await
    }

    async fn load_direct_children(
        &self,
        parent_id: ParticipantId,
    ) -> Result<Vec<ParticipantSnapshot>, StoreError> {
        let rows: Vec<String> = sqlx::query_scalar("SELECT participant_id FROM participants WHERE parent_participant_id = ? ORDER BY participant_id")
            .bind(parent_id.to_string()).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        let mut children = Vec::with_capacity(rows.len());
        for value in rows {
            children.push(self.load_participant(parse_participant_id(&value)?).await?);
        }
        Ok(children)
    }

    async fn load_template(&self, template_id: TemplateId) -> Result<TemplateRecord, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let value = load_template_in(&mut transaction, template_id)
            .await?
            .ok_or(StoreError::TemplateNotFound { template_id })?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(value)
    }

    async fn load_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<OperationSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let value = load_operation_in(&mut transaction, operation_id)
            .await?
            .ok_or(StoreError::OperationNotFound { operation_id })?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(value)
    }

    async fn load_operation_input(
        &self,
        operation_id: OperationId,
    ) -> Result<BoundedBytes<MAX_OPERATION_INPUT_BYTES>, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let snapshot = load_operation_in(&mut transaction, operation_id)
            .await?
            .ok_or(StoreError::OperationNotFound { operation_id })?;
        let participant = load_participant_in(&mut transaction, snapshot.participant_id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        let registered = load_template_in(&mut transaction, participant.template_id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        if participant.template_compatibility != registered.compatibility {
            return Err(StoreError::Corrupt);
        }
        let template =
            navigator_domain::Template::try_from(registered).map_err(|_| StoreError::Corrupt)?;
        let bytes: Vec<u8> =
            sqlx::query_scalar("SELECT input_payload FROM operations WHERE operation_id = ?")
                .bind(operation_id.to_string())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_sqlx)?
                .ok_or(StoreError::OperationNotFound { operation_id })?;
        let canonical = template
            .validate_input(&bytes)
            .map_err(|_| StoreError::Corrupt)?;
        let digest = *SemanticDigest::v1(
            &Capability::new("operation.input.v1").expect("static capability"),
            canonical.as_bytes(),
        )
        .as_bytes();
        if canonical.as_bytes() != bytes || digest != snapshot.input_digest {
            return Err(StoreError::Corrupt);
        }
        transaction.commit().await.map_err(map_sqlx)?;
        BoundedBytes::new(bytes).map_err(|_| StoreError::Corrupt)
    }
}

async fn retire_correlated_messages(
    transaction: &mut Transaction<'_, Sqlite>,
    request_id: RequestId,
    operation: &OperationSnapshot,
    observed_at: Timestamp,
) -> Result<(), StoreError> {
    let rows = sqlx::query(
        "SELECT message_id, session_id, source_participant_id, destination_participant_id, mailbox_sequence, priority, snapshot FROM messages WHERE session_id = ? AND correlation_operation_id = ? AND destination_participant_id = ? AND delivery_state IN ('queued','retry_scheduled','leased','acceptance_pending','acceptance_unknown') ORDER BY mailbox_sequence",
    )
    .bind(operation.session_id.to_string())
    .bind(operation.operation_id.to_string())
    .bind(operation.participant_id.to_string())
    .fetch_all(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    for row in &rows {
        let mut message = decode_message_row(row)?;
        if message.destination != operation.participant_id {
            return Err(StoreError::Corrupt);
        }
        message.revision = message.revision.next().ok_or(StoreError::Corrupt)?;
        message.updated_at = observed_at.max(message.updated_at);
        let reason = BoundedText::new("correlated operation became terminal".to_owned())
            .map_err(|_| StoreError::Corrupt)?;
        message.state = match &message.state {
            MessageDeliveryState::AcceptancePending { lease }
            | MessageDeliveryState::AcceptanceUnknown { lease } => {
                MessageDeliveryState::Uncertain {
                    attempt_id: lease.attempt_id,
                    reason,
                }
            }
            MessageDeliveryState::Queued
            | MessageDeliveryState::RetryScheduled { .. }
            | MessageDeliveryState::Leased { .. } => MessageDeliveryState::DeadLetter { reason },
            MessageDeliveryState::Accepted { .. }
            | MessageDeliveryState::Uncertain { .. }
            | MessageDeliveryState::DeadLetter { .. } => return Err(StoreError::Corrupt),
        };
        update_message_snapshot(transaction, &message).await?;
        decrement_mailbox_bytes(transaction, &message).await?;
        append_message_event(transaction, request_id, &message, observed_at).await?;
    }
    Ok(())
}

impl AuthorityStore for SqliteStore {
    async fn register_authority_template_policy(
        &self,
        command: RegisterAuthorityTemplatePolicy,
    ) -> Result<Mutation<AuthorityTemplatePolicy>, StoreError> {
        let observed_at = self.now();
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(value) = replay_json::<AuthorityTemplatePolicy>(&mut tx, &command).await? {
            let current = load_authority_template_policy_in(&mut tx, value.template_id).await?;
            if current.as_ref() != Some(&value) {
                return Err(StoreError::Corrupt);
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(value));
        }
        if let Err(error) = authorize_launch(
            &mut tx,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(tx, command.session_id, &command, error).await?);
        }
        if command.policy.allowed_parent_templates.is_empty()
            || command.policy.allowed_parent_templates.len() > 256
            || load_template_in(&mut tx, command.policy.template_id)
                .await?
                .is_none()
        {
            return Err(
                finish_failure(tx, command.session_id, &command, StoreError::Invalid).await?,
            );
        }
        if let Some(existing) =
            load_authority_template_policy_in(&mut tx, command.policy.template_id).await?
        {
            if existing != command.policy {
                return Err(
                    finish_failure(tx, command.session_id, &command, StoreError::Invalid).await?,
                );
            }
            record_json_with_effect(
                &mut tx,
                command.session_id,
                &command,
                StoredEffect::Unchanged,
                &existing,
            )
            .await?;
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Unchanged(existing));
        }
        sqlx::query("INSERT INTO authority_template_policies(template_id,snapshot) VALUES(?,?)")
            .bind(command.policy.template_id.to_string())
            .bind(serde_json::to_vec(&command.policy).map_err(|_| StoreError::Corrupt)?)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        record_json(&mut tx, command.session_id, &command, &command.policy).await?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(Mutation::Applied(command.policy))
    }
    #[expect(
        clippy::too_many_lines,
        reason = "single atomic authority policy transaction"
    )]
    async fn put_authority_policy(
        &self,
        command: PutAuthorityPolicy,
    ) -> Result<Mutation<AuthorityPolicySnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(value) = replay_json(&mut transaction, &command).await? {
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(value));
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        if command.policy.session_id != command.session_id {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let participant =
            load_participant_in(&mut transaction, command.policy.participant_id).await?;
        if participant.is_none_or(|value| value.session_id != command.session_id) {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let ceilings = navigator_domain::AuthorityCeilings {
            session: &command.policy.session,
            parent: &command.policy.parent,
            template: &command.policy.template,
            relationship: &command.policy.relationship,
            subject: &command.policy.subject,
        };
        for requested in command.policy.subject.active() {
            if ceilings
                .authorize_effect(
                    command.policy.participant_id,
                    command.session_id,
                    requested,
                    None,
                    observed_at,
                )
                .is_err()
            {
                return Err(finish_failure(
                    transaction,
                    command.session_id,
                    &command,
                    StoreError::Invalid,
                )
                .await?);
            }
        }
        for requested in command.policy.subject.delegable() {
            if ceilings.authorize_child_creation(requested).is_err() {
                return Err(finish_failure(
                    transaction,
                    command.session_id,
                    &command,
                    StoreError::Invalid,
                )
                .await?);
            }
        }
        let existing: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT snapshot FROM authority_policies WHERE participant_id = ?")
                .bind(command.policy.participant_id.to_string())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        if let Some(bytes) = existing {
            let value: AuthorityPolicySnapshot =
                serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
            if value != command.policy {
                return Err(finish_failure(
                    transaction,
                    command.session_id,
                    &command,
                    StoreError::Invalid,
                )
                .await?);
            }
            record_json_with_effect(
                &mut transaction,
                command.session_id,
                &command,
                StoredEffect::Unchanged,
                &value,
            )
            .await?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Unchanged(value));
        }
        sqlx::query(
            "INSERT INTO authority_policies(participant_id, session_id, snapshot) VALUES (?, ?, ?)",
        )
        .bind(command.policy.participant_id.to_string())
        .bind(command.session_id.to_string())
        .bind(serde_json::to_vec(&command.policy).map_err(|_| StoreError::Corrupt)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        append_authority_event(
            &mut transaction,
            command.session_id,
            &command,
            "authority.policy_applied",
            command.policy.participant_id,
            observed_at,
        )
        .await?;
        record_json(
            &mut transaction,
            command.session_id,
            &command,
            &command.policy,
        )
        .await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(Mutation::Applied(command.policy))
    }

    async fn issue_grant(
        &self,
        command: IssueGrant,
    ) -> Result<Mutation<GrantSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(value) = replay_json(&mut transaction, &command).await? {
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(value));
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        if command.grant.session_id != command.session_id
            || command.grant.revoked
            || !command.grant.is_active(observed_at)
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let policy = load_authority_policy_in(&mut transaction, command.grant.subject)
            .await?
            .ok_or(StoreError::Invalid)?;
        let ceilings = policy_ceilings(&policy);
        if ceilings
            .authorize_effect(
                command.grant.subject,
                command.session_id,
                &command.grant.authority,
                None,
                observed_at,
            )
            .is_err()
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let snapshot = GrantSnapshot {
            grant: command.grant.clone(),
            single_use: command.single_use,
            consumed_at: None,
        };
        if load_grant_in(&mut transaction, snapshot.grant.id)
            .await?
            .is_some()
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        sqlx::query("INSERT INTO authority_grants(grant_id, session_id, subject_participant_id, snapshot) VALUES (?, ?, ?, ?)")
            .bind(snapshot.grant.id.to_string()).bind(command.session_id.to_string()).bind(snapshot.grant.subject.to_string())
            .bind(serde_json::to_vec(&snapshot).map_err(|_| StoreError::Corrupt)?).execute(&mut *transaction).await.map_err(map_sqlx)?;
        append_authority_event(
            &mut transaction,
            command.session_id,
            &command,
            "authority.grant_issued",
            snapshot.grant.subject,
            observed_at,
        )
        .await?;
        record_json(&mut transaction, command.session_id, &command, &snapshot).await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(Mutation::Applied(snapshot))
    }

    async fn revoke_grant(
        &self,
        command: RevokeGrant,
    ) -> Result<Mutation<GrantSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(value) = replay_json(&mut transaction, &command).await? {
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(value));
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        let mut snapshot = load_grant_in(&mut transaction, command.grant_id)
            .await?
            .ok_or(StoreError::Invalid)?;
        if snapshot.grant.session_id != command.session_id {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        snapshot.grant.revoked = true;
        update_grant_in(&mut transaction, &snapshot).await?;
        append_authority_event(
            &mut transaction,
            command.session_id,
            &command,
            "authority.grant_revoked",
            snapshot.grant.subject,
            observed_at,
        )
        .await?;
        record_json(&mut transaction, command.session_id, &command, &snapshot).await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(Mutation::Applied(snapshot))
    }

    async fn check_authority_effect(
        &self,
        command: CheckAuthorityEffect,
    ) -> Result<Mutation<AuthorityEffectOutcome>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(value) = replay_json(&mut transaction, &command).await? {
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(value));
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        let now = load_session_in(&mut transaction, command.session_id)
            .await?
            .ok_or(StoreError::Corrupt)?
            .time_floor;
        let policy = load_authority_policy_in(&mut transaction, command.participant_id).await?;
        let mut grant = match command.grant_id {
            Some(id) => load_grant_in(&mut transaction, id).await?,
            None => None,
        };
        let decision = policy.as_ref().and_then(|policy| {
            policy_ceilings(policy)
                .authorize_effect(
                    command.participant_id,
                    command.session_id,
                    &command.requested,
                    grant.as_ref().map(|value| &value.grant),
                    now,
                )
                .ok()
        });
        let usable_grant = grant
            .as_ref()
            .is_none_or(|value| value.consumed_at.is_none());
        let outcome = if let Some(decision) = decision.filter(|_| usable_grant) {
            if let Some(value) = grant.as_mut().filter(|value| value.single_use) {
                value.consumed_at = Some(now);
                update_grant_in(&mut transaction, value).await?;
            }
            AuthorityEffectOutcome::Allowed {
                decision: decision.into(),
            }
        } else {
            AuthorityEffectOutcome::Denied
        };
        let event = if matches!(outcome, AuthorityEffectOutcome::Allowed { .. }) {
            "authority.allowed"
        } else {
            "authority.denied"
        };
        append_authority_event(
            &mut transaction,
            command.session_id,
            &command,
            event,
            command.participant_id,
            now,
        )
        .await?;
        record_json(&mut transaction, command.session_id, &command, &outcome).await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(Mutation::Applied(outcome))
    }

    #[expect(
        clippy::too_many_lines,
        reason = "single atomic authorized spawn transaction"
    )]
    async fn create_authorized_child(
        &self,
        command: CreateAuthorizedChild,
    ) -> Result<Mutation<AuthorizedChildOutcome>, StoreError> {
        let observed_at = self.now();
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(value) = replay_json::<AuthorizedChildOutcome>(&mut tx, &command).await? {
            if let AuthorizedChildOutcome::Allowed {
                participant,
                policy,
                operation,
                ..
            } = &value
            {
                let message = load_message_in(&mut tx, operation.input_message_id).await?;
                let message_matches = message.is_some_and(|message| {
                    message.session_id == participant.session_id
                        && message.source == participant.participant_id
                        && message.destination == participant.participant_id
                        && message.correlation.operation_id == Some(operation.operation_id)
                        && message.envelope
                            == navigator_domain::ValidatedMessageEnvelope::operation_input(
                                operation.operation_id,
                                operation.input_digest,
                            )
                });
                let current_operation = load_operation_in(&mut tx, operation.operation_id).await?;
                let operation_matches = current_operation.is_some_and(|current| {
                    current.session_id == operation.session_id
                        && current.operation_id == operation.operation_id
                        && current.participant_id == operation.participant_id
                        && current.start_request_id == operation.start_request_id
                        && current.input_message_id == operation.input_message_id
                        && current.input_digest == operation.input_digest
                        && current.created_at == operation.created_at
                });
                if load_participant_in(&mut tx, participant.participant_id).await?
                    != Some(participant.clone())
                    || load_authority_policy_in(&mut tx, participant.participant_id).await?
                        != Some(*policy.clone())
                    || !operation_matches
                    || !message_matches
                {
                    return Err(StoreError::Corrupt);
                }
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(value));
        }
        if let Err(error) = authorize_launch(
            &mut tx,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(tx, command.session_id, &command, error).await?);
        }
        let now = load_session_in(&mut tx, command.session_id)
            .await?
            .ok_or(StoreError::Corrupt)?
            .time_floor;
        let parent = load_participant_in(&mut tx, command.parent_participant_id).await?;
        if participant_cancellation_requested(&mut tx, command.parent_participant_id).await? {
            return Err(
                finish_failure(tx, command.session_id, &command, StoreError::Invalid).await?,
            );
        }
        let template = load_template_in(&mut tx, command.template_id).await?;
        let template_policy =
            load_authority_template_policy_in(&mut tx, command.template_id).await?;
        let validated_input = template
            .clone()
            .and_then(|registered| navigator_domain::Template::try_from(registered).ok())
            .and_then(|trusted| trusted.validate_input(command.input.as_bytes()).ok())
            .filter(|value| value == &command.input);
        let parent_policy =
            load_authority_policy_in(&mut tx, command.parent_participant_id).await?;
        let mut grant = match command.grant_id {
            Some(id) => load_grant_in(&mut tx, id).await?,
            None => None,
        };
        let decision = parent_policy
            .as_ref()
            .and_then(|policy| {
                policy_ceilings(policy)
                    .authorize_effect(
                        command.parent_participant_id,
                        command.session_id,
                        &command.requested,
                        grant.as_ref().map(|value| &value.grant),
                        now,
                    )
                    .ok()
            })
            .filter(|_| {
                grant
                    .as_ref()
                    .is_none_or(|value| value.consumed_at.is_none())
            });
        let child_policy =
            template_policy
                .as_ref()
                .zip(parent_policy.as_ref())
                .map(|(trusted, parent)| AuthorityPolicySnapshot {
                    session_id: command.session_id,
                    participant_id: command.participant_id,
                    session: parent.session.clone(),
                    parent: parent.subject.clone(),
                    template: trusted.template.clone(),
                    relationship: trusted.relationship.clone(),
                    subject: trusted.subject.clone(),
                });
        let child_valid = child_policy.as_ref().is_some_and(|child_policy| {
            let child_ceilings = policy_ceilings(child_policy);
            child_policy.subject.active().all(|scope| {
                child_ceilings
                    .authorize_effect(command.participant_id, command.session_id, scope, None, now)
                    .is_ok()
            }) && child_policy
                .subject
                .delegable()
                .all(|scope| child_ceilings.authorize_child_creation(scope).is_ok())
        });
        let direct: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM participants WHERE session_id = ? AND parent_participant_id = ?",
        )
        .bind(command.session_id.to_string())
        .bind(command.parent_participant_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM participants WHERE session_id = ?")
                .bind(command.session_id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        let operation_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM operations WHERE operation_id = ?)")
                .bind(command.operation_id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        let message_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM messages WHERE message_id = ?)")
                .bind(command.input_message_id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(map_sqlx)?;
        let template_allowed = match &template {
            Some(template) => {
                session_allows_template(&mut tx, command.session_id, template).await?
            }
            None => false,
        };
        let valid = child_valid
            && command.participant_id != command.parent_participant_id
            && parent.as_ref().is_some_and(|value| {
                value.session_id == command.session_id && value.depth < MAX_PARTICIPANT_DEPTH
            })
            && parent
                .as_ref()
                .zip(template_policy.as_ref())
                .is_some_and(|(parent, trusted)| {
                    trusted
                        .allowed_parent_templates
                        .contains(&parent.template_id)
                })
            && template
                .as_ref()
                .is_some_and(|value| value.compatibility == command.expected_compatibility)
            && template_allowed
            && load_participant_in(&mut tx, command.participant_id)
                .await?
                .is_none()
            && validated_input.is_some()
            && !operation_exists
            && !message_exists
            && direct < i64::from(MAX_DIRECT_CHILDREN)
            && total < i64::from(MAX_SESSION_PARTICIPANTS);
        let Some(decision) = decision.filter(|_| valid) else {
            let outcome = AuthorizedChildOutcome::Denied;
            append_authority_event(
                &mut tx,
                command.session_id,
                &command,
                "authority.denied",
                command.parent_participant_id,
                now,
            )
            .await?;
            record_json(&mut tx, command.session_id, &command, &outcome).await?;
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Applied(outcome));
        };
        let parent = parent.ok_or(StoreError::Corrupt)?;
        let child_policy = child_policy.ok_or(StoreError::Corrupt)?;
        let participant = ParticipantSnapshot {
            session_id: command.session_id,
            participant_id: command.participant_id,
            parent_participant_id: Some(command.parent_participant_id),
            depth: parent.depth.checked_add(1).ok_or(StoreError::Corrupt)?,
            template_id: command.template_id,
            template_compatibility: command.expected_compatibility,
            revision: Revision::initial(),
        };
        sqlx::query("INSERT INTO participants(participant_id,session_id,parent_participant_id,template_id,template_compatibility,revision,depth) VALUES(?,?,?,?,?,1,?)")
            .bind(participant.participant_id.to_string()).bind(command.session_id.to_string()).bind(command.parent_participant_id.to_string()).bind(command.template_id.to_string()).bind(command.expected_compatibility.as_bytes().as_slice()).bind(i64::from(participant.depth)).execute(&mut *tx).await.map_err(map_sqlx)?;
        crash_at("authority.spawn.after_child");
        sqlx::query(
            "INSERT INTO authority_policies(participant_id,session_id,snapshot) VALUES(?,?,?)",
        )
        .bind(participant.participant_id.to_string())
        .bind(command.session_id.to_string())
        .bind(serde_json::to_vec(&child_policy).map_err(|_| StoreError::Corrupt)?)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        crash_at("authority.spawn.after_policy");
        let input = validated_input.ok_or(StoreError::Corrupt)?;
        let input_digest = *SemanticDigest::v1(
            &Capability::new("operation.input.v1").expect("static capability"),
            input.as_bytes(),
        )
        .as_bytes();
        let operation = OperationSnapshot {
            session_id: command.session_id,
            operation_id: command.operation_id,
            participant_id: command.participant_id,
            start_request_id: command.context.request_id(),
            input_message_id: command.input_message_id,
            waiting_on_message_id: None,
            input_digest,
            state: OperationState::Queued,
            revision: Revision::initial(),
            terminal_outcome: None,
            created_at: now,
            updated_at: now,
        };
        sqlx::query("INSERT INTO operations (operation_id,session_id,participant_id,start_request_id,input_message_id,waiting_on_message_id,input_digest,input_payload,state,terminal_outcome,terminal_payload,revision,created_at_seconds,created_at_nanos,updated_at_seconds,updated_at_nanos) VALUES(?,?,?,?,?,NULL,?,?,'queued',NULL,NULL,1,?,?,?,?)")
            .bind(operation.operation_id.to_string()).bind(command.session_id.to_string())
            .bind(command.participant_id.to_string()).bind(operation.start_request_id.to_string())
            .bind(operation.input_message_id.to_string()).bind(operation.input_digest.as_slice())
            .bind(input.as_bytes()).bind(now.unix_seconds()).bind(i64::from(now.nanoseconds()))
            .bind(now.unix_seconds()).bind(i64::from(now.nanoseconds()))
            .execute(&mut *tx).await.map_err(map_sqlx)?;
        crash_at("authority.spawn.after_operation");
        let envelope = navigator_domain::ValidatedMessageEnvelope::operation_input(
            operation.operation_id,
            operation.input_digest,
        );
        let message = MessageSnapshot {
            session_id: command.session_id,
            message_id: command.input_message_id,
            source: command.participant_id,
            destination: command.participant_id,
            mailbox_sequence: 1,
            priority: MessagePriority::Ordinary,
            correlation: MessageCorrelation {
                operation_id: Some(command.operation_id),
                in_reply_to: None,
            },
            envelope,
            attempt_count: 0,
            state: MessageDeliveryState::Queued,
            revision: Revision::initial(),
            created_at: now,
            updated_at: now,
        };
        let message_bytes = i64::try_from(message.envelope.as_bytes().len())
            .map_err(|_| StoreError::MessageOversize)?;
        sqlx::query("INSERT INTO messages(message_id,session_id,source_participant_id,destination_participant_id,mailbox_sequence,priority,snapshot) VALUES(?,?,?,?,1,1,?)")
            .bind(message.message_id.to_string()).bind(command.session_id.to_string())
            .bind(command.participant_id.to_string()).bind(command.participant_id.to_string())
            .bind(serde_json::to_vec(&message).map_err(|_| StoreError::Corrupt)?)
            .execute(&mut *tx).await.map_err(map_sqlx)?;
        sqlx::query("INSERT INTO mailbox_counters(destination_participant_id,next_sequence,queued_bytes,queued_messages) VALUES(?,2,?,1)")
            .bind(command.participant_id.to_string()).bind(message_bytes).execute(&mut *tx).await.map_err(map_sqlx)?;
        crash_at("authority.spawn.after_message");
        append_event_data(
            &mut tx,
            command.context.request_id(),
            command.session_id,
            operation.revision,
            "operation.queued",
            &operation_event_payload(&operation)?,
            now,
        )
        .await?;
        append_message_event(&mut tx, command.context.request_id(), &message, now).await?;
        if let Some(value) = grant.as_mut().filter(|value| value.single_use) {
            value.consumed_at = Some(now);
            update_grant_in(&mut tx, value).await?;
        }
        crash_at("authority.spawn.after_grant");
        let data = serde_json::to_vec(&serde_json::json!({"schema_version":1,"participant_id":participant.participant_id,"parent_participant_id":participant.parent_participant_id,"template_id":participant.template_id,"depth":participant.depth,"revision":participant.revision.get(),"lifecycle":"registered"})).map_err(|_| StoreError::Corrupt)?;
        append_event_data(
            &mut tx,
            command.context.request_id(),
            command.session_id,
            Revision::initial(),
            "participant.created",
            &data,
            now,
        )
        .await?;
        crash_at("authority.spawn.after_events");
        append_authority_event(
            &mut tx,
            command.session_id,
            &command,
            "authority.allowed",
            command.parent_participant_id,
            now,
        )
        .await?;
        let outcome = AuthorizedChildOutcome::Allowed {
            participant,
            policy: Box::new(child_policy),
            operation: Box::new(operation),
            decision: decision.into(),
        };
        record_json(&mut tx, command.session_id, &command, &outcome).await?;
        crash_at("authority.spawn.after_ledger");
        crash_at("authority.spawn.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("authority.spawn.after_commit");
        Ok(Mutation::Applied(outcome))
    }

    async fn load_authority_policy(
        &self,
        participant_id: ParticipantId,
    ) -> Result<AuthorityPolicySnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        load_authority_policy_in(&mut transaction, participant_id)
            .await?
            .ok_or(StoreError::Invalid)
    }
    async fn load_grant(
        &self,
        grant_id: navigator_domain::GrantId,
    ) -> Result<GrantSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        load_grant_in(&mut transaction, grant_id)
            .await?
            .ok_or(StoreError::Invalid)
    }

    async fn load_authority_template_policy(
        &self,
        template_id: TemplateId,
    ) -> Result<AuthorityTemplatePolicy, StoreError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        load_authority_template_policy_in(&mut tx, template_id)
            .await?
            .ok_or(StoreError::Invalid)
    }
}

impl HierarchyStore for SqliteStore {
    #[expect(
        clippy::too_many_lines,
        reason = "atomic subtree cancellation protocol"
    )]
    async fn cancel_subtree(
        &self,
        command: CancelSubtree,
    ) -> Result<Mutation<CancelSubtreeOutcome>, StoreError> {
        let observed_at = self.now();
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(stored) = replay_json::<CancelSubtreeOutcome>(&mut tx, &command).await? {
            let outcome = refresh_cancellation_outcome(&mut tx, stored).await?;
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(outcome));
        }
        if let Err(error) = authorize_launch(
            &mut tx,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(tx, command.session_id, &command, error).await?);
        }
        let root = load_participant_in(&mut tx, command.root_participant_id).await?;
        if root.is_none_or(|value| value.session_id != command.session_id) {
            return Err(
                finish_failure(tx, command.session_id, &command, StoreError::Invalid).await?,
            );
        }
        sqlx::query(
            "WITH RECURSIVE subtree(participant_id) AS (SELECT ? UNION ALL SELECT p.participant_id FROM participants p JOIN subtree s ON p.parent_participant_id=s.participant_id WHERE p.session_id=?) UPDATE participants SET cancellation_requested=1 WHERE participant_id IN (SELECT participant_id FROM subtree)",
        )
        .bind(command.root_participant_id.to_string())
        .bind(command.session_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        crash_at("cancellation.after_subtree_tombstone");
        let rows = sqlx::query(
            "WITH RECURSIVE subtree(participant_id) AS (SELECT ? UNION ALL SELECT p.participant_id FROM participants p JOIN subtree s ON p.parent_participant_id=s.participant_id WHERE p.session_id=?) SELECT o.operation_id FROM operations o JOIN subtree s ON o.participant_id=s.participant_id WHERE o.session_id=? ORDER BY o.created_at_seconds,o.created_at_nanos,o.operation_id",
        )
        .bind(command.root_participant_id.to_string())
        .bind(command.session_id.to_string())
        .bind(command.session_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let now = load_session_in(&mut tx, command.session_id)
            .await?
            .ok_or(StoreError::Corrupt)?
            .time_floor;
        let mut records = Vec::new();
        for row in rows {
            let raw: String = row.try_get("operation_id").map_err(map_sqlx)?;
            let operation_id =
                OperationId::from_uuid(Uuid::parse_str(&raw).map_err(|_| StoreError::Corrupt)?)
                    .map_err(|_| StoreError::Corrupt)?;
            let Some(mut operation) = load_operation_in(&mut tx, operation_id).await? else {
                return Err(StoreError::Corrupt);
            };
            let mut notification = load_cancel_notification_in(&mut tx, &operation).await?;
            if !operation.state.is_terminal() && operation.state != OperationState::Cancelling {
                let launch_exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM launch_attempts WHERE session_id=? AND participant_id=?)",
                )
                .bind(command.session_id.to_string())
                .bind(operation.participant_id.to_string())
                .fetch_one(&mut *tx)
                .await
                .map_err(map_sqlx)?;
                let terminal_without_driver = operation.state == OperationState::Queued
                    || (operation.state == OperationState::Starting && !launch_exists);
                let previous = operation.revision;
                operation.state = if terminal_without_driver {
                    OperationState::Cancelled
                } else {
                    OperationState::Cancelling
                };
                operation.waiting_on_message_id = None;
                operation.terminal_outcome =
                    terminal_without_driver.then_some(OperationTerminalOutcome::Cancelled);
                operation.revision = operation.revision.next().ok_or(StoreError::Corrupt)?;
                operation.updated_at = now.max(operation.updated_at);
                let terminal_name = operation
                    .terminal_outcome
                    .as_ref()
                    .map(terminal_outcome_name);
                let terminal_payload = operation
                    .terminal_outcome
                    .as_ref()
                    .map(|value| serde_json::to_vec(value).map_err(|_| StoreError::Corrupt))
                    .transpose()?;
                let changed = sqlx::query("UPDATE operations SET state=?,waiting_on_message_id=NULL,terminal_outcome=?,terminal_payload=?,revision=?,updated_at_seconds=?,updated_at_nanos=? WHERE operation_id=? AND revision=?")
                    .bind(operation_state_name(operation.state)).bind(terminal_name).bind(terminal_payload)
                    .bind(to_i64(operation.revision.get())?).bind(operation.updated_at.unix_seconds()).bind(i64::from(operation.updated_at.nanoseconds()))
                    .bind(operation.operation_id.to_string()).bind(to_i64(previous.get())?)
                    .execute(&mut *tx).await.map_err(map_sqlx)?;
                if changed.rows_affected() != 1 {
                    return Err(StoreError::Corrupt);
                }
                crash_at("cancellation.after_operation");
                append_event_data(
                    &mut tx,
                    command.context.request_id(),
                    command.session_id,
                    operation.revision,
                    operation_event_name(operation.state),
                    &operation_event_payload(&operation)?,
                    now,
                )
                .await?;
                crash_at("cancellation.after_operation_event");
                if !terminal_without_driver {
                    let mut domain = b"navigator.operation.cancel.v1".to_vec();
                    domain.extend_from_slice(operation.operation_id.as_uuid().as_bytes());
                    let message_id =
                        derived_store_message_id(command.context.request_id(), &domain)?;
                    notification = Some(
                        insert_hierarchy_message(
                            &mut tx,
                            command.session_id,
                            command.context.request_id(),
                            message_id,
                            operation.participant_id,
                            operation.participant_id,
                            MessageCorrelation {
                                operation_id: Some(operation.operation_id),
                                in_reply_to: None,
                            },
                            navigator_domain::ValidatedMessageEnvelope::control(
                                operation.operation_id,
                                navigator_domain::ControlMessageKind::Cancel,
                            ),
                            now,
                        )
                        .await?,
                    );
                    crash_at("cancellation.after_notification");
                }
            }
            records.push(CancellationRecord {
                operation,
                notification,
            });
        }
        let outcome = CancelSubtreeOutcome {
            root_participant_id: command.root_participant_id,
            records,
        };
        crash_at("cancellation.after_effects");
        record_json(&mut tx, command.session_id, &command, &outcome).await?;
        crash_at("cancellation.after_ledger");
        crash_at("cancellation.before_commit");
        tx.commit().await.map_err(map_sqlx)?;
        crash_at("cancellation.after_commit");
        Ok(Mutation::Applied(outcome))
    }

    async fn inspect_subtree_cancellation(
        &self,
        session_id: SessionId,
        root_participant_id: ParticipantId,
    ) -> Result<CancelSubtreeOutcome, StoreError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let root = load_participant_in(&mut tx, root_participant_id).await?;
        if root.is_none_or(|value| value.session_id != session_id) {
            return Err(StoreError::Invalid);
        }
        let rows = sqlx::query(
            "WITH RECURSIVE subtree(participant_id) AS (SELECT ? UNION ALL SELECT p.participant_id FROM participants p JOIN subtree s ON p.parent_participant_id=s.participant_id WHERE p.session_id=?) SELECT o.operation_id FROM operations o JOIN subtree s ON o.participant_id=s.participant_id WHERE o.session_id=? ORDER BY o.created_at_seconds,o.created_at_nanos,o.operation_id",
        )
        .bind(root_participant_id.to_string())
        .bind(session_id.to_string())
        .bind(session_id.to_string())
        .fetch_all(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            let raw: String = row.try_get("operation_id").map_err(map_sqlx)?;
            let operation_id =
                OperationId::from_uuid(Uuid::parse_str(&raw).map_err(|_| StoreError::Corrupt)?)
                    .map_err(|_| StoreError::Corrupt)?;
            let operation = load_operation_in(&mut tx, operation_id)
                .await?
                .ok_or(StoreError::Corrupt)?;
            let notification = load_cancel_notification_in(&mut tx, &operation).await?;
            records.push(CancellationRecord {
                operation,
                notification,
            });
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(CancelSubtreeOutcome {
            root_participant_id,
            records,
        })
    }

    async fn cancellation_requested(
        &self,
        participant_id: ParticipantId,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        let requested = participant_cancellation_requested(&mut tx, participant_id).await?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(requested)
    }

    async fn authorized_status(
        &self,
        query: AuthorizedStatus,
    ) -> Result<Mutation<AuthorizedStatusOutcome>, StoreError> {
        let observed_at = self.now();
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(outcome) = replay_json::<AuthorizedStatusOutcome>(&mut tx, &query).await? {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(outcome));
        }
        if authorize_launch(
            &mut tx,
            query.session_id,
            query.context,
            query.epoch,
            StoreAction::CheckAuthorityEffect,
            observed_at,
        )
        .await
        .is_err()
        {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Unchanged(AuthorizedStatusOutcome::Denied));
        }
        let caller = load_participant_in(&mut tx, query.caller_participant_id).await?;
        let target = load_participant_in(&mut tx, query.target_participant_id).await?;
        let policy = load_authority_policy_in(&mut tx, query.caller_participant_id).await?;
        let now = load_session_in(&mut tx, query.session_id)
            .await?
            .ok_or(StoreError::Corrupt)?
            .time_floor;
        let direct = caller
            .as_ref()
            .zip(target.as_ref())
            .is_some_and(|(caller, target)| {
                caller.session_id == query.session_id
                    && target.session_id == query.session_id
                    && target.parent_participant_id == Some(caller.participant_id)
            });
        let requested = ScopedCapability::new(
            Capability::new("participant.status").expect("static capability"),
            navigator_domain::ResourceScope::Participant(query.target_participant_id),
        );
        let allowed = direct
            && policy.as_ref().is_some_and(|policy| {
                policy_ceilings(policy)
                    .authorize_effect(
                        query.caller_participant_id,
                        query.session_id,
                        &requested,
                        None,
                        now,
                    )
                    .is_ok()
            });
        if !allowed {
            let outcome = AuthorizedStatusOutcome::Denied;
            record_json(&mut tx, query.session_id, &query, &outcome).await?;
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Applied(outcome));
        }
        let participant = target.ok_or(StoreError::Corrupt)?;
        let operation = match query.operation_id {
            Some(operation_id) => match load_operation_in(&mut tx, operation_id).await? {
                Some(value)
                    if value.session_id == query.session_id
                        && value.participant_id == participant.participant_id =>
                {
                    Some(value)
                }
                _ => {
                    let outcome = AuthorizedStatusOutcome::Denied;
                    record_json(&mut tx, query.session_id, &query, &outcome).await?;
                    tx.commit().await.map_err(map_sqlx)?;
                    return Ok(Mutation::Applied(outcome));
                }
            },
            None => None,
        };
        let outcome = AuthorizedStatusOutcome::Allowed {
            participant: Box::new(participant),
            operation: operation.map(Box::new),
        };
        record_json(&mut tx, query.session_id, &query, &outcome).await?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(Mutation::Applied(outcome))
    }

    #[expect(clippy::too_many_lines, reason = "single atomic hierarchy effect")]
    async fn apply_hierarchy_effect(
        &self,
        command: ApplyHierarchyEffect,
    ) -> Result<Mutation<HierarchyEffectOutcome>, StoreError> {
        let observed_at = self.now();
        let mut tx = begin_immediate(&self.pool).await?;
        if let Some(outcome) = replay_json::<HierarchyEffectOutcome>(&mut tx, &command).await? {
            if let HierarchyEffectOutcome::Allowed { message, .. } = &outcome {
                if load_message_in(&mut tx, message.message_id).await? != Some((**message).clone())
                {
                    return Err(StoreError::Corrupt);
                }
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(outcome));
        }
        if let Err(error) = authorize_launch(
            &mut tx,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(tx, command.session_id, &command, error).await?);
        }
        let now = load_session_in(&mut tx, command.session_id)
            .await?
            .ok_or(StoreError::Corrupt)?
            .time_floor;
        let caller = load_participant_in(&mut tx, command.caller_participant_id).await?;
        let Some(caller) = caller.filter(|value| value.session_id == command.session_id) else {
            return commit_hierarchy_denied(tx, &command, now).await;
        };
        let (message_id, destination, envelope, correlation, grant_id, requested, operation_change) =
            match &command.effect {
                HierarchyEffect::QuestionUpward {
                    message_id,
                    operation_id,
                    delivered_message_id,
                    code,
                    grant_id,
                } => {
                    let Some(parent_id) = caller.parent_participant_id else {
                        return commit_hierarchy_denied(tx, &command, now).await;
                    };
                    let operation = load_operation_in(&mut tx, *operation_id).await?;
                    let Some(operation) = operation.filter(|value| {
                        value.session_id == command.session_id
                            && value.participant_id == caller.participant_id
                            && value.input_message_id == *delivered_message_id
                            && value.state == OperationState::Running
                            && value.waiting_on_message_id.is_none()
                    }) else {
                        return commit_hierarchy_denied(tx, &command, now).await;
                    };
                    (
                        *message_id,
                        parent_id,
                        navigator_domain::ValidatedMessageEnvelope::question(
                            *operation_id,
                            code.clone(),
                        ),
                        MessageCorrelation {
                            operation_id: Some(*operation_id),
                            in_reply_to: None,
                        },
                        *grant_id,
                        ScopedCapability::new(
                            Capability::new("message.question").expect("static capability"),
                            navigator_domain::ResourceScope::Operation(*operation_id),
                        ),
                        Some((operation, OperationAction::Wait)),
                    )
                }
                HierarchyEffect::Send {
                    message_id,
                    destination,
                    envelope,
                    grant_id,
                } => {
                    if !matches!(
                        envelope.body(),
                        navigator_domain::MessageBody::Control {
                            command: navigator_domain::ControlMessageKind::Reminder,
                            ..
                        }
                    ) {
                        return commit_hierarchy_denied(tx, &command, now).await;
                    }
                    let operation_id = match envelope.body() {
                        navigator_domain::MessageBody::Control { operation_id, .. } => {
                            *operation_id
                        }
                        _ => unreachable!(),
                    };
                    if load_operation_in(&mut tx, operation_id)
                        .await?
                        .as_ref()
                        .is_none_or(|value| {
                            value.session_id != command.session_id
                                || value.participant_id != *destination
                                || value.state.is_terminal()
                        })
                    {
                        return commit_hierarchy_denied(tx, &command, now).await;
                    }
                    (
                        *message_id,
                        *destination,
                        envelope.clone(),
                        MessageCorrelation {
                            operation_id: Some(operation_id),
                            in_reply_to: None,
                        },
                        *grant_id,
                        ScopedCapability::new(
                            Capability::new("message.send").expect("static capability"),
                            navigator_domain::ResourceScope::Participant(*destination),
                        ),
                        None,
                    )
                }
                HierarchyEffect::CancelChild {
                    message_id,
                    child_id,
                    operation_id,
                    grant_id,
                } => {
                    let Some(operation) =
                        load_operation_in(&mut tx, *operation_id)
                            .await?
                            .filter(|value| {
                                value.session_id == command.session_id
                                    && value.participant_id == *child_id
                                    && !value.state.is_terminal()
                            })
                    else {
                        return commit_hierarchy_denied(tx, &command, now).await;
                    };
                    (
                        *message_id,
                        *child_id,
                        navigator_domain::ValidatedMessageEnvelope::control(
                            *operation_id,
                            navigator_domain::ControlMessageKind::Cancel,
                        ),
                        MessageCorrelation {
                            operation_id: Some(*operation_id),
                            in_reply_to: None,
                        },
                        *grant_id,
                        ScopedCapability::new(
                            Capability::new("operation.cancel").expect("static capability"),
                            navigator_domain::ResourceScope::Operation(*operation_id),
                        ),
                        Some((operation, OperationAction::RequestCancel)),
                    )
                }
                HierarchyEffect::ResumeChild {
                    message_id,
                    child_id,
                    operation_id,
                    in_reply_to,
                    feedback,
                    grant_id,
                } => {
                    let Some(_operation) =
                        load_operation_in(&mut tx, *operation_id)
                            .await?
                            .filter(|value| {
                                value.session_id == command.session_id
                                    && value.participant_id == *child_id
                                    && value.state == OperationState::Waiting
                                    && value.waiting_on_message_id == Some(*in_reply_to)
                            })
                    else {
                        return commit_hierarchy_denied(tx, &command, now).await;
                    };
                    (
                        *message_id,
                        *child_id,
                        navigator_domain::ValidatedMessageEnvelope::correlated_feedback(
                            *operation_id,
                            *in_reply_to,
                            *feedback,
                        ),
                        MessageCorrelation {
                            operation_id: Some(*operation_id),
                            in_reply_to: Some(*in_reply_to),
                        },
                        *grant_id,
                        ScopedCapability::new(
                            Capability::new("operation.resume").expect("static capability"),
                            navigator_domain::ResourceScope::Operation(*operation_id),
                        ),
                        None,
                    )
                }
            };
        if operation_change
            .as_ref()
            .is_some_and(|(operation, action)| {
                next_operation_state(operation.state, *action).is_none()
            })
        {
            return commit_hierarchy_denied(tx, &command, now).await;
        }
        let target = load_participant_in(&mut tx, destination).await?;
        let direct = target.as_ref().is_some_and(|value| {
            if value.session_id != command.session_id {
                return false;
            }
            match command.effect {
                HierarchyEffect::CancelChild { .. } | HierarchyEffect::ResumeChild { .. } => {
                    value.parent_participant_id == Some(caller.participant_id)
                }
                HierarchyEffect::QuestionUpward { .. } => {
                    caller.parent_participant_id == Some(value.participant_id)
                }
                HierarchyEffect::Send { .. } => {
                    value.participant_id == caller.participant_id
                        || value.parent_participant_id == Some(caller.participant_id)
                        || caller.parent_participant_id == Some(value.participant_id)
                }
            }
        });
        let policy = load_authority_policy_in(&mut tx, caller.participant_id).await?;
        let grant = match grant_id {
            Some(id) => load_grant_in(&mut tx, id).await?,
            None => None,
        };
        let decision = policy.as_ref().and_then(|policy| {
            policy_ceilings(policy)
                .authorize_effect(
                    caller.participant_id,
                    command.session_id,
                    &requested,
                    grant.as_ref().map(|value| &value.grant),
                    now,
                )
                .ok()
        });
        if !direct
            || decision.is_none()
            || grant
                .as_ref()
                .is_some_and(|value| value.consumed_at.is_some())
        {
            return commit_hierarchy_denied(tx, &command, now).await;
        }
        let message = match insert_hierarchy_message(
            &mut tx,
            command.session_id,
            command.context.request_id(),
            message_id,
            caller.participant_id,
            destination,
            correlation,
            envelope,
            now,
        )
        .await
        {
            Ok(value) => value,
            Err(
                StoreError::Invalid
                | StoreError::MailboxQuotaExceeded
                | StoreError::MessageOversize,
            ) => {
                return commit_hierarchy_denied(tx, &command, now).await;
            }
            Err(error) => return Err(error),
        };
        let mut operation_result = None;
        if let Some((mut operation, action)) = operation_change {
            let next = next_operation_state(operation.state, action).ok_or(StoreError::Corrupt)?;
            operation.state = next;
            operation.revision = operation.revision.next().ok_or(StoreError::Corrupt)?;
            operation.updated_at = now.max(operation.updated_at);
            operation.waiting_on_message_id =
                (action == OperationAction::Wait).then_some(message_id);
            let changed = sqlx::query("UPDATE operations SET state=?, waiting_on_message_id=?, revision=?, updated_at_seconds=?, updated_at_nanos=? WHERE operation_id=? AND revision=?")
                .bind(operation_state_name(next)).bind(operation.waiting_on_message_id.map(|id| id.to_string()))
                .bind(to_i64(operation.revision.get())?).bind(operation.updated_at.unix_seconds()).bind(i64::from(operation.updated_at.nanoseconds()))
                .bind(operation.operation_id.to_string()).bind(to_i64(operation.revision.get() - 1)?).execute(&mut *tx).await.map_err(map_sqlx)?;
            if changed.rows_affected() != 1 {
                return Err(StoreError::Corrupt);
            }
            operation_result = Some(Box::new(operation));
        } else if let HierarchyEffect::ResumeChild { operation_id, .. } = &command.effect {
            operation_result = load_operation_in(&mut tx, *operation_id)
                .await?
                .filter(|value| {
                    value.session_id == command.session_id
                        && value.participant_id == destination
                        && !value.state.is_terminal()
                })
                .map(Box::new);
            if operation_result.is_none() {
                return commit_hierarchy_denied(tx, &command, now).await;
            }
        } else if let HierarchyEffect::Send { envelope, .. } = &command.effect {
            let navigator_domain::MessageBody::Control { operation_id, .. } = envelope.body()
            else {
                return Err(StoreError::Corrupt);
            };
            operation_result = load_operation_in(&mut tx, *operation_id)
                .await?
                .filter(|value| {
                    value.session_id == command.session_id
                        && value.participant_id == destination
                        && !value.state.is_terminal()
                })
                .map(Box::new);
            if operation_result.is_none() {
                return commit_hierarchy_denied(tx, &command, now).await;
            }
        }
        if let Some(mut grant) = grant.filter(|value| value.single_use) {
            grant.consumed_at = Some(now);
            update_grant_in(&mut tx, &grant).await?;
        }
        let outcome = HierarchyEffectOutcome::Allowed {
            message: Box::new(message),
            operation: operation_result,
        };
        append_authority_event(
            &mut tx,
            command.session_id,
            &command,
            "authority.allowed",
            command.caller_participant_id,
            now,
        )
        .await?;
        record_json(&mut tx, command.session_id, &command, &outcome).await?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(Mutation::Applied(outcome))
    }
}

async fn commit_hierarchy_denied(
    mut tx: Transaction<'_, Sqlite>,
    command: &ApplyHierarchyEffect,
    now: Timestamp,
) -> Result<Mutation<HierarchyEffectOutcome>, StoreError> {
    let outcome = HierarchyEffectOutcome::Denied;
    append_authority_event(
        &mut tx,
        command.session_id,
        command,
        "authority.denied",
        command.caller_participant_id,
        now,
    )
    .await?;
    record_json(&mut tx, command.session_id, command, &outcome).await?;
    tx.commit().await.map_err(map_sqlx)?;
    Ok(Mutation::Applied(outcome))
}

async fn load_cancel_notification_in(
    tx: &mut Transaction<'_, Sqlite>,
    operation: &OperationSnapshot,
) -> Result<Option<MessageSnapshot>, StoreError> {
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT snapshot FROM messages WHERE session_id=? AND destination_participant_id=? ORDER BY mailbox_sequence",
    )
    .bind(operation.session_id.to_string())
    .bind(operation.participant_id.to_string())
    .fetch_all(&mut **tx)
    .await
    .map_err(map_sqlx)?;
    for bytes in rows {
        let message: MessageSnapshot =
            serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
        if matches!(
            message.envelope.body(),
            navigator_domain::MessageBody::Control {
                operation_id,
                command: navigator_domain::ControlMessageKind::Cancel,
            } if *operation_id == operation.operation_id
        ) {
            return Ok(Some(message));
        }
    }
    Ok(None)
}

async fn refresh_cancellation_outcome(
    tx: &mut Transaction<'_, Sqlite>,
    stored: CancelSubtreeOutcome,
) -> Result<CancelSubtreeOutcome, StoreError> {
    let mut records = Vec::with_capacity(stored.records.len());
    for previous in stored.records {
        let operation = load_operation_in(tx, previous.operation.operation_id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        let notification = match previous.notification {
            Some(message) => Some(
                load_message_in(tx, message.message_id)
                    .await?
                    .ok_or(StoreError::Corrupt)?,
            ),
            None => None,
        };
        records.push(CancellationRecord {
            operation,
            notification,
        });
    }
    Ok(CancelSubtreeOutcome {
        root_participant_id: stored.root_participant_id,
        records,
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "atomic mailbox row has explicit identities"
)]
async fn insert_hierarchy_message(
    tx: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    request_id: RequestId,
    message_id: MessageId,
    source: ParticipantId,
    destination: ParticipantId,
    correlation: MessageCorrelation,
    envelope: navigator_domain::ValidatedMessageEnvelope,
    now: Timestamp,
) -> Result<MessageSnapshot, StoreError> {
    if load_message_in(tx, message_id).await?.is_some() {
        return Err(StoreError::Invalid);
    }
    let counter: Option<(i64, i64, i64)> = sqlx::query_as(
        "SELECT next_sequence, queued_bytes, queued_messages FROM mailbox_counters WHERE destination_participant_id = ?",
    )
    .bind(destination.to_string())
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx)?;
    let (sequence, queued_bytes, queued_messages) = counter.unwrap_or((1, 0, 0));
    let new_bytes = u64::try_from(queued_bytes)
        .map_err(|_| StoreError::Corrupt)?
        .checked_add(u64::try_from(envelope.as_bytes().len()).map_err(|_| StoreError::Corrupt)?)
        .ok_or(StoreError::MailboxQuotaExceeded)?;
    let new_messages = u64::try_from(queued_messages)
        .map_err(|_| StoreError::Corrupt)?
        .checked_add(1)
        .ok_or(StoreError::MailboxQuotaExceeded)?;
    let outcome_reserve = envelope.kind() == navigator_domain::MessageKind::OperationOutcome;
    let byte_limit = MAX_MAILBOX_QUEUED_BYTES
        + if outcome_reserve {
            MAX_MAILBOX_RESERVED_OUTCOME_BYTES
        } else {
            0
        };
    let message_limit = MAX_MAILBOX_QUEUED_MESSAGES
        + if outcome_reserve {
            MAX_MAILBOX_RESERVED_OUTCOMES
        } else {
            0
        };
    if new_bytes > byte_limit || new_messages > message_limit {
        return Err(StoreError::MailboxQuotaExceeded);
    }
    let snapshot = MessageSnapshot {
        session_id,
        message_id,
        source,
        destination,
        mailbox_sequence: u64::try_from(sequence).map_err(|_| StoreError::Corrupt)?,
        priority: priority_for(envelope.kind()),
        correlation,
        envelope,
        attempt_count: 0,
        state: MessageDeliveryState::Queued,
        revision: Revision::initial(),
        created_at: now,
        updated_at: now,
    };
    sqlx::query("INSERT INTO messages(message_id,session_id,source_participant_id,destination_participant_id,mailbox_sequence,priority,snapshot) VALUES(?,?,?,?,?,?,?)")
        .bind(message_id.to_string()).bind(session_id.to_string()).bind(source.to_string()).bind(destination.to_string()).bind(sequence)
        .bind(match snapshot.priority { MessagePriority::Control => 0_i64, MessagePriority::Ordinary => 1_i64 })
        .bind(serde_json::to_vec(&snapshot).map_err(|_| StoreError::Corrupt)?)
        .execute(&mut **tx).await.map_err(map_sqlx)?;
    sqlx::query("INSERT INTO mailbox_counters(destination_participant_id,next_sequence,queued_bytes,queued_messages) VALUES(?,?,?,?) ON CONFLICT(destination_participant_id) DO UPDATE SET next_sequence=excluded.next_sequence,queued_bytes=excluded.queued_bytes,queued_messages=excluded.queued_messages")
        .bind(destination.to_string()).bind(sequence.checked_add(1).ok_or(StoreError::Corrupt)?)
        .bind(i64::try_from(new_bytes).map_err(|_| StoreError::Corrupt)?)
        .bind(i64::try_from(new_messages).map_err(|_| StoreError::Corrupt)?)
        .execute(&mut **tx).await.map_err(map_sqlx)?;
    append_message_event(tx, request_id, &snapshot, now).await?;
    Ok(snapshot)
}

fn policy_ceilings(policy: &AuthorityPolicySnapshot) -> navigator_domain::AuthorityCeilings<'_> {
    navigator_domain::AuthorityCeilings {
        session: &policy.session,
        parent: &policy.parent,
        template: &policy.template,
        relationship: &policy.relationship,
        subject: &policy.subject,
    }
}

async fn load_authority_policy_in(
    transaction: &mut Transaction<'_, Sqlite>,
    participant_id: ParticipantId,
) -> Result<Option<AuthorityPolicySnapshot>, StoreError> {
    let bytes: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT snapshot FROM authority_policies WHERE participant_id = ?")
            .bind(participant_id.to_string())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(map_sqlx)?;
    bytes
        .map(|value| serde_json::from_slice(&value).map_err(|_| StoreError::Corrupt))
        .transpose()
}

async fn load_authority_template_policy_in(
    transaction: &mut Transaction<'_, Sqlite>,
    template_id: TemplateId,
) -> Result<Option<AuthorityTemplatePolicy>, StoreError> {
    let bytes: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT snapshot FROM authority_template_policies WHERE template_id = ?",
    )
    .bind(template_id.to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    bytes
        .map(|value| serde_json::from_slice(&value).map_err(|_| StoreError::Corrupt))
        .transpose()
}

async fn load_grant_in(
    transaction: &mut Transaction<'_, Sqlite>,
    grant_id: navigator_domain::GrantId,
) -> Result<Option<GrantSnapshot>, StoreError> {
    let bytes: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT snapshot FROM authority_grants WHERE grant_id = ?")
            .bind(grant_id.to_string())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(map_sqlx)?;
    bytes
        .map(|value| serde_json::from_slice(&value).map_err(|_| StoreError::Corrupt))
        .transpose()
}

async fn update_grant_in(
    transaction: &mut Transaction<'_, Sqlite>,
    snapshot: &GrantSnapshot,
) -> Result<(), StoreError> {
    let changed = sqlx::query("UPDATE authority_grants SET snapshot = ? WHERE grant_id = ?")
        .bind(serde_json::to_vec(snapshot).map_err(|_| StoreError::Corrupt)?)
        .bind(snapshot.grant.id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(map_sqlx)?
        .rows_affected();
    if changed != 1 {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

async fn append_authority_event(
    transaction: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    command: &impl MutableRequest,
    event_type: &str,
    participant_id: ParticipantId,
    observed_at: Timestamp,
) -> Result<(), StoreError> {
    let data =
        serde_json::to_vec(&serde_json::json!({ "schema": 1, "participant_id": participant_id }))
            .map_err(|_| StoreError::Corrupt)?;
    append_event_data(
        transaction,
        command.context().request_id(),
        session_id,
        Revision::initial(),
        event_type,
        &data,
        observed_at,
    )
    .await
}

async fn commit_root_participant(
    mut transaction: Transaction<'_, Sqlite>,
    command: &CreateRootParticipant,
    snapshot: ParticipantSnapshot,
    observed_at: Timestamp,
) -> Result<Mutation<ParticipantSnapshot>, StoreError> {
    sqlx::query("INSERT INTO participants (participant_id, session_id, parent_participant_id, template_id, template_compatibility, revision, depth) VALUES (?, ?, NULL, ?, ?, 1, 1)")
        .bind(snapshot.participant_id.to_string()).bind(snapshot.session_id.to_string())
        .bind(snapshot.template_id.to_string()).bind(snapshot.template_compatibility.as_bytes().as_slice())
        .execute(&mut *transaction).await.map_err(map_sqlx)?;
    crash_at("participant.create.after_insert");
    let data = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1, "session_id": snapshot.session_id,
        "participant_id": snapshot.participant_id,
        "parent_participant_id":null,"template_id": snapshot.template_id,"depth":snapshot.depth,
        "revision":snapshot.revision.get(),"lifecycle":"registered",
    }))
    .map_err(|_| StoreError::Corrupt)?;
    append_event_data(
        &mut transaction,
        command.context.request_id(),
        command.session_id,
        snapshot.revision,
        "participant.created",
        &data,
        observed_at,
    )
    .await?;
    crash_at("participant.create.after_event");
    record_json(&mut transaction, command.session_id, command, &snapshot).await?;
    crash_at("participant.create.after_ledger");
    crash_at("participant.create.before_commit");
    transaction.commit().await.map_err(map_sqlx)?;
    crash_at("participant.create.after_commit");
    Ok(Mutation::Applied(snapshot))
}

async fn commit_operation_start(
    mut transaction: Transaction<'_, Sqlite>,
    command: &StartOperation,
    snapshot: OperationSnapshot,
    observed_at: Timestamp,
) -> Result<Mutation<OperationSnapshot>, StoreError> {
    sqlx::query("INSERT INTO operations (operation_id, session_id, participant_id, start_request_id, input_message_id, waiting_on_message_id, input_digest, input_payload, state, terminal_outcome, terminal_payload, revision, created_at_seconds, created_at_nanos, updated_at_seconds, updated_at_nanos) VALUES (?, ?, ?, ?, ?, NULL, ?, ?, 'queued', NULL, NULL, 1, ?, ?, ?, ?)")
        .bind(snapshot.operation_id.to_string()).bind(snapshot.session_id.to_string()).bind(snapshot.participant_id.to_string())
        .bind(snapshot.start_request_id.to_string()).bind(snapshot.input_message_id.to_string()).bind(snapshot.input_digest.as_slice()).bind(command.input.as_bytes())
        .bind(observed_at.unix_seconds()).bind(i64::from(observed_at.nanoseconds())).bind(observed_at.unix_seconds()).bind(i64::from(observed_at.nanoseconds()))
        .execute(&mut *transaction).await.map_err(map_sqlx)?;
    crash_at("operation.start.after_insert");
    let envelope = navigator_domain::ValidatedMessageEnvelope::operation_input(
        snapshot.operation_id,
        snapshot.input_digest,
    );
    let message = MessageSnapshot {
        session_id: snapshot.session_id,
        message_id: snapshot.input_message_id,
        source: snapshot.participant_id,
        destination: snapshot.participant_id,
        mailbox_sequence: 1,
        priority: MessagePriority::Ordinary,
        correlation: MessageCorrelation {
            operation_id: Some(snapshot.operation_id),
            in_reply_to: None,
        },
        envelope,
        attempt_count: 0,
        state: MessageDeliveryState::Queued,
        revision: Revision::initial(),
        created_at: observed_at,
        updated_at: observed_at,
    };
    let counter: Option<(i64, i64, i64)> = sqlx::query_as("SELECT next_sequence, queued_bytes, queued_messages FROM mailbox_counters WHERE destination_participant_id = ?")
        .bind(snapshot.participant_id.to_string()).fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
    let (sequence, queued_bytes, queued_messages) = counter.unwrap_or((1, 0, 0));
    let message_bytes = i64::try_from(message.envelope.as_bytes().len())
        .map_err(|_| StoreError::MessageOversize)?;
    if u64::try_from(queued_bytes)
        .map_err(|_| StoreError::Corrupt)?
        .saturating_add(u64::try_from(message_bytes).map_err(|_| StoreError::Corrupt)?)
        > MAX_MAILBOX_QUEUED_BYTES
        || u64::try_from(queued_messages)
            .map_err(|_| StoreError::Corrupt)?
            .saturating_add(1)
            > MAX_MAILBOX_QUEUED_MESSAGES
    {
        return Err(StoreError::MailboxQuotaExceeded);
    }
    let mut message = message;
    message.mailbox_sequence = u64::try_from(sequence).map_err(|_| StoreError::Corrupt)?;
    sqlx::query("INSERT INTO messages(message_id, session_id, source_participant_id, destination_participant_id, mailbox_sequence, priority, snapshot) VALUES (?, ?, ?, ?, ?, 1, ?)")
        .bind(message.message_id.to_string()).bind(message.session_id.to_string()).bind(message.source.to_string()).bind(message.destination.to_string()).bind(sequence)
        .bind(serde_json::to_vec(&message).map_err(|_| StoreError::Corrupt)?).execute(&mut *transaction).await.map_err(map_sqlx)?;
    sqlx::query("INSERT INTO mailbox_counters(destination_participant_id, next_sequence, queued_bytes, queued_messages) VALUES (?, ?, ?, ?) ON CONFLICT(destination_participant_id) DO UPDATE SET next_sequence = excluded.next_sequence, queued_bytes = excluded.queued_bytes, queued_messages = excluded.queued_messages")
        .bind(snapshot.participant_id.to_string()).bind(sequence.checked_add(1).ok_or(StoreError::Corrupt)?)
        .bind(queued_bytes.checked_add(message_bytes).ok_or(StoreError::Corrupt)?)
        .bind(queued_messages.checked_add(1).ok_or(StoreError::Corrupt)?)
        .execute(&mut *transaction).await.map_err(map_sqlx)?;
    crash_at("operation.start.after_mailbox");
    let data = operation_event_payload(&snapshot)?;
    append_event_data(
        &mut transaction,
        command.context.request_id(),
        command.session_id,
        snapshot.revision,
        "operation.queued",
        &data,
        observed_at,
    )
    .await?;
    append_message_event(
        &mut transaction,
        command.context.request_id(),
        &message,
        observed_at,
    )
    .await?;
    crash_at("operation.start.after_event");
    record_json(&mut transaction, command.session_id, command, &snapshot).await?;
    crash_at("operation.start.after_ledger");
    crash_at("operation.start.before_commit");
    transaction.commit().await.map_err(map_sqlx)?;
    crash_at("operation.start.after_commit");
    Ok(Mutation::Applied(snapshot))
}

async fn append_operation_event(
    transaction: &mut Transaction<'_, Sqlite>,
    command: &TransitionOperation,
    snapshot: &OperationSnapshot,
    observed_at: Timestamp,
) -> Result<(), StoreError> {
    let data = operation_event_payload(snapshot)?;
    append_event_data(
        transaction,
        command.context.request_id(),
        command.session_id,
        snapshot.revision,
        operation_event_name(snapshot.state),
        &data,
        observed_at,
    )
    .await
}

async fn load_template_in(
    transaction: &mut Transaction<'_, Sqlite>,
    template_id: TemplateId,
) -> Result<Option<TemplateRecord>, StoreError> {
    sqlx::query("SELECT template_id, compatibility_identity, registration FROM templates WHERE template_id = ?")
        .bind(template_id.to_string()).fetch_optional(&mut **transaction).await.map_err(map_sqlx)?
        .map(|row| {
            let identity = parse_template_id(&row.try_get::<String, _>("template_id").map_err(map_sqlx)?)?;
            let compatibility = CompatibilityIdentity::from_bytes(row.try_get::<Vec<u8>, _>("compatibility_identity").map_err(map_sqlx)?.try_into().map_err(|_| StoreError::Corrupt)?);
            let record: TemplateRecord = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("registration").map_err(map_sqlx)?)
                .map_err(|_| StoreError::Corrupt)?;
            if record.identity != identity || record.compatibility != compatibility
                || navigator_domain::Template::try_from(record.clone()).is_err()
            {
                return Err(StoreError::Corrupt);
            }
            Ok(record)
        }).transpose()
}

async fn load_participant_in(
    transaction: &mut Transaction<'_, Sqlite>,
    participant_id: ParticipantId,
) -> Result<Option<ParticipantSnapshot>, StoreError> {
    sqlx::query("SELECT participant_id, session_id, parent_participant_id, template_id, template_compatibility, revision, depth FROM participants WHERE participant_id = ?")
        .bind(participant_id.to_string()).fetch_optional(&mut **transaction).await.map_err(map_sqlx)?
        .map(|row| {
            let snapshot = ParticipantSnapshot {
                participant_id: parse_participant_id(&row.try_get::<String, _>("participant_id").map_err(map_sqlx)?)?,
                session_id: parse_session_id(&row.try_get::<String, _>("session_id").map_err(map_sqlx)?)?,
                parent_participant_id: row.try_get::<Option<String>, _>("parent_participant_id").map_err(map_sqlx)?.map(|value| parse_participant_id(&value)).transpose()?,
                depth: u32::try_from(row.try_get::<i64, _>("depth").map_err(map_sqlx)?).map_err(|_| StoreError::Corrupt)?,
                template_id: parse_template_id(&row.try_get::<String, _>("template_id").map_err(map_sqlx)?)?,
                template_compatibility: CompatibilityIdentity::from_bytes(row.try_get::<Vec<u8>, _>("template_compatibility").map_err(map_sqlx)?.try_into().map_err(|_| StoreError::Corrupt)?),
                revision: decode_revision(row.try_get("revision").map_err(map_sqlx)?)?,
            };
            if snapshot.depth == 0
                || snapshot.depth > MAX_PARTICIPANT_DEPTH
                || (snapshot.parent_participant_id.is_none() && snapshot.depth != 1)
                || (snapshot.parent_participant_id.is_some() && snapshot.depth == 1)
            {
                return Err(StoreError::Corrupt);
            }
            Ok(snapshot)
        }).transpose()
}

async fn participant_cancellation_requested(
    transaction: &mut Transaction<'_, Sqlite>,
    participant_id: ParticipantId,
) -> Result<bool, StoreError> {
    let value: Option<i64> = sqlx::query_scalar(
        "SELECT cancellation_requested FROM participants WHERE participant_id = ?",
    )
    .bind(participant_id.to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    match value {
        Some(0) | None => Ok(false),
        Some(1) => Ok(true),
        Some(_) => Err(StoreError::Corrupt),
    }
}

async fn load_operation_in(
    transaction: &mut Transaction<'_, Sqlite>,
    operation_id: OperationId,
) -> Result<Option<OperationSnapshot>, StoreError> {
    sqlx::query("SELECT operation_id, session_id, participant_id, start_request_id, input_message_id, waiting_on_message_id, input_digest, state, terminal_outcome, terminal_payload, revision, created_at_seconds, created_at_nanos, updated_at_seconds, updated_at_nanos FROM operations WHERE operation_id = ?")
        .bind(operation_id.to_string()).fetch_optional(&mut **transaction).await.map_err(map_sqlx)?
        .map(|row| {
            let terminal = row.try_get::<Option<Vec<u8>>, _>("terminal_payload").map_err(map_sqlx)?
                .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)).transpose()?;
            let state = parse_operation_state(&row.try_get::<String, _>("state").map_err(map_sqlx)?)?;
            let terminal_name = row.try_get::<Option<String>, _>("terminal_outcome").map_err(map_sqlx)?;
            let created_at = decode_timestamp(row.try_get("created_at_seconds").map_err(map_sqlx)?, row.try_get("created_at_nanos").map_err(map_sqlx)?)?;
            let updated_at = decode_timestamp(row.try_get("updated_at_seconds").map_err(map_sqlx)?, row.try_get("updated_at_nanos").map_err(map_sqlx)?)?;
            if updated_at < created_at
                || state.is_terminal() != terminal.is_some()
                || terminal_name.as_deref() != terminal.as_ref().map(terminal_outcome_name)
                || terminal.as_ref().is_some_and(|outcome| !terminal_matches_state(state, outcome))
            {
                return Err(StoreError::Corrupt);
            }
            let snapshot = OperationSnapshot {
                operation_id: parse_operation_id(&row.try_get::<String, _>("operation_id").map_err(map_sqlx)?)?,
                session_id: parse_session_id(&row.try_get::<String, _>("session_id").map_err(map_sqlx)?)?,
                participant_id: parse_participant_id(&row.try_get::<String, _>("participant_id").map_err(map_sqlx)?)?,
                start_request_id: parse_request_id(&row.try_get::<String, _>("start_request_id").map_err(map_sqlx)?)?,
                input_message_id: parse_message_id(&row.try_get::<String, _>("input_message_id").map_err(map_sqlx)?)?,
                waiting_on_message_id: row.try_get::<Option<String>, _>("waiting_on_message_id").map_err(map_sqlx)?.map(|value| parse_message_id(&value)).transpose()?,
                input_digest: row.try_get::<Vec<u8>, _>("input_digest").map_err(map_sqlx)?.try_into().map_err(|_| StoreError::Corrupt)?,
                state,
                revision: decode_revision(row.try_get("revision").map_err(map_sqlx)?)?,
                terminal_outcome: terminal,
                created_at,
                updated_at,
            };
            if (snapshot.state == OperationState::Waiting)
                != snapshot.waiting_on_message_id.is_some()
            {
                return Err(StoreError::Corrupt);
            }
            Ok(snapshot)
        }).transpose()
}

fn terminal_matches_state(state: OperationState, outcome: &OperationTerminalOutcome) -> bool {
    matches!(
        (state, outcome),
        (
            OperationState::Succeeded,
            OperationTerminalOutcome::Succeeded { .. }
        ) | (
            OperationState::Failed,
            OperationTerminalOutcome::Failed { .. }
        ) | (
            OperationState::Cancelled,
            OperationTerminalOutcome::Cancelled
        ) | (
            OperationState::Blocked,
            OperationTerminalOutcome::Blocked { .. }
        ) | (
            OperationState::Uncertain,
            OperationTerminalOutcome::Uncertain { .. }
        )
    )
}

fn next_operation_state(state: OperationState, action: OperationAction) -> Option<OperationState> {
    use OperationAction::{
        BeginStart, ReportBlocked, ReportCancelled, ReportFailure, ReportRunning, ReportSuccess,
        ReportUncertain, RequestCancel, Resume, Wait,
    };
    use OperationState::{
        Blocked, Cancelled, Cancelling, Failed, Queued, Running, Starting, Succeeded, Uncertain,
        Waiting,
    };
    match (state, action) {
        (Queued, BeginStart) => Some(Starting),
        (Starting, ReportRunning) | (Waiting, Resume) => Some(Running),
        (Running, Wait) => Some(Waiting),
        (Queued | Starting | Running | Waiting, RequestCancel) => Some(Cancelling),
        (Queued | Cancelling, ReportCancelled) => Some(Cancelled),
        (Queued | Starting | Running | Waiting | Cancelling, ReportFailure) => Some(Failed),
        (Running, ReportSuccess) => Some(Succeeded),
        (Running | Waiting, ReportBlocked) => Some(Blocked),
        (Starting | Running | Waiting | Cancelling, ReportUncertain) => Some(Uncertain),
        _ => None,
    }
}

async fn valid_report_correlation(
    transaction: &mut Transaction<'_, Sqlite>,
    snapshot: &OperationSnapshot,
    command: &TransitionOperation,
) -> Result<bool, StoreError> {
    if command.action == OperationAction::Wait {
        return Ok(command.report_message_id.is_some()
            && command.report_message_id != Some(snapshot.input_message_id)
            && snapshot.waiting_on_message_id.is_none());
    }
    if command.action == OperationAction::Resume {
        return Ok(snapshot.waiting_on_message_id.is_some()
            && command.report_message_id == snapshot.waiting_on_message_id);
    }
    let driver_report = matches!(
        command.action,
        OperationAction::ReportRunning
            | OperationAction::ReportSuccess
            | OperationAction::ReportFailure
            | OperationAction::ReportCancelled
            | OperationAction::ReportBlocked
            | OperationAction::ReportUncertain
    );
    if driver_report {
        if command.report_message_id.is_none()
            && matches!(
                command.action,
                OperationAction::ReportFailure | OperationAction::ReportUncertain
            )
            && matches!(
                snapshot.state,
                OperationState::Queued | OperationState::Starting
            )
        {
            return Ok(true);
        }
        let Some(message_id) = command.report_message_id else {
            return Ok(false);
        };
        let Some(message) = load_message_in(transaction, message_id).await? else {
            return Ok(false);
        };
        Ok(message.session_id == snapshot.session_id
            && message.destination == snapshot.participant_id
            && message.correlation.operation_id == Some(snapshot.operation_id)
            && matches!(message.state, MessageDeliveryState::Accepted { .. }))
    } else {
        Ok(command.report_message_id.is_none())
    }
}

fn valid_terminal_outcome(
    state: OperationState,
    outcome: Option<&OperationTerminalOutcome>,
) -> bool {
    matches!(
        (state, outcome),
        (
            OperationState::Succeeded,
            Some(OperationTerminalOutcome::Succeeded { .. })
        ) | (
            OperationState::Failed,
            Some(OperationTerminalOutcome::Failed { .. })
        ) | (
            OperationState::Cancelled,
            Some(OperationTerminalOutcome::Cancelled)
        ) | (
            OperationState::Blocked,
            Some(OperationTerminalOutcome::Blocked { .. })
        ) | (
            OperationState::Uncertain,
            Some(OperationTerminalOutcome::Uncertain { .. })
        )
    ) || (!state.is_terminal() && outcome.is_none())
}

fn terminal_outcome_name(outcome: &OperationTerminalOutcome) -> &'static str {
    match outcome {
        OperationTerminalOutcome::Succeeded { .. } => "succeeded",
        OperationTerminalOutcome::Failed { .. } => "failed",
        OperationTerminalOutcome::Cancelled => "cancelled",
        OperationTerminalOutcome::Blocked { .. } => "blocked",
        OperationTerminalOutcome::Uncertain { .. } => "uncertain",
    }
}

fn terminal_public_digest(outcome: &OperationTerminalOutcome) -> [u8; 32] {
    let canonical = serde_json::to_vec(outcome).expect("validated terminal outcome serializes");
    *SemanticDigest::v1(
        &Capability::new("operation.public-outcome.v1").expect("static capability"),
        &canonical,
    )
    .as_bytes()
}

fn derived_store_message_id(request_id: RequestId, domain: &[u8]) -> Result<MessageId, StoreError> {
    let mut bytes: [u8; 16] = SemanticDigest::v1(
        &Capability::new("message.identity.v1").expect("static capability"),
        &[domain, request_id.as_uuid().as_bytes()].concat(),
    )
    .as_bytes()[..16]
        .try_into()
        .map_err(|_| StoreError::Corrupt)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    MessageId::from_uuid(Uuid::from_bytes(bytes)).map_err(|_| StoreError::Corrupt)
}

fn public_terminal_outcome(
    outcome: &OperationTerminalOutcome,
) -> navigator_domain::PublicOperationOutcome {
    match outcome {
        OperationTerminalOutcome::Succeeded { .. } => {
            navigator_domain::PublicOperationOutcome::Succeeded
        }
        OperationTerminalOutcome::Failed { .. } => navigator_domain::PublicOperationOutcome::Failed,
        OperationTerminalOutcome::Cancelled => navigator_domain::PublicOperationOutcome::Cancelled,
        OperationTerminalOutcome::Blocked { .. } => {
            navigator_domain::PublicOperationOutcome::Blocked
        }
        OperationTerminalOutcome::Uncertain { .. } => {
            navigator_domain::PublicOperationOutcome::Uncertain
        }
    }
}

fn operation_state_name(state: OperationState) -> &'static str {
    match state {
        OperationState::Queued => "queued",
        OperationState::Starting => "starting",
        OperationState::Running => "running",
        OperationState::Waiting => "waiting",
        OperationState::Cancelling => "cancelling",
        OperationState::Succeeded => "succeeded",
        OperationState::Failed => "failed",
        OperationState::Cancelled => "cancelled",
        OperationState::Blocked => "blocked",
        OperationState::Uncertain => "uncertain",
    }
}

fn session_event_payload(snapshot: &SessionSnapshot) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "session_id": snapshot.id(),
        "status": match snapshot.status() { SessionStatus::Open => "open", SessionStatus::Closed => "closed" },
        "revision": snapshot.revision().get(),
        "created_at": snapshot.created_at(),
        "updated_at": snapshot.updated_at(),
    }))
    .map_err(|_| StoreError::Corrupt)
}

async fn append_message_event(
    transaction: &mut Transaction<'_, Sqlite>,
    request_id: RequestId,
    snapshot: &MessageSnapshot,
    observed_at: Timestamp,
) -> Result<(), StoreError> {
    let (event_type, state) = match &snapshot.state {
        MessageDeliveryState::Queued => ("message.enqueued", "queued"),
        MessageDeliveryState::RetryScheduled { .. } => {
            ("message.retry_scheduled", "retry_scheduled")
        }
        MessageDeliveryState::Leased { .. } => ("message.leased", "leased"),
        MessageDeliveryState::AcceptancePending { .. } => {
            ("message.acceptance_pending", "acceptance_pending")
        }
        MessageDeliveryState::AcceptanceUnknown { .. } => {
            ("message.acceptance_unknown", "acceptance_unknown")
        }
        MessageDeliveryState::Accepted { .. } => ("message.accepted", "accepted"),
        MessageDeliveryState::Uncertain { .. } => ("message.uncertain", "uncertain"),
        MessageDeliveryState::DeadLetter { .. } => ("message.dead_lettered", "dead_lettered"),
    };
    let data = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "session_id": snapshot.session_id,
        "message_id": snapshot.message_id,
        "source": snapshot.source,
        "destination": snapshot.destination,
        "mailbox_sequence": snapshot.mailbox_sequence,
        "priority": snapshot.priority,
        "operation_id": snapshot.correlation.operation_id,
        "in_reply_to": snapshot.correlation.in_reply_to,
        "state": state,
        "attempt_count": snapshot.attempt_count,
        "revision": snapshot.revision.get(),
        "created_at": snapshot.created_at,
        "updated_at": snapshot.updated_at,
    }))
    .map_err(|_| StoreError::Corrupt)?;
    append_event_data(
        transaction,
        request_id,
        snapshot.session_id,
        snapshot.revision,
        event_type,
        &data,
        observed_at,
    )
    .await
}

fn operation_event_name(state: OperationState) -> &'static str {
    match state {
        OperationState::Queued => "operation.queued",
        OperationState::Starting => "operation.starting",
        OperationState::Running => "operation.running",
        OperationState::Waiting => "operation.waiting",
        OperationState::Cancelling => "operation.cancelling",
        OperationState::Succeeded => "operation.succeeded",
        OperationState::Failed => "operation.failed",
        OperationState::Cancelled => "operation.cancelled",
        OperationState::Blocked => "operation.blocked",
        OperationState::Uncertain => "operation.uncertain",
    }
}

fn operation_event_payload(snapshot: &OperationSnapshot) -> Result<Vec<u8>, StoreError> {
    let terminal = snapshot.terminal_outcome.as_ref();
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "session_id": snapshot.session_id,
        "operation_id": snapshot.operation_id,
        "participant_id": snapshot.participant_id,
        "state": operation_state_name(snapshot.state),
        "input_message_id": snapshot.input_message_id,
        "waiting_on_message_id": snapshot.waiting_on_message_id,
        "terminal_outcome": terminal.map(terminal_outcome_name),
        "terminal_public_digest": terminal.map(terminal_public_digest),
        "revision": snapshot.revision.get(),
        "created_at": snapshot.created_at,
        "updated_at": snapshot.updated_at,
    }))
    .map_err(|_| StoreError::Corrupt)
}

fn tool_invocation_event_payload(snapshot: &ToolInvocationSnapshot) -> Result<Vec<u8>, StoreError> {
    let invocation = snapshot.invocation();
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "invocation_id": invocation.invocation_id(),
        "request_id": invocation.request_id(),
        "participant_id": invocation.participant_id(),
        "operation_id": invocation.operation_id(),
        "registration_id": snapshot.registration_id(),
        "tool_name": invocation.tool_name(),
        "tool_version": invocation.tool_version(),
        "phase": snapshot.phase(),
        "revision": snapshot.revision().get(),
        "connection_generation": snapshot.dispatch().connection_generation,
        "terminal_digest": snapshot.dispatch().terminal_digest,
    }))
    .map_err(|_| StoreError::Corrupt)
}

fn parse_operation_state(value: &str) -> Result<OperationState, StoreError> {
    match value {
        "queued" => Ok(OperationState::Queued),
        "starting" => Ok(OperationState::Starting),
        "running" => Ok(OperationState::Running),
        "waiting" => Ok(OperationState::Waiting),
        "cancelling" => Ok(OperationState::Cancelling),
        "succeeded" => Ok(OperationState::Succeeded),
        "failed" => Ok(OperationState::Failed),
        "cancelled" => Ok(OperationState::Cancelled),
        "blocked" => Ok(OperationState::Blocked),
        "uncertain" => Ok(OperationState::Uncertain),
        _ => Err(StoreError::Corrupt),
    }
}

#[allow(clippy::too_many_arguments)]
async fn mutate_launch<R: MutableRequest>(
    store: &SqliteStore,
    session_id: SessionId,
    context: navigator_store_api::RequestContext,
    epoch: FencingEpoch,
    attempt_id: LaunchAttemptId,
    expected_revision: Revision,
    request: &R,
    apply: impl FnOnce(&mut LaunchSnapshot) -> Result<(), StoreError>,
) -> Result<Mutation<LaunchSnapshot>, StoreError> {
    let observed_at = store.now();
    let mut transaction = begin_immediate(&store.pool).await?;
    if let Some(snapshot) = replay_json::<LaunchSnapshot>(&mut transaction, request).await? {
        transaction.commit().await.map_err(map_sqlx)?;
        return Ok(Mutation::Replayed(snapshot));
    }
    if let Err(error) = authorize_launch(
        &mut transaction,
        session_id,
        context,
        epoch,
        request.action(),
        observed_at,
    )
    .await
    {
        return Err(finish_failure(transaction, session_id, request, error).await?);
    }
    let mut snapshot = match load_launch_in(&mut transaction, attempt_id).await? {
        Some(snapshot) if snapshot.session_id == session_id => snapshot,
        _ => {
            return Err(
                finish_failure(transaction, session_id, request, StoreError::Invalid).await?,
            );
        }
    };
    if snapshot.revision != expected_revision {
        return Err(finish_failure(transaction, session_id, request, StoreError::Invalid).await?);
    }
    if let Err(error) = apply(&mut snapshot) {
        return Err(finish_failure(transaction, session_id, request, error).await?);
    }
    if let Some(instance_id) = snapshot.instance_id {
        let conflicting: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM launch_attempts WHERE instance_id = ? AND attempt_id <> ? LIMIT 1",
        )
        .bind(instance_id.to_string())
        .bind(attempt_id.to_string())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        if conflicting.is_some() {
            return Err(
                finish_failure(transaction, session_id, request, StoreError::Invalid).await?,
            );
        }
    }
    snapshot.revision = snapshot.revision.next().ok_or(StoreError::Corrupt)?;
    update_launch(&mut transaction, &snapshot, expected_revision).await?;
    crash_at("launch.mutate.after_update");
    record_json(&mut transaction, session_id, request, &snapshot).await?;
    crash_at("launch.mutate.after_ledger");
    crash_at("launch.mutate.before_commit");
    transaction.commit().await.map_err(map_sqlx)?;
    crash_at("launch.mutate.after_commit");
    Ok(Mutation::Applied(snapshot))
}

impl MailboxStore for SqliteStore {
    #[expect(clippy::too_many_lines, reason = "single atomic mailbox transaction")]
    async fn enqueue_message(
        &self,
        command: EnqueueMessage,
    ) -> Result<Mutation<MessageSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(replayed) =
            replay_json::<Option<MessageSnapshot>>(&mut transaction, &command).await?
        {
            transaction.commit().await.map_err(map_sqlx)?;
            return replayed.map(Mutation::Replayed).ok_or(StoreError::Corrupt);
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        let now = load_session_in(&mut transaction, command.session_id)
            .await?
            .ok_or(StoreError::Corrupt)?
            .time_floor;
        ensure_derived_capacity(
            &mut transaction,
            &self.limit_profile,
            command.session_id,
            CapacityResource::Messages,
            1,
        )
        .await?;
        ensure_derived_capacity(
            &mut transaction,
            &self.limit_profile,
            command.session_id,
            CapacityResource::MessageBytes,
            u64::try_from(command.envelope.as_bytes().len()).map_err(|_| StoreError::Invalid)?,
        )
        .await?;
        let source_session: Option<String> =
            sqlx::query_scalar("SELECT session_id FROM participants WHERE participant_id = ?")
                .bind(command.source.to_string())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        let destination_session: Option<String> =
            sqlx::query_scalar("SELECT session_id FROM participants WHERE participant_id = ?")
                .bind(command.destination.to_string())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        let expected = command.session_id.to_string();
        if source_session.as_deref() != Some(expected.as_str())
            || destination_session.as_deref() != Some(expected.as_str())
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let operation_id = match command.envelope.body() {
            navigator_domain::MessageBody::OperationInput {
                operation_id,
                input_digest,
            } => {
                let operation = load_operation_in(&mut transaction, *operation_id).await?;
                if command.correlation.operation_id != Some(*operation_id)
                    || command.correlation.in_reply_to.is_some()
                    || !operation.is_some_and(|operation| {
                        operation.session_id == command.session_id
                            && operation.participant_id == command.destination
                            && operation.input_message_id == command.message_id
                            && operation.input_digest == *input_digest
                    })
                {
                    return Err(finish_failure(
                        transaction,
                        command.session_id,
                        &command,
                        StoreError::Invalid,
                    )
                    .await?);
                }
                *operation_id
            }
            navigator_domain::MessageBody::Control { operation_id, .. } => {
                let operation = load_operation_in(&mut transaction, *operation_id).await?;
                if command.correlation.operation_id != Some(*operation_id)
                    || command.correlation.in_reply_to.is_some()
                    || !operation.is_some_and(|operation| {
                        operation.session_id == command.session_id
                            && operation.participant_id == command.destination
                    })
                {
                    return Err(finish_failure(
                        transaction,
                        command.session_id,
                        &command,
                        StoreError::Invalid,
                    )
                    .await?);
                }
                *operation_id
            }
            navigator_domain::MessageBody::Question { operation_id, .. } => {
                let operation = load_operation_in(&mut transaction, *operation_id).await?;
                if command.correlation.operation_id != Some(*operation_id)
                    || command.correlation.in_reply_to.is_some()
                    || !operation.is_some_and(|operation| {
                        operation.session_id == command.session_id
                            && operation.participant_id == command.source
                            && operation.state == OperationState::Waiting
                            && operation.waiting_on_message_id == Some(command.message_id)
                    })
                {
                    return Err(finish_failure(
                        transaction,
                        command.session_id,
                        &command,
                        StoreError::Invalid,
                    )
                    .await?);
                }
                *operation_id
            }
            navigator_domain::MessageBody::OperationOutcome {
                operation_id,
                result_digest,
                ..
            } => {
                let operation = load_operation_in(&mut transaction, *operation_id).await?;
                if command.correlation.operation_id != Some(*operation_id)
                    || command.correlation.in_reply_to.is_some()
                    || !operation.is_some_and(|operation| {
                        operation.session_id == command.session_id
                            && operation.participant_id == command.source
                            && operation.state.is_terminal()
                            && operation.terminal_outcome.as_ref().is_some_and(|outcome| {
                                terminal_public_digest(outcome) == *result_digest
                            })
                    })
                {
                    return Err(finish_failure(
                        transaction,
                        command.session_id,
                        &command,
                        StoreError::Invalid,
                    )
                    .await?);
                }
                *operation_id
            }
            navigator_domain::MessageBody::CorrelatedFeedback {
                operation_id,
                in_reply_to,
                ..
            } => {
                if command.correlation.operation_id != Some(*operation_id)
                    || command.correlation.in_reply_to != Some(*in_reply_to)
                    || *in_reply_to == command.message_id
                {
                    return Err(finish_failure(
                        transaction,
                        command.session_id,
                        &command,
                        StoreError::Invalid,
                    )
                    .await?);
                }
                let operation = load_operation_in(&mut transaction, *operation_id).await?;
                if !operation.is_some_and(|operation| {
                    operation.session_id == command.session_id
                        && operation.participant_id == command.source
                }) {
                    return Err(finish_failure(
                        transaction,
                        command.session_id,
                        &command,
                        StoreError::Invalid,
                    )
                    .await?);
                }
                let reply_id = *in_reply_to;
                let reply = load_message_in(&mut transaction, reply_id).await?;
                if !reply.is_some_and(|message| {
                    message.session_id == command.session_id
                        && message.source == command.destination
                        && message.destination == command.source
                }) {
                    return Err(finish_failure(
                        transaction,
                        command.session_id,
                        &command,
                        StoreError::Invalid,
                    )
                    .await?);
                }
                *operation_id
            }
            navigator_domain::MessageBody::ApprovalDecision { .. } => {
                return Err(finish_failure(
                    transaction,
                    command.session_id,
                    &command,
                    StoreError::Invalid,
                )
                .await?);
            }
        };
        debug_assert_eq!(command.correlation.operation_id, Some(operation_id));
        let existing: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT snapshot FROM messages WHERE message_id = ?")
                .bind(command.message_id.to_string())
                .fetch_optional(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
        if existing.is_some() {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let counter: Option<(i64, i64, i64)> = sqlx::query_as(
            "SELECT next_sequence, queued_bytes, queued_messages FROM mailbox_counters WHERE destination_participant_id = ?",
        ).bind(command.destination.to_string()).fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        let (sequence, queued, queued_messages) = counter.unwrap_or((1, 0, 0));
        let new_queued = u64::try_from(queued)
            .map_err(|_| StoreError::Corrupt)?
            .checked_add(
                u64::try_from(command.envelope.as_bytes().len())
                    .map_err(|_| StoreError::MessageOversize)?,
            )
            .ok_or(StoreError::MailboxQuotaExceeded)?;
        let new_count = u64::try_from(queued_messages)
            .map_err(|_| StoreError::Corrupt)?
            .checked_add(1)
            .ok_or(StoreError::MailboxQuotaExceeded)?;
        if new_queued > MAX_MAILBOX_QUEUED_BYTES || new_count > MAX_MAILBOX_QUEUED_MESSAGES {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::MailboxQuotaExceeded,
            )
            .await?);
        }
        let snapshot = MessageSnapshot {
            session_id: command.session_id,
            message_id: command.message_id,
            source: command.source,
            destination: command.destination,
            mailbox_sequence: u64::try_from(sequence).map_err(|_| StoreError::Corrupt)?,
            priority: priority_for(command.envelope.kind()),
            correlation: command.correlation.clone(),
            envelope: command.envelope.clone(),
            attempt_count: 0,
            state: MessageDeliveryState::Queued,
            revision: Revision::initial(),
            created_at: now,
            updated_at: now,
        };
        sqlx::query("INSERT INTO messages(message_id, session_id, source_participant_id, destination_participant_id, mailbox_sequence, priority, snapshot) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(snapshot.message_id.to_string()).bind(snapshot.session_id.to_string())
            .bind(snapshot.source.to_string()).bind(snapshot.destination.to_string()).bind(sequence)
            .bind(match snapshot.priority { MessagePriority::Control => 0_i64, MessagePriority::Ordinary => 1_i64 })
            .bind(serde_json::to_vec(&snapshot).map_err(|_| StoreError::Corrupt)?)
            .execute(&mut *transaction).await.map_err(map_sqlx)?;
        crash_at("mailbox.enqueue.after_message");
        sqlx::query("INSERT INTO mailbox_counters(destination_participant_id, next_sequence, queued_bytes, queued_messages) VALUES (?, ?, ?, ?) ON CONFLICT(destination_participant_id) DO UPDATE SET next_sequence = excluded.next_sequence, queued_bytes = excluded.queued_bytes, queued_messages = excluded.queued_messages")
            .bind(snapshot.destination.to_string()).bind(sequence.checked_add(1).ok_or(StoreError::Corrupt)?)
            .bind(i64::try_from(new_queued).map_err(|_| StoreError::Corrupt)?)
            .bind(i64::try_from(new_count).map_err(|_| StoreError::Corrupt)?)
            .execute(&mut *transaction).await.map_err(map_sqlx)?;
        crash_at("mailbox.enqueue.after_counter");
        append_message_event(
            &mut transaction,
            command.context.request_id(),
            &snapshot,
            observed_at,
        )
        .await?;
        record_json(
            &mut transaction,
            command.session_id,
            &command,
            &Some(snapshot.clone()),
        )
        .await?;
        crash_at("mailbox.enqueue.after_ledger");
        crash_at("mailbox.enqueue.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("mailbox.enqueue.after_commit");
        Ok(Mutation::Applied(snapshot))
    }

    #[expect(clippy::too_many_lines, reason = "single atomic mailbox transaction")]
    async fn lease_next_message(
        &self,
        command: LeaseNextMessage,
    ) -> Result<Mutation<Option<MessageSnapshot>>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(replayed) =
            replay_json::<Option<MessageSnapshot>>(&mut transaction, &command).await?
        {
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Replayed(replayed));
        }
        let Some(duration) = u64::try_from(command.lease_duration.as_millis())
            .ok()
            .and_then(|value| LeaseDuration::from_millis(value).ok())
        else {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::LeaseTooLong,
            )
            .await?);
        };
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        let now = load_session_in(&mut transaction, command.session_id)
            .await?
            .ok_or(StoreError::Corrupt)?
            .time_floor;
        let expires_at = match self.expiry(now, duration) {
            Ok(value) => value,
            Err(error) => {
                return Err(
                    finish_failure(transaction, command.session_id, &command, error).await?,
                );
            }
        };
        let rows: Vec<SqliteRow> = sqlx::query("SELECT message_id, session_id, source_participant_id, destination_participant_id, mailbox_sequence, priority, snapshot FROM messages WHERE session_id = ? AND destination_participant_id = ? ORDER BY priority, mailbox_sequence")
            .bind(command.session_id.to_string()).bind(command.destination.to_string()).fetch_all(&mut *transaction).await.map_err(map_sqlx)?;
        let messages = rows
            .into_iter()
            .map(|row| decode_message_row(&row))
            .collect::<Result<Vec<_>, _>>()?;
        let recovery = messages.iter().position(|message| match &message.state {
            MessageDeliveryState::AcceptancePending { lease }
            | MessageDeliveryState::AcceptanceUnknown { lease } => lease.expires_at <= now,
            _ => false,
        });
        let has_active_lease = messages.iter().any(|message| match &message.state {
            MessageDeliveryState::Leased { lease }
            | MessageDeliveryState::AcceptancePending { lease }
            | MessageDeliveryState::AcceptanceUnknown { lease } => lease.expires_at > now,
            _ => false,
        });
        if recovery.is_none() && has_active_lease {
            record_json(
                &mut transaction,
                command.session_id,
                &command,
                &Option::<MessageSnapshot>::None,
            )
            .await?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Applied(None));
        }
        let head = messages
            .iter()
            .enumerate()
            .find(|(_, message)| {
                message.priority == MessagePriority::Control && !message.state.is_terminal()
            })
            .or_else(|| {
                messages.iter().enumerate().find(|(_, message)| {
                    message.priority == MessagePriority::Ordinary && !message.state.is_terminal()
                })
            });
        let eligible = head.and_then(|(index, head)| match &head.state {
            MessageDeliveryState::Queued => Some(index),
            MessageDeliveryState::RetryScheduled { not_before } if *not_before <= now => {
                Some(index)
            }
            MessageDeliveryState::Leased { lease } if lease.expires_at <= now => Some(index),
            _ => None,
        });
        let selected = recovery.or(eligible).map(|index| messages[index].clone());
        let Some(mut snapshot) = selected else {
            record_json(
                &mut transaction,
                command.session_id,
                &command,
                &Option::<MessageSnapshot>::None,
            )
            .await?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Applied(None));
        };
        if matches!(
            snapshot.state,
            MessageDeliveryState::AcceptancePending { .. }
                | MessageDeliveryState::AcceptanceUnknown { .. }
        ) {
            let replacement = |lease: &DeliveryLease| DeliveryLease {
                attempt_id: lease.attempt_id,
                owner: command.context.caller(),
                ownership_epoch: command.epoch,
                driver_ownership_epoch: lease.driver_ownership_epoch,
                driver_launch_attempt_id: lease.driver_launch_attempt_id,
                instance_id: lease.instance_id,
                expires_at,
            };
            snapshot.state = match &snapshot.state {
                MessageDeliveryState::AcceptancePending { lease } => {
                    MessageDeliveryState::AcceptancePending {
                        lease: replacement(lease),
                    }
                }
                MessageDeliveryState::AcceptanceUnknown { lease } => {
                    MessageDeliveryState::AcceptanceUnknown {
                        lease: replacement(lease),
                    }
                }
                _ => unreachable!(),
            };
            snapshot.revision = snapshot.revision.next().ok_or(StoreError::Corrupt)?;
            snapshot.updated_at = now;
            update_message_snapshot(&mut transaction, &snapshot).await?;
            append_message_event(
                &mut transaction,
                command.context.request_id(),
                &snapshot,
                observed_at,
            )
            .await?;
            record_json(
                &mut transaction,
                command.session_id,
                &command,
                &Some(snapshot.clone()),
            )
            .await?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Applied(Some(snapshot)));
        }
        let instance_valid: Option<i64> = sqlx::query_scalar("SELECT 1 FROM launch_attempts WHERE attempt_id = ? AND session_id = ? AND ownership_epoch = ? AND participant_id = ? AND instance_id = ? AND state = 'ready' LIMIT 1")
            .bind(command.driver_launch_attempt_id.to_string()).bind(command.session_id.to_string()).bind(to_i64(command.epoch.get())?).bind(command.destination.to_string()).bind(command.instance_id.to_string())
            .fetch_optional(&mut *transaction).await.map_err(map_sqlx)?;
        if instance_valid.is_none() {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        if snapshot.attempt_count >= MAX_DELIVERY_ATTEMPTS {
            snapshot.revision = snapshot.revision.next().ok_or(StoreError::Corrupt)?;
            snapshot.updated_at = now;
            snapshot.state = MessageDeliveryState::DeadLetter {
                reason: BoundedText::new("delivery attempt limit exhausted".to_owned())
                    .map_err(|_| StoreError::Corrupt)?,
            };
            update_message_snapshot(&mut transaction, &snapshot).await?;
            decrement_mailbox_bytes(&mut transaction, &snapshot).await?;
            append_message_event(
                &mut transaction,
                command.context.request_id(),
                &snapshot,
                observed_at,
            )
            .await?;
            record_json(
                &mut transaction,
                command.session_id,
                &command,
                &Some(snapshot.clone()),
            )
            .await?;
            transaction.commit().await.map_err(map_sqlx)?;
            return Ok(Mutation::Applied(Some(snapshot)));
        }
        snapshot.attempt_count += 1;
        snapshot.revision = snapshot.revision.next().ok_or(StoreError::Corrupt)?;
        snapshot.updated_at = now;
        snapshot.state = MessageDeliveryState::Leased {
            lease: DeliveryLease {
                attempt_id: command.proposed_attempt_id,
                owner: command.context.caller(),
                ownership_epoch: command.epoch,
                driver_ownership_epoch: command.epoch,
                driver_launch_attempt_id: command.driver_launch_attempt_id,
                instance_id: command.instance_id,
                expires_at,
            },
        };
        update_message_snapshot(&mut transaction, &snapshot).await?;
        crash_at("mailbox.lease.after_message");
        append_message_event(
            &mut transaction,
            command.context.request_id(),
            &snapshot,
            observed_at,
        )
        .await?;
        record_json(
            &mut transaction,
            command.session_id,
            &command,
            &Some(snapshot.clone()),
        )
        .await?;
        crash_at("mailbox.lease.after_ledger");
        crash_at("mailbox.lease.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("mailbox.lease.after_commit");
        Ok(Mutation::Applied(Some(snapshot)))
    }

    #[expect(clippy::too_many_lines, reason = "single atomic mailbox transaction")]
    async fn transition_message_delivery(
        &self,
        command: TransitionMessageDelivery,
    ) -> Result<Mutation<MessageSnapshot>, StoreError> {
        let observed_at = self.now();
        let mut transaction = begin_immediate(&self.pool).await?;
        if let Some(replayed) =
            replay_json::<Option<MessageSnapshot>>(&mut transaction, &command).await?
        {
            transaction.commit().await.map_err(map_sqlx)?;
            return replayed.map(Mutation::Replayed).ok_or(StoreError::Corrupt);
        }
        if let Err(error) = authorize_launch(
            &mut transaction,
            command.session_id,
            command.context,
            command.epoch,
            command.action(),
            observed_at,
        )
        .await
        {
            return Err(finish_failure(transaction, command.session_id, &command, error).await?);
        }
        let now = load_session_in(&mut transaction, command.session_id)
            .await?
            .ok_or(StoreError::Corrupt)?
            .time_floor;
        let retry_not_before = if let DeliveryTransition::RetryAfter { delay } = &command.transition
        {
            let duration = u64::try_from(delay.as_millis())
                .ok()
                .and_then(|millis| LeaseDuration::from_millis(millis).ok());
            let Some(duration) = duration else {
                return Err(finish_failure(
                    transaction,
                    command.session_id,
                    &command,
                    StoreError::LeaseTooLong,
                )
                .await?);
            };
            match self.expiry(now, duration) {
                Ok(value) => Some(value),
                Err(error) => {
                    return Err(
                        finish_failure(transaction, command.session_id, &command, error).await?,
                    );
                }
            }
        } else {
            None
        };
        let Some(mut snapshot) = load_message_in(&mut transaction, command.message_id).await?
        else {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::MessageNotFound {
                    message_id: command.message_id,
                },
            )
            .await?);
        };
        if snapshot.session_id != command.session_id
            || snapshot.revision != command.expected_revision
            || snapshot.state.is_terminal()
        {
            return Err(finish_failure(
                transaction,
                command.session_id,
                &command,
                StoreError::Invalid,
            )
            .await?);
        }
        let lease = match &snapshot.state {
            MessageDeliveryState::Leased { lease }
                if lease.attempt_id == command.attempt_id
                    && lease.owner == command.context.caller()
                    && lease.ownership_epoch == command.epoch
                    && now < lease.expires_at =>
            {
                lease.clone()
            }
            MessageDeliveryState::AcceptancePending { lease }
            | MessageDeliveryState::AcceptanceUnknown { lease }
                if lease.attempt_id == command.attempt_id
                    && lease.owner == command.context.caller()
                    && lease.ownership_epoch == command.epoch =>
            {
                lease.clone()
            }
            _ => {
                return Err(finish_failure(
                    transaction,
                    command.session_id,
                    &command,
                    StoreError::Invalid,
                )
                .await?);
            }
        };
        if matches!(command.transition, DeliveryTransition::RetryAfter { .. }) {
            ensure_derived_capacity(
                &mut transaction,
                &self.limit_profile,
                command.session_id,
                CapacityResource::Retries,
                1,
            )
            .await?;
        }
        ensure_derived_capacity(
            &mut transaction,
            &self.limit_profile,
            command.session_id,
            CapacityResource::RetainedEvents,
            1,
        )
        .await?;
        snapshot.state = match &command.transition {
            DeliveryTransition::AcceptancePending
                if matches!(snapshot.state, MessageDeliveryState::Leased { .. }) =>
            {
                MessageDeliveryState::AcceptancePending { lease }
            }
            DeliveryTransition::AcceptanceUnknown
                if matches!(
                    snapshot.state,
                    MessageDeliveryState::AcceptancePending { .. }
                ) =>
            {
                MessageDeliveryState::AcceptanceUnknown { lease }
            }
            DeliveryTransition::RetryAfter { delay }
                if matches!(
                    snapshot.state,
                    MessageDeliveryState::AcceptancePending { .. }
                        | MessageDeliveryState::AcceptanceUnknown { .. }
                ) =>
            {
                MessageDeliveryState::RetryScheduled {
                    not_before: retry_not_before.ok_or(StoreError::Corrupt)?,
                }
            }
            DeliveryTransition::Accepted { proof_digest }
                if matches!(
                    snapshot.state,
                    MessageDeliveryState::AcceptancePending { .. }
                        | MessageDeliveryState::AcceptanceUnknown { .. }
                ) =>
            {
                MessageDeliveryState::Accepted {
                    attempt_id: command.attempt_id,
                    proof_digest: *proof_digest,
                    accepted_at: now,
                }
            }
            DeliveryTransition::Uncertain { reason }
                if matches!(
                    snapshot.state,
                    MessageDeliveryState::AcceptancePending { .. }
                        | MessageDeliveryState::AcceptanceUnknown { .. }
                ) =>
            {
                MessageDeliveryState::Uncertain {
                    attempt_id: command.attempt_id,
                    reason: reason.clone(),
                }
            }
            DeliveryTransition::DeadLetter { reason } => MessageDeliveryState::DeadLetter {
                reason: reason.clone(),
            },
            _ => {
                return Err(finish_failure(
                    transaction,
                    command.session_id,
                    &command,
                    StoreError::Invalid,
                )
                .await?);
            }
        };
        snapshot.revision = snapshot.revision.next().ok_or(StoreError::Corrupt)?;
        snapshot.updated_at = now;
        update_message_snapshot(&mut transaction, &snapshot).await?;
        crash_at("mailbox.transition.after_message_state");
        append_message_event(
            &mut transaction,
            command.context.request_id(),
            &snapshot,
            observed_at,
        )
        .await?;
        crash_at("mailbox.transition.after_message_event");
        if matches!(snapshot.state, MessageDeliveryState::Accepted { .. })
            && let navigator_domain::MessageBody::CorrelatedFeedback {
                operation_id,
                in_reply_to,
                ..
            } = snapshot.envelope.body()
        {
            let Some(mut operation) = load_operation_in(&mut transaction, *operation_id).await?
            else {
                return Err(StoreError::Corrupt);
            };
            if operation.session_id == command.session_id
                && operation.participant_id == snapshot.destination
                && operation.state == OperationState::Waiting
                && operation.waiting_on_message_id == Some(*in_reply_to)
            {
                let previous_revision = operation.revision;
                operation.state = OperationState::Running;
                operation.waiting_on_message_id = None;
                operation.revision = operation.revision.next().ok_or(StoreError::Corrupt)?;
                operation.updated_at = now.max(operation.updated_at);
                let changed = sqlx::query("UPDATE operations SET state='running', waiting_on_message_id=NULL, revision=?, updated_at_seconds=?, updated_at_nanos=? WHERE operation_id=? AND revision=? AND state='waiting' AND waiting_on_message_id=?")
                .bind(to_i64(operation.revision.get())?)
                .bind(operation.updated_at.unix_seconds())
                .bind(i64::from(operation.updated_at.nanoseconds()))
                .bind(operation.operation_id.to_string())
                .bind(to_i64(previous_revision.get())?)
                .bind(in_reply_to.to_string())
                .execute(&mut *transaction)
                .await
                .map_err(map_sqlx)?;
                if changed.rows_affected() != 1 {
                    return Err(StoreError::Corrupt);
                }
                crash_at("mailbox.transition.after_operation_state");
                append_event_data(
                    &mut transaction,
                    command.context.request_id(),
                    command.session_id,
                    operation.revision,
                    "operation.resumed",
                    &operation_event_payload(&operation)?,
                    observed_at,
                )
                .await?;
                crash_at("mailbox.transition.after_operation_event");
            }
        }
        crash_at("mailbox.transition.after_message");
        if snapshot.state.is_terminal() {
            decrement_mailbox_bytes(&mut transaction, &snapshot).await?;
            crash_at("mailbox.transition.after_counter");
        }
        record_json(
            &mut transaction,
            command.session_id,
            &command,
            &Some(snapshot.clone()),
        )
        .await?;
        crash_at("mailbox.transition.after_ledger");
        crash_at("mailbox.transition.before_commit");
        transaction.commit().await.map_err(map_sqlx)?;
        crash_at("mailbox.transition.after_commit");
        Ok(Mutation::Applied(snapshot))
    }

    async fn load_message(&self, message_id: MessageId) -> Result<MessageSnapshot, StoreError> {
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let value = load_message_in(&mut transaction, message_id)
            .await?
            .ok_or(StoreError::MessageNotFound { message_id })?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(value)
    }

    async fn load_mailbox(
        &self,
        destination: ParticipantId,
    ) -> Result<Vec<MessageSnapshot>, StoreError> {
        let rows: Vec<SqliteRow> = sqlx::query("SELECT message_id, session_id, source_participant_id, destination_participant_id, mailbox_sequence, priority, snapshot FROM messages WHERE destination_participant_id = ? ORDER BY mailbox_sequence")
            .bind(destination.to_string()).fetch_all(&self.pool).await.map_err(map_sqlx)?;
        rows.into_iter()
            .map(|row| decode_message_row(&row))
            .collect()
    }

    async fn load_due_session_delivery_work(
        &self,
        session_id: SessionId,
        limit: usize,
    ) -> Result<Vec<SessionDeliveryWork>, StoreError> {
        if limit == 0 || limit > MAX_SESSION_DELIVERY_WORK {
            return Err(StoreError::Invalid);
        }
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let now = self.now().max(
            load_session_in(&mut transaction, session_id)
                .await?
                .ok_or(StoreError::Invalid)?
                .time_floor,
        );
        let rows: Vec<SqliteRow> = sqlx::query(DUE_SESSION_DELIVERY_WORK_SQL)
            .bind(now.unix_seconds())
            .bind(now.unix_seconds())
            .bind(i64::from(now.nanoseconds()))
            .bind(now.unix_seconds())
            .bind(now.unix_seconds())
            .bind(i64::from(now.nanoseconds()))
            .bind(session_id.to_string())
            .bind(now.unix_seconds())
            .bind(now.unix_seconds())
            .bind(i64::from(now.nanoseconds()))
            .bind(i64::try_from(limit).map_err(|_| StoreError::Invalid)?)
            .fetch_all(&mut *transaction)
            .await
            .map_err(map_sqlx)?;
        let mut work = Vec::with_capacity(rows.len());
        for row in &rows {
            let message = decode_message_row(row)?;
            let operation_id = row
                .try_get::<Option<String>, _>("active_operation_id")
                .map_err(map_sqlx)?
                .ok_or(StoreError::Corrupt)
                .and_then(|value| parse_operation_id(&value))?;
            let operation = load_operation_in(&mut transaction, operation_id)
                .await?
                .filter(|operation| {
                    operation.session_id == session_id
                        && operation.participant_id == message.destination
                        && !operation.state.is_terminal()
                })
                .ok_or(StoreError::Corrupt)?;
            work.push(SessionDeliveryWork { message, operation });
        }
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(work)
    }
}

async fn load_message_in(
    transaction: &mut Transaction<'_, Sqlite>,
    message_id: MessageId,
) -> Result<Option<MessageSnapshot>, StoreError> {
    let row: Option<SqliteRow> =
        sqlx::query("SELECT message_id, session_id, source_participant_id, destination_participant_id, mailbox_sequence, priority, snapshot FROM messages WHERE message_id = ?")
            .bind(message_id.to_string())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(map_sqlx)?;
    row.as_ref().map(decode_message_row).transpose()
}

fn decode_message_row(row: &SqliteRow) -> Result<MessageSnapshot, StoreError> {
    let bytes: Vec<u8> = row.try_get("snapshot").map_err(map_sqlx)?;
    let snapshot: MessageSnapshot =
        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
    let expected_priority = match snapshot.priority {
        MessagePriority::Control => 0_i64,
        MessagePriority::Ordinary => 1_i64,
    };
    if row.try_get::<String, _>("message_id").map_err(map_sqlx)? != snapshot.message_id.to_string()
        || row.try_get::<String, _>("session_id").map_err(map_sqlx)?
            != snapshot.session_id.to_string()
        || row
            .try_get::<String, _>("source_participant_id")
            .map_err(map_sqlx)?
            != snapshot.source.to_string()
        || row
            .try_get::<String, _>("destination_participant_id")
            .map_err(map_sqlx)?
            != snapshot.destination.to_string()
        || row
            .try_get::<i64, _>("mailbox_sequence")
            .map_err(map_sqlx)?
            != i64::try_from(snapshot.mailbox_sequence).map_err(|_| StoreError::Corrupt)?
        || row.try_get::<i64, _>("priority").map_err(map_sqlx)? != expected_priority
        || !snapshot.is_structurally_valid()
    {
        return Err(StoreError::Corrupt);
    }
    Ok(snapshot)
}

async fn update_message_snapshot(
    transaction: &mut Transaction<'_, Sqlite>,
    snapshot: &MessageSnapshot,
) -> Result<(), StoreError> {
    let result = sqlx::query("UPDATE messages SET snapshot = ? WHERE message_id = ?")
        .bind(serde_json::to_vec(snapshot).map_err(|_| StoreError::Corrupt)?)
        .bind(snapshot.message_id.to_string())
        .execute(&mut **transaction)
        .await
        .map_err(map_sqlx)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(StoreError::Corrupt)
    }
}

async fn decrement_mailbox_bytes(
    transaction: &mut Transaction<'_, Sqlite>,
    snapshot: &MessageSnapshot,
) -> Result<(), StoreError> {
    let bytes =
        i64::try_from(snapshot.envelope.as_bytes().len()).map_err(|_| StoreError::Corrupt)?;
    let result = sqlx::query("UPDATE mailbox_counters SET queued_bytes = queued_bytes - ?, queued_messages = queued_messages - 1 WHERE destination_participant_id = ? AND queued_bytes >= ? AND queued_messages > 0")
        .bind(bytes).bind(snapshot.destination.to_string()).bind(bytes)
        .execute(&mut **transaction).await.map_err(map_sqlx)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(StoreError::Corrupt)
    }
}

async fn begin_immediate(pool: &SqlitePool) -> Result<Transaction<'static, Sqlite>, StoreError> {
    pool.begin_with("BEGIN IMMEDIATE").await.map_err(map_sqlx)
}

async fn authorize_artifact(
    tx: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    owner: HostId,
    epoch: FencingEpoch,
    observed: Timestamp,
) -> Result<(), StoreError> {
    let row = require_open_session(tx, session_id, StoreAction::PublishArtifact).await?;
    let now = advance_time_floor(tx, session_id, row.time_floor, observed).await?;
    require_owner(&row, owner, epoch, now)
}

fn decode_artifact(row: &SqliteRow) -> Result<ArtifactSnapshot, StoreError> {
    let state = match row
        .try_get::<String, _>("state")
        .map_err(map_sqlx)?
        .as_str()
    {
        "available" => ArtifactState::Available,
        "logically_deleted" => ArtifactState::LogicallyDeleted,
        "physically_erased" => ArtifactState::PhysicallyErased,
        _ => return Err(StoreError::Corrupt),
    };
    let digest: [u8; 32] = row
        .try_get::<Vec<u8>, _>("digest")
        .map_err(map_sqlx)?
        .try_into()
        .map_err(|_| StoreError::Corrupt)?;
    let deleted_seconds: Option<i64> = row.try_get("deleted_seconds").map_err(map_sqlx)?;
    let deleted_nanos: Option<i64> = row.try_get("deleted_nanos").map_err(map_sqlx)?;
    let snapshot = ArtifactSnapshot {
        artifact_id: ArtifactId::from_uuid(
            Uuid::parse_str(&row.try_get::<String, _>("artifact_id").map_err(map_sqlx)?)
                .map_err(|_| StoreError::Corrupt)?,
        )
        .map_err(|_| StoreError::Corrupt)?,
        session_id: parse_session_id(&row.try_get::<String, _>("session_id").map_err(map_sqlx)?)?,
        creator_participant_id: parse_participant_id(
            &row.try_get::<Option<String>, _>("creator_participant_id")
                .map_err(map_sqlx)?
                .ok_or(StoreError::Corrupt)?,
        )?,
        creator_operation_id: parse_operation_id(
            &row.try_get::<Option<String>, _>("creator_operation_id")
                .map_err(map_sqlx)?
                .ok_or(StoreError::Corrupt)?,
        )?,
        media_type: ArtifactMediaType::new(
            row.try_get::<String, _>("media_type").map_err(map_sqlx)?,
        )
        .map_err(|_| StoreError::Corrupt)?,
        size: u64::try_from(row.try_get::<i64, _>("size").map_err(map_sqlx)?)
            .map_err(|_| StoreError::Corrupt)?,
        digest: ArtifactDigest::from_bytes(digest),
        locator: row.try_get("locator").map_err(map_sqlx)?,
        state,
        revision: Revision::new(
            u64::try_from(row.try_get::<i64, _>("revision").map_err(map_sqlx)?)
                .map_err(|_| StoreError::Corrupt)?,
        )
        .map_err(|_| StoreError::Corrupt)?,
        retention_until: decode_timestamp(
            row.try_get("retention_seconds").map_err(map_sqlx)?,
            row.try_get("retention_nanos").map_err(map_sqlx)?,
        )?,
        created_at: decode_timestamp(
            row.try_get("created_seconds").map_err(map_sqlx)?,
            row.try_get("created_nanos").map_err(map_sqlx)?,
        )?,
        deleted_at: match (deleted_seconds, deleted_nanos) {
            (None, None) => None,
            (Some(s), Some(n)) => Some(decode_timestamp(s, n)?),
            _ => return Err(StoreError::Corrupt),
        },
    };
    snapshot
        .structurally_valid()
        .then_some(snapshot)
        .ok_or(StoreError::Corrupt)
}

async fn load_artifact_in(
    tx: &mut Transaction<'_, Sqlite>,
    artifact_id: ArtifactId,
) -> Result<Option<ArtifactSnapshot>, StoreError> {
    sqlx::query("SELECT * FROM artifacts WHERE artifact_id = ?")
        .bind(artifact_id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx)?
        .as_ref()
        .map(decode_artifact)
        .transpose()
}

async fn transition_artifact(
    store: &SqliteStore,
    request: DeleteArtifact,
    erased: bool,
) -> Result<Mutation<ArtifactSnapshot>, StoreError> {
    let mut tx = begin_immediate(&store.pool).await?;
    if let Some(snapshot) = replay_json::<ArtifactSnapshot>(&mut tx, &request).await? {
        tx.commit().await.map_err(map_sqlx)?;
        return Ok(Mutation::Replayed(snapshot));
    }
    authorize_artifact(
        &mut tx,
        request.session_id,
        request.owner,
        request.epoch,
        store.now(),
    )
    .await?;
    let mut snapshot = load_artifact_in(&mut tx, request.artifact_id)
        .await?
        .ok_or(StoreError::ArtifactNotFound {
            artifact_id: request.artifact_id,
        })?;
    if snapshot.session_id != request.session_id || erased {
        return Err(StoreError::Invalid);
    }
    if snapshot.state != ArtifactState::Available {
        return Err(StoreError::Invalid);
    }
    let now = store.now();
    snapshot.state = ArtifactState::LogicallyDeleted;
    snapshot.deleted_at = Some(now);
    snapshot.revision = snapshot.revision.next().ok_or(StoreError::Corrupt)?;
    sqlx::query("UPDATE artifacts SET state='logically_deleted',revision=?,deleted_seconds=?,deleted_nanos=? WHERE artifact_id=? AND revision=?")
        .bind(to_i64(snapshot.revision.get())?).bind(now.unix_seconds()).bind(i64::from(now.nanoseconds()))
        .bind(snapshot.artifact_id.to_string()).bind(to_i64(snapshot.revision.get()-1)?).execute(&mut *tx).await.map_err(map_sqlx)?;
    append_event(
        &mut tx,
        request.context.request_id(),
        request.session_id,
        snapshot.revision,
        "artifact.logically_deleted",
        now,
    )
    .await?;
    record_json(&mut tx, request.session_id, &request, &snapshot).await?;
    tx.commit().await.map_err(map_sqlx)?;
    Ok(Mutation::Applied(snapshot))
}

async fn transition_erased(
    store: &SqliteStore,
    request: EraseArtifact,
) -> Result<Mutation<ArtifactSnapshot>, StoreError> {
    let mut tx = begin_immediate(&store.pool).await?;
    if let Some(snapshot) = replay_json::<ArtifactSnapshot>(&mut tx, &request).await? {
        tx.commit().await.map_err(map_sqlx)?;
        return Ok(Mutation::Replayed(snapshot));
    }
    authorize_artifact(
        &mut tx,
        request.session_id,
        request.owner,
        request.epoch,
        store.now(),
    )
    .await?;
    let mut snapshot = load_artifact_in(&mut tx, request.artifact_id)
        .await?
        .ok_or(StoreError::ArtifactNotFound {
            artifact_id: request.artifact_id,
        })?;
    if snapshot.session_id != request.session_id
        || snapshot.state != ArtifactState::LogicallyDeleted
        || snapshot.retention_until > store.now()
    {
        return Err(StoreError::Invalid);
    }
    snapshot.state = ArtifactState::PhysicallyErased;
    snapshot.revision = snapshot.revision.next().ok_or(StoreError::Corrupt)?;
    sqlx::query("UPDATE artifacts SET state='physically_erased',revision=? WHERE artifact_id=? AND revision=?")
        .bind(to_i64(snapshot.revision.get())?).bind(snapshot.artifact_id.to_string()).bind(to_i64(snapshot.revision.get()-1)?).execute(&mut *tx).await.map_err(map_sqlx)?;
    let now = store.now();
    append_event(
        &mut tx,
        request.context.request_id(),
        request.session_id,
        snapshot.revision,
        "artifact.physically_erased",
        now,
    )
    .await?;
    record_json(&mut tx, request.session_id, &request, &snapshot).await?;
    tx.commit().await.map_err(map_sqlx)?;
    Ok(Mutation::Applied(snapshot))
}

async fn authorize_launch(
    transaction: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    context: navigator_store_api::RequestContext,
    epoch: FencingEpoch,
    action: StoreAction,
    observed_at: Timestamp,
) -> Result<(), StoreError> {
    let row = require_open_session(transaction, session_id, action).await?;
    let now = advance_time_floor(transaction, session_id, row.time_floor, observed_at).await?;
    require_owner(&row, context.caller(), epoch, now)
}

async fn insert_launch(
    transaction: &mut Transaction<'_, Sqlite>,
    snapshot: &LaunchSnapshot,
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO launch_attempts (
            attempt_id, session_id, ownership_epoch, participant_id, driver_id, instance_id, state,
            revision, credential_digest, driver_configuration_digest, evidence, cleanup_reason
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(snapshot.attempt_id.to_string())
    .bind(snapshot.session_id.to_string())
    .bind(
        snapshot
            .ownership_epoch
            .map(FencingEpoch::get)
            .map(to_i64)
            .transpose()?,
    )
    .bind(snapshot.participant_id.to_string())
    .bind(snapshot.driver_id.to_string())
    .bind(snapshot.instance_id.map(|id| id.to_string()))
    .bind(launch_state_name(snapshot.state))
    .bind(to_i64(snapshot.revision.get())?)
    .bind(snapshot.credential_digest.to_vec())
    .bind(snapshot.driver_configuration_digest.to_vec())
    .bind(encode_evidence(snapshot.evidence.as_ref())?)
    .bind(snapshot.cleanup_reason.as_ref().map(BoundedText::as_str))
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

async fn update_launch(
    transaction: &mut Transaction<'_, Sqlite>,
    snapshot: &LaunchSnapshot,
    expected_revision: Revision,
) -> Result<(), StoreError> {
    let result = sqlx::query(
        "UPDATE launch_attempts SET instance_id = ?, state = ?, revision = ?, evidence = ?,
         cleanup_reason = ? WHERE attempt_id = ? AND revision = ?",
    )
    .bind(snapshot.instance_id.map(|id| id.to_string()))
    .bind(launch_state_name(snapshot.state))
    .bind(to_i64(snapshot.revision.get())?)
    .bind(encode_evidence(snapshot.evidence.as_ref())?)
    .bind(snapshot.cleanup_reason.as_ref().map(BoundedText::as_str))
    .bind(snapshot.attempt_id.to_string())
    .bind(to_i64(expected_revision.get())?)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    if result.rows_affected() == 1 {
        Ok(())
    } else {
        Err(StoreError::Invalid)
    }
}

async fn load_launch_in(
    transaction: &mut Transaction<'_, Sqlite>,
    attempt_id: LaunchAttemptId,
) -> Result<Option<LaunchSnapshot>, StoreError> {
    sqlx::query("SELECT * FROM launch_attempts WHERE attempt_id = ?")
        .bind(attempt_id.to_string())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_sqlx)?
        .map(|row| decode_launch(&row))
        .transpose()
}

fn decode_launch(row: &sqlx::sqlite::SqliteRow) -> Result<LaunchSnapshot, StoreError> {
    let attempt_id =
        parse_launch_attempt(&row.try_get::<String, _>("attempt_id").map_err(map_sqlx)?)?;
    let credential: Vec<u8> = row.try_get("credential_digest").map_err(map_sqlx)?;
    let driver_configuration: Vec<u8> = row
        .try_get("driver_configuration_digest")
        .map_err(map_sqlx)?;
    Ok(LaunchSnapshot {
        session_id: parse_session_id(&row.try_get::<String, _>("session_id").map_err(map_sqlx)?)?,
        ownership_epoch: row
            .try_get::<Option<i64>, _>("ownership_epoch")
            .map_err(map_sqlx)?
            .map(|value| {
                FencingEpoch::new(u64::try_from(value).map_err(|_| StoreError::Corrupt)?)
                    .map_err(|_| StoreError::Corrupt)
            })
            .transpose()?,
        participant_id: parse_participant_id(
            &row.try_get::<String, _>("participant_id")
                .map_err(map_sqlx)?,
        )?,
        driver_id: parse_driver_id(&row.try_get::<String, _>("driver_id").map_err(map_sqlx)?)?,
        driver_configuration_digest: driver_configuration
            .try_into()
            .map_err(|_| StoreError::Corrupt)?,
        attempt_id,
        instance_id: row
            .try_get::<Option<String>, _>("instance_id")
            .map_err(map_sqlx)?
            .map(|value| parse_instance_id(&value))
            .transpose()?,
        state: parse_launch_state(&row.try_get::<String, _>("state").map_err(map_sqlx)?)?,
        revision: decode_revision(row.try_get("revision").map_err(map_sqlx)?)?,
        credential_digest: credential.try_into().map_err(|_| StoreError::Corrupt)?,
        evidence: row
            .try_get::<Option<Vec<u8>>, _>("evidence")
            .map_err(map_sqlx)?
            .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt))
            .transpose()?,
        cleanup_reason: row
            .try_get::<Option<String>, _>("cleanup_reason")
            .map_err(map_sqlx)?
            .map(BoundedText::new)
            .transpose()
            .map_err(|_| StoreError::Corrupt)?,
    })
}

fn encode_evidence(evidence: Option<&ProcessEvidence>) -> Result<Option<Vec<u8>>, StoreError> {
    evidence
        .map(|value| serde_json::to_vec(value).map_err(|_| StoreError::Corrupt))
        .transpose()
}

fn valid_launch_transition(from: LaunchState, to: LaunchState) -> bool {
    matches!(
        (from, to),
        (LaunchState::Attached, LaunchState::Ready)
            | (
                LaunchState::Attached | LaunchState::Ready,
                LaunchState::Stopping
            )
            | (
                LaunchState::Prepared
                    | LaunchState::Attached
                    | LaunchState::Ready
                    | LaunchState::Stopping
                    | LaunchState::CleanupRequired,
                LaunchState::CleanupRequired
            )
            | (
                LaunchState::Stopping | LaunchState::CleanupRequired,
                LaunchState::Stopped
            )
    )
}

fn launch_state_name(state: LaunchState) -> &'static str {
    match state {
        LaunchState::Prepared => "prepared",
        LaunchState::Attached => "attached",
        LaunchState::Ready => "ready",
        LaunchState::Stopping => "stopping",
        LaunchState::Stopped => "stopped",
        LaunchState::CleanupRequired => "cleanup_required",
    }
}

fn parse_launch_state(value: &str) -> Result<LaunchState, StoreError> {
    match value {
        "prepared" => Ok(LaunchState::Prepared),
        "attached" => Ok(LaunchState::Attached),
        "ready" => Ok(LaunchState::Ready),
        "stopping" => Ok(LaunchState::Stopping),
        "stopped" => Ok(LaunchState::Stopped),
        "cleanup_required" => Ok(LaunchState::CleanupRequired),
        _ => Err(StoreError::Corrupt),
    }
}

const SESSION_SELECT: &str =
    "SELECT session_id, consumer_key, public_consumer_key, compatibility_identity, revision, closed,
     created_at_seconds, created_at_nanos, updated_at_seconds, updated_at_nanos,
     owner_host_id, owner_epoch, owner_expires_at_seconds, owner_expires_at_nanos,
     epoch_high_water, observed_time_floor_seconds, observed_time_floor_nanos
     FROM sessions WHERE session_id = ?";

async fn load_session_from_pool(
    pool: &SqlitePool,
    session_id: SessionId,
) -> Result<Option<SessionRow>, StoreError> {
    sqlx::query(SESSION_SELECT)
        .bind(session_id.to_string())
        .fetch_optional(pool)
        .await
        .map_err(map_sqlx)?
        .map(|row| decode_session(&row))
        .transpose()
}

async fn load_session_in(
    transaction: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
) -> Result<Option<SessionRow>, StoreError> {
    sqlx::query(SESSION_SELECT)
        .bind(session_id.to_string())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_sqlx)?
        .map(|row| decode_session(&row))
        .transpose()
}

async fn require_open_session(
    transaction: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    action: StoreAction,
) -> Result<SessionRow, StoreError> {
    let row = load_session_in(transaction, session_id)
        .await?
        .ok_or(StoreError::SessionNotFound { session_id })?;
    if row.snapshot.status() == SessionStatus::Closed {
        return Err(if action == StoreAction::CloseSession {
            StoreError::AlreadyClosed { session_id }
        } else {
            StoreError::SessionClosed { session_id }
        });
    }
    Ok(row)
}

fn ownership_snapshot(lease: &OwnershipLease) -> OwnershipSnapshot {
    OwnershipSnapshot::Owned {
        host_id: lease.owner(),
        epoch: lease.epoch(),
        expires_at: lease.expires_at(),
    }
}

fn validate_open_replay(
    snapshot: &SessionSnapshot,
    command: &OpenSession,
) -> Result<(), StoreError> {
    if snapshot.id() != command.session_id()
        || snapshot.consumer_key() != command.consumer_key()
        || snapshot.compatibility() != command.compatibility()
    {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

async fn validate_session_manifest_in(
    transaction: &mut Transaction<'_, Sqlite>,
    command: &OpenSession,
) -> Result<(), StoreError> {
    let complete: i64 = sqlx::query_scalar(
        "SELECT compatibility_manifest_complete FROM sessions WHERE session_id = ?",
    )
    .bind(command.session_id().to_string())
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    match command.manifest() {
        None if complete == 0 => Ok(()),
        Some(manifest) if complete == 1 => {
            let rows = sqlx::query(
                "SELECT template_id, template_compatibility
                 FROM session_template_manifest WHERE session_id = ? ORDER BY template_id",
            )
            .bind(command.session_id().to_string())
            .fetch_all(&mut **transaction)
            .await
            .map_err(map_sqlx)?;
            if rows.len() != manifest.templates().len() {
                return Err(StoreError::CompatibilityConflict {
                    session_id: command.session_id(),
                    persisted: command.compatibility(),
                    requested: command.compatibility(),
                });
            }
            for (row, expected) in rows.iter().zip(manifest.templates()) {
                let template_id =
                    parse_template_id(&row.try_get::<String, _>("template_id").map_err(map_sqlx)?)?;
                let compatibility = CompatibilityIdentity::from_bytes(
                    row.try_get::<Vec<u8>, _>("template_compatibility")
                        .map_err(map_sqlx)?
                        .try_into()
                        .map_err(|_| StoreError::Corrupt)?,
                );
                if template_id != expected.template_id || compatibility != expected.compatibility {
                    return Err(StoreError::CompatibilityConflict {
                        session_id: command.session_id(),
                        persisted: command.compatibility(),
                        requested: command.compatibility(),
                    });
                }
            }
            Ok(())
        }
        None | Some(_) => Err(StoreError::CompatibilityConflict {
            session_id: command.session_id(),
            persisted: command.compatibility(),
            requested: command.compatibility(),
        }),
    }
}

async fn new_session_manifest_is_registered(
    transaction: &mut Transaction<'_, Sqlite>,
    command: &OpenSession,
) -> Result<bool, StoreError> {
    let Some(manifest) = command.manifest() else {
        return Ok(true);
    };
    for binding in manifest.templates() {
        if !load_template_in(transaction, binding.template_id)
            .await?
            .is_some_and(|template| template.compatibility == binding.compatibility)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn validate_template_set_before_open(
    transaction: &mut Transaction<'_, Sqlite>,
    templates: &[TemplateRecord],
) -> Result<(), StoreError> {
    for template in templates {
        navigator_domain::Template::try_from(template.clone()).map_err(|_| StoreError::Invalid)?;
        if load_template_in(transaction, template.identity)
            .await?
            .is_some_and(|existing| existing != *template)
        {
            return Err(StoreError::Invalid);
        }
    }
    Ok(())
}

async fn validate_registered_templates(
    transaction: &mut Transaction<'_, Sqlite>,
    templates: &[TemplateRecord],
) -> Result<(), StoreError> {
    for template in templates {
        if load_template_in(transaction, template.identity).await? != Some(template.clone()) {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(())
}

async fn insert_missing_templates(
    transaction: &mut Transaction<'_, Sqlite>,
    templates: &[TemplateRecord],
) -> Result<(), StoreError> {
    for template in templates {
        if load_template_in(transaction, template.identity)
            .await?
            .is_none()
        {
            sqlx::query(
                "INSERT INTO templates (template_id, compatibility_identity, registration)
                 VALUES (?, ?, ?)",
            )
            .bind(template.identity.to_string())
            .bind(template.compatibility.as_bytes().as_slice())
            .bind(serde_json::to_vec(template).map_err(|_| StoreError::Invalid)?)
            .execute(&mut **transaction)
            .await
            .map_err(map_sqlx)?;
        }
    }
    Ok(())
}

async fn insert_session_manifest(
    transaction: &mut Transaction<'_, Sqlite>,
    command: &OpenSession,
) -> Result<(), StoreError> {
    let Some(manifest) = command.manifest() else {
        return Ok(());
    };
    for binding in manifest.templates() {
        sqlx::query(
            "INSERT INTO session_template_manifest
             (session_id, template_id, template_compatibility) VALUES (?, ?, ?)",
        )
        .bind(command.session_id().to_string())
        .bind(binding.template_id.to_string())
        .bind(binding.compatibility.as_bytes().as_slice())
        .execute(&mut **transaction)
        .await
        .map_err(map_sqlx)?;
    }
    Ok(())
}

async fn insert_session_row(
    transaction: &mut Transaction<'_, Sqlite>,
    command: &OpenSession,
    now: Timestamp,
) -> Result<(), StoreError> {
    let occupied: i64 =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sessions WHERE consumer_key = ? LIMIT 1)")
            .bind(command.consumer_key().as_str())
            .fetch_one(&mut **transaction)
            .await
            .map_err(map_sqlx)?;
    let storage_key = if occupied == 0 {
        command.consumer_key().as_str().to_owned()
    } else {
        format!("session:{}", command.session_id())
    };
    sqlx::query(
        "INSERT INTO sessions (
            session_id, consumer_key, public_consumer_key, compatibility_identity, revision, closed,
            created_at_seconds, created_at_nanos, updated_at_seconds, updated_at_nanos,
            epoch_high_water, observed_time_floor_seconds, observed_time_floor_nanos,
            compatibility_manifest_complete, compatibility_configuration_identity
         ) VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?, ?, 0, ?, ?, ?, ?)",
    )
    .bind(command.session_id().to_string())
    .bind(storage_key)
    .bind(command.consumer_key().as_str())
    .bind(command.compatibility().as_bytes().as_slice())
    .bind(now.unix_seconds())
    .bind(i64::from(now.nanoseconds()))
    .bind(now.unix_seconds())
    .bind(i64::from(now.nanoseconds()))
    .bind(now.unix_seconds())
    .bind(i64::from(now.nanoseconds()))
    .bind(i64::from(command.manifest().is_some()))
    .bind(
        command
            .manifest()
            .map(|manifest| manifest.configuration_identity().as_bytes().to_vec()),
    )
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

async fn session_allows_template(
    transaction: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    template: &TemplateRecord,
) -> Result<bool, StoreError> {
    let row = sqlx::query(
        "SELECT compatibility_identity, compatibility_manifest_complete
         FROM sessions WHERE session_id = ?",
    )
    .bind(session_id.to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let complete: i64 = row
        .try_get("compatibility_manifest_complete")
        .map_err(map_sqlx)?;
    if complete == 0 {
        let compatibility = CompatibilityIdentity::from_bytes(
            row.try_get::<Vec<u8>, _>("compatibility_identity")
                .map_err(map_sqlx)?
                .try_into()
                .map_err(|_| StoreError::Corrupt)?,
        );
        return Ok(compatibility == template.compatibility);
    }
    let stored: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT template_compatibility FROM session_template_manifest
         WHERE session_id = ? AND template_id = ?",
    )
    .bind(session_id.to_string())
    .bind(template.identity.to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(stored.is_some_and(|value| value.as_slice() == template.compatibility.as_bytes()))
}

fn validate_lease_replay(
    lease: &OwnershipLease,
    bytes: &[u8],
    session_id: SessionId,
    caller: HostId,
    epoch: Option<FencingEpoch>,
    duration: LeaseDuration,
) -> Result<(), StoreError> {
    let wire: LeaseWire = serde_json::from_slice(bytes).map_err(|_| StoreError::Corrupt)?;
    let issued_at =
        Timestamp::new(wire.issued_seconds, wire.issued_nanos).map_err(|_| StoreError::Corrupt)?;
    let elapsed = lease
        .expires_at()
        .to_datetime()
        .map_err(|_| StoreError::Corrupt)?
        - issued_at.to_datetime().map_err(|_| StoreError::Corrupt)?;
    if lease.session_id() != session_id
        || lease.owner() != caller
        || epoch.is_some_and(|expected| lease.epoch() != expected)
        || elapsed.whole_milliseconds() != i128::from(duration.as_millis())
    {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

fn require_owner(
    row: &SessionRow,
    caller: HostId,
    attempted: FencingEpoch,
    observed_at: Timestamp,
) -> Result<(), StoreError> {
    let Some(owner) = &row.owner else {
        return Err(StoreError::StaleOwnership {
            session_id: row.snapshot.id(),
            attempted,
            current: None,
        });
    };
    if owner.epoch() != attempted || owner.owner() != caller {
        return Err(StoreError::StaleOwnership {
            session_id: row.snapshot.id(),
            attempted,
            current: Some(owner.epoch()),
        });
    }
    if !owner.is_effective_at(observed_at) {
        return Err(StoreError::OwnershipExpired {
            session_id: row.snapshot.id(),
            epoch: attempted,
        });
    }
    Ok(())
}

async fn advance_time_floor(
    transaction: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    persisted: Timestamp,
    observed: Timestamp,
) -> Result<Timestamp, StoreError> {
    let effective = persisted.max(observed);
    sqlx::query(
        "UPDATE sessions SET observed_time_floor_seconds = ?, observed_time_floor_nanos = ?
         WHERE session_id = ?",
    )
    .bind(effective.unix_seconds())
    .bind(i64::from(effective.nanoseconds()))
    .bind(session_id.to_string())
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(effective)
}

async fn append_event(
    transaction: &mut Transaction<'_, Sqlite>,
    request_id: RequestId,
    session_id: SessionId,
    revision: Revision,
    event_type: &str,
    occurred_at: Timestamp,
) -> Result<(), StoreError> {
    append_event_data(
        transaction,
        request_id,
        session_id,
        revision,
        event_type,
        b"{}",
        occurred_at,
    )
    .await
}

async fn append_event_data(
    transaction: &mut Transaction<'_, Sqlite>,
    request_id: RequestId,
    session_id: SessionId,
    revision: Revision,
    event_type: &str,
    data: &[u8],
    occurred_at: Timestamp,
) -> Result<(), StoreError> {
    let (session_limit, global_limit): (i64, i64) = sqlx::query_as(
        "SELECT per_session,global_limit FROM capacity_limits WHERE resource='retained_events' AND configured=1",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?
    .ok_or(StoreError::Corrupt)?;
    let session_used: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE session_id=?")
        .bind(session_id.to_string())
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_sqlx)?;
    if session_used >= session_limit {
        return Err(StoreError::CapacityExceeded {
            reason: CapacityReason::SessionLimit {
                resource: CapacityResource::RetainedEvents,
            },
        });
    }
    let global_used: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_sqlx)?;
    if global_used >= global_limit {
        return Err(StoreError::CapacityExceeded {
            reason: CapacityReason::GlobalLimit {
                resource: CapacityResource::RetainedEvents,
            },
        });
    }
    crash_at("event.append.before_insert");
    let previous = sqlx::query(
        "SELECT occurred_at_seconds, occurred_at_nanos FROM events
         WHERE session_id = ? ORDER BY position DESC LIMIT 1",
    )
    .bind(session_id.to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?
    .map(|row| {
        decode_timestamp(
            row.try_get("occurred_at_seconds").map_err(map_sqlx)?,
            row.try_get("occurred_at_nanos").map_err(map_sqlx)?,
        )
    })
    .transpose()?;
    let occurred_at = previous.map_or(occurred_at, |value| value.max(occurred_at));
    let position: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(position), 0) + 1 FROM events WHERE session_id = ?",
    )
    .bind(session_id.to_string())
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    let mut event_input = request_id.as_uuid().as_bytes().to_vec();
    event_input.extend_from_slice(event_type.as_bytes());
    let mut event_id: [u8; 16] = SemanticDigest::v1(
        &Capability::new("event.identity.v1").expect("static capability"),
        &event_input,
    )
    .as_bytes()[..16]
        .try_into()
        .map_err(|_| StoreError::Corrupt)?;
    event_id[6] = (event_id[6] & 0x0f) | 0x40;
    event_id[8] = (event_id[8] & 0x3f) | 0x80;
    sqlx::query(
        "INSERT INTO events (session_id, position, event_id, revision, event_type,
         schema_version, related_request_id, data, occurred_at_seconds, occurred_at_nanos)
         VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
    )
    .bind(session_id.to_string())
    .bind(position)
    .bind(Uuid::from_bytes(event_id).to_string())
    .bind(to_i64(revision.get())?)
    .bind(event_type)
    .bind(request_id.to_string())
    .bind(data)
    .bind(occurred_at.unix_seconds())
    .bind(i64::from(occurred_at.nanoseconds()))
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    crash_at("event.append.after_insert");
    Ok(())
}

async fn replay_json<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Sqlite>,
    request: &impl MutableRequest,
) -> Result<Option<T>, StoreError> {
    replay_bytes(transaction, request)
        .await?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt))
        .transpose()
}

async fn reject_global_request_collision(
    transaction: &mut Transaction<'_, Sqlite>,
    request_id: RequestId,
) -> Result<(), StoreError> {
    let collision: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM request_ledger WHERE request_id = ? UNION ALL SELECT 1 FROM approval_mutations WHERE request_id = ? UNION ALL SELECT 1 FROM approval_effect_intents WHERE effect_id = ? LIMIT 1")
            .bind(request_id.to_string())
            .bind(request_id.to_string())
            .bind(request_id.to_string())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(map_sqlx)?;
    if collision.is_some() {
        return Err(StoreError::RequestConflict { request_id });
    }
    Ok(())
}

async fn reject_recovery_request_collision(
    transaction: &mut Transaction<'_, Sqlite>,
    request_id: RequestId,
) -> Result<(), StoreError> {
    let collision: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM recovery_classifications WHERE request_id = ? LIMIT 1")
            .bind(request_id.to_string())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(map_sqlx)?;
    if collision.is_some() {
        return Err(StoreError::RequestConflict { request_id });
    }
    Ok(())
}

async fn reject_effect_request_collision(
    transaction: &mut Transaction<'_, Sqlite>,
    request_id: RequestId,
) -> Result<(), StoreError> {
    let collision: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM effect_journal WHERE request_id=? UNION ALL SELECT 1 FROM effect_journal_mutations WHERE request_id=? LIMIT 1",
    )
    .bind(request_id.to_string())
    .bind(request_id.to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    if collision.is_some() {
        return Err(StoreError::RequestConflict { request_id });
    }
    Ok(())
}

async fn approval_effect_identity_available(
    transaction: &mut Transaction<'_, Sqlite>,
    mutation_request_id: RequestId,
    effect_id: RequestId,
) -> Result<(), StoreError> {
    if mutation_request_id == effect_id {
        return Err(StoreError::RequestConflict {
            request_id: effect_id,
        });
    }
    let collision: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM request_ledger WHERE request_id=?
         UNION ALL SELECT 1 FROM effect_journal WHERE request_id=?
         UNION ALL SELECT 1 FROM effect_journal_mutations WHERE request_id=?
         UNION ALL SELECT 1 FROM recovery_classifications WHERE request_id=?
         UNION ALL SELECT 1 FROM tool_invocation_mutations WHERE request_id=?
         UNION ALL SELECT 1 FROM approval_mutations WHERE request_id=?
         UNION ALL SELECT 1 FROM approval_effect_intents WHERE effect_id=? LIMIT 1",
    )
    .bind(effect_id.to_string())
    .bind(effect_id.to_string())
    .bind(effect_id.to_string())
    .bind(effect_id.to_string())
    .bind(effect_id.to_string())
    .bind(effect_id.to_string())
    .bind(effect_id.to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    if collision.is_some() {
        Err(StoreError::RequestConflict {
            request_id: effect_id,
        })
    } else {
        Ok(())
    }
}

async fn reject_effect_identity_collision(
    transaction: &mut Transaction<'_, Sqlite>,
    mutation_request_id: RequestId,
    effect_request_id: RequestId,
) -> Result<(), StoreError> {
    if mutation_request_id == effect_request_id {
        return Err(StoreError::RequestConflict {
            request_id: mutation_request_id,
        });
    }
    let collision: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM effect_journal WHERE request_id = ? LIMIT 1")
            .bind(mutation_request_id.to_string())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(map_sqlx)?;
    if collision.is_some() {
        return Err(StoreError::RequestConflict {
            request_id: mutation_request_id,
        });
    }
    Ok(())
}

async fn replay_bytes(
    transaction: &mut Transaction<'_, Sqlite>,
    request: &impl MutableRequest,
) -> Result<Option<Vec<u8>>, StoreError> {
    let row = sqlx::query(
        "SELECT caller_host_id, action, semantic_digest, outcome, result FROM request_ledger
         WHERE request_id = ?",
    )
    .bind(request.context().request_id().to_string())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    let Some(row) = row else {
        let journal_collision: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM effect_journal WHERE request_id = ?
             UNION ALL SELECT 1 FROM effect_journal_mutations WHERE request_id = ?
             UNION ALL SELECT 1 FROM recovery_classifications WHERE request_id = ?
             UNION ALL SELECT 1 FROM tool_invocation_mutations WHERE request_id = ?
             UNION ALL SELECT 1 FROM approval_mutations WHERE request_id = ?
             UNION ALL SELECT 1 FROM approval_effect_intents WHERE effect_id = ? LIMIT 1",
        )
        .bind(request.context().request_id().to_string())
        .bind(request.context().request_id().to_string())
        .bind(request.context().request_id().to_string())
        .bind(request.context().request_id().to_string())
        .bind(request.context().request_id().to_string())
        .bind(request.context().request_id().to_string())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_sqlx)?;
        if journal_collision.is_some() {
            return Err(StoreError::RequestConflict {
                request_id: request.context().request_id(),
            });
        }
        return Ok(None);
    };
    let caller: String = row.try_get("caller_host_id").map_err(map_sqlx)?;
    let action: String = row.try_get("action").map_err(map_sqlx)?;
    let digest: Vec<u8> = row.try_get("semantic_digest").map_err(map_sqlx)?;
    if caller != request.context().caller().to_string()
        || action != request.action().as_str()
        || digest.as_slice() != request.digest().as_bytes()
    {
        return Err(StoreError::RequestConflict {
            request_id: request.context().request_id(),
        });
    }
    let outcome: String = row.try_get("outcome").map_err(map_sqlx)?;
    if outcome == "failed" {
        let bytes: Vec<u8> = row.try_get("result").map_err(map_sqlx)?;
        let error: FailureWire = serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
        return Err(error.into());
    }
    if outcome != "succeeded" {
        return Err(StoreError::Corrupt);
    }
    row.try_get("result").map(Some).map_err(map_sqlx)
}

async fn record_json<T: Serialize>(
    transaction: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    request: &impl MutableRequest,
    value: &T,
) -> Result<(), StoreError> {
    record_json_with_effect(
        transaction,
        session_id,
        request,
        StoredEffect::Applied,
        value,
    )
    .await
}

async fn record_json_with_effect<T: Serialize>(
    transaction: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    request: &impl MutableRequest,
    effect: StoredEffect,
    value: &T,
) -> Result<(), StoreError> {
    record_bytes(
        transaction,
        session_id,
        request,
        effect,
        &serde_json::to_vec(value).map_err(|_| StoreError::Corrupt)?,
    )
    .await
}

async fn record_bytes(
    transaction: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    request: &impl MutableRequest,
    effect: StoredEffect,
    result: &[u8],
) -> Result<(), StoreError> {
    sqlx::query(
        "INSERT INTO request_ledger
         (session_id, request_id, caller_host_id, action, semantic_digest, outcome, effect, result)
         VALUES (?, ?, ?, ?, ?, 'succeeded', ?, ?)",
    )
    .bind(session_id.to_string())
    .bind(request.context().request_id().to_string())
    .bind(request.context().caller().to_string())
    .bind(request.action().as_str())
    .bind(request.digest().as_bytes().as_slice())
    .bind(match effect {
        StoredEffect::Applied => "applied",
        StoredEffect::Unchanged => "unchanged",
    })
    .bind(result)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

async fn record_failure(
    transaction: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    request: &impl MutableRequest,
    error: &StoreError,
) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(&FailureWire::from(error)).map_err(|_| StoreError::Corrupt)?;
    sqlx::query(
        "INSERT INTO request_ledger
         (session_id, request_id, caller_host_id, action, semantic_digest, outcome, effect, result)
         VALUES (?, ?, ?, ?, ?, 'failed', NULL, ?)",
    )
    .bind(session_id.to_string())
    .bind(request.context().request_id().to_string())
    .bind(request.context().caller().to_string())
    .bind(request.action().as_str())
    .bind(request.digest().as_bytes().as_slice())
    .bind(bytes)
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

async fn finish_failure(
    mut transaction: Transaction<'_, Sqlite>,
    session_id: SessionId,
    request: &impl MutableRequest,
    error: StoreError,
) -> Result<StoreError, StoreError> {
    record_failure(&mut transaction, session_id, request, &error).await?;
    transaction.commit().await.map_err(map_sqlx)?;
    Ok(error)
}

fn encode_lease(lease: &OwnershipLease, issued_at: Timestamp) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(&LeaseWire::from_lease(lease, issued_at)).map_err(|_| StoreError::Corrupt)
}

fn decode_lease(bytes: &[u8]) -> Result<OwnershipLease, StoreError> {
    serde_json::from_slice::<LeaseWire>(bytes)
        .map_err(|_| StoreError::Corrupt)?
        .into_lease()
}

#[allow(clippy::too_many_lines)]
fn decode_stored_request(
    row: &sqlx::sqlite::SqliteRow,
    request_id: RequestId,
) -> Result<StoredRequest, StoreError> {
    let caller = parse_host_id(
        &row.try_get::<String, _>("caller_host_id")
            .map_err(map_sqlx)?,
    )?;
    let action = parse_action(&row.try_get::<String, _>("action").map_err(map_sqlx)?)?;
    let digest_bytes: Vec<u8> = row.try_get("semantic_digest").map_err(map_sqlx)?;
    if digest_bytes.len() != 32 {
        return Err(StoreError::Corrupt);
    }
    let digest = serde_json::from_value(serde_json::Value::Array(
        digest_bytes
            .into_iter()
            .map(|value| serde_json::Value::from(u64::from(value)))
            .collect(),
    ))
    .map_err(|_| StoreError::Corrupt)?;
    let bytes: Vec<u8> = row.try_get("result").map_err(map_sqlx)?;
    let outcome = match row
        .try_get::<String, _>("outcome")
        .map_err(map_sqlx)?
        .as_str()
    {
        "failed" => StoredRequestOutcome::Failed(
            serde_json::from_slice::<FailureWire>(&bytes)
                .map_err(|_| StoreError::Corrupt)?
                .into(),
        ),
        "succeeded" => {
            let effect = match row
                .try_get::<Option<String>, _>("effect")
                .map_err(map_sqlx)?
                .as_deref()
            {
                Some("applied") => StoredEffect::Applied,
                Some("unchanged") => StoredEffect::Unchanged,
                _ => return Err(StoreError::Corrupt),
            };
            let result = match action {
                StoreAction::OpenSession | StoreAction::CloseSession => StoredResult::Session(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                ),
                StoreAction::AcquireOwnership | StoreAction::RenewOwnership => {
                    StoredResult::OwnershipLease(decode_lease(&bytes)?)
                }
                StoreAction::ReleaseOwnership => {
                    StoredResult::Ownership(OwnershipSnapshot::Unowned)
                }
                StoreAction::PrepareLaunch
                | StoreAction::AttachLaunch
                | StoreAction::TransitionLaunch => StoredResult::Launch(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                ),
                StoreAction::CreateRootParticipant | StoreAction::CreateChildParticipant => {
                    StoredResult::Participant(
                        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                    )
                }
                StoreAction::StartOperation | StoreAction::TransitionOperation => {
                    StoredResult::Operation(
                        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                    )
                }
                StoreAction::EnqueueMessage
                | StoreAction::LeaseNextMessage
                | StoreAction::TransitionMessageDelivery => StoredResult::Message(Box::new(
                    serde_json::from_slice::<Option<MessageSnapshot>>(&bytes)
                        .map_err(|_| StoreError::Corrupt)?,
                )),
                StoreAction::PutAuthorityPolicy => StoredResult::AuthorityPolicy(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                ),
                StoreAction::IssueGrant | StoreAction::RevokeGrant => StoredResult::Grant(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                ),
                StoreAction::CheckAuthorityEffect => StoredResult::AuthorityEffect(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                ),
                StoreAction::CreateAuthorizedChild => StoredResult::AuthorizedChild(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                ),
                StoreAction::ApplyHierarchyEffect => StoredResult::HierarchyEffect(Box::new(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                )),
                StoreAction::CancelSubtree => StoredResult::Cancellation(Box::new(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                )),
                StoreAction::PublishArtifact
                | StoreAction::DeleteArtifact
                | StoreAction::EraseArtifact => StoredResult::Artifact(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                ),
                StoreAction::RegisterAuthorityTemplatePolicy => {
                    StoredResult::AuthorityTemplatePolicy(
                        serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                    )
                }
                StoreAction::RegisterTool => StoredResult::ToolRegistration(Box::new(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                )),
                StoreAction::ConnectToolProvider => StoredResult::ToolProviderConnection(Box::new(
                    serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?,
                )),
                StoreAction::ReserveEffect
                | StoreAction::StartEffect
                | StoreAction::ResolveEffect
                | StoreAction::TakeoverEffect
                | StoreAction::ResolveAuthorizedEffect
                | StoreAction::ReserveToolInvocation
                | StoreAction::TransitionToolInvocation => return Err(StoreError::Corrupt),
            };
            StoredRequestOutcome::Succeeded { effect, result }
        }
        _ => return Err(StoreError::Corrupt),
    };
    StoredRequest::new(request_id, caller, action, digest, outcome).map_err(|_| StoreError::Corrupt)
}

fn parse_action(value: &str) -> Result<StoreAction, StoreError> {
    match value {
        "session.open" => Ok(StoreAction::OpenSession),
        "session.close" => Ok(StoreAction::CloseSession),
        "ownership.acquire" => Ok(StoreAction::AcquireOwnership),
        "ownership.renew" => Ok(StoreAction::RenewOwnership),
        "ownership.release" => Ok(StoreAction::ReleaseOwnership),
        "instance.prepare_launch" => Ok(StoreAction::PrepareLaunch),
        "instance.attach_launch" => Ok(StoreAction::AttachLaunch),
        "instance.transition_launch" => Ok(StoreAction::TransitionLaunch),
        "participant.create_root" => Ok(StoreAction::CreateRootParticipant),
        "participant.create_child" => Ok(StoreAction::CreateChildParticipant),
        "operation.start" => Ok(StoreAction::StartOperation),
        "operation.transition" => Ok(StoreAction::TransitionOperation),
        "message.enqueue" => Ok(StoreAction::EnqueueMessage),
        "message.lease_next" => Ok(StoreAction::LeaseNextMessage),
        "message.transition_delivery" => Ok(StoreAction::TransitionMessageDelivery),
        "authority.put_policy" => Ok(StoreAction::PutAuthorityPolicy),
        "authority.issue_grant" => Ok(StoreAction::IssueGrant),
        "authority.revoke_grant" => Ok(StoreAction::RevokeGrant),
        "authority.check_effect" => Ok(StoreAction::CheckAuthorityEffect),
        "authority.create_child" => Ok(StoreAction::CreateAuthorizedChild),
        "hierarchy.apply_effect" => Ok(StoreAction::ApplyHierarchyEffect),
        "authority.register_template_policy" => Ok(StoreAction::RegisterAuthorityTemplatePolicy),
        _ => Err(StoreError::Corrupt),
    }
}

fn decode_session(row: &sqlx::sqlite::SqliteRow) -> Result<SessionRow, StoreError> {
    let session_id = parse_session_id(&row.try_get::<String, _>("session_id").map_err(map_sqlx)?)?;
    let consumer_key = ConsumerKey::new(
        row.try_get::<String, _>("public_consumer_key")
            .map_err(map_sqlx)?,
    )
    .map_err(|_| StoreError::Corrupt)?;
    let bytes: Vec<u8> = row.try_get("compatibility_identity").map_err(map_sqlx)?;
    let compatibility =
        CompatibilityIdentity::from_bytes(bytes.try_into().map_err(|_| StoreError::Corrupt)?);
    let revision = decode_revision(row.try_get("revision").map_err(map_sqlx)?)?;
    let status = match row.try_get::<i64, _>("closed").map_err(map_sqlx)? {
        0 => SessionStatus::Open,
        1 => SessionStatus::Closed,
        _ => return Err(StoreError::Corrupt),
    };
    let created_at = decode_timestamp(
        row.try_get("created_at_seconds").map_err(map_sqlx)?,
        row.try_get("created_at_nanos").map_err(map_sqlx)?,
    )?;
    let updated_at = decode_timestamp(
        row.try_get("updated_at_seconds").map_err(map_sqlx)?,
        row.try_get("updated_at_nanos").map_err(map_sqlx)?,
    )?;
    let snapshot = SessionSnapshot::new(
        session_id,
        consumer_key,
        compatibility,
        status,
        revision,
        created_at,
        updated_at,
    )
    .map_err(|_| StoreError::Corrupt)?;
    let owner_host: Option<String> = row.try_get("owner_host_id").map_err(map_sqlx)?;
    let owner = owner_host
        .map(|host| {
            let seconds = row.try_get("owner_expires_at_seconds").map_err(map_sqlx)?;
            let nanos = row.try_get("owner_expires_at_nanos").map_err(map_sqlx)?;
            OwnershipLease::new(
                session_id,
                parse_host_id(&host)?,
                decode_epoch(row.try_get("owner_epoch").map_err(map_sqlx)?)?,
                timestamp_before(
                    seconds,
                    u32::try_from(nanos).map_err(|_| StoreError::Corrupt)?,
                )?,
                decode_timestamp(seconds, nanos)?,
            )
            .map_err(|_| StoreError::Corrupt)
        })
        .transpose()?;
    let epoch_high_water = to_u64(row.try_get("epoch_high_water").map_err(map_sqlx)?)?;
    if owner
        .as_ref()
        .is_some_and(|lease| lease.epoch().get() > epoch_high_water)
    {
        return Err(StoreError::Corrupt);
    }
    Ok(SessionRow {
        snapshot,
        owner,
        epoch_high_water,
        time_floor: decode_timestamp(
            row.try_get("observed_time_floor_seconds")
                .map_err(map_sqlx)?,
            row.try_get("observed_time_floor_nanos").map_err(map_sqlx)?,
        )?,
    })
}

fn decode_event(
    row: &sqlx::sqlite::SqliteRow,
    session_id: SessionId,
) -> Result<SessionEvent, StoreError> {
    let event_id = EventId::from_uuid(
        Uuid::parse_str(&row.try_get::<String, _>("event_id").map_err(map_sqlx)?)
            .map_err(|_| StoreError::Corrupt)?,
    )
    .map_err(|_| StoreError::Corrupt)?;
    let position = EventPosition::new(to_u64(row.try_get("position").map_err(map_sqlx)?)?)
        .map_err(|_| StoreError::Corrupt)?;
    let revision = decode_revision(row.try_get("revision").map_err(map_sqlx)?)?;
    let event_type = EventType::new(row.try_get::<String, _>("event_type").map_err(map_sqlx)?)
        .map_err(|_| StoreError::Corrupt)?;
    let schema_version = EventSchemaVersion::new(
        u16::try_from(row.try_get::<i64, _>("schema_version").map_err(map_sqlx)?)
            .map_err(|_| StoreError::Corrupt)?,
    )
    .map_err(|_| StoreError::Corrupt)?;
    let related_request_id = row
        .try_get::<Option<String>, _>("related_request_id")
        .map_err(map_sqlx)?
        .map(|value| {
            RequestId::from_uuid(Uuid::parse_str(&value).map_err(|_| StoreError::Corrupt)?)
                .map_err(|_| StoreError::Corrupt)
        })
        .transpose()?;
    let data = RedactedEventData::new(row.try_get::<Vec<u8>, _>("data").map_err(map_sqlx)?)
        .map_err(|_| StoreError::Corrupt)?;
    let occurred_at = decode_timestamp(
        row.try_get("occurred_at_seconds").map_err(map_sqlx)?,
        row.try_get("occurred_at_nanos").map_err(map_sqlx)?,
    )?;
    Ok(SessionEvent::new(
        event_id,
        session_id,
        position,
        revision,
        event_type,
        schema_version,
        related_request_id,
        data,
        occurred_at,
    ))
}

fn parse_session_id(value: &str) -> Result<SessionId, StoreError> {
    SessionId::from_uuid(Uuid::parse_str(value).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Corrupt)
}

fn parse_participant_id(value: &str) -> Result<ParticipantId, StoreError> {
    ParticipantId::from_uuid(Uuid::parse_str(value).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Corrupt)
}

fn parse_template_id(value: &str) -> Result<TemplateId, StoreError> {
    TemplateId::from_uuid(Uuid::parse_str(value).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Corrupt)
}

fn parse_operation_id(value: &str) -> Result<OperationId, StoreError> {
    OperationId::from_uuid(Uuid::parse_str(value).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Corrupt)
}

fn parse_message_id(value: &str) -> Result<MessageId, StoreError> {
    MessageId::from_uuid(Uuid::parse_str(value).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Corrupt)
}

fn parse_request_id(value: &str) -> Result<RequestId, StoreError> {
    RequestId::from_uuid(Uuid::parse_str(value).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Corrupt)
}

fn parse_driver_id(value: &str) -> Result<DriverId, StoreError> {
    DriverId::from_uuid(Uuid::parse_str(value).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Corrupt)
}

fn effect_expiry(now: Timestamp, duration: std::time::Duration) -> Result<Timestamp, StoreError> {
    let millis = i64::try_from(duration.as_millis()).map_err(|_| StoreError::LeaseTooLong)?;
    now.to_datetime()
        .map_err(|_| StoreError::Corrupt)?
        .checked_add(time::Duration::milliseconds(millis))
        .map(Timestamp::from_datetime)
        .ok_or(StoreError::Invalid)
}

async fn transition_effect(
    store: &SqliteStore,
    command: EffectTransition,
) -> Result<EffectJournalEntry, StoreError> {
    let mut tx = begin_immediate(&store.pool).await?;
    reject_global_request_collision(&mut tx, command.context().request_id()).await?;
    reject_recovery_request_collision(&mut tx, command.context().request_id()).await?;
    reject_effect_identity_collision(
        &mut tx,
        command.context().request_id(),
        command.effect_request_id(),
    )
    .await?;
    if let Some(row) = sqlx::query("SELECT effect_request_id, caller_host_id, semantic_digest, result FROM effect_journal_mutations WHERE request_id = ?")
        .bind(command.context().request_id().to_string()).fetch_optional(&mut *tx).await.map_err(map_sqlx)? {
        let digest: Vec<u8> = row.try_get("semantic_digest").map_err(map_sqlx)?;
        if row.try_get::<String,_>("effect_request_id").map_err(map_sqlx)? != command.effect_request_id().to_string()
            || row.try_get::<String,_>("caller_host_id").map_err(map_sqlx)? != command.context().caller().to_string()
            || digest.as_slice() != command.semantic_digest().as_bytes() { return Err(StoreError::RequestConflict { request_id: command.context().request_id() }); }
        let bytes: Vec<u8> = row.try_get("result").map_err(map_sqlx)?;
        let entry = serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
        tx.commit().await.map_err(map_sqlx)?; return Ok(entry);
    }
    let mut entry = load_effect_in(&mut tx, command.effect_request_id())
        .await?
        .ok_or(StoreError::Invalid)?;
    let action = if command.resolution().is_some() {
        StoreAction::ResolveEffect
    } else {
        StoreAction::StartEffect
    };
    let session = require_open_session(&mut tx, entry.session_id, action).await?;
    let now =
        advance_time_floor(&mut tx, entry.session_id, session.time_floor, store.now()).await?;
    require_owner(
        &session,
        command.context().caller(),
        command.owner_epoch(),
        now,
    )?;
    if entry.owner_host != command.context().caller()
        || entry.owner_epoch != command.owner_epoch()
        || entry.revision != command.expected_revision()
    {
        return Err(StoreError::Invalid);
    }
    match command.resolution().cloned() {
        None if matches!(
            entry.phase,
            EffectJournalPhase::Reserved | EffectJournalPhase::RetryAuthorized
        ) && entry.lease_expires_at > now =>
        {
            entry.phase = EffectJournalPhase::Started;
        }
        Some(EffectResolution::Uncertain) if entry.phase == EffectJournalPhase::Started => {
            entry.phase = EffectJournalPhase::Uncertain;
        }
        Some(EffectResolution::Completed(value)) if entry.phase == EffectJournalPhase::Started => {
            entry.phase = EffectJournalPhase::Completed;
            entry.terminal = Some(EffectTerminal::Completed(value));
        }
        Some(EffectResolution::Failed(value)) if entry.phase == EffectJournalPhase::Started => {
            entry.phase = EffectJournalPhase::Failed;
            entry.terminal = Some(EffectTerminal::Failed(value));
        }
        _ => return Err(StoreError::Invalid),
    }
    entry.revision = entry.revision.next().ok_or(StoreError::Corrupt)?;
    update_effect(&mut tx, &entry).await?;
    let result = serde_json::to_vec(&entry).map_err(|_| StoreError::Corrupt)?;
    sqlx::query("INSERT INTO effect_journal_mutations(request_id,effect_request_id,caller_host_id,semantic_digest,result) VALUES(?,?,?,?,?)")
        .bind(command.context().request_id().to_string()).bind(command.effect_request_id().to_string())
        .bind(command.context().caller().to_string()).bind(command.semantic_digest().as_bytes().as_slice()).bind(result)
        .execute(&mut *tx).await.map_err(map_sqlx)?;
    crash_at("effect.transition.after_write");
    crash_at("effect.transition.before_commit");
    tx.commit().await.map_err(map_sqlx)?;
    crash_at("effect.transition.after_commit");
    Ok(entry)
}

async fn takeover_effect(
    store: &SqliteStore,
    command: TakeoverEffect,
) -> Result<EffectJournalEntry, StoreError> {
    if command.lease_duration.is_zero()
        || command.lease_duration.as_millis() > u128::from(store.max_lease_millis)
    {
        return Err(StoreError::LeaseTooLong);
    }
    let mut tx = begin_immediate(&store.pool).await?;
    reject_global_request_collision(&mut tx, command.context.request_id()).await?;
    reject_recovery_request_collision(&mut tx, command.context.request_id()).await?;
    reject_effect_identity_collision(
        &mut tx,
        command.context.request_id(),
        command.effect_request_id,
    )
    .await?;
    if let Some(row)=sqlx::query("SELECT effect_request_id,caller_host_id,semantic_digest,result FROM effect_journal_mutations WHERE request_id=?").bind(command.context.request_id().to_string()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?{
        let digest:Vec<u8>=row.try_get("semantic_digest").map_err(map_sqlx)?;
        if row.try_get::<String,_>("effect_request_id").map_err(map_sqlx)?!=command.effect_request_id.to_string()||row.try_get::<String,_>("caller_host_id").map_err(map_sqlx)?!=command.context.caller().to_string()||digest.as_slice()!=command.semantic_digest.as_bytes(){return Err(StoreError::RequestConflict{request_id:command.context.request_id()});}
        let bytes:Vec<u8>=row.try_get("result").map_err(map_sqlx)?;let value=serde_json::from_slice(&bytes).map_err(|_|StoreError::Corrupt)?;tx.commit().await.map_err(map_sqlx)?;return Ok(value);
    }
    let mut entry = load_effect_in(&mut tx, command.effect_request_id)
        .await?
        .ok_or(StoreError::Invalid)?;
    let session =
        require_open_session(&mut tx, entry.session_id, StoreAction::TakeoverEffect).await?;
    let now =
        advance_time_floor(&mut tx, entry.session_id, session.time_floor, store.now()).await?;
    require_owner(&session, command.context.caller(), command.owner_epoch, now)?;
    if entry.lease_expires_at > now
        || entry.revision != command.expected_revision
        || !matches!(
            entry.phase,
            EffectJournalPhase::Reserved | EffectJournalPhase::Started
        )
    {
        return Err(StoreError::Invalid);
    }
    if entry.phase == EffectJournalPhase::Reserved {
        entry.owner_host = command.context.caller();
        entry.owner_epoch = command.owner_epoch;
        entry.lease_expires_at = effect_expiry(now, command.lease_duration)?;
    } else {
        entry.phase = EffectJournalPhase::Uncertain;
    }
    entry.revision = entry.revision.next().ok_or(StoreError::Corrupt)?;
    update_effect(&mut tx, &entry).await?;
    let result = serde_json::to_vec(&entry).map_err(|_| StoreError::Corrupt)?;
    sqlx::query("INSERT INTO effect_journal_mutations(request_id,effect_request_id,caller_host_id,semantic_digest,result) VALUES(?,?,?,?,?)").bind(command.context.request_id().to_string()).bind(command.effect_request_id.to_string()).bind(command.context.caller().to_string()).bind(command.semantic_digest.as_bytes().as_slice()).bind(result).execute(&mut *tx).await.map_err(map_sqlx)?;
    crash_at("effect.takeover.after_write");
    crash_at("effect.takeover.before_commit");
    tx.commit().await.map_err(map_sqlx)?;
    crash_at("effect.takeover.after_commit");
    Ok(entry)
}

#[allow(clippy::too_many_lines)]
async fn resolve_authorized_effect(
    store: &SqliteStore,
    command: ResolveAuthorizedEffect,
) -> Result<Mutation<AuthorizedEffectResolution>, StoreError> {
    let mut tx = begin_immediate(&store.pool).await?;
    reject_global_request_collision(&mut tx, command.context.request_id()).await?;
    reject_recovery_request_collision(&mut tx, command.context.request_id()).await?;
    reject_effect_identity_collision(
        &mut tx,
        command.context.request_id(),
        command.effect_request_id,
    )
    .await?;
    if let Some(row)=sqlx::query("SELECT effect_request_id,caller_host_id,semantic_digest,result FROM effect_journal_mutations WHERE request_id=?").bind(command.context.request_id().to_string()).fetch_optional(&mut *tx).await.map_err(map_sqlx)?{
        let digest:Vec<u8>=row.try_get("semantic_digest").map_err(map_sqlx)?;
        if row.try_get::<String,_>("effect_request_id").map_err(map_sqlx)?!=command.effect_request_id.to_string()||row.try_get::<String,_>("caller_host_id").map_err(map_sqlx)?!=command.context.caller().to_string()||digest.as_slice()!=command.digest().as_bytes(){return Err(StoreError::RequestConflict{request_id:command.context.request_id()});}
        let bytes:Vec<u8>=row.try_get("result").map_err(map_sqlx)?;
        let value: AuthorizedEffectResolution = serde_json::from_slice(&bytes).map_err(|_|StoreError::Corrupt)?;
        validate_authorized_effect_replay(&mut tx, &command, &value).await?;
        tx.commit().await.map_err(map_sqlx)?;return Ok(Mutation::Replayed(value));
    }
    let row = require_open_session(&mut tx, command.session_id, command.action()).await?;
    let now = advance_time_floor(&mut tx, command.session_id, row.time_floor, store.now()).await?;
    require_owner(&row, command.context.caller(), command.owner_epoch, now)?;
    let mut effect = load_effect_in(&mut tx, command.effect_request_id)
        .await?
        .ok_or(StoreError::Invalid)?;
    let operation = load_operation_in(&mut tx, command.decision.operation_id())
        .await?
        .ok_or(StoreError::Invalid)?;
    if effect.phase != EffectJournalPhase::Uncertain
        || effect.revision != command.expected_effect_revision
        || effect.session_id != command.session_id
        || effect.participant_id != command.participant_id
        || effect.operation_id != operation.operation_id
        || operation.session_id != command.session_id
        || operation.participant_id != command.participant_id
        || operation.state != OperationState::Uncertain
    {
        return Err(StoreError::Invalid);
    }
    let policy = load_authority_policy_in(&mut tx, command.participant_id).await?;
    let mut grant = load_grant_in(&mut tx, command.grant_id)
        .await?
        .ok_or(StoreError::Invalid)?;
    let requested = ScopedCapability::new(
        Capability::new("effect.resolve_uncertainty").expect("static capability"),
        ResourceScope::Operation(operation.operation_id),
    );
    let decision = policy
        .as_ref()
        .and_then(|p| {
            policy_ceilings(p)
                .authorize_effect(
                    command.participant_id,
                    command.session_id,
                    &requested,
                    Some(&grant.grant),
                    now,
                )
                .ok()
        })
        .filter(|_| grant.consumed_at.is_none())
        .ok_or(StoreError::Invalid)?;
    let allowed = match command.decision.resolution() {
        UncertaintyResolution::ConfirmCompleted { proof } => effect
            .resolution_contract
            .allows_completion_proof(proof.kind()),
        UncertaintyResolution::DoNotRetry => effect.resolution_contract.allow_do_not_retry,
        UncertaintyResolution::RetryWithEffectProof { proof } => {
            effect.resolution_contract.allows_retry_proof(proof.kind())
        }
    };
    if !allowed {
        return Err(StoreError::Invalid);
    }
    match command.decision.resolution() {
        UncertaintyResolution::ConfirmCompleted { .. } => {
            effect.phase = EffectJournalPhase::Completed;
            effect.terminal = Some(EffectTerminal::Completed(
                BoundedBytes::new(Vec::new()).expect("empty redacted result is bounded"),
            ));
        }
        UncertaintyResolution::DoNotRetry => {
            effect.phase = EffectJournalPhase::Failed;
            effect.terminal = Some(EffectTerminal::Failed(
                BoundedText::new("effect.do_not_retry").expect("static failure"),
            ));
        }
        UncertaintyResolution::RetryWithEffectProof { .. } => {
            effect.phase = EffectJournalPhase::RetryAuthorized;
            effect.terminal = None;
            effect.owner_host = command.context.caller();
            effect.owner_epoch = command.owner_epoch;
            effect.lease_expires_at = effect_expiry(now, std::time::Duration::from_secs(10))?;
        }
    }
    effect.revision = effect.revision.next().ok_or(StoreError::Corrupt)?;
    update_effect(&mut tx, &effect).await?;
    let tool_id: Option<String> =
        sqlx::query_scalar("SELECT invocation_id FROM tool_invocations WHERE effect_request_id=?")
            .bind(command.effect_request_id.to_string())
            .fetch_optional(&mut *tx)
            .await
            .map_err(map_sqlx)?;
    if let Some(id) = tool_id {
        let invocation_id =
            ToolInvocationId::from_uuid(Uuid::parse_str(&id).map_err(|_| StoreError::Corrupt)?)
                .map_err(|_| StoreError::Corrupt)?;
        let current: ToolInvocationSnapshot = serde_json::from_slice(
            &sqlx::query_scalar::<_, Vec<u8>>(
                "SELECT snapshot FROM tool_invocations WHERE invocation_id=?",
            )
            .bind(&id)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_sqlx)?,
        )
        .map_err(|_| StoreError::Corrupt)?;
        if current.phase() != ToolInvocationPhase::Uncertain
            || current.invocation().invocation_id() != invocation_id
        {
            return Err(StoreError::Corrupt);
        }
        let (phase, terminal) = match (
            command.decision.resolution(),
            command.tool_terminal.as_ref(),
        ) {
            // A Tool's creator Operation is already terminal Uncertain here;
            // silently returning the invocation to Reserved would manufacture
            // work that can never pass effect-time authority/linkage checks.
            // Tool retry therefore requires a new Operation/invocation.
            (UncertaintyResolution::RetryWithEffectProof { .. }, None) => {
                return Err(StoreError::Invalid);
            }
            (
                UncertaintyResolution::ConfirmCompleted { .. },
                Some(ToolTerminal::Completed(result)),
            ) => {
                current
                    .definition()
                    .validate_output(result.output())
                    .map_err(|_| StoreError::Invalid)?;
                (
                    ToolInvocationPhase::Completed,
                    Some(ToolTerminal::Completed(result.clone())),
                )
            }
            (UncertaintyResolution::DoNotRetry, Some(ToolTerminal::Failed(failure))) => (
                ToolInvocationPhase::Failed,
                Some(ToolTerminal::Failed(failure.clone())),
            ),
            _ => return Err(StoreError::Invalid),
        };
        let mut dispatch = current.dispatch().clone();
        if let Some(terminal) = &terminal {
            let (capability, bytes) = match terminal {
                ToolTerminal::Completed(result) => (
                    "tool.result",
                    serde_json::to_vec(result).map_err(|_| StoreError::Corrupt)?,
                ),
                ToolTerminal::Failed(failure) => (
                    "tool.failure",
                    serde_json::to_vec(failure).map_err(|_| StoreError::Corrupt)?,
                ),
            };
            dispatch.terminal_digest = Some(SemanticDigest::v1(
                &Capability::new(capability).expect("static capability"),
                &bytes,
            ));
        }
        let updated = ToolInvocationSnapshot::new(
            current.registration_id(),
            current.definition().clone(),
            current.invocation().clone(),
            phase,
            terminal,
            effect.revision,
            dispatch.clone(),
        )
        .map_err(|_| StoreError::Corrupt)?;
        sqlx::query(
            "UPDATE tool_invocations SET snapshot=?,terminal_digest=? WHERE invocation_id=?",
        )
        .bind(serde_json::to_vec(&updated).map_err(|_| StoreError::Corrupt)?)
        .bind(dispatch.terminal_digest.map(|v| v.as_bytes().to_vec()))
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    } else if command.tool_terminal.is_some() {
        return Err(StoreError::Invalid);
    }
    if grant.single_use {
        grant.consumed_at = Some(now);
        update_grant_in(&mut tx, &grant).await?;
    }
    let (resolution_name, proof_kind, proof_digest) = match command.decision.resolution() {
        UncertaintyResolution::ConfirmCompleted { proof } => (
            "confirm_completed",
            Some(proof.kind()),
            Some(proof.digest()),
        ),
        UncertaintyResolution::DoNotRetry => ("do_not_retry", None, None),
        UncertaintyResolution::RetryWithEffectProof { proof } => (
            "retry_with_effect_proof",
            Some(proof.kind()),
            Some(proof.digest()),
        ),
    };
    let reason_action = Capability::new("effect.resolution.reason.v1").expect("static capability");
    let reason_digest = SemanticDigest::v1(&reason_action, command.decision.reason().as_bytes());
    let assertion_digest = command.assertion_digest(effect.semantic_digest);
    let audit = serde_json::to_vec(&serde_json::json!({"effect_request_id":command.effect_request_id,"effect_semantic_digest":effect.semantic_digest,"operation_id":operation.operation_id,"participant_id":command.participant_id,"resolution":resolution_name,"reason":"redacted","reason_digest":reason_digest,"proof_kind":proof_kind,"proof_digest":proof_digest,"assertion_digest":assertion_digest})).map_err(|_|StoreError::Corrupt)?;
    append_event_data(
        &mut tx,
        command.context.request_id(),
        command.session_id,
        effect.revision,
        "effect.uncertainty_resolved",
        &audit,
        now,
    )
    .await?;
    let position: i64 = sqlx::query_scalar("SELECT MAX(position) FROM events WHERE session_id=?")
        .bind(command.session_id.to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;
    let outcome = AuthorizedEffectResolution {
        effect_entry: effect,
        current_operation: operation,
        audit_event_position: EventPosition::new(to_u64(position)?)
            .map_err(|_| StoreError::Corrupt)?,
        authority_decision: decision.into(),
    };
    let bytes = serde_json::to_vec(&outcome).map_err(|_| StoreError::Corrupt)?;
    sqlx::query("INSERT INTO effect_journal_mutations(request_id,effect_request_id,caller_host_id,semantic_digest,result) VALUES(?,?,?,?,?)").bind(command.context.request_id().to_string()).bind(command.effect_request_id.to_string()).bind(command.context.caller().to_string()).bind(command.digest().as_bytes().as_slice()).bind(bytes).execute(&mut *tx).await.map_err(map_sqlx)?;
    crash_at("effect.resolve_authorized.after_write");
    crash_at("effect.resolve_authorized.before_commit");
    tx.commit().await.map_err(map_sqlx)?;
    crash_at("effect.resolve_authorized.after_commit");
    Ok(Mutation::Applied(outcome))
}

async fn validate_authorized_effect_replay(
    tx: &mut Transaction<'_, Sqlite>,
    command: &ResolveAuthorizedEffect,
    recorded: &AuthorizedEffectResolution,
) -> Result<(), StoreError> {
    let effect = load_effect_in(tx, command.effect_request_id)
        .await?
        .ok_or(StoreError::Corrupt)?;
    if recorded.effect_entry.request_id != command.effect_request_id
        || recorded.effect_entry.session_id != command.session_id
        || recorded.effect_entry.participant_id != command.participant_id
        || recorded.effect_entry.operation_id != command.decision.operation_id()
        || recorded.effect_entry != effect
        || recorded.current_operation.operation_id != command.decision.operation_id()
        || recorded.current_operation.session_id != command.session_id
        || recorded.current_operation.participant_id != command.participant_id
    {
        return Err(StoreError::Corrupt);
    }
    let expected_phase = match command.decision.resolution() {
        UncertaintyResolution::ConfirmCompleted { .. } => EffectJournalPhase::Completed,
        UncertaintyResolution::DoNotRetry => EffectJournalPhase::Failed,
        UncertaintyResolution::RetryWithEffectProof { .. } => EffectJournalPhase::RetryAuthorized,
    };
    if recorded.effect_entry.phase != expected_phase {
        return Err(StoreError::Corrupt);
    }
    let tool_id: Option<String> =
        sqlx::query_scalar("SELECT invocation_id FROM tool_invocations WHERE effect_request_id=?")
            .bind(command.effect_request_id.to_string())
            .fetch_optional(&mut **tx)
            .await
            .map_err(map_sqlx)?;
    match (tool_id, command.tool_terminal.as_ref()) {
        (Some(id), Some(terminal)) => {
            let id =
                ToolInvocationId::from_uuid(Uuid::parse_str(&id).map_err(|_| StoreError::Corrupt)?)
                    .map_err(|_| StoreError::Corrupt)?;
            let tool = load_tool_invocation_in(tx, id)
                .await?
                .ok_or(StoreError::Corrupt)?;
            if tool.invocation().request_id() != command.effect_request_id
                || tool.terminal() != Some(terminal)
                || !matches!(
                    (command.decision.resolution(), tool.phase()),
                    (
                        UncertaintyResolution::ConfirmCompleted { .. },
                        ToolInvocationPhase::Completed
                    ) | (
                        UncertaintyResolution::DoNotRetry,
                        ToolInvocationPhase::Failed
                    )
                )
            {
                return Err(StoreError::Corrupt);
            }
        }
        (None, None)
            if matches!(
                command.decision.resolution(),
                UncertaintyResolution::RetryWithEffectProof { .. }
            ) => {}
        (None, None) => {}
        _ => return Err(StoreError::Corrupt),
    }
    Ok(())
}

async fn insert_effect(
    tx: &mut Transaction<'_, Sqlite>,
    e: &EffectJournalEntry,
) -> Result<(), StoreError> {
    sqlx::query("INSERT INTO effect_journal(request_id,session_id,participant_id,operation_id,caller_host_id,action,semantic_digest,effect_class,resolution_contract,phase,owner_host_id,owner_epoch,lease_expires_at_seconds,lease_expires_at_nanos,terminal,revision) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(e.request_id.to_string()).bind(e.session_id.to_string()).bind(e.participant_id.to_string()).bind(e.operation_id.to_string()).bind(e.caller.to_string()).bind(e.action.as_str())
        .bind(e.semantic_digest.as_bytes().as_slice()).bind(effect_class_name(e.effect_class)).bind(serde_json::to_vec(&e.resolution_contract).map_err(|_|StoreError::Corrupt)?).bind(effect_phase_name(e.phase)).bind(e.owner_host.to_string())
        .bind(to_i64(e.owner_epoch.get())?).bind(e.lease_expires_at.unix_seconds()).bind(i64::from(e.lease_expires_at.nanoseconds()))
        .bind(e.terminal.as_ref().map(serde_json::to_vec).transpose().map_err(|_| StoreError::Corrupt)?)
        .bind(to_i64(e.revision.get())?).execute(&mut **tx).await.map_err(map_sqlx)?;
    Ok(())
}
async fn update_effect(
    tx: &mut Transaction<'_, Sqlite>,
    e: &EffectJournalEntry,
) -> Result<(), StoreError> {
    let result = sqlx::query("UPDATE effect_journal SET phase=?,owner_host_id=?,owner_epoch=?,lease_expires_at_seconds=?,lease_expires_at_nanos=?,terminal=?,revision=? WHERE request_id=? AND revision=?")
        .bind(effect_phase_name(e.phase)).bind(e.owner_host.to_string()).bind(to_i64(e.owner_epoch.get())?).bind(e.lease_expires_at.unix_seconds()).bind(i64::from(e.lease_expires_at.nanoseconds()))
        .bind(e.terminal.as_ref().map(serde_json::to_vec).transpose().map_err(|_| StoreError::Corrupt)?)
        .bind(to_i64(e.revision.get())?).bind(e.request_id.to_string()).bind(to_i64(e.revision.get()-1)?)
        .execute(&mut **tx).await.map_err(map_sqlx)?;
    if result.rows_affected() != 1 {
        return Err(StoreError::Invalid);
    }
    Ok(())
}
async fn load_effect_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: RequestId,
) -> Result<Option<EffectJournalEntry>, StoreError> {
    let entry = sqlx::query("SELECT * FROM effect_journal WHERE request_id=?")
        .bind(id.to_string())
        .fetch_optional(&mut **tx)
        .await
        .map_err(map_sqlx)?
        .as_ref()
        .map(decode_effect)
        .transpose()?;
    if let Some(value) = &entry {
        let participant = load_participant_in(tx, value.participant_id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        let operation = load_operation_in(tx, value.operation_id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        if participant.session_id != value.session_id
            || operation.session_id != value.session_id
            || operation.participant_id != value.participant_id
        {
            return Err(StoreError::Corrupt);
        }
    }
    Ok(entry)
}
fn decode_effect(row: &SqliteRow) -> Result<EffectJournalEntry, StoreError> {
    let digest: Vec<u8> = row.try_get("semantic_digest").map_err(map_sqlx)?;
    let entry = EffectJournalEntry {
        request_id: parse_request_id(&row.try_get::<String, _>("request_id").map_err(map_sqlx)?)?,
        session_id: parse_session_id(&row.try_get::<String, _>("session_id").map_err(map_sqlx)?)?,
        participant_id: parse_participant_id(
            &row.try_get::<String, _>("participant_id")
                .map_err(map_sqlx)?,
        )?,
        operation_id: parse_operation_id(
            &row.try_get::<String, _>("operation_id").map_err(map_sqlx)?,
        )?,
        caller: parse_host_id(
            &row.try_get::<String, _>("caller_host_id")
                .map_err(map_sqlx)?,
        )?,
        action: Capability::new(row.try_get::<String, _>("action").map_err(map_sqlx)?)
            .map_err(|_| StoreError::Corrupt)?,
        semantic_digest: SemanticDigest::from_bytes(
            digest.try_into().map_err(|_| StoreError::Corrupt)?,
        ),
        effect_class: parse_effect_class(
            &row.try_get::<String, _>("effect_class").map_err(map_sqlx)?,
        )?,
        resolution_contract: serde_json::from_slice(
            &row.try_get::<Vec<u8>, _>("resolution_contract")
                .map_err(map_sqlx)?,
        )
        .map_err(|_| StoreError::Corrupt)?,
        phase: parse_effect_phase(&row.try_get::<String, _>("phase").map_err(map_sqlx)?)?,
        owner_host: parse_host_id(
            &row.try_get::<String, _>("owner_host_id")
                .map_err(map_sqlx)?,
        )?,
        owner_epoch: decode_epoch(row.try_get("owner_epoch").map_err(map_sqlx)?)?,
        lease_expires_at: decode_timestamp(
            row.try_get("lease_expires_at_seconds").map_err(map_sqlx)?,
            row.try_get("lease_expires_at_nanos").map_err(map_sqlx)?,
        )?,
        terminal: row
            .try_get::<Option<Vec<u8>>, _>("terminal")
            .map_err(map_sqlx)?
            .map(|v| serde_json::from_slice(&v).map_err(|_| StoreError::Corrupt))
            .transpose()?,
        revision: decode_revision(row.try_get("revision").map_err(map_sqlx)?)?,
    };
    if !matches!(
        (&entry.phase, &entry.terminal),
        (
            EffectJournalPhase::Completed,
            Some(EffectTerminal::Completed(_))
        ) | (EffectJournalPhase::Failed, Some(EffectTerminal::Failed(_)))
            | (
                EffectJournalPhase::Reserved
                    | EffectJournalPhase::Started
                    | EffectJournalPhase::Uncertain
                    | EffectJournalPhase::RetryAuthorized,
                None
            )
    ) {
        return Err(StoreError::Corrupt);
    }
    if !entry.resolution_contract.is_valid() {
        return Err(StoreError::Corrupt);
    }
    Ok(entry)
}
fn effect_class_name(v: EffectClass) -> &'static str {
    match v {
        EffectClass::ReadOnly => "read_only",
        EffectClass::Idempotent => "idempotent",
        EffectClass::Transactional => "transactional",
        EffectClass::NonIdempotent => "non_idempotent",
        EffectClass::Unknown => "unknown",
    }
}
fn parse_effect_class(v: &str) -> Result<EffectClass, StoreError> {
    match v {
        "read_only" => Ok(EffectClass::ReadOnly),
        "idempotent" => Ok(EffectClass::Idempotent),
        "transactional" => Ok(EffectClass::Transactional),
        "non_idempotent" => Ok(EffectClass::NonIdempotent),
        "unknown" => Ok(EffectClass::Unknown),
        _ => Err(StoreError::Corrupt),
    }
}
fn effect_phase_name(v: EffectJournalPhase) -> &'static str {
    match v {
        EffectJournalPhase::Reserved => "reserved",
        EffectJournalPhase::Started => "started",
        EffectJournalPhase::Uncertain => "uncertain",
        EffectJournalPhase::Completed => "completed",
        EffectJournalPhase::Failed => "failed",
        EffectJournalPhase::RetryAuthorized => "retry_authorized",
    }
}
fn parse_effect_phase(v: &str) -> Result<EffectJournalPhase, StoreError> {
    match v {
        "reserved" => Ok(EffectJournalPhase::Reserved),
        "started" => Ok(EffectJournalPhase::Started),
        "uncertain" => Ok(EffectJournalPhase::Uncertain),
        "completed" => Ok(EffectJournalPhase::Completed),
        "failed" => Ok(EffectJournalPhase::Failed),
        "retry_authorized" => Ok(EffectJournalPhase::RetryAuthorized),
        _ => Err(StoreError::Corrupt),
    }
}

fn parse_launch_attempt(value: &str) -> Result<LaunchAttemptId, StoreError> {
    LaunchAttemptId::from_uuid(Uuid::parse_str(value).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Corrupt)
}

fn parse_instance_id(value: &str) -> Result<InstanceId, StoreError> {
    InstanceId::from_uuid(Uuid::parse_str(value).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Corrupt)
}

fn parse_host_id(value: &str) -> Result<HostId, StoreError> {
    HostId::from_uuid(Uuid::parse_str(value).map_err(|_| StoreError::Corrupt)?)
        .map_err(|_| StoreError::Corrupt)
}

fn decode_revision(value: i64) -> Result<Revision, StoreError> {
    Revision::new(to_u64(value)?).map_err(|_| StoreError::Corrupt)
}

fn decode_epoch(value: i64) -> Result<FencingEpoch, StoreError> {
    FencingEpoch::new(to_u64(value)?).map_err(|_| StoreError::Corrupt)
}

fn decode_timestamp(seconds: i64, nanos: i64) -> Result<Timestamp, StoreError> {
    Timestamp::new(
        seconds,
        u32::try_from(nanos).map_err(|_| StoreError::Corrupt)?,
    )
    .map_err(|_| StoreError::Corrupt)
}

fn timestamp_before(seconds: i64, nanos: u32) -> Result<Timestamp, StoreError> {
    if nanos > 0 {
        Timestamp::new(seconds, nanos - 1).map_err(|_| StoreError::Corrupt)
    } else {
        Timestamp::new(
            seconds.checked_sub(1).ok_or(StoreError::Corrupt)?,
            999_999_999,
        )
        .map_err(|_| StoreError::Corrupt)
    }
}

fn to_u64(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::Corrupt)
}

fn to_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::Corrupt)
}

async fn derived_capacity_usage(
    tx: &mut Transaction<'_, Sqlite>,
    session_id: SessionId,
    resource: CapacityResource,
) -> Result<(u64, u64), StoreError> {
    let session = session_id.to_string();
    let (session_used, global_used): (i64, i64) = match resource {
        CapacityResource::Participants => (
            sqlx::query_scalar("SELECT COUNT(*) FROM participants WHERE session_id=?").bind(&session).fetch_one(&mut **tx).await.map_err(map_sqlx)?,
            sqlx::query_scalar("SELECT COUNT(*) FROM participants").fetch_one(&mut **tx).await.map_err(map_sqlx)?,
        ),
        CapacityResource::ActiveOperations => (
            sqlx::query_scalar("SELECT COUNT(*) FROM operations WHERE session_id=? AND terminal_outcome IS NULL AND state<>'queued'").bind(&session).fetch_one(&mut **tx).await.map_err(map_sqlx)?,
            sqlx::query_scalar("SELECT COUNT(*) FROM operations WHERE terminal_outcome IS NULL AND state<>'queued'").fetch_one(&mut **tx).await.map_err(map_sqlx)?,
        ),
        CapacityResource::QueuedOperations => (
            sqlx::query_scalar("SELECT COUNT(*) FROM operations WHERE session_id=? AND state='queued'").bind(&session).fetch_one(&mut **tx).await.map_err(map_sqlx)?,
            sqlx::query_scalar("SELECT COUNT(*) FROM operations WHERE state='queued'").fetch_one(&mut **tx).await.map_err(map_sqlx)?,
        ),
        CapacityResource::Messages => (
            sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE session_id=? AND delivery_state NOT IN ('accepted','retired')").bind(&session).fetch_one(&mut **tx).await.map_err(map_sqlx)?,
            sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE delivery_state NOT IN ('accepted','retired')").fetch_one(&mut **tx).await.map_err(map_sqlx)?,
        ),
        CapacityResource::MessageBytes => (
            sqlx::query_scalar("SELECT COALESCE(SUM(length(snapshot)),0) FROM messages WHERE session_id=? AND delivery_state NOT IN ('accepted','retired')").bind(&session).fetch_one(&mut **tx).await.map_err(map_sqlx)?,
            sqlx::query_scalar("SELECT COALESCE(SUM(length(snapshot)),0) FROM messages WHERE delivery_state NOT IN ('accepted','retired')").fetch_one(&mut **tx).await.map_err(map_sqlx)?,
        ),
        CapacityResource::Artifacts => (
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE session_id=? AND state<>'erased'").bind(&session).fetch_one(&mut **tx).await.map_err(map_sqlx)?,
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE state<>'erased'").fetch_one(&mut **tx).await.map_err(map_sqlx)?,
        ),
        CapacityResource::ArtifactBytes => (
            sqlx::query_scalar("SELECT COALESCE(SUM(size),0) FROM artifacts WHERE session_id=? AND state<>'erased'").bind(&session).fetch_one(&mut **tx).await.map_err(map_sqlx)?,
            sqlx::query_scalar("SELECT COALESCE(SUM(size),0) FROM artifacts WHERE state<>'erased'").fetch_one(&mut **tx).await.map_err(map_sqlx)?,
        ),
        CapacityResource::Retries => (
            sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE session_id=? AND delivery_state='retry_scheduled'").bind(&session).fetch_one(&mut **tx).await.map_err(map_sqlx)?,
            sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE delivery_state='retry_scheduled'").fetch_one(&mut **tx).await.map_err(map_sqlx)?,
        ),
        CapacityResource::RetainedEvents => (
            sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE session_id=?").bind(&session).fetch_one(&mut **tx).await.map_err(map_sqlx)?,
            sqlx::query_scalar("SELECT COUNT(*) FROM events").fetch_one(&mut **tx).await.map_err(map_sqlx)?,
        ),
        CapacityResource::PendingRequests | CapacityResource::Subscriptions => (0, 0),
    };
    Ok((
        u64::try_from(session_used).map_err(|_| StoreError::Corrupt)?,
        u64::try_from(global_used).map_err(|_| StoreError::Corrupt)?,
    ))
}

async fn configure_capacity_limits(
    pool: &SqlitePool,
    profile: &LimitProfile,
) -> Result<(), StoreError> {
    let mut tx = begin_immediate(pool).await?;
    for resource in CapacityResource::ALL {
        let row: Option<(i64, i64, i64)> = sqlx::query_as(
            "SELECT per_session,global_limit,configured FROM capacity_limits WHERE resource=?",
        )
        .bind(resource.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        let (stored_session, stored_global, configured) = row.ok_or(StoreError::Corrupt)?;
        let limit = profile.get(resource);
        let requested_session =
            i64::try_from(limit.per_session).map_err(|_| StoreError::Invalid)?;
        let requested_global = i64::try_from(limit.global).map_err(|_| StoreError::Invalid)?;
        if configured == 0 {
            sqlx::query(
                "UPDATE capacity_limits SET per_session=?,global_limit=?,configured=1 WHERE resource=? AND configured=0",
            )
            .bind(requested_session)
            .bind(requested_global)
            .bind(resource.as_str())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx)?;
        } else if configured != 1
            || stored_session != requested_session
            || stored_global != requested_global
        {
            return Err(StoreError::Invalid);
        }
    }
    tx.commit().await.map_err(map_sqlx)
}

async fn consume_capacity_reservation(
    tx: &mut Transaction<'_, Sqlite>,
    reservation_id: RequestId,
    session_id: SessionId,
    campaign_id: ParticipantId,
    resource: CapacityResource,
    amount: u64,
    now: Timestamp,
) -> Result<(), StoreError> {
    let row: Option<(String, String, String, i64, i64)> = sqlx::query_as(
        "SELECT session_id,campaign_id,resource,amount,released FROM capacity_reservations WHERE reservation_id=?",
    )
    .bind(reservation_id.to_string())
    .fetch_optional(&mut **tx)
    .await
    .map_err(map_sqlx)?;
    let (stored_session, stored_campaign, stored_resource, stored_amount, released) =
        row.ok_or(StoreError::Invalid)?;
    if stored_session != session_id.to_string()
        || stored_campaign != campaign_id.to_string()
        || stored_resource != resource.as_str()
        || u64::try_from(stored_amount).map_err(|_| StoreError::Corrupt)? != amount
        || released != 0
    {
        return Err(StoreError::Invalid);
    }
    let amount = i64::try_from(amount).map_err(|_| StoreError::Corrupt)?;
    if sqlx::query("UPDATE capacity_reservations SET released=1,released_at_seconds=?,released_at_nanos=? WHERE reservation_id=? AND released=0")
        .bind(now.unix_seconds()).bind(i64::from(now.nanoseconds())).bind(reservation_id.to_string())
        .execute(&mut **tx).await.map_err(map_sqlx)?.rows_affected()!=1
        || sqlx::query("UPDATE capacity_session_usage SET used=used-? WHERE session_id=? AND resource=? AND used>=?")
            .bind(amount).bind(session_id.to_string()).bind(resource.as_str()).bind(amount)
            .execute(&mut **tx).await.map_err(map_sqlx)?.rows_affected()!=1
        || sqlx::query("UPDATE capacity_global_usage SET used=used-? WHERE resource=? AND used>=?")
            .bind(amount).bind(resource.as_str()).bind(amount)
            .execute(&mut **tx).await.map_err(map_sqlx)?.rows_affected()!=1
    {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

async fn ensure_derived_capacity(
    tx: &mut Transaction<'_, Sqlite>,
    profile: &LimitProfile,
    session_id: SessionId,
    resource: CapacityResource,
    amount: u64,
) -> Result<(), StoreError> {
    let (derived_session, derived_global) =
        derived_capacity_usage(tx, session_id, resource).await?;
    let reserved_session: i64 = sqlx::query_scalar("SELECT COALESCE((SELECT used FROM capacity_session_usage WHERE session_id=? AND resource=?),0)")
        .bind(session_id.to_string()).bind(resource.as_str()).fetch_one(&mut **tx).await.map_err(map_sqlx)?;
    let reserved_global: i64 = sqlx::query_scalar(
        "SELECT COALESCE((SELECT used FROM capacity_global_usage WHERE resource=?),0)",
    )
    .bind(resource.as_str())
    .fetch_one(&mut **tx)
    .await
    .map_err(map_sqlx)?;
    let session_after = derived_session
        .checked_add(u64::try_from(reserved_session).map_err(|_| StoreError::Corrupt)?)
        .and_then(|used| used.checked_add(amount));
    let global_after = derived_global
        .checked_add(u64::try_from(reserved_global).map_err(|_| StoreError::Corrupt)?)
        .and_then(|used| used.checked_add(amount));
    let limit = profile.get(resource);
    if session_after.is_none_or(|used| used > limit.per_session) {
        return Err(StoreError::CapacityExceeded {
            reason: CapacityReason::SessionLimit { resource },
        });
    }
    if global_after.is_none_or(|used| used > limit.global) {
        return Err(StoreError::CapacityExceeded {
            reason: CapacityReason::GlobalLimit { resource },
        });
    }
    Ok(())
}

fn map_database_error(error: DatabaseError) -> StoreError {
    match error {
        DatabaseError::SchemaTooNew { found, .. } => StoreError::SchemaTooNew {
            found: u32::try_from(found).unwrap_or(u32::MAX),
            supported: u32::try_from(SCHEMA_VERSION).unwrap_or(u32::MAX),
        },
        DatabaseError::Sqlx(error) => map_sqlx(error),
        DatabaseError::SchemaCorrupt => StoreError::Corrupt,
        DatabaseError::InvalidPath => StoreError::Invalid,
    }
}

fn map_sqlx(error: sqlx::Error) -> StoreError {
    match error {
        sqlx::Error::Database(database)
            if matches!(database.code().as_deref(), Some("5" | "6")) =>
        {
            StoreError::Busy
        }
        sqlx::Error::Database(database)
            if matches!(database.code().as_deref(), Some("11" | "17" | "26")) =>
        {
            StoreError::Corrupt
        }
        _ => StoreError::Unavailable,
    }
}
