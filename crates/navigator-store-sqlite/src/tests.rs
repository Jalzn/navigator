use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::{
        fs::{FileTypeExt, MetadataExt},
        net::UnixListener,
    },
    path::Path,
    process::Command,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};

static DURABLE_SENTINELS_SURVIVED: AtomicBool = AtomicBool::new(false);

use navigator_domain::{
    ApprovalDecisionSource, ApprovalEffectIntent, ApprovalEffectPhase, ApprovalGrant,
    ApprovalRequest, ApprovalRequestId, ApprovalResource, ApprovalStatus, ApprovalSummary,
    ArtifactDigest, ArtifactId, ArtifactMediaType, ArtifactState, AuthorityProfile, BoundedBytes,
    BoundedText, CanonicalJson, Capability, Clock, CompatibilityIdentity, ConsumerKey,
    DeliveryAttemptId, DriverId, DriverRequirement, EffectClass, EffectProof, EffectProofKind,
    EventPosition, FeedbackKind, FencingEpoch, Grant, GrantId, HostId, IdempotencyContract,
    InputSchema, InstanceId, LaunchAttemptId, MAX_TOOL_INLINE_BYTES, MAX_TOOL_SCHEMA_BYTES,
    MessageId, MonotonicInstant, OperationAction, OperationId, OperationState, ParticipantId,
    RequestId, ResolveUncertaintyDecision, ResourceBounds, ResourceScope, Revision,
    ScopedCapability, SemanticDigest, SessionCompatibilityManifest, SessionId, SessionStatus,
    Template, TemplateCompatibilityBinding, TemplateId, TerminalApprovalEffectPhase, Timestamp,
    ToolCancellation, ToolCancellationId, ToolConnectionId, ToolDefinition, ToolDispatchId,
    ToolFailure, ToolFailureKind, ToolInvocation, ToolInvocationId, ToolName, ToolProviderId,
    ToolRegistrationId, ToolResult, ToolTimeout, ToolVersion, TrustedConfiguration,
    UncertaintyResolution, ValidatedMessageEnvelope,
};
use navigator_store_api::{
    AcquireOwnership, ApprovalStore, ApproveRequest, ArtifactAccess, ArtifactStore, AttachLaunch,
    AuthorityPolicySnapshot, AuthorityStore, AuthorityTemplatePolicy, CancelSubtree,
    CapacityReason, CapacityResource, CapacityStore, CloseSession, ConnectToolProvider,
    ConsumeApprovalGrant, CreateAuthorizedChild, CreateChildParticipant, CreateRootParticipant,
    DeleteArtifact, DeliveryTransition, DenyRequest, EffectJournalStore, EffectResolutionContract,
    EffectTransition, EnqueueMessage, EraseArtifact, EventReadLimit, ExpireApproval,
    FinishApprovalEffect, HierarchyStore, InstanceStore, IssueGrant, LaunchState, LeaseDuration,
    LeaseNextMessage, LimitProfile, MailboxStore, MessageCorrelation, MessageDeliveryState,
    MutableRequest, Mutation, OpenSession, OperationStore, PrepareLaunch, ProcessEvidence,
    ProjectionPageSize, ProjectionPageToken, ProjectionStore, ProjectionView, PublishArtifact,
    PutAuthorityPolicy, ReadEvents, ReadProjection, RecordRecoveryClassifications,
    RecoveryEventClassification, RecoveryEventEntity, RecoveryStore,
    RegisterAuthorityTemplatePolicy, RegisterTemplatesAndOpenSession, RegisterTool,
    ReleaseOwnership, RenewOwnership, RequestApproval, RequestContext, ReserveCapacity,
    ReserveEffect, ReserveSubscriptionLease, ReserveToolInvocation, ResolveAuthorizedEffect,
    ResourceLimit, RevokeApprovalGrant, SessionOpenMode, SessionStore, StartOperation, StoreError,
    StoredRequestOutcome, TakeoverEffect, TemplateRecord, ToolInvocationPhase,
    ToolInvocationSnapshot, ToolRegistrationSnapshot, ToolStore, ToolTransition, TransitionLaunch,
    TransitionMessageDelivery, TransitionOperation, TransitionToolInvocation,
};
use sha2::{Digest, Sha256};
use sqlx::{
    AssertSqlSafe, Connection, Executor, Row, SqliteConnection, sqlite::SqliteConnectOptions,
};
use tempfile::TempDir;
use tokio::sync::Barrier;
use tracing::{
    Event as TraceEvent, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use uuid::Uuid;

use crate::{
    SqliteStore,
    store::{
        projection_signature, set_approval_consume_pause, set_capacity_reserve_pause,
        wait_approval_consume_entered, wait_capacity_reserve_entered,
    },
};

fn fault_matrix_point_selected(point: &str) -> bool {
    std::env::var("NAVIGATOR_FAULT_MATRIX_ONLY").map_or(true, |only| only == point)
}

#[derive(Clone, Copy)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "conformance record intentionally exposes independent safety facts"
)]
struct DurableFaultFacts {
    no_duplicate_unfinished_participant: bool,
    no_duplicate_unfinished_operation: bool,
    no_orphan_reservation: bool,
    uncertain_effect_not_ordinarily_replayed: bool,
    stale_owner_cannot_commit: bool,
    unrelated_process_not_terminated: bool,
    classified_final_state: bool,
    duplicate_unfinished_participants: i64,
    duplicate_unfinished_operations: i64,
    orphan_violations: i64,
    stale_snapshot_unchanged: bool,
    stale_first_ledger_delta: i64,
    stale_replay_ledger_delta: i64,
    stale_domain_unchanged: bool,
    uncertain_replay_basis: &'static str,
}

async fn durable_stale_predecessor_rejected(store: &SqliteStore) -> (bool, i64, i64, bool) {
    let Some(session_text): Option<String> = sqlx::query_scalar(
        "SELECT session_id FROM sessions WHERE closed=0 ORDER BY session_id LIMIT 1",
    )
    .fetch_optional(store.pool())
    .await
    .unwrap() else {
        return (false, 0, 0, false);
    };
    let session = SessionId::from_uuid(Uuid::parse_str(&session_text).unwrap()).unwrap();
    let predecessor_host = host(9_990_001);
    let predecessor = match store.read_ownership(session).await.unwrap() {
        navigator_domain::OwnershipSnapshot::Owned {
            host_id,
            epoch,
            expires_at: _,
        } => {
            store
                .release_ownership(ReleaseOwnership::new(
                    context(9_990_002, host_id),
                    session,
                    epoch,
                ))
                .await
                .unwrap();
            (host_id, epoch)
        }
        navigator_domain::OwnershipSnapshot::Unowned => {
            let lease = store
                .acquire_ownership(AcquireOwnership::new(
                    context(9_990_003, predecessor_host),
                    session,
                    LeaseDuration::from_millis(60_000).unwrap(),
                ))
                .await
                .unwrap()
                .value()
                .clone();
            store
                .release_ownership(ReleaseOwnership::new(
                    context(9_990_004, predecessor_host),
                    session,
                    lease.epoch(),
                ))
                .await
                .unwrap();
            (predecessor_host, lease.epoch())
        }
    };
    let successor = host(9_990_005);
    store
        .acquire_ownership(AcquireOwnership::new(
            context(9_990_006, successor),
            session,
            LeaseDuration::from_millis(60_000).unwrap(),
        ))
        .await
        .unwrap();
    let before = store.read_ownership(session).await.unwrap();
    let before_request_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let first = store
        .renew_ownership(RenewOwnership::new(
            context(9_990_007, predecessor.0),
            session,
            predecessor.1,
            LeaseDuration::from_millis(60_000).unwrap(),
        ))
        .await;
    let after_first: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let replay = store
        .renew_ownership(RenewOwnership::new(
            context(9_990_007, predecessor.0),
            session,
            predecessor.1,
            LeaseDuration::from_millis(60_000).unwrap(),
        ))
        .await;
    let after_replay: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let first_delta = after_first - before_request_count;
    let replay_delta = after_replay - after_first;
    let domain_unchanged = before == store.read_ownership(session).await.unwrap();
    let proven = matches!(first, Err(StoreError::StaleOwnership { .. }))
        && matches!(replay, Err(StoreError::StaleOwnership { .. }))
        && first_delta == 1
        && replay_delta == 0
        && domain_unchanged;
    (proven, first_delta, replay_delta, domain_unchanged)
}

#[expect(
    clippy::too_many_lines,
    reason = "one adversarial sweep keeps cross-table invariant queries visible together"
)]
async fn observe_durable_fault_facts(
    store: &SqliteStore,
    replay_was_exact: bool,
    classified_final_state: bool,
) -> DurableFaultFacts {
    // These are business-key checks, not PK distinctness tautologies. A
    // Session has one unfinished hierarchy root and a Participant has at most
    // one unfinished Operation (the exact keys enforced by migrations/0003).
    let duplicate_unfinished_participants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (
           SELECT session_id FROM participants
           WHERE parent_participant_id IS NULL
           GROUP BY session_id HAVING COUNT(*) > 1
         )",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let duplicate_unfinished_operations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM (
           SELECT participant_id FROM operations
           WHERE terminal_outcome IS NULL
           GROUP BY participant_id HAVING COUNT(*) > 1
         )",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let foreign_key_violations = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(store.pool())
        .await
        .unwrap()
        .len();
    let capacity_pair_violations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM capacity_reservations r
         LEFT JOIN capacity_global_reservations g ON g.reservation_id=r.reservation_id
         WHERE g.reservation_id IS NULL OR g.resource<>r.resource OR g.amount<>r.amount OR g.released<>r.released",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let reverse_capacity_pair_violations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM capacity_global_reservations g
         LEFT JOIN capacity_reservations r ON r.reservation_id=g.reservation_id
         WHERE (r.reservation_id IS NULL AND g.resource<>'pending_requests')
            OR (r.reservation_id IS NOT NULL AND (g.resource<>r.resource OR g.amount<>r.amount OR g.released<>r.released))",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let capacity_usage_violations: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM capacity_session_usage u
         WHERE u.resource='subscriptions' AND u.used <> COALESCE((SELECT SUM(r.amount) FROM capacity_reservations r
          WHERE r.session_id=u.session_id AND r.resource=u.resource AND r.released=0),0)
         UNION ALL
         SELECT COUNT(*) FROM capacity_global_usage u
         WHERE u.resource IN ('subscriptions','pending_requests') AND u.used <> COALESCE((SELECT SUM(r.amount) FROM capacity_global_reservations r
          WHERE r.resource=u.resource AND r.released=0),0)",
    )
    .fetch_all(store.pool())
    .await
    .unwrap()
    .into_iter()
    .sum();
    let effect_owner_violations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM effect_journal e
         LEFT JOIN sessions s ON s.session_id=e.session_id
         LEFT JOIN participants p ON p.participant_id=e.participant_id AND p.session_id=e.session_id
         LEFT JOIN operations o ON o.operation_id=e.operation_id AND o.session_id=e.session_id
         WHERE s.session_id IS NULL OR p.participant_id IS NULL OR o.operation_id IS NULL",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let approval_intent_violations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_effect_intents i
         LEFT JOIN approval_grants g ON g.grant_id=i.grant_id AND g.session_id=i.session_id AND g.operation_id=i.operation_id
         WHERE g.grant_id IS NULL",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let artifact_owner_violations: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM artifacts a
         LEFT JOIN participants p ON p.participant_id=a.creator_participant_id AND p.session_id=a.session_id
         LEFT JOIN operations o ON o.operation_id=a.creator_operation_id AND o.session_id=a.session_id
         WHERE a.creator_participant_id IS NOT NULL AND (p.participant_id IS NULL OR o.operation_id IS NULL)",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let uncertain_effects: i64 = sqlx::query_scalar(
        "SELECT (SELECT COUNT(*) FROM effect_journal WHERE phase='uncertain') +
                (SELECT COUNT(*) FROM approval_effect_intents WHERE phase='uncertain')",
    )
    .fetch_one(store.pool())
    .await
    .unwrap();
    let (
        stale_snapshot_unchanged,
        stale_first_ledger_delta,
        stale_replay_ledger_delta,
        stale_domain_unchanged,
    ) = durable_stale_predecessor_rejected(store).await;
    let orphan_violations = i64::try_from(foreign_key_violations).unwrap()
        + capacity_pair_violations
        + reverse_capacity_pair_violations
        + capacity_usage_violations
        + effect_owner_violations
        + approval_intent_violations
        + artifact_owner_violations;
    DurableFaultFacts {
        no_duplicate_unfinished_participant: duplicate_unfinished_participants == 0,
        no_duplicate_unfinished_operation: duplicate_unfinished_operations == 0,
        no_orphan_reservation: orphan_violations == 0,
        uncertain_effect_not_ordinarily_replayed: replay_was_exact,
        stale_owner_cannot_commit: stale_snapshot_unchanged,
        unrelated_process_not_terminated: DURABLE_SENTINELS_SURVIVED.load(Ordering::SeqCst),
        classified_final_state,
        duplicate_unfinished_participants,
        duplicate_unfinished_operations,
        orphan_violations,
        stale_snapshot_unchanged,
        stale_first_ledger_delta,
        stale_replay_ledger_delta,
        stale_domain_unchanged,
        uncertain_replay_basis: if uncertain_effects == 0 {
            "non_applicable_no_uncertain_effect"
        } else if replay_was_exact {
            // The Store owns no provider receipt/call counter. Recovery of an
            // uncertain external effect is exclusively a reconciler action;
            // replay here is therefore deliberately non-applicable.
            "non_applicable_uncertain_receipt_owned_by_reconciler"
        } else {
            "uncertain_effect_replay_changed_receipt"
        },
    }
}

fn write_durable_fault_result(
    point: &str,
    committed: bool,
    facts: DurableFaultFacts,
    mut diagnostic: serde_json::Value,
) {
    let (Some(path), Ok(seed), Ok(only)) = (
        std::env::var_os("NAVIGATOR_FAULT_CASE_RESULT"),
        std::env::var("NAVIGATOR_FAULT_CASE_SEED"),
        std::env::var("NAVIGATOR_FAULT_MATRIX_ONLY"),
    ) else {
        return;
    };
    if only != point {
        return;
    }
    let seed: u64 = seed.parse().expect("fault matrix seed must be an integer");
    let object = diagnostic
        .as_object_mut()
        .expect("durable fault diagnostic must be an object");
    object.insert("observation_schema".into(), serde_json::json!("durable-v2"));
    object.insert(
        "duplicate_unfinished_participants".into(),
        serde_json::json!(facts.duplicate_unfinished_participants),
    );
    object.insert(
        "duplicate_unfinished_operations".into(),
        serde_json::json!(facts.duplicate_unfinished_operations),
    );
    object.insert(
        "orphan_violations".into(),
        serde_json::json!(facts.orphan_violations),
    );
    object.insert(
        "stale_predecessor_rejected_without_mutation".into(),
        serde_json::json!(facts.stale_snapshot_unchanged),
    );
    object.insert(
        "stale_first_ledger_delta".into(),
        serde_json::json!(facts.stale_first_ledger_delta),
    );
    object.insert(
        "stale_replay_ledger_delta".into(),
        serde_json::json!(facts.stale_replay_ledger_delta),
    );
    object.insert(
        "stale_domain_unchanged".into(),
        serde_json::json!(facts.stale_domain_unchanged),
    );
    object.insert(
        "uncertain_replay_basis".into(),
        serde_json::json!(facts.uncertain_replay_basis),
    );
    object.insert(
        "classification_basis".into(),
        serde_json::json!(if committed {
            "committed_row_and_exact_replay"
        } else {
            "prior_state_and_fresh_apply"
        }),
    );
    object.insert(
        "unrelated_process_and_socket_survived".into(),
        serde_json::json!(facts.unrelated_process_not_terminated),
    );
    let record = serde_json::json!({
        "schema_version": 1,
        "seed": seed,
        "fault_point": point,
        "actual_classification": if committed { "terminal" } else { "recoverable" },
        "facts": {
            "no_duplicate_unfinished_participant": facts.no_duplicate_unfinished_participant,
            "no_duplicate_unfinished_operation": facts.no_duplicate_unfinished_operation,
            "no_orphan_reservation": facts.no_orphan_reservation,
            "uncertain_effect_not_ordinarily_replayed": facts.uncertain_effect_not_ordinarily_replayed,
            "stale_owner_cannot_commit": facts.stale_owner_cannot_commit,
            "unrelated_process_not_terminated": facts.unrelated_process_not_terminated,
            "classified_final_state": facts.classified_final_state,
        },
        "diagnostics": diagnostic,
    });
    std::fs::write(path, serde_json::to_vec(&record).unwrap()).expect("write durable fault result");
}

#[derive(Clone, Default)]
struct TraceRecorder(Arc<Mutex<Vec<String>>>);

struct TraceVisitor<'a>(&'a Mutex<Vec<String>>);

impl Visit for TraceVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0.lock().unwrap().push(format!("{field}={value:?}"));
    }
}

async fn capacity_store_with_limit(
    directory: &TempDir,
    per_session: u64,
    global: u64,
) -> (SqliteStore, std::path::PathBuf, Arc<TestClock>) {
    let path = directory.path().join("capacity.db");
    let clock = Arc::new(TestClock::new(100));
    let limits = LimitProfile::new([(
        CapacityResource::ActiveOperations,
        ResourceLimit {
            per_session,
            global,
        },
    )])
    .unwrap();
    let store = SqliteStore::open_with_clock_and_limits(
        &path,
        clock.clone(),
        LeaseDuration::from_millis(60_000).unwrap(),
        limits.clone(),
    )
    .await
    .unwrap();
    store.open_session(open_command(120_000)).await.unwrap();
    store
        .acquire_ownership(acquire_command(120_001, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    (store, path, clock)
}

fn capacity_command(id: u128, amount: u64) -> ReserveCapacity {
    ReserveCapacity {
        reservation_id: RequestId::from_uuid(Uuid::from_u128(id)).unwrap(),
        session_id: session_id(),
        campaign_id: participant_command().participant_id,
        resource: CapacityResource::ActiveOperations,
        amount,
    }
}

#[tokio::test]
async fn capacity_exact_limit_plus_one_release_and_reopen_are_exactly_once() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = capacity_store_with_limit(&directory, 2, 2).await;
    let full = store
        .reserve_capacity(capacity_command(120_010, 2))
        .await
        .unwrap();
    assert!(!full.released);
    assert_eq!(
        store
            .reserve_capacity(capacity_command(120_010, 2))
            .await
            .unwrap(),
        full
    );
    assert_eq!(
        store.reserve_capacity(capacity_command(120_011, 1)).await,
        Err(StoreError::CapacityExceeded {
            reason: CapacityReason::SessionLimit {
                resource: CapacityResource::ActiveOperations
            }
        })
    );
    let released = store.release_capacity(full.reservation_id).await.unwrap();
    assert!(released.released);
    assert_eq!(
        store.release_capacity(full.reservation_id).await.unwrap(),
        released
    );
    store.pool().close().await;
    drop(store);
    let limits = LimitProfile::new([(
        CapacityResource::ActiveOperations,
        ResourceLimit {
            per_session: 2,
            global: 2,
        },
    )])
    .unwrap();
    let reopened = SqliteStore::open_with_clock_and_limits(
        &path,
        clock,
        LeaseDuration::from_millis(60_000).unwrap(),
        limits,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened
            .capacity_metrics(session_id())
            .await
            .unwrap()
            .into_iter()
            .find(|metric| metric.resource == CapacityResource::ActiveOperations)
            .unwrap()
            .session_used,
        0
    );
    reopened
        .reserve_capacity(capacity_command(120_012, 2))
        .await
        .unwrap();
}

#[tokio::test]
async fn concurrent_last_capacity_slot_has_exactly_one_winner() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = capacity_store_with_limit(&directory, 1, 1).await;
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for id in [120_020, 120_021] {
        let store = store.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.reserve_capacity(capacity_command(id, 1)).await
        }));
    }
    barrier.wait().await;
    let mut applied = 0;
    let mut capacity = 0;
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => applied += 1,
            Err(StoreError::CapacityExceeded { .. }) => capacity += 1,
            other => panic!("unexpected capacity result: {other:?}"),
        }
    }
    assert_eq!((applied, capacity), (1, 1));
    let metric = store
        .capacity_metrics(session_id())
        .await
        .unwrap()
        .into_iter()
        .find(|value| value.resource == CapacityResource::ActiveOperations)
        .unwrap();
    assert_eq!((metric.session_used, metric.global_used), (1, 1));
}

#[tokio::test]
async fn global_only_pending_requests_are_durable_across_pools_and_release_exactly_once() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("global-pending.db");
    let limits = LimitProfile::new([(
        CapacityResource::PendingRequests,
        ResourceLimit {
            per_session: 2,
            global: 1,
        },
    )])
    .unwrap_err();
    assert_eq!(
        limits,
        navigator_store_api::LimitProfileError::SessionExceedsGlobal
    );
    let limits = LimitProfile::new([(
        CapacityResource::PendingRequests,
        ResourceLimit {
            per_session: 1,
            global: 1,
        },
    )])
    .unwrap();
    let first = SqliteStore::open_with_limits(&path, limits.clone())
        .await
        .unwrap();
    let second = SqliteStore::open_with_limits(&path, limits.clone())
        .await
        .unwrap();
    let command = navigator_store_api::ReserveGlobalCapacity {
        reservation_id: RequestId::from_uuid(Uuid::from_u128(120_030)).unwrap(),
        resource: CapacityResource::PendingRequests,
        amount: 1,
    };
    let reserved = first.reserve_global_capacity(command).await.unwrap();
    assert_eq!(
        first.reserve_global_capacity(command).await.unwrap(),
        reserved
    );
    assert!(matches!(
        second
            .reserve_global_capacity(navigator_store_api::ReserveGlobalCapacity {
                reservation_id: RequestId::from_uuid(Uuid::from_u128(120_031)).unwrap(),
                ..command
            })
            .await,
        Err(StoreError::CapacityExceeded {
            reason: CapacityReason::GlobalLimit {
                resource: CapacityResource::PendingRequests
            }
        })
    ));
    let released = second
        .release_global_capacity(command.reservation_id)
        .await
        .unwrap();
    assert!(released.released);
    first.pool().close().await;
    second.pool().close().await;
    let reopened = SqliteStore::open_with_limits(&path, limits).await.unwrap();
    reopened
        .reserve_global_capacity(navigator_store_api::ReserveGlobalCapacity {
            reservation_id: RequestId::from_uuid(Uuid::from_u128(120_032)).unwrap(),
            ..command
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn global_capacity_is_atomic_across_sessions_and_reports_typed_reason() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = capacity_store_with_limit(&directory, 1, 1).await;
    let second_session = SessionId::from_uuid(Uuid::from_u128(120_100)).unwrap();
    store
        .open_session(OpenSession::new(
            context(120_101, host(30)),
            second_session,
            ConsumerKey::new("consumer-capacity-b").unwrap(),
            template_record().compatibility,
        ))
        .await
        .unwrap();
    let second_lease = store
        .acquire_ownership(AcquireOwnership::new(
            context(120_102, host(30)),
            second_session,
            LeaseDuration::from_millis(20_000).unwrap(),
        ))
        .await
        .unwrap()
        .value()
        .clone();
    let second_participant = ParticipantId::from_uuid(Uuid::from_u128(120_103)).unwrap();
    store
        .create_root_participant(CreateRootParticipant {
            context: context(120_104, host(30)),
            session_id: second_session,
            epoch: second_lease.epoch(),
            participant_id: second_participant,
            template_id: template_record().identity,
            expected_compatibility: template_record().compatibility,
        })
        .await
        .unwrap();
    store
        .reserve_capacity(capacity_command(120_105, 1))
        .await
        .unwrap();
    let second = ReserveCapacity {
        reservation_id: RequestId::from_uuid(Uuid::from_u128(120_106)).unwrap(),
        session_id: second_session,
        campaign_id: second_participant,
        resource: CapacityResource::ActiveOperations,
        amount: 1,
    };
    assert_eq!(
        store.reserve_capacity(second).await,
        Err(StoreError::CapacityExceeded {
            reason: CapacityReason::GlobalLimit {
                resource: CapacityResource::ActiveOperations
            },
        })
    );
}

#[tokio::test]
async fn abandoned_subscription_is_reclaimed_atomically_on_reopen() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = capacity_store_with_limit(&directory, 2, 2).await;
    let command = ReserveSubscriptionLease {
        reservation_id: RequestId::from_uuid(Uuid::from_u128(120_107)).unwrap(),
        session_id: session_id(),
        campaign_id: participant_command().participant_id,
        owner_host_id: host(20),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        expires_at: Timestamp::new(110, 0).unwrap(),
    };
    store.reserve_subscription_lease(command).await.unwrap();
    assert_eq!(
        store
            .capacity_metrics(session_id())
            .await
            .unwrap()
            .into_iter()
            .find(|metric| metric.resource == CapacityResource::Subscriptions)
            .unwrap()
            .session_used,
        1
    );
    sqlx::query(
        "UPDATE sessions SET owner_host_id=NULL,owner_epoch=NULL,owner_expires_at_seconds=NULL,owner_expires_at_nanos=NULL WHERE session_id=?",
    )
    .bind(session_id().to_string())
    .execute(store.pool())
    .await
    .unwrap();
    store.pool().close().await;
    drop(store);

    let reopened = SqliteStore::open_with_clock_and_limits(
        &path,
        clock,
        LeaseDuration::from_millis(60_000).unwrap(),
        LimitProfile::new([(
            CapacityResource::ActiveOperations,
            ResourceLimit {
                per_session: 2,
                global: 2,
            },
        )])
        .unwrap(),
    )
    .await
    .unwrap();
    let metric = reopened
        .capacity_metrics(session_id())
        .await
        .unwrap()
        .into_iter()
        .find(|metric| metric.resource == CapacityResource::Subscriptions)
        .unwrap();
    assert_eq!((metric.session_used, metric.global_used), (0, 0));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM capacity_reservations WHERE resource='subscriptions'",
        )
        .fetch_one(reopened.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "single multi-pool oracle keeps live, takeover, equality, and rollback phases causal"
)]
async fn concurrent_pool_preserves_live_subscription_and_takeover_reclaims_fenced_lease() {
    let directory = TempDir::new().unwrap();
    let (store_a, path, clock) = capacity_store_with_limit(&directory, 2, 2).await;
    let command = ReserveSubscriptionLease {
        reservation_id: RequestId::from_uuid(Uuid::from_u128(120_108)).unwrap(),
        session_id: session_id(),
        campaign_id: participant_command().participant_id,
        owner_host_id: host(20),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        expires_at: Timestamp::new(110, 0).unwrap(),
    };
    store_a
        .reserve_subscription_lease(command.clone())
        .await
        .unwrap();
    for index in 1_u128..32 {
        let mut additional = command.clone();
        additional.reservation_id = RequestId::from_uuid(Uuid::from_u128(120_108 + index)).unwrap();
        store_a
            .reserve_subscription_lease(additional)
            .await
            .unwrap();
    }
    let limits = LimitProfile::new([(
        CapacityResource::ActiveOperations,
        ResourceLimit {
            per_session: 2,
            global: 2,
        },
    )])
    .unwrap();
    let store_b = SqliteStore::open_with_clock_and_limits(
        &path,
        clock.clone(),
        LeaseDuration::from_millis(60_000).unwrap(),
        limits.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM subscription_leases")
            .fetch_one(store_b.pool())
            .await
            .unwrap(),
        32,
        "opening another pool must retain the live owner lease",
    );
    let mut over = command.clone();
    over.reservation_id = RequestId::from_uuid(Uuid::from_u128(120_150)).unwrap();
    assert_eq!(
        store_b.reserve_subscription_lease(over).await,
        Err(StoreError::CapacityExceeded {
            reason: CapacityReason::SessionLimit {
                resource: CapacityResource::Subscriptions,
            },
        }),
        "pool B must observe pool A's durable usage",
    );

    clock.set(121);
    store_b
        .acquire_ownership(acquire_command(120_209, host(30), 121, 141))
        .await
        .unwrap();
    let successor = ReserveSubscriptionLease {
        reservation_id: RequestId::from_uuid(Uuid::from_u128(120_210)).unwrap(),
        session_id: session_id(),
        campaign_id: participant_command().participant_id,
        owner_host_id: host(30),
        owner_epoch: FencingEpoch::new(2).unwrap(),
        expires_at: Timestamp::new(130, 0).unwrap(),
    };
    store_b
        .reserve_subscription_lease(successor.clone())
        .await
        .expect("takeover admission must reclaim fenced leases without reopen");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM subscription_leases")
            .fetch_one(store_b.pool())
            .await
            .unwrap(),
        1,
    );
    assert!(matches!(
        store_b.renew_subscription_lease(command).await,
        Err(StoreError::StaleOwnership { .. })
    ));
    clock.set(130);
    store_b
        .renew_ownership(RenewOwnership::new(
            context(120_211, host(30)),
            session_id(),
            FencingEpoch::new(2).unwrap(),
            LeaseDuration::from_millis(20_000).unwrap(),
        ))
        .await
        .unwrap();
    clock.set(100);
    let regressed = ReserveSubscriptionLease {
        reservation_id: RequestId::from_uuid(Uuid::from_u128(120_212)).unwrap(),
        expires_at: Timestamp::new(140, 0).unwrap(),
        ..successor
    };
    store_b
        .reserve_subscription_lease(regressed)
        .await
        .expect("durable floor equality reclaims expired lease despite clock rollback");
    store_b.pool().close().await;
    drop(store_b);
    let reopened = SqliteStore::open_with_clock_and_limits(
        &path,
        clock,
        LeaseDuration::from_millis(60_000).unwrap(),
        limits,
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM subscription_leases")
            .fetch_one(reopened.pool())
            .await
            .unwrap(),
        1,
        "only the current post-rollback lease remains",
    );
    let metric = reopened
        .capacity_metrics(session_id())
        .await
        .unwrap()
        .into_iter()
        .find(|metric| metric.resource == CapacityResource::Subscriptions)
        .unwrap();
    assert_eq!((metric.session_used, metric.global_used), (1, 1));
}

#[tokio::test]
async fn participant_admission_uses_the_central_profile_not_a_parallel_limit() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("participants-capacity.db");
    let clock = Arc::new(TestClock::new(100));
    let limits = LimitProfile::new([(
        CapacityResource::Participants,
        ResourceLimit {
            per_session: 1,
            global: 16,
        },
    )])
    .unwrap();
    let store = SqliteStore::open_with_clock_and_limits(
        &path,
        clock,
        LeaseDuration::from_millis(60_000).unwrap(),
        limits,
    )
    .await
    .unwrap();
    store.open_session(open_command(120_200)).await.unwrap();
    store
        .acquire_ownership(acquire_command(120_201, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .register_template(child_template_record())
        .await
        .unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    assert_eq!(
        store.create_child_participant(child_command()).await,
        Err(StoreError::CapacityExceeded {
            reason: CapacityReason::SessionLimit {
                resource: CapacityResource::Participants
            },
        })
    );
}

#[tokio::test]
async fn every_capacity_resource_has_an_exact_bound_and_plus_one_reason() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = capacity_store_with_limit(&directory, 256, 4_096).await;
    let metrics = store.capacity_metrics(session_id()).await.unwrap();
    for (index, metric) in metrics.into_iter().enumerate() {
        if metric.resource == CapacityResource::Subscriptions {
            continue;
        }
        let available = metric
            .session_limit
            .checked_sub(metric.session_used)
            .unwrap();
        if available == 0 {
            continue;
        }
        let exact = ReserveCapacity {
            reservation_id: RequestId::from_uuid(Uuid::from_u128(120_300 + index as u128 * 2))
                .unwrap(),
            session_id: session_id(),
            campaign_id: participant_command().participant_id,
            resource: metric.resource,
            amount: available,
        };
        store.reserve_capacity(exact).await.unwrap();
        let plus_one = ReserveCapacity {
            reservation_id: RequestId::from_uuid(Uuid::from_u128(120_301 + index as u128 * 2))
                .unwrap(),
            amount: 1,
            ..exact
        };
        assert_eq!(
            store.reserve_capacity(plus_one).await,
            Err(StoreError::CapacityExceeded {
                reason: CapacityReason::SessionLimit {
                    resource: metric.resource
                },
            }),
            "resource {:?} admitted +1",
            metric.resource
        );
        store.release_capacity(exact.reservation_id).await.unwrap();
    }
}

#[tokio::test]
async fn aborting_a_reservation_future_rolls_back_and_retry_commits_once() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = capacity_store_with_limit(&directory, 1, 1).await;
    let command = capacity_command(120_400, 1);
    set_capacity_reserve_pause(Some(command.reservation_id));
    let task_store = store.clone();
    let task = tokio::spawn(async move { task_store.reserve_capacity(command).await });
    wait_capacity_reserve_entered().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    set_capacity_reserve_pause(None);
    store.pool().close().await;
    drop(store);
    let limits = LimitProfile::new([(
        CapacityResource::ActiveOperations,
        ResourceLimit {
            per_session: 1,
            global: 1,
        },
    )])
    .unwrap();
    let reopened = SqliteStore::open_with_clock_and_limits(
        &path,
        clock,
        LeaseDuration::from_millis(60_000).unwrap(),
        limits,
    )
    .await
    .unwrap();
    let metric = reopened
        .capacity_metrics(session_id())
        .await
        .unwrap()
        .into_iter()
        .find(|value| value.resource == CapacityResource::ActiveOperations)
        .unwrap();
    assert_eq!((metric.session_used, metric.global_used), (0, 0));
    let applied = reopened.reserve_capacity(command).await.unwrap();
    assert_eq!(reopened.reserve_capacity(command).await.unwrap(), applied);
    let rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM capacity_reservations WHERE reservation_id=?")
            .bind(command.reservation_id.to_string())
            .fetch_one(reopened.pool())
            .await
            .unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn capacity_schema_and_accounting_mutants_fail_closed_on_reopen() {
    for mutant in [
        "missing-index",
        "counter-drift",
        "missing-counter",
        "missing-global-counter",
        "missing-limit",
        "limit-over-ceiling",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = capacity_store_with_limit(&directory, 2, 2).await;
        store
            .reserve_capacity(capacity_command(120_450, 1))
            .await
            .unwrap();
        store.pool().close().await;
        drop(store);

        let mut connection =
            SqliteConnection::connect_with(&SqliteConnectOptions::new().filename(&path))
                .await
                .unwrap();
        match mutant {
            "missing-index" => {
                connection
                    .execute("DROP INDEX capacity_reservations_session_resource")
                    .await
                    .unwrap();
            }
            "counter-drift" => {
                connection
                    .execute("UPDATE capacity_session_usage SET used=used+1")
                    .await
                    .unwrap();
            }
            "missing-counter" => {
                connection
                    .execute("DELETE FROM capacity_session_usage")
                    .await
                    .unwrap();
            }
            "missing-global-counter" => {
                connection
                    .execute("DELETE FROM capacity_global_usage")
                    .await
                    .unwrap();
            }
            "missing-limit" => {
                connection
                    .execute("DELETE FROM capacity_limits WHERE resource='subscriptions'")
                    .await
                    .unwrap();
            }
            "limit-over-ceiling" => {
                connection
                    .execute("UPDATE capacity_limits SET per_session=4194305,global_limit=4194305 WHERE resource='retained_events'")
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        connection.close().await.unwrap();

        let limits = LimitProfile::new([(
            CapacityResource::ActiveOperations,
            ResourceLimit {
                per_session: 2,
                global: 2,
            },
        )])
        .unwrap();
        assert!(matches!(
            SqliteStore::open_with_clock_and_limits(
                &path,
                clock,
                LeaseDuration::from_millis(60_000).unwrap(),
                limits,
            )
            .await,
            Err(StoreError::Corrupt)
        ));
    }
}

#[tokio::test]
async fn retained_event_admission_is_universal_exact_and_replay_is_free() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("retained-events.db");
    let limits = LimitProfile::new([(
        CapacityResource::RetainedEvents,
        ResourceLimit {
            per_session: 16,
            global: 16,
        },
    )])
    .unwrap();
    let store = SqliteStore::open_with_clock_and_limits(
        &path,
        Arc::new(TestClock::new(100)),
        LeaseDuration::from_millis(60_000).unwrap(),
        limits.clone(),
    )
    .await
    .unwrap();
    store.open_session(open_command(120_460)).await.unwrap();
    store
        .acquire_ownership(acquire_command(120_461, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    let root = store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    let before_replay: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE session_id=?")
        .bind(session_id().to_string())
        .fetch_one(store.pool())
        .await
        .unwrap();
    let replay = store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    assert!(matches!(replay, Mutation::Replayed(_)));
    assert_eq!(replay.value(), root.value());
    let after_replay: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE session_id=?")
        .bind(session_id().to_string())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(after_replay, before_replay);

    for index in usize::try_from(after_replay).unwrap()..16 {
        store
            .append_capacity_test_event(
                RequestId::from_uuid(Uuid::from_u128(120_500 + index as u128)).unwrap(),
                session_id(),
            )
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .append_capacity_test_event(
                RequestId::from_uuid(Uuid::from_u128(120_600)).unwrap(),
                session_id(),
            )
            .await,
        Err(StoreError::CapacityExceeded {
            reason: CapacityReason::SessionLimit {
                resource: CapacityResource::RetainedEvents,
            },
        })
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE session_id=?")
        .bind(session_id().to_string())
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 16);
    store.pool().close().await;
    drop(store);
    let reopened = SqliteStore::open_with_limits(&path, limits).await.unwrap();
    assert_eq!(
        reopened
            .append_capacity_test_event(
                RequestId::from_uuid(Uuid::from_u128(120_601)).unwrap(),
                session_id(),
            )
            .await,
        Err(StoreError::CapacityExceeded {
            reason: CapacityReason::SessionLimit {
                resource: CapacityResource::RetainedEvents,
            },
        })
    );
}

#[tokio::test]
async fn retained_event_append_crash_is_prior_or_full_and_retry_is_exact() {
    for point in [
        "event.append.before_insert",
        "event.append.after_insert",
        "event.append.after_commit",
    ] {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("retained-event-crash.db");
        let limits = LimitProfile::new([(
            CapacityResource::RetainedEvents,
            ResourceLimit {
                per_session: 16,
                global: 16,
            },
        )])
        .unwrap();
        let store = SqliteStore::open_with_clock_and_limits(
            &path,
            Arc::new(TestClock::new(100)),
            LeaseDuration::from_millis(60_000).unwrap(),
            limits.clone(),
        )
        .await
        .unwrap();
        store.open_session(open_command(120_680)).await.unwrap();
        store.pool().close().await;
        drop(store);
        let before: i64 = {
            let connection = SqliteStore::open_with_limits(&path, limits.clone())
                .await
                .unwrap();
            let value = sqlx::query_scalar("SELECT COUNT(*) FROM events")
                .fetch_one(connection.pool())
                .await
                .unwrap();
            connection.pool().close().await;
            value
        };
        run_crash_worker(&path, "event-append", point);
        let reopened = SqliteStore::open_with_limits(&path, limits.clone())
            .await
            .unwrap();
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        assert_eq!(after, before + i64::from(point.ends_with("after_commit")));
        reopened
            .append_capacity_test_event(
                RequestId::from_uuid(Uuid::from_u128(120_700)).unwrap(),
                session_id(),
            )
            .await
            .unwrap();
        let final_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        assert_eq!(final_count, before + 1);
        assert_integrity(&reopened).await;
    }
}

#[tokio::test]
async fn retained_event_global_limit_is_atomic_across_sessions() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("retained-events-global.db");
    let limits = LimitProfile::new([(
        CapacityResource::RetainedEvents,
        ResourceLimit {
            per_session: 16,
            global: 20,
        },
    )])
    .unwrap();
    let store = SqliteStore::open_with_limits(&path, limits).await.unwrap();
    store.open_session(open_command(120_720)).await.unwrap();
    let second = SessionId::from_uuid(Uuid::from_u128(120_721)).unwrap();
    store
        .open_session(OpenSession::new(
            context(120_722, host(30)),
            second,
            ConsumerKey::new("retained-global-b").unwrap(),
            template_record().compatibility,
        ))
        .await
        .unwrap();
    for (session, target, base) in [
        (session_id(), 12_i64, 120_730_u128),
        (second, 8_i64, 120_750_u128),
    ] {
        let current: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE session_id=?")
            .bind(session.to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert!(current <= target);
        for index in current..target {
            store
                .append_capacity_test_event(
                    RequestId::from_uuid(Uuid::from_u128(base + u128::try_from(index).unwrap()))
                        .unwrap(),
                    session,
                )
                .await
                .unwrap();
        }
    }
    assert_eq!(
        store
            .append_capacity_test_event(
                RequestId::from_uuid(Uuid::from_u128(120_780)).unwrap(),
                second,
            )
            .await,
        Err(StoreError::CapacityExceeded {
            reason: CapacityReason::GlobalLimit {
                resource: CapacityResource::RetainedEvents,
            },
        })
    );
}

#[tokio::test]
async fn capacity_reserve_and_release_crashes_are_prior_or_full_and_retry_converges() {
    for (operation, points) in [
        (
            "capacity-reserve",
            &[
                "capacity.reserve.after_reservation",
                "capacity.reserve.after_accounting",
                "capacity.reserve.after_commit",
            ][..],
        ),
        (
            "capacity-release",
            &[
                "capacity.release.after_reservation",
                "capacity.release.after_accounting",
                "capacity.release.after_commit",
            ][..],
        ),
    ] {
        for point in points {
            let directory = TempDir::new().unwrap();
            let (store, path, clock) = capacity_store_with_limit(&directory, 8, 8).await;
            if operation == "capacity-release" {
                store
                    .reserve_capacity(capacity_command(120_501, 1))
                    .await
                    .unwrap();
            }
            store.pool().close().await;
            drop(store);
            run_crash_worker(&path, operation, point);
            let reopened = SqliteStore::open_with_clock_and_limits(
                &path,
                clock,
                LeaseDuration::from_millis(60_000).unwrap(),
                LimitProfile::new([(
                    CapacityResource::ActiveOperations,
                    ResourceLimit {
                        per_session: 8,
                        global: 8,
                    },
                )])
                .unwrap(),
            )
            .await
            .unwrap();
            let committed = point.ends_with("after_commit");
            let row: Option<i64> = sqlx::query_scalar(
                "SELECT released FROM capacity_reservations WHERE reservation_id=?",
            )
            .bind(
                if operation == "capacity-reserve" {
                    capacity_command(120_500, 1).reservation_id
                } else {
                    capacity_command(120_501, 1).reservation_id
                }
                .to_string(),
            )
            .fetch_optional(reopened.pool())
            .await
            .unwrap();
            assert_eq!(
                row,
                if operation == "capacity-reserve" {
                    committed.then_some(0)
                } else {
                    Some(i64::from(committed))
                }
            );
            if operation == "capacity-reserve" {
                let applied = reopened
                    .reserve_capacity(capacity_command(120_500, 1))
                    .await
                    .unwrap();
                assert!(!applied.released);
            } else {
                let released = reopened
                    .release_capacity(capacity_command(120_501, 1).reservation_id)
                    .await
                    .unwrap();
                assert!(released.released);
            }
            let count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM capacity_reservations WHERE reservation_id=?",
            )
            .bind(
                if operation == "capacity-reserve" {
                    capacity_command(120_500, 1).reservation_id
                } else {
                    capacity_command(120_501, 1).reservation_id
                }
                .to_string(),
            )
            .fetch_one(reopened.pool())
            .await
            .unwrap();
            assert_eq!(count, 1);
        }
    }
}

impl Subscriber for TraceRecorder {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &TraceEvent<'_>) {
        event.record(&mut TraceVisitor(&self.0));
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn session_id() -> SessionId {
    SessionId::from_uuid(Uuid::from_u128(1)).unwrap()
}

fn host(value: u128) -> HostId {
    HostId::from_uuid(Uuid::from_u128(value)).unwrap()
}

fn context(request: u128, caller: HostId) -> RequestContext {
    RequestContext::new(
        RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
        caller,
    )
}

fn open_command(request: u128) -> OpenSession {
    OpenSession::new(
        context(request, host(10)),
        session_id(),
        ConsumerKey::new("consumer-a").unwrap(),
        template_record().compatibility,
    )
}

fn acquire_command(request: u128, caller: HostId, observed: i64, expires: i64) -> AcquireOwnership {
    AcquireOwnership::new(
        context(request, caller),
        session_id(),
        LeaseDuration::from_millis(u64::try_from(expires - observed).unwrap() * 1_000).unwrap(),
    )
}

#[derive(Debug)]
struct TestClock(AtomicI64);

impl TestClock {
    fn new(seconds: i64) -> Self {
        Self(AtomicI64::new(seconds))
    }
    fn set(&self, seconds: i64) {
        self.0.store(seconds, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn wall_now(&self) -> time::OffsetDateTime {
        time::OffsetDateTime::from_unix_timestamp(self.0.load(Ordering::SeqCst)).unwrap()
    }
    fn monotonic_now(&self) -> MonotonicInstant {
        MonotonicInstant::from_ticks(0)
    }
}

async fn new_store(directory: &TempDir) -> (SqliteStore, std::path::PathBuf, Arc<TestClock>) {
    let path = directory.path().join("navigator.db");
    let clock = Arc::new(TestClock::new(100));
    let store = SqliteStore::open_with_clock(
        &path,
        clock.clone(),
        LeaseDuration::from_millis(60_000).unwrap(),
    )
    .await
    .unwrap();
    (store, path, clock)
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one lifecycle oracle covers quota conversion, replay, deletion, and erasure"
)]
async fn artifact_metadata_is_fenced_idempotent_and_erasure_is_retention_separated() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let owner = host(20);
    let lease_epoch = FencingEpoch::new(1).unwrap();
    let artifact_id = ArtifactId::from_uuid(Uuid::from_u128(90_002)).unwrap();
    let artifact_reservation_id = RequestId::from_uuid(Uuid::from_u128(90_004)).unwrap();
    let byte_reservation_id = RequestId::from_uuid(Uuid::from_u128(90_005)).unwrap();
    for (reservation_id, resource, amount) in [
        (artifact_reservation_id, CapacityResource::Artifacts, 1),
        (byte_reservation_id, CapacityResource::ArtifactBytes, 3),
    ] {
        store
            .reserve_capacity(ReserveCapacity {
                reservation_id,
                session_id: session_id(),
                campaign_id: participant_command().participant_id,
                resource,
                amount,
            })
            .await
            .unwrap();
    }
    let publish = PublishArtifact {
        context: context(90_003, owner),
        session_id: session_id(),
        owner,
        epoch: lease_epoch,
        artifact_id,
        creator_participant_id: participant_command().participant_id,
        creator_operation_id: start_operation_command().operation_id,
        media_type: ArtifactMediaType::new("application/octet-stream").unwrap(),
        size: 3,
        digest: ArtifactDigest::from_bytes([4; 32]),
        locator: format!("{}/{}.blob", session_id(), artifact_id),
        retention_until: Timestamp::new(120, 0).unwrap(),
        artifact_reservation_id,
        byte_reservation_id: Some(byte_reservation_id),
    };
    let first = store.publish_artifact(publish.clone()).await.unwrap();
    assert!(matches!(first, Mutation::Applied(_)));
    assert!(matches!(
        store.publish_artifact(publish).await.unwrap(),
        Mutation::Replayed(_)
    ));
    let access = ArtifactAccess {
        session_id: session_id(),
        owner,
        epoch: lease_epoch,
        artifact_id,
    };
    assert_eq!(
        store.load_artifact(access).await.unwrap().state,
        ArtifactState::Available
    );
    let deleted = store
        .logically_delete_artifact(DeleteArtifact {
            context: context(90_004, owner),
            session_id: session_id(),
            owner,
            epoch: lease_epoch,
            artifact_id,
        })
        .await
        .unwrap();
    assert_eq!(deleted.value().state, ArtifactState::LogicallyDeleted);
    assert!(matches!(
        store.load_artifact(access).await,
        Err(StoreError::ArtifactNotFound { .. })
    ));
    assert!(
        store
            .retention_eligible_artifacts(Timestamp::new(119, 0).unwrap(), 10)
            .await
            .unwrap()
            .is_empty()
    );
    clock.set(120);
    assert_eq!(
        store
            .retention_eligible_artifacts(Timestamp::new(120, 0).unwrap(), 10)
            .await
            .unwrap()
            .len(),
        1
    );
    let forged = EraseArtifact {
        context: context(90_006, host(21)),
        session_id: session_id(),
        owner: host(21),
        epoch: lease_epoch,
        artifact_id,
    };
    assert!(matches!(
        store.authorize_physical_erasure(&forged).await,
        Err(StoreError::StaleOwnership { .. })
    ));
    let erase = EraseArtifact {
        context: context(90_005, owner),
        session_id: session_id(),
        owner,
        epoch: lease_epoch,
        artifact_id,
    };
    let erased = store.record_physical_erasure(erase).await.unwrap();
    assert_eq!(erased.state, ArtifactState::PhysicallyErased);
    assert!(
        store
            .retention_eligible_artifacts(Timestamp::new(121, 0).unwrap(), 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn zero_byte_artifact_converts_only_the_count_reservation_atomically() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let owner = host(20);
    let artifact_id = ArtifactId::from_uuid(Uuid::from_u128(90_102)).unwrap();
    let artifact_reservation_id = RequestId::from_uuid(Uuid::from_u128(90_104)).unwrap();
    store
        .reserve_capacity(ReserveCapacity {
            reservation_id: artifact_reservation_id,
            session_id: session_id(),
            campaign_id: participant_command().participant_id,
            resource: CapacityResource::Artifacts,
            amount: 1,
        })
        .await
        .unwrap();
    let publish = PublishArtifact {
        context: context(90_103, owner),
        session_id: session_id(),
        owner,
        epoch: FencingEpoch::new(1).unwrap(),
        artifact_id,
        creator_participant_id: participant_command().participant_id,
        creator_operation_id: start_operation_command().operation_id,
        media_type: ArtifactMediaType::new("application/octet-stream").unwrap(),
        size: 0,
        digest: ArtifactDigest::from_bytes([0; 32]),
        locator: format!("{}/{}.blob", session_id(), artifact_id),
        retention_until: Timestamp::new(120, 0).unwrap(),
        artifact_reservation_id,
        byte_reservation_id: None,
    };
    assert!(matches!(
        store.publish_artifact(publish.clone()).await.unwrap(),
        Mutation::Applied(_)
    ));
    assert!(matches!(
        store.publish_artifact(publish).await.unwrap(),
        Mutation::Replayed(_)
    ));
    let metrics = store.capacity_metrics(session_id()).await.unwrap();
    assert_eq!(
        metrics
            .iter()
            .find(|metric| metric.resource == CapacityResource::ArtifactBytes)
            .unwrap()
            .session_used,
        0
    );
}

#[tokio::test]
async fn recovery_inventory_is_fenced_and_classifications_commit_once_atomically() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    store.open_session(open_command(70_000)).await.unwrap();
    let lease = store
        .acquire_ownership(acquire_command(70_001, host(20), 100, 120))
        .await
        .unwrap()
        .value()
        .clone();
    assert!(matches!(
        store
            .load_recovery_inventory(session_id(), host(21), lease.epoch())
            .await,
        Err(StoreError::StaleOwnership { .. })
    ));
    let inventory = store
        .load_recovery_inventory(session_id(), host(20), lease.epoch())
        .await
        .unwrap();
    assert_eq!(inventory.session_id, session_id());
    assert!(inventory.operations.is_empty());

    let command = RecordRecoveryClassifications {
        context: context(70_002, host(20)),
        session_id: session_id(),
        epoch: lease.epoch(),
        classifications: vec![RecoveryEventClassification {
            entity: RecoveryEventEntity::Session(session_id()),
            state: navigator_domain::RecoveryState::SessionOpen,
            observation: navigator_domain::LiveObservation::NotApplicable,
            decision: navigator_domain::classify_recovery(
                navigator_domain::RecoveryState::SessionOpen,
                navigator_domain::LiveObservation::NotApplicable,
            )
            .unwrap(),
        }],
    };
    let mut forged = command.clone();
    forged.classifications[0] = RecoveryEventClassification {
        entity: RecoveryEventEntity::Participant(
            ParticipantId::from_uuid(Uuid::from_u128(70_099)).unwrap(),
        ),
        state: navigator_domain::RecoveryState::ParticipantRegistered,
        observation: navigator_domain::LiveObservation::NotApplicable,
        decision: navigator_domain::classify_recovery(
            navigator_domain::RecoveryState::ParticipantRegistered,
            navigator_domain::LiveObservation::NotApplicable,
        )
        .unwrap(),
    };
    assert_eq!(
        store.record_recovery_classifications(forged).await,
        Err(StoreError::Invalid)
    );
    store
        .record_recovery_classifications(command.clone())
        .await
        .unwrap();
    assert_recovery_replay_conflicts(&store, &clock, command).await;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE event_type='recovery.classified'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(count, 1);
}

async fn assert_recovery_replay_conflicts(
    store: &SqliteStore,
    clock: &TestClock,
    command: RecordRecoveryClassifications,
) {
    store
        .record_recovery_classifications(command.clone())
        .await
        .unwrap();
    let mut changed_payload = command.clone();
    changed_payload
        .classifications
        .push(RecoveryEventClassification {
            entity: RecoveryEventEntity::Participant(
                ParticipantId::from_uuid(Uuid::from_u128(70_098)).unwrap(),
            ),
            state: navigator_domain::RecoveryState::ParticipantRegistered,
            observation: navigator_domain::LiveObservation::NotApplicable,
            decision: navigator_domain::classify_recovery(
                navigator_domain::RecoveryState::ParticipantRegistered,
                navigator_domain::LiveObservation::NotApplicable,
            )
            .unwrap(),
        });
    assert!(matches!(
        store.record_recovery_classifications(changed_payload).await,
        Err(StoreError::RequestConflict { .. })
    ));
    clock.set(121);
    let replacement = store
        .acquire_ownership(acquire_command(70_003, host(21), 121, 141))
        .await
        .unwrap()
        .value()
        .clone();
    let mut changed_caller_epoch = command;
    changed_caller_epoch.context = context(70_002, host(21));
    changed_caller_epoch.epoch = replacement.epoch();
    assert!(matches!(
        store
            .record_recovery_classifications(changed_caller_epoch)
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
}

#[tokio::test]
async fn recovery_classification_crash_is_prior_or_one_atomic_event() {
    for (point, committed) in [
        ("recovery.classifications.before_commit", false),
        ("recovery.classifications.after_commit", true),
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        store.open_session(open_command(70_100)).await.unwrap();
        store
            .acquire_ownership(acquire_command(70_101, host(20), 100, 120))
            .await
            .unwrap();
        store.register_template(template_record()).await.unwrap();
        store
            .create_root_participant(participant_command())
            .await
            .unwrap();
        store
            .start_operation(start_operation_command())
            .await
            .unwrap();
        drop(store);
        run_crash_worker(&path, "recovery-classify", point);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recovery_classifications")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events WHERE event_type='recovery.classified'",
        )
        .fetch_one(reopened.pool())
        .await
        .unwrap();
        assert_eq!(rows, i64::from(committed));
        assert_eq!(events, i64::from(committed));
        if committed {
            let payload: Vec<u8> = sqlx::query_scalar(
                "SELECT payload FROM recovery_classifications WHERE request_id=?",
            )
            .bind(context(70_102, host(20)).request_id().to_string())
            .fetch_one(reopened.pool())
            .await
            .unwrap();
            let rows: Vec<RecoveryEventClassification> = serde_json::from_slice(&payload).unwrap();
            assert_eq!(rows.len(), 4);
        }
    }
}

#[tokio::test]
async fn recovery_classification_rejects_a_stale_entity_state() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(70_200)).await.unwrap();
    store
        .acquire_ownership(acquire_command(70_201, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    store
        .start_operation(start_operation_command())
        .await
        .unwrap();
    let state = navigator_domain::RecoveryState::OperationQueued;
    let observation = navigator_domain::LiveObservation::NotApplicable;
    let stale_batch = RecordRecoveryClassifications {
        context: context(70_202, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        classifications: vec![RecoveryEventClassification {
            entity: RecoveryEventEntity::Operation(start_operation_command().operation_id),
            state,
            observation,
            decision: navigator_domain::classify_recovery(state, observation).unwrap(),
        }],
    };
    store
        .transition_operation(transition_operation_command())
        .await
        .unwrap();
    assert_eq!(
        store.record_recovery_classifications(stale_batch).await,
        Err(StoreError::Invalid)
    );
}

#[tokio::test]
async fn recovery_classification_rejects_changed_session_replay_and_real_cross_session_entity() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    let other_session = SessionId::from_uuid(Uuid::from_u128(70_300)).unwrap();
    let other_participant = ParticipantId::from_uuid(Uuid::from_u128(70_301)).unwrap();
    store.open_session(open_command(70_302)).await.unwrap();
    store
        .acquire_ownership(acquire_command(70_303, host(20), 100, 120))
        .await
        .unwrap();
    store
        .open_session(OpenSession::new(
            context(70_304, host(20)),
            other_session,
            ConsumerKey::new("recovery-other-session").unwrap(),
            template_record().compatibility,
        ))
        .await
        .unwrap();
    let other_lease = store
        .acquire_ownership(AcquireOwnership::new(
            context(70_305, host(20)),
            other_session,
            LeaseDuration::from_millis(20_000).unwrap(),
        ))
        .await
        .unwrap()
        .value()
        .clone();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(CreateRootParticipant {
            context: context(70_306, host(20)),
            session_id: other_session,
            epoch: other_lease.epoch(),
            participant_id: other_participant,
            template_id: template_record().identity,
            expected_compatibility: template_record().compatibility,
        })
        .await
        .unwrap();

    let session_decision = navigator_domain::classify_recovery(
        navigator_domain::RecoveryState::SessionOpen,
        navigator_domain::LiveObservation::NotApplicable,
    )
    .unwrap();
    let original = RecordRecoveryClassifications {
        context: context(70_307, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        classifications: vec![RecoveryEventClassification {
            entity: RecoveryEventEntity::Session(session_id()),
            state: navigator_domain::RecoveryState::SessionOpen,
            observation: navigator_domain::LiveObservation::NotApplicable,
            decision: session_decision,
        }],
    };
    store
        .record_recovery_classifications(original.clone())
        .await
        .unwrap();
    let before = recovery_mutation_counts(&store).await;

    let mut changed_session = original;
    changed_session.context = RequestContext::new(
        RequestId::from_uuid(Uuid::from_u128(70_307)).unwrap(),
        host(20),
    );
    changed_session.session_id = other_session;
    changed_session.epoch = other_lease.epoch();
    changed_session.classifications[0].entity = RecoveryEventEntity::Session(other_session);
    assert!(matches!(
        store.record_recovery_classifications(changed_session).await,
        Err(StoreError::RequestConflict { .. })
    ));
    assert_eq!(recovery_mutation_counts(&store).await, before);

    let participant_state = navigator_domain::RecoveryState::ParticipantRegistered;
    let cross_session = RecordRecoveryClassifications {
        context: context(70_308, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        classifications: vec![RecoveryEventClassification {
            entity: RecoveryEventEntity::Participant(other_participant),
            state: participant_state,
            observation: navigator_domain::LiveObservation::NotApplicable,
            decision: navigator_domain::classify_recovery(
                participant_state,
                navigator_domain::LiveObservation::NotApplicable,
            )
            .unwrap(),
        }],
    };
    assert_eq!(
        store.record_recovery_classifications(cross_session).await,
        Err(StoreError::Invalid)
    );
    assert_eq!(recovery_mutation_counts(&store).await, before);
}

async fn recovery_mutation_counts(store: &SqliteStore) -> (i64, i64) {
    let rows = sqlx::query_scalar("SELECT COUNT(*) FROM recovery_classifications")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let events =
        sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE event_type='recovery.classified'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    (rows, events)
}

#[tokio::test]
async fn launch_mutations_are_globally_idempotent_fenced_and_validate_identity() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    store.open_session(open_command(900)).await.unwrap();
    let lease = store
        .acquire_ownership(acquire_command(901, host(20), 100, 120))
        .await
        .unwrap()
        .value()
        .clone();
    let attempt = LaunchAttemptId::from_uuid(Uuid::from_u128(902)).unwrap();
    let prepare = PrepareLaunch {
        context: context(903, host(20)),
        epoch: lease.epoch(),
        session_id: session_id(),
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(904)).unwrap(),
        driver_id: DriverId::from_uuid(Uuid::from_u128(905)).unwrap(),
        attempt_id: attempt,
        credential_digest: [9; 32],
        driver_configuration_digest: [19; 32],
    };
    assert!(matches!(
        store.prepare_launch(prepare.clone()).await.unwrap(),
        Mutation::Applied(_)
    ));
    assert!(matches!(
        store.prepare_launch(prepare).await.unwrap(),
        Mutation::Replayed(_)
    ));
    assert!(store.session_has_launches(session_id()).await.unwrap());
    assert!(
        store
            .session_has_unresolved_launches(session_id())
            .await
            .unwrap()
    );
    sqlx::query("UPDATE launch_attempts SET state = 'cleanup_required' WHERE attempt_id = ?")
        .bind(attempt.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(
        store
            .session_has_unresolved_launches(session_id())
            .await
            .unwrap()
    );
    sqlx::query("UPDATE launch_attempts SET state = 'stopped' WHERE attempt_id = ?")
        .bind(attempt.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert!(store.session_has_launches(session_id()).await.unwrap());
    assert!(
        !store
            .session_has_unresolved_launches(session_id())
            .await
            .unwrap()
    );

    let invalid = AttachLaunch {
        context: context(906, host(20)),
        session_id: session_id(),
        epoch: lease.epoch(),
        attempt_id: attempt,
        expected_revision: Revision::initial(),
        instance_id: InstanceId::from_uuid(Uuid::from_u128(907)).unwrap(),
        evidence: ProcessEvidence {
            process_id: 0,
            process_group_id: 1,
            parent_process_id: 1,
            creation_marker: 1,
            executable_identity: [1; 32],
        },
    };
    assert_eq!(store.attach_launch(invalid).await, Err(StoreError::Invalid));

    clock.set(120);
    assert!(matches!(
        store
            .validate_launch_authority(session_id(), host(20), lease.epoch())
            .await,
        Err(StoreError::OwnershipExpired { .. })
    ));
    let conflicting = PrepareLaunch {
        context: context(903, host(20)),
        epoch: lease.epoch(),
        session_id: session_id(),
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(908)).unwrap(),
        driver_id: DriverId::from_uuid(Uuid::from_u128(905)).unwrap(),
        attempt_id: LaunchAttemptId::from_uuid(Uuid::from_u128(909)).unwrap(),
        credential_digest: [9; 32],
        driver_configuration_digest: [19; 32],
    };
    assert_eq!(
        store.prepare_launch(conflicting).await,
        Err(StoreError::RequestConflict {
            request_id: RequestId::from_uuid(Uuid::from_u128(903)).unwrap()
        })
    );
    corrupt_launch_configuration_digest(&store, attempt).await;
    assert_eq!(store.load_launch(attempt).await, Err(StoreError::Corrupt));
}

#[tokio::test]
async fn launch_authority_validation_remains_read_only_while_writer_is_busy() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(910)).await.unwrap();
    let lease = store
        .acquire_ownership(acquire_command(911, host(20), 100, 120))
        .await
        .unwrap()
        .value()
        .clone();

    let mut writer = store.pool().acquire().await.unwrap();
    writer.execute("BEGIN IMMEDIATE").await.unwrap();
    tokio::time::timeout(
        Duration::from_millis(500),
        store.validate_launch_authority(session_id(), host(20), lease.epoch()),
    )
    .await
    .expect("authority validation must not wait for SQLite's writer lock")
    .unwrap();
    writer.execute("ROLLBACK").await.unwrap();
}

#[tokio::test]
async fn expired_launch_authority_cannot_resurrect_after_clock_regression_or_reopen() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    store.open_session(open_command(912)).await.unwrap();
    let lease = store
        .acquire_ownership(acquire_command(913, host(20), 100, 120))
        .await
        .unwrap()
        .value()
        .clone();

    clock.set(121);
    assert!(matches!(
        store
            .validate_launch_authority(session_id(), host(20), lease.epoch())
            .await,
        Err(StoreError::OwnershipExpired { .. })
    ));
    clock.set(110);
    assert!(matches!(
        store
            .validate_launch_authority(session_id(), host(20), lease.epoch())
            .await,
        Err(StoreError::OwnershipExpired { .. })
    ));

    drop(store);
    let reopened =
        SqliteStore::open_with_clock(path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    assert!(matches!(
        reopened
            .validate_launch_authority(session_id(), host(20), lease.epoch())
            .await,
        Err(StoreError::OwnershipExpired { .. })
    ));
}

async fn corrupt_launch_configuration_digest(store: &SqliteStore, attempt: LaunchAttemptId) {
    let mut connection = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE launch_attempts SET driver_configuration_digest = X'01' WHERE attempt_id = ?",
    )
    .bind(attempt.to_string())
    .execute(&mut *connection)
    .await
    .unwrap();
}

#[tokio::test]
async fn reopen_preserves_snapshot_events_and_replay() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    let created = store.open_session(open_command(100)).await.unwrap();
    assert!(matches!(created, Mutation::Applied(_)));
    store.pool().close().await;

    let reopened =
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap_or_else(|error| panic!("v3 upgrade failed: {error:?}"));
    assert_eq!(
        reopened
            .load_session(session_id())
            .await
            .unwrap()
            .revision()
            .get(),
        1
    );
    assert!(matches!(
        reopened.open_session(open_command(100)).await.unwrap(),
        Mutation::Replayed(_)
    ));
    let page = reopened
        .read_events(ReadEvents {
            session_id: session_id(),
            consumer: ConsumerKey::new("consumer-a").unwrap(),
            after: None,
            limit: EventReadLimit::new(10).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].event_type().as_str(), "session.created");
    assert_eq!(page.events[0].schema_version().get(), 1);
    let payload: serde_json::Value =
        serde_json::from_slice(page.events[0].data().as_slice()).unwrap();
    assert_eq!(payload["schema_version"], 1);
    assert_eq!(payload["status"], "open");
    assert_eq!(payload["revision"], 1);
    let rendered = String::from_utf8(page.events[0].data().as_slice().to_vec()).unwrap();
    assert!(!rendered.contains("consumer-a"));
    assert_eq!(
        page.events[0].related_request_id(),
        Some(RequestId::from_uuid(Uuid::from_u128(100)).unwrap())
    );
}

#[tokio::test]
async fn required_sqlite_durability_pragmas_are_active() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let busy_timeout: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(journal, "wal");
    assert_eq!(synchronous, 2);
    assert_eq!(foreign_keys, 1);
    assert_eq!(busy_timeout, 5_000);
}

#[tokio::test]
async fn semantic_failure_is_durable_and_replayed_after_conditions_change() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    store.open_session(open_command(109)).await.unwrap();
    store
        .acquire_ownership(acquire_command(209, host(20), 100, 120))
        .await
        .unwrap();
    let rejected = acquire_command(210, host(21), 100, 120);
    assert!(matches!(
        store.acquire_ownership(rejected.clone()).await,
        Err(StoreError::OwnershipHeld { .. })
    ));
    let stored = store
        .read_request(RequestId::from_uuid(Uuid::from_u128(210)).unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        stored.outcome(),
        StoredRequestOutcome::Failed(StoreError::OwnershipHeld { .. })
    ));

    clock.set(121);
    assert!(matches!(
        store.acquire_ownership(rejected).await,
        Err(StoreError::OwnershipHeld { .. })
    ));
}

#[tokio::test]
// Guarantees: NAV-STORE-001
async fn lifecycle_and_event_are_one_atomic_commit() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    sqlx::query(
        "CREATE TRIGGER reject_event BEFORE INSERT ON events
         BEGIN SELECT RAISE(ABORT, 'injected event failure'); END",
    )
    .execute(store.pool())
    .await
    .unwrap();

    assert_eq!(
        store.open_session(open_command(101)).await.unwrap_err(),
        StoreError::Unavailable
    );
    assert_eq!(
        store.load_session(session_id()).await.unwrap_err(),
        StoreError::SessionNotFound {
            session_id: session_id()
        }
    );
    sqlx::query("DROP TRIGGER reject_event")
        .execute(store.pool())
        .await
        .unwrap();
    assert!(matches!(
        store.open_session(open_command(101)).await.unwrap(),
        Mutation::Applied(_)
    ));
}

#[tokio::test]
async fn logical_close_releases_owner_and_survives_reopen_with_history() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    store.open_session(open_command(111)).await.unwrap();
    let lease = store
        .acquire_ownership(acquire_command(211, host(20), 100, 120))
        .await
        .unwrap()
        .value()
        .clone();
    let close = CloseSession::new(context(212, host(20)), session_id(), lease.epoch());
    let closed = store.close_session(close.clone()).await.unwrap();
    assert_eq!(closed.value().status(), SessionStatus::Closed);
    assert_eq!(
        store.read_ownership(session_id()).await.unwrap(),
        navigator_domain::OwnershipSnapshot::Unowned
    );
    assert!(matches!(
        store.close_session(close).await.unwrap(),
        Mutation::Replayed(_)
    ));
    assert_eq!(
        store
            .close_session(CloseSession::new(
                context(213, host(20)),
                session_id(),
                lease.epoch(),
            ))
            .await
            .unwrap_err(),
        StoreError::AlreadyClosed {
            session_id: session_id()
        }
    );
    store.pool().close().await;

    let reopened =
        SqliteStore::open_with_clock(path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    assert_eq!(
        reopened.load_session(session_id()).await.unwrap().status(),
        SessionStatus::Closed
    );
    let events = reopened
        .read_events(ReadEvents {
            session_id: session_id(),
            consumer: ConsumerKey::new("consumer-a").unwrap(),
            after: None,
            limit: EventReadLimit::new(10).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(
        events
            .events
            .iter()
            .map(|event| event.event_type().as_str())
            .collect::<Vec<_>>(),
        ["session.created", "ownership.acquired", "session.closed"]
    );
}

#[tokio::test]
async fn release_upgrade_v18_to_v20_preserves_compatible_session() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("stateful-v18.db");
    let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
        .unwrap()
        .create_if_missing(true);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    for migration in [
        include_str!("../migrations/0001.sql"),
        include_str!("../migrations/0002.sql"),
        include_str!("../migrations/0003.sql"),
        include_str!("../migrations/0004.sql"),
        include_str!("../migrations/0005.sql"),
        include_str!("../migrations/0006.sql"),
        include_str!("../migrations/0007.sql"),
        include_str!("../migrations/0008.sql"),
        include_str!("../migrations/0009.sql"),
        include_str!("../migrations/0010.sql"),
        include_str!("../migrations/0011.sql"),
        include_str!("../migrations/0012.sql"),
        include_str!("../migrations/0013.sql"),
        include_str!("../migrations/0014.sql"),
        include_str!("../migrations/0015.sql"),
        include_str!("../migrations/0016.sql"),
        include_str!("../migrations/0017.sql"),
        include_str!("../migrations/0018.sql"),
    ] {
        sqlx::raw_sql(migration)
            .execute(&mut connection)
            .await
            .unwrap();
    }
    let fixture_session = Uuid::from_u128(18);
    sqlx::query(
        "INSERT INTO sessions (
            session_id, consumer_key, compatibility_identity, revision, closed,
            created_at_seconds, created_at_nanos, updated_at_seconds, updated_at_nanos,
            epoch_high_water, observed_time_floor_seconds, observed_time_floor_nanos
         ) VALUES (?, 'v18-consumer', zeroblob(32), 1, 0, 18, 0, 18, 0, 0, 18, 0)",
    )
    .bind(fixture_session.to_string())
    .execute(&mut connection)
    .await
    .unwrap();
    connection
        .execute("PRAGMA user_version = 18")
        .await
        .unwrap();
    connection.close().await.unwrap();

    let store = SqliteStore::open(&path).await.unwrap();
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(version, 20);
    let preserved: (String, Vec<u8>, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT consumer_key,compatibility_identity,revision,closed,
                created_at_seconds,created_at_nanos,updated_at_seconds,updated_at_nanos,
                epoch_high_water FROM sessions WHERE session_id = ?",
    )
    .bind(fixture_session.to_string())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(
        preserved,
        (
            "v18-consumer".to_owned(),
            vec![0; 32],
            1,
            0,
            18,
            0,
            18,
            0,
            0
        )
    );
    let capacity_limits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM capacity_limits")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let capacity_reservations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM capacity_reservations")
            .fetch_one(store.pool())
            .await
            .unwrap();
    let subscription_leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscription_leases")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(
        (capacity_limits, capacity_reservations, subscription_leases),
        (11, 0, 0)
    );
    assert_integrity(&store).await;
}

#[tokio::test]
async fn frozen_rich_v18_and_v19_migrate_and_survive_every_crash_boundary() {
    let fixtures: [(i64, &[u8], &str); 2] = [
        (
            18,
            include_bytes!("../fixtures/release/schema-v18-rich.db"),
            "00000000-0000-0000-0000-000000000018",
        ),
        (
            19,
            include_bytes!("../fixtures/release/schema-v19-rich.db"),
            "00000000-0000-0000-0000-000000000019",
        ),
    ];
    for (historical, fixture, session) in fixtures {
        for point in MIGRATION_CRASH_POINTS {
            let directory = TempDir::new().unwrap();
            let path = directory.path().join(format!("v{historical}.db"));
            std::fs::write(&path, fixture).unwrap();
            run_crash_worker(&path, "migration", point);
            let version = sqlite_user_version(&path).await;
            assert!(
                version == historical || version == 20,
                "v{historical} crash at {point} left hybrid schema {version}"
            );
            let store = SqliteStore::open(&path).await.unwrap();
            let preserved: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
                "SELECT
                   (SELECT COUNT(*) FROM sessions WHERE session_id=?),
                   (SELECT COUNT(*) FROM participants WHERE session_id=?),
                   (SELECT COUNT(*) FROM operations WHERE session_id=? AND state='running'),
                   (SELECT COUNT(*) FROM events WHERE session_id=?),
                   (SELECT COUNT(*) FROM request_ledger WHERE session_id=?),
                   (SELECT COUNT(*) FROM sessions WHERE session_id=? AND owner_epoch=2)",
            )
            .bind(session)
            .bind(session)
            .bind(session)
            .bind(session)
            .bind(session)
            .bind(session)
            .fetch_one(store.pool())
            .await
            .unwrap();
            assert_eq!(preserved, (1, 1, 1, 1, 1, 1), "v{historical} at {point}");
            assert_integrity(&store).await;
        }
    }
}

async fn sqlite_user_version(path: &Path) -> i64 {
    let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
        .unwrap()
        .read_only(true);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut connection)
        .await
        .unwrap()
}

#[tokio::test]
async fn future_schema_probe_changes_no_database_or_sidecar() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("future.db");
    let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
        .unwrap()
        .create_if_missing(true);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    connection
        .execute("PRAGMA user_version = 21")
        .await
        .unwrap();
    connection.close().await.unwrap();
    let before = directory_snapshot(directory.path());

    assert_eq!(
        SqliteStore::open(&path).await.unwrap_err(),
        StoreError::SchemaTooNew {
            found: 21,
            supported: 20
        }
    );
    assert_eq!(directory_snapshot(directory.path()), before);
}

#[tokio::test]
async fn unrecognized_schema_fails_closed_without_writes() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("foreign.db");
    let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
        .unwrap()
        .create_if_missing(true);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    connection
        .execute("CREATE TABLE foreign_state (sentinel TEXT NOT NULL)")
        .await
        .unwrap();
    connection
        .execute("INSERT INTO foreign_state VALUES ('untouched')")
        .await
        .unwrap();
    connection.close().await.unwrap();
    let before = directory_snapshot(directory.path());

    assert_eq!(
        SqliteStore::open(&path).await.unwrap_err(),
        StoreError::Corrupt
    );
    assert_eq!(directory_snapshot(directory.path()), before);
}

#[tokio::test]
async fn failure_for_missing_session_is_committed_and_replayed() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    let command = acquire_command(299, host(20), 100, 120);
    assert_eq!(
        store.acquire_ownership(command.clone()).await.unwrap_err(),
        StoreError::SessionNotFound {
            session_id: session_id()
        }
    );
    assert_eq!(
        store.acquire_ownership(command).await.unwrap_err(),
        StoreError::SessionNotFound {
            session_id: session_id()
        }
    );
    assert!(
        store
            .read_request(RequestId::from_uuid(Uuid::from_u128(299)).unwrap())
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_pools_racing_to_acquire_produce_one_owner() {
    let directory = TempDir::new().unwrap();
    let (first, path, clock) = new_store(&directory).await;
    first.open_session(open_command(102)).await.unwrap();
    let second =
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    let barrier = Arc::new(Barrier::new(3));

    let left_barrier = Arc::clone(&barrier);
    let left = tokio::spawn(async move {
        left_barrier.wait().await;
        first
            .acquire_ownership(acquire_command(201, host(20), 101, 120))
            .await
    });
    let right_barrier = Arc::clone(&barrier);
    let right = tokio::spawn(async move {
        right_barrier.wait().await;
        second
            .acquire_ownership(acquire_command(202, host(21), 101, 120))
            .await
    });
    barrier.wait().await;
    let outcomes = [left.await.unwrap(), right.await.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Ok(Mutation::Applied(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(StoreError::OwnershipHeld { .. })))
            .count(),
        1
    );
}

#[tokio::test]
async fn expiry_equality_and_time_regression_never_resurrect_owner() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    store.open_session(open_command(103)).await.unwrap();
    clock.set(101);
    let first = store
        .acquire_ownership(acquire_command(203, host(20), 101, 110))
        .await
        .unwrap()
        .value()
        .clone();

    clock.set(110);
    let renew_at_equality = RenewOwnership::new(
        context(204, host(20)),
        session_id(),
        first.epoch(),
        LeaseDuration::from_millis(10_000).unwrap(),
    );
    assert!(matches!(
        store.renew_ownership(renew_at_equality).await,
        Err(StoreError::OwnershipExpired { .. })
    ));

    clock.set(105);
    let regressed = RenewOwnership::new(
        context(205, host(20)),
        session_id(),
        first.epoch(),
        LeaseDuration::from_millis(16_000).unwrap(),
    );
    assert!(matches!(
        store.renew_ownership(regressed).await,
        Err(StoreError::OwnershipExpired { .. })
    ));
}

#[tokio::test]
async fn takeover_increments_epoch_and_fences_previous_owner() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    store.open_session(open_command(104)).await.unwrap();
    clock.set(101);
    let first = store
        .acquire_ownership(acquire_command(206, host(20), 101, 110))
        .await
        .unwrap()
        .value()
        .clone();
    clock.set(110);
    let second = store
        .acquire_ownership(acquire_command(207, host(21), 110, 130))
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(first.epoch().get(), 1);
    assert_eq!(second.epoch().get(), 2);

    let stale_release = ReleaseOwnership::new(context(208, host(20)), session_id(), first.epoch());
    assert_eq!(
        store.release_ownership(stale_release).await.unwrap_err(),
        StoreError::StaleOwnership {
            session_id: session_id(),
            attempted: FencingEpoch::new(1).unwrap(),
            current: Some(FencingEpoch::new(2).unwrap())
        }
    );
}

#[tokio::test]
async fn request_digest_conflict_does_not_append_event() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(105)).await.unwrap();
    let conflicting = OpenSession::new(
        context(105, host(10)),
        session_id(),
        ConsumerKey::new("consumer-b").unwrap(),
        CompatibilityIdentity::from_bytes([7; 32]),
    );
    assert!(matches!(
        store.open_session(conflicting).await,
        Err(StoreError::RequestConflict { .. })
    ));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn global_ledger_rejects_caller_and_action_reuse() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(500)).await.unwrap();

    let other_caller = OpenSession::new(
        context(500, host(99)),
        session_id(),
        ConsumerKey::new("consumer-a").unwrap(),
        CompatibilityIdentity::from_bytes([7; 32]),
    );
    assert!(matches!(
        store.open_session(other_caller).await,
        Err(StoreError::RequestConflict { .. })
    ));
    let other_action = CloseSession::new(
        context(500, host(10)),
        session_id(),
        FencingEpoch::new(1).unwrap(),
    );
    assert!(matches!(
        store.close_session(other_action).await,
        Err(StoreError::RequestConflict { .. })
    ));
}

#[tokio::test]
async fn corrupted_replay_result_is_rejected() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(501)).await.unwrap();
    let mut result: serde_json::Value = serde_json::from_slice(
        &sqlx::query_scalar::<_, Vec<u8>>("SELECT result FROM request_ledger WHERE request_id = ?")
            .bind(
                RequestId::from_uuid(Uuid::from_u128(501))
                    .unwrap()
                    .to_string(),
            )
            .fetch_one(store.pool())
            .await
            .unwrap(),
    )
    .unwrap();
    result["id"] = serde_json::Value::String(Uuid::from_u128(999).to_string());
    sqlx::query("UPDATE request_ledger SET result = ? WHERE request_id = ?")
        .bind(serde_json::to_vec(&result).unwrap())
        .bind(
            RequestId::from_uuid(Uuid::from_u128(501))
                .unwrap()
                .to_string(),
        )
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store.open_session(open_command(501)).await.unwrap_err(),
        StoreError::Corrupt
    );
}

#[tokio::test]
async fn corrupted_lease_replay_and_epoch_high_water_are_rejected() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(520)).await.unwrap();
    let acquire = acquire_command(521, host(20), 100, 120);
    store.acquire_ownership(acquire.clone()).await.unwrap();
    let request_id = RequestId::from_uuid(Uuid::from_u128(521)).unwrap();
    let mut result: serde_json::Value = serde_json::from_slice(
        &sqlx::query_scalar::<_, Vec<u8>>("SELECT result FROM request_ledger WHERE request_id = ?")
            .bind(request_id.to_string())
            .fetch_one(store.pool())
            .await
            .unwrap(),
    )
    .unwrap();
    result["owner"] = serde_json::to_value(Uuid::from_u128(99)).unwrap();
    sqlx::query("UPDATE request_ledger SET result = ? WHERE request_id = ?")
        .bind(serde_json::to_vec(&result).unwrap())
        .bind(request_id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store.acquire_ownership(acquire).await.unwrap_err(),
        StoreError::Corrupt
    );

    let mut connection = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("UPDATE sessions SET epoch_high_water = 0 WHERE session_id = ?")
        .bind(session_id().to_string())
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    assert_eq!(
        store.load_session(session_id()).await.unwrap_err(),
        StoreError::Corrupt
    );
}

#[tokio::test]
async fn schema_shape_and_malformed_database_fail_as_corrupt() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    sqlx::query("ALTER TABLE request_ledger DROP COLUMN result")
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;
    assert_eq!(
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap(),)
            .await
            .unwrap_err(),
        StoreError::Corrupt
    );

    let malformed = directory.path().join("malformed.db");
    std::fs::write(&malformed, b"not a sqlite database").unwrap();
    assert_eq!(
        SqliteStore::open(&malformed).await.unwrap_err(),
        StoreError::Corrupt
    );
}

#[tokio::test]
async fn corrupted_participant_topology_fails_closed_on_load_replay_and_reopen() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    store.open_session(open_command(938)).await.unwrap();
    store
        .acquire_ownership(acquire_command(939, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    let command = child_command();
    store
        .create_child_participant(command.clone())
        .await
        .unwrap();

    let mut connection = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("UPDATE participants SET depth = 9 WHERE participant_id = ?")
        .bind(command.participant_id.to_string())
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);

    assert_eq!(
        store
            .load_participant(command.participant_id)
            .await
            .unwrap_err(),
        StoreError::Corrupt
    );
    assert_eq!(
        store.create_child_participant(command).await.unwrap_err(),
        StoreError::Corrupt
    );
    store.pool().close().await;
    assert_eq!(
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap_err(),
        StoreError::Corrupt
    );
}

#[tokio::test]
async fn corrupted_authority_snapshot_fails_closed_on_replay_and_reopen() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    store.open_session(open_command(9_600)).await.unwrap();
    store
        .acquire_ownership(acquire_command(9_601, host(20), 100, 160))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    prepare_authorized_spawn(&store).await;
    let command = authorized_spawn_command();
    store
        .create_authorized_child(command.clone())
        .await
        .unwrap();
    sqlx::query("UPDATE authority_policies SET snapshot = X'7B7D' WHERE participant_id = ?")
        .bind(command.participant_id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store.create_authorized_child(command).await.unwrap_err(),
        StoreError::Corrupt
    );
    store.pool().close().await;
    assert_eq!(
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap_err(),
        StoreError::Corrupt
    );
}

#[tokio::test]
async fn waiting_operation_resumes_only_with_the_exact_durable_correlation() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    store.open_session(open_command(938)).await.unwrap();
    store
        .acquire_ownership(acquire_command(939, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    let started = store
        .start_operation(start_operation_command())
        .await
        .unwrap()
        .value()
        .clone();
    prepare_real_mailbox_launch(&store).await;
    accept_input_message(&store, 9_000_100).await;
    let mut begin = transition_operation_command();
    begin.expected_revision = started.revision;
    let starting = store
        .transition_operation(begin)
        .await
        .unwrap()
        .value()
        .clone();
    let mut running_command = transition_operation_command();
    running_command.context = context(980, host(20));
    running_command.expected_revision = starting.revision;
    running_command.action = navigator_domain::OperationAction::ReportRunning;
    running_command.report_message_id = Some(started.input_message_id);
    let running = store
        .transition_operation(running_command)
        .await
        .unwrap()
        .value()
        .clone();
    let question = MessageId::from_uuid(Uuid::from_u128(981)).unwrap();
    let mut wait = transition_operation_command();
    wait.context = context(982, host(20));
    wait.expected_revision = running.revision;
    wait.action = navigator_domain::OperationAction::Wait;
    wait.report_message_id = Some(question);
    let waiting = store
        .transition_operation(wait)
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(waiting.waiting_on_message_id, Some(question));

    store.pool().close().await;
    let reopened =
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    let mut wrong = transition_operation_command();
    wrong.context = context(983, host(20));
    wrong.expected_revision = waiting.revision;
    wrong.action = navigator_domain::OperationAction::Resume;
    wrong.report_message_id = Some(MessageId::from_uuid(Uuid::from_u128(984)).unwrap());
    assert_eq!(
        reopened.transition_operation(wrong).await.unwrap_err(),
        StoreError::Invalid
    );
    let mut exact = transition_operation_command();
    exact.context = context(985, host(20));
    exact.expected_revision = waiting.revision;
    exact.action = navigator_domain::OperationAction::Resume;
    exact.report_message_id = Some(question);
    let resumed = reopened
        .transition_operation(exact)
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(resumed.state, navigator_domain::OperationState::Running);
    assert_eq!(resumed.waiting_on_message_id, None);
}

#[tokio::test]
async fn corrupted_waiting_correlation_is_never_restored() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    store.open_session(open_command(938)).await.unwrap();
    store
        .acquire_ownership(acquire_command(939, host(20), 100, 120))
        .await
        .unwrap();
    eprintln!("replay-test: started");
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    eprintln!("replay-test: completed");
    store
        .start_operation(start_operation_command())
        .await
        .unwrap();
    sqlx::query("UPDATE operations SET waiting_on_message_id = ? WHERE operation_id = ?")
        .bind(
            MessageId::from_uuid(Uuid::from_u128(990))
                .unwrap()
                .to_string(),
        )
        .bind(start_operation_command().operation_id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store
            .load_operation(start_operation_command().operation_id)
            .await
            .unwrap_err(),
        StoreError::Corrupt
    );
    store.pool().close().await;
    assert_eq!(
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap_err(),
        StoreError::Corrupt
    );
}

#[tokio::test]
async fn missing_launch_identity_index_fails_closed_before_write() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    sqlx::query("DROP INDEX current_instance_identity")
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;
    assert_eq!(
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap_err(),
        StoreError::Corrupt
    );
}

#[tokio::test]
async fn missing_launch_session_foreign_key_fails_closed_before_write() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    let mut connection = store.pool().acquire().await.unwrap();
    sqlx::query("PRAGMA writable_schema = ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE sqlite_master SET sql = replace(sql, ' REFERENCES sessions(session_id)', '')
         WHERE type = 'table' AND name = 'launch_attempts'",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    sqlx::query("PRAGMA schema_version = 99")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    store.pool().close().await;
    assert_eq!(
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap_err(),
        StoreError::Corrupt
    );
}

#[tokio::test]
async fn missing_operation_uniqueness_or_participant_foreign_key_fails_closed() {
    for corruption in ["index", "foreign-key"] {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        let mut connection = store.pool().acquire().await.unwrap();
        if corruption == "index" {
            sqlx::query("DROP INDEX one_unfinished_operation_per_participant")
                .execute(&mut *connection)
                .await
                .unwrap();
        } else {
            sqlx::query("PRAGMA writable_schema = ON")
                .execute(&mut *connection)
                .await
                .unwrap();
            sqlx::query("UPDATE sqlite_master SET sql = replace(sql, ' REFERENCES participants(participant_id)', '') WHERE type = 'table' AND name = 'operations'")
                .execute(&mut *connection).await.unwrap();
            sqlx::query("PRAGMA schema_version = 100")
                .execute(&mut *connection)
                .await
                .unwrap();
        }
        drop(connection);
        store.pool().close().await;
        assert_eq!(
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap_err(),
            StoreError::Corrupt
        );
    }
}

#[tokio::test]
async fn missing_mailbox_order_uniqueness_or_session_foreign_key_fails_closed() {
    for corruption in ["unique", "foreign-key"] {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        let mut connection = store.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA writable_schema = ON")
            .execute(&mut *connection)
            .await
            .unwrap();
        let statement = if corruption == "unique" {
            "UPDATE sqlite_master SET sql = replace(sql, 'UNIQUE(destination_participant_id, mailbox_sequence)', 'CHECK (mailbox_sequence > 0)') WHERE type = 'table' AND name = 'messages'"
        } else {
            "UPDATE sqlite_master SET sql = replace(sql, ' REFERENCES sessions(session_id)', '') WHERE type = 'table' AND name = 'messages'"
        };
        sqlx::query(statement)
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query("PRAGMA schema_version = 101")
            .execute(&mut *connection)
            .await
            .unwrap();
        drop(connection);
        store.pool().close().await;
        assert_eq!(
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap_err(),
            StoreError::Corrupt
        );
    }
}

#[tokio::test]
// Guarantees: NAV-IDEMPOTENCY-001, NAV-IDEMPOTENCY-002, NAV-IDENTITY-001
async fn stale_close_and_renew_cannot_mutate_after_takeover() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    store.open_session(open_command(502)).await.unwrap();
    clock.set(101);
    let first = store
        .acquire_ownership(acquire_command(503, host(20), 101, 110))
        .await
        .unwrap()
        .value()
        .clone();
    clock.set(110);
    store
        .acquire_ownership(acquire_command(504, host(21), 110, 130))
        .await
        .unwrap();
    let revision = store.load_session(session_id()).await.unwrap().revision();

    assert!(matches!(
        store
            .renew_ownership(RenewOwnership::new(
                context(505, host(20)),
                session_id(),
                first.epoch(),
                LeaseDuration::from_millis(10_000).unwrap(),
            ))
            .await,
        Err(StoreError::StaleOwnership { .. })
    ));
    assert!(matches!(
        store
            .close_session(CloseSession::new(
                context(506, host(20)),
                session_id(),
                first.epoch(),
            ))
            .await,
        Err(StoreError::StaleOwnership { .. })
    ));
    assert_eq!(
        store.load_session(session_id()).await.unwrap().revision(),
        revision
    );
}

#[tokio::test]
async fn same_host_reacquire_increments_epoch_and_renew_is_invisible_to_history() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    store.open_session(open_command(507)).await.unwrap();
    let first = store
        .acquire_ownership(acquire_command(508, host(20), 100, 120))
        .await
        .unwrap()
        .value()
        .clone();
    let before = store.load_session(session_id()).await.unwrap();
    let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(store.pool())
        .await
        .unwrap();
    clock.set(105);
    store
        .renew_ownership(RenewOwnership::new(
            context(509, host(20)),
            session_id(),
            first.epoch(),
            LeaseDuration::from_millis(20_000).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(store.load_session(session_id()).await.unwrap(), before);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events")
            .fetch_one(store.pool())
            .await
            .unwrap(),
        event_count
    );
    store
        .release_ownership(ReleaseOwnership::new(
            context(510, host(20)),
            session_id(),
            first.epoch(),
        ))
        .await
        .unwrap();
    let second = store
        .acquire_ownership(acquire_command(511, host(20), 105, 125))
        .await
        .unwrap();
    assert_eq!(second.value().epoch().get(), first.epoch().get() + 1);
}

#[tokio::test]
async fn max_lease_and_event_pagination_are_enforced() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(512)).await.unwrap();
    assert_eq!(
        store
            .acquire_ownership(AcquireOwnership::new(
                context(513, host(20)),
                session_id(),
                LeaseDuration::from_millis(60_001).unwrap(),
            ))
            .await
            .unwrap_err(),
        StoreError::LeaseTooLong
    );
    let lease = store
        .acquire_ownership(acquire_command(514, host(20), 100, 120))
        .await
        .unwrap()
        .value()
        .clone();
    store
        .release_ownership(ReleaseOwnership::new(
            context(515, host(20)),
            session_id(),
            lease.epoch(),
        ))
        .await
        .unwrap();
    let first = store
        .read_events(ReadEvents {
            session_id: session_id(),
            consumer: ConsumerKey::new("consumer-a").unwrap(),
            after: None,
            limit: EventReadLimit::new(2).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(first.events.len(), 2);
    assert!(first.has_more);
    assert_eq!(first.last_position, Some(EventPosition::new(2).unwrap()));
    let second = store
        .read_events(ReadEvents {
            session_id: session_id(),
            consumer: ConsumerKey::new("consumer-a").unwrap(),
            after: first.last_position,
            limit: EventReadLimit::new(2).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(second.events.len(), 1);
    assert!(!second.has_more);
    assert_eq!(second.last_position, Some(EventPosition::new(3).unwrap()));
}

const OPEN_CRASH_POINTS: &[&str] = &[
    "open.after_session_insert",
    "open.after_event_insert",
    "open.after_ledger_insert",
    "open.before_commit",
    "open.after_commit",
];

const CLOSE_CRASH_POINTS: &[&str] = &[
    "close.after_session_update",
    "close.after_event_insert",
    "close.after_ledger_insert",
    "close.before_commit",
    "close.after_commit",
];

const ACQUIRE_CRASH_POINTS: &[&str] = &[
    "acquire.after_time_floor",
    "acquire.after_session_update",
    "acquire.after_event_insert",
    "acquire.after_ledger_insert",
    "acquire.before_commit",
    "acquire.after_commit",
];

const RENEW_CRASH_POINTS: &[&str] = &[
    "renew.after_time_floor",
    "renew.after_session_update",
    "renew.after_ledger_insert",
    "renew.before_commit",
    "renew.after_commit",
];

const RELEASE_CRASH_POINTS: &[&str] = &[
    "release.after_time_floor",
    "release.after_session_update",
    "release.after_event_insert",
    "release.after_ledger_insert",
    "release.before_commit",
    "release.after_commit",
];

const MIGRATION_CRASH_POINTS: &[&str] = &[
    "migration.after_begin",
    "migration.after_schema_apply",
    "migration.after_version_set",
    "migration.before_commit",
    "migration.after_commit",
];

const PREPARE_LAUNCH_CRASH_POINTS: &[&str] = &[
    "launch.prepare.after_insert",
    "launch.prepare.after_ledger",
    "launch.prepare.before_commit",
    "launch.prepare.after_commit",
];

const PARTICIPANT_CRASH_POINTS: &[&str] = &[
    "participant.create.after_insert",
    "participant.create.after_event",
    "participant.create.after_ledger",
    "participant.create.before_commit",
    "participant.create.after_commit",
];
const CHILD_CRASH_POINTS: &[&str] = &[
    "participant.child.after_insert",
    "participant.child.after_event",
    "participant.child.after_ledger",
    "participant.child.before_commit",
    "participant.child.after_commit",
];
const OPERATION_START_CRASH_POINTS: &[&str] = &[
    "operation.start.after_insert",
    "operation.start.after_mailbox",
    "operation.start.after_event",
    "operation.start.after_ledger",
    "operation.start.before_commit",
    "operation.start.after_commit",
];
const OPERATION_TRANSITION_CRASH_POINTS: &[&str] = &[
    "operation.transition.after_state",
    "operation.transition.after_event",
    "operation.transition.after_ledger",
    "operation.transition.before_commit",
    "operation.transition.after_commit",
];
const AUTHORITY_SPAWN_CRASH_POINTS: &[&str] = &[
    "authority.spawn.after_child",
    "authority.spawn.after_policy",
    "authority.spawn.after_operation",
    "authority.spawn.after_message",
    "authority.spawn.after_grant",
    "authority.spawn.after_events",
    "authority.spawn.after_ledger",
    "authority.spawn.before_commit",
    "authority.spawn.after_commit",
];

fn spawn_scope() -> ScopedCapability {
    ScopedCapability::new(
        Capability::new("participant.spawn").unwrap(),
        ResourceScope::Participant(participant_command().participant_id),
    )
}

fn authorized_spawn_command() -> CreateAuthorizedChild {
    CreateAuthorizedChild {
        context: context(9_620, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        parent_participant_id: participant_command().participant_id,
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(9_621)).unwrap(),
        template_id: template_record().identity,
        expected_compatibility: template_record().compatibility,
        requested: spawn_scope(),
        grant_id: Some(GrantId::from_uuid(Uuid::from_u128(9_622)).unwrap()),
        operation_id: OperationId::from_uuid(Uuid::from_u128(9_623)).unwrap(),
        input_message_id: MessageId::from_uuid(Uuid::from_u128(9_624)).unwrap(),
        input: Template::try_from(template_record())
            .unwrap()
            .validate_input(br"{}")
            .unwrap(),
    }
}

async fn prepare_authorized_spawn(store: &SqliteStore) {
    let full = AuthorityProfile::new([spawn_scope()], [spawn_scope()]).unwrap();
    store
        .put_authority_policy(PutAuthorityPolicy {
            context: context(9_610, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            policy: AuthorityPolicySnapshot {
                session_id: session_id(),
                participant_id: participant_command().participant_id,
                session: full.clone(),
                parent: full.clone(),
                template: full.clone(),
                relationship: full.clone(),
                subject: full.clone(),
            },
        })
        .await
        .unwrap();
    store
        .register_authority_template_policy(RegisterAuthorityTemplatePolicy {
            context: context(9_611, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            policy: AuthorityTemplatePolicy {
                template_id: template_record().identity,
                allowed_parent_templates: BTreeSet::from([template_record().identity]),
                template: full.clone(),
                relationship: full.clone(),
                subject: full,
            },
        })
        .await
        .unwrap();
    store
        .issue_grant(IssueGrant {
            context: context(9_612, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            grant: Grant {
                id: GrantId::from_uuid(Uuid::from_u128(9_622)).unwrap(),
                session_id: session_id(),
                subject: participant_command().participant_id,
                authority: spawn_scope(),
                expires_at: Timestamp::new(200, 0).unwrap(),
                revoked: false,
            },
            single_use: true,
        })
        .await
        .unwrap();
}

fn resolution_scope() -> ScopedCapability {
    ScopedCapability::new(
        Capability::new("effect.resolve_uncertainty").unwrap(),
        ResourceScope::Operation(start_operation_command().operation_id),
    )
}

fn journal_reserve_command() -> ReserveEffect {
    ReserveEffect::new(
        context(80_005, host(20)),
        session_id(),
        participant_command().participant_id,
        start_operation_command().operation_id,
        FencingEpoch::new(1).unwrap(),
        Capability::new("tool.send").unwrap(),
        b"semantic",
        EffectClass::NonIdempotent,
        EffectResolutionContract {
            allow_confirm_completed: true,
            allow_do_not_retry: true,
            allow_retry_with_proof: true,
            allowed_proof_kinds: vec![
                EffectProofKind::ExternalCommit,
                EffectProofKind::EffectAbsent,
            ],
        },
        std::time::Duration::from_secs(10),
    )
}

fn tool_definition() -> ToolDefinition {
    tool_definition_with(ToolCancellation::Cooperative)
}

fn tool_definition_with(cancellation: ToolCancellation) -> ToolDefinition {
    tool_definition_contract(
        cancellation,
        EffectClass::Transactional,
        IdempotencyContract::ExternalTransactionProof,
    )
}

fn tool_definition_contract(
    cancellation: ToolCancellation,
    effect_class: EffectClass,
    idempotency: IdempotencyContract,
) -> ToolDefinition {
    ToolDefinition::new(
        ToolName::new("records.lookup").unwrap(), ToolVersion::new("v1").unwrap(),
        CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(r#"{"additionalProperties":false,"properties":{"key":{"type":"string"}},"required":["key"],"type":"object"}"#).unwrap(),
        CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(r#"{"additionalProperties":false,"properties":{"found":{"type":"boolean"}},"required":["found"],"type":"object"}"#).unwrap(),
        Capability::new("tool.records.lookup").unwrap(), ToolTimeout::from_millis(10_000).unwrap(),
        cancellation, effect_class, idempotency,
    ).unwrap()
}

async fn prepare_tool_authority(store: &SqliteStore) {
    prepare_running_effect_operation(store).await;
    let scope = ScopedCapability::new(
        Capability::new("tool.records.lookup").unwrap(),
        ResourceScope::Operation(start_operation_command().operation_id),
    );
    let full = AuthorityProfile::new(
        [scope.clone(), resolution_scope()],
        [scope, resolution_scope()],
    )
    .unwrap();
    store
        .put_authority_policy(PutAuthorityPolicy {
            context: context(81_000, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            policy: AuthorityPolicySnapshot {
                session_id: session_id(),
                participant_id: participant_command().participant_id,
                session: full.clone(),
                parent: full.clone(),
                template: full.clone(),
                relationship: full.clone(),
                subject: full,
            },
        })
        .await
        .unwrap();
}

async fn prepare_tool_registration(store: &SqliteStore) {
    prepare_tool_authority(store).await;
    store
        .register_tool(RegisterTool {
            context: context(81_001, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap(),
            consumer_key: ConsumerKey::new("consumer-a").unwrap(),
            definition: tool_definition(),
        })
        .await
        .unwrap();
}

async fn prepare_tool_store(store: &SqliteStore) {
    prepare_tool_registration(store).await;
    store
        .connect_tool_provider(ConnectToolProvider {
            context: context(81_003, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            consumer_key: ConsumerKey::new("consumer-a").unwrap(),
            provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
            connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_005)).unwrap(),
            after_server_sequence: 0,
            registration_ids: vec![ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap()],
        })
        .await
        .unwrap();
}

fn tool_reserve(
    request: u128,
    invocation: u128,
    caller: HostId,
    epoch: u64,
    lease: u64,
) -> ReserveToolInvocation {
    ReserveToolInvocation {
        context: context(request, caller),
        owner_epoch: FencingEpoch::new(epoch).unwrap(),
        dispatch_id: ToolDispatchId::from_uuid(Uuid::from_u128(81_006)).unwrap(),
        provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
        registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap(),
        deadline: Timestamp::new(105, 0).unwrap(),
        invocation: ToolInvocation::new(
            ToolInvocationId::from_uuid(Uuid::from_u128(invocation)).unwrap(),
            RequestId::from_uuid(Uuid::from_u128(request)).unwrap(),
            session_id(),
            participant_command().participant_id,
            start_operation_command().operation_id,
            ToolName::new("records.lookup").unwrap(),
            ToolVersion::new("v1").unwrap(),
            CanonicalJson::<MAX_TOOL_INLINE_BYTES>::new(r#"{"key":"x"}"#).unwrap(),
        )
        .unwrap(),
        lease_duration: std::time::Duration::from_secs(lease),
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn tool_reservation_is_pre_dispatch_durable_globally_idempotent_and_fenced() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_tool_store(&store).await;
    let command = tool_reserve(81_010, 81_011, host(20), 1, 10);
    let reserved = store
        .reserve_tool_invocation(command.clone())
        .await
        .unwrap();
    assert_eq!(reserved.phase(), ToolInvocationPhase::Reserved);
    assert_eq!(
        store
            .reserve_tool_invocation(command.clone())
            .await
            .unwrap(),
        reserved
    );
    for mutant in [
        tool_reserve(81_010, 81_011, host(21), 1, 10),
        tool_reserve(81_010, 81_011, host(20), 2, 10),
        tool_reserve(81_010, 81_011, host(20), 1, 11),
        tool_reserve(81_010, 81_012, host(20), 1, 10),
    ] {
        assert!(matches!(
            store.reserve_tool_invocation(mutant).await,
            Err(StoreError::RequestConflict { .. })
        ));
    }
    let recoverable = store
        .list_recoverable_tool_invocations(session_id())
        .await
        .unwrap();
    assert_eq!(recoverable, vec![reserved.clone()]);
    assert_eq!(
        store
            .connect_tool_provider(ConnectToolProvider {
                context: context(81_013, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_014)).unwrap(),
                after_server_sequence: 1,
                registration_ids: vec![
                    ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap(),
                ],
            })
            .await,
        Err(StoreError::Invalid),
        "a watermark cannot jump over a nonterminal dispatch"
    );
    assert_eq!(
        store
            .list_provider_replay(
                session_id(),
                ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                u64::try_from(i64::MAX).unwrap(),
            )
            .await
            .unwrap(),
        recoverable
    );
    let cancel = TransitionToolInvocation {
        context: context(81_015, host(20)),
        invocation_id: reserved.invocation().invocation_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        expected_revision: reserved.revision(),
        transition: ToolTransition::RequestCancel {
            cancellation_id: ToolCancellationId::from_uuid(Uuid::from_u128(81_016)).unwrap(),
        },
        provider_id: reserved.dispatch().provider_id,
        connection_id: reserved.dispatch().connection_id.unwrap(),
        connection_generation: reserved.dispatch().connection_generation.unwrap(),
        dispatch_id: reserved.dispatch().dispatch_id,
        server_sequence: reserved.dispatch().server_sequence,
    };
    let cancelled = store
        .transition_tool_invocation(cancel.clone())
        .await
        .unwrap();
    assert_eq!(cancelled.dispatch().cancellation_server_sequence, Some(2));
    assert_eq!(
        store.transition_tool_invocation(cancel).await.unwrap(),
        cancelled
    );
    assert_eq!(
        store
            .transition_tool_invocation(TransitionToolInvocation {
                context: context(81_020, host(20)),
                invocation_id: cancelled.invocation().invocation_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                expected_revision: cancelled.revision(),
                transition: ToolTransition::Start,
                provider_id: cancelled.dispatch().provider_id,
                connection_id: cancelled.dispatch().connection_id.unwrap(),
                connection_generation: cancelled.dispatch().connection_generation.unwrap(),
                dispatch_id: cancelled.dispatch().dispatch_id,
                server_sequence: cancelled.dispatch().server_sequence,
            })
            .await,
        Err(StoreError::Invalid)
    );
    let mut second = tool_reserve(81_017, 81_018, host(20), 1, 10);
    second.dispatch_id = ToolDispatchId::from_uuid(Uuid::from_u128(81_019)).unwrap();
    let second = store.reserve_tool_invocation(second).await.unwrap();
    assert_eq!(second.dispatch().server_sequence, 3);
}

#[tokio::test]
async fn tool_transition_replay_is_bound_and_historical_then_alien_snapshot_is_corrupt() {
    let directory = TempDir::new().unwrap();
    let (store, path, _) = new_store(&directory).await;
    prepare_tool_store(&store).await;
    let reserved = store
        .reserve_tool_invocation(tool_reserve(81_320, 81_321, host(20), 1, 10))
        .await
        .unwrap();
    let start = TransitionToolInvocation {
        context: context(81_322, host(20)),
        invocation_id: reserved.invocation().invocation_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        expected_revision: reserved.revision(),
        transition: ToolTransition::Start,
        provider_id: reserved.dispatch().provider_id,
        connection_id: reserved.dispatch().connection_id.unwrap(),
        connection_generation: reserved.dispatch().connection_generation.unwrap(),
        dispatch_id: reserved.dispatch().dispatch_id,
        server_sequence: reserved.dispatch().server_sequence,
    };
    let started = store
        .transition_tool_invocation(start.clone())
        .await
        .unwrap();
    let completed = store
        .transition_tool_invocation(TransitionToolInvocation {
            context: context(81_323, host(20)),
            invocation_id: started.invocation().invocation_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            expected_revision: started.revision(),
            transition: ToolTransition::Complete(
                ToolResult::new(
                    started.invocation().invocation_id(),
                    CanonicalJson::new(r#"{"found":true}"#).unwrap(),
                    vec![],
                )
                .unwrap(),
            ),
            provider_id: started.dispatch().provider_id,
            connection_id: started.dispatch().connection_id.unwrap(),
            connection_generation: started.dispatch().connection_generation.unwrap(),
            dispatch_id: started.dispatch().dispatch_id,
            server_sequence: started.dispatch().server_sequence,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .transition_tool_invocation(start.clone())
            .await
            .unwrap(),
        started,
        "a historical Start replay remains its original result after completion"
    );
    assert_eq!(completed.phase(), ToolInvocationPhase::Completed);

    let mut other = tool_reserve(81_324, 81_325, host(20), 1, 10);
    other.dispatch_id = ToolDispatchId::from_uuid(Uuid::from_u128(81_326)).unwrap();
    let alien = store.reserve_tool_invocation(other).await.unwrap();
    sqlx::query("UPDATE tool_invocation_mutations SET result=? WHERE request_id=?")
        .bind(serde_json::to_vec(&alien).unwrap())
        .bind(start.context.request_id().to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store.transition_tool_invocation(start).await,
        Err(StoreError::Corrupt)
    );
    store.pool().close().await;
    assert!(SqliteStore::open(&path).await.is_err());
}

#[tokio::test]
async fn tool_register_and_connect_alien_replay_results_fail_live_and_reopen() {
    for mutation in ["register", "connect"] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_tool_store(&store).await;
        let (request_id, alien) = if mutation == "register" {
            let definition = ToolDefinition::new(
                ToolName::new("records.other").unwrap(), ToolVersion::new("v1").unwrap(),
                CanonicalJson::new(r#"{"additionalProperties":false,"properties":{"key":{"type":"string"}},"required":["key"],"type":"object"}"#).unwrap(),
                CanonicalJson::new(r#"{"additionalProperties":false,"properties":{"found":{"type":"boolean"}},"required":["found"],"type":"object"}"#).unwrap(),
                Capability::new("tool.records.lookup").unwrap(), ToolTimeout::from_millis(10_000).unwrap(),
                ToolCancellation::Cooperative, EffectClass::Transactional,
                IdempotencyContract::ExternalTransactionProof,
            ).unwrap();
            let value = store
                .register_tool(RegisterTool {
                    context: context(81_330, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(81_331))
                        .unwrap(),
                    consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                    definition,
                })
                .await
                .unwrap()
                .value()
                .clone();
            (
                RequestId::from_uuid(Uuid::from_u128(81_001)).unwrap(),
                serde_json::to_vec(&value).unwrap(),
            )
        } else {
            let value = store
                .connect_tool_provider(ConnectToolProvider {
                    context: context(81_332, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                    provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_333)).unwrap(),
                    connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_334)).unwrap(),
                    after_server_sequence: 0,
                    registration_ids: vec![
                        ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap(),
                    ],
                })
                .await
                .unwrap();
            (
                RequestId::from_uuid(Uuid::from_u128(81_003)).unwrap(),
                serde_json::to_vec(&value).unwrap(),
            )
        };
        sqlx::query("UPDATE request_ledger SET result=? WHERE request_id=?")
            .bind(alien)
            .bind(request_id.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        let live = if mutation == "register" {
            store
                .register_tool(RegisterTool {
                    context: context(81_001, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(81_002))
                        .unwrap(),
                    consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                    definition: tool_definition(),
                })
                .await
                .map(|_| ())
        } else {
            store
                .connect_tool_provider(ConnectToolProvider {
                    context: context(81_003, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                    provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                    connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_005)).unwrap(),
                    after_server_sequence: 0,
                    registration_ids: vec![
                        ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap(),
                    ],
                })
                .await
                .map(|_| ())
        };
        assert_eq!(live, Err(StoreError::Corrupt), "{mutation}");
        store.pool().close().await;
        assert!(SqliteStore::open(&path).await.is_err(), "{mutation}");
    }
}

#[tokio::test]
async fn historical_connect_replays_its_own_registration_set_after_reconnect_and_reopen() {
    let directory = TempDir::new().unwrap();
    let (store, path, _) = new_store(&directory).await;
    prepare_tool_store(&store).await;
    let definition = ToolDefinition::new(
        ToolName::new("records.other").unwrap(), ToolVersion::new("v1").unwrap(),
        CanonicalJson::new(r#"{"additionalProperties":false,"properties":{"key":{"type":"string"}},"required":["key"],"type":"object"}"#).unwrap(),
        CanonicalJson::new(r#"{"additionalProperties":false,"properties":{"found":{"type":"boolean"}},"required":["found"],"type":"object"}"#).unwrap(),
        Capability::new("tool.records.lookup").unwrap(), ToolTimeout::from_millis(10_000).unwrap(),
        ToolCancellation::Cooperative, EffectClass::Transactional,
        IdempotencyContract::ExternalTransactionProof,
    ).unwrap();
    let second_id = ToolRegistrationId::from_uuid(Uuid::from_u128(81_341)).unwrap();
    store
        .register_tool(RegisterTool {
            context: context(81_340, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            registration_id: second_id,
            consumer_key: ConsumerKey::new("consumer-a").unwrap(),
            definition,
        })
        .await
        .unwrap();
    let first_id = ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap();
    let connect_a = ConnectToolProvider {
        context: context(81_342, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        consumer_key: ConsumerKey::new("consumer-a").unwrap(),
        provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
        connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_343)).unwrap(),
        after_server_sequence: 0,
        registration_ids: vec![first_id],
    };
    let historical = store
        .connect_tool_provider(connect_a.clone())
        .await
        .unwrap();
    assert_eq!(historical.registration_ids, vec![first_id]);
    let invocation = store
        .reserve_tool_invocation(tool_reserve(81_346, 81_347, host(20), 1, 10))
        .await
        .unwrap();
    store
        .connect_tool_provider(ConnectToolProvider {
            context: context(81_344, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            consumer_key: ConsumerKey::new("consumer-a").unwrap(),
            provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
            connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_345)).unwrap(),
            after_server_sequence: 0,
            registration_ids: vec![second_id],
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .connect_tool_provider(connect_a.clone())
            .await
            .unwrap(),
        historical
    );
    store.pool().close().await;
    let reopened = SqliteStore::open(&path).await.unwrap();
    assert_eq!(
        reopened
            .load_tool_invocation(invocation.invocation().invocation_id())
            .await
            .unwrap()
            .unwrap()
            .registration_id(),
        first_id
    );
    assert_eq!(
        reopened.connect_tool_provider(connect_a).await.unwrap(),
        historical
    );
}

#[tokio::test]
async fn current_provider_projection_must_match_the_latest_connect_record() {
    for mutation in ["connection", "generation", "connected_at"] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_tool_store(&store).await;
        match mutation {
            "connection" => {
                sqlx::query("UPDATE tool_provider_connections SET connection_id=?")
                    .bind(
                        ToolConnectionId::from_uuid(Uuid::from_u128(81_399))
                            .unwrap()
                            .to_string(),
                    )
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            "generation" => {
                sqlx::query("UPDATE tool_provider_connections SET generation=generation+1")
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            "connected_at" => {
                sqlx::query(
                    "UPDATE tool_provider_connections SET connected_at_seconds=connected_at_seconds+1",
                )
                .execute(store.pool())
                .await
                .unwrap();
            }
            _ => unreachable!(),
        }
        store.pool().close().await;
        assert!(SqliteStore::open(&path).await.is_err(), "{mutation}");
    }
}

#[tokio::test]
async fn live_tool_loader_rejects_coherent_mirrored_column_mutation() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_tool_store(&store).await;
    let invocation = store
        .reserve_tool_invocation(tool_reserve(81_392, 81_393, host(20), 1, 10))
        .await
        .unwrap();
    sqlx::query(
        "UPDATE tool_invocations SET server_sequence=server_sequence+1 WHERE invocation_id=?",
    )
    .bind(invocation.invocation().invocation_id().to_string())
    .execute(store.pool())
    .await
    .unwrap();
    assert_eq!(
        store
            .load_tool_invocation(invocation.invocation().invocation_id())
            .await,
        Err(StoreError::Corrupt)
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one boundary matrix proves mutation, connect, and reopen enforce the same exact cap"
)]
async fn tool_registration_bound_is_enforced_at_mutation_and_connect_boundaries() {
    let directory = TempDir::new().unwrap();
    let (store, path, _) = new_store(&directory).await;
    prepare_tool_authority(&store).await;
    for index in 0..navigator_store_api::MAX_TOOL_REGISTRATIONS {
        let definition = ToolDefinition::new(
            ToolName::new(format!("records.lookup{index}")).unwrap(),
            ToolVersion::new("v1").unwrap(),
            CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(
                r#"{"additionalProperties":false,"properties":{},"type":"object"}"#,
            )
            .unwrap(),
            CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(
                r#"{"additionalProperties":false,"properties":{},"type":"object"}"#,
            )
            .unwrap(),
            Capability::new("tool.records.lookup").unwrap(),
            ToolTimeout::from_millis(10_000).unwrap(),
            ToolCancellation::Cooperative,
            EffectClass::Transactional,
            IdempotencyContract::ExternalTransactionProof,
        )
        .unwrap();
        store
            .register_tool(RegisterTool {
                context: context(82_000 + u128::try_from(index).unwrap(), host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(
                    82_100 + u128::try_from(index).unwrap(),
                ))
                .unwrap(),
                consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                definition,
            })
            .await
            .unwrap();
    }
    let overflow = ToolDefinition::new(
        ToolName::new("records.overflow").unwrap(),
        ToolVersion::new("v1").unwrap(),
        CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(
            r#"{"additionalProperties":false,"properties":{},"type":"object"}"#,
        )
        .unwrap(),
        CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(
            r#"{"additionalProperties":false,"properties":{},"type":"object"}"#,
        )
        .unwrap(),
        Capability::new("tool.records.lookup").unwrap(),
        ToolTimeout::from_millis(10_000).unwrap(),
        ToolCancellation::Cooperative,
        EffectClass::Transactional,
        IdempotencyContract::ExternalTransactionProof,
    )
    .unwrap();
    assert_eq!(
        store
            .register_tool(RegisterTool {
                context: context(82_999, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(82_999)).unwrap(),
                consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                definition: overflow.clone(),
            })
            .await,
        Err(StoreError::Invalid)
    );
    let ids = (0..=navigator_store_api::MAX_TOOL_REGISTRATIONS)
        .map(|index| {
            ToolRegistrationId::from_uuid(Uuid::from_u128(83_000 + u128::try_from(index).unwrap()))
                .unwrap()
        })
        .collect();
    assert_eq!(
        store
            .connect_tool_provider(ConnectToolProvider {
                context: context(83_999, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                provider_id: ToolProviderId::from_uuid(Uuid::from_u128(83_998)).unwrap(),
                connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(83_997)).unwrap(),
                after_server_sequence: 0,
                registration_ids: ids,
            })
            .await,
        Err(StoreError::Invalid)
    );
    let overflow_id = ToolRegistrationId::from_uuid(Uuid::from_u128(84_001)).unwrap();
    let snapshot = ToolRegistrationSnapshot {
        registration_id: overflow_id,
        session_id: session_id(),
        consumer_key: ConsumerKey::new("consumer-a").unwrap(),
        definition: overflow,
        revision: Revision::initial(),
        registered_at: Timestamp::new(1, 0).unwrap(),
    };
    sqlx::query("INSERT INTO tool_registrations(session_id,registration_id,tool_name,tool_version,consumer_key,snapshot) VALUES(?,?,?,?,?,?)")
        .bind(session_id().to_string())
        .bind(overflow_id.to_string())
        .bind(snapshot.definition.name())
        .bind(snapshot.definition.version())
        .bind("consumer-a")
        .bind(serde_json::to_vec(&snapshot).unwrap())
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;
    assert!(SqliteStore::open(&path).await.is_err());
}

#[tokio::test]
async fn impossible_connect_replay_snapshots_fail_live_and_reopen() {
    for mutation in [
        "generation_zero",
        "next_equals_ack",
        "next_below_ack",
        "timestamp",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_tool_store(&store).await;
        let request_id = RequestId::from_uuid(Uuid::from_u128(81_003)).unwrap();
        let bytes: Vec<u8> =
            sqlx::query_scalar("SELECT result FROM request_ledger WHERE request_id=?")
                .bind(request_id.to_string())
                .fetch_one(store.pool())
                .await
                .unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        match mutation {
            "generation_zero" => value["generation"] = serde_json::json!(0),
            "next_equals_ack" => {
                value["next_server_sequence"] = value["acknowledged_server_sequence"].clone();
            }
            "next_below_ack" => {
                value["acknowledged_server_sequence"] = serde_json::json!(1);
                value["next_server_sequence"] = serde_json::json!(0);
            }
            "timestamp" => {
                let seconds = value["connected_at"]["unix_seconds"].as_i64().unwrap();
                value["connected_at"]["unix_seconds"] = serde_json::json!(seconds + 1);
            }
            _ => unreachable!(),
        }
        sqlx::query("UPDATE request_ledger SET result=? WHERE request_id=?")
            .bind(serde_json::to_vec(&value).unwrap())
            .bind(request_id.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        let command = ConnectToolProvider {
            context: context(81_003, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            consumer_key: ConsumerKey::new("consumer-a").unwrap(),
            provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
            connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_005)).unwrap(),
            after_server_sequence: 0,
            registration_ids: vec![ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap()],
        };
        assert_eq!(
            store.connect_tool_provider(command).await,
            Err(StoreError::Corrupt),
            "{mutation}"
        );
        store.pool().close().await;
        assert!(SqliteStore::open(&path).await.is_err(), "{mutation}");
    }
}

#[tokio::test]
async fn tool_resolution_alien_valid_outcome_fails_live_and_reopen() {
    let directory = TempDir::new().unwrap();
    let (store, path, _) = new_store(&directory).await;
    let (uncertain, command) = prepare_uncertain_tool_resolution(&store).await;
    let outcome = store
        .resolve_authorized_effect(command.clone())
        .await
        .unwrap()
        .value()
        .clone();
    let mut alien = serde_json::to_value(outcome).unwrap();
    alien["effect_entry"]["request_id"] =
        serde_json::json!(RequestId::from_uuid(Uuid::from_u128(81_399)).unwrap());
    let _: navigator_store_api::AuthorizedEffectResolution =
        serde_json::from_value(alien.clone()).unwrap();
    sqlx::query("UPDATE effect_journal_mutations SET result=? WHERE request_id=?")
        .bind(serde_json::to_vec(&alien).unwrap())
        .bind(command.context.request_id().to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store.resolve_authorized_effect(command).await,
        Err(StoreError::Corrupt)
    );
    assert_eq!(
        store
            .load_tool_invocation(uncertain.invocation().invocation_id())
            .await
            .unwrap()
            .unwrap()
            .phase(),
        ToolInvocationPhase::Completed
    );
    store.pool().close().await;
    assert!(SqliteStore::open(&path).await.is_err());
}

#[tokio::test]
async fn tool_snapshot_registration_alias_and_mirrored_columns_fail_closed_on_reopen() {
    for mutation in [
        "registration",
        "sequence",
        "watermark",
        "terminal_digest",
        "effect_revision",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_tool_store(&store).await;
        let reserved = store
            .reserve_tool_invocation(tool_reserve(81_040, 81_041, host(20), 1, 10))
            .await
            .unwrap();
        match mutation {
            "registration" => {
                let mut snapshot = serde_json::to_value(&reserved).unwrap();
                snapshot["registration_id"] = serde_json::json!(
                    ToolRegistrationId::from_uuid(Uuid::from_u128(81_042)).unwrap()
                );
                sqlx::query("UPDATE tool_invocations SET snapshot=? WHERE invocation_id=?")
                    .bind(serde_json::to_vec(&snapshot).unwrap())
                    .bind(reserved.invocation().invocation_id().to_string())
                    .execute(store.pool())
                    .await
                    .unwrap();
                assert_eq!(
                    store.list_recoverable_tool_invocations(session_id()).await,
                    Err(StoreError::Corrupt)
                );
            }
            "sequence" => {
                sqlx::query("UPDATE tool_invocations SET server_sequence=server_sequence+1 WHERE invocation_id=?")
                    .bind(reserved.invocation().invocation_id().to_string())
                    .execute(store.pool()).await.unwrap();
            }
            "watermark" => {
                sqlx::query("UPDATE tool_provider_connections SET acknowledged_server_sequence=1")
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            "terminal_digest" => {
                sqlx::query("UPDATE tool_invocations SET terminal_digest=?")
                    .bind(vec![1_u8; 32])
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            "effect_revision" => {
                sqlx::query("UPDATE effect_journal SET revision=revision+1 WHERE request_id=?")
                    .bind(reserved.invocation().request_id().to_string())
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        store.pool().close().await;
        assert!(SqliteStore::open(&path).await.is_err(), "{mutation}");
    }
}

#[tokio::test]
async fn coherent_tool_cross_effect_tree_and_unconnected_consumer_mutants_fail_reopen() {
    for mutation in ["other_effect", "cross_tree", "unconnected_consumer"] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        if mutation == "unconnected_consumer" {
            prepare_tool_registration(&store).await;
            let bytes: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM tool_registrations")
                .fetch_one(store.pool())
                .await
                .unwrap();
            let mut snapshot: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            snapshot["consumer_key"] = serde_json::json!("other-consumer");
            sqlx::query("UPDATE tool_registrations SET consumer_key=?,snapshot=?")
                .bind("other-consumer")
                .bind(serde_json::to_vec(&snapshot).unwrap())
                .execute(store.pool())
                .await
                .unwrap();
            assert_eq!(
                store.list_tool_registrations(session_id()).await,
                Err(StoreError::Corrupt)
            );
        } else {
            prepare_tool_store(&store).await;
            let reserved = store
                .reserve_tool_invocation(tool_reserve(81_200, 81_201, host(20), 1, 10))
                .await
                .unwrap();
            let bytes: Vec<u8> =
                sqlx::query_scalar("SELECT snapshot FROM tool_invocations WHERE invocation_id=?")
                    .bind(reserved.invocation().invocation_id().to_string())
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            let mut snapshot: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if mutation == "other_effect" {
                let other = store
                    .reserve_effect(journal_reserve_command())
                    .await
                    .unwrap();
                snapshot["invocation"]["request_id"] = serde_json::json!(other.request_id);
                sqlx::query("UPDATE tool_invocations SET effect_request_id=?,snapshot=? WHERE invocation_id=?")
                    .bind(other.request_id.to_string()).bind(serde_json::to_vec(&snapshot).unwrap())
                    .bind(reserved.invocation().invocation_id().to_string()).execute(store.pool()).await.unwrap();
            } else {
                let child = child_command();
                store.create_child_participant(child.clone()).await.unwrap();
                snapshot["invocation"]["participant_id"] = serde_json::json!(child.participant_id);
                sqlx::query(
                    "UPDATE tool_invocations SET participant_id=?,snapshot=? WHERE invocation_id=?",
                )
                .bind(child.participant_id.to_string())
                .bind(serde_json::to_vec(&snapshot).unwrap())
                .bind(reserved.invocation().invocation_id().to_string())
                .execute(store.pool())
                .await
                .unwrap();
                sqlx::query("UPDATE effect_journal SET participant_id=? WHERE request_id=?")
                    .bind(child.participant_id.to_string())
                    .bind(reserved.invocation().request_id().to_string())
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            assert_eq!(
                store
                    .load_tool_invocation(reserved.invocation().invocation_id())
                    .await,
                Err(StoreError::Corrupt)
            );
            assert_eq!(
                store.list_recoverable_tool_invocations(session_id()).await,
                Err(StoreError::Corrupt)
            );
            assert_eq!(
                store
                    .list_provider_replay(
                        session_id(),
                        ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                        0,
                    )
                    .await,
                Err(StoreError::Corrupt)
            );
        }
        store.pool().close().await;
        assert!(SqliteStore::open(&path).await.is_err(), "{mutation}");
    }
}

#[tokio::test]
async fn provider_reconnect_rebinds_replay_and_fences_stale_generation() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_tool_store(&store).await;
    let reserved = store
        .reserve_tool_invocation(tool_reserve(81_050, 81_051, host(20), 1, 10))
        .await
        .unwrap();
    let connection_id = ToolConnectionId::from_uuid(Uuid::from_u128(81_052)).unwrap();
    let connection = store
        .connect_tool_provider(ConnectToolProvider {
            context: context(81_053, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            consumer_key: ConsumerKey::new("consumer-a").unwrap(),
            provider_id: reserved.dispatch().provider_id,
            connection_id,
            after_server_sequence: 0,
            registration_ids: vec![reserved.registration_id()],
        })
        .await
        .unwrap();
    let start = |request, connection_id, generation| TransitionToolInvocation {
        context: context(request, host(20)),
        invocation_id: reserved.invocation().invocation_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        expected_revision: reserved.revision(),
        transition: ToolTransition::Start,
        provider_id: reserved.dispatch().provider_id,
        connection_id,
        connection_generation: generation,
        dispatch_id: reserved.dispatch().dispatch_id,
        server_sequence: reserved.dispatch().server_sequence,
    };
    assert_eq!(
        store
            .transition_tool_invocation(start(
                81_054,
                reserved.dispatch().connection_id.unwrap(),
                reserved.dispatch().connection_generation.unwrap(),
            ))
            .await,
        Err(StoreError::Invalid)
    );
    let rebound = store
        .load_tool_invocation(reserved.invocation().invocation_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rebound.dispatch().connection_id, Some(connection_id));
    assert_eq!(
        rebound.dispatch().connection_generation,
        Some(connection.generation)
    );
    assert_eq!(
        store
            .transition_tool_invocation(start(81_055, connection_id, connection.generation))
            .await
            .unwrap()
            .phase(),
        ToolInvocationPhase::Started
    );
}

#[tokio::test]
async fn waiting_operation_cannot_cross_the_tool_start_effect_boundary() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_tool_store(&store).await;
    let reserved = store
        .reserve_tool_invocation(tool_reserve(81_056, 81_057, host(20), 1, 10))
        .await
        .unwrap();
    let mut wait = mailbox_enqueue_command();
    wait.context = context(81_054, host(20));
    wait.message_id = MessageId::from_uuid(Uuid::from_u128(81_055)).unwrap();
    let wait_message = wait.message_id;
    store.enqueue_message(wait).await.unwrap();
    store
        .transition_operation(TransitionOperation {
            context: context(81_058, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            operation_id: start_operation_command().operation_id,
            expected_revision: Revision::new(3).unwrap(),
            action: OperationAction::Wait,
            report_message_id: Some(wait_message),
            terminal_outcome: None,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .transition_tool_invocation(TransitionToolInvocation {
                context: context(81_059, host(20)),
                invocation_id: reserved.invocation().invocation_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                expected_revision: reserved.revision(),
                transition: ToolTransition::Start,
                provider_id: reserved.dispatch().provider_id,
                connection_id: reserved.dispatch().connection_id.unwrap(),
                connection_generation: reserved.dispatch().connection_generation.unwrap(),
                dispatch_id: reserved.dispatch().dispatch_id,
                server_sequence: reserved.dispatch().server_sequence,
            })
            .await,
        Err(StoreError::Invalid)
    );
}

#[tokio::test]
async fn unsupported_cancellation_never_allocates_a_cancel_sequence() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_tool_authority(&store).await;
    store
        .register_tool(RegisterTool {
            context: context(81_070, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(81_071)).unwrap(),
            consumer_key: ConsumerKey::new("consumer-a").unwrap(),
            definition: tool_definition_with(ToolCancellation::Unsupported),
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .connect_tool_provider(ConnectToolProvider {
                context: context(81_069, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                consumer_key: ConsumerKey::new("different-consumer").unwrap(),
                provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_073)).unwrap(),
                connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_074)).unwrap(),
                after_server_sequence: 0,
                registration_ids: vec![
                    ToolRegistrationId::from_uuid(Uuid::from_u128(81_071)).unwrap()
                ],
            })
            .await,
        Err(StoreError::Invalid)
    );
    store
        .connect_tool_provider(ConnectToolProvider {
            context: context(81_072, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            consumer_key: ConsumerKey::new("consumer-a").unwrap(),
            provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_073)).unwrap(),
            connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_074)).unwrap(),
            after_server_sequence: 0,
            registration_ids: vec![ToolRegistrationId::from_uuid(Uuid::from_u128(81_071)).unwrap()],
        })
        .await
        .unwrap();
    let mut reserve = tool_reserve(81_075, 81_076, host(20), 1, 10);
    reserve.provider_id = ToolProviderId::from_uuid(Uuid::from_u128(81_073)).unwrap();
    reserve.registration_id = ToolRegistrationId::from_uuid(Uuid::from_u128(81_071)).unwrap();
    reserve.dispatch_id = ToolDispatchId::from_uuid(Uuid::from_u128(81_077)).unwrap();
    let reserved = store.reserve_tool_invocation(reserve).await.unwrap();
    assert_eq!(
        store
            .transition_tool_invocation(TransitionToolInvocation {
                context: context(81_078, host(20)),
                invocation_id: reserved.invocation().invocation_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                expected_revision: reserved.revision(),
                transition: ToolTransition::RequestCancel {
                    cancellation_id: ToolCancellationId::from_uuid(Uuid::from_u128(81_079))
                        .unwrap()
                },
                provider_id: reserved.dispatch().provider_id,
                connection_id: reserved.dispatch().connection_id.unwrap(),
                connection_generation: reserved.dispatch().connection_generation.unwrap(),
                dispatch_id: reserved.dispatch().dispatch_id,
                server_sequence: reserved.dispatch().server_sequence,
            })
            .await,
        Err(StoreError::Invalid)
    );
    assert_eq!(
        store
            .load_tool_invocation(reserved.invocation().invocation_id())
            .await
            .unwrap()
            .unwrap(),
        reserved
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
// Guarantees: NAV-RECOVERY-001
async fn tool_recovery_matrix_marks_only_unsafe_effect_classes_uncertain() {
    for (index, effect_class, idempotency, unsafe_effect) in [
        (
            0,
            EffectClass::ReadOnly,
            IdempotencyContract::NoExternalEffect,
            false,
        ),
        (
            1,
            EffectClass::Idempotent,
            IdempotencyContract::InvocationIdentity,
            false,
        ),
        (
            2,
            EffectClass::Transactional,
            IdempotencyContract::ExternalTransactionProof,
            true,
        ),
        (
            3,
            EffectClass::NonIdempotent,
            IdempotencyContract::NeverReplay,
            true,
        ),
        (
            4,
            EffectClass::Unknown,
            IdempotencyContract::NeverReplay,
            true,
        ),
    ] {
        let directory = TempDir::new().unwrap();
        let (store, _, _) = new_store(&directory).await;
        prepare_tool_authority(&store).await;
        let registration_id =
            ToolRegistrationId::from_uuid(Uuid::from_u128(81_100 + index)).unwrap();
        let provider_id = ToolProviderId::from_uuid(Uuid::from_u128(81_110 + index)).unwrap();
        let connection_id = ToolConnectionId::from_uuid(Uuid::from_u128(81_120 + index)).unwrap();
        store
            .register_tool(RegisterTool {
                context: context(81_130 + index, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                registration_id,
                consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                definition: tool_definition_contract(
                    ToolCancellation::Cooperative,
                    effect_class,
                    idempotency,
                ),
            })
            .await
            .unwrap();
        store
            .connect_tool_provider(ConnectToolProvider {
                context: context(81_140 + index, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                provider_id,
                connection_id,
                after_server_sequence: 0,
                registration_ids: vec![registration_id],
            })
            .await
            .unwrap();
        let mut reserve = tool_reserve(81_150 + index, 81_160 + index, host(20), 1, 10);
        reserve.registration_id = registration_id;
        reserve.provider_id = provider_id;
        reserve.dispatch_id = ToolDispatchId::from_uuid(Uuid::from_u128(81_170 + index)).unwrap();
        let reserved = store.reserve_tool_invocation(reserve).await.unwrap();
        let command = |request, revision, transition| TransitionToolInvocation {
            context: context(request, host(20)),
            invocation_id: reserved.invocation().invocation_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            expected_revision: revision,
            transition,
            provider_id,
            connection_id,
            connection_generation: 1,
            dispatch_id: reserved.dispatch().dispatch_id,
            server_sequence: reserved.dispatch().server_sequence,
        };
        let started = store
            .transition_tool_invocation(command(
                81_180 + index,
                reserved.revision(),
                ToolTransition::Start,
            ))
            .await
            .unwrap();
        let outcome = store
            .transition_tool_invocation(command(
                81_190 + index,
                started.revision(),
                ToolTransition::MarkUncertain,
            ))
            .await;
        assert_eq!(outcome.is_ok(), unsafe_effect, "{effect_class:?}");
        if let Ok(value) = outcome {
            assert_eq!(value.phase(), ToolInvocationPhase::Uncertain);
        }
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn tool_transitions_validate_schema_cas_terminal_identity_and_replay() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_tool_store(&store).await;
    let reserved = store
        .reserve_tool_invocation(tool_reserve(81_020, 81_021, host(20), 1, 10))
        .await
        .unwrap();
    let start = TransitionToolInvocation {
        context: context(81_022, host(20)),
        invocation_id: reserved.invocation().invocation_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        expected_revision: reserved.revision(),
        transition: ToolTransition::Start,
        provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
        connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_005)).unwrap(),
        connection_generation: 1,
        dispatch_id: reserved.dispatch().dispatch_id,
        server_sequence: reserved.dispatch().server_sequence,
    };
    let started = store
        .transition_tool_invocation(start.clone())
        .await
        .unwrap();
    assert_eq!(started.phase(), ToolInvocationPhase::Started);
    assert_eq!(
        store.transition_tool_invocation(start).await.unwrap(),
        started
    );
    let invalid = ToolResult::new(
        started.invocation().invocation_id(),
        CanonicalJson::new(r#"{"found":"yes"}"#).unwrap(),
        vec![],
    )
    .unwrap();
    assert_eq!(
        store
            .transition_tool_invocation(TransitionToolInvocation {
                context: context(81_023, host(20)),
                invocation_id: started.invocation().invocation_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                expected_revision: started.revision(),
                transition: ToolTransition::Complete(invalid),
                provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_005)).unwrap(),
                connection_generation: 1,
                dispatch_id: started.dispatch().dispatch_id,
                server_sequence: started.dispatch().server_sequence,
            })
            .await,
        Err(StoreError::Invalid)
    );
    let result = ToolResult::new(
        started.invocation().invocation_id(),
        CanonicalJson::new(r#"{"found":true}"#).unwrap(),
        vec![],
    )
    .unwrap();
    let complete = TransitionToolInvocation {
        context: context(81_024, host(20)),
        invocation_id: started.invocation().invocation_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        expected_revision: started.revision(),
        transition: ToolTransition::Complete(result),
        provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
        connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_005)).unwrap(),
        connection_generation: 1,
        dispatch_id: started.dispatch().dispatch_id,
        server_sequence: started.dispatch().server_sequence,
    };
    let completed = store
        .transition_tool_invocation(complete.clone())
        .await
        .unwrap();
    assert_eq!(completed.phase(), ToolInvocationPhase::Completed);
    assert_eq!(
        store
            .list_provider_replay(
                session_id(),
                ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                0,
            )
            .await
            .unwrap(),
        vec![completed.clone()]
    );
    assert!(
        store
            .list_provider_replay(
                session_id(),
                ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                completed.dispatch().server_sequence,
            )
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.transition_tool_invocation(complete).await.unwrap(),
        completed
    );
    let divergent = ToolFailure {
        invocation_id: started.invocation().invocation_id(),
        kind: ToolFailureKind::HandlerFailed,
        message: BoundedText::new("different").unwrap(),
        retryable: false,
    };
    assert!(matches!(
        store
            .transition_tool_invocation(TransitionToolInvocation {
                context: context(81_025, host(20)),
                invocation_id: started.invocation().invocation_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                expected_revision: completed.revision(),
                transition: ToolTransition::Fail(divergent),
                provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_005)).unwrap(),
                connection_generation: 1,
                dispatch_id: completed.dispatch().dispatch_id,
                server_sequence: completed.dispatch().server_sequence,
            })
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
    let reconnect = store
        .connect_tool_provider(ConnectToolProvider {
            context: context(81_026, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            consumer_key: ConsumerKey::new("consumer-a").unwrap(),
            provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
            connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_027)).unwrap(),
            after_server_sequence: completed.dispatch().server_sequence,
            registration_ids: vec![ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap()],
        })
        .await
        .unwrap();
    assert_eq!(reconnect.generation, 2);
    for (request, after) in [(81_028, 0), (81_029, 2)] {
        assert_eq!(
            store
                .connect_tool_provider(ConnectToolProvider {
                    context: context(request, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                    provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                    connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(request + 100))
                        .unwrap(),
                    after_server_sequence: after,
                    registration_ids: vec![
                        ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap(),
                    ],
                })
                .await,
            Err(StoreError::Invalid)
        );
    }
}

#[allow(clippy::too_many_lines)]
async fn prepare_uncertain_tool_resolution(
    store: &SqliteStore,
) -> (ToolInvocationSnapshot, ResolveAuthorizedEffect) {
    prepare_tool_store(store).await;
    let reserved = store
        .reserve_tool_invocation(tool_reserve(81_030, 81_031, host(20), 1, 10))
        .await
        .unwrap();
    let transition = |request, revision, transition| TransitionToolInvocation {
        context: context(request, host(20)),
        invocation_id: reserved.invocation().invocation_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        expected_revision: revision,
        transition,
        provider_id: reserved.dispatch().provider_id,
        connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_005)).unwrap(),
        connection_generation: 1,
        dispatch_id: reserved.dispatch().dispatch_id,
        server_sequence: reserved.dispatch().server_sequence,
    };
    let started = store
        .transition_tool_invocation(transition(
            81_032,
            reserved.revision(),
            ToolTransition::Start,
        ))
        .await
        .unwrap();
    let uncertain = store
        .transition_tool_invocation(transition(
            81_033,
            started.revision(),
            ToolTransition::MarkUncertain,
        ))
        .await
        .unwrap();
    store
        .transition_operation(TransitionOperation {
            context: context(81_034, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            operation_id: start_operation_command().operation_id,
            expected_revision: Revision::new(3).unwrap(),
            action: OperationAction::ReportUncertain,
            report_message_id: Some(start_operation_command().input_message_id),
            terminal_outcome: Some(navigator_store_api::OperationTerminalOutcome::Uncertain {
                reason: BoundedText::new("Tool effect unknown").unwrap(),
            }),
        })
        .await
        .unwrap();
    let grant_id = GrantId::from_uuid(Uuid::from_u128(81_036)).unwrap();
    store
        .issue_grant(IssueGrant {
            context: context(81_037, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            grant: Grant {
                id: grant_id,
                session_id: session_id(),
                subject: participant_command().participant_id,
                authority: resolution_scope(),
                expires_at: Timestamp::new(150, 0).unwrap(),
                revoked: false,
            },
            single_use: true,
        })
        .await
        .unwrap();
    let command = tool_resolution_command(&uncertain);
    (uncertain, command)
}

fn tool_resolution_command(uncertain: &ToolInvocationSnapshot) -> ResolveAuthorizedEffect {
    let proof_bytes = b"TOOL_EXTERNAL_COMMIT".to_vec();
    let proof = EffectProof::new(
        EffectProofKind::ExternalCommit,
        Sha256::digest(&proof_bytes).into(),
        BoundedBytes::new(proof_bytes).unwrap(),
    )
    .unwrap();
    let result = ToolResult::new(
        uncertain.invocation().invocation_id(),
        CanonicalJson::new(r#"{"found":true}"#).unwrap(),
        vec![],
    )
    .unwrap();
    ResolveAuthorizedEffect {
        context: context(81_038, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        participant_id: participant_command().participant_id,
        grant_id: GrantId::from_uuid(Uuid::from_u128(81_036)).unwrap(),
        effect_request_id: uncertain.invocation().request_id(),
        expected_effect_revision: uncertain.revision(),
        decision: ResolveUncertaintyDecision::new(
            session_id(),
            start_operation_command().operation_id,
            BoundedText::new("provider reconciliation proved commit").unwrap(),
            UncertaintyResolution::ConfirmCompleted { proof },
        )
        .unwrap(),
        tool_terminal: Some(navigator_store_api::ToolTerminal::Completed(result)),
    }
}

fn tool_do_not_retry_command(uncertain: &ToolInvocationSnapshot) -> ResolveAuthorizedEffect {
    let mut command = tool_resolution_command(uncertain);
    command.decision = ResolveUncertaintyDecision::new(
        session_id(),
        start_operation_command().operation_id,
        BoundedText::new("operator forbids replay").unwrap(),
        UncertaintyResolution::DoNotRetry,
    )
    .unwrap();
    command.tool_terminal = Some(navigator_store_api::ToolTerminal::Failed(ToolFailure {
        invocation_id: uncertain.invocation().invocation_id(),
        kind: ToolFailureKind::EffectUncertain,
        message: BoundedText::new("effect could not be reconciled").unwrap(),
        retryable: false,
    }));
    command
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn uncertain_tool_resolution_binds_proof_and_terminal_atomically() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    let (uncertain, command) = prepare_uncertain_tool_resolution(&store).await;
    let retry_bytes = b"TOOL_ABSENCE_PROOF".to_vec();
    let retry_proof = EffectProof::new(
        EffectProofKind::EffectAbsent,
        Sha256::digest(&retry_bytes).into(),
        BoundedBytes::new(retry_bytes).unwrap(),
    )
    .unwrap();
    let mut impossible_retry = command.clone();
    impossible_retry.context = context(81_080, host(20));
    impossible_retry.decision = ResolveUncertaintyDecision::new(
        session_id(),
        start_operation_command().operation_id,
        BoundedText::new("retry must use a new Operation and invocation").unwrap(),
        UncertaintyResolution::RetryWithEffectProof { proof: retry_proof },
    )
    .unwrap();
    impossible_retry.tool_terminal = None;
    assert_eq!(
        store.resolve_authorized_effect(impossible_retry).await,
        Err(StoreError::Invalid)
    );
    assert!(
        store
            .load_grant(command.grant_id)
            .await
            .unwrap()
            .consumed_at
            .is_none()
    );
    let replacement = ToolInvocation::new(
        ToolInvocationId::from_uuid(Uuid::from_u128(81_081)).unwrap(),
        RequestId::from_uuid(Uuid::from_u128(81_082)).unwrap(),
        session_id(),
        uncertain.invocation().participant_id(),
        OperationId::from_uuid(Uuid::from_u128(81_083)).unwrap(),
        ToolName::new("records.lookup").unwrap(),
        ToolVersion::new("v1").unwrap(),
        CanonicalJson::new(r#"{"key":"x"}"#).unwrap(),
    )
    .unwrap();
    navigator_conformance::tool_store::assert_uncertain_tool_replacement_identity(
        uncertain.invocation(),
        &replacement,
    )
    .unwrap();
    let mut missing_terminal = command.clone();
    missing_terminal.context = context(81_039, host(20));
    missing_terminal.tool_terminal = None;
    assert_eq!(
        store.resolve_authorized_effect(missing_terminal).await,
        Err(StoreError::Invalid)
    );
    assert_eq!(
        store
            .load_tool_invocation(uncertain.invocation().invocation_id())
            .await
            .unwrap()
            .unwrap()
            .phase(),
        ToolInvocationPhase::Uncertain
    );
    store
        .resolve_authorized_effect(command.clone())
        .await
        .unwrap();
    let completed = store
        .load_tool_invocation(uncertain.invocation().invocation_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.phase(), ToolInvocationPhase::Completed);
    assert!(matches!(
        store.resolve_authorized_effect(command.clone()).await,
        Ok(Mutation::Replayed(_))
    ));
    let mut divergent = command;
    divergent.tool_terminal = Some(navigator_store_api::ToolTerminal::Failed(ToolFailure {
        invocation_id: uncertain.invocation().invocation_id(),
        kind: ToolFailureKind::HandlerFailed,
        message: BoundedText::new("divergent reconciliation").unwrap(),
        retryable: false,
    }));
    assert!(matches!(
        store.resolve_authorized_effect(divergent).await,
        Err(StoreError::RequestConflict { .. })
    ));
}

async fn prepare_running_effect_operation(store: &SqliteStore) {
    store.open_session(open_command(80_000)).await.unwrap();
    store
        .acquire_ownership(acquire_command(80_001, host(20), 100, 160))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    store
        .start_operation(start_operation_command())
        .await
        .unwrap();
    prepare_real_mailbox_launch(store).await;
    accept_input_message(store, 9_000_010).await;
    for (request, revision, action) in [
        (80_002, 1, OperationAction::BeginStart),
        (80_003, 2, OperationAction::ReportRunning),
    ] {
        store
            .transition_operation(TransitionOperation {
                context: context(request, host(20)),
                session_id: session_id(),
                epoch: FencingEpoch::new(1).unwrap(),
                operation_id: start_operation_command().operation_id,
                expected_revision: Revision::new(revision).unwrap(),
                action,
                report_message_id: (action == OperationAction::ReportRunning)
                    .then_some(start_operation_command().input_message_id),
                terminal_outcome: None,
            })
            .await
            .unwrap();
    }
}

#[allow(clippy::too_many_lines)]
async fn prepare_authorized_resolution(
    store: &SqliteStore,
    clock: &TestClock,
) -> (
    navigator_store_api::EffectJournalEntry,
    ResolveAuthorizedEffect,
) {
    prepare_running_effect_operation(store).await;
    let reserve = journal_reserve_command();
    let reserved = store.reserve_effect(reserve.clone()).await.unwrap();
    let started = store
        .start_effect(EffectTransition::start(
            context(80_006, host(20)),
            reserved.request_id,
            reserved.owner_epoch,
            reserved.revision,
        ))
        .await
        .unwrap();
    clock.0.store(111, Ordering::SeqCst);
    let uncertain = store.reserve_effect(reserve).await.unwrap();
    assert_ne!(started.revision, uncertain.revision);
    store
        .transition_operation(TransitionOperation {
            context: context(80_004, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            operation_id: start_operation_command().operation_id,
            expected_revision: Revision::new(3).unwrap(),
            action: OperationAction::ReportUncertain,
            report_message_id: Some(start_operation_command().input_message_id),
            terminal_outcome: Some(navigator_store_api::OperationTerminalOutcome::Uncertain {
                reason: BoundedText::new("effect outcome unknown").unwrap(),
            }),
        })
        .await
        .unwrap();
    let full = AuthorityProfile::new([resolution_scope()], [resolution_scope()]).unwrap();
    store
        .put_authority_policy(PutAuthorityPolicy {
            context: context(80_007, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            policy: AuthorityPolicySnapshot {
                session_id: session_id(),
                participant_id: participant_command().participant_id,
                session: full.clone(),
                parent: full.clone(),
                template: full.clone(),
                relationship: full.clone(),
                subject: full,
            },
        })
        .await
        .unwrap();
    let grant_id = GrantId::from_uuid(Uuid::from_u128(80_008)).unwrap();
    store
        .issue_grant(IssueGrant {
            context: context(80_009, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            grant: Grant {
                id: grant_id,
                session_id: session_id(),
                subject: participant_command().participant_id,
                authority: resolution_scope(),
                expires_at: Timestamp::new(150, 0).unwrap(),
                revoked: false,
            },
            single_use: true,
        })
        .await
        .unwrap();
    let proof_bytes = b"PRIVATE_PROOF_SENTINEL".to_vec();
    let proof = EffectProof::new(
        EffectProofKind::ExternalCommit,
        Sha256::digest(&proof_bytes).into(),
        BoundedBytes::new(proof_bytes).unwrap(),
    )
    .unwrap();
    let decision = ResolveUncertaintyDecision::new(
        session_id(),
        start_operation_command().operation_id,
        BoundedText::new("operator verified receipt").unwrap(),
        UncertaintyResolution::ConfirmCompleted { proof },
    )
    .unwrap();
    let command = ResolveAuthorizedEffect {
        context: context(80_010, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        participant_id: participant_command().participant_id,
        grant_id,
        effect_request_id: uncertain.request_id,
        expected_effect_revision: uncertain.revision,
        decision,
        tool_terminal: None,
    };
    (uncertain, command)
}

fn authorized_resolution_command(
    effect: &navigator_store_api::EffectJournalEntry,
) -> ResolveAuthorizedEffect {
    let proof_bytes = b"PRIVATE_PROOF_SENTINEL".to_vec();
    let proof = EffectProof::new(
        EffectProofKind::ExternalCommit,
        Sha256::digest(&proof_bytes).into(),
        BoundedBytes::new(proof_bytes).unwrap(),
    )
    .unwrap();
    ResolveAuthorizedEffect {
        context: context(80_010, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        participant_id: participant_command().participant_id,
        grant_id: GrantId::from_uuid(Uuid::from_u128(80_008)).unwrap(),
        effect_request_id: effect.request_id,
        expected_effect_revision: effect.revision,
        decision: ResolveUncertaintyDecision::new(
            session_id(),
            effect.operation_id,
            BoundedText::new("operator verified receipt").unwrap(),
            UncertaintyResolution::ConfirmCompleted { proof },
        )
        .unwrap(),
        tool_terminal: None,
    }
}

#[test]
fn proof_assertion_is_domain_separated_by_effect_identity_and_semantics() {
    let effect_digest = navigator_domain::SemanticDigest::v1(
        &Capability::new("tool.send").unwrap(),
        b"first semantics",
    );
    let effect = navigator_store_api::EffectJournalEntry {
        request_id: RequestId::from_uuid(Uuid::from_u128(80_005)).unwrap(),
        session_id: session_id(),
        participant_id: participant_command().participant_id,
        operation_id: start_operation_command().operation_id,
        caller: host(20),
        action: Capability::new("tool.send").unwrap(),
        semantic_digest: effect_digest,
        effect_class: EffectClass::NonIdempotent,
        resolution_contract: EffectResolutionContract::conservative(),
        phase: navigator_store_api::EffectJournalPhase::Uncertain,
        owner_host: host(20),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        lease_expires_at: Timestamp::new(110, 0).unwrap(),
        terminal: None,
        revision: Revision::initial(),
    };
    let command = authorized_resolution_command(&effect);
    let baseline = command.assertion_digest(effect_digest);
    let mut reused = command.clone();
    reused.effect_request_id = RequestId::from_uuid(Uuid::from_u128(80_006)).unwrap();
    assert_ne!(baseline, reused.assertion_digest(effect_digest));
    let changed_semantics = navigator_domain::SemanticDigest::v1(
        &Capability::new("tool.send").unwrap(),
        b"second semantics",
    );
    assert_ne!(baseline, command.assertion_digest(changed_semantics));
}

#[tokio::test]
async fn authorized_effect_resolution_is_atomic_redacted_and_idempotent() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    let (_uncertain, mut command) = prepare_authorized_resolution(&store, &clock).await;
    command.decision = ResolveUncertaintyDecision::new(
        session_id(),
        command.decision.operation_id(),
        BoundedText::new("PRIVATE_REASON_SENTINEL").unwrap(),
        command.decision.resolution().clone(),
    )
    .unwrap();
    let operation_before = store
        .load_operation(command.decision.operation_id())
        .await
        .unwrap();
    let applied = store
        .resolve_authorized_effect(command.clone())
        .await
        .unwrap();
    assert!(matches!(applied, Mutation::Applied(_)));
    assert_eq!(
        applied.value().effect_entry.phase,
        navigator_store_api::EffectJournalPhase::Completed
    );
    assert_eq!(
        applied.value().current_operation.state,
        OperationState::Uncertain
    );
    assert_eq!(applied.value().current_operation, operation_before);
    assert_eq!(
        store
            .load_operation(command.decision.operation_id())
            .await
            .unwrap(),
        operation_before
    );
    let events = store
        .read_events(ReadEvents {
            session_id: session_id(),
            consumer: ConsumerKey::new("consumer-a").unwrap(),
            after: None,
            limit: EventReadLimit::new(100).unwrap(),
        })
        .await
        .unwrap();
    assert!(events.events.iter().all(|event| {
        [
            b"PRIVATE_PROOF_SENTINEL".as_slice(),
            b"PRIVATE_REASON_SENTINEL".as_slice(),
        ]
        .iter()
        .all(|sentinel| {
            !event
                .data()
                .as_slice()
                .windows(sentinel.len())
                .any(|window| window == *sentinel)
        })
    }));
    assert_resolved_terminal_is_auditable_but_not_recovered(&store, &command).await;
    for entry in std::fs::read_dir(directory.path()).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let bytes = std::fs::read(path).unwrap();
            assert!(
                [
                    b"PRIVATE_PROOF_SENTINEL".as_slice(),
                    b"PRIVATE_REASON_SENTINEL".as_slice()
                ]
                .iter()
                .all(|sentinel| !bytes.windows(sentinel.len()).any(|w| w == *sentinel)),
                "private resolution material persisted in SQLite files"
            );
        }
    }
    assert!(matches!(
        store
            .resolve_authorized_effect(command.clone())
            .await
            .unwrap(),
        Mutation::Replayed(_)
    ));
    let mut changed_cas = command.clone();
    changed_cas.expected_effect_revision = applied.value().effect_entry.revision;
    changed_cas.owner_epoch = FencingEpoch::new(99).unwrap();
    assert!(matches!(
        store.resolve_authorized_effect(changed_cas).await.unwrap(),
        Mutation::Replayed(_)
    ));
    let mut changed = command;
    changed.decision = ResolveUncertaintyDecision::new(
        session_id(),
        changed.decision.operation_id(),
        BoundedText::new("different private reason").unwrap(),
        changed.decision.resolution().clone(),
    )
    .unwrap();
    assert!(matches!(
        store.resolve_authorized_effect(changed).await,
        Err(StoreError::RequestConflict { .. })
    ));
}

async fn assert_resolved_terminal_is_auditable_but_not_recovered(
    store: &SqliteStore,
    command: &ResolveAuthorizedEffect,
) {
    let inventory = store
        .load_recovery_inventory(session_id(), host(20), FencingEpoch::new(1).unwrap())
        .await
        .unwrap();
    assert!(
        inventory
            .operations
            .iter()
            .all(|operation| operation.operation_id != command.decision.operation_id())
    );
    assert!(
        inventory
            .effects
            .iter()
            .all(|effect| effect.request_id != command.effect_request_id)
    );
    assert_eq!(
        store
            .read_effect(command.effect_request_id)
            .await
            .unwrap()
            .unwrap()
            .phase,
        navigator_store_api::EffectJournalPhase::Completed
    );
}

#[tokio::test]
async fn unauthorized_effect_resolutions_leave_every_durable_surface_unchanged() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    let (effect, command) = prepare_authorized_resolution(&store, &clock).await;
    let before_operation = store.load_operation(effect.operation_id).await.unwrap();
    let before_grant = store.load_grant(command.grant_id).await.unwrap();
    let before_events = store
        .read_events(ReadEvents {
            session_id: session_id(),
            consumer: ConsumerKey::new("consumer-a").unwrap(),
            after: None,
            limit: EventReadLimit::new(100).unwrap(),
        })
        .await
        .unwrap()
        .events
        .len();
    let disallowed_bytes = b"PRIVATE_PROOF_SENTINEL".to_vec();
    let disallowed = EffectProof::new(
        EffectProofKind::IdempotencyReceipt,
        Sha256::digest(&disallowed_bytes).into(),
        BoundedBytes::new(disallowed_bytes).unwrap(),
    )
    .unwrap();
    let mut wrong_proof = command.clone();
    wrong_proof.context = context(80_011, host(20));
    wrong_proof.decision = ResolveUncertaintyDecision::new(
        session_id(),
        effect.operation_id,
        BoundedText::new("wrong proof").unwrap(),
        UncertaintyResolution::ConfirmCompleted { proof: disallowed },
    )
    .unwrap();
    let mut stale = command.clone();
    stale.context = context(80_012, host(20));
    stale.expected_effect_revision = Revision::initial();
    let absence_bytes = b"ABSENCE_IS_NOT_COMPLETION".to_vec();
    let absence = EffectProof::new(
        EffectProofKind::EffectAbsent,
        Sha256::digest(&absence_bytes).into(),
        BoundedBytes::new(absence_bytes).unwrap(),
    )
    .unwrap();
    let mut absence_as_completion = command.clone();
    absence_as_completion.context = context(80_013, host(20));
    absence_as_completion.decision = ResolveUncertaintyDecision::new(
        session_id(),
        effect.operation_id,
        BoundedText::new("absence cannot complete").unwrap(),
        UncertaintyResolution::ConfirmCompleted { proof: absence },
    )
    .unwrap();
    let commit_bytes = b"COMMIT_IS_NOT_ABSENCE".to_vec();
    let commit = EffectProof::new(
        EffectProofKind::ExternalCommit,
        Sha256::digest(&commit_bytes).into(),
        BoundedBytes::new(commit_bytes).unwrap(),
    )
    .unwrap();
    let mut commit_as_retry = command.clone();
    commit_as_retry.context = context(80_014, host(20));
    commit_as_retry.decision = ResolveUncertaintyDecision::new(
        session_id(),
        effect.operation_id,
        BoundedText::new("commit cannot authorize retry").unwrap(),
        UncertaintyResolution::RetryWithEffectProof { proof: commit },
    )
    .unwrap();
    for denied in [wrong_proof, stale, absence_as_completion, commit_as_retry] {
        assert_eq!(
            store.resolve_authorized_effect(denied).await,
            Err(StoreError::Invalid)
        );
        assert_eq!(
            store.read_effect(effect.request_id).await.unwrap().unwrap(),
            effect
        );
        assert_eq!(
            store.load_operation(effect.operation_id).await.unwrap(),
            before_operation
        );
        assert_eq!(
            store.load_grant(command.grant_id).await.unwrap(),
            before_grant
        );
        assert_eq!(
            store
                .read_events(ReadEvents {
                    session_id: session_id(),
                    consumer: ConsumerKey::new("consumer-a").unwrap(),
                    after: None,
                    limit: EventReadLimit::new(100).unwrap()
                })
                .await
                .unwrap()
                .events
                .len(),
            before_events
        );
    }
}

#[tokio::test]
async fn mismatched_authorized_resolution_identity_and_phase_never_mutate() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    let (effect, command) = prepare_authorized_resolution(&store, &clock).await;
    let operation_before = store.load_operation(effect.operation_id).await.unwrap();
    let grant_before = store.load_grant(command.grant_id).await.unwrap();
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let mut wrong_participant = command.clone();
    wrong_participant.context = context(80_020, host(20));
    wrong_participant.participant_id = ParticipantId::from_uuid(Uuid::from_u128(80_099)).unwrap();
    let mut wrong_operation = command.clone();
    wrong_operation.context = context(80_021, host(20));
    wrong_operation.decision = ResolveUncertaintyDecision::new(
        session_id(),
        OperationId::from_uuid(Uuid::from_u128(80_098)).unwrap(),
        BoundedText::new("wrong operation").unwrap(),
        command.decision.resolution().clone(),
    )
    .unwrap();
    let mut wrong_session = command.clone();
    wrong_session.context = context(80_022, host(20));
    wrong_session.session_id = SessionId::from_uuid(Uuid::from_u128(80_097)).unwrap();
    for denied in [wrong_participant, wrong_operation, wrong_session] {
        assert!(store.resolve_authorized_effect(denied).await.is_err());
        assert_eq!(
            store.read_effect(effect.request_id).await.unwrap(),
            Some(effect.clone())
        );
        assert_eq!(
            store.load_operation(effect.operation_id).await.unwrap(),
            operation_before
        );
        assert_eq!(
            store.load_grant(command.grant_id).await.unwrap(),
            grant_before
        );
        let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(events, events_before);
    }
    store
        .resolve_authorized_effect(command.clone())
        .await
        .unwrap();
    let completed = store.read_effect(effect.request_id).await.unwrap().unwrap();
    let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let mut wrong_phase = command;
    wrong_phase.context = context(80_023, host(20));
    wrong_phase.expected_effect_revision = completed.revision;
    assert_eq!(
        store.resolve_authorized_effect(wrong_phase).await,
        Err(StoreError::Invalid)
    );
    assert_eq!(
        store.read_effect(effect.request_id).await.unwrap(),
        Some(completed)
    );
    let final_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(final_events, events_after);
}

#[tokio::test]
async fn effect_reservation_rejects_non_active_operation_states() {
    for state in [
        OperationState::Queued,
        OperationState::Cancelling,
        OperationState::Uncertain,
        OperationState::Succeeded,
    ] {
        let directory = TempDir::new().unwrap();
        let (store, _, _) = new_store(&directory).await;
        store.open_session(open_command(81_000)).await.unwrap();
        store
            .acquire_ownership(acquire_command(81_001, host(20), 100, 160))
            .await
            .unwrap();
        store.register_template(template_record()).await.unwrap();
        store
            .create_root_participant(participant_command())
            .await
            .unwrap();
        store
            .start_operation(start_operation_command())
            .await
            .unwrap();
        let terminal = match state {
            OperationState::Uncertain => {
                Some(navigator_store_api::OperationTerminalOutcome::Uncertain {
                    reason: BoundedText::new("unknown").unwrap(),
                })
            }
            OperationState::Succeeded => {
                Some(navigator_store_api::OperationTerminalOutcome::Succeeded {
                    result: BoundedBytes::new(Vec::new()).unwrap(),
                })
            }
            _ => None,
        };
        sqlx::query("UPDATE operations SET state=?,terminal_outcome=?,terminal_payload=? WHERE operation_id=?").bind(match state{OperationState::Queued=>"queued",OperationState::Cancelling=>"cancelling",OperationState::Uncertain=>"uncertain",OperationState::Succeeded=>"succeeded",_=>unreachable!()}).bind(match state{OperationState::Uncertain=>Some("uncertain"),OperationState::Succeeded=>Some("succeeded"),_=>None}).bind(terminal.as_ref().map(serde_json::to_vec).transpose().unwrap()).bind(start_operation_command().operation_id.to_string()).execute(store.pool()).await.unwrap();
        let command = ReserveEffect::new(
            context(81_002, host(20)),
            session_id(),
            participant_command().participant_id,
            start_operation_command().operation_id,
            FencingEpoch::new(1).unwrap(),
            Capability::new("tool.send").unwrap(),
            b"state",
            EffectClass::NonIdempotent,
            EffectResolutionContract::conservative(),
            std::time::Duration::from_secs(10),
        );
        assert_eq!(
            store.reserve_effect(command).await,
            Err(StoreError::Invalid),
            "reserved effect while Operation was {state:?}"
        );
    }
}

#[tokio::test]
async fn effect_journal_participates_in_global_request_identity() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let mut collision = journal_reserve_command();
    collision.context = context(80_000, host(20));
    assert!(matches!(
        store.reserve_effect(collision).await,
        Err(StoreError::RequestConflict { .. })
    ));
    let effect = store
        .reserve_effect(journal_reserve_command())
        .await
        .unwrap();
    assert!(matches!(
        store
            .renew_ownership(RenewOwnership::new(
                RequestContext::new(effect.request_id, host(20)),
                session_id(),
                FencingEpoch::new(1).unwrap(),
                LeaseDuration::from_millis(10_000).unwrap(),
            ))
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
    assert_eq!(
        store.read_effect(effect.request_id).await.unwrap(),
        Some(effect)
    );
}

#[tokio::test]
async fn effect_reservation_rejects_semantically_impossible_resolution_contracts() {
    for (offset, contract) in [
        (
            0_u128,
            EffectResolutionContract {
                allow_confirm_completed: true,
                allow_do_not_retry: false,
                allow_retry_with_proof: false,
                allowed_proof_kinds: vec![EffectProofKind::EffectAbsent],
            },
        ),
        (
            1,
            EffectResolutionContract {
                allow_confirm_completed: false,
                allow_do_not_retry: false,
                allow_retry_with_proof: true,
                allowed_proof_kinds: vec![EffectProofKind::ExternalCommit],
            },
        ),
    ] {
        let directory = TempDir::new().unwrap();
        let (store, _, _) = new_store(&directory).await;
        prepare_running_effect_operation(&store).await;
        let request_id = RequestId::from_uuid(Uuid::from_u128(86_000 + offset)).unwrap();
        let command = ReserveEffect::new(
            RequestContext::new(request_id, host(20)),
            session_id(),
            participant_command().participant_id,
            start_operation_command().operation_id,
            FencingEpoch::new(1).unwrap(),
            Capability::new("tool.send").unwrap(),
            b"impossible contract",
            EffectClass::NonIdempotent,
            contract,
            std::time::Duration::from_secs(10),
        );
        assert_eq!(
            store.reserve_effect(command).await,
            Err(StoreError::Invalid)
        );
        assert!(store.read_effect(request_id).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn recovery_classifications_share_the_global_request_namespace() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let classification = |request| RecordRecoveryClassifications {
        context: context(request, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        classifications: vec![RecoveryEventClassification {
            entity: RecoveryEventEntity::Session(session_id()),
            state: navigator_domain::RecoveryState::SessionOpen,
            observation: navigator_domain::LiveObservation::NotApplicable,
            decision: navigator_domain::classify_recovery(
                navigator_domain::RecoveryState::SessionOpen,
                navigator_domain::LiveObservation::NotApplicable,
            )
            .unwrap(),
        }],
    };
    store
        .record_recovery_classifications(classification(87_000))
        .await
        .unwrap();
    let events_after_classification: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert!(matches!(
        store
            .renew_ownership(RenewOwnership::new(
                context(87_000, host(20)),
                session_id(),
                FencingEpoch::new(1).unwrap(),
                LeaseDuration::from_millis(10_000).unwrap(),
            ))
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
    assert!(matches!(
        store
            .record_recovery_classifications(classification(80_000))
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
    let reserve = journal_reserve_command();
    let reserved = store.reserve_effect(reserve.clone()).await.unwrap();
    assert!(matches!(
        store
            .record_recovery_classifications(classification(80_005))
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
    store
        .start_effect(EffectTransition::start(
            context(87_001, host(20)),
            reserved.request_id,
            reserved.owner_epoch,
            reserved.revision,
        ))
        .await
        .unwrap();
    assert!(matches!(
        store
            .record_recovery_classifications(classification(87_001))
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
    let mut recovery_collision = reserve;
    recovery_collision.context = context(87_000, host(20));
    assert!(matches!(
        store.reserve_effect(recovery_collision).await,
        Err(StoreError::RequestConflict { .. })
    ));
    let final_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(final_events, events_after_classification);
}

#[tokio::test]
async fn abandon_and_retry_proof_commit_declared_durable_outcomes() {
    for retry in [false, true] {
        let directory = TempDir::new().unwrap();
        let (store, _, clock) = new_store(&directory).await;
        let (effect, mut command) = prepare_authorized_resolution(&store, &clock).await;
        command.context = context(if retry { 82_001 } else { 82_002 }, host(20));
        command.decision = if retry {
            let proof_bytes = b"ABSENCE_PROOF_PRIVATE".to_vec();
            let proof = EffectProof::new(
                EffectProofKind::EffectAbsent,
                Sha256::digest(&proof_bytes).into(),
                BoundedBytes::new(proof_bytes).unwrap(),
            )
            .unwrap();
            ResolveUncertaintyDecision::new(
                session_id(),
                effect.operation_id,
                BoundedText::new("absence proven").unwrap(),
                UncertaintyResolution::RetryWithEffectProof { proof },
            )
            .unwrap()
        } else {
            ResolveUncertaintyDecision::new(
                session_id(),
                effect.operation_id,
                BoundedText::new("operator abandoned retry").unwrap(),
                UncertaintyResolution::DoNotRetry,
            )
            .unwrap()
        };
        let operation_before = store.load_operation(effect.operation_id).await.unwrap();
        let outcome = store
            .resolve_authorized_effect(command)
            .await
            .unwrap()
            .value()
            .clone();
        assert_eq!(outcome.current_operation.state, OperationState::Uncertain);
        assert_eq!(outcome.current_operation, operation_before);
        assert_eq!(
            store.load_operation(effect.operation_id).await.unwrap(),
            operation_before
        );
        if retry {
            assert_eq!(
                outcome.effect_entry.phase,
                navigator_store_api::EffectJournalPhase::RetryAuthorized
            );
            let started = store
                .start_effect(EffectTransition::start(
                    context(82_003, host(20)),
                    outcome.effect_entry.request_id,
                    outcome.effect_entry.owner_epoch,
                    outcome.effect_entry.revision,
                ))
                .await
                .unwrap();
            assert_eq!(
                started.phase,
                navigator_store_api::EffectJournalPhase::Started
            );
        } else {
            assert_eq!(
                outcome.effect_entry.phase,
                navigator_store_api::EffectJournalPhase::Failed
            );
        }
    }
}

#[tokio::test]
async fn forged_expired_revoked_consumed_or_wrong_scope_grants_cannot_resolve() {
    for variant in 0..6 {
        let directory = TempDir::new().unwrap();
        let (store, _, clock) = new_store(&directory).await;
        let (effect, command) = prepare_authorized_resolution(&store, &clock).await;
        let mut grant = store.load_grant(command.grant_id).await.unwrap();
        match variant {
            0 => grant.grant.expires_at = Timestamp::new(110, 0).unwrap(),
            1 => grant.grant.revoked = true,
            2 => grant.consumed_at = Some(Timestamp::new(110, 0).unwrap()),
            3 => grant.grant.subject = ParticipantId::from_uuid(Uuid::from_u128(99_999)).unwrap(),
            4 => {
                grant.grant.authority = ScopedCapability::new(
                    Capability::new("effect.resolve_uncertainty").unwrap(),
                    ResourceScope::Session(session_id()),
                );
            }
            5 => {
                grant.grant.authority = ScopedCapability::new(
                    Capability::new("effect.observe").unwrap(),
                    ResourceScope::Operation(start_operation_command().operation_id),
                );
            }
            _ => unreachable!(),
        }
        sqlx::query("UPDATE authority_grants SET snapshot=? WHERE grant_id=?")
            .bind(serde_json::to_vec(&grant).unwrap())
            .bind(command.grant_id.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        let before_operation = store.load_operation(effect.operation_id).await.unwrap();
        let before_events = store
            .read_events(ReadEvents {
                session_id: session_id(),
                consumer: ConsumerKey::new("consumer-a").unwrap(),
                after: None,
                limit: EventReadLimit::new(100).unwrap(),
            })
            .await
            .unwrap()
            .events
            .len();
        assert_eq!(
            store.resolve_authorized_effect(command).await,
            Err(StoreError::Invalid)
        );
        assert_eq!(
            store.read_effect(effect.request_id).await.unwrap().unwrap(),
            effect
        );
        assert_eq!(
            store.load_operation(effect.operation_id).await.unwrap(),
            before_operation
        );
        assert_eq!(store.load_grant(grant.grant.id).await.unwrap(), grant);
        assert_eq!(
            store
                .read_events(ReadEvents {
                    session_id: session_id(),
                    consumer: ConsumerKey::new("consumer-a").unwrap(),
                    after: None,
                    limit: EventReadLimit::new(100).unwrap()
                })
                .await
                .unwrap()
                .events
                .len(),
            before_events
        );
    }
}

#[tokio::test]
async fn concurrent_authorized_resolutions_commit_exactly_one() {
    let directory = TempDir::new().unwrap();
    let (first, path, clock) = new_store(&directory).await;
    let (_effect, command) = prepare_authorized_resolution(&first, &clock).await;
    let second = SqliteStore::open_with_clock(
        &path,
        clock.clone(),
        LeaseDuration::from_millis(60_000).unwrap(),
    )
    .await
    .unwrap();
    let mut competing = command.clone();
    competing.context = context(83_001, host(20));
    competing.decision = ResolveUncertaintyDecision::new(
        session_id(),
        start_operation_command().operation_id,
        BoundedText::new("competing abandonment").unwrap(),
        UncertaintyResolution::DoNotRetry,
    )
    .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let left = {
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            first.resolve_authorized_effect(command).await
        })
    };
    let right = {
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            second.resolve_authorized_effect(competing).await
        })
    };
    barrier.wait().await;
    let outcomes = [left.await.unwrap(), right.await.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Ok(Mutation::Applied(_))))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(StoreError::Invalid)))
            .count(),
        1
    );
}

#[tokio::test]
async fn authorized_resolution_crash_is_prior_or_full_and_replays_after_reopen() {
    for point in [
        "effect.resolve_authorized.after_write",
        "effect.resolve_authorized.before_commit",
        "effect.resolve_authorized.after_commit",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        let (before, command) = prepare_authorized_resolution(&store, &clock).await;
        let operation_before = store.load_operation(before.operation_id).await.unwrap();
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(store.pool())
            .await
            .unwrap();
        store.pool().close().await;

        run_crash_worker(&path, "effect-resolve-authorized", point);
        let reopened = SqliteStore::open_with_clock(
            &path,
            Arc::new(TestClock::new(111)),
            LeaseDuration::from_millis(60_000).unwrap(),
        )
        .await
        .unwrap();
        let committed = point.ends_with("after_commit");
        let observed = reopened
            .read_effect(before.request_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            observed.phase,
            if committed {
                navigator_store_api::EffectJournalPhase::Completed
            } else {
                navigator_store_api::EffectJournalPhase::Uncertain
            },
            "point {point}"
        );
        assert_eq!(
            reopened.load_operation(before.operation_id).await.unwrap(),
            operation_before,
            "resolution must never mutate the terminal Operation"
        );
        let grant_before_replay = reopened.load_grant(command.grant_id).await.unwrap();
        assert_eq!(grant_before_replay.consumed_at.is_some(), committed);
        let replay = reopened
            .resolve_authorized_effect(command.clone())
            .await
            .unwrap();
        assert_eq!(matches!(replay, Mutation::Replayed(_)), committed);
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        assert_eq!(events_after, events_before + 1, "point {point}");
        assert!(
            reopened
                .load_grant(command.grant_id)
                .await
                .unwrap()
                .consumed_at
                .is_some()
        );
        let ledger_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM effect_journal_mutations WHERE request_id = ?",
        )
        .bind(command.context.request_id().to_string())
        .fetch_one(reopened.pool())
        .await
        .unwrap();
        assert_eq!(ledger_count, 1, "point {point}");
        assert_integrity(&reopened).await;
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn tool_resolution_crash_is_prior_or_full_across_every_durable_surface() {
    for point in [
        "effect.resolve_authorized.after_write",
        "effect.resolve_authorized.before_commit",
        "effect.resolve_authorized.after_commit",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        let (uncertain, command) = prepare_uncertain_tool_resolution(&store).await;
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert!(
            store
                .load_grant(command.grant_id)
                .await
                .unwrap()
                .consumed_at
                .is_none()
        );
        store.pool().close().await;

        run_crash_worker(&path, "tool-resolve-authorized", point);
        let reopened = SqliteStore::open_with_clock(
            &path,
            Arc::new(TestClock::new(111)),
            LeaseDuration::from_millis(60_000).unwrap(),
        )
        .await
        .unwrap();
        let committed = point.ends_with("after_commit");
        let tool = reopened
            .load_tool_invocation(uncertain.invocation().invocation_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tool.registration_id(),
            uncertain.registration_id(),
            "{point}"
        );
        let effect = reopened
            .read_effect(uncertain.invocation().request_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tool.phase() == ToolInvocationPhase::Completed,
            committed,
            "{point}"
        );
        assert_eq!(
            effect.phase == navigator_store_api::EffectJournalPhase::Completed,
            committed,
            "{point}"
        );
        assert_eq!(
            reopened
                .load_grant(command.grant_id)
                .await
                .unwrap()
                .consumed_at
                .is_some(),
            committed,
            "{point}"
        );
        let mutation_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM effect_journal_mutations WHERE request_id=?")
                .bind(command.context.request_id().to_string())
                .fetch_one(reopened.pool())
                .await
                .unwrap();
        assert_eq!(mutation_count, i64::from(committed), "{point}");
        let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        assert_eq!(event_count, events_before + i64::from(committed), "{point}");

        let replay = reopened
            .resolve_authorized_effect(command.clone())
            .await
            .unwrap();
        assert_eq!(
            matches!(replay, Mutation::Replayed(_)),
            committed,
            "{point}"
        );
        assert_eq!(
            reopened
                .load_tool_invocation(uncertain.invocation().invocation_id())
                .await
                .unwrap()
                .unwrap()
                .phase(),
            ToolInvocationPhase::Completed
        );
        assert_integrity(&reopened).await;
    }
}

#[tokio::test]
async fn tool_do_not_retry_crash_is_prior_or_failed_atomically() {
    for point in [
        "effect.resolve_authorized.after_write",
        "effect.resolve_authorized.before_commit",
        "effect.resolve_authorized.after_commit",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        let (uncertain, _) = prepare_uncertain_tool_resolution(&store).await;
        let command = tool_do_not_retry_command(&uncertain);
        store.pool().close().await;
        run_crash_worker(&path, "tool-resolve-do-not-retry", point);
        let reopened = SqliteStore::open_with_clock(
            &path,
            Arc::new(TestClock::new(111)),
            LeaseDuration::from_millis(60_000).unwrap(),
        )
        .await
        .unwrap();
        let committed = point.ends_with("after_commit");
        let tool = reopened
            .load_tool_invocation(uncertain.invocation().invocation_id())
            .await
            .unwrap()
            .unwrap();
        let effect = reopened
            .read_effect(uncertain.invocation().request_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            tool.phase() == ToolInvocationPhase::Failed,
            committed,
            "{point}"
        );
        assert_eq!(
            effect.phase == navigator_store_api::EffectJournalPhase::Failed,
            committed,
            "{point}"
        );
        assert_eq!(
            reopened
                .load_grant(command.grant_id)
                .await
                .unwrap()
                .consumed_at
                .is_some(),
            committed,
            "{point}"
        );
        assert_integrity(&reopened).await;
    }
}

#[tokio::test]
async fn tool_connect_crash_is_prior_or_full_with_ledger_and_event() {
    for point in [
        "tool.connect.after_write",
        "tool.connect.before_commit",
        "tool.connect.after_commit",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_tool_registration(&store).await;
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(store.pool())
            .await
            .unwrap();
        store.pool().close().await;
        run_crash_worker(&path, "tool-connect", point);
        let reopened = SqliteStore::open(&path).await.unwrap();
        let committed = point.ends_with("after_commit");
        let provider_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tool_provider_connections")
                .fetch_one(reopened.pool())
                .await
                .unwrap();
        let ledger_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger WHERE request_id=?")
                .bind(
                    RequestId::from_uuid(Uuid::from_u128(81_003))
                        .unwrap()
                        .to_string(),
                )
                .fetch_one(reopened.pool())
                .await
                .unwrap();
        let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        assert_eq!(provider_count, i64::from(committed), "{point}");
        assert_eq!(ledger_count, i64::from(committed), "{point}");
        assert_eq!(event_count, events_before + i64::from(committed), "{point}");
        assert_integrity(&reopened).await;
    }
}

#[tokio::test]
async fn tool_reconnect_crash_rebinds_pending_dispatch_prior_or_full() {
    for point in [
        "tool.connect.after_write",
        "tool.connect.before_commit",
        "tool.connect.after_commit",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_tool_store(&store).await;
        let reserved = store
            .reserve_tool_invocation(tool_reserve(81_092, 81_093, host(20), 1, 10))
            .await
            .unwrap();
        store.pool().close().await;
        run_crash_worker(&path, "tool-reconnect", point);
        let reopened = SqliteStore::open(&path).await.unwrap();
        let committed = point.ends_with("after_commit");
        let pending = reopened
            .load_tool_invocation(reserved.invocation().invocation_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            pending.dispatch().connection_generation,
            Some(if committed { 2 } else { 1 }),
            "{point}"
        );
        assert_eq!(
            pending.dispatch().connection_id,
            Some(if committed {
                ToolConnectionId::from_uuid(Uuid::from_u128(81_091)).unwrap()
            } else {
                ToolConnectionId::from_uuid(Uuid::from_u128(81_005)).unwrap()
            }),
            "{point}"
        );
        assert_integrity(&reopened).await;
    }
}

#[tokio::test]
async fn tool_register_crash_is_prior_or_full_with_ledger_and_event() {
    for point in [
        "tool.register.after_write",
        "tool.register.before_commit",
        "tool.register.after_commit",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_tool_authority(&store).await;
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(store.pool())
            .await
            .unwrap();
        store.pool().close().await;
        run_crash_worker(&path, "tool-register", point);
        let reopened = SqliteStore::open(&path).await.unwrap();
        let committed = point.ends_with("after_commit");
        let registration_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tool_registrations")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        let ledger_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger WHERE request_id=?")
                .bind(
                    RequestId::from_uuid(Uuid::from_u128(81_001))
                        .unwrap()
                        .to_string(),
                )
                .fetch_one(reopened.pool())
                .await
                .unwrap();
        let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        assert_eq!(registration_count, i64::from(committed), "{point}");
        assert_eq!(ledger_count, i64::from(committed), "{point}");
        assert_eq!(event_count, events_before + i64::from(committed), "{point}");
        assert_integrity(&reopened).await;
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn tool_reserve_start_terminal_and_cancel_crashes_are_prior_or_full() {
    for scenario in [
        "tool-reserve",
        "tool-start",
        "tool-complete",
        "tool-fail",
        "tool-uncertain",
        "tool-cancel",
    ] {
        for suffix in ["after_write", "before_commit", "after_commit"] {
            let directory = TempDir::new().unwrap();
            let (store, path, _) = new_store(&directory).await;
            prepare_tool_store(&store).await;
            if scenario != "tool-reserve" {
                let reserved = store
                    .reserve_tool_invocation(tool_reserve(81_060, 81_061, host(20), 1, 10))
                    .await
                    .unwrap();
                if matches!(scenario, "tool-complete" | "tool-fail" | "tool-uncertain") {
                    store
                        .transition_tool_invocation(TransitionToolInvocation {
                            context: context(81_063, host(20)),
                            invocation_id: reserved.invocation().invocation_id(),
                            owner_epoch: FencingEpoch::new(1).unwrap(),
                            expected_revision: reserved.revision(),
                            transition: ToolTransition::Start,
                            provider_id: reserved.dispatch().provider_id,
                            connection_id: reserved.dispatch().connection_id.unwrap(),
                            connection_generation: reserved
                                .dispatch()
                                .connection_generation
                                .unwrap(),
                            dispatch_id: reserved.dispatch().dispatch_id,
                            server_sequence: reserved.dispatch().server_sequence,
                        })
                        .await
                        .unwrap();
                }
            }
            let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
                .fetch_one(store.pool())
                .await
                .unwrap();
            store.pool().close().await;
            let point = if scenario == "tool-reserve" {
                format!("tool.reserve.{suffix}")
            } else {
                format!("tool.transition.{suffix}")
            };
            if !fault_matrix_point_selected(&point) {
                continue;
            }
            run_crash_worker(&path, scenario, &point);
            let reopened = SqliteStore::open(&path).await.unwrap();
            let committed = suffix == "after_commit";
            let invocation = reopened
                .load_tool_invocation(ToolInvocationId::from_uuid(Uuid::from_u128(81_061)).unwrap())
                .await
                .unwrap();
            if scenario == "tool-reserve" {
                assert_eq!(invocation.is_some(), committed, "{scenario}/{suffix}");
            } else {
                let value = invocation.unwrap();
                match scenario {
                    "tool-start" => {
                        assert_eq!(value.phase() == ToolInvocationPhase::Started, committed);
                    }
                    "tool-complete" => {
                        assert_eq!(value.phase() == ToolInvocationPhase::Completed, committed);
                    }
                    "tool-fail" => {
                        assert_eq!(value.phase() == ToolInvocationPhase::Failed, committed);
                    }
                    "tool-uncertain" => {
                        assert_eq!(value.phase() == ToolInvocationPhase::Uncertain, committed);
                    }
                    "tool-cancel" => {
                        assert_eq!(value.dispatch().cancellation_id.is_some(), committed);
                    }
                    _ => unreachable!(),
                }
                let effect = reopened
                    .read_effect(value.invocation().request_id())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(effect.revision, value.revision(), "{scenario}/{suffix}");
            }
            let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
                .fetch_one(reopened.pool())
                .await
                .unwrap();
            assert_eq!(
                events_after,
                events_before + i64::from(committed),
                "{scenario}/{suffix}"
            );
            assert_integrity(&reopened).await;
            write_durable_fault_result(
                &point,
                committed,
                observe_durable_fault_facts(
                    &reopened,
                    events_after - events_before == i64::from(committed),
                    events_after - events_before == i64::from(committed),
                )
                .await,
                serde_json::json!({"area":"tool","operation":scenario,"events_before":events_before,"events_after":events_after}),
            );
        }
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "table-driven subprocess crash matrix keeps setup and prior-or-full assertions together"
)]
async fn reserve_start_and_takeover_crashes_are_prior_or_full_and_replay() {
    for scenario in ["effect-reserve", "effect-start", "effect-takeover"] {
        for suffix in ["after_write", "before_commit", "after_commit"] {
            let directory = TempDir::new().unwrap();
            let (store, path, clock) = new_store(&directory).await;
            prepare_running_effect_operation(&store).await;
            let reserve = journal_reserve_command();
            let command_request = match scenario {
                "effect-reserve" => reserve.context.request_id(),
                "effect-start" => {
                    store.reserve_effect(reserve.clone()).await.unwrap();
                    RequestId::from_uuid(Uuid::from_u128(85_001)).unwrap()
                }
                "effect-takeover" => {
                    store.reserve_effect(reserve.clone()).await.unwrap();
                    clock.set(111);
                    RequestId::from_uuid(Uuid::from_u128(85_002)).unwrap()
                }
                _ => unreachable!(),
            };
            let before = store
                .read_effect(reserve.context.request_id())
                .await
                .unwrap();
            store.pool().close().await;
            let crash_prefix = if scenario == "effect-start" {
                "effect.transition".to_owned()
            } else {
                scenario.replace('-', ".")
            };
            let point = format!("{crash_prefix}.{suffix}");
            run_crash_worker(&path, scenario, &point);
            let reopened = SqliteStore::open_with_clock(
                &path,
                Arc::new(TestClock::new(if scenario == "effect-takeover" {
                    111
                } else {
                    100
                })),
                LeaseDuration::from_millis(60_000).unwrap(),
            )
            .await
            .unwrap();
            let committed = suffix == "after_commit";
            let after_crash = reopened
                .read_effect(reserve.context.request_id())
                .await
                .unwrap();
            if committed {
                assert!(after_crash.is_some(), "point {point}");
            } else {
                assert_eq!(after_crash, before, "point {point}");
            }
            match scenario {
                "effect-reserve" => {
                    reopened.reserve_effect(reserve.clone()).await.unwrap();
                }
                "effect-start" => {
                    let original = before.as_ref().unwrap();
                    reopened
                        .start_effect(EffectTransition::start(
                            context(85_001, host(20)),
                            original.request_id,
                            original.owner_epoch,
                            original.revision,
                        ))
                        .await
                        .unwrap();
                }
                "effect-takeover" => {
                    let original = before.as_ref().unwrap();
                    reopened
                        .takeover_effect(TakeoverEffect::new(
                            context(85_002, host(20)),
                            original.request_id,
                            original.owner_epoch,
                            original.revision,
                            std::time::Duration::from_secs(10),
                        ))
                        .await
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let ledger_count: i64 = if scenario == "effect-reserve" {
                sqlx::query_scalar("SELECT COUNT(*) FROM effect_journal WHERE request_id = ?")
                    .bind(command_request.to_string())
                    .fetch_one(reopened.pool())
                    .await
                    .unwrap()
            } else {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM effect_journal_mutations WHERE request_id = ?",
                )
                .bind(command_request.to_string())
                .fetch_one(reopened.pool())
                .await
                .unwrap()
            };
            assert_eq!(ledger_count, 1, "point {point}");
            let final_entry = reopened
                .read_effect(reserve.context.request_id())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                final_entry.phase,
                if scenario == "effect-start" {
                    navigator_store_api::EffectJournalPhase::Started
                } else {
                    navigator_store_api::EffectJournalPhase::Reserved
                }
            );
            assert_integrity(&reopened).await;
        }
    }
}
const MAILBOX_ENQUEUE_CRASH_POINTS: &[&str] = &[
    "mailbox.enqueue.after_message",
    "mailbox.enqueue.after_counter",
    "mailbox.enqueue.after_ledger",
    "mailbox.enqueue.before_commit",
    "mailbox.enqueue.after_commit",
];
const MAILBOX_LEASE_CRASH_POINTS: &[&str] = &[
    "mailbox.lease.after_message",
    "mailbox.lease.after_ledger",
    "mailbox.lease.before_commit",
    "mailbox.lease.after_commit",
];
const MAILBOX_TRANSITION_CRASH_POINTS: &[&str] = &[
    "mailbox.transition.after_message",
    "mailbox.transition.after_ledger",
    "mailbox.transition.before_commit",
    "mailbox.transition.after_commit",
];
const MAILBOX_FEEDBACK_CRASH_POINTS: &[&str] = &[
    "mailbox.transition.after_counter",
    "mailbox.transition.after_message_state",
    "mailbox.transition.after_message_event",
    "mailbox.transition.after_operation_state",
    "mailbox.transition.after_operation_event",
];
const FEEDBACK_ACCEPT_CRASH_POINTS: &[&str] = &[
    "mailbox.transition.after_message_state",
    "mailbox.transition.after_message_event",
    "mailbox.transition.after_operation_state",
    "mailbox.transition.after_operation_event",
    "mailbox.transition.after_ledger",
    "mailbox.transition.before_commit",
    "mailbox.transition.after_commit",
];
const CANCELLATION_CRASH_POINTS: &[&str] = &[
    "cancellation.after_subtree_tombstone",
    "cancellation.after_operation",
    "cancellation.after_operation_event",
    "cancellation.after_notification",
    "cancellation.after_effects",
    "cancellation.after_ledger",
    "cancellation.before_commit",
    "cancellation.after_commit",
];

fn template_record() -> TemplateRecord {
    Template::register(
        TemplateId::from_uuid(Uuid::from_u128(940)).unwrap(),
        BoundedText::new("root".to_owned()).unwrap(),
        DriverRequirement::new(DriverId::from_uuid(Uuid::from_u128(941)).unwrap(), vec![]).unwrap(),
        TrustedConfiguration::new(BoundedText::new("trusted-config".to_owned()).unwrap(), [])
            .unwrap(),
        ResourceBounds::new(1024, 1000, 1).unwrap(),
        InputSchema::new(vec![]).unwrap(),
    )
    .unwrap()
    .registration_snapshot()
}

fn child_template_record() -> TemplateRecord {
    Template::register(
        TemplateId::from_uuid(Uuid::from_u128(950)).unwrap(),
        BoundedText::new("child".to_owned()).unwrap(),
        DriverRequirement::new(DriverId::from_uuid(Uuid::from_u128(951)).unwrap(), vec![]).unwrap(),
        TrustedConfiguration::new(BoundedText::new("child-config".to_owned()).unwrap(), [])
            .unwrap(),
        ResourceBounds::new(2048, 1000, 1).unwrap(),
        InputSchema::new(vec![]).unwrap(),
    )
    .unwrap()
    .registration_snapshot()
}

async fn open_heterogeneous_manifest(
    store: &SqliteStore,
) -> (TemplateRecord, TemplateRecord, SessionCompatibilityManifest) {
    let root = template_record();
    let child = child_template_record();
    store.register_template(root.clone()).await.unwrap();
    store.register_template(child.clone()).await.unwrap();
    let manifest = SessionCompatibilityManifest::new(
        CompatibilityIdentity::from_bytes([42; 32]),
        vec![
            TemplateCompatibilityBinding {
                template_id: root.identity,
                compatibility: root.compatibility,
            },
            TemplateCompatibilityBinding {
                template_id: child.identity,
                compatibility: child.compatibility,
            },
        ],
    )
    .unwrap();
    let open = OpenSession::with_manifest(
        context(80_000, host(10)),
        session_id(),
        ConsumerKey::new("manifest-consumer").unwrap(),
        manifest.clone(),
    );
    store.open_session(open.clone()).await.unwrap();
    assert!(matches!(
        store.open_session(open).await.unwrap(),
        Mutation::Replayed(_)
    ));
    let reordered = SessionCompatibilityManifest::new(
        CompatibilityIdentity::from_bytes([42; 32]),
        vec![
            TemplateCompatibilityBinding {
                template_id: child.identity,
                compatibility: child.compatibility,
            },
            TemplateCompatibilityBinding {
                template_id: root.identity,
                compatibility: root.compatibility,
            },
        ],
    )
    .unwrap();
    assert!(matches!(
        store
            .open_session(OpenSession::with_manifest(
                context(80_000, host(10)),
                session_id(),
                ConsumerKey::new("manifest-consumer").unwrap(),
                reordered,
            ))
            .await
            .unwrap(),
        Mutation::Replayed(_)
    ));
    let changed_configuration = SessionCompatibilityManifest::new(
        CompatibilityIdentity::from_bytes([43; 32]),
        manifest.templates().to_vec(),
    )
    .unwrap();
    assert!(matches!(
        store
            .open_session(OpenSession::with_manifest(
                context(80_000, host(10)),
                session_id(),
                ConsumerKey::new("manifest-consumer").unwrap(),
                changed_configuration,
            ))
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
    (root, child, manifest)
}

fn atomic_manifest_open_command(request: u128) -> RegisterTemplatesAndOpenSession {
    let root = template_record();
    let child = child_template_record();
    let manifest = SessionCompatibilityManifest::new(
        CompatibilityIdentity::from_bytes([42; 32]),
        vec![
            TemplateCompatibilityBinding {
                template_id: root.identity,
                compatibility: root.compatibility,
            },
            TemplateCompatibilityBinding {
                template_id: child.identity,
                compatibility: child.compatibility,
            },
        ],
    )
    .unwrap();
    RegisterTemplatesAndOpenSession::new(
        OpenSession::with_manifest(
            context(request, host(10)),
            session_id(),
            ConsumerKey::new("manifest-consumer").unwrap(),
            manifest,
        ),
        vec![root, child],
    )
    .unwrap()
}

fn mode_open_command(
    request: u128,
    candidate: u128,
    mode: SessionOpenMode,
) -> RegisterTemplatesAndOpenSession {
    mode_open_command_with_template(request, candidate, mode, template_record())
}

fn mode_open_command_with_template(
    request: u128,
    candidate: u128,
    mode: SessionOpenMode,
    root: TemplateRecord,
) -> RegisterTemplatesAndOpenSession {
    RegisterTemplatesAndOpenSession::new(
        OpenSession::new(
            context(request, host(10)),
            SessionId::from_uuid(Uuid::from_u128(candidate)).unwrap(),
            ConsumerKey::new("mode-consumer").unwrap(),
            root.compatibility,
        )
        .with_mode(mode),
        vec![root],
    )
    .unwrap()
}

#[tokio::test]
async fn open_modes_resolve_consumer_key_and_reset_preserves_audit() {
    let directory = TempDir::new().unwrap();
    let (store, _path, _clock) = new_store(&directory).await;
    let first = store
        .register_templates_and_open_session(mode_open_command(
            91_001,
            92_001,
            SessionOpenMode::Open,
        ))
        .await
        .unwrap()
        .value()
        .clone();
    let reopened = store
        .register_templates_and_open_session(mode_open_command(
            91_002,
            92_002,
            SessionOpenMode::Open,
        ))
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(reopened.id(), first.id());

    let lease = store
        .acquire_ownership(AcquireOwnership::new(
            context(91_010, host(10)),
            first.id(),
            LeaseDuration::from_millis(60_000).unwrap(),
        ))
        .await
        .unwrap();
    store
        .close_session(CloseSession::new(
            context(91_011, host(10)),
            first.id(),
            lease.value().epoch(),
        ))
        .await
        .unwrap();

    let replacement = store
        .register_templates_and_open_session(mode_open_command(
            91_003,
            92_003,
            SessionOpenMode::Reset,
        ))
        .await
        .unwrap()
        .value()
        .clone();
    assert_ne!(replacement.id(), first.id());
    assert_eq!(
        store.load_session(first.id()).await.unwrap().status(),
        SessionStatus::Closed
    );
    assert_eq!(
        store
            .load_session(first.id())
            .await
            .unwrap()
            .consumer_key()
            .as_str(),
        "mode-consumer"
    );
    let events = store
        .read_events(ReadEvents {
            session_id: first.id(),
            consumer: store
                .load_session(first.id())
                .await
                .unwrap()
                .consumer_key()
                .clone(),
            after: None,
            limit: EventReadLimit::new(100).unwrap(),
        })
        .await
        .unwrap();
    assert!(
        events
            .events
            .iter()
            .any(|event| event.event_type().as_str() == "session.closed")
    );
}

#[tokio::test]
async fn open_refuses_interrupted_work_and_requires_an_explicit_mode() {
    let directory = TempDir::new().unwrap();
    let (store, _path, _clock) = new_store(&directory).await;
    store
        .register_templates_and_open_session(mode_open_command(97_001, 1, SessionOpenMode::Open))
        .await
        .unwrap();
    store
        .acquire_ownership(acquire_command(97_002, host(20), 100, 120))
        .await
        .unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    store
        .start_operation(start_operation_command())
        .await
        .unwrap();
    assert!(matches!(
        store.register_templates_and_open_session(mode_open_command(97_003, 97_004, SessionOpenMode::Open)).await,
        Err(StoreError::InterruptedSession { session_id: found }) if found == session_id()
    ));
}

#[tokio::test]
async fn reset_accepts_a_new_incompatible_specification() {
    let directory = TempDir::new().unwrap();
    let (store, _path, _clock) = new_store(&directory).await;
    let old = store
        .register_templates_and_open_session(mode_open_command(
            98_001,
            98_002,
            SessionOpenMode::Open,
        ))
        .await
        .unwrap()
        .value()
        .id();
    let lease = store
        .acquire_ownership(AcquireOwnership::new(
            context(98_010, host(10)),
            old,
            LeaseDuration::from_millis(60_000).unwrap(),
        ))
        .await
        .unwrap();
    store
        .close_session(CloseSession::new(
            context(98_011, host(10)),
            old,
            lease.value().epoch(),
        ))
        .await
        .unwrap();
    let replacement = store
        .register_templates_and_open_session(mode_open_command_with_template(
            98_003,
            98_004,
            SessionOpenMode::Reset,
            child_template_record(),
        ))
        .await
        .unwrap()
        .value()
        .clone();
    assert_ne!(replacement.id(), old);
    assert_eq!(
        replacement.compatibility(),
        child_template_record().compatibility
    );
    assert_eq!(
        store
            .load_session(old)
            .await
            .unwrap()
            .consumer_key()
            .as_str(),
        "mode-consumer"
    );
}

#[test]
fn open_mode_digest_ignores_candidate_but_binds_mode() {
    let left = mode_open_command(99_001, 99_002, SessionOpenMode::Open);
    let right = mode_open_command(99_001, 99_003, SessionOpenMode::Open);
    assert_eq!(left.digest(), right.digest());
    assert_ne!(
        left.digest(),
        mode_open_command(99_001, 99_003, SessionOpenMode::Reset).digest()
    );
}

#[tokio::test]
async fn reset_never_publishes_while_a_closed_predecessor_has_unresolved_launches() {
    let directory = TempDir::new().unwrap();
    let (store, _path, _clock) = new_store(&directory).await;
    store
        .register_templates_and_open_session(mode_open_command(99_101, 1, SessionOpenMode::Open))
        .await
        .unwrap();
    let lease = store
        .acquire_ownership(acquire_command(99_102, host(20), 100, 120))
        .await
        .unwrap();
    store
        .prepare_launch(prepare_launch_command())
        .await
        .unwrap();
    store
        .close_session(CloseSession::new(
            context(99_103, host(20)),
            session_id(),
            lease.value().epoch(),
        ))
        .await
        .unwrap();
    assert!(matches!(
        store
            .register_templates_and_open_session(mode_open_command(
                99_104,
                99_105,
                SessionOpenMode::Reset,
            ))
            .await,
        Err(StoreError::Invalid)
    ));
    assert!(matches!(
        store
            .load_session(SessionId::from_uuid(Uuid::from_u128(99_105)).unwrap())
            .await,
        Err(StoreError::SessionNotFound { .. })
    ));
}

#[tokio::test]
async fn open_mode_is_stable_across_restart_and_serializes_concurrent_candidates() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    let first = store
        .register_templates_and_open_session(mode_open_command(
            93_001,
            94_001,
            SessionOpenMode::Open,
        ))
        .await
        .unwrap()
        .value()
        .id();
    drop(store);
    let reopened =
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    let after_restart = reopened
        .register_templates_and_open_session(mode_open_command(
            93_002,
            94_002,
            SessionOpenMode::Open,
        ))
        .await
        .unwrap()
        .value()
        .id();
    assert_eq!(after_restart, first);

    let reopened = Arc::new(reopened);
    let left_store = Arc::clone(&reopened);
    let right_store = Arc::clone(&reopened);
    let (left, right) = tokio::join!(
        async move {
            left_store
                .register_templates_and_open_session(mode_open_command(
                    93_003,
                    94_003,
                    SessionOpenMode::Open,
                ))
                .await
                .unwrap()
                .value()
                .id()
        },
        async move {
            right_store
                .register_templates_and_open_session(mode_open_command(
                    93_004,
                    94_004,
                    SessionOpenMode::Open,
                ))
                .await
                .unwrap()
                .value()
                .id()
        }
    );
    assert_eq!(left, first);
    assert_eq!(right, first);
}

#[tokio::test]
async fn open_mode_rejects_an_incompatible_consumer_key_rebind() {
    let directory = TempDir::new().unwrap();
    let (store, _path, _clock) = new_store(&directory).await;
    let first = store
        .register_templates_and_open_session(mode_open_command(
            95_001,
            96_001,
            SessionOpenMode::Open,
        ))
        .await
        .unwrap()
        .value()
        .id();
    let error = store
        .register_templates_and_open_session(mode_open_command_with_template(
            95_002,
            96_002,
            SessionOpenMode::Open,
            child_template_record(),
        ))
        .await
        .unwrap_err();
    assert!(
        matches!(error, StoreError::CompatibilityConflict { session_id, .. } if session_id == first)
    );
    assert_eq!(
        store.load_session(first).await.unwrap().status(),
        SessionStatus::Open
    );
}

#[tokio::test]
async fn atomic_manifest_open_rolls_back_all_templates_on_late_conflict() {
    let directory = TempDir::new().unwrap();
    let (store, _path, _clock) = new_store(&directory).await;
    let root = template_record();
    let child = child_template_record();
    let conflicting_child = Template::register(
        child.identity,
        BoundedText::new("different child".to_owned()).unwrap(),
        child.driver.clone(),
        child.trusted_configuration.clone(),
        child.resources,
        child.input_schema.clone(),
    )
    .unwrap()
    .registration_snapshot();
    store.register_template(conflicting_child).await.unwrap();
    let manifest = SessionCompatibilityManifest::new(
        CompatibilityIdentity::from_bytes([42; 32]),
        vec![
            TemplateCompatibilityBinding {
                template_id: root.identity,
                compatibility: root.compatibility,
            },
            TemplateCompatibilityBinding {
                template_id: child.identity,
                compatibility: child.compatibility,
            },
        ],
    )
    .unwrap();
    let open = OpenSession::with_manifest(
        context(80_050, host(10)),
        session_id(),
        ConsumerKey::new("manifest-consumer").unwrap(),
        manifest,
    );
    let command = RegisterTemplatesAndOpenSession::new(open, vec![root.clone(), child]).unwrap();

    assert_eq!(
        store.register_templates_and_open_session(command).await,
        Err(StoreError::Invalid)
    );
    assert!(matches!(
        store.load_template(root.identity).await,
        Err(StoreError::TemplateNotFound { .. })
    ));
    assert!(matches!(
        store.load_session(session_id()).await,
        Err(StoreError::SessionNotFound { .. })
    ));
    let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let request_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger WHERE request_id = ?")
            .bind(
                RequestId::from_uuid(Uuid::from_u128(80_050))
                    .unwrap()
                    .to_string(),
            )
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!((event_count, request_count), (0, 0));
}

#[tokio::test]
async fn closed_manifest_allows_heterogeneous_child_and_rejects_outside_template() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    let (_root, child, _manifest) = open_heterogeneous_manifest(&store).await;
    store
        .acquire_ownership(acquire_command(80_001, host(20), 100, 120))
        .await
        .unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    let child_command = CreateChildParticipant {
        context: context(80_002, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(80_003)).unwrap(),
        parent_participant_id: participant_command().participant_id,
        template_id: child.identity,
        expected_compatibility: child.compatibility,
    };
    store.create_child_participant(child_command).await.unwrap();

    let outside = Template::register(
        TemplateId::from_uuid(Uuid::from_u128(80_004)).unwrap(),
        BoundedText::new("outside".to_owned()).unwrap(),
        DriverRequirement::new(
            DriverId::from_uuid(Uuid::from_u128(80_005)).unwrap(),
            vec![],
        )
        .unwrap(),
        TrustedConfiguration::new(BoundedText::new("outside".to_owned()).unwrap(), []).unwrap(),
        ResourceBounds::new(1024, 1000, 1).unwrap(),
        InputSchema::new(vec![]).unwrap(),
    )
    .unwrap()
    .registration_snapshot();
    store.register_template(outside.clone()).await.unwrap();
    let rejected = CreateChildParticipant {
        context: context(80_006, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(80_007)).unwrap(),
        parent_participant_id: participant_command().participant_id,
        template_id: outside.identity,
        expected_compatibility: outside.compatibility,
    };
    assert_eq!(
        store.create_child_participant(rejected).await,
        Err(StoreError::Invalid)
    );
    store.pool().close().await;
    let reopened =
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    assert_eq!(
        reopened
            .load_participant(ParticipantId::from_uuid(Uuid::from_u128(80_003)).unwrap())
            .await
            .unwrap()
            .template_id,
        child.identity
    );
}

#[tokio::test]
async fn corrupted_complete_manifest_fails_closed_on_reopen() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    let (_, child, _) = open_heterogeneous_manifest(&store).await;
    sqlx::query(
        "UPDATE session_template_manifest SET template_compatibility = ?
         WHERE session_id = ? AND template_id = ?",
    )
    .bind(vec![99_u8; 32])
    .bind(session_id().to_string())
    .bind(child.identity.to_string())
    .execute(store.pool())
    .await
    .unwrap();
    store.pool().close().await;
    assert_eq!(
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap(),)
            .await
            .unwrap_err(),
        StoreError::Corrupt
    );
}

#[tokio::test]
async fn legacy_session_remains_singleton_and_cannot_gain_a_new_template() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(80_100)).await.unwrap();
    store
        .acquire_ownership(acquire_command(80_101, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .register_template(child_template_record())
        .await
        .unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    let child = child_template_record();
    assert_eq!(
        store
            .create_child_participant(CreateChildParticipant {
                context: context(80_102, host(20)),
                session_id: session_id(),
                epoch: FencingEpoch::new(1).unwrap(),
                participant_id: ParticipantId::from_uuid(Uuid::from_u128(80_103)).unwrap(),
                parent_participant_id: participant_command().participant_id,
                template_id: child.identity,
                expected_compatibility: child.compatibility,
            })
            .await,
        Err(StoreError::Invalid)
    );
}

fn participant_command() -> CreateRootParticipant {
    CreateRootParticipant {
        context: context(942, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(943)).unwrap(),
        template_id: template_record().identity,
        expected_compatibility: template_record().compatibility,
    }
}

fn child_command() -> CreateChildParticipant {
    CreateChildParticipant {
        context: context(948, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(949)).unwrap(),
        parent_participant_id: participant_command().participant_id,
        template_id: template_record().identity,
        expected_compatibility: template_record().compatibility,
    }
}

fn start_operation_command() -> StartOperation {
    StartOperation {
        context: context(944, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        operation_id: OperationId::from_uuid(Uuid::from_u128(945)).unwrap(),
        participant_id: participant_command().participant_id,
        input_message_id: MessageId::from_uuid(Uuid::from_u128(946)).unwrap(),
        input: InputSchema::new(vec![]).unwrap().validate(b"{}").unwrap(),
    }
}

fn transition_operation_command() -> TransitionOperation {
    TransitionOperation {
        context: context(947, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        operation_id: start_operation_command().operation_id,
        expected_revision: Revision::initial(),
        action: OperationAction::BeginStart,
        report_message_id: None,
        terminal_outcome: None,
    }
}

fn mailbox_enqueue_command() -> EnqueueMessage {
    EnqueueMessage {
        context: context(960, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        message_id: MessageId::from_uuid(Uuid::from_u128(961)).unwrap(),
        source: participant_command().participant_id,
        destination: participant_command().participant_id,
        correlation: MessageCorrelation {
            operation_id: Some(start_operation_command().operation_id),
            in_reply_to: None,
        },
        envelope: navigator_domain::ValidatedMessageEnvelope::control(
            start_operation_command().operation_id,
            navigator_domain::ControlMessageKind::Reminder,
        ),
    }
}

fn mailbox_lease_command() -> LeaseNextMessage {
    LeaseNextMessage {
        context: context(962, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        destination: participant_command().participant_id,
        instance_id: InstanceId::from_uuid(Uuid::from_u128(964)).unwrap(),
        driver_launch_attempt_id: LaunchAttemptId::from_uuid(Uuid::from_u128(963)).unwrap(),
        proposed_attempt_id: DeliveryAttemptId::from_uuid(Uuid::from_u128(965)).unwrap(),
        lease_duration: std::time::Duration::from_secs(10),
    }
}

fn mailbox_transition_command() -> TransitionMessageDelivery {
    TransitionMessageDelivery {
        context: context(966, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        message_id: mailbox_enqueue_command().message_id,
        attempt_id: mailbox_lease_command().proposed_attempt_id,
        expected_revision: Revision::new(2).unwrap(),
        transition: DeliveryTransition::AcceptancePending,
    }
}

fn feedback_message_id() -> MessageId {
    MessageId::from_uuid(Uuid::from_u128(9_680)).unwrap()
}

fn feedback_question_id() -> MessageId {
    MessageId::from_uuid(Uuid::from_u128(9_681)).unwrap()
}

fn feedback_accept_command() -> TransitionMessageDelivery {
    TransitionMessageDelivery {
        context: context(9_686, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        message_id: feedback_message_id(),
        attempt_id: DeliveryAttemptId::from_uuid(Uuid::from_u128(9_685)).unwrap(),
        expected_revision: Revision::new(3).unwrap(),
        transition: DeliveryTransition::Accepted {
            proof_digest: [9; 32],
        },
    }
}

fn prepare_launch_command() -> PrepareLaunch {
    PrepareLaunch {
        context: context(930, host(20)),
        epoch: FencingEpoch::new(1).unwrap(),
        session_id: session_id(),
        participant_id: ParticipantId::from_uuid(Uuid::from_u128(931)).unwrap(),
        driver_id: DriverId::from_uuid(Uuid::from_u128(932)).unwrap(),
        attempt_id: LaunchAttemptId::from_uuid(Uuid::from_u128(933)).unwrap(),
        credential_digest: [3; 32],
        driver_configuration_digest: [13; 32],
    }
}

fn attach_launch_command() -> AttachLaunch {
    AttachLaunch {
        context: context(934, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        attempt_id: LaunchAttemptId::from_uuid(Uuid::from_u128(933)).unwrap(),
        expected_revision: Revision::initial(),
        instance_id: InstanceId::from_uuid(Uuid::from_u128(935)).unwrap(),
        evidence: ProcessEvidence {
            process_id: 11,
            process_group_id: 11,
            parent_process_id: 10,
            creation_marker: 1,
            executable_identity: [5; 32],
        },
    }
}

fn transition_launch_command() -> TransitionLaunch {
    TransitionLaunch {
        context: context(936, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        attempt_id: LaunchAttemptId::from_uuid(Uuid::from_u128(933)).unwrap(),
        expected_revision: Revision::new(2).unwrap(),
        target: LaunchState::Ready,
        cleanup_reason: None,
    }
}

async fn prepare_real_mailbox_launch(store: &SqliteStore) {
    let lease = mailbox_lease_command();
    let mut prepare = prepare_launch_command();
    prepare.context = context(970, host(20));
    prepare.participant_id = participant_command().participant_id;
    prepare.driver_id = template_record().driver.driver_id();
    prepare.attempt_id = lease.driver_launch_attempt_id;
    store.prepare_launch(prepare).await.unwrap();

    let mut attach = attach_launch_command();
    attach.context = context(971, host(20));
    attach.attempt_id = lease.driver_launch_attempt_id;
    attach.instance_id = lease.instance_id;
    store.attach_launch(attach).await.unwrap();

    let mut ready = transition_launch_command();
    ready.context = context(972, host(20));
    ready.attempt_id = lease.driver_launch_attempt_id;
    store.transition_launch(ready).await.unwrap();
}

async fn accept_input_message(store: &SqliteStore, request: u128) {
    let mut lease = mailbox_lease_command();
    lease.context = context(request, host(20));
    let leased = store
        .lease_next_message(lease)
        .await
        .unwrap()
        .value()
        .clone()
        .unwrap();
    let pending = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(request + 1, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: leased.message_id,
            attempt_id: mailbox_lease_command().proposed_attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .unwrap()
        .value()
        .clone();
    store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(request + 2, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: pending.message_id,
            attempt_id: mailbox_lease_command().proposed_attempt_id,
            expected_revision: pending.revision,
            transition: DeliveryTransition::Accepted {
                proof_digest: [8; 32],
            },
        })
        .await
        .unwrap();
}

async fn prepare_real_recovery_message(
    store: &SqliteStore,
) -> navigator_store_api::MessageSnapshot {
    store.open_session(open_command(969)).await.unwrap();
    store
        .acquire_ownership(acquire_command(968, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    store
        .start_operation(start_operation_command())
        .await
        .unwrap();
    prepare_real_mailbox_launch(store).await;
    store
        .lease_next_message(mailbox_lease_command())
        .await
        .unwrap()
        .value()
        .clone()
        .unwrap()
}

#[tokio::test]
async fn recovery_inventory_preserves_real_mailbox_lease_and_retry_boundaries() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    let leased = prepare_real_recovery_message(&store).await;
    let mut missing_correlation = mailbox_enqueue_command();
    missing_correlation.context = context(976, host(20));
    missing_correlation.correlation.operation_id = None;
    assert_eq!(
        store.enqueue_message(missing_correlation).await,
        Err(StoreError::Invalid)
    );
    let inventory = store
        .load_recovery_inventory(session_id(), host(20), FencingEpoch::new(1).unwrap())
        .await
        .unwrap();
    assert!(
        matches!(inventory.messages[0].state, MessageDeliveryState::Leased { ref lease } if lease.expires_at > inventory.snapshot_at)
    );

    let pending = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(973, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: leased.message_id,
            attempt_id: mailbox_lease_command().proposed_attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .unwrap()
        .value()
        .clone();
    assert!(matches!(
        store
            .load_recovery_inventory(session_id(), host(20), FencingEpoch::new(1).unwrap())
            .await
            .unwrap()
            .messages[0]
            .state,
        MessageDeliveryState::AcceptancePending { .. }
    ));
    let unknown = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(974, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: pending.message_id,
            attempt_id: mailbox_lease_command().proposed_attempt_id,
            expected_revision: pending.revision,
            transition: DeliveryTransition::AcceptanceUnknown,
        })
        .await
        .unwrap()
        .value()
        .clone();
    assert!(matches!(
        store
            .load_recovery_inventory(session_id(), host(20), FencingEpoch::new(1).unwrap())
            .await
            .unwrap()
            .messages[0]
            .state,
        MessageDeliveryState::AcceptanceUnknown { .. }
    ));
    store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(975, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: unknown.message_id,
            attempt_id: mailbox_lease_command().proposed_attempt_id,
            expected_revision: unknown.revision,
            transition: DeliveryTransition::RetryAfter {
                delay: std::time::Duration::from_secs(10),
            },
        })
        .await
        .unwrap();
    let future = store
        .load_recovery_inventory(session_id(), host(20), FencingEpoch::new(1).unwrap())
        .await
        .unwrap();
    assert!(
        matches!(future.messages[0].state, MessageDeliveryState::RetryScheduled { not_before } if not_before > future.snapshot_at)
    );
    clock.set(110);
    let due = store
        .load_recovery_inventory(session_id(), host(20), FencingEpoch::new(1).unwrap())
        .await
        .unwrap();
    assert!(
        matches!(due.messages[0].state, MessageDeliveryState::RetryScheduled { not_before } if not_before <= due.snapshot_at)
    );
}

#[tokio::test]
async fn recovery_inventory_exposes_expired_real_lease_at_fenced_store_time() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    prepare_real_recovery_message(&store).await;
    clock.set(110);
    let inventory = store
        .load_recovery_inventory(session_id(), host(20), FencingEpoch::new(1).unwrap())
        .await
        .unwrap();
    assert!(
        matches!(inventory.messages[0].state, MessageDeliveryState::Leased { ref lease } if lease.expires_at <= inventory.snapshot_at)
    );
}

#[tokio::test]
async fn due_session_work_preserves_real_mailbox_lease_retry_and_acceptance_boundaries() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    let leased = prepare_real_recovery_message(&store).await;
    assert!(
        store
            .load_due_session_delivery_work(session_id(), 1)
            .await
            .unwrap()
            .is_empty()
    );

    let pending = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(9_790, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: leased.message_id,
            attempt_id: mailbox_lease_command().proposed_attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .unwrap()
        .value()
        .clone();
    assert!(
        store
            .load_due_session_delivery_work(session_id(), 1)
            .await
            .unwrap()
            .is_empty()
    );
    clock.set(110);
    let due = store
        .load_due_session_delivery_work(session_id(), 1)
        .await
        .unwrap();
    assert_eq!(due[0].message.message_id, leased.message_id);
    assert_eq!(
        due[0].operation.operation_id,
        start_operation_command().operation_id
    );
    assert_eq!(
        store
            .load_due_session_delivery_work(session_id(), 1)
            .await
            .unwrap()[0]
            .message
            .message_id,
        pending.message_id
    );
    let mut recover = mailbox_lease_command();
    recover.context = context(9_792, host(20));
    let recovered = store
        .lease_next_message(recover)
        .await
        .unwrap()
        .value()
        .clone()
        .unwrap();
    let retry = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(9_791, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: pending.message_id,
            attempt_id: mailbox_lease_command().proposed_attempt_id,
            expected_revision: recovered.revision,
            transition: DeliveryTransition::RetryAfter {
                delay: std::time::Duration::from_secs(10),
            },
        })
        .await
        .unwrap()
        .value()
        .clone();
    assert!(matches!(
        retry.state,
        MessageDeliveryState::RetryScheduled { .. }
    ));
    assert!(
        store
            .load_due_session_delivery_work(session_id(), 1)
            .await
            .unwrap()
            .is_empty()
    );
    clock.set(120);
    assert_eq!(
        store
            .load_due_session_delivery_work(session_id(), 1)
            .await
            .unwrap()[0]
            .message
            .message_id,
        retry.message_id
    );
    assert_delivery_work_limits(&store).await;
}

async fn assert_delivery_work_limits(store: &SqliteStore) {
    for limit in [0, navigator_store_api::MAX_SESSION_DELIVERY_WORK + 1] {
        assert_eq!(
            store
                .load_due_session_delivery_work(session_id(), limit)
                .await,
            Err(StoreError::Invalid)
        );
    }
    let explain = format!(
        "EXPLAIN QUERY PLAN {}",
        crate::store::DUE_SESSION_DELIVERY_WORK_SQL
    );
    let plan = sqlx::query(AssertSqlSafe(explain.as_str()))
        .bind(100_i64)
        .bind(100_i64)
        .bind(0_i64)
        .bind(100_i64)
        .bind(100_i64)
        .bind(0_i64)
        .bind(session_id().to_string())
        .bind(100_i64)
        .bind(100_i64)
        .bind(0_i64)
        .bind(1_i64)
        .fetch_all(store.pool())
        .await
        .unwrap();
    assert!(plan.iter().any(|row| {
        row.get::<String, _>("detail")
            .contains("mailbox_session_delivery_state")
    }));
}

async fn enqueue_control(store: &SqliteStore, ordinal: u128) -> MessageId {
    let message_id = MessageId::from_uuid(Uuid::from_u128(20_000 + ordinal)).unwrap();
    store
        .enqueue_message(EnqueueMessage {
            context: context(30_000 + ordinal, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id,
            source: participant_command().participant_id,
            destination: participant_command().participant_id,
            correlation: MessageCorrelation {
                operation_id: Some(start_operation_command().operation_id),
                in_reply_to: None,
            },
            envelope: ValidatedMessageEnvelope::control(
                start_operation_command().operation_id,
                navigator_domain::ControlMessageKind::Reminder,
            ),
        })
        .await
        .unwrap();
    message_id
}

async fn accept_next_control(store: &SqliteStore, ordinal: u128) {
    let attempt_id = DeliveryAttemptId::from_uuid(Uuid::from_u128(40_000 + ordinal)).unwrap();
    let mut lease = mailbox_lease_command();
    lease.context = context(50_000 + ordinal * 3, host(20));
    lease.proposed_attempt_id = attempt_id;
    let leased = store
        .lease_next_message(lease)
        .await
        .unwrap()
        .value()
        .clone()
        .unwrap();
    let pending = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(50_001 + ordinal * 3, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: leased.message_id,
            attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .unwrap()
        .value()
        .clone();
    store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(50_002 + ordinal * 3, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: pending.message_id,
            attempt_id,
            expected_revision: pending.revision,
            transition: DeliveryTransition::Accepted {
                proof_digest: [17; 32],
            },
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn terminal_mailbox_history_does_not_hide_the_current_due_head() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_due_work_fixture(&store, 59_000).await;
    accept_input_message(&store, 60_000).await;

    for ordinal in 1..=navigator_store_api::MAX_SESSION_DELIVERY_WORK as u128 + 1 {
        enqueue_control(&store, ordinal).await;
        accept_next_control(&store, ordinal).await;
    }
    let due = enqueue_control(
        &store,
        navigator_store_api::MAX_SESSION_DELIVERY_WORK as u128 + 2,
    )
    .await;
    let work = store
        .load_due_session_delivery_work(session_id(), 1)
        .await
        .unwrap();
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].message.message_id, due);
}

#[tokio::test]
// Guarantees: NAV-ACCEPT-001, NAV-MAILBOX-001
async fn queued_report_correlation_is_rejected_and_accepted_causal_message_is_allowed() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_due_work_fixture(&store, 69_000).await;
    let started = store
        .load_operation(start_operation_command().operation_id)
        .await
        .unwrap();
    accept_input_message(&store, 70_000).await;
    let starting = store
        .transition_operation(transition_operation_command())
        .await
        .unwrap()
        .value()
        .clone();
    let causal = enqueue_control(&store, 70).await;
    let mut queued_report = transition_operation_command();
    queued_report.context = context(70_100, host(20));
    queued_report.expected_revision = starting.revision;
    queued_report.action = OperationAction::ReportRunning;
    queued_report.report_message_id = Some(causal);
    assert_eq!(
        store.transition_operation(queued_report).await.unwrap_err(),
        StoreError::Invalid
    );

    accept_next_control(&store, 70).await;
    store
        .create_child_participant(child_command())
        .await
        .unwrap();
    let mut child_start = start_operation_command();
    child_start.context = context(70_102, host(20));
    child_start.operation_id = OperationId::from_uuid(Uuid::from_u128(70_103)).unwrap();
    child_start.participant_id = child_command().participant_id;
    child_start.input_message_id = MessageId::from_uuid(Uuid::from_u128(70_104)).unwrap();
    let child = store
        .start_operation(child_start)
        .await
        .unwrap()
        .value()
        .clone();
    let mut child_begin = transition_operation_command();
    child_begin.context = context(70_105, host(20));
    child_begin.operation_id = child.operation_id;
    child_begin.expected_revision = child.revision;
    let child_starting = store
        .transition_operation(child_begin)
        .await
        .unwrap()
        .value()
        .clone();
    let mut wrong_destination_and_operation = transition_operation_command();
    wrong_destination_and_operation.context = context(70_106, host(20));
    wrong_destination_and_operation.operation_id = child.operation_id;
    wrong_destination_and_operation.expected_revision = child_starting.revision;
    wrong_destination_and_operation.action = OperationAction::ReportRunning;
    wrong_destination_and_operation.report_message_id = Some(causal);
    assert_eq!(
        store
            .transition_operation(wrong_destination_and_operation)
            .await
            .unwrap_err(),
        StoreError::Invalid
    );
    let mut accepted_report = transition_operation_command();
    accepted_report.context = context(70_101, host(20));
    accepted_report.expected_revision = starting.revision;
    accepted_report.action = OperationAction::ReportRunning;
    accepted_report.report_message_id = Some(causal);
    let running = store
        .transition_operation(accepted_report)
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(running.state, OperationState::Running);
    assert_ne!(causal, started.input_message_id);
}

async fn prepare_due_work_fixture(store: &SqliteStore, request: u128) {
    store.open_session(open_command(request)).await.unwrap();
    store
        .acquire_ownership(acquire_command(request + 1, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    store
        .start_operation(start_operation_command())
        .await
        .unwrap();
    prepare_real_mailbox_launch(store).await;
}

#[tokio::test]
async fn future_control_head_blocks_the_ordinary_message_behind_it() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_due_work_fixture(&store, 80_000).await;
    let control = enqueue_control(&store, 80).await;
    let attempt_id = DeliveryAttemptId::from_uuid(Uuid::from_u128(80_090)).unwrap();
    let mut lease = mailbox_lease_command();
    lease.context = context(80_091, host(20));
    lease.proposed_attempt_id = attempt_id;
    let leased = store
        .lease_next_message(lease)
        .await
        .unwrap()
        .value()
        .clone()
        .unwrap();
    assert_eq!(leased.message_id, control);
    let pending = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(80_092, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: control,
            attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .unwrap()
        .value()
        .clone();
    let unknown = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(80_093, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: control,
            attempt_id,
            expected_revision: pending.revision,
            transition: DeliveryTransition::AcceptanceUnknown,
        })
        .await
        .unwrap()
        .value()
        .clone();
    store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(80_094, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: control,
            attempt_id,
            expected_revision: unknown.revision,
            transition: DeliveryTransition::RetryAfter {
                delay: std::time::Duration::from_secs(30),
            },
        })
        .await
        .unwrap();
    assert!(
        store
            .load_due_session_delivery_work(session_id(), 2)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "single semantic matrix keeps terminal retirement, in-flight uncertainty, stale response fencing, counters, and sibling progress causally adjacent"
)]
async fn terminal_operation_retires_stale_head_and_does_not_block_sibling() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_due_work_fixture(&store, 81_000).await;
    accept_input_message(&store, 81_100).await;
    let starting = store
        .transition_operation(transition_operation_command())
        .await
        .unwrap()
        .value()
        .clone();
    let mut running_command = transition_operation_command();
    running_command.context = context(81_200, host(20));
    running_command.expected_revision = starting.revision;
    running_command.action = OperationAction::ReportRunning;
    running_command.report_message_id = Some(starting.input_message_id);
    let running = store
        .transition_operation(running_command)
        .await
        .unwrap()
        .value()
        .clone();
    let in_flight = enqueue_control(&store, 81).await;
    let attempt_id = DeliveryAttemptId::from_uuid(Uuid::from_u128(81_250)).unwrap();
    let mut lease = mailbox_lease_command();
    lease.context = context(81_251, host(20));
    lease.proposed_attempt_id = attempt_id;
    let leased = store
        .lease_next_message(lease)
        .await
        .unwrap()
        .value()
        .clone()
        .unwrap();
    let pending = store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(81_252, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: in_flight,
            attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .unwrap()
        .value()
        .clone();
    let stale = enqueue_control(&store, 82).await;
    store
        .create_child_participant(child_command())
        .await
        .unwrap();
    let sibling_operation = OperationId::from_uuid(Uuid::from_u128(81_300)).unwrap();
    let sibling_message = MessageId::from_uuid(Uuid::from_u128(81_301)).unwrap();
    let mut sibling_start = start_operation_command();
    sibling_start.context = context(81_302, host(20));
    sibling_start.operation_id = sibling_operation;
    sibling_start.participant_id = child_command().participant_id;
    sibling_start.input_message_id = sibling_message;
    store.start_operation(sibling_start).await.unwrap();
    let mut terminal = transition_operation_command();
    terminal.context = context(81_201, host(20));
    terminal.expected_revision = running.revision;
    terminal.action = OperationAction::ReportSuccess;
    terminal.report_message_id = Some(running.input_message_id);
    terminal.terminal_outcome = Some(navigator_store_api::OperationTerminalOutcome::Succeeded {
        result: BoundedBytes::new(Vec::new()).unwrap(),
    });
    store.transition_operation(terminal).await.unwrap();
    assert!(matches!(
        store.load_message(stale).await.unwrap().state,
        MessageDeliveryState::DeadLetter { .. }
    ));
    let uncertain = store.load_message(in_flight).await.unwrap();
    assert!(matches!(
        uncertain.state,
        MessageDeliveryState::Uncertain { attempt_id: value, .. } if value == attempt_id
    ));
    assert_eq!(
        store
            .transition_message_delivery(TransitionMessageDelivery {
                context: context(81_253, host(20)),
                session_id: session_id(),
                epoch: FencingEpoch::new(1).unwrap(),
                message_id: in_flight,
                attempt_id,
                expected_revision: pending.revision,
                transition: DeliveryTransition::Accepted {
                    proof_digest: [20; 32],
                },
            })
            .await
            .unwrap_err(),
        StoreError::Invalid
    );
    let queued: i64 = sqlx::query_scalar(
        "SELECT queued_messages FROM mailbox_counters WHERE destination_participant_id = ?",
    )
    .bind(participant_command().participant_id.to_string())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(queued, 0);
    let work = store
        .load_due_session_delivery_work(session_id(), 2)
        .await
        .unwrap();
    assert_eq!(work.len(), 1);
    assert_eq!(work[0].message.message_id, sibling_message);
    assert_eq!(work[0].operation.operation_id, sibling_operation);
}

const MUTATE_LAUNCH_CRASH_POINTS: &[&str] = &[
    "launch.mutate.after_update",
    "launch.mutate.after_ledger",
    "launch.mutate.before_commit",
    "launch.mutate.after_commit",
];

#[tokio::test]
#[ignore = "subprocess entry point for crash tests"]
#[expect(
    clippy::too_many_lines,
    reason = "single subprocess crash dispatch table"
)]
async fn crash_worker() {
    let path = std::env::var_os("NAVIGATOR_SQLITE_CRASH_DB").unwrap();
    let operation = std::env::var("NAVIGATOR_SQLITE_CRASH_OPERATION").unwrap();
    let worker_now = if matches!(
        operation.as_str(),
        "effect-takeover"
            | "effect-resolve-authorized"
            | "tool-resolve-authorized"
            | "tool-resolve-do-not-retry"
    ) {
        111
    } else if operation == "approval-expire" {
        150
    } else {
        100
    };
    let store = if matches!(operation.as_str(), "capacity-reserve" | "capacity-release") {
        SqliteStore::open_with_clock_and_limits(
            Path::new(&path),
            Arc::new(TestClock::new(worker_now)),
            LeaseDuration::from_millis(60_000).unwrap(),
            LimitProfile::new([(
                CapacityResource::ActiveOperations,
                ResourceLimit {
                    per_session: 8,
                    global: 8,
                },
            )])
            .unwrap(),
        )
        .await
        .unwrap()
    } else if operation == "event-append" {
        SqliteStore::open_with_clock_and_limits(
            Path::new(&path),
            Arc::new(TestClock::new(worker_now)),
            LeaseDuration::from_millis(60_000).unwrap(),
            LimitProfile::new([(
                CapacityResource::RetainedEvents,
                ResourceLimit {
                    per_session: 16,
                    global: 16,
                },
            )])
            .unwrap(),
        )
        .await
        .unwrap()
    } else {
        SqliteStore::open_with_clock(
            Path::new(&path),
            Arc::new(TestClock::new(worker_now)),
            LeaseDuration::from_millis(60_000).unwrap(),
        )
        .await
        .unwrap()
    };

    match operation.as_str() {
        "event-append" => {
            store
                .append_capacity_test_event(
                    RequestId::from_uuid(Uuid::from_u128(120_700)).unwrap(),
                    session_id(),
                )
                .await
                .unwrap();
        }
        "capacity-reserve" => {
            let _ = store
                .reserve_capacity(capacity_command(120_500, 1))
                .await
                .unwrap();
        }
        "capacity-release" => {
            let id = RequestId::from_uuid(Uuid::from_u128(120_501)).unwrap();
            let _ = store.release_capacity(id).await.unwrap();
        }
        "projection-rebuild" => {
            let _ = store.rebuild_projection(session_id()).await.unwrap();
        }
        "approval-request" => {
            let _ = store
                .request_approval(RequestApproval {
                    context: context(94_110, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(94_101)).unwrap(),
                    requester_id: participant_command().participant_id,
                    operation_id: start_operation_command().operation_id,
                    source_message_id: start_operation_command().input_message_id,
                    source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
                    capability: Capability::new("repository.publish").unwrap(),
                    resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
                    summary: ApprovalSummary::new("request crash atomic").unwrap(),
                    expires_at: Timestamp::new(300, 0).unwrap(),
                })
                .await
                .unwrap();
        }
        "approval-approve" => {
            let _ = store
                .approve_request(ApproveRequest {
                    context: context(94_011, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(94_001)).unwrap(),
                    expected_revision: Revision::initial(),
                    grant_id: GrantId::from_uuid(Uuid::from_u128(94_002)).unwrap(),
                    grant_expires_at: Timestamp::new(190, 0).unwrap(),
                    max_uses: 1,
                })
                .await
                .unwrap();
        }
        "approval-deny" => {
            let _ = store
                .deny_request(DenyRequest {
                    context: context(94_211, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(94_201)).unwrap(),
                    expected_revision: Revision::initial(),
                })
                .await
                .unwrap();
        }
        "approval-expire" => {
            let _ = store
                .expire_approval(ExpireApproval {
                    context: context(94_311, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(94_301)).unwrap(),
                    expected_revision: Revision::initial(),
                })
                .await
                .unwrap();
        }
        "approval-revoke" => {
            let _ = store
                .revoke_approval_grant(RevokeApprovalGrant {
                    context: context(94_420, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    grant_id: GrantId::from_uuid(Uuid::from_u128(94_402)).unwrap(),
                    expected_revision: Revision::initial(),
                })
                .await
                .unwrap();
        }
        "approval-consume" => {
            let _ = store
                .consume_approval_grant(ConsumeApprovalGrant {
                    context: context(94_520, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    grant_id: GrantId::from_uuid(Uuid::from_u128(94_502)).unwrap(),
                    expected_revision: Revision::initial(),
                    effect_id: RequestId::from_uuid(Uuid::from_u128(94_530)).unwrap(),
                    subject_id: participant_command().participant_id,
                    operation_id: start_operation_command().operation_id,
                    capability: Capability::new("repository.publish").unwrap(),
                    resource_hash: ApprovalResource::new(br#"{"branch":"main"}"#)
                        .unwrap()
                        .digest(),
                })
                .await
                .unwrap();
        }
        "approval-finish" => {
            let _ = store
                .finish_approval_effect(FinishApprovalEffect {
                    context: context(94_640, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    effect_id: RequestId::from_uuid(Uuid::from_u128(94_630)).unwrap(),
                    expected_revision: Revision::initial(),
                    phase: TerminalApprovalEffectPhase::Succeeded,
                })
                .await
                .unwrap();
        }
        "open" => {
            let _ = store.open_session(open_command(310)).await.unwrap();
        }
        "atomic-manifest-open" => {
            let _ = store
                .register_templates_and_open_session(atomic_manifest_open_command(80_060))
                .await
                .unwrap();
        }
        "close" => {
            let command = CloseSession::new(
                context(412, host(20)),
                session_id(),
                FencingEpoch::new(1).unwrap(),
            );
            let _ = store.close_session(command).await.unwrap();
        }
        "acquire" => {
            let _ = store
                .acquire_ownership(acquire_command(421, host(20), 100, 120))
                .await
                .unwrap();
        }
        "renew" => {
            let command = RenewOwnership::new(
                context(422, host(20)),
                session_id(),
                FencingEpoch::new(1).unwrap(),
                LeaseDuration::from_millis(30_000).unwrap(),
            );
            let _ = store.renew_ownership(command).await.unwrap();
        }
        "release" => {
            let command = ReleaseOwnership::new(
                context(423, host(20)),
                session_id(),
                FencingEpoch::new(1).unwrap(),
            );
            let _ = store.release_ownership(command).await.unwrap();
        }
        "prepare-launch" => {
            let _ = store
                .prepare_launch(prepare_launch_command())
                .await
                .unwrap();
        }
        "attach-launch" => {
            let _ = store.attach_launch(attach_launch_command()).await.unwrap();
        }
        "transition-launch" => {
            let _ = store
                .transition_launch(transition_launch_command())
                .await
                .unwrap();
        }
        "participant-create" => {
            let _ = store
                .create_root_participant(participant_command())
                .await
                .unwrap();
        }
        "participant-child" => {
            let _ = store
                .create_child_participant(child_command())
                .await
                .unwrap();
        }
        "operation-start" => {
            let _ = store
                .start_operation(start_operation_command())
                .await
                .unwrap();
        }
        "operation-transition" => {
            let _ = store
                .transition_operation(transition_operation_command())
                .await
                .unwrap();
        }
        "recovery-classify" => {
            let observation = navigator_domain::LiveObservation::NotApplicable;
            let classified = |entity, state| RecoveryEventClassification {
                entity,
                state,
                observation,
                decision: navigator_domain::classify_recovery(state, observation).unwrap(),
            };
            store
                .record_recovery_classifications(RecordRecoveryClassifications {
                    context: context(70_102, host(20)),
                    session_id: session_id(),
                    epoch: FencingEpoch::new(1).unwrap(),
                    classifications: vec![
                        classified(
                            RecoveryEventEntity::Session(session_id()),
                            navigator_domain::RecoveryState::SessionOpen,
                        ),
                        classified(
                            RecoveryEventEntity::Participant(participant_command().participant_id),
                            navigator_domain::RecoveryState::ParticipantRegistered,
                        ),
                        classified(
                            RecoveryEventEntity::Operation(start_operation_command().operation_id),
                            navigator_domain::RecoveryState::OperationQueued,
                        ),
                        classified(
                            RecoveryEventEntity::Message(
                                start_operation_command().input_message_id,
                            ),
                            navigator_domain::RecoveryState::MessageQueued,
                        ),
                    ],
                })
                .await
                .unwrap();
        }
        "effect-reserve" => {
            store
                .reserve_effect(journal_reserve_command())
                .await
                .unwrap();
        }
        "effect-start" => {
            let effect = store
                .read_effect(RequestId::from_uuid(Uuid::from_u128(80_005)).unwrap())
                .await
                .unwrap()
                .unwrap();
            store
                .start_effect(EffectTransition::start(
                    context(85_001, host(20)),
                    effect.request_id,
                    effect.owner_epoch,
                    effect.revision,
                ))
                .await
                .unwrap();
        }
        "effect-takeover" => {
            let effect = store
                .read_effect(RequestId::from_uuid(Uuid::from_u128(80_005)).unwrap())
                .await
                .unwrap()
                .unwrap();
            store
                .takeover_effect(TakeoverEffect::new(
                    context(85_002, host(20)),
                    effect.request_id,
                    effect.owner_epoch,
                    effect.revision,
                    std::time::Duration::from_secs(10),
                ))
                .await
                .unwrap();
        }
        "effect-resolve-authorized" => {
            let effect = store
                .read_effect(RequestId::from_uuid(Uuid::from_u128(80_005)).unwrap())
                .await
                .unwrap()
                .unwrap();
            store
                .resolve_authorized_effect(authorized_resolution_command(&effect))
                .await
                .unwrap();
        }
        "tool-resolve-authorized" => {
            let invocation_id = ToolInvocationId::from_uuid(Uuid::from_u128(81_031)).unwrap();
            let uncertain = store
                .load_tool_invocation(invocation_id)
                .await
                .unwrap()
                .unwrap();
            store
                .resolve_authorized_effect(tool_resolution_command(&uncertain))
                .await
                .unwrap();
        }
        "tool-resolve-do-not-retry" => {
            let invocation_id = ToolInvocationId::from_uuid(Uuid::from_u128(81_031)).unwrap();
            let uncertain = store
                .load_tool_invocation(invocation_id)
                .await
                .unwrap()
                .unwrap();
            store
                .resolve_authorized_effect(tool_do_not_retry_command(&uncertain))
                .await
                .unwrap();
        }
        "tool-connect" => {
            store
                .connect_tool_provider(ConnectToolProvider {
                    context: context(81_003, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                    provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                    connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_005)).unwrap(),
                    after_server_sequence: 0,
                    registration_ids: vec![
                        ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap(),
                    ],
                })
                .await
                .unwrap();
        }
        "tool-reconnect" => {
            store
                .connect_tool_provider(ConnectToolProvider {
                    context: context(81_090, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                    provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                    connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(81_091)).unwrap(),
                    after_server_sequence: 0,
                    registration_ids: vec![
                        ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap(),
                    ],
                })
                .await
                .unwrap();
        }
        "tool-register" => {
            store
                .register_tool(RegisterTool {
                    context: context(81_001, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(81_002))
                        .unwrap(),
                    consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                    definition: tool_definition(),
                })
                .await
                .unwrap();
        }
        "tool-reserve" => {
            store
                .reserve_tool_invocation(tool_reserve(81_060, 81_061, host(20), 1, 10))
                .await
                .unwrap();
        }
        "tool-start" | "tool-complete" | "tool-fail" | "tool-uncertain" | "tool-cancel" => {
            let invocation_id = ToolInvocationId::from_uuid(Uuid::from_u128(81_061)).unwrap();
            let current = store
                .load_tool_invocation(invocation_id)
                .await
                .unwrap()
                .unwrap();
            let transition = match operation.as_str() {
                "tool-start" => ToolTransition::Start,
                "tool-complete" => ToolTransition::Complete(
                    ToolResult::new(
                        invocation_id,
                        CanonicalJson::new(r#"{"found":true}"#).unwrap(),
                        vec![],
                    )
                    .unwrap(),
                ),
                "tool-fail" => ToolTransition::Fail(ToolFailure {
                    invocation_id,
                    kind: ToolFailureKind::HandlerFailed,
                    message: BoundedText::new("handler failed").unwrap(),
                    retryable: false,
                }),
                "tool-uncertain" => ToolTransition::MarkUncertain,
                "tool-cancel" => ToolTransition::RequestCancel {
                    cancellation_id: ToolCancellationId::from_uuid(Uuid::from_u128(81_062))
                        .unwrap(),
                },
                _ => unreachable!(),
            };
            store
                .transition_tool_invocation(TransitionToolInvocation {
                    context: context(
                        match operation.as_str() {
                            "tool-start" => 81_063,
                            "tool-complete" => 81_064,
                            "tool-fail" => 81_066,
                            "tool-uncertain" => 81_067,
                            _ => 81_065,
                        },
                        host(20),
                    ),
                    invocation_id,
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    expected_revision: current.revision(),
                    transition,
                    provider_id: current.dispatch().provider_id,
                    connection_id: current.dispatch().connection_id.unwrap(),
                    connection_generation: current.dispatch().connection_generation.unwrap(),
                    dispatch_id: current.dispatch().dispatch_id,
                    server_sequence: current.dispatch().server_sequence,
                })
                .await
                .unwrap();
        }
        "cancel-subtree" => {
            let _ = store
                .cancel_subtree(CancelSubtree {
                    context: context(9_900, host(20)),
                    session_id: session_id(),
                    epoch: FencingEpoch::new(1).unwrap(),
                    root_participant_id: participant_command().participant_id,
                })
                .await
                .unwrap();
        }
        "authority-spawn" => {
            let _ = store
                .create_authorized_child(authorized_spawn_command())
                .await
                .unwrap();
        }
        "mailbox-enqueue" => {
            let _ = store
                .enqueue_message(mailbox_enqueue_command())
                .await
                .unwrap();
        }
        "mailbox-lease" => {
            let _ = store
                .lease_next_message(mailbox_lease_command())
                .await
                .unwrap();
        }
        "mailbox-transition" => {
            let _ = store
                .transition_message_delivery(mailbox_transition_command())
                .await
                .unwrap();
        }
        "feedback-accept" => {
            let _ = store
                .transition_message_delivery(feedback_accept_command())
                .await
                .unwrap();
        }
        "migration" => {}
        _ => panic!("unknown crash operation"),
    }
    panic!("configured crash point was not reached");
}

#[tokio::test]
async fn abrupt_process_loss_during_prepare_launch_is_prior_or_committed() {
    for point in PREPARE_LAUNCH_CRASH_POINTS {
        if !fault_matrix_point_selected(point) {
            continue;
        }
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        store.open_session(open_command(928)).await.unwrap();
        store
            .acquire_ownership(acquire_command(929, host(20), 100, 120))
            .await
            .unwrap();
        store.pool().close().await;

        run_crash_worker(&path, "prepare-launch", point);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        assert_integrity(&reopened).await;
        let committed = *point == "launch.prepare.after_commit";
        let retry = reopened
            .prepare_launch(prepare_launch_command())
            .await
            .unwrap();
        assert_eq!(matches!(retry, Mutation::Replayed(_)), committed);
        write_durable_fault_result(
            point,
            committed,
            observe_durable_fault_facts(
                &reopened,
                matches!(retry, Mutation::Replayed(_)) == committed,
                matches!(retry, Mutation::Replayed(_)) == committed,
            )
            .await,
            serde_json::json!({"area":"launch","operation":"prepare","replayed":committed}),
        );
    }
}

#[tokio::test]
async fn abrupt_process_loss_during_attach_and_transition_is_prior_or_committed() {
    for operation in ["attach-launch", "transition-launch"] {
        for point in MUTATE_LAUNCH_CRASH_POINTS {
            if !fault_matrix_point_selected(point) {
                continue;
            }
            let directory = TempDir::new().unwrap();
            let (store, path, clock) = new_store(&directory).await;
            store.open_session(open_command(928)).await.unwrap();
            store
                .acquire_ownership(acquire_command(929, host(20), 100, 120))
                .await
                .unwrap();
            store
                .prepare_launch(prepare_launch_command())
                .await
                .unwrap();
            if operation == "transition-launch" {
                store.attach_launch(attach_launch_command()).await.unwrap();
            }
            store.pool().close().await;

            run_crash_worker(&path, operation, point);
            let reopened = SqliteStore::open_with_clock(
                &path,
                clock,
                LeaseDuration::from_millis(60_000).unwrap(),
            )
            .await
            .unwrap();
            assert_integrity(&reopened).await;
            let committed = *point == "launch.mutate.after_commit";
            let replayed = if operation == "attach-launch" {
                matches!(
                    reopened
                        .attach_launch(attach_launch_command())
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                )
            } else {
                matches!(
                    reopened
                        .transition_launch(transition_launch_command())
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                )
            };
            assert_eq!(replayed, committed, "{operation} at {point}");
            write_durable_fault_result(
                point,
                committed,
                observe_durable_fault_facts(
                    &reopened,
                    replayed == committed,
                    replayed == committed,
                )
                .await,
                serde_json::json!({"area":"launch","operation":operation,"replayed":replayed}),
            );
        }
    }
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "single crash-boundary matrix")]
async fn participant_and_operation_crash_boundaries_are_prior_or_committed() {
    for (operation, points) in [
        ("participant-create", PARTICIPANT_CRASH_POINTS),
        ("participant-child", CHILD_CRASH_POINTS),
        ("operation-start", OPERATION_START_CRASH_POINTS),
        ("operation-transition", OPERATION_TRANSITION_CRASH_POINTS),
    ] {
        for point in points {
            if !fault_matrix_point_selected(point) {
                continue;
            }
            let directory = TempDir::new().unwrap();
            let (store, path, clock) = new_store(&directory).await;
            store.open_session(open_command(938)).await.unwrap();
            store
                .acquire_ownership(acquire_command(939, host(20), 100, 120))
                .await
                .unwrap();
            store.register_template(template_record()).await.unwrap();
            if operation != "participant-create" {
                store
                    .create_root_participant(participant_command())
                    .await
                    .unwrap();
            }
            if operation == "operation-transition" {
                store
                    .start_operation(start_operation_command())
                    .await
                    .unwrap();
            }
            store.pool().close().await;
            run_crash_worker(&path, operation, point);
            let reopened = SqliteStore::open_with_clock(
                &path,
                clock,
                LeaseDuration::from_millis(60_000).unwrap(),
            )
            .await
            .unwrap();
            assert_integrity(&reopened).await;
            let committed = *point
                == format!(
                    "{}.after_commit",
                    if operation == "participant-create" {
                        "participant.create"
                    } else if operation == "participant-child" {
                        "participant.child"
                    } else if operation == "operation-start" {
                        "operation.start"
                    } else {
                        "operation.transition"
                    }
                );
            if operation == "operation-start" {
                assert_eq!(
                    reopened
                        .load_message(start_operation_command().input_message_id)
                        .await
                        .is_ok(),
                    committed,
                    "Operation and input Message diverged at {point}"
                );
            }
            if operation == "participant-child" {
                assert_eq!(
                    reopened
                        .load_participant(child_command().participant_id)
                        .await
                        .is_ok(),
                    committed,
                    "child/Event diverged at {point}"
                );
            }
            let replayed = match operation {
                "participant-create" => matches!(
                    reopened
                        .create_root_participant(participant_command())
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                ),
                "participant-child" => matches!(
                    reopened
                        .create_child_participant(child_command())
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                ),
                "operation-start" => matches!(
                    reopened
                        .start_operation(start_operation_command())
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                ),
                _ => matches!(
                    reopened
                        .transition_operation(transition_operation_command())
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                ),
            };
            assert_eq!(replayed, committed, "{operation} at {point}");
            let expected_event = match operation {
                "participant-create" | "participant-child" => "participant.created",
                "operation-start" => "operation.queued",
                _ => "operation.starting",
            };
            let related_request = match operation {
                "participant-create" => participant_command().context.request_id(),
                "participant-child" => child_command().context.request_id(),
                "operation-start" => start_operation_command().context.request_id(),
                _ => transition_operation_command().context.request_id(),
            };
            let events = reopened
                .read_events(ReadEvents {
                    session_id: session_id(),
                    consumer: ConsumerKey::new("consumer-a").unwrap(),
                    after: None,
                    limit: EventReadLimit::new(100).unwrap(),
                })
                .await
                .unwrap();
            assert_eq!(
                events
                    .events
                    .iter()
                    .filter(|event| {
                        event.event_type().as_str() == expected_event
                            && event.related_request_id() == Some(related_request)
                    })
                    .count(),
                1,
                "{operation} at {point} exposed a missing or duplicate committed Event"
            );
            write_durable_fault_result(
                point,
                committed,
                observe_durable_fault_facts(
                    &reopened,
                    replayed == committed,
                    replayed == committed,
                )
                .await,
                serde_json::json!({"area":"operation","operation":operation,"replayed":replayed}),
            );
        }
    }
}

#[tokio::test]
async fn authorized_spawn_is_prior_or_fully_committed_at_every_boundary() {
    for point in AUTHORITY_SPAWN_CRASH_POINTS {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        store.open_session(open_command(9_600)).await.unwrap();
        store
            .acquire_ownership(acquire_command(9_601, host(20), 100, 160))
            .await
            .unwrap();
        store.register_template(template_record()).await.unwrap();
        store
            .create_root_participant(participant_command())
            .await
            .unwrap();
        prepare_authorized_spawn(&store).await;
        store.pool().close().await;
        run_crash_worker(&path, "authority-spawn", point);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        let committed = *point == "authority.spawn.after_commit";
        let command = authorized_spawn_command();
        assert_eq!(
            reopened
                .load_participant(command.participant_id)
                .await
                .is_ok(),
            committed
        );
        assert_eq!(
            reopened.load_operation(command.operation_id).await.is_ok(),
            committed
        );
        assert_eq!(
            reopened
                .load_message(command.input_message_id)
                .await
                .is_ok(),
            committed
        );
        assert_eq!(
            reopened
                .load_grant(command.grant_id.unwrap())
                .await
                .unwrap()
                .consumed_at
                .is_some(),
            committed
        );
        let replay = reopened
            .create_authorized_child(command.clone())
            .await
            .unwrap();
        assert_eq!(matches!(replay, Mutation::Replayed(_)), committed);
        if committed {
            let inventory = reopened
                .load_recovery_inventory(session_id(), host(20), FencingEpoch::new(1).unwrap())
                .await
                .unwrap();
            assert!(inventory.operations.iter().any(|operation| {
                operation.operation_id == command.operation_id
                    && operation.input_message_id == command.input_message_id
                    && operation.state == OperationState::Queued
            }));
            assert!(inventory.messages.iter().any(|message| {
                message.message_id == command.input_message_id
                    && message.state == MessageDeliveryState::Queued
            }));
        }
    }
}

async fn prepare_mailbox_crash_database(store: &SqliteStore, phase: &str) {
    store.open_session(open_command(938)).await.unwrap();
    store
        .acquire_ownership(acquire_command(939, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    store
        .start_operation(start_operation_command())
        .await
        .unwrap();
    sqlx::query("INSERT INTO launch_attempts(attempt_id, session_id, ownership_epoch, participant_id, driver_id, instance_id, state, revision, credential_digest, evidence, cleanup_reason) VALUES (?, ?, ?, ?, ?, ?, 'ready', 1, ?, NULL, NULL)")
        .bind(mailbox_lease_command().driver_launch_attempt_id.to_string())
        .bind(session_id().to_string())
        .bind(i64::try_from(mailbox_lease_command().epoch.get()).unwrap())
        .bind(participant_command().participant_id.to_string())
        .bind(template_record().driver.driver_id().to_string())
        .bind(mailbox_lease_command().instance_id.to_string())
        .bind(vec![1_u8; 32])
        .execute(store.pool()).await.unwrap();
    if phase != "mailbox-enqueue" {
        store
            .enqueue_message(mailbox_enqueue_command())
            .await
            .unwrap();
    }
    if phase == "mailbox-transition" {
        store
            .lease_next_message(mailbox_lease_command())
            .await
            .unwrap();
    }
}

async fn prepare_feedback_accept_crash_database(store: &SqliteStore) {
    prepare_mailbox_crash_database(store, "mailbox-enqueue").await;
    accept_input_message(store, 9_000_200).await;
    let mut operation = store
        .load_operation(start_operation_command().operation_id)
        .await
        .unwrap();
    for (request, action, report_message_id) in [
        (9_670, OperationAction::BeginStart, None),
        (
            9_671,
            OperationAction::ReportRunning,
            Some(start_operation_command().input_message_id),
        ),
        (9_672, OperationAction::Wait, Some(feedback_question_id())),
    ] {
        operation = store
            .transition_operation(TransitionOperation {
                context: context(request, host(20)),
                session_id: session_id(),
                epoch: FencingEpoch::new(1).unwrap(),
                operation_id: operation.operation_id,
                expected_revision: operation.revision,
                action,
                report_message_id,
                terminal_outcome: None,
            })
            .await
            .unwrap()
            .value()
            .clone();
    }
    store
        .enqueue_message(EnqueueMessage {
            context: context(9_673, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: feedback_question_id(),
            source: participant_command().participant_id,
            destination: participant_command().participant_id,
            correlation: MessageCorrelation {
                operation_id: Some(operation.operation_id),
                in_reply_to: None,
            },
            envelope: ValidatedMessageEnvelope::question(
                operation.operation_id,
                Capability::new("input.required").unwrap(),
            ),
        })
        .await
        .unwrap();
    store
        .enqueue_message(EnqueueMessage {
            context: context(9_674, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: feedback_message_id(),
            source: participant_command().participant_id,
            destination: participant_command().participant_id,
            correlation: MessageCorrelation {
                operation_id: Some(operation.operation_id),
                in_reply_to: Some(feedback_question_id()),
            },
            envelope: ValidatedMessageEnvelope::correlated_feedback(
                operation.operation_id,
                feedback_question_id(),
                FeedbackKind::Acknowledged,
            ),
        })
        .await
        .unwrap();
    let mut lease = mailbox_lease_command();
    lease.context = context(9_683, host(20));
    lease.proposed_attempt_id = feedback_accept_command().attempt_id;
    let leased = store
        .lease_next_message(lease)
        .await
        .unwrap()
        .value()
        .clone()
        .unwrap();
    assert_eq!(leased.message_id, feedback_message_id());
    store
        .transition_message_delivery(TransitionMessageDelivery {
            context: context(9_684, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            message_id: feedback_message_id(),
            attempt_id: feedback_accept_command().attempt_id,
            expected_revision: leased.revision,
            transition: DeliveryTransition::AcceptancePending,
        })
        .await
        .unwrap();
}

async fn prepare_cancellation_crash_database(store: &SqliteStore) {
    prepare_mailbox_crash_database(store, "mailbox-enqueue").await;
    accept_input_message(store, 9_000_300).await;
    let starting = store
        .transition_operation(transition_operation_command())
        .await
        .unwrap()
        .value()
        .clone();
    store
        .transition_operation(TransitionOperation {
            context: context(9_899, host(20)),
            session_id: session_id(),
            epoch: FencingEpoch::new(1).unwrap(),
            operation_id: starting.operation_id,
            expected_revision: starting.revision,
            action: OperationAction::ReportRunning,
            report_message_id: Some(starting.input_message_id),
            terminal_outcome: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "migration compatibility mutant enumerates every post-v3 schema object explicitly"
)]
async fn legacy_v3_ready_launch_remains_unknown_and_cannot_authorize_a_fresh_lease() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    prepare_mailbox_crash_database(&store, "mailbox-lease").await;
    let before = store
        .load_message(mailbox_enqueue_command().message_id)
        .await
        .unwrap();
    store.pool().close().await;

    let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
        .unwrap()
        .foreign_keys(false);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    connection
        .execute("ALTER TABLE launch_attempts DROP COLUMN ownership_epoch")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE launch_attempts DROP COLUMN driver_configuration_digest")
        .await
        .unwrap();
    connection
        .execute("DROP INDEX participant_children")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE participants DROP COLUMN depth")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE participants DROP COLUMN cancellation_requested")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE operations DROP COLUMN waiting_on_message_id")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE authority_grants")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE authority_policies")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE authority_template_policies")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE effect_journal_mutations")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE effect_journal")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE recovery_classifications")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE session_template_manifest")
        .await
        .unwrap();
    connection.execute("DROP TABLE artifacts").await.unwrap();
    connection
        .execute("DROP TABLE projection_rows")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE projection_progress")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE projection_heads")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE projection_generations")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE projection_metadata")
        .await
        .unwrap();
    connection
        .execute("DROP INDEX one_open_session_per_public_consumer_key")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE sessions DROP COLUMN public_consumer_key")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE sessions DROP COLUMN compatibility_configuration_identity")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE tool_provider_connections")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE tool_invocation_mutations")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE tool_invocations")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE tool_registrations")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE approval_effect_intents")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE approval_grants")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE approval_requests")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE approval_mutations")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE sessions DROP COLUMN compatibility_manifest_complete")
        .await
        .unwrap();
    connection
        .execute("DROP INDEX mailbox_session_delivery_state")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE messages DROP COLUMN delivery_due_nanos")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE messages DROP COLUMN delivery_due_seconds")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE messages DROP COLUMN correlation_operation_id")
        .await
        .unwrap();
    connection
        .execute("ALTER TABLE messages DROP COLUMN delivery_state")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE subscription_leases")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE capacity_reservations")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE capacity_global_reservations")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE capacity_session_usage")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE capacity_global_usage")
        .await
        .unwrap();
    connection
        .execute("DROP TABLE capacity_limits")
        .await
        .unwrap();
    connection.execute("PRAGMA user_version = 3").await.unwrap();
    connection.close().await.unwrap();

    let reopened =
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    let launch = reopened
        .load_launch(mailbox_lease_command().driver_launch_attempt_id)
        .await
        .unwrap();
    assert_eq!(launch.ownership_epoch, None);
    assert_eq!(
        reopened.lease_next_message(mailbox_lease_command()).await,
        Err(StoreError::Invalid)
    );
    let after = reopened.load_message(before.message_id).await.unwrap();
    assert_eq!(after.revision, before.revision);
    assert_eq!(after.attempt_count, before.attempt_count);
    assert_eq!(
        reopened.load_session(session_id()).await.unwrap().id(),
        session_id()
    );
}

#[tokio::test]
async fn mailbox_mutations_are_prior_or_committed_at_every_transaction_boundary() {
    for (operation, points) in [
        ("mailbox-enqueue", MAILBOX_ENQUEUE_CRASH_POINTS),
        ("mailbox-lease", MAILBOX_LEASE_CRASH_POINTS),
        ("mailbox-transition", MAILBOX_TRANSITION_CRASH_POINTS),
        ("feedback-accept", MAILBOX_FEEDBACK_CRASH_POINTS),
    ] {
        for point in points {
            if !fault_matrix_point_selected(point) {
                continue;
            }
            let directory = TempDir::new().unwrap();
            let (store, path, clock) = new_store(&directory).await;
            if operation == "feedback-accept" {
                prepare_feedback_accept_crash_database(&store).await;
            } else {
                prepare_mailbox_crash_database(&store, operation).await;
            }
            store.pool().close().await;
            run_crash_worker(&path, operation, point);
            let reopened = SqliteStore::open_with_clock(
                &path,
                clock,
                LeaseDuration::from_millis(60_000).unwrap(),
            )
            .await
            .unwrap();
            let snapshot = match operation {
                "mailbox-enqueue" => reopened
                    .enqueue_message(mailbox_enqueue_command())
                    .await
                    .unwrap()
                    .value()
                    .clone(),
                "mailbox-lease" => reopened
                    .lease_next_message(mailbox_lease_command())
                    .await
                    .unwrap()
                    .value()
                    .clone()
                    .unwrap(),
                "mailbox-transition" => reopened
                    .transition_message_delivery(mailbox_transition_command())
                    .await
                    .unwrap()
                    .value()
                    .clone(),
                "feedback-accept" => reopened
                    .transition_message_delivery(feedback_accept_command())
                    .await
                    .unwrap()
                    .value()
                    .clone(),
                _ => unreachable!(),
            };
            let expected_message_id = if operation == "feedback-accept" {
                feedback_message_id()
            } else {
                mailbox_enqueue_command().message_id
            };
            assert_eq!(snapshot.message_id, expected_message_id);
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE message_id = ?")
                    .bind(snapshot.message_id.to_string())
                    .fetch_one(reopened.pool())
                    .await
                    .unwrap();
            assert_eq!(count, 1, "{operation} at {point} duplicated durable truth");
            let committed = point.ends_with("after_commit");
            write_durable_fault_result(
                point,
                committed,
                observe_durable_fault_facts(&reopened, count == 1, count == 1).await,
                serde_json::json!({"area":"mailbox","operation":operation,"message_count":count}),
            );
        }
    }
}

#[tokio::test]
async fn feedback_acceptance_crash_is_prior_or_fully_resumed() {
    for point in FEEDBACK_ACCEPT_CRASH_POINTS {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        prepare_feedback_accept_crash_database(&store).await;
        let before = store
            .load_operation(start_operation_command().operation_id)
            .await
            .unwrap();
        store.pool().close().await;
        run_crash_worker(&path, "feedback-accept", point);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        assert_integrity(&reopened).await;
        let message = reopened.load_message(feedback_message_id()).await.unwrap();
        let operation = reopened
            .load_operation(start_operation_command().operation_id)
            .await
            .unwrap();
        let committed = *point == "mailbox.transition.after_commit";
        assert_eq!(
            matches!(message.state, MessageDeliveryState::Accepted { .. }),
            committed,
            "Message acceptance diverged at {point}"
        );
        assert_eq!(operation.state == OperationState::Running, committed);
        assert_eq!(operation.waiting_on_message_id.is_none(), committed);
        assert_eq!(operation.revision != before.revision, committed);
        let events = reopened
            .read_events(ReadEvents {
                session_id: session_id(),
                consumer: ConsumerKey::new("consumer-a").unwrap(),
                after: None,
                limit: EventReadLimit::new(128).unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(
            events
                .events
                .iter()
                .filter(|event| event.event_type().as_str() == "operation.resumed")
                .count(),
            usize::from(committed)
        );
    }
}

#[tokio::test]
async fn cancellation_crash_is_prior_or_fully_committed() {
    for point in CANCELLATION_CRASH_POINTS {
        if !fault_matrix_point_selected(point) {
            continue;
        }
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        prepare_cancellation_crash_database(&store).await;
        store.pool().close().await;
        run_crash_worker(&path, "cancel-subtree", point);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        assert_integrity(&reopened).await;
        let committed = *point == "cancellation.after_commit";
        let tombstone: i64 = sqlx::query_scalar(
            "SELECT cancellation_requested FROM participants WHERE participant_id=?",
        )
        .bind(participant_command().participant_id.to_string())
        .fetch_one(reopened.pool())
        .await
        .unwrap();
        let operation = reopened
            .load_operation(start_operation_command().operation_id)
            .await
            .unwrap();
        let notifications = reopened
            .load_mailbox(participant_command().participant_id)
            .await
            .unwrap()
            .into_iter()
            .filter(|message| {
                matches!(
                    message.envelope.body(),
                    navigator_domain::MessageBody::Control {
                        command: navigator_domain::ControlMessageKind::Cancel,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(tombstone == 1, committed, "tombstone diverged at {point}");
        assert_eq!(
            operation.state == OperationState::Cancelling,
            committed,
            "Operation diverged at {point}"
        );
        assert_eq!(notifications, usize::from(committed));
        write_durable_fault_result(
            point,
            committed,
            observe_durable_fault_facts(
                &reopened,
                notifications == usize::from(committed),
                (operation.state == OperationState::Cancelling) == committed,
            )
            .await,
            serde_json::json!({"area":"cancellation","notifications":notifications,"operation_state":format!("{:?}", operation.state)}),
        );
    }
}

#[tokio::test]
async fn cancellation_and_child_creation_serialize_without_post_cancel_work() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(9_910)).await.unwrap();
    store
        .acquire_ownership(acquire_command(9_911, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let cancel_store = store.clone();
    let cancel_barrier = barrier.clone();
    let cancel = tokio::spawn(async move {
        cancel_barrier.wait().await;
        cancel_store
            .cancel_subtree(CancelSubtree {
                context: context(9_912, host(20)),
                session_id: session_id(),
                epoch: FencingEpoch::new(1).unwrap(),
                root_participant_id: participant_command().participant_id,
            })
            .await
    });
    let child_store = store.clone();
    let child_barrier = barrier.clone();
    let child = tokio::spawn(async move {
        child_barrier.wait().await;
        child_store.create_child_participant(child_command()).await
    });
    barrier.wait().await;
    cancel.await.unwrap().unwrap();
    let child_result = child.await.unwrap();
    let child_row: Option<i64> = sqlx::query_scalar(
        "SELECT cancellation_requested FROM participants WHERE participant_id=?",
    )
    .bind(child_command().participant_id.to_string())
    .fetch_optional(store.pool())
    .await
    .unwrap();
    match child_result {
        Ok(_) => assert_eq!(child_row, Some(1), "admitted child must be in cancel scope"),
        Err(StoreError::Invalid) => assert_eq!(child_row, None),
        other => panic!("unexpected serialized outcome: {other:?}"),
    }
}

#[tokio::test]
async fn cancellation_and_launch_prepare_never_authorize_a_post_cancel_spawn() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(9_920)).await.unwrap();
    store
        .acquire_ownership(acquire_command(9_921, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut launch_command = prepare_launch_command();
    launch_command.participant_id = participant_command().participant_id;
    let cancel_store = store.clone();
    let cancel_barrier = barrier.clone();
    let cancel = tokio::spawn(async move {
        cancel_barrier.wait().await;
        cancel_store
            .cancel_subtree(CancelSubtree {
                context: context(9_922, host(20)),
                session_id: session_id(),
                epoch: FencingEpoch::new(1).unwrap(),
                root_participant_id: participant_command().participant_id,
            })
            .await
    });
    let launch_store = store.clone();
    let launch_barrier = barrier.clone();
    let retry_command = launch_command.clone();
    let launch = tokio::spawn(async move {
        launch_barrier.wait().await;
        launch_store.prepare_launch(launch_command).await
    });
    barrier.wait().await;
    cancel.await.unwrap().unwrap();
    let first_prepare = launch.await.unwrap();
    assert!(matches!(first_prepare, Ok(_) | Err(StoreError::Invalid)));
    assert_eq!(
        store.prepare_launch(retry_command).await,
        Err(StoreError::Invalid),
        "a pre-cancel Prepared replay cannot authorize process spawn"
    );
}

#[tokio::test]
async fn concurrent_operation_starts_commit_exactly_one_unfinished_operation() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(938)).await.unwrap();
    store
        .acquire_ownership(acquire_command(939, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(3));
    let spawn = |request: u128, operation: u128, message: u128| {
        let store = store.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            let mut command = start_operation_command();
            command.context = context(request, host(20));
            command.operation_id = OperationId::from_uuid(Uuid::from_u128(operation)).unwrap();
            command.input_message_id = MessageId::from_uuid(Uuid::from_u128(message)).unwrap();
            barrier.wait().await;
            store.start_operation(command).await
        })
    };
    let left = spawn(950, 951, 952);
    let right = spawn(953, 954, 955);
    barrier.wait().await;
    let left = left.await.unwrap();
    let right = right.await.unwrap();
    assert!(matches!(
        (&left, &right),
        (Ok(Mutation::Applied(_)), Err(StoreError::Invalid))
            | (Err(StoreError::Invalid), Ok(Mutation::Applied(_)))
    ));
    let unfinished: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM operations WHERE terminal_outcome IS NULL")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(unfinished, 1);
}

#[tokio::test]
async fn corrupted_operation_payload_is_never_returned_for_delivery() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    store.open_session(open_command(938)).await.unwrap();
    store
        .acquire_ownership(acquire_command(939, host(20), 100, 120))
        .await
        .unwrap();
    store.register_template(template_record()).await.unwrap();
    store
        .create_root_participant(participant_command())
        .await
        .unwrap();
    let operation = store
        .start_operation(start_operation_command())
        .await
        .unwrap()
        .value()
        .operation_id;
    sqlx::query("UPDATE operations SET input_payload = ? WHERE operation_id = ?")
        .bind(b"{ }".as_slice())
        .bind(operation.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store.load_operation_input(operation).await,
        Err(StoreError::Corrupt)
    );
}

#[tokio::test]
async fn corrupted_registered_template_is_rejected_on_restore() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    let template = template_record();
    store.register_template(template.clone()).await.unwrap();
    sqlx::query("UPDATE templates SET registration = ? WHERE template_id = ?")
        .bind(b"{}".as_slice())
        .bind(template.identity.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        store.load_template(template.identity).await,
        Err(StoreError::Corrupt)
    );
}

#[tokio::test]
async fn abrupt_process_loss_during_acquire_is_prior_or_committed_never_hybrid() {
    for point in ACQUIRE_CRASH_POINTS {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        clock.set(90);
        store.open_session(open_command(320)).await.unwrap();
        store.pool().close().await;

        run_crash_worker(&path, "acquire", point);
        clock.set(95);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        assert_integrity(&reopened).await;

        let committed = *point == "acquire.after_commit";
        let snapshot = reopened.load_session(session_id()).await.unwrap();
        assert_eq!(snapshot.revision().get(), if committed { 2 } else { 1 });
        assert_eq!(ownership_expiry(&reopened).await, committed.then_some(120));
        assert_counts(
            &reopened,
            if committed { 2 } else { 1 },
            if committed { 2 } else { 1 },
        )
        .await;

        let retry = reopened
            .acquire_ownership(acquire_command(421, host(20), 100, 120))
            .await
            .unwrap();
        assert_eq!(matches!(retry, Mutation::Replayed(_)), committed);
        assert_eq!(
            ownership_expiry(&reopened).await,
            Some(if committed { 120 } else { 115 })
        );
        assert_counts(&reopened, 2, 2).await;
    }
}

#[tokio::test]
async fn abrupt_process_loss_during_renew_is_prior_or_committed_never_hybrid() {
    for point in RENEW_CRASH_POINTS {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        clock.set(90);
        store.open_session(open_command(321)).await.unwrap();
        store
            .acquire_ownership(acquire_command(424, host(20), 90, 110))
            .await
            .unwrap();
        store.pool().close().await;

        run_crash_worker(&path, "renew", point);
        clock.set(95);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        assert_integrity(&reopened).await;

        let committed = *point == "renew.after_commit";
        assert_eq!(
            ownership_expiry(&reopened).await,
            Some(if committed { 130 } else { 110 })
        );
        assert_counts(&reopened, 2, if committed { 3 } else { 2 }).await;

        let command = RenewOwnership::new(
            context(422, host(20)),
            session_id(),
            FencingEpoch::new(1).unwrap(),
            LeaseDuration::from_millis(30_000).unwrap(),
        );
        let retry = reopened.renew_ownership(command).await.unwrap();
        assert_eq!(matches!(retry, Mutation::Replayed(_)), committed);
        assert_eq!(
            ownership_expiry(&reopened).await,
            Some(if committed { 130 } else { 125 })
        );
        assert_counts(&reopened, 2, 3).await;
    }
}

#[tokio::test]
async fn abrupt_process_loss_during_release_is_prior_or_committed_never_hybrid() {
    for point in RELEASE_CRASH_POINTS {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        clock.set(90);
        store.open_session(open_command(322)).await.unwrap();
        store
            .acquire_ownership(acquire_command(425, host(20), 90, 110))
            .await
            .unwrap();
        store.pool().close().await;

        run_crash_worker(&path, "release", point);
        clock.set(95);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        assert_integrity(&reopened).await;

        let committed = *point == "release.after_commit";
        let snapshot = reopened.load_session(session_id()).await.unwrap();
        assert_eq!(snapshot.revision().get(), if committed { 3 } else { 2 });
        assert_eq!(
            ownership_expiry(&reopened).await,
            (!committed).then_some(110)
        );
        assert_counts(
            &reopened,
            if committed { 3 } else { 2 },
            if committed { 3 } else { 2 },
        )
        .await;

        let command = ReleaseOwnership::new(
            context(423, host(20)),
            session_id(),
            FencingEpoch::new(1).unwrap(),
        );
        let retry = reopened.release_ownership(command).await.unwrap();
        assert_eq!(matches!(retry, Mutation::Replayed(_)), committed);
        assert_eq!(ownership_expiry(&reopened).await, None);
        assert_eq!(
            reopened
                .load_session(session_id())
                .await
                .unwrap()
                .updated_at()
                .unix_seconds(),
            if committed { 100 } else { 95 }
        );
        assert_counts(&reopened, 3, 3).await;
    }
}

#[tokio::test]
async fn abrupt_process_loss_during_migration_is_old_or_new_schema_never_partial() {
    for point in MIGRATION_CRASH_POINTS {
        let directory = TempDir::new().unwrap();
        let path = directory.path().join("migration.db");
        run_crash_worker(&path, "migration", point);

        let (version, tables) = migration_state(&path).await;
        let committed = *point == "migration.after_commit";
        assert_eq!(version, if committed { 20 } else { 0 });
        assert_eq!(tables, if committed { 36 } else { 0 });

        let reopened = SqliteStore::open_with_clock(
            &path,
            Arc::new(TestClock::new(100)),
            LeaseDuration::from_millis(60_000).unwrap(),
        )
        .await
        .unwrap();
        assert_integrity(&reopened).await;
        let (version, tables) = migration_state(&path).await;
        assert_eq!((version, tables), (20, 36));
    }
}

#[tokio::test]
async fn abrupt_process_loss_during_open_is_prior_or_committed_never_hybrid() {
    for point in OPEN_CRASH_POINTS {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        store.pool().close().await;

        run_crash_worker(&path, "open", point);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        assert_integrity(&reopened).await;

        let committed = *point == "open.after_commit";
        let snapshot = reopened.load_session(session_id()).await;
        assert_eq!(snapshot.is_ok(), committed, "point {point}");
        assert_counts(&reopened, usize::from(committed), usize::from(committed)).await;

        let retry = reopened.open_session(open_command(310)).await.unwrap();
        assert_eq!(
            matches!(retry, Mutation::Replayed(_)),
            committed,
            "point {point}"
        );
        assert_counts(&reopened, 1, 1).await;
        assert_integrity(&reopened).await;
    }
}

#[tokio::test]
async fn abrupt_process_loss_during_atomic_manifest_open_is_never_partial() {
    for point in [
        "open_with_templates.after_templates",
        "open_with_templates.before_commit",
        "open_with_templates.after_commit",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        store.pool().close().await;
        run_crash_worker(&path, "atomic-manifest-open", point);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        let committed = point.ends_with("after_commit");
        let template_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM templates")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        assert_eq!(template_count, if committed { 2 } else { 0 }, "{point}");
        assert_eq!(event_count, i64::from(committed), "{point}");
        assert_eq!(reopened.load_session(session_id()).await.is_ok(), committed);
        let retry = reopened
            .register_templates_and_open_session(atomic_manifest_open_command(80_060))
            .await
            .unwrap();
        assert_eq!(matches!(retry, Mutation::Replayed(_)), committed);
    }
}

#[tokio::test]
async fn abrupt_process_loss_during_close_is_prior_or_committed_never_hybrid() {
    for point in CLOSE_CRASH_POINTS {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        store.open_session(open_command(311)).await.unwrap();
        store
            .acquire_ownership(acquire_command(411, host(20), 100, 120))
            .await
            .unwrap();
        store.pool().close().await;

        run_crash_worker(&path, "close", point);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        assert_integrity(&reopened).await;

        let committed = *point == "close.after_commit";
        let snapshot = reopened.load_session(session_id()).await.unwrap();
        assert_eq!(
            snapshot.status() == SessionStatus::Closed,
            committed,
            "point {point}"
        );
        assert_eq!(snapshot.revision().get(), if committed { 3 } else { 2 });
        let ownership = reopened.read_ownership(session_id()).await.unwrap();
        assert_eq!(
            matches!(ownership, navigator_domain::OwnershipSnapshot::Unowned),
            committed,
            "point {point}"
        );
        assert_counts(
            &reopened,
            if committed { 3 } else { 2 },
            if committed { 3 } else { 2 },
        )
        .await;

        let command = CloseSession::new(
            context(412, host(20)),
            session_id(),
            FencingEpoch::new(1).unwrap(),
        );
        let retry = reopened.close_session(command).await.unwrap();
        assert_eq!(
            matches!(retry, Mutation::Replayed(_)),
            committed,
            "point {point}"
        );
        assert_counts(&reopened, 3, 3).await;
        assert_integrity(&reopened).await;
    }
}

fn run_crash_worker(path: &Path, operation: &str, point: &str) {
    let marker = path.with_extension("crash-marker");
    let sentinel_socket = path.with_extension("unrelated.sock");
    let _listener = UnixListener::bind(&sentinel_socket).unwrap();
    let socket_before = std::fs::symlink_metadata(&sentinel_socket).unwrap();
    let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("tests::crash_worker")
        .arg("--ignored")
        .arg("--nocapture")
        .env("NAVIGATOR_SQLITE_CRASH_DB", path)
        .env("NAVIGATOR_SQLITE_CRASH_OPERATION", operation)
        .env("NAVIGATOR_SQLITE_CRASH_AT", point)
        .env("NAVIGATOR_SQLITE_CRASH_MARKER", &marker)
        .status()
        .unwrap();
    assert!(!status.success(), "worker did not crash at {point}");
    assert_eq!(std::fs::read_to_string(marker).unwrap(), point);
    let process_survived = unrelated.try_wait().unwrap().is_none();
    let socket_after = std::fs::symlink_metadata(&sentinel_socket).unwrap();
    let socket_survived = socket_after.file_type().is_socket()
        && socket_after.dev() == socket_before.dev()
        && socket_after.ino() == socket_before.ino();
    assert!(
        process_survived,
        "crash at {point} killed an unrelated process"
    );
    assert!(
        socket_survived,
        "crash at {point} replaced an unrelated socket"
    );
    DURABLE_SENTINELS_SURVIVED.store(process_survived && socket_survived, Ordering::SeqCst);
    unrelated.kill().unwrap();
    unrelated.wait().unwrap();
}

async fn assert_counts(store: &SqliteStore, events: usize, requests: usize) {
    let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let request_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM request_ledger")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(usize::try_from(event_count).unwrap(), events);
    assert_eq!(usize::try_from(request_count).unwrap(), requests);
}

async fn assert_integrity(store: &SqliteStore) {
    let result: String = sqlx::query_scalar("PRAGMA integrity_check")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(result, "ok");
}

async fn ownership_expiry(store: &SqliteStore) -> Option<i64> {
    match store.read_ownership(session_id()).await.unwrap() {
        navigator_domain::OwnershipSnapshot::Unowned => None,
        navigator_domain::OwnershipSnapshot::Owned { expires_at, .. } => {
            Some(expires_at.unix_seconds())
        }
    }
}

async fn migration_state(path: &Path) -> (i64, usize) {
    let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
        .unwrap()
        .create_if_missing(false)
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    let tables: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    connection.close().await.unwrap();
    (version, usize::try_from(tables).unwrap())
}

#[tokio::test]
async fn tool_current_projection_rejects_latest_connect_field_mutants() {
    for mutation in ["consumer", "ack", "registrations"] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_tool_store(&store).await;
        match mutation {
            "consumer" => {
                sqlx::query("UPDATE tool_provider_connections SET consumer_key='other-consumer'")
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            "ack" => {
                sqlx::query("UPDATE tool_provider_connections SET acknowledged_server_sequence=1")
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            "registrations" => {
                sqlx::query("UPDATE tool_provider_connections SET registrations=?")
                    .bind(
                        serde_json::to_vec(&vec![
                            ToolRegistrationId::from_uuid(Uuid::from_u128(81_399)).unwrap(),
                        ])
                        .unwrap(),
                    )
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        store.pool().close().await;
        assert!(SqliteStore::open(&path).await.is_err(), "{mutation}");
    }
}

#[tokio::test]
async fn tool_connect_generation_ledger_must_be_contiguous_and_unique() {
    for mutation in ["missing", "duplicate"] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_tool_store(&store).await;
        for (request, connection) in [(81_380, 81_381), (81_382, 81_383)] {
            store
                .connect_tool_provider(ConnectToolProvider {
                    context: context(request, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                    provider_id: ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                    connection_id: ToolConnectionId::from_uuid(Uuid::from_u128(connection))
                        .unwrap(),
                    after_server_sequence: 0,
                    registration_ids: vec![
                        ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap(),
                    ],
                })
                .await
                .unwrap();
        }
        if mutation == "missing" {
            sqlx::query("DELETE FROM request_ledger WHERE request_id=?")
                .bind(
                    RequestId::from_uuid(Uuid::from_u128(81_380))
                        .unwrap()
                        .to_string(),
                )
                .execute(store.pool())
                .await
                .unwrap();
        } else {
            let mut second: serde_json::Value = serde_json::from_slice(
                &sqlx::query_scalar::<_, Vec<u8>>(
                    "SELECT result FROM request_ledger WHERE request_id=?",
                )
                .bind(
                    RequestId::from_uuid(Uuid::from_u128(81_380))
                        .unwrap()
                        .to_string(),
                )
                .fetch_one(store.pool())
                .await
                .unwrap(),
            )
            .unwrap();
            second["generation"] = serde_json::json!(1);
            sqlx::query("UPDATE request_ledger SET result=? WHERE request_id=?")
                .bind(serde_json::to_vec(&second).unwrap())
                .bind(
                    RequestId::from_uuid(Uuid::from_u128(81_380))
                        .unwrap()
                        .to_string(),
                )
                .execute(store.pool())
                .await
                .unwrap();
        }
        store.pool().close().await;
        assert!(SqliteStore::open(&path).await.is_err(), "{mutation}");
    }
}

#[tokio::test]
async fn tool_current_next_sequence_is_rebuilt_from_invocation_ledgers() {
    let directory = TempDir::new().unwrap();
    let (store, path, _) = new_store(&directory).await;
    prepare_tool_store(&store).await;
    store
        .reserve_tool_invocation(tool_reserve(81_384, 81_385, host(20), 1, 10))
        .await
        .unwrap();
    sqlx::query("UPDATE tool_provider_connections SET next_server_sequence=next_server_sequence+1")
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;
    assert!(SqliteStore::open(&path).await.is_err());
}

#[tokio::test]
async fn tool_invocation_registration_must_exist_in_provider_connect_history() {
    let directory = TempDir::new().unwrap();
    let (store, path, _) = new_store(&directory).await;
    prepare_tool_store(&store).await;
    let second_id = ToolRegistrationId::from_uuid(Uuid::from_u128(81_386)).unwrap();
    let mut second = tool_definition();
    let mut encoded = serde_json::to_value(&second).unwrap();
    encoded["name"] = serde_json::json!("records.unpublished");
    second = serde_json::from_value(encoded).unwrap();
    store
        .register_tool(RegisterTool {
            context: context(81_387, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            consumer_key: ConsumerKey::new("consumer-a").unwrap(),
            registration_id: second_id,
            definition: second.clone(),
        })
        .await
        .unwrap();
    let reserved = store
        .reserve_tool_invocation(tool_reserve(81_388, 81_389, host(20), 1, 10))
        .await
        .unwrap();
    let mut snapshot = serde_json::to_value(&reserved).unwrap();
    snapshot["registration_id"] = serde_json::json!(second_id);
    snapshot["definition"] = serde_json::to_value(&second).unwrap();
    snapshot["invocation"]["tool_name"] = serde_json::json!("records.unpublished");
    sqlx::query("UPDATE tool_invocations SET registration_id=?,tool_name=?,snapshot=? WHERE invocation_id=?")
        .bind(second_id.to_string()).bind("records.unpublished")
        .bind(serde_json::to_vec(&snapshot).unwrap())
        .bind(reserved.invocation().invocation_id().to_string()).execute(store.pool()).await.unwrap();
    store.pool().close().await;
    assert!(SqliteStore::open(&path).await.is_err());
}

#[tokio::test]
async fn tool_register_and_connect_replay_semantic_digests_are_verified() {
    for request in [81_001_u128, 81_003_u128] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_tool_store(&store).await;
        sqlx::query("UPDATE request_ledger SET semantic_digest=? WHERE request_id=?")
            .bind(vec![0x5a_u8; 32])
            .bind(
                RequestId::from_uuid(Uuid::from_u128(request))
                    .unwrap()
                    .to_string(),
            )
            .execute(store.pool())
            .await
            .unwrap();
        store.pool().close().await;
        assert!(SqliteStore::open(&path).await.is_err(), "{request}");
    }
}

#[tokio::test]
async fn live_tool_loader_rejects_every_mirrored_column_mutant() {
    let mutations = [
        (
            "effect_request_id",
            "'00000000-0000-4000-8000-000000000399'",
        ),
        ("registration_id", "'00000000-0000-4000-8000-000000000399'"),
        ("dispatch_id", "'00000000-0000-4000-8000-000000000399'"),
        ("provider_id", "'00000000-0000-4000-8000-000000000399'"),
        ("server_sequence", "server_sequence+1"),
        ("deadline_seconds", "deadline_seconds+1"),
        ("deadline_nanos", "deadline_nanos+1"),
        ("connection_generation", "connection_generation+1"),
        ("cancellation_id", "'00000000-0000-4000-8000-000000000399'"),
        ("cancellation_server_sequence", "server_sequence+1"),
        ("terminal_digest", "zeroblob(32)"),
        ("session_id", "'00000000-0000-4000-8000-000000000399'"),
        ("participant_id", "'00000000-0000-4000-8000-000000000399'"),
        ("operation_id", "'00000000-0000-4000-8000-000000000399'"),
        ("tool_name", "'records.mutant'"),
        ("tool_version", "'v999'"),
    ];
    for (column, replacement) in mutations {
        let directory = TempDir::new().unwrap();
        let (store, _, _) = new_store(&directory).await;
        prepare_tool_store(&store).await;
        let reserved = store
            .reserve_tool_invocation(tool_reserve(81_390, 81_391, host(20), 1, 10))
            .await
            .unwrap();
        let mut connection = store.pool().acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        let statement =
            format!("UPDATE tool_invocations SET {column}={replacement} WHERE invocation_id=?");
        sqlx::query(AssertSqlSafe(statement.as_str()))
            .bind(reserved.invocation().invocation_id().to_string())
            .execute(&mut *connection)
            .await
            .unwrap();
        drop(connection);
        assert_eq!(
            store
                .load_tool_invocation(reserved.invocation().invocation_id())
                .await,
            Err(StoreError::Corrupt),
            "{column}"
        );
    }
}

fn migration_tool_definition(name: impl Into<String>) -> ToolDefinition {
    ToolDefinition::new(
        ToolName::new(name.into()).unwrap(),
        ToolVersion::new("v1").unwrap(),
        CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(
            r#"{"additionalProperties":false,"properties":{},"type":"object"}"#,
        )
        .unwrap(),
        CanonicalJson::<MAX_TOOL_SCHEMA_BYTES>::new(
            r#"{"additionalProperties":false,"properties":{},"type":"object"}"#,
        )
        .unwrap(),
        Capability::new("tool.records.lookup").unwrap(),
        ToolTimeout::from_millis(10_000).unwrap(),
        ToolCancellation::Cooperative,
        EffectClass::Transactional,
        IdempotencyContract::ExternalTransactionProof,
    )
    .unwrap()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the migration oracle keeps historical fixture construction and preservation assertions together"
)]
async fn migration_from_v15_creates_v16_tool_and_v17_approval_schema_then_enforces_tool_cap() {
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("v15.db");
    let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
        .unwrap()
        .create_if_missing(true)
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::raw_sql(concat!(
        include_str!("../migrations/0001.sql"),
        include_str!("../migrations/0002.sql"),
        include_str!("../migrations/0003.sql"),
        include_str!("../migrations/0004.sql"),
        include_str!("../migrations/0005.sql"),
        include_str!("../migrations/0006.sql"),
        include_str!("../migrations/0007.sql"),
        include_str!("../migrations/0008.sql"),
        include_str!("../migrations/0009.sql"),
        include_str!("../migrations/0010.sql"),
        include_str!("../migrations/0011.sql"),
        include_str!("../migrations/0012.sql"),
        include_str!("../migrations/0013.sql"),
        include_str!("../migrations/0014.sql"),
        include_str!("../migrations/0015.sql")
    ))
    .execute(&mut connection)
    .await
    .unwrap();
    sqlx::query("PRAGMA user_version=15")
        .execute(&mut connection)
        .await
        .unwrap();
    let artifact_session = SessionId::from_uuid(Uuid::from_u128(86_000)).unwrap();
    sqlx::query(
        "INSERT INTO sessions(session_id,consumer_key,compatibility_identity,revision,closed,
         created_at_seconds,created_at_nanos,updated_at_seconds,updated_at_nanos,epoch_high_water,
         observed_time_floor_seconds,observed_time_floor_nanos)
         VALUES(?,?,?,1,0,100,0,100,0,0,100,0)",
    )
    .bind(artifact_session.to_string())
    .bind("migration-artifact-consumer")
    .bind([7_u8; 32].as_slice())
    .execute(&mut connection)
    .await
    .unwrap();
    let artifact_id = ArtifactId::from_uuid(Uuid::from_u128(86_001)).unwrap();
    sqlx::query(
        "INSERT INTO artifacts(artifact_id,session_id,media_type,size,digest,locator,state,revision,
         retention_seconds,retention_nanos,created_seconds,created_nanos)
         VALUES(?,?,?,3,?,?,'available',1,200,0,100,0)",
    )
    .bind(artifact_id.to_string())
    .bind(artifact_session.to_string())
    .bind("application/octet-stream")
    .bind([4_u8; 32].as_slice())
    .bind(format!("migration/{artifact_id}.blob"))
    .execute(&mut connection)
    .await
    .unwrap();
    connection.close().await.unwrap();
    let store = SqliteStore::open(&path).await.unwrap();
    let preserved: (i64, Vec<u8>, String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT size,digest,locator,creator_participant_id,creator_operation_id FROM artifacts WHERE artifact_id=?",
    ).bind(artifact_id.to_string()).fetch_one(store.pool()).await.unwrap();
    assert_eq!(
        preserved,
        (
            3,
            vec![4_u8; 32],
            format!("migration/{artifact_id}.blob"),
            None,
            None
        )
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tool_registrations")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 0, "v15 had no Tool tables or Tool state to migrate");
    for (table, query) in [
        (
            "approval_requests",
            "SELECT COUNT(*) FROM approval_requests",
        ),
        ("approval_grants", "SELECT COUNT(*) FROM approval_grants"),
        (
            "approval_effect_intents",
            "SELECT COUNT(*) FROM approval_effect_intents",
        ),
        (
            "approval_mutations",
            "SELECT COUNT(*) FROM approval_mutations",
        ),
    ] {
        let count: i64 = sqlx::query_scalar(query)
            .fetch_one(store.pool())
            .await
            .unwrap();
        assert_eq!(count, 0, "v15 had no Approval state in {table} to migrate");
    }
    prepare_tool_authority(&store).await;
    for index in 0..navigator_store_api::MAX_TOOL_REGISTRATIONS {
        store
            .register_tool(RegisterTool {
                context: context(84_000 + u128::try_from(index).unwrap(), host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(
                    84_100 + u128::try_from(index).unwrap(),
                ))
                .unwrap(),
                consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                definition: migration_tool_definition(format!("records.migrated{index}")),
            })
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .register_tool(RegisterTool {
                context: context(84_999, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(84_999)).unwrap(),
                consumer_key: ConsumerKey::new("consumer-a").unwrap(),
                definition: migration_tool_definition("records.migrated-overflow"),
            })
            .await,
        Err(StoreError::Invalid)
    );
    store.pool().close().await;
    assert_eq!(migration_state(&path).await.0, 20);
    let reopened = SqliteStore::open(&path).await.unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tool_registrations")
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(count, 64);
}

async fn create_authoritative_v16_fixture(path: &Path, populated_v17: &Path) {
    let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
        .unwrap()
        .create_if_missing(true)
        .foreign_keys(false);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::raw_sql(concat!(
        include_str!("../migrations/0001.sql"),
        include_str!("../migrations/0002.sql"),
        include_str!("../migrations/0003.sql"),
        include_str!("../migrations/0004.sql"),
        include_str!("../migrations/0005.sql"),
        include_str!("../migrations/0006.sql"),
        include_str!("../migrations/0007.sql"),
        include_str!("../migrations/0008.sql"),
        include_str!("../migrations/0009.sql"),
        include_str!("../migrations/0010.sql"),
        include_str!("../migrations/0011.sql"),
        include_str!("../migrations/0012.sql"),
        include_str!("../migrations/0013.sql"),
        include_str!("../migrations/0014.sql"),
        include_str!("../migrations/0015.sql"),
        include_str!("../migrations/0016.sql")
    ))
    .execute(&mut connection)
    .await
    .unwrap();
    sqlx::query("ATTACH DATABASE ? AS populated")
        .bind(populated_v17.to_str().unwrap())
        .execute(&mut connection)
        .await
        .unwrap();
    for table in [
        "sessions",
        "events",
        "request_ledger",
        "launch_attempts",
        "templates",
        "participants",
        "operations",
        "mailbox_counters",
        "authority_policies",
        "authority_grants",
        "authority_template_policies",
        "effect_journal",
        "effect_journal_mutations",
        "recovery_classifications",
        "session_template_manifest",
        "artifacts",
        "tool_registrations",
        "tool_invocations",
        "tool_invocation_mutations",
        "tool_provider_connections",
    ] {
        let statement = format!("INSERT INTO {table} SELECT * FROM populated.{table}");
        sqlx::query(AssertSqlSafe(statement.as_str()))
            .execute(&mut connection)
            .await
            .unwrap();
    }
    connection
        .execute("DETACH DATABASE populated")
        .await
        .unwrap();
    connection.execute("PRAGMA user_version=16").await.unwrap();
    connection.close().await.unwrap();
}

async fn schema_fingerprint(path: &Path) -> Vec<String> {
    let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
        .unwrap()
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    let rows = sqlx::query_scalar(
        "SELECT type||'|'||name||'|'||tbl_name||'|'||coalesce(sql,'') FROM sqlite_master
         WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY type,name",
    )
    .fetch_all(&mut connection)
    .await
    .unwrap();
    connection.close().await.unwrap();
    rows
}

async fn tool_state_fingerprint(path: &Path) -> Vec<String> {
    let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
        .unwrap()
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
    let values = sqlx::query_scalar(
        "SELECT 'registration:'||registration_id||':'||hex(snapshot) FROM tool_registrations
         UNION ALL SELECT 'invocation:'||invocation_id||':'||hex(snapshot) FROM tool_invocations
         UNION ALL SELECT 'mutation:'||request_id||':'||hex(result) FROM tool_invocation_mutations
         UNION ALL SELECT 'provider:'||provider_id||':'||connection_id||':'||generation||':'||acknowledged_server_sequence||':'||next_server_sequence||':'||hex(registrations) FROM tool_provider_connections
         ORDER BY 1",
    )
    .fetch_all(&mut connection)
    .await
    .unwrap();
    connection.close().await.unwrap();
    values
}

#[tokio::test]
async fn v16_to_v17_crash_is_old_or_new_and_preserves_nonempty_tool_state_exactly() {
    for point in MIGRATION_CRASH_POINTS {
        let directory = TempDir::new().unwrap();
        let populated_directory = TempDir::new().unwrap();
        let (store, populated_path, _) = new_store(&populated_directory).await;
        prepare_tool_store(&store).await;
        store
            .reserve_tool_invocation(tool_reserve(88_020, 88_021, host(20), 1, 10))
            .await
            .unwrap();
        store.pool().close().await;
        let path = directory.path().join("authoritative-v16.db");
        create_authoritative_v16_fixture(&path, &populated_path).await;
        let before = tool_state_fingerprint(&path).await;
        assert_eq!(before.len(), 3, "fixture omitted persisted Tool state");
        let old_schema = schema_fingerprint(&path).await;
        assert!(old_schema.iter().all(|line| !line.contains("approval_")));
        let source_preapproval = schema_fingerprint(&populated_path)
            .await
            .into_iter()
            .filter(|line| {
                !line.contains("approval_")
                    && !line.contains("projection_")
                    && !line.contains("capacity_")
                    && !line.contains("subscription_leases")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            old_schema, source_preapproval,
            "historical v16 DDL drifted from pre-Approval schema"
        );
        let expected_path = directory.path().join("expected-v17.db");
        std::fs::copy(&path, &expected_path).unwrap();
        run_crash_worker(&expected_path, "migration", "migration.after_commit");
        let new_schema = schema_fingerprint(&expected_path).await;

        run_crash_worker(&path, "migration", point);
        let committed = *point == "migration.after_commit";
        assert_eq!(
            migration_state(&path).await,
            if committed { (20, 36) } else { (16, 21) }
        );
        assert_eq!(
            schema_fingerprint(&path).await,
            if committed {
                new_schema.clone()
            } else {
                old_schema.clone()
            }
        );
        assert_eq!(
            tool_state_fingerprint(&path).await,
            before,
            "migration changed Tool state at {point}"
        );

        let reopened = SqliteStore::open(&path).await.unwrap();
        assert_eq!(migration_state(&path).await, (20, 36));
        assert_eq!(schema_fingerprint(&path).await, new_schema);
        assert_eq!(tool_state_fingerprint(&path).await, before);
        assert_eq!(
            reopened
                .load_tool_registration(
                    session_id(),
                    ToolRegistrationId::from_uuid(Uuid::from_u128(81_002)).unwrap(),
                )
                .await
                .unwrap()
                .unwrap()
                .definition,
            tool_definition(),
        );
        assert_eq!(
            reopened
                .list_provider_replay(
                    session_id(),
                    ToolProviderId::from_uuid(Uuid::from_u128(81_004)).unwrap(),
                    0,
                )
                .await
                .unwrap()
                .len(),
            1,
        );
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the structural mutant matrix is intentionally explicit and auditable"
)]
async fn approval_schema_structure_mutants_fail_closed_before_use() {
    for mutant in [
        "request-index",
        "grant-index",
        "request-foreign-key",
        "grant-request-unique",
        "mutation-check",
        "mutation-strict",
        "request-index-unique",
        "request-index-partial",
        "foreign-key-action",
        "request-capability-check",
        "request-nanos-check",
        "grant-revoked-check",
        "effect-revision-check",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        store.pool().close().await;
        let options = SqliteConnectOptions::from_str(path.to_str().unwrap())
            .unwrap()
            .foreign_keys(false);
        let mut connection = SqliteConnection::connect_with(&options).await.unwrap();
        match mutant {
            "request-index" => {
                connection
                    .execute("DROP INDEX approval_requests_session_status")
                    .await
                    .unwrap();
            }
            "grant-index" => {
                connection
                    .execute("DROP INDEX approval_grants_session_subject")
                    .await
                    .unwrap();
            }
            "request-index-unique" | "request-index-partial" => {
                connection
                    .execute("DROP INDEX approval_requests_session_status")
                    .await
                    .unwrap();
                connection.execute(if mutant == "request-index-unique" {
                    "CREATE UNIQUE INDEX approval_requests_session_status ON approval_requests(session_id,status,approval_id)"
                } else {
                    "CREATE INDEX approval_requests_session_status ON approval_requests(session_id,status,approval_id) WHERE status='pending'"
                }).await.unwrap();
            }
            value => {
                connection
                    .execute("PRAGMA writable_schema=ON")
                    .await
                    .unwrap();
                let (from, to) = match value {
                    "request-foreign-key" => (
                        "requester_id TEXT NOT NULL REFERENCES participants(participant_id)",
                        "requester_id TEXT NOT NULL",
                    ),
                    "grant-request-unique" => (
                        "approval_id TEXT UNIQUE NOT NULL REFERENCES approval_requests(approval_id)",
                        "approval_id TEXT NOT NULL REFERENCES approval_requests(approval_id)",
                    ),
                    "mutation-check" => (
                        "semantic_digest BLOB NOT NULL CHECK(length(semantic_digest) = 32)",
                        "semantic_digest BLOB NOT NULL",
                    ),
                    "mutation-strict" => (") STRICT", ")"),
                    "foreign-key-action" => (
                        "requester_id TEXT NOT NULL REFERENCES participants(participant_id)",
                        "requester_id TEXT NOT NULL REFERENCES participants(participant_id) ON DELETE CASCADE",
                    ),
                    "request-capability-check" => (
                        "capability TEXT NOT NULL CHECK(length(capability) BETWEEN 1 AND 128)",
                        "capability TEXT NOT NULL",
                    ),
                    "request-nanos-check" => (
                        "expires_nanos INTEGER NOT NULL CHECK(expires_nanos BETWEEN 0 AND 999999999)",
                        "expires_nanos INTEGER NOT NULL",
                    ),
                    "grant-revoked-check" => (
                        "revoked INTEGER NOT NULL CHECK(revoked IN (0,1))",
                        "revoked INTEGER NOT NULL",
                    ),
                    "effect-revision-check" => (
                        "revision INTEGER NOT NULL CHECK(revision > 0)",
                        "revision INTEGER NOT NULL",
                    ),
                    _ => unreachable!(),
                };
                let table = if matches!(
                    value,
                    "request-foreign-key"
                        | "foreign-key-action"
                        | "request-capability-check"
                        | "request-nanos-check"
                ) {
                    "approval_requests"
                } else if matches!(value, "grant-request-unique" | "grant-revoked-check") {
                    "approval_grants"
                } else if value == "effect-revision-check" {
                    "approval_effect_intents"
                } else {
                    "approval_mutations"
                };
                sqlx::query(
                    "UPDATE sqlite_master SET sql=replace(sql,?,?) WHERE type='table' AND name=?",
                )
                .bind(from)
                .bind(to)
                .bind(table)
                .execute(&mut connection)
                .await
                .unwrap();
                connection
                    .execute("PRAGMA schema_version=200")
                    .await
                    .unwrap();
            }
        }
        connection.close().await.unwrap();
        assert_eq!(
            SqliteStore::open_with_clock(
                &path,
                clock,
                LeaseDuration::from_millis(60_000).unwrap(),
            )
            .await
            .unwrap_err(),
            StoreError::Corrupt,
            "approval schema mutant remained trusted: {mutant}",
        );
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the complete Approval history fixture is intentionally visible in one place"
)]
async fn prepare_raw_approval_rows(store: &SqliteStore) {
    prepare_running_effect_operation(store).await;
    let resource = ApprovalResource::new(br#"{"branch":"main","repository":"navigator"}"#).unwrap();
    let pending = ApprovalRequest {
        id: ApprovalRequestId::from_uuid(Uuid::from_u128(89_001)).unwrap(),
        session_id: session_id(),
        requester_id: participant_command().participant_id,
        operation_id: start_operation_command().operation_id,
        source_message_id: start_operation_command().input_message_id,
        source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
        coordinator_id: participant_command().participant_id,
        capability: Capability::new("repository.publish").unwrap(),
        resource: resource.clone(),
        summary: ApprovalSummary::new("publish exact revision").unwrap(),
        status: ApprovalStatus::Pending,
        expires_at: Timestamp::new(200, 0).unwrap(),
        grant_id: None,
        decision_source: None,
        created_at: Timestamp::new(100, 0).unwrap(),
        decided_at: None,
        revision: Revision::initial(),
    };
    let grant_id = GrantId::from_uuid(Uuid::from_u128(89_002)).unwrap();
    let mut request = pending.clone();
    request.status = ApprovalStatus::Granted;
    request.grant_id = Some(grant_id);
    request.decision_source = Some(ApprovalDecisionSource::TrustedConsumer);
    request.decided_at = Some(Timestamp::new(100, 0).unwrap());
    request.revision = request.revision.next().unwrap();
    let grant = ApprovalGrant {
        id: grant_id,
        request_id: request.id,
        session_id: request.session_id,
        subject_id: request.requester_id,
        operation_id: request.operation_id,
        capability: request.capability.clone(),
        resource_hash: resource.digest(),
        issued_by: ApprovalDecisionSource::TrustedConsumer,
        max_uses: 1,
        used_count: 1,
        expires_at: Timestamp::new(190, 0).unwrap(),
        revoked_at: None,
        created_at: Timestamp::new(100, 0).unwrap(),
        revision: Revision::new(2).unwrap(),
    };
    let effect = ApprovalEffectIntent {
        effect_id: RequestId::from_uuid(Uuid::from_u128(89_003)).unwrap(),
        session_id: request.session_id,
        grant_id,
        subject_id: request.requester_id,
        operation_id: request.operation_id,
        capability: request.capability.clone(),
        resource_hash: resource.digest(),
        phase: ApprovalEffectPhase::Reserved,
        created_at: Timestamp::new(100, 0).unwrap(),
        finished_at: None,
        revision: Revision::initial(),
    };
    sqlx::query("INSERT INTO approval_requests(approval_id,session_id,requester_id,operation_id,capability,resource_hash,status,expires_seconds,expires_nanos,revision,snapshot) VALUES(?,?,?,?,?,?,'granted',200,0,2,?)")
        .bind(request.id.to_string()).bind(request.session_id.to_string()).bind(request.requester_id.to_string())
        .bind(request.operation_id.to_string()).bind(request.capability.as_str()).bind(resource.digest().as_bytes().as_slice())
        .bind(serde_json::to_vec(&request).unwrap()).execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO approval_grants(grant_id,approval_id,session_id,subject_id,operation_id,capability,resource_hash,max_uses,used_count,expires_seconds,expires_nanos,revoked,revision,snapshot) VALUES(?,?,?,?,?,?,?,1,1,190,0,0,2,?)")
        .bind(grant.id.to_string()).bind(grant.request_id.to_string()).bind(grant.session_id.to_string()).bind(grant.subject_id.to_string())
        .bind(grant.operation_id.to_string()).bind(grant.capability.as_str()).bind(grant.resource_hash.as_bytes().as_slice())
        .bind(serde_json::to_vec(&grant).unwrap()).execute(store.pool()).await.unwrap();
    sqlx::query("INSERT INTO approval_effect_intents(effect_id,session_id,grant_id,operation_id,phase,revision,snapshot) VALUES(?,?,?,?,'reserved',1,?)")
        .bind(effect.effect_id.to_string()).bind(effect.session_id.to_string()).bind(effect.grant_id.to_string()).bind(effect.operation_id.to_string())
        .bind(serde_json::to_vec(&effect).unwrap()).execute(store.pool()).await.unwrap();
    let mut relay_tx = store.pool().begin().await.unwrap();
    crate::store::approval_insert_decision_relay(
        &mut relay_tx,
        RequestId::from_uuid(Uuid::from_u128(89_005)).unwrap(),
        &request,
        Timestamp::new(100, 0).unwrap(),
    )
    .await
    .unwrap();
    relay_tx.commit().await.unwrap();
    sqlx::query("INSERT INTO approval_mutations(request_id,session_id,caller_host_id,action,semantic_digest,result) VALUES(?,?,?,'approval.request',?,?)")
        .bind(RequestId::from_uuid(Uuid::from_u128(89_004)).unwrap().to_string()).bind(request.session_id.to_string()).bind(host(20).to_string())
        .bind(SemanticDigest::v1(&Capability::new("approval.request").unwrap(), b"fixture").as_bytes().as_slice())
        .bind(serde_json::to_vec(&pending).unwrap()).execute(store.pool()).await.unwrap();
    let approved = navigator_store_api::ApprovedRequest {
        request: request.clone(),
        grant: grant.clone(),
    };
    let consumed = navigator_store_api::ConsumedApprovalGrant {
        grant: grant.clone(),
        effect: effect.clone(),
    };
    let mut revoked = grant.clone();
    revoked.revoked_at = Some(Timestamp::new(110, 0).unwrap());
    let mut finished = effect.clone();
    finished.phase = ApprovalEffectPhase::Succeeded;
    finished.finished_at = Some(Timestamp::new(110, 0).unwrap());
    for (offset, action, result) in [
        (
            5_u128,
            "approval.approve",
            serde_json::to_vec(&approved).unwrap(),
        ),
        (6, "approval.revoke", serde_json::to_vec(&revoked).unwrap()),
        (
            7,
            "approval.consume",
            serde_json::to_vec(&consumed).unwrap(),
        ),
        (
            8,
            "approval.effect.finish",
            serde_json::to_vec(&finished).unwrap(),
        ),
    ] {
        sqlx::query("INSERT INTO approval_mutations(request_id,session_id,caller_host_id,action,semantic_digest,result) VALUES(?,?,?,?,?,?)")
            .bind(RequestId::from_uuid(Uuid::from_u128(89_000 + offset)).unwrap().to_string())
            .bind(request.session_id.to_string()).bind(host(20).to_string()).bind(action)
            .bind(SemanticDigest::v1(&Capability::new(action).unwrap(), b"fixture").as_bytes().as_slice())
            .bind(result).execute(store.pool()).await.unwrap();
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "end-to-end Approval lifecycle oracle keeps every durable surface visible"
)]
async fn approval_lifecycle_is_atomic_bounded_and_replays_without_refund() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let resource = ApprovalResource::new(br#"{"branch":"main"}"#).unwrap();
    let approval_id = ApprovalRequestId::from_uuid(Uuid::from_u128(91_001)).unwrap();
    let request = RequestApproval {
        context: context(91_010, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        approval_id,
        requester_id: participant_command().participant_id,
        operation_id: start_operation_command().operation_id,
        source_message_id: start_operation_command().input_message_id,
        source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
        capability: Capability::new("repository.publish").unwrap(),
        resource: resource.clone(),
        summary: ApprovalSummary::new("publish main").unwrap(),
        expires_at: Timestamp::new(200, 0).unwrap(),
    };
    let mut prior_collision = request.clone();
    prior_collision.context = context(80_000, host(20));
    assert!(matches!(
        store.request_approval(prior_collision).await,
        Err(StoreError::RequestConflict { .. })
    ));
    assert!(matches!(
        store.request_approval(request.clone()).await.unwrap(),
        Mutation::Applied(_)
    ));
    assert!(matches!(
        store.request_approval(request).await.unwrap(),
        Mutation::Replayed(_)
    ));
    assert!(matches!(
        store.open_session(open_command(91_010)).await,
        Err(StoreError::RequestConflict { .. })
    ));
    let grant_id = GrantId::from_uuid(Uuid::from_u128(91_002)).unwrap();
    let approve = ApproveRequest {
        context: context(91_011, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        approval_id,
        expected_revision: Revision::initial(),
        grant_id,
        grant_expires_at: Timestamp::new(190, 0).unwrap(),
        max_uses: 2,
    };
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM approval_grants")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let mut invalid = approve.clone();
    invalid.max_uses = 0;
    assert_eq!(
        store.approve_request(invalid).await,
        Err(StoreError::Invalid)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM approval_grants")
            .fetch_one(store.pool())
            .await
            .unwrap(),
        before
    );
    let approved = store
        .approve_request(approve)
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(approved.grant.used_count, 0);
    let consume = |request_id: u128, effect_id: u128, revision: u64| ConsumeApprovalGrant {
        context: context(request_id, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        grant_id,
        expected_revision: Revision::new(revision).unwrap(),
        effect_id: RequestId::from_uuid(Uuid::from_u128(effect_id)).unwrap(),
        subject_id: approved.grant.subject_id,
        operation_id: approved.grant.operation_id,
        capability: approved.grant.capability.clone(),
        resource_hash: resource.digest(),
    };
    let first_command = consume(91_012, 91_020, 1);
    assert!(matches!(
        store
            .consume_approval_grant(consume(91_019, 80_000, 1))
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
    assert!(matches!(
        store
            .consume_approval_grant(consume(91_018, 91_018, 1))
            .await,
        Err(StoreError::RequestConflict { .. })
    ));
    let first = store
        .consume_approval_grant(first_command.clone())
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(first.grant.used_count, 1);
    assert_eq!(
        store
            .list_reserved_approval_effects(session_id())
            .await
            .unwrap(),
        vec![first.effect.clone()]
    );
    let replay_a = store.clone();
    let replay_b = store.clone();
    let command_a = first_command.clone();
    let command_b = first_command.clone();
    let (a, b) = tokio::join!(
        replay_a.consume_approval_grant(command_a),
        replay_b.consume_approval_grant(command_b)
    );
    assert!(matches!(a.unwrap(), Mutation::Replayed(_)));
    assert!(matches!(b.unwrap(), Mutation::Replayed(_)));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM approval_effect_intents WHERE effect_id=?"
        )
        .bind(first.effect.effect_id.to_string())
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );
    assert!(matches!(
        store.open_session(open_command(91_020)).await,
        Err(StoreError::RequestConflict { .. })
    ));
    assert_eq!(
        store
            .load_approval_request(approval_id)
            .await
            .unwrap()
            .status,
        ApprovalStatus::Granted
    );
    let second = store
        .consume_approval_grant(consume(91_013, 91_021, 2))
        .await
        .unwrap()
        .value()
        .clone();
    assert_eq!(
        store
            .list_reserved_approval_effects(session_id())
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(second.grant.used_count, 2);
    assert_eq!(
        store
            .load_approval_request(approval_id)
            .await
            .unwrap()
            .status,
        ApprovalStatus::Consumed
    );
    let replay = store.consume_approval_grant(first_command).await.unwrap();
    assert!(matches!(replay, Mutation::Replayed(_)));
    assert_eq!(replay.value().grant.used_count, 1);
    assert_eq!(
        store
            .load_approval_grant(grant_id)
            .await
            .unwrap()
            .used_count,
        2
    );
    let finished = store
        .finish_approval_effect(FinishApprovalEffect {
            context: context(91_014, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            effect_id: first.effect.effect_id,
            expected_revision: Revision::initial(),
            phase: TerminalApprovalEffectPhase::Succeeded,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .list_reserved_approval_effects(session_id())
            .await
            .unwrap(),
        vec![second.effect.clone()]
    );
    assert_eq!(finished.value().phase, ApprovalEffectPhase::Succeeded);
    let audit: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT data FROM events WHERE event_type LIKE 'approval.%' ORDER BY position",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(audit.len(), 5);
    for data in audit {
        let text = String::from_utf8(data.clone()).unwrap();
        assert!(
            !text.contains("publish main") && !text.contains("branch") && !text.contains("main")
        );
        let value: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert!(
            value["approval_id"].is_string()
                || value["grant_id"].is_string()
                || value["effect_id"].is_string()
        );
    }
    let rows = sqlx::query("SELECT event_id,event_type,related_request_id,data FROM events WHERE event_type LIKE 'approval.%' ORDER BY position")
        .fetch_all(store.pool()).await.unwrap();
    let expected = [
        (
            "approval.requested",
            91_010_u128,
            Some(approval_id.to_string()),
            None,
            None,
        ),
        (
            "approval.granted",
            91_011,
            Some(approval_id.to_string()),
            Some(grant_id.to_string()),
            None,
        ),
        (
            "approval.consumed",
            91_012,
            Some(approval_id.to_string()),
            Some(grant_id.to_string()),
            Some(first.effect.effect_id.to_string()),
        ),
        (
            "approval.consumed",
            91_013,
            Some(approval_id.to_string()),
            Some(grant_id.to_string()),
            Some(second.effect.effect_id.to_string()),
        ),
        (
            "approval.effect.finished",
            91_014,
            Some(approval_id.to_string()),
            Some(grant_id.to_string()),
            Some(first.effect.effect_id.to_string()),
        ),
    ];
    for (row, (event_type, request_number, approval, grant, effect)) in rows.iter().zip(expected) {
        let related = RequestId::from_uuid(Uuid::from_u128(request_number)).unwrap();
        assert_eq!(row.get::<String, _>("event_type"), event_type);
        assert_eq!(
            row.get::<String, _>("related_request_id"),
            related.to_string()
        );
        let mut input = related.as_uuid().as_bytes().to_vec();
        input.extend_from_slice(event_type.as_bytes());
        let mut bytes: [u8; 16] =
            SemanticDigest::v1(&Capability::new("event.identity.v1").unwrap(), &input).as_bytes()
                [..16]
                .try_into()
                .unwrap();
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        assert_eq!(
            row.get::<String, _>("event_id"),
            Uuid::from_bytes(bytes).to_string()
        );
        let data: serde_json::Value =
            serde_json::from_slice(&row.get::<Vec<u8>, _>("data")).unwrap();
        assert_eq!(data["approval_id"].as_str(), approval.as_deref());
        assert_eq!(data["grant_id"].as_str(), grant.as_deref());
        assert_eq!(data["effect_id"].as_str(), effect.as_deref());
    }
    let trace = TraceRecorder::default();
    let trace_fields = trace.0.clone();
    let trace_guard = tracing::subscriber::set_default(trace);
    store.rebuild_projection(session_id()).await.unwrap();
    drop(trace_guard);
    let approval_page = store
        .read_projection(ReadProjection {
            session_id: session_id(),
            consumer: ConsumerKey::new("consumer-a").unwrap(),
            view: ProjectionView::Approval,
            page_size: ProjectionPageSize::new(128).unwrap(),
            page_token: None,
        })
        .await
        .unwrap();
    assert_eq!(approval_page.items.len(), 1);
    let projected = String::from_utf8(approval_page.items[0].data.as_slice().to_vec()).unwrap();
    assert!(!projected.contains("publish main"));
    let rendered_trace = trace_fields.lock().unwrap().join("\n");
    assert!(!rendered_trace.contains("publish main"));
    assert!(!format!("{:?}", StoreError::Corrupt).contains("publish main"));

    let granted_data: Vec<u8> = sqlx::query_scalar(
        "SELECT data FROM events WHERE session_id=? AND event_type='approval.granted'",
    )
    .bind(session_id().to_string())
    .fetch_one(store.pool())
    .await
    .unwrap();
    let mut gap: serde_json::Value = serde_json::from_slice(&granted_data).unwrap();
    gap["request_revision"] = serde_json::json!(99);
    sqlx::query("UPDATE events SET data=? WHERE session_id=? AND event_type='approval.granted'")
        .bind(serde_json::to_vec(&gap).unwrap())
        .bind(session_id().to_string())
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE projection_heads SET checkpoint_position=checkpoint_position-1,source_head_position=source_head_position-1 WHERE session_id=?")
        .bind(session_id().to_string()).execute(store.pool()).await.unwrap();
    assert_eq!(
        store.rebuild_projection(session_id()).await,
        Err(StoreError::Corrupt)
    );
    sqlx::query("UPDATE events SET data=? WHERE session_id=? AND event_type='approval.granted'")
        .bind(granted_data)
        .bind(session_id().to_string())
        .execute(store.pool())
        .await
        .unwrap();

    let finished_data: Vec<u8> = sqlx::query_scalar(
        "SELECT data FROM events WHERE session_id=? AND event_type='approval.effect.finished'",
    )
    .bind(session_id().to_string())
    .fetch_one(store.pool())
    .await
    .unwrap();
    let mut forged: serde_json::Value = serde_json::from_slice(&finished_data).unwrap();
    forged["effect_id"] = serde_json::json!(Uuid::from_u128(999_999).to_string());
    sqlx::query(
        "UPDATE events SET data=? WHERE session_id=? AND event_type='approval.effect.finished'",
    )
    .bind(serde_json::to_vec(&forged).unwrap())
    .bind(session_id().to_string())
    .execute(store.pool())
    .await
    .unwrap();
    assert_eq!(
        store.rebuild_projection(session_id()).await,
        Err(StoreError::Corrupt)
    );
}

#[tokio::test]
async fn concurrent_final_approval_use_commits_exactly_one_intent() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let resource = ApprovalResource::new(br#"{"branch":"main"}"#).unwrap();
    let approval_id = ApprovalRequestId::from_uuid(Uuid::from_u128(92_001)).unwrap();
    store
        .request_approval(RequestApproval {
            context: context(92_010, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id,
            requester_id: participant_command().participant_id,
            operation_id: start_operation_command().operation_id,
            source_message_id: start_operation_command().input_message_id,
            source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
            capability: Capability::new("repository.publish").unwrap(),
            resource: resource.clone(),
            summary: ApprovalSummary::new("one use").unwrap(),
            expires_at: Timestamp::new(200, 0).unwrap(),
        })
        .await
        .unwrap();
    let grant_id = GrantId::from_uuid(Uuid::from_u128(92_002)).unwrap();
    let approved = store
        .approve_request(ApproveRequest {
            context: context(92_011, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id,
            expected_revision: Revision::initial(),
            grant_id,
            grant_expires_at: Timestamp::new(190, 0).unwrap(),
            max_uses: 1,
        })
        .await
        .unwrap()
        .value()
        .clone();
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for index in 0_u128..2 {
        let store = store.clone();
        let barrier = barrier.clone();
        let capability = approved.grant.capability.clone();
        let hash = resource.digest();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .consume_approval_grant(ConsumeApprovalGrant {
                    context: context(92_020 + index, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    grant_id,
                    expected_revision: Revision::initial(),
                    effect_id: RequestId::from_uuid(Uuid::from_u128(92_030 + index)).unwrap(),
                    subject_id: participant_command().participant_id,
                    operation_id: start_operation_command().operation_id,
                    capability,
                    resource_hash: hash,
                })
                .await
        }));
    }
    barrier.wait().await;
    let mut applied = 0;
    for task in tasks {
        if task.await.unwrap().is_ok() {
            applied += 1;
        }
    }
    assert_eq!(applied, 1);
    assert_eq!(
        store
            .load_approval_grant(grant_id)
            .await
            .unwrap()
            .used_count,
        1
    );
    assert_eq!(
        store
            .load_approval_request(approval_id)
            .await
            .unwrap()
            .status,
        ApprovalStatus::Consumed
    );
    let intents: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM approval_effect_intents WHERE grant_id=?")
            .bind(grant_id.to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(intents, 1);
}

#[tokio::test]
async fn approval_temporal_rejection_persists_floor_across_regression_and_reopen() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let approval_id = ApprovalRequestId::from_uuid(Uuid::from_u128(93_001)).unwrap();
    let resource = ApprovalResource::new(br#"{"branch":"main"}"#).unwrap();
    store
        .request_approval(RequestApproval {
            context: context(93_010, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id,
            requester_id: participant_command().participant_id,
            operation_id: start_operation_command().operation_id,
            source_message_id: start_operation_command().input_message_id,
            source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
            capability: Capability::new("repository.publish").unwrap(),
            resource,
            summary: ApprovalSummary::new("expires at boundary").unwrap(),
            expires_at: Timestamp::new(105, 0).unwrap(),
        })
        .await
        .unwrap();
    let approve = ApproveRequest {
        context: context(93_011, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        approval_id,
        expected_revision: Revision::initial(),
        grant_id: GrantId::from_uuid(Uuid::from_u128(93_002)).unwrap(),
        grant_expires_at: Timestamp::new(105, 0).unwrap(),
        max_uses: 1,
    };
    clock.set(105);
    assert_eq!(
        store.approve_request(approve.clone()).await,
        Err(StoreError::Invalid)
    );
    clock.set(100);
    assert_eq!(
        store.approve_request(approve.clone()).await,
        Err(StoreError::Invalid)
    );
    store.pool().close().await;
    let reopened =
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    assert_eq!(
        reopened.approve_request(approve).await,
        Err(StoreError::Invalid)
    );
    assert_eq!(
        reopened
            .load_approval_request(approval_id)
            .await
            .unwrap()
            .status,
        ApprovalStatus::Pending
    );
}

const APPROVAL_CRASH_POINTS: [&str; 8] = [
    "approval.after_row_write",
    "approval.after_relay_message",
    "approval.after_relay_counter",
    "approval.before_ledger_write",
    "approval.after_ledger_write",
    "approval.after_audit_write",
    "approval.before_commit",
    "approval.after_commit",
];

async fn prepare_pending_approval_crash_fixture(
    store: &SqliteStore,
    base: u128,
    expires_at: i64,
) -> ApprovalRequestId {
    prepare_running_effect_operation(store).await;
    let approval_id = ApprovalRequestId::from_uuid(Uuid::from_u128(base + 1)).unwrap();
    store
        .request_approval(RequestApproval {
            context: context(base + 10, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id,
            requester_id: participant_command().participant_id,
            operation_id: start_operation_command().operation_id,
            source_message_id: start_operation_command().input_message_id,
            source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
            capability: Capability::new("repository.publish").unwrap(),
            resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
            summary: ApprovalSummary::new("approval crash fixture").unwrap(),
            expires_at: Timestamp::new(expires_at, 0).unwrap(),
        })
        .await
        .unwrap();
    approval_id
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "each Approval crash shape retains an explicit exact replay oracle"
)]
async fn approval_mutation_crash_matrix_is_atomic_and_exactly_replayable() {
    for operation in [
        "approval-request",
        "approval-deny",
        "approval-expire",
        "approval-revoke",
        "approval-consume",
        "approval-finish",
    ] {
        for point in APPROVAL_CRASH_POINTS {
            if operation != "approval-deny"
                && matches!(
                    point,
                    "approval.after_relay_message" | "approval.after_relay_counter"
                )
            {
                continue;
            }
            if !fault_matrix_point_selected(point) {
                continue;
            }
            let directory = TempDir::new().unwrap();
            let (store, path, _) = new_store(&directory).await;
            match operation {
                "approval-request" => prepare_running_effect_operation(&store).await,
                "approval-deny" => {
                    prepare_pending_approval_crash_fixture(&store, 94_200, 300).await;
                }
                "approval-expire" => {
                    prepare_pending_approval_crash_fixture(&store, 94_300, 150).await;
                }
                "approval-revoke" => {
                    approved_race_fixture(&store, 94_400, 2).await;
                }
                "approval-consume" => {
                    approved_race_fixture(&store, 94_500, 1).await;
                }
                "approval-finish" => {
                    let (_, grant_id, resource) = approved_race_fixture(&store, 94_600, 1).await;
                    store
                        .consume_approval_grant(ConsumeApprovalGrant {
                            context: context(94_620, host(20)),
                            session_id: session_id(),
                            owner_epoch: FencingEpoch::new(1).unwrap(),
                            grant_id,
                            expected_revision: Revision::initial(),
                            effect_id: RequestId::from_uuid(Uuid::from_u128(94_630)).unwrap(),
                            subject_id: participant_command().participant_id,
                            operation_id: start_operation_command().operation_id,
                            capability: Capability::new("repository.publish").unwrap(),
                            resource_hash: resource.digest(),
                        })
                        .await
                        .unwrap();
                }
                _ => unreachable!(),
            }
            store.pool().close().await;

            run_crash_worker(&path, operation, point);
            let reopened = SqliteStore::open_with_clock(
                &path,
                Arc::new(TestClock::new(if operation == "approval-expire" {
                    150
                } else {
                    100
                })),
                LeaseDuration::from_millis(60_000).unwrap(),
            )
            .await
            .unwrap();
            assert_integrity(&reopened).await;
            let committed = point == "approval.after_commit";

            let replayed = match operation {
                "approval-request" => matches!(
                    reopened
                        .request_approval(RequestApproval {
                            context: context(94_110, host(20)),
                            session_id: session_id(),
                            owner_epoch: FencingEpoch::new(1).unwrap(),
                            approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(94_101))
                                .unwrap(),
                            requester_id: participant_command().participant_id,
                            operation_id: start_operation_command().operation_id,
                            source_message_id: start_operation_command().input_message_id,
                            source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
                            capability: Capability::new("repository.publish").unwrap(),
                            resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
                            summary: ApprovalSummary::new("request crash atomic").unwrap(),
                            expires_at: Timestamp::new(300, 0).unwrap(),
                        })
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                ),
                "approval-deny" => matches!(
                    reopened
                        .deny_request(DenyRequest {
                            context: context(94_211, host(20)),
                            session_id: session_id(),
                            owner_epoch: FencingEpoch::new(1).unwrap(),
                            approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(94_201))
                                .unwrap(),
                            expected_revision: Revision::initial(),
                        })
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                ),
                "approval-expire" => matches!(
                    reopened
                        .expire_approval(ExpireApproval {
                            context: context(94_311, host(20)),
                            session_id: session_id(),
                            owner_epoch: FencingEpoch::new(1).unwrap(),
                            approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(94_301))
                                .unwrap(),
                            expected_revision: Revision::initial(),
                        })
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                ),
                "approval-revoke" => matches!(
                    reopened
                        .revoke_approval_grant(RevokeApprovalGrant {
                            context: context(94_420, host(20)),
                            session_id: session_id(),
                            owner_epoch: FencingEpoch::new(1).unwrap(),
                            grant_id: GrantId::from_uuid(Uuid::from_u128(94_402)).unwrap(),
                            expected_revision: Revision::initial(),
                        })
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                ),
                "approval-consume" => matches!(
                    reopened
                        .consume_approval_grant(ConsumeApprovalGrant {
                            context: context(94_520, host(20)),
                            session_id: session_id(),
                            owner_epoch: FencingEpoch::new(1).unwrap(),
                            grant_id: GrantId::from_uuid(Uuid::from_u128(94_502)).unwrap(),
                            expected_revision: Revision::initial(),
                            effect_id: RequestId::from_uuid(Uuid::from_u128(94_530)).unwrap(),
                            subject_id: participant_command().participant_id,
                            operation_id: start_operation_command().operation_id,
                            capability: Capability::new("repository.publish").unwrap(),
                            resource_hash: ApprovalResource::new(br#"{"branch":"main"}"#)
                                .unwrap()
                                .digest(),
                        })
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                ),
                "approval-finish" => matches!(
                    reopened
                        .finish_approval_effect(FinishApprovalEffect {
                            context: context(94_640, host(20)),
                            session_id: session_id(),
                            owner_epoch: FencingEpoch::new(1).unwrap(),
                            effect_id: RequestId::from_uuid(Uuid::from_u128(94_630)).unwrap(),
                            expected_revision: Revision::initial(),
                            phase: TerminalApprovalEffectPhase::Succeeded,
                        })
                        .await
                        .unwrap(),
                    Mutation::Replayed(_)
                ),
                _ => unreachable!(),
            };
            assert_eq!(replayed, committed, "{operation} at {point}");

            let (action, event, row_query) = match operation {
                "approval-request" => (
                    "approval.request",
                    "approval.requested",
                    "SELECT COUNT(*) FROM approval_requests WHERE approval_id='00000000-0000-0000-0000-000000016f95'",
                ),
                "approval-deny" => (
                    "approval.deny",
                    "approval.denied",
                    "SELECT COUNT(*) FROM approval_requests WHERE status='denied' AND approval_id='00000000-0000-0000-0000-000000016ff9'",
                ),
                "approval-expire" => (
                    "approval.expire",
                    "approval.expired",
                    "SELECT COUNT(*) FROM approval_requests WHERE status='expired' AND approval_id='00000000-0000-0000-0000-00000001705d'",
                ),
                "approval-revoke" => (
                    "approval.revoke",
                    "approval.revoked",
                    "SELECT COUNT(*) FROM approval_grants WHERE revoked=1 AND grant_id='00000000-0000-0000-0000-0000000170c2'",
                ),
                "approval-consume" => (
                    "approval.consume",
                    "approval.consumed",
                    "SELECT COUNT(*) FROM approval_effect_intents WHERE effect_id='00000000-0000-0000-0000-000000017142'",
                ),
                "approval-finish" => (
                    "approval.effect.finish",
                    "approval.effect.finished",
                    "SELECT COUNT(*) FROM approval_effect_intents WHERE phase='succeeded' AND effect_id='00000000-0000-0000-0000-0000000171a6'",
                ),
                _ => unreachable!(),
            };
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM approval_mutations WHERE action=?"
                )
                .bind(action)
                .fetch_one(reopened.pool())
                .await
                .unwrap(),
                1,
                "{operation} mutation at {point}"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events WHERE event_type=?")
                    .bind(event)
                    .fetch_one(reopened.pool())
                    .await
                    .unwrap(),
                1,
                "{operation} event at {point}"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>(row_query)
                    .fetch_one(reopened.pool())
                    .await
                    .unwrap(),
                1,
                "{operation} row effect at {point}"
            );
            if operation == "approval-deny" {
                assert_eq!(
                    sqlx::query_scalar::<_, i64>(
                        "SELECT COUNT(*) FROM messages WHERE snapshot LIKE '%approval_decision%'"
                    )
                    .fetch_one(reopened.pool())
                    .await
                    .unwrap(),
                    1
                );
                assert_eq!(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events WHERE event_type='message.enqueued' AND related_request_id=?").bind(RequestId::from_uuid(Uuid::from_u128(94_211)).unwrap().to_string()).fetch_one(reopened.pool()).await.unwrap(), 1);
            }
            write_durable_fault_result(
                point,
                committed,
                observe_durable_fault_facts(
                    &reopened,
                    replayed == committed,
                    replayed == committed,
                )
                .await,
                serde_json::json!({"area":"approval","operation":operation,"replayed":replayed}),
            );
        }
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "crash oracle asserts every durable relay surface"
)]
async fn approval_approve_crash_is_prior_or_fully_committed_and_replayable() {
    for point in [
        "approval.after_row_write",
        "approval.after_relay_message",
        "approval.after_relay_counter",
        "approval.before_ledger_write",
        "approval.after_ledger_write",
        "approval.after_audit_write",
        "approval.before_commit",
        "approval.after_commit",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, _) = new_store(&directory).await;
        prepare_running_effect_operation(&store).await;
        let approval_id = ApprovalRequestId::from_uuid(Uuid::from_u128(94_001)).unwrap();
        store
            .request_approval(RequestApproval {
                context: context(94_010, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                approval_id,
                requester_id: participant_command().participant_id,
                operation_id: start_operation_command().operation_id,
                source_message_id: start_operation_command().input_message_id,
                source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
                capability: Capability::new("repository.publish").unwrap(),
                resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
                summary: ApprovalSummary::new("crash atomic").unwrap(),
                expires_at: Timestamp::new(200, 0).unwrap(),
            })
            .await
            .unwrap();
        store.pool().close().await;
        run_crash_worker(&path, "approval-approve", point);
        let reopened = SqliteStore::open_with_clock(
            &path,
            Arc::new(TestClock::new(100)),
            LeaseDuration::from_millis(60_000).unwrap(),
        )
        .await
        .unwrap();
        let committed = point == "approval.after_commit";
        assert_eq!(
            reopened
                .load_approval_request(approval_id)
                .await
                .unwrap()
                .status,
            if committed {
                ApprovalStatus::Granted
            } else {
                ApprovalStatus::Pending
            }
        );
        let retry = reopened
            .approve_request(ApproveRequest {
                context: context(94_011, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                approval_id,
                expected_revision: Revision::initial(),
                grant_id: GrantId::from_uuid(Uuid::from_u128(94_002)).unwrap(),
                grant_expires_at: Timestamp::new(190, 0).unwrap(),
                max_uses: 1,
            })
            .await
            .unwrap();
        assert_eq!(matches!(retry, Mutation::Replayed(_)), committed);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM approval_grants")
                .fetch_one(reopened.pool())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM approval_mutations WHERE action='approval.approve'"
            )
            .fetch_one(reopened.pool())
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM events WHERE event_type='approval.granted'"
            )
            .fetch_one(reopened.pool())
            .await
            .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM messages WHERE snapshot LIKE '%approval_decision%'"
            )
            .fetch_one(reopened.pool())
            .await
            .unwrap(),
            1
        );
        assert_eq!(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events WHERE event_type='message.enqueued' AND related_request_id=?").bind(RequestId::from_uuid(Uuid::from_u128(94_011)).unwrap().to_string()).fetch_one(reopened.pool()).await.unwrap(), 1);
    }
}

#[tokio::test]
async fn concurrent_approve_and_deny_commit_exactly_one_terminal_decision() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let approval_id = ApprovalRequestId::from_uuid(Uuid::from_u128(95_001)).unwrap();
    store
        .request_approval(RequestApproval {
            context: context(95_010, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id,
            requester_id: participant_command().participant_id,
            operation_id: start_operation_command().operation_id,
            source_message_id: start_operation_command().input_message_id,
            source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
            capability: Capability::new("repository.publish").unwrap(),
            resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
            summary: ApprovalSummary::new("race decision").unwrap(),
            expires_at: Timestamp::new(200, 0).unwrap(),
        })
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let approve_store = store.clone();
    let deny_store = store.clone();
    let a = barrier.clone();
    let b = barrier.clone();
    let approve = tokio::spawn(async move {
        a.wait().await;
        approve_store
            .approve_request(ApproveRequest {
                context: context(95_011, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                approval_id,
                expected_revision: Revision::initial(),
                grant_id: GrantId::from_uuid(Uuid::from_u128(95_002)).unwrap(),
                grant_expires_at: Timestamp::new(190, 0).unwrap(),
                max_uses: 1,
            })
            .await
            .map(|_| ())
    });
    let deny = tokio::spawn(async move {
        b.wait().await;
        deny_store
            .deny_request(DenyRequest {
                context: context(95_012, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                approval_id,
                expected_revision: Revision::initial(),
            })
            .await
            .map(|_| ())
    });
    barrier.wait().await;
    let results = [approve.await.unwrap(), deny.await.unwrap()];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    let status = store
        .load_approval_request(approval_id)
        .await
        .unwrap()
        .status;
    assert!(matches!(
        status,
        ApprovalStatus::Granted | ApprovalStatus::Denied
    ));
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM approval_mutations WHERE action IN ('approval.approve','approval.deny')").fetch_one(store.pool()).await.unwrap(),1);
}

#[tokio::test]
async fn approval_at_expiry_boundary_can_only_expire() {
    let directory = TempDir::new().unwrap();
    let (store, _, clock) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let approval_id = ApprovalRequestId::from_uuid(Uuid::from_u128(95_101)).unwrap();
    store
        .request_approval(RequestApproval {
            context: context(95_110, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id,
            requester_id: participant_command().participant_id,
            operation_id: start_operation_command().operation_id,
            source_message_id: start_operation_command().input_message_id,
            source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
            capability: Capability::new("repository.publish").unwrap(),
            resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
            summary: ApprovalSummary::new("expiry boundary").unwrap(),
            expires_at: Timestamp::new(105, 0).unwrap(),
        })
        .await
        .unwrap();
    clock.set(105);
    let barrier = Arc::new(Barrier::new(3));
    let approve_store = store.clone();
    let expire_store = store.clone();
    let a = barrier.clone();
    let b = barrier.clone();
    let approve = tokio::spawn(async move {
        a.wait().await;
        approve_store
            .approve_request(ApproveRequest {
                context: context(95_111, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                approval_id,
                expected_revision: Revision::initial(),
                grant_id: GrantId::from_uuid(Uuid::from_u128(95_102)).unwrap(),
                grant_expires_at: Timestamp::new(105, 0).unwrap(),
                max_uses: 1,
            })
            .await
            .map(|_| ())
    });
    let expire = tokio::spawn(async move {
        b.wait().await;
        expire_store
            .expire_approval(ExpireApproval {
                context: context(95_112, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                approval_id,
                expected_revision: Revision::initial(),
            })
            .await
            .map(|_| ())
    });
    barrier.wait().await;
    assert!(approve.await.unwrap().is_err());
    assert!(expire.await.unwrap().is_ok());
    assert_eq!(
        store
            .load_approval_request(approval_id)
            .await
            .unwrap()
            .status,
        ApprovalStatus::Expired
    );
}

async fn approved_race_fixture(
    store: &SqliteStore,
    base: u128,
    max_uses: u32,
) -> (ApprovalRequestId, GrantId, ApprovalResource) {
    prepare_running_effect_operation(store).await;
    let approval_id = ApprovalRequestId::from_uuid(Uuid::from_u128(base + 1)).unwrap();
    let grant_id = GrantId::from_uuid(Uuid::from_u128(base + 2)).unwrap();
    let resource = ApprovalResource::new(br#"{"branch":"main"}"#).unwrap();
    store
        .request_approval(RequestApproval {
            context: context(base + 10, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id,
            requester_id: participant_command().participant_id,
            operation_id: start_operation_command().operation_id,
            source_message_id: start_operation_command().input_message_id,
            source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
            capability: Capability::new("repository.publish").unwrap(),
            resource: resource.clone(),
            summary: ApprovalSummary::new("race fixture").unwrap(),
            expires_at: Timestamp::new(200, 0).unwrap(),
        })
        .await
        .unwrap();
    store
        .approve_request(ApproveRequest {
            context: context(base + 11, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id,
            expected_revision: Revision::initial(),
            grant_id,
            grant_expires_at: Timestamp::new(190, 0).unwrap(),
            max_uses,
        })
        .await
        .unwrap();
    (approval_id, grant_id, resource)
}

#[tokio::test]
async fn concurrent_consume_and_revoke_have_one_coherent_winner() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    let (approval_id, grant_id, resource) = approved_race_fixture(&store, 96_000, 2).await;
    let barrier = Arc::new(Barrier::new(3));
    let consume_store = store.clone();
    let revoke_store = store.clone();
    let a = barrier.clone();
    let b = barrier.clone();
    let consume = tokio::spawn(async move {
        a.wait().await;
        consume_store
            .consume_approval_grant(ConsumeApprovalGrant {
                context: context(96_020, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                grant_id,
                expected_revision: Revision::initial(),
                effect_id: RequestId::from_uuid(Uuid::from_u128(96_030)).unwrap(),
                subject_id: participant_command().participant_id,
                operation_id: start_operation_command().operation_id,
                capability: Capability::new("repository.publish").unwrap(),
                resource_hash: resource.digest(),
            })
            .await
            .map(|_| ())
    });
    let revoke = tokio::spawn(async move {
        b.wait().await;
        revoke_store
            .revoke_approval_grant(RevokeApprovalGrant {
                context: context(96_021, host(20)),
                session_id: session_id(),
                owner_epoch: FencingEpoch::new(1).unwrap(),
                grant_id,
                expected_revision: Revision::initial(),
            })
            .await
            .map(|_| ())
    });
    barrier.wait().await;
    let results = [consume.await.unwrap(), revoke.await.unwrap()];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    let request = store.load_approval_request(approval_id).await.unwrap();
    let grant = store.load_approval_grant(grant_id).await.unwrap();
    assert!(matches!(
        (request.status, grant.used_count, grant.revoked_at.is_some()),
        (ApprovalStatus::Granted, 1, false) | (ApprovalStatus::Revoked, 0, true)
    ));
}

#[tokio::test]
async fn cancelled_consume_transaction_rolls_back_and_retry_commits_once() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    let (_, grant_id, resource) = approved_race_fixture(&store, 96_500, 1).await;
    let effect_id = RequestId::from_uuid(Uuid::from_u128(96_530)).unwrap();
    let command = ConsumeApprovalGrant {
        context: context(96_520, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        grant_id,
        expected_revision: Revision::initial(),
        effect_id,
        subject_id: participant_command().participant_id,
        operation_id: start_operation_command().operation_id,
        capability: Capability::new("repository.publish").unwrap(),
        resource_hash: resource.digest(),
    };
    set_approval_consume_pause(Some(effect_id));
    let task_store = store.clone();
    let task_command = command.clone();
    let task = tokio::spawn(async move { task_store.consume_approval_grant(task_command).await });
    wait_approval_consume_entered().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    set_approval_consume_pause(None);
    store.pool().close().await;
    let reopened =
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    assert_eq!(
        reopened
            .load_approval_grant(grant_id)
            .await
            .unwrap()
            .used_count,
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM approval_effect_intents WHERE effect_id=?"
        )
        .bind(effect_id.to_string())
        .fetch_one(reopened.pool())
        .await
        .unwrap(),
        0
    );
    assert!(matches!(
        reopened
            .consume_approval_grant(command.clone())
            .await
            .unwrap(),
        Mutation::Applied(_)
    ));
    assert!(matches!(
        reopened.consume_approval_grant(command).await.unwrap(),
        Mutation::Replayed(_)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM approval_mutations WHERE request_id=?")
            .bind(
                RequestId::from_uuid(Uuid::from_u128(96_520))
                    .unwrap()
                    .to_string()
            )
            .fetch_one(reopened.pool())
            .await
            .unwrap(),
        1
    );
    assert_eq!(sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM events WHERE event_type='approval.consumed' AND related_request_id=?").bind(RequestId::from_uuid(Uuid::from_u128(96_520)).unwrap().to_string()).fetch_one(reopened.pool()).await.unwrap(), 1);
}

#[tokio::test]
async fn approval_effect_identity_blocks_recovery_effect_and_tool_writers() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    let (_, grant_id, resource) = approved_race_fixture(&store, 96_700, 1).await;
    let effect_id = RequestId::from_uuid(Uuid::from_u128(96_730)).unwrap();
    store
        .consume_approval_grant(ConsumeApprovalGrant {
            context: context(96_720, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            grant_id,
            expected_revision: Revision::initial(),
            effect_id,
            subject_id: participant_command().participant_id,
            operation_id: start_operation_command().operation_id,
            capability: Capability::new("repository.publish").unwrap(),
            resource_hash: resource.digest(),
        })
        .await
        .unwrap();

    let mut reserve = journal_reserve_command();
    reserve.context = RequestContext::new(effect_id, host(20));
    assert!(matches!(
        store.reserve_effect(reserve).await,
        Err(StoreError::RequestConflict { .. })
    ));
    let recovery = RecordRecoveryClassifications {
        context: RequestContext::new(effect_id, host(20)),
        session_id: session_id(),
        epoch: FencingEpoch::new(1).unwrap(),
        classifications: vec![RecoveryEventClassification {
            entity: RecoveryEventEntity::Session(session_id()),
            state: navigator_domain::RecoveryState::SessionOpen,
            observation: navigator_domain::LiveObservation::NotApplicable,
            decision: navigator_domain::classify_recovery(
                navigator_domain::RecoveryState::SessionOpen,
                navigator_domain::LiveObservation::NotApplicable,
            )
            .unwrap(),
        }],
    };
    assert!(matches!(
        store.record_recovery_classifications(recovery).await,
        Err(StoreError::RequestConflict { .. })
    ));
    let tool = RegisterTool {
        context: RequestContext::new(effect_id, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        registration_id: ToolRegistrationId::from_uuid(Uuid::from_u128(96_740)).unwrap(),
        consumer_key: ConsumerKey::new("consumer-a").unwrap(),
        definition: tool_definition(),
    };
    assert!(matches!(
        store.register_tool(tool).await,
        Err(StoreError::RequestConflict { .. })
    ));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "relay oracle keeps topology, delivery, replay, and redaction together"
)]
async fn approval_decision_relay_is_causal_redacted_and_exactly_once() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let approval_id = ApprovalRequestId::from_uuid(Uuid::from_u128(96_801)).unwrap();
    let request = RequestApproval {
        context: context(96_810, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        approval_id,
        requester_id: participant_command().participant_id,
        operation_id: start_operation_command().operation_id,
        source_message_id: start_operation_command().input_message_id,
        source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
        capability: Capability::new("repository.publish").unwrap(),
        resource: ApprovalResource::new(br#"{"secret":"sentinel-value"}"#).unwrap(),
        summary: ApprovalSummary::new("sentinel summary").unwrap(),
        expires_at: Timestamp::new(200, 0).unwrap(),
    };
    store.request_approval(request).await.unwrap();
    let approve = ApproveRequest {
        context: context(96_811, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        approval_id,
        expected_revision: Revision::initial(),
        grant_id: GrantId::from_uuid(Uuid::from_u128(96_802)).unwrap(),
        grant_expires_at: Timestamp::new(190, 0).unwrap(),
        max_uses: 1,
    };
    assert!(matches!(
        store.approve_request(approve.clone()).await.unwrap(),
        Mutation::Applied(_)
    ));
    assert!(matches!(
        store.approve_request(approve.clone()).await.unwrap(),
        Mutation::Replayed(_)
    ));
    let rows: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT snapshot FROM messages WHERE snapshot LIKE '%approval_decision%'",
    )
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 1);
    let relay: navigator_store_api::MessageSnapshot = serde_json::from_slice(&rows[0]).unwrap();
    let causal = store
        .load_message(start_operation_command().input_message_id)
        .await
        .unwrap();
    assert_eq!(relay.source, causal.source);
    assert_eq!(relay.destination, participant_command().participant_id);
    assert_eq!(
        relay.correlation.operation_id,
        Some(start_operation_command().operation_id)
    );
    assert_eq!(relay.correlation.in_reply_to, Some(causal.message_id));
    assert_eq!(
        relay.priority,
        navigator_store_api::MessagePriority::Control
    );
    assert!(
        matches!(relay.envelope.body(), navigator_domain::MessageBody::ApprovalDecision { approval_id: id, status: ApprovalStatus::Granted, grant_id: Some(_), .. } if *id == approval_id)
    );
    let due = store
        .load_due_session_delivery_work(session_id(), 8)
        .await
        .unwrap();
    let relayed = due
        .iter()
        .find(|work| work.message.message_id == relay.message_id)
        .unwrap();
    assert_eq!(
        relayed.operation.operation_id,
        start_operation_command().operation_id
    );
    assert_eq!(relayed.operation.participant_id, relay.destination);
    let persisted = String::from_utf8(rows[0].clone()).unwrap();
    assert!(!persisted.contains("sentinel-value") && !persisted.contains("sentinel summary"));
    let denied_id = ApprovalRequestId::from_uuid(Uuid::from_u128(96_803)).unwrap();
    store
        .request_approval(RequestApproval {
            context: context(96_812, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id: denied_id,
            requester_id: participant_command().participant_id,
            operation_id: start_operation_command().operation_id,
            source_message_id: start_operation_command().input_message_id,
            source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
            capability: Capability::new("repository.publish").unwrap(),
            resource: ApprovalResource::new(br#"{"secret":"denied-sentinel"}"#).unwrap(),
            summary: ApprovalSummary::new("denied sentinel summary").unwrap(),
            expires_at: Timestamp::new(200, 0).unwrap(),
        })
        .await
        .unwrap();
    let deny = DenyRequest {
        context: context(96_813, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        approval_id: denied_id,
        expected_revision: Revision::initial(),
    };
    assert!(matches!(
        store.deny_request(deny.clone()).await.unwrap(),
        Mutation::Applied(_)
    ));
    assert!(matches!(
        store.deny_request(deny.clone()).await.unwrap(),
        Mutation::Replayed(_)
    ));
    let denied: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM messages WHERE snapshot LIKE '%approval_decision%' AND snapshot LIKE '%\"denied\"%'").fetch_one(store.pool()).await.unwrap();
    assert!(
        !String::from_utf8(denied)
            .unwrap()
            .contains("denied-sentinel")
    );
    let (next_sequence, queued_messages): (i64, i64) = sqlx::query_as("SELECT next_sequence,queued_messages FROM mailbox_counters WHERE destination_participant_id=?")
        .bind(participant_command().participant_id.to_string()).fetch_one(store.pool()).await.unwrap();
    let sequences: Vec<i64> = sqlx::query_scalar("SELECT mailbox_sequence FROM messages WHERE snapshot LIKE '%approval_decision%' ORDER BY mailbox_sequence").fetch_all(store.pool()).await.unwrap();
    assert_eq!(queued_messages, 2);
    assert_eq!(sequences.len(), 2);
    assert_eq!(sequences[1], sequences[0] + 1);
    assert_eq!(next_sequence, sequences[1] + 1);
    store.pool().close().await;
    let reopened =
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    assert!(matches!(
        reopened.approve_request(approve).await.unwrap(),
        Mutation::Replayed(_)
    ));
    assert!(matches!(
        reopened.deny_request(deny).await.unwrap(),
        Mutation::Replayed(_)
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM messages WHERE snapshot LIKE '%approval_decision%'"
        )
        .fetch_one(reopened.pool())
        .await
        .unwrap(),
        2
    );
}

#[tokio::test]
async fn approval_request_rejects_forged_causal_attempt_without_writes() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let command = RequestApproval {
        context: context(96_910, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(96_901)).unwrap(),
        requester_id: participant_command().participant_id,
        operation_id: start_operation_command().operation_id,
        source_message_id: start_operation_command().input_message_id,
        source_delivery_attempt_id: DeliveryAttemptId::from_uuid(Uuid::from_u128(999_999)).unwrap(),
        capability: Capability::new("repository.publish").unwrap(),
        resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
        summary: ApprovalSummary::new("forged causal attempt").unwrap(),
        expires_at: Timestamp::new(200, 0).unwrap(),
    };
    assert_eq!(
        store.request_approval(command).await,
        Err(StoreError::Invalid)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM approval_requests WHERE approval_id=?")
            .bind(
                ApprovalRequestId::from_uuid(Uuid::from_u128(96_901))
                    .unwrap()
                    .to_string()
            )
            .fetch_one(store.pool())
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn approval_request_rejects_wrong_causal_kind_input_and_topology() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let original = store
        .load_message(start_operation_command().input_message_id)
        .await
        .unwrap();
    let mut wrong_kind = original.clone();
    wrong_kind.envelope = ValidatedMessageEnvelope::control(
        start_operation_command().operation_id,
        navigator_domain::ControlMessageKind::Reminder,
    );
    let mut wrong_digest = original.clone();
    wrong_digest.envelope =
        ValidatedMessageEnvelope::operation_input(start_operation_command().operation_id, [99; 32]);
    let mut wrong_source = original.clone();
    wrong_source.source = ParticipantId::from_uuid(Uuid::from_u128(96_999)).unwrap();
    let mut wrong_message = original.clone();
    wrong_message.message_id = MessageId::from_uuid(Uuid::from_u128(96_998)).unwrap();
    for (offset, mutant) in [wrong_kind, wrong_digest, wrong_source, wrong_message]
        .into_iter()
        .enumerate()
    {
        sqlx::query("UPDATE messages SET snapshot=? WHERE message_id=?")
            .bind(serde_json::to_vec(&mutant).unwrap())
            .bind(original.message_id.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        let n = u128::try_from(offset).unwrap();
        let command = RequestApproval {
            context: context(96_950 + n, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(96_940 + n)).unwrap(),
            requester_id: participant_command().participant_id,
            operation_id: start_operation_command().operation_id,
            source_message_id: original.message_id,
            source_delivery_attempt_id: mailbox_lease_command().proposed_attempt_id,
            capability: Capability::new("repository.publish").unwrap(),
            resource: ApprovalResource::new(br#"{"branch":"main"}"#).unwrap(),
            summary: ApprovalSummary::new("causal mutant").unwrap(),
            expires_at: Timestamp::new(200, 0).unwrap(),
        };
        assert_eq!(
            store.request_approval(command).await,
            Err(StoreError::Invalid)
        );
    }
    sqlx::query("UPDATE messages SET snapshot=? WHERE message_id=?")
        .bind(serde_json::to_vec(&original).unwrap())
        .bind(original.message_id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM approval_requests WHERE approval_id IN (?,?,?,?)"
        )
        .bind(
            ApprovalRequestId::from_uuid(Uuid::from_u128(96_940))
                .unwrap()
                .to_string()
        )
        .bind(
            ApprovalRequestId::from_uuid(Uuid::from_u128(96_941))
                .unwrap()
                .to_string()
        )
        .bind(
            ApprovalRequestId::from_uuid(Uuid::from_u128(96_942))
                .unwrap()
                .to_string()
        )
        .bind(
            ApprovalRequestId::from_uuid(Uuid::from_u128(96_943))
                .unwrap()
                .to_string()
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn concurrent_finish_is_one_way_and_replay_safe() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    let (_, grant_id, resource) = approved_race_fixture(&store, 97_000, 1).await;
    let effect_id = RequestId::from_uuid(Uuid::from_u128(97_030)).unwrap();
    store
        .consume_approval_grant(ConsumeApprovalGrant {
            context: context(97_020, host(20)),
            session_id: session_id(),
            owner_epoch: FencingEpoch::new(1).unwrap(),
            grant_id,
            expected_revision: Revision::initial(),
            effect_id,
            subject_id: participant_command().participant_id,
            operation_id: start_operation_command().operation_id,
            capability: Capability::new("repository.publish").unwrap(),
            resource_hash: resource.digest(),
        })
        .await
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for (offset, phase) in [
        (0, TerminalApprovalEffectPhase::Succeeded),
        (1, TerminalApprovalEffectPhase::Failed),
    ] {
        let store = store.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .finish_approval_effect(FinishApprovalEffect {
                    context: context(97_040 + offset, host(20)),
                    session_id: session_id(),
                    owner_epoch: FencingEpoch::new(1).unwrap(),
                    effect_id,
                    expected_revision: Revision::initial(),
                    phase,
                })
                .await
                .map(|_| ())
        }));
    }
    barrier.wait().await;
    let mut winners = 0;
    for task in tasks {
        winners += usize::from(task.await.unwrap().is_ok());
    }
    assert_eq!(winners, 1);
    assert!(matches!(
        store.load_approval_effect(effect_id).await.unwrap().phase,
        ApprovalEffectPhase::Succeeded | ApprovalEffectPhase::Failed
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM approval_mutations WHERE action='approval.effect.finish'"
        )
        .fetch_one(store.pool())
        .await
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn approval_replay_and_operation_liveness_fail_closed_without_reopen() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    let (_, grant_id, resource) = approved_race_fixture(&store, 98_000, 1).await;
    let consume = ConsumeApprovalGrant {
        context: context(98_020, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        grant_id,
        expected_revision: Revision::initial(),
        effect_id: RequestId::from_uuid(Uuid::from_u128(98_030)).unwrap(),
        subject_id: participant_command().participant_id,
        operation_id: start_operation_command().operation_id,
        capability: Capability::new("repository.publish").unwrap(),
        resource_hash: resource.digest(),
    };
    let running = store
        .load_operation(start_operation_command().operation_id)
        .await
        .unwrap();
    let mut terminal = transition_operation_command();
    terminal.context = context(98_015, host(20));
    terminal.expected_revision = running.revision;
    terminal.action = OperationAction::ReportSuccess;
    terminal.report_message_id = Some(running.input_message_id);
    terminal.terminal_outcome = Some(navigator_store_api::OperationTerminalOutcome::Succeeded {
        result: BoundedBytes::new(Vec::new()).unwrap(),
    });
    store.transition_operation(terminal).await.unwrap();
    assert_eq!(
        store.consume_approval_grant(consume.clone()).await,
        Err(StoreError::Invalid)
    );
    assert_eq!(
        store.consume_approval_grant(consume).await,
        Err(StoreError::Invalid)
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM approval_effect_intents")
            .fetch_one(store.pool())
            .await
            .unwrap(),
        0
    );

    let replay_id = RequestId::from_uuid(Uuid::from_u128(98_011)).unwrap();
    sqlx::query("UPDATE approval_mutations SET result=? WHERE request_id=?")
        .bind(b"{}".as_slice())
        .bind(replay_id.to_string())
        .execute(store.pool())
        .await
        .unwrap();
    let approve = ApproveRequest {
        context: context(98_011, host(20)),
        session_id: session_id(),
        owner_epoch: FencingEpoch::new(1).unwrap(),
        approval_id: ApprovalRequestId::from_uuid(Uuid::from_u128(98_001)).unwrap(),
        expected_revision: Revision::initial(),
        grant_id,
        grant_expires_at: Timestamp::new(190, 0).unwrap(),
        max_uses: 1,
    };
    // A live audit runs before any Approval replay result is trusted.
    assert_eq!(
        store.approve_request(approve).await,
        Err(StoreError::Corrupt)
    );
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the adversarial Approval row mutant matrix is intentionally explicit"
)]
async fn approval_row_projection_and_mutation_ledger_mutants_fail_closed() {
    for mutant in [
        "request-projection",
        "grant-projection",
        "effect-projection",
        "mutation-action",
        "mutation-result",
        "mutation-identity",
        "request-decision",
        "effect-scope",
        "effect-finished",
        "used-count",
        "mutation-binding",
        "grant-request-binding",
        "grant-expiry",
        "approve-scope",
        "revoke-expiry",
        "consume-scope",
        "finish-created",
        "grant-revocation-parity",
        "expired-with-grant",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        prepare_raw_approval_rows(&store).await;
        match mutant {
            "request-projection" => sqlx::query("UPDATE approval_requests SET status='denied'").execute(store.pool()).await.unwrap(),
            "grant-projection" => sqlx::query("UPDATE approval_grants SET capability='repository.delete'").execute(store.pool()).await.unwrap(),
            "effect-projection" => sqlx::query("UPDATE approval_effect_intents SET phase='failed'").execute(store.pool()).await.unwrap(),
            "mutation-action" => sqlx::query("UPDATE approval_mutations SET action='approval.forged'").execute(store.pool()).await.unwrap(),
            "mutation-result" => sqlx::query("UPDATE approval_mutations SET result=X'7B7D'").execute(store.pool()).await.unwrap(),
            "mutation-identity" => sqlx::query("UPDATE approval_mutations SET caller_host_id='00000000-0000-0000-0000-000000000000'").execute(store.pool()).await.unwrap(),
            "request-decision" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM approval_requests").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalRequest = serde_json::from_slice(&bytes).unwrap();
                value.decision_source = None;
                sqlx::query("UPDATE approval_requests SET snapshot=?").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "effect-scope" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM approval_effect_intents").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalEffectIntent = serde_json::from_slice(&bytes).unwrap();
                value.capability = Capability::new("repository.delete").unwrap();
                sqlx::query("UPDATE approval_effect_intents SET snapshot=?").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "effect-finished" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM approval_effect_intents").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalEffectIntent = serde_json::from_slice(&bytes).unwrap();
                value.phase = ApprovalEffectPhase::Succeeded;
                sqlx::query("UPDATE approval_effect_intents SET phase='succeeded',snapshot=?").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "used-count" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM approval_grants").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalGrant = serde_json::from_slice(&bytes).unwrap();
                value.used_count = 0;
                sqlx::query("UPDATE approval_grants SET used_count=0,snapshot=?").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "mutation-binding" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT result FROM approval_mutations").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalRequest = serde_json::from_slice(&bytes).unwrap();
                value.id = ApprovalRequestId::from_uuid(Uuid::from_u128(89_999)).unwrap();
                sqlx::query("UPDATE approval_mutations SET result=?").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "grant-request-binding" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM approval_requests").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalRequest = serde_json::from_slice(&bytes).unwrap();
                value.grant_id = Some(GrantId::from_uuid(Uuid::from_u128(89_998)).unwrap());
                sqlx::query("UPDATE approval_requests SET snapshot=?").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "grant-expiry" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM approval_grants").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalGrant = serde_json::from_slice(&bytes).unwrap();
                value.expires_at = Timestamp::new(201, 0).unwrap();
                sqlx::query("UPDATE approval_grants SET expires_seconds=201,snapshot=?").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "approve-scope" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT result FROM approval_mutations WHERE action='approval.approve'").fetch_one(store.pool()).await.unwrap();
                let mut value: navigator_store_api::ApprovedRequest = serde_json::from_slice(&bytes).unwrap();
                value.request.capability = Capability::new("repository.delete").unwrap();
                value.grant.capability = value.request.capability.clone();
                sqlx::query("UPDATE approval_mutations SET result=? WHERE action='approval.approve'").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "revoke-expiry" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT result FROM approval_mutations WHERE action='approval.revoke'").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalGrant = serde_json::from_slice(&bytes).unwrap();
                value.expires_at = Timestamp::new(189, 0).unwrap();
                sqlx::query("UPDATE approval_mutations SET result=? WHERE action='approval.revoke'").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "consume-scope" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT result FROM approval_mutations WHERE action='approval.consume'").fetch_one(store.pool()).await.unwrap();
                let mut value: navigator_store_api::ConsumedApprovalGrant = serde_json::from_slice(&bytes).unwrap();
                value.grant.capability = Capability::new("repository.delete").unwrap();
                value.effect.capability = value.grant.capability.clone();
                sqlx::query("UPDATE approval_mutations SET result=? WHERE action='approval.consume'").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "finish-created" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT result FROM approval_mutations WHERE action='approval.effect.finish'").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalEffectIntent = serde_json::from_slice(&bytes).unwrap();
                value.created_at = Timestamp::new(99, 0).unwrap();
                sqlx::query("UPDATE approval_mutations SET result=? WHERE action='approval.effect.finish'").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "grant-revocation-parity" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM approval_grants").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalGrant = serde_json::from_slice(&bytes).unwrap();
                value.revoked_at = Some(Timestamp::new(110, 0).unwrap());
                sqlx::query("UPDATE approval_grants SET revoked=1,snapshot=?").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            "expired-with-grant" => {
                let bytes: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM approval_requests").fetch_one(store.pool()).await.unwrap();
                let mut value: ApprovalRequest = serde_json::from_slice(&bytes).unwrap();
                value.status = ApprovalStatus::Expired;
                sqlx::query("UPDATE approval_requests SET status='expired',snapshot=?").bind(serde_json::to_vec(&value).unwrap()).execute(store.pool()).await.unwrap()
            },
            _ => unreachable!(),
        };
        assert_eq!(
            store
                .load_approval_request(
                    ApprovalRequestId::from_uuid(Uuid::from_u128(89_001)).unwrap()
                )
                .await
                .unwrap_err(),
            StoreError::Corrupt,
            "live Approval loader trusted mutant: {mutant}"
        );
        store.pool().close().await;
        assert_eq!(
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap_err(),
            StoreError::Corrupt,
            "approval row mutant remained trusted: {mutant}"
        );
    }
}

fn directory_snapshot(path: &Path) -> BTreeMap<String, Vec<u8>> {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            (
                entry.file_name().to_string_lossy().into_owned(),
                std::fs::read(entry.path()).unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn projection_rebuild_is_deterministic_and_pages_are_generation_bound() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;

    let first = store.rebuild_projection(session_id()).await.unwrap();
    let tree = store
        .read_projection(ReadProjection {
            session_id: session_id(),
            consumer: ConsumerKey::new("consumer-a").unwrap(),
            view: ProjectionView::SessionTree,
            page_size: ProjectionPageSize::new(1).unwrap(),
            page_token: None,
        })
        .await
        .unwrap();
    assert_eq!(tree.generation, first.generation);
    assert_eq!(tree.items.len(), 1);
    assert!(
        tree.items[0]
            .data
            .as_slice()
            .windows(12)
            .all(|w| w != b"consumer-key")
    );

    let rebuilt = store.rebuild_projection(session_id()).await.unwrap();
    assert_eq!(rebuilt.generation, first.generation);
    let current = store
        .read_projection(ReadProjection {
            session_id: session_id(),
            consumer: ConsumerKey::new("consumer-a").unwrap(),
            view: ProjectionView::SessionTree,
            page_size: ProjectionPageSize::new(128).unwrap(),
            page_token: None,
        })
        .await
        .unwrap();
    assert_eq!(current.generation, rebuilt.generation);
    assert_eq!(current.items, tree.items);
}

#[tokio::test]
async fn projection_fold_advances_optional_events_and_rejects_required_schema_and_gaps() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let original: (String, Vec<u8>) =
        sqlx::query_as("SELECT event_type,data FROM events WHERE session_id=? AND position=1")
            .bind(session_id().to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();

    sqlx::query("UPDATE events SET event_type='optional.future',data=x'7b7d' WHERE session_id=? AND position=1")
        .bind(session_id().to_string()).execute(store.pool()).await.unwrap();
    store.rebuild_projection(session_id()).await.unwrap();

    sqlx::query(
        "UPDATE events SET event_type='participant.future' WHERE session_id=? AND position=1",
    )
    .bind(session_id().to_string())
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE projection_heads SET source_head_position=source_head_position-1,checkpoint_position=checkpoint_position-1")
        .execute(store.pool()).await.unwrap();
    assert_eq!(
        store.rebuild_projection(session_id()).await,
        Err(StoreError::Corrupt)
    );

    sqlx::query("UPDATE events SET event_type=?,data=? WHERE session_id=? AND position=1")
        .bind(original.0)
        .bind(original.1)
        .bind(session_id().to_string())
        .execute(store.pool())
        .await
        .unwrap();
    let head: i64 = sqlx::query_scalar("SELECT MAX(position) FROM events WHERE session_id=?")
        .bind(session_id().to_string())
        .fetch_one(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE events SET position=? WHERE session_id=? AND position=?")
        .bind(head + 1)
        .bind(session_id().to_string())
        .bind(head)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE projection_heads SET source_head_position=source_head_position-1,checkpoint_position=checkpoint_position-1")
        .execute(store.pool()).await.unwrap();
    assert_eq!(
        store.rebuild_projection(session_id()).await,
        Err(StoreError::Corrupt)
    );
}

#[tokio::test]
async fn projection_first_entity_event_requires_revision_one_and_required_identity() {
    for mutation in ["revision", "identity"] {
        let directory = TempDir::new().unwrap();
        let (store, _, _) = new_store(&directory).await;
        prepare_running_effect_operation(&store).await;
        if mutation == "revision" {
            sqlx::query("UPDATE events SET revision=99 WHERE session_id=? AND event_type='participant.created'")
                .bind(session_id().to_string()).execute(store.pool()).await.unwrap();
        } else {
            let data: Vec<u8> = sqlx::query_scalar(
                "SELECT data FROM events WHERE session_id=? AND event_type='operation.queued'",
            )
            .bind(session_id().to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();
            let mut value: serde_json::Value = serde_json::from_slice(&data).unwrap();
            value.as_object_mut().unwrap().remove("operation_id");
            sqlx::query(
                "UPDATE events SET data=? WHERE session_id=? AND event_type='operation.queued'",
            )
            .bind(serde_json::to_vec(&value).unwrap())
            .bind(session_id().to_string())
            .execute(store.pool())
            .await
            .unwrap();
        }
        assert_eq!(
            store.rebuild_projection(session_id()).await,
            Err(StoreError::Corrupt)
        );
    }
}

#[tokio::test]
async fn projection_required_view_fields_and_required_family_allowlists_fail_closed() {
    for event_type in [
        "participant.created",
        "operation.queued",
        "message.enqueued",
        "approval.requested",
        "recovery.classified",
        "capacity.observed",
        "failure.recorded",
        "capacity.future",
        "failure.future",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, _, _) = new_store(&directory).await;
        store.open_session(open_command(985_000)).await.unwrap();
        let payload = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "session_id": session_id(),
            "revision": 1,
        }))
        .unwrap();
        sqlx::query("UPDATE events SET event_type=?,data=? WHERE session_id=?")
            .bind(event_type)
            .bind(payload)
            .bind(session_id().to_string())
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            store.rebuild_projection(session_id()).await,
            Err(StoreError::Corrupt),
            "required event mutant was accepted: {event_type}"
        );
    }
}

#[tokio::test]
async fn projection_typed_payload_state_and_range_mutants_fail_closed() {
    for mutant in [
        "operation_revision",
        "operation_state",
        "message_state",
        "participant_lifecycle",
        "capacity_available_string",
        "capacity_total_object",
        "capacity_revision_bool",
        "failure_code_array",
        "failure_entity_number",
    ] {
        let directory = TempDir::new().unwrap();
        let (store, _, _) = new_store(&directory).await;
        prepare_running_effect_operation(&store).await;
        let (event_type, mut value): (String, serde_json::Value) = match mutant {
            value if value.starts_with("operation_") => sqlx::query_as::<_, (String, Vec<u8>)>("SELECT event_type,data FROM events WHERE session_id=? AND event_type='operation.queued'")
                .bind(session_id().to_string()).fetch_one(store.pool()).await.map(|(kind,data)|(kind,serde_json::from_slice(&data).unwrap())).unwrap(),
            "message_state" => sqlx::query_as::<_, (String, Vec<u8>)>("SELECT event_type,data FROM events WHERE session_id=? AND event_type='message.enqueued'")
                .bind(session_id().to_string()).fetch_one(store.pool()).await.map(|(kind,data)|(kind,serde_json::from_slice(&data).unwrap())).unwrap(),
            "participant_lifecycle" => sqlx::query_as::<_, (String, Vec<u8>)>("SELECT event_type,data FROM events WHERE session_id=? AND event_type='participant.created' LIMIT 1")
                .bind(session_id().to_string()).fetch_one(store.pool()).await.map(|(kind,data)|(kind,serde_json::from_slice(&data).unwrap())).unwrap(),
            value if value.starts_with("capacity_") => ("capacity.observed".to_owned(), serde_json::json!({"schema_version":1,"session_id":session_id(),"scope_id":"session","resource":"workers","available":1,"total":2,"revision":1})),
            _ => ("failure.recorded".to_owned(), serde_json::json!({"schema_version":1,"session_id":session_id(),"failure_id":Uuid::from_u128(986_001),"code":"failed","entity_id":Uuid::from_u128(986_002).to_string(),"revision":1})),
        };
        match mutant {
            "operation_revision" => value["revision"] = serde_json::json!(99),
            "operation_state" => value["state"] = serde_json::json!("succeeded"),
            "message_state" => value["state"] = serde_json::json!("accepted"),
            "participant_lifecycle" => value["lifecycle"] = serde_json::json!("terminal"),
            "capacity_available_string" => value["available"] = serde_json::json!("1"),
            "capacity_total_object" => value["total"] = serde_json::json!({}),
            "capacity_revision_bool" => value["revision"] = serde_json::json!(true),
            "failure_code_array" => value["code"] = serde_json::json!([]),
            "failure_entity_number" => value["entity_id"] = serde_json::json!(7),
            _ => unreachable!(),
        }
        sqlx::query("UPDATE events SET event_type=?,data=? WHERE session_id=? AND position=1")
            .bind(event_type)
            .bind(serde_json::to_vec(&value).unwrap())
            .bind(session_id().to_string())
            .execute(store.pool())
            .await
            .unwrap();
        assert_eq!(
            store.rebuild_projection(session_id()).await,
            Err(StoreError::Corrupt),
            "typed projection mutant accepted: {mutant}"
        );
    }
}

#[tokio::test]
async fn projection_schema_index_and_head_coherence_fail_closed_on_reopen() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    store.rebuild_projection(session_id()).await.unwrap();
    sqlx::query("UPDATE projection_heads SET checkpoint_position=checkpoint_position-1")
        .execute(store.pool())
        .await
        .unwrap();
    store.pool().close().await;
    assert_eq!(
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap_err(),
        StoreError::Corrupt
    );
}

#[tokio::test]
async fn projection_schema_metadata_and_row_binding_mutants_fail_closed_on_reopen() {
    for mutant in ["secret", "row_json", "published_without_head"] {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        prepare_running_effect_operation(&store).await;
        store.rebuild_projection(session_id()).await.unwrap();
        match mutant {
            "secret" => {
                sqlx::query("UPDATE projection_metadata SET token_secret=zeroblob(32)")
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            "row_json" => {
                sqlx::query("UPDATE projection_rows SET data=x'7b7d' WHERE rowid=(SELECT rowid FROM projection_rows WHERE session_id=? LIMIT 1)")
                    .bind(session_id().to_string())
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            "published_without_head" => {
                sqlx::query("DELETE FROM projection_heads WHERE session_id=?")
                    .bind(session_id().to_string())
                    .execute(store.pool())
                    .await
                    .unwrap();
            }
            _ => unreachable!(),
        }
        drop(store);
        assert_eq!(
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap_err(),
            StoreError::Corrupt,
            "projection schema mutant trusted: {mutant}"
        );
    }
}

#[tokio::test]
async fn projection_projector_coalesces_hints_and_polls_the_durable_tail() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    let projector = crate::ProjectionProjector::start(store.clone());
    for _ in 0..32 {
        projector.notify(session_id());
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM projection_heads WHERE session_id=?")
                    .bind(session_id().to_string())
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            if count == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let progress: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM projection_progress WHERE session_id=?")
            .bind(session_id().to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(progress, 1);
    for _ in 0..32 {
        projector.notify(session_id());
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let dropped: i64 =
        sqlx::query_scalar("SELECT dropped_updates FROM projection_progress WHERE session_id=?")
            .bind(session_id().to_string())
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert!(dropped > 0);
    projector.shutdown().await;
}

#[tokio::test]
async fn projection_progress_retains_exactly_the_latest_eight_causal_observations() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    store.rebuild_projection(session_id()).await.unwrap();
    for ordinal in 1_u128..=10 {
        let position: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(position),0)+1 FROM events WHERE session_id=?")
                .bind(session_id().to_string())
                .fetch_one(store.pool())
                .await
                .unwrap();
        sqlx::query("INSERT INTO events(session_id,position,event_id,revision,event_type,schema_version,related_request_id,data,occurred_at_seconds,occurred_at_nanos) VALUES(?,?,?,?, 'optional.progress',1,NULL,x'7b7d',100,0)")
            .bind(session_id().to_string())
            .bind(position)
            .bind(Uuid::from_u128(970_000 + ordinal).to_string())
            .bind(position)
            .execute(store.pool())
            .await
            .unwrap();
        store.rebuild_projection(session_id()).await.unwrap();
    }
    let observations: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT generation,checkpoint_position FROM projection_progress WHERE session_id=? ORDER BY generation,ordinal",
    )
    .bind(session_id().to_string())
    .fetch_all(store.pool())
    .await
    .unwrap();
    assert_eq!(observations.len(), 8);
    assert!(observations.windows(2).all(|pair| pair[0] < pair[1]));
}

#[tokio::test]
async fn projection_projector_marks_a_bad_session_unhealthy_without_unbounded_retries() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    sqlx::query(
        "UPDATE events SET data=x'7b7d' WHERE session_id=? AND event_type='participant.created'",
    )
    .bind(session_id().to_string())
    .execute(store.pool())
    .await
    .unwrap();
    let projector = crate::ProjectionProjector::start(store.clone());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projection_generations WHERE session_id=? AND state='unhealthy'")
                .bind(session_id().to_string()).fetch_one(store.pool()).await.unwrap();
            if count == 1 { break; }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM projection_generations WHERE session_id=? AND state='unhealthy'",
    )
    .bind(session_id().to_string())
    .fetch_one(store.pool())
    .await
    .unwrap();
    assert_eq!(count, 1);
    projector.shutdown().await;
}

#[tokio::test]
async fn projection_projector_isolates_a_corrupt_session_while_a_healthy_session_converges() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    sqlx::query(
        "UPDATE events SET data=x'7b7d' WHERE session_id=? AND event_type='participant.created'",
    )
    .bind(session_id().to_string())
    .execute(store.pool())
    .await
    .unwrap();
    let healthy = SessionId::from_uuid(Uuid::from_u128(123_456)).unwrap();
    store
        .open_session(OpenSession::new(
            context(123_457, host(10)),
            healthy,
            ConsumerKey::new("healthy-projection").unwrap(),
            template_record().compatibility,
        ))
        .await
        .unwrap();
    let projector = crate::ProjectionProjector::start(store.clone());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let unhealthy: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projection_generations WHERE session_id=? AND state='unhealthy'")
                .bind(session_id().to_string()).fetch_one(store.pool()).await.unwrap();
            let healthy_head: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projection_heads WHERE session_id=?")
                .bind(healthy.to_string()).fetch_one(store.pool()).await.unwrap();
            if unhealthy == 1 && healthy_head == 1 { break; }
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    projector.shutdown().await;
}

#[tokio::test]
async fn projection_projector_quarantines_a_full_corrupt_batch_before_healthy_tail() {
    let directory = TempDir::new().unwrap();
    let (store, _, _) = new_store(&directory).await;
    for number in 2_u128..=130 {
        let session = SessionId::from_uuid(Uuid::from_u128(number)).unwrap();
        store
            .open_session(OpenSession::new(
                context(980_000 + number, host(10)),
                session,
                ConsumerKey::new(format!("projection-consumer-{number}")).unwrap(),
                template_record().compatibility,
            ))
            .await
            .unwrap();
        if number < 130 {
            sqlx::query(
                "UPDATE events SET event_type='participant.future',data=x'7b7d' WHERE session_id=?",
            )
            .bind(session.to_string())
            .execute(store.pool())
            .await
            .unwrap();
        }
    }
    let healthy = SessionId::from_uuid(Uuid::from_u128(130)).unwrap();
    let projector = crate::ProjectionProjector::start(store.clone());
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let published: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM projection_heads WHERE session_id=?")
                    .bind(healthy.to_string())
                    .fetch_one(store.pool())
                    .await
                    .unwrap();
            if published == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let quarantined: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM projection_generations WHERE state='unhealthy'")
            .fetch_one(store.pool())
            .await
            .unwrap();
    assert_eq!(quarantined, 128);
    projector.shutdown().await;
}

#[tokio::test]
async fn projection_page_token_binds_generation_view_size_and_composite_cursor() {
    let directory = TempDir::new().unwrap();
    let (store, path, clock) = new_store(&directory).await;
    prepare_running_effect_operation(&store).await;
    store
        .create_child_participant(child_command())
        .await
        .unwrap();
    store.rebuild_projection(session_id()).await.unwrap();
    let base = ReadProjection {
        session_id: session_id(),
        consumer: ConsumerKey::new("consumer-a").unwrap(),
        view: ProjectionView::SessionTree,
        page_size: ProjectionPageSize::new(1).unwrap(),
        page_token: None,
    };
    let first = store.read_projection(base.clone()).await.unwrap();
    let token = first.next_page_token.clone().unwrap();
    let mut forged_wire: serde_json::Value = serde_json::from_str(token.as_str()).unwrap();
    let forged_signature = projection_signature(
        &[0; 32],
        &ConsumerKey::new("consumer-a").unwrap(),
        serde_json::from_value(forged_wire["session_id"].clone()).unwrap(),
        serde_json::from_value(forged_wire["view"].clone()).unwrap(),
        forged_wire["generation"].as_u64().unwrap(),
        forged_wire["checkpoint"].as_u64().unwrap(),
        forged_wire["expires_seconds"].as_i64().unwrap(),
        u16::try_from(forged_wire["page_size"].as_u64().unwrap()).unwrap(),
        forged_wire["last_sort_key"].as_str().unwrap(),
        forged_wire["last_item_key"].as_str().unwrap(),
    );
    forged_wire["signature"] = serde_json::to_value(forged_signature).unwrap();
    let mut zero_key_forgery = base.clone();
    zero_key_forgery.page_token = Some(ProjectionPageToken::new(forged_wire.to_string()).unwrap());
    assert_eq!(
        store.read_projection(zero_key_forgery).await,
        Err(StoreError::Invalid)
    );
    let mut next = base.clone();
    next.page_token = Some(token.clone());
    let second = store.read_projection(next.clone()).await.unwrap();
    assert_eq!(second.items.len(), 1);
    assert_ne!(first.items[0].key, second.items[0].key);

    for _ in 0..10 {
        store.rebuild_projection(session_id()).await.unwrap();
    }
    assert_eq!(
        store
            .read_projection(next.clone())
            .await
            .unwrap()
            .generation,
        first.generation
    );
    clock.set(1_000);
    store.rebuild_projection(session_id()).await.unwrap();
    assert_eq!(
        store.read_projection(next).await,
        Err(StoreError::ProjectionStale)
    );
    let mut wrong_view = base.clone();
    wrong_view.view = ProjectionView::Failure;
    wrong_view.page_token = Some(token.clone());
    assert_eq!(
        store.read_projection(wrong_view).await,
        Err(StoreError::Invalid)
    );
    let mut wrong_size = base;
    wrong_size.page_size = ProjectionPageSize::new(2).unwrap();
    wrong_size.page_token = Some(token.clone());
    assert_eq!(
        store.read_projection(wrong_size).await,
        Err(StoreError::Invalid)
    );
    store.pool().close().await;
    clock.set(50);
    let reopened =
        SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
            .await
            .unwrap();
    let mut regressed = ReadProjection {
        session_id: session_id(),
        consumer: ConsumerKey::new("consumer-a").unwrap(),
        view: ProjectionView::SessionTree,
        page_size: ProjectionPageSize::new(1).unwrap(),
        page_token: None,
    };
    regressed.page_token = Some(token);
    assert_eq!(
        reopened.read_projection(regressed).await,
        Err(StoreError::ProjectionStale)
    );
}

#[tokio::test]
async fn projection_generation_swap_crash_is_prior_or_full_and_retry_converges() {
    for (point, committed) in [
        ("projection.before_generation_swap", false),
        ("projection.after_generation_swap", true),
    ] {
        let directory = TempDir::new().unwrap();
        let (store, path, clock) = new_store(&directory).await;
        prepare_running_effect_operation(&store).await;
        store.pool().close().await;
        run_crash_worker(&path, "projection-rebuild", point);
        let reopened =
            SqliteStore::open_with_clock(&path, clock, LeaseDuration::from_millis(60_000).unwrap())
                .await
                .unwrap();
        let heads: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projection_heads")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
        assert_eq!(heads, i64::from(committed));
        reopened.rebuild_projection(session_id()).await.unwrap();
        let published: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM projection_generations WHERE state='published'",
        )
        .fetch_one(reopened.pool())
        .await
        .unwrap();
        assert_eq!(published, 1);
        let head: (i64, i64) =
            sqlx::query_as("SELECT checkpoint_position,source_head_position FROM projection_heads")
                .fetch_one(reopened.pool())
                .await
                .unwrap();
        assert_eq!(head.0, head.1);
    }
}
