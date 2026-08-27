use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::Path,
    str::FromStr,
    time::Duration,
};

use navigator_domain::{
    ApprovalEffectIntent, ApprovalGrant, ApprovalRequest, ApprovalStatus, Capability, EffectClass,
    FencingEpoch, HostId, RequestId, SemanticDigest, SessionId,
};
use navigator_store_api::{
    ApprovedRequest, AuthorityPolicySnapshot, AuthorityTemplatePolicy, AuthorizedEffectResolution,
    CapacityResource, ConnectToolProvider, ConsumedApprovalGrant, EffectJournalEntry,
    GrantSnapshot, LimitProfile, MessageDeliveryState, MessageSnapshot, MutableRequest,
    RegisterTool, RequestContext, ToolInvocationSnapshot, ToolProviderConnectionSnapshot,
    ToolRegistrationSnapshot,
};
use sqlx::{
    Connection, Executor, Row, SqliteConnection, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use thiserror::Error;

use crate::crash_at;

pub(crate) const SCHEMA_VERSION: i64 = 20;

#[derive(Debug, Error)]
pub(crate) enum DatabaseError {
    #[error("database path is not valid UTF-8")]
    InvalidPath,
    #[error("database schema version {found} is newer than supported version {supported}")]
    SchemaTooNew { found: i64, supported: i64 },
    #[error("database schema is not a recognized Navigator schema")]
    SchemaCorrupt,
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

pub(crate) async fn open_pool(path: &Path) -> Result<SqlitePool, DatabaseError> {
    if path.exists() {
        probe_schema(path).await?;
    }

    let path = path.to_str().ok_or(DatabaseError::InvalidPath)?;
    let options = SqliteConnectOptions::from_str(path)?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await?;
    migrate(&pool).await?;
    Ok(pool)
}

async fn probe_schema(path: &Path) -> Result<(), DatabaseError> {
    let path = path.to_str().ok_or(DatabaseError::InvalidPath)?;
    let options = SqliteConnectOptions::from_str(path)?
        .read_only(true)
        .foreign_keys(true);
    let mut connection = SqliteConnection::connect_with(&options).await?;
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut connection)
        .await?;
    if version > SCHEMA_VERSION {
        connection.close().await?;
        return Err(DatabaseError::SchemaTooNew {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(&mut connection)
    .await?;
    if version == 0 && !tables.is_empty() {
        connection.close().await?;
        return Err(DatabaseError::SchemaCorrupt);
    }
    if version == SCHEMA_VERSION {
        if ![
            "sessions",
            "events",
            "request_ledger",
            "launch_attempts",
            "templates",
            "participants",
            "operations",
            "mailbox_counters",
            "messages",
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
            "approval_requests",
            "approval_grants",
            "approval_effect_intents",
            "approval_mutations",
            "projection_generations",
            "projection_rows",
            "projection_heads",
            "projection_progress",
            "projection_metadata",
            "capacity_reservations",
            "capacity_global_reservations",
            "capacity_session_usage",
            "capacity_global_usage",
            "capacity_limits",
            "subscription_leases",
        ]
        .iter()
        .all(|required| tables.iter().any(|table| table == required))
        {
            connection.close().await?;
            return Err(DatabaseError::SchemaCorrupt);
        }
        validate_schema(&mut connection).await?;
    }
    connection.close().await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn validate_schema(connection: &mut SqliteConnection) -> Result<(), DatabaseError> {
    const SESSIONS: &[&str] = &[
        "session_id",
        "consumer_key",
        "compatibility_identity",
        "revision",
        "closed",
        "created_at_seconds",
        "created_at_nanos",
        "updated_at_seconds",
        "updated_at_nanos",
        "owner_host_id",
        "owner_epoch",
        "owner_expires_at_seconds",
        "owner_expires_at_nanos",
        "epoch_high_water",
        "observed_time_floor_seconds",
        "observed_time_floor_nanos",
        "compatibility_manifest_complete",
        "compatibility_configuration_identity",
        "public_consumer_key",
    ];
    const EVENTS: &[&str] = &[
        "session_id",
        "position",
        "event_id",
        "revision",
        "event_type",
        "schema_version",
        "related_request_id",
        "data",
        "occurred_at_seconds",
        "occurred_at_nanos",
    ];
    const REQUESTS: &[&str] = &[
        "request_id",
        "session_id",
        "caller_host_id",
        "action",
        "semantic_digest",
        "outcome",
        "effect",
        "result",
    ];
    const LAUNCHES: &[&str] = &[
        "attempt_id",
        "session_id",
        "ownership_epoch",
        "participant_id",
        "driver_id",
        "instance_id",
        "state",
        "revision",
        "credential_digest",
        "driver_configuration_digest",
        "evidence",
        "cleanup_reason",
    ];
    const TEMPLATES: &[&str] = &["template_id", "compatibility_identity", "registration"];
    const SESSION_TEMPLATE_MANIFEST: &[&str] =
        &["session_id", "template_id", "template_compatibility"];
    const PARTICIPANTS: &[&str] = &[
        "participant_id",
        "session_id",
        "parent_participant_id",
        "template_id",
        "template_compatibility",
        "revision",
        "depth",
        "cancellation_requested",
    ];
    const OPERATIONS: &[&str] = &[
        "operation_id",
        "session_id",
        "participant_id",
        "start_request_id",
        "input_message_id",
        "waiting_on_message_id",
        "input_digest",
        "input_payload",
        "state",
        "terminal_outcome",
        "terminal_payload",
        "revision",
        "created_at_seconds",
        "created_at_nanos",
        "updated_at_seconds",
        "updated_at_nanos",
    ];
    const MAILBOX_COUNTERS: &[&str] = &[
        "destination_participant_id",
        "next_sequence",
        "queued_bytes",
        "queued_messages",
    ];
    const MESSAGES: &[&str] = &[
        "message_id",
        "session_id",
        "source_participant_id",
        "destination_participant_id",
        "mailbox_sequence",
        "priority",
        "snapshot",
    ];
    const AUTHORITY_POLICIES: &[&str] = &["participant_id", "session_id", "snapshot"];
    const AUTHORITY_GRANTS: &[&str] = &[
        "grant_id",
        "session_id",
        "subject_participant_id",
        "snapshot",
    ];
    const AUTHORITY_TEMPLATE_POLICIES: &[&str] = &["template_id", "snapshot"];
    const EFFECT_JOURNAL: &[&str] = &[
        "request_id",
        "session_id",
        "participant_id",
        "operation_id",
        "caller_host_id",
        "action",
        "semantic_digest",
        "effect_class",
        "resolution_contract",
        "phase",
        "owner_host_id",
        "owner_epoch",
        "lease_expires_at_seconds",
        "lease_expires_at_nanos",
        "terminal",
        "revision",
    ];
    const EFFECT_MUTATIONS: &[&str] = &[
        "request_id",
        "effect_request_id",
        "caller_host_id",
        "semantic_digest",
        "result",
    ];
    const RECOVERY_CLASSIFICATIONS: &[&str] = &[
        "request_id",
        "session_id",
        "caller_host_id",
        "owner_epoch",
        "semantic_digest",
        "payload",
    ];
    const ARTIFACTS: &[&str] = &[
        "artifact_id",
        "session_id",
        "creator_participant_id",
        "creator_operation_id",
        "media_type",
        "size",
        "digest",
        "locator",
        "state",
        "revision",
        "retention_seconds",
        "retention_nanos",
        "created_seconds",
        "created_nanos",
        "deleted_seconds",
        "deleted_nanos",
    ];
    const TOOL_REGISTRATIONS: &[&str] = &[
        "session_id",
        "registration_id",
        "tool_name",
        "tool_version",
        "consumer_key",
        "snapshot",
    ];
    const TOOL_INVOCATIONS: &[&str] = &[
        "invocation_id",
        "effect_request_id",
        "registration_id",
        "dispatch_id",
        "provider_id",
        "server_sequence",
        "deadline_seconds",
        "deadline_nanos",
        "connection_generation",
        "cancellation_id",
        "cancellation_server_sequence",
        "terminal_digest",
        "session_id",
        "participant_id",
        "operation_id",
        "tool_name",
        "tool_version",
        "snapshot",
    ];
    const TOOL_INVOCATION_MUTATIONS: &[&str] = &[
        "request_id",
        "invocation_id",
        "caller_host_id",
        "semantic_digest",
        "result",
    ];
    const TOOL_PROVIDER_CONNECTIONS: &[&str] = &[
        "session_id",
        "provider_id",
        "connection_id",
        "consumer_key",
        "generation",
        "acknowledged_server_sequence",
        "next_server_sequence",
        "connected_at_seconds",
        "connected_at_nanos",
        "registrations",
    ];
    const APPROVAL_REQUESTS: &[&str] = &[
        "approval_id",
        "session_id",
        "requester_id",
        "operation_id",
        "capability",
        "resource_hash",
        "status",
        "expires_seconds",
        "expires_nanos",
        "revision",
        "snapshot",
    ];
    const APPROVAL_GRANTS: &[&str] = &[
        "grant_id",
        "approval_id",
        "session_id",
        "subject_id",
        "operation_id",
        "capability",
        "resource_hash",
        "max_uses",
        "used_count",
        "expires_seconds",
        "expires_nanos",
        "revoked",
        "revision",
        "snapshot",
    ];
    const APPROVAL_EFFECT_INTENTS: &[&str] = &[
        "effect_id",
        "session_id",
        "grant_id",
        "operation_id",
        "phase",
        "revision",
        "snapshot",
    ];
    const APPROVAL_MUTATIONS: &[&str] = &[
        "request_id",
        "session_id",
        "caller_host_id",
        "action",
        "semantic_digest",
        "result",
    ];
    const PROJECTION_GENERATIONS: &[&str] = &[
        "session_id",
        "generation",
        "state",
        "checkpoint_position",
        "source_head_position",
        "observed_time_floor_seconds",
        "observed_time_floor_nanos",
        "created_at_seconds",
        "created_at_nanos",
    ];
    const PROJECTION_ROWS: &[&str] = &[
        "session_id",
        "generation",
        "view",
        "item_key",
        "sort_key",
        "data",
    ];
    const PROJECTION_HEADS: &[&str] = &[
        "session_id",
        "generation",
        "checkpoint_position",
        "source_head_position",
    ];
    const PROJECTION_PROGRESS: &[&str] = &[
        "session_id",
        "generation",
        "ordinal",
        "checkpoint_position",
        "dropped_updates",
        "recorded_at_seconds",
        "recorded_at_nanos",
    ];
    const CAPACITY_RESERVATIONS: &[&str] = &[
        "reservation_id",
        "session_id",
        "campaign_id",
        "resource",
        "amount",
        "released",
        "created_at_seconds",
        "created_at_nanos",
        "released_at_seconds",
        "released_at_nanos",
    ];
    const CAPACITY_GLOBAL_RESERVATIONS: &[&str] = &[
        "reservation_id",
        "resource",
        "amount",
        "released",
        "created_at_seconds",
        "created_at_nanos",
        "released_at_seconds",
        "released_at_nanos",
    ];
    const CAPACITY_SESSION_USAGE: &[&str] = &["session_id", "resource", "used"];
    const CAPACITY_GLOBAL_USAGE: &[&str] = &["resource", "used"];
    const CAPACITY_LIMITS: &[&str] = &["resource", "per_session", "global_limit", "configured"];
    const SUBSCRIPTION_LEASES: &[&str] = &[
        "reservation_id",
        "session_id",
        "campaign_id",
        "owner_host_id",
        "owner_epoch",
        "expires_at_seconds",
        "expires_at_nanos",
    ];

    for (query, expected) in [
        ("PRAGMA table_info(sessions)", SESSIONS),
        ("PRAGMA table_info(events)", EVENTS),
        ("PRAGMA table_info(request_ledger)", REQUESTS),
        ("PRAGMA table_info(launch_attempts)", LAUNCHES),
        ("PRAGMA table_info(templates)", TEMPLATES),
        (
            "PRAGMA table_info(session_template_manifest)",
            SESSION_TEMPLATE_MANIFEST,
        ),
        ("PRAGMA table_info(participants)", PARTICIPANTS),
        ("PRAGMA table_info(operations)", OPERATIONS),
        ("PRAGMA table_info(mailbox_counters)", MAILBOX_COUNTERS),
        ("PRAGMA table_info(messages)", MESSAGES),
        ("PRAGMA table_info(authority_policies)", AUTHORITY_POLICIES),
        ("PRAGMA table_info(authority_grants)", AUTHORITY_GRANTS),
        (
            "PRAGMA table_info(authority_template_policies)",
            AUTHORITY_TEMPLATE_POLICIES,
        ),
        ("PRAGMA table_info(effect_journal)", EFFECT_JOURNAL),
        (
            "PRAGMA table_info(effect_journal_mutations)",
            EFFECT_MUTATIONS,
        ),
        (
            "PRAGMA table_info(recovery_classifications)",
            RECOVERY_CLASSIFICATIONS,
        ),
        ("PRAGMA table_info(artifacts)", ARTIFACTS),
        ("PRAGMA table_info(tool_registrations)", TOOL_REGISTRATIONS),
        ("PRAGMA table_info(tool_invocations)", TOOL_INVOCATIONS),
        (
            "PRAGMA table_info(tool_invocation_mutations)",
            TOOL_INVOCATION_MUTATIONS,
        ),
        (
            "PRAGMA table_info(tool_provider_connections)",
            TOOL_PROVIDER_CONNECTIONS,
        ),
        ("PRAGMA table_info(approval_requests)", APPROVAL_REQUESTS),
        ("PRAGMA table_info(approval_grants)", APPROVAL_GRANTS),
        (
            "PRAGMA table_info(approval_effect_intents)",
            APPROVAL_EFFECT_INTENTS,
        ),
        ("PRAGMA table_info(approval_mutations)", APPROVAL_MUTATIONS),
        (
            "PRAGMA table_info(projection_generations)",
            PROJECTION_GENERATIONS,
        ),
        ("PRAGMA table_info(projection_rows)", PROJECTION_ROWS),
        ("PRAGMA table_info(projection_heads)", PROJECTION_HEADS),
        (
            "PRAGMA table_info(projection_progress)",
            PROJECTION_PROGRESS,
        ),
        (
            "PRAGMA table_info(projection_metadata)",
            &["singleton", "token_secret"],
        ),
        (
            "PRAGMA table_info(capacity_reservations)",
            CAPACITY_RESERVATIONS,
        ),
        (
            "PRAGMA table_info(capacity_global_reservations)",
            CAPACITY_GLOBAL_RESERVATIONS,
        ),
        (
            "PRAGMA table_info(capacity_session_usage)",
            CAPACITY_SESSION_USAGE,
        ),
        (
            "PRAGMA table_info(capacity_global_usage)",
            CAPACITY_GLOBAL_USAGE,
        ),
        ("PRAGMA table_info(capacity_limits)", CAPACITY_LIMITS),
        (
            "PRAGMA table_info(subscription_leases)",
            SUBSCRIPTION_LEASES,
        ),
    ] {
        let rows = sqlx::query(query).fetch_all(&mut *connection).await?;
        let columns: Vec<String> = rows.iter().map(|row| row.get("name")).collect();
        if columns.len() != expected.len()
            || !expected
                .iter()
                .all(|name| columns.iter().any(|column| column == name))
            || rows
                .iter()
                .any(|row| !valid_column_shape(table_name(query), row))
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }

    let foreign_keys = sqlx::query("PRAGMA foreign_key_list(events)")
        .fetch_all(&mut *connection)
        .await?;
    if !foreign_keys.iter().any(|row| {
        row.get::<String, _>("table") == "sessions"
            && row.get::<String, _>("from") == "session_id"
            && row.get::<String, _>("to") == "session_id"
    }) {
        return Err(DatabaseError::SchemaCorrupt);
    }
    let launch_foreign_keys = sqlx::query("PRAGMA foreign_key_list(launch_attempts)")
        .fetch_all(&mut *connection)
        .await?;
    if !launch_foreign_keys.iter().any(|row| {
        row.get::<String, _>("table") == "sessions"
            && row.get::<String, _>("from") == "session_id"
            && row.get::<String, _>("to") == "session_id"
    }) {
        return Err(DatabaseError::SchemaCorrupt);
    }
    for (foreign_keys, expected) in [
        (
            sqlx::query("PRAGMA foreign_key_list(participants)")
                .fetch_all(&mut *connection)
                .await?,
            &[("session_id", "sessions"), ("template_id", "templates")][..],
        ),
        (
            sqlx::query("PRAGMA foreign_key_list(session_template_manifest)")
                .fetch_all(&mut *connection)
                .await?,
            &[("session_id", "sessions"), ("template_id", "templates")][..],
        ),
        (
            sqlx::query("PRAGMA foreign_key_list(operations)")
                .fetch_all(&mut *connection)
                .await?,
            &[
                ("session_id", "sessions"),
                ("participant_id", "participants"),
            ][..],
        ),
        (
            sqlx::query("PRAGMA foreign_key_list(messages)")
                .fetch_all(&mut *connection)
                .await?,
            &[
                ("session_id", "sessions"),
                ("source_participant_id", "participants"),
                ("destination_participant_id", "participants"),
            ][..],
        ),
        (
            sqlx::query("PRAGMA foreign_key_list(artifacts)")
                .fetch_all(&mut *connection)
                .await?,
            &[("session_id", "sessions")][..],
        ),
    ] {
        if expected.iter().any(|(column, target)| {
            !foreign_keys.iter().any(|row| {
                row.get::<String, _>("table") == *target && row.get::<String, _>("from") == *column
            })
        }) {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    let identity_index: Option<String> = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type = 'index'
         AND name = 'current_instance_identity' AND tbl_name = 'launch_attempts'",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let Some(identity_index) = identity_index else {
        return Err(DatabaseError::SchemaCorrupt);
    };
    let normalized = identity_index.to_ascii_lowercase();
    if !normalized.contains("unique")
        || !normalized.contains("instance_id")
        || !normalized.contains("where instance_id is not null")
    {
        return Err(DatabaseError::SchemaCorrupt);
    }
    for (name, table, predicate) in [
        (
            "one_root_participant_per_session",
            "participants",
            "where parent_participant_id is null",
        ),
        (
            "one_unfinished_operation_per_participant",
            "operations",
            "where terminal_outcome is null",
        ),
    ] {
        let sql: Option<String> = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ? AND tbl_name = ?",
        )
        .bind(name)
        .bind(table)
        .fetch_optional(&mut *connection)
        .await?;
        let Some(sql) = sql else {
            return Err(DatabaseError::SchemaCorrupt);
        };
        let normalized = sql.to_ascii_lowercase();
        if !normalized.contains("unique") || !normalized.contains(predicate) {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    let message_indexes = sqlx::query("PRAGMA index_list(messages)")
        .fetch_all(&mut *connection)
        .await?;
    let mut ordered_unique = false;
    for index in message_indexes {
        if index.get::<i64, _>("unique") == 0 {
            continue;
        }
        let name: String = index.get("name");
        let columns = if name == "sqlite_autoindex_messages_2" {
            sqlx::query("PRAGMA index_info(sqlite_autoindex_messages_2)")
                .fetch_all(&mut *connection)
                .await?
        } else {
            continue;
        };
        let names = columns
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect::<Vec<_>>();
        ordered_unique |= names == ["destination_participant_id", "mailbox_sequence"];
    }
    if !ordered_unique {
        return Err(DatabaseError::SchemaCorrupt);
    }
    let delivery_index: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'mailbox_session_delivery_state' AND tbl_name = 'messages'",
    )
    .fetch_optional(&mut *connection)
    .await?;
    if delivery_index.is_none() {
        return Err(DatabaseError::SchemaCorrupt);
    }
    validate_message_delivery_projection(connection).await?;
    let topology_index: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'participant_children' AND sql LIKE '%session_id, parent_participant_id, participant_id%'",
    )
    .fetch_optional(&mut *connection)
    .await?;
    if topology_index.is_none() {
        return Err(DatabaseError::SchemaCorrupt);
    }
    let invalid_topology: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM participants child
         LEFT JOIN participants parent ON parent.participant_id = child.parent_participant_id
         WHERE child.depth NOT BETWEEN 1 AND 8
            OR (child.parent_participant_id IS NULL AND child.depth != 1)
            OR (child.parent_participant_id IS NOT NULL AND
                (parent.participant_id IS NULL OR parent.session_id != child.session_id OR child.depth != parent.depth + 1))",
    )
    .fetch_one(&mut *connection)
    .await?;
    let excessive_children: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM participants WHERE parent_participant_id IS NOT NULL GROUP BY session_id, parent_participant_id HAVING COUNT(*) > 64 LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let excessive_total: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM participants GROUP BY session_id HAVING COUNT(*) > 1024 LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await?;
    if invalid_topology != 0 || excessive_children.is_some() || excessive_total.is_some() {
        return Err(DatabaseError::SchemaCorrupt);
    }
    let invalid_waiting_correlation: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM operations
         WHERE (state = 'waiting') != (waiting_on_message_id IS NOT NULL)",
    )
    .fetch_one(&mut *connection)
    .await?;
    if invalid_waiting_correlation != 0 {
        return Err(DatabaseError::SchemaCorrupt);
    }
    validate_authority_rows(connection).await?;
    validate_tool_rows(connection).await?;
    validate_approval_schema(connection).await?;
    validate_projection_schema(connection).await?;
    if !sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&mut *connection)
        .await?
        .is_empty()
    {
        return Err(DatabaseError::SchemaCorrupt);
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "fail-closed projection schema audit is intentionally centralized"
)]
async fn validate_projection_schema(
    connection: &mut SqliteConnection,
) -> Result<(), DatabaseError> {
    let metadata: Option<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT singleton,token_secret FROM projection_metadata")
            .fetch_optional(&mut *connection)
            .await?;
    if metadata.is_none_or(|(singleton, secret)| {
        singleton != 1 || secret.len() != 32 || secret.iter().all(|byte| *byte == 0)
    }) {
        return Err(DatabaseError::SchemaCorrupt);
    }
    let index = sqlx::query(
        "SELECT `unique`,partial FROM pragma_index_list('projection_rows') WHERE name='projection_rows_page'",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let columns =
        sqlx::query("SELECT name FROM pragma_index_info('projection_rows_page') ORDER BY seqno")
            .fetch_all(&mut *connection)
            .await?
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect::<Vec<_>>();
    if index
        .as_ref()
        .is_none_or(|row| row.get::<i64, _>("unique") != 0 || row.get::<i64, _>("partial") != 0)
        || columns != ["session_id", "generation", "view", "sort_key", "item_key"]
    {
        return Err(DatabaseError::SchemaCorrupt);
    }
    let lease_fks = sqlx::query("SELECT `table`,`from`,`to`,`on_update`,`on_delete`,`match` FROM pragma_foreign_key_list('subscription_leases')")
        .fetch_all(&mut *connection).await?;
    for (from, target, to, on_delete) in [
        (
            "reservation_id",
            "capacity_reservations",
            "reservation_id",
            "CASCADE",
        ),
        ("session_id", "sessions", "session_id", "NO ACTION"),
        ("campaign_id", "participants", "participant_id", "NO ACTION"),
    ] {
        if !lease_fks.iter().any(|row| {
            row.get::<String, _>("from") == from
                && row.get::<String, _>("table") == target
                && row.get::<String, _>("to") == to
                && row.get::<String, _>("on_update") == "NO ACTION"
                && row.get::<String, _>("on_delete") == on_delete
                && row.get::<String, _>("match") == "NONE"
        }) {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    let lease_index: Option<(i64,i64)> = sqlx::query_as("SELECT `unique`,partial FROM pragma_index_list('subscription_leases') WHERE name='subscription_leases_session_owner_expiry'")
        .fetch_optional(&mut *connection).await?;
    let lease_index_columns: Vec<String> = sqlx::query("SELECT name FROM pragma_index_info('subscription_leases_session_owner_expiry') ORDER BY seqno")
        .fetch_all(&mut *connection).await?.iter().map(|row|row.get("name")).collect();
    if lease_index != Some((0, 0))
        || lease_index_columns
            != [
                "session_id",
                "owner_epoch",
                "expires_at_seconds",
                "expires_at_nanos",
                "reservation_id",
            ]
    {
        return Err(DatabaseError::SchemaCorrupt);
    }
    for (query, expected) in [
        (
            "PRAGMA foreign_key_list(projection_generations)",
            vec![("session_id", "sessions", "session_id", "NO ACTION")],
        ),
        (
            "PRAGMA foreign_key_list(projection_rows)",
            vec![
                (
                    "session_id",
                    "projection_generations",
                    "session_id",
                    "CASCADE",
                ),
                (
                    "generation",
                    "projection_generations",
                    "generation",
                    "CASCADE",
                ),
            ],
        ),
        (
            "PRAGMA foreign_key_list(projection_heads)",
            vec![
                (
                    "session_id",
                    "projection_generations",
                    "session_id",
                    "NO ACTION",
                ),
                (
                    "generation",
                    "projection_generations",
                    "generation",
                    "NO ACTION",
                ),
                ("session_id", "sessions", "session_id", "NO ACTION"),
            ],
        ),
        (
            "PRAGMA foreign_key_list(projection_progress)",
            vec![
                (
                    "session_id",
                    "projection_generations",
                    "session_id",
                    "CASCADE",
                ),
                (
                    "generation",
                    "projection_generations",
                    "generation",
                    "CASCADE",
                ),
                ("session_id", "sessions", "session_id", "NO ACTION"),
            ],
        ),
    ] {
        let foreign_keys = sqlx::query(query).fetch_all(&mut *connection).await?;
        let actual = foreign_keys
            .iter()
            .map(|row| {
                (
                    row.get::<String, _>("from"),
                    row.get::<String, _>("table"),
                    row.get::<String, _>("to"),
                    row.get::<String, _>("on_delete"),
                )
            })
            .collect::<Vec<_>>();
        if actual.len() != expected.len()
            || expected.iter().any(|expected| {
                !actual.iter().any(|actual| {
                    actual.0 == expected.0
                        && actual.1 == expected.1
                        && actual.2 == expected.2
                        && actual.3 == expected.3
                })
            })
            || foreign_keys.iter().any(|row| {
                row.get::<String, _>("on_update") != "NO ACTION"
                    || row.get::<String, _>("match") != "NONE"
            })
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    let invalid: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM projection_heads h JOIN projection_generations g ON g.session_id=h.session_id AND g.generation=h.generation WHERE g.state!='published' OR h.checkpoint_position!=g.checkpoint_position OR h.source_head_position!=g.source_head_position",
    )
    .fetch_one(&mut *connection)
    .await?;
    let invalid_generation: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM projection_generations g
         LEFT JOIN projection_heads h ON h.session_id=g.session_id AND h.generation=g.generation
         WHERE (g.state='published') != (h.session_id IS NOT NULL)
            OR (g.state='unhealthy' AND EXISTS (SELECT 1 FROM projection_rows r WHERE r.session_id=g.session_id AND r.generation=g.generation))
         LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let invalid_row: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM projection_rows r JOIN projection_generations g USING(session_id,generation)
         WHERE g.state='unhealthy' OR length(r.item_key)=0 OR length(r.item_key)>512
            OR length(r.sort_key)>512 OR json_valid(r.data)=0
            OR COALESCE(json_extract(r.data,'$.schema_version'),-1)!=1
            OR COALESCE(json_extract(r.data,'$.session_id'),'')!=r.session_id
            OR (r.view='session_tree' AND COALESCE(json_extract(r.data,'$.participant_id'),'')!=r.item_key)
            OR (r.view='active_work' AND COALESCE(json_extract(r.data,'$.operation_id'),'')!=r.item_key)
            OR (r.view='delivery' AND COALESCE(json_extract(r.data,'$.message_id'),'')!=r.item_key)
            OR (r.view='approval' AND COALESCE(json_extract(r.data,'$.approval_id'),'')!=r.item_key)
            OR (r.view='recovery' AND COALESCE(json_extract(r.data,'$.entity_id'),json_extract(r.data,'$.request_id'),'')!=r.item_key)
         LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let invalid_progress: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM projection_progress p JOIN projection_generations g USING(session_id,generation)
         WHERE p.checkpoint_position>g.checkpoint_position
            OR EXISTS (SELECT 1 FROM projection_progress prior WHERE prior.session_id=p.session_id AND prior.generation=p.generation AND prior.ordinal<p.ordinal AND prior.checkpoint_position>p.checkpoint_position)
         LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let excessive_progress: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM projection_progress GROUP BY session_id HAVING COUNT(*)>8 LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await?;
    if invalid != 0
        || invalid_generation.is_some()
        || invalid_row.is_some()
        || invalid_progress.is_some()
        || excessive_progress.is_some()
    {
        return Err(DatabaseError::SchemaCorrupt);
    }
    validate_capacity_schema(connection).await?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fail-closed audit keeps capacity DDL, ceilings, and accounting together"
)]
async fn validate_capacity_schema(connection: &mut SqliteConnection) -> Result<(), DatabaseError> {
    for (table, required) in [
        (
            "capacity_reservations",
            &[
                " strict",
                "amount > 0",
                "released in (0,1)",
                "released_at_nanos between 0 and 999999999",
            ][..],
        ),
        (
            "capacity_global_reservations",
            &[
                " strict",
                "amount > 0",
                "released in (0,1)",
                "released_at_nanos between 0 and 999999999",
            ][..],
        ),
        (
            "capacity_session_usage",
            &[" strict", "used >= 0", "primary key (session_id, resource)"][..],
        ),
        (
            "capacity_global_usage",
            &[" strict", "used >= 0", "resource text primary key not null"][..],
        ),
        (
            "capacity_limits",
            &[
                " strict",
                "per_session > 0",
                "global_limit >= per_session",
                "configured in (0,1)",
            ][..],
        ),
        (
            "subscription_leases",
            &[
                " strict",
                "owner_epoch > 0",
                "expires_at_nanos between 0 and 999999999",
            ][..],
        ),
    ] {
        let sql: String =
            sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE type='table' AND name=?")
                .bind(table)
                .fetch_optional(&mut *connection)
                .await?
                .ok_or(DatabaseError::SchemaCorrupt)?;
        let normalized = sql.to_ascii_lowercase().replace(['\n', '\t'], " ");
        if required
            .iter()
            .any(|fragment| !normalized.contains(fragment))
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    for (table, expected) in [
        (
            "capacity_reservations",
            &[
                ("session_id", "sessions", "session_id"),
                ("campaign_id", "participants", "participant_id"),
            ][..],
        ),
        (
            "capacity_session_usage",
            &[("session_id", "sessions", "session_id")][..],
        ),
    ] {
        let rows = sqlx::query("SELECT `table`,`from`,`to`,`on_update`,`on_delete`,`match` FROM pragma_foreign_key_list(?)")
            .bind(table).fetch_all(&mut *connection).await?;
        if rows.len() != expected.len()
            || expected.iter().any(|(from, target, to)| {
                !rows.iter().any(|row| {
                    row.get::<String, _>("from") == *from
                        && row.get::<String, _>("table") == *target
                        && row.get::<String, _>("to") == *to
                        && row.get::<String, _>("on_update") == "NO ACTION"
                        && row.get::<String, _>("on_delete") == "NO ACTION"
                        && row.get::<String, _>("match") == "NONE"
                })
            })
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    let index = sqlx::query("SELECT `unique`,partial FROM pragma_index_list('capacity_reservations') WHERE name='capacity_reservations_session_resource'")
        .fetch_optional(&mut *connection).await?;
    let columns: Vec<String> = sqlx::query("SELECT name FROM pragma_index_info('capacity_reservations_session_resource') ORDER BY seqno")
        .fetch_all(&mut *connection).await?.iter().map(|row|row.get("name")).collect();
    if index
        .as_ref()
        .is_none_or(|row| row.get::<i64, _>("unique") != 0 || row.get::<i64, _>("partial") != 0)
        || columns != ["session_id", "resource", "released", "reservation_id"]
    {
        return Err(DatabaseError::SchemaCorrupt);
    }
    let invalid: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM capacity_reservations r JOIN participants p ON p.participant_id=r.campaign_id
         WHERE p.session_id!=r.session_id OR r.amount<=0 OR (r.released=0)!=(r.released_at_seconds IS NULL AND r.released_at_nanos IS NULL) LIMIT 1"
    ).fetch_optional(&mut *connection).await?;
    let mismatched_session: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM capacity_session_usage u WHERE u.used != COALESCE((SELECT SUM(r.amount) FROM capacity_reservations r WHERE r.session_id=u.session_id AND r.resource=u.resource AND r.released=0),0)
         OR u.used=0 AND NOT EXISTS(SELECT 1 FROM capacity_reservations r WHERE r.session_id=u.session_id AND r.resource=u.resource) LIMIT 1"
    ).fetch_optional(&mut *connection).await?;
    let mismatched_global: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM capacity_global_usage u WHERE u.used !=
         COALESCE((SELECT SUM(r.amount) FROM capacity_reservations r WHERE r.resource=u.resource AND r.released=0),0)+
         COALESCE((SELECT SUM(r.amount) FROM capacity_global_reservations r WHERE r.resource=u.resource AND r.released=0),0)
         OR u.used=0 AND NOT EXISTS(SELECT 1 FROM capacity_reservations r WHERE r.resource=u.resource)
         AND NOT EXISTS(SELECT 1 FROM capacity_global_reservations r WHERE r.resource=u.resource) LIMIT 1"
    ).fetch_optional(&mut *connection).await?;
    let missing_session_counter: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM capacity_reservations r WHERE r.released=0 AND NOT EXISTS(
         SELECT 1 FROM capacity_session_usage u WHERE u.session_id=r.session_id AND u.resource=r.resource
         ) LIMIT 1",
    ).fetch_optional(&mut *connection).await?;
    let missing_global_counter: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM (
         SELECT resource FROM capacity_reservations WHERE released=0 UNION ALL
         SELECT resource FROM capacity_global_reservations WHERE released=0
         ) r WHERE NOT EXISTS(SELECT 1 FROM capacity_global_usage u WHERE u.resource=r.resource) LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await?;
    let invalid_limits: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM capacity_limits WHERE per_session<=0 OR global_limit<per_session OR configured NOT IN (0,1) LIMIT 1",
    ).fetch_optional(&mut *connection).await?;
    let invalid_subscription_lease: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM subscription_leases l
         JOIN capacity_reservations r ON r.reservation_id=l.reservation_id
         JOIN participants p ON p.participant_id=l.campaign_id
         WHERE r.resource!='subscriptions' OR r.amount!=1 OR r.released!=0
            OR r.session_id!=l.session_id OR r.campaign_id!=l.campaign_id OR p.session_id!=l.session_id
            OR l.owner_epoch<=0 LIMIT 1",
    ).fetch_optional(&mut *connection).await?;
    let missing_subscription_lease: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM capacity_reservations r WHERE r.resource='subscriptions' AND r.released=0
         AND NOT EXISTS(SELECT 1 FROM subscription_leases l WHERE l.reservation_id=r.reservation_id) LIMIT 1",
    ).fetch_optional(&mut *connection).await?;
    let limit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM capacity_limits")
        .fetch_one(&mut *connection)
        .await?;
    let limit_rows = sqlx::query(
        "SELECT resource,per_session,global_limit FROM capacity_limits ORDER BY resource",
    )
    .fetch_all(&mut *connection)
    .await?;
    let limits_within_ceiling = limit_rows.iter().all(|row| {
        let resource = match row.get::<String, _>("resource").as_str() {
            "participants" => CapacityResource::Participants,
            "active_operations" => CapacityResource::ActiveOperations,
            "queued_operations" => CapacityResource::QueuedOperations,
            "messages" => CapacityResource::Messages,
            "message_bytes" => CapacityResource::MessageBytes,
            "artifacts" => CapacityResource::Artifacts,
            "artifact_bytes" => CapacityResource::ArtifactBytes,
            "pending_requests" => CapacityResource::PendingRequests,
            "subscriptions" => CapacityResource::Subscriptions,
            "retries" => CapacityResource::Retries,
            "retained_events" => CapacityResource::RetainedEvents,
            _ => return false,
        };
        let ceiling = LimitProfile::hard_ceiling(resource);
        u64::try_from(row.get::<i64, _>("per_session"))
            .is_ok_and(|value| value <= ceiling.per_session)
            && u64::try_from(row.get::<i64, _>("global_limit"))
                .is_ok_and(|value| value <= ceiling.global)
    });
    if invalid.is_some()
        || mismatched_session.is_some()
        || mismatched_global.is_some()
        || missing_session_counter.is_some()
        || missing_global_counter.is_some()
        || invalid_limits.is_some()
        || invalid_subscription_lease.is_some()
        || missing_subscription_lease.is_some()
        || limit_count != 11
        || !limits_within_ceiling
    {
        return Err(DatabaseError::SchemaCorrupt);
    }
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fail-closed audit keeps the approval schema, projections, and ledger coherent"
)]
pub(crate) async fn validate_approval_schema(
    connection: &mut SqliteConnection,
) -> Result<(), DatabaseError> {
    for (table, expected) in [
        (
            "approval_requests",
            &[
                ("session_id", "sessions", "session_id"),
                ("requester_id", "participants", "participant_id"),
                ("operation_id", "operations", "operation_id"),
            ][..],
        ),
        (
            "approval_grants",
            &[
                ("approval_id", "approval_requests", "approval_id"),
                ("session_id", "sessions", "session_id"),
                ("subject_id", "participants", "participant_id"),
                ("operation_id", "operations", "operation_id"),
            ][..],
        ),
        (
            "approval_effect_intents",
            &[
                ("session_id", "sessions", "session_id"),
                ("grant_id", "approval_grants", "grant_id"),
                ("operation_id", "operations", "operation_id"),
            ][..],
        ),
        (
            "approval_mutations",
            &[("session_id", "sessions", "session_id")][..],
        ),
    ] {
        let foreign_keys = sqlx::query(
            "SELECT `table`,`from`,`to`,`on_update`,`on_delete`,`match` FROM pragma_foreign_key_list(?)",
        )
                .bind(table)
                .fetch_all(&mut *connection)
                .await?;
        if foreign_keys.len() != expected.len()
            || expected.iter().any(|(from, target, to)| {
                !foreign_keys.iter().any(|row| {
                    row.get::<String, _>("from") == *from
                        && row.get::<String, _>("table") == *target
                        && row.get::<String, _>("to") == *to
                        && row.get::<String, _>("on_update") == "NO ACTION"
                        && row.get::<String, _>("on_delete") == "NO ACTION"
                        && row.get::<String, _>("match") == "NONE"
                })
            })
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }

    for (name, table, columns) in [
        (
            "approval_requests_session_status",
            "approval_requests",
            &["session_id", "status", "approval_id"][..],
        ),
        (
            "approval_grants_session_subject",
            "approval_grants",
            &["session_id", "subject_id", "grant_id"][..],
        ),
    ] {
        let index = sqlx::query("SELECT `unique`,partial FROM pragma_index_list(?) WHERE name=?")
            .bind(table)
            .bind(name)
            .fetch_optional(&mut *connection)
            .await?;
        let actual = sqlx::query("SELECT name FROM pragma_index_info(?) ORDER BY seqno")
            .bind(name)
            .fetch_all(&mut *connection)
            .await?
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect::<Vec<_>>();
        if index
            .as_ref()
            .is_none_or(|row| row.get::<i64, _>("unique") != 0 || row.get::<i64, _>("partial") != 0)
            || actual != columns
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    let indexes = sqlx::query("PRAGMA index_list(approval_grants)")
        .fetch_all(&mut *connection)
        .await?;
    let mut unique_request = false;
    for index in indexes {
        if index.get::<i64, _>("unique") == 0
            || index.get::<i64, _>("partial") != 0
            || index.get::<String, _>("origin") != "u"
        {
            continue;
        }
        let name: String = index.get("name");
        let columns = sqlx::query("SELECT name FROM pragma_index_info(?) ORDER BY seqno")
            .bind(name)
            .fetch_all(&mut *connection)
            .await?
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect::<Vec<_>>();
        unique_request |= columns == ["approval_id"];
    }
    if !unique_request {
        return Err(DatabaseError::SchemaCorrupt);
    }

    for (table, required) in [
        (
            "approval_requests",
            &[
                " strict",
                "status in ('pending','granted','consumed','denied','expired','revoked')",
                "length(capability) between 1 and 128",
                "length(resource_hash) = 32",
                "expires_nanos between 0 and 999999999",
                "revision > 0",
            ][..],
        ),
        (
            "approval_grants",
            &[
                " strict",
                "max_uses between 1 and 1024",
                "used_count between 0 and max_uses",
                "length(capability) between 1 and 128",
                "length(resource_hash) = 32",
                "expires_nanos between 0 and 999999999",
                "revoked in (0,1)",
                "revision > 0",
            ][..],
        ),
        (
            "approval_effect_intents",
            &[
                " strict",
                "phase in ('reserved','succeeded','failed','uncertain')",
                "revision > 0",
            ][..],
        ),
        (
            "approval_mutations",
            &[" strict", "length(semantic_digest) = 32"][..],
        ),
    ] {
        let sql: String =
            sqlx::query_scalar("SELECT sql FROM sqlite_master WHERE type='table' AND name=?")
                .bind(table)
                .fetch_optional(&mut *connection)
                .await?
                .ok_or(DatabaseError::SchemaCorrupt)?;
        let normalized = sql.to_ascii_lowercase().replace(['\n', '\t'], " ");
        if required
            .iter()
            .any(|fragment| !normalized.contains(fragment))
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }

    for row in sqlx::query("SELECT approval_id,session_id,requester_id,operation_id,capability,resource_hash,status,expires_seconds,expires_nanos,revision,snapshot FROM approval_requests")
        .fetch_all(&mut *connection).await?
    {
        let value: ApprovalRequest = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("snapshot")?)
            .map_err(|_| DatabaseError::SchemaCorrupt)?;
        let status = format!("{:?}", value.status).to_ascii_lowercase();
        if value.id.to_string() != row.try_get::<String, _>("approval_id")?
            || value.session_id.to_string() != row.try_get::<String, _>("session_id")?
            || value.requester_id.to_string() != row.try_get::<String, _>("requester_id")?
            || value.operation_id.to_string() != row.try_get::<String, _>("operation_id")?
            || value.capability.as_str() != row.try_get::<String, _>("capability")?
            || value.resource.digest().as_bytes().as_slice() != row.try_get::<Vec<u8>, _>("resource_hash")?
            || status != row.try_get::<String, _>("status")?
            || value.expires_at.unix_seconds() != row.try_get::<i64, _>("expires_seconds")?
            || i64::from(value.expires_at.nanoseconds()) != row.try_get::<i64, _>("expires_nanos")?
            || i64::try_from(value.revision.get()).ok() != Some(row.try_get("revision")?)
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let coherent_decision = match value.status {
            ApprovalStatus::Pending | ApprovalStatus::Expired => value.grant_id.is_none() && value.decision_source.is_none() && value.decided_at.is_none(),
            ApprovalStatus::Denied => value.grant_id.is_none() && value.decision_source.is_some() && value.decided_at.is_some(),
            ApprovalStatus::Granted | ApprovalStatus::Consumed | ApprovalStatus::Revoked => value.grant_id.is_some() && value.decision_source.is_some() && value.decided_at.is_some(),
        };
        if !coherent_decision { return Err(DatabaseError::SchemaCorrupt); }
        let causal: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT snapshot FROM messages WHERE message_id=? AND session_id=?",
        )
        .bind(value.source_message_id.to_string())
        .bind(value.session_id.to_string())
        .fetch_optional(&mut *connection)
        .await?;
        let causal = causal
            .and_then(|bytes| serde_json::from_slice::<navigator_store_api::MessageSnapshot>(&bytes).ok())
            .ok_or(DatabaseError::SchemaCorrupt)?;
        if causal.destination != value.requester_id
            || causal.source != value.coordinator_id
            || causal.correlation.operation_id != Some(value.operation_id)
            || !matches!(causal.state, navigator_store_api::MessageDeliveryState::Accepted { attempt_id, .. } if attempt_id == value.source_delivery_attempt_id)
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let operation: Option<(String, String, Vec<u8>)> = sqlx::query_as("SELECT participant_id,input_message_id,input_digest FROM operations WHERE operation_id=? AND session_id=?")
            .bind(value.operation_id.to_string()).bind(value.session_id.to_string()).fetch_optional(&mut *connection).await?;
        let (operation_participant, operation_input_message, operation_input_digest) = operation.ok_or(DatabaseError::SchemaCorrupt)?;
        let requester_parent: Option<Option<String>> = sqlx::query_scalar("SELECT parent_participant_id FROM participants WHERE participant_id=? AND session_id=?")
            .bind(value.requester_id.to_string()).bind(value.session_id.to_string()).fetch_optional(&mut *connection).await?;
        let requester_parent = requester_parent.ok_or(DatabaseError::SchemaCorrupt)?;
        let expected_coordinator = requester_parent.unwrap_or_else(|| value.requester_id.to_string());
        if operation_participant != value.requester_id.to_string()
            || operation_input_message != value.source_message_id.to_string()
            || expected_coordinator != value.coordinator_id.to_string()
            || !matches!(causal.envelope.body(), navigator_domain::MessageBody::OperationInput { operation_id, input_digest } if *operation_id == value.operation_id && input_digest.as_slice() == operation_input_digest.as_slice())
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let relay_required = matches!(value.status, ApprovalStatus::Denied | ApprovalStatus::Granted | ApprovalStatus::Consumed | ApprovalStatus::Revoked);
        let relay_rows: Vec<Vec<u8>> = sqlx::query_scalar("SELECT snapshot FROM messages WHERE session_id=? AND destination_participant_id=?")
            .bind(value.session_id.to_string()).bind(value.requester_id.to_string()).fetch_all(&mut *connection).await?;
        let matching: Vec<navigator_store_api::MessageSnapshot> = relay_rows.into_iter().filter_map(|bytes| serde_json::from_slice(&bytes).ok()).filter(|message: &navigator_store_api::MessageSnapshot| matches!(message.envelope.body(), navigator_domain::MessageBody::ApprovalDecision { approval_id, .. } if *approval_id == value.id)).collect();
        if relay_required != (matching.len() == 1) {
            return Err(DatabaseError::SchemaCorrupt);
        }
        if let Some(relay) = matching.first() {
            let expected_status = if value.status == ApprovalStatus::Denied { ApprovalStatus::Denied } else { ApprovalStatus::Granted };
            if relay.source != value.coordinator_id || relay.destination != value.requester_id
                || relay.correlation.operation_id != Some(value.operation_id)
                || relay.correlation.in_reply_to != Some(value.source_message_id)
                || !matches!(relay.envelope.body(), navigator_domain::MessageBody::ApprovalDecision { approval_id, operation_id, status, grant_id } if *approval_id == value.id && *operation_id == value.operation_id && *status == expected_status && *grant_id == value.grant_id)
            {
                return Err(DatabaseError::SchemaCorrupt);
            }
        }
    }
    for row in sqlx::query("SELECT grant_id,approval_id,session_id,subject_id,operation_id,capability,resource_hash,max_uses,used_count,expires_seconds,expires_nanos,revoked,revision,snapshot FROM approval_grants")
        .fetch_all(&mut *connection).await?
    {
        let value: ApprovalGrant = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("snapshot")?)
            .map_err(|_| DatabaseError::SchemaCorrupt)?;
        if value.id.to_string() != row.try_get::<String, _>("grant_id")?
            || value.request_id.to_string() != row.try_get::<String, _>("approval_id")?
            || value.session_id.to_string() != row.try_get::<String, _>("session_id")?
            || value.subject_id.to_string() != row.try_get::<String, _>("subject_id")?
            || value.operation_id.to_string() != row.try_get::<String, _>("operation_id")?
            || value.capability.as_str() != row.try_get::<String, _>("capability")?
            || value.resource_hash.as_bytes().as_slice() != row.try_get::<Vec<u8>, _>("resource_hash")?
            || i64::from(value.max_uses) != row.try_get::<i64, _>("max_uses")?
            || i64::from(value.used_count) != row.try_get::<i64, _>("used_count")?
            || value.expires_at.unix_seconds() != row.try_get::<i64, _>("expires_seconds")?
            || i64::from(value.expires_at.nanoseconds()) != row.try_get::<i64, _>("expires_nanos")?
            || value.revoked_at.is_some() != (row.try_get::<i64, _>("revoked")? == 1)
            || i64::try_from(value.revision.get()).ok() != Some(row.try_get("revision")?)
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    for row in sqlx::query("SELECT effect_id,session_id,grant_id,operation_id,phase,revision,snapshot FROM approval_effect_intents")
        .fetch_all(&mut *connection).await?
    {
        let value: ApprovalEffectIntent = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("snapshot")?)
            .map_err(|_| DatabaseError::SchemaCorrupt)?;
        let phase = format!("{:?}", value.phase).to_ascii_lowercase();
        if value.effect_id.to_string() != row.try_get::<String, _>("effect_id")?
            || value.session_id.to_string() != row.try_get::<String, _>("session_id")?
            || value.grant_id.to_string() != row.try_get::<String, _>("grant_id")?
            || value.operation_id.to_string() != row.try_get::<String, _>("operation_id")?
            || phase != row.try_get::<String, _>("phase")?
            || i64::try_from(value.revision.get()).ok() != Some(row.try_get("revision")?)
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        if matches!(value.phase, navigator_domain::ApprovalEffectPhase::Reserved) != value.finished_at.is_none() {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    let invalid_scope: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM approval_requests a
         JOIN participants p ON p.participant_id=a.requester_id
         JOIN operations o ON o.operation_id=a.operation_id
         WHERE p.session_id!=a.session_id OR o.session_id!=a.session_id OR o.participant_id!=a.requester_id
         UNION ALL
         SELECT 1 FROM approval_grants g JOIN approval_requests a ON a.approval_id=g.approval_id
         WHERE g.session_id!=a.session_id OR g.subject_id!=a.requester_id OR g.operation_id!=a.operation_id
            OR g.capability!=a.capability OR g.resource_hash!=a.resource_hash
            OR a.status NOT IN ('granted','consumed','revoked')
            OR (a.status='revoked')!=(g.revoked=1)
            OR (a.status IN ('granted','consumed'))!=(g.revoked=0)
            OR json_extract(a.snapshot,'$.grant_id')!=g.grant_id
            OR g.expires_seconds>a.expires_seconds
            OR (g.expires_seconds=a.expires_seconds AND g.expires_nanos>a.expires_nanos)
         UNION ALL
         SELECT 1 FROM approval_effect_intents e JOIN approval_grants g ON g.grant_id=e.grant_id
         WHERE e.session_id!=g.session_id OR e.operation_id!=g.operation_id
            OR json_extract(e.snapshot,'$.subject_id')!=g.subject_id
            OR json_extract(e.snapshot,'$.capability')!=g.capability
            OR json_extract(e.snapshot,'$.resource_hash')!=json_extract(g.snapshot,'$.resource_hash')
         UNION ALL
         SELECT 1 FROM approval_grants g
         WHERE g.used_count!=(SELECT COUNT(*) FROM approval_effect_intents e WHERE e.grant_id=g.grant_id)
         LIMIT 1",
    )
    .fetch_optional(&mut *connection)
    .await?;
    if invalid_scope.is_some() {
        return Err(DatabaseError::SchemaCorrupt);
    }
    for row in sqlx::query("SELECT request_id,session_id,caller_host_id,action,semantic_digest,result FROM approval_mutations")
        .fetch_all(&mut *connection).await?
    {
        let request_id = row.try_get::<String, _>("request_id")?;
        let caller = row.try_get::<String, _>("caller_host_id")?;
        if uuid::Uuid::parse_str(&request_id)
            .ok()
            .is_none_or(|value| value.is_nil())
            || uuid::Uuid::parse_str(&caller)
                .ok()
                .is_none_or(|value| value.is_nil())
            || row.try_get::<Vec<u8>, _>("semantic_digest")?.len() != 32
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let session_id = row.try_get::<String, _>("session_id")?;
        let result = row.try_get::<Vec<u8>, _>("result")?;
        let action = row.try_get::<String, _>("action")?;
        let valid = match action.as_str() {
            "approval.request" | "approval.deny" | "approval.expire" => {
                let historical = serde_json::from_slice::<ApprovalRequest>(&result)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?;
                let current: Option<Vec<u8>> = sqlx::query_scalar(
                    "SELECT snapshot FROM approval_requests WHERE approval_id=? AND session_id=?",
                ).bind(historical.id.to_string()).bind(&session_id)
                    .fetch_optional(&mut *connection).await?;
                let current = current.and_then(|bytes| serde_json::from_slice::<ApprovalRequest>(&bytes).ok());
                current.is_some_and(|current| {
                    historical.session_id.to_string() == session_id
                        && historical.id == current.id
                        && historical.session_id == current.session_id
                        && historical.requester_id == current.requester_id
                        && historical.operation_id == current.operation_id
                        && historical.capability == current.capability
                        && historical.resource == current.resource
                        && historical.summary == current.summary
                        && historical.created_at == current.created_at
                        && historical.expires_at == current.expires_at
                        && historical.revision <= current.revision
                        && matches!((action.as_str(), historical.status),
                            ("approval.request", ApprovalStatus::Pending)
                            | ("approval.deny", ApprovalStatus::Denied)
                            | ("approval.expire", ApprovalStatus::Expired))
                })
            }
            "approval.approve" => {
                let historical = serde_json::from_slice::<ApprovedRequest>(&result)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?;
                let request: Option<Vec<u8>> = sqlx::query_scalar("SELECT snapshot FROM approval_requests WHERE approval_id=? AND session_id=?")
                    .bind(historical.request.id.to_string()).bind(&session_id).fetch_optional(&mut *connection).await?;
                let grant: Option<Vec<u8>> = sqlx::query_scalar("SELECT snapshot FROM approval_grants WHERE grant_id=? AND approval_id=? AND session_id=?")
                    .bind(historical.grant.id.to_string()).bind(historical.request.id.to_string()).bind(&session_id)
                    .fetch_optional(&mut *connection).await?;
                request.and_then(|b| serde_json::from_slice::<ApprovalRequest>(&b).ok()).is_some_and(|current| {
                    historical.request.session_id.to_string() == session_id
                        && historical.grant.session_id.to_string() == session_id
                        && historical.request.id == current.id
                        && historical.request.requester_id == current.requester_id
                        && historical.request.operation_id == current.operation_id
                        && historical.request.capability == current.capability
                        && historical.request.resource == current.resource
                        && historical.request.summary == current.summary
                        && historical.request.expires_at == current.expires_at
                        && historical.request.created_at == current.created_at
                        && historical.request.status == ApprovalStatus::Granted
                        && historical.request.grant_id == Some(historical.grant.id)
                        && historical.request.requester_id == historical.grant.subject_id
                        && historical.request.operation_id == historical.grant.operation_id
                        && historical.request.capability == historical.grant.capability
                        && historical.request.resource.digest() == historical.grant.resource_hash
                        && historical.request.revision <= current.revision
                }) && grant.and_then(|b| serde_json::from_slice::<ApprovalGrant>(&b).ok()).is_some_and(|current| {
                    historical.grant.request_id == historical.request.id
                        && historical.grant.revision <= current.revision
                        && historical.grant.session_id == current.session_id
                        && historical.grant.subject_id == current.subject_id
                        && historical.grant.operation_id == current.operation_id
                        && historical.grant.capability == current.capability
                        && historical.grant.resource_hash == current.resource_hash
                        && historical.grant.id == current.id
                        && historical.grant.request_id == current.request_id
                        && historical.grant.max_uses == current.max_uses
                        && historical.grant.expires_at == current.expires_at
                        && historical.grant.created_at == current.created_at
                        && historical.grant.issued_by == current.issued_by
                })
            }
            "approval.revoke" => {
                let historical = serde_json::from_slice::<ApprovalGrant>(&result)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?;
                let current: Option<Vec<u8>> = sqlx::query_scalar("SELECT snapshot FROM approval_grants WHERE grant_id=? AND session_id=?")
                    .bind(historical.id.to_string()).bind(&session_id).fetch_optional(&mut *connection).await?;
                historical.session_id.to_string() == session_id && historical.revoked_at.is_some() && current.and_then(|b| serde_json::from_slice::<ApprovalGrant>(&b).ok()).is_some_and(|current| {
                    historical.id == current.id && historical.request_id == current.request_id && historical.subject_id == current.subject_id
                        && historical.operation_id == current.operation_id && historical.capability == current.capability
                        && historical.resource_hash == current.resource_hash && historical.max_uses == current.max_uses
                        && historical.expires_at == current.expires_at && historical.created_at == current.created_at
                        && historical.issued_by == current.issued_by && historical.revision <= current.revision
                })
            }
            "approval.consume" => {
                let historical = serde_json::from_slice::<ConsumedApprovalGrant>(&result)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?;
                let grant: Option<Vec<u8>> = sqlx::query_scalar("SELECT snapshot FROM approval_grants WHERE grant_id=? AND session_id=?")
                    .bind(historical.grant.id.to_string()).bind(&session_id).fetch_optional(&mut *connection).await?;
                let effect: Option<Vec<u8>> = sqlx::query_scalar("SELECT snapshot FROM approval_effect_intents WHERE effect_id=? AND grant_id=? AND session_id=?")
                    .bind(historical.effect.effect_id.to_string()).bind(historical.grant.id.to_string()).bind(&session_id)
                    .fetch_optional(&mut *connection).await?;
                historical.grant.session_id.to_string() == session_id
                    && historical.effect.session_id.to_string() == session_id
                    && historical.effect.phase == navigator_domain::ApprovalEffectPhase::Reserved
                    && historical.effect.subject_id == historical.grant.subject_id
                    && historical.effect.operation_id == historical.grant.operation_id
                    && historical.effect.capability == historical.grant.capability
                    && historical.effect.resource_hash == historical.grant.resource_hash
                    && grant.and_then(|b| serde_json::from_slice::<ApprovalGrant>(&b).ok()).is_some_and(|c| {
                        historical.grant.id == c.id && historical.grant.request_id == c.request_id
                            && historical.grant.subject_id == c.subject_id && historical.grant.operation_id == c.operation_id
                            && historical.grant.capability == c.capability && historical.grant.resource_hash == c.resource_hash
                            && historical.grant.max_uses == c.max_uses && historical.grant.expires_at == c.expires_at
                            && historical.grant.created_at == c.created_at && historical.grant.issued_by == c.issued_by
                            && historical.grant.revision <= c.revision
                    })
                    && effect.and_then(|b| serde_json::from_slice::<ApprovalEffectIntent>(&b).ok()).is_some_and(|c| {
                        historical.effect.effect_id == c.effect_id && historical.effect.grant_id == c.grant_id
                            && historical.effect.subject_id == c.subject_id && historical.effect.operation_id == c.operation_id
                            && historical.effect.capability == c.capability && historical.effect.resource_hash == c.resource_hash
                            && historical.effect.created_at == c.created_at && historical.effect.revision <= c.revision
                    })
            }
            "approval.effect.finish" => {
                let historical = serde_json::from_slice::<ApprovalEffectIntent>(&result)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?;
                let current: Option<Vec<u8>> = sqlx::query_scalar("SELECT snapshot FROM approval_effect_intents WHERE effect_id=? AND session_id=?")
                    .bind(historical.effect_id.to_string()).bind(&session_id).fetch_optional(&mut *connection).await?;
                historical.session_id.to_string() == session_id
                    && historical.phase != navigator_domain::ApprovalEffectPhase::Reserved
                    && historical.finished_at.is_some()
                    && current.and_then(|b| serde_json::from_slice::<ApprovalEffectIntent>(&b).ok()).is_some_and(|c| {
                        historical.effect_id == c.effect_id && historical.grant_id == c.grant_id && historical.subject_id == c.subject_id
                            && historical.operation_id == c.operation_id && historical.capability == c.capability
                            && historical.resource_hash == c.resource_hash && historical.created_at == c.created_at
                            && historical.revision <= c.revision
                    })
            }
            _ => return Err(DatabaseError::SchemaCorrupt),
        };
        if !valid {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn validate_tool_rows(connection: &mut SqliteConnection) -> Result<(), DatabaseError> {
    let oversized_registration_set: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM tool_registrations GROUP BY session_id HAVING COUNT(*) > ? LIMIT 1",
    )
    .bind(i64::try_from(navigator_store_api::MAX_TOOL_REGISTRATIONS).expect("static bound fits"))
    .fetch_optional(&mut *connection)
    .await?;
    if oversized_registration_set.is_some() {
        return Err(DatabaseError::SchemaCorrupt);
    }
    for row in sqlx::query("SELECT session_id,registration_id,tool_name,tool_version,consumer_key,snapshot FROM tool_registrations")
        .fetch_all(&mut *connection).await?
    {
        let value: ToolRegistrationSnapshot = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("snapshot")?)
            .map_err(|_| DatabaseError::SchemaCorrupt)?;
        if value.session_id.to_string() != row.try_get::<String, _>("session_id")?
            || value.registration_id.to_string() != row.try_get::<String, _>("registration_id")?
            || value.definition.name() != row.try_get::<String, _>("tool_name")?
            || value.definition.version() != row.try_get::<String, _>("tool_version")?
            || value.consumer_key.as_str() != row.try_get::<String, _>("consumer_key")?
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let session_consumer: Option<String> = sqlx::query_scalar(
            "SELECT consumer_key FROM sessions WHERE session_id=?",
        )
        .bind(value.session_id.to_string())
        .fetch_optional(&mut *connection)
        .await?;
        if session_consumer.as_deref() != Some(value.consumer_key.as_str()) {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    for row in sqlx::query("SELECT invocation_id,effect_request_id,registration_id,dispatch_id,provider_id,server_sequence,deadline_seconds,deadline_nanos,connection_generation,cancellation_id,cancellation_server_sequence,terminal_digest,session_id,participant_id,operation_id,tool_name,tool_version,snapshot FROM tool_invocations")
        .fetch_all(&mut *connection).await?
    {
        let value: ToolInvocationSnapshot = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("snapshot")?)
            .map_err(|_| DatabaseError::SchemaCorrupt)?;
        let invocation = value.invocation();
        let dispatch = value.dispatch();
        let text = |name| row.try_get::<String, _>(name);
        if invocation.invocation_id().to_string() != text("invocation_id")?
            || invocation.request_id().to_string() != text("effect_request_id")?
            || value.registration_id().to_string() != text("registration_id")?
            || dispatch.dispatch_id.to_string() != text("dispatch_id")?
            || dispatch.provider_id.to_string() != text("provider_id")?
            || i64::try_from(dispatch.server_sequence).ok() != Some(row.try_get("server_sequence")?)
            || dispatch.deadline.unix_seconds() != row.try_get::<i64, _>("deadline_seconds")?
            || i64::from(dispatch.deadline.nanoseconds()) != row.try_get::<i64, _>("deadline_nanos")?
            || dispatch.connection_generation.and_then(|v| i64::try_from(v).ok()) != row.try_get("connection_generation")?
            || dispatch.cancellation_id.map(|v| v.to_string()) != row.try_get("cancellation_id")?
            || dispatch.cancellation_server_sequence.and_then(|v| i64::try_from(v).ok()) != row.try_get("cancellation_server_sequence")?
            || dispatch.terminal_digest.map(|v| v.as_bytes().to_vec()) != row.try_get("terminal_digest")?
            || invocation.session_id().to_string() != text("session_id")?
            || invocation.participant_id().to_string() != text("participant_id")?
            || invocation.operation_id().to_string() != text("operation_id")?
            || invocation.tool_name() != text("tool_name")?
            || invocation.tool_version() != text("tool_version")?
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let registration: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM tool_registrations WHERE session_id=? AND registration_id=?")
            .bind(invocation.session_id().to_string()).bind(value.registration_id().to_string())
            .fetch_optional(&mut *connection).await?.ok_or(DatabaseError::SchemaCorrupt)?;
        let registration: ToolRegistrationSnapshot = serde_json::from_slice(&registration)
            .map_err(|_| DatabaseError::SchemaCorrupt)?;
        if registration.definition != *value.definition() {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let participant = sqlx::query("SELECT session_id FROM participants WHERE participant_id=?")
            .bind(invocation.participant_id().to_string()).fetch_optional(&mut *connection).await?
            .ok_or(DatabaseError::SchemaCorrupt)?;
        let operation = sqlx::query("SELECT session_id,participant_id FROM operations WHERE operation_id=?")
            .bind(invocation.operation_id().to_string()).fetch_optional(&mut *connection).await?
            .ok_or(DatabaseError::SchemaCorrupt)?;
        if participant.try_get::<String, _>("session_id")? != invocation.session_id().to_string()
            || operation.try_get::<String, _>("session_id")? != invocation.session_id().to_string()
            || operation.try_get::<String, _>("participant_id")? != invocation.participant_id().to_string()
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let effect = sqlx::query("SELECT session_id,participant_id,operation_id,action,effect_class,phase,revision FROM effect_journal WHERE request_id=?")
            .bind(invocation.request_id().to_string()).fetch_optional(&mut *connection).await?
            .ok_or(DatabaseError::SchemaCorrupt)?;
        let effect_phase: String = effect.try_get("phase")?;
        if effect.try_get::<String, _>("session_id")? != invocation.session_id().to_string()
            || effect.try_get::<String, _>("participant_id")? != invocation.participant_id().to_string()
            || effect.try_get::<String, _>("operation_id")? != invocation.operation_id().to_string()
            || effect.try_get::<String, _>("action")? != value.definition().required_authority().as_str()
            || effect.try_get::<String, _>("effect_class")? != effect_class_name(value.definition().effect_class())
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let phase_matches = matches!(
            (value.phase(), effect_phase.as_str()),
            (navigator_store_api::ToolInvocationPhase::Reserved, "reserved" | "retry_authorized")
                | (navigator_store_api::ToolInvocationPhase::Started, "started")
                | (navigator_store_api::ToolInvocationPhase::Uncertain, "uncertain")
                | (navigator_store_api::ToolInvocationPhase::Completed, "completed")
                | (navigator_store_api::ToolInvocationPhase::Failed, "failed" | "completed")
        );
        if !phase_matches || i64::try_from(value.revision().get()).ok() != Some(effect.try_get("revision")?) {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let expected_terminal_digest = match value.terminal() {
            Some(navigator_store_api::ToolTerminal::Completed(result)) => Some(SemanticDigest::v1(
                &Capability::new("tool.result").expect("static capability"),
                &serde_json::to_vec(result).map_err(|_| DatabaseError::SchemaCorrupt)?,
            )),
            Some(navigator_store_api::ToolTerminal::Failed(failure)) => Some(SemanticDigest::v1(
                &Capability::new("tool.failure").expect("static capability"),
                &serde_json::to_vec(failure).map_err(|_| DatabaseError::SchemaCorrupt)?,
            )),
            None => None,
        };
        if dispatch.terminal_digest != expected_terminal_digest {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let historical_connects: Vec<Vec<u8>> = sqlx::query_scalar(
            "SELECT result FROM request_ledger WHERE session_id=? AND action='tool.provider.connect' AND outcome='succeeded'",
        )
        .bind(invocation.session_id().to_string())
        .fetch_all(&mut *connection)
        .await?;
        let historically_registered = historical_connects.iter().any(|bytes| {
            serde_json::from_slice::<ToolProviderConnectionSnapshot>(bytes)
                .ok()
                .is_some_and(|provider| {
                    provider.provider_id == dispatch.provider_id
                        && provider.registration_ids.contains(&value.registration_id())
                        && dispatch
                            .connection_generation
                            .is_some_and(|generation| provider.generation <= generation)
                })
        });
        if !historically_registered {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    for row in sqlx::query("SELECT session_id,provider_id,connection_id,consumer_key,generation,acknowledged_server_sequence,next_server_sequence,registrations FROM tool_provider_connections")
        .fetch_all(&mut *connection).await?
    {
        let registrations: Vec<navigator_domain::ToolRegistrationId> = serde_json::from_slice(&row.try_get::<Vec<u8>, _>("registrations")?)
            .map_err(|_| DatabaseError::SchemaCorrupt)?;
        let mut unique = registrations.clone();
        unique.sort();
        unique.dedup();
        let ack: i64 = row.try_get("acknowledged_server_sequence")?;
        let next: i64 = row.try_get("next_server_sequence")?;
        let valid_id = |column| {
            row.try_get::<String, _>(column)
                .ok()
                .and_then(|value| uuid::Uuid::parse_str(&value).ok())
                .is_some_and(|value| !value.is_nil())
        };
        if registrations.is_empty()
            || registrations.len() > navigator_store_api::MAX_TOOL_REGISTRATIONS
            || unique.len() != registrations.len()
            || !valid_id("session_id")
            || !valid_id("provider_id")
            || !valid_id("connection_id")
            || row.try_get::<i64, _>("generation")? <= 0
            || ack < 0
            || next <= ack
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let session_id = row.try_get::<String, _>("session_id")?;
        let provider_id = row.try_get::<String, _>("provider_id")?;
        let provider_consumer: String = row.try_get("consumer_key")?;
        let session_consumer: Option<String> = sqlx::query_scalar(
            "SELECT consumer_key FROM sessions WHERE session_id=?",
        )
        .bind(&session_id)
        .fetch_optional(&mut *connection)
        .await?;
        if session_consumer.as_deref() != Some(provider_consumer.as_str()) {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let mut allocated = BTreeMap::<i64, bool>::new();
        for invocation_row in sqlx::query("SELECT server_sequence,cancellation_server_sequence,snapshot FROM tool_invocations WHERE session_id=? AND provider_id=?")
            .bind(&session_id).bind(&provider_id).fetch_all(&mut *connection).await?
        {
            let value: ToolInvocationSnapshot = serde_json::from_slice(&invocation_row.try_get::<Vec<u8>, _>("snapshot")?)
                .map_err(|_| DatabaseError::SchemaCorrupt)?;
            let dispatch_sequence: i64 = invocation_row.try_get("server_sequence")?;
            let dispatch_ackable = matches!(value.phase(), navigator_store_api::ToolInvocationPhase::Completed | navigator_store_api::ToolInvocationPhase::Failed)
                || value.dispatch().cancellation_id.is_some();
            if allocated.insert(dispatch_sequence, dispatch_ackable).is_some() {
                return Err(DatabaseError::SchemaCorrupt);
            }
            if let Some(cancel_sequence) = invocation_row.try_get::<Option<i64>, _>("cancellation_server_sequence")?
                && allocated.insert(cancel_sequence, true).is_some()
            {
                return Err(DatabaseError::SchemaCorrupt);
            }
        }
        if i64::try_from(allocated.len()).map_err(|_| DatabaseError::SchemaCorrupt)? != next - 1
            || allocated.keys().copied().ne(1..next)
            || (ack > 0 && allocated.range(1..=ack).any(|(_, ackable)| !ackable))
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        for id in registrations {
            let consumer: Option<String> = sqlx::query_scalar("SELECT consumer_key FROM tool_registrations WHERE session_id=? AND registration_id=?")
                .bind(row.try_get::<String, _>("session_id")?).bind(id.to_string()).fetch_optional(&mut *connection).await?;
            if consumer.as_deref() != Some(provider_consumer.as_str()) { return Err(DatabaseError::SchemaCorrupt); }
        }
    }
    validate_tool_replay_results(connection).await?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn validate_tool_replay_results(
    connection: &mut SqliteConnection,
) -> Result<(), DatabaseError> {
    let mut latest_connections = HashMap::<
        (SessionId, navigator_domain::ToolProviderId),
        ToolProviderConnectionSnapshot,
    >::new();
    let mut connection_generations =
        HashMap::<(SessionId, navigator_domain::ToolProviderId), BTreeSet<u64>>::new();
    for row in sqlx::query("SELECT session_id,request_id,caller_host_id,action,semantic_digest,result FROM request_ledger WHERE outcome='succeeded' AND action IN ('tool.register','tool.provider.connect')")
        .fetch_all(&mut *connection).await?
    {
        let session_id: String = row.try_get("session_id")?;
        let bytes: Vec<u8> = row.try_get("result")?;
        let request_id = RequestId::from_uuid(uuid::Uuid::parse_str(&row.try_get::<String, _>("request_id")?).map_err(|_| DatabaseError::SchemaCorrupt)?).map_err(|_| DatabaseError::SchemaCorrupt)?;
        let caller = HostId::from_uuid(uuid::Uuid::parse_str(&row.try_get::<String, _>("caller_host_id")?).map_err(|_| DatabaseError::SchemaCorrupt)?).map_err(|_| DatabaseError::SchemaCorrupt)?;
        let session = SessionId::from_uuid(uuid::Uuid::parse_str(&session_id).map_err(|_| DatabaseError::SchemaCorrupt)?).map_err(|_| DatabaseError::SchemaCorrupt)?;
        let digest: Vec<u8> = row.try_get("semantic_digest")?;
        let high_water: i64 = sqlx::query_scalar("SELECT epoch_high_water FROM sessions WHERE session_id=?").bind(&session_id).fetch_one(&mut *connection).await?;
        match row.try_get::<String, _>("action")?.as_str() {
            "tool.register" => {
                let value: ToolRegistrationSnapshot = serde_json::from_slice(&bytes)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?;
                let current: Vec<u8> = sqlx::query_scalar("SELECT snapshot FROM tool_registrations WHERE session_id=? AND registration_id=?")
                    .bind(&session_id).bind(value.registration_id.to_string())
                    .fetch_optional(&mut *connection).await?.ok_or(DatabaseError::SchemaCorrupt)?;
                let current: ToolRegistrationSnapshot = serde_json::from_slice(&current)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?;
                if value.session_id.to_string() != session_id || value != current {
                    return Err(DatabaseError::SchemaCorrupt);
                }
                let mut digest_matches = false;
                for raw_epoch in 1..=high_water {
                    let epoch = FencingEpoch::new(u64::try_from(raw_epoch).map_err(|_| DatabaseError::SchemaCorrupt)?).map_err(|_| DatabaseError::SchemaCorrupt)?;
                    let command = RegisterTool { context: RequestContext::new(request_id, caller), session_id: session, owner_epoch: epoch, consumer_key: value.consumer_key.clone(), registration_id: value.registration_id, definition: value.definition.clone() };
                    digest_matches |= command.digest().as_bytes() == digest.as_slice();
                }
                if !digest_matches {
                    return Err(DatabaseError::SchemaCorrupt);
                }
            }
            "tool.provider.connect" => {
                let value: ToolProviderConnectionSnapshot = serde_json::from_slice(&bytes)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?;
                let event = sqlx::query("SELECT occurred_at_seconds,occurred_at_nanos FROM events WHERE related_request_id=? AND event_type='tool.provider_connected'")
                    .bind(request_id.to_string()).fetch_optional(&mut *connection).await?
                    .ok_or(DatabaseError::SchemaCorrupt)?;
                let current = sqlx::query("SELECT connection_id,generation,acknowledged_server_sequence,next_server_sequence FROM tool_provider_connections WHERE session_id=? AND provider_id=?")
                    .bind(&session_id).bind(value.provider_id.to_string())
                    .fetch_optional(&mut *connection).await?.ok_or(DatabaseError::SchemaCorrupt)?;
                let generation: i64 = current.try_get("generation")?;
                let acknowledged: i64 = current.try_get("acknowledged_server_sequence")?;
                let next: i64 = current.try_get("next_server_sequence")?;
                let recorded_generation = i64::try_from(value.generation).ok();
                let mut canonical_ids = value.registration_ids.clone();
                canonical_ids.sort();
                canonical_ids.dedup();
                let durable_consumer: String = sqlx::query_scalar(
                    "SELECT consumer_key FROM sessions WHERE session_id=?",
                )
                .bind(&session_id)
                .fetch_one(&mut *connection)
                .await?;
                if !value.is_structurally_valid()
                    || value.connected_at.unix_seconds() != event.try_get::<i64, _>("occurred_at_seconds")?
                    || i64::from(value.connected_at.nanoseconds()) != event.try_get::<i64, _>("occurred_at_nanos")?
                    || value.session_id.to_string() != session_id
                    || value.consumer_key.as_str() != durable_consumer
                    || value.registration_ids.is_empty()
                    || value.registration_ids != canonical_ids
                    || recorded_generation.is_none_or(|v| v > generation)
                    || i64::try_from(value.acknowledged_server_sequence).ok().is_none_or(|v| v > acknowledged)
                    || i64::try_from(value.next_server_sequence).ok().is_none_or(|v| v > next)
                {
                    return Err(DatabaseError::SchemaCorrupt);
                }
                for registration_id in &value.registration_ids {
                    let registration: Vec<u8> = sqlx::query_scalar(
                        "SELECT snapshot FROM tool_registrations WHERE session_id=? AND registration_id=? AND consumer_key=?",
                    )
                    .bind(&session_id)
                    .bind(registration_id.to_string())
                    .bind(value.consumer_key.as_str())
                    .fetch_optional(&mut *connection)
                    .await?
                    .ok_or(DatabaseError::SchemaCorrupt)?;
                    let registration: ToolRegistrationSnapshot = serde_json::from_slice(&registration)
                        .map_err(|_| DatabaseError::SchemaCorrupt)?;
                    if registration.session_id != value.session_id
                        || registration.consumer_key != value.consumer_key
                        || registration.registration_id != *registration_id
                    {
                        return Err(DatabaseError::SchemaCorrupt);
                    }
                }
                let mut digest_matches = false;
                for raw_epoch in 1..=high_water {
                    let epoch = FencingEpoch::new(u64::try_from(raw_epoch).map_err(|_| DatabaseError::SchemaCorrupt)?).map_err(|_| DatabaseError::SchemaCorrupt)?;
                    let command = ConnectToolProvider { context: RequestContext::new(request_id, caller), session_id: session, owner_epoch: epoch, consumer_key: value.consumer_key.clone(), provider_id: value.provider_id, connection_id: value.connection_id, after_server_sequence: value.acknowledged_server_sequence, registration_ids: value.registration_ids.clone() };
                    digest_matches |= command.digest().as_bytes() == digest.as_slice();
                }
                if !digest_matches {
                    return Err(DatabaseError::SchemaCorrupt);
                }
                let key = (value.session_id, value.provider_id);
                if !connection_generations
                    .entry(key)
                    .or_default()
                    .insert(value.generation)
                {
                    return Err(DatabaseError::SchemaCorrupt);
                }
                match latest_connections.get(&key) {
                    Some(latest)
                        if latest.generation == value.generation && latest != &value =>
                    {
                        return Err(DatabaseError::SchemaCorrupt);
                    }
                    Some(latest) if latest.generation > value.generation => {}
                    _ => {
                        latest_connections.insert(key, value);
                    }
                }
            }
            _ => unreachable!(),
        }
    }
    for ((session_id, provider_id), latest) in latest_connections {
        let generations = connection_generations
            .remove(&(session_id, provider_id))
            .ok_or(DatabaseError::SchemaCorrupt)?;
        if generations.len()
            != usize::try_from(latest.generation).map_err(|_| DatabaseError::SchemaCorrupt)?
            || generations.iter().copied().ne(1..=latest.generation)
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        let current = sqlx::query("SELECT connection_id,consumer_key,generation,acknowledged_server_sequence,next_server_sequence,connected_at_seconds,connected_at_nanos,registrations FROM tool_provider_connections WHERE session_id=? AND provider_id=?")
            .bind(session_id.to_string())
            .bind(provider_id.to_string())
            .fetch_optional(&mut *connection)
            .await?
            .ok_or(DatabaseError::SchemaCorrupt)?;
        let registrations: Vec<navigator_domain::ToolRegistrationId> =
            serde_json::from_slice(&current.try_get::<Vec<u8>, _>("registrations")?)
                .map_err(|_| DatabaseError::SchemaCorrupt)?;
        if current.try_get::<String, _>("connection_id")? != latest.connection_id.to_string()
            || current.try_get::<String, _>("consumer_key")? != latest.consumer_key.as_str()
            || current.try_get::<i64, _>("generation")?
                != i64::try_from(latest.generation).map_err(|_| DatabaseError::SchemaCorrupt)?
            || current.try_get::<i64, _>("acknowledged_server_sequence")?
                != i64::try_from(latest.acknowledged_server_sequence)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?
            || current.try_get::<i64, _>("next_server_sequence")?
                < i64::try_from(latest.next_server_sequence)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?
            || current.try_get::<i64, _>("connected_at_seconds")?
                != latest.connected_at.unix_seconds()
            || current.try_get::<i64, _>("connected_at_nanos")?
                != i64::from(latest.connected_at.nanoseconds())
            || registrations != latest.registration_ids
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    for row in sqlx::query("SELECT invocation_id,result FROM tool_invocation_mutations")
        .fetch_all(&mut *connection)
        .await?
    {
        let invocation_id: String = row.try_get("invocation_id")?;
        let recorded: ToolInvocationSnapshot =
            serde_json::from_slice(&row.try_get::<Vec<u8>, _>("result")?)
                .map_err(|_| DatabaseError::SchemaCorrupt)?;
        let current: Vec<u8> =
            sqlx::query_scalar("SELECT snapshot FROM tool_invocations WHERE invocation_id=?")
                .bind(&invocation_id)
                .fetch_optional(&mut *connection)
                .await?
                .ok_or(DatabaseError::SchemaCorrupt)?;
        let current: ToolInvocationSnapshot =
            serde_json::from_slice(&current).map_err(|_| DatabaseError::SchemaCorrupt)?;
        if recorded.invocation().invocation_id().to_string() != invocation_id
            || recorded.invocation() != current.invocation()
            || recorded.definition() != current.definition()
            || recorded.registration_id() != current.registration_id()
            || recorded.dispatch().dispatch_id != current.dispatch().dispatch_id
            || recorded.dispatch().provider_id != current.dispatch().provider_id
            || recorded.dispatch().server_sequence != current.dispatch().server_sequence
            || recorded.revision() > current.revision()
            || (recorded.terminal().is_some()
                && (recorded.terminal() != current.terminal()
                    || recorded.phase() != current.phase()))
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    for row in sqlx::query("SELECT effect_request_id,result FROM effect_journal_mutations")
        .fetch_all(&mut *connection)
        .await?
    {
        let effect_id: String = row.try_get("effect_request_id")?;
        let tool: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT snapshot FROM tool_invocations WHERE effect_request_id=?")
                .bind(&effect_id)
                .fetch_optional(&mut *connection)
                .await?;
        let Some(tool) = tool else { continue };
        let tool: ToolInvocationSnapshot =
            serde_json::from_slice(&tool).map_err(|_| DatabaseError::SchemaCorrupt)?;
        let bytes: Vec<u8> = row.try_get("result")?;
        let authorized = serde_json::from_slice::<AuthorizedEffectResolution>(&bytes).ok();
        let recorded = authorized
            .as_ref()
            .map(|value| value.effect_entry.clone())
            .map_or_else(|| serde_json::from_slice::<EffectJournalEntry>(&bytes), Ok)
            .map_err(|_| DatabaseError::SchemaCorrupt)?;
        if recorded.request_id.to_string() != effect_id
            || recorded.session_id != tool.invocation().session_id()
            || recorded.participant_id != tool.invocation().participant_id()
            || recorded.operation_id != tool.invocation().operation_id()
            || recorded.action != *tool.definition().required_authority()
            || recorded.effect_class != tool.definition().effect_class()
            || recorded.revision > tool.revision()
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
        if let Some(outcome) = authorized
            && (outcome.current_operation.operation_id != recorded.operation_id
                || outcome.current_operation.session_id != recorded.session_id
                || outcome.current_operation.participant_id != recorded.participant_id
                || recorded.revision != tool.revision()
                || !matches!(
                    (recorded.phase, tool.phase(), tool.terminal()),
                    (
                        navigator_store_api::EffectJournalPhase::Completed,
                        navigator_store_api::ToolInvocationPhase::Completed,
                        Some(navigator_store_api::ToolTerminal::Completed(_))
                    ) | (
                        navigator_store_api::EffectJournalPhase::Failed,
                        navigator_store_api::ToolInvocationPhase::Failed,
                        Some(navigator_store_api::ToolTerminal::Failed(_))
                    )
                ))
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    Ok(())
}

const fn effect_class_name(value: EffectClass) -> &'static str {
    match value {
        EffectClass::ReadOnly => "read_only",
        EffectClass::Idempotent => "idempotent",
        EffectClass::Transactional => "transactional",
        EffectClass::NonIdempotent => "non_idempotent",
        EffectClass::Unknown => "unknown",
    }
}

async fn validate_message_delivery_projection(
    connection: &mut SqliteConnection,
) -> Result<(), DatabaseError> {
    for row in sqlx::query(
        "SELECT message_id, session_id, source_participant_id, destination_participant_id, mailbox_sequence, priority, snapshot, delivery_state, delivery_due_seconds, delivery_due_nanos FROM messages",
    )
    .fetch_all(&mut *connection)
    .await?
    {
        let snapshot: MessageSnapshot = serde_json::from_slice(&row.get::<Vec<u8>, _>("snapshot"))
            .map_err(|_| DatabaseError::SchemaCorrupt)?;
        let (state, due) = match &snapshot.state {
            MessageDeliveryState::Queued => ("queued", None),
            MessageDeliveryState::RetryScheduled { not_before } => {
                ("retry_scheduled", Some(*not_before))
            }
            MessageDeliveryState::Leased { lease } => ("leased", Some(lease.expires_at)),
            MessageDeliveryState::AcceptancePending { lease } => {
                ("acceptance_pending", Some(lease.expires_at))
            }
            MessageDeliveryState::AcceptanceUnknown { lease } => {
                ("acceptance_unknown", Some(lease.expires_at))
            }
            MessageDeliveryState::Accepted { .. } => ("accepted", None),
            MessageDeliveryState::Uncertain { .. } => ("uncertain", None),
            MessageDeliveryState::DeadLetter { .. } => ("dead_letter", None),
        };
        let due_seconds = row.get::<Option<i64>, _>("delivery_due_seconds");
        let due_nanos = row.get::<Option<i64>, _>("delivery_due_nanos");
        if !snapshot.is_structurally_valid()
            || row.get::<String, _>("message_id") != snapshot.message_id.to_string()
            || row.get::<String, _>("session_id") != snapshot.session_id.to_string()
            || row.get::<String, _>("source_participant_id") != snapshot.source.to_string()
            || row.get::<String, _>("destination_participant_id")
                != snapshot.destination.to_string()
            || row.get::<i64, _>("mailbox_sequence")
                != i64::try_from(snapshot.mailbox_sequence)
                    .map_err(|_| DatabaseError::SchemaCorrupt)?
            || row.get::<i64, _>("priority") != i64::from(snapshot.priority as u8)
            || row.get::<String, _>("delivery_state") != state
            || due_seconds != due.map(navigator_domain::Timestamp::unix_seconds)
            || due_nanos != due.map(|value| i64::from(value.nanoseconds()))
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    Ok(())
}

async fn validate_authority_rows(connection: &mut SqliteConnection) -> Result<(), DatabaseError> {
    for row in sqlx::query("SELECT participant_id,session_id,snapshot FROM authority_policies")
        .fetch_all(&mut *connection)
        .await?
    {
        let value: AuthorityPolicySnapshot =
            serde_json::from_slice(&row.get::<Vec<u8>, _>("snapshot"))
                .map_err(|_| DatabaseError::SchemaCorrupt)?;
        if value.participant_id.to_string() != row.get::<String, _>("participant_id")
            || value.session_id.to_string() != row.get::<String, _>("session_id")
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    for row in sqlx::query(
        "SELECT grant_id,session_id,subject_participant_id,snapshot FROM authority_grants",
    )
    .fetch_all(&mut *connection)
    .await?
    {
        let value: GrantSnapshot = serde_json::from_slice(&row.get::<Vec<u8>, _>("snapshot"))
            .map_err(|_| DatabaseError::SchemaCorrupt)?;
        if value.grant.id.to_string() != row.get::<String, _>("grant_id")
            || value.grant.session_id.to_string() != row.get::<String, _>("session_id")
            || value.grant.subject.to_string() != row.get::<String, _>("subject_participant_id")
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    for row in sqlx::query("SELECT template_id,snapshot FROM authority_template_policies")
        .fetch_all(&mut *connection)
        .await?
    {
        let value: AuthorityTemplatePolicy =
            serde_json::from_slice(&row.get::<Vec<u8>, _>("snapshot"))
                .map_err(|_| DatabaseError::SchemaCorrupt)?;
        if value.template_id.to_string() != row.get::<String, _>("template_id")
            || value.allowed_parent_templates.is_empty()
            || value.allowed_parent_templates.len() > 256
        {
            return Err(DatabaseError::SchemaCorrupt);
        }
    }
    Ok(())
}

fn table_name(query: &str) -> &'static str {
    match query {
        "PRAGMA table_info(sessions)" => "sessions",
        "PRAGMA table_info(events)" => "events",
        "PRAGMA table_info(request_ledger)" => "request_ledger",
        "PRAGMA table_info(launch_attempts)" => "launch_attempts",
        "PRAGMA table_info(templates)" => "templates",
        "PRAGMA table_info(session_template_manifest)" => "session_template_manifest",
        "PRAGMA table_info(participants)" => "participants",
        "PRAGMA table_info(operations)" => "operations",
        "PRAGMA table_info(mailbox_counters)" => "mailbox_counters",
        "PRAGMA table_info(messages)" => "messages",
        "PRAGMA table_info(authority_policies)" => "authority_policies",
        "PRAGMA table_info(authority_grants)" => "authority_grants",
        "PRAGMA table_info(authority_template_policies)" => "authority_template_policies",
        "PRAGMA table_info(effect_journal)" => "effect_journal",
        "PRAGMA table_info(effect_journal_mutations)" => "effect_journal_mutations",
        "PRAGMA table_info(recovery_classifications)" => "recovery_classifications",
        "PRAGMA table_info(artifacts)" => "artifacts",
        "PRAGMA table_info(tool_registrations)" => "tool_registrations",
        "PRAGMA table_info(tool_invocations)" => "tool_invocations",
        "PRAGMA table_info(tool_invocation_mutations)" => "tool_invocation_mutations",
        "PRAGMA table_info(tool_provider_connections)" => "tool_provider_connections",
        "PRAGMA table_info(approval_requests)" => "approval_requests",
        "PRAGMA table_info(approval_grants)" => "approval_grants",
        "PRAGMA table_info(approval_effect_intents)" => "approval_effect_intents",
        "PRAGMA table_info(approval_mutations)" => "approval_mutations",
        "PRAGMA table_info(projection_generations)" => "projection_generations",
        "PRAGMA table_info(projection_rows)" => "projection_rows",
        "PRAGMA table_info(projection_heads)" => "projection_heads",
        "PRAGMA table_info(projection_progress)" => "projection_progress",
        "PRAGMA table_info(projection_metadata)" => "projection_metadata",
        "PRAGMA table_info(capacity_reservations)" => "capacity_reservations",
        "PRAGMA table_info(capacity_global_reservations)" => "capacity_global_reservations",
        "PRAGMA table_info(capacity_session_usage)" => "capacity_session_usage",
        "PRAGMA table_info(capacity_global_usage)" => "capacity_global_usage",
        "PRAGMA table_info(capacity_limits)" => "capacity_limits",
        "PRAGMA table_info(subscription_leases)" => "subscription_leases",
        _ => unreachable!("schema queries are static"),
    }
}

#[allow(clippy::too_many_lines)]
fn valid_column_shape(table: &str, row: &sqlx::sqlite::SqliteRow) -> bool {
    let name: String = row.get("name");
    let declared_type: String = row.get("type");
    let not_null: i64 = row.get("notnull");
    let primary_key: i64 = row.get("pk");
    let expected_type = if matches!(
        name.as_str(),
        "compatibility_identity"
            | "compatibility_configuration_identity"
            | "data"
            | "semantic_digest"
            | "result"
            | "credential_digest"
            | "driver_configuration_digest"
            | "content_digest"
            | "input_schema_digest"
            | "trusted_configuration"
            | "input_schema"
            | "template_compatibility"
            | "input_digest"
            | "input_payload"
            | "terminal_payload"
            | "evidence"
            | "registration"
            | "snapshot"
            | "terminal"
            | "resolution_contract"
            | "payload"
            | "digest"
            | "resource_hash"
            | "terminal_digest"
            | "registrations"
            | "token_secret"
    ) {
        "BLOB"
    } else if matches!(
        name.as_str(),
        "session_id"
            | "consumer_key"
            | "public_consumer_key"
            | "owner_host_id"
            | "event_id"
            | "event_type"
            | "related_request_id"
            | "request_id"
            | "caller_host_id"
            | "action"
            | "outcome"
            | "effect"
            | "attempt_id"
            | "participant_id"
            | "subject_participant_id"
            | "grant_id"
            | "driver_id"
            | "instance_id"
            | "state"
            | "cleanup_reason"
            | "template_id"
            | "parent_participant_id"
            | "operation_id"
            | "start_request_id"
            | "input_message_id"
            | "waiting_on_message_id"
            | "terminal"
            | "terminal_outcome"
            | "message_id"
            | "source_participant_id"
            | "destination_participant_id"
            | "effect_request_id"
            | "effect_class"
            | "phase"
            | "artifact_id"
            | "media_type"
            | "locator"
            | "tool_name"
            | "tool_version"
            | "invocation_id"
            | "registration_id"
            | "creator_participant_id"
            | "creator_operation_id"
            | "provider_id"
            | "connection_id"
            | "dispatch_id"
            | "cancellation_id"
            | "approval_id"
            | "requester_id"
            | "subject_id"
            | "effect_id"
            | "capability"
            | "status"
            | "view"
            | "item_key"
            | "sort_key"
            | "reservation_id"
            | "campaign_id"
            | "resource"
    ) {
        "TEXT"
    } else {
        "INTEGER"
    };
    let expected_not_null = (((table == "effect_journal" || table == "subscription_leases")
        && matches!(name.as_str(), "owner_epoch" | "owner_host_id"))
        || (table == "recovery_classifications" && name == "owner_epoch"))
        || !matches!(
            name.as_str(),
            "owner_host_id"
                | "owner_epoch"
                | "ownership_epoch"
                | "owner_expires_at_seconds"
                | "owner_expires_at_nanos"
                | "related_request_id"
                | "effect"
                | "instance_id"
                | "evidence"
                | "cleanup_reason"
                | "parent_participant_id"
                | "terminal_outcome"
                | "terminal_payload"
                | "waiting_on_message_id"
                | "terminal"
                | "compatibility_configuration_identity"
                | "deleted_seconds"
                | "deleted_nanos"
                | "creator_participant_id"
                | "creator_operation_id"
                | "connection_generation"
                | "cancellation_id"
                | "cancellation_server_sequence"
                | "terminal_digest"
                | "released_at_seconds"
                | "released_at_nanos"
        );
    let expected_primary_key = match (table, name.as_str()) {
        (
            "sessions"
            | "events"
            | "session_template_manifest"
            | "tool_registrations"
            | "tool_provider_connections"
            | "projection_heads"
            | "projection_generations"
            | "projection_rows"
            | "projection_progress"
            | "capacity_session_usage",
            "session_id",
        )
        | (
            "request_ledger"
            | "effect_journal"
            | "effect_journal_mutations"
            | "recovery_classifications"
            | "tool_invocation_mutations"
            | "approval_mutations",
            "request_id",
        )
        | ("launch_attempts", "attempt_id")
        | ("templates" | "authority_template_policies", "template_id")
        | ("participants" | "authority_policies", "participant_id")
        | ("operations", "operation_id")
        | ("mailbox_counters", "destination_participant_id")
        | ("messages", "message_id")
        | ("authority_grants" | "approval_grants", "grant_id")
        | ("approval_requests", "approval_id")
        | ("approval_effect_intents", "effect_id")
        | ("artifacts", "artifact_id")
        | ("tool_invocations", "invocation_id")
        | ("projection_metadata", "singleton")
        | (
            "capacity_reservations" | "capacity_global_reservations" | "subscription_leases",
            "reservation_id",
        )
        | ("capacity_global_usage" | "capacity_limits", "resource") => 1,
        ("events", "position")
        | ("session_template_manifest", "template_id")
        | ("capacity_session_usage", "resource")
        | ("tool_registrations", "tool_name")
        | ("tool_provider_connections", "provider_id")
        | ("projection_generations" | "projection_rows" | "projection_progress", "generation") => 2,
        ("projection_rows", "view")
        | ("projection_progress", "ordinal")
        | ("tool_registrations", "tool_version") => 3,
        ("projection_rows", "item_key") => 4,
        _ => 0,
    };
    declared_type.eq_ignore_ascii_case(expected_type)
        && (not_null != 0) == expected_not_null
        && primary_key == expected_primary_key
}

#[allow(clippy::too_many_lines)]
async fn migrate(pool: &SqlitePool) -> Result<(), DatabaseError> {
    let mut connection = pool.acquire().await?;
    let version: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&mut *connection)
        .await?;
    if version > SCHEMA_VERSION {
        return Err(DatabaseError::SchemaTooNew {
            found: version,
            supported: SCHEMA_VERSION,
        });
    }
    if version == SCHEMA_VERSION {
        return Ok(());
    }

    connection.execute("BEGIN IMMEDIATE").await?;
    crash_at("migration.after_begin");
    let migration = async {
        if version == 0 {
            sqlx::raw_sql(include_str!("../migrations/0001.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 2 {
            sqlx::raw_sql(include_str!("../migrations/0002.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 3 {
            sqlx::raw_sql(include_str!("../migrations/0003.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 4 {
            sqlx::raw_sql(include_str!("../migrations/0004.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 5 {
            sqlx::raw_sql(include_str!("../migrations/0005.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 6 {
            sqlx::raw_sql(include_str!("../migrations/0006.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 7 {
            sqlx::raw_sql(include_str!("../migrations/0007.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 8 {
            sqlx::raw_sql(include_str!("../migrations/0008.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 9 {
            sqlx::raw_sql(include_str!("../migrations/0009.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 10 {
            sqlx::raw_sql(include_str!("../migrations/0010.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 11 {
            sqlx::raw_sql(include_str!("../migrations/0011.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 12 {
            sqlx::raw_sql(include_str!("../migrations/0012.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 13 {
            sqlx::raw_sql(include_str!("../migrations/0013.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 14 {
            sqlx::raw_sql(include_str!("../migrations/0014.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 15 {
            sqlx::raw_sql(include_str!("../migrations/0015.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 16 {
            sqlx::raw_sql(include_str!("../migrations/0016.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 17 {
            sqlx::raw_sql(include_str!("../migrations/0017.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 18 {
            sqlx::raw_sql(include_str!("../migrations/0018.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 19 {
            sqlx::raw_sql(include_str!("../migrations/0019.sql"))
                .execute(&mut *connection)
                .await?;
        }
        if version < 20 {
            sqlx::raw_sql(include_str!("../migrations/0020.sql"))
                .execute(&mut *connection)
                .await?;
        }
        Ok::<_, sqlx::Error>(())
    }
    .await;
    if let Err(error) = migration {
        let _ = connection.execute("ROLLBACK").await;
        return Err(error.into());
    }
    finish_migration(&mut connection).await
}

async fn finish_migration(connection: &mut SqliteConnection) -> Result<(), DatabaseError> {
    crash_at("migration.after_schema_apply");
    if let Err(error) = validate_schema(connection).await {
        let _ = connection.execute("ROLLBACK").await;
        return Err(error);
    }
    if let Err(error) = connection.execute("PRAGMA user_version = 20").await {
        let _ = connection.execute("ROLLBACK").await;
        return Err(error.into());
    }
    crash_at("migration.after_version_set");
    crash_at("migration.before_commit");
    connection.execute("COMMIT").await?;
    crash_at("migration.after_commit");
    Ok(())
}
