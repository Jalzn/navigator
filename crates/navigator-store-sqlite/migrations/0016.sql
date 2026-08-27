CREATE TABLE tool_registrations (
    session_id TEXT NOT NULL,
    registration_id TEXT UNIQUE NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    consumer_key TEXT NOT NULL,
    snapshot BLOB NOT NULL,
    PRIMARY KEY (session_id, tool_name, tool_version),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
) WITHOUT ROWID;

CREATE TABLE tool_invocations (
    invocation_id TEXT PRIMARY KEY NOT NULL,
    effect_request_id TEXT UNIQUE NOT NULL,
    registration_id TEXT NOT NULL,
    dispatch_id TEXT UNIQUE NOT NULL,
    provider_id TEXT NOT NULL,
    server_sequence INTEGER NOT NULL CHECK(server_sequence > 0),
    deadline_seconds INTEGER NOT NULL,
    deadline_nanos INTEGER NOT NULL CHECK(deadline_nanos BETWEEN 0 AND 999999999),
    connection_generation INTEGER CHECK(connection_generation > 0),
    cancellation_id TEXT,
    cancellation_server_sequence INTEGER CHECK(cancellation_server_sequence > server_sequence),
    terminal_digest BLOB CHECK(length(terminal_digest)=32),
    session_id TEXT NOT NULL,
    participant_id TEXT NOT NULL,
    operation_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    snapshot BLOB NOT NULL,
    FOREIGN KEY (effect_request_id) REFERENCES effect_journal(request_id),
    FOREIGN KEY (registration_id) REFERENCES tool_registrations(registration_id),
    FOREIGN KEY (session_id, tool_name, tool_version)
        REFERENCES tool_registrations(session_id, tool_name, tool_version),
    FOREIGN KEY (participant_id) REFERENCES participants(participant_id),
    FOREIGN KEY (operation_id) REFERENCES operations(operation_id)
);

CREATE INDEX tool_invocations_recovery
    ON tool_invocations(session_id, invocation_id);

CREATE TABLE tool_provider_connections (
    session_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    connection_id TEXT UNIQUE NOT NULL,
    consumer_key TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation > 0),
    acknowledged_server_sequence INTEGER NOT NULL CHECK(acknowledged_server_sequence >= 0),
    next_server_sequence INTEGER NOT NULL CHECK(next_server_sequence > 0),
    connected_at_seconds INTEGER NOT NULL,
    connected_at_nanos INTEGER NOT NULL CHECK(connected_at_nanos BETWEEN 0 AND 999999999),
    registrations BLOB NOT NULL,
    PRIMARY KEY(session_id, provider_id),
    FOREIGN KEY(session_id) REFERENCES sessions(session_id)
) WITHOUT ROWID;

CREATE TABLE tool_invocation_mutations (
    request_id TEXT PRIMARY KEY NOT NULL,
    invocation_id TEXT NOT NULL,
    caller_host_id TEXT NOT NULL,
    semantic_digest BLOB NOT NULL CHECK(length(semantic_digest) = 32),
    result BLOB NOT NULL,
    FOREIGN KEY (invocation_id) REFERENCES tool_invocations(invocation_id)
);

ALTER TABLE artifacts RENAME TO artifacts_v15;
CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    creator_participant_id TEXT REFERENCES participants(participant_id),
    creator_operation_id TEXT REFERENCES operations(operation_id),
    media_type TEXT NOT NULL CHECK (length(media_type) BETWEEN 1 AND 255),
    size INTEGER NOT NULL CHECK (size BETWEEN 0 AND 67108864),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    locator TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('available', 'logically_deleted', 'physically_erased')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    retention_seconds INTEGER NOT NULL,
    retention_nanos INTEGER NOT NULL CHECK (retention_nanos BETWEEN 0 AND 999999999),
    created_seconds INTEGER NOT NULL,
    created_nanos INTEGER NOT NULL CHECK (created_nanos BETWEEN 0 AND 999999999),
    deleted_seconds INTEGER,
    deleted_nanos INTEGER CHECK (deleted_nanos BETWEEN 0 AND 999999999),
    CHECK ((creator_participant_id IS NULL) = (creator_operation_id IS NULL)),
    CHECK ((state = 'available' AND deleted_seconds IS NULL AND deleted_nanos IS NULL)
        OR (state != 'available' AND deleted_seconds IS NOT NULL AND deleted_nanos IS NOT NULL))
) STRICT;
INSERT INTO artifacts(artifact_id,session_id,media_type,size,digest,locator,state,revision,
 retention_seconds,retention_nanos,created_seconds,created_nanos,deleted_seconds,deleted_nanos)
SELECT artifact_id,session_id,media_type,size,digest,locator,state,revision,
 retention_seconds,retention_nanos,created_seconds,created_nanos,deleted_seconds,deleted_nanos
FROM artifacts_v15;
DROP TABLE artifacts_v15;
CREATE INDEX artifacts_retention ON artifacts(state,retention_seconds,retention_nanos,artifact_id);
CREATE INDEX artifacts_session ON artifacts(session_id,artifact_id);
