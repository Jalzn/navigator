CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY NOT NULL,
    consumer_key TEXT NOT NULL UNIQUE,
    compatibility_identity BLOB NOT NULL CHECK (length(compatibility_identity) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0),
    closed INTEGER NOT NULL DEFAULT 0 CHECK (closed IN (0, 1)),
    created_at_seconds INTEGER NOT NULL,
    created_at_nanos INTEGER NOT NULL CHECK (created_at_nanos BETWEEN 0 AND 999999999),
    updated_at_seconds INTEGER NOT NULL,
    updated_at_nanos INTEGER NOT NULL CHECK (updated_at_nanos BETWEEN 0 AND 999999999),
    owner_host_id TEXT,
    owner_epoch INTEGER CHECK (owner_epoch IS NULL OR owner_epoch > 0),
    owner_expires_at_seconds INTEGER,
    owner_expires_at_nanos INTEGER CHECK (owner_expires_at_nanos IS NULL OR owner_expires_at_nanos BETWEEN 0 AND 999999999),
    epoch_high_water INTEGER NOT NULL DEFAULT 0 CHECK (epoch_high_water >= 0),
    observed_time_floor_seconds INTEGER NOT NULL,
    observed_time_floor_nanos INTEGER NOT NULL CHECK (observed_time_floor_nanos BETWEEN 0 AND 999999999),
    CHECK (
        (owner_host_id IS NULL AND owner_expires_at_seconds IS NULL AND owner_expires_at_nanos IS NULL)
        OR
        (owner_host_id IS NOT NULL AND owner_epoch IS NOT NULL AND owner_expires_at_seconds IS NOT NULL AND owner_expires_at_nanos IS NOT NULL)
    ),
    CHECK (owner_epoch IS NULL OR epoch_high_water >= owner_epoch)
);

CREATE TABLE events (
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    position INTEGER NOT NULL CHECK (position > 0),
    event_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision > 0),
    event_type TEXT NOT NULL,
    schema_version INTEGER NOT NULL CHECK (schema_version > 0),
    related_request_id TEXT,
    data BLOB NOT NULL,
    occurred_at_seconds INTEGER NOT NULL,
    occurred_at_nanos INTEGER NOT NULL CHECK (occurred_at_nanos BETWEEN 0 AND 999999999),
    PRIMARY KEY (session_id, position),
    UNIQUE (session_id, event_id)
);

CREATE TABLE request_ledger (
    request_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL,
    caller_host_id TEXT NOT NULL,
    action TEXT NOT NULL,
    semantic_digest BLOB NOT NULL CHECK (length(semantic_digest) = 32),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded', 'failed')),
    effect TEXT CHECK (effect IS NULL OR effect IN ('applied', 'unchanged')),
    result BLOB NOT NULL
);

CREATE INDEX events_by_session_position ON events(session_id, position);
