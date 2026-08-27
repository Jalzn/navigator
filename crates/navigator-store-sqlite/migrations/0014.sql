CREATE TABLE artifacts (
    artifact_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
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
    CHECK ((state = 'available' AND deleted_seconds IS NULL AND deleted_nanos IS NULL)
        OR (state != 'available' AND deleted_seconds IS NOT NULL AND deleted_nanos IS NOT NULL))
) STRICT;

CREATE INDEX artifacts_retention
ON artifacts(state, retention_seconds, retention_nanos, artifact_id);

CREATE INDEX artifacts_session
ON artifacts(session_id, artifact_id);

PRAGMA user_version = 14;
