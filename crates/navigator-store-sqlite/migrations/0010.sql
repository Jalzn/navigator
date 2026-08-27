CREATE TABLE recovery_classifications (
    request_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    caller_host_id TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL CHECK(owner_epoch > 0),
    semantic_digest BLOB NOT NULL CHECK(length(semantic_digest) = 32),
    payload BLOB NOT NULL
);
CREATE INDEX recovery_classifications_session
ON recovery_classifications(session_id, request_id);
