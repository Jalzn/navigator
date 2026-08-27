CREATE TABLE launch_attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    participant_id TEXT NOT NULL,
    driver_id TEXT NOT NULL,
    instance_id TEXT,
    state TEXT NOT NULL CHECK (state IN ('prepared', 'attached', 'ready', 'stopping', 'stopped', 'cleanup_required')),
    revision INTEGER NOT NULL CHECK (revision > 0),
    credential_digest BLOB NOT NULL CHECK (length(credential_digest) = 32),
    evidence BLOB,
    cleanup_reason TEXT
);

CREATE UNIQUE INDEX current_instance_identity
ON launch_attempts(instance_id)
WHERE instance_id IS NOT NULL;
