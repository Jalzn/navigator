CREATE TABLE approval_requests (
    approval_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    requester_id TEXT NOT NULL REFERENCES participants(participant_id),
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    capability TEXT NOT NULL CHECK(length(capability) BETWEEN 1 AND 128),
    resource_hash BLOB NOT NULL CHECK(length(resource_hash) = 32),
    status TEXT NOT NULL CHECK(status IN ('pending','granted','consumed','denied','expired','revoked')),
    expires_seconds INTEGER NOT NULL,
    expires_nanos INTEGER NOT NULL CHECK(expires_nanos BETWEEN 0 AND 999999999),
    revision INTEGER NOT NULL CHECK(revision > 0),
    snapshot BLOB NOT NULL
) STRICT;

CREATE INDEX approval_requests_session_status
ON approval_requests(session_id,status,approval_id);

CREATE TABLE approval_grants (
    grant_id TEXT PRIMARY KEY NOT NULL,
    approval_id TEXT UNIQUE NOT NULL REFERENCES approval_requests(approval_id),
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    subject_id TEXT NOT NULL REFERENCES participants(participant_id),
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    capability TEXT NOT NULL CHECK(length(capability) BETWEEN 1 AND 128),
    resource_hash BLOB NOT NULL CHECK(length(resource_hash) = 32),
    max_uses INTEGER NOT NULL CHECK(max_uses BETWEEN 1 AND 1024),
    used_count INTEGER NOT NULL CHECK(used_count BETWEEN 0 AND max_uses),
    expires_seconds INTEGER NOT NULL,
    expires_nanos INTEGER NOT NULL CHECK(expires_nanos BETWEEN 0 AND 999999999),
    revoked INTEGER NOT NULL CHECK(revoked IN (0,1)),
    revision INTEGER NOT NULL CHECK(revision > 0),
    snapshot BLOB NOT NULL
) STRICT;

CREATE INDEX approval_grants_session_subject
ON approval_grants(session_id,subject_id,grant_id);

CREATE TABLE approval_effect_intents (
    effect_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    grant_id TEXT NOT NULL REFERENCES approval_grants(grant_id),
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    phase TEXT NOT NULL CHECK(phase IN ('reserved','succeeded','failed','uncertain')),
    revision INTEGER NOT NULL CHECK(revision > 0),
    snapshot BLOB NOT NULL
) STRICT;

CREATE TABLE approval_mutations (
    request_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    caller_host_id TEXT NOT NULL,
    action TEXT NOT NULL,
    semantic_digest BLOB NOT NULL CHECK(length(semantic_digest) = 32),
    result BLOB NOT NULL
) STRICT;
