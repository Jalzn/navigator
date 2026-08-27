CREATE TABLE effect_journal (
    request_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    operation_id TEXT NOT NULL REFERENCES operations(operation_id),
    caller_host_id TEXT NOT NULL,
    action TEXT NOT NULL,
    semantic_digest BLOB NOT NULL CHECK(length(semantic_digest) = 32),
    effect_class TEXT NOT NULL CHECK(effect_class IN ('read_only','idempotent','transactional','non_idempotent','unknown')),
    resolution_contract BLOB NOT NULL,
    phase TEXT NOT NULL CHECK(phase IN ('reserved','started','uncertain','completed','failed','retry_authorized')),
    owner_host_id TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL CHECK(owner_epoch > 0),
    lease_expires_at_seconds INTEGER NOT NULL,
    lease_expires_at_nanos INTEGER NOT NULL CHECK(lease_expires_at_nanos BETWEEN 0 AND 999999999),
    terminal BLOB,
    revision INTEGER NOT NULL CHECK(revision > 0),
    CHECK((phase IN ('completed','failed')) = (terminal IS NOT NULL))
);
CREATE INDEX effect_journal_session ON effect_journal(session_id);
CREATE TABLE effect_journal_mutations (
    request_id TEXT PRIMARY KEY NOT NULL,
    effect_request_id TEXT NOT NULL REFERENCES effect_journal(request_id),
    caller_host_id TEXT NOT NULL,
    semantic_digest BLOB NOT NULL CHECK(length(semantic_digest) = 32),
    result BLOB NOT NULL
);
