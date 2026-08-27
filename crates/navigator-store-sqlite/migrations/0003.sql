CREATE TABLE templates (
    template_id TEXT PRIMARY KEY NOT NULL,
    compatibility_identity BLOB NOT NULL CHECK (length(compatibility_identity) = 32),
    registration BLOB NOT NULL
);

CREATE TABLE participants (
    participant_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    parent_participant_id TEXT REFERENCES participants(participant_id),
    template_id TEXT NOT NULL REFERENCES templates(template_id),
    template_compatibility BLOB NOT NULL CHECK (length(template_compatibility) = 32),
    revision INTEGER NOT NULL CHECK (revision > 0)
);

CREATE UNIQUE INDEX one_root_participant_per_session
ON participants(session_id)
WHERE parent_participant_id IS NULL;

CREATE TABLE operations (
    operation_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    start_request_id TEXT NOT NULL,
    input_message_id TEXT NOT NULL,
    input_digest BLOB NOT NULL CHECK (length(input_digest) = 32),
    input_payload BLOB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'starting', 'running', 'waiting', 'cancelling', 'succeeded', 'failed', 'cancelled', 'blocked', 'uncertain')),
    terminal_outcome TEXT CHECK (terminal_outcome IS NULL OR terminal_outcome IN ('succeeded', 'failed', 'cancelled', 'blocked', 'uncertain')),
    terminal_payload BLOB,
    revision INTEGER NOT NULL CHECK (revision > 0),
    created_at_seconds INTEGER NOT NULL,
    created_at_nanos INTEGER NOT NULL CHECK (created_at_nanos BETWEEN 0 AND 999999999),
    updated_at_seconds INTEGER NOT NULL,
    updated_at_nanos INTEGER NOT NULL CHECK (updated_at_nanos BETWEEN 0 AND 999999999),
    CHECK ((terminal_outcome IS NULL) = (state NOT IN ('succeeded', 'failed', 'cancelled', 'blocked', 'uncertain'))),
    CHECK ((terminal_outcome IS NULL) = (terminal_payload IS NULL))
);

CREATE UNIQUE INDEX one_unfinished_operation_per_participant
ON operations(participant_id)
WHERE terminal_outcome IS NULL;
