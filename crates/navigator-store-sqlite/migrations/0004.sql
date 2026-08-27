ALTER TABLE launch_attempts
ADD COLUMN ownership_epoch INTEGER CHECK (ownership_epoch > 0);

CREATE TABLE IF NOT EXISTS mailbox_counters (
    destination_participant_id TEXT PRIMARY KEY NOT NULL REFERENCES participants(participant_id),
    next_sequence INTEGER NOT NULL CHECK (next_sequence > 0),
    queued_bytes INTEGER NOT NULL CHECK (queued_bytes >= 0),
    queued_messages INTEGER NOT NULL CHECK (queued_messages >= 0)
);

CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    source_participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    destination_participant_id TEXT NOT NULL REFERENCES participants(participant_id),
    mailbox_sequence INTEGER NOT NULL CHECK (mailbox_sequence > 0),
    priority INTEGER NOT NULL CHECK (priority IN (0, 1)),
    snapshot BLOB NOT NULL,
    UNIQUE(destination_participant_id, mailbox_sequence)
);

CREATE INDEX IF NOT EXISTS mailbox_order
ON messages(destination_participant_id, priority, mailbox_sequence);
