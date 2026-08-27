-- Separate immutable public identity from the legacy physical uniqueness slot.
ALTER TABLE sessions ADD COLUMN public_consumer_key TEXT NOT NULL DEFAULT '';
UPDATE sessions SET public_consumer_key = consumer_key;
CREATE UNIQUE INDEX one_open_session_per_public_consumer_key
ON sessions(public_consumer_key) WHERE closed = 0;
