ALTER TABLE participants
ADD COLUMN depth INTEGER NOT NULL DEFAULT 1 CHECK (depth BETWEEN 1 AND 8);

CREATE INDEX participant_children
ON participants(session_id, parent_participant_id, participant_id);
