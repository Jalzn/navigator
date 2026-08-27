CREATE TABLE projection_generations (
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    generation INTEGER NOT NULL CHECK (generation > 0),
    state TEXT NOT NULL CHECK (state IN ('building','published','retired','unhealthy')),
    checkpoint_position INTEGER NOT NULL CHECK (checkpoint_position >= 0),
    source_head_position INTEGER NOT NULL CHECK (source_head_position >= checkpoint_position),
    observed_time_floor_seconds INTEGER NOT NULL,
    observed_time_floor_nanos INTEGER NOT NULL CHECK (observed_time_floor_nanos BETWEEN 0 AND 999999999),
    created_at_seconds INTEGER NOT NULL,
    created_at_nanos INTEGER NOT NULL CHECK (created_at_nanos BETWEEN 0 AND 999999999),
    PRIMARY KEY (session_id, generation)
) STRICT;

CREATE TABLE projection_rows (
    session_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    view TEXT NOT NULL CHECK (view IN ('session_tree','active_work','delivery','approval','recovery','capacity','failure')),
    item_key TEXT NOT NULL,
    sort_key TEXT NOT NULL,
    data BLOB NOT NULL CHECK (length(data) <= 16384),
    PRIMARY KEY (session_id, generation, view, item_key),
    FOREIGN KEY (session_id, generation) REFERENCES projection_generations(session_id, generation) ON DELETE CASCADE
) STRICT;

CREATE INDEX projection_rows_page
ON projection_rows(session_id, generation, view, sort_key, item_key);

CREATE TABLE projection_heads (
    session_id TEXT PRIMARY KEY NOT NULL REFERENCES sessions(session_id),
    generation INTEGER NOT NULL CHECK (generation > 0),
    checkpoint_position INTEGER NOT NULL CHECK (checkpoint_position >= 0),
    source_head_position INTEGER NOT NULL CHECK (source_head_position >= checkpoint_position),
    FOREIGN KEY (session_id, generation) REFERENCES projection_generations(session_id, generation)
) STRICT;

CREATE TABLE projection_progress (
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    generation INTEGER NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 8),
    checkpoint_position INTEGER NOT NULL CHECK (checkpoint_position >= 0),
    dropped_updates INTEGER NOT NULL CHECK (dropped_updates >= 0),
    recorded_at_seconds INTEGER NOT NULL,
    recorded_at_nanos INTEGER NOT NULL CHECK (recorded_at_nanos BETWEEN 0 AND 999999999),
    PRIMARY KEY (session_id, generation, ordinal),
    FOREIGN KEY (session_id, generation) REFERENCES projection_generations(session_id, generation) ON DELETE CASCADE
) STRICT;

CREATE TABLE projection_metadata (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK (singleton = 1),
    token_secret BLOB NOT NULL CHECK (length(token_secret) = 32)
) STRICT;

INSERT INTO projection_metadata(singleton, token_secret) VALUES(1, randomblob(32));
