CREATE TABLE capacity_reservations (
    reservation_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    resource TEXT NOT NULL CHECK (resource IN ('participants','active_operations','queued_operations','messages','message_bytes','artifacts','artifact_bytes','pending_requests','subscriptions','retries','retained_events')),
    amount INTEGER NOT NULL CHECK (amount > 0),
    released INTEGER NOT NULL CHECK (released IN (0,1)),
    created_at_seconds INTEGER NOT NULL,
    created_at_nanos INTEGER NOT NULL CHECK (created_at_nanos BETWEEN 0 AND 999999999),
    released_at_seconds INTEGER,
    released_at_nanos INTEGER CHECK (released_at_nanos BETWEEN 0 AND 999999999),
    CHECK ((released = 0 AND released_at_seconds IS NULL AND released_at_nanos IS NULL) OR
           (released = 1 AND released_at_seconds IS NOT NULL AND released_at_nanos IS NOT NULL)),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (campaign_id) REFERENCES participants(participant_id)
) STRICT;

CREATE INDEX capacity_reservations_session_resource
    ON capacity_reservations(session_id, resource, released, reservation_id);

CREATE TABLE capacity_global_reservations (
    reservation_id TEXT PRIMARY KEY NOT NULL,
    resource TEXT NOT NULL CHECK (resource IN ('participants','active_operations','queued_operations','messages','message_bytes','artifacts','artifact_bytes','pending_requests','subscriptions','retries','retained_events')),
    amount INTEGER NOT NULL CHECK (amount > 0),
    released INTEGER NOT NULL CHECK (released IN (0,1)),
    created_at_seconds INTEGER NOT NULL,
    created_at_nanos INTEGER NOT NULL CHECK (created_at_nanos BETWEEN 0 AND 999999999),
    released_at_seconds INTEGER,
    released_at_nanos INTEGER CHECK (released_at_nanos BETWEEN 0 AND 999999999),
    CHECK ((released = 0 AND released_at_seconds IS NULL AND released_at_nanos IS NULL) OR
           (released = 1 AND released_at_seconds IS NOT NULL AND released_at_nanos IS NOT NULL))
) STRICT;

CREATE TABLE capacity_session_usage (
    session_id TEXT NOT NULL,
    resource TEXT NOT NULL CHECK (resource IN ('participants','active_operations','queued_operations','messages','message_bytes','artifacts','artifact_bytes','pending_requests','subscriptions','retries','retained_events')),
    used INTEGER NOT NULL CHECK (used >= 0),
    PRIMARY KEY (session_id, resource),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
) STRICT;

CREATE TABLE capacity_global_usage (
    resource TEXT PRIMARY KEY NOT NULL CHECK (resource IN ('participants','active_operations','queued_operations','messages','message_bytes','artifacts','artifact_bytes','pending_requests','subscriptions','retries','retained_events')),
    used INTEGER NOT NULL CHECK (used >= 0)
) STRICT;

CREATE TABLE capacity_limits (
    resource TEXT PRIMARY KEY NOT NULL CHECK (resource IN ('participants','active_operations','queued_operations','messages','message_bytes','artifacts','artifact_bytes','pending_requests','subscriptions','retries','retained_events')),
    per_session INTEGER NOT NULL CHECK (per_session > 0),
    global_limit INTEGER NOT NULL CHECK (global_limit >= per_session),
    configured INTEGER NOT NULL CHECK (configured IN (0,1))
) STRICT;

INSERT INTO capacity_limits(resource,per_session,global_limit,configured) VALUES
('participants',1024,16384,0),
('active_operations',256,4096,0),
('queued_operations',4096,65536,0),
('messages',65536,1048576,0),
('message_bytes',268435456,4294967296,0),
('artifacts',4096,65536,0),
('artifact_bytes',4294967296,68719476736,0),
('pending_requests',4096,65536,0),
('subscriptions',32,512,0),
('retries',4096,65536,0),
('retained_events',262144,4194304,0);
