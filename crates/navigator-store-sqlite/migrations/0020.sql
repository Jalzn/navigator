CREATE TABLE subscription_leases (
    reservation_id TEXT PRIMARY KEY NOT NULL,
    session_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    owner_host_id TEXT NOT NULL,
    owner_epoch INTEGER NOT NULL CHECK (owner_epoch > 0),
    expires_at_seconds INTEGER NOT NULL,
    expires_at_nanos INTEGER NOT NULL CHECK (expires_at_nanos BETWEEN 0 AND 999999999),
    FOREIGN KEY (reservation_id) REFERENCES capacity_reservations(reservation_id) ON DELETE CASCADE,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (campaign_id) REFERENCES participants(participant_id)
) STRICT;

CREATE INDEX subscription_leases_session_owner_expiry
    ON subscription_leases(session_id, owner_epoch, expires_at_seconds, expires_at_nanos, reservation_id);

-- v19 subscriptions were process-owned but carried no durable owner/epoch and
-- therefore cannot be proven live after an exclusive schema migration. Reclaim
-- only those legacy rows; v20 writers always create the lease atomically.
DELETE FROM capacity_reservations WHERE resource = 'subscriptions';
DELETE FROM capacity_session_usage WHERE resource = 'subscriptions';
UPDATE capacity_global_usage SET used = 0 WHERE resource = 'subscriptions';
DELETE FROM capacity_global_usage WHERE resource = 'subscriptions' AND used = 0;
