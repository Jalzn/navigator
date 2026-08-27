ALTER TABLE messages ADD COLUMN delivery_state TEXT GENERATED ALWAYS AS (
    json_extract(CAST(snapshot AS TEXT), '$.state.kind')
) VIRTUAL;

ALTER TABLE messages ADD COLUMN delivery_due_seconds INTEGER GENERATED ALWAYS AS (
    CASE json_extract(CAST(snapshot AS TEXT), '$.state.kind')
        WHEN 'retry_scheduled' THEN json_extract(CAST(snapshot AS TEXT), '$.state.not_before.unix_seconds')
        WHEN 'leased' THEN json_extract(CAST(snapshot AS TEXT), '$.state.lease.expires_at.unix_seconds')
        WHEN 'acceptance_pending' THEN json_extract(CAST(snapshot AS TEXT), '$.state.lease.expires_at.unix_seconds')
        WHEN 'acceptance_unknown' THEN json_extract(CAST(snapshot AS TEXT), '$.state.lease.expires_at.unix_seconds')
        ELSE NULL
    END
) VIRTUAL;

ALTER TABLE messages ADD COLUMN delivery_due_nanos INTEGER GENERATED ALWAYS AS (
    CASE json_extract(CAST(snapshot AS TEXT), '$.state.kind')
        WHEN 'retry_scheduled' THEN json_extract(CAST(snapshot AS TEXT), '$.state.not_before.nanoseconds')
        WHEN 'leased' THEN json_extract(CAST(snapshot AS TEXT), '$.state.lease.expires_at.nanoseconds')
        WHEN 'acceptance_pending' THEN json_extract(CAST(snapshot AS TEXT), '$.state.lease.expires_at.nanoseconds')
        WHEN 'acceptance_unknown' THEN json_extract(CAST(snapshot AS TEXT), '$.state.lease.expires_at.nanoseconds')
        ELSE NULL
    END
) VIRTUAL;

ALTER TABLE messages ADD COLUMN correlation_operation_id TEXT GENERATED ALWAYS AS (
    json_extract(CAST(snapshot AS TEXT), '$.correlation.operation_id')
) VIRTUAL;

CREATE INDEX mailbox_session_delivery_state
ON messages(
    session_id,
    delivery_state,
    delivery_due_seconds,
    delivery_due_nanos,
    destination_participant_id,
    correlation_operation_id,
    priority,
    mailbox_sequence
);
