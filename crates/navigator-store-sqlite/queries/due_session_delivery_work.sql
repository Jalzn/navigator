WITH nonterminal AS (
 SELECT *, ROW_NUMBER() OVER (PARTITION BY destination_participant_id ORDER BY priority, mailbox_sequence) AS head_rank,
 CASE WHEN delivery_state IN ('acceptance_pending','acceptance_unknown') AND (delivery_due_seconds < ? OR (delivery_due_seconds = ? AND delivery_due_nanos <= ?)) THEN 1 ELSE 0 END AS expired_acceptance,
 CASE WHEN delivery_state IN ('leased','acceptance_pending','acceptance_unknown') AND (delivery_due_seconds > ? OR (delivery_due_seconds = ? AND delivery_due_nanos > ?)) THEN 1 ELSE 0 END AS active_lease
 FROM messages WHERE session_id = ? AND delivery_state IN ('queued','retry_scheduled','leased','acceptance_pending','acceptance_unknown')
), marked AS (
 SELECT *, MAX(expired_acceptance) OVER (PARTITION BY destination_participant_id) AS has_recovery,
 MAX(active_lease) OVER (PARTITION BY destination_participant_id) AS has_active_lease,
 ROW_NUMBER() OVER (PARTITION BY destination_participant_id, expired_acceptance ORDER BY priority, mailbox_sequence) AS class_rank FROM nonterminal
), selected AS (
 SELECT * FROM marked WHERE (expired_acceptance = 1 AND class_rank = 1) OR
 (has_recovery = 0 AND has_active_lease = 0 AND head_rank = 1 AND (delivery_state = 'queued' OR
 (delivery_state IN ('retry_scheduled','leased') AND (delivery_due_seconds < ? OR (delivery_due_seconds = ? AND delivery_due_nanos <= ?)))))
)
SELECT selected.message_id, selected.session_id, selected.source_participant_id,
 selected.destination_participant_id, selected.mailbox_sequence, selected.priority, selected.snapshot,
 operations.operation_id AS active_operation_id FROM selected JOIN operations
 ON operations.session_id = selected.session_id AND operations.participant_id = selected.destination_participant_id
 AND operations.operation_id = selected.correlation_operation_id
 AND operations.terminal_outcome IS NULL
ORDER BY selected.priority, selected.mailbox_sequence, selected.message_id LIMIT ?
