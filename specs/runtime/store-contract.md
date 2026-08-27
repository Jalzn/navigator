# Store contract

## Purpose

Store is the transactional authority for Runtime state. Its API expresses
atomic lifecycle and mailbox operations rather than generic table CRUD. Pi,
WebSocket, subprocess, renderer, and artifact filesystem effects never occur
inside Store transactions.

`MemoryStore` and `SQLiteStore` pass the same behavioral contract suite. Tests
assert results, conflicts, revisions, leases, ordering, idempotency, and failure
atomicity rather than implementation-specific SQL.

## SQLite tables

### runtime_meta

One row stores the schema version and database identity. Schema migrations are
ordered, forward-only, transactional package functions. A newer unknown schema
fails before mutation. There is no migration history table or plugin migration
registry in version 1.

### sessions

Principal fields:

```text
id, name, status, coordinator_id,
owner_id, owner_lease_expires_at, owner_epoch,
created_at, updated_at, revision
```

Only one non-closed Session may be current for a consumer `name`. Runtime claims
ownership with a random `owner_id`, bounded expiry, and monotonically increasing
`owner_epoch`. Every mutation of live Session state carries that epoch. This is
a fencing token: an old paused owner cannot resume writing after its lease
expired and another Runtime claimed the Session.

Claim, bounded renewal, and release use compare-and-swap. An “active” value
without an unexpired lease is never ownership evidence. `OPEN` refuses
interrupted work, `RESUME` claims it explicitly after reconciliation, and
`RESET` closes the prior Session logically before creating a new identity.

### agents

Principal fields:

```text
id, session_id, parent_id, role, template_id, status,
next_message_sequence,
process_id, process_created_at, connection_token_digest,
created_at, updated_at, revision
```

Session, parent, role, and template identity are immutable. Parent existence,
role topology, depth, and template relationship are validated before insertion.
Process identity fields are nullable until launch and cleared/retained according
to explicit terminal-state rules. Only the SHA-256 digest of the random
connection token is stored.

`next_message_sequence` is incremented in the same transaction that inserts a
message. FIFO sequence never uses `SELECT MAX(...) + 1`.

### operations

Principal fields:

```text
id, session_id, agent_id, status, initiating_message_id,
waiting_message_id, attempt, error_code, error_details,
started_at, finished_at, created_at, updated_at, revision
```

A partial unique index permits only one active operation per Agent where status
is `pending`, `delivered`, `running`, or `waiting_for_parent`.
`waiting_message_id` is non-null only in `waiting_for_parent` and references the
single unresolved `question` or `blocked` message. Opening a wait persists the
message and operation transition atomically. Resolving it inserts the correlated
parent response, clears the wait, and transitions to `delivered` atomically.

### messages

Principal fields:

```text
id, session_id, operation_id, sender_id, recipient_id,
reply_to_message_id, sequence, kind, payload_json,
status, lease_owner, lease_expires_at, attempts, error_code,
idempotency_key, created_at, acknowledged_at, revision
```

Recipient plus sequence is unique. Message ID is globally unique. A message
lease is bounded and renewable only by its owner. Expiry makes an unacknowledged
message eligible for redelivery; it does not delete or mark it successful.
Acknowledgement verifies owner and revision. Retry attempts are bounded and
exhaustion moves the message to dead letter with a typed error.

### events

Principal fields:

```text
id, session_id, agent_id, operation_id,
type, level, facts_json, created_at
```

Events are append-only audit records and presentation inputs. When an event
describes a state mutation, it is inserted in the same transaction. Events are
not the sole source for rebuilding current state. Facts are bounded, validated,
and redacted before insertion.

### artifacts

Principal fields:

```text
id, session_id, agent_id, operation_id,
relative_path, media_type, byte_size, content_hash,
temporary, expires_at, created_at, revision
```

The table stores metadata only. ArtifactStore performs bounded atomic file
creation first, then registers verified metadata in a short transaction. A file
left before metadata commit is unreferenced temporary data eligible for bounded
garbage collection; a database row never points to an unverified partial file.

### idempotency

Principal fields:

```text
scope, key, input_hash, status,
result_json, error_code, created_at, completed_at, revision
```

Scope plus key is unique. Reservation stores a canonical input hash. Reuse with
the same hash returns pending or the durable prior result; reuse with a different
hash is rejected. A pending reservation is not automatically assumed safe to
retry after an unknown external side effect.

### context_checkpoints

Principal fields:

```text
id, session_id, agent_id, through_sequence,
summary_artifact_id, created_by_operation_id, created_at
```

Agent plus covered sequence is unique. Runtime selects the latest checkpoint not
beyond the requested mailbox sequence. Checkpoints never delete underlying
messages or events.

### approvals

Principal fields:

```text
id, session_id, agent_id, operation_id,
capability, resource_hash, status,
expires_at, max_uses, used_count,
decision_source, created_at, decided_at, revision
```

Lifecycle is:

```text
pending → granted → consumed
       ↘ denied
       ↘ expired
```

Version 1 permits one decision per request. Grant consumption checks subject,
capability, exact resource hash, expiry, remaining uses, expected revision, and
Session ownership epoch. Incrementing `used_count`, recording the authorized
operation intent, and appending its audit event are atomic. A separate grant-use
table is unnecessary because events retain the individual audit records.

## Public Store operations

Names below describe the intended contract; final Python parameter grouping may
use frozen request models to keep signatures bounded.

### Lifetime and Sessions

```python
await store.open()
await store.close()
await store.open_session(...)
await store.claim_session(...)
await store.renew_session_claim(...)
await store.release_session(...)
await store.get_session(...)
await store.close_session(...)
```

### Agents and operations

```python
await store.create_agent(...)
await store.get_agent(...)
await store.transition_agent(...)
await store.create_operation(...)
await store.get_operation(...)
await store.transition_operation(...)
await store.open_parent_wait(...)
await store.resolve_parent_wait(...)
```

### Mailboxes

```python
await store.enqueue_message(...)
await store.lease_next_message(...)
await store.renew_message_lease(...)
await store.ack_message(...)
await store.fail_delivery(...)
await store.release_expired_message_leases(...)
```

### Idempotency, approval, context, and artifacts

```python
await store.reserve_idempotency(...)
await store.complete_idempotency(...)
await store.request_approval(...)
await store.decide_approval(...)
await store.consume_grant(...)
await store.save_checkpoint(...)
await store.get_latest_checkpoint(...)
await store.register_artifact(...)
await store.get_artifact(...)
await store.append_event(...)
```

List/query methods are added only for concrete Runtime use cases and always have
explicit scope, stable ordering, and a hard limit. Store does not expose raw SQL,
generic filters, arbitrary JSON queries, or a repository object per table.

## Transaction rules

- Mutations use short `BEGIN IMMEDIATE` transactions in SQLite.
- Foreign keys are enabled on every connection.
- One `SQLiteStore` owns one write connection in version 1.
- Busy waits and all leases have explicit bounds.
- Existing mutable rows use expected revision compare-and-swap.
- Live Session mutations also require the current ownership epoch.
- State change and its required event commit together.
- Pydantic validation occurs before beginning a transaction where possible.
- No network, subprocess, Pi, renderer, or artifact filesystem wait occurs in a
  database transaction.
- Cancellation cannot interrupt a transaction midway; commit or rollback is
  allowed to finish inside a short bounded shield.

Version 1 uses the rollback journal. WAL is not enabled speculatively for a
single writer. Backup uses SQLite's consistent backup API rather than copying a
live database file.

## Required contract tests

The identical MemoryStore and SQLiteStore suite covers at least:

- stale revision rejection;
- expired Session claim takeover and old-owner fencing;
- two owners racing to claim one Session;
- one active operation per Agent;
- atomic wait creation and correlated resolution;
- per-recipient FIFO allocation under concurrent enqueue;
- lease expiry, redelivery, acknowledgement ownership, and dead letter;
- idempotency replay and mismatched-input rejection;
- grant expiry, scope mismatch, and concurrent final-use consumption;
- state transition plus event atomicity;
- malformed/newer schema refusal;
- cancellation during commit/rollback;
- backup consistency;
- behavior parity on macOS, Linux, and Windows.
