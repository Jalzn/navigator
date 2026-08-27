# Slice 04 verification evidence

Status: verified by the complete repository gate and adversarial review.

Authoritative run: `target/conformance/run.CO6uIc`. Every stage in
`gate-results.tsv` passed.

## Durable Mailbox

- Starting an Operation and persisting its input Message is one SQLite
  transaction. Request replay validates the semantic input and returns the
  durable result without allocating another Operation or Message.
- Mailbox sequence, message and byte quotas, delivery attempt, lease,
  acceptance state, request correlation, and redelivery deadline are durable.
  Concurrent allocation is gap-free and failures leave no partial state.
- Only the current Session owner epoch may lease or acknowledge. The immutable
  origin Driver epoch remains distinct from the current Store lease owner, so
  recovery cannot relabel the external effect that originally accepted work.
- Control traffic has strict precedence and FIFO ordering within its class. A
  delayed control head blocks later control and ordinary traffic; a live lease
  or unresolved acceptance blocks competing delivery loops.
- Exhausted attempts and quotas have typed terminal outcomes. Accepted
  identities remain retained for the complete redelivery horizon.

## Delivery and acceptance reconciliation

- Driver delivery and acceptance-query frames authenticate and correlate the
  exact Message identity and exact delivery attempt. Responses with changed
  identity, attempt, body, epoch, launch attempt, or Instance are rejected.
- The delivery loop distinguishes durable acceptance, retryable rejection,
  unknown acceptance, and dead-letter. It queries the Driver before retrying an
  uncertain effect and never blindly reinjects it.
- The fake Driver has a durable acceptance journal. Process and black-box tests
  crash before delivery, after native acceptance, before Navigator commit, and
  after commit, then restart and prove one accepted Message identity without a
  duplicate native injection.
- The production Operation path uses `MailboxBackedOperationExecutor`; the
  lower-level Driver executor is internal and cannot bypass the Mailbox.

## Events and Consumer replay

- Every Message transition appends a redacted durable `message.*` Event in the
  same Store transaction as its state change.
- Session event positions are committed and subscriptions resume from an
  exclusive position. Reconnect tests cover every event boundary and identify
  replay by stable Event identity.
- Live queues are bounded. A slow Consumer is disconnected without delaying
  commits and can catch up from its last committed position.
- Closed structured Message bodies exclude credential-shaped arbitrary data;
  raw database and wire-level sentinel tests prove secrets do not appear in
  persisted or streamed bytes.

## Repository gate

The authoritative gate passed:

- `format`
- `clippy`
- `semantic-evidence`
- `semantic-tests`
- `driver-typescript`
- `offline-build`
- `clean-source`
- `architecture`
- `supply-chain`
- `unused-dependencies`

Detailed logs and machine-readable evidence are under
`target/conformance/run.CO6uIc`; `target/conformance/latest` points to this run.
