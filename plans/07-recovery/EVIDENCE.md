# Slice 07 verification evidence

Status: verified by semantic Store contracts, real SQLite and UDS demonstrations,
subprocess crash injection, two adversarial review rounds, and the complete
repository gate.

Authoritative run: `target/conformance/run.FFqP0W`. Every stage in
`gate-results.tsv` passed.

## Effect journal and authorized resolution

- Effects have durable `Reserved`, `Started`, `Uncertain`, `Completed`,
  `Failed`, and `RetryAuthorized` phases, immutable identity and semantic input,
  fenced ownership, revisioned transitions, leases, and a closed resolution
  contract.
- An expired reservation can be taken over. An expired started effect becomes
  uncertain and cannot be completed through the ordinary executor transition;
  only the authorized resolution transaction may leave that phase.
- Confirm, abandonment, and retry are checked against action-specific proof
  policy. The assertion binds the proof digest to the exact Effect identity and
  immutable semantic digest. External truth is an authorized assertion, not a
  generic claim that Navigator independently verified an external system.
- Resolution atomically rechecks the scoped Grant, consumes it, changes the
  Effect, appends one redacted Event, and records the global request identity.
  The terminal uncertain Operation remains immutable. Retry authorizes the same
  Effect identity and is reported as pending until an effect-specific executor
  (introduced with Consumer Tools) performs it; it never requeues the whole
  Operation.
- Raw proof bytes and free-form reason are absent from responses, Events, the
  main database, and WAL. Stable digests preserve conflict detection without
  persisting those values.
- Subprocess tests interrupt reserve, start, takeover, and authorized resolution
  before and after commit, reopen SQLite, and prove prior-or-full state, exact
  replay, one ledger/Event, Grant consumption only on commit, and integrity.

## Reconciliation

- Recovery acquires a fresh fenced ownership epoch before inspection, validates
  the whole bounded inventory, records a classification batch atomically, then
  performs only verified safe actions.
- An independent declarative oracle covers every current persisted recovery
  state and live observation pair with exact class, reason, action, or
  contradiction. Global effect uncertainty blocks every resume action;
  cleanup-required blocks unrelated work, and uncertainty takes precedence.
- Queued child work resumes through the exact existing Operation and Message
  identities. Mailbox tests use real public SQLite transitions to prove future
  retry and active leases cannot redeliver, due retry and expired leases can,
  and acceptance-pending or unknown remains uncertain.
- Multi-entity crash tests prove a classification batch is all-or-none with one
  Event. Replay, changed caller/session/epoch/payload, stale state, cross-session
  entities, duplicates, ordering, and `MAX`/`MAX+1` boundaries fail closed with
  no partial mutation.
- A terminal uncertain Operation remains immutable and outside unfinished
  recovery inventory after its Effect is resolved, while the resolved Effect
  and its audit remain directly queryable.

## Consumer boundary

- Recovery capability is negotiated only when a configured runtime exists.
  Resume over a real UDS and reopened SQLite schedules the exact committed pair
  once without replacement rows and returns typed per-action status.
- The real UDS resolution matrix covers forged, expired, and revoked Grants with
  zero ownership, Effect, Operation, Grant, Event, or classification mutation.
  It covers Confirm, DoNotRetry, and Retry, exact replay, changed-input conflict,
  Grant consumption, redaction, and the three exact durable Effect phases.
- `allowed_actions` is derived from the persisted Effect resolution contract and
  its compatible proof kinds; non-effect and non-uncertain classifications do
  not advertise resolution actions.

## Repository gate

The authoritative gate passed `format`, `clippy`, `semantic-evidence`,
`semantic-tests`, `driver-typescript`, `offline-build`, `clean-source`,
`architecture`, `supply-chain`, and `unused-dependencies`.

The architecture allowlist was updated for the reviewed test-only `sha2` and
`sqlx` dependencies introduced by the semantic DB/WAL oracles. Detailed logs
and machine-readable evidence are under `target/conformance/run.FFqP0W`.
