# Vertical 02 — Durable Session and Store

## Outcome

Runtime operational state is durable, transactionally constrained, and owned by
a renewable fenced Session lease. The complete Store architecture is introduced
in tested schema slices, beginning with the core lifecycle tables.

## End-to-end proof

Open a Session, register its Coordinator process, record an operation and event,
close it, reopen the database, and obtain the same immutable snapshot without
silently resuming work.

## Scope

- migration runner and `runtime_meta`;
- `sessions`, `agents`, `operations`, `messages`, and `events` tables;
- revisions and compare-and-swap;
- ownership lease, epoch fencing, injected clock, and bounded future validity;
- unfinished-operation uniqueness using `finished_at IS NULL`;
- SQLite rollback-journal defaults, foreign keys, busy timeout, and short
  `BEGIN IMMEDIATE` transactions;
- `MemoryStore` contract parity for the operations introduced here;
- append remaining planned tables through later verticals without changing the
  accepted core identities.

## Invariants

- no permanent boolean active lock;
- only the current unexpired owner epoch mutates a live Session;
- parent exists before child and topology is immutable;
- one unfinished operation per Agent;
- state and its audit event commit atomically;
- no transaction spans process, WebSocket, or filesystem effects;
- normal open never resumes interrupted work.

## Acceptance

- identical Store contract cases run against SQLite and MemoryStore;
- two owners race for one Session and only one wins;
- stale epoch writes fail after takeover;
- clock equality, regression, and far-future lease cases are deterministic;
- crash/reopen after each transaction boundary preserves constraints;
- unknown newer schema fails closed;
- migration rollback leaves the prior version usable;
- database path and locking behavior pass on macOS.

## Adversarial review

- inspect every multi-row mutation for missing event atomicity;
- attempt duplicate unfinished operations in every nonterminal status;
- force busy/locked/database-full conditions;
- verify Store API does not expose SQL-shaped consumer behavior;
- verify MemoryStore is not weaker than SQLite.

## Excluded from this slice

Automatic resume, message delivery leases, artifact files, approvals, and
context checkpoints.

