# Slice 05 adversarial review

Independent implementation and cross-review rounds covered authority laws,
SQLite topology and spawn transactions, authenticated Driver messages, local
scheduling, the durable fake Driver, and the real three-level scenario.

## Findings resolved

- Prevented a crash after child commit but before scheduling from creating a
  second Operation: spawn now schedules the exact already-persisted Operation,
  and recovery discovers the same durable work.
- Removed trusted policy and caller identity from model-controlled Driver
  fields. Template policy comes only from the trusted catalog, and caller
  identity comes from the authenticated connection.
- Fixed request replay that could return newly generated identities instead of
  the identities committed by the original atomic spawn.
- Bound hierarchy result authentication to the exact Instance; an initially
  omitted request variant could otherwise bypass the common binding path.
- Fixed report cursor advancement before Store acknowledgement. Progress and
  terminal reports remain pending until their durable effect commits, and
  restart redelivers the same report rather than silently losing it.
- Corrected feedback semantics so enqueueing a response does not resume an
  Operation. Only acceptance of the exact correlated Message transitions
  `waiting` to `running` and appends the causal Events atomically.
- Added reserved, bounded control capacity for upward outcomes so ordinary
  mailbox pressure cannot silently erase terminal propagation.
- Rejected status queries with forged ownership or Instance identity before
  loading target topology, preventing an authorization oracle.

## Test-quality review

The final tests observe public snapshots, immutable ordered Events, exact
Message and Operation identities, authenticated protocol frames, durable fake
Driver journals, subprocess exits, and reopened SQLite state. They deliberately
reject authority union, sibling shortcuts, forged identity, commit-before-
schedule duplication, cursor-before-commit loss, enqueue-before-accept resume,
stale delivery attempts, duplicate acceptance, and every partial feedback
commit boundary. Assertions do not depend on private helper call counts or on a
test-only in-process Executor substitute for the vertical scenario.

## Deferred by explicit slice ownership

Subtree cancellation, graceful and forced process stop, and host-wide ordered
shutdown belong to Slice 06. Recovery scanning and idempotent rescheduling of
durable unfinished work belong to Slice 07. Trusted generic Driver catalog
configuration and the first Pi catalog entry belong to Slice 08; daemon
composition belongs to Slice 09. These boundaries are represented by explicit
later tasks rather than hidden assumptions in the Slice 05 claim.
