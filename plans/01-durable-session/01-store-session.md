---
status: verified
slice: 01-durable-session
depends_on:
  - plans/00-foundation/04-conformance-harness.md
specs:
  - docs/domain-model.md
  - docs/compatibility.md
---

# Task: Persist Session lifecycle

## Outcome

Implement the smallest SQLite Store supporting Session create, open, snapshot,
logical close, and ordered Events.

## Implementation

- Define Store traits around domain transactions, not SQL records.
- Create forward schema migrations with explicit schema version.
- Persist Session compatibility identity and revision.
- Commit lifecycle transition and Event atomically.
- Reject unknown newer schema before any write.
- Configure explicit transaction and busy-time behavior.

## Verification

- Store contract runs against SQLite.
- Crash after each statement boundary preserves a valid prior or next state.
- Reopening retains identity, revision, and Event order.
- Logical close retains all history.

## Done

Session behavior is durable and independent of process lifetime.
