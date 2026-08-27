---
status: verified
slice: 11-approvals-observability
depends_on:
  - plans/11-approvals-observability/01-approval-lifecycle.md
  - plans/04-reliable-messaging/03-event-replay.md
specs:
  - docs/principles.md
  - docs/communication.md
---

# Task: Build operational projections

## Outcome

Project durable Events into Session tree, active work, delivery, approval,
recovery, capacity, and failure views.

## Implementation

- Keep projection read-only and rebuildable.
- Expose snapshots through Consumer API.
- Add structured tracing correlated by public identities.
- Keep logs separate from durable Events.
- Bound progress retention and live update rate.

## Verification

- Rebuild projection from Events and compare current snapshot.
- Crash during projection update does not affect source state.
- Slow viewer cannot block commits.
- Secret sentinels absent from Event, trace, and error output.

## Done

Important operational questions are answerable from committed facts.
