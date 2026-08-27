---
status: verified
slice: 04-reliable-messaging
depends_on:
  - plans/03-first-operation/03-end-to-end-operation.md
specs:
  - docs/domain-model.md
  - docs/communication.md
---

# Task: Implement ordered Mailbox storage

## Outcome

Persist ordered Messages with lease, attempt, acceptance, and correlation state.

## Implementation

- Allocate sequence atomically per Mailbox.
- Lease only to current Session owner epoch.
- Make acceptance conditional on lease and exact attempt.
- Preserve accepted identities for the redelivery horizon.
- Bound attempts, payload, and queued bytes.
- Define explicit terminal delivery failure.

## Verification

- Concurrent sends produce a gap-free unique order.
- Expired lease redelivers; current lease does not.
- Stale epoch cannot lease or acknowledge.
- Oversize and quota errors have no partial Message.

## Done

Mailbox state alone explains every delivery decision.
