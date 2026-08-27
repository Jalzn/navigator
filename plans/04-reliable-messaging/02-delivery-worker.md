---
status: verified
slice: 04-reliable-messaging
depends_on:
  - plans/04-reliable-messaging/01-mailbox-store.md
specs:
  - docs/communication.md
---

# Task: Build delivery and deduplication loop

## Outcome

Serialize delivery per Participant and reconcile uncommitted acceptance.

## Implementation

- Select next eligible Message deterministically.
- Correlate attempt, Driver response, and Store acknowledgement.
- Ask Driver to prove prior acceptance before redelivery.
- Never blindly reinject unknown acceptance.
- Separate control priority from ordinary FIFO.
- Back off within bounded retry and Session ownership.

## Verification

- Fault test every Store commit and Driver effect boundary.
- Duplicate Driver frames are idempotent.
- Ordinary older Message cannot consume correlated feedback priority.
- Unknown acceptance transitions to explicit uncertainty.

## Done

At-least-once delivery has no hidden exactly-once assumption.
