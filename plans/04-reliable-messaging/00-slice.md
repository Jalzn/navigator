---
status: verified
slice: 04-reliable-messaging
depends_on:
  - plans/03-first-operation/00-slice.md
specs:
  - docs/communication.md
---

# Slice: Reliable Messaging

## Outcome

A Message survives disconnect at every delivery boundary and is accepted at
least once without duplicate native injection.

## Demonstration

Crash before delivery, after native acceptance, before Navigator acknowledgement,
and after acknowledgement. Reconcile each case and show one accepted Message
identity.

## Exit gate

Mailbox order, leases, acceptance, retry, deduplication, dead-letter policy, and
subscription replay are verified.
