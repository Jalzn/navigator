---
status: verified
slice: 04-reliable-messaging
depends_on:
  - plans/04-reliable-messaging/02-delivery-worker.md
specs:
  - docs/communication.md
---

# Task: Complete durable Event subscriptions

## Outcome

Consumers disconnect and replay ordered Session Events without blocking commits.

## Implementation

- Assign committed Session event positions.
- Stream from an exclusive after-position.
- Bound live subscriber queues.
- Disconnect slow subscribers with resumable position.
- Redact before persistence and emission.

## Verification

- Reconnect after each event boundary gives no missing fact.
- Duplicate replay is identifiable.
- Slow Consumer cannot exhaust memory or delay state commit.
- Secret sentinel never appears in stored or streamed bytes.

## Done

Operational observation is durable rather than log-dependent.
