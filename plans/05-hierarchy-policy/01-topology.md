---
status: verified
slice: 05-hierarchy-policy
depends_on:
  - plans/04-reliable-messaging/02-delivery-worker.md
specs:
  - docs/domain-model.md
  - docs/architecture.md
---

# Task: Persist Participant topology

## Outcome

Insert parent and child atomically while enforcing one Session, acyclicity,
depth, child count, and total count.

## Implementation

- Validate relationship inside the Store transaction.
- Store immutable parent identity.
- Maintain queryable direct-child snapshots.
- Reject move or reparent in the first implementation.
- Emit Participant-created Event after commit.

## Verification

- Concurrent child creation respects exact capacity.
- Cross-Session and cyclic relationships fail.
- Boundary values for depth and count are deterministic.

## Done

The durable graph cannot represent an invalid topology.
