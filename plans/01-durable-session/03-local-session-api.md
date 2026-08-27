---
status: verified
slice: 01-durable-session
depends_on:
  - plans/01-durable-session/02-ownership-lease.md
specs:
  - docs/consumer-api.md
---

# Task: Expose local Session commands

## Outcome

Provide a minimal local protocol and CLI test client for open, snapshot, close,
and Event subscription.

## Implementation

- Define versioned Protobuf messages and bounded fields.
- Serve over a Unix domain socket with restrictive permissions.
- Authenticate the local Consumer using a scoped bootstrap credential.
- Implement open modes only where current behavior is supported.
- Stream Events from a committed position with replay.

## Verification

- Protocol fixtures round-trip across generated clients.
- Malformed, oversized, unauthenticated, and unsupported-version requests fail.
- Reconnecting subscriber resumes without event loss.
- CLI demonstration proves the slice outcome.

## Done

Session durability is visible across the real Consumer process boundary.
