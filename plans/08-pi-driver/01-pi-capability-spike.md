---
status: verified
slice: 08-pi-driver
depends_on:
  - plans/02-driver-contract/01-driver-protocol.md
specs:
  - docs/drivers.md
---

# Task: Validate Pi capability mapping

## Outcome

Prove native Pi APIs can honestly implement each capability before the Driver
advertises it.

## Implementation

- Pin one exact Pi SDK and Node version.
- Validate headless lifetime, interactive mode, custom Tools, delivery,
  transcript persistence, settlement, cancellation, and disposal.
- Disable untrusted automatic resource discovery.
- Define the exact durable acceptance proof for Message identity.
- Record unsupported features as absent capabilities.

## Verification

- Use a deterministic fake model provider.
- Observe the exact persisted Message identity before acceptance.
- Prove idle delivery and mid-turn delivery semantics separately.
- Prove process exit after bounded Navigator channel loss.

## Done

Every advertised Pi capability has a native executable proof.
