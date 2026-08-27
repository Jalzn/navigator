---
status: verified
slice: 02-driver-contract
depends_on:
  - plans/01-durable-session/03-local-session-api.md
specs:
  - docs/drivers.md
  - docs/communication.md
---

# Task: Define the Driver protocol

## Outcome

Specify versioned messages for describe, start, ready, inspect, deliver,
acceptance, report, cancel, stop, and disconnect.

## Implementation

- Keep Driver protocol separate from Consumer protocol.
- Add capability identifiers with version and parameters.
- Bind every mutable request to stable request identity.
- Bound payload and pending correlation counts.
- Define explicit unknown acceptance and uncertain stop outcomes.
- Generate Rust and TypeScript bindings.

## Verification

- Golden protocol fixtures decode in Rust and TypeScript.
- Compatibility tests cover optional additions and required unknown behavior.
- Fuzz malformed envelopes and limit boundaries.

## Done

Protocol expresses every required Driver semantic without mentioning Pi.
