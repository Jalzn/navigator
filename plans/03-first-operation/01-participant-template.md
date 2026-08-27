---
status: verified
slice: 03-first-operation
depends_on:
  - plans/02-driver-contract/03-instance-supervision.md
specs:
  - docs/domain-model.md
---

# Task: Persist root Participant and Template

## Outcome

A Session creates one root Participant from trusted immutable Template data.

## Implementation

- Validate Template identity, Driver requirements, bounds, and task schema.
- Compute Session compatibility identity from trusted behavior.
- Persist Participant and Template reference atomically.
- Separate trusted configuration from untrusted Operation input.
- Bind current Instance only through the launch protocol.

## Verification

- Reject unregistered Template, invalid input schema, and compatibility mismatch.
- Prove secret values are absent from compatibility digest and Events.
- Reopen and reproduce the same public snapshot.

## Done

The root Participant can be launched without trusting Executor-supplied config.
