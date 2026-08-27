---
status: verified
slice: 03-first-operation
depends_on:
  - plans/03-first-operation/01-participant-template.md
specs:
  - docs/domain-model.md
  - docs/execution.md
---

# Task: Implement Operation transitions

## Outcome

Persist one Operation from queue through explicit terminal report.

## Implementation

- Enforce uniqueness where terminal outcome is absent.
- Validate closed transition table in the domain crate.
- Bind mutable request identity to semantic input digest.
- Persist state transition and Event atomically.
- Reject terminal mutation and ambiguous report correlation.
- Treat idle as lifecycle only.

## Verification

- Property-test valid and invalid transition sequences.
- Concurrent starts yield one Operation and one conflict.
- Retry with identical input returns existing Operation.
- Retry identity with different input fails.

## Done

Operation truth no longer depends on live Driver state.
