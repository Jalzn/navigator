---
status: verified
slice: 05-hierarchy-policy
depends_on:
  - plans/05-hierarchy-policy/02-authority.md
specs:
  - docs/execution.md
  - docs/communication.md
---

# Task: Execute hierarchical work

## Outcome

Expose generic spawn, send, status, and cancel commands through the Driver.

## Implementation

- Derive caller from authenticated Instance.
- Allow only policy-authorized direct-child operations.
- Route outcomes and questions upward.
- Route sibling requests through common ancestor policy.
- Correlate parent feedback to waiting child Operation.

## Verification

- End-to-end three-level success.
- Direct sibling and cross-tree send are rejected.
- Forged caller identity is ignored and audited.
- Parent response resumes only the correlated waiting Operation.

## Done

The standard hierarchy works entirely through generic core mechanisms.
