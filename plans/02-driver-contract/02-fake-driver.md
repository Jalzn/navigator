---
status: verified
slice: 02-driver-contract
depends_on:
  - plans/02-driver-contract/01-driver-protocol.md
specs:
  - docs/drivers.md
---

# Task: Implement deterministic fake Driver

## Outcome

Create an out-of-process fake Executor controlled by a scripted scenario.

## Implementation

- Support selectable capabilities and durability boundary.
- Persist accepted Message identities in a small test journal.
- Script ready, idle, progress, outcome, disconnect, hang, and crash.
- Authenticate launch attempt and Instance identity.
- Exit after bounded ownership-channel loss.
- Expose no test-only bypass in production protocol.

## Verification

- Run full Driver conformance suite.
- Restart fake between acceptance and commit; prove identity reconciliation.
- Attempt forged Instance and replayed credential.
- Verify unsupported capability fails before process start.

## Done

The fake can deterministically reproduce every protocol failure window.
