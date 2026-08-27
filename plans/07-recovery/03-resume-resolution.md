---
status: verified
slice: 07-recovery
depends_on:
  - plans/07-recovery/02-reconciler.md
specs:
  - docs/consumer-api.md
---

# Task: Expose resume and uncertainty resolution

## Outcome

Consumers resume safe work and resolve uncertain effects through explicit typed
commands.

## Implementation

- Reject ordinary open when interrupted work requires a choice.
- Resume only classifications with safe actions.
- Require authority and reason for uncertain resolution.
- Support confirm-completed, do-not-retry, and retry-with-effect-proof only where
  the effect contract permits.
- Audit every decision.

## Verification

- Plain resume cannot override uncertainty.
- Duplicate resolution is idempotent.
- Unauthorized resolution fails.
- Full crash matrix produces no duplicate unfinished Operation.

## Done

Recovery behavior satisfies the central no-blind-replay guarantee.
