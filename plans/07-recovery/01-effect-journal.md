---
status: verified
slice: 07-recovery
depends_on:
  - plans/06-cancellation-shutdown/03-runtime-shutdown.md
specs:
  - docs/principles.md
  - docs/domain-model.md
---

# Task: Persist effect phases

## Outcome

Record request reservation, effect start, uncertainty, and completion with owner
epoch and lease.

## Implementation

- Bind semantic input digest before reservation.
- Permit takeover only for expired reserved work.
- Once effect starts, require effect-specific reconciliation.
- Store terminal result or typed failure idempotently.
- Prevent permanent pending flags through lease and classification.

## Verification

- Crash each phase and reopen.
- Reuse with different input conflicts.
- Expired reservation is recoverable.
- Effect-started without proof becomes uncertain.

## Done

The Store can distinguish retryable intent from ambiguous effect.
