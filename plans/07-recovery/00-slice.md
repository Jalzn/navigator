---
status: verified
slice: 07-recovery
depends_on:
  - plans/06-cancellation-shutdown/00-slice.md
specs:
  - docs/execution.md
  - docs/principles.md
---

# Slice: Recovery

## Outcome

After crash at any known commit/effect boundary, Navigator reconciles without a
duplicate Participant or Operation and never replays an uncertain effect.

## Demonstration

Run a fault matrix, restart, inspect classification, resume safe work, and
require explicit resolution for uncertain work.

## Exit gate

Classification, takeover, effect phases, cleanup, and resolution audit tests all
pass.
