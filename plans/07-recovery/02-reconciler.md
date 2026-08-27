---
status: verified
slice: 07-recovery
depends_on:
  - plans/07-recovery/01-effect-journal.md
specs:
  - docs/execution.md
---

# Task: Implement reconciliation engine

## Outcome

Classify unfinished Sessions, Participants, Instances, Operations, Messages, and
effects before accepting resume.

## Implementation

- Acquire a new ownership epoch first.
- Inspect Instances through Driver without trusting stale connection state.
- Produce stable RecoveryClass and reasons.
- Build an executable list of safe actions.
- Scan atomically spawned child Operations that remain `queued` because the host
  crashed after the spawn commit but before local scheduling. Feed them through
  the idempotent existing-Operation scheduler; never create a replacement
  Operation or Message.
- Stop on internal contradiction or corrupted state.
- Emit classification Events.

## Verification

- Table covers every persisted state and observable live-state combination.
- Old owner is fenced before inspection side effects.
- Reconciliation itself is idempotent.
- Crash after authorized child commit and before scheduling, restart, and prove
  the original Operation/Message identities execute exactly once.
- No classification silently maps uncertainty to safe.

## Done

Every unfinished entity has an explicit next-action classification.
