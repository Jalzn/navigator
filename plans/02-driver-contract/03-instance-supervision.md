---
status: verified
slice: 02-driver-contract
depends_on:
  - plans/02-driver-contract/02-fake-driver.md
specs:
  - docs/execution.md
  - docs/policy-security.md
---

# Task: Supervise owned Instances

## Outcome

Launch and stop a Driver process only when its identity and ownership are
verified.

## Implementation

- Persist launch attempt before spawn.
- Attach PID and creation evidence by compare-and-set.
- Use a process group for owned descendants on Unix.
- Require authenticated ready before delivery.
- Implement graceful stop, bounded wait, verified escalation, and cleanup state.
- Prevent ambient environment inheritance except explicit allowlist.

## Verification

- Fault inject before spawn, after spawn, after attach, and before ready.
- Simulate PID reuse and mismatched executable or parentage.
- Prove unrelated process is never signaled.
- Prove child self-exits after ownership loss.

## Done

Instance lifecycle is safe enough to support the first real Operation.
