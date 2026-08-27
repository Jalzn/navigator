---
status: verified
slice: 06-cancellation-shutdown
depends_on:
  - plans/06-cancellation-shutdown/01-cancellation-protocol.md
specs:
  - docs/policy-security.md
---

# Task: Implement verified Unix process termination

## Outcome

Gracefully stop, then escalate only against a verified owned process group.

## Implementation

- Reinspect PID, creation evidence, executable, and parentage.
- Send graceful request through Driver before OS signal.
- Apply bounded waits and signal escalation.
- Record cleanup required when identity or termination cannot be proven.
- Never broaden a target using an unresolved variable or unvalidated group.

## Verification

- PID-reuse and identity-mismatch fixtures never receive a signal.
- Grandchild process in owned group terminates.
- Resistant child follows escalation sequence.
- Ambiguous identity becomes cleanup required.

## Done

Navigator makes no stronger process ownership claim than it can prove.
