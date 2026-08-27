---
status: verified
slice: 01-durable-session
depends_on:
  - plans/01-durable-session/01-store-session.md
specs:
  - docs/execution.md
  - docs/principles.md
---

# Task: Implement exclusive ownership

## Outcome

Only one host epoch can mutate a Session and lease loss fences the old owner.

## Implementation

- Acquire ownership with host identity, epoch, and bounded expiry.
- Verify epoch on every protected mutation.
- Renew through a critical supervised task.
- Stop admission immediately after renewal failure or expiry.
- Apply maximum future validity to persisted deadlines.
- Expose ownership status without exposing credentials.

## Verification

- Two-host race yields one owner.
- Old epoch writes fail after takeover even if its process is alive.
- Equality at expiry and clock regression behave as specified.
- Renewal task failure initiates bounded shutdown.

## Done

No stale owner can commit state after ownership transfer.
