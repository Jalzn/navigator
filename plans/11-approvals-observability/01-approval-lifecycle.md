---
status: verified
slice: 11-approvals-observability
depends_on:
  - plans/10-tools-artifacts/01-consumer-tools.md
specs:
  - docs/policy-security.md
---

# Task: Implement approval and Grant lifecycle

## Outcome

Request, decide, issue, consume, expire, and revoke a scoped Grant.

## Implementation

- Persist approval request from untrusted Executor.
- Accept decision only from authenticated trusted Consumer authority.
- Bind Grant to subject, action, resource, Session, expiry, and use count.
- Atomically consume single-use Grant with privileged effect reservation.
- Audit request, decision, denial, expiry, revocation, and consumption.

## Verification

- Executor cannot self-approve or broaden scope.
- Concurrent use consumes exactly once.
- Expired and revoked Grant fails at effect time.
- Approval request does not itself authorize action.

## Done

Navigator has a complete trusted approval path rather than a pending-only model.
