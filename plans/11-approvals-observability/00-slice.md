---
status: verified
slice: 11-approvals-observability
depends_on:
  - plans/10-tools-artifacts/00-slice.md
specs:
  - docs/policy-security.md
  - docs/communication.md
---

# Slice: Approvals and Observability

## Outcome

An Executor requests a privileged action, a trusted Consumer grants it narrowly,
the action consumes the Grant, and an operator can reconstruct the full timeline
without reading logs.

## Demonstration

Deny action, request approval, approve once with expiry, perform action, reject
reuse, and show a redacted durable timeline.

## Exit gate

Trusted decision boundary, Grant atomicity, expiry, revocation, projection,
redaction, and slow-subscriber tests pass.
