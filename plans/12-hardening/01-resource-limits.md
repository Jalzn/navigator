---
status: verified
slice: 12-hardening
depends_on:
  - plans/11-approvals-observability/03-local-inspector.md
specs:
  - docs/policy-security.md
evidence:
  - plans/12-hardening/RESOURCE-LIMITS-EVIDENCE.md
review:
  - plans/12-hardening/RESOURCE-LIMITS-REVIEW.md
---

# Task: Prove resource bounds and fairness

## Outcome

Validate limits for Participants, depth, concurrent Operations, queues, frames,
Messages, Artifacts, requests, subscriptions, retries, and retained Events.

## Implementation

- Centralize configurable defaults with hard safety ceilings.
- Add per-Session and global accounting.
- Make admission atomic with reservation.
- Prevent one subtree from starving peers.
- Expose capacity reasons and metrics.

## Verification

- Saturation and queue-timeout tests.
- Fairness test across multiple Campaigns.
- Memory remains bounded with slow Drivers and Consumers.
- Capacity cancellation releases every reservation.

## Done

Resource exhaustion becomes typed backpressure, not instability.

Verified on 2026-08-26. Schema 20 provides durable per-Session and global
capacity accounting plus fenced subscription leases. Exact-bound, concurrent
last-slot, cancellation, crash/reopen, retained-Event, Artifact, subscription,
and cross-Campaign fairness cases passed; the independent adversarial review
returned GO. See the evidence and review documents linked above.
