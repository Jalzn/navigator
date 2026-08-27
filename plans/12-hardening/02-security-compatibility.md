---
status: verified
slice: 12-hardening
depends_on:
  - plans/12-hardening/01-resource-limits.md
specs:
  - docs/compatibility.md
  - docs/policy-security.md
evidence:
  - plans/12-hardening/SECURITY-COMPATIBILITY-EVIDENCE.md
review:
  - plans/12-hardening/TASK02-REVIEW.md
---

# Task: Complete security and compatibility matrix

## Outcome

Prove authentication, authorization, bounds, redaction, schema migration, and
protocol negotiation against adversarial cases.

## Verification

- Forged identity, replay, expired credential, downgrade, oversized frame.
- Invalid Template, escalation, sibling route, Grant reuse.
- Newer Store schema and failed forward migration.
- Old compatible client and Driver fixtures.
- cargo-deny, dependency audit, license report, and secret scan.

## Done

Release claims match executable evidence and supported-version policy.

The executable matrix includes old Consumer and Driver real-process fixtures,
schema 18/19 migration fixtures, event-read and subscription authorization,
Python SDK bounds, CycloneDX SBOM, complete license closure, secret inventory,
and digest-bound provenance. Completion requires a fresh external review
sidecar for the current source digest.
