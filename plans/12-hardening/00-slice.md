---
status: verified
slice: 12-hardening
depends_on:
  - plans/11-approvals-observability/00-slice.md
specs:
  - docs/compatibility.md
  - docs/policy-security.md
evidence:
  - plans/12-hardening/EVIDENCE.md
review:
  - plans/12-hardening/SLICE-REVIEW.md
---

# Slice: Hardening and First Release

The `verified` slice status records implemented hardening and gate contracts.
Release eligibility is a separate, source-bound result requiring external
Task02 and final release attestations.

## Outcome

Navigator meets its documented local guarantees under resource pressure,
malformed input, dependency audit, upgrade, crash matrix, and sustained
multi-Participant execution.

## Demonstration

Run the release conformance suite from clean installation through a real Pi
hierarchy, injected failure, safe recovery, and final shutdown.

## Exit gate

Every canonical specification has mapped automated evidence or an explicitly
scoped unsupported capability. No release-blocking uncertainty remains.

Verified on 2026-08-26. Resource pressure, security/compatibility, the complete
fault matrix, and the reproducible release gate passed their semantic oracles
and independent adversarial reviews. The release is scoped to macOS/aarch64;
no broader platform claim is made.
