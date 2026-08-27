---
status: verified
slice: 12-hardening
depends_on:
  - plans/12-hardening/03-fault-matrix.md
specs:
  - docs/README.md
  - docs/testing.md
evidence:
  - plans/12-hardening/RELEASE-GATE-EVIDENCE.md
review:
  - plans/12-hardening/RELEASE-GATE-REVIEW.md
---

# Task: Verify first release

The `verified` task status records the executable gate implementation. It does
not self-authorize the current source; eligibility requires the external
attestations named by the release invocation.

## Outcome

Produce a reproducible local release containing Navigator binaries, Pi Driver,
Python SDK, schemas, migrations, and conformance evidence.

## Implementation

- Build pinned release artifacts from a clean environment.
- Generate checksums and software bill of materials.
- Run installation and upgrade smoke tests.
- Verify docs-to-test traceability.
- Verify every MUST-level guarantee has semantic evidence and every semantic
  test points back to a canonical guarantee.
- Run the critical mutation suite and require every injected semantic defect to
  be detected.
- Record supported Unix platforms, protocol ranges, and Driver capabilities.
- Ensure temporary plans are not presented as product contracts.

## Verification

- Clean-machine install executes the full acceptance scenario.
- Upgrade preserves a compatible Session.
- Incompatible Template change requires explicit reset or migration.
- Final shutdown leaves no managed processes or sockets.

## Done

Navigator can make its first public implementation claims with evidence.

Verified on 2026-08-26 for macOS/aarch64. The required release run forced all
five semantic oracles, six canonical critical mutants, extracted-bundle
lifecycle checks, and two independently built byte-identical archives. Every
execution transcript and index is persisted and digest-bound; the final
independent attestation binds the completed authorization sidecar.
