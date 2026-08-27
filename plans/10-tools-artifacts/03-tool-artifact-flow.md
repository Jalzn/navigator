---
status: verified
slice: 10-tools-artifacts
depends_on:
  - plans/10-tools-artifacts/02-artifact-store.md
specs:
  - docs/communication.md
---

# Task: Complete Tool-to-Artifact flow

## Outcome

Return an Artifact reference from Consumer Tool to Worker and propagate it to
the root result.

## Verification

- End-to-end Python Consumer and Pi Worker.
- Artifact authority follows Session and Participant policy.
- Result replay references same immutable Artifact.
- Removed or corrupted content produces typed failure, never silent bytes.

## Done

The complete flow handles real-sized outputs with integrity.
