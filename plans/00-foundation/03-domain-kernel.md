---
status: verified
slice: 00-foundation
depends_on:
  - plans/00-foundation/01-workspace.md
specs:
  - docs/domain-model.md
  - docs/principles.md
---

# Task: Implement domain kernel types

## Outcome

Provide opaque identities, revisions, fencing epochs, bounded text and bytes,
timestamps, stable error information, and effect classifications.

## Implementation

- Use newtypes rather than raw strings for every entity identity.
- Define Clock as an injected boundary.
- Define closed public error codes and redacted ErrorInfo.
- Define EffectClass and RecoveryClass without infrastructure knowledge.
- Enforce bounds at construction.
- Prevent secrets from implementing display or serialization accidentally.

## Verification

- Property tests cover identity round trips and bound edges.
- Serialization snapshots are stable.
- Secret and redaction tests inspect debug and display output.
- Invalid future timestamps and zero epochs fail deterministically.

## Done

All later crates can share canonical types without depending on an adapter.
