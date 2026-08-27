---
status: verified
slice: 10-tools-artifacts
depends_on:
  - plans/10-tools-artifacts/01-consumer-tools.md
specs:
  - docs/domain-model.md
  - docs/policy-security.md
---

# Task: Implement local Artifact Store

## Outcome

Write, verify, open, and logically delete bounded content through stable
Artifact references.

## Implementation

- Stream into an owned temporary file while hashing and counting.
- Atomically publish beneath a Session-scoped root.
- Persist metadata only after successful publication.
- Validate locator, size, hash, and access authority on read.
- Separate logical deletion, retention eligibility, and physical erasure.

## Verification

- Traversal, symlink, oversize, hash mismatch, partial write, and crash tests.
- Concurrent identical content does not corrupt metadata.
- Message payload quota encourages Artifact reference.

## Done

Large results are durable and safe without entering ordinary Messages.
