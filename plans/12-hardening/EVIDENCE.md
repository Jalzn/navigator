# Slice 12 verification evidence

The Slice 12 implementation and gate infrastructure are verified on macOS/arm64.
Current-source release eligibility remains conditional on fresh external
Task02 and release review sidecars.

## Task evidence

- Resource bounds and fairness: `RESOURCE-LIMITS-EVIDENCE.md` records exact
  boundary, contention, cancellation, reopen, retention, subscription, and
  cross-Campaign fairness cases; `RESOURCE-LIMITS-REVIEW.md` records the
  independent GO.
- Security and compatibility: `SECURITY-COMPATIBILITY-EVIDENCE.md` defines the
  publication protocol. The current-source evidence directory and its external
  review sidecar are authoritative for exact counts, logs, hashes, inventory,
  SBOM, license closure, and secret scan.
- Fault matrix: `target/conformance/fault-matrix-task03-final.jsonl` contains 85
  ordered cases and the matching results directory retains all 85 raw product
  observations. The log, digest closure, 16 mutation checks, review, and
  attestation close the matrix.
- Release publications name their exact security evidence and external review
  sidecar. Older release directories remain historical snapshots and do not
  authorize the current source tree.

## Release semantics

The required release invocation forces the exact release-contract commands,
the canonical critical mutation registry, bundle construction, extracted
install/reset/failure/recovery/shutdown checks, and a second build. It refuses
authorization unless the independently reviewed security evidence matches the
current source tree and Task 03 remains digest-closed.

The execution evidence is deliberately split without circularity. The bundle
manifest binds the prebuild oracle/mutant index and transcripts. The completed
authorization index adds the extracted smoke, binds it to the physical primary
archive, and records both primary/witness archive and manifest hashes. The final
independent attestation binds the completed authorization report.

All 17 canonical MUST-level identifiers have bidirectional semantic-test
traceability; the release gate rejects missing, duplicate, unknown, unbound, or
one-way mappings. The supported platform set is exactly macOS/aarch64.

## Final gate

The final source-stable run uses a newly generated, independently reviewed
security publication and the required release workflow. Machine-readable hashes
and individual command transcripts live in the evidence directories rather than
being copied into this source document, so the source digest remains stable and
rehashable.
