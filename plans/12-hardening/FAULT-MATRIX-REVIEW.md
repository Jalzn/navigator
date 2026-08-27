# Task 03 fault-matrix review

Status: **GO** (2026-08-26).

An independent read-only adversarial review verified the final canonical run:

- `target/conformance/fault-matrix-task03-final.jsonl` contains 85 ordered,
  unique fault points and seeds; the matching results directory contains 85 raw
  product observations, each of which reconstructs its JSONL record exactly.
- The schema split is 53 `durable-v2`, 16 `external-driver-v2`, 8
  `external-tool-v2`, 4 `external-artifact-v2`, and 4 `shutdown-v2` records.
- `fault-matrix-task03-final.digests` recomputes for the JSONL, log, validator,
  mutation suite, and sorted raw-result manifest.
- `python3 scripts/test-fault-matrix.py` passes 16/16 adversarial mutation and
  shape tests. `cargo fmt --all -- --check` and the focused Store, Local, and
  Driver clippy gate with `-D warnings` pass.
- Unsafe Tool work in Reserved or Uncertain state emits no executable frame on
  ordinary reconnect; unsafe Started work becomes durably Uncertain without
  replay. Safe ReadOnly/Idempotent work remains replayable and terminal work
  emits only its durable acknowledgement.
- Shutdown observations cover the pre-attempt domain fingerprint, ownership and
  Event preservation, one idempotent stale-owner rejection receipt followed by
  zero-delta replay and altered-request conflict, component-derived orphan and
  reservation-liveness checks, restart reconciliation, and independent process
  and Unix-socket sentinels.

No release-blocking uncertainty or surviving semantic substitution was found.
