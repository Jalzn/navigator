# Slice 12 release-gate evidence

Status: release-gate infrastructure verified; current-source authorization awaits
fresh external Task02 and release review sidecars.

The release gate deliberately separates mechanical bundle validation from release
authorization. `scripts/check.sh` generates a fresh current-source security
candidate but does not self-authorize it. After independent review produces a
digest-bound attestation, the operator supplies both
`NAVIGATOR_REVIEWED_SECURITY_EVIDENCE` and `NAVIGATOR_SECURITY_ATTESTATION`;
only then does `--require-release` run the complete authorization workflow.

## Contract and artifacts

- `conformance/release-v1.json` pins supported platforms, protocol sources,
  Store schema source, bundle inputs, executable release oracles, and predecessor
  reviews.
- `conformance/release-critical-mutations-v1.json` identifies the critical
  security/durability mutants which must remain executable.
- `scripts/release-gate.py --build-bundle` uses locked/offline Rust inputs, builds
  the Pi Driver from its lockfile, copies the Python SDK, migrations and protocol
  schemas, consumes the Task 02 SBOM/license/secret outputs, and emits sorted
  `MANIFEST.json` plus `SHA256SUMS`.
- Consumer and Driver proto directories retain distinct names in the bundle.
- The bundle includes the Task 03 canonical JSONL, log, digest closure, all 85
  raw observations, and both predecessor review attestations. `MANIFEST.json`
  binds the release contract, evidence indices, source scan, toolchains, reviews,
  and attestations.

## Executable oracles

The release contract binds each claim to both an exact command and a source
evidence symbol. It covers process restart, schema 18 to 20 preservation,
incompatible Template reset, the real Pi hierarchy, and external shutdown with
reopen/reconciliation. Symbol presence is not treated as execution: exits are
recorded only when `--run-oracles` is used.

## Current review state

- Tasks 02 and 03 are independently verified with immutable, digest-bound
  evidence and review attestations.
- Final release authorization uses a schema-2 security directory generated from
  the stabilized current source plus an independent machine-readable GO
  attestation. The gate rehashes its index and current source inventory and does
  not rewrite `summary.json` to manufacture GO.
- The primary bundle and separately persisted reproducibility witness have
  byte-identical manifests and archives. The final Task 04 adversarial review
  independently rehashed both.
- All 17 normative `MUST` lines have unique canonical IDs. The traceability
  manifest maps every ID to semantic evidence, and every listed test source
  reciprocally declares the same IDs. The gate rejects missing, duplicate,
  unknown, unbound, or one-way mappings.

`--require-release` also forces all release oracles, all critical mutants, an
extracted install/lifecycle smoke, and two byte-identical bundle/archive builds;
omitting their flags cannot weaken authorization. Oracle, mutant, and smoke
transcripts are persisted in a closed execution index. The bundle manifest
binds the prebuild index; the completed authorization sidecar binds the smoke,
primary and witness hashes, and an external independent attestation binds the
authorization report itself.

## Focused execution (2026-08-26)

- `CARGO_TARGET_DIR=target/release-gate-isolated cargo test -p navigator-store-sqlite release_upgrade_v18_to_v20_preserves_compatible_session --locked`: pass (1/1).
- `CARGO_TARGET_DIR=target/release-gate-isolated cargo test -p navigator-store-sqlite reset_accepts_a_new_incompatible_specification --locked`: pass (1/1).
- `CARGO_TARGET_DIR=target/release-gate-isolated cargo test -p navigator-driver-fake --test pi_controller_tree --locked`: pass (8/8, 431.87 s). This exercised real Node/Pi processes and the explicit tree shutdown oracle.
- `CARGO_TARGET_DIR=target/release-gate-isolated cargo test -p navigator-local --test acceptance lifecycle_replay_and_subscription_survive_a_real_process_restart --locked`: pass (1/1).
- The first shutdown invocation omitted `--features fault-injection` and failed because its worker exited successfully instead of aborting. The release contract was corrected; `CARGO_TARGET_DIR=target/release-gate-isolated cargo test -p navigator-local --features fault-injection --test acceptance external_shutdown_fault_matrix_reopens_and_reconciles_owned_session --locked` then passed (1/1). Its four nested workers fail at their injected boundary by design; the parent proves reopen/reconciliation and unrelated-process survival.
- `python3 -m py_compile scripts/release-gate.py`, JSON parsing, and `cargo fmt --all -- --check`: pass.
- Two consecutive `--build-bundle` executions produced byte-identical `MANIFEST.json`; `sha256sum -c SHA256SUMS` passed and the bundle contained no `.venv`, Ruff cache, Python bytecode, or `__pycache__`. The normalized PAX archive supports the long packaged runtime paths. The first comparison before cache exclusions changed as expected and was not counted as reproducible evidence.
- The gate extracts that archive into a fresh directory, installs the packaged
  SDK offline from its complete wheelhouse, executes the extracted daemon/CLI
  and Pi entrypoint checks, starts and stops `Navigator.local`, then runs the
  packaged `managed_work.py` through Session, hierarchy, mailbox, Operation and
  terminal result. It rejects surviving processes whose command contains the
  extraction/output paths and any remaining managed-data Unix socket.
- An initial extracted vertical exposed that the copied Python runtime still
  contained a historical pre-v20 daemon (the Operation dead-lettered). The
  builder now regenerates the wheel runtime from the just-built release daemon,
  Pi package, protocol package and pinned Node before packaging; the rerun passed.
- Two additional extracted-only lifecycle oracles now pass. The incompatible
  reset oracle runs the installed public acceptance workflow, proves one old
  Session is closed and unfenced, one replacement Session is open, exact
  `session.closed`/`session.created` events exist, no old Artifact or managed
  socket remains, and a separately started `/bin/sleep` PID survives. The fault
  oracle durably queues real Driver work, identifies the managed `navigatord`
  host by its exact database argument, kills only that PID, reopens from the
  installed wheel, observes a bounded recovery disposition (including the
  authoritative `CleanupRequired` path), resets when cleanup is required, and
  proves the old Operation is terminal, the old Session is closed, no socket
  remains, and the unrelated sentinel process survives.
- Focused command used for those two oracles: an offline clean-venv install from
  `target/release-bundle-extracted/wheelhouse`, followed by direct calls to
  `_assert_extracted_reset_cleanup` and
  `_assert_extracted_driver_failure_recovery`; exit 0 (`reset PASS`,
  `fault recovery PASS`). A preceding run correctly exposed that
  `CleanupRequired` classifications are consumed by reset rather than always
  retained in `recovery_classifications`; the oracle now requires the returned
  authoritative classification plus terminal durable cleanup instead of a
  false ledger-row assumption.
- The critical mutation runner applies six concrete implementation defects in
  six temporary source copies. All six corresponding product oracles failed;
  no mutant survived the final run. An earlier too-narrow stale-owner mutant
  survived and was strengthened to remove the actual fencing guard before the
  final green run.

## Final authorization

A current authorization must consume an explicitly supplied external Task02
attestation, record zero blockers, retain all oracle and mutant transcripts,
exercise the extracted primary archive, and produce byte-identical primary and
witness artifacts. Its independent release attestation must bind the completed
report and machine-readable indices. Earlier release directories remain
historical evidence for their own source snapshots.

The final integral workspace gate and slice-wide audit are recorded in
`EVIDENCE.md` and `SLICE-REVIEW.md`.
