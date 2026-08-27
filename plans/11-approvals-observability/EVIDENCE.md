# Slice 11 verification evidence

Verified on 2026-08-26 on macOS/arm64. The authoritative machine-readable
evidence is under
`target/slice11-consolidation-evidence/slice11-verified.xMs4B5/`; its
`summary.json` reports `overall: pass` and its `gate-results.tsv` reports all
twelve gates as `pass`.

## Integral gate

The final confirmation used an isolated Cargo target and isolated evidence
directory:

```text
CARGO_TARGET_DIR=target/slice11-consolidation \
NAVIGATOR_EVIDENCE_ROOT=target/slice11-consolidation-evidence \
NAVIGATOR_EVIDENCE_RUN_PREFIX=slice11-verified \
./scripts/check.sh
```

Exit status: `0`.

| Gate | Result | Material facts |
|---|---:|---|
| format | pass | Workspace formatting check completed. |
| clippy | pass | Workspace, all targets, warnings denied. |
| semantic-evidence | pass | Machine and human evidence generation completed. |
| semantic-tests | pass | Complete locked Rust workspace suite and doc tests completed. |
| driver-typescript | pass | Type check, build, and fixture test completed. |
| pi-driver-typescript | pass | 47 passed, 0 failed/skipped. |
| offline-build | pass | Workspace built from the locked dependency set. |
| python-sdk | pass | Ruff and strict mypy passed; source 48/48, managed 1/1, installed wheel 50/50. |
| clean-source | pass | Fresh source copy rebuilt and reran Rust, TypeScript, and Python verification. |
| architecture | pass | Dependency-direction allowlist passed. |
| supply-chain | pass | Advisories, bans, licenses, and sources passed. Duplicate-version notices were warnings only. |
| unused-dependencies | pass | `cargo machete` found no unused crate dependencies. |

The Rust run includes `navigator-store-sqlite` at 148 passed, 0 failed, 1
ignored and `navigator-local` at 112 passed, 0 failed, 1 ignored. The inspector
CLI integration passed 1/1.

## Requirement evidence

### Approval lifecycle

- Domain/API matrices reject malformed request, Grant, effect and command
  states, recursively non-canonical JSON, scope mutants and invalid lifecycle
  transitions.
- SQLite tests cover atomic lifecycle/replay, exact expiry, durable time floors,
  final-use concurrency, namespace collisions, causal decision relay, row and
  ledger corruption, subprocess crash boundaries, and recovery after reopen.
- The local vertical proves the authenticated request/decision relay reaches the
  requester and that Grant consumption reserves the privileged effect before
  execution. Reconnect reconciliation closes terminal tool effects exactly
  once.
- Negative protocol/service tests prove an Executor cannot supply trusted
  decision authority, broaden scope, forge topology/correlation, or treat a
  pending request as authorization.

Representative passing tests include
`approval_lifecycle_is_atomic_bounded_and_replays_without_refund`,
`concurrent_final_approval_use_commits_exactly_one_intent`,
`approval_mutation_crash_matrix_is_atomic_and_exactly_replayable`,
`approval_decision_relay_is_causal_redacted_and_exactly_once`, and
`real_bidi_rpc_consumes_approval_before_handler_and_finishes_terminal`.

### Operational projections

- Migration/schema audit tests cover projection tables, foreign keys, indexes,
  cardinality, published-head coherence, row binding, secret material, and
  corruption on reopen.
- Typed folds enforce first revision, per-entity continuity, required identities,
  legal Operation/Delivery/Approval/Recovery transitions, terminal effect
  uniqueness, and exact Capacity/Failure families.
- Rebuild/current equality, atomic generation swap, authenticated bounded page
  tokens, durable clock floor, slow readers, unhealthy-session quarantine,
  progress retention/coalescing, and secret-sentinel redaction are exercised.
- Projector tests show a corrupt session cannot starve a healthy session and
  subscription hints are not on the commit path.

Representative passing tests include
`projection_rebuild_is_deterministic_and_pages_are_generation_bound`,
`projection_generation_swap_crash_is_prior_or_full_and_retry_converges`,
`projection_page_token_binds_generation_view_size_and_composite_cursor`,
`projection_projector_quarantines_a_full_corrupt_batch_before_healthy_tail`,
and the table-driven typed payload/schema mutants.

### Read-only inspector

- The Consumer API exposes bounded projection pages behind negotiated
  capabilities and authenticated session binding.
- `inspector_rpc_is_read_only_bounded_and_resumes_after_reconnect` and
  `inspector_fingerprint_detects_a_mutant_in_every_mutable_table` prove bounded
  reads and byte-stable domain state across inspection.
- `navigatorctl_inspect_is_finite_noninteractive_and_bound_to_prior_negotiation`
  proves the separate non-interactive terminal path; the Unicode truncation
  subprocess/UDS integration test proves bounded safe rendering.

## Initial failures and correction audit

The first non-isolated diagnostic run was not used as the verification result.
It reported three failures: a missing `ApprovalDecision` match arm in the fake
driver, a stale public mailbox-event key allowlist, and an architecture allowlist
that did not yet name the reviewed `hmac` and `tracing` SQLite dependencies.
All three were corrected. The full isolated command above then passed without a
retry inside any gate.

## Ignored, skipped, flaky, and warnings

- `navigator-store-sqlite::tests::crash_worker` is ignored by design because it
  is a subprocess crash entry point invoked by the surrounding crash matrix.
- `navigator-local::artifact_store::tests::crash_after_publish_worker` is
  likewise a subprocess entry point exercised by its parent crash test.
- The clean-copy installed Python run reported 47 passed and 3 skipped because
  optional built daemon/fake-driver binaries are unavailable in that installed
  test context (`test_managed_local.py` explicit skip guards). The primary
  installed-wheel run had those binaries and passed 50/50.
- No flaky test or retry was observed. The two `pi_controller_tree` executions
  took about 345 and 343 seconds and passed normally.
- Supply-chain emitted duplicate-version warnings for transitive crates; the
  enforced advisory, ban, license, and source policies all passed.

No Slice 12 work was included in this verification.
