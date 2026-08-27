---
status: verified
slice: 12-hardening
depends_on:
  - plans/12-hardening/02-security-compatibility.md
specs:
  - docs/execution.md
  - docs/communication.md
---

# Task: Run complete fault matrix

## Outcome

Inject failure before and after every durable commit and external effect in
launch, delivery, Tool invocation, report, cancellation, Artifact publication,
approval consumption, and shutdown.

## Verification

- No duplicate unfinished Participant or Operation.
- No permanent reservation without lease or classification.
- No uncertain effect replayed by ordinary resume.
- No stale owner commits.
- No unrelated process receives termination.
- Every scenario ends terminal, recoverable, uncertain, or cleanup required.

## Evidence

Machine-readable matrix with seed, fault point, expected classification, actual
classification, and final invariant checks.

Verified evidence (2026-08-26):

- `target/conformance/fault-matrix-task03-final.jsonl`: 85 ordered cases.
- `target/conformance/fault-matrix-task03-final-results/`: 85 independent raw
  product result files retained before aggregation.
- `target/conformance/fault-matrix-task03-final.log`: full runner output; the
  final line records `fault-matrix: 85 cases passed`. Nested worker failures in
  the shutdown cases are the deliberately injected aborts and are accepted only
  when their parent reopen/reconciliation oracle exits successfully.
- `target/conformance/fault-matrix-task03-final.digests`: binds the canonical
  JSONL, log, all sorted raw-result digests, validator, and mutant suite.
- `python3 scripts/test-fault-matrix.py`: 16 mutation/shape tests pass, including
  substitutions of Driver receipt/state, Artifact file/metadata state, and Tool
  reconnect/call/receipt state, plus durable/shutdown schema, ledger, fingerprint,
  reservation-liveness, and orphan-component state; each substitution invalidates
  the claimed fact/classification.
- The Tool reconnect oracle executes the production replay path: unsafe
  Reserved/Uncertain work emits zero frames until explicit reconciliation,
  while terminal work emits only its durable acknowledgement. Provider call and
  terminal-receipt row counts remain identical before and after reconnect.
- `CARGO_TARGET_DIR=/tmp/navigator-task03-check cargo clippy -p
  navigator-store-sqlite -p navigator-local -p navigator-driver-fake --tests --
  -D warnings`: pass.
- `cargo fmt --all -- --check`: pass.

Independent adversarial review reconstructed every raw record, recomputed the
digest set, reran the mutation and compiler gates, and inspected the production
recovery paths. The final verdict is GO; see `FAULT-MATRIX-REVIEW.md`.

## Done

The central recovery promises survive systematic crash injection.
