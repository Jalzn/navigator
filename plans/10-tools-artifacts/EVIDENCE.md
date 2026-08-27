# Slice 10 verification evidence

Status: verified by domain and wire conformance, durable SQLite mutation and
crash tests, local Artifact security tests, Python SDK tests, real Driver
restart tests, and the installed-wheel Python/Pi vertical demonstration.

This is Slice-specific evidence. The repository-wide `scripts/check.sh` run is
not claimed as passing here: the stale Slice 11 schema-migration fixtures were
corrected, but no complete global run was recorded afterward.

## Authoritative vertical demonstration

The retained installed-wheel run is
`target/conformance/slice10/wheel-run-3`:

- `vertical.exit` is `0`, and `vertical.stdout` records `status: ok`, one Tool
  effect, the exact Artifact reference, and connection watermarks
  `[0, 0, 0, 1]`.
- `durable-state.txt` records provider generation 4, acknowledged server
  sequence 1, one each of reserved/started/completed Tool Events, a completed
  invocation with a terminal digest and one Artifact, and four bounded provider
  connection Events.
- `scripts/slice10_vertical.py` builds and installs the wheel into an isolated
  environment, starts the real managed daemon and Pi Driver, registers a stable
  Tool, and makes the faux model's second response depend observably on the
  Tool result's Artifact reference. The root Operation result must equal that
  exact reference.
- The provider is disconnected while its handler is paused. The terminal ACK
  is deliberately dropped, the terminal invocation is already durable while
  generation 3 still reports watermark 0, and generation 4 replays the
  terminal ACK before advancing to watermark 1. The handler-side effect log
  remains exactly one line.
- Artifact bytes are read and hashed through the public SDK. Logical deletion
  makes a subsequent read return `NotFound`; independent on-disk corruption
  makes a subsequent read return `CorruptedState`. Temporary managed runtime
  directories are absent after cleanup.
- The `SLICE10_DROP_TOOL_ARTIFACT=1` mutant removes the Artifact reference from
  the Tool result. It proves that the successful root result cannot be produced
  while the handler effect remains one. It does **not**, by itself, prove that
  every such omission is surfaced as one particular typed failure.

## Durable Tool contract

- `crates/navigator-domain/src/tool.rs` and
  `crates/navigator-store-api/src/tool.rs` define bounded, serde-revalidated
  Tool definitions, registration identity, invocations, dispatch identity,
  results/failures, Artifact references, effect classes, cancellation and
  timeout contracts.
- Consumer and Driver protocol tests reject oversized or context-divergent
  inputs, outputs and Artifact references. The broker validates authority,
  registration/provider binding, current connection and generation before
  accepting Started or terminal frames.
- SQLite persists registration, provider connection, invocation, dispatch,
  mutation ledger, terminal digest and effect-journal relationships. Strong
  loaders and open-time audit compare canonical blobs with mirrored columns,
  cross-tree identities, consumer binding, effect and grant state.
- Shared Store conformance and SQLite mutants cover exact replay versus
  semantic conflict, caller/epoch/lease/registration/dispatch divergence,
  terminal duplicate versus conflict, cancellation ordering, watermark holes,
  stale generations, reconnect replacement, uncertainty resolution and the
  effect-class recovery matrix.
- SQLite crash fixtures cover registration, connection, reserve, Started,
  terminal, cancellation and uncertainty boundaries. The asserted contract is
  prior-or-fully-committed across Tool snapshot, request ledger, Event,
  authority grant and effect journal.

The guarantee is Navigator's durable **logical exactly-once** contract: one
invocation identity, one accepted terminal truth and replay-safe recovery.
Navigator cannot promise absolute exactly-once execution in an arbitrary
external system. Non-idempotent work that becomes uncertain is not blindly
replayed; it requires the declared recovery contract and proof or a terminal
do-not-retry decision.

## Reconnect, lifecycle and cancellation safety

- `crates/navigator-local/src/tool_broker.rs` creates the bounded response
  stream before replay, orders dispatch/cancel/terminal replay by durable server
  sequence, fences stale providers, and uses bounded cancellation-aware sends.
- `packages/navigator-python/src/navigator/tools.py` retains provider state
  across stream reconnect, validates connection sequence/watermark invariants,
  correlates cancellation by dispatch, coalesces duplicate work and prunes
  terminal relays.
- `crates/navigator-local/src/driver_executor.rs` publishes a reconnected
  control/observe channel pair atomically. `LifecycleFence` serializes final
  publication against request-stop, shutdown and every watchdog terminal exit.
  Panic and abort close the fence through the production drop guard.
- Supervisor mutants cover retryable `load_launch` expiry, nonretryable Store
  errors, pre-existing `Stopped`/`CleanupRequired`, ownership loss, panic and
  abort. The retryable-expiry oracle observes that the lifecycle fence is closed
  before backend ownership revocation.
- A real fake-Driver restart persists the PID receiving Stop. The final Python
  test proves the replacement PID B, and not crashed PID A, receives the
  shutdown Stop; both processes are subsequently absent.
- Session close/reset supervision is cancellation-safe: an in-flight close
  remains discoverable, per-session close serialization is bounded and weakly
  retained, exact retry can finish durable close, and a newer supervisor cannot
  be removed by stale cleanup.
- A pending launch cancelled after in-memory publication but before durable
  prepare may be removed only while holding its launch lock and only on the
  explicit `LaunchNotFound` result. Busy, unavailable, corrupt and ambiguous
  launch states remain fail-closed.

## Artifact Store

- `crates/navigator-local/src/artifact_store.rs` writes to an owned temporary
  file, counts and hashes while streaming, atomically publishes beneath the
  Session root, and persists metadata only after publication.
- Domain, protocol and SDK bounds cap Artifact and chunk sizes before unbounded
  accumulation. Tests cover traversal, symlink and locator attacks, partial and
  oversized writes, declared-size and hash mismatch, concurrent publication,
  crash boundaries, corrupt bytes and bounded reads.
- Artifact references bind immutable digest, size and media type to Session,
  creator Participant and creator Operation. Tool results must use the same
  Session/Participant/Operation context as their invocation, and the generic
  Driver result carries those references through Worker to root.
- Logical deletion changes durable visibility and makes reads fail. It is not
  physical erasure. Retention eligibility and authorized physical erasure are
  separate operations with replay recorded before destructive I/O.

## Reproducible execution ledger

The entries below are ordered by the final stabilization sequence known on
2026-08-25. A count is stated only when it was retained in command output or an
authoritative artifact.

| Command or artifact | Observed result |
| --- | --- |
| `./scripts/check-python-sdk.sh` | Exit 0. Ruff passed; mypy passed 11 checked source files; contract and acceptance tests passed 44; unconfigured-daemon test passed 1; managed-local tests passed 50. |
| `cargo test -p navigator-driver-fake --test vertical_e2e` | 7 passed, 0 failed in the final full vertical-e2e run. |
| `./scripts/check-pi-driver-typescript.sh` | 45 passed, 0 failed in the retained final Pi TypeScript run. |
| Installed wheel plus `scripts/slice10_vertical.py` | 1 successful vertical run (`vertical.exit` = 0). Raw result: `target/conformance/slice10/wheel-run-3/vertical.stdout`; durable projection: `target/conformance/slice10/wheel-run-3/durable-state.txt`; daemon/Pi stderr: `target/conformance/slice10/wheel-run-3/vertical.stderr` and `run/pi.stderr`. |
| `uv run pytest -q tests/test_managed_local.py::test_mailbox_fake_restart_reconciles_to_succeeded_exactly_once` from `packages/navigator-python` | 1 passed, 0 failed in 2.24s. It includes the final fake journal assertion that Stop was received only by replacement PID B. |
| `cargo test -p navigator-supervisor watchdog_ --lib --no-fail-fast` | 5 passed, 0 failed, 36 filtered. |
| `cargo test -p navigator-local --lib` in the final local-suite run | 105 passed, 0 failed, 1 ignored (106 total). |
| `cargo test -p navigator-local production_watchdog_drop_guard_fences_panic_and_abort --lib`; `cargo test -p navigator-local watchdog_fence_wins_when_reconnect_is_paused_before_publish --lib`; `cargo test -p navigator-local reconnected_pair_is_atomic_fenced_and_visible_to_old_holders --lib` | Each command passed 1, failed 0, with 105 filtered. |
| `cargo test -p navigator-supervisor watchdog_retryable_authority_expiry_closes_terminal_fence --lib` | 1 passed, 0 failed, 40 filtered. The backend observed the fence closed before revoke. |
| `cargo fmt --all -- --check` | Exit 0 after applying `cargo fmt --all` to the final import/assertion layout. |
| `cargo clippy -p navigator-supervisor -p navigator-driver-fake --all-targets -- -D warnings` | Exit 0. |
| `cargo clippy -p navigator-local --lib -- -D warnings` | Exit 0 after the reconnect/lifecycle changes. |
| `cargo test -p navigator-local reopened_store_reconciles_exact_committed_pair_once_without_replacement_rows --lib` | 1 passed, 0 failed, 105 filtered after the final recovery-test correction. |
| `cargo clippy -p navigator-local --all-targets -- -D warnings` | Exit 0 after that recovery-test correction; `cargo fmt --all -- --check` also exited 0. |
| `cargo test -p navigator-store-sqlite --lib` after correcting the stale 0017 migration fixtures | 119 passed, 0 failed, 1 ignored. |

The full Python gate precedes the last Rust-only recovery test correction in
this ledger. That correction changed `crates/navigator-local/src/recovery_backend.rs`
test orchestration and expectations; it did not change Python sources, generated
transport, daemon runtime production code, Tool/Artifact protocol, or the wheel.
The affected Rust focal and `navigator-local` all-target clippy were rerun after
it.

## Global-gate status

Several `scripts/check.sh` attempts were made during final integration. The
latest retained nonzero attempt reached the SQLite suite and failed only four
tests whose fixtures still described schema 16 after migration 0017 introduced
schema 17: the legacy-v3 downgrade fixture retained the four new Approval
tables, the future-schema oracle used the old version boundary, and migration
version/table-count expectations were stale. Those fixtures were corrected,
and the subsequent Store library result was 119 passed, 0 failed, 1 ignored.

No complete `scripts/check.sh` run was recorded with exit 0 after those fixes.
Accordingly this document claims the Slice-specific results above, not a current
repository-wide green gate.
