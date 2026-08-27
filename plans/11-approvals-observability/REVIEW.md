# Slice 11 adversarial review

Verdict: **GO**. The final isolated integral gate exited successfully with all
twelve checks passing. No unresolved Slice 11 correctness blocker was found.

## Requirement audit

| Plan requirement | Adversarial question | Evidence | Verdict |
|---|---|---|---:|
| Trusted decision boundary | Can an Executor self-approve or inject trusted source/scope? | Decision commands omit caller-controlled trust/scope; authenticated Consumer service and negative topology/correlation tests fail closed. | GO |
| Narrow Grant | Can decision broaden subject, operation, capability, resource, Session, expiry, or use count? | Relational validators, custom deserialization, digest mutants, SQLite row audits, and causal relay tests bind every field. | GO |
| Atomic effect authorization | Can use be refunded, duplicated, or separated from effect reservation? | One immediate transaction updates Grant/request, reserves the effect, writes event/ledger; replay, crash and concurrent-final-use tests pass. | GO |
| Expiry/revocation | Can clock regression, equality, reopen, or a race resurrect authority? | Durable time floor, exact-boundary, reopen, consume/revoke and approve/expire race tests pass. | GO |
| Request is not authority | Can Pending/Denied/Expired authorize the tool? | Effect-time validation requires the exact live Granted state and Grant; local vertical and status mutants fail closed. | GO |
| Durable audit | Can a mutation commit without a reconstructible, redacted event? | Same-transaction event/ledger tests, exact event identity/payload tests, secret sentinels and crash matrices pass. | GO |
| Seven projections | Are tree, work, delivery, approval, recovery, capacity and failure merely latest payloads? | Typed per-family state machines enforce required identity, revision continuity and legal transitions; malformed-family mutants fail. | GO |
| Rebuildable/read-only source | Can projection mutate source or differ after rebuild? | Online/rebuild equality, source fingerprint and atomic generation-swap tests pass. | GO |
| Bounded viewers | Can paging be forged, grow without bound, resurrect after clock rollback, or block commits? | HMAC tokens, page cap, durable time floor, stale/slow-reader tests, capacity-one hints and durable polling pass. | GO |
| Failure isolation/progress | Can corrupt Session A starve B or progress grow without bound? | 128-corrupt-session quarantine test, healthy-session convergence, N=8 retention and coalescing/drop tests pass. | GO |
| Redaction/tracing | Can secret payloads appear in Events, projections, traces, or errors? | Event decoder/allowlists and observable sentinel tests cover all four surfaces; traces contain public IDs only. | GO |
| Consumer API | Are snapshots bounded and capability/session bound? | Protocol round-trip/mutant tests and service authentication/negotiation tests pass. | GO |
| Read-only inspector | Does paging/reconnect change any mutable state? | Full mutable-table fingerprint is identical; reconnect/resume and bounded RPC tests pass. | GO |
| Terminal/non-interactive UI | Can output contaminate an Executor terminal or become unbounded? | Separate `navigatorctl inspect`, finite non-interactive integration, count bound and Unicode-safe truncation tests pass. | GO |
| Slice exit gate | Do trust, atomicity, expiry, revocation, projection, redaction and slow-subscriber checks all pass together? | Isolated `scripts/check.sh` result: 12/12 gates pass. | GO |

## Adversarial history

Review iterations rejected incomplete migration metadata audits, weak relational
bindings, caller-asserted trust, non-atomic relay, global request-namespace
asymmetry, replay that advanced clocks, non-semantic projection folds, public
token keys, starvation, read-side lease writes, and insufficient typed event
decoding. Each rejection gained a focused mutant or crash/concurrency oracle
before the final integral run.

The final run still records two ignored Rust subprocess entry points and three
environment-guarded skips in the clean-copy installed Python run. They are
classified in `EVIDENCE.md`; none suppresses product behavior, and the primary
installed-wheel suite passes 50/50. Duplicate transitive dependency warnings are
non-blocking because all enforced supply-chain policies pass.

## Residual risk

The remaining risk is operational rather than a known correctness defect:
process-crash and PI-tree tests are comparatively slow, and duplicate transitive
crate versions increase update surface. Neither produced a failure or retry in
the final run. No requirement is deferred to Slice 12.
