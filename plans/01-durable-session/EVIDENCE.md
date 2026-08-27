# Durable Session semantic evidence

Status: verified by the full repository gate and three adversarial review rounds.

Authoritative gate: `./scripts/check.sh`

Evidence run: `target/conformance/run.vsPc3c` (also available through
`target/conformance/latest`). Every stage in `gate-results.tsv` passed: format,
clippy, semantic evidence, semantic tests, offline build, clean-source rebuild,
architecture, supply-chain policy, and unused dependencies.

| Required behavior | Semantic evidence |
|---|---|
| Session lifecycle is atomic and durable | Shared Store contract plus SQLite open/close crash matrices prove the committed state is either the valid prior state or the valid next state. |
| Schema and migration fail closed | SQLite schema validation rejects unknown versions before writes; migration abort tests verify integrity and recoverability. |
| Request identity is globally idempotent | Store conformance rejects a session-scoped ledger mutant; SQLite tests preserve request outcome and digest across reopen and crash. |
| Ownership is exclusive and fenced | Store contract, two-host acceptance scenario, and acquire/renew/release crash matrices prove one live epoch and rejection of stale epochs. |
| Lease time cannot regress or be extended without bound | Fake-clock contract and persisted time-floor tests cover equality, wall-clock regression, and maximum future validity. |
| Renewal and shutdown are supervised | Core tests cover renewal loss, bounded shutdown, release failure, and the already-cleared ownership path that performs no second release. |
| Consumer protocol is versioned and bounded | Protocol tests cover negotiation, every request shape, canonical error mapping, malformed identifiers, raw oversize frames, and exact boundary values. |
| Authentication and capability authority fail closed | Local acceptance tests reject invalid credentials, unnegotiated tokens, unsupported versions, and capability escalation without Store effects. |
| Behavior crosses a real process boundary | Local acceptance launches the daemon and CLI over a Unix socket and proves lifecycle, replay, restart, competing hosts, and Event subscription. |
| Local transport cleanup is safe | Acceptance tests cover restrictive permissions, unsafe parents, active sockets, files, symlinks, SIGKILL stale-socket recovery, inode-safe cleanup, and nonzero cleanup failure. |
| Capacity is bounded and recoverable | Subscription acceptance tests exhaust the global limit, observe typed failure, drop a stream, and prove capacity is returned. |

The adversarial rounds found and drove fixes for capability-registry exhaustion,
stream-task retention, stale-socket replacement, hidden cleanup failures, and a
Close/SIGTERM double-release race. The final read-only round found no remaining
Slice 01 blocker. Concurrent duplicate Close calls may transiently observe a
stale response while the first commit is in flight; retry is resolved by the
durable global request ledger and does not weaken the slice contract.
