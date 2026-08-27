# Slice 02 verification evidence

Verified by the complete repository gate recorded at
`target/conformance/run.1odR5Y`. Every stage in `gate-results.tsv` passed.

## Driver protocol

- The versioned protobuf contract covers describe, start, inspect, delivery,
  acceptance, report, cancellation, stop, observation, and events without a
  Pi-specific type.
- Bounded framing, explicit success/failure unions, unknown acceptance, and
  uncertain cleanup outcomes are exercised by 13 Rust protocol tests.
- Canonical HMAC authentication binds the decoded body, request and envelope
  identities, nonce, expiry, Participant, launch attempt, and ownership epoch.
  Replay storage is bounded and fails closed.
- Rust and TypeScript decode the shared `start-v1.bin` fixture. The TypeScript
  compiler and golden-fixture check ran in the `driver-typescript` gate.

## Deterministic fake Driver

- The conformance harness drives the real fake binary through bounded
  length-delimited stdin/stdout frames; it does not call an in-process test
  shortcut.
- The journal commits an `Unknown` delivery intent before the external effect
  and commits `Accepted` afterward. Ten injected commit boundaries establish
  `NotAccepted`, `Unknown`, or `Accepted` according to the durable boundary.
- Restart and redelivery preserve at-most-one externally recorded effect;
  conflicting semantic input cannot reuse the Message identity.
- Authentication mutation, exact expiry, nonce replay across restart,
  malformed/truncated/oversized frames, disconnection, and EOF ownership loss
  are covered by the black-box suite.
- The fake Driver contributes 11 tests; the reusable conformance crate
  contributes 12 tests, including an independent semantic mutant.

## Instance persistence and supervision

- The shared `InstanceStore` contract proves atomic launch preparation,
  evidence attachment, lifecycle transitions, global request identity,
  fencing, takeover, exact expiry, replay, conflict, and reopen behavior.
- SQLite schema version 2 validates its foreign keys and uniqueness indexes
  and uses immediate transactions. Prepare and attach/transition crash matrices
  cover every mutation/ledger/commit boundary.
- The supervisor persists before spawn, attaches verified creation evidence by
  compare-and-set, requires a challenge-bound ready proof, and refuses blind
  process adoption after restart.
- Twenty supervisor tests cover dual-supervisor races, every requested launch
  fault window, ownership loss, readiness authentication, reconciliation,
  graceful and forced cleanup, stable `CleanupRequired`, executable
  replacement, forged process evidence, EOF self-exit, and a stubborn process
  group descendant. The unrelated-process tests prove identity mismatch never
  reaches signaling.
- Environment inheritance is cleared and rebuilt from an explicit allowlist;
  credential directories/files use private Unix permissions.

## Repository gate

The authoritative gate passed these stages:

- `format`
- `clippy`
- `semantic-evidence`
- `semantic-tests`
- `driver-typescript`
- `offline-build`
- `clean-source`
- `architecture`
- `supply-chain`
- `unused-dependencies`

The detailed immutable run artifacts are under
`target/conformance/run.1odR5Y`; `target/conformance/latest` points to that run.
