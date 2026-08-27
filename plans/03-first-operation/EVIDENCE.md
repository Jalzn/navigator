# Slice 03 verification evidence

Status: verified by the complete repository gate and adversarial review.

Authoritative run: `target/conformance/run.JKOr0Z`. Every stage in
`gate-results.tsv` passed.

## Template and root Participant

- Template restoration recomputes compatibility and revalidates Driver,
  resource, trusted-configuration, schema, and input bounds.
- Secret values have no serializable or Consumer-visible representation.
- SQLite persists the complete registered Template and an exact root
  Participant binding. Corrupt registrations and forged compatibility fail
  before operation delivery.

## Durable Operation state machine

- Start is globally idempotent and returns the current durable snapshot on
  replay. Canonically equivalent JSON inputs replay; changed input conflicts.
- A partial unique index and a concurrent barrier test prove at most one
  unfinished Operation per Participant.
- Every transition commits state, typed terminal outcome, request ledger, and
  structured Event atomically. Terminal state is immutable.
- Crash matrices cover root creation, operation admission, and every transition
  boundary. Reopen tests verify Template, Participant, Operation input, result,
  and ordered Events.

## Authenticated Driver boundary

- Driver requests and responses use domain-separated HMAC authentication.
  Exact request, response, body, correlation, Instance, launch attempt, and
  fencing identities are bound before any result is trusted.
- The UDS suite rejects forged correlated responses, body mutation,
  cross-request replay, wrong credentials, prebound/replaced sockets, unsafe
  permissions, symlink credentials, oversized frames, and partial-frame denial
  of service.
- Navigator selects the Instance identity. Describe, protocol range, DriverId,
  Template capabilities, Start disposition, and the complete returned identity
  are checked before durable Ready.
- Cached Instances are epoch-scoped. The stale-epoch mutant proves no Driver
  effect, bounded cleanup of epoch N, and a fresh authenticated Instance for
  epoch N+1.

## Vertical result

`navigator-driver-fake/tests/vertical_e2e.rs` necessarily launches the real
fake binary and proves two complete paths:

- SQLite ownership, Template/root, FirstOperationService, Unix supervisor,
  authenticated UDS Driver, success, explicit failure, and idle followed by one
  reminder and `result_deadline` failure;
- LocalClient negotiation, Session open, Operation start, Consumer disconnect,
  a new LocalClient connection, durable terminal observation, and exact ordered
  Operation Events.

Dropping the Consumer-side handle does not cancel durable work. Driver catalog
mismatch has no spawn or journal effect. Explicit lifecycle cleanup leaves no
owned process or control socket.

## Repository gate

The authoritative gate passed:

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

Detailed logs and machine-readable evidence are under
`target/conformance/run.JKOr0Z`; `target/conformance/latest` points to this run.
