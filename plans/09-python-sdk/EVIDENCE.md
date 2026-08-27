# Slice 09 verification evidence

Status: verified by installed-wheel acceptance, real managed `navigatord` and
Pi subprocesses, restart and replay tests, adversarial fault review, clean-source
reproduction, and the complete repository gate.

Authoritative run: `target/conformance/run.q8dm34`. Every stage in
`gate-results.tsv` passed.

## Generated and wrapped Consumer client

- The Python package generates its private protobuf/gRPC transport
  reproducibly with pinned tooling. Rust and Python share a golden negotiation
  fixture; generated modules remain behind frozen public models and one typed
  failure hierarchy.
- Session, Participant, Operation, Message, cancellation, Event, ownership,
  recovery, and uncertainty snapshots are validated at their public bounds.
  Unknown Event types remain observable without weakening validation of known
  schemas.
- Exact retry preserves request identity and semantics. Conflicting reuse is a
  typed conflict. Reset replay reads the durable ledger before destructive
  preflight, so retrying reset cannot close the replacement Session.
- Async cancellation remains distinct from durable Navigator cancellation;
  transport errors and diagnostics do not expose credentials or private
  terminal output.

## Managed local lifecycle and packaging

- `Navigator.local()` installs and starts the bundled `navigatord`, pinned Node
  runtime, Pi adapter, faux provider, and trusted catalog without requiring the
  Consumer to know Rust, Node, or Pi paths. The default startup budget is
  finite and exercised without a test-only override.
- Bootstrap and public Unix sockets are private at their first observable path.
  Concurrent publishers cannot overwrite an active socket, and symlinks,
  regular files, unsafe parents, stale credentials, and catalog mutations fail
  before admission.
- Startup timeout, early exit, invalid configuration, incompatible catalog,
  competing ownership, daemon crash/restart, context exit, and host shutdown
  are bounded. Owned processes and process groups are reaped; cleanup failure
  cannot be reported as success.
- The wheel is built from its sdist as
  `py3-none-macosx_11_0_arm64`, installed into an isolated Python 3.13
  environment, and carries the runtime bundle required by managed local mode.

## Real Operation and recovery behavior

- The managed examples open Sessions, run Operations through the generic Pi
  catalog, stream and resume Events from exact positions, cancel work, resume
  interrupted work, and reset incompatible state. The same public client also
  connects to an external endpoint.
- A real fake Driver restart completes exactly once. A real Pi restart across
  an unsafe boundary fails closed as `CleanupRequired` without redelivery.
- Real hierarchy tests execute Coordinator/Campaign/Worker and sibling trees,
  preserve public causal outcomes, and stop every live process child-first.
- The intermittent tree failure was traced to the ownership watchdog treating
  one retryable SQLite `Busy`/`Unavailable` as definitive fencing loss. The
  watchdog now shares one bounded uncertainty window across launch reads and
  authority validation, resets it only after full validation, and still
  revokes immediately on authoritative loss or after sustained uncertainty.
  Non-conforming Drivers are escalated with verified TERM/KILL and bindings are
  retained whenever exit or cleanup is unproven.

## Test quality and execution evidence

- Deterministic supervisor mutants cover alternating retryable Store failures,
  sustained uncertainty, validation reset, nonretryable corruption, zero and
  unrepresentable deadlines, a Driver that ignores ownership EOF, a process
  that never exits, and cleanup/binding retention. The supervisor suite passed
  38/38.
- The Pi TypeScript suite passed 45/45. The installed Python package passed 39
  contract/example tests, the unconfigured-daemon smoke, and 49 managed-local
  tests.
- In the authoritative run the semantic Pi tree suite passed 7/7 in 399.57s.
  The independent clean-source copy rebuilt dependencies and the wheel, then
  passed the same tree suite 7/7 in 364.95s, including
  `session_shutdown_stops_every_live_pi_tree_process`.

## Repository gate

The authoritative gate passed `format`, `clippy`, `semantic-evidence`,
`semantic-tests`, `driver-typescript`, `pi-driver-typescript`, `offline-build`,
`python-sdk`, `clean-source`, `architecture`, `supply-chain`, and
`unused-dependencies` in one run.
