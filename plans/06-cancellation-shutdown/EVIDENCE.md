# Slice 06 verification evidence

Status: verified by semantic tests, real subprocess demonstrations, the complete
repository gate, and adversarial review.

Authoritative run: `target/conformance/run.y4uDwH`. Every stage in
`gate-results.tsv` passed.

## Durable subtree cancellation

- A cancellation request atomically marks the selected Participant subtree and
  records explicit outcomes for every affected Operation. Queued work becomes
  terminal without launching a Driver; active work enters `Cancelling`.
- Child creation, Operation start, and launch preparation recheck the durable
  cancellation tombstone transactionally. Crash and concurrency matrices prove
  that no post-cancellation work can escape through a race.
- Control Messages have reserved priority and are translated into authenticated
  Driver `CancelRequest` frames. Driver acknowledgement is durable but remains
  distinct from the terminal `Cancelled` report.
- Repeated cancellation returns current durable state without reinjecting the
  native effect. Late success after committed cancellation is rejected.
- SQLite contract tests keep an unrelated sibling outside the cancelled scope;
  the real Consumer/UDS/Driver scenario proves `Running -> Cancelling ->
  Cancelled`, ordered Events, one native cancellation, replay, and restart.

## Verified process termination

- Driver Stop is attempted first, while one absolute deadline reserves enough
  budget for operating-system escalation. `StopConfirmed` is accepted only when
  the Driver process actually exits.
- Unix termination retains the original non-adoptable `Child` handle, validates
  stored PID, PGID, parentage, creation evidence, and executable identity, and
  never signals using persisted PID/PGID alone.
- Identity mismatch and missing topology fail closed before any signal.
  Graceful and forced group termination include descendants and are bounded.
- Failed cleanup remains registered and durably `CleanupRequired`, allowing a
  later retry; successful cleanup removes only the exact active entry.
- Credential directories require private ownership and reject symlinks without
  touching their targets. Cleanup oracles distinguish a safe empty structural
  directory from leaked credentials, sockets, executables, or process handles.

## Composed Session and host shutdown

- `Close` durably requests cancellation, waits for explicit Operation terminal
  states, stops only that Session's Drivers child-before-parent, verifies that no
  unresolved persisted launch remains, and only then commits `Closed`.
- Cleanup failure, cleanup timeout, ownership loss during the wait, unavailable
  controller with possible launch evidence, and persisted non-`Stopped` launches
  all return `CleanupRequired` without a false close. The same Close identity can
  be retried after reconciliation.
- Drivers at the same hierarchy depth stop concurrently; separate Sessions are
  filtered exactly. Missing or corrupt topology prevents all shutdown effects.
- Host shutdown closes admission, Operation workers, tracked background tasks,
  transports, socket ownership, and Session ownership under one absolute
  deadline. Concurrent/repeated shutdown calls share an idempotent outcome;
  stuck tasks are aborted and joined rather than detached.
- The fake Driver's event journal separates delivery, acknowledgement, and
  scripted-event position, proving exact unacknowledged replay across reads and
  restart while barrier polling cannot consume an event.

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
`target/conformance/run.y4uDwH`; `target/conformance/latest` points to this run.
