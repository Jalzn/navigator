# Slice 06 adversarial review

Independent implementation and cross-review rounds covered the cancellation
Store contract, Driver protocol and fake, process supervisor, composed Session
Close, host shutdown, and their semantic tests.

## Findings resolved

- Corrected a fake Driver that returned `StopConfirmed` without exiting. The
  stronger behavior exposed and prevented Session `Closed` while an Operation
  remained `Cancelling`.
- Prevented transport failure, idle reports, reminders, or report deadlines from
  fabricating `Failed` while cancellation is pending. Only an authenticated
  terminal report completes active cancellation.
- Removed a fallback that converted executor cleanup failure into controller
  unavailability and could close after failed process cleanup. Cleanup failure
  and timeout now remain `CleanupRequired` end to end.
- Made Session-scoped executor shutdown mandatory instead of a default no-op.
  A controller-free close is allowed only when the Store proves the Session has
  never had a launch.
- Added a final durable launch check because an in-memory active map cannot
  represent orphaned launches from an earlier daemon. Every historical launch
  must be `Stopped`; `Prepared`, `Attached`, `Ready`, `Stopping`,
  `CleanupRequired`, unavailable, or corrupt evidence blocks Close.
- Reserved forced-stop budget so a hung Driver RPC cannot consume the entire
  global deadline, and retained failed entries for deterministic retry.
- Rejected credential-directory symlinks and unsafe parent permissions, and
  changed topology failure from an artificial maximum depth to fail-closed
  before signaling.
- Separated delivered, acknowledged, and scripted event cursors in the fake
  Driver. Reading no longer consumes an event, ACK persists across restart, and
  Ready barrier polls do not advance the scripted outcome.

## Test-quality review

The final tests observe durable SQLite state, ordered public Events,
authenticated Consumer and Driver frames, process-group exits, child handles,
filesystem ownership, socket inodes, task joins, and replay after restart. They
include deterministic barriers or pending futures for cancellation races,
cleanup timeout, ownership loss, and event replay; no sleep is used as proof of
those state transitions.

Named mutants prove that terminal Operations cannot hide cleanup failure or
timeout, ownership loss during terminal wait fails before cleanup, a missing
controller cannot close when launch evidence may exist, a sibling remains
outside the cancelled subtree, identity mismatch never receives a signal, and
an unacknowledged Driver event remains exact in-process and after restart.

## Bounded platform claim

The executable-path hash is an audit and fail-conservative check, not a claim
that path bytes cryptographically identify the already executed image. Unix
termination authority comes from the original, non-adoptable `Child` handle and
the process group created by Navigator. Without that strong live handle,
Navigator records cleanup required and never signals solely from PID or PGID.

## Deferred by explicit slice ownership

Crash-start reconciliation, unfinished-work scanning, effect-journal recovery,
and explicit resume resolution belong to Slice 07. Generic Driver catalog
composition and the first Pi implementation belong to Slice 08. Python SDK and
managed-local packaging belong to Slice 09.
