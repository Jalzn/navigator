# Slice 04 adversarial review

Independent implementation and cross-review rounds covered the domain
envelope, Store state machine, authenticated Driver protocol, fake Driver,
delivery loop, local service, and Consumer Event stream.

## Findings resolved

- Closed a crash gap by making Operation creation and its first input Message
  atomic, including the request ledger and Event stream.
- Replaced arbitrary JSON Message payloads with closed typed bodies so secret
  exclusion is structural rather than a key-name heuristic.
- Separated a Message's immutable origin Driver epoch from the current Store
  lease owner epoch; recovery can fence work without rewriting history.
- Prevented concurrent delivery loops from overtaking live leased, pending, or
  unknown acceptance states. Recovery is permitted only at the durable expiry.
- Made control priority strict even when the oldest control Message is delayed;
  later ordinary work cannot bypass it.
- Bound Driver responses and acceptance proofs to the exact attempt as well as
  Message, Instance, launch attempt, and epoch.
- Removed the direct production `DriverExecutor` path that could deliver an
  Operation without Mailbox durability.
- Shortened blocking socket I/O below the outer delivery deadline so a timed-out
  call cannot retain a shared client lock and corrupt subsequent reconciliation.
- Added durable redacted Events to every Message transition transaction.
- Hardened SQLite restoration against malformed blobs and old-schema launch
  rows, and made clock behavior bounded and deterministic across reopen.

## Test-quality review

The final oracles inspect transactionally reopened SQLite state, exact ordered
Events, authenticated frames, fake Driver journal records, native-injection
counts, subprocess restart behavior, and Consumer reconnects. Crash matrices
exercise every Store commit and Driver-effect boundary. Mutants for changed
attempts, stale epochs, cross-loop races, control overtaking, missing Events,
and blind reinjection must fail for the intended semantic reason; accepting an
arbitrary error is not considered proof.

## Deferred by explicit slice ownership

The default `navigatord` binary still has no configured Driver catalog or
composed controller. This is intentional: generic trusted Driver catalog
configuration belongs to Slice 08, and managed local binary composition plus
recovery scheduling belongs to Slice 09. Slice 06 owns bounded shutdown of that
composed controller. Those tasks carry executable exit gates; Slice 04 claims
only the reusable reliable messaging path.
