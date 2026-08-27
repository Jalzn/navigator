# Slice 03 adversarial review

Separate implementation and review rounds covered the domain model, Consumer
and Driver protocols, Store, core operation worker, Unix transport, supervisor,
local service, and process-level vertical test.

## Findings resolved

- Replaced absence collapsed into generic invalid state with typed,
  identity-bearing Store errors.
- Rejected duplicate JSON keys, duplicate capabilities/parameters/secrets,
  malformed restored Templates, forged Participant bindings, regressed
  timestamps, incoherent terminal outcomes, and corrupted input digests.
- Made Start replay load current state so a terminal Operation cannot be
  redelivered from a stale queued snapshot.
- Revalidated ownership immediately before input read and external delivery;
  a deterministic mutant proves zero effect after fencing loss.
- Added an absolute report budget and bounded report/progress sizes so repeated
  disconnects or progress cannot extend execution indefinitely.
- Added explicit reminder protocol semantics; idle can never imply success.
- Authenticated Driver responses after a review demonstrated that request-only
  authentication allowed a same-UID socket imposter to forge success.
- Bound Navigator-selected Instance identity and Driver capabilities through
  authenticated bootstrap and durable Ready.
- Partitioned cache, attempt, socket, and fake journal identity by fencing epoch.
- Closed launch-error leaks with bounded compensation and visible
  `CleanupRequired`; ownership EOF is attempted before signals.
- Corrected UDS path bounds, inode-safe cleanup, credential/socket permission
  checks, partial-frame starvation, and exact frame-limit handling.
- Corrected the local shutdown budget to close admission immediately and share
  one deadline across transport drain and lease release.

## Test-quality review

The final oracles observe durable Store state, exact public Events, process
effects, journal bytes, socket identity, and subprocess exit. Tests do not accept
an arbitrary error as proof: terminal identities and failure codes are exact,
the fresh epoch must authenticate as N+1, and the Consumer reconnect uses a new
LocalClient and negotiation. The fake binary is required through
`CARGO_BIN_EXE_navigator-driver-fake`; there is no early return or prebuilt-binary
fallback.

## Deferred by explicit slice ownership

Composed shutdown of every operation controller and Instance is an exit gate of
Slice 06, and Navigator crash reconciliation/adoption is an exit gate of Slice
07. Their tasks record those dependencies. Slice 03 does not claim either
later guarantee.
