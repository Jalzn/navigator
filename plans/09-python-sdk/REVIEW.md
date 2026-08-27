# Slice 09 adversarial review

Specialists independently reviewed the public Python surface, generated code,
packaging, managed process lifecycle, reset/replay semantics, socket publication,
real Driver recovery, hierarchy shutdown, generated tests, and final execution
evidence. Earlier green-looking runs were rejected until their intermittent
failure was reproduced and causally explained.

## Findings resolved

- Completed missing public models, point snapshots, cancellation state, typed
  failures, unknown Event preservation, capability negotiation, and private
  generated transport boundaries.
- Made source generation and runtime packaging reproducible from lockfiles and
  pinned tools; the installed wheel now contains the trusted daemon, Node, Pi,
  provider, and catalog assets used by the acceptance tests.
- Reworked managed startup and shutdown around finite deadlines, process groups,
  private paths, bounded stderr, exact inode checks, early-exit handling, and
  cleanup failure propagation.
- Made public socket publication private and atomic: the daemon binds and chmods
  a compact private temporary socket before a no-clobber publication step.
- Corrected reset ordering so exact replay consults the ledger before any close
  or reconciliation side effect; a conflicting request identity still fails.
- Corrected watchdog completion handling so transient Store or join errors do
  not suppress the explicit shutdown path.
- Corrected the default hierarchy shutdown budget for sequential depth levels
  while retaining concurrent sibling cleanup and explicit absolute deadlines.
- Rejected multiple timeout-only explanations for the Pi tree flake. Reason-coded
  instrumentation captured premature ownership EOF, and source tracing showed
  that a retryable SQLite authority check was being treated as permanent loss.
- The first watchdog patch was rejected twice: first because retryable
  `load_launch` could silently terminate monitoring and deadline addition could
  panic, then because a non-conforming Driver could remain alive after its
  binding was discarded. The final implementation uses one bounded uncertainty
  machine, checked deadlines, verified escalation, and retains every unproven
  binding.

## Test-quality verdict

The final tests assert semantic state and effects, not merely successful return
shapes. They observe durable request identities, revisions, Events, process
identity, signal attempts, process groups, cleanup, socket inodes and modes,
installed package contents, replay stability, and absence of duplicate Driver
effects. Mutants independently vary caller/action/digest fields, retryable and
authoritative Store outcomes, deadlines, ownership behavior, process exit, and
cleanup proof.

The full gate and its clean-source repetition both passed the exact real Pi tree
test that previously failed. Temporary production markers used to identify the
ownership EOF were removed after the cause was proven; detailed failure-state
diagnostics remain in the semantic test.

## Verdict

GO. Slice 09 demonstrates the stable Python Consumer contract and managed local
deployment from an installed package, including real Pi-backed work, replay,
recovery, Event streaming, and bounded cleanup. The remaining work begins at
Slice 10; Slices 00–08 were not restarted.
