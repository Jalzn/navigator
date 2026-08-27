# Slice 08 adversarial review

Specialists independently reviewed Pi acceptance, fault injection, real-tree
semantics, shutdown, and repository evidence. Initial green gates were not
accepted as certification until the tests themselves survived mutation review.

## Findings resolved

- Replaced response-shape acceptance with an append-and-fsync journal contract
  bound to exact Message, attempt, Operation, prompt, and Instance identities.
- Added authenticated typed failures after authentication while preserving
  silent fail-closed behavior before authentication; invalid traffic cannot
  poison the Stop or request ledgers.
- Retained the ownership worker across garbage collection and made terminal
  shutdown close admission, drain bounded work, and stop child-first.
- Replaced a fault oracle that could infer a crash from transport failure with
  positive per-generation `REACHED -> kill -> SIGKILL reap` evidence. Real
  mismatch and EOF mutants must fail and block restart.
- Moved durable expected-state commit until the child and watcher are installed,
  fenced watcher generations, and required the same persistent binding across
  recovery.
- Strengthened ownership loss so connection failure cannot bypass the durable
  absence oracle. A mutant native delivery after EOF is rejected.
- Replaced nonempty/unique hierarchy journal checks with exact canonical
  protobuf semantics and made malformed lines fail closed.
- Corrected shutdown evidence to the actual domain depths and required exact
  parent correlation plus the public semantic outcome digest.
- Updated the concurrent gate oracle for all current gates and made it validate
  both isolated run directories, not merely the winning `latest` link.

## Test-quality verdict

The final suite observes native provider calls, append-only journal records,
fsync boundaries, authenticated wire identities, exit signals, process groups,
mailbox records, public outcomes, and child-first shutdown. Independent mutants
cover wrong semantic fields, post-EOF admission, malformed journals, fault-frame
mismatch, watcher EOF, duplicate native delivery, and stale process identity.

The prior review claim that protocol errors could still become `Unavailable`
without a completed fault was withdrawn after rereading the corrected state.
The current mapping requires the same generation to reach the exact fault frame,
be killed, and be reaped by the expected signal.

## Verdict

GO. The Pi Driver demonstrates the generic Driver contract without introducing
Pi concepts into Navigator domain, Store, or Consumer protocol boundaries.
