# Slice 02 adversarial review

The slice received separate implementation and adversarial passes over the
protocol, fake Driver, durable Instance store, and process supervisor.

## Findings resolved

- Replaced ambiguous enum-plus-optional-error replies with explicit protobuf
  success/failure unions.
- Bound authentication to the decoded semantic body and all mutable authority
  dimensions, then made replay capacity fail closed.
- Moved durable delivery intent before the external effect. This closes the
  crash window where an effect could occur while recovery claimed
  `NotAccepted`.
- Added a global request ledger so request identity cannot be reused across
  Sessions with another semantic digest.
- Removed blind respawn/adoption during reconciliation and made uncertain
  ownership converge conservatively to `CleanupRequired`.
- Retained the ownership channel, validated executable/process evidence before
  signaling, and verified absence of the whole process group rather than only
  its leader.
- Fixed the dual-supervisor launch race so one durable attempt produces at most
  one spawn.

## Test-quality review

The checks assert semantic outcomes at durability and process boundaries, not
implementation-shaped return values. Independent mutants were used where a
shared implementation could otherwise make production and tests agree on the
same defect. Crash matrices enumerate pre-commit, commit, and post-commit
windows and reopen state from durable storage.

## Deferred, non-blocking hardening

Native process handles such as pidfd/kqueue and cross-host adoption belong to
later recovery and remote-execution slices. The current local backend remains
safe by refusing adoption when it cannot prove ownership; it does not pretend
uncertain cleanup succeeded.
