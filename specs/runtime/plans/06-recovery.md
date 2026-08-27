# Vertical 06 — Timeouts, reconciliation, and recovery

## Outcome

A previously observed stuck-active failure class is impossible: timeout or
worker loss always reaches a reconcilable state, and resume cannot duplicate
uncertain work.

## End-to-end proof

Kill a Worker during a CPU-style operation after preserving a candidate commit
identifier. Runtime detects the dead process, releases or interrupts the active
operation, preserves the candidate reference, and permits an explicit safe
resume or cancel without creating a duplicate Agent.

## Scope

- startup, operation, parent-response, cancellation, and shutdown deadlines;
- process identity with PID, creation time, executable, cwd, and parentage;
- graceful abort followed by bounded terminate/kill;
- Session lease renewal as a critical Runtime task;
- reconciliation classifications: terminal, safe to redeliver, effect uncertain,
  cleanup required;
- explicit resume/reset decisions and fencing takeover;
- launch intent persisted before spawn and process attachment by CAS;
- stale process and orphan detection;
- recovery events and Coordinator-visible diagnostics.

## Invariants

- timeout cannot leave an unfinished operation indefinitely owned;
- no raw channel token is required for post-crash process inspection;
- stale owners stop delivery immediately after lease loss;
- uncertain external effects are never replayed by plain resume;
- cancel remains possible when worker/channel is gone;
- cleanup uncertainty is reported honestly rather than marked successful;
- no replacement starts before previous ownership is resolved.

## Acceptance

- reproduce the recorded return-code-2 plus correction-agent-timeout incident;
- crash after every Store commit/process effect boundary;
- kill Host, Coordinator, Campaign, Worker, and WebSocket independently;
- race resume against an old surviving owner;
- PID reuse simulation refuses unsafe termination;
- cancel after worker loss reaches a terminal operation;
- repeated resume never duplicates Agent, operation, or mutable candidate;
- all failure states appear in status and logs with actionable cause.

## Adversarial review

- search for every status/flag without lease or terminal path;
- verify shielded cleanup is bounded;
- test cancellation while cancellation is already running;
- inject clock regression and delayed lease renewal;
- distinguish model failure, tool failure, process loss, protocol loss, timeout,
  and supervisor defect in public errors.

## Excluded from this slice

Automatic boot restart, distributed recovery, remote workers, and platform claims
beyond the currently approved macOS scope.
