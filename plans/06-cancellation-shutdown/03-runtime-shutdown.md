---
status: verified
slice: 06-cancellation-shutdown
depends_on:
  - plans/06-cancellation-shutdown/02-process-stop.md
specs:
  - docs/execution.md
---

# Task: Implement bounded host shutdown

## Outcome

Stop admission, descendants, root, transports, Store tasks, and ownership in a
defined order.

## Verification

- Test normal close, signal, owner lease loss, and root Executor exit.
- Give the composed Operation controller a bounded shutdown hook. `serve` must
  await and aggregate Driver/Instance cleanup before releasing ownership, and
  surface `CleanupRequired` instead of relying on process exit or a detached
  watchdog.
- Enforce one end-to-end shutdown deadline across controller cleanup,
  ownership release, active Consumer streams, and transport drain; nested
  timeouts must consume the remaining budget rather than restart it.
- Run the real Consumer/Driver subprocess flow without manually shutting down
  the Executor, then prove bounded server exit and inode-safe socket/process
  cleanup.
- Task registry is empty after shutdown.
- Socket and process handles are closed.
- Second shutdown call is idempotent.

## Done

No managed task or Instance outlives its owning Navigator scope.
