# Delivery and migration plan

This plan records the current implementation direction. Detailed API names and
limits remain subject to adversarial review before code is written.

## Phase 0: repository and contracts

1. Correct the root distribution naming conflict.
2. Add `runtime/` as a uv workspace member.
3. Create the `arara-runtime` distribution and `arara_runtime` package.
4. Add dependency decision records and supported-platform matrix.
5. Define Pydantic models, typed errors, Store/AgentLauncher/AgentChannel
   protocols, and contract tests before production implementations.
6. Implement the closed ErrorCode registry, ErrorInfo projection, RuntimeFailure,
   redaction, and boundary translation tests.

## Phase 1: durable core

1. Implement `MemoryStore` with full invariants.
2. Implement the ten-table `SQLiteStore`, forward migrations, revisions,
   Session ownership leases, transactions, and backups.
3. Implement artifact references and bounded atomic ArtifactStore.
4. Implement hierarchical Agent insertion and policy non-escalation.
5. Implement immutable in-process TemplateCatalog validation.
6. Implement mailbox sequence, lease, ack, retry, dead-letter, and idempotency
   result storage.
7. Implement context checkpoints, quotas, retention, and explicit deletion seams.
8. Implement the unified approval lifecycle and atomic grant consumption.
9. Run identical Store contract tests against MemoryStore and SQLiteStore.

## Phase 2: local async runtime

1. Implement `Runtime` async context with private local dispatch.
2. Implement foreground `Runtime` as the Session process root; do not create a
   second `RuntimeHost` class.
3. Implement ordered Store/channel/Coordinator bootstrap with rollback.
4. Implement Coordinator-attached and background-worker process modes.
5. Implement signal, Coordinator-exit, and normal child-before-parent shutdown.
6. Implement global/per-Campaign capacity limits and FIFO queue timeout.
7. Implement one active operation per Agent.
8. Implement parent/child send, upward feedback, and parent broadcast.
9. Implement important-event wake-up and bounded progress batching.
10. Implement mechanical context windows and parent-produced checkpoints.
11. Implement cascade cancellation and child-before-parent close.
12. Implement explicit reconciliation without automatic restart.
13. Implement the bounded Rich Runtime event view.

## Phase 3: direct Pi integration

1. Implement `PiProcessLauncher` with direct async subprocess startup.
2. Implement the loopback `WebSocketAgentChannel` and versioned JSON protocol.
3. Implement the Pi runtime extension that connects, invokes runtime tools, and
   injects accepted deliveries into Pi.
4. Add per-Agent connection tokens, handshake, native ping/pong keepalive,
   reconnect, bounded frames, request correlation, acknowledgement, and
   extension-side deduplication.
5. Implement inspect, graceful stop, identity validation, explicit timeout, and
   typed errors.
6. Implement owned process-tree termination with psutil behind capabilities.
7. Add real Pi/WebSocket smoke tests separately from hermetic contract tests.
8. Verify `agent_end` followed by retry/compaction is never mistaken for terminal
   operation success.

## Phase 4: Coordinator and Campaign tree

1. Add a thin consumer CLI/mise integration that injects templates and starts
   `Runtime` through the `run_session()` convenience function.
2. Implement default open/create plus mutually exclusive `--resume` and
   logical `--reset` flags without an administrative subcommand hierarchy.
3. Open a fresh Coordinator Agent Session; resume remains explicit.
4. Create Campaign Agents as Coordinator children.
5. Expose role-scoped Pi tools for parent-authorized autonomous delegation.
6. Deliver progress/results upward and instructions downward.
7. Ensure only the Coordinator communicates with the user.
8. Implement one bounded report reminder and `missing_result` failure for a
   settled non-Coordinator Agent without an explicit report.
9. Implement correlated `question`/`blocked` waits and parent `feedback` replies
   that continue the same operation without `runtime_resume`.
10. Release/reacquire execution capacity while retaining the waiting Agent slot,
    and enforce `parent_response_timeout` without repeated reminders.
11. Verify multiple concurrent Campaigns and enforced depth/capacity limits.

## Phase 5: Factory migration

1. Replace Factory's private Pi/Herdr orchestration seam with `arara_runtime`.
2. Preserve Factory prompts, tools, scopes, gates, worktree, state, and publish
   semantics outside the runtime.
3. Map the resident Leader to Coordinator, one execution to Campaign, and
   Scout/Builder/Reviewer to child Agents.
4. Route gate failure feedback through the Campaign hierarchy.
5. Replace stale worker/agent handling with runtime reconciliation.
6. Reproduce and pass the recorded timeout/recovery incident without changing
   the preserved candidate SHA or duplicating a mutable Agent.

## Phase 6: Laboratory migration

1. Compare behavior against existing Laboratory Pi/Herdr tests.
2. Migrate generic launcher/channel/lifecycle behavior only.
3. Preserve experiment and benchmark semantics in Laboratory.
4. Remove duplicate seams only after parity and real smoke validation.

## Phase 7: adversarial validation

- crash between Pi message injection and Store acknowledgement;
- process/PID reuse and stale launcher handles;
- WebSocket disconnect during request, delivery, and acknowledgement;
- forged Agent identity, invalid token, replay, oversized frame, and incompatible
  protocol version;
- two runtimes racing for one mailbox;
- expired leases and duplicate delivery;
- idempotency key reuse with different input;
- parent/child authority escalation;
- unregistered template and unsafe template parameters;
- sibling/cross-Campaign routing attempts;
- cancellation during startup, prompt, result persistence, and close;
- queue starvation and capacity timeout;
- malformed/newer database schema;
- artifact path traversal, symlink, oversize, and hash mismatch;
- macOS, Linux, and Windows Store/core tests;
- unsupported launcher/channel capabilities failing before side effects.

## Explicit non-goals for version 1

- automatic restart after boot/process crash;
- distributed execution;
- calendar scheduler or cron;
- external broker;
- network-exposed WebSocket listener;
- Herdr integration or per-Agent terminal tabs;
- arbitrary DAG/workflow DSL;
- autonomous model-controlled agent spawning;
- direct sibling messaging;
- exactly-once delivery claims;
- database server or ORM;
- generic secret manager;
- Factory/Laboratory domain logic in the runtime.

## Remaining design questions

- Exact public method names and model fields.
- Default byte, retention, lease, retry, timeout, and concurrency limits.
- Exact Pi extension lifecycle and session-entry API used for delivery deduplication.
- Message summarization/context-window policy at each parent.
- Artifact retention and garbage collection authorization.
- Launcher cancellation escalation on each supported platform.
- SQLite WAL/busy-timeout defaults after multi-process tests.
- Package versioning and compatibility policy.
- A later compatibility strategy for Sessions across consumer template changes;
  version 1 requires reset instead.
