# Adversarial review

Status: findings and proposed corrections, not yet normative. This review was
performed independently across simplicity/API, Store/concurrency, and Pi/
WebSocket/security, then deduplicated by the primary review.

## Conclusion

The architecture direction and planned capabilities remain sound, but building
all of them simultaneously would hide integration failures and several
guarantees are stronger than the selected mechanisms can currently provide.
First build a blocking Pi launcher spike, correct the critical contracts below,
then deliver one walking skeleton before adding the remaining planned subsystems
as tested slices. This staging does not remove those subsystems from the target
architecture.

## Critical findings

### Pi delivery acknowledgement is not implementable as written

The installed Pi 0.84.2 `ExtensionAPI.sendMessage()` returns `void`; its internal
asynchronous error is not returned to the extension. The current spec cannot
interpret the call returning as durable injection.

Minimum correction:

1. serialize deliveries per Agent;
2. call `sendMessage` with `details.messageId`;
3. poll `ctx.sessionManager.getEntries()` for the exact persisted custom message;
4. ACK only after it appears;
5. on timeout, classify the effect as uncertain and do not reinject blindly;
6. make this Pi behavior a compatibility smoke test.

Transport ACK and operation result are separate transactions. ACK means persisted
delivery acceptance only; a terminal report is committed later.

### Process identity and cleanup can recreate a permanently stuck Session

The specs require PID, creation time, and runtime token to authorize cleanup, but
persist only the token digest. After Host crash, the raw token is unavailable, so
a surviving Pi could be neither killed nor safely replaced.

Minimum correction:

- channel token authenticates WebSocket only;
- process cleanup uses registered PID, creation time, executable/cwd/parentage,
  plus a native handle when available;
- cleanup is best-effort and records `cleanup_required` when termination cannot
  be proven;
- Pi self-terminates after bounded loss of its owning Runtime channel;
- Windows requires a Job Object later if strong tree termination is a hard
  requirement; psutil alone cannot promise it.

### `launch_cwd` and environment secrecy are not sandbox guarantees

A Pi Agent with Bash can leave its cwd and inspect its process environment. The
Runtime cannot honestly claim filesystem confinement or secrecy from arbitrary
code running as the same OS user across macOS, Linux, and Windows.

Minimum correction:

- call cwd a launch workspace, not a security boundary;
- Factory enforces allowed changes by isolated worktree plus post-effect diff/
  gate validation in the first delivery;
- strong preventive confinement requires a future platform sandbox/tool proxy;
- extension captures bootstrap channel values and removes them from `process.env`
  before registering tools so later subprocesses do not inherit them;
- document that the token authenticates the local Agent process and is not a
  sandbox against that Agent.

## High findings

### Opinionated roles are intentional

The review originally identified fixed `campaign`/`worker` roles as a possible
Factory leak. This concern was reviewed and explicitly rejected: Coordinator,
Campaign, and Worker are intentional Runtime concepts shared by its consumers.

The implementation must still avoid knowing Factory, Laboratory, models,
targets, Git, or publication. Reuse comes from keeping Campaign and Worker
semantics broad and configuring their prompts, tools, limits, and workspaces
through trusted templates—not from erasing the roles.

Topology remains bounded by `allowed_children`, `max_children`, `max_depth`,
global `max_agents`, and `max_concurrent_operations`.

### The first delivery contains too many unproven subsystems

Ten tables, public Store, MemoryStore parity, approvals, artifacts/GC, context
checkpoints, Rich live view, generic idempotency, backup, and full cross-platform
process guarantees precede the first Pi child exchange.

Correction: the first walking skeleton exercises only Sessions, Agents,
Operations, Messages, and Events. Approvals, ArtifactStore, checkpoints, backup,
MemoryStore parity, and the public Store contract remain planned, but are
implemented afterward as isolated slices with their own acceptance tests.

### Worker execution mode is unproven

It is not established that interactive Pi remains resident without a TTY, while
Pi RPC mode has a different stdin/stdout contract.

Correction: before the package scaffold grows, spike Coordinator attached to a
terminal and one background Worker. Verify startup, idle lifetime, WebSocket,
message injection, tool call, settlement, shutdown, and supported platforms.

### Crash window exists between spawn and process registration

Host can die after child creation and before PID/handshake persistence.

Correction: persist a launch attempt and token digest before spawn; pass attempt
identity to Pi; attach PID/creation time by CAS immediately after spawn; forbid
work before authenticated `ready`; require child self-exit if ready/channel cannot
be established within an overall deadline; fault-inject every boundary.

### Pending idempotency can become another permanent active flag

An idempotency reservation has no owner lease or effect phase. Crash after reserve
can leave it pending forever.

Correction for the later generic idempotency subsystem: use owner epoch, lease,
and `reserved/effect_started/effect_uncertain/completed`. Only expired `reserved`
may be taken over. The walking skeleton should use entity-specific unique request
IDs for internal spawn/send/report effects instead of building this subsystem.

### Active-operation uniqueness is fragile

The partial index enumerates only some nonterminal states and omits recovering,
cancelling, report grace, and interruption semantics.

Correction: define terminal rows with `finished_at IS NOT NULL`; enforce one row
per Agent where `finished_at IS NULL`. Resume transitions that row and never
creates a second operation.

### Resume may repeat an uncertain external effect

`--resume` currently sounds broader than idempotency permits.

Correction: reconciliation classifies work as `safe_to_redeliver`,
`effect_uncertain`, or terminal. Resume continues only provably safe/idempotent
work. An uncertain filesystem/publication effect requires consumer/user decision,
cancel, or reset; `--resume` alone does not override it.

### Pi Session switching breaks Agent identity

`/new`, fork, clone, or switch can create a new Pi Session while reusing the
Runtime Agent, losing context and deduplication history.

Correction: bind the expected Pi Session identity in handshake. Version 1 permits
reload of the same Session only. New/fork/switch/resume inside Pi interrupts the
Agent and requires explicit Runtime-level handling.

### Approval flow has no trusted decision entrypoint

Runtime models request approval, but the minimal public API has no consumer/native
decision callback. Requests would remain pending.

Correction: defer generic approvals from the walking skeleton. Factory retains
its native confirmation mechanism. Promote approval into Runtime only with a
complete trusted UI boundary and a second proven consumer.

## Medium findings

- Session compatibility cannot be detected without the deliberately omitted
  fingerprint. Simplest v1 rule: Runtime does not claim compatibility detection;
  consumer is responsible for `--reset` after trusted configuration changes.
- Dedup IDs cannot be evicted while Store may redeliver them. Reconcile exact
  unacknowledged IDs or retain all Runtime message IDs within a Session quota.
- When `waiting_for_parent`, FIFO selection must explicitly lease only the
  correlated feedback even if an older ordinary instruction is pending.
- Session lease renewal must be a critical task. Losing the ownership epoch stops
  delivery and begins bounded Agent shutdown immediately, not on the next write.
- Wall-clock leases need an injected clock, a maximum future validity, and tests
  for equality and clock regression.
- Pi hooks do not provide Runtime `operation_id`. Lifecycle frames make it
  optional; Runtime correlates through the single active operation and rejects
  ambiguity.
- Bidirectional generic RPC is unnecessary initially. Extension calls Runtime
  tools; Runtime uses explicit delivery and a tiny closed control frame. Every
  mutable request has a stable idempotency/request ID.
- Rich cannot safely share stdout/stderr with the Pi TUI. First delivery writes
  structured operational logs to a file and sends important summaries through
  Pi. A live Rich view requires a separate terminal or non-TUI mode.
- `runtime_resume` duplicates Session recovery and `runtime_children` duplicates
  status. Walking skeleton tools should be `spawn`, `send`, `status`, `cancel`.
- “Autonomous spawn” is allowed only through trusted templates/policy; the
  non-goal should say “unconstrained/dynamic spawning”.

## Revised first delivery

```text
1. Pi compatibility spike
   ├── interactive Coordinator
   └── background Worker

2. Walking skeleton
   run_session
     → internal SQLite (5 tables)
     → local WebSocket
     → Coordinator Pi
     → Coordinator spawns one Campaign
     → Campaign spawns one Worker
     → send instruction
     → explicit results travel through each parent
     → orderly shutdown

3. Recovery proof
   → crash at launch/ACK/result boundaries
   → lease takeover with fencing
   → no duplicate Agent/operation
   → no permanent active flag
   → uncertain effect blocks automatic replay
```

Initial tools:

```text
runtime_spawn
runtime_send
runtime_status
runtime_cancel
```

Initial tables:

```text
sessions
agents
operations
messages
events
```

Add approvals, artifacts, checkpoints, generic idempotency, MemoryStore, live
Rich rendering, and stronger process isolation only as separately tested slices.

## Blocking acceptance tests

- `sendMessage` ACK is withheld until the exact Pi Session entry is observable;
- child exits when launch handshake or owning channel is lost beyond its bound;
- crash after every Store commit/external effect boundary does not create a
  duplicate mutable Agent or permanent active marker;
- old Session owner is fenced immediately after lease loss;
- active operation uniqueness uses unfinished-row semantics;
- effect-uncertain work is never replayed by plain `--resume`;
- Pi new/fork/switch cannot silently reuse a Runtime Agent;
- background Worker remains alive and processes one delivery without a TTY;
- scope enforcement is described honestly as validation unless a real sandbox is
  present.
