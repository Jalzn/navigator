# Lifecycle, concurrency, and recovery

## Async model

The core is async-first and uses structured concurrency. Runtime-owned tasks
live in an AnyIO task group and are cancelled or completed before the Runtime
context exits. Cleanup may use a bounded shielded cancel scope.

There is no daemon, private event loop, thread-based scheduler, or task that is
allowed to silently survive the owning context.

## Host and process ownership

The foreground Runtime Host is the Session's process root and the sole owner of
Agent launch decisions. The Coordinator is its interactive Pi child; Campaign
and Worker Agents are background Pi children. A child Agent may request another
Agent through runtime tools, but only the Host validates and performs the launch.

Normal shutdown begins when the Coordinator exits, the user ends the consumer
command, or the Host receives a supported termination signal. The Host then:

1. stops accepting new Agent creation;
2. records the Session as closing;
3. closes descendants child-before-parent with bounded grace periods;
4. closes AgentChannel connections;
5. flushes Store events and renderer output;
6. closes the Store and exits with a meaningful status.

An unexpected Coordinator exit does not silently resume or replace it. The Host
marks the active operation interrupted, performs bounded descendant cleanup, and
reports that explicit resume or reset is required.

## Agent states

Initial lifecycle:

```text
created → queued → starting → idle ↔ running
                              ↓       ↓
                         interrupted failed
                              ↓
                         recovering → idle

idle/running/queued → cancelling → cancelled
idle → closing → closed
failed/interrupted → dead_letter (when recovery policy is exhausted)
```

Transitions are explicit tables plus invariant checks, not a third-party state
machine framework. Terminal and recoverable states must be distinguishable.

## Operation states

```text
pending → delivered → running ── completed ──→ succeeded
                    │       └── failed ─────→ failed
                    │       └── question ───→ waiting_for_parent
                    │       └── blocked ────→ waiting_for_parent
                    │                           │
                    │                           └── reply → delivered → running
                    └────────────────────────────── interrupted
```

Only one operation can be active per Agent. A control cancellation is not an
ordinary mailbox message and may interrupt the active operation.

Pi becoming settled is not a terminal operation transition. Campaign and Worker
Agents must explicitly report `completed`, `failed`, `blocked`, or `question`
through an authorized runtime tool. `completed` and `failed` are terminal.
`blocked` and `question` satisfy the reporting requirement but move the same
operation to `waiting_for_parent`; they do not create or resume another
operation.

There is at most one unresolved wait per operation. A second `blocked` or
`question` report while waiting is rejected unless it is an idempotent replay.
The direct parent answers with a message correlated by `reply_to_message_id`.
Only that correlated reply or an authorized control action may advance the
waiting operation. A valid reply moves it to `delivered`, and Pi processing moves
it back to `running`. `runtime_resume` is reserved for interrupted Agents and is
not part of this flow.

A settled child with an active `running` operation and no report enters
`idle_without_result`. After a bounded grace period, the Runtime delivers one
request to report status. If the Agent settles again without reporting, the
operation fails with `missing_result`. The Coordinator is exempt because its
ordinary terminal output is the trusted interactive user conversation.

`waiting_for_parent` retains the Agent/process capacity slot but releases the
execution concurrency token. Delivery of the correlated reply must reacquire an
execution token. The wait has one consumer-configured bounded deadline, emits no
repeated reminders, and fails as `parent_response_timeout` when it expires.

## Capacity

The runtime supports multiple simultaneous Campaigns. Limits exist globally and
per subtree:

```python
RuntimeLimits(
    max_campaigns=3,
    max_agents=10,
    max_children_per_agent=3,
    max_depth=3,
    max_concurrent_operations=4,
)
```

Values above are provisional defaults, not final constants. AnyIO capacity
limiters enforce them. Waiting is FIFO/fair to the degree guaranteed by the
chosen primitives.

When capacity is unavailable, an Agent enters `queued`. Queue waiting always has
a timeout. Expiry records `capacity_timeout`; it does not wait forever.

This is capacity dispatch, not a general scheduler. There are no cron triggers,
calendar jobs, priorities, or arbitrary DAGs in version 1.

## Notifications and wake-up

Ordinary progress is batched. Important messages—initially `question`,
`blocked`, `failed`, and `completed`—wake an idle parent automatically. A parent
already processing an operation is never interrupted; delivery waits until it
becomes idle.

Status remains queryable on demand. Push delivery and pull inspection coexist.
The runtime decides delivery timing, not user-facing wording.

```python
NotificationPolicy(
    wake_on={"question", "blocked", "failed", "completed"},
    batch_kinds={"progress"},
    batch_window=2.0,
    max_batch=20,
)
```

## Restart behavior

State and messages survive a process or machine restart. Work does not restart
automatically. This is a safety property: an agent must not resume modifying
external state merely because a machine booted or a Coordinator reopened.

`reconcile()`:

1. loads and validates durable state;
2. inspects launcher handles, channel state, and local process identities;
3. distinguishes live, interrupted, stale, and uncertain resources;
4. releases expired message leases;
5. records recoverable work and cleanup requirements;
6. performs no mutation beyond safe reconciliation bookkeeping unless explicitly
   authorized by the caller.

Resume requires an explicit caller/user action. It preserves node identity,
mailboxes, policies, attempts, and durable operation correlation.

The default consumer command may reopen an idle compatible Session, but an
interrupted active operation is never considered idle. `--resume` authorizes
reconciliation followed by continuation of recoverable work. `--reset` closes
the old Session logically and starts a new Session identity; it is not physical
history deletion. The two flags cannot be combined.

## Process and channel identity

PID alone is never proof of identity because it can be reused. A process/agent
handle includes PID, creation time, and a runtime-issued random identity.
Inspection validates them before signaling a process. The WebSocket handshake
independently proves possession of the per-Agent connection token. Neither an
open socket nor an existing lock file proves that the stored process still owns
the Agent operation.

Uncertain cleanup fails closed: the runtime must not create a replacement writer
while it cannot rule out a live predecessor.

## Cancellation

Cancellation is graceful first and forced only when ownership is proven:

1. persist `cancelling` and stop ordinary delivery;
2. cancel descendants and wait child-before-parent;
3. send channel control and ask the AgentLauncher to stop gracefully;
4. wait for a bounded grace period;
5. terminate only runtime-owned surviving process trees;
6. kill only confirmed survivors after a second bounded wait;
7. persist `cancelled` or `cleanup_required`.

psutil applies only to registered, runtime-owned Pi processes. Identity uses PID
plus creation time and a runtime-issued token. The Runtime never signals an
unregistered process or broad machine/user process group.

## Timeouts

Every external wait has an explicit bound:

- queue wait;
- launcher startup;
- WebSocket handshake and delivery;
- operation completion;
- inspect;
- close;
- cancellation grace period;
- reconciliation.

Timeouts become typed failures with phase, elapsed time, and recoverability. They
must not leave the owning task group or store transaction permanently occupied.
