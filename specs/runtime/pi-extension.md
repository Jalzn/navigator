# Pi runtime extension

## Purpose

The runtime extension is the thin trusted adapter between a Pi Session and the
Runtime Host. It registers generic runtime tools, maintains one authenticated
WebSocket connection, injects parent/child messages, reports Pi lifecycle
observations, and reconstructs delivery deduplication from Pi Session entries.

It does not implement scheduling, hierarchy, policy decisions, mailbox leases,
retries, domain workflow, Factory/Laboratory behavior, or durable Runtime state.
It is the only Runtime-managed Pi extension in version 1; templates cannot add
arbitrary executable extension modules.

## Initialization

At extension load, it validates the trusted launch environment and registers
only the runtime tools enabled for the Agent template. Registered tools remain
present if the channel is temporarily unavailable, but return a typed
`runtime_unavailable` result rather than hanging or performing local fallback.

On Pi `session_start`, the extension:

1. verifies that the Pi Session is compatible with the launched Agent identity;
2. scans `ctx.sessionManager.getEntries()` for injected runtime custom messages;
3. reconstructs an in-memory bounded set of accepted message IDs;
4. connects to the supplied loopback endpoint;
5. performs `hello` / `ready` within the bounded startup timeout;
6. begins receive, RPC correlation, and lifecycle event tasks.

Async network resources start in `session_start`, not at module load. A reload,
new Session, resume, or fork tears down the old extension instance before a new
one establishes its channel.

On `session_shutdown`, the extension stops reconnect attempts, rejects pending
tool RPCs with a typed shutdown error, emits `agent.exiting` when possible, and
closes the socket. Cleanup is idempotent and bounded.

## Runtime tools

The extension registers the six generic tools described in `pi-tools.md` and the
conditional approval tool when allowed. Each tool:

1. receives model-controlled arguments;
2. validates them locally for shape and bounds;
3. sends a correlated `rpc.request`;
4. waits with timeout and cancellation support;
5. returns the bounded structured `rpc.response` to Pi.

Caller identity, parent identity, policy, cwd boundary, and Session identity are
never accepted as model arguments. The Host derives them from the authenticated
connection and Store.

## Message injection

Agent-to-Agent delivery uses a Pi custom message, not a user message:

```typescript
pi.sendMessage(
  {
    customType: "arara-runtime-message",
    content,
    display: true,
    details: { messageId },
  },
  {
    deliverAs: "followUp",
    triggerTurn: true,
  },
);
```

`sendUserMessage()` is not used because a parent or child message must not
impersonate the human user. `followUp` preserves the rule that ordinary mailbox
messages do not interrupt an Agent already processing an operation. When idle,
`triggerTurn` starts processing immediately.

Before injection, the extension checks IDs reconstructed from persisted
`arara-runtime-message` entries. For an unseen ID, `sendMessage` persists the
custom message with `details.messageId`; that same entry is both model-visible
delivery and deduplication record. The extension updates its in-memory set only
after `sendMessage` succeeds, then acknowledges acceptance. On reload/reconnect,
the messages reconstruct the set. Duplicate delivery is acknowledged without a
second injection.

There is deliberately no separate `appendEntry` marker. A marker written before
injection could cause message loss if Pi exits between the two calls; one written
after injection would not close the duplicate window. Using the persisted custom
message avoids this two-write consistency problem. The first implementation must
verify Pi persists the custom entry before `sendMessage` returns; if that contract
is absent, delivery remains uncertain and startup must fail rather than claim
at-least-once behavior.

## Pi lifecycle mapping

The extension observes only stable hooks:

```text
Pi session_start     → connect and ready
Pi agent_start       → agent.started
Pi agent_settled     → agent.settled
Pi session_shutdown  → agent.exiting and disconnect
```

`agent_end` is deliberately not mapped to completion. Pi may auto-retry,
auto-compact and retry, or process queued follow-up messages after that hook.
`agent_settled` is the correct observation that Pi currently has no automatic
continuation, but it still does not prove task success.

## Explicit report contract

Campaign and Worker Agents must report operation status through an authorized
runtime tool:

```text
completed
failed
blocked
question
```

`completed` and `failed` are terminal reports. `blocked` and `question` persist a
single correlated wait and continue the same operation after the direct parent's
`feedback` reply. Natural-language Pi output and lifecycle hooks cannot silently
declare success. The Coordinator is different: its normal output is the direct
interactive conversation with the user and does not require a report for each
turn.

When a non-Coordinator emits `agent.settled` with an active operation but no
explicit report, the Runtime records `idle_without_result`. It waits a bounded
grace period and delivers one follow-up requesting a structured report. If Pi
settles again without reporting, the Runtime fails the operation with
`missing_result` and notifies the parent. There is no unbounded reminder loop.

The grace duration and reminder text are configurable by the consumer within
Runtime bounds; provisional defaults are selected during integration tests.

## Reconnect

Reconnect uses bounded exponential delay with jitter while the Pi process and
Session remain alive. There is at most one connection attempt loop and one live
socket. A reconnect reauthenticates with the same per-Agent lifetime token,
reconstructs pending RPC state conservatively, and lets the Host redeliver
unacknowledged mailbox messages.

The extension never starts another Runtime Host, Pi process, Agent, or operation
as a fallback. Reconnect exhaustion produces a visible interruption and leaves
resume authority with the Host/user.
