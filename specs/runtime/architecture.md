# Architecture

## Purpose

The runtime owns the mechanics of creating, communicating with, observing,
cancelling, and recovering a hierarchy of Pi agents. Consumers provide prompts,
tools, policies, and domain decisions.

```text
User
  ↕
Coordinator Agent
  ↕
Campaign Agent
  ↕
Worker Agent
  ↕
Child Agent
```

The user talks only to the Coordinator. Feedback and results travel upward
through parents. Instructions and delegated work travel downward. Siblings do
not communicate directly; cross-tree communication is routed through their
nearest common ancestor.

## Package boundary

The runtime knows:

- agent identities and parent/child topology;
- sessions, campaigns, operations, and mailboxes;
- lifecycle, cancellation, timeouts, capacity, and recovery;
- launcher handles such as PID, creation time, and runtime-issued agent identity;
- live channel connections and protocol delivery state;
- generic capabilities, immutable policies, and non-escalation rules;
- persistence, revisions, messages, events, and artifact references.

The runtime does not know:

- Factory or Laboratory;
- model, operation, CPU, M4, backend, benchmark, or target semantics;
- Git branches, worktrees, commits, gates, or pull requests;
- when a candidate is correct or an experiment is successful;
- which roles a particular consumer needs;
- domain-specific workflow transitions.

## Core entities

### Runtime

Owns a `Store`, `AgentLauncher`, `AgentChannel`, internal local dispatch, limits,
and the active task group. It is an async context manager. No background task
may outlive its Runtime context.

For an interactive Session, Runtime is the foreground host tied to the
Coordinator lifecycle. It owns LocalDispatcher, mailbox delivery, wake-up, and
the live operational view. It does not start at boot or survive Session closure.

## Bootstrap ownership

The Runtime is the root process of an interactive Session. A consumer CLI,
normally exposed through a short `mise` task, constructs the consumer's
TemplateCatalog and Runtime configuration, then starts Runtime. Runtime opens
the Store and AgentChannel before launching the Coordinator Pi process.

```text
mise task / consumer CLI
  └── Runtime
        ├── SQLiteStore
        ├── WebSocketAgentChannel
        ├── Coordinator Pi (interactive child)
        └── Campaign/Worker Pi processes (background children)
```

There is no service discovery, daemon registration, or independently started
Coordinator. For every Pi child, the Host supplies the loopback endpoint,
protocol version, Agent ID, and per-Agent token through a trusted explicit
launch environment. The model cannot read, select, or override its runtime
identity through tool arguments.

Startup is ordered and transactional at the Runtime level:

1. open and validate the Store;
2. reconcile previous incomplete state without resuming it;
3. bind the loopback AgentChannel on an ephemeral port;
4. register the Coordinator as `starting`;
5. launch Coordinator Pi attached to the interactive terminal;
6. require an authenticated channel handshake within a bounded timeout;
7. mark the Coordinator `idle` and enter the interactive Session.

Failure at any step closes resources already acquired and persists the
Coordinator as interrupted or failed when it was registered. It never leaves a
second Host or Coordinator running in the background.

## Consumer command

Version 1 keeps the user entrypoint intentionally small:

```text
mise run <consumer>            # open an idle compatible Session or create one
mise run <consumer> --resume   # explicitly resume interrupted recoverable work
mise run <consumer> --reset    # start a clean Session
```

The concrete task name belongs to the consumer, for example Factory or
Laboratory; the Runtime does not contain those names. Normal start may reopen an
idle compatible Session but never resumes interrupted operations implicitly. If
recoverable work exists, it reports the condition and requires `--resume` or
`--reset`.

`--reset` is explicit authorization to close the previous Session and create a
new identity with empty operational state. It does not physically erase audit
history or consumer artifacts. Physical deletion remains a separate explicitly
authorized storage operation. A Session whose consumer templates, prompts,
tools, or policies changed is incompatible and requires reset.

`--resume` runs reconciliation first and fails closed on uncertain live process
ownership. It preserves Agent IDs, mailboxes, attempts, grants, and operation
correlation; it does not create a duplicate mutable candidate. The flags are
mutually exclusive. Version 1 adds no `start`, `status`, or administrative
subcommand hierarchy: the default command and Coordinator conversation expose
the useful status.

### Session

Represents the durable interactive context containing the Coordinator and its
Campaigns. A session belongs to a user-facing workspace but does not encode a
specific product role such as “Leader”.

### AgentNode

The single communicating node type. `role` distinguishes `coordinator`,
`campaign`, and `worker`; hierarchy distinguishes agents from subagents.

```python
AgentNode(
    id=...,
    session_id=...,
    parent_id=...,
    role="coordinator" | "campaign" | "worker",
    policy=...,
    status=...,
)
```

A Campaign is always represented by an agent node in version 1. There is no
`controller="external"` mode. “Subagent” is not a separate class.

### Operation

Represents one prompt/action being processed by an Agent. An Agent has at most
one active operation. Ordinary messages wait while it is busy; control actions
such as cancellation use a separate path.

### Message

A durable envelope routed between parent and child. See `messaging.md`.

### Artifact

A bounded external file referenced by ID, relative location, content hash,
media type, and size. Large logs, patches, and datasets are never message bodies.

### AgentTemplate and TemplateCatalog

Consumers provide an immutable catalog when opening a Session. A template defines
the trusted, non-model-controlled ceiling for a kind of Agent:

```python
AgentTemplate(
    id=...,
    role=...,
    system_prompt=...,
    tools=...,
    delegated_tools=...,
    policy=...,
    task_schema=...,
)
```

The runtime treats IDs and prompt contents as opaque. It validates allowed
parent/template relationships and parameter schemas. Dynamic task data is
separate from the immutable base prompt.

## Interfaces

```python
class Store(Protocol): ...
class AgentLauncher(Protocol): ...
class AgentChannel(Protocol): ...
```

Initial implementations:

- `SQLiteStore`
- `MemoryStore` for tests
- `PiProcessLauncher`
- `WebSocketAgentChannel`
- `RichRuntimeRenderer`

Local dispatch is based on AnyIO but remains a private implementation detail.
It becomes a public interface only if a second real dispatch mechanism appears.

## Agent lifecycle and communication

Process lifecycle and agent communication are different responsibilities and
must not share a combined adapter.

`AgentLauncher` exposes only `start`, `inspect`, `stop`, and capability
reporting. `PiProcessLauncher` starts Pi directly with an explicit extension,
tools, bounded environment, working directory, and per-Agent connection token.
It records enough identity to inspect and terminate only the process tree it
owns. Herdr is not involved.

`AgentChannel` owns authenticated, bidirectional communication after a process
connects. `WebSocketAgentChannel` listens only on loopback using an ephemeral
port. The Pi runtime extension connects to it and translates Runtime deliveries
into Pi extension messages. Tool invocations travel in the opposite direction
as correlated requests and responses.

The initial JSON protocol is intentionally small and versioned:

- `hello`: protocol negotiation and Agent authentication;
- `request` / `response`: runtime tool calls;
- `deliver` / `ack`: mailbox delivery and acceptance;
- closed RPC control methods: cancellation and orderly close;
- native WebSocket ping/pong: liveness and disconnect detection.

See `protocol.md` for the authoritative frame schemas. Application-level JSON
heartbeat frames are deliberately excluded because WebSocket already provides
the required control frames.

The Store remains authoritative. A connected socket is evidence of a live
channel, not proof that an operation completed. Delivery is at-least-once, and
the Pi extension persists accepted delivery IDs in its session so reconnects
can deduplicate an injection that succeeded before its acknowledgement reached
the Host.

## Agent orchestration tools

Coordinator and Campaign nodes are genuine coordinating agents. They receive
six generic runtime tools for managing direct children. This is autonomous delegation, but
not arbitrary spawning: caller identity comes from the trusted session and the
runtime enforces topology, policy, depth, capabilities, and capacity. See
`pi-tools.md`.

Possible future implementations, without commitments:

- a remote/durable dispatch mechanism, which would justify a new interface;
- another AgentLauncher or AgentChannel;
- another Store.

There is no dynamic plugin registry in version 1. Consumers construct and inject
implementations directly.

`TemplateCatalog` is not a plugin registry. It is a closed Session input whose
templates are explicitly constructed by the consumer.

Version 1 does not support resuming persisted Sessions across consumer template,
prompt, tool, or policy changes. Consumers must close/reset their
Sessions during such upgrades. There is no catalog versioning, hot reload,
migration, or persisted template snapshot initially.

## API direction

The public API is async-only and deliberately smaller than the internal agent
orchestration surface. See `public-api.md`. Synchronous CLIs use `anyio.run()` at
their outer boundary; the package does not maintain equivalent sync/async APIs.
