# Pi SDK integration proposal

Status: proposed architecture pending a blocking spike. This document records
the evaluation of Pi's `agent`, `ai`, and `coding-agent` packages; it does not yet
replace the extension-based contracts in the normative specifications.

## Decision under evaluation

Integrate the Runtime through `@earendil-works/pi-coding-agent`, not directly
through `@earendil-works/pi-agent-core` or `@earendil-works/pi-ai`.

The lower packages solve useful but narrower problems:

- `pi-ai` owns provider/model discovery, authentication, streaming, tool schemas,
  token usage, and provider-specific message conversion;
- `pi-agent-core` owns the stateful model/tool loop, steering/follow-up queues,
  tool-call hooks, cancellation, settlement, and event streaming;
- `pi-coding-agent` composes both and adds the coding tools, session management,
  compaction, configuration, resource loading, and terminal/SDK integration that
  Arara would otherwise have to recreate.

Using either lower package directly would duplicate Pi behavior without reducing
the responsibilities that are specific to Arara.

## Proposed boundary

```text
Python arara_runtime
  graph, policy, mailbox, leases, recovery, durable operational state
                    │
           local authenticated WebSocket
                    │
Node PiAgentHost (small adapter owned by arara-runtime)
  @earendil-works/pi-coding-agent
    @earendil-works/pi-agent-core
      @earendil-works/pi-ai
```

Python remains the source of truth for the opinionated Coordinator → Campaign →
Worker graph and delivery state.
Pi remains the source of truth for each Agent's transcript, model interaction,
tool loop, and context compaction. Neither side mirrors the other's state.

The WebSocket remains useful as the language and process boundary. It is not an
application server, broker, or generic event bus.

## Process model

Start with one Node process and one Pi `AgentSession` per Runtime agent role:

- the Coordinator uses the SDK's interactive terminal mode;
- Campaigns and Workers use a headless `AgentSession` with no TTY;
- both modes use the same adapter and Runtime protocol;
- Runtime tools are explicit SDK custom tools that call Python over WebSocket;
- the coding-tool allowlist is explicit per trusted Agent template.

Do not host every Agent in one Node process initially. That would couple their
failure domains and complicate cwd, resource, cancellation, and log isolation for
little immediate benefit.

## Simplifications if the spike succeeds

- replace `PiProcessLauncher + custom Pi extension` with a `PiSdkHostLauncher`;
- use awaitable SDK session methods for prompt, steering, follow-up, and custom
  message delivery rather than treating the extension's void `sendMessage()` as
  an acknowledgement;
- observe SDK session-entry events before committing delivery acknowledgement;
- use SDK settlement, abort, and disposal signals for lifecycle integration;
- stop designing transcript checkpoints or model authentication in Python;
- use Pi's coding tools instead of rebuilding Bash/read/edit/write/grep/find;
- depend only on the coding-agent package at the adapter boundary and allow its
  compatible agent-core/ai dependencies to remain implementation details.

This does not remove Runtime mailboxes, fencing, crash recovery, or operation
state. Pi's session persistence is per Agent and does not replace those
multi-Agent guarantees.

## Security and configuration constraints

- Disable unrestricted automatic discovery of user/project extensions, prompts,
  and skills for managed Agents. Load only resources allowed by a trusted
  template.
- Keep model credentials inside Pi's model/auth runtime. Never send credentials
  through the WebSocket or persist them in Runtime state.
- An explicit tool allowlist and pre-tool hook improve policy and auditing, but
  Bash with a cwd is still not a filesystem sandbox.
- Pin an exact initially validated coding-agent version. Do not independently pin
  mismatched `agent-core` and `ai` versions.
- Keep Pi session switching/forking disabled until Runtime Agent identity has an
  explicit mapping for it.

## Blocking spike

Before changing normative architecture or scaffolding the full package, prove one
small vertical path:

1. create a headless coding `AgentSession` with explicit cwd and tool allowlist;
2. expose one custom Runtime tool over the local WebSocket;
3. deliver a message through an awaitable SDK call and correlate the exact
   appended session entry before acknowledging it;
4. observe idle/settled state, then verify abort and disposal;
5. run the same adapter as an interactive Coordinator;
6. prove a headless child remains alive without a TTY;
7. prove model/auth resolution works without credentials crossing into Python;
8. prove managed Agents do not auto-load untrusted project/user resources;
9. exercise a fake model/provider for deterministic adapter tests;
10. repeat lifecycle checks on macOS, Linux, and Windows before claiming full
    process portability.

If this spike fails, retain the current extension boundary and correct its ACK
contract. Do not fall back to directly rebuilding coding-agent on `agent-core` or
`pi-ai` without a separately demonstrated need.

## Deferred choices

- Whether Coordinator Pi sessions are persisted by Pi or kept in memory. Worker
  sessions should begin in memory unless restart continuity becomes a proven
  requirement.
- Whether multiple Agents share a Node host after isolation and performance data
  justify that optimization.
- Whether a future consumer needs `pi-agent-core` directly for a non-coding Agent.
- Whether `pi-ai`'s fake provider becomes the permanent hermetic test adapter.

## Spike result — 2026-08-23

An isolated executable spike lives in
`runtime/spikes/pi-coding-agent-host`. It targets Pi `0.84.2` on Node `22.23.2`
and validates without a real model credential:

- a headless `AgentSession` starts without a TTY;
- a strict allowlist exposes only one custom Runtime tool;
- extensions, skills, prompts, themes, and context-file discovery can be disabled;
- the Pi faux provider performs a complete prompt → tool call → tool result →
  final answer cycle;
- the custom tool crosses a real loopback WebSocket request/response boundary;
- `agent_settled` is observable after completion;
- `abort()` settles an actively streaming headless session;
- `sendCustomMessage()` can persist a delivery carrying an exact Runtime
  `messageId`, and `SessionManager.getEntries()` can prove that exact entry before
  Runtime acknowledges it.

Two API nuances are now part of the design:

1. Pi `0.84.2` did not emit `entry_appended` for the tested
   `sendCustomMessage()` path. Durable ACK must inspect
   `SessionManager.getEntries()` rather than depend on that event.
2. Supplying `deliverAs: "nextTurn"` while the session is idle queues the custom
   message instead of immediately persisting it. Idle delivery must omit
   `deliverAs`; streaming delivery must distinguish queued acceptance from
   durable transcript insertion and must not ACK prematurely.

The first automated pass did not yet prove the interactive Coordinator TUI,
steering/follow-up, or process self-exit after WebSocket ownership loss. The
macOS follow-up below closes those cases except for queue injection during a
real long-running tool. Linux and Windows are deferred by project decision.

### macOS follow-up validation

The same spike was subsequently exercised on Apple Silicon macOS with:

- queued `steer()` and `followUp()` messages during an actively streaming turn,
  both consumed into the same Agent session;
- a separately spawned Node child hosting the headless Pi session;
- deliberate termination of the owning Runtime WebSocket, followed by clean
  child exit within the bounded test deadline;
- `InteractiveMode` mounted inside the macOS `/usr/bin/script` pseudo-terminal,
  showing the isolated faux Coordinator and restoring the terminal after normal
  double-`Ctrl-C` shutdown.

An additional test queues steering and follow-up while the Runtime WebSocket
tool is still awaiting its delayed result; both messages are consumed after the
tool completes. Linux and Windows are explicitly deferred by current project
decision.
