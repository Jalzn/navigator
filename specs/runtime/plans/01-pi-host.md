# Vertical 01 — Production Pi host boundary

## Outcome

The validated SDK spike becomes a supported Node adapter launched through
`AgentLauncher` and connected through `AgentChannel`, without leaking Pi types
into Python.

## End-to-end proof

Python launches one interactive Coordinator and one headless Worker on macOS.
The Worker calls one Runtime tool over the authenticated loopback WebSocket,
receives its result, reports settlement, and closes cleanly. The Coordinator TUI
opens and restores the terminal.

## Scope

- promote the spike into a versioned Node package inside `runtime/`;
- exact compatible Pi SDK dependency and Node engine check;
- `PiProcessLauncher` process handles with PID and creation time;
- loopback `WebSocketAgentChannel` with hello/ready authentication;
- explicit resource and tool allowlists;
- prompt, steer, follow-up, abort, close, and event translation;
- delivery proof through the exact `SessionManager` entry;
- structured adapter logs to file;
- bounded startup, request, shutdown, and ownership-loss deadlines.

## Invariants

- one process and Pi Session per Runtime Agent initially;
- credentials remain inside Pi and never cross WebSocket or Store;
- no auto-discovered extension, skill, prompt, theme, or context file;
- WebSocket binds only to loopback and authenticates one Agent identity;
- queued acceptance is not durable delivery acknowledgement;
- loss of the owning channel causes bounded child self-exit;
- cwd is a workspace, not a claimed security sandbox.

## Acceptance

- retain all existing six spike tests;
- verify hello/ready refuses invalid token, Agent ID, and protocol version;
- verify oversized/malformed frames close safely;
- kill before handshake, during tool call, during ACK, and during shutdown;
- prove interactive and headless modes use the same adapter contract;
- prove `deliverAs` selection for idle, streaming, steering, and follow-up;
- dependency audit has no high/critical finding;
- manual macOS TUI smoke is documented as one command.

## Adversarial review

- inspect environment inheritance and log redaction;
- test PID reuse defense and a forged reconnect;
- make WebSocket disappear with a pending RPC;
- confirm a Pi upgrade fails compatibility checks before doing work;
- assess whether SDK behavior still justifies replacing the extension path;
- do not delete the extension specification until the adapter is accepted.

## Excluded from this slice

Durable Runtime state, multi-Agent graph, retry/resume, approvals, artifacts, and
consumer-specific tools.

