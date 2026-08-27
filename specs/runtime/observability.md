# Runtime Host and observability

“Runtime Host” names the foreground role played by `Runtime`; it is not a
separate `RuntimeHost` class or service.

## Foreground Host

Every interactive Session runs one foreground Runtime Host:

```text
consumer command
  └── Runtime Host
        ├── Store
        ├── LocalDispatcher
        ├── PiProcessLauncher
        ├── WebSocketAgentChannel
        ├── Coordinator Agent
        ├── Campaign/Worker Agents
        └── Runtime event view
```

The Host is not a daemon. It does not start at boot, survive the owning command,
or automatically resume work after restart. Structured AnyIO tasks complete or
cancel before shutdown. Incomplete work becomes explicitly recoverable.

The primary entrypoint is a consumer-owned CLI wrapped by a short `mise` task.
The Runtime package supplies reusable Host APIs and may supply thin generic CLI
helpers, but it does not discover Factory, Laboratory, or their templates. The
consumer injects those values explicitly before the Host starts.

The entrypoint has only the default behavior, `--resume`, and `--reset` in
version 1. Startup prints a concise reconciliation summary before Pi takes over
the interactive terminal. Detailed state remains available through the
Coordinator rather than a separate status command.

## Terminal layout

```text
user terminal
  ├── Coordinator conversation
  └── bounded Runtime event feed

background Runtime-owned processes
  ├── Campaign A
  ├── Worker A1
  └── Worker A2
```

The Coordinator Pi child owns the terminal's interactive input. The Host keeps
control of process lifetime and routes its bounded Runtime feed through a
presentation path that cannot write into Pi's input. The consumer may render the
feed beside or below the conversation, or redirect it to a separate standard
stream. Background Agents use bounded captured streams and do not require
interactive terminals.

## Runtime events

```python
RuntimeEvent(
    type="agent_started",
    session_id=...,
    agent_id=...,
    parent_id=...,
    operation_id=...,
    level="info",
    facts={...},
    created_at=...,
)
```

Store events are the durable audit trail. Terminal lines and standard logging
are projections, never sources of truth.

## Rich renderer

`RichRuntimeRenderer` renders bounded readable lines or a small live view.
Version 1 does not use Textual or implement a dashboard.

```text
15:42:10  campaign  fashion-mnist  started
15:42:13  agent     cpu-builder    running
15:44:02  message   cpu-builder    result → campaign
15:44:04  campaign  fashion-mnist  blocked
```

The renderer is replaceable and optional in tests. It may integrate with
standard logging; structlog is not required initially.

## User notifications

Important events still travel through hierarchical mailboxes and wake an idle
Coordinator. The Runtime event feed provides detail but never replaces concise
user feedback from the Coordinator.

## Redaction and bounds

Default display excludes full prompts/responses, environment mappings,
credentials, unrestricted approval resources, artifact bodies, and unrestricted
stdout/stderr. Outputs are truncated and marked. Agent markup is escaped. Short
display IDs map to full Store IDs. `verbose` adds bounded protocol diagnostics but
never disables redaction.

## Log levels

- `debug`: bounded launcher/channel/protocol detail, normally hidden;
- `info`: lifecycle and meaningful progress;
- `warning`: retry, degraded capability, quota, or recoverable interruption;
- `error`: blocked/failed work or uncertain cleanup.

Filtering changes presentation only, not required event persistence.
