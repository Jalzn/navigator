# Security and authority

## Generic policy

The runtime does not interpret Factory or Laboratory permissions. It handles
opaque capabilities and tools while enforcing universal non-escalation rules.

```python
AgentPolicy(
    capabilities=frozenset(...),
    environment=...,
    launch_cwd=...,
    limits=...,
)
```

For every child:

```text
child.capabilities ⊆ parent.capabilities
child template tools ⊆ tools delegated by the parent template
child environment keys ⊆ delegated keys
child launch workspace is inside the delegated workspace
child resource limits ≤ parent resource limits
child depth/count fit Runtime limits
```

`AgentSpec` and policy are immutable after startup. Increasing authority requires
closing the Agent and creating a new one through an explicitly authorized parent
operation.

Coordinator and Campaign Agents may request child creation through runtime tools.
The model cannot choose its trusted caller identity or parent relationship.
Every child spec remains a subset of the immutable parent policy, so delegation
is autonomous but bounded.

Every Agent originates from a trusted AgentTemplate in the Session's immutable
catalog. Models may select an allowed template and provide schema-validated task
parameters, but cannot construct executables, base prompts, tools, or policy
ceilings. Version 1 does not load arbitrary consumer Pi extensions; the Runtime
extension is fixed infrastructure.

## Communication authority

- Nodes may communicate only with direct parent or children.
- Sender identity comes from runtime state, never message payload.
- User communication belongs exclusively to the Coordinator.
- A child cannot address another Campaign.
- Broadcast is parent-to-direct-children only.
- Control operations require parent/runtime authority and are separately audited.

## Environment

Launcher environments use explicit allowlists. Secrets are never inherited by
default, persisted in messages/events, or returned in diagnostics. A consumer may
provide opaque secret references through a future secret provider; raw secret
storage is outside version 1.

## Outputs and prompt injection

Agent output, diagnostics, artifact metadata, and messages are untrusted data.
They are bounded and labeled before being passed to another Agent. The runtime
does not claim to solve semantic prompt injection, but it prevents arbitrary
route/authority changes encoded in content.

## Process identity and cleanup

- PID without token/native identity is insufficient.
- Stale handles are reconciled before replacement.
- Uncertain live writers prevent a second mutable Agent.
- Cancellation has a bounded graceful phase followed by platform-appropriate
  process-tree termination when authorized.
- Cleanup is idempotent and recorded.
- The runtime never deletes consumer worktrees or domain artifacts.
- psutil may signal only a process whose PID, creation time, ownership record,
  and runtime-issued identity match.

## Local AgentChannel

The WebSocket server binds only to `127.0.0.1`/loopback on an ephemeral port; it
is not a remote API. Every Agent receives an independent random connection token
through its trusted launch environment. Agent identity is derived from the
authenticated connection, never a request body. Tokens are redacted; only their
SHA-256 digests are persisted and compared with `hmac.compare_digest`. Raw tokens
expire with the Agent and never appear in Store events or model-visible messages.
Frames, pending requests,
ping/pong timings, and connection attempts are bounded.

## Idempotency

At-least-once delivery requires mutating tools to use idempotency keys. The
runtime supplies identity and storage primitives; consumers implement idempotent
domain actions. A key reused with different input is rejected.

## Trusted approvals

Agent messages and model text never grant authority. An Agent may create an
approval request, which travels hierarchically to the Coordinator. Only the
trusted user/consumer channel may issue a Grant. Grants bind subject Agent,
capability, exact resource hash, expiry, and use count. They are non-transferable
and audited. See `approvals.md`.

## Cross-platform requirements

Core and Store must pass on macOS, Linux, and Windows. Launcher and channel
capabilities are discovered explicitly. Unsupported process-tree or Pi extension
features fail before an Agent starts rather than degrading silently.
