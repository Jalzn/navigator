# Pi orchestration tools

## Purpose

Coordinator and Campaign nodes are Pi agents that coordinate their child tree.
The runtime exposes a small extension whose tools call the trusted Python runtime
boundary. TypeScript performs schema validation and presentation only; it does
not own lifecycle, authorization, persistence, or routing.

## Trusted caller identity

The extension does not accept `caller_id`. Runtime launcher configuration binds
the Pi session to one Agent ID through a trusted, non-model-controlled channel.
Every tool operation resolves that identity server-side.

The model cannot select a parent, Session, Store path, launcher/channel handle, or
capability set outside its delegated policy.

## Uniform tool surface

Version 1 exposes six generic orchestration tools:

```text
runtime_spawn
runtime_send
runtime_children
runtime_status
runtime_cancel
runtime_resume
```

A seventh conditional tool is exposed only when policy allows approval requests:

```text
runtime_request_approval
```

Behavior is derived from trusted caller role and topology:

- Coordinator `runtime_spawn` creates a Campaign child.
- Campaign `runtime_spawn` creates a Worker child.
- Worker `runtime_spawn` creates another Worker child only when policy and depth
  permit.
- `runtime_send(direction="parent")` reports upward.
- `runtime_send(child_id=...)` sends to one direct child. A response to
  `question` or `blocked` uses `kind="feedback"` plus the required
  `reply_to_message_id`.
- `runtime_children` lists direct children and their compact status.
- `runtime_status` inspects self or an authorized descendant.
- `runtime_cancel` controls descendants only.
- `runtime_resume` applies only to recoverable nodes in the caller's subtree.
- `runtime_request_approval` creates a request and conveys no authority by itself.

The Coordinator communicates with the user through the normal interactive Pi
channel and therefore needs no `runtime_report_user` tool.

Tools forbidden by immutable policy are omitted from the Agent's tool set. The
runtime revalidates every call even when the tool is visible.

Approval grant issuance is never an Agent tool. It belongs to the trusted
user/consumer channel described in `approvals.md`.

## Routing rules

- `runtime_send` addresses the direct parent or direct children only.
- Agents cannot address siblings or another Campaign.
- Status visibility is limited to self plus descendants.
- Cancel is limited to descendants.
- User reporting is Coordinator-only.
- Ordinary feedback uses the persistent mailbox; control actions use the control
  path and are separately audited.
- `question` and `blocked` create one correlated wait on the caller's current
  operation; they do not invoke `runtime_resume`.

## Child creation

Starting a child is an idempotent, policy-bound operation:

1. derive trusted caller and parent;
2. resolve `template_id` from the Session's immutable TemplateCatalog;
3. validate the template is allowed for this parent and role;
4. validate parameters against the template schema;
5. validate delegated policy is within both template and parent ceilings;
6. validate depth, count, capacity, and cwd boundary;
7. persist child, template ID, and operation intent transactionally;
8. queue or start through LocalDispatcher;
9. return a stable child ID and current state.

Retrying the same tool call with the same idempotency key returns the existing
child. Reusing the key with a different spec is rejected.

The spawn request supplies a `template_id`, bounded task data, and optionally a
more restrictive delegated policy. It never supplies executable, base system
prompt, extensions, or an authority ceiling.

## Confirmations

Runtime tools do not invent confirmation dialogs. Consumers decide which domain
actions require native user confirmation. Starting a policy-approved child inside
an already authorized Campaign does not require confirmation per Agent.
Destructive deletion and authority expansion remain explicitly confirmed at the
consumer boundary.

## Tool schemas

Each tool uses an exclusive Pydantic request union so mutually incompatible modes
cannot be mixed. `runtime_send`, for example, accepts exactly one of `parent` or
`child_id`. The Python boundary rejects unknown fields and derives identity,
Session, Store, and parent relationships server-side.

For an upward report, allowed kinds are `progress`, `completed`, `failed`,
`question`, and `blocked`. A downward response uses `feedback` and requires
`reply_to_message_id`; an ordinary instruction must omit it. The Runtime rejects
a reply when the referenced wait is absent, resolved, expired, belongs to another
operation, or was not emitted by that direct child.
