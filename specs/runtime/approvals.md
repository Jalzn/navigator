# Approvals and grants

## Purpose

Agent autonomy must not turn conversational text into authority. The runtime
provides a generic request/grant mechanism while consumers retain control of the
native user confirmation interface and domain capability names.

```text
Agent requests approval
  → request travels to Coordinator
  → Coordinator explains it to the user
  → consumer obtains native confirmation
  → trusted boundary issues a Grant
  → Agent presents Grant for the exact operation
```

## ApprovalRequest

```python
ApprovalRequest(
    id=...,
    requester_id=...,
    capability="factory.publish",
    resource_hash=...,
    summary=...,
    status="pending",
    expires_at=...,
    created_by_operation_id=...,
)
```

The capability is opaque to the runtime. `resource_hash` binds a canonical,
Pydantic-validated resource description rather than arbitrary prose. Summary is
untrusted display context and cannot alter the canonical request.

Request creation is idempotent. Reusing its idempotency key with different
canonical content is rejected.

## Grant

```python
Grant(
    id=...,
    request_id=...,
    subject_agent_id=...,
    capability=...,
    resource_hash=...,
    issued_by="trusted_user_channel",
    max_uses=1,
    expires_at=...,
)
```

The Store record is authoritative; a serialized grant ID alone is not a bearer
secret sufficient to bypass validation. Consumption verifies all bindings and
records the authorized operation atomically.

## Invariants

- Agents may request but never issue grants.
- Only the Coordinator may relay requests to the user interface.
- Only a trusted consumer adapter may issue or deny a grant.
- Grant subject, capability, resource hash, expiry, and remaining uses must match.
- Grants are not inherited or transferable to children.
- Single-use consumption is atomic with operation intent creation.
- Cancellation, denial, expiry, consumption, and result are audited.
- A request modified after confirmation requires a new grant.
- Retrying an idempotent authorized operation returns its stored result without
  consuming another use.
- Unknown or uncertain operation completion never silently restores a grant.

## Tool and interface boundary

An authorized Agent may receive `runtime_request_approval`. No Pi tool issues a
grant. The trusted consumer calls an API such as:

```python
await runtime.issue_grant(
    request_id=request.id,
    decision=trusted_decision,
)
```

The consumer must display canonical capability and resource details in its native
confirmation. Model-generated display text is supplementary and labeled.

## Factory compatibility example

Factory can represent its existing two confirmations as:

```text
factory.execute → exact proposal hash/base/scope
factory.publish → exact repository/base/branch/head
```

The runtime does not define those resources or decide when they are required.

## Non-goals

- human identity/account management;
- cryptographic remote authorization tokens;
- policy interpretation for Factory or Laboratory;
- blanket “approve all future actions” grants;
- approval inferred from chat text;
- confirmations for every internal Agent spawn inside an already authorized
  Campaign policy.
