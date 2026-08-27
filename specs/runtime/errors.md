# Typed errors

## Goals

Expected operational failures must cross Python, Store, WebSocket, Pi tools, and
the Coordinator without relying on exception text. Codes are stable contracts;
messages are concise safe explanations and are not parsed by callers.

Version 1 uses one public exception rather than a subclass per failure:

```python
class RuntimeFailure(Exception):
    error: ErrorInfo
```

```python
class ErrorInfo(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: ErrorCode
    message: str
    retryable: bool
    recoverable: bool
    phase: ErrorPhase | None = None
    correlation_id: str | None = None
    details: dict[str, JsonValue] = Field(default_factory=dict)
```

`details` is bounded and allowlisted per code. It never contains tokens,
environment values, raw prompts, unrestricted paths, full subprocess output, SQL,
tracebacks, or arbitrary caught exception strings.

## Semantics

- `retryable`: repeating the same idempotent infrastructure attempt may succeed
  without new user authority or duplicating an uncertain side effect.
- `recoverable`: explicit reconciliation, resume, feedback, approval, or external
  intervention can preserve the same durable Session/Agent/operation identity.
- neither flag authorizes a retry or resume; policy and idempotency checks still
  decide whether the action is allowed.

Flags are derived from one immutable registry keyed by `ErrorCode`. Call sites
select a code and safe contextual fields; they cannot independently choose the
flags. Protocol deserialization verifies that received flags match the local
registry for that protocol version.

## Error phases

```text
store
bootstrap
launcher
handshake
channel
delivery
operation
approval
artifact
shutdown
reconcile
```

Phase identifies where the failure surfaced, not who is at fault. It is optional
when the code already carries enough context.

## Closed codes

### Input and state

| Code | Retryable | Recoverable | Meaning |
|---|---:|---:|---|
| `invalid_input` | no | no | Boundary model or closed method input is invalid. |
| `not_found` | no | no | Scoped entity does not exist or is intentionally undisclosed. |
| `state_conflict` | no | yes | Requested effect conflicts with current durable state. |
| `invalid_transition` | no | yes | Lifecycle transition is not allowed from current state. |
| `stale_revision` | yes | yes | Compare-and-swap revision lost a race. |
| `incompatible_session` | no | no | Trusted templates/tools/policies changed; reset is required. |

### Ownership and capacity

| Code | Retryable | Recoverable | Meaning |
|---|---:|---:|---|
| `session_claimed` | yes | yes | Another unexpired owner holds the Session lease. |
| `session_lease_lost` | no | yes | This Runtime lost its ownership epoch and is fenced. |
| `capacity_timeout` | yes | yes | Bounded wait for execution capacity expired. |
| `limit_exceeded` | no | yes | A fixed count, depth, byte, or resource limit was exceeded. |

### Authority and approvals

| Code | Retryable | Recoverable | Meaning |
|---|---:|---:|---|
| `policy_denied` | no | no | Requested authority is outside the immutable policy ceiling. |
| `approval_required` | no | yes | Trusted user approval is required before the effect. |
| `approval_denied` | no | no | The trusted user denied the request. |
| `approval_expired` | no | yes | Approval expired before atomic use. |
| `grant_exhausted` | no | yes | No authorized uses remain. |

### Store and idempotency

| Code | Retryable | Recoverable | Meaning |
|---|---:|---:|---|
| `store_busy` | yes | yes | Bounded SQLite contention prevented the transaction. |
| `schema_too_new` | no | no | Database schema is newer than this Runtime. |
| `store_corrupt` | no | yes | Integrity/decoding failure requires intervention or restore. |
| `idempotency_conflict` | no | no | The same key was reused with different canonical input. |
| `effect_uncertain` | no | yes | External effect may have happened; automatic retry is unsafe. |

### Launcher and channel

| Code | Retryable | Recoverable | Meaning |
|---|---:|---:|---|
| `launcher_start_failed` | yes | yes | Pi process could not start before any operation effect. |
| `process_lost` | no | yes | Owned Pi process exited or identity no longer matches. |
| `launcher_stop_failed` | no | yes | Bounded cleanup could not prove process termination. |
| `authentication_failed` | no | no | Agent handshake credential or identity was invalid. |
| `protocol_violation` | no | no | Peer sent an invalid, oversized, or incompatible frame. |
| `channel_unavailable` | yes | yes | Authenticated AgentChannel is temporarily unavailable. |
| `rpc_timeout` | yes | yes | Idempotent correlated RPC exceeded its deadline. |

### Delivery and operation

| Code | Retryable | Recoverable | Meaning |
|---|---:|---:|---|
| `delivery_failed` | yes | yes | A mailbox delivery attempt failed before exhaustion. |
| `delivery_dead_letter` | no | yes | Delivery exhausted its bounded attempts. |
| `missing_result` | no | yes | Settled child failed to report after one reminder. |
| `parent_response_timeout` | no | yes | Correlated parent feedback did not arrive before deadline. |
| `operation_failed` | no | yes | Agent explicitly reported a task failure. |
| `cancelled` | no | yes | Durable operation was cancelled through Runtime authority. |
| `shutting_down` | no | yes | New work was rejected during orderly shutdown. |

### Artifacts

| Code | Retryable | Recoverable | Meaning |
|---|---:|---:|---|
| `artifact_invalid` | no | no | Path, metadata, media type, or reference is invalid. |
| `artifact_too_large` | no | yes | Configured artifact bound would be exceeded. |
| `artifact_hash_mismatch` | no | yes | Content does not match registered digest. |

The list grows only when callers need distinct behavior. It does not mirror every
internal exception or SQL/Pi error.

## Boundary translation

### Store

SQLite constraint, busy, schema, and decoding failures are translated at the
Store boundary. Raw SQL messages do not escape. Unknown database errors become
an internal unexpected exception and trigger rollback; they are not mislabeled
as retryable.

### Launcher and channel

Known process and protocol conditions map to their closed codes with bounded
phase and identity facts. Raw stdout/stderr may be stored as a redacted artifact
reference, not embedded in ErrorInfo.

### Pi tools

`rpc.response` serializes ErrorInfo. The extension renders `message` plus a short
code and returns structured error data to Pi. Authentication failure responses
do not reveal whether Agent ID, token, Session, or protocol detail mismatched.

### Coordinator and logs

The Coordinator may explain or request action using code and safe message.
Detailed internal diagnostics remain bounded Runtime events. User-visible text
never includes a traceback by default.

## Cancellation and unexpected defects

AnyIO/asyncio cancellation is control flow. Code must re-raise native cancellation
after bounded cleanup and must not wrap it in `RuntimeFailure(code="cancelled")`.
The `cancelled` code represents a persisted domain outcome requested through
Runtime authority, not task cancellation inside Python.

`KeyboardInterrupt`, `SystemExit`, assertions, type errors, and unexpected bugs
are not converted into expected operational failures. Runtime records a bounded
internal event, performs safe cleanup, and lets the defect remain visible to
tests/operators.

## Correlation and stability

Correlation IDs connect a safe user/tool error to events without exposing raw
details. Error codes and their retry/recovery meaning are wire-compatible within
protocol version 1. Messages and details may improve without a compatibility
promise; callers branch only on `code`.
