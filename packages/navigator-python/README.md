# Navigator Python SDK

The public `navigator` package exposes immutable domain snapshots and an async
client. Generated protobuf/gRPC modules live under the private
`navigator._transport` namespace and are not part of compatibility guarantees.

The supported runtime is CPython 3.13 or newer on macOS 11+ arm64. The
repository gate runs on CPython 3.13.15; older Python releases and unsupported
platforms are rejected by package metadata or fail closed before launch.

Regenerate deterministically from the repository's canonical proto with:

```sh
python -m pip install -e '.[dev]'
python scripts/generate.py
```

Applications must persist `bytes(Identity)` and `int(EventPosition)` without
interpreting their representation. `asyncio.CancelledError` is never converted
to a Navigator domain failure.

## Tools and Artifacts

`navigator.tools.register(...)` registers a frozen `ToolDefinition`, and
`navigator.tools.provide(...)` serves a closed mapping from registration identities to async
handlers. The provider performs the durable `HandlerStarted` handshake internally: application
handler code is not entered until Navigator acknowledges that boundary. Its server watermark and
completed terminal values survive stream reconnection, so an in-flight handler is not executed a
second time after a transient disconnect. Cancelling the provider task uses native
`asyncio.CancelledError`.

`navigator.artifacts.write(...)` and `read(...)` stream bounded chunks while checking declared
size, offsets, and SHA-256. Reads buffer privately until the stream ends successfully; a terminal
failure, truncation, or digest mismatch discards all partial content. Snapshot and logical-delete
operations are available through the same `navigator.artifacts` resource group.

## Executable workflow

[`examples/acceptance_workflow.py`](examples/acceptance_workflow.py) demonstrates
open, run, cursor-based event subscription, cancel, resume, and logical reset.
It imports only the public `navigator` API. The workflow is identical for a
managed-local daemon and an external daemon; only deployment configuration changes:

```sh
NAVIGATOR_MODE=external \
NAVIGATOR_ENDPOINT=unix:///run/navigator.sock \
NAVIGATOR_CREDENTIAL=... \
python examples/acceptance_workflow.py
```

For managed-local mode, install the platform wheel and set only
`NAVIGATOR_MODE=local` and `NAVIGATOR_DATA_DIR`. The wheel supplies and verifies
the managed Navigator and generic agent runtime; applications do not configure
Rust, Node, or Pi. The event cursor is saved
atomically only after the handler succeeds, so reconnect continues after the last
handled event. Reset closes the old session and opens a new identity; it never
deletes the previous session or its audit events.

Event subscriptions return frozen typed variants for stable schema-v1 session,
participant, operation, message, authority, ownership, and artifact events.
For observation after ownership has been released, use
`await navigator.read_events(session_id, after=position, page_size=128)` and
follow `EventPage.has_more`; pages are immutable, contiguous from `after + 1`,
and bounded to 128 events. `events()` remains an ownership-bound live
subscription.
Callers should always retain an `UnknownEvent` branch: new event types, newer
schemas, and payloads this SDK cannot safely validate are delivered losslessly
with their original `type`, `schema_version`, `data`, and `opaque_wire` bytes.

`examples/managed_work.py` is the minimal managed-local acceptance program. It
opens a Session, starts work with `managed_template`, streams ordered Events to
a terminal successful Operation, and leaves bounded process cleanup to the
async context manager. Executable and catalog overrides remain available for
operators and conformance tests, but are not part of the beginner path.

The managed runtime is copied into a fresh private directory and every bundled
byte is checked against the wheel manifest before launch. This is an integrity
boundary against damaged or replaced package content, not a sandbox against a
malicious process already running as the same operating-system user: such a
process can modify any user-owned runtime after verification. Use an external
daemon under a separate service identity when that stronger boundary is needed.
