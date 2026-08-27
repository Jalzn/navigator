# Pi extension WebSocket protocol

## Scope

This protocol connects one Pi runtime extension to the foreground Runtime Host.
It is a local AgentChannel adapter, not a public or remote API. The Store and
mailbox contracts remain authoritative when a socket disconnects or frames are
repeated.

The Python endpoint uses `websockets.asyncio`. The Pi extension uses the native
WebSocket client from the supported Node.js runtime when verified. No Socket.IO,
JSON-RPC, REST API, broker, or application-level event bus is introduced.

## Connection

The Host binds to loopback on an ephemeral port before launching Pi. It passes
the endpoint, protocol version, Agent ID, and a random per-Agent token through a
trusted explicit launch environment. The extension connects once and must send
`hello` as its first application frame within the handshake timeout.

The Host accepts only text JSON frames. Binary frames, invalid JSON, oversized
messages, an unexpected first type, extra fields, invalid credentials, and an
unsupported protocol version cause a bounded protocol error and connection
close. Raw frames and tokens are never logged.

## Common envelope

```json
{
  "protocol": 1,
  "type": "rpc.request",
  "id": "req_...",
  "payload": {}
}
```

- `protocol` is the integer wire-protocol version;
- `type` is a closed discriminator;
- `id` is a UUID4 encoded with a readable type prefix;
- `payload` is validated by the schema for `type`;
- extra fields are rejected at every level.

Sender, destination, and server timestamps are absent. Identity comes from the
authenticated connection, routing comes from Runtime state, and receive time is
recorded by the Host. Pydantic discriminated unions plus one `TypeAdapter`
validate and serialize the complete frame union.

## Frame types

Version 1 has exactly eight application frame types:

```text
hello
ready
rpc.request
rpc.response
message.deliver
message.ack
agent.event
protocol.error
```

### hello and ready

The extension sends:

```json
{
  "protocol": 1,
  "type": "hello",
  "id": "hello_...",
  "payload": {
    "agent_id": "agt_...",
    "token": "secret",
    "extension_version": "0.1.0"
  }
}
```

The Host hashes the presented high-entropy token with SHA-256, compares it to the
stored digest with `hmac.compare_digest`, binds the connection to the stored
Agent, and replies:

```json
{
  "protocol": 1,
  "type": "ready",
  "id": "ready_...",
  "payload": {
    "session_id": "ses_..."
  }
}
```

No other application frame is processed before `ready`. A second live
connection for the same Agent is rejected unless reconciliation has first made
the previous connection stale. The credential remains valid only for reconnects
by that Agent during its lifetime and is revoked when the Agent closes.

### rpc.request and rpc.response

RPC is symmetric: the extension invokes Runtime tools and the Host may invoke a
small closed set of Pi extension control methods.

```json
{
  "protocol": 1,
  "type": "rpc.request",
  "id": "req_...",
  "payload": {
    "method": "runtime.spawn",
    "params": {}
  }
}
```

The response reuses the request `id`:

```json
{
  "protocol": 1,
  "type": "rpc.response",
  "id": "req_...",
  "payload": {
    "ok": true,
    "result": {}
  }
}
```

Failure uses `ok: false` with the public `ErrorInfo` projection: stable
`error.code`, bounded safe `error.message`, `retryable`, `recoverable`, and
optional `phase`/correlation. Exactly one of `result` or `error` is present. Method names
and parameter schemas are closed and role/policy filtered. At most 32 requests
may be pending per connection and the provisional default timeout is 30 seconds.
Late or duplicate responses are ignored and recorded as bounded diagnostics.

### message.deliver and message.ack

Mailbox delivery is not modeled as RPC because its acceptance has durable
at-least-once semantics:

```json
{
  "protocol": 1,
  "type": "message.deliver",
  "id": "delivery_...",
  "payload": {
    "message_id": "mail_...",
    "operation_id": "op_...",
    "reply_to_message_id": null,
    "kind": "completed",
    "content": "bounded text",
    "artifacts": []
  }
}
```

The extension first checks message IDs reconstructed from persisted Pi custom
messages. If unseen, it injects a custom message containing `messageId` in its
details with `pi.sendMessage(..., { deliverAs: "followUp", triggerTurn: true })`.
The persisted custom message itself is the deduplication record. The extension
then replies with the same delivery ID and message ID:

```json
{
  "protocol": 1,
  "type": "message.ack",
  "id": "delivery_...",
  "payload": {
    "message_id": "mail_...",
    "status": "accepted"
  }
}
```

`accepted` means persisted and accepted for injection into Pi. It does not mean
the model processed the message or completed an operation. If the connection
breaks before the Host commits the acknowledgement, the Store may redeliver;
the extension returns the same acceptance without injecting it twice.

For a parent response continuing `waiting_for_parent`, `kind` is `feedback` and
`reply_to_message_id` identifies the child's persisted `question` or `blocked`
message. Other deliveries set it to null. The Host validates correlation before
putting the frame on the channel; the extension treats these identifiers as
opaque context and cannot reroute them.

### agent.event

The extension sends bounded observations about Pi lifecycle:

```json
{
  "protocol": 1,
  "type": "agent.event",
  "id": "evt_...",
  "payload": {
    "kind": "agent.settled",
    "operation_id": "op_...",
    "facts": {}
  }
}
```

Initial event kinds are `agent.started`, `agent.settled`, and `agent.exiting`.
They map to Pi's `agent_start`, `agent_settled`, and `session_shutdown` hooks.
Events are observations, not authority: they cannot declare operation success or
failure, or change topology, policy, grants, and message routing. In particular,
`agent.settled` means only that Pi has no automatic continuation pending.

### protocol.error

When safe, the receiver reports a bounded machine-readable error before closing
or ignoring the offending frame. It contains a closed error code, safe message,
and optional correlation ID. Authentication failures do not reveal whether an
Agent ID or token was correct.

## Keepalive and reconnect

Liveness uses native WebSocket ping/pong configured by `websockets`; there is no
JSON heartbeat type. The provisional server values are a 20-second ping interval
and 20-second pong timeout. The JavaScript client must respond to protocol pings;
this capability is verified against the supported Node.js client before the
implementation is locked.

On disconnect, the extension retries only while its owning Pi process remains
alive. It uses bounded exponential backoff with jitter and no dependency. The
Host allows a short reconnect window, authenticates again, then resumes durable
delivery. Exhaustion marks the Agent interrupted; it never spawns a replacement
or resumes an operation automatically.

## Bounds

Provisional version 1 defaults:

- handshake application frame within 10 seconds;
- maximum decoded message size: 256 KiB;
- maximum pending RPCs per connection: 32;
- RPC timeout: 30 seconds unless the closed method schema specifies less;
- compression disabled for local bounded messages;
- one Agent identity per connection;
- artifacts referenced by ID rather than transferred as binary frames.

Exact values remain configurable Runtime limits and will be finalized by load,
failure, and cross-platform tests.

## Standard-library support

- `secrets` generates Agent connection tokens;
- `hmac.compare_digest` compares them;
- `uuid.uuid4` generates protocol IDs because Python 3.12 is supported;
- no ULID, JWT, MessagePack, Protobuf, or reconnection package is required.
