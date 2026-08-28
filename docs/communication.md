# Communication

## Categories

Navigator distinguishes:

- Commands: requests to change state.
- Queries: read-only requests for snapshots.
- Messages: durable Participant-to-Participant envelopes.
- Events: immutable facts after committed transitions.
- Driver control: bounded lifecycle commands to an Instance.

These categories are not interchangeable.

## Message routing

Every Message is validated against Session topology and policy before
persistence. A Participant may address itself, its parent, or direct children
when policy permits. Cross-tree routing is resolved through an authorized common
ancestor rather than direct sibling delivery.

Consumers may send through trusted Session entrypoints. Driver-supplied caller
identity is derived from its authenticated connection, not from message input.

## Delivery transaction

Delivery has separate phases:

1. Message persisted in a Mailbox.
2. Delivery lease assigned to an owner epoch.
3. Driver receives a delivery attempt with stable Message identity.
4. Driver reaches its declared durable acceptance boundary.
5. Driver acknowledges the exact Message identity.
6. Navigator commits acceptance.

A disconnect before step 6 permits reconciliation and possible redelivery. The
Driver deduplicates using Message identity and reports whether previous
acceptance can be proven.

## Durability boundary

`[NAV-ACCEPT-001]` Each Driver declares what accepted means. It MUST be stronger than receipt in a
volatile transport buffer. Acceptable boundaries include a durable native queue,
persisted session entry, or completed handoff to an idempotent Executor API.

If the Driver cannot prove acceptance, it reports unknown rather than
acknowledging optimistically.

## Operation reports

Participants report:

- progress: non-terminal bounded update;
- question: correlated request for information;
- blocked: cannot continue without external change;
- succeeded: explicit terminal result;
- failed: explicit typed terminal failure;
- cancelled: execution ended because of cancellation;
- uncertain: outcome or effect cannot be proven.

Progress may be coalesced. Terminal reports never are.

## Ordering

Ordering is guaranteed per Mailbox, not globally. Event order is stable within a
Session. Cross-Session ordering has no semantic meaning.

Control traffic such as cancellation may bypass ordinary Message order through
a separate channel or priority class. This bypass is explicit and audited.

## Cancellation cleanup confirmation

Each public cancellation operation exposes `cleanup_confirmed`. This is true
when no Driver notification was needed because the operation is already
terminal, or when the cancellation notification is present and its durable
delivery state is accepted. A terminal operation does not override a pending,
unknown, or failed notification: when a notification exists, only accepted
delivery confirms cleanup. Running and cancelling operations without accepted
notification remain unconfirmed.

## Correlation

All mutable Commands, deliveries, reports, and responses carry stable
correlation identity. A response references the request it resolves. Unknown,
expired, duplicate-with-different-input, and ambiguous correlation are rejected.

## Backpressure

Payload, frame, queue, subscription, and pending-request sizes are bounded.
Senders receive typed capacity or timeout failures instead of unbounded memory
growth. Large content is represented by Artifacts.

## Event subscriptions

A Consumer subscribes from a Session event position. Reconnect may replay
Events. Consumers deduplicate by Event identity or resume from the last committed
position.

Slow subscribers do not block state commits. They receive bounded buffering,
disconnect, or durable catch-up according to the transport capability.

## Version envelope

Every protocol message declares protocol version, message type, identity,
correlation where applicable, and bounded payload. Unknown required fields,
unsupported versions, malformed input, and oversized messages fail closed with
stable error codes.

## Redaction

Messages and Events use structured redaction before persistence and emission.
Credentials, raw environment values, authentication material, and private
Executor internals are never placed in public event data.
