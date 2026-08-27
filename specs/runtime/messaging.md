# Hierarchical messaging

## Routing model

Messages are allowed only between directly related nodes:

- parent to child;
- child to parent;
- parent broadcast to its direct children;
- Coordinator to/from the user through the trusted interactive consumer boundary.

Sibling and arbitrary node-to-node delivery is rejected. A result that must reach
another branch travels upward to the common ancestor and is deliberately routed
back down. This preserves context ownership and authority.

## Mailbox behavior

Each Agent owns a persistent FIFO inbox. There is at most one active operation
per Agent. If the Agent is busy, messages remain pending. When it becomes idle,
the LocalDispatcher leases and delivers the next eligible message.

Cancellation, close, pause, and inspection are control operations and do not wait
behind ordinary messages.

## Envelope

```python
Message(
    id=...,
    correlation_id=...,
    causation_id=...,
    reply_to_message_id=...,
    sender_id=...,
    recipient_id=...,
    sequence=...,
    kind="instruction" | "progress" | "completed" | "failed" |
         "feedback" | "question" | "blocked",
    payload=...,
    idempotency_key=...,
    created_at=...,
)
```

Payloads are Pydantic-validated, bounded, and free of credentials. Large content
is represented by an `ArtifactRef`.

## Waiting for a parent

`question` and `blocked` sent upward place the sender's current operation in
`waiting_for_parent`. They use the same mechanical state: `question` requests
information or a decision, while `blocked` requests intervention or an external
state change.

The parent replies downward with `kind="feedback"` and
`reply_to_message_id=<question-or-blocked-message-id>`. Runtime verifies direct
parent/child topology, that the referenced message belongs to the same operation,
and that it is the one unresolved wait. Model-controlled content cannot choose a
different operation or tree through correlation fields.

Ordinary mailbox messages remain FIFO-pending while an Agent waits. Only the
matching reply is eligible to bypass them and continue the existing operation;
cancellation and close remain control operations. The reply is persisted before
delivery, and retries use its stable ID without starting duplicate work.

## Delivery guarantee

Delivery is at-least-once. Exactly-once is not promised because a crash can occur
after Pi receives a prompt but before acknowledgement is durably committed.

States:

```text
pending → delivered → acknowledged
              ↓
            failed → pending (bounded retry)
                       ↓
                  dead_letter
```

Delivery uses a lease. If the owner dies, an expired lease makes the message
eligible for redelivery. Acknowledgement and operation result persistence should
occur in one Store transaction where possible.

## Ordering and deduplication

- Sequence is monotonic per recipient mailbox.
- Unique message IDs reject duplicate inserts.
- Recipient plus sequence is unique.
- Mutating tools receive an idempotency key derived from the message/operation.
- Reprocessing returns the prior durable result or rejects incompatible reuse.
- Retrying a delivery does not imply retrying an unsafe external side effect.

Retry policy is explicit and typed. Infrastructure failures may be retryable;
domain failures and unknown side effects are not retried automatically.

## Feedback propagation

Children send progress, results, questions, and errors to their parent. Parents
decide what context to summarize and propagate upward. The Coordinator is the
only Agent that communicates with the user.

This enables proactive feedback without exposing every raw child transcript to
the Coordinator. Consumers decide summarization prompts; the runtime only routes
validated envelopes.

## Context windows and checkpoints

The runtime performs only mechanical selection: bounded recent messages, total
bytes, artifact references, current state, truncation markers, and the latest
applicable checkpoint. Semantic summarization belongs to the parent Agent. There
is no global summarizer Agent in version 1.

```python
ContextCheckpoint(
    agent_id=...,
    through_sequence=...,
    summary_artifact_id=...,
    created_by_operation_id=...,
)
```

A checkpoint may replace older bodies in future prompts but never deletes the
audit history. Its creation is idempotent and correlated to the covered sequence
range.

## Bounds

Exact limits remain to be finalized, but version 1 must bound:

- message body bytes;
- messages per mailbox;
- delivery attempts;
- lease duration;
- retained acknowledged messages;
- diagnostic/output bytes delivered to an Agent;
- artifact count and size.
