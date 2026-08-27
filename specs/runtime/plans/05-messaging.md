# Vertical 05 — Durable hierarchical messaging

## Outcome

Instructions, feedback, questions, progress, and results survive disconnects
and are delivered in parent-mediated order with explicit acknowledgement.

## End-to-end proof

During a Worker tool call, Campaign sends steering and follow-up feedback. A
disconnect occurs between Pi injection and ACK. Reconnect reconciles the exact
Pi entry without duplicate model-visible delivery, and the result returns to the
Coordinator.

## Scope

- persistent per-Agent FIFO mailbox and sequence allocation;
- message IDs, correlation IDs, delivery attempts, leases, and dead letters;
- prompt/steer/follow-up selection by Agent state;
- exact Pi Session-entry reconciliation;
- question/blocked wait with correlated parent feedback;
- important-event wake-up and bounded progress batching;
- parent broadcast to direct children;
- size limits and artifact-reference requirement for large payloads;
- entity-specific idempotency plus the planned generic idempotency lifecycle.

## Invariants

- acknowledgement means exact persisted acceptance, not socket receipt;
- result persistence is a separate terminal transaction;
- at-least-once transport never becomes an exactly-once claim;
- only direct parent/child routing is accepted;
- waiting feedback may select its correlated reply without corrupting FIFO;
- uncertain injection is reconciled before any redelivery;
- delivery IDs remain retained while Store may redeliver them.

## Acceptance

- crash before injection, after injection, before ACK, and after ACK;
- duplicate delivery and reconnect deduplication;
- steer/follow-up while text streams and while a tool runs;
- question waits release execution capacity and retain Agent capacity;
- parent-response timeout fires once without reminder loops;
- oversized, malformed, wrong-parent, and cross-Campaign messages fail closed;
- mailbox starvation and retry exhaustion are observable.

## Adversarial review

- construct every ambiguous external-effect boundary;
- reorder frames and reconnect with stale connection epoch;
- exhaust message quotas and correlation maps;
- verify progress batching cannot hide terminal events;
- inspect whether generic idempotency is justified beyond entity constraints.

## Excluded from this slice

Automatic process replacement, artifact contents, approval decisions, and domain
workflow meaning.

