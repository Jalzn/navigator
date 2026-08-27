# Principles and guarantees

## Control plane owns work, not cognition

Navigator is authoritative for operational state. An executor is authoritative
for its private reasoning, transcript, and model interaction. Neither side
mirrors the complete private state of the other.

## Extensions adapt to Navigator

Drivers translate Navigator contracts into executor behavior. Executor-specific
session types, hooks, formats, and tool APIs `[NAV-BOUNDARY-001]` MUST NOT enter the domain model.
Unsupported behavior is represented as an absent capability.

## Identity precedes effects

`[NAV-IDEMPOTENCY-001]` Every mutable action MUST have stable identity before its external effect begins.
Retrying the same identity with different semantic input `[NAV-IDEMPOTENCY-002]` MUST be rejected.

## Acceptance is not completion

Delivery acknowledgement means only that the receiver reached its declared
durability boundary. It does not mean work succeeded. Success, failure,
blocking, cancellation, and uncertainty require explicit outcomes.

## Delivery is at-least-once

Navigator assumes delivery can repeat across disconnects and crashes. Receivers
`[NAV-MAILBOX-001]` MUST deduplicate accepted message identities. Navigator MUST NOT claim
exactly-once execution.

## Uncertainty is first-class

When Navigator cannot prove whether an external effect occurred, it records the
effect as uncertain. Generic retry or resume `[NAV-RECOVERY-001]` MUST NOT replay it. Resolution
requires proof, an authorized consumer decision, or explicit abandonment.

## Authority only decreases

A participant cannot exercise or delegate authority beyond the intersection of
the Session ceiling, its effective authority, the trusted Template, relationship
policy, and active grants. Model and executor input is untrusted.

## Ownership is exclusive and fenced

At most one owner may mutate a Session. Ownership includes a monotonic fencing
value, preventing a previous owner from writing after lease loss. Connection
presence alone is not ownership.

## Durable state wins

Processes, sockets, streams, and memory queues are observations or mechanisms.
Durable records decide what work exists, which transitions committed, and what
recovery is allowed.

## Recovery is explicit and conservative

Recovery reconciles durable state with observable executor state before
continuing. Infrastructure restart does not authorize repeating work.

## Cancellation is a protocol

Cancellation is a request, not proof that execution stopped. Requested,
acknowledged, completed, forced, and uncertain outcomes remain distinguishable.

## Observability derives from facts

Views are projections of durable events and snapshots. Logs may supplement them
but are not the only source for important state.

## Local is complete

Local execution preserves the same identities, policies, lifecycle semantics,
and failure classifications as future distributed deployments.

## Security claims are honest

A working directory, prompt, tool list, or environment is not a filesystem
sandbox. Enforcement is described according to the mechanism actually present.

## Mechanism and policy are separate

The core provides universal mechanisms. Consumers choose business policy.
Coordinator, Campaign, and Worker may be a standard policy without becoming
executor or core primitives.
