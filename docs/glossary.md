# Glossary

Terms in this document are normative.

## Acceptance

Proof that a Driver reached its declared durable boundary for one Message.
Acceptance is not Operation completion.

## Artifact

Durable reference to bounded content too large or unsuitable for a Message.

## Capability

Versioned declaration of behavior a Participant, Driver, or authority can
support or exercise.

## Command

Correlated request to change Navigator state.

## Consumer

Application or trusted user-facing system that creates and governs work through
Navigator.

## Control plane

Navigator mechanisms responsible for identity, durable state, policy,
scheduling, communication, recovery, and audit.

## Driver

Adapter implementing Navigator execution semantics for one Executor technology.

## Effect

Externally observable mutation caused while processing a request.

## Event

Immutable durable fact emitted after a committed transition.

## Executor

System that performs work for a Participant, including an AI agent, process,
service, or human.

## Fencing epoch

Monotonic ownership value checked by writes to reject a previous owner.

## Grant

Scoped, expiring trusted authorization for an otherwise unavailable action.

## Instance

Concrete Driver and Executor binding for a Participant.

## Lease

Bounded temporary claim over ownership, delivery, or capacity.

## Mailbox

Durable ordered collection of Messages addressed to a Participant.

## Message

Durable envelope routed between authorized Participants.

## Navigator

The language-neutral control plane defined by these specifications.

## Operation

One durable unit of work processed by a Participant.

## Participant

Addressable actor within a Session, backed by an Executor.

## Policy

Trusted rules constraining topology, authority, resources, and behavior.

## Query

Read-only request for a snapshot or projection.

## Reconciliation

Comparison of durable intent with observable live state to classify safe next
actions after interruption.

## Request identity

Stable identity binding a mutable request to its semantic input and result.

## Session

Durable boundary containing one related topology of autonomous work.

## Snapshot

Immutable projection of current committed state.

## Template

Immutable trusted ceiling for creating a kind of Participant.

## Tool

Schema-defined action available to an Executor through a trusted provider.

## Uncertain effect

State in which Navigator cannot prove whether an external mutation occurred and
therefore cannot safely replay it generically.
