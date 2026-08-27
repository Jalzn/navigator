# Vision

## Thesis

Navigator is a control plane for governed autonomous work.

It connects consumers that express intent to executors that perform work while
preserving identity, authority, durable progress, communication, and history.
An executor may be an AI agent, conventional process, remote service, human
participant, or a future execution system.

Navigator is not defined by any model provider, agent SDK, programming language,
storage engine, transport, or deployment topology.

## Problem

Starting an agent is easy. Reliably coordinating consequential work is not.
Applications otherwise mix domain logic with process management, prompt
delivery, retries, authorization, state recovery, and engine-specific signals.
Ambiguity appears when a connection drops, a caller retries, two hosts compete
for ownership, authority is exceeded, or an external effect cannot be proven.

Navigator gives these situations explicit, durable semantics.

## Product identity

Navigator owns:

- durable work identity and lifecycle;
- relationships among participants;
- delegation and authority enforcement;
- reliable communication and correlation;
- scheduling, capacity, cancellation, and time bounds;
- recovery classification and ownership fencing;
- audit history and operational observation;
- executor capability negotiation.

Consumers own:

- business meaning and success criteria;
- trusted templates and instructions;
- domain tools and external effects;
- user experience and approval interfaces;
- interpretation and publication of results.

Drivers own:

- translation between Navigator and one executor;
- executor process or connection lifecycle;
- delivery into the executor native session;
- translation of native signals into Navigator events;
- honest reporting of supported capabilities.

## Desired future

Navigator begins as a complete local system and may evolve into a distributed
control plane without changing its conceptual model. The same consumer contract
should address a locally managed instance, a standalone service, remote worker
nodes, and mixed trees of agents, processes, services, and humans.

Distribution is a deployment choice, not a different product.

## Success

Navigator succeeds when a consumer can answer:

1. What work exists and who owns it?
2. What authority did every participant receive?
3. Which messages were durably accepted?
4. Which outcomes were explicitly reported?
5. Which effects are safe to retry and which remain uncertain?
6. What happened before, during, and after a failure?
7. Can execution continue without duplicating mutable work?

## Non-goals

Navigator is not a model API, prompt framework, transcript database, universal
workflow language, business-domain engine, generic secret manager, claim of
exactly-once execution, or guarantee that arbitrary code is sandboxed.

These capabilities may exist around Navigator, but they do not define its core.
