# Architecture

## Logical topology

    Consumer
       | commands, queries, subscriptions
       v
    Navigator control plane
       +-- durable state
       +-- policy and topology
       +-- scheduler and lifecycle
       +-- mailbox and correlation
       +-- audit and recovery
       |
       +-- Driver A -- Executor A
       +-- Driver B -- Executor B
       +-- Driver C -- Executor C

The consumer-facing and driver-facing boundaries are distinct. Consumers
describe and observe work. Drivers execute work.

## Control plane

`[NAV-CONTROL-001]` The control plane MUST:

- assign stable identities;
- validate every state transition;
- persist intent before dispatching a mutable external action;
- enforce topology, policy, capacity, and ownership;
- correlate commands, messages, operations, and outcomes;
- classify incomplete work during reconciliation;
- expose immutable snapshots and ordered event streams.

`[NAV-CONTROL-002]` The control plane MUST NOT:

- interpret private model reasoning;
- infer completion from executor idleness;
- allow drivers to mutate storage directly;
- treat a live connection as proof of success;
- embed consumer business semantics.

## Consumer boundary

A Consumer uses Navigator to create and control work. It supplies trusted
configuration and may provide domain tools.

The boundary supports opening Sessions, registering immutable Templates,
starting and observing Operations, cancellation, authorized messaging, artifact
access, approval decisions, and resolution of uncertain effects.

SDKs SHOULD feel idiomatic in their language while preserving common semantics,
identities, and errors.

## Driver boundary

A Driver connects Navigator to one class of Executor. It may run in-process, as
a child, sidecar, worker, or remote service. Deployment does not change the
contract.

`[NAV-DRIVER-001]` A Driver MUST authenticate Instance identity, advertise capabilities, preserve
correlation, acknowledge only at its declared durability boundary, report
explicit lifecycle outcomes, and stop accepting work after losing ownership.

## Storage boundary

`[NAV-STORE-001]` Durable storage is an implementation seam. It MUST support atomic transitions,
uniqueness for unfinished work, ordered mailbox sequencing, compare-and-set with
revision or fencing epoch, durable request correlation, and event ordering
sufficient to reconstruct public snapshots.

No public contract depends on a database product or schema layout.

## Transport boundary

Transport carries a versioned protocol and may be in-process, local IPC,
standard streams, sockets, or network protocols. `[NAV-TRANSPORT-001]` It MUST provide bounded
messages, peer identity binding, correlation, disconnect semantics, and
backpressure or bounded buffering.

Transport availability never determines durable completion.

## Deployment forms

Managed local mode allows an SDK to start and supervise Navigator. Standalone
local mode allows independent consumers to connect. Distributed mode separates
the control plane from remote worker nodes hosting Drivers.

`[NAV-DEPLOY-001]` Every form MUST preserve externally observable lifecycle and failure semantics.

## Coordination policies

Parent and child topology is a universal delegation mechanism. One standard
policy may define:

    User <-> Coordinator <-> Campaign <-> Worker <-> Child Worker

Instructions travel downward. Questions, progress, and outcomes travel upward.
Sibling communication routes through a common ancestor. Creation is bounded by
trusted Templates and effective authority.

Other policies may reuse the same topology primitives without changing core or
Driver contracts.
