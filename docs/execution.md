# Execution semantics

## Session ownership

Before mutating a Session, a Navigator host acquires a bounded ownership lease
with a monotonic epoch. Every protected write verifies the current epoch.

Lease loss immediately stops new delivery and begins bounded shutdown or
handoff. A stale host cannot regain authority merely because its processes or
connections remain alive.

## Participant lifecycle

Public lifecycle states are:

- registered: durable identity exists;
- starting: an Instance is being established;
- idle: ready and has no active execution;
- busy: processing an Operation;
- waiting: Operation awaits a correlated response;
- stopping: orderly termination is underway;
- stopped: no current Instance remains;
- failed: lifecycle failed with a typed reason;
- uncertain: live state cannot be proven safely.

Executor-native idle or settled signals update liveness and availability. They
do not determine Operation success.

## Launch protocol

Launching follows this order:

1. validate policy, topology, capacity, and Driver capabilities;
2. persist Participant, launch attempt, and request identity;
3. create the external Instance;
4. attach verifiable Instance identity using compare-and-set;
5. authenticate and declare readiness;
6. permit delivery.

`[NAV-READINESS-001]` Work MUST NOT begin before identity and readiness are bound. If a host fails
between steps, reconciliation determines whether cleanup is safe, required, or
uncertain.

## Scheduling and capacity

Navigator enforces explicit limits for Participants, children, depth, queued
work, concurrent Operations, and resource-specific capacity.

Queue ordering is deterministic within the same priority class. Capacity waits
are bounded or cancellable. Waiting for a parent response may release execution
capacity while retaining Participant identity and Operation correlation.

## Operation lifecycle

Starting work:

1. persist the Operation and request identity;
2. acquire required capacity;
3. ensure a ready Instance;
4. create and lease the input Message;
5. deliver and await acceptance;
6. process explicit progress, question, blocked, and terminal reports;
7. commit the terminal outcome before publishing its Event.

One Participant cannot begin a second Operation while another is unfinished.

## Delegation

Delegation creates a child Participant from a trusted Template. Navigator
validates the caller identity, relationship, role policy, Template allowlist,
task schema, authority intersection, depth, child count, and global capacity.

Untrusted callers select permitted options; they never construct trusted
configuration.

## Questions and waiting

A Participant may report a question or blocking condition correlated to its
current Operation. Navigator transitions the Operation to waiting and routes
the request to the authorized parent or Consumer.

Only the correlated response resumes the waiting context. Older ordinary
Messages do not accidentally satisfy it. Waiting has a deadline and one outcome:
response, cancellation, timeout, parent loss, or explicit failure.

## Cancellation

Cancellation propagates from child to parent during normal shutdown, and from
parent to descendants when the scope is a subtree.

The protocol distinguishes:

- request persisted;
- Driver notified;
- Executor acknowledged;
- graceful stop observed;
- forced stop attempted;
- terminal cancellation committed;
- stop effect uncertain.

Navigator verifies Instance identity before forcefully terminating anything.
It owns and terminates only Instances it created or explicitly adopted through
a trusted protocol.

## Recovery classification

Reconciliation inspects every unfinished entity and classifies it:

- safe to continue: no non-idempotent effect began;
- safe to redeliver: receiver can deduplicate the exact Message;
- externally alive: the same authenticated Instance can reconnect;
- effect uncertain: an effect may have occurred without committed proof;
- cleanup required: stale resources exist but cannot yet be removed safely;
- terminal: durable outcome already exists.

Resume continues only work whose classification permits it. It never creates a
duplicate unfinished Operation for the same Participant.

## Shutdown

Shutdown stops admission, persists cancellation intent where required, closes
children before parents, waits within bounds, escalates only against verified
owned Instances, releases ownership, and closes resources.

No background task may outlive the Navigator scope that owns it.

## Time

Lease and timeout logic uses an injectable monotonic source where possible.
Persisted wall-clock deadlines have maximum future validity and defined
behavior for equality, delay, and clock regression.
