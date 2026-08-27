# Domain model

## Identity

`[NAV-IDENTITY-001]` Every durable entity has an opaque stable identifier. Identity MUST NOT encode
mutable attributes, locations, roles, or storage keys. Identifiers are never
reused within their scope.

## Session

A Session is the durable boundary for related autonomous work. It contains one
Participant topology, Operations, Messages, trusted Template references,
ownership state, Events, and Artifact references.

A Session has at most one effective owner. Closing prevents new work but does
not erase history.

## Participant

A Participant is an addressable actor backed by an agent, process, service, or
human.

It has identity, Session, optional parent, policy-defined role, trusted Template,
effective capabilities, lifecycle status, and an optional current Instance.

Invariants:

- A Participant belongs to exactly one Session.
- Parent and child belong to the same Session.
- Parent relationships are acyclic.
- Effective authority cannot exceed delegated authority.
- A Participant has at most one unfinished Operation.
- Removing a Participant never reuses identity or erases history.

## Template

A Template is immutable trusted configuration defining the maximum behavior of
a kind of Participant.

It may define role, Driver requirements, trusted base instructions, tools,
delegable tools, allowed child Templates, capability ceilings, resource
ceilings, and a schema for untrusted task input.

An Executor may choose only permitted Template identities and provide validated
task input. It cannot construct trusted instructions, executable paths,
capabilities, or tool definitions.

Changing trusted Template content creates a compatibility boundary. Existing
Sessions do not silently adopt it.

## Instance

An Instance is one concrete Executor binding for a Participant. It records
Driver identity, locator or handle, connection and health state, capabilities,
creation attempt, and evidence required for safe inspection or termination.

A Participant may have historical Instances but at most one current Instance.

## Operation

An Operation is one unit of work processed by a Participant.

Public states:

    queued -> starting -> running
                           +-> waiting
                           +-> cancelling
                           +-> succeeded
                           +-> failed
                           +-> cancelled
                           +-> blocked
                           +-> uncertain

Implementations may add internal states but preserve these meanings publicly.
An Operation is unfinished until it has a committed terminal outcome.
Uniqueness is enforced from unfinished status, not a fragile list of active
state names.

A terminal outcome is immutable. Continuing later creates a new explicitly
correlated Operation.

## Message and Mailbox

A Message is a durable envelope with stable identity, Session, source,
destination, mailbox sequence, kind, bounded payload, correlation, creation
time, and delivery state.

Every Participant has an ordered durable Mailbox. Sequence is monotonic. Leasing
does not remove a Message. Acknowledgement commits accepted delivery. An expired
lease permits redelivery. Accepted identities remain deduplicable while
redelivery is possible. Control Messages may have explicit precedence over
ordinary FIFO work.

## Artifact

An Artifact is a durable reference to bounded content outside ordinary Message
payloads. Metadata includes identity, Session, media type, size, cryptographic
hash, storage-relative locator, and retention data.

Implementations protect against traversal, aliasing, symlink escape, oversize,
and hash mismatch.

## Event

An Event is an immutable fact emitted after its underlying transition commits.
It has identity, Session, ordered position, type, schema version, related
identities, bounded redacted data, and timestamps.

Events never contain secrets or unbounded Executor output.

## Request identity

Every mutable public request has stable identity. The durable record binds
caller, action, semantic input digest, effect phase, and result or failure.
Reusing identity with different semantic input is a conflict.

## Grant

A Grant is trusted, scoped, expiring authorization. It is issued only through a
trusted boundary, bound to subject/action/resource/Session, no broader than its
issuer, atomically consumed when single-use, and invalid after expiration or
revocation.
