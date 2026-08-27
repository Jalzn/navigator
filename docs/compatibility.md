# Compatibility and conformance

## Versioned boundaries

Navigator versions all boundaries that cross process, language, persistence, or
release lines:

- Consumer protocol;
- Driver protocol;
- Event schemas;
- Artifact metadata;
- durable storage schema;
- Template compatibility identity.

Internal module interfaces need not be public protocols.

## Compatibility rule

A newer implementation may accept older compatible input and add optional
output. It does not change the meaning of existing fields, states, errors, or
capabilities.

Required unknown behavior fails negotiation before mutable effects.

## Protocol negotiation

Peers exchange supported protocol ranges and capabilities before work. They
select one mutually supported version. No overlap results in a typed
incompatible-protocol failure.

Negotiation cannot be controlled by untrusted Executor task input.

## Schema evolution

Compatible changes include adding optional fields, new Event types that
subscribers may ignore, new capabilities, and new typed errors for previously
unspecified cases.

Breaking changes include removing or renaming fields, changing field meaning,
weakening guarantees, reusing identifiers, changing terminal outcome meaning,
or making previously optional behavior required without negotiation.

## Session compatibility

A Session is bound to a compatibility identity derived from trusted Templates,
policy, protocol requirements, and other behavior-defining configuration.

A Session does not silently continue across an incompatible identity. The
Consumer must migrate through a defined procedure, resume under proven
compatibility, or reset to a new Session.

Credentials and secret values are never included in the identity.

## Durable migrations

Storage implementations use forward, transactional, versioned migrations.
Unknown newer schema versions fail closed without writes. Migration failure
leaves the previous committed state readable or recoverable.

Logical deletion, retention, backup, and physical erasure remain distinct.

## Stable errors

Error codes are a closed versioned registry. Codes are never repurposed.
Additional redacted details may evolve compatibly. Retry classification is part
of the public contract.

At minimum, the registry distinguishes validation, authentication,
authorization, conflict, capacity, timeout, unavailable, unsupported,
incompatible, cancelled, uncertain effect, cleanup required, corrupted state,
and internal failure.

## Conformance suites

A conforming implementation passes:

- domain transition tests;
- Store atomicity and fencing tests;
- Consumer protocol tests;
- Driver contract tests;
- delivery and deduplication fault tests;
- recovery tests at every commit/effect boundary;
- policy non-escalation tests;
- redaction and bounded-input tests;
- compatibility negotiation tests.

Claims are scoped. A Driver may conform on a subset of platforms or
capabilities, but it declares that subset precisely.

## Canonical change process

A change to these specifications states:

1. the problem and affected invariant;
2. whether behavior is compatible;
3. migration or negotiation requirements;
4. conformance tests that prove the new contract;
5. effects on existing Sessions.

Implementation convenience alone is not sufficient reason to weaken a
guarantee.
