# Navigator implementation plans

Status: temporary execution material.

This directory describes how the current implementation is expected to reach
the contracts in ../docs. It is deliberately mutable and may be rewritten or
deleted after delivery. It never overrides the canonical specifications.

## Planning unit

Each numbered directory is a vertical slice. A slice ends in externally
observable behavior that can be demonstrated and verified. It includes only the
domain, persistence, protocol, API, and operational work needed for that result.

Every slice contains:

- 00-slice.md: outcome, boundaries, dependencies, demo, and exit gate;
- numbered task files: independently reviewable implementation tasks.

Task ordering is local to a slice. Cross-slice dependencies use full relative
paths.

## Status lifecycle

    proposed -> approved -> in_progress -> implemented -> verified

Only verified work satisfies a slice exit gate. Code completion without the
specified evidence remains implemented, not verified.

## Required task structure

Every task records:

- outcome;
- canonical specifications covered;
- dependencies;
- scope and explicit exclusions;
- implementation notes;
- verification and fault cases;
- review evidence;
- definition of done.

## Vertical-slice rule

A task may be technical, but a slice MUST deliver a user- or integration-visible
capability. Horizontal infrastructure without a consumer is not a completed
slice.

## Review rules

- Review the 00-slice.md before approving its tasks.
- Reject code that weakens a canonical guarantee to simplify implementation.
- New dependency choices are recorded in 00-foundation/02-rust-dependencies.md.
- Any protocol shape must include versioning and bounded-input behavior.
- Every mutable effect has a fault test before its slice is verified.
- Test doubles prove core semantics; a real adapter proves integration claims.
- Defaults belong to implementation configuration, not canonical docs.

## Semantic testing strategy

Tests are executable specifications, not patch gates. Every test MUST name the
canonical invariant it proves and the incorrect behavior it would reject.

The default construction order is:

1. state the semantic law or scenario in implementation-independent terms;
2. define observations and forbidden effects;
3. implement a reference model or contract fixture where applicable;
4. prove the test fails against a deliberately broken implementation;
5. run the same suite against every implementation of the boundary;
6. add fault points around every commit and external effect;
7. retain the minimized counterexample as a regression scenario.

Coverage, function-level mocks, and green patch checks are supporting signals,
never proof of correctness. See ../docs/testing.md.

## Planned sequence

| Slice | Demonstrable outcome |
|---|---|
| 00 Foundation | Reproducible workspace and executable conformance harness |
| 01 Durable Session | Open, inspect, close, and exclusively own a local Session |
| 02 Driver Contract | Run the language-neutral Driver contract against a fake |
| 03 First Operation | Execute one Operation end-to-end through the fake Driver |
| 04 Reliable Messaging | Survive disconnect and redelivery without duplicate acceptance |
| 05 Hierarchy and Policy | Delegate a bounded child and reject escalation |
| 06 Cancellation | Cancel and shut down a verified owned subtree |
| 07 Recovery | Reconcile crashes and block uncertain effect replay |
| 08 Pi Driver | Execute the same contract through a real Pi-backed Driver |
| 09 Python SDK | Control a managed local Navigator from Python |
| 10 Tools and Artifacts | Invoke a Consumer Tool and exchange validated Artifacts |
| 11 Approvals and Observability | Complete trusted approval and durable event views |
| 12 Hardening | Prove resource bounds, compatibility, and release readiness |

## Completion policy

A slice is verified only when:

1. its acceptance scenario runs from a clean checkout;
2. required automated tests pass;
3. declared fault cases pass deterministically;
4. public behavior matches docs;
5. evidence named in the slice exists;
6. no deferred item is required for the claimed outcome.
