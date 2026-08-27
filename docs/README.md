# Navigator specifications

Status: canonical.

This directory is the source of truth for Navigator. It defines the identity,
boundaries, vocabulary, invariants, and externally observable contracts of the
project.

Code, tests, examples, roadmaps, and adapters must conform to these documents.
When an implementation disagrees with these specifications, the implementation
is wrong. Changing a canonical guarantee requires an explicit specification and
compatibility decision before changing code.

## What belongs here

These documents contain decisions intended to remain stable across programming
languages, frameworks, deployments, storage engines, transports, executors,
model providers, and consumer applications.

Temporary plans, dependency choices, milestones, spikes, and adapter-specific
details do not belong here.

## Reading order

1. [vision.md](vision.md): purpose, thesis, scope, and product identity.
2. [principles.md](principles.md): permanent principles and guarantees.
3. [architecture.md](architecture.md): boundaries and responsibilities.
4. [domain-model.md](domain-model.md): canonical entities and invariants.
5. [execution.md](execution.md): lifecycle, delegation, cancellation, recovery.
6. [communication.md](communication.md): messages, events, delivery, ordering.
7. [drivers.md](drivers.md): language-neutral executor integration.
8. [consumer-api.md](consumer-api.md): SDK semantics for products.
9. [policy-security.md](policy-security.md): authority and trust boundaries.
10. [compatibility.md](compatibility.md): evolution and conformance.
11. [testing.md](testing.md): semantic verification philosophy.
12. [glossary.md](glossary.md): normative terminology.

## Normative language

`[NAV-DOC-001]` MUST and MUST NOT express requirements for conformance. SHOULD and SHOULD NOT
express expected behavior unless a documented reason justifies a deviation
without violating an invariant. MAY expresses optional behavior.

Examples are illustrative. Normative prose and declared invariants take
precedence.

## Governance

- Concepts receive stable names before public APIs expose them.
- Public identifiers and error codes are never silently repurposed.
- New implementations may add capabilities but may not weaken guarantees.
- Adapter limitations are represented by capabilities, never hidden.
- Deployment-specific features do not leak into the domain model.
- Historical material outside this directory is not authoritative.
