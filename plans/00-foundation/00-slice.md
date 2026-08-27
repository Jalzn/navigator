---
status: verified
slice: 00-foundation
depends_on: []
specs:
  - docs/README.md
  - docs/compatibility.md
---

# Slice: Foundation

## Outcome

A clean checkout builds the dependency-free domain kernel, protocol kernel, and
semantic conformance harness, then produces deterministic quality evidence.

## Demonstration

One command builds every current crate offline, runs generated semantic traces
against the domain subject, proves deliberately broken subjects are rejected,
validates protocol-kernel boundaries, and runs quality policy.

## Scope

- minimal workspace and crate boundaries;
- shared identity, clock, error, and revision types;
- protocol version, identity, bounds, negotiation, and correlation kernel;
- reusable semantic harness infrastructure and first domain suites;
- CI-equivalent local command.

## Excluded

No generated Consumer/Driver operations, Store, Driver process, RPC server, or
Consumer feature is delivered. Concrete contract suites are added by the slice
that defines each contract.

## Exit gate

- all tasks are verified;
- no domain crate depends on storage, transport, CLI, or adapter crates;
- protocol-kernel fixtures and negotiation behavior are deterministic;
- test and lint commands succeed from a clean checkout.
