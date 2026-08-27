---
status: verified
slice: 02-driver-contract
depends_on:
  - plans/01-durable-session/00-slice.md
specs:
  - docs/drivers.md
---

# Slice: Driver Contract

## Outcome

Navigator can start, inspect, deliver to, cancel, and stop a deterministic fake
Executor through the same language-neutral contract later used by Pi.

## Demonstration

Register a fake Driver, negotiate capabilities, start an Instance, deliver one
Message, observe acceptance, cancel, and stop it. Repeat with missing required
capability and prove failure occurs before launch.

## Exit gate

Protocol, authentication, capability negotiation, Instance identity, and Driver
conformance tests pass.
