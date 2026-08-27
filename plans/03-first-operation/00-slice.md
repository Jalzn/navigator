---
status: verified
slice: 03-first-operation
depends_on:
  - plans/02-driver-contract/00-slice.md
specs:
  - docs/execution.md
  - docs/consumer-api.md
---

# Slice: First Operation

## Outcome

A Consumer starts one Operation on one Participant; the fake Executor accepts
input, reports an explicit result, and the Consumer observes a durable terminal
snapshot and ordered Events.

## Demonstration

Run success, explicit failure, and native idle-without-result scenarios. Only
the explicit result succeeds.

## Exit gate

One-unfinished-Operation uniqueness, request idempotency, terminal immutability,
and Event publication are proven through the process boundary.
