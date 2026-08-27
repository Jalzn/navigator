---
status: verified
slice: 08-pi-driver
depends_on:
  - plans/07-recovery/00-slice.md
specs:
  - docs/drivers.md
---

# Slice: Pi Driver

## Outcome

The first real Driver executes the same Operation and recovery scenarios against
Pi without adding Pi concepts to Navigator core.

## Demonstration

Run an interactive root and a headless child. Deliver work, invoke a generic
Navigator command, report explicit success, disconnect at acceptance, reconnect,
and shut down on ownership loss.

## Exit gate

The Pi adapter passes the Driver conformance suite plus native integration tests
for every claimed capability.
