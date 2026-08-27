---
status: verified
slice: 00-foundation
depends_on:
  - plans/00-foundation/03-domain-kernel.md
specs:
  - docs/compatibility.md
  - docs/testing.md
---

# Task: Build the conformance harness

## Outcome

Create reusable semantic harness infrastructure and the first Operation,
authority, fencing, clock, recovery-classification, and protocol-kernel suites.
Store, Driver, and Mailbox suites are added when those contracts exist.

## Implementation

- Define black-box subject traits and an independent Operation reference model.
- Give each case a semantic invariant ID and specification reference.
- Add the first reference models for Operation, fencing, and authority laws.
- Add deterministic fake Clock, identity source, and fault injector.
- Make every fault point addressable by stable name.
- Produce machine-readable and human-readable results.
- Include a deliberately broken fake to prove the harness catches violations.

## Verification

- The domain Operation subject matches the independent reference model over
  generated command histories.
- Broken fencing, authority-union, and idle-as-success subjects fail at named
  assertions.
- Boundaries and classification laws without a replaceable subject are reported
  as properties, not mutation evidence.
- Fake time, deterministic identity, named faults, and retained minimized
  Proptest regressions reproduce failures.

Acknowledgement mutants belong to Reliable Messaging, redaction subjects to the
boundary that emits diagnostics, and uncertain-replay mutants to Recovery. They
are not counted as Foundation evidence before those contracts exist.

## Done

Later tasks extend and run this shared harness; no empty future suite is counted
as evidence.
