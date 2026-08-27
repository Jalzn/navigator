# Semantic verification

## Purpose

Navigator tests are executable statements of system meaning.

Their primary purpose is to prove that an implementation preserves canonical
invariants and externally observable semantics under valid use, concurrency,
failure, retry, recovery, and incompatible input.

Tests are not primarily a patch-acceptance mechanism. A test suite that merely
confirms the current implementation, mirrors its functions, or increases
coverage without proving behavior is insufficient.

## Semantic test rule

Every important test answers all of these questions:

1. Which canonical guarantee is being exercised?
2. What observation would prove that guarantee to a Consumer or Driver?
3. Which alternative incorrect implementation must the test reject?
4. Which state and effect boundaries influence the outcome?
5. Is the assertion independent of private implementation structure?

If these questions cannot be answered, the test is not evidence of conformance.

## Test layers

### Domain laws

Domain tests express laws that hold for every implementation:

- authority never increases through delegation;
- a Participant has at most one unfinished Operation;
- terminal outcomes are immutable;
- a stale ownership epoch cannot mutate state;
- acceptance never implies completion;
- uncertainty is never classified as safe without proof.

These tests favor state-machine and property-based exploration over isolated
examples.

### Contract suites

Every replaceable boundary has one shared semantic suite. All Store, Driver,
transport, and Consumer protocol implementations run the same suite.

Contract tests observe inputs, committed facts, outputs, and allowed failures.
They do not depend on private tables, functions, task scheduling, or native
Executor types.

### Scenario tests

Scenarios describe meaningful stories spanning boundaries, such as:

- a Consumer starts work and receives one explicit outcome;
- a Message is accepted before a disconnect and is not injected twice;
- two hosts race for one Session and only one epoch can write;
- a child attempts to escalate authority and the effect never begins;
- a non-idempotent Tool disconnects after effect start and resume blocks replay.

A scenario asserts both the intended result and the absence of forbidden side
effects.

### Fault-boundary tests

Every transition involving durable commit and external effect is tested with
failure before and after each boundary. Tests verify resulting classification,
not merely that restart succeeds.

Fault points are stable semantic names. A fault matrix records intended effect
phase, durable facts, allowed recovery, and forbidden action.

### Adapter conformance

Fakes prove Navigator semantics deterministically. They do not prove a real
Executor behaves like the fake.

Every real Driver runs the shared contract suite and native compatibility tests
that prove its claimed durability boundary, lifecycle translation,
deduplication, cancellation, and ownership-loss behavior.

### Model-based tests

Stateful subsystems SHOULD have a small reference model. Generated command
sequences execute against both model and implementation and compare observable
state.

This is especially important for Operations, Mailboxes, leases, Grants,
capacity reservations, and recovery classification.

## Assertions

Tests SHOULD assert:

- durable snapshots and ordered Events;
- typed outcomes and stable error codes;
- permitted and forbidden effects;
- idempotency under repetition;
- behavior after restart and reconnection;
- equivalence across implementations of one contract.

Tests SHOULD NOT rely primarily on:

- private function call counts;
- exact internal task ordering without semantic meaning;
- database row layout;
- sleeps as synchronization;
- broad snapshots of incidental output;
- mocks that return the result the implementation expects;
- coverage percentage as proof of correctness.

## Determinism

Time, identity generation, scheduling decisions, capacity, and fault injection
must be controllable in semantic tests. Concurrency tests use explicit barriers
and observable state rather than timing guesses.

A failing randomized or property test records enough seed and command history to
reproduce and minimize the counterexample.

## Mutation resistance

Critical semantic suites SHOULD be evaluated with deliberate broken
implementations or mutation testing. A meaningful suite rejects at least:

- acknowledgement before durable acceptance;
- missing fencing check;
- duplicate unfinished Operation;
- authority union where intersection is required;
- automatic retry of uncertain effect;
- terminal result inferred from idleness.

Passing tests after one of these mutations indicates a gap in the specification
evidence.

## Traceability

`[NAV-TRACE-001]` Every canonical MUST-level guarantee maps to one or more semantic tests. Every
test names the specification section and invariant it proves.

Traceability is bidirectional:

- specification to evidence shows that guarantees are implemented;
- test to specification prevents accidental tests from becoming undocumented
  product requirements.

## Review standard

A code change is accepted because its behavior satisfies reviewed semantics, not
because an AI or developer made the existing test suite green.

When implementation and a valid semantic test disagree, the implementation is
fixed. When the test encodes no canonical guarantee, the test is revised or
removed rather than turning incidental behavior into contract.
