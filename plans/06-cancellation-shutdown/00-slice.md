---
status: verified
slice: 06-cancellation-shutdown
depends_on:
  - plans/05-hierarchy-policy/00-slice.md
specs:
  - docs/execution.md
---

# Slice: Cancellation and Shutdown

## Outcome

A Consumer cancels one active subtree and Navigator shuts it down child-first
without signaling an unrelated process.

## Demonstration

Run two sibling Campaign subtrees, cancel one, prove the other continues, then
close the Session and observe ordered child-before-parent termination.

## Exit gate

Cancellation states, control priority, graceful and forced stop, ownership
verification, and shutdown leak tests pass.
