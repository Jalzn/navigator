---
status: verified
slice: 06-cancellation-shutdown
depends_on:
  - plans/05-hierarchy-policy/03-hierarchical-flow.md
specs:
  - docs/execution.md
---

# Task: Persist and propagate cancellation

## Outcome

Cancellation becomes an idempotent durable protocol with explicit outcomes.

## Implementation

- Persist request before Driver notification.
- Give control delivery precedence over ordinary work.
- Cascade only within the selected subtree.
- Translate Driver acknowledgement separately from terminal cancellation.
- Make repeated cancellation return current state.

## Verification

- Cancel during queue, launch, delivery, running, waiting, and result commit.
- Duplicate request produces no duplicate effect.
- Unaffected sibling continues.
- Late success report follows defined cancellation race rule.

## Done

Every cancellation race has one durable explainable outcome.
