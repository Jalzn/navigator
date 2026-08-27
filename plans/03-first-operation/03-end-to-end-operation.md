---
status: verified
slice: 03-first-operation
depends_on:
  - plans/03-first-operation/02-operation-state-machine.md
specs:
  - docs/consumer-api.md
  - docs/communication.md
---

# Task: Connect Consumer request to Driver result

## Outcome

Wire Consumer start, scheduler, Instance, delivery, report, snapshot, and Events
into one complete flow.

## Implementation

- Add bounded execution-capacity acquisition.
- Ensure ready Instance or launch it.
- Deliver Operation input through a durable Message.
- Accept progress but require explicit terminal report.
- Return typed failure when Executor settles without report after one bounded
  reminder or deadline.

## Verification

- Black-box success and explicit failure scenarios.
- Idle-without-result cannot succeed.
- Consumer disconnect does not cancel durable work.
- Restart Consumer and observe committed terminal state.

## Done

Navigator delivers its first externally observable autonomous work result.
