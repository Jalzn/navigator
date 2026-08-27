# Vertical review — `<ID and name>`

Status: `accept | corrections_required | blocked`

Date:
Reviewer(s):
Implementation reference:

## Outcome demonstrated

Describe the end-to-end behavior that was observed. Link commands, focused test
output, logs, screenshots, or artifacts required to reproduce it.

## Acceptance results

| Acceptance item | Result | Evidence |
|---|---|---|
| `<copied from the vertical plan>` | pass/fail | `<test or artifact>` |

Skipped blocking items make the review `corrections_required`; they are not
silently converted into follow-up work.

## Invariant audit

For each invariant in the vertical plan, record where it is enforced and which
test would fail if that enforcement were removed.

| Invariant | Enforcement | Failure test |
|---|---|---|
| | | |

## Failure injection

Record success, failure, timeout, cancellation, process loss, connection loss,
and crash-boundary results applicable to this slice.

| Boundary | Injected failure | Observed final state | Recoverable? |
|---|---|---|---|
| | | | |

## Security and authority

- caller identity and authentication:
- tool/capability ceiling:
- paths and filesystem effects:
- environment and credential exposure:
- untrusted payload bounds/redaction:
- post-effect validation:

## Concurrency and recovery

- ownership/lease/fencing behavior:
- duplicate request/delivery behavior:
- unfinished state terminal path:
- uncertain external effects:
- cleanup/orphan behavior:

## Simplicity review

- new dependencies and why each is justified:
- new public abstractions and their concrete consumers:
- duplicate sources of truth checked:
- layers or states removed during review:
- intentionally deferred optimizations:

## Observability

From one failed run, confirm whether an operator can determine:

- Session, Agent, operation, message, and request involved;
- whether failure came from model, tool, process, protocol, Store, policy, or
  consumer logic;
- whether an external effect occurred, did not occur, or is uncertain;
- the safe next action: retry, resume, cancel, reset, clean up, or intervene.

## Findings

### Blocking

- None.

### Non-blocking

- None.

Each finding must have an owner, correction slice, and acceptance test. A
blocking finding stays in the current slice.

## Specification changes

List normative documents changed because implementation disproved or clarified
an assumption. Absence of changes should be explicit.

## Decision

State why the slice is accepted or which exact corrections remain. Identify the
next vertical slice only when this one is accepted.

