---
status: verified
slice: 10-tools-artifacts
depends_on:
  - plans/09-python-sdk/02-managed-local.md
  - plans/07-recovery/01-effect-journal.md
specs:
  - docs/consumer-api.md
---

# Task: Implement Consumer Tool provider

## Outcome

Persist a Tool invocation before dispatching it to an authenticated Consumer
handler.

## Implementation

- Register stable Tool name, version, schemas, authority, timeout, and effect
  class.
- Validate input before reservation.
- Correlate reconnect and duplicate response.
- Apply recovery rules from declared effect class.
- Translate bounded typed result or failure.

## Verification

- Consumer disconnect before and during handler.
- Duplicate invocation and response are idempotent.
- Non-idempotent uncertain invocation cannot be replayed.
- Unauthorized Instance cannot call Tool.

## Done

Consumer domain behavior remains outside Navigator but gains durable invocation.
