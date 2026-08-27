---
status: verified
slice: 09-python-sdk
depends_on:
  - plans/03-first-operation/03-end-to-end-operation.md
specs:
  - docs/consumer-api.md
  - docs/compatibility.md
---

# Task: Generate and wrap Python protocol client

## Outcome

Provide typed async Session, Participant, Operation, Message, and Event clients.

## Implementation

- Generate Protobuf and gRPC code reproducibly.
- Wrap generated types with frozen Pydantic models.
- Map stable Navigator failures to one typed exception hierarchy.
- Preserve opaque identities and Event positions.
- Keep transport objects private.

## Verification

- Golden fixtures match Rust encoding.
- Unknown optional fields remain compatible.
- Cancellation propagates as native async cancellation where appropriate.
- Error mapping never leaks raw transport or secrets.

## Done

Python users interact only with stable Navigator concepts.
