---
status: verified
slice: 09-python-sdk
depends_on:
  - plans/09-python-sdk/02-managed-local.md
specs:
  - docs/consumer-api.md
---

# Task: Publish executable Python acceptance examples

## Outcome

Provide tested examples for open, run, subscribe, cancel, resume, and reset.

## Verification

- Examples execute in isolated environment.
- Type checker and formatter pass.
- Event reconnect resumes from saved position.
- Same example can switch from local to external endpoint through configuration.

## Done

The Consumer contract is demonstrably usable without internal knowledge.
