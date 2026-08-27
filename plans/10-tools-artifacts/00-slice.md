---
status: verified
slice: 10-tools-artifacts
depends_on:
  - plans/09-python-sdk/00-slice.md
specs:
  - docs/consumer-api.md
  - docs/domain-model.md
---

# Slice: Tools and Artifacts

## Outcome

A Pi Worker invokes a Python Consumer Tool and returns a validated Artifact
without placing large content in Messages.

## Demonstration

Register one idempotent Tool, disconnect the Consumer during invocation,
reconnect, return one Artifact, verify its hash, and deliver its reference.

## Exit gate

Tool effect phases, schema validation, reconnect, Artifact integrity, quotas,
and path-security tests pass.
