---
status: verified
slice: 11-approvals-observability
depends_on:
  - plans/11-approvals-observability/02-operational-projections.md
specs:
  - docs/consumer-api.md
---

# Task: Add a read-only local inspector

## Outcome

Provide a bounded terminal view of tree, Operations, recent Events, capacity, and
recovery state without sharing output with an interactive Executor terminal.

## Verification

- Inspector reconnects and resumes.
- It performs no state-changing request.
- Rendering truncates unbounded values safely.
- It works in a separate terminal and non-interactive output mode.

## Done

Operators can observe Navigator without contaminating agent conversation.
