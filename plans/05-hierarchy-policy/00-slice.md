---
status: verified
slice: 05-hierarchy-policy
depends_on:
  - plans/04-reliable-messaging/00-slice.md
specs:
  - docs/architecture.md
  - docs/policy-security.md
---

# Slice: Hierarchy and Policy

## Outcome

A root Participant delegates a child from a trusted Template, sends work
downward, and receives the result upward. Escalation and sibling routing fail.

## Demonstration

Create Coordinator, Campaign, and Worker as policy roles over generic
Participants. Execute one Worker task and show denied excess depth, tool, and
cross-tree attempts.

## Exit gate

Topology, authority intersection, capacity, routing, and policy audit tests pass.
