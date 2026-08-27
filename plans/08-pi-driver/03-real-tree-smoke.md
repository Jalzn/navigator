---
status: verified
slice: 08-pi-driver
depends_on:
  - plans/08-pi-driver/02-typescript-adapter.md
specs:
  - docs/architecture.md
---

# Task: Prove a real Pi hierarchy

## Outcome

Run Coordinator, Campaign, and Worker policy roles using three Pi Instances.

## Verification

- Root interactive Instance creates Campaign through generic spawn.
- Headless Campaign creates Worker and remains alive without terminal.
- Instruction reaches Worker and explicit result returns through each parent.
- Concurrent sibling Campaign remains isolated.
- Session shutdown ends Worker, Campaign, then root.

## Done

The first real Executor proves the generic Navigator design end to end.
