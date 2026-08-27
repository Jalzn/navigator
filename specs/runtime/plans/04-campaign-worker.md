# Vertical 04 — Coordinator → Campaign → Worker

## Outcome

The opinionated hierarchy performs one complete delegation and explicit result
return without consumer-domain semantics.

## End-to-end proof

Coordinator creates a Campaign, the Campaign creates one Worker, the Worker
executes an allowlisted faux task, explicitly reports its result, the Campaign
synthesizes it, and the Coordinator presents it to the user.

## Scope

- enforce relationships `Coordinator → Campaign`, `Campaign → Worker`, and
  policy-authorized `Worker → Worker`;
- immutable TemplateCatalog and task-schema validation;
- spawn, status, cancel, and explicit terminal report mechanics;
- role-specific prompts and tool ceilings;
- capacity limits for campaigns, children, depth, total Agents, and concurrent
  operations;
- result propagation through each direct parent;
- one bounded reminder followed by `missing_result` when a settled child fails
  to report.

## Invariants

- idle/settled is never interpreted as success;
- terminal outcomes are completed, failed, blocked, or cancelled;
- model-selected task data cannot alter template authority;
- siblings and separate Campaign branches do not communicate directly;
- capacity reservation and Agent creation cannot produce duplicate nodes;
- cancellation cascades child-before-parent.

## Acceptance

- one happy path through all three roles;
- Worker child creation allowed and denied by template;
- invalid role edge, depth, capacity, and task schema fail before spawn;
- explicit success/failure/blocked/cancelled reports;
- missing report reminder fires once and terminates predictably;
- parent death and child death produce consistent graph state;
- two Campaigns run concurrently without crossing results.

## Adversarial review

- attempt authority escalation at every generation;
- race two spawn requests at the final capacity slot;
- report another Agent's operation ID;
- create cancellation/report races;
- verify the hierarchy supports two distinct neutral consumer configurations
  without introducing domain vocabulary.

## Excluded from this slice

Full durable mailbox retry, approvals, artifacts, semantic checkpoints, PRs, and
consumer migrations.
