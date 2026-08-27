# Vertical 10 — Runtime hardening and release

## Outcome

The independent Runtime package is internally complete, documented, and proven
on the currently approved macOS platform without depending on a consumer
migration for acceptance.

## End-to-end proof

A neutral example consumer opens a Coordinator, launches concurrent Campaigns
and Workers, exercises messaging, approval, artifacts, context management,
cancellation, crash recovery, explicit resume/reset, and orderly shutdown. The
entire scenario runs with the faux provider and no product-specific semantics.

## Scope

- neutral example templates for Coordinator, Campaign, Worker, and child Worker;
- one complete scenario covering all accepted Runtime subsystems;
- full Store, process, WebSocket, recovery, policy, artifact, approval, context,
  and observability suites on macOS;
- package and schema compatibility rules;
- Python, Node, and Pi version checks;
- installation, upgrade/reset, operations, recovery, and troubleshooting docs;
- dependency, license, security, secret, and filesystem audit;
- public API and specification consistency review;
- performance and resource measurements for documented conservative limits;
- release checklist and versioning policy.

## Invariants

- no consumer-domain vocabulary or behavior appears in Runtime implementation;
- the neutral example uses only public consumer inputs and APIs;
- every planned subsystem has an end-to-end acceptance path;
- infrastructure failure remains distinguishable from Agent-declared failure;
- unsupported platforms are not claimed;
- package installation does not depend on repository-global mutable state;
- no skipped blocking test is hidden by the final aggregate suite.

## Acceptance

- install `arara-runtime` from a clean local artifact and run the neutral example;
- run the full faux-provider hierarchy without external credentials;
- run concurrent Campaigns and nested Workers at documented limits;
- inject failure at Store, process, WebSocket, message, tool, artifact, approval,
  context, renderer, and shutdown boundaries;
- verify no permanent active state after every injected timeout/process loss;
- verify fresh open, idle reopen, explicit safe resume, uncertain-effect refusal,
  cancel, logical reset, backup, export, and close;
- run dependency audit with no unresolved high/critical finding;
- run secret scan and inspect built distributions for unintended files;
- `git diff --check`, lint, type checks, unit, contract, integration, and macOS
  smoke suites pass from a clean environment;
- documentation exposes one minimal start path and actionable recovery guidance.

## Adversarial review

- search source, schemas, prompts, fixtures, tests, and docs for consumer leakage;
- ask whether every public protocol has a credible substitution/testing purpose;
- inspect duplicate sources of truth between Pi and Runtime;
- attempt authority escalation through every role and persisted resume path;
- repeat the stuck-active failure pattern at each operation boundary;
- review dependencies, transitive size, licenses, vulnerabilities, and exit cost;
- run a clean-room operator test using only published documentation;
- identify planned features not exercised by the neutral scenario and block
  release until they are proven or explicitly moved beyond the release scope.

## Package completion gate

Runtime version 1 is complete when this vertical is accepted. Integrations must
have their own plans in their owning packages. Consumer migration may reveal
Runtime defects, but it is not part of this roadmap and cannot introduce
consumer semantics into the package.

## Deferred beyond version 1

Linux/Windows certification, distributed Agents, remote brokers, daemon mode,
automatic boot recovery, calendar scheduling, cross-machine coordination, and
consumer-specific migration or publication workflows.
