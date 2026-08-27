# Vertical 00 — Package foundation

## Outcome

`runtime/` is an independent Python workspace package named `arara-runtime`,
imported as `arara_runtime`, with stable configuration models, typed errors, and
foundational value objects. It contains no consumer-domain knowledge.

## End-to-end proof

A tiny neutral consumer installs the wheel from a clean directory, imports only
the documented foundation surface, validates a complete Coordinator → Campaign
→ Worker catalog, serializes it canonically, and receives safe typed failures for
invalid input. It creates no process, socket, database, task, or Session.

## Scope

- correct the root distribution naming conflict;
- add `runtime/` to the uv workspace;
- package metadata and supported Python/core platforms; Node belongs to the Pi
  adapter slice;
- deeply immutable Pydantic configuration models for roles, templates, policies,
  limits, and protocol-safe IDs;
- `RuntimeFailure`, closed error codes, safe redaction, and boundary translation;
- deterministic ID seam for tests;
- package exports and minimal documentation.

`Store` is promoted in slice 02, while `AgentLauncher`, `AgentChannel`, Runtime
lifecycle, and operational snapshots are promoted with their first real
adapters. They remain part of the target architecture but are not frozen around
foundation-only fakes.

## Invariants

- roles are `coordinator`, `campaign`, and `worker`;
- topology is opinionated but domain payloads remain opaque;
- models cannot supply prompts, executables, extension paths, tools, or secrets;
- native cancellation and programmer errors are not converted to domain errors;
- importing or validating foundation values performs no I/O or background work.

## Acceptance

- package installs alone and through the root workspace;
- imports expose only documented symbols;
- invalid topology, limits, paths, and extra fields fail closed;
- redaction tests contain representative tokens, environment values, and paths;
- unexpected exceptions and native cancellation are never translated by the
  error projection helpers;
- existing workspace test discovery remains unchanged.

## Adversarial review

- search the package for consumer-domain vocabulary and behavior;
- attempt mutable access through every frozen public model;
- inject unknown error codes and oversized/untrusted display strings;
- confirm no unproved infrastructure seam is re-exported prematurely;
- remove any abstraction that exists only to wrap one function without policy.

## Excluded from this slice

Runtime Session lifecycle and status transitions, public infrastructure
protocols, Pi, WebSocket, SQLite schema, subprocess ownership, mailboxes,
approvals, artifacts, rendering, and consumer migration.
