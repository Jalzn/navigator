---
status: verified
slice: 08-pi-driver
depends_on:
  - plans/08-pi-driver/01-pi-capability-spike.md
  - plans/07-recovery/03-resume-resolution.md
specs:
  - docs/drivers.md
  - docs/communication.md
---

# Task: Implement Pi Driver adapter

## Outcome

Build a small TypeScript process implementing generated Driver protocol bindings.

## Implementation

- Add trusted generic Driver catalog/configuration to `navigatord`; Pi is the
  first catalog entry, never a special case in core or the server binary.
- Translate trusted Template config to Pi session construction.
- Register only allowed Navigator and coding Tools.
- Bind launch attempt and Participant identity before readiness.
- Map delivery identity into Pi persisted session data.
- Translate progress and explicit reports without treating settlement as result.
- Remove bootstrap secrets from inherited environment after capture.

## Verification

- Reject missing, unknown, model-selected, and capability-mismatched catalog
  entries before process launch; prove the generic fake Driver can use the same
  configuration path.
- Run generic Driver conformance suite against the adapter.
- Forge identity, replay credential, and exceed frame bounds.
- Disconnect in request, delivery, acceptance, report, and shutdown phases.
- Prove no Pi type is serialized into Navigator domain records.

## Done

Pi is replaceable without modifying core domain or Store crates.
