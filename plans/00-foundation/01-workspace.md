---
status: verified
slice: 00-foundation
depends_on: []
specs:
  - docs/architecture.md
---

# Task: Create the Rust workspace

## Outcome

Establish only domain, protocol, and conformance crates. Later crates are created
when their slice gives them executable behavior.

## Implementation

- Create one workspace manifest with a pinned minimum Rust toolchain.
- Add navigator-domain as a leaf, navigator-protocol as a wire kernel, and
  navigator-conformance as an external semantic oracle.
- Document the future target graph without creating empty architectural shells.
- Add deny, format, lint, test, and coverage configuration.
- Document the allowed dependency direction in the workspace README.

## Verification

- cargo build and cargo test work with no services running.
- A dependency graph check proves domain has no infrastructure dependencies.
- Formatting and warnings-as-errors lint pass.
- A clean build does not require network after dependencies are fetched.

## Evidence

Workspace graph, command transcript, and CI configuration.

## Done

The minimal architecture compiles and boundary violations have an automated
check.
