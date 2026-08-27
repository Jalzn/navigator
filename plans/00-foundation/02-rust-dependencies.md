---
status: verified
slice: 00-foundation
depends_on:
  - plans/00-foundation/01-workspace.md
specs:
  - docs/README.md
---

# Task: Pin and govern dependencies

## Outcome

Turn DEPENDENCY-MAP.md into a minimal pinned workspace dependency set.

## Implementation

- Add only crates required by the current slice.
- Centralize versions and feature flags in the workspace manifest.
- Disable default features and opt back into only the audited `std`, derive,
  macro, timeout, and property-test facilities used by this slice.
- Configure cargo-deny for advisories, licenses, sources, and duplicates.
- Record exceptions with reason, owner, and expiry.
- Add an update procedure requiring tests and protocol fixture comparison.

## Verification

- `mise exec -- cargo deny check` passes with registry, advisory, license, and
  duplicate-version policy from `deny.toml`.
- `mise exec -- cargo machete` reports no unused direct dependency.
- Feature tree contains no accidental TLS, HTTP server, or database backend.
- License output is suitable for redistribution.
- `scripts/update-dependencies.sh` runs the full gate and rejects byte-level
  drift in committed protocol fixtures until it receives an explicit
  compatibility review.

## Procedure

1. Run `scripts/update-dependencies.sh`.
2. Review the `Cargo.lock` diff, duplicate versions, features, advisories, and
   licenses even when the automated gate passes.
3. If a fixture must change, review backward and forward compatibility first,
   update the fixture in the protocol-owning slice, then rerun the procedure.
4. Record any `deny.toml` exception with its reason, owner, and expiry. Path
   dependencies are governed by the workspace architecture gate and are the
   only reason wildcard dependency sources remain allowed.

`Zlib` is allowed because SQLx 0.9's reviewed hash table dependency uses this
OSI-approved permissive license. It is a license baseline, not a policy bypass;
ownership remains with the Store slice and is re-reviewed on SQLx updates.

`BSD-3-Clause` is allowed because the local authentication boundary uses
`subtle` for constant-time credential comparison. The license is OSI-approved
and permissive; ownership remains with the local transport slice and is
re-reviewed whenever that dependency changes.

`navigator-consumer-protocol` suppresses `cargo-machete`'s report for
`tonic-prost` because the generated Tonic source in `OUT_DIR` references its
codec directly. Removing it breaks a clean build; the suppression is scoped to
that generated-code dependency.

`nix` 0.30.1 is pinned with only `process` and `signal` enabled so the Unix
supervisor can address an owned process group through reviewed safe APIs. HMAC
0.12.1 and SHA-256 bind Instance readiness to the launch identity and a fresh
challenge without transmitting the bootstrap credential.

## Done

The implementation has a reviewed dependency baseline and automated drift gate.
