# Adversarial review round 1

Status: findings incorporated, exit gate still open.

## Review team

- Rust architecture reviewer;
- semantic and model-based testing reviewer;
- protocol and Pi-boundary reviewer.

## Decisions

- Foundation contains only domain, protocol-kernel, and conformance crates.
- Store API, Driver API, core, server, and CLI are created by their owning slice.
- Wire operations are not invented before Consumer and Driver slices.
- Protocol Foundation covers raw frame bounds, version-range negotiation,
  required features, identity binding, and correlation primitives.
- Real contract mutants implement the same subject trait; local constants do not
  count as mutation evidence.
- Pi remains constrained by the generic Driver contract and advertises only
  capabilities proven against native behavior.

## Findings corrected

- Operation fields made private.
- Operation transitions now accept semantic actions, preventing Resume from
  being confused with initial ReportRunning.
- Revision, fencing epoch, capability, and identity validation cannot be bypassed
  by deserialization.
- identity generation is injectable rather than ambient.
- raw frame size is checked before decode.
- version ranges negotiate a mutual version.
- required feature duplicates and unknown requirements fail closed.
- semantic digest is domain-separated.
- public error debug and display redact message text.
- property-generated Operation traces found and prevented a real semantic bug.
- authority-union and missing-fence mutants now implement shared subject traits.

## Findings intentionally deferred

- Store, Mailbox, Driver, ACK, and recovery-executor mutants belong to the slices
  that first implement those contracts.
- Protobuf schemas and generated Rust/TypeScript code belong to Driver and
  Consumer protocol slices.
- Pi mid-turn durable acceptance remains an unproven capability until the Pi
  spike.

## Remaining Foundation gate

- pin exact toolchain and dependency versions;
- add automated dependency-direction check;
- add cargo-deny policy and aggregate local gate;
- add traceability matrix for implemented invariants;
- rerun a final independent review after these items.
