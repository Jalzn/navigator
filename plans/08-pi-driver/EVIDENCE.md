# Slice 08 verification evidence

Status: verified by native Pi integration, the shared Driver conformance
oracles, real subprocess crash injection, a real Coordinator/Campaign/Worker
tree, adversarial test review, clean-source reproduction, and the complete
repository gate.

Authoritative run: `target/conformance/run.cxXveM`. Every stage in
`gate-results.tsv` passed.

## Capability and process boundary

- Node and the Pi SDK are pinned. The adapter advertises only capabilities
  backed by native executable proofs; terminal capability is conditional on the
  configured process mode.
- The generic trusted Driver catalog resolves both fake and Pi Drivers without
  a Pi branch in Navigator core. Unknown, untrusted, or capability-mismatched
  entries fail before process creation. Required capabilities are repeated in
  the authenticated `Start` request and checked by the Driver.
- Bootstrap credentials are captured then removed from inherited environment.
  Instance readiness binds Driver, Session, Participant, launch attempt,
  Instance, and ownership epoch. Forged bindings and authentication replay fail
  while an authenticated channel remains usable.

## Durable acceptance and recovery

- The v3 append-only inbox persists the exact Message, delivery attempt,
  Operation, prompt digest, and Instance binding before acknowledging
  acceptance. Replay with a new RPC identity does not inject twice; mutation of
  any semantic identity conflicts.
- A deterministic FD4 fault controller proves the exact `before_append`,
  `after_fsync`, and volatile-receipt windows. Each armed generation must report
  the exact reached frame, be killed, and be reaped by `SIGKILL`; mismatched
  frames and EOF mark the generation failed and prohibit restart.
- Restart under the same persistent binding proves `NotAccepted` before the
  durable boundary, `Accepted` after fsync without duplicate native delivery,
  and no invented acceptance after volatile receipt.
- Ownership EOF is observed while the process is alive and no fault is armed.
  The oracle always waits for reap and proves the post-EOF Message is absent
  from every inbox and the native delivery observer, even when reconnect fails.

## Native Pi semantics

- Deterministic native-provider tests cover headless and PTY lifetimes, idle and
  mid-turn delivery, explicit report tools, cancellation, disposal, and bounded
  ownership loss. Settlement is never interpreted as an Operation outcome.
- Bounded fail-closed observers correlate native prompt delivery by Message,
  attempt, and digest. Malformed, reordered, orphaned, duplicate, or conflicting
  hierarchy results do not become accepted Navigator results.
- The adapter passes the shared normative Driver base and durable-acceptance
  suites rather than a Pi-specific approximation.

## Real hierarchy

- A real interactive root creates headless Campaign and Worker Instances through
  generic spawn. Work and explicit results travel through the exact parent
  Operations; a sibling Campaign remains isolated.
- The journal oracle parses every line fail-closed, decodes the canonical
  protobuf command/result, and checks exact request, Template, Grant, parent,
  child, Operation, and input-Message identities. Field-mutant fixtures are
  rejected.
- Shutdown evidence proves depth order Worker, Campaign, root and verifies no
  owned Pi process or process group remains.

## Repository gate

The authoritative gate passed `format`, `clippy`, `semantic-evidence`,
`semantic-tests`, `driver-typescript`, `pi-driver-typescript`, `offline-build`,
`python-sdk`, `clean-source`, `architecture`, `supply-chain`, and
`unused-dependencies`. The independent concurrency gate also ran two complete
isolated gates and proved both evidence directories, every log, atomic `latest`
publication, and absence of temporary publisher state.
