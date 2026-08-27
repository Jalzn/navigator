# Resource limits evidence

Status: verified. An independent adversarial review returned GO for Task01 on
2026-08-26 after reviewing the implementation, focused tests, schema audit,
crash workers, and mutation coverage.

## Implemented boundary

`CapacityResource::ALL` is the single accounting vocabulary for Participants,
active and queued Operations, Messages and message bytes, Artifacts and
artifact bytes, retries, retained Events, pending requests, and subscriptions.
Admission reserves both per-Session and global capacity in one Store
transaction and reports typed per-Session or global exhaustion. Replay does not
reserve twice; release is idempotent.

Schema 20 is the reviewed Store schema. The capacity tables retain usage and
reservations across reopen. Migration `0020.sql` adds fenced, expiring
`subscription_leases` tied by foreign key to capacity reservations. Reopen
reclaims abandoned leases while a live owner remains protected; takeover is
epoch-fenced.

Artifact publication reserves count and bytes independently, converts the
reservations atomically with metadata publication, and keeps metadata erasure
separate from retained-byte cleanup. The zero-byte case consumes only the
Artifact-count reservation. Retained Events use the same exact session/global
accounting and replay is free.

The scheduler uses campaign-aware round-robin selection. The fairness test
keeps one subtree hot while proving that a peer Campaign is admitted. Dropped
or cancelled reservation futures roll back; subscription drop releases its
permit and setup failures surface as typed stream items.

## Fresh focused commands

These commands were run from the workspace root on 2026-08-26 with the shared
Task03 target directory. Counts below are Cargo's observed final counts.

```text
CARGO_TARGET_DIR=target/slice12-task03 cargo test -p navigator-store-sqlite capacity --lib --locked
6 passed; 0 failed; 0 ignored; 160 filtered out

CARGO_TARGET_DIR=target/slice12-task03 cargo test -p navigator-core hot_campaign_subtree_cannot_starve_a_peer_campaign --lib --locked
1 passed; 0 failed; 0 ignored; 44 filtered out

CARGO_TARGET_DIR=target/slice12-task03 cargo test -p navigator-local --test acceptance subscription_capacity_is_global_and_drop_recovers_a_permit --locked
1 passed; 0 failed; 0 ignored; 20 filtered out

CARGO_TARGET_DIR=target/slice12-task03 cargo test -p navigator-store-sqlite artifact_metadata_is_fenced_idempotent_and_erasure_is_retention_separated --lib --locked
1 passed; 0 failed; 0 ignored; 165 filtered out
```

The six `capacity` matches include exact limit-plus-one/reopen, global atomic
admission, schema/accounting corruption mutants, and reserve/release crash
convergence. Additional reviewed named cases cover concurrent last-slot,
aborted reservation futures, all-resource exact bounds, durable subscriptions,
retained-Event admission/crash/global limits, zero-byte Artifact conversion,
and participant admission through the central profile.

Two deliberately ignored tests are subprocess entry points, not omitted
verification:

- `navigator-store-sqlite::tests::crash_worker` is invoked by parent crash
  tests that terminate the child at named durable boundaries and audit reopen.
- `navigator-local::artifact_store::tests::crash_after_publish_worker` is
  invoked by its parent Artifact crash test to inspect publish/reopen cleanup.

During the final documentation pass, a later full-package rerun was not used as
new evidence because concurrent Task03 work temporarily left a test-only type
inference error and changed `Cargo.lock`. The successful focused results above
precede that unrelated shared-worktree churn; Task01's independent GO is the
closure authority.

## Adversarial history

Review did not accept process-local counters or happy-path saturation as proof.
It required one central resource vocabulary, bidirectional session/global
accounting, an atomic final-slot race, replay-free accounting, cancellation and
crash convergence, durable and fenced subscriptions, exact Artifact count/byte
conversion, retained-Event coverage, and a peer-progress fairness oracle.
Schema-shape and usage-corruption mutants were added so reopen fails closed
instead of silently repairing an unprovable ledger. The final review found no
remaining Task01 semantic gap.
