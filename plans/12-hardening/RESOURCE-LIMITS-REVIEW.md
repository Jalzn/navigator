# Resource limits adversarial review

Date: 2026-08-26  
Decision: **GO**

The final review accepts Task01 at Store schema 20. This decision is limited to
resource limits and fairness; it does not change the status of Task03 or
Task04.

## Accepted oracles

- Exact admission: limit succeeds, limit plus one returns the typed resource
  and session/global reason, release permits exactly one later admission.
- Atomic concurrency: contenders for the final session or global slot produce
  one winner and no over-accounting.
- Durable replay: reopen preserves committed reservations; retry and release
  are idempotent, while crash at reserve/release is observably prior-or-full.
- Cancellation: aborting an in-flight reservation leaves no committed permit;
  retry commits once.
- Subscriptions: permits are global, lease-backed, owner/epoch fenced, reclaimed
  on abandon/takeover, and released on stream drop. Setup failures are typed.
- Artifacts: count and byte reservations match metadata, zero-byte conversion
  does not consume byte capacity, and metadata erasure is distinct from blob
  retention cleanup.
- Retained Events: every append path uses exact accounting, replay is free, and
  crash/reopen plus cross-Session global saturation converge.
- Fairness: a continuously hot Campaign subtree cannot starve a peer Campaign.
- Fail-closed audit: missing indexes/tables, malformed reservation shape, and
  inconsistent usage ledgers are rejected on reopen.

## Review history and exclusions

Earlier review challenges targeted process-only subscription permits, parallel
participant limits, non-atomic session/global accounting, cancellation leaks,
Artifact count/byte mismatches, crash windows, and a scheduler that could pass
throughput tests while starving peers. The implementation and focused mutants
now exercise each of those failure modes directly.

The two ignored subprocess functions are intentionally non-standalone. Their
parent tests supply fixture paths and fault points, terminate the child, reopen
the database or Artifact root, and assert final invariants. They therefore do
not represent skipped product behavior.

Task03's fault-matrix evidence and Task04's release infrastructure remain
separate gates and are not implied by this GO.
