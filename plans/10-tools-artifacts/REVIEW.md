# Slice 10 adversarial review

Slice 10 was repeatedly reviewed across the public Tool/Artifact model, wire
protocols, broker, SQLite Store, Python SDK, Pi integration, lifecycle fencing
and installed-wheel vertical. Green-looking implementations were rejected until
replay results, provider history, watermark continuity, reconnect publication
and Artifact creator context were independently observable.

## Findings resolved

- Added stable registration identity and exact Session/consumer binding rather
  than deriving runtime identity from request IDs or current name/version
  lookup.
- Persisted dispatch ID, provider/connection generation, server sequence,
  deadline, cancellation, terminal digest and registration ID with each Tool
  invocation. Started now means the handler/effect actually started; sending a
  dispatch alone does not advance the effect phase.
- Bound every replay result to its historical command and durable identity.
  Connect replay uses the historical canonical registration set and consumer,
  while the current provider projection is checked only for compatible identity
  and monotonic sequence state.
- Reconstructed acknowledged watermarks from the contiguous durable prefix;
  forged, ahead, regressing and hole-skipping watermarks fail closed. Terminal
  ACK and cancellation replay share the global durable sequence.
- Required authority and active Operation state at effect time. Reserved work
  with a persisted cancellation cannot Start or consume a grant. Unsafe
  uncertainty is resolved atomically with an effect proof or explicit terminal
  decision; it is never converted into an unsafe blind retry.
- Made provider admission and replacement fenced. Stale connections cannot
  remain selectable, remove a newer route, acknowledge frames or publish a
  reconnected channel pair after lifecycle termination.
- Made broker replay producer-driven so more than one response-queue capacity
  cannot deadlock stream creation. Sends, queues and long-lived tasks are
  bounded and cancellation-aware.
- Added canonical JSON-schema validation before reservation and before terminal
  completion, plus same-context validation for every returned Artifact
  reference.
- Persisted Artifact creator Participant and Operation through domain, Store,
  wire, SDK and Driver/Pi result contracts. Reads verify immutable metadata and
  content; delete and physical erasure remain deliberately separate.
- Hardened Session and Driver lifecycle around cancellation-safe supervisor
  discovery, exact epoch/identity removal, pending pre-prepare launch absence,
  atomic reconnect channel pairs and a lifecycle fence shared with the
  ownership watchdog.

## Adversarial oracles

- Mutants swap valid-but-alien replay snapshots for Connect, Register,
  Transition and uncertainty Resolution, both live and after reopen.
- Store mutants alter mirrored columns, cross-Session Participant/Operation
  links, consumer bindings, effect request/action/class/phase/revision, grants,
  terminal digests, registration membership and provider history.
- Crash matrices assert no mixed Tool/effect/grant/request/Event state at
  transaction boundaries.
- Broker/SDK mutants exercise more than 32 replay rows, stale provider routes,
  lost terminal ACK, cancellation before Started, duplicate divergence,
  reconnect generation changes and thousands of sequential terminal relays.
- Artifact mutants cover symlink/traversal, chunk and total oversize, partial
  writes, hash mismatch, corrupt backing bytes, concurrent identical content,
  crash boundaries and creator-context divergence.
- Lifecycle mutants cover retryable and nonretryable Store errors, ownership
  expiry/loss, watchdog panic/abort, publication-wins and fence-wins orderings,
  stale cleanup, launch absence before prepare and process identity replacement.

## Scope precision

- “Exactly once” means one durable logical Tool invocation and terminal truth
  inside Navigator. External side effects still require the declared
  idempotency/effect recovery contract.
- Artifact delete is logical deletion. It does not claim that bytes have been
  physically erased; retention and authorized erasure are separate.
- The installed-wheel Artifact-drop mutant proves absence of a successful root
  result with the same single handler effect. It is not cited as universal
  proof of one specific typed error for every missing-reference path.
- The vertical uses a real installed Python package, managed daemon and Pi
  subprocess with a faux model/provider. The faux response is nevertheless
  observably dependent on the actual Tool result Artifact; it is not a bypass
  that can synthesize the expected root result without that reference.

## Execution review

The command ledger in `EVIDENCE.md` is part of this verdict, not an informal
handoff claim. In particular:

- the complete Python SDK gate exited 0 with Ruff, mypy over 11 files, 44
  contract/acceptance tests, one unconfigured-daemon test and 50 managed-local
  tests;
- the final recorded Driver fake vertical suite was 7/7, the Pi TypeScript
  suite was 45/45, and the installed-wheel Slice 10 vertical was one successful
  run with raw and durable artifacts retained under `wheel-run-3`;
- the supervisor watchdog filter was 5/5, the local library suite was
  105 passed/0 failed/1 ignored, and the final recovery correction separately
  passed its focal 1/1 plus local all-target clippy;
- the Python full gate ran before that last Rust test-only recovery correction.
  No Python or daemon production path changed in the correction, and its
  directly affected Rust gates were rerun;
- the latest global `scripts/check.sh` attempt was nonzero because four schema
  0017 migration tests had stale version/fixture expectations. After correction,
  the Store library passed 119/0/1, but a new complete global exit-0 run has not
  been recorded.

This ordering prevents the Store rerun or focused lifecycle tests from being
misrepresented as a full repository-gate replacement.

## Verdict

GO for Slice 10. The four Slice documents are verified by Slice-specific
semantic and vertical evidence. The overall repository gate remains pending
after the Slice 11 migration fixture corrections, so this review does not claim
that `scripts/check.sh` currently exits zero.
