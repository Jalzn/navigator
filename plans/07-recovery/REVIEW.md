# Slice 07 adversarial review

Specialists independently implemented the effect journal, reconciliation
engine, and local Consumer boundary. Two cross-review rounds inspected both the
production semantics and whether tests used independent durable oracles.

## Findings resolved

- Closed an authorization bypass where the ordinary Effect transition could
  move `Uncertain` directly to completed or failed without a Grant.
- Replaced a shared proof-kind union with action-specific policy and rejected
  contracts that enabled an action without a compatible proof kind.
- Changed the wire report from a hard-coded `DoNotRetry` action to the exact
  actions permitted by the persisted Effect contract.
- Moved free-form resolution reason out of public audit data. Only a redacted
  category and stable digest remain; sentinel tests scan Events, database, WAL,
  response, and errors.
- Bound proof assertions to Effect identity and immutable semantics, expanded
  negative authorization mutants, and made effect and recovery request IDs
  participate symmetrically in the global request namespace.
- Separated stable public idempotency input from transient owner epoch and CAS
  revision. The first apply remains fenced and revision-checked; an identical
  replay after commit returns the original result, while changed reason, proof,
  identity, or decision conflicts.
- Replaced a self-derived classification hash with an independent declarative
  state-by-observation oracle.
- Added the missing cleanup barrier, uncertainty precedence, malformed inventory,
  multi-row crash atomicity, limit, stale-state, and cross-session mutants.
- Corrected recovery ownership reuse so an installed permit is used only while
  valid and Store fencing/time are rechecked before classification.
- Made Retry honest at the Consumer boundary: it commits `RetryAuthorized` for
  the same Effect and reports `Pending`, with no new Operation, Message, or
  whole-Operation scheduling. Execution belongs to the effect-specific provider,
  first supplied by the Consumer Tool slice.

## Test-quality review

Final evidence observes SQLite rows and WAL bytes, global request ledgers,
ordered Events, ownership epochs, exact Operation/Message/Effect identities,
Grant state, UDS protocol responses, scheduler attempts, reopened databases,
and subprocess termination at named transaction boundaries. Classification
expectations are encoded independently of the production classifier.

The exact `MAX`/`MAX+1` classification boundary is exercised at the Store API;
the SQLite adapter has the corresponding aggregate `MAX+1` guard. Constructing
16,385 valid Participants through public mutations would add cost without a
different semantic oracle, so the persisted tests instead concentrate on real
heterogeneous batches, transactional validation, and crash atomicity.

## Explicit scope boundary

`RetryAuthorized` is a durable authorization checkpoint, not a fabricated claim
that a generic reconciler can execute an arbitrary external effect. The first
production effect-specific executor is the Consumer Tool provider in Slice 10.
The Pi adapter and generic Driver catalog are Slice 08; Python managed-local
composition is Slice 09.
