# Slice 05 verification evidence

Status: verified by the complete repository gate and adversarial review.

Authoritative run: `target/conformance/run.p7CTQH`. Every stage in
`gate-results.tsv` passed.

## Topology and atomic delegation

- Participant creation validates the immutable parent, same Session, Template
  compatibility, depth, direct-child capacity, and total Session capacity in
  one fenced SQLite transaction.
- Concurrent creators contend at the transaction boundary and cannot exceed an
  exact capacity. Reopen and deliberately corrupted topology tests fail closed.
- Authorized spawn atomically commits the child, its effective policy, first
  Operation, input Message, Events, request ledger, and single-use Grant
  consumption. Fault injection at every commit boundary proves either no
  effect or the complete effect.
- Request replay reloads and returns the original child, Operation, and Message
  identities. Reusing an identity with different semantic input is rejected.

## Non-escalating authority

- Typed capabilities and Session, Participant, Operation, and Artifact scopes
  are evaluated as the intersection of Session, parent-delegation, Template,
  relationship, subject, and Grant ceilings.
- Active and delegable authority are distinct. A parent may delegate an
  allowed capability without possessing it actively, but may never delegate
  beyond its delegable ceiling.
- Expiry, revocation, scope, subject, and single-use state are rechecked at the
  effect transaction. Driver/model input cannot provide trusted policy fields.
- Table-driven domain laws identify the exact trusted origins for every
  effective capability and denial Events remain structured and redacted.

## Authenticated hierarchical flow

- Generic Driver commands implement spawn, send, status, and cancel while the
  caller is derived from the exact authenticated Driver Instance and host
  ownership epoch.
- The Store applies hierarchy effects in one fenced transaction and permits
  only the defined direct relationship. Direct sibling and cross-tree effects
  are rejected without topology enumeration; optional routing through a common
  ancestor is a separate policy decision.
- A real three-process scenario executes root to child to grandchild using
  distinct launch attempts, Instances, sockets, and durable fake-Driver
  journals. It proves downward work, an upward question, exact correlated
  feedback, resumption only after durable acceptance, and upward terminal
  outcomes.
- Feedback retry, stale attempt, concurrent acknowledgement, and subprocess
  crash matrices prove that `message.accepted` precedes exactly one
  `operation.resumed`, or that the prior waiting state remains intact.
- Signed hierarchy responses are bound to request correlation and the exact
  authenticated Instance; forged caller and response identities fail closed.

## Repository gate

The authoritative gate passed:

- `format`
- `clippy`
- `semantic-evidence`
- `semantic-tests`
- `driver-typescript`
- `offline-build`
- `clean-source`
- `architecture`
- `supply-chain`
- `unused-dependencies`

Detailed logs and machine-readable evidence are under
`target/conformance/run.p7CTQH`; `target/conformance/latest` points to this run.
