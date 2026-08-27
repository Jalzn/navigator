# Security and compatibility evidence v3

Status: awaiting a fresh independent adversarial review.

`conformance/security-compatibility-v1.json` is the authoritative matrix.
`scripts/check-security-compatibility.py` executes every declared identity and
publishes logs, endpoint matrix, source inventory, SBOM, license closure,
secret scan, summary, toolchains, and a digest-closed evidence index into a
fresh directory. Cargo identities must resolve to one test. Python identities
are collected and executed through a pinned interpreter; structured pytest
phase reports must prove exactly one clean setup, call, and teardown. Terminal
output is retained as evidence but is never the pass oracle.

The current matrix explicitly covers Consumer event-read authorization and
existence-oracle resistance, subscription authorization before ownership and
capacity fencing, protocol page bounds, and Python cursor/page coercion and
forged-page rejection. It also retains frozen Consumer and Driver compatibility,
Authority and approval boundaries, Store schema 18/19 migration and crash
recovery, future-schema zero-write rejection, frame bounds, replay/expiry, and
attempt-private Driver control-socket cleanup across cancellation, replacement,
and restart.

The evidence index, not this source document, is authoritative for run paths,
counts, hashes, tool versions, and output identities. Independent review must
produce an external sidecar attestation under `evidence/`; source files must not
be edited after the evidence source digest is frozen. Earlier publications are
historical evidence for their own source snapshots only.
