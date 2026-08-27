# Vertical 08 — Approvals, artifacts, and retention

## Outcome

Large outputs and sensitive effects use durable bounded artifacts and trusted,
scoped approval decisions rather than oversized messages or model self-approval.

## End-to-end proof

A Worker produces a bounded patch artifact and requests a specific effect. The
Coordinator presents the request through the trusted user channel; one scoped,
expiring grant is issued, atomically consumed, and audited with the resulting
operation and artifact.

## Scope

- artifact metadata table and atomic no-follow filesystem writes;
- content hash, size/media bounds, ownership, references, and quotas;
- temporary/permanent retention and explicit deletion authorization;
- approval request, decision, expiry, revocation, and consumption lifecycle;
- trusted user decision callback/UI boundary;
- scoped grants tied to exact effect, Agent, Session, and expiry;
- export and SQLite backup APIs;
- Coordinator notifications for quota and pending approval.

## Invariants

- models can request but never grant approval;
- one-use grant consumption is atomic with authorized operation intent;
- artifact paths are Runtime-generated relative paths;
- symlinks, traversal, overwrite, hash mismatch, and oversize fail closed;
- history is not automatically deleted;
- temporary cleanup cannot remove referenced or permanent artifacts;
- message bodies reference large artifacts rather than embedding them.

## Acceptance

- approve, deny, expire, revoke, double-consume, and concurrent-consume cases;
- user channel loss leaves approval pending/cancelled predictably;
- traversal, symlink swap, partial write, disk full, and hash mismatch;
- quota warning and hard-limit behavior;
- export-before-delete and explicit exact-ID deletion;
- consistent live SQLite backup;
- restart preserves approval and artifact audit state.

## Adversarial review

- attempt confused-deputy approval reuse across Agents/Campaigns;
- change effect parameters after grant issuance;
- race artifact GC with reference creation;
- inspect artifact rendering for terminal/control-sequence injection;
- verify no approval framework exists without a trusted decision entrypoint.

## Excluded from this slice

Cloud object storage, remote approvers, organization policy engines, and
consumer-specific publication confirmation.
