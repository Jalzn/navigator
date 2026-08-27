---
status: verified
slice: 09-python-sdk
depends_on:
  - plans/09-python-sdk/01-generated-client.md
  - plans/08-pi-driver/03-real-tree-smoke.md
specs:
  - docs/architecture.md
  - docs/consumer-api.md
---

# Task: Manage local Navigator lifecycle

## Outcome

Navigator.local starts the correct bundled binary, performs handshake, connects,
and performs bounded cleanup.

## Implementation

- Compose `navigatord` with the generic Driver catalog, mailbox-backed Operation
  controller, delivery workers, and recovery scheduler before accepting a
  Consumer connection.
- Resolve a platform-specific signed or checksummed binary.
- Use a private temporary bootstrap channel and restrictive socket permissions.
- Capture startup diagnostics without exposing credentials.
- Detect early exit and incompatible protocol.
- Keep Consumer exit distinct from Session cancellation.

## Verification

- Launch the real `navigatord` subprocess and prove the default unconfigured
  server fails closed, while an explicitly configured fake Driver completes an
  Operation through the Mailbox and survives server restart reconciliation.
- Clean start, existing Session, crash, timeout, and incompatible binary.
- Two SDK processes respect Session ownership.
- Context exit leaves no owned process.
- User interruption produces deterministic cleanup.

## Done

The local deployment feels like a Python library without embedding Rust.
