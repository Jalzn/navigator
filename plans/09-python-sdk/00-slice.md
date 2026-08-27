---
status: verified
slice: 09-python-sdk
depends_on:
  - plans/08-pi-driver/00-slice.md
specs:
  - docs/consumer-api.md
---

# Slice: Python SDK

## Outcome

A Python Consumer installs one package, opens a managed local Navigator, starts
Pi-backed work, streams Events, and exits with bounded cleanup.

## Demonstration

Run one async Python file from a clean environment with no direct Rust or Pi
knowledge.

## Exit gate

Managed binary lifecycle, generated protocol client, idiomatic models, replay,
errors, and packaging are verified.
