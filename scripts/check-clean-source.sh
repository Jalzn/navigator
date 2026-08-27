#!/usr/bin/env bash
set -euo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly clean_root="$(mktemp -d)"
trap 'rm -rf "${clean_root}"' EXIT

cd "${project_root}"
tar -cf - \
  --exclude='node_modules' --exclude='dist' --exclude='target' \
  --exclude='__pycache__' --exclude='.pytest_cache' --exclude='.mypy_cache' \
  --exclude='.ruff_cache' --exclude='*.pyc' \
  Cargo.toml Cargo.lock rust-toolchain.toml mise.toml deny.toml \
  crates packages/navigator-driver-pi packages/navigator-python scripts | tar -xf - -C "${clean_root}"

cd "${clean_root}"
(
  cd crates/navigator-driver-protocol/typescript
  npm ci --ignore-scripts
  npm run build
)
(
  cd packages/navigator-driver-pi
  npm ci --ignore-scripts
  npm run check
)
mise exec -- cargo build --workspace --locked --offline
mise exec -- cargo test --workspace --locked --offline
./scripts/check-driver-typescript.sh
./scripts/check-python-sdk.sh
