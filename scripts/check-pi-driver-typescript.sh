#!/usr/bin/env bash
set -euo pipefail
readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly check_dir="$(mktemp -d)"
trap 'rm -rf "${check_dir}"' EXIT
mkdir -p "${check_dir}/packages/navigator-driver-pi" \
  "${check_dir}/crates/navigator-driver-protocol/typescript"
cp -R "${project_root}/packages/navigator-driver-pi/package.json" \
  "${project_root}/packages/navigator-driver-pi/package-lock.json" \
  "${project_root}/packages/navigator-driver-pi/tsconfig.json" \
  "${project_root}/packages/navigator-driver-pi/tsconfig.build.json" \
  "${project_root}/packages/navigator-driver-pi/src" \
  "${project_root}/packages/navigator-driver-pi/test" \
  "${check_dir}/packages/navigator-driver-pi/"
cp -R "${project_root}/crates/navigator-driver-protocol/typescript/package.json" \
  "${project_root}/crates/navigator-driver-protocol/typescript/package-lock.json" \
  "${project_root}/crates/navigator-driver-protocol/typescript/tsconfig.json" \
  "${project_root}/crates/navigator-driver-protocol/typescript/tsconfig.build.json" \
  "${project_root}/crates/navigator-driver-protocol/typescript/gen" \
  "${check_dir}/crates/navigator-driver-protocol/typescript/"
cd "${check_dir}/crates/navigator-driver-protocol/typescript"
npm ci --ignore-scripts
npm run build
cd "${check_dir}/packages/navigator-driver-pi"
npm ci --ignore-scripts
npm run check
