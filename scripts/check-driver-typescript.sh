#!/usr/bin/env bash
set -euo pipefail
readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly source_dir="${project_root}/crates/navigator-driver-protocol/typescript"
readonly check_dir="$(mktemp -d)"
trap 'rm -rf "${check_dir}"' EXIT
mkdir -p "${check_dir}/typescript" "${check_dir}/fixtures"
cp -R "${source_dir}/package.json" "${source_dir}/package-lock.json" \
  "${source_dir}/tsconfig.json" "${source_dir}/tsconfig.build.json" \
  "${source_dir}/gen" "${source_dir}/test" "${check_dir}/typescript/"
cp "${project_root}/crates/navigator-driver-protocol/fixtures/start-v1.bin" "${check_dir}/fixtures/"
cd "${check_dir}/typescript"
npm ci --ignore-scripts
npm run check
