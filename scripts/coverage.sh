#!/usr/bin/env bash
set -euo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly output_dir="${project_root}/target/coverage"

mkdir -p "${output_dir}"
cd "${project_root}"

mise exec -- cargo llvm-cov clean --workspace
mise exec -- cargo llvm-cov --workspace --all-targets --locked --no-report
mise exec -- cargo llvm-cov report --lcov --output-path "${output_dir}/lcov.info"
mise exec -- cargo llvm-cov report --json --output-path "${output_dir}/coverage.json"
mise exec -- cargo llvm-cov report --html --output-dir "${output_dir}/html"
mise exec -- cargo llvm-cov report --summary-only >"${output_dir}/summary.txt"

printf 'coverage evidence: %s\n' "${output_dir}"

