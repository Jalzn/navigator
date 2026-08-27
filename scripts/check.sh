#!/usr/bin/env bash
set -uo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly evidence_root="${NAVIGATOR_EVIDENCE_ROOT:-${project_root}/target/conformance}"
mkdir -p "${evidence_root}"
readonly run_prefix="${NAVIGATOR_EVIDENCE_RUN_PREFIX:-run}"
if [[ ! "${run_prefix}" =~ ^[a-zA-Z0-9._-]+$ ]]; then
  printf 'invalid evidence run prefix\n' >&2
  exit 2
fi
readonly evidence_dir="$(mktemp -d "${evidence_root}/${run_prefix}.XXXXXX")"
readonly results_file="${evidence_dir}/gate-results.tsv"
readonly execution_log="${evidence_dir}/execution.log"

: >"${results_file}"
: >"${execution_log}"
overall=0

run_gate() {
  local name="$1"
  shift
  local gate_log="${evidence_dir}/${name}.log"

  printf '== %s ==\n' "${name}" | tee -a "${execution_log}"
  if CARGO_TERM_COLOR=never NO_COLOR=1 "$@" 2>&1 | tee "${gate_log}" | tee -a "${execution_log}"; then
    printf '%s\tpass\n' "${name}" >>"${results_file}"
  else
    printf '%s\tfail\n' "${name}" >>"${results_file}"
    overall=1
  fi
}

cd "${project_root}"
run_gate format mise exec -- cargo fmt --all -- --check
run_gate clippy mise exec -- cargo clippy --workspace --all-targets -- -D warnings
run_gate semantic-evidence mise exec -- cargo run --quiet -p navigator-conformance --bin foundation-evidence --locked -- "${evidence_dir}"
run_gate semantic-tests python3 scripts/with-source-gate-lock.py mise exec -- cargo test --workspace --locked
run_gate driver-typescript ./scripts/check-driver-typescript.sh
run_gate pi-driver-typescript ./scripts/check-pi-driver-typescript.sh
run_gate offline-build mise exec -- cargo build --workspace --locked --offline
run_gate python-sdk ./scripts/check-python-sdk.sh
run_gate clean-source python3 scripts/with-source-gate-lock.py ./scripts/check-clean-source.sh
run_gate architecture python3 scripts/with-source-gate-lock.py /bin/sh -c \
  'python3 scripts/check_architecture.py && python3 scripts/test-check-architecture.py'
run_gate fault-matrix python3 scripts/test-fault-matrix.py
run_gate fault-matrix-evidence python3 scripts/check-fault-matrix.py --output "${evidence_dir}/fault-matrix.jsonl"
run_gate supply-chain mise exec -- cargo deny check
run_gate security-compatibility-mutants python3 scripts/test-security-compatibility.py
run_gate security-compatibility python3 scripts/check-security-compatibility.py "${evidence_dir}/security-compatibility"
run_gate release-gate-infrastructure python3 scripts/release-gate.py \
  --security-evidence "${evidence_dir}/security-compatibility" \
  --report "${evidence_dir}/release-gate.json"
run_gate release-gate-mutants python3 scripts/test-release-gate.py
run_gate release-critical-mutants python3 scripts/run-release-critical-mutants.py \
  --report "${evidence_dir}/release-critical-mutants.json"
run_gate unused-dependencies python3 scripts/with-source-gate-lock.py mise exec -- cargo machete crates
if [[ -n "${NAVIGATOR_REVIEWED_SECURITY_EVIDENCE:-}" && -n "${NAVIGATOR_SECURITY_ATTESTATION:-}" ]]; then
  run_gate release-authorization python3 scripts/release-gate.py \
    --security-evidence "${NAVIGATOR_REVIEWED_SECURITY_EVIDENCE}" \
    --security-attestation "${NAVIGATOR_SECURITY_ATTESTATION}" \
    --output "${evidence_dir}/release-bundle" \
    --require-release --report "${evidence_dir}/release-authorization.json"
else
  printf 'Fresh security candidate awaits independent review; release authorization not attempted.\n' \
    >"${evidence_dir}/release-authorization.awaiting-review"
fi

if ! python3 scripts/write_check_summary.py "${results_file}" "${evidence_dir}"; then
  overall=1
fi
if ! python3 scripts/publish_latest.py "${evidence_root}" "${evidence_dir}"; then
  overall=1
fi
exit "${overall}"
