#!/usr/bin/env bash
set -euo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${project_root}"
test_root="${project_root}/target/conformance-concurrency.$$.${RANDOM}"
mkdir -p "${test_root}"
trap 'rm -rf -- "${test_root}"' EXIT
export NAVIGATOR_EVIDENCE_ROOT="${test_root}"
run_prefix="concurrency.$$.${RANDOM}"
export NAVIGATOR_EVIDENCE_RUN_PREFIX="${run_prefix}"
./scripts/check.sh >/dev/null &
first=$!
./scripts/check.sh >/dev/null &
second=$!
wait "${first}"
wait "${second}"

RUN_PREFIX="${run_prefix}" TEST_ROOT="${test_root}" python3 - <<'PY'
import json
import os
import pathlib

expected = {
    "format", "clippy", "semantic-evidence", "semantic-tests", "offline-build",
    "driver-typescript", "pi-driver-typescript", "clean-source", "architecture",
    "python-sdk", "supply-chain", "unused-dependencies",
}
root = pathlib.Path(os.environ["TEST_ROOT"])
runs = sorted(root.glob(f"{os.environ['RUN_PREFIX']}.*"))
assert len(runs) == 2, runs

for run in runs:
    summary = json.loads((run / "summary.json").read_text())
    names = [gate["name"] for gate in summary["gates"]]
    assert len(names) == len(expected), (run, names)
    assert set(names) == expected, (run, names)
    assert summary["overall"] == "pass", run
    assert (run / "semantic-evidence.json").is_file(), run
    assert (run / "semantic-evidence.txt").is_file(), run
    for name in expected:
        assert (run / f"{name}.log").is_file(), (run, name)

latest = (root / "latest").resolve()
assert latest in [run.resolve() for run in runs], (latest, runs)
assert not list(root.glob(".latest.*"))
PY
