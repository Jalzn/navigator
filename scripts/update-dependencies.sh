#!/usr/bin/env bash
set -euo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly snapshot_dir="$(mktemp -d)"
trap 'rm -rf "${snapshot_dir}"' EXIT

snapshot_fixtures() {
  local destination="$1"
  PROJECT_ROOT="${project_root}" DESTINATION="${destination}" python3 - <<'PY'
import hashlib
import os
import pathlib

root = pathlib.Path(os.environ["PROJECT_ROOT"])
destination = pathlib.Path(os.environ["DESTINATION"])
fixtures = sorted(root.glob("crates/*/tests/fixtures/**/*"))
lines = []
for fixture in fixtures:
    if fixture.is_file():
        digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
        lines.append(f"{digest}  {fixture.relative_to(root).as_posix()}")
destination.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
PY
}

cd "${project_root}"
snapshot_fixtures "${snapshot_dir}/before.sha256"
mise exec -- cargo update
./scripts/check.sh
snapshot_fixtures "${snapshot_dir}/after.sha256"

if ! cmp -s "${snapshot_dir}/before.sha256" "${snapshot_dir}/after.sha256"; then
  diff -u "${snapshot_dir}/before.sha256" "${snapshot_dir}/after.sha256" || true
  printf 'protocol fixture drift requires explicit compatibility review\n' >&2
  exit 1
fi

printf 'dependency update verified; protocol fixtures unchanged\n'

