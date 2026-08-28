#!/usr/bin/env bash
set -euo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly build_root="$(mktemp -d)"
readonly package_root="${build_root}/navigator-python"
readonly output_root="${project_root}/dist/python"

cleanup_build_root() {
  rm -rf "${build_root}"
}
trap cleanup_build_root EXIT

cd "${project_root}"
readonly cargo_target="${project_root}/target/python-wheel"
CARGO_TARGET_DIR="${cargo_target}" mise exec -- cargo build --locked --offline \
  -p navigator-local --bin navigatord

mkdir -p "${build_root}/javascript/crates/navigator-driver-protocol" \
  "${build_root}/javascript/packages"
rsync -a --exclude node_modules --exclude dist \
  "${project_root}/crates/navigator-driver-protocol/typescript/" \
  "${build_root}/javascript/crates/navigator-driver-protocol/typescript/"
rsync -a --exclude node_modules --exclude dist \
  "${project_root}/packages/navigator-driver-pi/" \
  "${build_root}/javascript/packages/navigator-driver-pi/"

readonly protocol_root="${build_root}/javascript/crates/navigator-driver-protocol/typescript"
readonly pi_root="${build_root}/javascript/packages/navigator-driver-pi"
mise exec -- npm --prefix "${protocol_root}" ci --ignore-scripts
mise exec -- npm --prefix "${protocol_root}" run build
mise exec -- npm --prefix "${pi_root}" ci --ignore-scripts
mise exec -- npm --prefix "${pi_root}" run build

cp -R "${project_root}/packages/navigator-python" "${package_root}"
mise exec python@3.13.15 -- python -m venv "${build_root}/venv"
readonly build_python="${build_root}/venv/bin/python"
"${build_python}" -m pip install --disable-pip-version-check \
  "build==1.4.4" "hatchling==1.27.0"

"${build_python}" "${package_root}/scripts/prepare_runtime.py" \
  "${cargo_target}/debug/navigatord" \
  --target darwin-arm64 \
  --node "$(mise which node)" \
  --pi-package "${pi_root}" \
  --protocol-package "${protocol_root}" \
  --output "${package_root}/src/navigator/_runtime"

mkdir -p "${output_root}"
cd "${package_root}"
"${build_python}" -m build --wheel --no-isolation --outdir "${output_root}"

"${build_python}" - "${output_root}"/*.whl <<'PY'
import hashlib
import json
import sys
import zipfile

wheel = sys.argv[1]
with zipfile.ZipFile(wheel) as archive:
    manifest = json.loads(archive.read("navigator/_runtime/manifest.json"))
    target = manifest["artifacts"]["darwin-arm64"]
    required = [target["navigatord"], target["node"], target["pi_entrypoint"]]
    for record in required:
        payload = archive.read("navigator/_runtime/" + record["path"])
        assert len(payload) == record["size"]
        assert hashlib.sha256(payload).hexdigest() == record["sha256"]
print(wheel)
PY
