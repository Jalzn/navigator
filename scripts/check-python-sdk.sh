#!/usr/bin/env bash
set -euo pipefail

readonly project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly sdk_root="${project_root}/packages/navigator-python"
readonly check_root="$(mktemp -d)"
readonly package_sdk="${check_root}/package/navigator-python"
cleanup_check_root() {
  if [[ "${NAVIGATOR_KEEP_CHECK_ROOT:-0}" == "1" ]]; then
    echo "preserved Python SDK check root: ${check_root}" >&2
  else
    rm -rf "${check_root}"
  fi
}
trap cleanup_check_root EXIT

cd "${project_root}"
CARGO_TARGET_DIR="${check_root}/cargo-target" mise exec -- cargo build --locked --offline \
  -p navigator-local --bin navigatord
readonly javascript_root="${check_root}/javascript"
mkdir -p "${javascript_root}/crates/navigator-driver-protocol" "${javascript_root}/packages"
rsync -a --exclude node_modules --exclude dist \
  "${project_root}/crates/navigator-driver-protocol/typescript" \
  "${javascript_root}/crates/navigator-driver-protocol/"
rsync -a --exclude node_modules --exclude dist \
  "${project_root}/packages/navigator-driver-pi" \
  "${javascript_root}/packages/"
readonly clean_protocol="${javascript_root}/crates/navigator-driver-protocol/typescript"
readonly clean_pi="${javascript_root}/packages/navigator-driver-pi"
mise exec -- npm --prefix "${clean_protocol}" ci --ignore-scripts
mise exec -- npm --prefix "${clean_protocol}" run build
mise exec -- npm --prefix "${clean_pi}" ci --ignore-scripts
mise exec -- npm --prefix "${clean_pi}" run build

mise exec python@3.13.15 -- python -m venv "${check_root}/bootstrap"
readonly bootstrap_python="${check_root}/bootstrap/bin/python"
"${bootstrap_python}" -m pip install --disable-pip-version-check \
  "hatchling==1.27.0" "build==1.4.4"
"${bootstrap_python}" -m pip install --disable-pip-version-check \
  "grpcio>=1.74,<2" "protobuf>=6.31,<7" "pydantic>=2.11,<3" \
  "grpcio-tools==1.80.0" "mypy==1.19.1" "pytest==8.4.2" \
  "pytest-asyncio==1.2.0" "ruff==0.16.4" "types-grpcio==1.0.0.20251009"
mkdir -p "${check_root}/package"
cp -R "${sdk_root}" "${package_sdk}"
"${bootstrap_python}" "${package_sdk}/scripts/prepare_runtime.py" \
  "${check_root}/cargo-target/debug/navigatord" --target darwin-arm64 \
  --node "$(mise which node)" \
  --pi-package "${clean_pi}" \
  --protocol-package "${clean_protocol}" \
  --output "${package_sdk}/src/navigator/_runtime"

mkdir -p "${check_root}/source/packages" "${check_root}/source/crates/navigator-consumer-protocol"
cp -R "${sdk_root}" "${check_root}/source/packages/navigator-python"
cp -R "${project_root}/crates/navigator-consumer-protocol/proto" \
  "${check_root}/source/crates/navigator-consumer-protocol/proto"
"${bootstrap_python}" "${check_root}/source/packages/navigator-python/scripts/generate.py"
diff -ru --exclude='__pycache__' "${sdk_root}/src/navigator/_transport" \
  "${check_root}/source/packages/navigator-python/src/navigator/_transport"

cd "${sdk_root}"
"${bootstrap_python}" -m ruff check src tests scripts examples
PYTHONPATH=src "${bootstrap_python}" -m mypy --strict src/navigator examples
cd "${package_sdk}"
"${bootstrap_python}" -m build --no-isolation --outdir "${check_root}/dist"
"${bootstrap_python}" -m pip wheel --no-build-isolation \
  --wheel-dir "${check_root}/wheelhouse" "${package_sdk}"

mise exec python@3.13.15 -- python -m venv "${check_root}/installed"
readonly installed_python="${check_root}/installed/bin/python"
"${installed_python}" -m pip install --disable-pip-version-check --no-index \
  --find-links "${check_root}/wheelhouse" "${check_root}"/dist/*.whl
cd "${check_root}"
test "$(find "${check_root}/dist" -maxdepth 1 -name '*.whl' | wc -l | tr -d ' ')" = 1
test "$(find "${check_root}/dist" -maxdepth 1 -name '*.tar.gz' | wc -l | tr -d ' ')" = 1
"${bootstrap_python}" - "${check_root}"/dist/*.whl "${check_root}"/dist/*.tar.gz <<'PY'
import sys
import tarfile
import zipfile
import hashlib
import json
from email.parser import Parser

from packaging.specifiers import SpecifierSet

wheel, source = sys.argv[1:]
required = {
    "navigator/py.typed",
    "navigator/client.py",
    "navigator/approvals.py",
    "navigator/connection.py",
    "navigator/_runtime/manifest.json",
    "navigator/_runtime/darwin-arm64/navigatord",
    "navigator/_runtime/darwin-arm64/node",
    "navigator/_runtime/darwin-arm64/pi/dist/main.js",
    "navigator/_runtime/darwin-arm64/pi/node_modules/@navigator/driver-protocol/dist/gen/navigator/driver/v1/driver_pb.js",
    "navigator/_runtime/darwin-arm64/pi/node_modules/@earendil-works/pi-ai/dist/index.js",
    "navigator/_runtime/darwin-arm64/acceptance/provider.mjs",
    "navigator/_transport/navigator/consumer/v1/consumer_pb2.py",
    "navigator/_transport/navigator/consumer/v1/consumer_pb2_grpc.py",
}
with zipfile.ZipFile(wheel) as archive:
    missing = required.difference(archive.namelist())
    assert not missing, f"wheel is missing required content: {sorted(missing)}"
    manifest = json.loads(archive.read("navigator/_runtime/manifest.json"))
    assert manifest["version"] == 2
    target = manifest["artifacts"]["darwin-arm64"]
    assert target["driver_id"] == "00000000000000000000000000000001"
    assert target["pi_tree"]
    for record in target["pi_tree"]:
        wheel_path = "navigator/_runtime/" + record["path"]
        assert wheel_path in archive.namelist()
        payload = archive.read(wheel_path)
        assert len(payload) == record["size"]
        assert hashlib.sha256(payload).hexdigest() == record["sha256"]
    metadata_name = next(name for name in archive.namelist() if name.endswith(".dist-info/METADATA"))
    metadata = Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
    requirement = metadata["Requires-Python"]
    assert requirement == ">=3.13"
    assert "3.12" not in SpecifierSet(requirement)
    assert "3.13" in SpecifierSet(requirement)
with tarfile.open(source, "r:gz") as archive:
    names = archive.getnames()
    assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)
PY
mise exec python@3.12.14 -- python -m venv "${check_root}/unsupported"
if "${check_root}/unsupported/bin/python" -m pip install --disable-pip-version-check \
  --no-deps "${check_root}"/dist/*.whl >"${check_root}/unsupported-install.log" 2>&1; then
  echo "Python 3.12 unexpectedly accepted the Navigator SDK wheel" >&2
  exit 1
fi
grep -q "requires a different Python" "${check_root}/unsupported-install.log"
"${installed_python}" - <<'PY'
from importlib import resources

import navigator
from navigator._transport.navigator.consumer.v1 import consumer_pb2

assert navigator.__package__ == "navigator"
assert resources.files("navigator").joinpath("py.typed").is_file()
assert consumer_pb2.NegotiateRequest is not None
PY

"${installed_python}" - "${check_root}/installed-data" <<'PY'
import asyncio
import sys
from pathlib import Path

from navigator import Navigator

async def smoke() -> None:
    data = Path(sys.argv[1])
    # Exercise the public default budget after native and TypeScript builds on
    # a potentially saturated release host.
    async with Navigator.local(data_dir=data) as client:
        assert client is not None

asyncio.run(smoke())
PY

cp "${package_sdk}/examples/managed_work.py" "${check_root}/managed_work.py"
"${installed_python}" - "${check_root}/managed_work.py" "${check_root}/vertical-data" <<'PY'
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

script, data = sys.argv[1:]
before = {path for path in Path("/tmp").glob("navigator-*") if path.is_dir()}
environment = {
    "HOME": os.environ["HOME"],
    "LANG": os.environ.get("LANG", "C"),
    "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
}
process = subprocess.Popen(
    [sys.executable, script, data, "complete the installed SDK demonstration"],
    cwd=Path(script).parent,
    env=environment,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    start_new_session=True,
)

def terminate_process_group(process: subprocess.Popen[str]) -> None:
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

try:
    stdout, stderr = process.communicate(timeout=60)
except subprocess.TimeoutExpired:
    terminate_process_group(process)
    raise
completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
assert completed.returncode == 0, (completed.stdout, completed.stderr)
assert Path(data, "navigator.sqlite").is_file()
after = {path for path in Path("/tmp").glob("navigator-*") if path.is_dir()}
assert after == before, f"managed runtime leaked: {sorted(after - before)}"
assert "operation." in completed.stdout, completed.stdout
assert "result:done" in completed.stdout, completed.stdout
PY

cp "${package_sdk}/examples/acceptance_workflow.py" "${check_root}/acceptance_workflow.py"
"${installed_python}" - "${check_root}/acceptance_workflow.py" \
  "${check_root}/workflow-data" <<'PY'
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

script, data = sys.argv[1:]
environment = {
    "HOME": os.environ["HOME"],
    "LANG": os.environ.get("LANG", "C"),
    "NAVIGATOR_DATA_DIR": data,
    "NAVIGATOR_MODE": "local",
    "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
}
process = subprocess.Popen(
    [sys.executable, script],
    cwd=Path(script).parent,
    env=environment,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    start_new_session=True,
)

def terminate_process_group(process: subprocess.Popen[str]) -> None:
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        process.poll()
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

try:
    stdout, stderr = process.communicate(timeout=60)
except subprocess.TimeoutExpired:
    terminate_process_group(process)
    raise
completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
assert completed.returncode == 0, (completed.stdout, completed.stderr)
assert Path(data, "navigator.sqlite").is_file()
assert Path(script).with_name("navigator.cursor").is_file()
PY

cd "${project_root}"
NAVIGATORD_TEST_BINARY="${check_root}/cargo-target/debug/navigatord" \
  PYTHONPATH="${package_sdk}/src" "${bootstrap_python}" -m pytest \
  "${sdk_root}/tests/test_contract.py" "${sdk_root}/tests/test_acceptance_examples.py" \
  "${sdk_root}/tests/test_slice11_sdk.py" \
  "${sdk_root}/tests/test_read_events_transport.py"
NAVIGATORD_TEST_BINARY="${check_root}/cargo-target/debug/navigatord" \
  PYTHONPATH="${package_sdk}/src" "${bootstrap_python}" -m pytest \
  "${sdk_root}/tests/test_managed_local.py::test_unconfigured_real_daemon_fails_closed_before_driver_execution"
NAVIGATORD_TEST_BINARY="${check_root}/cargo-target/debug/navigatord" \
  PYTHONPATH="${package_sdk}/src" "${bootstrap_python}" -m pytest \
  "${sdk_root}/tests/test_managed_local.py" \
  --deselect "${sdk_root}/tests/test_managed_local.py::test_unconfigured_real_daemon_fails_closed_before_driver_execution"
