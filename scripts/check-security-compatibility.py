#!/usr/bin/env python3
"""Execute the security matrix and emit deterministic release evidence."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import platform
import tempfile
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance/security-compatibility-v1.json"
SKIP_DIRS = {".git", "target", "evidence", "node_modules", ".venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
SECRET_PATTERNS = {
    "private-key": re.compile(b"-----BEGIN " + b"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws-access-key": re.compile(b"AK" + b"IA[0-9A-Z]{16}"),
    "github-token": re.compile(b"g" + b"h[pousr]_[A-Za-z0-9]{30,}"),
    "openai-token": re.compile(b"s" + b"k-[A-Za-z0-9]{32,}"),
}
PYTHON_LICENSES = {
    "grpcio": "Apache-2.0", "protobuf": "BSD-3-Clause", "pydantic": "MIT",
    "pydantic-core": "MIT", "typing-inspection": "MIT", "typing-extensions": "PSF-2.0",
}
REQUIRED_CELLS = {
    "consumer-old-negotiate", "consumer-old-snapshot", "consumer-old-real-process",
    "consumer-template-invalid",
    "hierarchy-template-runtime", "consumer-oversize", "consumer-approval-auth",
    "driver-old-wire", "driver-old-real-process", "driver-auth-replay", "driver-expiry-equality",
    "driver-frame-oversize", "authority-grant-boundary", "authority-rule-bounds",
    "authority-grant-store-runtime", "store-v18-stateful", "store-future",
    "store-frozen-v18-v19-crash", "store-migration-crash",
    "consumer-event-read-auth", "consumer-event-subscription-auth",
    "consumer-event-read-bounds", "python-event-read-bounds",
    "python-event-read-forged-empty-page",
    "consumer-cli-token-file", "consumer-cli-token-lifecycle",
    "consumer-cli-inspector-token",
    "driver-pending-control-cleanup", "driver-private-root-identity",
    "driver-private-root-restart",
}


def fail(message: str) -> None:
    raise SystemExit(message)


def relevant_files(extra: pathlib.Path | None = None) -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for base, directories, names in os.walk(ROOT):
        directories[:] = sorted(name for name in directories if name not in SKIP_DIRS)
        for name in sorted(names):
            path = pathlib.Path(base, name)
            if path.is_file() or path.is_symlink():
                files.append(path)
    if extra is not None:
        files.append(extra)
    return sorted(files)


def scan(files: list[pathlib.Path]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    inventory, findings = [], []
    for path in files:
        link_target = None
        if path.is_symlink():
            resolved = path.resolve(strict=True)
            if not resolved.is_relative_to(ROOT):
                fail(f"workspace symlink escapes source root: {path}")
            link_target = str(resolved.relative_to(ROOT))
        data = path.read_bytes()
        relative = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else "<sentinel>"
        entry = {"path": relative, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                 "kind": "symlink" if link_target is not None else "file"}
        if link_target is not None:
            entry["target"] = link_target
        inventory.append(entry)
        # Binary release fixtures remain in the inventory with exact size and
        # digest. Regex scanning arbitrary machine code creates random token
        # matches; textual and extensionless executable scripts are scanned.
        if b"\0" not in data[:8192]:
            for kind, pattern in SECRET_PATTERNS.items():
                if pattern.search(data):
                    findings.append({"kind": kind, "path": relative})
    return inventory, findings


def component(ecosystem: str, name: str, version: str, license_id: str) -> dict[str, object]:
    if not license_id or license_id.upper() == "UNKNOWN":
        fail(f"unresolved license: {ecosystem}:{name}@{version}")
    namespace = {"cargo": "cargo", "npm": "npm", "pypi": "pypi"}[ecosystem]
    purl = f"pkg:{namespace}/{name}@{version}"
    return {
        "type": "library", "name": name, "version": version, "bom-ref": purl,
        "purl": purl, "licenses": [{"expression": license_id}],
    }


def supply_chain() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--offline", "--format-version", "1"], cwd=ROOT
    ))
    components: dict[str, dict[str, object]] = {}
    dependencies: dict[str, set[str]] = {}
    cargo_refs: dict[str, str] = {}
    workspace_root = "urn:navigator:workspace"
    dependencies[workspace_root] = set()
    for package in metadata["packages"]:
        item = component("cargo", package["name"], package["version"], package.get("license", "UNKNOWN"))
        components[str(item["bom-ref"])] = item
        cargo_refs[package["id"]] = str(item["bom-ref"])
    dependencies[workspace_root].update(cargo_refs[item] for item in metadata["workspace_members"])
    for node in metadata["resolve"]["nodes"]:
        source = cargo_refs[node["id"]]
        dependencies[source] = {cargo_refs[dep] for dep in node["dependencies"]}

    lock_names = subprocess.check_output(
        ["rg", "--files", "-g", "package-lock.json", "-g", "!target/**", "-g", "!**/node_modules/**"],
        cwd=ROOT, text=True,
    ).splitlines()
    for lock_path in sorted(ROOT / name for name in lock_names):
        lock = json.loads(lock_path.read_text())
        root_ref = f"urn:navigator:npm-lock:{lock_path.relative_to(ROOT)}"
        components[root_ref] = {
            "type": "application", "name": lock.get("name", lock_path.parent.name),
            "version": lock.get("version", "0.0.0"), "bom-ref": root_ref,
            "licenses": [{"expression": "Apache-2.0"}],
        }
        dependencies.setdefault(root_ref, set())
        dependencies[workspace_root].add(root_ref)
        path_refs: dict[str, str] = {}
        for package_path, package in sorted(lock.get("packages", {}).items()):
            if not package_path or "version" not in package:
                continue
            name = package.get("name", package_path.rsplit("node_modules/", 1)[-1])
            license_id = package.get("license")
            if not license_id and name.startswith("@navigator/"):
                license_id = "Apache-2.0"
            item = component("npm", name, package["version"], license_id or "UNKNOWN")
            ref = str(item["bom-ref"])
            components[ref] = item
            path_refs[package_path] = ref
            dependencies.setdefault(ref, set())
        for package_path, package in sorted(lock.get("packages", {}).items()):
            source = root_ref if not package_path else path_refs.get(package_path)
            if source is None:
                continue
            requested_names = set(package.get("dependencies", {}))
            requested_names.update(package.get("optionalDependencies", {}))
            requested_names.update(package.get("peerDependencies", {}))
            for dependency_name in sorted(requested_names):
                parent = package_path
                while True:
                    candidate = f"{parent}/node_modules/{dependency_name}".lstrip("/")
                    if candidate in path_refs:
                        dependencies[source].add(path_refs[candidate])
                        break
                    if "/node_modules/" not in parent:
                        candidate = f"node_modules/{dependency_name}"
                        if candidate in path_refs:
                            dependencies[source].add(path_refs[candidate])
                        break
                    parent = parent.rsplit("/node_modules/", 1)[0]

    project = tomllib.loads((ROOT / "packages/navigator-python/pyproject.toml").read_text())
    python_root = "pkg:pypi/navigator-sdk@0.1.0"
    components[python_root] = {
        "type": "application", "name": "navigator-sdk", "version": "0.1.0",
        "bom-ref": python_root, "purl": python_root,
        "licenses": [{"expression": "Apache-2.0"}],
    }
    dependencies[python_root] = set()
    dependencies[workspace_root].add(python_root)
    venv_python = ROOT / "packages/navigator-python/.venv/bin/python"
    if not venv_python.is_file():
        fail("Python SDK environment is absent; installed dependency evidence required")
    metadata_program = """import importlib.metadata as m,json
from packaging.requirements import Requirement
roots=%s
seen={}; todo=list(roots)
while todo:
 n=todo.pop(0).lower()
 if n in seen: continue
 d=m.distribution(n); req=[]
 for value in d.requires or []:
  parsed=Requirement(value)
  if parsed.marker is not None and not parsed.marker.evaluate(): continue
  name=parsed.name.lower().replace('_','-')
  if name: req.append(name); todo.append(name)
 seen[n]={'name':d.metadata['Name'].lower().replace('_','-'),'version':d.version,'license':d.metadata.get('License'),'classifiers':d.metadata.get_all('Classifier') or [],'requires':req}
print(json.dumps(seen))""" % repr([re.split(r"[<>=!~ ]", value, maxsplit=1)[0].lower() for value in project["project"].get("dependencies", [])])
    installed = json.loads(subprocess.check_output([venv_python, "-c", metadata_program], text=True))
    classifier_licenses = {"License :: OSI Approved :: MIT License": "MIT", "License :: OSI Approved :: Apache Software License": "Apache-2.0", "License :: OSI Approved :: BSD License": "BSD-3-Clause"}
    python_refs: dict[str, str] = {}
    for key, package in installed.items():
        license_id = PYTHON_LICENSES.get(key)
        if license_id is None:
            raw = package.get("license")
            if raw in {"MIT", "Apache-2.0", "BSD-3-Clause"}:
                license_id = raw
            else:
                license_id = next((value for classifier, value in classifier_licenses.items() if classifier in package["classifiers"]), None)
        item = component("pypi", package["name"], package["version"], license_id or "UNKNOWN")
        python_refs[key] = str(item["bom-ref"])
        components[str(item["bom-ref"])] = item
        dependencies.setdefault(str(item["bom-ref"]), set())
    roots = [re.split(r"[<>=!~ ]", value, maxsplit=1)[0].lower() for value in project["project"].get("dependencies", [])]
    dependencies[python_root].update(python_refs[name] for name in roots)
    for key, package in installed.items():
        dependencies[python_refs[key]].update(python_refs[name] for name in package["requires"] if name in python_refs)
    graph = [{"ref": ref, "dependsOn": sorted(values)} for ref, values in sorted(dependencies.items())]
    return sorted(components.values(), key=lambda value: str(value["bom-ref"])), graph


def execute_cells(manifest: dict[str, object], output_dir: pathlib.Path) -> list[dict[str, object]]:
    results = []
    seen: set[str] = set()
    cargo_environment = os.environ.copy()
    cargo_environment.setdefault("CARGO_TARGET_DIR", str(ROOT / "target/task02-isolated"))
    for raw in manifest["executed_cells"]:
        cell = dict(raw)
        cell_id = str(cell["id"])
        if cell_id in seen:
            fail(f"duplicate matrix cell: {cell_id}")
        seen.add(cell_id)
        command = [str(value) for value in cell["command"]]
        runner = str(cell.get("runner", "cargo"))
        if runner == "pytest":
            result = execute_pytest_cell(cell_id, cell, command, output_dir)
            results.append(result)
            continue
        if runner != "cargo" or command[:2] != ["cargo", "test"] or len(command) < 3:
            fail(f"matrix cell has an invalid runner or Cargo command: {cell_id}")
        listed = subprocess.run(
            [*command, "--", "--list", "--format", "terse"], cwd=ROOT, text=True,
            env=cargo_environment,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
        )
        identities = [
            line.removesuffix(": test") for line in listed.stdout.splitlines()
            if line.endswith(": test")
        ]
        if listed.returncode or len(identities) != 1:
            fail(f"matrix cell filter must resolve exactly one test: {cell_id}: {identities}")
        test_identity = identities[0]
        exact_command = [*command[:-1], test_identity, "--", "--exact"]
        completed = subprocess.run(exact_command, cwd=ROOT, env=cargo_environment, text=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, check=False)
        log = completed.stdout
        (output_dir / f"cell-{cell_id}.log").write_text(log)
        passed = sum(int(value) for value in re.findall(r"(\d+) passed", log))
        exact_success = f"test {test_identity} ... ok" in log
        result = {"id": cell_id, "boundary": cell["boundary"], "attack": cell["attack"],
                  "command": exact_command, "listed_test_identity": test_identity,
                  "exit_code": completed.returncode, "passed_tests": passed,
                  "log_sha256": hashlib.sha256(log.encode()).hexdigest()}
        results.append(result)
        if completed.returncode or passed != 1 or not exact_success:
            fail(f"matrix cell did not execute a passing test: {cell_id}")
    if seen != REQUIRED_CELLS:
        fail(f"matrix cell completeness mismatch: missing={sorted(REQUIRED_CELLS - seen)}, extra={sorted(seen - REQUIRED_CELLS)}")
    return results


def execute_pytest_cell(
    cell_id: str,
    cell: dict[str, object],
    command: list[str],
    output_dir: pathlib.Path,
) -> dict[str, object]:
    helper = "scripts/run-exact-pytest.py"
    expected_python = "packages/navigator-python/.venv/bin/python"
    if len(command) != 3 or command[:2] != [expected_python, helper]:
        fail(f"pytest cell must name the pinned interpreter, helper, and one node id: {cell_id}")
    nodeid = command[2]
    if "::" not in nodeid or nodeid.startswith("-"):
        fail(f"pytest cell is not an exact node id: {cell_id}")
    environment = os.environ.copy()
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    collect_path = (output_dir / f"cell-{cell_id}-collect.json").resolve()
    execute_path = (output_dir / f"cell-{cell_id}-result.json").resolve()
    collected = subprocess.run(
        [*command[:2], "--collect", "--result", str(collect_path), nodeid],
        cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    if not collect_path.is_file():
        fail(f"pytest cell produced no collection result: {cell_id}")
    collection = json.loads(collect_path.read_text())
    if (
        collected.returncode != 0
        or collection.get("schema") != 1
        or collection.get("mode") != "collect"
        or collection.get("requested") != nodeid
        or collection.get("collected") != [nodeid]
        or collection.get("reports") != []
        or collection.get("exit_code") != 0
    ):
        fail(f"pytest cell must collect exactly its requested node id: {cell_id}")
    completed = subprocess.run(
        [*command[:2], "--result", str(execute_path), nodeid],
        cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, check=False,
    )
    if not execute_path.is_file():
        fail(f"pytest cell produced no execution result: {cell_id}")
    execution_bytes = execute_path.read_bytes()
    execution = json.loads(execution_bytes)
    reports = execution.get("reports")
    expected_reports = [
        {"nodeid": nodeid, "when": phase, "outcome": "passed", "wasxfail": None}
        for phase in ("setup", "call", "teardown")
    ]
    if (
        completed.returncode != 0
        or execution.get("schema") != 1
        or execution.get("mode") != "execute"
        or execution.get("requested") != nodeid
        or execution.get("collected") != [nodeid]
        or reports != expected_reports
        or execution.get("exit_code") != 0
        or execution.get("pytest_version") != collection.get("pytest_version")
    ):
        fail(f"pytest cell did not execute one clean passing call: {cell_id}")
    log = collected.stdout + "\n--- execution ---\n" + completed.stdout
    log_path = output_dir / f"cell-{cell_id}.log"
    log_path.write_text(log)
    return {
        "id": cell_id, "boundary": cell["boundary"], "attack": cell["attack"],
        "runner": "pytest", "command": command, "listed_test_identity": nodeid,
        "exit_code": completed.returncode, "passed_tests": 1,
        "pytest_version": execution["pytest_version"],
        "structured_result_sha256": hashlib.sha256(execution_bytes).hexdigest(),
        "log_sha256": hashlib.sha256(log.encode()).hexdigest(),
    }


def main() -> None:
    output_dir = pathlib.Path(sys.argv[1]) if len(sys.argv) == 2 else ROOT / "target/security-compatibility"
    if output_dir.exists() and any(output_dir.iterdir()):
        fail(f"evidence output must be fresh and empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text())
    if manifest.get("status") != "awaiting-adversarial-review":
        fail("security evidence must not self-declare verified")
    schema_source = ROOT / manifest["boundaries"]["store"]["current_schema_source"]
    match = re.search(r"SCHEMA_VERSION:\s*i64\s*=\s*(\d+)", schema_source.read_text())
    if not match:
        fail("could not derive current Store schema")
    current = int(match.group(1))
    historical = manifest["boundaries"]["store"]["compatible_fixture_schemas"]
    if current != 20 or historical != [18, 19]:
        fail(f"stale Store compatibility evidence: current={current}, historical={historical}")
    for fixture in manifest["compatibility_fixtures"]:
        if not (ROOT / fixture["path"]).is_file():
            fail(f"missing compatibility fixture: {fixture['path']}")
    fixture_provenance = json.loads(
        (ROOT / "crates/navigator-store-sqlite/fixtures/release/PROVENANCE.json").read_text()
    )
    for fixture in fixture_provenance.get("fixtures", []):
        fixture_path = ROOT / "crates/navigator-store-sqlite/fixtures/release" / fixture["path"]
        actual = hashlib.sha256(fixture_path.read_bytes()).hexdigest()
        if actual != fixture["sha256"]:
            fail(f"frozen Store fixture digest drifted: {fixture['path']}")
    consumer_source = ROOT / manifest["boundaries"]["consumer"]["service_source"]
    consumer_rpcs = set(re.findall(r"^\s*rpc\s+(\w+)\s*\(", consumer_source.read_text(), re.MULTILINE))
    if not consumer_rpcs:
        fail("could not derive Consumer RPC surface")
    declared_consumer = {
        boundary.split("/", 1)[1]
        for cell in manifest["executed_cells"] for boundary in cell["boundary"]
        if boundary.startswith("Consumer/") and boundary.split("/", 1)[1] != "decoder"
    }
    if invalid := declared_consumer - consumer_rpcs:
        fail(f"matrix names unknown Consumer RPCs: {sorted(invalid)}")

    matrix = execute_cells(manifest, output_dir)
    (output_dir / "endpoint-matrix.json").write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n")

    with tempfile.NamedTemporaryFile(dir=ROOT, prefix=".secret-sentinel-", delete=False) as handle:
        sentinel = pathlib.Path(handle.name)
        handle.write(
            b"-----BEGIN " + b"PRIVATE KEY-----\n" + b"AK" + b"IAABCDEFGHIJKLMNOP\n"
            + b"g" + b"hp_abcdefghijklmnopqrstuvwxyz123456\n"
            + b"s" + b"k-abcdefghijklmnopqrstuvwxyz1234567890\n"
        )
    try:
        _, sentinel_findings = scan(relevant_files(sentinel))
        sentinel_name = str(sentinel.relative_to(ROOT))
        if {item["kind"] for item in sentinel_findings if item["path"] == sentinel_name} != set(SECRET_PATTERNS):
            fail("secret sentinel escaped the actual file scanner")
    finally:
        sentinel.unlink(missing_ok=True)
    inventory, findings = scan(relevant_files())
    report = {"schema": 2, "files_scanned": len(inventory), "inventory": inventory, "findings": findings,
              "includes_extensionless_and_binary_metadata": True}
    (output_dir / "secret-scan.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if findings:
        fail(f"secret scan findings: {findings}")

    components, dependency_graph = supply_chain()
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000020",
            "version": 1, "metadata": {"component": {"type": "application", "name": "navigator", "version": "0.1.0", "bom-ref": "urn:navigator:workspace"}},
            "components": components, "dependencies": dependency_graph}
    (output_dir / "sbom.cdx.json").write_text(json.dumps(sbom, indent=2, sort_keys=True) + "\n")
    pinned_schemas = {
        "cyclonedx-bom-1.5.schema.json": "067f7824b08653839ea050ae9e09ca48375eadc2652b0e2a299476e7db90335b",
        "cyclonedx-spdx.schema.json": "4f6e2b05c05d26a4f2dc5879fbc2fca94b0a28db46289d0c51345621b71cfbfc",
        "cyclonedx-jsf-0.82.schema.json": "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae",
    }
    if any(hashlib.sha256((ROOT / "conformance" / name).read_bytes()).hexdigest() != digest for name, digest in pinned_schemas.items()):
        fail("vendored official CycloneDX schema digest drifted")
    subprocess.run(
        ["node", "scripts/validate-cyclonedx.js", str(output_dir / "sbom.cdx.json")],
        cwd=ROOT, check=True,
    )
    licenses = [{"bom-ref": item["bom-ref"], "license": item["licenses"][0]["expression"]} for item in components]
    (output_dir / "licenses.json").write_text(json.dumps({"schema": 2, "components": licenses}, indent=2, sort_keys=True) + "\n")
    summary = {"status": manifest["status"], "manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
               "executed_cells": len(matrix), "components": len(components), "files_scanned": len(inventory),
               "current_store_schema": current, "future_schema_probe": current + 1,
               "consumer_rpc_count": len(consumer_rpcs),
               "python_marker_environment": {
                   "system": platform.system(), "machine": platform.machine(),
                   "python": platform.python_version(),
               }}
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    toolchains = {
        "rustc": subprocess.check_output(["rustc", "--version", "--verbose"], text=True),
        "cargo": subprocess.check_output(["cargo", "--version", "--verbose"], text=True),
        "python": subprocess.check_output([sys.executable, "--version"], text=True, stderr=subprocess.STDOUT),
        "node": subprocess.check_output(["node", "--version"], text=True),
    }
    source_digest = hashlib.sha256(
        "\n".join(f"{item['path']}\0{item['sha256']}" for item in inventory).encode()
    ).hexdigest()
    output_digests = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(output_dir.iterdir()) if path.is_file()
    }
    evidence_index = {
        "schema": 1, "fresh_output": True, "source_tree_sha256": source_digest,
        "toolchains": toolchains, "outputs": output_digests,
    }
    (output_dir / "evidence-index.json").write_text(
        json.dumps(evidence_index, indent=2, sort_keys=True) + "\n"
    )


if __name__ == "__main__":
    main()
