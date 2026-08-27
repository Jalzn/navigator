#!/usr/bin/env python3
"""Build or verify the deterministic local release bundle.

Infrastructure verification is intentionally distinct from release authorization:
`--require-release` fails while predecessor reviews or executable claims are open.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import tarfile
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "conformance/release-v1.json"
TRACEABILITY = ROOT / "conformance/release-traceability-v1.json"
TASK03_REVIEW = ROOT / "plans/12-hardening/FAULT-MATRIX-REVIEW.md"
TASK03_ATTESTATION = ROOT / "conformance/task03-review-attestation.json"
FAULT_EVIDENCE = ROOT / "target/conformance/fault-matrix-task03-final.jsonl"
SMOKE_COMMAND_ID = "navigator.release.extracted-smoke.v1"
SMOKE_CLAIM = "extracted install/reset/failure/recovery/shutdown/leak sweep"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def status(path: Path) -> str | None:
    match = re.search(r"^status:\s*([a-z_]+)\s*$", path.read_text(), re.MULTILINE)
    return match.group(1) if match else None


def source_contains(symbol: str) -> bool:
    completed = subprocess.run(
        ["rg", "-l", "--fixed-strings", symbol, "crates", "packages", "scripts"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def current_security_inventory() -> tuple[list[dict[str, Any]], str]:
    skipped = {
        ".git", "target", "evidence", "node_modules", ".venv", "__pycache__",
        ".mypy_cache", ".pytest_cache", ".ruff_cache",
    }
    inventory: list[dict[str, Any]] = []
    for base, directories, names in os.walk(ROOT):
        directories[:] = sorted(name for name in directories if name not in skipped)
        for name in sorted(names):
            path = Path(base, name)
            if not (path.is_file() or path.is_symlink()):
                continue
            data = path.read_bytes()
            row: dict[str, Any] = {
                "path": str(path.relative_to(ROOT)),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "kind": "symlink" if path.is_symlink() else "file",
            }
            if path.is_symlink():
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(ROOT):
                    raise ValueError(f"workspace symlink escapes source root: {path}")
                row["target"] = str(resolved.relative_to(ROOT))
            inventory.append(row)
    # Match check-security-compatibility.py's `sorted(Path)` ordering exactly;
    # string ordering differs for a file and a descendant directory sharing a
    # prefix (for example `server.json` versus `server/...`).
    inventory.sort(key=lambda row: Path(row["path"]))
    digest = hashlib.sha256(
        "\n".join(f"{row['path']}\0{row['sha256']}" for row in inventory).encode()
    ).hexdigest()
    return inventory, digest


def must_requirements() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((ROOT / "docs").rglob("*.md")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(r"\bMUST(?: NOT)?\b", line):
                identifiers = re.findall(r"\[([A-Z][A-Z0-9-]+-\d{3})\]", line)
                rows.append(
                    {
                        "document": str(path.relative_to(ROOT)),
                        "line": number,
                        "text": line.strip(),
                        "identifiers": identifiers,
                    }
                )
    return rows


def verify_traceability(serialized: str | None = None) -> dict[str, Any]:
    requirements = must_requirements()
    invalid = [row for row in requirements if len(row["identifiers"]) != 1]
    if invalid:
        raise ValueError(f"each MUST line needs exactly one canonical guarantee ID: {invalid}")
    canonical = {row["identifiers"][0] for row in requirements}
    if len(canonical) != len(requirements):
        raise ValueError("canonical guarantee IDs are not unique")
    manifest = json.loads(serialized if serialized is not None else TRACEABILITY.read_text())
    mapped: set[str] = set()
    unbound_tests: list[str] = []
    for evidence in manifest["evidence"]:
        guarantees = set(evidence["guarantees"])
        unknown = guarantees.difference(canonical)
        if unknown:
            raise ValueError(f"unknown guarantee for {evidence['test']}: {sorted(unknown)}")
        if not guarantees:
            unbound_tests.append(evidence["test"])
            continue
        source = (ROOT / evidence["source"]).read_text()
        declaration = f"Guarantees: {', '.join(evidence['guarantees'])}"
        if declaration not in source or evidence["test"] not in source:
            raise ValueError(f"test declaration does not reciprocate manifest: {evidence['test']}")
        mapped.update(guarantees)
    return {
        "requirements": requirements,
        "unmapped_guarantees": sorted(canonical.difference(mapped)),
        "unbound_tests": sorted(unbound_tests),
    }


def verify_security_outputs(
    directory: Path, attestation_path: Path | None = None
) -> list[str]:
    directory = directory.resolve()
    errors: list[str] = []
    try:
        summary = json.loads((directory / "summary.json").read_text())
        licenses = json.loads((directory / "licenses.json").read_text())
        sbom = json.loads((directory / "sbom.cdx.json").read_text())
        secrets = json.loads((directory / "secret-scan.json").read_text())
        index = json.loads((directory / "evidence-index.json").read_text())
    except (OSError, json.JSONDecodeError) as error:
        return [f"security-output-unreadable:{error}"]
    expected_digest = sha256(ROOT / "conformance/security-compatibility-v1.json")
    try:
        attestation = json.loads(attestation_path.read_text()) if attestation_path else {}
    except (OSError, json.JSONDecodeError) as error:
        return [f"security-attestation-unreadable:{error}"]
    evidence_relative = (
        str(directory.relative_to(ROOT)) if directory.is_relative_to(ROOT) else None
    )
    attested = (
        attestation.get("verdict") == "GO"
        and attestation.get("evidence_directory") == evidence_relative
        and attestation.get("evidence_index_sha256") == sha256(directory / "evidence-index.json")
        and attestation.get("source_tree_sha256") == index.get("source_tree_sha256")
        and attestation.get("endpoint_matrix_sha256") == sha256(directory / "endpoint-matrix.json")
        and attestation.get("sbom_sha256") == sha256(directory / "sbom.cdx.json")
    )
    if not attested:
        errors.append("security-review-not-go")
    indexed = index.get("outputs", {})
    for name, digest in indexed.items():
        path = directory / name
        if not path.is_file() or sha256(path) != digest:
            errors.append(f"security-index-digest-mismatch:{name}")
    if summary.get("status") not in {"verified", "awaiting-adversarial-review"}:
        errors.append(f"security-status:{summary.get('status')}")
    if summary.get("manifest_sha256") != expected_digest:
        errors.append("security-manifest-digest-mismatch")
    if summary.get("current_store_schema") != 20 or summary.get("future_schema_probe") != 21:
        errors.append("security-schema-range-mismatch")
    legacy_attested = index.get("schema") == 1 and attested
    if licenses.get("schema") not in ({None, 2} if legacy_attested else {2}) or not isinstance(licenses.get("components"), list):
        errors.append("licenses-schema-invalid")
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") not in {"1.5", "1.6"}:
        errors.append("sbom-schema-invalid")
    if secrets.get("schema") not in ({None, 2} if legacy_attested else {2}) or secrets.get("findings") != []:
        errors.append("secret-scan-not-clean")
    current_inventory, current_digest = current_security_inventory()
    if secrets.get("inventory") != current_inventory or index.get("source_tree_sha256") != current_digest:
        errors.append("security-source-tree-mismatch")
    return errors


def verify_fault_matrix_outputs() -> list[str]:
    errors: list[str] = []
    digest_path = FAULT_EVIDENCE.with_suffix(".digests")
    results = FAULT_EVIDENCE.parent / f"{FAULT_EVIDENCE.stem}-results"
    log = FAULT_EVIDENCE.with_suffix(".log")
    try:
        digests = dict(
            line.split(": ", 1)
            for line in digest_path.read_text().splitlines()
            if ": " in line
        )
        records = [json.loads(line) for line in FAULT_EVIDENCE.read_text().splitlines()]
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return [f"fault-evidence-unreadable:{error}"]
    raw_paths = sorted(results.glob("*.json"))
    raw_manifest = "".join(
        f"{sha256(path)}  {path.relative_to(ROOT)}\n" for path in raw_paths
    ).encode()
    checks = {
        "jsonl_sha256": sha256(FAULT_EVIDENCE),
        "log_sha256": sha256(log),
        "raw_sorted_sha256_manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
        "validator_sha256": sha256(ROOT / "scripts/check-fault-matrix.py"),
        "mutants_sha256": sha256(ROOT / "scripts/test-fault-matrix.py"),
    }
    if any(digests.get(name) != value for name, value in checks.items()):
        errors.append("fault-evidence-digest-mismatch")
    if len(records) != 85 or len(raw_paths) != 85 or any(
        not all(record.get("final_invariants", {}).values()) for record in records
    ):
        errors.append("fault-evidence-cardinality-or-invariant")
    review = TASK03_REVIEW.read_text()
    attestation = json.loads(TASK03_ATTESTATION.read_text())
    if (
        "Status: **GO**" not in review
        or attestation.get("verdict") != "GO"
        or attestation.get("jsonl_sha256") != checks["jsonl_sha256"]
        or attestation.get("case_count") != len(records)
        or attestation.get("raw_result_count") != len(raw_paths)
        or attestation.get("raw_sorted_sha256_manifest_sha256")
        != checks["raw_sorted_sha256_manifest_sha256"]
    ):
        errors.append("fault-review-not-go")
    return errors


def verify(
    contract: dict[str, Any], security_dir: Path,
    security_attestation: Path | None = None,
) -> tuple[list[str], dict[str, Any]]:
    blockers: list[str] = []
    for relative in contract["blocking_tasks"]:
        task_status = status(ROOT / relative)
        if task_status != "verified":
            blockers.append(f"dependency-not-verified:{relative}:{task_status}")
    schema_source = ROOT / contract["protocols"]["store"]["current_schema_source"]
    blockers.extend(verify_fault_matrix_outputs())
    match = re.search(r"SCHEMA_VERSION:\s*i64\s*=\s*(\d+)", schema_source.read_text())
    if not match:
        raise SystemExit("release gate cannot derive Store schema")
    schema = int(match.group(1))
    if schema != 20:
        blockers.append(f"unreviewed-store-schema:{schema}")
    host_os = {"darwin": "macos"}.get(platform.system().lower(), platform.system().lower())
    host_arch = {"arm64": "aarch64"}.get(platform.machine().lower(), platform.machine().lower())
    supported = {(row["os"], row["arch"]) for row in contract["supported_platforms"]}
    if len(supported) != len(contract["supported_platforms"]):
        blockers.append("duplicate-supported-platform")
    if (host_os, host_arch) not in supported:
        blockers.append(f"unsupported-build-host:{host_os}-{host_arch}")
    capability_source = (ROOT / contract["capabilities_source"]).read_text()
    capabilities = sorted(set(re.findall(r'pub const CAPABILITY_[A-Z0-9_]+: &str = "([^"]+)"', capability_source)))
    if not capabilities:
        blockers.append("capability-inventory-empty")
    for oracle in contract["release_oracles"]:
        symbol = oracle["evidence"]
        if not source_contains(symbol):
            blockers.append(f"missing-release-oracle:{oracle['claim']}:{symbol}")
    mutation = json.loads((ROOT / contract["critical_mutation_manifest"]).read_text())
    for row in mutation["mutations"]:
        if not source_contains(row["evidence"]):
            blockers.append(f"missing-critical-mutant:{row['id']}:{row['evidence']}")
    for name in contract["bundle"]["required_evidence"]:
        if not (security_dir / name).is_file():
            blockers.append(f"missing-security-output:{name}")
    blockers.extend(verify_security_outputs(security_dir, security_attestation))
    traceability = verify_traceability()
    if traceability["unmapped_guarantees"]:
        blockers.append(
            f"must-traceability-unmapped:{len(traceability['unmapped_guarantees'])}"
        )
    if traceability["unbound_tests"]:
        blockers.append(f"semantic-tests-unbound:{len(traceability['unbound_tests'])}")
    facts = {
        "schema_version": 1,
        "release_status": "blocked" if blockers else "eligible",
        "current_store_schema": schema,
        "supported_platforms": sorted([list(pair) for pair in supported]),
        "capabilities": capabilities,
        "traceability": traceability,
        "blockers": blockers,
    }
    return blockers, facts


def copy_tree(source: Path, destination: Path, *, omit_node_modules: bool = True) -> None:
    omitted = [
        "__pycache__", "*.pyc", ".venv", ".ruff_cache", ".mypy_cache", ".pytest_cache"
    ]
    if omit_node_modules:
        omitted.append("node_modules")
    shutil.copytree(
        source,
        destination,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(*omitted),
    )


def _evidence_row(base: Path, path: Path, **fields: Any) -> dict[str, Any]:
    return {
        **fields,
        "path": str(path.resolve().relative_to(base.resolve())),
        "sha256": sha256(path),
    }


def _safe_evidence_path(base: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative:
        raise ValueError("evidence path must be a non-empty relative string")
    wire = Path(relative)
    if wire.is_absolute() or ".." in wire.parts:
        raise ValueError("evidence path escapes its root")
    root = base.resolve()
    candidate = (base / wire).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise ValueError("evidence path resolves outside its root") from error
    return candidate


def _canonical_digest(value: Any) -> str:
    wire = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(wire).hexdigest()


def verify_execution_evidence(
    base: Path, index_path: Path, expected_archive: Path | None = None,
) -> list[str]:
    """Verify the closed prebuild or authorization execution evidence schema."""
    try:
        index = json.loads(index_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        return [f"execution-evidence-unreadable:{error}"]
    errors: list[str] = []
    entries = index.get("entries")
    if not isinstance(entries, list):
        return ["execution-evidence-index-invalid"]
    paths: list[str] = []
    for row in entries:
        try:
            path = _safe_evidence_path(base, row["path"])
            paths.append(row["path"])
            if not path.is_file():
                errors.append(f"execution-evidence-missing:{row.get('path')}")
            elif sha256(path) != row.get("sha256"):
                errors.append(f"execution-evidence-digest:{row.get('path')}")
            if not isinstance(row.get("exit"), int):
                errors.append(f"execution-evidence-exit:{row.get('path')}")
            kind = row.get("kind")
            if kind == "release-oracle" and (
                not isinstance(row.get("command"), list)
                or not isinstance(row.get("claim"), str)
                or not row["claim"]
            ):
                errors.append(f"execution-evidence-claim:{row.get('path')}")
            elif kind == "extracted-smoke" and (
                row.get("command_id") != SMOKE_COMMAND_ID
                or row.get("claim") != SMOKE_CLAIM
                or not isinstance(row.get("artifact_archive_path"), str)
                or not isinstance(row.get("artifact_archive_sha256"), str)
            ):
                errors.append(f"execution-evidence-smoke-identity:{row.get('path')}")
            elif kind == "critical-mutant" and (
                not isinstance(row.get("command"), list)
                or not isinstance(row.get("expected_marker"), str)
                or row.get("marker_observed") is not True
            ):
                errors.append(f"execution-evidence-marker:{row.get('path')}")
            elif kind not in {
                "release-oracle", "extracted-smoke", "critical-mutant",
                "critical-mutant-report",
            }:
                errors.append(f"execution-evidence-kind:{row.get('path')}")
        except (KeyError, TypeError, ValueError):
            errors.append("execution-evidence-row-invalid")
    if len(paths) != len(set(paths)):
        errors.append("execution-evidence-duplicate-path")
    phase = index.get("phase")
    contract = json.loads(CONTRACT.read_text())
    expected_oracles = {
        (tuple(row["command"]), row["claim"]) for row in contract["release_oracles"]
    }
    oracle_rows = [row for row in entries if row.get("kind") == "release-oracle"]
    mutant_reports = [row for row in entries if row.get("kind") == "critical-mutant-report"]
    mutant_rows = [row for row in entries if row.get("kind") == "critical-mutant"]
    smoke_rows = [row for row in entries if row.get("kind") == "extracted-smoke"]
    actual_oracles = {
        (tuple(row.get("command", [])), row.get("claim")) for row in oracle_rows
    }
    mutant_definitions = json.loads(
        (ROOT / contract["critical_mutation_manifest"]).read_text()
    )["mutations"]
    expected_mutants = {row["id"] for row in mutant_definitions}
    definitions_by_id = {row["id"]: row for row in mutant_definitions}
    mutant_tuples_valid = all(
        row.get("id") in definitions_by_id
        and row.get("command") == definitions_by_id[row["id"]]["command"]
        and row.get("exit") == definitions_by_id[row["id"]]["expected_exit"]
        and row.get("expected_exit") == definitions_by_id[row["id"]]["expected_exit"]
        and row.get("expected_marker")
        == definitions_by_id[row["id"]]["expected_failure_marker"]
        and row.get("registry_entry_sha256")
        == _canonical_digest(definitions_by_id[row["id"]])
        for row in mutant_rows
    )
    common_valid = (
        len(oracle_rows) == 5
        and actual_oracles == expected_oracles
        and all(row.get("exit") == 0 for row in oracle_rows)
        and len(mutant_reports) == 1
        and mutant_reports[0].get("exit") == 0
        and len(mutant_rows) == 6
        and {row.get("id") for row in mutant_rows} == expected_mutants
        and mutant_tuples_valid
    )
    if len(mutant_reports) == 1:
        try:
            mutant_report_path = _safe_evidence_path(base, mutant_reports[0]["path"])
            derived_rows, derived_errors = _mutant_evidence(base, mutant_report_path)
            if derived_errors or derived_rows != mutant_reports + mutant_rows:
                errors.append("execution-evidence-mutant-report-closure")
        except (KeyError, TypeError, ValueError):
            errors.append("execution-evidence-mutant-report-closure")
    if phase == "prebuild":
        if (
            not common_valid or smoke_rows or len(entries) != 12
            or "prebuild_index" in index or expected_archive is not None
        ):
            errors.append("execution-evidence-prebuild-shape")
    elif phase == "authorization":
        linked = index.get("prebuild_index")
        try:
            linked_path = _safe_evidence_path(base, linked["path"])
            if not linked_path.is_file() or sha256(linked_path) != linked["sha256"]:
                errors.append("execution-evidence-prebuild-closure")
                linked_index = {}
            else:
                linked_index = json.loads(linked_path.read_text())
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
            errors.append("execution-evidence-prebuild-closure")
            linked_index = {}
        expected_entries = linked_index.get("entries", [])
        without_smoke = [row for row in entries if row.get("kind") != "extracted-smoke"]
        if (
            not common_valid
            or len(smoke_rows) != 1
            or smoke_rows[0].get("exit") != 0
            or len(entries) != 13
            or without_smoke != expected_entries
        ):
            errors.append("execution-evidence-authorization-shape")
        if expected_archive is None or len(smoke_rows) != 1:
            errors.append("execution-evidence-archive-binding")
        else:
            try:
                report_root = base.parent.resolve()
                archive = expected_archive.resolve()
                canonical = str(archive.relative_to(report_root))
                safely_reopened = _safe_evidence_path(report_root, canonical)
                smoke = smoke_rows[0]
                digest = smoke.get("artifact_archive_sha256")
                if (
                    safely_reopened != archive
                    or expected_archive.is_symlink()
                    or not archive.is_file()
                    or smoke.get("artifact_archive_path") != canonical
                    or not isinstance(digest, str)
                    or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                    or sha256(archive) != digest
                ):
                    errors.append("execution-evidence-archive-binding")
            except (OSError, ValueError):
                errors.append("execution-evidence-archive-binding")
    else:
        errors.append("execution-evidence-phase-invalid")
    if index.get("schema_version") != 1:
        errors.append("execution-evidence-index-invalid")
    return errors


def _mutant_evidence(base: Path, report_path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    errors: list[str] = []
    rows: list[dict[str, Any]] = []
    try:
        report = json.loads(report_path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        return [], [f"critical-mutant-report-unreadable:{error}"]
    contract = json.loads(CONTRACT.read_text())
    registry = json.loads((ROOT / contract["critical_mutation_manifest"]).read_text())
    expected = {row["id"]: row for row in registry["mutations"]}
    results = report.get("results")
    if report.get("schema_version") != 2 or not isinstance(results, list):
        return [], ["critical-mutant-report-schema"]
    if len(results) != 6 or {row.get("id") for row in results} != set(expected):
        return [], ["critical-mutant-report-identity"]
    rows.append(_evidence_row(base, report_path, kind="critical-mutant-report", exit=0))
    for result in results:
        definition = expected[result["id"]]
        try:
            transcript = _safe_evidence_path(report_path.parent, result.get("transcript"))
            transcript.relative_to(base.resolve())
        except (ValueError, TypeError):
            errors.append(f"critical-mutant-evidence-invalid:{result.get('id')}")
            continue
        marker = result.get("expected_failure_marker")
        try:
            contents = transcript.read_text()
        except OSError:
            contents = ""
        observed = isinstance(marker, str) and marker in contents
        if (
            not transcript.is_file()
            or sha256(transcript) != result.get("transcript_sha256")
            or result.get("oracle_exit") != result.get("expected_exit")
            or result.get("command") != definition["command"]
            or result.get("expected_exit") != definition["expected_exit"]
            or marker != definition["expected_failure_marker"]
            or result.get("registry_entry_sha256") != _canonical_digest(definition)
            or result.get("failure_marker_observed") is not True
            or not observed
            or result.get("killed") is not True
        ):
            errors.append(f"critical-mutant-evidence-invalid:{result.get('id')}")
            continue
        rows.append(_evidence_row(
            base, transcript, kind="critical-mutant", id=result["id"],
            command=result.get("command"), exit=result["oracle_exit"],
            expected_exit=result["expected_exit"], expected_marker=marker,
            registry_entry_sha256=result["registry_entry_sha256"],
            marker_observed=observed,
        ))
    if len(rows) != 7:
        errors.append("critical-mutant-evidence-cardinality")
    return rows, errors


def _run_transcribed(command: list[str], cwd: Path, transcript: Path) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command, cwd=cwd, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    combined = completed.stdout
    transcript.parent.mkdir(parents=True, exist_ok=True)
    transcript.write_text(combined)
    if combined:
        print(combined, end="")
    return completed


def _capture_callable(transcript: Path, function: Any, *args: Any) -> None:
    """Capture Python and inherited subprocess output while retaining a durable log."""
    transcript.parent.mkdir(parents=True, exist_ok=True)
    saved_out, saved_err = os.dup(1), os.dup(2)
    try:
        with transcript.open("wb") as target:
            os.dup2(target.fileno(), 1)
            os.dup2(target.fileno(), 2)
            print("release-smoke: extracted lifecycle begin", flush=True)
            function(*args)
            print("release-smoke: reset/failure/shutdown/leak checks passed", flush=True)
    finally:
        os.dup2(saved_out, 1)
        os.dup2(saved_err, 2)
        os.close(saved_out)
        os.close(saved_err)
    if transcript.stat().st_size:
        print(transcript.read_text(errors="replace"), end="")


def write_deterministic_archive(output: Path, archive_root: str) -> Path:
    """Archive a bundle independently of its physical witness directory name."""
    archive = output.with_suffix(".tar")
    with tarfile.open(archive, "w", format=tarfile.PAX_FORMAT) as target:
        for path in sorted(output.rglob("*")):
            info = target.gettarinfo(
                path, arcname=str(Path(archive_root) / path.relative_to(output))
            )
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            if path.is_file():
                with path.open("rb") as source:
                    target.addfile(info, source)
            else:
                target.addfile(info)
    return archive


def build_bundle(
    contract: dict[str, Any], output: Path, security_dir: Path,
    security_attestation: Path,
    archive_root: str | None = None,
    execution_evidence: Path | None = None,
) -> None:
    with tempfile.TemporaryDirectory(prefix="navigator-release-") as temporary:
        staging = Path(temporary) / "bundle"
        (staging / "bin").mkdir(parents=True)
        subprocess.run(["cargo", "build", "--release", "--locked", "--offline", "-p", "navigator-local"], cwd=ROOT, check=True)
        for binary in contract["bundle"]["rust_binaries"]:
            shutil.copy2(ROOT / "target/release" / binary, staging / "bin" / binary)
        subprocess.run(["npm", "ci", "--ignore-scripts"], cwd=ROOT / contract["bundle"]["pi_driver"], check=True)
        subprocess.run(["npm", "run", "build"], cwd=ROOT / contract["bundle"]["pi_driver"], check=True)
        copy_tree(ROOT / contract["bundle"]["pi_driver"] / "dist", staging / "pi-driver")
        copy_tree(
            ROOT / contract["bundle"]["python_sdk"],
            staging / "python-sdk",
            omit_node_modules=False,
        )
        python = ROOT / contract["bundle"]["python_sdk"] / ".venv/bin/python"
        if not python.is_file():
            raise SystemExit("pinned Python build environment is absent; run the Python SDK gate")
        node = subprocess.run(
            ["mise", "which", "node"], cwd=ROOT, check=True, text=True, capture_output=True
        ).stdout.strip()
        subprocess.run(
            [
                str(python),
                str(staging / "python-sdk/scripts/prepare_runtime.py"),
                str(ROOT / "target/release/navigatord"),
                "--target", "darwin-arm64",
                "--node", node,
                "--pi-package", str(ROOT / contract["bundle"]["pi_driver"]),
                "--protocol-package", str(ROOT / "crates/navigator-driver-protocol/typescript"),
                "--output", str(staging / "python-sdk/src/navigator/_runtime"),
            ],
            cwd=ROOT,
            check=True,
        )
        wheel_dir = staging / "wheels"
        wheel_dir.mkdir()
        subprocess.run(
            [str(python), "-m", "build", "--wheel", "--no-isolation", "--outdir", str(wheel_dir)],
            cwd=staging / "python-sdk",
            check=True,
        )
        # The wheel backend imports hatch_build.py and may leave a timestamped
        # bytecode cache in the copied source tree. It is neither a release
        # input nor reproducible, so remove all build-created caches before the
        # manifest is computed.
        for cache in (staging / "python-sdk").rglob("__pycache__"):
            shutil.rmtree(cache)
        wheelhouse = staging / "wheelhouse"
        wheelhouse.mkdir()
        wheel = next(wheel_dir.glob("navigator_sdk-*.whl"))
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", "--wheel-dir", str(wheelhouse), str(wheel)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        copy_tree(ROOT / contract["bundle"]["migrations"], staging / "migrations")
        for schema in contract["bundle"]["schemas"]:
            source = Path(schema)
            destination = f"{source.parent.name}-{source.name}"
            copy_tree(ROOT / schema, staging / "schemas" / destination)
        copy_tree(security_dir, staging / "evidence/security-compatibility")
        copy_tree(
            FAULT_EVIDENCE.parent / f"{FAULT_EVIDENCE.stem}-results",
            staging / "evidence/fault-matrix/results",
        )
        for path in (
            FAULT_EVIDENCE,
            FAULT_EVIDENCE.with_suffix(".log"),
            FAULT_EVIDENCE.with_suffix(".digests"),
            TASK03_REVIEW,
            security_attestation,
            TASK03_ATTESTATION,
        ):
            shutil.copy2(path, staging / "evidence" / path.name)
        shutil.copy2(CONTRACT, staging / "release-contract.json")
        if execution_evidence is not None:
            copy_tree(execution_evidence, staging / "evidence/execution")
        files = sorted(path for path in staging.rglob("*") if path.is_file())
        checksums = [{"path": str(path.relative_to(staging)), "sha256": sha256(path), "size": path.stat().st_size} for path in files]
        manifest = {
            "schema_version": 1,
            "build_host": {"os": platform.system().lower(), "arch": platform.machine().lower()},
            "bindings": {
                "release_contract_sha256": sha256(CONTRACT),
                "security_evidence_index_sha256": sha256(security_dir / "evidence-index.json"),
                "security_attestation_sha256": sha256(security_attestation),
                "fault_matrix_sha256": sha256(FAULT_EVIDENCE),
                "fault_matrix_digests_sha256": sha256(FAULT_EVIDENCE.with_suffix(".digests")),
                "fault_review_sha256": sha256(TASK03_REVIEW),
                "fault_attestation_sha256": sha256(TASK03_ATTESTATION),
                "source_tree_sha256": json.loads((security_dir / "evidence-index.json").read_text())["source_tree_sha256"],
                "toolchains": json.loads((security_dir / "evidence-index.json").read_text())["toolchains"],
                "execution_prebuild_index_sha256": (
                    sha256(execution_evidence / "prebuild-index.json")
                    if execution_evidence is not None else None
                ),
            },
            "files": checksums,
        }
        (staging / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        (staging / "SHA256SUMS").write_text("".join(f"{row['sha256']}  {row['path']}\n" for row in checksums))
        if output.exists():
            shutil.rmtree(output)
        shutil.copytree(staging, output)
        write_deterministic_archive(output, archive_root or output.name)


def _assert_extracted_reset_cleanup(
    output: Path, installed: Path, temporary: Path
) -> None:
    """Exercise reset from installed artifacts without touching an unrelated PID."""
    data = temporary / "reset-data"
    unrelated = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True)
    try:
        completed = subprocess.run(
            [str(installed), str(output / "python-sdk/examples/acceptance_workflow.py")],
            check=False,
            cwd=temporary,
            env={
                "HOME": os.environ["HOME"],
                "LANG": os.environ.get("LANG", "C"),
                "NAVIGATOR_DATA_DIR": str(data),
                "NAVIGATOR_MODE": "local",
                "PATH": f"{installed.parent}:/usr/bin:/bin",
            },
            text=True,
            capture_output=True,
            timeout=60,
        )
        if completed.returncode:
            raise SystemExit(
                "extracted incompatible-reset workflow failed: "
                f"stdout={completed.stdout!r} stderr={completed.stderr!r}"
            )
        if unrelated.poll() is not None:
            raise SystemExit("incompatible reset terminated an unrelated process")
        database = data / "navigator.sqlite"
        with sqlite3.connect(database) as connection:
            sessions = connection.execute(
                "SELECT closed, owner_host_id, owner_epoch FROM sessions "
                "ORDER BY created_at_seconds"
            ).fetchall()
            event_counts = dict(
                connection.execute(
                    "SELECT event_type, COUNT(*) FROM events GROUP BY event_type"
                ).fetchall()
            )
            old_artifacts = connection.execute(
                "SELECT COUNT(*) FROM artifacts WHERE session_id = "
                "(SELECT session_id FROM sessions WHERE closed = 1 "
                "ORDER BY created_at_seconds LIMIT 1)"
            ).fetchone()[0]
        if len(sessions) != 2 or sessions[0][0] != 1 or sessions[1][0] != 0:
            raise SystemExit(f"reset did not replace exactly one old session: {sessions}")
        if sessions[0][1] is not None:
            raise SystemExit(f"reset retained ownership of the old session: {sessions[0]}")
        if event_counts.get("session.closed") != 1 or event_counts.get("session.created") != 2:
            raise SystemExit(f"reset lifecycle events were incomplete: {event_counts}")
        if old_artifacts:
            raise SystemExit("reset retained Artifact rows for the incompatible old session")
        if list(data.rglob("*.sock")):
            raise SystemExit("reset retained a managed socket")
    finally:
        if unrelated.poll() is None:
            os.killpg(unrelated.pid, signal.SIGTERM)
        unrelated.wait(timeout=5)


def _assert_extracted_driver_failure_recovery(installed: Path, temporary: Path) -> None:
    """Kill the exact managed Driver host and reconcile its durable operation."""
    data = temporary / "fault-data"
    marker = temporary / "fault.json"
    setup = """import asyncio,json,sys
from pathlib import Path
from navigator import Navigator,managed_template,new_identity
async def main():
  data,marker=map(Path,sys.argv[1:])
  async with Navigator.local(data_dir=data) as client:
    session=await client.open(new_identity(),new_identity(),'release-fault',b'',managed_template('Complete the task.'))
    operation=await client.start(new_identity(),session.id,session.root_id,b'{\"task\":\"fault recovery\"}')
    marker.write_text(json.dumps({'session':bytes(session.id).hex(),'root':bytes(session.root_id).hex(),'operation':bytes(operation.id).hex()}))
    await asyncio.sleep(30)
asyncio.run(main())
"""
    process = subprocess.Popen(
        [str(installed), "-c", setup, str(data), str(marker)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    unrelated = subprocess.Popen(["/bin/sleep", "60"], start_new_session=True)
    try:
        deadline = time.monotonic() + 20
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        if not marker.exists():
            raise SystemExit("managed Driver fault setup did not become durable")
        rows = subprocess.run(
            ["ps", "-axo", "pid=,command="], check=True, text=True, capture_output=True
        ).stdout.splitlines()
        database_argument = f"--database {data / 'navigator.sqlite'}"
        candidates = [
            row.strip().split(maxsplit=1)[0]
            for row in rows
            if database_argument in row and "navigatord" in row
        ]
        if len(candidates) != 1:
            raise SystemExit(f"could not identify exact managed Driver host: {candidates}")
        os.kill(int(candidates[0]), signal.SIGKILL)
        # The public client is intentionally idle at this boundary; terminate
        # that exact managed lifecycle rather than waiting for its sleep.
        os.killpg(process.pid, signal.SIGTERM)
        process.communicate(timeout=15)
        if unrelated.poll() is not None:
            raise SystemExit("Driver failure handling terminated an unrelated process")
        recovery = """import asyncio,json,sys
from pathlib import Path
from navigator import CleanupRequired,Identity,Navigator,SessionSpec,managed_template,new_identity
async def main():
  data,marker=map(Path,sys.argv[1:]); ids=json.loads(marker.read_text())
  sid=Identity(bytes.fromhex(ids['session'])); oid=Identity(bytes.fromhex(ids['operation']))
  async with Navigator.local(data_dir=data) as client:
    classification='RECONCILED'; actions=0
    try:
      report=await client.resume(new_identity(),sid); actions=len(report.actions); classification=report.disposition.name
    except CleanupRequired:
      classification='CLEANUP_REQUIRED'
      await client.sessions.open(SessionSpec(consumer_key='release-fault',compatibility_identity=b'',root_template=managed_template('Complete the task.')),mode='reset')
    operation=await client.operation(sid,oid)
    print(json.dumps({'operation':operation.status.name,'actions':actions,'disposition':classification}))
asyncio.run(main())
"""
        resumed = subprocess.run(
            [str(installed), "-c", recovery, str(data), str(marker)],
            check=False,
            text=True,
            capture_output=True,
            timeout=45,
        )
        if resumed.returncode:
            raise SystemExit(
                "managed Driver recovery failed: "
                f"stdout={resumed.stdout!r} stderr={resumed.stderr!r}"
            )
        recovered = json.loads(resumed.stdout.splitlines()[-1])
        if recovered["operation"] not in {"SUCCEEDED", "FAILED", "CANCELLED", "UNCERTAIN"}:
            raise SystemExit(f"recovery left operation nonterminal: {recovered}")
        if recovered["disposition"] not in {
            "CLEANUP_REQUIRED",
            "SAFE_TO_CONTINUE",
            "SAFE_TO_REDELIVER",
            "TERMINAL",
        }:
            raise SystemExit(f"Driver failure had no bounded classification: {recovered}")
        with sqlite3.connect(data / "navigator.sqlite") as connection:
            classifications = connection.execute(
                "SELECT COUNT(*) FROM recovery_classifications"
            ).fetchone()[0]
            old_closed = connection.execute(
                "SELECT closed FROM sessions WHERE consumer_key = 'release-fault' "
                "ORDER BY created_at_seconds LIMIT 1"
            ).fetchone()[0]
        # Some classifications are returned authoritatively as CleanupRequired
        # and then consumed by reset rather than retained as ledger rows.
        if classifications < 1 and recovered["disposition"] != "CLEANUP_REQUIRED":
            raise SystemExit("Driver failure was not durably classified")
        if old_closed != 1:
            raise SystemExit("Driver failure recovery did not terminally close old state")
        if list(data.rglob("*.sock")):
            raise SystemExit("Driver recovery retained a managed socket")
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        if unrelated.poll() is None:
            os.killpg(unrelated.pid, signal.SIGTERM)
        unrelated.wait(timeout=5)


def smoke_bundle(output: Path, python: Path) -> None:
    for binary in ("navigatord", "navigatorctl"):
        subprocess.run([str(output / "bin" / binary), "--help"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["node", "--check", str(output / "pi-driver/main.js")], check=True)
    wheels = list((output / "wheels").glob("navigator_sdk-*.whl"))
    if len(wheels) != 1:
        raise SystemExit("release bundle needs exactly one Navigator SDK wheel")
    with tempfile.TemporaryDirectory(prefix="navigator-wheel-smoke-") as temporary:
        environment = Path(temporary) / "venv"
        subprocess.run([str(python), "-m", "venv", str(environment)], check=True)
        installed = environment / "bin/python"
        subprocess.run(
            [str(installed), "-m", "pip", "install", "--no-index", "--find-links",
             str(output / "wheelhouse"), "navigator-sdk==0.1.0"],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        subprocess.run(
            [str(installed), "-c", "import importlib.metadata as m; assert m.version('navigator-sdk') == '0.1.0'"],
            check=True,
        )
        data = Path(temporary) / "managed-data"
        lifecycle = (
            "import asyncio,sys\n"
            "from pathlib import Path\n"
            "from navigator import Navigator\n"
            "async def main():\n"
            "  async with Navigator.local(data_dir=Path(sys.argv[1])) as client:\n"
            "    assert client is not None\n"
            "asyncio.run(main())\n"
        )
        subprocess.run([str(installed), "-c", lifecycle, str(data)], check=True)
        subprocess.run(
            [str(installed), str(output / "python-sdk/examples/managed_work.py"),
             str(Path(temporary) / "managed-work-data"),
             "complete the installed SDK demonstration"],
            check=True,
            cwd=output / "python-sdk/examples",
            env={
                "HOME": os.environ["HOME"],
                "LANG": os.environ.get("LANG", "C"),
                "PATH": f"{installed.parent}:/usr/bin:/bin",
            },
            stdout=subprocess.DEVNULL,
            timeout=60,
        )
        print("release-smoke: installed wheel lifecycle and shutdown passed", flush=True)
        _assert_extracted_reset_cleanup(output, installed, Path(temporary))
        print("release-smoke: incompatible reset cleanup passed", flush=True)
        _assert_extracted_driver_failure_recovery(installed, Path(temporary))
        print("release-smoke: injected Driver failure and recovery passed", flush=True)
        process_rows = subprocess.run(
            ["ps", "-axo", "command="], check=True, text=True, capture_output=True
        ).stdout.splitlines()
        leaked = [row for row in process_rows if temporary in row or str(output) in row]
        if leaked:
            raise SystemExit(f"bundle lifecycle leaked processes: {leaked}")
        sockets = list(data.rglob("*.sock"))
        if sockets:
            raise SystemExit(f"bundle lifecycle leaked sockets: {sockets}")
        print("release-smoke: process and socket leak sweep passed", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "target/release-bundle")
    parser.add_argument("--report", type=Path, default=ROOT / "target/release-gate-report.json")
    parser.add_argument(
        "--security-evidence",
        type=Path,
        default=ROOT / "target/security-compatibility-review",
    )
    parser.add_argument("--security-attestation", type=Path)
    parser.add_argument("--build-bundle", action="store_true")
    parser.add_argument("--run-oracles", action="store_true")
    parser.add_argument("--require-release", action="store_true")
    args = parser.parse_args()
    if args.require_release:
        # Authorization is self-contained: it may not reuse a prior report or
        # rely on callers remembering the expensive executable gates.
        args.build_bundle = True
        args.run_oracles = True
        if args.security_attestation is None:
            raise SystemExit(
                "release authorization requires an explicit independent attestation for the fresh security evidence"
            )
    security_attestation = args.security_attestation
    contract = json.loads(CONTRACT.read_text())
    blockers, report = verify(contract, args.security_evidence, security_attestation)
    evidence_dir = args.report.parent / "release-execution-evidence"
    if evidence_dir.exists():
        shutil.rmtree(evidence_dir)
    evidence_dir.mkdir(parents=True)
    evidence_rows: list[dict[str, Any]] = []
    if args.run_oracles:
        outcomes = []
        for number, oracle in enumerate(contract["release_oracles"], 1):
            transcript = evidence_dir / f"oracle-{number}.log"
            completed = _run_transcribed(oracle["command"], ROOT, transcript)
            row = _evidence_row(
                evidence_dir, transcript, kind="release-oracle",
                command=oracle["command"], claim=oracle["claim"],
                exit=completed.returncode,
            )
            outcomes.append(row)
            evidence_rows.append(row)
            if completed.returncode:
                blockers.append(f"release-oracle-failed:{oracle['claim']}")
        report["oracle_outcomes"] = outcomes
        report["blockers"] = blockers
        report["release_status"] = "blocked" if blockers else "eligible"
    if args.require_release:
        mutant_report = evidence_dir / "release-critical-mutants.json"
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts/run-release-critical-mutants.py"),
             "--report", str(mutant_report)], cwd=ROOT
        )
        report["critical_mutants"] = {
            "exit": completed.returncode,
            "report": str(mutant_report.relative_to(args.report.parent)),
            "report_sha256": sha256(mutant_report) if mutant_report.is_file() else None,
        }
        if completed.returncode:
            blockers.append("critical-mutants-failed")
        else:
            mutant_rows, mutant_errors = _mutant_evidence(evidence_dir, mutant_report)
            evidence_rows.extend(mutant_rows)
            blockers.extend(mutant_errors)
    prebuild_index = evidence_dir / "prebuild-index.json"
    prebuild_index.write_text(json.dumps({
        "schema_version": 1,
        "phase": "prebuild",
        "entries": evidence_rows,
    }, indent=2, sort_keys=True) + "\n")
    blockers.extend(verify_execution_evidence(evidence_dir, prebuild_index))
    bundled_execution_evidence = args.report.parent / "release-prebuild-evidence"
    if bundled_execution_evidence.exists():
        shutil.rmtree(bundled_execution_evidence)
    shutil.copytree(evidence_dir, bundled_execution_evidence)
    if args.build_bundle:
        if blockers:
            raise SystemExit(f"refusing to build a release bundle with blockers: {blockers}")
        build_bundle(
            contract, args.output, args.security_evidence, security_attestation,
            execution_evidence=bundled_execution_evidence,
        )
        smoke_transcript = evidence_dir / "extracted-smoke.log"
        with tempfile.TemporaryDirectory(prefix="navigator-release-extracted-") as temporary:
            with tarfile.open(args.output.with_suffix(".tar"), "r") as archive:
                archive.extractall(temporary, filter="data")
            extracted = Path(temporary) / args.output.name
            _capture_callable(
                smoke_transcript, smoke_bundle, extracted,
                ROOT / contract["bundle"]["python_sdk"] / ".venv/bin/python",
            )
        smoke_row = _evidence_row(
            evidence_dir, smoke_transcript, kind="extracted-smoke",
            command_id=SMOKE_COMMAND_ID, claim=SMOKE_CLAIM,
            artifact_archive_path=str(
                args.output.with_suffix(".tar").resolve().relative_to(
                    args.report.parent.resolve()
                )
            ),
            artifact_archive_sha256=sha256(args.output.with_suffix(".tar")),
            exit=0,
        )
        evidence_rows.append(smoke_row)
        report["bundle"] = {
            "archive_sha256": sha256(args.output.with_suffix(".tar")),
            "manifest_sha256": sha256(args.output / "MANIFEST.json"),
            "extracted_smoke": "passed",
        }
        if args.require_release:
            second = args.output.parent / f"{args.output.name}-reproducibility-witness"
            build_bundle(
                contract,
                second,
                args.security_evidence,
                security_attestation,
                archive_root=args.output.name,
                execution_evidence=bundled_execution_evidence,
            )
            primary_archive = sha256(args.output.with_suffix(".tar"))
            witness_archive = sha256(second.with_suffix(".tar"))
            primary_manifest = sha256(args.output / "MANIFEST.json")
            witness_manifest = sha256(second / "MANIFEST.json")
            archive_equal = primary_archive == witness_archive
            manifest_equal = primary_manifest == witness_manifest
            report["reproducibility"] = {
                "primary_bundle": str(args.output),
                "witness_bundle": str(second),
                "primary_archive_sha256": primary_archive,
                "witness_archive_sha256": witness_archive,
                "primary_manifest_sha256": primary_manifest,
                "witness_manifest_sha256": witness_manifest,
                "archive_byte_identical": archive_equal,
                "manifest_byte_identical": manifest_equal,
            }
            if not archive_equal or not manifest_equal:
                blockers.append("bundle-not-byte-reproducible")
    final_index = evidence_dir / "authorization-index.json"
    final_index.write_text(json.dumps({
        "schema_version": 1,
        "phase": "authorization",
        "entries": evidence_rows,
        "prebuild_index": {
            "path": str(prebuild_index.relative_to(evidence_dir)),
            "sha256": sha256(prebuild_index),
        },
    }, indent=2, sort_keys=True) + "\n")
    blockers.extend(verify_execution_evidence(
        evidence_dir, final_index, args.output.with_suffix(".tar"),
    ))
    report["execution_evidence"] = {
        "root": str(evidence_dir.relative_to(args.report.parent)),
        "index": str(final_index.relative_to(args.report.parent)),
        "index_sha256": sha256(final_index),
        "prebuild_index": str(prebuild_index.relative_to(args.report.parent)),
        "prebuild_index_sha256": sha256(prebuild_index),
        "entries": evidence_rows,
    }
    report["sidecar_binding"] = {
        "authorization_index_sha256": sha256(final_index),
        "prebuild_index_sha256": sha256(prebuild_index),
        "critical_mutant_report_sha256": (
            report.get("critical_mutants", {}).get("report_sha256")
        ),
        "primary_archive_sha256": report.get("bundle", {}).get("archive_sha256"),
        "primary_manifest_sha256": report.get("bundle", {}).get("manifest_sha256"),
        "witness_archive_sha256": report.get("reproducibility", {}).get(
            "witness_archive_sha256"
        ),
        "witness_manifest_sha256": report.get("reproducibility", {}).get(
            "witness_manifest_sha256"
        ),
        "independent_attestation_contract": (
            "an independent attestation binds the SHA-256 of this completed report"
        ),
    }
    report["blockers"] = blockers
    report["release_status"] = "blocked" if blockers else "eligible"
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"release-gate: infrastructure valid; status={report['release_status']}; blockers={len(blockers)}; report={args.report}")
    return 1 if args.require_release and blockers else 0


if __name__ == "__main__":
    raise SystemExit(main())
