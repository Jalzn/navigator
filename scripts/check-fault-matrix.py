#!/usr/bin/env python3
"""Validate and execute the Slice 12 semantic fault inventory.

The parent process owns discovery and invariant validation.  A fresh subprocess
materializes every case, making accidental process-local state or ordering
dependencies visible in the evidence stream.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "plans/12-hardening/fault-matrix.json"
POINT = re.compile(r'(?:crash_at|artifact_crash_at)\("([a-z0-9_.-]+)"\)')
EXTERNAL_POINT = re.compile(r'"([a-z]+\.external\.[a-z0-9_.-]+)"')
EXTERNAL_CALL = re.compile(
    r'external_fault_at\("([a-z]+\.external\.[a-z0-9_.-]+)"\)'
)
VALID_CLASSIFICATIONS = {"terminal", "recoverable", "uncertain", "cleanup_required"}
FINAL_INVARIANTS = [
    "no_duplicate_unfinished_participant",
    "no_duplicate_unfinished_operation",
    "no_orphan_reservation",
    "uncertain_effect_not_ordinarily_replayed",
    "stale_owner_cannot_commit",
    "unrelated_process_not_terminated",
    "classified_final_state",
]


def validate_external_inventory(declared: set[str], calls: list[str]) -> None:
    called = set(calls)
    duplicates = sorted(point for point in called if calls.count(point) != 1)
    if declared != called or duplicates:
        raise ValueError(
            f"external product hook drift: missing={sorted(declared - called)} "
            f"extra={sorted(called - declared)} duplicates={duplicates}"
        )


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("fault manifest root must be an object")
    return value


def durable_points(manifest: dict[str, Any]) -> set[str]:
    source = manifest["source"]
    prefixes = tuple(source["durable_prefixes"])
    found: set[str] = set()
    production_sources = sorted((ROOT / "crates").glob("*/src/**/*.rs"))
    for path in production_sources:
        text = path.read_text(encoding="utf-8")
        found.update(point for point in POINT.findall(text) if point.startswith(prefixes))
    serialized = "\n".join(sorted(found)).encode()
    if len(found) != source.get("durable_point_count") or hashlib.sha256(serialized).hexdigest() != source.get("durable_point_sha256"):
        raise ValueError("source durable fault-point inventory drifted")
    return found


def cases(manifest: dict[str, Any]) -> list[dict[str, str]]:
    result = [
        {"area": point.split(".", 1)[0], "fault_point": point,
         "expected": "terminal" if point.endswith("after_commit") else "recoverable"}
        for point in sorted(durable_points(manifest))
    ]
    for effect in manifest["external_effects"]:
        points = effect["points"]
        expected = effect["expected"]
        if len(points) != 4 or len(expected) != 4:
            raise ValueError(f"external effect {effect.get('area')} needs four boundaries")
        required = ("before_call", "after_call", "before_", "after_")
        if not (points[0].endswith(required[0]) and points[1].endswith(required[1])
                and required[2] in points[2] and required[3] in points[3]):
            raise ValueError(f"external effect {effect.get('area')} lacks call/proof boundaries")
        result.extend({"area": effect["area"], "fault_point": point, "expected": classification}
                      for point, classification in zip(points, expected, strict=True))
    declared = set(EXTERNAL_POINT.findall(
        (ROOT / "crates/navigator-local/src/fault_matrix.rs").read_text(encoding="utf-8")))
    calls: list[str] = []
    for source_path in (ROOT / "crates").glob("*/src/**/*.rs"):
        if source_path.name != "fault_matrix.rs":
            calls.extend(EXTERNAL_CALL.findall(source_path.read_text(encoding="utf-8")))
    validate_external_inventory(declared, calls)
    manifested = {row["fault_point"] for row in result if ".external." in row["fault_point"]}
    if declared != manifested:
        raise ValueError(
            f"external source/manifest drift: missing={sorted(declared - manifested)} "
            f"extra={sorted(manifested - declared)}"
        )
    return result


def validate(manifest: dict[str, Any]) -> list[dict[str, str]]:
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("seed"), int):
        raise ValueError("unsupported fault manifest")
    if set(manifest.get("classifications", [])) != VALID_CLASSIFICATIONS:
        raise ValueError("classification registry drifted")
    rows = cases(manifest)
    names = [row["fault_point"] for row in rows]
    if len(names) != len(set(names)) or not names:
        raise ValueError("fault points must be non-empty and unique")
    areas = {row["area"] for row in rows}
    required = {"launch", "mailbox", "delivery", "tool", "operation", "report",
                "cancellation", "artifact", "approval", "shutdown"}
    if not required <= areas:
        raise ValueError(f"missing fault areas: {sorted(required - areas)}")
    invariants = manifest.get("final_invariants", [])
    if invariants != FINAL_INVARIANTS:
        raise ValueError("final invariant sweep is incomplete")
    if any(row["expected"] not in VALID_CLASSIFICATIONS for row in rows):
        raise ValueError("fault point has unknown expected classification")
    return rows


def validate_evidence_bindings(
    manifest: dict[str, Any], rows: list[dict[str, str]]
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    external = manifest.get("evidence_tests", {})
    if set(external) != {row["area"] for row in rows}:
        raise ValueError("every fault area must bind exactly one product evidence test")
    durable = manifest.get("durable_evidence_tests", {})
    durable_areas = {
        row["area"] for row in rows if ".external." not in row["fault_point"]
    }
    if set(durable) != durable_areas:
        raise ValueError("every durable fault area must bind exact durable evidence")
    return external, durable


def validate_records(
    records: list[dict[str, Any]], rows: list[dict[str, str]], invariants: list[str]
) -> None:
    expected_points = [row["fault_point"] for row in rows]
    if [record.get("fault_point") for record in records] != expected_points:
        raise ValueError("JSONL evidence is incomplete, duplicated, or reordered")
    if len({record.get("seed") for record in records}) != len(records):
        raise ValueError("JSONL evidence seeds are not unique")
    required = {
        "schema_version", "seed", "fault_point", "expected_classification",
        "actual_classification", "evidence_test", "final_invariants", "diagnostics",
    }
    for record in records:
        if set(record) != required:
            raise ValueError("JSONL evidence record shape drifted")
        if set(record["final_invariants"]) != set(invariants):
            raise ValueError("JSONL invariant order/shape drifted")
        if not all(record["final_invariants"].values()):
            raise ValueError(f"final invariant failed at {record['fault_point']}")


def run_product_oracle(command: list[str], context: str, env: dict[str, str] | None = None) -> bool:
    completed = subprocess.run(command, cwd=ROOT, text=True, env=env)
    if completed.returncode != 0:
        raise ValueError(f"product evidence failed for {context}: {command!r}")
    return True


def load_product_result(
    path: Path, row: dict[str, str], seed: int, evidence_test: list[str]
) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"product worker omitted result for {row['fault_point']}")
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(
            f"product worker emitted corrupt result for {row['fault_point']}"
        ) from error
    if not isinstance(record, dict):
        raise ValueError("product worker result must be one JSON object")
    if record.get("schema_version") != 1 or record.get("seed") != seed:
        raise ValueError("product worker result schema/seed mismatch")
    if record.get("fault_point") != row["fault_point"]:
        raise ValueError("product worker result fault-point mismatch")
    if set(record.get("facts", {})) != set(FINAL_INVARIANTS):
        raise ValueError("product worker result invariant shape mismatch")
    if not all(record["facts"].values()):
        raise ValueError(f"product invariant failed at {row['fault_point']}")
    if not isinstance(record.get("diagnostics"), dict) or not record["diagnostics"]:
        raise ValueError("product worker omitted state diagnostics")
    validate_observed_diagnostics(record)
    record["final_invariants"] = record.pop("facts")
    record["expected_classification"] = row["expected"]
    record["evidence_test"] = evidence_test
    return record


def validate_observed_diagnostics(record: dict[str, Any]) -> None:
    """Reject result booleans/classifications contradicted by observed state."""
    facts = record["facts"]
    diagnostic = record["diagnostics"]
    actual = record["actual_classification"]
    schema = diagnostic.get("observation_schema")
    point = record.get("fault_point", "")
    area = point.split(".", 1)[0]
    if ".external." not in point:
        expected_schema = "durable-v2"
    elif area == "shutdown":
        expected_schema = "shutdown-v2"
    elif area == "artifact":
        expected_schema = "external-artifact-v2"
    elif area in {"tool", "approval"}:
        expected_schema = "external-tool-v2"
    else:
        expected_schema = "external-driver-v2"
    if schema != expected_schema:
        raise ValueError(
            f"wrong observation schema for {point}: {schema!r}, expected {expected_schema!r}"
        )
    signatures = {
        "external-driver-v2": "external_receipt_unchanged_after_ordinary_replay",
        "external-artifact-v2": "file_present_before_retry",
        "external-tool-v2": "invocation_before_reconcile",
    }
    present_signatures = {name for name, key in signatures.items() if key in diagnostic}
    if expected_schema in signatures and present_signatures != {expected_schema}:
        raise ValueError("external diagnostics are missing their typed state or are hybrid")
    if expected_schema not in signatures and present_signatures:
        raise ValueError("durable/shutdown diagnostics contain hybrid external state")
    if schema == "durable-v2":
        replay_basis = diagnostic.get("uncertain_replay_basis")
        classification_basis = diagnostic.get("classification_basis")
        expected = {
            "no_duplicate_unfinished_participant": diagnostic.get("duplicate_unfinished_participants") == 0,
            "no_duplicate_unfinished_operation": diagnostic.get("duplicate_unfinished_operations") == 0,
            "no_orphan_reservation": diagnostic.get("orphan_violations") == 0,
            "uncertain_effect_not_ordinarily_replayed": replay_basis in {
                "non_applicable_no_uncertain_effect",
                "non_applicable_uncertain_receipt_owned_by_reconciler",
                "exact_request_replay_preserved_receipt",
            },
            "stale_owner_cannot_commit": (
                diagnostic.get("stale_predecessor_rejected_without_mutation") is True
                and diagnostic.get("stale_first_ledger_delta") == 1
                and diagnostic.get("stale_replay_ledger_delta") == 0
                and diagnostic.get("stale_domain_unchanged") is True
            ),
            "unrelated_process_not_terminated": diagnostic.get("unrelated_process_and_socket_survived") is True,
            "classified_final_state": (
                (actual == "terminal" and classification_basis == "committed_row_and_exact_replay")
                or (actual == "recoverable" and classification_basis == "prior_state_and_fresh_apply")
            ),
        }
        if any(facts[name] is not value for name, value in expected.items()):
            raise ValueError("durable facts/classification contradict typed observations")
    if schema == "shutdown-v2":
        receipt = diagnostic.get("stale_rejection_receipt")
        stale_proof = (
            diagnostic.get("stale_predecessor_rejected_without_mutation") is True
            and diagnostic.get("stale_first_ledger_delta") == 1
            and diagnostic.get("stale_replay_ledger_delta") == 0
            and diagnostic.get("stale_altered_digest_ledger_delta") == 0
            and diagnostic.get("stale_mutation_policy") == "zero domain mutation; one durable rejection receipt"
            and isinstance(receipt, str)
            and re.fullmatch(r"[0-9A-F]{64}:failed:[0-9A-F]+", receipt) is not None
            and diagnostic.get("stale_ownership_unchanged") is True
            and diagnostic.get("stale_events_unchanged") is True
            and diagnostic.get("stale_domain_fingerprint_unchanged") is True
        )
        orphan_components = (
            "foreign_key_violations", "capacity_pair_violations",
            "reverse_capacity_pair_violations", "capacity_usage_violations",
            "unreleased_reservation_violations", "effect_owner_violations",
            "approval_intent_violations", "artifact_owner_violations",
        )
        orphan_total = sum(diagnostic.get(name, -1) for name in orphan_components)
        reservation_basis = diagnostic.get("reservation_reconciliation_basis")
        reservation_proven = (
            diagnostic.get("unreleased_reservation_violations") == 0
            and (
                (reservation_basis == "reclaimed_after_restart"
                 and diagnostic.get("unreleased_reservations_before_reconcile", 0) > 0
                 and diagnostic.get("reservation_reconciliation_exercised") is True)
                or (reservation_basis == "non_applicable_no_unreleased_reservation"
                    and diagnostic.get("unreleased_reservations_before_reconcile") == 0
                    and diagnostic.get("reservation_reconciliation_exercised") is False)
            )
        )
        expected = {
            "no_duplicate_unfinished_participant": diagnostic.get("duplicate_unfinished_participants") == 0,
            "no_duplicate_unfinished_operation": diagnostic.get("duplicate_unfinished_operations") == 0,
            "no_orphan_reservation": diagnostic.get("orphan_violations") == orphan_total == 0 and reservation_proven,
            "uncertain_effect_not_ordinarily_replayed": diagnostic.get("uncertain_replay_basis") == "non_applicable_shutdown_has_no_effect_receipt",
            "stale_owner_cannot_commit": stale_proof,
            "unrelated_process_not_terminated": diagnostic.get("unrelated_process_and_socket_survived") is True,
            "classified_final_state": (
                (actual == "terminal" and diagnostic.get("ownership_released_before_restart") is True)
                or (actual == "cleanup_required" and diagnostic.get("ownership_released_before_restart") is False)
            ) and diagnostic.get("sqlite_reopened") is True and diagnostic.get("session_snapshot_reloaded") is True,
        }
        if any(facts[name] is not value for name, value in expected.items()):
            raise ValueError("shutdown facts/classification contradict typed observations")
    if "external_receipt_unchanged_after_ordinary_replay" in diagnostic:
        expected = {
            "no_duplicate_unfinished_participant": diagnostic["duplicate_roots"] == 0,
            "no_duplicate_unfinished_operation": diagnostic["duplicate_unfinished_operations"] == 0,
            "no_orphan_reservation": diagnostic["orphan_rows"] == 0,
            "uncertain_effect_not_ordinarily_replayed": (
                actual != "uncertain"
                or diagnostic["external_receipt_unchanged_after_ordinary_replay"] is True
            ),
            "stale_owner_cannot_commit": diagnostic["stale_predecessor_rejected_without_mutation"] is True,
            "unrelated_process_not_terminated": diagnostic["unrelated_process_survived"] is True,
        }
        classified = {
            "terminal": diagnostic["terminal_operations"] > 0,
            "recoverable": diagnostic["unfinished_operations"] > 0,
            "uncertain": diagnostic["accepted_count"] > 0 or diagnostic["cancel_count"] > 0,
            "cleanup_required": diagnostic["cleanup_launches"] > 0
            or diagnostic["unfinished_launches"] > 0,
        }.get(actual, False)
        expected["classified_final_state"] = classified
        if any(facts[name] is not value for name, value in expected.items()):
            raise ValueError("product facts/classification contradict observed Driver state")
    if "file_present_before_retry" in diagnostic:
        file_present = diagnostic["file_present_before_retry"]
        metadata_present = diagnostic["metadata_committed_before_retry"]
        derived = (
            "terminal" if metadata_present else "cleanup_required" if file_present else "recoverable"
        )
        artifact_facts = (
            facts["no_duplicate_unfinished_participant"]
            is (diagnostic["duplicate_roots"] == 0)
            and facts["no_duplicate_unfinished_operation"]
            is (diagnostic["duplicate_unfinished_operations"] == 0)
            and facts["no_orphan_reservation"]
            is (diagnostic["retry_blob_count"] == 1 and diagnostic["foreign_key_violations"] == 0)
            and facts["stale_owner_cannot_commit"]
            is diagnostic["stale_predecessor_rejected_without_mutation"]
            and facts["unrelated_process_not_terminated"]
            is diagnostic["unrelated_process_survived"]
        )
        if actual != derived or facts["classified_final_state"] is not True or not artifact_facts:
            raise ValueError("Artifact classification contradicts file/row observations")
    if "invocation_before_reconcile" in diagnostic:
        terminal = diagnostic["terminal_invocation_before_reconcile"]
        invoked = diagnostic["invocation_before_reconcile"]
        derived = "terminal" if terminal else "uncertain" if invoked else "recoverable"
        tool_facts = (
            facts["no_duplicate_unfinished_participant"]
            is (diagnostic["duplicate_roots"] == 0)
            and facts["no_duplicate_unfinished_operation"]
            is (diagnostic["duplicate_unfinished_operations"] == 0)
            and facts["no_orphan_reservation"]
            is (diagnostic["foreign_key_violations"] == 0 and diagnostic["reconciler_completed"])
            and facts["stale_owner_cannot_commit"]
            is diagnostic["stale_predecessor_rejected_without_mutation"]
            and facts["unrelated_process_not_terminated"]
            is diagnostic["unrelated_process_survived"]
            and facts["uncertain_effect_not_ordinarily_replayed"] is (
                actual != "uncertain" or (
                    diagnostic["ordinary_reconnect_attempted"] is True
                    and diagnostic["replay_frames_emitted"] == 0
                    and diagnostic["provider_calls_before"] == diagnostic["provider_calls_after"]
                    and diagnostic["provider_receipts_before"] == diagnostic["provider_receipts_after"]
                )
            )
        )
        if actual != derived or facts["classified_final_state"] is not True or not tool_facts:
            raise ValueError("Tool/Approval classification contradicts durable observations")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manifest = load(args.manifest)
    rows = validate(manifest)
    output = args.output or Path(os.environ.get(
        "NAVIGATOR_FAULT_MATRIX_OUTPUT", ROOT / "target/conformance/fault-matrix.jsonl"))
    output.parent.mkdir(parents=True, exist_ok=True)
    raw_results = output.parent / f"{output.stem}-results"
    raw_results.mkdir(parents=True, exist_ok=True)
    evidence_tests, durable_tests = validate_evidence_bindings(manifest, rows)
    records: list[dict[str, Any]] = []
    for ordinal, row in enumerate(rows):
        seed = manifest["seed"] + ordinal
        command = (
            evidence_tests[row["area"]]
            if ".external." in row["fault_point"]
            else durable_tests[row["area"]]
        )
        environment = os.environ.copy()
        environment["NAVIGATOR_FAULT_MATRIX_ONLY"] = row["fault_point"]
        with tempfile.TemporaryDirectory(prefix="navigator-fault-result-") as result_dir:
            result_path = Path(result_dir) / "observed.json"
            environment["NAVIGATOR_FAULT_CASE_RESULT"] = str(result_path)
            environment["NAVIGATOR_FAULT_CASE_SEED"] = str(seed)
            run_product_oracle(command, row["fault_point"], environment)
            shutil.copyfile(result_path, raw_results / f"{row['fault_point']}.json")
            record = load_product_result(result_path, row, seed, command)
        if record["actual_classification"] != record["expected_classification"]:
            raise ValueError(f"classification mismatch at {row['fault_point']}")
        records.append(record)
    validate_records(records, rows, manifest["final_invariants"])
    output.write_text(
        "\n".join(json.dumps(record, sort_keys=True, separators=(",", ":")) for record in records)
        + "\n",
        encoding="utf-8",
    )
    print(f"fault-matrix: {len(records)} cases passed; evidence={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
