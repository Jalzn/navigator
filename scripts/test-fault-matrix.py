#!/usr/bin/env python3
"""Mutation tests for the Slice 12 fault manifest validator."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile
import json

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("fault_matrix", ROOT / "scripts/check-fault-matrix.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FaultMatrixMutants(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = MODULE.load(ROOT / "plans/12-hardening/fault-matrix.json")

    def rejects_missing_area(self) -> None:
        mutant = copy.deepcopy(self.manifest)
        mutant["external_effects"] = [e for e in mutant["external_effects"] if e["area"] != "shutdown"]
        with self.assertRaises(ValueError):
            MODULE.validate(mutant)

    def test_rejects_missing_area(self) -> None:
        self.rejects_missing_area()

    def test_rejects_duplicate_point(self) -> None:
        mutant = copy.deepcopy(self.manifest)
        mutant["external_effects"][1]["points"][0] = mutant["external_effects"][0]["points"][0]
        with self.assertRaises(ValueError):
            MODULE.validate(mutant)

    def test_rejects_missing_proof_boundary(self) -> None:
        mutant = copy.deepcopy(self.manifest)
        mutant["external_effects"][0]["points"][2] = "launch.external.middle"
        with self.assertRaises(ValueError):
            MODULE.validate(mutant)

    def test_rejects_unknown_classification(self) -> None:
        mutant = copy.deepcopy(self.manifest)
        mutant["external_effects"][0]["expected"][0] = "safe_to_guess"
        with self.assertRaises(ValueError):
            MODULE.validate(mutant)

    def test_rejects_incomplete_invariant_sweep(self) -> None:
        mutant = copy.deepcopy(self.manifest)
        mutant["final_invariants"].pop()
        with self.assertRaises(ValueError):
            MODULE.validate(mutant)

    def test_rejects_renamed_invariant_that_would_default_true(self) -> None:
        mutant = copy.deepcopy(self.manifest)
        mutant["final_invariants"][0] = "looks_healthy"
        with self.assertRaises(ValueError):
            MODULE.validate(mutant)

    def test_runner_requires_durable_evidence_separate_from_external_vertical(self) -> None:
        mutant = copy.deepcopy(self.manifest)
        mutant["durable_evidence_tests"].pop("launch")
        rows = MODULE.validate(mutant)
        with self.assertRaises(ValueError):
            MODULE.validate_evidence_bindings(mutant, rows)

    def test_rejects_source_manifest_external_drift(self) -> None:
        mutant = copy.deepcopy(self.manifest)
        mutant["external_effects"][0]["points"][0] = "launch.external.before_other_call"
        with self.assertRaises(ValueError):
            MODULE.validate(mutant)

    def test_rejects_removed_product_crash_point(self) -> None:
        mutant = copy.deepcopy(self.manifest)
        mutant["source"]["durable_point_count"] -= 1
        with self.assertRaises(ValueError):
            MODULE.validate(mutant)

    def test_rejects_removed_or_duplicated_external_product_hook(self) -> None:
        declared = {"tool.external.before_call", "tool.external.after_call"}
        with self.assertRaises(ValueError):
            MODULE.validate_external_inventory(declared, ["tool.external.before_call"])
        with self.assertRaises(ValueError):
            MODULE.validate_external_inventory(
                declared,
                [
                    "tool.external.before_call",
                    "tool.external.after_call",
                    "tool.external.after_call",
                ],
            )

    def test_in_memory_driver_proof_is_not_classified_terminal(self) -> None:
        expected = {
            point: classification
            for effect in self.manifest["external_effects"]
            for point, classification in zip(effect["points"], effect["expected"], strict=True)
        }
        self.assertEqual(expected["launch.external.after_identity_proof"], "cleanup_required")
        self.assertEqual(expected["delivery.external.after_acceptance_proof"], "uncertain")
        self.assertEqual(expected["report.external.after_correlation_proof"], "recoverable")
        self.assertEqual(expected["cancellation.external.after_stop_proof"], "uncertain")

    def test_jsonl_completeness_and_invariant_mutants_fail(self) -> None:
        rows = [
            {"area": "tool", "fault_point": "tool.external.before_call", "expected": "uncertain"},
            {"area": "tool", "fault_point": "tool.external.after_call", "expected": "uncertain"},
        ]
        def record(point: str, seed: int) -> dict[str, object]:
            return {
                "schema_version": 1,
                "seed": seed,
                "fault_point": point,
                "expected_classification": "recoverable",
                "actual_classification": "recoverable",
                "evidence_test": ["true"],
                "final_invariants": {
                    name: True for name in self.manifest["final_invariants"]
                },
                "diagnostics": {"state": "observed"},
            }
        records = [record(row["fault_point"], index) for index, row in enumerate(rows)]
        MODULE.validate_records(records, rows, self.manifest["final_invariants"])
        with self.assertRaises(ValueError):
            MODULE.validate_records(records[:-1], rows, self.manifest["final_invariants"])
        records[0]["final_invariants"]["stale_owner_cannot_commit"] = False
        with self.assertRaises(ValueError):
            MODULE.validate_records(records, rows, self.manifest["final_invariants"])

    def test_product_result_missing_corrupt_and_state_mutants(self) -> None:
        row = {
            "area": "artifact",
            "fault_point": "artifact.external.before_call",
            "expected": "recoverable",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            with self.assertRaises(ValueError):
                MODULE.load_product_result(path, row, 7, ["oracle"])
            path.write_text("{", encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.load_product_result(path, row, 7, ["oracle"])
            record = {
                "schema_version": 1,
                "seed": 7,
                "fault_point": row["fault_point"],
                "actual_classification": "cleanup_required",
                "facts": {name: True for name in self.manifest["final_invariants"]},
                "diagnostics": {
                    "observation_schema": "external-artifact-v2",
                    "file_present_before_retry": True,
                    "metadata_committed_before_retry": False,
                    "duplicate_roots": 0,
                    "duplicate_unfinished_operations": 0,
                    "retry_blob_count": 1,
                    "foreign_key_violations": 0,
                    "stale_predecessor_rejected_without_mutation": True,
                    "unrelated_process_survived": True,
                },
            }
            path.write_text(json.dumps(record), encoding="utf-8")
            MODULE.load_product_result(path, row, 7, ["oracle"])
            record["diagnostics"]["metadata_committed_before_retry"] = True
            path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.load_product_result(path, row, 7, ["oracle"])
            record["diagnostics"]["metadata_committed_before_retry"] = False
            record["facts"]["no_orphan_reservation"] = False
            path.write_text(json.dumps(record), encoding="utf-8")
            with self.assertRaises(ValueError):
                MODULE.load_product_result(path, row, 7, ["oracle"])

    def test_observed_driver_state_substitution_mutants_are_rejected(self) -> None:
        row = {
            "area": "delivery",
            "fault_point": "delivery.external.after_call",
            "expected": "uncertain",
        }
        record = {
            "schema_version": 1,
            "seed": 9,
            "fault_point": row["fault_point"],
            "actual_classification": "uncertain",
            "facts": {name: True for name in self.manifest["final_invariants"]},
            "diagnostics": {
                "observation_schema": "external-driver-v2",
                "duplicate_roots": 0,
                "duplicate_unfinished_operations": 0,
                "orphan_rows": 0,
                "external_receipt_unchanged_after_ordinary_replay": True,
                "stale_predecessor_rejected_without_mutation": True,
                "unrelated_process_survived": True,
                "terminal_operations": 0,
                "unfinished_operations": 1,
                "accepted_count": 1,
                "cancel_count": 0,
                "cleanup_launches": 0,
                "unfinished_launches": 1,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            MODULE.load_product_result(path, row, 9, ["oracle"])
            for mutate in (
                lambda value: value["facts"].__setitem__("stale_owner_cannot_commit", False),
                lambda value: value["diagnostics"].__setitem__("accepted_count", 0),
                lambda value: value.__setitem__("actual_classification", "terminal"),
            ):
                mutant = copy.deepcopy(record)
                mutate(mutant)
                path.write_text(json.dumps(mutant), encoding="utf-8")
                with self.assertRaises(ValueError):
                    MODULE.load_product_result(path, row, 9, ["oracle"])

    def test_artifact_and_tool_observation_substitutions_are_rejected(self) -> None:
        facts = {name: True for name in self.manifest["final_invariants"]}
        artifact = {
            "fault_point": "artifact.external.before_call",
            "actual_classification": "cleanup_required",
            "facts": facts,
            "diagnostics": {
                "observation_schema": "external-artifact-v2",
                "file_present_before_retry": True,
                "metadata_committed_before_retry": False,
                "duplicate_roots": 0,
                "duplicate_unfinished_operations": 0,
                "retry_blob_count": 1,
                "foreign_key_violations": 0,
                "stale_predecessor_rejected_without_mutation": True,
                "unrelated_process_survived": True,
            },
        }
        MODULE.validate_observed_diagnostics(artifact)
        mutant = copy.deepcopy(artifact)
        mutant["diagnostics"]["metadata_committed_before_retry"] = True
        with self.assertRaises(ValueError):
            MODULE.validate_observed_diagnostics(mutant)
        tool = {
            "fault_point": "tool.external.after_call",
            "actual_classification": "uncertain",
            "facts": facts,
            "diagnostics": {
                "observation_schema": "external-tool-v2",
                "invocation_before_reconcile": True,
                "terminal_invocation_before_reconcile": False,
                "ordinary_reconnect_attempted": True,
                "replay_frames_emitted": 0,
                "provider_calls_before": 1,
                "provider_calls_after": 1,
                "provider_receipts_before": 1,
                "provider_receipts_after": 1,
                "duplicate_roots": 0,
                "duplicate_unfinished_operations": 0,
                "foreign_key_violations": 0,
                "reconciler_completed": True,
                "stale_predecessor_rejected_without_mutation": True,
                "unrelated_process_survived": True,
            },
        }
        MODULE.validate_observed_diagnostics(tool)
        mutant = copy.deepcopy(tool)
        mutant["diagnostics"]["invocation_before_reconcile"] = False
        with self.assertRaises(ValueError):
            MODULE.validate_observed_diagnostics(mutant)
        for field, replacement in (
            ("ordinary_reconnect_attempted", False),
            ("replay_frames_emitted", 1),
            ("provider_calls_after", 2),
            ("provider_receipts_after", 0),
        ):
            mutant = copy.deepcopy(tool)
            mutant["diagnostics"][field] = replacement
            with self.assertRaises(ValueError):
                MODULE.validate_observed_diagnostics(mutant)

    def test_durable_and_shutdown_typed_substitutions_are_rejected(self) -> None:
        facts = {name: True for name in self.manifest["final_invariants"]}
        durable = {
            "fault_point": "session.after_commit",
            "actual_classification": "terminal",
            "facts": facts,
            "diagnostics": {
                "observation_schema": "durable-v2",
                "duplicate_unfinished_participants": 0,
                "duplicate_unfinished_operations": 0,
                "orphan_violations": 0,
                "foreign_key_violations": 0,
                "capacity_pair_violations": 0,
                "reverse_capacity_pair_violations": 0,
                "capacity_usage_violations": 0,
                "unreleased_reservation_violations": 0,
                "effect_owner_violations": 0,
                "approval_intent_violations": 0,
                "artifact_owner_violations": 0,
                "uncertain_replay_basis": "non_applicable_no_uncertain_effect",
                "stale_predecessor_rejected_without_mutation": True,
                "stale_first_ledger_delta": 1,
                "stale_replay_ledger_delta": 0,
                "stale_domain_unchanged": True,
                "unrelated_process_and_socket_survived": True,
                "classification_basis": "committed_row_and_exact_replay",
            },
        }
        MODULE.validate_observed_diagnostics(durable)
        shutdown = {
            "fault_point": "shutdown.external.after_call",
            "actual_classification": "terminal",
            "facts": facts,
            "diagnostics": {
                "observation_schema": "shutdown-v2",
                "duplicate_unfinished_participants": 0,
                "duplicate_unfinished_operations": 0,
                "orphan_violations": 0,
                "foreign_key_violations": 0,
                "capacity_pair_violations": 0,
                "reverse_capacity_pair_violations": 0,
                "capacity_usage_violations": 0,
                "unreleased_reservation_violations": 0,
                "effect_owner_violations": 0,
                "approval_intent_violations": 0,
                "artifact_owner_violations": 0,
                "uncertain_replay_basis": "non_applicable_shutdown_has_no_effect_receipt",
                "stale_predecessor_rejected_without_mutation": True,
                "stale_first_ledger_delta": 1,
                "stale_replay_ledger_delta": 0,
                "stale_altered_digest_ledger_delta": 0,
                "stale_mutation_policy": "zero domain mutation; one durable rejection receipt",
                "stale_rejection_receipt": "AA" * 32 + ":failed:BB",
                "stale_ownership_unchanged": True,
                "stale_events_unchanged": True,
                "stale_domain_fingerprint_unchanged": True,
                "unreleased_reservations_before_reconcile": 1,
                "reservation_reconciliation_exercised": True,
                "reservation_reconciliation_basis": "reclaimed_after_restart",
                "unrelated_process_and_socket_survived": True,
                "ownership_released_before_restart": True,
                "sqlite_reopened": True,
                "session_snapshot_reloaded": True,
            },
        }
        MODULE.validate_observed_diagnostics(shutdown)
        for base, field, replacement in (
            (durable, "orphan_violations", 1),
            (durable, "uncertain_replay_basis", "exact_replay_changed_receipt"),
            (durable, "stale_predecessor_rejected_without_mutation", False),
            (shutdown, "duplicate_unfinished_operations", 1),
            (shutdown, "unrelated_process_and_socket_survived", False),
            (shutdown, "ownership_released_before_restart", False),
            (shutdown, "stale_first_ledger_delta", 0),
            (shutdown, "stale_replay_ledger_delta", 1),
            (shutdown, "stale_ownership_unchanged", False),
            (shutdown, "stale_events_unchanged", False),
            (shutdown, "stale_domain_fingerprint_unchanged", False),
            (shutdown, "foreign_key_violations", 1),
            (shutdown, "capacity_pair_violations", 1),
            (shutdown, "reverse_capacity_pair_violations", 1),
            (shutdown, "capacity_usage_violations", 1),
            (shutdown, "unreleased_reservation_violations", 1),
            (shutdown, "effect_owner_violations", 1),
            (shutdown, "approval_intent_violations", 1),
            (shutdown, "artifact_owner_violations", 1),
            (shutdown, "reservation_reconciliation_exercised", False),
        ):
            mutant = copy.deepcopy(base)
            mutant["diagnostics"][field] = replacement
            with self.assertRaises(ValueError):
                MODULE.validate_observed_diagnostics(mutant)
        for base in (durable, shutdown):
            mutant = copy.deepcopy(base)
            del mutant["diagnostics"]["observation_schema"]
            with self.assertRaises(ValueError):
                MODULE.validate_observed_diagnostics(mutant)
        hybrid = copy.deepcopy(shutdown)
        hybrid["diagnostics"]["file_present_before_retry"] = False
        with self.assertRaises(ValueError):
            MODULE.validate_observed_diagnostics(hybrid)


if __name__ == "__main__":
    unittest.main()
