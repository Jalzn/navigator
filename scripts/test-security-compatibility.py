#!/usr/bin/env python3
"""Adversarial checks for exact security-matrix test selection."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "security_compatibility", ROOT / "scripts/check-security-compatibility.py"
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class SecurityCompatibilityRunnerTests(unittest.TestCase):
    NODEID = (
        "tests/test_contract.py::"
        "test_read_events_maps_failure_and_rejects_bounds_before_transport"
    )

    @staticmethod
    def _cell() -> tuple[dict[str, object], list[str]]:
        return (
            {"runner": "pytest", "boundary": ["Consumer/ReadEvents"], "attack": "mutant"},
            [
                "packages/navigator-python/.venv/bin/python",
                "scripts/run-exact-pytest.py",
                SecurityCompatibilityRunnerTests.NODEID,
            ],
        )

    def test_manifest_cell_registry_is_closed(self) -> None:
        manifest = json.loads(CHECK.MANIFEST.read_text())
        self.assertEqual(
            {cell["id"] for cell in manifest["executed_cells"]},
            CHECK.REQUIRED_CELLS,
        )

    def test_exact_pytest_cell_uses_structured_phases(self) -> None:
        nodeid = self.NODEID
        cell, command = self._cell()
        with tempfile.TemporaryDirectory() as temporary:
            result = CHECK.execute_pytest_cell(
                "python-exact-mutant", cell, command, Path(temporary)
            )
        self.assertEqual(result["listed_test_identity"], nodeid)
        self.assertEqual(result["passed_tests"], 1)

    def test_parametrized_base_is_rejected_as_non_exact(self) -> None:
        nodeid = "tests/test_contract.py::test_read_events_rejects_forged_pages"
        cell = {
            "runner": "pytest", "boundary": ["Consumer/ReadEvents"],
            "attack": "broad-selection",
        }
        command = [
            "packages/navigator-python/.venv/bin/python",
            "scripts/run-exact-pytest.py", nodeid,
        ]
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(SystemExit, "exactly its requested node id"):
                CHECK.execute_pytest_cell(
                    "python-broad-mutant", cell, command, Path(temporary)
                )

    def _mocked_execution_is_rejected(self, mutate: object) -> None:
        cell, command = self._cell()
        calls = 0

        def run(argv: list[str], **_: object) -> SimpleNamespace:
            nonlocal calls
            calls += 1
            result_path = Path(argv[argv.index("--result") + 1])
            mode = "collect" if "--collect" in argv else "execute"
            reports = [] if mode == "collect" else [
                {"nodeid": self.NODEID, "when": phase, "outcome": "passed", "wasxfail": None}
                for phase in ("setup", "call", "teardown")
            ]
            result: object = {
                "schema": 1, "mode": mode, "requested": self.NODEID,
                "collected": [self.NODEID], "reports": reports,
                "pytest_version": "8.4.2", "exit_code": 0,
            }
            if mode == "execute":
                if mutate == "missing":
                    return SimpleNamespace(returncode=0, stdout="1 passed\n")
                if mutate == "corrupt":
                    result_path.write_text("not-json")
                    return SimpleNamespace(returncode=0, stdout="1 passed\n")
                assert callable(mutate)
                mutate(result)
            result_path.write_text(json.dumps(result))
            return SimpleNamespace(returncode=0, stdout="1 passed\n")

        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(
            CHECK.subprocess, "run", side_effect=run
        ):
            with self.assertRaises((SystemExit, json.JSONDecodeError)):
                CHECK.execute_pytest_cell("structured-mutant", cell, command, Path(temporary))
        self.assertGreaterEqual(calls, 2)

    def test_missing_or_corrupt_structured_result_is_rejected(self) -> None:
        self._mocked_execution_is_rejected("missing")
        self._mocked_execution_is_rejected("corrupt")

    def test_identity_and_extra_report_mutants_are_rejected(self) -> None:
        self._mocked_execution_is_rejected(
            lambda result: result.update({"requested": "tests/test_contract.py::neighbor"})
        )
        self._mocked_execution_is_rejected(
            lambda result: result["reports"].append(dict(result["reports"][1]))
        )

    def test_skip_xfail_and_phase_failure_mutants_are_rejected(self) -> None:
        for phase, outcome, wasxfail in (
            (0, "skipped", None),
            (1, "passed", "expected failure"),
            (2, "failed", None),
        ):
            def mutate(result: dict[str, object], phase: int = phase,
                       outcome: str = outcome, wasxfail: str | None = wasxfail) -> None:
                report = result["reports"][phase]
                report["outcome"] = outcome
                report["wasxfail"] = wasxfail
            self._mocked_execution_is_rejected(mutate)

    def test_wrong_interpreter_helper_and_non_node_selection_are_rejected(self) -> None:
        cell, command = self._cell()
        mutants = [
            ["python3", *command[1:]],
            [command[0], "scripts/other.py", command[2]],
            [command[0], command[1], "tests/test_contract.py"],
            [*command, "-k"],
        ]
        with tempfile.TemporaryDirectory() as temporary:
            for mutant in mutants:
                with self.assertRaises(SystemExit):
                    CHECK.execute_pytest_cell(
                        "command-shape-mutant", cell, mutant, Path(temporary)
                    )


if __name__ == "__main__":
    unittest.main()
