#!/usr/bin/env python3
"""Mutation checks for dependency-kind architecture boundaries."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_architecture", ROOT / "scripts/check_architecture.py"
)
assert SPEC is not None and SPEC.loader is not None
ARCHITECTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ARCHITECTURE)


class ArchitectureDependencyKindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.metadata = ARCHITECTURE.load_metadata()

    def test_current_workspace_obeys_dependency_kind_boundaries(self) -> None:
        self.assertEqual(ARCHITECTURE.validate(self.metadata), [])

    def test_dev_only_dependencies_are_rejected_when_promoted_to_runtime(self) -> None:
        for package_name, dependency_name in (
            ("navigator-driver-fake", "sqlx"),
            ("navigator-local", "prost"),
        ):
            with self.subTest(package=package_name, dependency=dependency_name):
                mutant = copy.deepcopy(self.metadata)
                package = next(
                    row for row in mutant["packages"] if row["name"] == package_name
                )
                dependency = next(
                    row
                    for row in package["dependencies"]
                    if row["name"] == dependency_name and row.get("kind") == "dev"
                )
                dependency["kind"] = None
                violations = ARCHITECTURE.validate(mutant)
                self.assertIn(
                    f"{package_name} may depend on {dependency_name} only as a "
                    "dev-dependency; observed kinds: ['normal']",
                    violations,
                )


if __name__ == "__main__":
    unittest.main()
