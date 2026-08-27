#!/usr/bin/env python3
"""Run one exact pytest node and emit a machine-readable result.

This helper is intentionally tiny and independent of pytest's human-readable
terminal output.  The security evidence runner validates the JSON instead of
trusting strings a test can print.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import pytest

SDK_ROOT = Path(__file__).resolve().parents[1] / "packages/navigator-python"


class ExactResult:
    def __init__(self) -> None:
        self.collected: list[str] = []
        self.reports: list[dict[str, Any]] = []

    def pytest_collection_finish(self, session: pytest.Session) -> None:
        self.collected = [item.nodeid for item in session.items]

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        self.reports.append(
            {
                "nodeid": report.nodeid,
                "when": report.when,
                "outcome": report.outcome,
                "wasxfail": getattr(report, "wasxfail", None),
            }
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("nodeid")
    args = parser.parse_args()
    if "::" not in args.nodeid or args.nodeid.startswith("-"):
        parser.error("an exact pytest node id is required")

    # Third-party auto-loaded plugins make the release oracle depend on the
    # ambient developer environment.  Explicit project plugins still load via
    # conftest.py.
    os.environ["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    plugin = ExactResult()
    os.chdir(SDK_ROOT)
    pytest_args = [
        args.nodeid,
        "-q",
        "-p",
        "no:cacheprovider",
        "-p",
        "pytest_asyncio.plugin",
    ]
    if args.collect:
        pytest_args.append("--collect-only")
    exit_code = int(pytest.main(pytest_args, plugins=[plugin]))
    result = {
        "schema": 1,
        "mode": "collect" if args.collect else "execute",
        "requested": args.nodeid,
        "collected": plugin.collected,
        "reports": plugin.reports,
        "pytest_version": pytest.__version__,
        "exit_code": exit_code,
    }
    args.result.write_text(json.dumps(result, sort_keys=True) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
