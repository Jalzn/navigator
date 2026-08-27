#!/usr/bin/env python3
"""Inject each critical defect in an isolated source copy and require its oracle to fail."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "conformance/release-critical-mutations-v1.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_digest(value: object) -> str:
    wire = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(wire).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", type=Path, default=ROOT / "target/release-critical-mutants.json")
    parser.add_argument("--only")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    results = []
    transcript_dir = args.report.parent / f"{args.report.stem}-transcripts"
    transcript_dir.mkdir(parents=True, exist_ok=True)
    shared_target = ROOT / "target/release-critical-mutants-target"
    for mutation in manifest["mutations"]:
        if args.only is not None and mutation["id"] != args.only:
            continue
        with tempfile.TemporaryDirectory(prefix=f"navigator-mutant-{mutation['id']}-") as temporary:
            checkout = Path(temporary) / "navigator"
            subprocess.run(
                ["rsync", "-a", "--delete", "--exclude", "target", "--exclude", ".git",
                 "--exclude", "node_modules", f"{ROOT}/", f"{checkout}/"],
                check=True,
            )
            path = checkout / mutation["file"]
            source = path.read_text()
            count = source.count(mutation["from"])
            if count < 1:
                raise SystemExit(f"{mutation['id']}: mutation anchor is absent")
            path.write_text(source.replace(mutation["from"], mutation["to"], 1))
            environment = os.environ.copy()
            environment["CARGO_TARGET_DIR"] = str(shared_target)
            completed = subprocess.run(
                mutation["command"], cwd=checkout, env=environment,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            )
            transcript = completed.stdout
            transcript_path = transcript_dir / f"{mutation['id']}.log"
            transcript_path.write_text(transcript)
            marker = mutation["expected_failure_marker"]
            killed = (
                completed.returncode == mutation["expected_exit"]
                and marker in transcript
            )
            print(
                f"critical-mutant {mutation['id']}: exit={completed.returncode}; "
                f"semantic-marker={'yes' if marker in transcript else 'no'}"
            )
            results.append({
                "id": mutation["id"],
                "registry_entry_sha256": canonical_digest(mutation),
                "oracle_exit": completed.returncode,
                "command": mutation["command"],
                "expected_exit": mutation["expected_exit"],
                "expected_failure_marker": marker,
                "failure_marker_observed": marker in transcript,
                "transcript": str(transcript_path.relative_to(args.report.parent)),
                "transcript_sha256": sha256(transcript_path),
                "killed": killed,
            })
            if not killed:
                raise SystemExit(f"critical mutant survived: {mutation['id']}")
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps({"schema_version": 2, "results": results}, indent=2) + "\n")
    print(f"release-critical-mutants: {len(results)} defects killed; report={args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
