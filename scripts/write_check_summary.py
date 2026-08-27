#!/usr/bin/env python3

import json
import pathlib
import sys


results_path = pathlib.Path(sys.argv[1])
output_dir = pathlib.Path(sys.argv[2])
gates = []

for line in results_path.read_text(encoding="utf-8").splitlines():
    name, status = line.split("\t", maxsplit=1)
    gates.append({"name": name, "status": status})

overall = "pass" if gates and all(gate["status"] == "pass" for gate in gates) else "fail"
evidence = {"schema_version": 1, "overall": overall, "gates": gates}

(output_dir / "summary.json").write_text(
    json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)

human = [f"Navigator verification: {overall.upper()}"]
human.extend(f"{gate['name']}: {gate['status']}" for gate in gates)
(output_dir / "summary.txt").write_text("\n".join(human) + "\n", encoding="utf-8")

transcript = ["navigator-conformance-v1"]
transcript.extend(f"[{gate['status']}] {gate['name']}" for gate in gates)
(output_dir / "transcript.txt").write_text(
    "\n".join(transcript) + "\n", encoding="utf-8"
)
