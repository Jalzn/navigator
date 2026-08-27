#!/usr/bin/env python3
"""Mutation-resistant unit checks for the release traceability gate."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import shutil
import tarfile
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_gate", ROOT / "scripts/release-gate.py")
assert SPEC is not None and SPEC.loader is not None
RELEASE_GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE_GATE)


def write_prebuild_fixture(base: Path) -> tuple[Path, list[dict[str, object]]]:
    contract = json.loads(RELEASE_GATE.CONTRACT.read_text())
    entries: list[dict[str, object]] = []
    for number, oracle in enumerate(contract["release_oracles"], 1):
        transcript = base / f"oracle-{number}.log"
        transcript.write_text("passed\n")
        entries.append({
            "kind": "release-oracle", "claim": oracle["claim"],
            "command": oracle["command"], "exit": 0,
            "path": transcript.name, "sha256": RELEASE_GATE.sha256(transcript),
        })
    registry = json.loads(
        (ROOT / contract["critical_mutation_manifest"]).read_text()
    )["mutations"]
    report = base / "mutants.json"
    results = []
    for mutation in registry:
        transcript = base / f"{mutation['id']}.log"
        transcript.write_text(mutation["expected_failure_marker"] + "\n")
        results.append({
            "id": mutation["id"], "command": mutation["command"],
            "registry_entry_sha256": RELEASE_GATE._canonical_digest(mutation),
            "oracle_exit": mutation["expected_exit"],
            "expected_exit": mutation["expected_exit"],
            "expected_failure_marker": mutation["expected_failure_marker"],
            "failure_marker_observed": True, "transcript": transcript.name,
            "transcript_sha256": RELEASE_GATE.sha256(transcript), "killed": True,
        })
    report.write_text(json.dumps({"schema_version": 2, "results": results}))
    mutant_rows, errors = RELEASE_GATE._mutant_evidence(base, report)
    assert errors == []
    entries.extend(mutant_rows)
    index = base / "prebuild-index.json"
    index.write_text(json.dumps({
        "schema_version": 1, "phase": "prebuild", "entries": entries,
    }))
    return index, entries


class ReleaseGateTests(unittest.TestCase):
    # Guarantees: NAV-TRACE-001
    def test_release_traceability_is_bidirectional(self) -> None:
        facts = RELEASE_GATE.verify_traceability()
        self.assertEqual(facts["unmapped_guarantees"], [])
        self.assertEqual(facts["unbound_tests"], [])

        manifest = RELEASE_GATE.TRACEABILITY.read_text()
        mutated = manifest.replace("NAV-STORE-001", "NAV-MISSING-999", 1)
        with self.assertRaisesRegex(ValueError, "unknown guarantee"):
            RELEASE_GATE.verify_traceability(mutated)

    def test_reviewed_legacy_security_evidence_is_digest_bound(self) -> None:
        source = ROOT / "evidence/task02-final-20260826T0752"
        attestation = ROOT / "conformance/task02-review-attestation.historical.json"
        self.assertEqual(
            RELEASE_GATE.verify_security_outputs(source, attestation),
            ["security-manifest-digest-mismatch", "security-source-tree-mismatch"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            mutant = Path(temporary) / "security"
            shutil.copytree(source, mutant)
            (mutant / "licenses.json").write_text('{"components": []}\n')
            self.assertIn(
                "security-index-digest-mismatch:licenses.json",
                RELEASE_GATE.verify_security_outputs(mutant, attestation),
            )

    def test_security_candidate_cannot_self_authorize_without_sidecar(self) -> None:
        source = ROOT / "evidence/task02-final-20260826T0752"
        self.assertIn(
            "security-review-not-go",
            RELEASE_GATE.verify_security_outputs(source),
        )

    def test_verified_summary_cannot_bypass_an_invalid_sidecar(self) -> None:
        source = ROOT / "evidence/task02-final-20260826T0752"
        with tempfile.TemporaryDirectory() as temporary:
            mutant = Path(temporary) / "security"
            shutil.copytree(source, mutant)
            summary = json.loads((mutant / "summary.json").read_text())
            summary["status"] = "verified"
            (mutant / "summary.json").write_text(json.dumps(summary))
            sidecar = Path(temporary) / "invalid-attestation.json"
            sidecar.write_text('{"verdict":"NO-GO"}')
            self.assertIn(
                "security-review-not-go",
                RELEASE_GATE.verify_security_outputs(mutant, sidecar),
            )

    def test_fault_matrix_requires_digest_closure_and_go_attestation(self) -> None:
        self.assertEqual(RELEASE_GATE.verify_fault_matrix_outputs(), [])
        original = RELEASE_GATE.TASK03_REVIEW
        with tempfile.TemporaryDirectory() as temporary:
            review = Path(temporary) / "review.md"
            review.write_text("Status: NO-GO\n")
            RELEASE_GATE.TASK03_REVIEW = review
            try:
                self.assertIn(
                    "fault-review-not-go", RELEASE_GATE.verify_fault_matrix_outputs()
                )
            finally:
                RELEASE_GATE.TASK03_REVIEW = original

    def test_archive_bytes_do_not_depend_on_witness_directory_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            primary = root / "release-bundle"
            witness = root / "release-bundle-reproducibility-witness"
            for bundle in (primary, witness):
                (bundle / "nested").mkdir(parents=True)
                (bundle / "nested/payload").write_bytes(b"same release payload\n")
                executable = bundle / "nested/tool"
                executable.write_bytes(b"#!/bin/sh\nexit 0\n")
                executable.chmod(0o755)
                os.symlink("payload", bundle / "nested/payload-link")
            first = RELEASE_GATE.write_deterministic_archive(primary, "release-bundle")
            second = RELEASE_GATE.write_deterministic_archive(witness, "release-bundle")
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).hexdigest(),
                hashlib.sha256(second.read_bytes()).hexdigest(),
            )
            with tarfile.open(first) as archive:
                member_list = archive.getmembers()
                members = {member.name: member for member in member_list}
            self.assertEqual(len(member_list), 4)
            self.assertEqual(
                set(members),
                {
                    "release-bundle/nested",
                    "release-bundle/nested/payload",
                    "release-bundle/nested/payload-link",
                    "release-bundle/nested/tool",
                },
            )
            self.assertEqual(members["release-bundle/nested/tool"].mode, 0o755)
            link = members["release-bundle/nested/payload-link"]
            self.assertTrue(link.issym())
            self.assertEqual(link.linkname, "payload")
            for member in members.values():
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual((member.uname, member.gname), ("", ""))

            baseline = first.read_bytes()
            mutations = {
                "content": lambda bundle: (bundle / "nested/payload").write_bytes(b"changed\n"),
                "added-member": lambda bundle: (bundle / "extra").write_bytes(b"extra\n"),
                "mode": lambda bundle: (bundle / "nested/tool").chmod(0o644),
                "link-target": lambda bundle: (bundle / "nested/payload-link").unlink()
                or os.symlink("tool", bundle / "nested/payload-link"),
            }
            for name, mutate in mutations.items():
                with self.subTest(name=name):
                    candidate = root / f"mutant-{name}"
                    shutil.copytree(primary, candidate, symlinks=True)
                    mutate(candidate)
                    archive = RELEASE_GATE.write_deterministic_archive(
                        candidate, "release-bundle"
                    )
                    self.assertNotEqual(archive.read_bytes(), baseline)

            wrong_root = RELEASE_GATE.write_deterministic_archive(
                witness, "different-root"
            )
            self.assertNotEqual(wrong_root.read_bytes(), baseline)

    def test_execution_evidence_closure_rejects_missing_and_adulterated_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            index, entries = write_prebuild_fixture(base)
            self.assertEqual(RELEASE_GATE.verify_execution_evidence(base, index), [])

            transcript = base / str(entries[0]["path"])
            transcript.write_text("forged\n")
            self.assertIn(
                f"execution-evidence-digest:{entries[0]['path']}",
                RELEASE_GATE.verify_execution_evidence(base, index),
            )
            transcript.write_text("passed\n")
            transcript.unlink()
            self.assertIn(
                f"execution-evidence-missing:{entries[0]['path']}",
                RELEASE_GATE.verify_execution_evidence(base, index),
            )
            transcript.write_text("passed\n")
            entries[0]["exit"] = 1
            index.write_text(json.dumps({
                "schema_version": 1, "phase": "prebuild", "entries": entries,
            }))
            self.assertIn(
                "execution-evidence-prebuild-shape",
                RELEASE_GATE.verify_execution_evidence(base, index),
            )
            entries[0]["exit"] = 0
            index.write_text(json.dumps({
                "schema_version": 1, "phase": "prebuild", "entries": entries,
            }))
            smoke = base / "smoke.log"
            smoke.write_text("passed\n")
            archive = base / "release-bundle.tar"
            archive.write_bytes(b"primary archive\n")
            authorization_entries = entries + [{
                "kind": "extracted-smoke", "claim": RELEASE_GATE.SMOKE_CLAIM,
                "command_id": RELEASE_GATE.SMOKE_COMMAND_ID,
                "artifact_archive_path": str(
                    archive.resolve().relative_to(base.parent.resolve())
                ),
                "artifact_archive_sha256": RELEASE_GATE.sha256(archive),
                "exit": 0, "path": smoke.name, "sha256": RELEASE_GATE.sha256(smoke),
            }]
            authorization = base / "authorization-index.json"
            authorization.write_text(json.dumps({
                "schema_version": 1, "phase": "authorization",
                "entries": authorization_entries,
                "prebuild_index": {"path": index.name, "sha256": RELEASE_GATE.sha256(index)},
            }))
            self.assertEqual(
                RELEASE_GATE.verify_execution_evidence(base, authorization, archive), []
            )
            authorization_entries[0] = dict(authorization_entries[0], claim="forged")
            authorization.write_text(json.dumps({
                "schema_version": 1, "phase": "authorization",
                "entries": authorization_entries,
                "prebuild_index": {"path": index.name, "sha256": RELEASE_GATE.sha256(index)},
            }))
            self.assertIn(
                "execution-evidence-authorization-shape",
                RELEASE_GATE.verify_execution_evidence(base, authorization, archive),
            )
            entries[0]["exit"] = 0
            index.write_text(json.dumps({
                "schema_version": 1, "phase": "wrong", "entries": entries,
            }))
            self.assertIn(
                "execution-evidence-phase-invalid",
                RELEASE_GATE.verify_execution_evidence(base, index),
            )

    def test_mutant_evidence_binds_exit_marker_report_and_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            report = base / "mutants.json"
            transcripts = base / "mutants-transcripts"
            transcripts.mkdir()
            results = []
            contract = json.loads(RELEASE_GATE.CONTRACT.read_text())
            registry = json.loads(
                (ROOT / contract["critical_mutation_manifest"]).read_text()
            )["mutations"]
            for mutation in registry:
                marker = mutation["expected_failure_marker"]
                transcript = transcripts / f"{mutation['id']}.log"
                transcript.write_text(marker + "\n")
                results.append({
                    "id": mutation["id"], "command": mutation["command"],
                    "registry_entry_sha256": RELEASE_GATE._canonical_digest(mutation),
                    "oracle_exit": mutation["expected_exit"],
                    "expected_exit": mutation["expected_exit"],
                    "expected_failure_marker": marker,
                    "failure_marker_observed": True,
                    "transcript": str(transcript.relative_to(base)),
                    "transcript_sha256": RELEASE_GATE.sha256(transcript),
                    "killed": True,
                })
            report.write_text(json.dumps({"schema_version": 2, "results": results}))
            rows, errors = RELEASE_GATE._mutant_evidence(base, report)
            self.assertEqual(errors, [])
            self.assertEqual(len(rows), 7)

            results[0]["oracle_exit"] = 0
            report.write_text(json.dumps({"schema_version": 2, "results": results}))
            self.assertIn(
                f"critical-mutant-evidence-invalid:{registry[0]['id']}",
                RELEASE_GATE._mutant_evidence(base, report)[1],
            )

    def test_evidence_paths_reject_absolute_parent_and_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "evidence"
            base.mkdir()
            outside = Path(temporary) / "outside.log"
            outside.write_text("outside\n")
            os.symlink(outside, base / "escape.log")
            for path in (str(outside), "../outside.log", "escape.log"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    RELEASE_GATE._safe_evidence_path(base, path)

    def test_prebuild_rejects_duplicate_missing_and_extra_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            index, entries = write_prebuild_fixture(base)
            mutations = {
                "duplicate": entries + [entries[0]],
                "missing": entries[:-1],
                "extra": entries + [dict(entries[0], path="extra.log")],
                "repeated-id": entries[:-1] + [dict(entries[-2], path=entries[-1]["path"])],
            }
            (base / "extra.log").write_text("passed\n")
            mutations["extra"][-1]["sha256"] = RELEASE_GATE.sha256(base / "extra.log")
            for name, rows in mutations.items():
                with self.subTest(name=name):
                    index.write_text(json.dumps({
                        "schema_version": 1, "phase": "prebuild", "entries": rows,
                    }))
                    self.assertTrue(RELEASE_GATE.verify_execution_evidence(base, index))

    def test_mutant_registry_identity_is_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            contract = json.loads(RELEASE_GATE.CONTRACT.read_text())
            registry = json.loads(
                (ROOT / contract["critical_mutation_manifest"]).read_text()
            )["mutations"]
            transcripts = base / "logs"
            transcripts.mkdir()
            results = []
            for definition in registry:
                log = transcripts / f"{definition['id']}.log"
                log.write_text(definition["expected_failure_marker"] + "\n")
                results.append({
                    "id": definition["id"], "command": definition["command"],
                    "registry_entry_sha256": RELEASE_GATE._canonical_digest(definition),
                    "oracle_exit": definition["expected_exit"],
                    "expected_exit": definition["expected_exit"],
                    "expected_failure_marker": definition["expected_failure_marker"],
                    "failure_marker_observed": True,
                    "transcript": str(log.relative_to(base)),
                    "transcript_sha256": RELEASE_GATE.sha256(log), "killed": True,
                })
            report = base / "report.json"
            alterations = (
                ("command", ["false"]), ("expected_exit", 0),
                ("expected_failure_marker", "wrong"),
                ("registry_entry_sha256", "0" * 64),
            )
            for field, value in alterations:
                with self.subTest(field=field):
                    mutant = json.loads(json.dumps(results))
                    mutant[0][field] = value
                    report.write_text(json.dumps({"schema_version": 2, "results": mutant}))
                    self.assertTrue(RELEASE_GATE._mutant_evidence(base, report)[1])
            repeated = json.loads(json.dumps(results))
            repeated[-1]["id"] = repeated[0]["id"]
            report.write_text(json.dumps({"schema_version": 2, "results": repeated}))
            self.assertIn(
                "critical-mutant-report-identity",
                RELEASE_GATE._mutant_evidence(base, report)[1],
            )

    def test_authorization_rejects_coordinated_mutant_and_smoke_forgery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            index, original_entries = write_prebuild_fixture(base)
            smoke = base / "smoke.log"
            smoke.write_text("passed\n")
            archive = base / "release-bundle.tar"
            archive.write_bytes(b"primary archive\n")

            def write_authorization(entries: list[dict[str, object]], smoke_row: dict[str, object]) -> Path:
                index.write_text(json.dumps({
                    "schema_version": 1, "phase": "prebuild", "entries": entries,
                }))
                authorization = base / "authorization-index.json"
                authorization.write_text(json.dumps({
                    "schema_version": 1, "phase": "authorization",
                    "entries": entries + [smoke_row],
                    "prebuild_index": {
                        "path": index.name, "sha256": RELEASE_GATE.sha256(index),
                    },
                }))
                return authorization

            smoke_row: dict[str, object] = {
                "kind": "extracted-smoke", "claim": RELEASE_GATE.SMOKE_CLAIM,
                "command_id": RELEASE_GATE.SMOKE_COMMAND_ID,
                "artifact_archive_path": str(
                    archive.resolve().relative_to(base.parent.resolve())
                ),
                "artifact_archive_sha256": RELEASE_GATE.sha256(archive), "exit": 0,
                "path": smoke.name, "sha256": RELEASE_GATE.sha256(smoke),
            }
            alterations = (
                ("command", ["forged"]), ("expected_marker", "forged"),
                ("exit", 0), ("expected_exit", 0),
                ("registry_entry_sha256", "0" * 64),
            )
            for field, value in alterations:
                with self.subTest(mutant_field=field):
                    entries = json.loads(json.dumps(original_entries))
                    mutant = next(row for row in entries if row["kind"] == "critical-mutant")
                    mutant[field] = value
                    authorization = write_authorization(entries, smoke_row)
                    self.assertTrue(
                        RELEASE_GATE.verify_execution_evidence(base, authorization, archive)
                    )
            for field, value in (
                ("claim", "forged claim"), ("command_id", "forged.command.v1"),
            ):
                with self.subTest(smoke_field=field):
                    forged_smoke = dict(smoke_row)
                    forged_smoke[field] = value
                    authorization = write_authorization(original_entries, forged_smoke)
                    self.assertTrue(
                        RELEASE_GATE.verify_execution_evidence(base, authorization, archive)
                    )

    def test_authorization_binds_the_real_archive_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            prebuild, entries = write_prebuild_fixture(base)
            archive = base / "release-bundle.tar"
            archive.write_bytes(b"primary archive\n")
            other = base / "other.tar"
            other.write_bytes(b"other archive\n")
            smoke_log = base / "smoke.log"
            smoke_log.write_text("passed\n")
            canonical = str(archive.resolve().relative_to(base.parent.resolve()))
            smoke = {
                "kind": "extracted-smoke", "claim": RELEASE_GATE.SMOKE_CLAIM,
                "command_id": RELEASE_GATE.SMOKE_COMMAND_ID,
                "artifact_archive_path": canonical,
                "artifact_archive_sha256": RELEASE_GATE.sha256(archive),
                "exit": 0, "path": smoke_log.name,
                "sha256": RELEASE_GATE.sha256(smoke_log),
            }
            authorization = base / "authorization-index.json"

            def write(smoke_row: dict[str, object]) -> None:
                authorization.write_text(json.dumps({
                    "schema_version": 1, "phase": "authorization",
                    "entries": entries + [smoke_row],
                    "prebuild_index": {
                        "path": prebuild.name,
                        "sha256": RELEASE_GATE.sha256(prebuild),
                    },
                }))

            write(dict(smoke, artifact_archive_path="other.tar"))
            self.assertIn(
                "execution-evidence-archive-binding",
                RELEASE_GATE.verify_execution_evidence(base, authorization, archive),
            )
            write(dict(smoke, artifact_archive_sha256="not-a-digest"))
            self.assertIn(
                "execution-evidence-archive-binding",
                RELEASE_GATE.verify_execution_evidence(base, authorization, archive),
            )
            write(dict(smoke, artifact_archive_sha256=RELEASE_GATE.sha256(other)))
            self.assertIn(
                "execution-evidence-archive-binding",
                RELEASE_GATE.verify_execution_evidence(base, authorization, archive),
            )
            write(smoke)
            archive.write_bytes(b"altered after smoke\n")
            self.assertIn(
                "execution-evidence-archive-binding",
                RELEASE_GATE.verify_execution_evidence(base, authorization, archive),
            )
            archive.unlink()
            self.assertIn(
                "execution-evidence-archive-binding",
                RELEASE_GATE.verify_execution_evidence(base, authorization, archive),
            )


if __name__ == "__main__":
    unittest.main()
