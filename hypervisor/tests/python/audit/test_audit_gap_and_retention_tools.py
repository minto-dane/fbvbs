#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


GAP_TOOL = pathlib.Path(__file__).resolve().parents[3] / "tools" / "audit" / "detect_audit_gaps.py"
INTEGRITY_TOOL = pathlib.Path(__file__).resolve().parents[3] / "tools" / "audit" / "check_retention_integrity.py"
EXPORT_DIAG = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "export_diagnostic_bundle.py"
GENERATE_PACK = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "generate_standalone_evidence_pack.py"


class AuditGapAndRetentionTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def make_diag_inputs(self, temp_dir: pathlib.Path) -> dict[str, pathlib.Path]:
        schema = temp_dir / "schema.json"
        inventory = temp_dir / "inventory.json"
        partition_list = temp_dir / "partition-list.json"
        self.write_json(
            schema,
            {
                "management_abi_version": 1,
                "health_schema_version": 1,
                "audit_schema_version": 1,
                "inventory_schema_version": 1,
                "guidance_schema_version": 1,
                "fault_record_schema_version": 1,
                "compatibility_flags": 15,
            },
        )
        self.write_json(inventory, {"occupied_partition_count": 1})
        self.write_json(partition_list, {"count": 1, "entries": [{"partition_id": 4097}]})
        return {
            "schema": schema,
            "inventory": inventory,
            "partition_list": partition_list,
        }

    def make_timeline(self, temp_dir: pathlib.Path) -> pathlib.Path:
        timeline = temp_dir / "timeline.json"
        self.write_json(
            timeline,
            {
                "root_chain_sha384": "a" * 96,
                "record_count": 3,
                "boot_sessions": [
                    {
                        "boot_id": "global",
                        "gap_count": 1,
                        "gaps": [
                            {
                                "after_sequence": 1,
                                "before_sequence": 3,
                                "missing_count": 1,
                            }
                        ],
                    }
                ],
            },
        )
        return timeline

    def test_audit_gap_report_and_fail_on_gap(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-gap-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            timeline = self.make_timeline(temp_dir)

            subprocess.run(
                [
                    "python3",
                    str(GAP_TOOL),
                    "--timeline",
                    str(timeline),
                    "--locale",
                    "ja",
                    "--output-dir",
                    str(temp_dir),
                ],
                check=True,
            )

            payload = json.loads((temp_dir / "audit-gap-report.json").read_text(encoding="utf-8"))
            markdown = (temp_dir / "audit-gap-report.md").read_text(encoding="utf-8")
            self.assertEqual(payload["gap_count_total"], 1)
            self.assertEqual(payload["missing_record_count_total"], 1)
            self.assertIn("監査欠落レポート", markdown)

            result = subprocess.run(
                [
                    "python3",
                    str(GAP_TOOL),
                    "--timeline",
                    str(timeline),
                    "--output-dir",
                    str(temp_dir),
                    "--fail-on-gap",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("audit gaps detected", result.stderr)

    def test_retention_integrity_checks_diagnostic_and_evidence_archives(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-retention-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            diag_inputs = self.make_diag_inputs(temp_dir)
            timeline = self.make_timeline(temp_dir)
            severity = temp_dir / "severity.json"
            self.write_json(
                severity,
                {
                    "overall_severity": {"name": "WARNING", "value": 3},
                    "presentation_locale": "en",
                    "partitions": [
                        {
                            "partition_id": 4097,
                            "health_state": {"name": "DEGRADED", "value": 1},
                            "fault_code": 0,
                            "quarantine_reason": 0,
                            "severity": {"name": "WARNING", "value": 3, "source": "guidance"},
                        }
                    ],
                },
            )
            diag_bundle = temp_dir / "diag.tar.gz"
            evidence_pack = temp_dir / "evidence.tar.gz"

            subprocess.run(
                [
                    "python3",
                    str(EXPORT_DIAG),
                    "--output",
                    str(diag_bundle),
                    "--allow-input-root",
                    str(temp_dir),
                    "--schema-registry",
                    str(diag_inputs["schema"]),
                    "--inventory",
                    str(diag_inputs["inventory"]),
                    "--partition-list",
                    str(diag_inputs["partition_list"]),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(GENERATE_PACK),
                    "--output",
                    str(evidence_pack),
                    "--allow-input-root",
                    str(temp_dir),
                    "--diagnostic-bundle",
                    str(diag_bundle),
                    "--timeline",
                    str(timeline),
                    "--severity-summary",
                    str(severity),
                ],
                check=True,
            )

            diag_report_path = temp_dir / "diag-retention.json"
            evidence_report_path = temp_dir / "evidence-retention.json"
            subprocess.run(
                [
                    "python3",
                    str(INTEGRITY_TOOL),
                    "--archive",
                    str(diag_bundle),
                    "--output",
                    str(diag_report_path),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(INTEGRITY_TOOL),
                    "--archive",
                    str(evidence_pack),
                    "--output",
                    str(evidence_report_path),
                ],
                check=True,
            )

            diag_report = json.loads(diag_report_path.read_text(encoding="utf-8"))
            evidence_report = json.loads(evidence_report_path.read_text(encoding="utf-8"))
            self.assertEqual(diag_report["bundle_type"], "fbvbs-standalone-diagnostic")
            self.assertEqual(evidence_report["bundle_type"], "fbvbs-standalone-evidence-pack")
            self.assertGreaterEqual(diag_report["artifact_count"], 3)
            self.assertGreaterEqual(evidence_report["artifact_count"], 5)


if __name__ == "__main__":
    unittest.main()
