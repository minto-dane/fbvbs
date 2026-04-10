#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


TIME_TOOL = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "validate_time_source_integrity.py"
RETRY_TOOL = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "plan_remote_export_retry.py"
GENERATE_PACK = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "generate_standalone_evidence_pack.py"
EXPORT_DIAG = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "export_diagnostic_bundle.py"


class TimeSourceAndRemoteExportTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def make_timeline(self, path: pathlib.Path) -> None:
        self.write_json(
            path,
            {
                "audit_schema_version": 1,
                "root_chain_sha384": "a" * 96,
                "record_count": 3,
                "records": [
                    {"timestamp_ns": 100, "sequence": 1},
                    {"timestamp_ns": 200, "sequence": 2},
                    {"timestamp_ns": 150, "sequence": 3},
                ],
            },
        )

    def make_diag_inputs(self, temp_dir: pathlib.Path) -> dict[str, pathlib.Path]:
        schema = temp_dir / "schema.json"
        inventory = temp_dir / "inventory.json"
        partition_list = temp_dir / "partition-list.json"
        severity = temp_dir / "severity.json"
        timeline = temp_dir / "timeline.json"
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
        self.write_json(
            severity,
            {
                "presentation_locale": "en",
                "overall_severity": {"name": "WARNING", "value": 3},
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
        self.write_json(
            timeline,
            {
                "audit_schema_version": 1,
                "root_chain_sha384": "a" * 96,
                "record_count": 1,
                "boot_sessions": [{"boot_id": "global", "gap_count": 0, "gaps": []}],
                "records": [{"timestamp_ns": 100, "sequence": 1}],
            },
        )
        return {
            "schema": schema,
            "inventory": inventory,
            "partition_list": partition_list,
            "severity": severity,
            "timeline": timeline,
        }

    def test_time_source_integrity_detects_non_monotonic_timestamps(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-time-src-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            timeline = temp_dir / "timeline.json"
            self.make_timeline(timeline)

            subprocess.run(
                [
                    "python3",
                    str(TIME_TOOL),
                    "--timeline",
                    str(timeline),
                    "--locale",
                    "ja",
                    "--output-dir",
                    str(temp_dir),
                ],
                check=True,
            )

            report = json.loads((temp_dir / "time-source-integrity-report.json").read_text(encoding="utf-8"))
            markdown = (temp_dir / "time-source-integrity-report.md").read_text(encoding="utf-8")
            self.assertEqual(report["audit_schema_version"], 1)
            self.assertEqual(report["status"], "warning")
            self.assertGreaterEqual(report["issue_count"], 1)
            self.assertIn("時刻源整合性レポート", markdown)

            result = subprocess.run(
                [
                    "python3",
                    str(TIME_TOOL),
                    "--timeline",
                    str(timeline),
                    "--output-dir",
                    str(temp_dir),
                    "--fail-on-issue",
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("time source integrity issues detected", result.stderr)

    def test_remote_export_retry_manifest_and_forensic_preservation_mode(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-remote-retry-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            inputs = self.make_diag_inputs(temp_dir)
            diag_bundle = temp_dir / "diagnostic-bundle.tar.gz"
            evidence_pack = temp_dir / "evidence-pack.tar.gz"
            retry_manifest = temp_dir / "remote-retry.json"
            key = temp_dir / "signing-key.pem"
            cert = temp_dir / "signing-cert.pem"

            subprocess.run(
                [
                    "python3",
                    str(EXPORT_DIAG),
                    "--output",
                    str(diag_bundle),
                    "--allow-input-root",
                    str(temp_dir),
                    "--schema-registry",
                    str(inputs["schema"]),
                    "--inventory",
                    str(inputs["inventory"]),
                    "--partition-list",
                    str(inputs["partition_list"]),
                    "--capture-complete",
                ],
                check=True,
            )

            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-out",
                    str(key),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    str(key),
                    "-subj",
                    "/CN=FBVBS Forensic Preservation Test",
                    "-days",
                    "1",
                    "-out",
                    str(cert),
                ],
                check=True,
                capture_output=True,
                text=True,
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
                    str(inputs["timeline"]),
                    "--severity-summary",
                    str(inputs["severity"]),
                    "--capture-complete",
                    "--forensic-preservation-mode",
                    "--signing-key",
                    str(key),
                    "--signing-cert",
                    str(cert),
                ],
                check=True,
            )

            subprocess.run(
                [
                    "python3",
                    str(RETRY_TOOL),
                    "--archive",
                    str(evidence_pack),
                    "--destination",
                    "s3://standalone-evidence-archive",
                    "--max-attempts",
                    "3",
                    "--initial-delay-seconds",
                    "10",
                    "--backoff-factor",
                    "2",
                    "--output",
                    str(retry_manifest),
                ],
                check=True,
            )

            retry = json.loads(retry_manifest.read_text(encoding="utf-8"))
            self.assertEqual(retry["max_attempts"], 3)
            self.assertEqual(len(retry["retry_schedule"]), 3)
            self.assertEqual(retry["retry_schedule"][0]["delay_seconds"], 10)
            self.assertEqual(retry["retry_schedule"][1]["delay_seconds"], 20)

            import tarfile

            with tarfile.open(evidence_pack, "r:gz") as archive:
                manifest = json.load(
                    archive.extractfile("evidence/standalone-evidence-pack-manifest.json")
                )
                forensic = json.load(
                    archive.extractfile("evidence/forensic-preservation.json")
                )
            self.assertTrue(manifest["signed"])
            self.assertTrue(manifest["capture_complete"])
            self.assertTrue(manifest["forensic_preservation"]["enabled"])
            self.assertTrue(forensic["retention_lock_required"])


if __name__ == "__main__":
    unittest.main()
