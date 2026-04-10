#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


EXPORT_DIAG = pathlib.Path(__file__).resolve().parents[3] / "tools" / "diagnostics" / "export_diagnostic_bundle.py"
STATE_MANIFEST = pathlib.Path(__file__).resolve().parents[3] / "tools" / "compatibility" / "generate_standalone_state_manifest.py"
DOWNGRADE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "compatibility" / "check_standalone_downgrade_compatibility.py"
MIGRATION = pathlib.Path(__file__).resolve().parents[3] / "tools" / "compatibility" / "check_standalone_migration_compatibility.py"


class StateManifestAndCompatibilityToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def make_diag_bundle(self, temp_dir: pathlib.Path) -> pathlib.Path:
        schema = temp_dir / "schema.json"
        inventory = temp_dir / "inventory.json"
        partition_list = temp_dir / "partition-list.json"
        guidance = temp_dir / "guidance.json"
        fault_record = temp_dir / "fault-record.json"
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
        self.write_json(
            inventory,
            {
                "occupied_partition_count": 2,
                "quarantined_partition_count": 1,
                "recovery_partition_count": 0,
            },
        )
        self.write_json(
            partition_list,
            {
                "count": 2,
                "entries": [
                    {"partition_id": 1, "health_state": 2, "fault_code": 77, "quarantine_reason": 77},
                    {"partition_id": 2, "health_state": 1, "fault_code": 0, "quarantine_reason": 0},
                ],
            },
        )
        self.write_json(guidance, {"partition_id": 1, "reason_domain": 4, "severity": 3, "runbook_code": 7})
        self.write_json(fault_record, {"partition_id": 1, "severity": 6, "fault_code": 77})
        output = temp_dir / "diagnostic-bundle.tar.gz"
        subprocess.run(
            [
                "python3",
                str(EXPORT_DIAG),
                "--output",
                str(output),
                "--allow-input-root",
                str(temp_dir),
                "--schema-registry",
                str(schema),
                "--inventory",
                str(inventory),
                "--partition-list",
                str(partition_list),
                "--guidance",
                str(guidance),
                "--fault-record",
                str(fault_record),
            ],
            check=True,
        )
        return output

    def make_operator_artifacts(self, temp_dir: pathlib.Path) -> dict[str, pathlib.Path]:
        timeline = temp_dir / "timeline.json"
        severity = temp_dir / "severity.json"
        ack = temp_dir / "ack.json"
        matrix = temp_dir / "matrix.json"
        panel = temp_dir / "panel.json"
        self.write_json(
            timeline,
            {
                "audit_schema_version": 1,
                "root_chain_sha384": "a" * 96,
                "record_count": 2,
                "boot_sessions": [{"boot_id": "global", "record_count": 2, "gap_count": 0}],
            },
        )
        self.write_json(
            severity,
            {
                "summary_schema_version": 1,
                "presentation_locale": "ja",
                "overall_severity": {"name": "ALERT", "value": 6},
                "partitions": [],
            },
        )
        self.write_json(
            ack,
            {
                "ledger_schema_version": 1,
                "timeline_root_chain_sha384": "a" * 96,
                "acknowledgment_count": 1,
            },
        )
        self.write_json(
            matrix,
            {
                "matrix_schema_version": 1,
                "summary": {"row_count": 12},
                "schema_registry": {"management_abi_version": 1},
            },
        )
        self.write_json(
            panel,
            {
                "presentation_locale": "ja",
                "style": "mainframe-ispf-inspired",
            },
        )
        return {
            "timeline": timeline,
            "severity": severity,
            "ack": ack,
            "matrix": matrix,
            "panel": panel,
        }

    def generate_manifest(self, temp_dir: pathlib.Path) -> pathlib.Path:
        temp_dir.mkdir(parents=True, exist_ok=True)
        diag_bundle = self.make_diag_bundle(temp_dir)
        artifacts = self.make_operator_artifacts(temp_dir)
        output = temp_dir / "standalone-state-manifest.json"
        subprocess.run(
            [
                "python3",
                str(STATE_MANIFEST),
                "--diagnostic-bundle",
                str(diag_bundle),
                "--timeline",
                str(artifacts["timeline"]),
                "--severity-summary",
                str(artifacts["severity"]),
                "--ack-ledger",
                str(artifacts["ack"]),
                "--compatibility-matrix",
                str(artifacts["matrix"]),
                "--panel-manifest",
                str(artifacts["panel"]),
                "--evidence-pack-format-version",
                "1",
                "--output",
                str(output),
            ],
            check=True,
        )
        return output

    def run_tool(self, script: pathlib.Path, source: pathlib.Path, target: pathlib.Path, expected_code: int = 0) -> dict:
        result = subprocess.run(
            [
                "python3",
                str(script),
                "--source-manifest",
                str(source),
                "--target-manifest",
                str(target),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, expected_code, msg=result.stdout + result.stderr)
        return json.loads(result.stdout)

    def test_generates_state_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-state-manifest-") as temp_dir_raw:
            manifest_path = self.generate_manifest(pathlib.Path(temp_dir_raw))
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["state_manifest_schema_version"], 1)
            self.assertEqual(payload["compatibility_windows"]["management_abi_version"]["current"], 1)
            self.assertEqual(payload["compatibility_windows"]["severity_summary_schema_version"]["current"], 1)
            self.assertEqual(payload["artifact_state"]["severity_locale"], "ja")
            self.assertEqual(payload["artifact_state"]["panel_style"], "mainframe-ispf-inspired")

    def test_downgrade_checker_rejects_schema_regression(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-state-downgrade-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            source = self.generate_manifest(temp_dir / "source")
            target_payload = json.loads(source.read_text(encoding="utf-8"))
            target_payload["compatibility_windows"]["audit_schema_version"]["maximum_accepted"] = 0
            target = temp_dir / "target.json"
            self.write_json(target, target_payload)
            report = self.run_tool(DOWNGRADE, source, target, expected_code=1)
            self.assertFalse(report["compatible"])
            self.assertIn(
                "source-version-outside-target-window",
                [entry["reason"] for entry in report["incompatibilities"]],
            )

    def test_migration_checker_rejects_gap_budget_violation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-state-migration-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            source = self.generate_manifest(temp_dir / "source")
            source_payload = json.loads(source.read_text(encoding="utf-8"))
            source_payload["artifact_state"]["timeline_gap_count_total"] = 2
            self.write_json(source, source_payload)
            target = self.generate_manifest(temp_dir / "target")
            report = self.run_tool(MIGRATION, source, target, expected_code=1)
            self.assertFalse(report["compatible"])
            self.assertIn(
                "migration-gap-budget-exceeded",
                [entry["reason"] for entry in report["incompatibilities"]],
            )


if __name__ == "__main__":
    unittest.main()
