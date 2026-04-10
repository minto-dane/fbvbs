#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


STALE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "partition" / "detect_stale_mappings.py"
TEARDOWN = pathlib.Path(__file__).resolve().parents[3] / "tools" / "partition" / "validate_teardown_postconditions.py"
FAULT_MATRIX = pathlib.Path(__file__).resolve().parents[3] / "tools" / "partition" / "generate_fault_escalation_matrix.py"
HEALTH_SCORE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "partition" / "score_partition_health.py"
QUOTA_DRIFT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "partition" / "detect_quota_drift.py"


class BoundaryAndCapacityToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_detects_stale_mapping(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-stale-map-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            input_path = temp_dir / "mappings.json"
            output = temp_dir / "report.json"
            self.write_json(
                input_path,
                {
                    "partitions": [
                        {"partition_id": 1, "occupied": True, "state_name": "RUNNABLE"},
                        {"partition_id": 2, "occupied": False, "state_name": "DESTROYED"},
                    ],
                    "memory_mappings": [
                        {"mapping_id": 10, "owner_partition_id": 1, "target_partition_id": 2, "active": True, "revoked": False},
                    ],
                },
            )
            result = subprocess.run(["python3", str(STALE), "--input", str(input_path), "--output", str(output)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["stale_mapping_count"], 1)

    def test_validates_teardown_postconditions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-teardown-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            input_path = temp_dir / "teardown.json"
            output = temp_dir / "report.json"
            self.write_json(
                input_path,
                {
                    "memory_objects": [{"object_id": 1, "owner_partition_id": 99}],
                    "shared_objects": [],
                    "memory_mappings": [],
                    "attached_vdisks": [],
                },
            )
            result = subprocess.run(
                ["python3", str(TEARDOWN), "--input", str(input_path), "--partition-id", "99", "--output", str(output)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(payload["allowed"])
            self.assertEqual(payload["violation_count"], 1)

    def test_generates_fault_escalation_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-fault-matrix-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            subprocess.run(["python3", str(FAULT_MATRIX), "--output-dir", str(temp_dir)], check=True)
            payload = json.loads((temp_dir / "fault-escalation-matrix.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["matrix_schema_version"], 1)
            self.assertTrue(any(row["containment_policy"] == "quarantine" for row in payload["rows"]))

    def test_scores_partition_health(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-health-score-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            input_path = temp_dir / "summary.json"
            output = temp_dir / "score.json"
            self.write_json(
                input_path,
                {
                    "partitions": [
                        {
                            "partition_id": 7,
                            "health_state": {"name": "DEGRADED"},
                            "severity": {"name": "WARNING"},
                            "policy_deny_count": 2,
                            "lockout_windows": 1,
                            "fault_code": 77,
                            "quarantine_reason": 0,
                        }
                    ]
                },
            )
            subprocess.run(["python3", str(HEALTH_SCORE), "--input", str(input_path), "--output", str(output)], check=True)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["rows"][0]["partition_id"], 7)
            self.assertEqual(payload["rows"][0]["band"], "AT_RISK")

    def test_detects_quota_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-quota-drift-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            limits = temp_dir / "limits.json"
            usage = temp_dir / "usage.json"
            output = temp_dir / "report.json"
            self.write_json(limits, {"runtime_max_vm_count": 4, "runtime_max_vcpus_per_vm": 8, "runtime_max_vdisks_per_vm": 16, "runtime_max_vdisk_size_bytes": 1024})
            self.write_json(usage, {"current_vm_count": 5, "max_vcpus_per_vm_observed": 6, "max_vdisks_per_vm_observed": 20, "max_vdisk_size_observed_bytes": 512})
            result = subprocess.run(["python3", str(QUOTA_DRIFT), "--limits", str(limits), "--usage", str(usage), "--output", str(output)], capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["noncompliant_count"], 2)


if __name__ == "__main__":
    unittest.main()
