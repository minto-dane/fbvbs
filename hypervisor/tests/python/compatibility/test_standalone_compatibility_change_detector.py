#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
MATRIX_SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "compatibility" / "generate_operator_tooling_compatibility_matrix.py"
)
DETECTOR_SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "compatibility" / "check_standalone_compatibility_changes.py"
)
COMMITTED_BASELINE = (
    pathlib.Path(__file__).resolve().parents[4]
    / "plan"
    / "standalone"
    / "assurance"
    / "baselines"
    / "operator-tooling-compatibility-baseline.json"
)


class StandaloneCompatibilityChangeDetectorTests(unittest.TestCase):
    def generate_matrix(self, output_dir: pathlib.Path) -> pathlib.Path:
        subprocess.run(
            [
                "python3",
                str(MATRIX_SCRIPT),
                "--output-dir",
                str(output_dir),
            ],
            cwd=REPO_ROOT,
            check=True,
        )
        return output_dir / "operator-tooling-compatibility-matrix.json"

    def run_detector(
        self,
        baseline_path: pathlib.Path,
        current_path: pathlib.Path,
        expected_returncode: int = 0,
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory(prefix="fbvbs-compat-report-") as report_dir_raw:
            report_path = pathlib.Path(report_dir_raw) / "report.json"
            result = subprocess.run(
                [
                    "python3",
                    str(DETECTOR_SCRIPT),
                    "--baseline",
                    str(baseline_path),
                    "--current",
                    str(current_path),
                    "--report",
                    str(report_path),
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, expected_returncode, msg=result.stdout + result.stderr)
            self.assertTrue(report_path.is_file())
            return json.loads(report_path.read_text(encoding="utf-8"))

    def test_detector_accepts_committed_baseline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-compat-current-") as temp_dir_raw:
            current_path = self.generate_matrix(pathlib.Path(temp_dir_raw))
            report = self.run_detector(COMMITTED_BASELINE, current_path)
            self.assertTrue(report["compatible"])
            self.assertEqual(report["summary"]["incompatible_count"], 0)

    def test_detector_rejects_removed_call(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-compat-removed-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            baseline_path = self.generate_matrix(temp_dir / "baseline")
            current_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
            current_payload["matrix"] = [
                row
                for row in current_payload["matrix"]
                if row["call"]["name"] != "FBVBS_CALL_DIAG_GET_INVENTORY"
            ]
            current_path = temp_dir / "current.json"
            current_path.write_text(json.dumps(current_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            report = self.run_detector(baseline_path, current_path, expected_returncode=1)
            self.assertFalse(report["compatible"])
            self.assertIn("call-removed", [item["reason"] for item in report["incompatibilities"]])

    def test_detector_rejects_capability_change(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-compat-cap-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            baseline_path = self.generate_matrix(temp_dir / "baseline")
            current_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
            for row in current_payload["matrix"]:
                if row["call"]["name"] == "FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION":
                    row["required_capability"]["name"] = "FBVBS_CAP_PARTITION_MANAGE"
                    break
            current_path = temp_dir / "current.json"
            current_path.write_text(json.dumps(current_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            report = self.run_detector(baseline_path, current_path, expected_returncode=1)
            self.assertFalse(report["compatible"])
            self.assertIn("field-changed", [item["reason"] for item in report["incompatibilities"]])

    def test_detector_rejects_negotiation_status_change(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-compat-negotiation-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            baseline_path = self.generate_matrix(temp_dir / "baseline")
            current_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
            for row in current_payload["matrix"]:
                if row["call"]["name"] == "FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION":
                    row["abi_version"]["negotiation_status"] = "auto"
                    break
            current_path = temp_dir / "current.json"
            current_path.write_text(json.dumps(current_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            report = self.run_detector(baseline_path, current_path, expected_returncode=1)
            self.assertFalse(report["compatible"])
            self.assertIn("abi_version.negotiation_status", [item.get("field") for item in report["incompatibilities"]])

    def test_detector_accepts_additive_schema_growth(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-compat-growth-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            baseline_path = self.generate_matrix(temp_dir / "baseline")
            current_payload = json.loads(baseline_path.read_text(encoding="utf-8"))
            current_payload["schema_registry"]["audit_schema_version"] += 1
            current_payload["matrix"][0]["schema_version"]["value"] += 1
            current_payload["matrix"][0]["abi_version"]["maximum"] += 1
            current_payload["matrix"].append(
                {
                    "category": "diagnostic",
                    "call": {"name": "FBVBS_CALL_FAKE_ADDITIVE_EXTENSION", "id": 65534, "hex": "0xFFFE"},
                    "request_type": None,
                    "response_type": "fbvbs_fake_extension_response",
                    "abi_version": {"minimum": 1, "maximum": 1, "negotiation_status": "exact"},
                    "command_class_flags": {
                        "names": ["FBVBS_COMMAND_CLASS_HOST_PARTITION"],
                        "value": 1,
                        "hex": "0x0000000000000001",
                    },
                    "service_kind": {"name": "SERVICE_KIND_NONE", "value": 0, "hex": "0x0000000000000000"},
                    "required_capability": {
                        "name": "FBVBS_CAP_AUDIT_DIAG",
                        "value": 8,
                        "hex": "0x0000000000000008",
                    },
                    "compatibility_flags": [],
                    "lifecycle": {"stage": "experimental", "deprecated_fields": []},
                    "schema_version": None,
                    "notes": ["additive call for compatibility growth"],
                }
            )
            current_path = temp_dir / "current.json"
            current_path.write_text(json.dumps(current_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            report = self.run_detector(baseline_path, current_path)
            self.assertTrue(report["compatible"])
            self.assertGreaterEqual(report["summary"]["compatible_change_count"], 3)


if __name__ == "__main__":
    unittest.main()
