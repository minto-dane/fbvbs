#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


ISSUE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "incident" / "issue_recovery_approval.py"
VERIFY = pathlib.Path(__file__).resolve().parents[3] / "tools" / "incident" / "verify_recovery_approval.py"


class RecoveryApprovalToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def make_inputs(self, temp_dir: pathlib.Path) -> dict[str, pathlib.Path]:
        timeline = temp_dir / "timeline.json"
        severity = temp_dir / "severity.json"
        ledger = temp_dir / "ledger.json"
        self.write_json(
            timeline,
            {
                "root_chain_sha384": "a" * 96,
            },
        )
        self.write_json(
            severity,
            {
                "overall_severity": {"name": "ALERT", "value": 6},
                "partitions": [
                    {
                        "partition_id": 4097,
                        "health_state": {"name": "QUARANTINED", "value": 2},
                        "fault_code": 77,
                        "quarantine_reason": 77,
                        "severity": {"name": "ALERT", "value": 6, "source": "fault-record"},
                    }
                ],
            },
        )
        self.write_json(
            ledger,
            {
                "timeline_root_chain_sha384": "a" * 96,
                "session_correlation_id": "sess-001",
                "acknowledgment_count": 1,
                "latest_ack_sha384": "b" * 96,
            },
        )
        return {"timeline": timeline, "severity": severity, "ledger": ledger}

    def test_issue_and_verify_recovery_approval(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-recovery-approval-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            inputs = self.make_inputs(temp_dir)
            output = temp_dir / "recovery-approval.json"

            subprocess.run(
                [
                    "python3",
                    str(ISSUE),
                    "--timeline-seal",
                    str(inputs["timeline"]),
                    "--severity-summary",
                    str(inputs["severity"]),
                    "--ack-ledger",
                    str(inputs["ledger"]),
                    "--partition-id",
                    "4097",
                    "--operator-id",
                    "alice",
                    "--reason",
                    "runbook completed and diagnostics stable",
                    "--output",
                    str(output),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(VERIFY),
                    "--input",
                    str(output),
                ],
                check=True,
            )

            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["action"], "recover-approved")
            self.assertEqual(payload["partition_id"], 4097)
            self.assertEqual(payload["latest_ack_sha384"], "b" * 96)
            self.assertEqual(payload["session_correlation_id"], "sess-001")

    def test_rejects_healthy_partition_and_mismatched_ledger(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-recovery-reject-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            inputs = self.make_inputs(temp_dir)
            output = temp_dir / "recovery-approval.json"

            severity = json.loads(inputs["severity"].read_text(encoding="utf-8"))
            severity["partitions"][0]["health_state"]["name"] = "HEALTHY"
            inputs["severity"].write_text(
                json.dumps(severity, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )

            result = subprocess.run(
                [
                    "python3",
                    str(ISSUE),
                    "--timeline-seal",
                    str(inputs["timeline"]),
                    "--severity-summary",
                    str(inputs["severity"]),
                    "--ack-ledger",
                    str(inputs["ledger"]),
                    "--partition-id",
                    "4097",
                    "--operator-id",
                    "alice",
                    "--reason",
                    "should fail",
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("non-healthy", result.stderr)

            severity["partitions"][0]["health_state"]["name"] = "QUARANTINED"
            inputs["severity"].write_text(
                json.dumps(severity, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            ledger = json.loads(inputs["ledger"].read_text(encoding="utf-8"))
            ledger["timeline_root_chain_sha384"] = "c" * 96
            inputs["ledger"].write_text(
                json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )

            result = subprocess.run(
                [
                    "python3",
                    str(ISSUE),
                    "--timeline-seal",
                    str(inputs["timeline"]),
                    "--severity-summary",
                    str(inputs["severity"]),
                    "--ack-ledger",
                    str(inputs["ledger"]),
                    "--partition-id",
                    "4097",
                    "--operator-id",
                    "alice",
                    "--reason",
                    "should also fail",
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not match timeline root", result.stderr)


if __name__ == "__main__":
    unittest.main()
