#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "partition" / "validate_partition_transition_preconditions.py"
)
ISSUE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "incident" / "issue_recovery_approval.py"


class PartitionTransitionPreconditionValidatorTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def make_partition_list(self, path: pathlib.Path) -> None:
        self.write_json(
            path,
            {
                "count": 3,
                "entries": [
                    {
                        "partition_id": 4097,
                        "state": 5,
                        "health_state": 0,
                        "fault_code": 0,
                        "quarantine_reason": 0,
                    },
                    {
                        "partition_id": 4098,
                        "state": 6,
                        "health_state": 1,
                        "fault_code": 0,
                        "quarantine_reason": 0,
                    },
                    {
                        "partition_id": 4099,
                        "state": 7,
                        "health_state": 2,
                        "fault_code": 77,
                        "quarantine_reason": 77,
                    },
                ],
            },
        )

    def make_recovery_inputs(self, temp_dir: pathlib.Path) -> pathlib.Path:
        timeline = temp_dir / "timeline.json"
        severity = temp_dir / "severity.json"
        ledger = temp_dir / "ledger.json"
        approval = temp_dir / "recovery-approval.json"
        self.write_json(timeline, {"root_chain_sha384": "a" * 96})
        self.write_json(
            severity,
            {
                "partitions": [
                    {
                        "partition_id": 4099,
                        "health_state": {"name": "QUARANTINED", "value": 2},
                        "fault_code": 77,
                        "quarantine_reason": 77,
                        "severity": {"name": "ALERT", "value": 6, "source": "fault-record"},
                    }
                ]
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
        subprocess.run(
            [
                "python3",
                str(ISSUE),
                "--timeline-seal",
                str(timeline),
                "--severity-summary",
                str(severity),
                "--ack-ledger",
                str(ledger),
                "--partition-id",
                "4099",
                "--operator-id",
                "alice",
                "--reason",
                "recovery preconditions satisfied",
                "--output",
                str(approval),
            ],
            check=True,
        )
        return approval

    def test_validates_quiesce_resume_and_recover(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-transition-preconditions-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            partition_list = temp_dir / "partition-list.json"
            self.make_partition_list(partition_list)
            approval = self.make_recovery_inputs(temp_dir)

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--partition-list",
                    str(partition_list),
                    "--action",
                    "quiesce",
                    "--partition-id",
                    "4097",
                    "--output",
                    str(temp_dir / "partition-transition-quiesce-4097.json"),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--partition-list",
                    str(partition_list),
                    "--action",
                    "resume",
                    "--partition-id",
                    "4098",
                    "--output",
                    str(temp_dir / "partition-transition-resume-4098.json"),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--partition-list",
                    str(partition_list),
                    "--action",
                    "recover",
                    "--partition-id",
                    "4099",
                    "--recovery-approval",
                    str(approval),
                    "--output",
                    str(temp_dir / "partition-transition-recover-4099.json"),
                ],
                check=True,
            )

            recover_payload = json.loads(
                (temp_dir / "partition-transition-recover-4099.json").read_text(encoding="utf-8")
            )
            self.assertTrue(recover_payload["allowed"])
            self.assertEqual(recover_payload["current_state"]["name"], "FAULTED")
            self.assertEqual(recover_payload["predicted_status"]["name"], "OK")
            self.assertEqual(recover_payload["approval_summary"]["operator_id"], "alice")

    def test_rejects_invalid_state_and_missing_approval(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-transition-preconditions-reject-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            partition_list = temp_dir / "partition-list.json"
            self.make_partition_list(partition_list)

            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--partition-list",
                    str(partition_list),
                    "--action",
                    "resume",
                    "--partition-id",
                    "4097",
                    "--output",
                    str(temp_dir / "partition-transition-resume-4097.json"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)

            payload = json.loads(
                (temp_dir / "partition-transition-resume-4097.json").read_text(encoding="utf-8")
            )
            self.assertFalse(payload["allowed"])
            self.assertEqual(payload["predicted_status"]["name"], "INVALID_STATE")
            self.assertFalse(payload["checks"][1]["passed"])

            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--partition-list",
                    str(partition_list),
                    "--action",
                    "recover",
                    "--partition-id",
                    "4099",
                    "--output",
                    str(temp_dir / "partition-transition-recover-4099.json"),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(
                (temp_dir / "partition-transition-recover-4099.json").read_text(encoding="utf-8")
            )
            self.assertFalse(payload["allowed"])
            self.assertTrue(payload["approval_required"])


if __name__ == "__main__":
    unittest.main()
