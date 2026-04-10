#!/usr/bin/env python3

import datetime
import json
import pathlib
import subprocess
import tempfile
import unittest


GENERATE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "partition" / "generate_standalone_command_contracts.py"
VALIDATE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "partition" / "validate_partition_transition_preconditions.py"


class StandaloneCommandContractsToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_generates_command_contracts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-command-contracts-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            subprocess.run(
                ["python3", str(GENERATE), "--output-dir", str(temp_dir)],
                check=True,
            )

            payload = json.loads((temp_dir / "standalone-command-contracts.json").read_text(encoding="utf-8"))
            markdown = (temp_dir / "standalone-command-contracts.md").read_text(encoding="utf-8")
            rows = {row["call"]["name"]: row for row in payload["contracts"]}

            self.assertEqual(payload["contracts_schema_version"], 1)
            self.assertIn("FBVBS_CALL_PARTITION_RECOVER", rows)
            self.assertEqual(rows["FBVBS_CALL_PARTITION_RECOVER"]["idempotency_class"], "single-transition")
            self.assertEqual(rows["FBVBS_CALL_PARTITION_RECOVER"]["repeat_status"]["name"], "INVALID_STATE")
            self.assertEqual(rows["FBVBS_CALL_PARTITION_RECOVER"]["authorization"]["domain"], "partition")
            self.assertEqual(
                rows["FBVBS_CALL_PARTITION_RECOVER"]["authorization"]["allowed_roles"],
                ["incident-responder"],
            )
            self.assertTrue(rows["FBVBS_CALL_PARTITION_RECOVER"]["authorization"]["separate_break_glass_audit"])
            self.assertTrue(rows["FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION"]["safe_replay"])
            self.assertIn(
                "observer",
                rows["FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION"]["authorization"]["allowed_roles"],
            )
            self.assertEqual(rows["FBVBS_CALL_STORAGE_CREATE_POOL"]["idempotency_class"], "allocate-new-object")
            self.assertIn("Standalone Command Contracts", markdown)

    def test_validates_partition_transition_preconditions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-transition-validator-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            partition_list = temp_dir / "partition-list.json"
            approval = temp_dir / "approval.json"
            output = temp_dir / "result.json"

            self.write_json(
                partition_list,
                {
                    "count": 2,
                    "entries": [
                        {
                            "partition_id": 4097,
                            "state": 4,
                            "health_state": 0,
                            "fault_code": 0,
                            "quarantine_reason": 0,
                        },
                        {
                            "partition_id": 4098,
                            "state": 7,
                            "health_state": 2,
                            "fault_code": 77,
                            "quarantine_reason": 77,
                        },
                    ],
                },
            )
            expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
            approval_payload = {
                "action": "recover-approved",
                "partition_id": 4098,
                "operator_id": "alice",
                "expires_utc": expires.isoformat(),
                "latest_ack_sha384": "b" * 96,
                "timeline_root_chain_sha384": "a" * 96,
            }
            approval_payload["approval_sha384"] = __import__("hashlib").sha384(
                json.dumps(
                    approval_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            self.write_json(approval, approval_payload)

            subprocess.run(
                [
                    "python3",
                    str(VALIDATE),
                    "--partition-list",
                    str(partition_list),
                    "--action",
                    "quiesce",
                    "--partition-id",
                    "4097",
                    "--output",
                    str(output),
                ],
                check=True,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["allowed"])
            self.assertEqual(payload["predicted_status"]["name"], "OK")

            result = subprocess.run(
                [
                    "python3",
                    str(VALIDATE),
                    "--partition-list",
                    str(partition_list),
                    "--action",
                    "resume",
                    "--partition-id",
                    "4097",
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(payload["allowed"])
            self.assertEqual(payload["predicted_status"]["name"], "INVALID_STATE")

            subprocess.run(
                [
                    "python3",
                    str(VALIDATE),
                    "--partition-list",
                    str(partition_list),
                    "--action",
                    "recover",
                    "--partition-id",
                    "4098",
                    "--recovery-approval",
                    str(approval),
                    "--output",
                    str(output),
                ],
                check=True,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["allowed"])
            self.assertEqual(payload["approval_summary"]["operator_id"], "alice")

            result = subprocess.run(
                [
                    "python3",
                    str(VALIDATE),
                    "--partition-list",
                    str(partition_list),
                    "--action",
                    "recover",
                    "--partition-id",
                    "4098",
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(payload["allowed"])
            self.assertTrue(payload["approval_required"])


if __name__ == "__main__":
    unittest.main()
