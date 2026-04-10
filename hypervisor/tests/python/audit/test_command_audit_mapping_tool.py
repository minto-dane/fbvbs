#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "audit" / "generate_command_audit_mapping.py"


class CommandAuditMappingToolTests(unittest.TestCase):
    def test_generates_mapping(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-command-audit-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output-dir",
                    str(temp_dir),
                ],
                check=True,
            )

            json_path = temp_dir / "command-audit-mapping.json"
            md_path = temp_dir / "command-audit-mapping.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")
            self.assertEqual(payload["mapping_schema_version"], 1)
            self.assertGreaterEqual(payload["summary"]["row_count"], 10)
            self.assertIn("FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES", markdown)

            rows = {row["call"]["name"]: row for row in payload["rows"]}
            guest_features = rows["FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES"]
            self.assertIn(
                "FBVBS_EVENT_POLICY_DENY",
                [event["name"] for event in guest_features["audit_events"]],
            )
            assign_device = rows["FBVBS_CALL_VM_ASSIGN_DEVICE"]
            self.assertIn(
                "FBVBS_EVENT_VM_DEVICE_ASSIGN",
                [event["name"] for event in assign_device["audit_events"]],
            )
            self.assertIn(
                "FBVBS_EVENT_VM_PLATFORM_GATE",
                [event["name"] for event in assign_device["audit_events"]],
            )


if __name__ == "__main__":
    unittest.main()
