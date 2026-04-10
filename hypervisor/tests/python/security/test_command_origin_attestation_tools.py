#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


ISSUE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "security" / "issue_command_origin_attestation.py"
VERIFY = pathlib.Path(__file__).resolve().parents[3] / "tools" / "security" / "verify_command_origin_attestation.py"


class CommandOriginAttestationToolTests(unittest.TestCase):
    def test_issue_and_verify_break_glass_attestation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-origin-attestation-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output = temp_dir / "origin-attestation.json"
            subprocess.run(
                [
                    "python3",
                    str(ISSUE),
                    "--call",
                    "FBVBS_CALL_PARTITION_RECOVER",
                    "--operator-id",
                    "alice",
                    "--operator-role",
                    "incident-responder",
                    "--session-correlation-id",
                    "sess-origin-001",
                    "--origin-transport",
                    "ocs-vcd",
                    "--origin-console",
                    "mainframe-tui",
                    "--host-callsite",
                    "FBVBS_HOST_CALLSITE_FBVBS_PRIMARY",
                    "--partition-id",
                    "4097",
                    "--timeline-root-sha384",
                    "a" * 96,
                    "--break-glass",
                    "--justification",
                    "sev1-failover",
                    "--output",
                    str(output),
                ],
                check=True,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["origin_attestation_schema_version"], 1)
            self.assertEqual(payload["operator_role"], "incident-responder")
            self.assertTrue(payload["command_context"]["break_glass"])
            self.assertEqual(payload["authorization"]["domain"], "partition")

            subprocess.run(
                [
                    "python3",
                    str(VERIFY),
                    "--input",
                    str(output),
                    "--call",
                    "FBVBS_CALL_PARTITION_RECOVER",
                    "--operator-role",
                    "incident-responder",
                    "--session-correlation-id",
                    "sess-origin-001",
                    "--timeline-root-sha384",
                    "a" * 96,
                ],
                check=True,
            )

    def test_issue_rejects_unauthorized_role(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-origin-attestation-fail-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output = temp_dir / "origin-attestation.json"
            result = subprocess.run(
                [
                    "python3",
                    str(ISSUE),
                    "--call",
                    "FBVBS_CALL_PARTITION_RECOVER",
                    "--operator-id",
                    "alice",
                    "--operator-role",
                    "observer",
                    "--session-correlation-id",
                    "sess-origin-002",
                    "--origin-transport",
                    "ocs-vcd",
                    "--origin-console",
                    "mainframe-tui",
                    "--host-callsite",
                    "FBVBS_HOST_CALLSITE_FBVBS_PRIMARY",
                    "--partition-id",
                    "4097",
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("not authorized", result.stderr)


if __name__ == "__main__":
    unittest.main()
