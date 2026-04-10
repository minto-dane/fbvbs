#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


ISSUE_ORIGIN = pathlib.Path(__file__).resolve().parents[3] / "tools" / "security" / "issue_command_origin_attestation.py"
RECORD = pathlib.Path(__file__).resolve().parents[3] / "tools" / "audit" / "record_break_glass_audit.py"
VERIFY = pathlib.Path(__file__).resolve().parents[3] / "tools" / "audit" / "verify_break_glass_audit.py"


class BreakGlassAuditToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_record_and_verify_break_glass_ledger(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-break-glass-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            origin = temp_dir / "origin-attestation.json"
            timeline = temp_dir / "timeline.json"
            severity = temp_dir / "severity.json"
            ack = temp_dir / "ack-ledger.json"
            ledger = temp_dir / "break-glass-ledger.json"

            self.write_json(
                timeline,
                {
                    "root_chain_sha384": "a" * 96,
                    "record_count": 2,
                    "boot_sessions": [{"boot_id": "boot0", "record_count": 2, "gap_count": 0}],
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
                            "severity": {"name": "ALERT", "value": 6},
                        }
                    ],
                },
            )
            self.write_json(
                ack,
                {
                    "timeline_root_chain_sha384": "a" * 96,
                    "session_correlation_id": "sess-break-001",
                    "acknowledgment_count": 1,
                    "latest_ack_sha384": "b" * 96,
                    "acknowledgments": [
                        {
                            "ack_sequence": 1,
                            "operator_id": "alice",
                            "session_correlation_id": "sess-break-001",
                            "ack_sha384": "b" * 96,
                        }
                    ],
                },
            )
            subprocess.run(
                [
                    "python3",
                    str(ISSUE_ORIGIN),
                    "--call",
                    "FBVBS_CALL_PARTITION_RECOVER",
                    "--operator-id",
                    "alice",
                    "--operator-role",
                    "incident-responder",
                    "--session-correlation-id",
                    "sess-break-001",
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
                    "sev1-restore",
                    "--output",
                    str(origin),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(RECORD),
                    "--origin-attestation",
                    str(origin),
                    "--timeline-seal",
                    str(timeline),
                    "--severity-summary",
                    str(severity),
                    "--ack-ledger",
                    str(ack),
                    "--ticket-id",
                    "INC-9001",
                    "--operator-id",
                    "alice",
                    "--output",
                    str(ledger),
                ],
                check=True,
            )

            payload = json.loads(ledger.read_text(encoding="utf-8"))
            self.assertEqual(payload["audit_channel"], "operator-break-glass")
            self.assertEqual(payload["break_glass_count"], 1)
            self.assertEqual(payload["session_correlation_id"], "sess-break-001")
            self.assertEqual(
                payload["break_glass_events"][0]["audit_event"],
                "FBVBS_EVENT_OPERATOR_BREAK_GLASS",
            )

            subprocess.run(
                [
                    "python3",
                    str(VERIFY),
                    "--input",
                    str(ledger),
                    "--timeline-root-sha384",
                    "a" * 96,
                    "--session-correlation-id",
                    "sess-break-001",
                ],
                check=True,
            )


if __name__ == "__main__":
    unittest.main()
