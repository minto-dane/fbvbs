#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


TIMELINE_SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "incident" / "reconstruct_incident_timeline.py"
)
ACK_SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "incident" / "record_operator_acknowledgment.py"
)


class OperatorAcknowledgmentToolTests(unittest.TestCase):
    def test_appends_chained_acknowledgments(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-ack-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            audit_log = temp_dir / "audit.log"
            timeline = temp_dir / "timeline.json"
            severity_summary = temp_dir / "severity.json"
            ack_log = temp_dir / "ack-log.json"
            audit_log.write_text(
                "AUDIT seq=1 ts=1774747065123456789 src=1 sev=2 event=6 len=8 payload=0100000000000000\n",
                encoding="utf-8",
            )
            severity_summary.write_text(
                json.dumps(
                    {
                        "overall_severity": {
                            "name": "WARNING",
                            "value": 3,
                        }
                    },
                    indent=2,
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )

            subprocess.run(
                [
                    "python3",
                    str(TIMELINE_SCRIPT),
                    "--input",
                    str(audit_log),
                    "--output",
                    str(timeline),
                ],
                check=True,
            )

            subprocess.run(
                [
                    "python3",
                    str(ACK_SCRIPT),
                    "--timeline-seal",
                    str(timeline),
                    "--severity-summary",
                    str(severity_summary),
                    "--operator-id",
                    "ops@example",
                    "--session-correlation-id",
                    "sess-001",
                    "--action",
                    "triage-complete",
                    "--note",
                    "triaged degraded partition",
                    "--output",
                    str(ack_log),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(ACK_SCRIPT),
                    "--timeline-seal",
                    str(timeline),
                    "--severity-summary",
                    str(severity_summary),
                    "--operator-id",
                    "ops@example",
                    "--session-correlation-id",
                    "sess-001",
                    "--action",
                    "review-complete",
                    "--note",
                    "follow-up review complete",
                    "--previous-ledger",
                    str(ack_log),
                    "--output",
                    str(ack_log),
                ],
                check=True,
            )

            payload = json.loads(ack_log.read_text(encoding="utf-8"))
            self.assertEqual(payload["ledger_schema_version"], 1)
            self.assertEqual(payload["acknowledgment_count"], 2)
            self.assertEqual(payload["session_correlation_id"], "sess-001")
            self.assertEqual(len(payload["acknowledgments"]), 2)
            self.assertEqual(payload["timeline_root_chain_sha384"], json.loads(timeline.read_text(encoding="utf-8"))["root_chain_sha384"])
            self.assertEqual(payload["acknowledgments"][0]["previous_ack_sha384"], "0" * 96)
            self.assertEqual(
                payload["acknowledgments"][1]["previous_ack_sha384"],
                payload["acknowledgments"][0]["ack_sha384"],
            )
            self.assertEqual(payload["acknowledgments"][0]["session_correlation_id"], "sess-001")
            self.assertEqual(payload["latest_ack_sha384"], payload["acknowledgments"][1]["ack_sha384"])


if __name__ == "__main__":
    unittest.main()
