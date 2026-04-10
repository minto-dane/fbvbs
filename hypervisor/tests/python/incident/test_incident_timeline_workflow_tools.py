#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


RECONSTRUCT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "incident" / "reconstruct_incident_timeline.py"
SEAL = pathlib.Path(__file__).resolve().parents[3] / "tools" / "incident" / "seal_incident_timeline.py"
VERIFY = pathlib.Path(__file__).resolve().parents[3] / "tools" / "incident" / "verify_incident_timeline.py"
ACK = pathlib.Path(__file__).resolve().parents[3] / "tools" / "incident" / "record_operator_acknowledgment.py"


class IncidentTimelineWorkflowToolTests(unittest.TestCase):
    def test_seal_and_verify_timeline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-seal-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            log_path = temp_dir / "audit.log"
            timeline_path = temp_dir / "timeline.json"
            sealed_path = temp_dir / "timeline-sealed.json"
            log_path.write_text(
                "\n".join(
                    [
                        "AUDIT seq=1 ts=10 event=20 payload=aa",
                        "AUDIT seq=2 ts=11 event=21 payload=bb",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            subprocess.run(
                [
                    "python3",
                    str(RECONSTRUCT),
                    "--input",
                    str(log_path),
                    "--output",
                    str(timeline_path),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(SEAL),
                    "--input",
                    str(timeline_path),
                    "--output",
                    str(sealed_path),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(VERIFY),
                    "--input",
                    str(sealed_path),
                ],
                check=True,
            )

            sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
            self.assertEqual(sealed["record_count"], 2)
            self.assertEqual(len(sealed["record_chain"]), 2)
            self.assertNotEqual(sealed["root_chain_sha384"], "0" * 96)

    def test_operator_acknowledgment_ledger_chains_entries(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-ack-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            sealed_path = temp_dir / "timeline-sealed.json"
            severity_path = temp_dir / "severity.json"
            ledger0_path = temp_dir / "ack-ledger-0.json"
            ledger1_path = temp_dir / "ack-ledger-1.json"

            sealed_path.write_text(
                json.dumps(
                    {
                        "root_chain_sha384": "a" * 96,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            severity_path.write_text(
                json.dumps(
                    {
                        "overall_severity": {
                            "name": "ALERT",
                        }
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )

            subprocess.run(
                [
                    "python3",
                    str(ACK),
                    "--timeline-seal",
                    str(sealed_path),
                    "--severity-summary",
                    str(severity_path),
                    "--operator-id",
                    "alice",
                    "--session-correlation-id",
                    "sess-001",
                    "--action",
                    "acknowledge",
                    "--note",
                    "triaged",
                    "--output",
                    str(ledger0_path),
                ],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(ACK),
                    "--timeline-seal",
                    str(sealed_path),
                    "--severity-summary",
                    str(severity_path),
                    "--operator-id",
                    "bob",
                    "--session-correlation-id",
                    "sess-001",
                    "--action",
                    "recover-approved",
                    "--previous-ledger",
                    str(ledger0_path),
                    "--output",
                    str(ledger1_path),
                ],
                check=True,
            )

            ledger = json.loads(ledger1_path.read_text(encoding="utf-8"))
            self.assertEqual(ledger["acknowledgment_count"], 2)
            self.assertEqual(ledger["session_correlation_id"], "sess-001")
            self.assertEqual(ledger["acknowledgments"][0]["operator_id"], "alice")
            self.assertEqual(ledger["acknowledgments"][1]["operator_id"], "bob")
            self.assertEqual(
                ledger["acknowledgments"][1]["previous_ack_sha384"],
                ledger["acknowledgments"][0]["ack_sha384"],
            )
            self.assertEqual(ledger["timeline_root_chain_sha384"], "a" * 96)


if __name__ == "__main__":
    unittest.main()
