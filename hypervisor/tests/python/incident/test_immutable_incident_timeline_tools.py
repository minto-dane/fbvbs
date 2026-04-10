#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


RECONSTRUCT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "incident" / "reconstruct_incident_timeline.py"
)
SEAL = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "incident" / "seal_incident_timeline.py"
)
ACK = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "incident" / "acknowledge_incident_timeline.py"
)


class ImmutableIncidentTimelineToolTests(unittest.TestCase):
    def test_seals_timeline_and_generates_ack(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-incident-seal-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            audit_path = temp_dir / "audit.log"
            timeline_path = temp_dir / "timeline.json"
            sealed_path = temp_dir / "timeline-sealed.json"
            ack_path = temp_dir / "timeline-ack.json"

            audit_path.write_text(
                "\n".join(
                    [
                        "AUDIT seq=1 ts=1774747065123456789 src=1 sev=3 event=6 len=4 payload=01020304",
                        "AUDIT seq=2 ts=1774747065123456790 src=1 sev=4 event=7 len=4 payload=05060708",
                    ]
                ) + "\n",
                encoding="utf-8",
            )

            subprocess.run(
                ["python3", str(RECONSTRUCT), "--input", str(audit_path), "--output", str(timeline_path)],
                check=True,
            )
            subprocess.run(
                ["python3", str(SEAL), "--input", str(timeline_path), "--output", str(sealed_path)],
                check=True,
            )
            subprocess.run(
                [
                    "python3",
                    str(ACK),
                    "--timeline",
                    str(sealed_path),
                    "--operator-id",
                    "ops@example.test",
                    "--session-correlation-id",
                    "sess-immutable-001",
                    "--acknowledgment-id",
                    "ack-001",
                    "--decision",
                    "triaged",
                    "--note",
                    "reviewed",
                    "--output",
                    str(ack_path),
                ],
                check=True,
            )

            sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
            ack = json.loads(ack_path.read_text(encoding="utf-8"))
            self.assertEqual(sealed["immutability"]["record_count"], 2)
            self.assertEqual(sealed["record_chain"][0]["previous_chain_sha384"], "0" * 96)
            self.assertEqual(
                ack["timeline_root_sha384"],
                sealed["immutability"]["timeline_root_sha384"],
            )
            self.assertEqual(ack["operator_id"], "ops@example.test")
            self.assertEqual(ack["session_correlation_id"], "sess-immutable-001")

    def test_rejects_tampered_sealed_timeline(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-incident-tamper-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            sealed_path = temp_dir / "timeline-sealed.json"
            ack_path = temp_dir / "timeline-ack.json"
            sealed_path.write_text(
                json.dumps(
                    {
                        "record_count": 1,
                        "boot_sessions": [],
                        "records": [
                            {
                                "sequence": 1,
                                "payload_hex": "aa",
                                "previous_record_sha384": "0" * 96,
                                "record_sha384": "1" * 96,
                            }
                        ],
                        "record_chain": [
                            {
                                "index": 0,
                                "sequence": 1,
                                "boot_id": "global",
                                "record_sha384": "1" * 96,
                                "previous_chain_sha384": "0" * 96,
                                "chain_sha384": "3" * 96,
                            }
                        ],
                        "root_chain_sha384": "2" * 96,
                        "immutability": {
                            "timeline_root_sha384": "2" * 96,
                        },
                    },
                    indent=2,
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    "python3",
                    str(ACK),
                    "--timeline",
                    str(sealed_path),
                    "--operator-id",
                    "ops@example.test",
                    "--session-correlation-id",
                    "sess-immutable-002",
                    "--acknowledgment-id",
                    "ack-002",
                    "--decision",
                    "triaged",
                    "--output",
                    str(ack_path),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("record_sha384 mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
