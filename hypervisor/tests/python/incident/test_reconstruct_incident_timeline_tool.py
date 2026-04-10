#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "incident" / "reconstruct_incident_timeline.py"
)


class ReconstructIncidentTimelineToolTests(unittest.TestCase):
    def test_reconstructs_boot_scoped_timeline_and_detects_gaps(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-timeline-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            input_path = temp_dir / "audit.log"
            output_path = temp_dir / "timeline.json"
            input_path.write_text(
                "\n".join(
                    [
                        "AUDIT seq=0000000000000001 boot_hi=1122334455667788 boot_lo=99AABBCCDDEEFF00 cpu=00000003 src=00000001 sev=0002 evt=1234 len=00000003 crc=00000000 payload=AABB01",
                        "AUDIT seq=0000000000000003 boot_hi=1122334455667788 boot_lo=99AABBCCDDEEFF00 cpu=00000004 src=00000001 sev=0004 evt=1235 len=00000002 crc=00000000 payload=CAFE",
                        "AUDIT seq=41 ts=1774747065123456789 src=1 sev=2 event=6 len=8 payload=0100000000000000",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--input",
                    str(input_path),
                    "--output",
                    str(output_path),
                ],
                check=True,
            )

            timeline = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(timeline["record_count"], 3)
            self.assertEqual(len(timeline["boot_sessions"]), 2)
            self.assertTrue(timeline["sealed"])
            self.assertEqual(timeline["chain_algorithm"], "sha384-forward-chain-v1")
            self.assertEqual(
                timeline["boot_sessions"][0]["boot_id"],
                "1122334455667788:99aabbccddeeff00",
            )
            self.assertEqual(timeline["boot_sessions"][0]["gap_count"], 1)
            self.assertEqual(timeline["boot_sessions"][0]["gaps"][0]["missing_count"], 1)
            self.assertEqual(timeline["records"][0]["sequence"], 1)
            self.assertIsNone(timeline["records"][0]["previous_entry_sha384"])
            self.assertEqual(
                timeline["records"][1]["previous_entry_sha384"],
                timeline["records"][0]["entry_sha384"],
            )
            self.assertEqual(
                timeline["timeline_sha384"],
                timeline["records"][-1]["entry_sha384"],
            )
            self.assertEqual(timeline["records"][0]["event_code"], 0x1234)
            self.assertEqual(timeline["records"][0]["payload_hex"], "aabb01")
            self.assertEqual(timeline["records"][2]["boot_id"], "global")
            self.assertEqual(timeline["records"][2]["timestamp_ns"], 1774747065123456789)

    def test_requires_input(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-timeline-empty-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            output_path = temp_dir / "timeline.json"

            result = subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--output",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("at least one --input is required", result.stderr)


if __name__ == "__main__":
    unittest.main()
