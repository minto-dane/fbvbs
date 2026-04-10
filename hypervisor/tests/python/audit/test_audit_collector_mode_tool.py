#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "audit" / "evaluate_audit_collector_mode.py"


class AuditCollectorModeToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_halts_when_collector_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-collector-halt-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            status = temp_dir / "status.json"
            output = temp_dir / "report.json"
            self.write_json(
                status,
                {
                    "collector_present": False,
                    "heartbeat_ok": False,
                    "spool_usage_pct": 10,
                    "framing_error_count": 0,
                    "dropped_bytes": 0,
                },
            )
            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--status",
                    str(status),
                    "--output",
                    str(output),
                ],
                check=True,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["mode"], "HALT_NEW_MUTATIONS")
            self.assertIn("collector absent", payload["reasons"])
            self.assertTrue(payload["fail_closed"])

    def test_enters_degraded_backpressure_when_spool_high(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-collector-degraded-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            status = temp_dir / "status.json"
            output = temp_dir / "report.json"
            self.write_json(
                status,
                {
                    "collector_present": True,
                    "heartbeat_ok": True,
                    "spool_usage_pct": 85,
                    "framing_error_count": 1,
                    "dropped_bytes": 0,
                },
            )
            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--status",
                    str(status),
                    "--output",
                    str(output),
                ],
                check=True,
            )
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["mode"], "DEGRADED_BACKPRESSURE")
            self.assertIn("spool usage reached high watermark", payload["reasons"])
            self.assertIn("drain-existing-workload", payload["allowed_actions"])


if __name__ == "__main__":
    unittest.main()
