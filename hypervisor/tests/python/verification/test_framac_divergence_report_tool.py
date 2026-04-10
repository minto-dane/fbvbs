#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "verification" / "generate_framac_divergence_report.py"


class FramacDivergenceReportToolTests(unittest.TestCase):
    def test_generates_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-framac-report-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            subprocess.run(["python3", str(SCRIPT), "--output-dir", str(temp_dir)], check=True)

            payload = json.loads((temp_dir / "framac-divergence-report.json").read_text(encoding="utf-8"))
            markdown = (temp_dir / "framac-divergence-report.md").read_text(encoding="utf-8")

            self.assertEqual(payload["report_schema_version"], 1)
            self.assertGreater(payload["summary"]["total_blocks"], 0)
            self.assertIn("acceptable-stub", payload["summary"]["divergence_class_counts"])
            self.assertIn("Frama-C Divergence Report", markdown)


if __name__ == "__main__":
    unittest.main()
