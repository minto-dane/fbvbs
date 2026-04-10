#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "compatibility" / "check_standalone_reserved_fields.py"
)


class StandaloneReservedFieldCheckerTests(unittest.TestCase):
    def test_generates_reserved_field_report(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-reserved-fields-") as temp_dir_raw:
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

            json_path = temp_dir / "standalone-reserved-field-report.json"
            md_path = temp_dir / "standalone-reserved-field-report.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")

            self.assertEqual(payload["report_schema_version"], 1)
            self.assertEqual(payload["summary"]["failure_count"], 0)
            self.assertGreaterEqual(payload["summary"]["target_count"], 5)
            self.assertIn("Standalone Reserved Field Enforcement Report", markdown)

            rows = {row["request_type"]: row for row in payload["rows"]}

            command_page = rows["fbvbs_command_page_v1"]
            self.assertTrue(command_page["runtime_enforced"])
            self.assertIn("reserved0", command_page["reserved_fields"])

            guest_features = rows["fbvbs_diag_guest_feature_request"]
            self.assertEqual(
                guest_features["call_rows"],
                ["FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES"],
            )
            self.assertTrue(guest_features["compatibility_flag_present"])
            self.assertTrue(guest_features["runtime_enforced"])

            scaling = rows["fbvbs_diag_set_scaling_limits_request"]
            self.assertIn("FBVBS_CALL_DIAG_SET_SCALING_LIMITS", scaling["call_rows"])
            self.assertTrue(scaling["runtime_enforced"])


if __name__ == "__main__":
    unittest.main()
