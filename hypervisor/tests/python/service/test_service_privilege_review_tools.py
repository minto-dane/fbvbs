#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


GENERATE = pathlib.Path(__file__).resolve().parents[3] / "tools" / "service" / "generate_service_privilege_review.py"
DETECT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "service" / "detect_unused_service_capabilities.py"


class ServicePrivilegeReviewToolTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_generates_review(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-service-review-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            subprocess.run(["python3", str(GENERATE), "--output-dir", str(temp_dir)], check=True)
            payload = json.loads((temp_dir / "service-privilege-review.json").read_text(encoding="utf-8"))
            markdown = (temp_dir / "service-privilege-review.md").read_text(encoding="utf-8")
            rows = {row["service_kind"]["name"]: row for row in payload["service_roles"]}

            self.assertEqual(payload["review_schema_version"], 1)
            self.assertEqual(rows["SERVICE_KIND_OCS"]["role_name"], "ocs-console")
            self.assertEqual(
                rows["SERVICE_KIND_OCS"]["required_capabilities"][0]["name"],
                "FBVBS_CAP_OCS_ACCESS",
            )
            self.assertIn("Service Privilege Review", markdown)

    def test_detects_unused_capabilities(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-service-cap-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            assignment = temp_dir / "service-assignment.json"
            output = temp_dir / "report.json"
            self.write_json(
                assignment,
                {
                    "services": [
                        {
                            "partition_id": 5001,
                            "service_kind": "SERVICE_KIND_OCS",
                            "capability_mask": (1 << 13) | (1 << 11),
                        }
                    ]
                },
            )
            result = subprocess.run(
                ["python3", str(DETECT), "--input", str(assignment), "--output", str(output)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["noncompliant_count"], 1)
            self.assertEqual(
                payload["findings"][0]["unused_capability_mask"]["names"],
                ["FBVBS_CAP_STORAGE_MANAGE"],
            )


if __name__ == "__main__":
    unittest.main()
