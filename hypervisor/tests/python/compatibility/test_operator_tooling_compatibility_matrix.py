#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "compatibility" / "generate_operator_tooling_compatibility_matrix.py"
)


class OperatorToolingCompatibilityMatrixTests(unittest.TestCase):
    def test_generates_json_and_markdown_matrix(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-matrix-") as temp_dir_raw:
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

            json_path = temp_dir / "operator-tooling-compatibility-matrix.json"
            md_path = temp_dir / "operator-tooling-compatibility-matrix.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")

            self.assertEqual(payload["matrix_schema_version"], 1)
            self.assertEqual(payload["schema_registry"]["management_abi_version"], 1)
            self.assertEqual(payload["schema_registry"]["health_schema_version"], 1)
            self.assertEqual(payload["deprecated_field_policy"]["policy_schema_version"], 1)
            self.assertTrue(payload["deprecated_field_policy"]["reserved_fields_must_be_zero"])
            self.assertGreaterEqual(payload["summary"]["row_count"], 10)
            self.assertIn("FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION", markdown)
            self.assertIn("FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES", markdown)
            self.assertIn("FBVBS_CALL_DIAG_SET_SCALING_LIMITS", markdown)
            self.assertIn("FBVBS_CALL_STORAGE_CREATE_POOL", markdown)
            self.assertIn("FBVBS_CALL_OCS_VCD_ATTACH", markdown)
            self.assertIn("Operator Tooling Compatibility Matrix", markdown)

            rows = {row["call"]["name"]: row for row in payload["matrix"]}
            negotiate = rows["FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION"]
            self.assertEqual(negotiate["abi_version"]["minimum"], 1)
            self.assertEqual(negotiate["abi_version"]["maximum"], 1)
            self.assertEqual(
                negotiate["command_class_flags"]["value"],
                1,
            )
            self.assertEqual(negotiate["required_capability"]["name"], "FBVBS_CAP_AUDIT_DIAG")
            self.assertEqual(negotiate["service_kind"]["name"], "SERVICE_KIND_NONE")

            partition_status = rows["FBVBS_CALL_PARTITION_GET_STATUS"]
            self.assertEqual(partition_status["schema_version"]["name"], "FBVBS_HEALTH_SCHEMA_VERSION")
            self.assertEqual(partition_status["lifecycle"]["stage"], "stable")
            self.assertEqual(partition_status["lifecycle"]["deprecated_fields"], [])
            self.assertIn("FBVBS_COMPAT_FLAG_HEALTH_SCHEMA_STABLE", [flag["name"] for flag in partition_status["compatibility_flags"]])

            ocs_attach = rows["FBVBS_CALL_OCS_VCD_ATTACH"]
            self.assertEqual(ocs_attach["service_kind"]["name"], "SERVICE_KIND_OCS")
            self.assertIn("FBVBS_COMMAND_CLASS_SERVICE", ocs_attach["command_class_flags"]["names"])

            guest_features = rows["FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES"]
            self.assertEqual(guest_features["required_capability"]["name"], "FBVBS_CAP_AUDIT_DIAG")
            self.assertEqual(guest_features["schema_version"]["name"], "FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION")

            scaling = rows["FBVBS_CALL_DIAG_SET_SCALING_LIMITS"]
            self.assertEqual(scaling["required_capability"]["name"], "FBVBS_CAP_SCALE_MANAGE")
            self.assertEqual(scaling["schema_version"]["name"], "FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION")

            create_pool = rows["FBVBS_CALL_STORAGE_CREATE_POOL"]
            self.assertEqual(create_pool["required_capability"]["name"], "FBVBS_CAP_STORAGE_MANAGE")
            self.assertEqual(create_pool["schema_version"]["name"], "FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION")


if __name__ == "__main__":
    unittest.main()
