#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "operator" / "generate_standalone_operator_privilege_model.py"


class OperatorPrivilegeModelToolTests(unittest.TestCase):
    def test_generates_privilege_model(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-privilege-model-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            subprocess.run(["python3", str(SCRIPT), "--output-dir", str(temp_dir)], check=True)

            payload = json.loads(
                (temp_dir / "standalone-operator-privilege-model.json").read_text(encoding="utf-8")
            )
            markdown = (temp_dir / "standalone-operator-privilege-model.md").read_text(encoding="utf-8")
            rows = {row["call"]["name"]: row for row in payload["rows"]}
            roles = {row["name"] for row in payload["roles"]}

            self.assertEqual(payload["policy_schema_version"], 1)
            self.assertIn("observer", roles)
            self.assertIn("incident-responder", roles)
            self.assertIn("FBVBS_HOST_CALLSITE_FBVBS_PRIMARY", {row["name"] for row in payload["host_callsite_allowlist"]})
            self.assertEqual(
                rows["FBVBS_CALL_PARTITION_RECOVER"]["authorization"]["allowed_roles"],
                ["incident-responder"],
            )
            self.assertTrue(rows["FBVBS_CALL_PARTITION_RECOVER"]["authorization"]["separate_break_glass_audit"])
            self.assertIn(
                "observer",
                rows["FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY"]["authorization"]["allowed_roles"],
            )
            self.assertEqual(
                rows["FBVBS_CALL_DIAG_SET_SCALING_LIMITS"]["authorization"]["allowed_roles"],
                ["capacity-admin"],
            )
            self.assertIn("Standalone Operator Privilege Model", markdown)


if __name__ == "__main__":
    unittest.main()
