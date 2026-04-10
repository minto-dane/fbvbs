#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).resolve().parents[3] / "tools" / "operator" / "generate_management_rate_limit_policy.py"


class ManagementRateLimitPolicyToolTests(unittest.TestCase):
    def test_generates_policy(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-rate-policy-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            subprocess.run(["python3", str(SCRIPT), "--output-dir", str(temp_dir)], check=True)

            payload = json.loads(
                (temp_dir / "standalone-management-rate-limit-policy.json").read_text(encoding="utf-8")
            )
            markdown = (temp_dir / "standalone-management-rate-limit-policy.md").read_text(encoding="utf-8")

            self.assertEqual(payload["policy_schema_version"], 1)
            self.assertEqual(payload["window_policy"]["window_calls"], 128)
            self.assertEqual(payload["window_policy"]["max_calls_per_window"], 64)
            self.assertEqual(payload["window_policy"]["lockout_windows"], 4)
            self.assertIn("Standalone Management Command Rate Limit Policy", markdown)

            rows = {row["call"]["name"]: row for row in payload["rows"]}
            self.assertEqual(rows["FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION"]["retry_status"]["name"], "RETRY_LATER")
            self.assertTrue(rows["FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY"]["safe_replay"])
            self.assertFalse(rows["FBVBS_CALL_STORAGE_CREATE_POOL"]["safe_replay"])


if __name__ == "__main__":
    unittest.main()
