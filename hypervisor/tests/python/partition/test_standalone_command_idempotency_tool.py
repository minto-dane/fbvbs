#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "partition" / "generate_standalone_command_idempotency_rules.py"
)


class StandaloneCommandIdempotencyToolTests(unittest.TestCase):
    def test_generates_rules(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-idempotency-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            subprocess.run(
                ["python3", str(SCRIPT), "--output-dir", str(temp_dir)],
                check=True,
            )

            payload = json.loads(
                (temp_dir / "standalone-command-idempotency-rules.json").read_text(
                    encoding="utf-8"
                )
            )
            markdown = (
                temp_dir / "standalone-command-idempotency-rules.md"
            ).read_text(encoding="utf-8")

            self.assertEqual(payload["rules_schema_version"], 1)
            self.assertGreaterEqual(payload["summary"]["row_count"], 8)
            self.assertIn("Standalone Command Idempotency Rules", markdown)

            rows = {row["call_macro"]: row for row in payload["rules"]}
            self.assertEqual(
                rows["FBVBS_CALL_PARTITION_RECOVER"]["idempotency_class"],
                "non-idempotent-mutation",
            )
            self.assertEqual(
                rows["FBVBS_CALL_PARTITION_QUIESCE"]["duplicate_outcome"],
                "INVALID_STATE-after-success",
            )
            self.assertEqual(
                rows["FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY"]["idempotency_class"],
                "deterministic-read",
            )


if __name__ == "__main__":
    unittest.main()
