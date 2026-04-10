#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "operator" / "generate_operator_console_severity_summary.py"
)


class OperatorConsoleSeveritySummaryTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def test_generates_ordered_summary_and_display_rules(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-severity-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            inventory = temp_dir / "inventory.json"
            partition_list = temp_dir / "partition-list.json"
            guidance = temp_dir / "guidance.json"
            fault = temp_dir / "fault.json"

            self.write_json(
                inventory,
                {
                    "occupied_partition_count": 3,
                    "quarantined_partition_count": 1,
                    "recovery_partition_count": 1,
                },
            )
            self.write_json(
                partition_list,
                {
                    "count": 3,
                    "entries": [
                        {
                            "partition_id": 4097,
                            "health_state": 2,
                            "fault_code": 77,
                            "quarantine_reason": 77,
                        },
                        {
                            "partition_id": 4098,
                            "health_state": 1,
                            "fault_code": 0,
                            "quarantine_reason": 0,
                        },
                        {
                            "partition_id": 4099,
                            "health_state": 3,
                            "fault_code": 0,
                            "quarantine_reason": 0,
                        },
                    ],
                },
            )
            self.write_json(
                guidance,
                {
                    "partition_id": 4098,
                    "reason_domain": 4,
                    "severity": 3,
                    "runbook_code": 7,
                },
            )
            self.write_json(
                fault,
                {
                    "partition_id": 4097,
                    "severity": 6,
                    "fault_code": 77,
                },
            )

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--inventory",
                    str(inventory),
                    "--partition-list",
                    str(partition_list),
                    "--guidance",
                    str(guidance),
                    "--fault-record",
                    str(fault),
                    "--output-dir",
                    str(temp_dir),
                ],
                check=True,
            )

            json_path = temp_dir / "operator-console-severity-summary.json"
            md_path = temp_dir / "operator-console-severity-summary.md"
            ispf_path = temp_dir / "operator-console-ispf.txt"
            ispf_primary_path = temp_dir / "operator-console-ispf-primary.txt"
            ispf_list_path = temp_dir / "operator-console-ispf-partition-list.txt"
            ispf_detail_path = temp_dir / "operator-console-ispf-partition-detail-4097.txt"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())
            self.assertTrue(ispf_path.is_file())
            self.assertTrue(ispf_primary_path.is_file())
            self.assertTrue(ispf_list_path.is_file())
            self.assertTrue(ispf_detail_path.is_file())

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")
            ispf_panel = ispf_path.read_text(encoding="utf-8")
            ispf_primary = ispf_primary_path.read_text(encoding="utf-8")
            ispf_list = ispf_list_path.read_text(encoding="utf-8")
            ispf_detail = ispf_detail_path.read_text(encoding="utf-8")

            self.assertEqual(payload["summary_schema_version"], 1)
            self.assertEqual(payload["presentation_locale"], "en")
            self.assertEqual(payload["overall_severity"]["name"], "ALERT")
            self.assertEqual(payload["display_rules"]["banner"], "sticky-incident")
            self.assertEqual(payload["partitions"][0]["partition_id"], 4097)
            self.assertEqual(payload["partitions"][0]["severity"]["source"], "fault-record")
            self.assertEqual(payload["partitions"][1]["partition_id"], 4098)
            self.assertEqual(payload["partitions"][1]["severity"]["source"], "guidance")
            self.assertEqual(payload["partitions"][2]["severity"]["name"], "NOTICE")
            self.assertEqual(payload["severity_counts"]["ALERT"], 1)
            self.assertEqual(payload["severity_counts"]["WARNING"], 1)
            self.assertEqual(payload["severity_counts"]["NOTICE"], 1)
            self.assertIn("Operator Console Severity Summary", markdown)
            self.assertIn("4097", markdown)
            self.assertIn("FBVBS STANDALONE OPERATOR CONSOLE", ispf_panel)
            self.assertIn("PF5=REFRESH", ispf_panel)
            self.assertIn("QUIESCE <ID>", ispf_panel)
            self.assertIn("4097", ispf_panel)
            self.assertIn("Option ===>", ispf_primary)
            self.assertIn("Select an option or enter =2", ispf_primary)
            self.assertIn("1  System summary", ispf_primary)
            self.assertIn("Command ===>", ispf_list)
            self.assertIn("Scroll ===> PAGE", ispf_list)
            self.assertIn("Line commands: S=detail", ispf_list)
            self.assertIn("PARTITION LIST", ispf_list)
            self.assertIn("PARTITION DETAIL 4097", ispf_detail)
            self.assertIn("Runbook: none", ispf_detail)
            self.assertIn("Suggested action: immediate-security-escalation", ispf_detail)

    def test_generates_japanese_presentations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-severity-ja-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            inventory = temp_dir / "inventory.json"
            partition_list = temp_dir / "partition-list.json"

            self.write_json(
                inventory,
                {
                    "occupied_partition_count": 1,
                    "quarantined_partition_count": 1,
                    "recovery_partition_count": 0,
                },
            )
            self.write_json(
                partition_list,
                {
                    "count": 1,
                    "entries": [
                        {
                            "partition_id": 8193,
                            "health_state": 2,
                            "fault_code": 88,
                            "quarantine_reason": 88,
                        }
                    ],
                },
            )

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--inventory",
                    str(inventory),
                    "--partition-list",
                    str(partition_list),
                    "--locale",
                    "ja",
                    "--output-dir",
                    str(temp_dir),
                ],
                check=True,
            )

            payload = json.loads(
                (temp_dir / "operator-console-severity-summary.json").read_text(encoding="utf-8")
            )
            markdown = (temp_dir / "operator-console-severity-summary.md").read_text(
                encoding="utf-8"
            )
            ispf_panel = (temp_dir / "operator-console-ispf.txt").read_text(encoding="utf-8")
            ispf_primary = (temp_dir / "operator-console-ispf-primary.txt").read_text(
                encoding="utf-8"
            )
            ispf_list = (temp_dir / "operator-console-ispf-partition-list.txt").read_text(
                encoding="utf-8"
            )
            ispf_detail = (
                temp_dir / "operator-console-ispf-partition-detail-8193.txt"
            ).read_text(encoding="utf-8")

            self.assertEqual(payload["presentation_locale"], "ja")
            self.assertIn("オペレーターコンソール 重大度サマリー", markdown)
            self.assertIn("全体重大度", markdown)
            self.assertIn("障害 (ERROR)", markdown)
            self.assertIn("FBVBS スタンドアロン オペレーターコンソール", ispf_panel)
            self.assertIn("状態 障害(ERROR/4)", ispf_panel)
            self.assertIn("静止 <ID>", ispf_panel)
            self.assertIn("Option ===>", ispf_primary)
            self.assertIn("=2 でパーティション一覧へ直接移動", ispf_primary)
            self.assertIn("パーティション一覧", ispf_list)
            self.assertIn("行コマンド: S=詳細", ispf_list)
            self.assertIn("パーティション詳細 8193", ispf_detail)
            self.assertIn("推奨対応", ispf_detail)


if __name__ == "__main__":
    unittest.main()
