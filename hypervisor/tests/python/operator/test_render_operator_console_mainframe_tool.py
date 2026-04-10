#!/usr/bin/env python3

import json
import pathlib
import subprocess
import tempfile
import unittest


SCRIPT = (
    pathlib.Path(__file__).resolve().parents[3]
    / "tools" / "operator" / "render_operator_console_mainframe.py"
)


class RenderOperatorConsoleMainframeTests(unittest.TestCase):
    def write_json(self, path: pathlib.Path, data: dict) -> None:
        path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def make_summary(self, path: pathlib.Path) -> None:
        self.write_json(
            path,
            {
                "summary_schema_version": 1,
                "presentation_locale": "en",
                "inventory": {
                    "occupied_partition_count": 3,
                    "quarantined_partition_count": 1,
                    "recovery_partition_count": 1,
                },
                "overall_severity": {"name": "ALERT", "value": 6},
                "display_rules": {
                    "banner": "sticky-incident",
                    "operator_action": "immediate-security-escalation",
                    "auto_refresh_seconds": 5,
                },
                "partitions": [
                    {
                        "partition_id": 4097,
                        "fault_code": 77,
                        "quarantine_reason": 77,
                        "health_state": {"name": "QUARANTINED", "value": 2},
                        "severity": {
                            "name": "ALERT",
                            "value": 6,
                            "source": "fault-record",
                        },
                    },
                    {
                        "partition_id": 4098,
                        "fault_code": 0,
                        "quarantine_reason": 0,
                        "health_state": {"name": "DEGRADED", "value": 1},
                        "severity": {
                            "name": "WARNING",
                            "value": 3,
                            "source": "guidance",
                        },
                    },
                ],
                "severity_counts": {
                    "ALERT": 1,
                    "CRITICAL": 0,
                    "ERROR": 0,
                    "WARNING": 1,
                    "NOTICE": 0,
                    "INFO": 0,
                    "DEBUG": 0,
                },
            },
        )

    def test_renders_english_mainframe_panels(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-mainframe-en-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            summary = temp_dir / "summary.json"
            self.make_summary(summary)

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--summary",
                    str(summary),
                    "--output-dir",
                    str(temp_dir),
                    "--locale",
                    "en",
                ],
                check=True,
            )

            manifest = json.loads((temp_dir / "ocs-panel-manifest.json").read_text(encoding="utf-8"))
            primary = (temp_dir / "ocs-primary-option-menu.txt").read_text(encoding="utf-8")
            incidents = (temp_dir / "ocs-incident-list-panel.txt").read_text(encoding="utf-8")
            detail = (temp_dir / "ocs-partition-detail-panel.txt").read_text(encoding="utf-8")

            self.assertEqual(manifest["style"], "mainframe-ispf-inspired")
            self.assertEqual(manifest["presentation_locale"], "en")
            self.assertIn("PRIMARY OPTION MENU", primary)
            self.assertIn("OPTION ===>", primary)
            self.assertIn("1  System Summary", primary)
            self.assertIn("ACTIVE INCIDENT LIST", incidents)
            self.assertIn("COMMAND ===>", incidents)
            self.assertIn("SCROLL ===> PAGE", incidents)
            self.assertIn("4097", incidents)
            self.assertIn("PARTITION DETAIL", detail)
            self.assertIn("Partition ID: 4097", detail)
            self.assertIn("PF5=REFRESH", detail)

    def test_renders_japanese_mainframe_panels(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fbvbs-mainframe-ja-") as temp_dir_raw:
            temp_dir = pathlib.Path(temp_dir_raw)
            summary = temp_dir / "summary.json"
            self.make_summary(summary)

            subprocess.run(
                [
                    "python3",
                    str(SCRIPT),
                    "--summary",
                    str(summary),
                    "--output-dir",
                    str(temp_dir),
                    "--locale",
                    "ja",
                    "--focus-partition-id",
                    "4098",
                ],
                check=True,
            )

            primary = (temp_dir / "ocs-primary-option-menu.txt").read_text(encoding="utf-8")
            incidents = (temp_dir / "ocs-incident-list-panel.txt").read_text(encoding="utf-8")
            detail = (temp_dir / "ocs-partition-detail-panel.txt").read_text(encoding="utf-8")

            self.assertIn("基本オプションメニュー", primary)
            self.assertIn("番号を選択するか", primary)
            self.assertIn("アクティブ障害一覧", incidents)
            self.assertIn("S で選択", incidents)
            self.assertIn("重大度", incidents)
            self.assertIn("パーティション詳細", detail)
            self.assertIn("パーティション ID: 4098", detail)
            self.assertIn("推奨対応", detail)


if __name__ == "__main__":
    unittest.main()
