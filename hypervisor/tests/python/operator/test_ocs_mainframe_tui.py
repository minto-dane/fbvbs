#!/usr/bin/env python3

import pathlib
import sys
import unittest


TOOLS_DIR = pathlib.Path(__file__).resolve().parents[3] / "tools" / "operator"
sys.path.insert(0, str(TOOLS_DIR))

import ocs_mainframe_tui as tui  # noqa: E402


def make_summary() -> dict:
    return {
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
                "severity": {"name": "ALERT", "value": 6, "source": "fault-record"},
            },
            {
                "partition_id": 4098,
                "fault_code": 0,
                "quarantine_reason": 0,
                "health_state": {"name": "DEGRADED", "value": 1},
                "severity": {"name": "WARNING", "value": 3, "source": "guidance"},
            },
            {
                "partition_id": 4099,
                "fault_code": 0,
                "quarantine_reason": 0,
                "health_state": {"name": "RECOVERY", "value": 3},
                "severity": {"name": "NOTICE", "value": 2, "source": "health-state"},
            },
        ],
        "severity_counts": {
            "ALERT": 1,
            "CRITICAL": 0,
            "ERROR": 0,
            "WARNING": 1,
            "NOTICE": 1,
            "INFO": 0,
            "DEBUG": 0,
        },
    }


class OcsMainframeTuiTests(unittest.TestCase):
    def test_primary_to_list_to_detail_navigation(self) -> None:
        state = tui.make_initial_state(make_summary(), "en")

        tui.handle_key_token(state, "2")
        self.assertEqual(state.panel, tui.PANEL_LIST)

        tui.handle_key_token(state, "DOWN")
        self.assertEqual(state.selected_partition()["partition_id"], 4098)

        tui.handle_key_token(state, "DETAIL")
        self.assertEqual(state.panel, tui.PANEL_DETAIL)
        self.assertEqual(state.focus_partition_id, 4098)

        lines = tui.render_lines(state, 80)
        joined = "\n".join(lines)
        self.assertIn("PARTITION DETAIL 4098", joined)
        self.assertIn("Suggested action: immediate-security-escalation", joined)

    def test_help_and_return_use_previous_panel(self) -> None:
        state = tui.make_initial_state(make_summary(), "en")
        tui.execute_command(state, "=2")
        self.assertEqual(state.panel, tui.PANEL_LIST)

        tui.handle_key_token(state, "PF1")
        self.assertEqual(state.panel, tui.PANEL_REFERENCE)

        tui.handle_key_token(state, "PF4")
        self.assertEqual(state.panel, tui.PANEL_LIST)

    def test_filter_and_locate_commands(self) -> None:
        state = tui.make_initial_state(make_summary(), "en")

        tui.execute_command(state, "FILTER SEV>=WARNING")
        self.assertEqual(state.panel, tui.PANEL_LIST)
        self.assertEqual(len(state.visible_partitions()), 2)

        tui.execute_command(state, "LOCATE PART 4098")
        self.assertEqual(state.selected_partition()["partition_id"], 4098)

        tui.execute_command(state, "CLEAR")
        self.assertEqual(len(state.visible_partitions()), 3)

    def test_read_only_actions_do_not_leave_list_mode(self) -> None:
        state = tui.make_initial_state(make_summary(), "en")
        tui.execute_command(state, "=2")
        tui.execute_command(state, "ACK 4097")
        self.assertIn("read-only preview", state.message)
        self.assertEqual(state.panel, tui.PANEL_LIST)

        tui.execute_command(state, "QI 4097")
        self.assertIn("quiesce partition 4097", state.message)
        self.assertEqual(state.panel, tui.PANEL_LIST)

    def test_japanese_render_contains_mainframe_markers(self) -> None:
        state = tui.make_initial_state(make_summary(), "ja")
        tui.execute_command(state, "=2")
        lines = tui.render_lines(state, 80)
        joined = "\n".join(lines)

        self.assertIn("パーティション一覧", joined)
        self.assertIn("Command ===>", joined)
        self.assertIn("Scroll ===> PAGE", joined)
        self.assertIn("行コマンド: S=詳細", joined)

    def test_end_from_primary_requests_exit(self) -> None:
        state = tui.make_initial_state(make_summary(), "en")
        tui.handle_key_token(state, "PF3")
        self.assertTrue(state.should_exit)


if __name__ == "__main__":
    unittest.main()
