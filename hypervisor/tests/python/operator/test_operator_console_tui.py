#!/usr/bin/env python3

import pathlib
import sys
import unittest


TOOLS_DIR = pathlib.Path(__file__).resolve().parents[3] / "tools" / "operator"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import run_operator_console_tui as tui


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
                "fault_code": 10,
                "quarantine_reason": 10,
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


class OperatorConsoleTuiTests(unittest.TestCase):
    def test_primary_numeric_navigation_opens_list(self) -> None:
        state = tui.build_initial_state(make_summary(), "en")
        tui.execute_command(state, "2")
        self.assertEqual(state.current_panel, tui.PANEL_LIST)
        self.assertIn("Partition list", state.message)

    def test_filter_and_locate_commands_work(self) -> None:
        state = tui.build_initial_state(make_summary(), "en")
        tui.execute_command(state, "FILTER SEV>=ERROR")
        self.assertEqual(state.current_panel, tui.PANEL_LIST)
        self.assertEqual(state.filter_min_severity, 4)
        self.assertEqual(len(tui.visible_partitions(state)), 1)

        tui.execute_command(state, "FILTER CLEAR")
        tui.execute_command(state, "LOCATE PART 4098")
        self.assertEqual(state.current_panel, tui.PANEL_LIST)
        self.assertEqual(state.focus_partition_id, 4098)
        self.assertIn("Located partition 4098", state.message)

    def test_read_only_commands_fail_closed(self) -> None:
        state = tui.build_initial_state(make_summary(), "en")
        tui.execute_command(state, "ACK 4097")
        self.assertEqual(state.message, tui.READ_ONLY_MESSAGE)
        tui.execute_command(state, "QI 4097")
        self.assertEqual(state.message, tui.READ_ONLY_MESSAGE)
        self.assertIsNone(state.focus_partition_id)

    def test_list_navigation_and_detail_open(self) -> None:
        state = tui.build_initial_state(make_summary(), "en")
        tui.execute_command(state, "2")
        tui.handle_key(state, ord("j"), height=24)
        self.assertEqual(state.selected_index, 1)
        tui.handle_key(state, 10, height=24)
        self.assertEqual(state.current_panel, tui.PANEL_DETAIL)
        self.assertEqual(state.focus_partition_id, 4098)

    def test_render_screen_sanitizes_terminal_control_sequences(self) -> None:
        state = tui.build_initial_state(make_summary(), "en")
        tui.set_message(state, "\x1b[31mALERT\x1b[0m")
        rendered = tui.render_screen(state, 24, 80)
        joined = "\n".join(rendered)
        self.assertNotIn("\x1b", joined)
        self.assertIn("[31mALERT[0m", joined)

    def test_japanese_reference_rendering(self) -> None:
        state = tui.build_initial_state(make_summary(), "ja")
        state.current_panel = tui.PANEL_REFERENCE
        rendered = tui.render_screen(state, 24, 80)
        joined = "\n".join(rendered)
        self.assertIn("一次コマンド", joined)
        self.assertIn("PF1=HELP", joined)


if __name__ == "__main__":
    unittest.main()
