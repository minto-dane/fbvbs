#!/usr/bin/env python3

from __future__ import annotations

import argparse
import curses
import json
import pathlib
import string
import sys
from dataclasses import dataclass

import render_operator_console_mainframe as mainframe


TOOL_VERSION = 1
PANEL_PRIMARY = "primary"
PANEL_LIST = "list"
PANEL_DETAIL = "detail"
PANEL_REFERENCE = "reference"
READ_ONLY_MESSAGE = "Read-only console: command requires out-of-band operator path."

SEVERITY_NAME_TO_VALUE = {
    "DEBUG": 0,
    "INFO": 1,
    "NOTICE": 2,
    "WARNING": 3,
    "ERROR": 4,
    "CRITICAL": 5,
    "ALERT": 6,
}
SEVERITY_VALUE_TO_NAME = {value: name for name, value in SEVERITY_NAME_TO_VALUE.items()}


@dataclass
class ConsoleState:
    summary: dict
    locale: str
    current_panel: str = PANEL_PRIMARY
    previous_panel: str = PANEL_PRIMARY
    selected_index: int = 0
    top_index: int = 0
    filter_min_severity: int | None = None
    focus_partition_id: int | None = None
    message: str = ""
    command_buffer: str = ""
    should_exit: bool = False


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def read_json(path: pathlib.Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"missing summary JSON: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"JSON input must be an object: {path}")
    return payload


def sanitize_terminal_text(text: object) -> str:
    value = str(text)
    sanitized = []
    for char in value:
        if char in "\n\r\t":
            sanitized.append(" ")
            continue
        if char.isprintable():
            sanitized.append(char)
    return "".join(sanitized)


def format_line(text: object, width: int) -> str:
    clean = sanitize_terminal_text(text)
    if len(clean) > width:
        if width <= 1:
            return clean[:width]
        return clean[: width - 1] + ">"
    return clean.ljust(width)


def set_panel(state: ConsoleState, panel: str) -> None:
    if state.current_panel != panel:
        state.previous_panel = state.current_panel
        state.current_panel = panel


def set_message(state: ConsoleState, text: str) -> None:
    state.message = sanitize_terminal_text(text)


def visible_partitions(state: ConsoleState) -> list[dict]:
    partitions = []
    for row in state.summary.get("partitions", []):
        severity_value = int(row.get("severity", {}).get("value", 1))
        if state.filter_min_severity is not None and severity_value < state.filter_min_severity:
            continue
        partitions.append(row)
    return partitions


def clamp_selection(state: ConsoleState) -> None:
    rows = visible_partitions(state)
    if not rows:
        state.selected_index = 0
        state.top_index = 0
        return
    if state.selected_index >= len(rows):
        state.selected_index = len(rows) - 1
    if state.selected_index < 0:
        state.selected_index = 0
    if state.top_index > state.selected_index:
        state.top_index = state.selected_index
    if state.top_index < 0:
        state.top_index = 0


def current_partition(state: ConsoleState) -> dict | None:
    rows = visible_partitions(state)
    if state.focus_partition_id is not None:
        for row in rows:
            if int(row.get("partition_id", -1)) == state.focus_partition_id:
                return row
    if not rows:
        return None
    clamp_selection(state)
    return rows[state.selected_index]


def goto_partition_list(state: ConsoleState) -> None:
    set_panel(state, PANEL_LIST)
    clamp_selection(state)
    set_message(state, "Partition list ready.")


def goto_partition_detail(state: ConsoleState, partition: dict | None) -> None:
    if partition is None:
        set_message(state, "No partition selected.")
        return
    state.focus_partition_id = int(partition.get("partition_id", 0))
    set_panel(state, PANEL_DETAIL)
    set_message(state, f"Focused partition {state.focus_partition_id}.")


def severity_floor_from_token(token: str) -> int | None:
    normalized = token.strip().upper()
    if normalized.startswith("SEV>="):
        normalized = normalized.split(">=", 1)[1].strip()
    if normalized.startswith(">="):
        normalized = normalized[2:].strip()
    return SEVERITY_NAME_TO_VALUE.get(normalized)


def handle_primary_selection(state: ConsoleState, selection: str) -> None:
    if selection == "1":
        set_panel(state, PANEL_PRIMARY)
        set_message(state, "System summary is shown on the primary panel.")
        return
    if selection in {"2", "3", "=2"}:
        goto_partition_list(state)
        return
    if selection == "4":
        goto_partition_list(state)
        state.filter_min_severity = SEVERITY_NAME_TO_VALUE["NOTICE"]
        set_message(state, "Filtered to quarantine and recovery relevant partitions.")
        return
    if selection == "5":
        set_panel(state, PANEL_REFERENCE)
        set_message(state, "Runbook guidance lives in the reference panel for this read-only console.")
        return
    if selection in {"6", "7"}:
        set_message(state, READ_ONLY_MESSAGE)
        return
    if selection == "8":
        set_panel(state, PANEL_REFERENCE)
        set_message(state, "Help and cross reference panel.")
        return
    set_message(state, f"Unsupported option: {selection}")


def execute_command(state: ConsoleState, raw_command: str) -> None:
    command = sanitize_terminal_text(raw_command).strip()
    state.command_buffer = ""
    if not command:
        return
    upper = command.upper()

    if state.current_panel == PANEL_PRIMARY and command in {"1", "2", "3", "4", "5", "6", "7", "8", "=2"}:
        handle_primary_selection(state, command)
        return

    if upper in {"HELP", "PF1"}:
        set_panel(state, PANEL_REFERENCE)
        set_message(state, "Reference panel.")
        return
    if upper in {"END", "EXIT", "QUIT", "PF3"}:
        if state.current_panel == PANEL_PRIMARY:
            state.should_exit = True
            set_message(state, "Exiting operator console.")
        else:
            state.current_panel = state.previous_panel
            set_message(state, "Returned to previous panel.")
        return
    if upper in {"RETURN", "PF4"}:
        state.current_panel, state.previous_panel = state.previous_panel, state.current_panel
        set_message(state, "Returned to previous panel.")
        return
    if upper in {"REFRESH", "PF5"}:
        set_message(state, "Summary is static. Regenerate the summary JSON to refresh data.")
        return
    if upper in {"SWAP", "SPLIT", "PF9"}:
        set_message(state, "Split/swap is not available in this standalone single-session console.")
        return
    if upper.startswith("FILTER "):
        arg = upper.split(" ", 1)[1].strip()
        if arg in {"CLEAR", "RESET"}:
            state.filter_min_severity = None
            clamp_selection(state)
            set_message(state, "Filter cleared.")
            return
        floor = severity_floor_from_token(arg)
        if floor is None:
            set_message(state, f"Unsupported filter: {command}")
            return
        state.filter_min_severity = floor
        state.selected_index = 0
        state.top_index = 0
        goto_partition_list(state)
        set_message(state, f"Filter set to severity >= {SEVERITY_VALUE_TO_NAME[floor]}.")
        return
    if upper.startswith("LOCATE PART "):
        try:
            partition_id = int(command.split()[-1], 10)
        except ValueError:
            set_message(state, f"Invalid partition locator: {command}")
            return
        for index, row in enumerate(visible_partitions(state)):
            if int(row.get("partition_id", -1)) == partition_id:
                state.selected_index = index
                state.focus_partition_id = partition_id
                goto_partition_list(state)
                set_message(state, f"Located partition {partition_id}.")
                return
        set_message(state, f"Partition {partition_id} not found in current view.")
        return
    if upper.startswith(("ACK ", "EXPORT", "QI ", "RS ", "RC ")):
        set_message(state, READ_ONLY_MESSAGE)
        return
    if upper in {"LIST", "PARTITIONS"}:
        goto_partition_list(state)
        return
    if upper in {"DETAIL", "OPEN"}:
        goto_partition_detail(state, current_partition(state))
        return
    set_message(state, f"Unsupported command: {command}")


def handle_list_line_command(state: ConsoleState, token: str) -> bool:
    command = token.strip().upper()
    partition = current_partition(state)
    if partition is None:
        set_message(state, "No partition selected.")
        return True
    if command in {"S", "DETAIL"}:
        goto_partition_detail(state, partition)
        return True
    if command == "RB":
        set_panel(state, PANEL_REFERENCE)
        set_message(state, f"Runbook guidance for partition {partition.get('partition_id', 0)}.")
        return True
    if command in {"QI", "RS", "RC"}:
        set_message(state, READ_ONLY_MESSAGE)
        return True
    return False


def handle_key(state: ConsoleState, key: int, height: int = 24) -> None:
    visible_rows = max(5, height - 12)
    rows = visible_partitions(state)

    if key in {curses.KEY_F1}:
        execute_command(state, "HELP")
        return
    if key in {curses.KEY_F3}:
        execute_command(state, "END")
        return
    if key in {curses.KEY_F4}:
        execute_command(state, "RETURN")
        return
    if key in {curses.KEY_F5}:
        execute_command(state, "REFRESH")
        return
    if key in {curses.KEY_F9}:
        execute_command(state, "SWAP")
        return
    if key in {curses.KEY_F12}:
        state.command_buffer = ""
        set_message(state, "Command line cleared.")
        return

    if key in {curses.KEY_BACKSPACE, 127, 8}:
        state.command_buffer = state.command_buffer[:-1]
        return
    if key in {10, 13, curses.KEY_ENTER}:
        if state.command_buffer.strip():
            if state.current_panel == PANEL_LIST and handle_list_line_command(state, state.command_buffer):
                state.command_buffer = ""
                return
            execute_command(state, state.command_buffer)
            return
        if state.current_panel == PANEL_LIST:
            goto_partition_detail(state, current_partition(state))
            return
        if state.current_panel == PANEL_DETAIL:
            state.current_panel = PANEL_LIST
            set_message(state, "Returned to partition list.")
            return
        return

    if key in {curses.KEY_UP, ord("k"), ord("K")} and state.current_panel == PANEL_LIST:
        if rows:
            state.selected_index = max(0, state.selected_index - 1)
            if state.selected_index < state.top_index:
                state.top_index = state.selected_index
        return
    if key in {curses.KEY_DOWN, ord("j"), ord("J")} and state.current_panel == PANEL_LIST:
        if rows:
            state.selected_index = min(len(rows) - 1, state.selected_index + 1)
            if state.selected_index >= state.top_index + visible_rows:
                state.top_index = state.selected_index - visible_rows + 1
        return
    if key in {curses.KEY_NPAGE, curses.KEY_F8} and state.current_panel == PANEL_LIST:
        if rows:
            state.selected_index = min(len(rows) - 1, state.selected_index + visible_rows)
            state.top_index = min(max(0, len(rows) - visible_rows), state.top_index + visible_rows)
        return
    if key in {curses.KEY_PPAGE, curses.KEY_F7} and state.current_panel == PANEL_LIST:
        if rows:
            state.selected_index = max(0, state.selected_index - visible_rows)
            state.top_index = max(0, state.top_index - visible_rows)
        return

    if state.current_panel == PANEL_PRIMARY and key in {ord(str(value)) for value in range(1, 9)}:
        state.command_buffer = chr(key)
        execute_command(state, state.command_buffer)
        return

    if state.current_panel == PANEL_LIST and key in {ord("s"), ord("S"), ord("r"), ord("R")}:
        token = chr(key).upper()
        if token == "R":
            token = "RB"
        handle_list_line_command(state, token)
        return

    if 0 <= key < 256 and chr(key) in string.printable and chr(key) not in "\t\r\n\x0b\x0c":
        if len(state.command_buffer) < 192:
            state.command_buffer += chr(key)


def build_primary_body(state: ConsoleState) -> list[str]:
    tx = mainframe.tx
    summary = state.summary
    overall = summary.get("overall_severity", {})
    display = summary.get("display_rules", {})
    inventory = summary.get("inventory", {})
    locale = state.locale
    return [
        tx(locale, "message_menu"),
        "",
        f"{tx(locale, 'summary_status')}: {mainframe.SEVERITY_LABELS[locale].get(int(overall.get('value', 1)), 'INFO')} ({overall.get('name', 'INFO')}/{overall.get('value', 1)})",
        f"{tx(locale, 'summary_action')}: {display.get('operator_action', 'observe')}",
        f"{tx(locale, 'summary_banner')}: {display.get('banner', 'informational')}",
        f"{tx(locale, 'summary_occ')}: {inventory.get('occupied_partition_count', 0)}",
        f"{tx(locale, 'summary_quar')}: {inventory.get('quarantined_partition_count', 0)}",
        f"{tx(locale, 'summary_recovery')}: {inventory.get('recovery_partition_count', 0)}",
        "",
        tx(locale, "menu_heading"),
        tx(locale, "menu_1"),
        tx(locale, "menu_2"),
        tx(locale, "menu_3"),
        tx(locale, "menu_4"),
        tx(locale, "menu_5"),
        tx(locale, "menu_6"),
        tx(locale, "menu_7"),
        tx(locale, "menu_8"),
    ]


def build_list_body(state: ConsoleState, height: int) -> list[str]:
    locale = state.locale
    rows = visible_partitions(state)
    clamp_selection(state)
    visible_rows = max(5, height - 12)
    state.top_index = min(state.top_index, max(0, len(rows) - visible_rows))
    body = [
        mainframe.tx(locale, "message_list"),
        "",
        mainframe.tx(locale, "list_heading"),
    ]
    for index, row in enumerate(rows[state.top_index : state.top_index + visible_rows]):
        absolute_index = state.top_index + index
        marker = ">" if absolute_index == state.selected_index else " "
        body.append(
            f"{marker} "
            f"{format_line(row.get('partition_id', 0), 10).strip()} "
            f"{format_line(mainframe.severity_label(locale, row), 10).strip()} "
            f"{format_line(mainframe.health_label(locale, row), 12).strip()} "
            f"{format_line(row.get('fault_code', 0), 8).strip()} "
            f"{format_line(mainframe.source_label(locale, row), 14).strip()}"
        )
    body.append("")
    body.append(mainframe.tx(locale, "ref_line"))
    return body


def build_detail_body(state: ConsoleState) -> list[str]:
    locale = state.locale
    partition = current_partition(state)
    display = state.summary.get("display_rules", {})
    if partition is None:
        return ["No partition selected."]
    return [
        mainframe.tx(locale, "message_detail"),
        "",
        f"{mainframe.tx(locale, 'detail_partition')}: {partition.get('partition_id', 0)}",
        f"{mainframe.tx(locale, 'detail_severity')}: {mainframe.severity_label(locale, partition)} ({partition.get('severity', {}).get('name', 'INFO')})",
        f"{mainframe.tx(locale, 'detail_health')}: {mainframe.health_label(locale, partition)} ({partition.get('health_state', {}).get('name', 'HEALTHY')})",
        f"{mainframe.tx(locale, 'detail_fault')}: {partition.get('fault_code', 0)}",
        f"{mainframe.tx(locale, 'detail_reason')}: {partition.get('quarantine_reason', 0)}",
        f"{mainframe.tx(locale, 'detail_source')}: {mainframe.source_label(locale, partition)}",
        f"{mainframe.tx(locale, 'detail_runbook')}: {mainframe.tx(locale, 'detail_runbook_default')}",
        f"{mainframe.tx(locale, 'detail_suggested_action')}: {display.get('operator_action', 'observe')}",
        f"{mainframe.tx(locale, 'detail_guidance')}: {mainframe.tx(locale, 'detail_guidance_default')}",
    ]


def build_reference_body(state: ConsoleState) -> list[str]:
    locale = state.locale
    return [
        mainframe.tx(locale, "message_ref"),
        "",
        mainframe.tx(locale, "ref_primary"),
        "",
        mainframe.tx(locale, "ref_line"),
        "",
        mainframe.tx(locale, "ref_ops"),
    ]


def panel_title(state: ConsoleState) -> str:
    locale = state.locale
    if state.current_panel == PANEL_PRIMARY:
        return f"{mainframe.tx(locale, 'product_title')}  {mainframe.tx(locale, 'panel_primary')}"
    if state.current_panel == PANEL_LIST:
        return f"{mainframe.tx(locale, 'product_title')}  {mainframe.tx(locale, 'panel_incidents')}"
    if state.current_panel == PANEL_DETAIL:
        partition = current_partition(state)
        suffix = ""
        if partition is not None:
            suffix = f" {partition.get('partition_id', 0)}"
        return f"{mainframe.tx(locale, 'product_title')}  {mainframe.tx(locale, 'panel_detail')}{suffix}"
    return f"{mainframe.tx(locale, 'product_title')}  {mainframe.tx(locale, 'panel_reference')}"


def render_screen(state: ConsoleState, height: int, width: int) -> list[str]:
    content_width = max(20, width - 2)
    lines = [
        format_line(panel_title(state), content_width),
        format_line(mainframe.tx(state.locale, "action_bar"), content_width),
        format_line(state.message, content_width),
        "-" * content_width,
    ]

    if state.current_panel == PANEL_PRIMARY:
        body = build_primary_body(state)
    elif state.current_panel == PANEL_LIST:
        body = build_list_body(state, height)
    elif state.current_panel == PANEL_DETAIL:
        body = build_detail_body(state)
    else:
        body = build_reference_body(state)

    body_height = max(6, height - 8)
    for entry in body[:body_height]:
        lines.append(format_line(entry, content_width))
    while len(lines) < height - 3:
        lines.append(" " * content_width)

    lines.append("-" * content_width)
    prompt = f"{mainframe.tx(state.locale, 'command_prompt')} {state.command_buffer}"
    lines.append(format_line(prompt, content_width))
    lines.append(format_line(mainframe.tx(state.locale, "pf_keys"), content_width))
    return lines[:height]


def draw_screen(stdscr: curses.window, state: ConsoleState) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    for row_index, row in enumerate(render_screen(state, height, width)):
        try:
            stdscr.addnstr(row_index, 0, row, max(0, width - 1))
        except curses.error:
            pass
    stdscr.refresh()


def run_tui(stdscr: curses.window, state: ConsoleState) -> None:
    curses.curs_set(0)
    stdscr.keypad(True)
    curses.use_default_colors()
    draw_screen(stdscr, state)
    while not state.should_exit:
        key = stdscr.getch()
        handle_key(state, key, stdscr.getmaxyx()[0])
        draw_screen(stdscr, state)


def build_initial_state(summary: dict, locale: str) -> ConsoleState:
    return ConsoleState(
        summary=summary,
        locale=locale,
        focus_partition_id=None,
        message="Read-only standalone operator console.",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a read-only full-screen standalone operator console TUI."
    )
    parser.add_argument("--summary", required=True, help="operator-console-severity-summary.json")
    parser.add_argument(
        "--locale",
        choices=mainframe.SUPPORTED_LOCALES,
        default="en",
        help="Presentation locale",
    )
    args = parser.parse_args()

    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit("full-screen TUI requires a TTY")

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    summary = read_json(resolve_user_path(hypervisor_dir, args.summary))
    state = build_initial_state(summary, args.locale)
    curses.wrapper(run_tui, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
