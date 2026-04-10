#!/usr/bin/env python3

import argparse
import curses
import json
import pathlib
from dataclasses import dataclass
from typing import Optional

import render_operator_console_mainframe as mainframe


TOOL_VERSION = 1
SUPPORTED_LOCALES = ("en", "ja")
VISIBLE_LIST_ROWS = 10

PANEL_PRIMARY = "primary"
PANEL_LIST = "list"
PANEL_DETAIL = "detail"
PANEL_REFERENCE = "reference"

OPTION_TO_PANEL = {
    "1": PANEL_PRIMARY,
    "2": PANEL_LIST,
    "3": PANEL_LIST,
    "4": PANEL_LIST,
    "5": PANEL_REFERENCE,
    "6": PANEL_REFERENCE,
    "7": PANEL_REFERENCE,
    "8": PANEL_REFERENCE,
}

SEVERITY_NAME_TO_VALUE = {
    "DEBUG": 0,
    "INFO": 1,
    "NOTICE": 2,
    "WARNING": 3,
    "ERROR": 4,
    "CRITICAL": 5,
    "ALERT": 6,
}


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def read_json(path: pathlib.Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"JSON input must be an object: {path}")
    return payload


def fit_cell(text: object, width: int) -> str:
    return mainframe.fit_cell(text, width)


def severity_value(row: dict) -> int:
    value = row.get("severity", {}).get("value", 1)
    if isinstance(value, int):
        return value
    return 1


def health_label(locale: str, row: dict) -> str:
    return mainframe.health_label(locale, row)


def severity_label(locale: str, row: dict) -> str:
    return mainframe.severity_label(locale, row)


def source_label(locale: str, row: dict) -> str:
    return mainframe.source_label(locale, row)


def parse_severity_threshold(raw_value: str) -> Optional[int]:
    normalized = raw_value.strip().upper()
    if normalized.isdigit():
        value = int(normalized)
        if 0 <= value <= 6:
            return value
        return None
    return SEVERITY_NAME_TO_VALUE.get(normalized)


@dataclass
class ConsoleState:
    summary: dict
    locale: str
    panel: str = PANEL_PRIMARY
    previous_panel: str = PANEL_PRIMARY
    selected_index: int = 0
    list_offset: int = 0
    focus_partition_id: Optional[int] = None
    command_buffer: str = ""
    message: str = ""
    filter_min_severity: Optional[int] = None
    should_exit: bool = False

    def visible_partitions(self) -> list[dict]:
        rows = list(self.summary.get("partitions", []))
        if self.filter_min_severity is not None:
            rows = [row for row in rows if severity_value(row) >= self.filter_min_severity]
        return rows

    def selected_partition(self) -> Optional[dict]:
        rows = self.visible_partitions()
        if not rows:
            return None
        index = max(0, min(self.selected_index, len(rows) - 1))
        return rows[index]


def normalize_state(state: ConsoleState) -> None:
    rows = state.visible_partitions()
    if not rows:
        state.selected_index = 0
        state.list_offset = 0
        if state.panel == PANEL_DETAIL:
            state.panel = PANEL_LIST
        return
    if state.selected_index >= len(rows):
        state.selected_index = len(rows) - 1
    if state.selected_index < 0:
        state.selected_index = 0
    if state.selected_index < state.list_offset:
        state.list_offset = state.selected_index
    if state.selected_index >= state.list_offset + VISIBLE_LIST_ROWS:
        state.list_offset = state.selected_index - VISIBLE_LIST_ROWS + 1
    max_offset = max(0, len(rows) - VISIBLE_LIST_ROWS)
    if state.list_offset > max_offset:
        state.list_offset = max_offset
    selected = rows[state.selected_index]
    state.focus_partition_id = int(selected.get("partition_id", 0))


def set_panel(state: ConsoleState, panel: str) -> None:
    if state.panel != panel:
        state.previous_panel = state.panel
    state.panel = panel
    normalize_state(state)


def move_selection(state: ConsoleState, delta: int) -> None:
    rows = state.visible_partitions()
    if not rows:
        state.message = "no partitions available" if state.locale == "en" else "表示可能なパーティションがありません"
        return
    state.selected_index = max(0, min(state.selected_index + delta, len(rows) - 1))
    normalize_state(state)


def locate_partition(state: ConsoleState, partition_id: int) -> bool:
    rows = state.visible_partitions()
    for index, row in enumerate(rows):
        if int(row.get("partition_id", -1)) == partition_id:
            state.selected_index = index
            normalize_state(state)
            return True
    return False


def execute_primary_option(state: ConsoleState, option: str) -> None:
    panel = OPTION_TO_PANEL.get(option)
    if panel is None:
        state.message = f"unknown option: {option}" if state.locale == "en" else f"不明なオプションです: {option}"
        return
    set_panel(state, panel)
    if panel == PANEL_LIST:
        state.message = "partition list opened" if state.locale == "en" else "パーティション一覧を開きました"
    elif panel == PANEL_REFERENCE:
        state.message = "reference opened" if state.locale == "en" else "参照パネルを開きました"
    else:
        state.message = "summary refreshed" if state.locale == "en" else "概要を表示しました"


def open_selected_detail(state: ConsoleState) -> None:
    partition = state.selected_partition()
    if partition is None:
        state.message = "no partition selected" if state.locale == "en" else "パーティションが選択されていません"
        return
    state.focus_partition_id = int(partition.get("partition_id", 0))
    set_panel(state, PANEL_DETAIL)
    state.message = (
        f"detail opened for partition {state.focus_partition_id}"
        if state.locale == "en"
        else f"パーティション {state.focus_partition_id} の詳細を開きました"
    )


def execute_read_only_action(state: ConsoleState, verb: str, partition_id: Optional[int]) -> None:
    if partition_id is None:
        partition = state.selected_partition()
        if partition is not None:
            partition_id = int(partition.get("partition_id", 0))
    if verb == "ACK":
        state.message = (
            f"read-only preview: acknowledge partition {partition_id}"
            if state.locale == "en"
            else f"読み取り専用プレビュー: パーティション {partition_id} を確認"
        )
        return
    if verb == "EXPORT":
        state.message = (
            "read-only preview: export workflow requested"
            if state.locale == "en"
            else "読み取り専用プレビュー: エクスポート要求"
        )
        return
    if partition_id is None:
        state.message = "partition id required" if state.locale == "en" else "パーティション ID が必要です"
        return
    action_label = {
        "QI": "quiesce",
        "RS": "resume",
        "RC": "recover",
    }[verb]
    if state.locale == "en":
        state.message = f"read-only preview: {action_label} partition {partition_id}"
    else:
        jp = {"QI": "静止", "RS": "再開", "RC": "回復"}[verb]
        state.message = f"読み取り専用プレビュー: パーティション {partition_id} を{jp}"


def execute_command(state: ConsoleState, raw_command: str) -> None:
    command = raw_command.strip()
    state.command_buffer = ""
    if not command:
        if state.panel == PANEL_PRIMARY:
            state.message = (
                "enter an option number or a command"
                if state.locale == "en"
                else "オプション番号またはコマンドを入力してください"
            )
        elif state.panel == PANEL_LIST:
            open_selected_detail(state)
        return

    upper = command.upper()
    if upper in {"HELP", "PF1"}:
        set_panel(state, PANEL_REFERENCE)
        state.message = "help opened" if state.locale == "en" else "ヘルプを開きました"
        return
    if upper in {"END", "PF3", "EXIT", "QUIT"}:
        if state.panel == PANEL_PRIMARY:
            state.should_exit = True
            state.message = "exit requested" if state.locale == "en" else "終了します"
            return
        set_panel(state, PANEL_PRIMARY)
        state.message = "returned to primary menu" if state.locale == "en" else "基本メニューへ戻りました"
        return
    if upper in {"RETURN", "PF4"}:
        if state.panel == PANEL_REFERENCE:
            set_panel(state, state.previous_panel)
        else:
            set_panel(state, PANEL_PRIMARY)
        state.message = "return completed" if state.locale == "en" else "戻りました"
        return
    if upper in {"REFRESH", "PF5"}:
        normalize_state(state)
        state.message = "refreshed" if state.locale == "en" else "再表示しました"
        return
    if upper in {"SWAP", "PF9"}:
        old = state.panel
        set_panel(state, state.previous_panel)
        state.previous_panel = old
        state.message = "swapped panels" if state.locale == "en" else "パネルを切り替えました"
        return
    if upper == "=1" or upper == "SUMMARY":
        set_panel(state, PANEL_PRIMARY)
        state.message = "summary opened" if state.locale == "en" else "概要を開きました"
        return
    if upper in {"=2", "=3", "PARTITIONS", "LIST"}:
        set_panel(state, PANEL_LIST)
        state.message = "partition list opened" if state.locale == "en" else "パーティション一覧を開きました"
        return
    if upper in {"=8", "REFERENCE"}:
        set_panel(state, PANEL_REFERENCE)
        state.message = "reference opened" if state.locale == "en" else "参照パネルを開きました"
        return
    if upper.startswith("FILTER SEV>="):
        threshold = parse_severity_threshold(command.split(">=", 1)[1])
        if threshold is None:
            state.message = "invalid severity filter" if state.locale == "en" else "重大度フィルターが不正です"
            return
        state.filter_min_severity = threshold
        set_panel(state, PANEL_LIST)
        normalize_state(state)
        state.message = (
            f"filter applied: severity>={threshold}"
            if state.locale == "en"
            else f"重大度フィルターを適用しました: {threshold} 以上"
        )
        return
    if upper in {"CLEAR", "RESET", "FILTER CLEAR"}:
        state.filter_min_severity = None
        normalize_state(state)
        state.message = "filter cleared" if state.locale == "en" else "フィルターを解除しました"
        return
    if upper.startswith("LOCATE PART "):
        raw_id = command[12:].strip()
        if raw_id.isdigit() and locate_partition(state, int(raw_id)):
            set_panel(state, PANEL_LIST)
            state.message = (
                f"partition {raw_id} located"
                if state.locale == "en"
                else f"パーティション {raw_id} を表示しました"
            )
            return
        state.message = (
            f"partition not found: {raw_id}"
            if state.locale == "en"
            else f"パーティションが見つかりません: {raw_id}"
        )
        return
    if upper.startswith("DETAIL "):
        raw_id = command[7:].strip()
        if raw_id.isdigit() and locate_partition(state, int(raw_id)):
            open_selected_detail(state)
            return
        state.message = (
            f"partition not found: {raw_id}"
            if state.locale == "en"
            else f"パーティションが見つかりません: {raw_id}"
        )
        return
    for verb in ("ACK", "EXPORT", "QI", "RS", "RC"):
        if upper == verb:
            execute_read_only_action(state, verb, None)
            return
        if upper.startswith(verb + " "):
            raw_id = command[len(verb) + 1 :].strip()
            execute_read_only_action(state, verb, int(raw_id) if raw_id.isdigit() else None)
            return
    if state.panel == PANEL_PRIMARY and command in OPTION_TO_PANEL:
        execute_primary_option(state, command)
        return
    state.message = f"unknown command: {command}" if state.locale == "en" else f"不明なコマンドです: {command}"


def handle_key_token(state: ConsoleState, token: str) -> None:
    if token == "PF1":
        execute_command(state, "HELP")
    elif token == "PF3":
        execute_command(state, "END")
    elif token == "PF4":
        execute_command(state, "RETURN")
    elif token == "PF5":
        execute_command(state, "REFRESH")
    elif token == "PF7":
        if state.panel == PANEL_LIST:
            move_selection(state, -1)
        else:
            execute_command(state, "UP")
    elif token == "PF8":
        if state.panel == PANEL_LIST:
            move_selection(state, 1)
        else:
            execute_command(state, "DOWN")
    elif token == "PF9":
        execute_command(state, "SWAP")
    elif token == "PF12":
        execute_command(state, "END")
    elif token == "ENTER":
        execute_command(state, state.command_buffer)
    elif token == "UP":
        if state.panel == PANEL_LIST:
            move_selection(state, -1)
    elif token == "DOWN":
        if state.panel == PANEL_LIST:
            move_selection(state, 1)
    elif token == "DETAIL":
        open_selected_detail(state)
    elif token in OPTION_TO_PANEL and state.panel == PANEL_PRIMARY and not state.command_buffer:
        execute_primary_option(state, token)


def focused_partition(state: ConsoleState) -> Optional[dict]:
    rows = state.visible_partitions()
    if not rows:
        return None
    if state.focus_partition_id is not None:
        for row in rows:
            if int(row.get("partition_id", -1)) == state.focus_partition_id:
                return row
    return rows[min(state.selected_index, len(rows) - 1)]


def render_primary_lines(state: ConsoleState, width: int) -> list[str]:
    text = mainframe.TEXT[state.locale]
    overall = state.summary.get("overall_severity", {})
    display = state.summary.get("display_rules", {})
    inventory = state.summary.get("inventory", {})
    content = [
        f"{mainframe.hr('=')}",
        f"{mainframe.line(f' {text['product_title']}  {text['panel_primary']}  PANEL OCS0001')}",
        f"{mainframe.line(f' {text['action_bar']}')}",
        f"{mainframe.hr()}",
        f"{mainframe.line(f' {state.message or text['message_menu']}')}",
        f"{mainframe.line(f' {text['summary_status']}: {severity_label(state.locale, {'severity': overall})} ({overall.get('name', 'INFO')}/{overall.get('value', 1)})')}",
        f"{mainframe.line(f' {text['summary_action']}: {display.get('operator_action', 'observe')}   {text['summary_banner']}: {display.get('banner', 'informational')}')}",
        f"{mainframe.line(f' {text['summary_occ']}: {inventory.get('occupied_partition_count', 0)}   {text['summary_quar']}: {inventory.get('quarantined_partition_count', 0)}   {text['summary_recovery']}: {inventory.get('recovery_partition_count', 0)}')}",
        f"{mainframe.hr()}",
        f"{mainframe.line(f' {text['option_prompt']} {state.command_buffer}')}",
        f"{mainframe.line('')}",
        f"{mainframe.line(f' {text['menu_heading']}')}",
        f"{mainframe.line(f'   {text['menu_1']}')}",
        f"{mainframe.line(f'   {text['menu_1_alias']}')}",
        f"{mainframe.line(f'   {text['menu_2']}')}",
        f"{mainframe.line(f'   {text['menu_3']}')}",
        f"{mainframe.line(f'   {text['menu_4']}')}",
        f"{mainframe.line(f'   {text['menu_5']}')}",
        f"{mainframe.line(f'   {text['menu_6']}')}",
        f"{mainframe.line(f'   {text['menu_7']}')}",
        f"{mainframe.line(f'   {text['menu_8']}')}",
        f"{mainframe.hr()}",
        f"{mainframe.line(f' {text['pf_keys']}')}",
        f"{mainframe.hr('=')}",
    ]
    return [row[:width] for row in content]


def render_list_lines(state: ConsoleState, width: int) -> list[str]:
    text = mainframe.TEXT[state.locale]
    rows = state.visible_partitions()
    visible = rows[state.list_offset : state.list_offset + VISIBLE_LIST_ROWS]
    body = []
    for relative_index, row in enumerate(visible):
        actual_index = state.list_offset + relative_index
        marker = ">" if actual_index == state.selected_index else " "
        body.append(
            " "
            + marker
            + " "
            + fit_cell("S", 3)
            + fit_cell(row.get("partition_id", 0), 11)
            + fit_cell(severity_label(state.locale, row), 10)
            + fit_cell(health_label(state.locale, row), 14)
            + fit_cell(row.get("fault_code", 0), 9)
            + fit_cell(source_label(state.locale, row), 14)
        )
    while len(body) < VISIBLE_LIST_ROWS:
        body.append("")
    filter_note = ""
    if state.filter_min_severity is not None:
        filter_note = f" severity>={state.filter_min_severity}"
    content = [
        f"{mainframe.hr('=')}",
        f"{mainframe.line(f' {text['product_title']}  {text['panel_incidents']}  PANEL OCS0100')}",
        f"{mainframe.line(f' {text['action_bar']}')}",
        f"{mainframe.hr()}",
        f"{mainframe.line(f' {state.message or text['message_list']}{filter_note}')}",
        f"{mainframe.line(f' {text['command_prompt']} {state.command_buffer}   {text['scroll_prompt']}')}",
        f"{mainframe.hr()}",
        f"{mainframe.line(f' {text['list_heading']}')}",
    ]
    content.extend(mainframe.line(f" {row}") for row in body)
    content.extend(
        [
            f"{mainframe.hr()}",
            f"{mainframe.line(f' {text['ref_line']}')}",
            f"{mainframe.line(f' {text['pf_keys']}')}",
            f"{mainframe.hr('=')}",
        ]
    )
    return [row[:width] for row in content]


def render_detail_lines(state: ConsoleState, width: int) -> list[str]:
    text = mainframe.TEXT[state.locale]
    row = focused_partition(state)
    if row is None:
        detail = [
            f" {text['detail_partition']}: N/A",
            f" {text['detail_guidance']}: {text['detail_guidance_default']}",
        ]
        panel_suffix = ""
    else:
        panel_suffix = f" {row.get('partition_id', '')}"
        detail = [
            f" {text['detail_partition']}: {row.get('partition_id', 0)}",
            f" {text['detail_severity']}: {severity_label(state.locale, row)} ({row.get('severity', {}).get('name', 'INFO')})",
            f" {text['detail_health']}: {health_label(state.locale, row)} ({row.get('health_state', {}).get('name', 'HEALTHY')})",
            f" {text['detail_fault']}: {row.get('fault_code', 0)}",
            f" {text['detail_reason']}: {row.get('quarantine_reason', 0)}",
            f" {text['detail_source']}: {source_label(state.locale, row)}",
            f" {text['detail_runbook']}: {text['detail_runbook_default']}",
            f" {text['detail_suggested_action']}: {state.summary.get('display_rules', {}).get('operator_action', 'observe')}",
            f" {text['detail_guidance']}: {text['detail_guidance_default']}",
        ]
    while len(detail) < 12:
        detail.append("")
    content = [
        f"{mainframe.hr('=')}",
        f"{mainframe.line(f' {text['product_title']}  {text['panel_detail']}{panel_suffix}  PANEL OCS0200')}",
        f"{mainframe.line(f' {text['action_bar']}')}",
        f"{mainframe.hr()}",
        f"{mainframe.line(f' {state.message or text['message_detail']}')}",
        f"{mainframe.line(f' {text['command_prompt']} {state.command_buffer}   {text['scroll_prompt']}')}",
        f"{mainframe.hr()}",
    ]
    content.extend(mainframe.line(line) for line in detail)
    content.extend(
        [
            f"{mainframe.hr()}",
            f"{mainframe.line(f' {text['ref_ops']}')}",
            f"{mainframe.line(f' {text['pf_keys']}')}",
            f"{mainframe.hr('=')}",
        ]
    )
    return [row[:width] for row in content]


def render_reference_lines(state: ConsoleState, width: int) -> list[str]:
    text = mainframe.TEXT[state.locale]
    body = [
        f" {text['ref_primary']}",
        "",
        f" {text['ref_line']}",
        "",
        f" {text['ref_ops']}",
        "",
        (
            " Read-only mode: commands do not mutate hypervisor state."
            if state.locale == "en"
            else " 読み取り専用モードです。コマンドはハイパーバイザー状態を変更しません。"
        ),
    ]
    while len(body) < 12:
        body.append("")
    content = [
        f"{mainframe.hr('=')}",
        f"{mainframe.line(f' {text['product_title']}  {text['panel_reference']}  PANEL OCS0900')}",
        f"{mainframe.line(f' {text['action_bar']}')}",
        f"{mainframe.hr()}",
        f"{mainframe.line(f' {state.message or text['message_ref']}')}",
        f"{mainframe.line(f' {text['command_prompt']} {state.command_buffer}')}",
        f"{mainframe.hr()}",
    ]
    content.extend(mainframe.line(line) for line in body)
    content.extend(
        [
            f"{mainframe.hr()}",
            f"{mainframe.line(f' {text['pf_keys']}')}",
            f"{mainframe.hr('=')}",
        ]
    )
    return [row[:width] for row in content]


def render_lines(state: ConsoleState, width: int) -> list[str]:
    normalize_state(state)
    width = min(width, mainframe.PANEL_WIDTH)
    if state.panel == PANEL_PRIMARY:
        return render_primary_lines(state, width)
    if state.panel == PANEL_LIST:
        return render_list_lines(state, width)
    if state.panel == PANEL_DETAIL:
        return render_detail_lines(state, width)
    return render_reference_lines(state, width)


def draw_screen(stdscr: "curses._CursesWindow", state: ConsoleState) -> None:
    stdscr.erase()
    height, width = stdscr.getmaxyx()
    lines = render_lines(state, width)
    for row_index, row in enumerate(lines[:height]):
        stdscr.addnstr(row_index, 0, row, max(0, width - 1))
    stdscr.refresh()


def append_command_char(state: ConsoleState, key: int) -> bool:
    if 32 <= key <= 126:
        state.command_buffer += chr(key)
        return True
    return False


def curses_main(stdscr: "curses._CursesWindow", state: ConsoleState) -> None:
    curses.noecho()
    curses.cbreak()
    stdscr.keypad(True)
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    normalize_state(state)
    while not state.should_exit:
        draw_screen(stdscr, state)
        key = stdscr.getch()
        if key in (curses.KEY_F1,):
            handle_key_token(state, "PF1")
        elif key in (curses.KEY_F3,):
            handle_key_token(state, "PF3")
        elif key in (curses.KEY_F4,):
            handle_key_token(state, "PF4")
        elif key in (curses.KEY_F5,):
            handle_key_token(state, "PF5")
        elif key in (curses.KEY_F7,):
            handle_key_token(state, "PF7")
        elif key in (curses.KEY_F8,):
            handle_key_token(state, "PF8")
        elif key in (curses.KEY_F9,):
            handle_key_token(state, "PF9")
        elif key in (curses.KEY_F12,):
            handle_key_token(state, "PF12")
        elif key in (curses.KEY_UP, ord("k")):
            handle_key_token(state, "UP")
        elif key in (curses.KEY_DOWN, ord("j")):
            handle_key_token(state, "DOWN")
        elif key in (10, 13, curses.KEY_ENTER):
            handle_key_token(state, "ENTER")
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            state.command_buffer = state.command_buffer[:-1]
        elif key in (ord("q"),):
            execute_command(state, "END")
        elif key in (ord("?"), ord("h")):
            execute_command(state, "HELP")
        elif key in (ord("s"), ord("S")) and state.panel == PANEL_LIST and not state.command_buffer:
            handle_key_token(state, "DETAIL")
        elif key in (ord("r"), ord("R")) and not state.command_buffer:
            execute_command(state, "REFRESH")
        elif key in (ord("1"), ord("2"), ord("3"), ord("4"), ord("5"), ord("6"), ord("7"), ord("8")):
            if not state.command_buffer and state.panel == PANEL_PRIMARY:
                handle_key_token(state, chr(key))
            else:
                append_command_char(state, key)
        else:
            append_command_char(state, key)


def make_initial_state(summary: dict, locale: str) -> ConsoleState:
    state = ConsoleState(summary=summary, locale=locale)
    normalize_state(state)
    return state


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a full-screen standalone operator console TUI inspired by IBM mainframe ISPF workflows."
    )
    parser.add_argument("--summary", required=True, help="operator-console-severity-summary.json")
    parser.add_argument(
        "--locale",
        choices=SUPPORTED_LOCALES,
        default=None,
        help="Presentation locale; defaults to the summary locale or en",
    )
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    summary = read_json(resolve_user_path(hypervisor_dir, args.summary))
    locale = args.locale or str(summary.get("presentation_locale", "en"))
    if locale not in SUPPORTED_LOCALES:
        locale = "en"
    state = make_initial_state(summary, locale)
    curses.wrapper(curses_main, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
