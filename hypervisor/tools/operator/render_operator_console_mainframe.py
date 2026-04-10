#!/usr/bin/env python3

import argparse
import json
import pathlib


TOOL_VERSION = 1
SUPPORTED_LOCALES = ("en", "ja")
PANEL_WIDTH = 80

SEVERITY_LABELS = {
    "en": {
        0: "DEBUG",
        1: "INFO",
        2: "NOTICE",
        3: "WARNING",
        4: "ERROR",
        5: "CRITICAL",
        6: "ALERT",
    },
    "ja": {
        0: "DEBUG",
        1: "情報",
        2: "注意",
        3: "警告",
        4: "障害",
        5: "重大",
        6: "警報",
    },
}

HEALTH_LABELS = {
    "en": {
        0: "HEALTHY",
        1: "DEGRADED",
        2: "QUARANTINED",
        3: "RECOVERY",
    },
    "ja": {
        0: "正常",
        1: "劣化",
        2: "隔離",
        3: "回復中",
    },
}

SOURCE_LABELS = {
    "en": {
        "fault-record": "fault-record",
        "guidance": "guidance",
        "health-state": "health-state",
    },
    "ja": {
        "fault-record": "障害記録",
        "guidance": "ガイダンス",
        "health-state": "健全性推定",
    },
}

TEXT = {
    "en": {
        "product_title": "FBVBS STANDALONE OCS",
        "action_bar": "Actions  Diagnostics  View  Navigate  Control  Help",
        "message_menu": "Select an option or enter =2 to go directly to the partition list.",
        "message_list": "Use S to select, RB for runbook, QI/RS/RC for control actions.",
        "message_detail": "Partition detail panel. Primary commands: ACK EXPORT HELP END.",
        "message_ref": "Reference panel for primary commands, line commands, and PF keys.",
        "option_prompt": "Option ===>  (OPTION ===>)",
        "command_prompt": "Command ===>  (COMMAND ===>)",
        "scroll_prompt": "Scroll ===> PAGE  (SCROLL ===> PAGE)",
        "page": "PAGE",
        "panel_primary": "PRIMARY OPTION MENU",
        "panel_incidents": "PARTITION LIST / ACTIVE INCIDENT LIST",
        "panel_detail": "PARTITION DETAIL",
        "panel_reference": "COMMAND REFERENCE",
        "summary_status": "Overall severity",
        "summary_action": "Action",
        "summary_banner": "Banner",
        "summary_occ": "Occupied",
        "summary_quar": "Quarantined",
        "summary_recovery": "Recovery",
        "menu_heading": "Select one of the following",
        "menu_1": "1  System Summary",
        "menu_1_alias": "Shortcut: 1  System summary",
        "menu_2": "2  Partition list",
        "menu_3": "3  Partition List",
        "menu_4": "4  Quarantine and Recovery",
        "menu_5": "5  Runbook Guidance",
        "menu_6": "6  Evidence Export",
        "menu_7": "7  Operator Acknowledgment",
        "menu_8": "8  Help and Cross Reference",
        "list_heading": "Sel Partition  Severity  Health        Fault    Source",
        "detail_partition": "Partition ID",
        "detail_severity": "Severity",
        "detail_health": "Health",
        "detail_fault": "Fault code",
        "detail_reason": "Quarantine reason",
        "detail_source": "Severity source",
        "detail_guidance": "Recommended action",
        "detail_guidance_default": "Review runbook guidance and confirm recovery path.",
        "ref_primary": "Primary commands: HELP END RETURN UP DOWN LEFT RIGHT SWAP SPLIT",
        "ref_line": "Line commands: S=detail RB=runbook QI=quiesce RS=resume RC=recover",
        "ref_ops": "Ops commands: ACK <id>  EXPORT  FILTER SEV>=ERROR  LOCATE PART <id>",
        "detail_runbook": "Runbook",
        "detail_runbook_default": "none",
        "detail_suggested_action": "Suggested action",
        "pf_keys": "PF1=HELP PF3=END PF4=RETURN PF5=REFRESH PF7=UP PF8=DOWN PF9=SWAP PF12=CANCEL",
    },
    "ja": {
        "product_title": "FBVBS スタンドアロン OCS",
        "action_bar": "操作  診断  表示  移動  制御  ヘルプ",
        "message_menu": "番号を選択するか、=2 でパーティション一覧へ直接移動してください。",
        "message_list": "S で選択、RB でランブック、QI/RS/RC で制御操作です。",
        "message_detail": "パーティション詳細パネルです。一次コマンドは ACK EXPORT HELP END です。",
        "message_ref": "一次コマンド、行コマンド、PF キーの参照パネルです。",
        "option_prompt": "Option ===>",
        "command_prompt": "Command ===>  (COMMAND ===>)",
        "scroll_prompt": "Scroll ===> PAGE  (SCROLL ===> PAGE)",
        "page": "PAGE",
        "panel_primary": "基本オプションメニュー",
        "panel_incidents": "パーティション一覧 / アクティブ障害一覧",
        "panel_detail": "パーティション詳細",
        "panel_reference": "コマンド参照",
        "summary_status": "全体重大度",
        "summary_action": "対応",
        "summary_banner": "バナー",
        "summary_occ": "使用中",
        "summary_quar": "隔離",
        "summary_recovery": "回復中",
        "menu_heading": "次の項目から選択してください",
        "menu_1": "1  システム概要",
        "menu_1_alias": "",
        "menu_2": "2  アクティブ障害",
        "menu_3": "3  パーティション一覧",
        "menu_4": "4  隔離と回復",
        "menu_5": "5  ランブックガイダンス",
        "menu_6": "6  証跡エクスポート",
        "menu_7": "7  オペレーター確認",
        "menu_8": "8  ヘルプと索引",
        "list_heading": "Sel Partition  重大度    健全性        障害      根拠",
        "detail_partition": "パーティション ID",
        "detail_severity": "重大度",
        "detail_health": "健全性",
        "detail_fault": "障害コード",
        "detail_reason": "隔離理由",
        "detail_source": "重大度根拠",
        "detail_guidance": "推奨対応",
        "detail_guidance_default": "ランブックを確認し、回復手順を確定してください。",
        "ref_primary": "一次コマンド: HELP END RETURN UP DOWN LEFT RIGHT SWAP SPLIT",
        "ref_line": "行コマンド: S=詳細 RB=ランブック QI=静止 RS=再開 RC=回復",
        "ref_ops": "運用コマンド: ACK <id>  EXPORT  FILTER SEV>=ERROR  LOCATE PART <id>",
        "detail_runbook": "ランブック",
        "detail_runbook_default": "なし",
        "detail_suggested_action": "推奨対応",
        "pf_keys": "PF1=HELP PF3=END PF4=RETURN PF5=REFRESH PF7=UP PF8=DOWN PF9=SWAP PF12=CANCEL",
    },
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


def tx(locale: str, key: str) -> str:
    return TEXT[locale][key]


def fit_cell(text: object, width: int) -> str:
    value = str(text)
    if len(value) > width:
        if width <= 1:
            return value[:width]
        return value[: width - 1] + ">"
    return value.ljust(width)


def line(content: str = "") -> str:
    return "|" + fit_cell(content, PANEL_WIDTH - 2) + "|"


def hr(fill: str = "-") -> str:
    return "+" + (fill * (PANEL_WIDTH - 2)) + "+"


def severity_label(locale: str, row: dict) -> str:
    value = int(row.get("severity", {}).get("value", 1))
    return SEVERITY_LABELS[locale].get(value, str(row.get("severity", {}).get("name", value)))


def health_label(locale: str, row: dict) -> str:
    value = int(row.get("health_state", {}).get("value", 0))
    return HEALTH_LABELS[locale].get(value, str(row.get("health_state", {}).get("name", value)))


def source_label(locale: str, row: dict) -> str:
    source = str(row.get("severity", {}).get("source", "health-state"))
    return SOURCE_LABELS[locale].get(source, source)


def choose_focus_partition(summary: dict, explicit_partition_id: int | None) -> dict | None:
    partitions = summary.get("partitions", [])
    if explicit_partition_id is not None:
        for row in partitions:
            if int(row.get("partition_id", -1)) == explicit_partition_id:
                return row
    if partitions:
        return partitions[0]
    return None


def render_primary_panel(summary: dict, locale: str) -> str:
    overall = summary.get("overall_severity", {})
    display = summary.get("display_rules", {})
    inventory = summary.get("inventory", {})
    return "\n".join(
        [
            hr("="),
            line(f" {tx(locale, 'product_title')}  {tx(locale, 'panel_primary')}  PANEL OCS0001"),
            line(f" {tx(locale, 'action_bar')}"),
            hr(),
            line(f" {tx(locale, 'message_menu')}"),
            line(
                f" {tx(locale, 'summary_status')}: "
                f"{SEVERITY_LABELS[locale].get(int(overall.get('value', 1)), overall.get('name', 'INFO'))} "
                f"({overall.get('name', 'INFO')}/{overall.get('value', 1)})"
            ),
            line(
                f" {tx(locale, 'summary_action')}: {display.get('operator_action', 'observe')}   "
                f"{tx(locale, 'summary_banner')}: {display.get('banner', 'informational')}"
            ),
            line(
                f" {tx(locale, 'summary_occ')}: {inventory.get('occupied_partition_count', 0)}   "
                f"{tx(locale, 'summary_quar')}: {inventory.get('quarantined_partition_count', 0)}   "
                f"{tx(locale, 'summary_recovery')}: {inventory.get('recovery_partition_count', 0)}"
            ),
            hr(),
            line(f" {tx(locale, 'option_prompt')} "),
            line(""),
            line(f" {tx(locale, 'menu_heading')}"),
            line(f"   {tx(locale, 'menu_1')}"),
            line(f"   {tx(locale, 'menu_1_alias')}"),
            line(f"   {tx(locale, 'menu_2')}"),
            line(f"   {tx(locale, 'menu_3')}"),
            line(f"   {tx(locale, 'menu_4')}"),
            line(f"   {tx(locale, 'menu_5')}"),
            line(f"   {tx(locale, 'menu_6')}"),
            line(f"   {tx(locale, 'menu_7')}"),
            line(f"   {tx(locale, 'menu_8')}"),
            hr(),
            line(f" {tx(locale, 'pf_keys')}"),
            hr("="),
        ]
    ) + "\n"


def render_incident_list_panel(summary: dict, locale: str) -> str:
    partitions = summary.get("partitions", [])
    rows = [tx(locale, "list_heading")]
    for row in partitions[:10]:
        rows.append(
            " "
            + fit_cell("S", 3)
            + fit_cell(row.get("partition_id", 0), 11)
            + fit_cell(severity_label(locale, row), 10)
            + fit_cell(health_label(locale, row), 14)
            + fit_cell(row.get("fault_code", 0), 9)
            + fit_cell(source_label(locale, row), 14)
        )
    while len(rows) < 11:
        rows.append("")
    return "\n".join(
        [
            hr("="),
            line(f" {tx(locale, 'product_title')}  {tx(locale, 'panel_incidents')}  PANEL OCS0100"),
            line(f" {tx(locale, 'action_bar')}"),
            hr(),
            line(f" {tx(locale, 'message_list')}"),
            line(f" {tx(locale, 'command_prompt')}   {tx(locale, 'scroll_prompt')}"),
            hr(),
        ]
        + [line(f" {row}") for row in rows]
        + [
            hr(),
            line(f" {tx(locale, 'ref_line')}"),
            line(f" {tx(locale, 'pf_keys')}"),
            hr("="),
        ]
    ) + "\n"


def render_detail_panel(summary: dict, locale: str, focus_partition: dict | None) -> str:
    display = summary.get("display_rules", {})
    if focus_partition is None:
        detail_lines = [
            f" {tx(locale, 'detail_partition')}: N/A",
            f" {tx(locale, 'detail_guidance')}: {tx(locale, 'detail_guidance_default')}",
        ]
    else:
        detail_lines = [
            f" {tx(locale, 'detail_partition')}: {focus_partition.get('partition_id', 0)}",
            f" {tx(locale, 'detail_severity')}: {severity_label(locale, focus_partition)} "
            f"({focus_partition.get('severity', {}).get('name', 'INFO')})",
            f" {tx(locale, 'detail_health')}: {health_label(locale, focus_partition)} "
            f"({focus_partition.get('health_state', {}).get('name', 'HEALTHY')})",
            f" {tx(locale, 'detail_fault')}: {focus_partition.get('fault_code', 0)}",
            f" {tx(locale, 'detail_reason')}: {focus_partition.get('quarantine_reason', 0)}",
            f" {tx(locale, 'detail_source')}: {source_label(locale, focus_partition)}",
            f" {tx(locale, 'detail_runbook')}: {tx(locale, 'detail_runbook_default')}",
            f" {tx(locale, 'detail_suggested_action')}: {display.get('operator_action', 'observe')}",
            f" {tx(locale, 'detail_guidance')}: {tx(locale, 'detail_guidance_default')}",
        ]
    while len(detail_lines) < 12:
        detail_lines.append("")
    return "\n".join(
        [
            hr("="),
            line(
                f" {tx(locale, 'product_title')}  {tx(locale, 'panel_detail')} "
                f"{focus_partition.get('partition_id', '') if focus_partition is not None else ''}  PANEL OCS0200"
            ),
            line(f" {tx(locale, 'action_bar')}"),
            hr(),
            line(f" {tx(locale, 'message_detail')}"),
            line(f" {tx(locale, 'command_prompt')}   {tx(locale, 'scroll_prompt')}"),
            hr(),
        ]
        + [line(text) for text in detail_lines]
        + [
            hr(),
            line(f" {tx(locale, 'ref_ops')}"),
            line(f" {tx(locale, 'pf_keys')}"),
            hr("="),
        ]
    ) + "\n"


def render_reference_panel(locale: str) -> str:
    body = [
        f" {tx(locale, 'ref_primary')}",
        "",
        f" {tx(locale, 'ref_line')}",
        "",
        f" {tx(locale, 'ref_ops')}",
    ]
    while len(body) < 12:
        body.append("")
    return "\n".join(
        [
            hr("="),
            line(f" {tx(locale, 'product_title')}  {tx(locale, 'panel_reference')}  PANEL OCS0900"),
            line(f" {tx(locale, 'action_bar')}"),
            hr(),
            line(f" {tx(locale, 'message_ref')}"),
            line(f" {tx(locale, 'command_prompt')}"),
            hr(),
        ]
        + [line(text) for text in body]
        + [
            hr(),
            line(f" {tx(locale, 'pf_keys')}"),
            hr("="),
        ]
    ) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render a standalone operator console panel set inspired by IBM mainframe ISPF conventions."
    )
    parser.add_argument("--summary", required=True, help="operator-console-severity-summary.json")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--locale", choices=SUPPORTED_LOCALES, default="en", help="Presentation locale")
    parser.add_argument(
        "--focus-partition-id",
        type=int,
        default=None,
        help="Partition to focus in the detail panel; defaults to highest-severity partition",
    )
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    summary = read_json(resolve_user_path(hypervisor_dir, args.summary))
    output_dir = resolve_user_path(hypervisor_dir, args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    focus_partition = choose_focus_partition(summary, args.focus_partition_id)

    primary_path = output_dir / "ocs-primary-option-menu.txt"
    incidents_path = output_dir / "ocs-incident-list-panel.txt"
    detail_path = output_dir / "ocs-partition-detail-panel.txt"
    reference_path = output_dir / "ocs-command-reference-panel.txt"
    manifest_path = output_dir / "ocs-panel-manifest.json"

    primary_path.write_text(render_primary_panel(summary, args.locale), encoding="utf-8")
    incidents_path.write_text(render_incident_list_panel(summary, args.locale), encoding="utf-8")
    detail_path.write_text(
        render_detail_panel(summary, args.locale, focus_partition), encoding="utf-8"
    )
    reference_path.write_text(render_reference_panel(args.locale), encoding="utf-8")

    manifest = {
        "tool": {"name": "render_operator_console_mainframe.py", "version": TOOL_VERSION},
        "presentation_locale": args.locale,
        "style": "mainframe-ispf-inspired",
        "source_summary": str(resolve_user_path(hypervisor_dir, args.summary)),
        "panels": {
            "primary_option_menu": str(primary_path),
            "incident_list": str(incidents_path),
            "partition_detail": str(detail_path),
            "command_reference": str(reference_path),
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": str(manifest_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
