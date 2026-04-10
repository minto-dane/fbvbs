#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib

import render_operator_console_mainframe as mainframe


TOOL_VERSION = 2
SUMMARY_SCHEMA_VERSION = 1
SUPPORTED_LOCALES = ("en", "ja")

SEVERITY_NAMES = {
    0: "DEBUG",
    1: "INFO",
    2: "NOTICE",
    3: "WARNING",
    4: "ERROR",
    5: "CRITICAL",
    6: "ALERT",
}
HEALTH_STATE_NAMES = {
    0: "HEALTHY",
    1: "DEGRADED",
    2: "QUARANTINED",
    3: "RECOVERY",
}
HEALTH_TO_SEVERITY = {
    0: 1,
    1: 3,
    2: 4,
    3: 2,
}
UI_TRANSLATIONS = {
    "en": {
        "summary_title": "Operator Console Severity Summary",
        "generated_utc": "Generated UTC",
        "overall_severity": "Overall severity",
        "occupied_partitions": "Occupied partitions",
        "quarantined_partitions": "Quarantined partitions",
        "recovery_partitions": "Recovery partitions",
        "top_partitions": "Top Partitions",
        "partition": "Partition",
        "severity": "Severity",
        "health": "Health",
        "fault": "Fault",
        "source": "Source",
        "panel_title": "FBVBS STANDALONE OPERATOR CONSOLE",
        "panel_status": "STATUS",
        "panel_banner": "BANNER",
        "panel_action": "ACTION",
        "panel_refresh": "REFRESH",
        "panel_generated": "GENERATED",
        "panel_system": "SYSTEM",
        "panel_counts": "COUNTS",
        "panel_top_partitions": "TOP PARTITIONS",
        "panel_commands": "COMMANDS",
        "panel_actions": "ACTIONS",
        "cmd_summary": "SUMMARY",
        "cmd_partitions": "PARTITIONS",
        "cmd_storage": "STORAGE",
        "cmd_scaling": "SCALING",
        "cmd_health": "HEALTH",
        "cmd_export": "EXPORT",
        "cmd_ack": "ACK",
        "cmd_help": "HELP",
        "cmd_quiesce": "QUIESCE",
        "cmd_resume": "RESUME",
        "cmd_recover": "RECOVER",
        "source_fault_record": "fault-record",
        "source_guidance": "guidance",
        "source_health_state": "health-state",
        "actions_bar": "Actions  View  Navigate  Help",
        "option_prompt": "Option ===>",
        "command_prompt": "Command ===>",
        "scroll_prompt": "Scroll ===>",
        "scroll_page": "PAGE",
        "scroll_cursor": "CSR",
        "primary_menu_title": "FBVBS STANDALONE OPERATOR CONSOLE",
        "primary_menu_hint": "Select an option or enter =2 to jump directly to the partition list.",
        "primary_option_1": "System summary",
        "primary_option_2": "Partition list",
        "primary_option_3": "Health and incidents",
        "primary_option_4": "Storage status",
        "primary_option_5": "Export evidence bundle",
        "primary_option_6": "Acknowledge incident",
        "primary_option_7": "Command help",
        "primary_status": "System status",
        "primary_navigation": "Commands: HELP SETTINGS SPLIT SWAP =n n.m",
        "list_title": "PARTITION LIST",
        "list_hint": "Line commands: S=detail  Q=quiesce  R=resume  C=recover",
        "list_sel": "Sel",
        "detail_title": "PARTITION DETAIL",
        "detail_hint": "Enter END to return or =2 to jump back to the partition list.",
        "detail_partition_id": "Partition ID",
        "detail_runbook": "Runbook",
        "detail_reason_domain": "Reason domain",
        "detail_quarantine": "Quarantine",
        "detail_fault_code": "Fault code",
        "detail_source": "Severity source",
        "detail_action": "Suggested action",
        "detail_banner": "Banner",
        "detail_sequence": "Display order",
        "detail_none": "none",
        "pf_footer": "PF1=HELP PF3=END PF4=RETURN PF5=REFRESH PF7=UP PF8=DOWN PF9=SWAP PF12=CANCEL",
    },
    "ja": {
        "summary_title": "オペレーターコンソール 重大度サマリー",
        "generated_utc": "生成時刻 UTC",
        "overall_severity": "全体重大度",
        "occupied_partitions": "使用中パーティション数",
        "quarantined_partitions": "隔離パーティション数",
        "recovery_partitions": "回復中パーティション数",
        "top_partitions": "上位パーティション",
        "partition": "パーティション",
        "severity": "重大度",
        "health": "健全性",
        "fault": "障害",
        "source": "根拠",
        "panel_title": "FBVBS スタンドアロン オペレーターコンソール",
        "panel_status": "状態",
        "panel_banner": "バナー",
        "panel_action": "対応",
        "panel_refresh": "更新",
        "panel_generated": "生成",
        "panel_system": "システム",
        "panel_counts": "件数",
        "panel_top_partitions": "上位パーティション",
        "panel_commands": "照会",
        "panel_actions": "操作",
        "cmd_summary": "概要",
        "cmd_partitions": "一覧",
        "cmd_storage": "ストレージ",
        "cmd_scaling": "スケーリング",
        "cmd_health": "ヘルス",
        "cmd_export": "エクスポート",
        "cmd_ack": "確認",
        "cmd_help": "ヘルプ",
        "cmd_quiesce": "静止",
        "cmd_resume": "再開",
        "cmd_recover": "回復",
        "source_fault_record": "障害記録",
        "source_guidance": "ガイダンス",
        "source_health_state": "健全性推定",
        "actions_bar": "操作  表示  移動  ヘルプ",
        "option_prompt": "Option ===>",
        "command_prompt": "Command ===>",
        "scroll_prompt": "Scroll ===>",
        "scroll_page": "PAGE",
        "scroll_cursor": "CSR",
        "primary_menu_title": "FBVBS スタンドアロン オペレーターコンソール",
        "primary_menu_hint": "番号選択または =2 でパーティション一覧へ直接移動します。",
        "primary_option_1": "システム概要",
        "primary_option_2": "パーティション一覧",
        "primary_option_3": "ヘルスとインシデント",
        "primary_option_4": "ストレージ状態",
        "primary_option_5": "証跡バンドル出力",
        "primary_option_6": "インシデント確認",
        "primary_option_7": "コマンドヘルプ",
        "primary_status": "システム状態",
        "primary_navigation": "コマンド: HELP SETTINGS SPLIT SWAP =n n.m",
        "list_title": "パーティション一覧",
        "list_hint": "行コマンド: S=詳細  Q=静止  R=再開  C=回復",
        "list_sel": "選択",
        "detail_title": "パーティション詳細",
        "detail_hint": "END で戻るか =2 で一覧へ移動します。",
        "detail_partition_id": "パーティション ID",
        "detail_runbook": "ランブック",
        "detail_reason_domain": "理由ドメイン",
        "detail_quarantine": "隔離理由",
        "detail_fault_code": "障害コード",
        "detail_source": "重大度根拠",
        "detail_action": "推奨対応",
        "detail_banner": "バナー",
        "detail_sequence": "表示順",
        "detail_none": "なし",
        "pf_footer": "PF1=HELP PF3=END PF4=RETURN PF5=REFRESH PF7=UP PF8=DOWN PF9=SWAP PF12=CANCEL",
    },
}
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


def severity_name(value: int) -> str:
    return SEVERITY_NAMES.get(value, f"UNKNOWN_{value}")


def health_name(value: int) -> str:
    return HEALTH_STATE_NAMES.get(value, f"UNKNOWN_{value}")


def normalize_severity(value: object) -> int:
    if not isinstance(value, int):
        return 1
    if value < 0:
        return 0
    if value > 6:
        return 6
    return value


def translation(locale: str, key: str) -> str:
    return UI_TRANSLATIONS[locale][key]


def localized_severity(value: int, locale: str) -> str:
    return SEVERITY_LABELS[locale].get(value, severity_name(value))


def localized_health(value: int, locale: str) -> str:
    return HEALTH_LABELS[locale].get(value, health_name(value))


def source_translation_key(source: str) -> str:
    return "source_" + source.replace("-", "_")


def build_record_map(records: list[dict]) -> dict[int, dict]:
    mapping: dict[int, dict] = {}
    for record in records:
        partition_id = record.get("partition_id")
        if isinstance(partition_id, int):
            mapping[partition_id] = record
    return mapping


def build_partition_index(
    partition_list: dict,
    fault_records: list[dict],
    guidance_records: list[dict],
) -> list[dict[str, object]]:
    fault_by_partition: dict[int, dict] = {}
    guidance_by_partition: dict[int, dict] = {}
    rows: list[dict[str, object]] = []

    for record in fault_records:
        partition_id = record.get("partition_id")
        if isinstance(partition_id, int):
            fault_by_partition[partition_id] = record

    for record in guidance_records:
        partition_id = record.get("partition_id")
        if isinstance(partition_id, int):
            guidance_by_partition[partition_id] = record

    for entry in partition_list.get("entries", []):
        if not isinstance(entry, dict):
            continue
        partition_id = entry.get("partition_id")
        if not isinstance(partition_id, int):
            continue
        health_state = int(entry.get("health_state", 0))
        fault_record = fault_by_partition.get(partition_id)
        guidance_record = guidance_by_partition.get(partition_id)
        if fault_record is not None:
            severity = normalize_severity(fault_record.get("severity"))
            source = "fault-record"
        elif guidance_record is not None:
            severity = normalize_severity(guidance_record.get("severity"))
            source = "guidance"
        else:
            severity = HEALTH_TO_SEVERITY.get(health_state, 3)
            source = "health-state"

        rows.append(
            {
                "partition_id": partition_id,
                "health_state": {
                    "value": health_state,
                    "name": health_name(health_state),
                },
                "fault_code": int(entry.get("fault_code", 0)),
                "quarantine_reason": int(entry.get("quarantine_reason", 0)),
                "lockout_windows": int(entry.get("lockout_windows", 0)),
                "policy_deny_count": int(entry.get("policy_deny_count", 0)),
                "severity": {
                    "value": severity,
                    "name": severity_name(severity),
                    "source": source,
                },
            }
        )

    rows.sort(
        key=lambda row: (
            -int(row["severity"]["value"]),
            -int(row["fault_code"]),
            int(row["partition_id"]),
        )
    )
    return rows


def build_severity_counts(partitions: list[dict[str, object]]) -> dict[str, int]:
    counts = {name: 0 for name in SEVERITY_NAMES.values()}
    for row in partitions:
        counts[str(row["severity"]["name"])] += 1
    return counts


def display_rules_for_severity(severity: int) -> dict[str, object]:
    if severity >= 6:
        return {
            "banner": "sticky-incident",
            "operator_action": "immediate-security-escalation",
            "auto_refresh_seconds": 5,
        }
    if severity >= 5:
        return {
            "banner": "sticky-incident",
            "operator_action": "immediate-platform-recovery",
            "auto_refresh_seconds": 10,
        }
    if severity >= 4:
        return {
            "banner": "persistent-action",
            "operator_action": "recovery-required",
            "auto_refresh_seconds": 15,
        }
    if severity >= 3:
        return {
            "banner": "warning",
            "operator_action": "triage",
            "auto_refresh_seconds": 30,
        }
    if severity >= 2:
        return {
            "banner": "notice",
            "operator_action": "monitor",
            "auto_refresh_seconds": 60,
        }
    return {
        "banner": "informational",
        "operator_action": "observe",
        "auto_refresh_seconds": 120,
    }


def build_markdown(summary: dict, locale: str) -> str:
    overall = summary["overall_severity"]
    lines = [
        f"# {translation(locale, 'summary_title')}",
        "",
        f"- {translation(locale, 'generated_utc')}: {summary['generated_utc']}",
        f"- {translation(locale, 'overall_severity')}: {localized_severity(int(overall['value']), locale)} ({overall['name']} / {overall['value']})",
        f"- {translation(locale, 'occupied_partitions')}: {summary['inventory'].get('occupied_partition_count', 0)}",
        f"- {translation(locale, 'quarantined_partitions')}: {summary['inventory'].get('quarantined_partition_count', 0)}",
        f"- {translation(locale, 'recovery_partitions')}: {summary['inventory'].get('recovery_partition_count', 0)}",
        "",
        f"## {translation(locale, 'top_partitions')}",
        "",
        "| "
        f"{translation(locale, 'partition')} | "
        f"{translation(locale, 'severity')} | "
        f"{translation(locale, 'health')} | "
        f"{translation(locale, 'fault')} | "
        f"{translation(locale, 'source')} |",
        "|---|---|---|---|---|",
    ]
    for row in summary["partitions"][:8]:
        lines.append(
            "| "
            f"{row['partition_id']} | "
            f"{localized_severity(int(row['severity']['value']), locale)} ({row['severity']['name']}) | "
            f"{localized_health(int(row['health_state']['value']), locale)} ({row['health_state']['name']}) | "
            f"{row['fault_code']} | "
            f"{translation(locale, source_translation_key(str(row['severity']['source'])))} |"
        )
    return "\n".join(lines) + "\n"


def fit_cell(text: object, width: int) -> str:
    value = str(text)
    if len(value) > width:
        if width <= 1:
            return value[:width]
        return value[: width - 1] + ">"
    return value.ljust(width)


def build_ispf_panel(summary: dict, locale: str) -> str:
    width = 79
    overall = summary["overall_severity"]
    display = summary["display_rules"]
    partitions = summary["partitions"]
    inventory = summary["inventory"]
    generated_utc = str(summary["generated_utc"])
    timestamp = generated_utc.replace("T", " ").replace("+00:00", " UTC")

    def line(content: str = "") -> str:
        return "|" + fit_cell(content, width - 2) + "|"

    def hr(fill: str = "-") -> str:
        return "+" + (fill * (width - 2)) + "+"

    rows = [
        f"{fit_cell(translation(locale, 'partition').upper() if locale == 'en' else translation(locale, 'partition'), 10)} "
        f"{fit_cell(translation(locale, 'severity').upper() if locale == 'en' else translation(locale, 'severity'), 8)} "
        f"{fit_cell(translation(locale, 'health').upper() if locale == 'en' else translation(locale, 'health'), 12)} "
        f"{fit_cell(translation(locale, 'fault').upper() if locale == 'en' else translation(locale, 'fault'), 8)} "
        f"{fit_cell(translation(locale, 'source').upper() if locale == 'en' else translation(locale, 'source'), 14)}"
    ]
    for row in partitions[:8]:
        rows.append(
            f"{fit_cell(row['partition_id'], 10)} "
            f"{fit_cell(localized_severity(int(row['severity']['value']), locale), 8)} "
            f"{fit_cell(localized_health(int(row['health_state']['value']), locale), 12)} "
            f"{fit_cell(row['fault_code'], 8)} "
            f"{fit_cell(translation(locale, 'source_' + str(row['severity']['source']).replace('-', '_')), 14)}"
        )
    while len(rows) < 9:
        rows.append("")

    lines = [
        hr("="),
        line(f" {translation(locale, 'panel_title')}  PANEL OCS0001"),
        line(
            f" {translation(locale, 'panel_status')} "
            f"{localized_severity(int(overall['value']), locale)}({overall['name']}/{overall['value']})"
            f"  {translation(locale, 'panel_banner')} {display['banner']}"
        ),
        line(
            f" {translation(locale, 'panel_action')} {display['operator_action']}"
            f"  {translation(locale, 'panel_refresh')} {display['auto_refresh_seconds']}S"
        ),
        line(f" {translation(locale, 'panel_generated')} {timestamp}"),
        hr(),
        line(
            f" {translation(locale, 'panel_system')}  OCC="
            f"{inventory.get('occupied_partition_count', 0)}"
            "  QUAR="
            f"{inventory.get('quarantined_partition_count', 0)}"
            "  REC="
            f"{inventory.get('recovery_partition_count', 0)}"
        ),
        line(
            f" {translation(locale, 'panel_counts')}  ALERT="
            f"{summary['severity_counts'].get('ALERT', 0)}"
            "  CRIT="
            f"{summary['severity_counts'].get('CRITICAL', 0)}"
            "  ERROR="
            f"{summary['severity_counts'].get('ERROR', 0)}"
            "  WARN="
            f"{summary['severity_counts'].get('WARNING', 0)}"
        ),
        hr(),
        line(f" {translation(locale, 'panel_top_partitions')}"),
    ]
    lines.extend(line(row) for row in rows)
    lines.extend(
        [
            hr(),
            line(
                f" {translation(locale, 'panel_commands')}  "
                f"{translation(locale, 'cmd_summary')}  "
                f"{translation(locale, 'cmd_partitions')}  "
                f"{translation(locale, 'cmd_storage')}  "
                f"{translation(locale, 'cmd_scaling')}  "
                f"{translation(locale, 'cmd_health')}  "
                f"{translation(locale, 'cmd_export')}  "
                f"{translation(locale, 'cmd_ack')}"
            ),
            line(
                f" {translation(locale, 'panel_actions')}   "
                f"{translation(locale, 'cmd_quiesce')} <ID>   "
                f"{translation(locale, 'cmd_resume')} <ID>   "
                f"{translation(locale, 'cmd_recover')} <ID>   "
                f"{translation(locale, 'cmd_help')}"
            ),
            hr(),
            line(" PF1=HELP PF3=EXIT PF5=REFRESH PF9=SWAP PF10=LEFT PF11=RIGHT PF12=CANCEL"),
            hr("="),
        ]
    )
    return "\n".join(lines) + "\n"


def panel_line(content: str, width: int = 80) -> str:
    return fit_cell(content, width)


def build_panel_header(
    locale: str,
    panel_id: str,
    command_label: str,
    scroll_value: str | None,
) -> list[str]:
    header = [
        panel_line(f"{translation(locale, 'actions_bar')}  {panel_id}"),
        panel_line(command_label),
    ]
    if scroll_value is None:
        header.append(panel_line(""))
    else:
        header.append(panel_line(scroll_value))
    return header


def build_ispf_primary_panel(summary: dict, locale: str) -> str:
    overall = summary["overall_severity"]
    inventory = summary["inventory"]
    lines = build_panel_header(
        locale,
        "OCS0001",
        translation(locale, "option_prompt"),
        None,
    )
    lines.extend(
        [
            panel_line(""),
            panel_line(f"    {translation(locale, 'primary_menu_title')}"),
            panel_line(translation(locale, "primary_menu_hint")),
            panel_line(""),
            panel_line(f"  1  {translation(locale, 'primary_option_1')}"),
            panel_line(f"  2  {translation(locale, 'primary_option_2')}"),
            panel_line(f"  3  {translation(locale, 'primary_option_3')}"),
            panel_line(f"  4  {translation(locale, 'primary_option_4')}"),
            panel_line(f"  5  {translation(locale, 'primary_option_5')}"),
            panel_line(f"  6  {translation(locale, 'primary_option_6')}"),
            panel_line(f"  7  {translation(locale, 'primary_option_7')}"),
            panel_line(""),
            panel_line(
                f"{translation(locale, 'primary_status')}: "
                f"{localized_severity(int(overall['value']), locale)} ({overall['name']})"
            ),
            panel_line(
                "OCC="
                f"{inventory.get('occupied_partition_count', 0)}  "
                "QUAR="
                f"{inventory.get('quarantined_partition_count', 0)}  "
                "REC="
                f"{inventory.get('recovery_partition_count', 0)}"
            ),
            panel_line(translation(locale, "primary_navigation")),
            panel_line(""),
            panel_line(translation(locale, "pf_footer")),
        ]
    )
    return "\n".join(lines) + "\n"


def build_ispf_partition_list_panel(summary: dict, locale: str) -> str:
    lines = build_panel_header(
        locale,
        "OCS0100",
        translation(locale, "command_prompt"),
        f"{translation(locale, 'scroll_prompt')} {translation(locale, 'scroll_page')}",
    )
    lines.extend(
        [
            panel_line(translation(locale, "list_title")),
            panel_line(translation(locale, "list_hint")),
            panel_line(""),
            panel_line(
                f"{fit_cell(translation(locale, 'list_sel'), 4)} "
                f"{fit_cell(translation(locale, 'partition'), 12)} "
                f"{fit_cell(translation(locale, 'severity'), 12)} "
                f"{fit_cell(translation(locale, 'health'), 12)} "
                f"{fit_cell(translation(locale, 'fault'), 8)} "
                f"{fit_cell(translation(locale, 'source'), 14)}"
            ),
        ]
    )
    for row in summary["partitions"][:12]:
        lines.append(
            panel_line(
                f"{fit_cell('S', 4)} "
                f"{fit_cell(row['partition_id'], 12)} "
                f"{fit_cell(localized_severity(int(row['severity']['value']), locale), 12)} "
                f"{fit_cell(localized_health(int(row['health_state']['value']), locale), 12)} "
                f"{fit_cell(row['fault_code'], 8)} "
                f"{fit_cell(translation(locale, source_translation_key(str(row['severity']['source']))), 14)}"
            )
        )
    lines.extend(
        [
            panel_line(""),
            panel_line(
                f"{translation(locale, 'panel_actions')}: "
                f"Q={translation(locale, 'cmd_quiesce')}  "
                f"R={translation(locale, 'cmd_resume')}  "
                f"C={translation(locale, 'cmd_recover')}"
            ),
            panel_line(translation(locale, "pf_footer")),
        ]
    )
    return "\n".join(lines) + "\n"


def build_ispf_partition_detail_panel(
    row: dict[str, object],
    fault_record: dict | None,
    guidance_record: dict | None,
    summary: dict,
    locale: str,
    ordinal: int,
) -> str:
    partition_id = int(row["partition_id"])
    runbook = translation(locale, "detail_none")
    if isinstance(guidance_record, dict) and isinstance(guidance_record.get("runbook_code"), int):
        runbook = str(guidance_record["runbook_code"])
    reason_domain = translation(locale, "detail_none")
    if isinstance(guidance_record, dict) and isinstance(guidance_record.get("reason_domain"), int):
        reason_domain = str(guidance_record["reason_domain"])
    fault_code = int(row["fault_code"])
    if isinstance(fault_record, dict) and isinstance(fault_record.get("fault_code"), int):
        fault_code = int(fault_record["fault_code"])

    lines = build_panel_header(
        locale,
        f"OCS02{ordinal:02d}",
        translation(locale, "command_prompt"),
        f"{translation(locale, 'scroll_prompt')} {translation(locale, 'scroll_cursor')}",
    )
    lines.extend(
        [
            panel_line(f"{translation(locale, 'detail_title')} {partition_id}"),
            panel_line(translation(locale, "detail_hint")),
            panel_line(""),
            panel_line(f"{translation(locale, 'detail_partition_id')}: {partition_id}"),
            panel_line(
                f"{translation(locale, 'severity')}: "
                f"{localized_severity(int(row['severity']['value']), locale)} ({row['severity']['name']})"
            ),
            panel_line(
                f"{translation(locale, 'health')}: "
                f"{localized_health(int(row['health_state']['value']), locale)} ({row['health_state']['name']})"
            ),
            panel_line(
                f"{translation(locale, 'detail_fault_code')}: {fault_code}    "
                f"{translation(locale, 'detail_quarantine')}: {row['quarantine_reason']}"
            ),
            panel_line(
                f"{translation(locale, 'detail_source')}: "
                f"{translation(locale, source_translation_key(str(row['severity']['source'])))}"
            ),
            panel_line(
                f"{translation(locale, 'detail_runbook')}: {runbook}    "
                f"{translation(locale, 'detail_reason_domain')}: {reason_domain}"
            ),
            panel_line(
                f"{translation(locale, 'detail_banner')}: {summary['display_rules']['banner']}    "
                f"{translation(locale, 'detail_action')}: {summary['display_rules']['operator_action']}"
            ),
            panel_line(
                f"{translation(locale, 'detail_sequence')}: {ordinal}    "
                f"{translation(locale, 'panel_generated')}: {summary['generated_utc']}"
            ),
            panel_line(""),
            panel_line(
                f"{translation(locale, 'panel_actions')}: "
                f"{translation(locale, 'cmd_quiesce')} {partition_id}  "
                f"{translation(locale, 'cmd_resume')} {partition_id}  "
                f"{translation(locale, 'cmd_recover')} {partition_id}"
            ),
            panel_line(translation(locale, "pf_footer")),
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a one-screen operator console severity summary from standalone diagnostics."
    )
    parser.add_argument("--inventory", required=True, help="Inventory JSON")
    parser.add_argument("--partition-list", required=True, help="Partition list JSON")
    parser.add_argument(
        "--fault-record",
        action="append",
        default=[],
        help="Fault record JSON; may be repeated",
    )
    parser.add_argument(
        "--guidance",
        action="append",
        default=[],
        help="Reason guidance JSON; may be repeated",
    )
    parser.add_argument(
        "--locale",
        choices=SUPPORTED_LOCALES,
        default="en",
        help="Presentation locale for Markdown and ISPF-style panel output",
    )
    parser.add_argument("--output-dir", required=True, help="Output directory")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    output_dir = resolve_user_path(hypervisor_dir, args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    inventory = read_json(resolve_user_path(hypervisor_dir, args.inventory))
    partition_list = read_json(resolve_user_path(hypervisor_dir, args.partition_list))
    fault_records = [
        read_json(resolve_user_path(hypervisor_dir, raw_path))
        for raw_path in args.fault_record
    ]
    guidance_records = [
        read_json(resolve_user_path(hypervisor_dir, raw_path))
        for raw_path in args.guidance
    ]
    fault_by_partition = build_record_map(fault_records)
    guidance_by_partition = build_record_map(guidance_records)

    partitions = build_partition_index(partition_list, fault_records, guidance_records)
    overall_value = 1
    if partitions:
        overall_value = max(int(row["severity"]["value"]) for row in partitions)

    summary = {
        "tool": {
            "name": "generate_operator_console_severity_summary.py",
            "version": TOOL_VERSION,
        },
        "summary_schema_version": SUMMARY_SCHEMA_VERSION,
        "presentation_locale": args.locale,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "inventory": inventory,
        "overall_severity": {
            "value": overall_value,
            "name": severity_name(overall_value),
        },
        "severity_counts": build_severity_counts(partitions),
        "display_rules": display_rules_for_severity(overall_value),
        "partitions": partitions,
    }

    json_path = output_dir / "operator-console-severity-summary.json"
    md_path = output_dir / "operator-console-severity-summary.md"
    ispf_path = output_dir / "operator-console-ispf.txt"
    ispf_primary_path = output_dir / "operator-console-ispf-primary.txt"
    ispf_list_path = output_dir / "operator-console-ispf-partition-list.txt"
    json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(build_markdown(summary, args.locale), encoding="utf-8")
    ispf_path.write_text(build_ispf_panel(summary, args.locale), encoding="utf-8")
    ispf_primary_path.write_text(
        build_ispf_primary_panel(summary, args.locale),
        encoding="utf-8",
    )
    ispf_list_path.write_text(
        build_ispf_partition_list_panel(summary, args.locale),
        encoding="utf-8",
    )
    detail_paths: list[str] = []
    for ordinal, row in enumerate(partitions[:8], start=1):
        partition_id = int(row["partition_id"])
        detail_path = output_dir / f"operator-console-ispf-partition-detail-{partition_id}.txt"
        detail_path.write_text(
            build_ispf_partition_detail_panel(
                row,
                fault_by_partition.get(partition_id),
                guidance_by_partition.get(partition_id),
                summary,
                args.locale,
                ordinal,
            ),
            encoding="utf-8",
        )
        detail_paths.append(str(detail_path))
    print(
        json.dumps(
            {
                "json": str(json_path),
                "markdown": str(md_path),
                "ispf_panel": str(ispf_path),
                "ispf_primary_panel": str(ispf_primary_path),
                "ispf_partition_list_panel": str(ispf_list_path),
                "ispf_partition_detail_panels": detail_paths,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
