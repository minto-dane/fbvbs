#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib
import sys


TOOL_VERSION = 1
REPORT_SCHEMA_VERSION = 1

WINDOW_KEYS = (
    "management_abi_version",
    "health_schema_version",
    "audit_schema_version",
    "inventory_schema_version",
    "guidance_schema_version",
    "fault_record_schema_version",
    "diagnostic_bundle_format_version",
    "severity_summary_schema_version",
    "ack_ledger_schema_version",
    "compatibility_matrix_schema_version",
    "evidence_pack_format_version",
)


def read_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def compare_window(
    name: str,
    source_window: dict | None,
    target_window: dict | None,
    incompatibilities: list[dict[str, object]],
    compatible_changes: list[dict[str, object]],
) -> None:
    if not isinstance(source_window, dict):
        return
    source_current = source_window.get("current")
    if source_current is None:
        return
    if not isinstance(target_window, dict):
        incompatibilities.append(
            {
                "field": name,
                "reason": "missing-target-window",
                "source_current": source_current,
            }
        )
        return
    target_min = target_window.get("minimum_accepted")
    target_max = target_window.get("maximum_accepted")
    target_current = target_window.get("current")
    if not isinstance(target_min, int) or not isinstance(target_max, int):
        incompatibilities.append(
            {
                "field": name,
                "reason": "invalid-target-window",
                "target_window": target_window,
            }
        )
        return
    if source_current < target_min or source_current > target_max:
        incompatibilities.append(
            {
                "field": name,
                "reason": "source-version-outside-target-window",
                "source_current": source_current,
                "target_minimum_accepted": target_min,
                "target_maximum_accepted": target_max,
            }
        )
        return
    if isinstance(target_current, int) and target_current < int(source_current):
        compatible_changes.append(
            {
                "field": name,
                "reason": "downgrade-detected",
                "source_current": source_current,
                "target_current": target_current,
            }
        )


def build_report(
    source_path: pathlib.Path,
    target_path: pathlib.Path,
    source_payload: dict,
    target_payload: dict,
    incompatibilities: list[dict[str, object]],
    compatible_changes: list[dict[str, object]],
) -> dict:
    return {
        "tool": {
            "name": "check_standalone_downgrade_compatibility.py",
            "version": TOOL_VERSION,
        },
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_manifest": str(source_path),
        "target_manifest": str(target_path),
        "compatible": not incompatibilities,
        "source_state_manifest_schema_version": source_payload.get("state_manifest_schema_version"),
        "target_state_manifest_schema_version": target_payload.get("state_manifest_schema_version"),
        "summary": {
            "incompatible_count": len(incompatibilities),
            "compatible_change_count": len(compatible_changes),
        },
        "incompatibilities": incompatibilities,
        "compatible_changes": compatible_changes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check whether a standalone target can accept state produced by another standalone version."
    )
    parser.add_argument("--source-manifest", required=True, help="Source standalone-state-manifest.json")
    parser.add_argument("--target-manifest", required=True, help="Target standalone-state-manifest.json")
    parser.add_argument("--report", help="Optional downgrade compatibility report output")
    args = parser.parse_args()

    source_path = pathlib.Path(args.source_manifest).resolve()
    target_path = pathlib.Path(args.target_manifest).resolve()
    source_payload = read_json(source_path)
    target_payload = read_json(target_path)
    source_windows = source_payload.get("compatibility_windows", {})
    target_windows = target_payload.get("compatibility_windows", {})
    incompatibilities: list[dict[str, object]] = []
    compatible_changes: list[dict[str, object]] = []

    for name in WINDOW_KEYS:
        compare_window(
            name,
            source_windows.get(name) if isinstance(source_windows, dict) else None,
            target_windows.get(name) if isinstance(target_windows, dict) else None,
            incompatibilities,
            compatible_changes,
        )

    source_locale = source_payload.get("artifact_state", {}).get("severity_locale")
    target_locales = target_payload.get("supported_operator_console", {}).get("locales", [])
    if source_locale is not None and source_locale not in target_locales:
        incompatibilities.append(
            {
                "field": "severity_locale",
                "reason": "unsupported-operator-locale",
                "source_current": source_locale,
                "target_supported_locales": target_locales,
            }
        )

    report = build_report(
        source_path,
        target_path,
        source_payload,
        target_payload,
        incompatibilities,
        compatible_changes,
    )
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        report_path = pathlib.Path(args.report)
        if not report_path.is_absolute():
            report_path = (pathlib.Path.cwd() / report_path).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(payload, encoding="utf-8")
    sys.stdout.write(payload)
    return 0 if report["compatible"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
