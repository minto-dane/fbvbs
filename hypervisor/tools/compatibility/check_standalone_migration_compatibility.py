#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib
import sys

import check_standalone_downgrade_compatibility as downgrade


TOOL_VERSION = 1
REPORT_SCHEMA_VERSION = 1


def read_json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run standalone migration preflight against source and target state manifests."
    )
    parser.add_argument("--source-manifest", required=True, help="Source standalone-state-manifest.json")
    parser.add_argument("--target-manifest", required=True, help="Target standalone-state-manifest.json")
    parser.add_argument("--report", help="Optional migration compatibility report output")
    args = parser.parse_args()

    source_path = pathlib.Path(args.source_manifest).resolve()
    target_path = pathlib.Path(args.target_manifest).resolve()
    source_payload = read_json(source_path)
    target_payload = read_json(target_path)

    incompatibilities: list[dict[str, object]] = []
    compatible_changes: list[dict[str, object]] = []
    for name in downgrade.WINDOW_KEYS:
        downgrade.compare_window(
            name,
            source_payload.get("compatibility_windows", {}).get(name),
            target_payload.get("compatibility_windows", {}).get(name),
            incompatibilities,
            compatible_changes,
        )

    source_artifact_state = source_payload.get("artifact_state", {})
    target_requirements = target_payload.get("migration_requirements", {})
    target_locales = target_payload.get("supported_operator_console", {}).get("locales", [])
    target_styles = target_payload.get("supported_operator_console", {}).get("panel_styles", [])

    source_locale = source_artifact_state.get("severity_locale")
    if source_locale is not None and source_locale not in target_locales:
        incompatibilities.append(
            {
                "field": "severity_locale",
                "reason": "unsupported-operator-locale",
                "source_current": source_locale,
                "target_supported_locales": target_locales,
            }
        )

    if target_requirements.get("timeline_root_required") and not source_artifact_state.get("timeline_root_chain_sha384"):
        incompatibilities.append(
            {
                "field": "timeline_root_chain_sha384",
                "reason": "missing-timeline-root",
            }
        )

    if (
        target_requirements.get("allowed_gap_count_max") is not None
        and int(source_artifact_state.get("timeline_gap_count_total", 0))
        > int(target_requirements.get("allowed_gap_count_max", 0))
    ):
        incompatibilities.append(
            {
                "field": "timeline_gap_count_total",
                "reason": "migration-gap-budget-exceeded",
                "source_current": int(source_artifact_state.get("timeline_gap_count_total", 0)),
                "target_allowed_max": int(target_requirements.get("allowed_gap_count_max", 0)),
            }
        )

    if (
        target_requirements.get("signed_diagnostic_bundle_preferred")
        and not bool(source_artifact_state.get("diagnostic_bundle_signed", False))
    ):
        compatible_changes.append(
            {
                "field": "diagnostic_bundle_signed",
                "reason": "migration-warning-unsigned-diagnostic-bundle",
            }
        )

    source_panel_style = source_artifact_state.get("panel_style")
    if source_panel_style is not None and source_panel_style not in target_styles:
        incompatibilities.append(
            {
                "field": "panel_style",
                "reason": "unsupported-panel-style",
                "source_current": source_panel_style,
                "target_supported_styles": target_styles,
            }
        )

    if (
        target_requirements.get("compatibility_matrix_required")
        and not bool(source_artifact_state.get("compatibility_matrix_present", False))
    ):
        incompatibilities.append(
            {
                "field": "compatibility_matrix_present",
                "reason": "missing-compatibility-matrix",
            }
        )

    report = {
        "tool": {
            "name": "check_standalone_migration_compatibility.py",
            "version": TOOL_VERSION,
        },
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_manifest": str(source_path),
        "target_manifest": str(target_path),
        "compatible": not incompatibilities,
        "summary": {
            "incompatible_count": len(incompatibilities),
            "compatible_change_count": len(compatible_changes),
        },
        "incompatibilities": incompatibilities,
        "compatible_changes": compatible_changes,
    }
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
