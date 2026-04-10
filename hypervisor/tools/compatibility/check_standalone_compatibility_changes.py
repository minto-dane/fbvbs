#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib
import sys


TOOL_VERSION = 1
REPORT_SCHEMA_VERSION = 1

SCHEMA_KEYS = (
    "management_abi_version",
    "health_schema_version",
    "audit_schema_version",
    "inventory_schema_version",
    "guidance_schema_version",
    "fault_record_schema_version",
)

STRICT_ROW_FIELDS = (
    ("category",),
    ("call", "id"),
    ("request_type",),
    ("response_type",),
    ("abi_version", "negotiation_status"),
    ("service_kind", "name"),
    ("required_capability", "name"),
)


def read_json(path: pathlib.Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def path_value(payload: dict[str, object], path: tuple[str, ...]) -> object:
    current: object = payload
    for component in path:
        if not isinstance(current, dict) or component not in current:
            return None
        current = current[component]
    return current


def row_map(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    return {
        row["call"]["name"]: row
        for row in payload.get("matrix", [])
        if isinstance(row, dict) and isinstance(row.get("call"), dict) and "name" in row["call"]
    }


def row_flag_names(row: dict[str, object]) -> set[str]:
    return {
        flag["name"]
        for flag in row.get("compatibility_flags", [])
        if isinstance(flag, dict) and isinstance(flag.get("name"), str)
    }


def row_class_names(row: dict[str, object]) -> set[str]:
    data = row.get("command_class_flags", {})
    if not isinstance(data, dict):
        return set()
    return {name for name in data.get("names", []) if isinstance(name, str)}


def row_deprecated_fields(row: dict[str, object]) -> set[str]:
    lifecycle = row.get("lifecycle", {})
    if not isinstance(lifecycle, dict):
        return set()
    return {
        field for field in lifecycle.get("deprecated_fields", []) if isinstance(field, str)
    }


def compare_lifecycle_stage(
    call_name: str,
    baseline_row: dict[str, object],
    current_row: dict[str, object],
    incompatibilities: list[dict[str, object]],
    compatible_changes: list[dict[str, object]],
) -> None:
    baseline_stage = path_value(baseline_row, ("lifecycle", "stage"))
    current_stage = path_value(current_row, ("lifecycle", "stage"))
    if baseline_stage == current_stage:
        return
    if baseline_stage is None or current_stage is None:
        incompatibilities.append(
            {
                "scope": "matrix",
                "call": call_name,
                "reason": "lifecycle-stage-missing",
                "baseline": baseline_stage,
                "current": current_stage,
            }
        )
        return
    if current_stage == "experimental" and baseline_stage != "experimental":
        incompatibilities.append(
            {
                "scope": "matrix",
                "call": call_name,
                "reason": "lifecycle-weakened",
                "baseline": baseline_stage,
                "current": current_stage,
            }
        )
        return
    compatible_changes.append(
        {
            "scope": "matrix",
            "call": call_name,
            "reason": "lifecycle-stage-changed",
            "baseline": baseline_stage,
            "current": current_stage,
        }
    )


def compare_registry(
    baseline: dict[str, object],
    current: dict[str, object],
    incompatibilities: list[dict[str, object]],
    compatible_changes: list[dict[str, object]],
) -> None:
    baseline_registry = baseline.get("schema_registry", {})
    current_registry = current.get("schema_registry", {})
    if not isinstance(baseline_registry, dict) or not isinstance(current_registry, dict):
        incompatibilities.append(
            {
                "scope": "schema_registry",
                "reason": "missing-schema-registry",
                "message": "baseline or current payload is missing schema_registry",
            }
        )
        return

    for key in SCHEMA_KEYS:
        baseline_value = baseline_registry.get(key)
        current_value = current_registry.get(key)
        if current_value is None:
            incompatibilities.append(
                {
                    "scope": "schema_registry",
                    "reason": "missing-schema-key",
                    "field": key,
                    "baseline": baseline_value,
                    "current": None,
                }
            )
            continue
        if not isinstance(baseline_value, int) or not isinstance(current_value, int):
            incompatibilities.append(
                {
                    "scope": "schema_registry",
                    "reason": "non-integer-schema-version",
                    "field": key,
                    "baseline": baseline_value,
                    "current": current_value,
                }
            )
            continue
        if current_value < baseline_value:
            incompatibilities.append(
                {
                    "scope": "schema_registry",
                    "reason": "schema-version-regressed",
                    "field": key,
                    "baseline": baseline_value,
                    "current": current_value,
                }
            )
        elif current_value > baseline_value:
            compatible_changes.append(
                {
                    "scope": "schema_registry",
                    "reason": "schema-version-increased",
                    "field": key,
                    "baseline": baseline_value,
                    "current": current_value,
                }
            )

    baseline_flags = set(
        name
        for name in baseline_registry.get("compatibility_flags", {}).get("names", [])
        if isinstance(name, str)
    )
    current_flags = set(
        name
        for name in current_registry.get("compatibility_flags", {}).get("names", [])
        if isinstance(name, str)
    )
    if not current_flags and isinstance(current_registry.get("compatibility_flags"), dict):
        compatibility_value = current_registry["compatibility_flags"].get("value")
        if compatibility_value is not None:
            compatible_changes.append(
                {
                    "scope": "schema_registry",
                    "reason": "compatibility-flag-names-missing",
                    "message": "current schema_registry compatibility_flags has no names list; value-only mode was accepted",
                    "value": compatibility_value,
                }
            )
    removed_flags = sorted(baseline_flags - current_flags)
    if removed_flags:
        incompatibilities.append(
            {
                "scope": "schema_registry",
                "reason": "compatibility-flags-removed",
                "flags": removed_flags,
            }
        )


def compare_policy(
    baseline: dict[str, object],
    current: dict[str, object],
    incompatibilities: list[dict[str, object]],
) -> None:
    baseline_policy = baseline.get("deprecated_field_policy", {})
    current_policy = current.get("deprecated_field_policy", {})
    if not isinstance(baseline_policy, dict) or not isinstance(current_policy, dict):
        incompatibilities.append(
            {
                "scope": "deprecated_field_policy",
                "reason": "missing-policy",
                "message": "baseline or current payload is missing deprecated_field_policy",
            }
        )
        return

    baseline_version = baseline_policy.get("policy_schema_version")
    current_version = current_policy.get("policy_schema_version")
    if isinstance(baseline_version, int) and isinstance(current_version, int) and current_version < baseline_version:
        incompatibilities.append(
            {
                "scope": "deprecated_field_policy",
                "reason": "policy-schema-regressed",
                "baseline": baseline_version,
                "current": current_version,
            }
        )

    for field_name in (
        "append_only_within_major",
        "reserved_fields_must_be_zero",
        "removal_requires_major_version",
        "deprecated_fields_must_not_be_repurposed",
        "deprecated_fields_must_remain_accepted",
    ):
        if baseline_policy.get(field_name) and not current_policy.get(field_name):
            incompatibilities.append(
                {
                    "scope": "deprecated_field_policy",
                    "reason": "policy-weakened",
                    "field": field_name,
                    "baseline": baseline_policy.get(field_name),
                    "current": current_policy.get(field_name),
                }
            )


def compare_rows(
    baseline: dict[str, object],
    current: dict[str, object],
    incompatibilities: list[dict[str, object]],
    compatible_changes: list[dict[str, object]],
) -> None:
    baseline_rows = row_map(baseline)
    current_rows = row_map(current)

    removed_calls = sorted(set(baseline_rows) - set(current_rows))
    for call_name in removed_calls:
        incompatibilities.append(
            {
                "scope": "matrix",
                "call": call_name,
                "reason": "call-removed",
            }
        )

    added_calls = sorted(set(current_rows) - set(baseline_rows))
    for call_name in added_calls:
        compatible_changes.append(
            {
                "scope": "matrix",
                "call": call_name,
                "reason": "call-added",
            }
        )

    for call_name in sorted(set(baseline_rows) & set(current_rows)):
        baseline_row = baseline_rows[call_name]
        current_row = current_rows[call_name]

        for path in STRICT_ROW_FIELDS:
            baseline_value = path_value(baseline_row, path)
            current_value = path_value(current_row, path)
            if baseline_value != current_value:
                incompatibilities.append(
                    {
                        "scope": "matrix",
                        "call": call_name,
                        "reason": "field-changed",
                        "field": ".".join(path),
                        "baseline": baseline_value,
                        "current": current_value,
                    }
                )

        compare_lifecycle_stage(
            call_name,
            baseline_row,
            current_row,
            incompatibilities,
            compatible_changes,
        )

        baseline_classes = row_class_names(baseline_row)
        current_classes = row_class_names(current_row)
        if baseline_classes != current_classes:
            incompatibilities.append(
                {
                    "scope": "matrix",
                    "call": call_name,
                    "reason": "command-classes-changed",
                    "baseline": sorted(baseline_classes),
                    "current": sorted(current_classes),
                }
            )

        baseline_min = path_value(baseline_row, ("abi_version", "minimum"))
        current_min = path_value(current_row, ("abi_version", "minimum"))
        baseline_max = path_value(baseline_row, ("abi_version", "maximum"))
        current_max = path_value(current_row, ("abi_version", "maximum"))
        if isinstance(baseline_min, int) and isinstance(current_min, int) and current_min > baseline_min:
            incompatibilities.append(
                {
                    "scope": "matrix",
                    "call": call_name,
                    "reason": "minimum-abi-increased",
                    "baseline": baseline_min,
                    "current": current_min,
                }
            )
        if isinstance(baseline_max, int) and isinstance(current_max, int):
            if current_max < baseline_max:
                incompatibilities.append(
                    {
                        "scope": "matrix",
                        "call": call_name,
                        "reason": "maximum-abi-decreased",
                        "baseline": baseline_max,
                        "current": current_max,
                    }
                )
            elif current_max > baseline_max:
                compatible_changes.append(
                    {
                        "scope": "matrix",
                        "call": call_name,
                        "reason": "maximum-abi-increased",
                        "baseline": baseline_max,
                        "current": current_max,
                    }
                )

        baseline_schema_name = path_value(baseline_row, ("schema_version", "name"))
        current_schema_name = path_value(current_row, ("schema_version", "name"))
        if baseline_schema_name != current_schema_name:
            incompatibilities.append(
                {
                    "scope": "matrix",
                    "call": call_name,
                    "reason": "schema-macro-changed",
                    "baseline": baseline_schema_name,
                    "current": current_schema_name,
                }
            )
        baseline_schema_value = path_value(baseline_row, ("schema_version", "value"))
        current_schema_value = path_value(current_row, ("schema_version", "value"))
        if isinstance(baseline_schema_value, int) and isinstance(current_schema_value, int):
            if current_schema_value < baseline_schema_value:
                incompatibilities.append(
                    {
                        "scope": "matrix",
                        "call": call_name,
                        "reason": "schema-version-regressed",
                        "baseline": baseline_schema_value,
                        "current": current_schema_value,
                    }
                )
            elif current_schema_value > baseline_schema_value:
                compatible_changes.append(
                    {
                        "scope": "matrix",
                        "call": call_name,
                        "reason": "schema-version-increased",
                        "baseline": baseline_schema_value,
                        "current": current_schema_value,
                    }
                )

        removed_flags = sorted(row_flag_names(baseline_row) - row_flag_names(current_row))
        if removed_flags:
            incompatibilities.append(
                {
                    "scope": "matrix",
                    "call": call_name,
                    "reason": "compatibility-flags-removed",
                    "flags": removed_flags,
                }
            )

        removed_deprecated_fields = sorted(
            row_deprecated_fields(baseline_row) - row_deprecated_fields(current_row)
        )
        if removed_deprecated_fields:
            incompatibilities.append(
                {
                    "scope": "matrix",
                    "call": call_name,
                    "reason": "deprecated-field-removed",
                    "fields": removed_deprecated_fields,
                }
            )


def build_report(
    baseline_path: pathlib.Path,
    current_path: pathlib.Path,
    incompatibilities: list[dict[str, object]],
    compatible_changes: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "tool": {
            "name": "check_standalone_compatibility_changes.py",
            "version": TOOL_VERSION,
        },
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "baseline": str(baseline_path),
        "current": str(current_path),
        "compatible": not incompatibilities,
        "summary": {
            "incompatible_count": len(incompatibilities),
            "compatible_change_count": len(compatible_changes),
        },
        "incompatibilities": incompatibilities,
        "compatible_changes": compatible_changes,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect incompatible changes between standalone compatibility matrix snapshots."
    )
    parser.add_argument("--baseline", required=True, help="Baseline compatibility matrix JSON")
    parser.add_argument("--current", required=True, help="Current compatibility matrix JSON")
    parser.add_argument("--report", help="Optional report output path")
    args = parser.parse_args()

    baseline_path = pathlib.Path(args.baseline).resolve()
    current_path = pathlib.Path(args.current).resolve()
    baseline = read_json(baseline_path)
    current = read_json(current_path)

    incompatibilities: list[dict[str, object]] = []
    compatible_changes: list[dict[str, object]] = []
    compare_registry(baseline, current, incompatibilities, compatible_changes)
    compare_policy(baseline, current, incompatibilities)
    compare_rows(baseline, current, incompatibilities, compatible_changes)

    report = build_report(baseline_path, current_path, incompatibilities, compatible_changes)
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
