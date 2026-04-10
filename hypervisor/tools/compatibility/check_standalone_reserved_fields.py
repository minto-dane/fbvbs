#!/usr/bin/env python3

import argparse
import json
import pathlib
import re
import sys
from dataclasses import dataclass

from generate_operator_tooling_compatibility_matrix import (
    TOOL_VERSION as MATRIX_TOOL_VERSION,
    build_rows,
    collect_defines,
    read_text,
    resolve_repo_root,
)


TOOL_VERSION = 1
REPORT_SCHEMA_VERSION = 1
RESERVED_FLAG = "FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO"


@dataclass(frozen=True)
class EvidenceRule:
    path: str
    patterns: tuple[str, ...]


EVIDENCE_RULES: dict[str, tuple[EvidenceRule, ...]] = {
    "fbvbs_command_page_v1": (
        EvidenceRule(
            path="hypervisor/src/command.c",
            patterns=(
                "static int fbvbs_validate_command_page(",
                "if (page->reserved0 != 0U)",
                "if (reserved_flags != 0U)",
            ),
        ),
    ),
    "fbvbs_diag_command_version_request": (
        EvidenceRule(
            path="hypervisor/src/command.c",
            patterns=(
                "static int handle_diag_negotiate_command_version(",
                "if (request.reserved0 != 0U || request.reserved1 != 0U)",
            ),
        ),
    ),
    "fbvbs_diag_guest_feature_request": (
        EvidenceRule(
            path="hypervisor/src/command.c",
            patterns=(
                "static int handle_diag_negotiate_guest_features(",
                "if (request.reserved0 != 0U)",
            ),
        ),
    ),
    "fbvbs_diag_set_scaling_limits_request": (
        EvidenceRule(
            path="hypervisor/src/core/scaling.c",
            patterns=(
                "int fbvbs_diag_set_scaling_limits(",
                "if (request->reserved0 != 0U || (request->update_mask & ~allowed_mask) != 0U)",
            ),
        ),
    ),
    "fbvbs_storage_pool_create_request": (
        EvidenceRule(
            path="hypervisor/src/storage/storage_virtualization.c",
            patterns=(
                "int fbvbs_storage_create_pool(",
                "if (request->reserved0 != 0U)",
            ),
        ),
    ),
    "fbvbs_storage_vdisk_create_request": (
        EvidenceRule(
            path="hypervisor/src/storage/storage_virtualization.c",
            patterns=(
                "int fbvbs_storage_create_vdisk(",
                "if (request->reserved0 != 0U)",
            ),
        ),
    ),
    "fbvbs_storage_pool_destroy_request": (
        EvidenceRule(
            path="hypervisor/src/storage/storage_virtualization.c",
            patterns=(
                "int fbvbs_storage_destroy_pool(",
                "if (request->reserved0 != 0U || request->reserved1 != 0U)",
            ),
        ),
    ),
    "fbvbs_storage_vdisk_destroy_request": (
        EvidenceRule(
            path="hypervisor/src/storage/storage_virtualization.c",
            patterns=(
                "int fbvbs_storage_destroy_vdisk(",
                "if (request->reserved0 != 0U || request->reserved1 != 0U)",
            ),
        ),
    ),
}


def collect_struct_bodies(header_text: str) -> dict[str, str]:
    pattern = re.compile(
        r"struct\s+(fbvbs_[A-Za-z0-9_]+)\s*\{(?P<body>.*?)\};",
        re.DOTALL,
    )
    return {match.group(1): match.group("body") for match in pattern.finditer(header_text)}


def collect_reserved_fields(struct_body: str) -> list[str]:
    fields: list[str] = []
    for raw_line in struct_body.splitlines():
        line = raw_line.strip().rstrip(";")
        if not line or "reserved" not in line:
            continue
        field_name = line.split()[-1]
        fields.append(field_name)
    return fields


def build_report(repo_root: pathlib.Path) -> dict[str, object]:
    header_path = repo_root / "hypervisor" / "include" / "fbvbs_abi.h"
    header_text = read_text(header_path)
    struct_bodies = collect_struct_bodies(header_text)
    symbols = collect_defines(header_path)
    matrix_rows = build_rows(symbols)
    source_cache: dict[str, str] = {}
    report_rows: list[dict[str, object]] = []

    def source_text(path: str) -> str:
        if path not in source_cache:
            source_cache[path] = read_text(repo_root / path)
        return source_cache[path]

    standalone_request_types = {
        row.request_type
        for row in matrix_rows
        if row.request_type is not None
    }
    standalone_request_types.add("fbvbs_command_page_v1")

    for request_type in sorted(standalone_request_types):
        struct_body = struct_bodies.get(request_type)
        if struct_body is None:
            continue
        reserved_fields = collect_reserved_fields(struct_body)
        if not reserved_fields:
            continue

        related_rows = [
            row for row in matrix_rows
            if row.request_type == request_type
        ]
        compatibility_ok = True
        if related_rows:
            compatibility_ok = all(
                RESERVED_FLAG in row.compatibility_flag_macros
                for row in related_rows
            )

        evidence_rules = EVIDENCE_RULES.get(request_type, ())
        evidence_payload: list[dict[str, object]] = []
        runtime_ok = bool(evidence_rules)
        for rule in evidence_rules:
            text = source_text(rule.path)
            missing_patterns = [pattern for pattern in rule.patterns if pattern not in text]
            evidence_payload.append(
                {
                    "path": rule.path,
                    "patterns": list(rule.patterns),
                    "missing_patterns": missing_patterns,
                    "status": "ok" if not missing_patterns else "missing",
                }
            )
            if missing_patterns:
                runtime_ok = False

        report_rows.append(
            {
                "request_type": request_type,
                "reserved_fields": reserved_fields,
                "call_rows": [row.call_macro for row in related_rows],
                "compatibility_flag_present": compatibility_ok,
                "runtime_enforced": runtime_ok,
                "evidence": evidence_payload,
            }
        )

    failures = [
        row["request_type"]
        for row in report_rows
        if not row["compatibility_flag_present"] or not row["runtime_enforced"]
    ]
    return {
        "tool_version": TOOL_VERSION,
        "matrix_tool_version": MATRIX_TOOL_VERSION,
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "reserved_flag_name": RESERVED_FLAG,
        "summary": {
            "target_count": len(report_rows),
            "failure_count": len(failures),
            "failed_request_types": failures,
        },
        "rows": report_rows,
    }


def render_markdown(report: dict[str, object]) -> str:
    lines = [
        "# Standalone Reserved Field Enforcement Report",
        "",
        f"- report schema version: `{report['report_schema_version']}`",
        f"- target count: `{report['summary']['target_count']}`",
        f"- failure count: `{report['summary']['failure_count']}`",
        "",
        "| Request Type | Calls | Reserved Fields | Compatibility Flag | Runtime Enforcement |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in report["rows"]:
        calls = ", ".join(row["call_rows"]) if row["call_rows"] else "command-page invariant"
        fields = ", ".join(row["reserved_fields"])
        compat = "yes" if row["compatibility_flag_present"] else "no"
        runtime = "yes" if row["runtime_enforced"] else "no"
        lines.append(
            f"| `{row['request_type']}` | `{calls}` | `{fields}` | `{compat}` | `{runtime}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify standalone ABI reserved-field discipline and runtime enforcement."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write the report into")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    repo_root = resolve_repo_root(script_path)
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    report = build_report(repo_root)
    (output_dir / "standalone-reserved-field-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "standalone-reserved-field-report.md").write_text(
        render_markdown(report) + "\n",
        encoding="utf-8",
    )

    if report["summary"]["failure_count"] != 0:
        sys.stderr.write("reserved-field enforcement report contains failures\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
