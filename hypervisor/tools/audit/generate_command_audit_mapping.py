#!/usr/bin/env python3

import argparse
import ast
import datetime
import json
import pathlib
import re
from dataclasses import dataclass


TOOL_VERSION = 1
MAPPING_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class AuditMappingRow:
    call_macro: str
    category: str
    audit_event_macros: tuple[str, ...]
    payload_type: str | None
    trigger: str
    source_file: str
    notes: tuple[str, ...] = ()


def resolve_repo_root(script_path: pathlib.Path) -> pathlib.Path:
    return script_path.resolve().parents[3]


def read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*$", "", text, flags=re.MULTILINE)
    return text


def normalize_expression(expr: str) -> str:
    expr = expr.strip()
    expr = re.sub(r"\bUINT(8|16|32|64)_C\s*\(", "(", expr)
    expr = re.sub(r"\b(0x[0-9A-Fa-f]+|\d+)(?:[uUlL]+)\b", r"\1", expr)
    return expr


def evaluate_ast(node: ast.AST, symbols: dict[str, int]) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return int(node.value)
    if isinstance(node, ast.Name):
        return int(symbols[node.id])
    if isinstance(node, ast.BinOp):
        left = evaluate_ast(node.left, symbols)
        right = evaluate_ast(node.right, symbols)
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.LShift):
            return left << right
    raise ValueError(f"unsupported expression: {ast.dump(node, include_attributes=False)}")


def evaluate_define_expression(expr: str, symbols: dict[str, int]) -> int:
    tree = ast.parse(normalize_expression(expr), mode="eval")
    return evaluate_ast(tree.body, symbols)


def collect_defines(header_path: pathlib.Path) -> dict[str, int]:
    defines: dict[str, int] = {}
    lines = strip_comments(read_text(header_path)).splitlines()
    index = 0
    while index < len(lines):
        line = lines[index].rstrip()
        index += 1
        if not line.startswith("#define "):
            continue
        while line.endswith("\\") and index < len(lines):
            line = line[:-1].rstrip() + " " + lines[index].strip()
            index += 1
        tokens = line.split(None, 2)
        if len(tokens) < 3:
            continue
        name = tokens[1]
        expr = tokens[2].strip()
        if "(" in name or expr.startswith("/*"):
            continue
        defines[name] = evaluate_define_expression(expr, defines)
    return defines


def build_rows() -> list[AuditMappingRow]:
    policy_only_notes = (
        "policy deny / replay / rate-limit paths emit FBVBS_EVENT_POLICY_DENY via command.c",
    )
    return [
        AuditMappingRow(
            call_macro="FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION",
            category="diagnostic",
            audit_event_macros=("FBVBS_EVENT_POLICY_DENY",),
            payload_type="fbvbs_audit_policy_deny_event",
            trigger="deny-only",
            source_file="hypervisor/src/command.c",
            notes=policy_only_notes,
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES",
            category="diagnostic",
            audit_event_macros=("FBVBS_EVENT_POLICY_DENY",),
            payload_type="fbvbs_audit_policy_deny_event",
            trigger="deny-only",
            source_file="hypervisor/src/command.c",
            notes=policy_only_notes,
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_VM_ASSIGN_DEVICE",
            category="vm",
            audit_event_macros=(
                "FBVBS_EVENT_VM_DEVICE_ASSIGN",
                "FBVBS_EVENT_VM_PLATFORM_GATE",
                "FBVBS_EVENT_IOMMU_DOMAIN_CREATE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_device_assignment_event",
            trigger="success-and-platform-gate",
            source_file="hypervisor/src/partition.c",
            notes=("platform capability denial emits FBVBS_EVENT_VM_PLATFORM_GATE",),
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_VM_RELEASE_DEVICE",
            category="vm",
            audit_event_macros=(
                "FBVBS_EVENT_VM_DEVICE_RELEASE",
                "FBVBS_EVENT_IOMMU_DOMAIN_RELEASE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_device_assignment_event",
            trigger="success-and-release",
            source_file="hypervisor/src/partition.c",
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_OCS_VCD_ATTACH",
            category="control",
            audit_event_macros=(
                "FBVBS_EVENT_VCD_STATE_CHANGE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_vcd_event",
            trigger="success-and-status-change",
            source_file="hypervisor/src/io/vcd_virtualization.c",
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_OCS_VCD_STATUS",
            category="control",
            audit_event_macros=("FBVBS_EVENT_POLICY_DENY",),
            payload_type="fbvbs_audit_policy_deny_event",
            trigger="deny-only",
            source_file="hypervisor/src/command.c",
            notes=policy_only_notes,
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_STORAGE_CREATE_POOL",
            category="storage",
            audit_event_macros=(
                "FBVBS_EVENT_STORAGE_POOL_CHANGE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_storage_event",
            trigger="success-and-fail-close",
            source_file="hypervisor/src/storage/storage_virtualization.c",
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_STORAGE_DESTROY_POOL",
            category="storage",
            audit_event_macros=(
                "FBVBS_EVENT_STORAGE_POOL_CHANGE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_storage_event",
            trigger="success-and-fail-close",
            source_file="hypervisor/src/storage/storage_virtualization.c",
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_STORAGE_CREATE_VDISK",
            category="storage",
            audit_event_macros=(
                "FBVBS_EVENT_STORAGE_VDISK_CHANGE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_storage_event",
            trigger="success-and-fail-close",
            source_file="hypervisor/src/storage/storage_virtualization.c",
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_STORAGE_DESTROY_VDISK",
            category="storage",
            audit_event_macros=(
                "FBVBS_EVENT_STORAGE_VDISK_CHANGE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_storage_event",
            trigger="success-and-fail-close",
            source_file="hypervisor/src/storage/storage_virtualization.c",
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_STORAGE_ATTACH_VDISK",
            category="storage",
            audit_event_macros=(
                "FBVBS_EVENT_STORAGE_VDISK_CHANGE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_storage_event",
            trigger="success-and-fail-close",
            source_file="hypervisor/src/storage/storage_virtualization.c",
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_STORAGE_DETACH_VDISK",
            category="storage",
            audit_event_macros=(
                "FBVBS_EVENT_STORAGE_VDISK_CHANGE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_storage_event",
            trigger="success-and-fail-close",
            source_file="hypervisor/src/storage/storage_virtualization.c",
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_STORAGE_GET_POOL_STATUS",
            category="storage",
            audit_event_macros=(
                "FBVBS_EVENT_STORAGE_POOL_CHANGE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_storage_event",
            trigger="read-and-fail-close",
            source_file="hypervisor/src/storage/storage_virtualization.c",
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_STORAGE_GET_VDISK_STATUS",
            category="storage",
            audit_event_macros=(
                "FBVBS_EVENT_STORAGE_VDISK_CHANGE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_storage_event",
            trigger="read-and-fail-close",
            source_file="hypervisor/src/storage/storage_virtualization.c",
        ),
        AuditMappingRow(
            call_macro="FBVBS_CALL_STORAGE_SET_VDISK_QOS",
            category="storage",
            audit_event_macros=(
                "FBVBS_EVENT_STORAGE_VDISK_CHANGE",
                "FBVBS_EVENT_POLICY_DENY",
            ),
            payload_type="fbvbs_audit_storage_event",
            trigger="mutation-and-fail-close",
            source_file="hypervisor/src/storage/storage_virtualization.c",
        ),
    ]


def row_to_dict(symbols: dict[str, int], row: AuditMappingRow) -> dict[str, object]:
    return {
        "category": row.category,
        "call": {
            "name": row.call_macro,
            "id": symbols[row.call_macro],
            "hex": f"0x{symbols[row.call_macro]:04X}",
        },
        "audit_events": [
            {
                "name": macro,
                "id": symbols[macro],
                "hex": f"0x{symbols[macro]:04X}",
            }
            for macro in row.audit_event_macros
        ],
        "payload_type": row.payload_type,
        "trigger": row.trigger,
        "source_file": row.source_file,
        "notes": list(row.notes),
    }


def build_markdown(rows: list[dict[str, object]]) -> str:
    lines = [
        "# Command To Audit Mapping",
        "",
        "| Category | Call | Events | Payload | Trigger | Source |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        events = ", ".join(event["name"] for event in row["audit_events"])
        lines.append(
            f"| {row['category']} | `{row['call']['name']}` | {events} | `{row['payload_type']}` | {row['trigger']} | `{row['source_file']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate deterministic standalone command-to-audit mapping artifacts."
    )
    parser.add_argument("--output-dir", required=True, help="Directory for generated JSON and Markdown")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    repo_root = resolve_repo_root(script_path)
    header_path = repo_root / "hypervisor" / "include" / "fbvbs_abi.h"
    output_dir = pathlib.Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = (pathlib.Path.cwd() / output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    symbols = collect_defines(header_path)
    rows = [row_to_dict(symbols, row) for row in build_rows()]
    payload = {
        "tool": {"name": "generate_command_audit_mapping.py", "version": TOOL_VERSION},
        "mapping_schema_version": MAPPING_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_files": {
            "header": str(header_path.relative_to(repo_root)),
            "docs": [
                "plan/standalone/implementation/standalone-implementation-plan.md",
            ],
        },
        "rows": rows,
        "summary": {
            "row_count": len(rows),
            "policy_deny_mapped_call_count": sum(
                1
                for row in rows
                if any(event["name"] == "FBVBS_EVENT_POLICY_DENY" for event in row["audit_events"])
            ),
        },
    }
    json_path = output_dir / "command-audit-mapping.json"
    md_path = output_dir / "command-audit-mapping.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(build_markdown(rows), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
