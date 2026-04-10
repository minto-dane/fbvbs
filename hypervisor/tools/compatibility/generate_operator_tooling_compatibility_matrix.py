#!/usr/bin/env python3

import argparse
import ast
import datetime
import json
import pathlib
import re
from dataclasses import dataclass


TOOL_VERSION = 1
MATRIX_SCHEMA_VERSION = 1
DEPRECATED_FIELD_POLICY_VERSION = 1


@dataclass(frozen=True)
class MatrixRow:
    category: str
    call_macro: str
    request_type: str | None
    response_type: str | None
    notes: tuple[str, ...]
    schema_version_macro: str | None
    compatibility_flag_macros: tuple[str, ...]
    command_class_macros: tuple[str, ...]
    service_kind_macro: str
    capability_macro: str
    min_abi_version: int = 1
    max_abi_version: int = 1
    negotiation_status: str = "exact"
    lifecycle_stage: str = "stable"
    deprecated_fields: tuple[str, ...] = ()


def resolve_repo_root(script_path: pathlib.Path) -> pathlib.Path:
    return script_path.resolve().parents[3]


def read_text(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    text = re.sub(r"//.*$", "", text, flags=re.MULTILINE)
    return text


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
        if "(" in name:
            continue
        if expr.startswith("/*"):
            continue
        defines[name] = evaluate_define_expression(expr, defines)

    return defines


def normalize_expression(expr: str) -> str:
    expr = expr.strip()
    expr = re.sub(r"\bUINT(8|16|32|64)_C\s*\(", "(", expr)
    expr = re.sub(r"\b(0x[0-9A-Fa-f]+|\d+)(?:[uUlL]+)\b", r"\1", expr)
    return expr


def evaluate_ast(node: ast.AST, symbols: dict[str, int]) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return int(node.value)
    if isinstance(node, ast.Name):
        if node.id not in symbols:
            raise KeyError(node.id)
        return int(symbols[node.id])
    if isinstance(node, ast.UnaryOp):
        operand = evaluate_ast(node.operand, symbols)
        if isinstance(node.op, ast.UAdd):
            return +operand
        if isinstance(node.op, ast.USub):
            return -operand
        if isinstance(node.op, ast.Invert):
            return ~operand
    if isinstance(node, ast.BinOp):
        left = evaluate_ast(node.left, symbols)
        right = evaluate_ast(node.right, symbols)
        if isinstance(node.op, ast.BitOr):
            return left | right
        if isinstance(node.op, ast.BitAnd):
            return left & right
        if isinstance(node.op, ast.BitXor):
            return left ^ right
        if isinstance(node.op, ast.LShift):
            return left << right
        if isinstance(node.op, ast.RShift):
            return left >> right
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.FloorDiv):
            return left // right
    raise ValueError(f"unsupported expression: {ast.dump(node, include_attributes=False)}")


def evaluate_define_expression(expr: str, symbols: dict[str, int]) -> int:
    normalized = normalize_expression(expr)
    if normalized.startswith("(") and normalized.endswith(")"):
        normalized = normalized[1:-1].strip()
    tree = ast.parse(normalized, mode="eval")
    return evaluate_ast(tree.body, symbols)


def hex_u64(value: int) -> str:
    return f"0x{value:016X}"


def build_rows(symbols: dict[str, int]) -> list[MatrixRow]:
    return [
        MatrixRow(
            category="health",
            call_macro="FBVBS_CALL_PARTITION_GET_STATUS",
            request_type="fbvbs_partition_id_request",
            response_type="fbvbs_partition_status_response",
            notes=(
                "health_state is part of the stable operator-facing partition status view",
            ),
            schema_version_macro="FBVBS_HEALTH_SCHEMA_VERSION",
            compatibility_flag_macros=(
                "FBVBS_COMPAT_FLAG_HEALTH_SCHEMA_STABLE",
                "FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",
            ),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_PARTITION_MANAGE",
        ),
        MatrixRow(
            category="health",
            call_macro="FBVBS_CALL_DIAG_GET_PARTITION_LIST",
            request_type=None,
            response_type="fbvbs_diag_partition_list_response",
            notes=(
                "partition list exposes the stable partition diagnostics layout",
            ),
            schema_version_macro="FBVBS_HEALTH_SCHEMA_VERSION",
            compatibility_flag_macros=(
                "FBVBS_COMPAT_FLAG_PARTITION_DIAGNOSTICS_STABLE",
                "FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",
            ),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_AUDIT_DIAG",
        ),
        MatrixRow(
            category="diagnostic",
            call_macro="FBVBS_CALL_DIAG_GET_REASON_GUIDANCE",
            request_type="fbvbs_diag_reason_guidance_request",
            response_type="fbvbs_diag_reason_guidance_response",
            notes=(
                "deny / fault / health guidance is the primary operator remediation view",
            ),
            schema_version_macro="FBVBS_GUIDANCE_SCHEMA_VERSION",
            compatibility_flag_macros=(
                "FBVBS_COMPAT_FLAG_FAILURE_MODE_GUIDANCE_STABLE",
                "FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",
            ),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_AUDIT_DIAG",
        ),
        MatrixRow(
            category="diagnostic",
            call_macro="FBVBS_CALL_DIAG_GET_INVENTORY",
            request_type=None,
            response_type="fbvbs_diag_inventory_response",
            notes=("inventory counts power the one-screen operator summary",),
            schema_version_macro="FBVBS_INVENTORY_SCHEMA_VERSION",
            compatibility_flag_macros=("FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_AUDIT_DIAG",
        ),
        MatrixRow(
            category="diagnostic",
            call_macro="FBVBS_CALL_DIAG_GET_FAULT_RECORD",
            request_type="fbvbs_partition_id_request",
            response_type="fbvbs_diag_fault_record_response",
            notes=("latest partition fault and remediation guidance are stable",),
            schema_version_macro="FBVBS_FAULT_RECORD_SCHEMA_VERSION",
            compatibility_flag_macros=("FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_AUDIT_DIAG",
        ),
        MatrixRow(
            category="diagnostic",
            call_macro="FBVBS_CALL_PARTITION_GET_FAULT_INFO",
            request_type="fbvbs_partition_id_request",
            response_type="fbvbs_partition_fault_info_response",
            notes=(
                "partition fault info mirrors the structured fault record schema",
            ),
            schema_version_macro="FBVBS_FAULT_RECORD_SCHEMA_VERSION",
            compatibility_flag_macros=(
                "FBVBS_COMPAT_FLAG_PARTITION_FAULT_INFO_STABLE",
                "FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",
            ),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_PARTITION_MANAGE",
        ),
        MatrixRow(
            category="diagnostic",
            call_macro="FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY",
            request_type=None,
            response_type="fbvbs_diag_schema_registry_response",
            notes=("schema registry is the compatibility fixed point for tooling",),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=(
                "FBVBS_COMPAT_FLAG_HEALTH_SCHEMA_STABLE",
                "FBVBS_COMPAT_FLAG_AUDIT_SCHEMA_STABLE",
                "FBVBS_COMPAT_FLAG_FAILURE_MODE_GUIDANCE_STABLE",
                "FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",
                "FBVBS_COMPAT_FLAG_PARTITION_DIAGNOSTICS_STABLE",
                "FBVBS_COMPAT_FLAG_PARTITION_FAULT_INFO_STABLE",
            ),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_AUDIT_DIAG",
        ),
        MatrixRow(
            category="diagnostic",
            call_macro="FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION",
            request_type="fbvbs_diag_command_version_request",
            response_type="fbvbs_diag_command_version_response",
            notes=(
                "target-call negotiation exposes ABI version, class, capability, and feature flags",
            ),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=(
                "FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",
            ),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_AUDIT_DIAG",
        ),
        MatrixRow(
            category="diagnostic",
            call_macro="FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES",
            request_type="fbvbs_diag_guest_feature_request",
            response_type="fbvbs_diag_guest_feature_response",
            notes=(
                "guest feature bitmap negotiation exposes the standalone guest profile and runtime capability gating",
            ),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=(
                "FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",
            ),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_AUDIT_DIAG",
        ),
        MatrixRow(
            category="diagnostic",
            call_macro="FBVBS_CALL_DIAG_GET_SCALING_LIMITS",
            request_type=None,
            response_type="fbvbs_diag_scaling_limits_response",
            notes=("scaling summary is operator-readable and versioned with diagnostics",),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=("FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_SCALE_MANAGE",
        ),
        MatrixRow(
            category="diagnostic",
            call_macro="FBVBS_CALL_DIAG_SET_SCALING_LIMITS",
            request_type="fbvbs_diag_set_scaling_limits_request",
            response_type="fbvbs_diag_scaling_limits_response",
            notes=("runtime scaling limits remain operator-managed and reserved-zero stable",),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=("FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_SCALE_MANAGE",
        ),
        MatrixRow(
            category="control",
            call_macro="FBVBS_CALL_OCS_VCD_ATTACH",
            request_type="fbvbs_ocs_vcd_attach_request",
            response_type=None,
            notes=("optional OCS transport substrate remains capability gated",),
            schema_version_macro=None,
            compatibility_flag_macros=(),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION", "FBVBS_COMMAND_CLASS_SERVICE"),
            service_kind_macro="SERVICE_KIND_OCS",
            capability_macro="FBVBS_CAP_OCS_ACCESS",
        ),
        MatrixRow(
            category="control",
            call_macro="FBVBS_CALL_OCS_VCD_STATUS",
            request_type=None,
            response_type="fbvbs_ocs_vcd_status_response",
            notes=("status is owner-bound and fail-closed on mismatch",),
            schema_version_macro=None,
            compatibility_flag_macros=(),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION", "FBVBS_COMMAND_CLASS_SERVICE"),
            service_kind_macro="SERVICE_KIND_OCS",
            capability_macro="FBVBS_CAP_OCS_ACCESS",
        ),
        MatrixRow(
            category="storage",
            call_macro="FBVBS_CALL_STORAGE_CREATE_POOL",
            request_type="fbvbs_storage_pool_create_request",
            response_type="fbvbs_storage_pool_create_response",
            notes=("storage pool creation is a stable host-only management ABI",),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=("FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_STORAGE_MANAGE",
        ),
        MatrixRow(
            category="storage",
            call_macro="FBVBS_CALL_STORAGE_GET_POOL_STATUS",
            request_type="fbvbs_storage_pool_request",
            response_type="fbvbs_storage_pool_status_response",
            notes=("storage pool status is part of the standalone operator inventory surface",),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=("FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_STORAGE_MANAGE",
        ),
        MatrixRow(
            category="storage",
            call_macro="FBVBS_CALL_STORAGE_CREATE_VDISK",
            request_type="fbvbs_storage_vdisk_create_request",
            response_type="fbvbs_storage_vdisk_create_response",
            notes=("virtual disk creation keeps reserved-zero stable for tooling safety",),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=("FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_STORAGE_MANAGE",
        ),
        MatrixRow(
            category="storage",
            call_macro="FBVBS_CALL_STORAGE_DESTROY_POOL",
            request_type="fbvbs_storage_pool_destroy_request",
            response_type=None,
            notes=(
                "destroy-pool requires session correlation and confirmation digest artifact binding",
            ),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=("FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_STORAGE_MANAGE",
        ),
        MatrixRow(
            category="storage",
            call_macro="FBVBS_CALL_STORAGE_DESTROY_VDISK",
            request_type="fbvbs_storage_vdisk_destroy_request",
            response_type=None,
            notes=(
                "destroy-vdisk requires session correlation and confirmation digest artifact binding",
            ),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=("FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_STORAGE_MANAGE",
        ),
        MatrixRow(
            category="storage",
            call_macro="FBVBS_CALL_STORAGE_GET_VDISK_STATUS",
            request_type="fbvbs_storage_vdisk_request",
            response_type="fbvbs_storage_vdisk_status_response",
            notes=("virtual disk status remains stable for operator consoles and exports",),
            schema_version_macro="FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION",
            compatibility_flag_macros=("FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",),
            command_class_macros=("FBVBS_COMMAND_CLASS_HOST_PARTITION",),
            service_kind_macro="SERVICE_KIND_NONE",
            capability_macro="FBVBS_CAP_STORAGE_MANAGE",
        ),
    ]


def format_flags(symbols: dict[str, int], macros: tuple[str, ...]) -> list[dict[str, object]]:
    return [
        {"name": macro, "value": symbols[macro], "hex": hex_u64(symbols[macro])}
        for macro in macros
    ]


def row_to_dict(symbols: dict[str, int], row: MatrixRow) -> dict[str, object]:
    command_class_flags = 0
    for macro in row.command_class_macros:
        command_class_flags |= symbols[macro]

    data: dict[str, object] = {
        "category": row.category,
        "call": {
            "name": row.call_macro,
            "id": symbols[row.call_macro],
            "hex": f"0x{symbols[row.call_macro]:04X}",
        },
        "request_type": row.request_type,
        "response_type": row.response_type,
        "abi_version": {
            "minimum": row.min_abi_version,
            "maximum": row.max_abi_version,
            "negotiation_status": row.negotiation_status,
        },
        "command_class_flags": {
            "names": list(row.command_class_macros),
            "value": command_class_flags,
            "hex": hex_u64(command_class_flags),
        },
        "service_kind": {
            "name": row.service_kind_macro,
            "value": symbols[row.service_kind_macro],
            "hex": hex_u64(symbols[row.service_kind_macro]),
        },
        "required_capability": {
            "name": row.capability_macro,
            "value": symbols[row.capability_macro],
            "hex": hex_u64(symbols[row.capability_macro]),
        },
        "compatibility_flags": format_flags(symbols, row.compatibility_flag_macros),
        "lifecycle": {
            "stage": row.lifecycle_stage,
            "deprecated_fields": list(row.deprecated_fields),
        },
        "notes": list(row.notes),
    }
    if row.schema_version_macro is not None:
        data["schema_version"] = {
            "name": row.schema_version_macro,
            "value": symbols[row.schema_version_macro],
            "hex": hex_u64(symbols[row.schema_version_macro]),
        }
    else:
        data["schema_version"] = None
    return data


def build_markdown(matrix: list[dict[str, object]], symbols: dict[str, int]) -> str:
    lines = [
        "# Operator Tooling Compatibility Matrix",
        "",
        "Generated from `hypervisor/include/fbvbs_abi.h` and the standalone diagnostic plan docs.",
        "",
        "## Schema Registry",
        "",
        "| Field | Value |",
        "|---|---:|",
        f"| management ABI version | {symbols['FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION']} |",
        f"| health schema version | {symbols['FBVBS_HEALTH_SCHEMA_VERSION']} |",
        f"| audit schema version | {symbols['FBVBS_AUDIT_SCHEMA_VERSION']} |",
        f"| inventory schema version | {symbols['FBVBS_INVENTORY_SCHEMA_VERSION']} |",
        f"| guidance schema version | {symbols['FBVBS_GUIDANCE_SCHEMA_VERSION']} |",
        f"| fault record schema version | {symbols['FBVBS_FAULT_RECORD_SCHEMA_VERSION']} |",
        f"| compatibility flags | {hex_u64(symbols['FBVBS_COMPAT_FLAG_HEALTH_SCHEMA_STABLE'] | symbols['FBVBS_COMPAT_FLAG_AUDIT_SCHEMA_STABLE'] | symbols['FBVBS_COMPAT_FLAG_FAILURE_MODE_GUIDANCE_STABLE'] | symbols['FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO'] | symbols['FBVBS_COMPAT_FLAG_PARTITION_DIAGNOSTICS_STABLE'] | symbols['FBVBS_COMPAT_FLAG_PARTITION_FAULT_INFO_STABLE'])} |",
        "",
        "## Deprecated Field Policy",
        "",
        "- Fields are append-only within the current management ABI major version.",
        "- Reserved fields remain zero until promoted by a schema-versioned extension.",
        "- Deprecated fields must not be repurposed or removed in a minor upgrade.",
        "",
        "## Matrix",
        "",
        "| Category | Call | ID | ABI | Class | Service | Capability | Schema | Lifecycle | Compatibility | Notes |",
        "|---|---|---:|---:|---|---|---|---|---|---|---|",
    ]
    for row in matrix:
        compat = ", ".join(flag["name"] for flag in row["compatibility_flags"]) or "-"
        notes = "; ".join(row["notes"]) if row["notes"] else "-"
        schema = row["schema_version"]["name"] if row["schema_version"] else "-"
        lifecycle = row["lifecycle"]["stage"]
        if row["lifecycle"]["deprecated_fields"]:
            lifecycle = f"{lifecycle} (deprecated: {', '.join(row['lifecycle']['deprecated_fields'])})"
        lines.append(
            "| {category} | `{call}` | `{id}` | {abi}..{abi_max} | {class_flags} | `{service}` | `{cap}` | `{schema}` | {lifecycle} | {compat} | {notes} |".format(
                category=row["category"],
                call=row["call"]["name"],
                id=row["call"]["hex"],
                abi=row["abi_version"]["minimum"],
                abi_max=row["abi_version"]["maximum"],
                class_flags=", ".join(row["command_class_flags"]["names"]),
                service=row["service_kind"]["name"],
                cap=row["required_capability"]["name"],
                schema=schema,
                lifecycle=lifecycle,
                compat=compat,
                notes=notes,
            )
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the standalone operator tooling compatibility matrix."
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
    rows = [row_to_dict(symbols, row) for row in build_rows(symbols)]
    output_json = {
        "tool": {"name": "generate_operator_tooling_compatibility_matrix.py", "version": TOOL_VERSION},
        "matrix_schema_version": MATRIX_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_files": {
            "header": str(header_path.relative_to(repo_root)),
            "docs": [
                "plan/standalone/implementation/standalone-implementation-plan.md",
                "plan/standalone/assurance/management-diagnostics-abi.md",
                "plan/standalone/assurance/compatibility-and-versioning.md",
                "plan/standalone/operations/operator-control-plane.md",
            ],
        },
        "schema_registry": {
            "management_abi_version": symbols["FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION"],
            "health_schema_version": symbols["FBVBS_HEALTH_SCHEMA_VERSION"],
            "audit_schema_version": symbols["FBVBS_AUDIT_SCHEMA_VERSION"],
            "inventory_schema_version": symbols["FBVBS_INVENTORY_SCHEMA_VERSION"],
            "guidance_schema_version": symbols["FBVBS_GUIDANCE_SCHEMA_VERSION"],
            "fault_record_schema_version": symbols["FBVBS_FAULT_RECORD_SCHEMA_VERSION"],
            "compatibility_flags": {
                "names": [
                    "FBVBS_COMPAT_FLAG_HEALTH_SCHEMA_STABLE",
                    "FBVBS_COMPAT_FLAG_AUDIT_SCHEMA_STABLE",
                    "FBVBS_COMPAT_FLAG_FAILURE_MODE_GUIDANCE_STABLE",
                    "FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO",
                    "FBVBS_COMPAT_FLAG_PARTITION_DIAGNOSTICS_STABLE",
                    "FBVBS_COMPAT_FLAG_PARTITION_FAULT_INFO_STABLE",
                ],
                "value": symbols["FBVBS_COMPAT_FLAG_HEALTH_SCHEMA_STABLE"]
                | symbols["FBVBS_COMPAT_FLAG_AUDIT_SCHEMA_STABLE"]
                | symbols["FBVBS_COMPAT_FLAG_FAILURE_MODE_GUIDANCE_STABLE"]
                | symbols["FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO"]
                | symbols["FBVBS_COMPAT_FLAG_PARTITION_DIAGNOSTICS_STABLE"]
                | symbols["FBVBS_COMPAT_FLAG_PARTITION_FAULT_INFO_STABLE"],
                "hex": hex_u64(
                    symbols["FBVBS_COMPAT_FLAG_HEALTH_SCHEMA_STABLE"]
                    | symbols["FBVBS_COMPAT_FLAG_AUDIT_SCHEMA_STABLE"]
                    | symbols["FBVBS_COMPAT_FLAG_FAILURE_MODE_GUIDANCE_STABLE"]
                    | symbols["FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO"]
                    | symbols["FBVBS_COMPAT_FLAG_PARTITION_DIAGNOSTICS_STABLE"]
                    | symbols["FBVBS_COMPAT_FLAG_PARTITION_FAULT_INFO_STABLE"]
                ),
            },
        },
        "deprecated_field_policy": {
            "policy_schema_version": DEPRECATED_FIELD_POLICY_VERSION,
            "append_only_within_major": True,
            "reserved_fields_must_be_zero": True,
            "removal_requires_major_version": True,
            "deprecated_fields_must_not_be_repurposed": True,
            "deprecated_fields_must_remain_accepted": True,
            "notes": [
                "Current standalone management ABI exports no deprecated fields.",
                "Future deprecations must remain machine-declared in lifecycle.deprecated_fields until the next major ABI.",
            ],
        },
        "matrix": rows,
        "summary": {
            "row_count": len(rows),
            "diagnostic_row_count": sum(1 for row in rows if row["category"] == "diagnostic"),
            "control_row_count": sum(1 for row in rows if row["category"] == "control"),
        },
    }

    json_path = output_dir / "operator-tooling-compatibility-matrix.json"
    md_path = output_dir / "operator-tooling-compatibility-matrix.md"
    json_path.write_text(json.dumps(output_json, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(build_markdown(rows, symbols), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
