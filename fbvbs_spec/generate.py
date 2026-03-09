from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict
from pathlib import Path

from .models import CStructLayout, FrozenSpec, NamedValue, StructField
from .parser import parse_spec_document
from .validate import ensure_valid


def generate_outputs(source_path: str | Path, output_dir: str | Path) -> FrozenSpec:
    spec = parse_spec_document(source_path)
    ensure_valid(spec)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    (output_path / "bindings").mkdir(parents=True, exist_ok=True)

    write_json(output_path / "spec.json", asdict(spec))
    write_json(output_path / "requirements.json", [asdict(item) for item in spec.requirements])
    write_json(output_path / "abi.json", build_abi_payload(spec))
    write_json(output_path / "protected_structures.json", [asdict(item) for item in spec.protected_structures])
    write_json(output_path / "service_failure_matrix.json", [asdict(item) for item in spec.service_failures])
    write_json(
        output_path / "performance_budget.json",
        {
            "baseline": [asdict(item) for item in spec.performance_reference],
            "targets": [asdict(item) for item in spec.performance_targets],
        },
    )
    write_json(output_path / "roadmap.json", [asdict(item) for item in spec.roadmap_increments])
    write_json(output_path / "partition_state_machine.json", [asdict(item) for item in spec.partition_transitions])
    write_csv_requirements(output_path / "requirements.csv", spec)
    (output_path / "partition_state_machine.dot").write_text(render_partition_fsm_dot(spec), encoding="utf-8")
    (output_path / "bindings" / "fbvbs_abi_v1.h").write_text(render_c_header(spec), encoding="utf-8")
    (output_path / "bindings" / "fbvbs_abi_v1.rs").write_text(render_rust_bindings(spec), encoding="utf-8")

    return spec


def build_abi_payload(spec: FrozenSpec) -> dict[str, object]:
    return {
        "layouts": [asdict(item) for item in spec.layouts],
        "command_flags": [asdict(item) for item in spec.command_flags],
        "command_states": [asdict(item) for item in spec.command_states],
        "frozen_enumerations": [asdict(item) for item in spec.frozen_enumerations],
        "additional_fixed_rules": [asdict(item) for item in spec.additional_fixed_rules],
        "object_namespaces": [asdict(item) for item in spec.object_namespaces],
        "payload_rules": [asdict(item) for item in spec.payload_rules],
        "manifest_rules": list(spec.manifest_rules),
        "loader_rules": list(spec.loader_rules),
        "vm_exit_layouts": [asdict(item) for item in spec.vm_exit_layouts],
        "call_categories": [asdict(item) for item in spec.call_categories],
        "hypercalls": [asdict(item) for item in spec.hypercalls],
        "error_codes": [asdict(item) for item in spec.error_codes],
    }


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def write_csv_requirements(path: Path, spec: FrozenSpec) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "requirement_id",
                "subsection",
                "text",
                "verification_phrase",
                "verification_labels",
                "verification_classes",
                "requirement_types",
                "source_sections",
                "target_components",
                "status",
                "test_id",
                "evidence_id",
            ]
        )
        for requirement in spec.requirements:
            writer.writerow(
                [
                    requirement.requirement_id,
                    requirement.subsection,
                    requirement.text,
                    requirement.verification_phrase,
                    "|".join(requirement.verification_labels),
                    "|".join(requirement.verification_classes),
                    "|".join(requirement.requirement_types),
                    "|".join(requirement.source_sections),
                    "|".join(requirement.target_components),
                    requirement.status,
                    requirement.test_id,
                    requirement.evidence_id,
                ]
            )


def render_partition_fsm_dot(spec: FrozenSpec) -> str:
    lines = [
        "digraph fbvbs_partition_fsm {",
        "  rankdir=LR;",
        '  node [shape=ellipse, fontname="Helvetica"];',
    ]
    seen = set()
    for transition in spec.partition_transitions:
        for current_state in transition.current_states:
            if current_state == "なし":
                edge = f'  START -> "{transition.next_state}" [label="{transition.trigger}"];'
            else:
                edge = f'  "{current_state}" -> "{transition.next_state}" [label="{transition.trigger}"];'
            if edge not in seen:
                seen.add(edge)
                lines.append(edge)
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_c_header(spec: FrozenSpec) -> str:
    lines = [
        "/* Generated from plan/fbvbs-design.md. Do not edit manually. */",
        "#ifndef FBVBS_ABI_V1_H",
        "#define FBVBS_ABI_V1_H",
        "",
        "#include <stdint.h>",
        "",
    ]
    lines.extend(render_c_defines(spec.command_flags))
    lines.append("")
    lines.extend(render_c_defines(spec.command_states))
    lines.append("")
    lines.extend(render_c_hypercall_defines(spec))
    lines.append("")
    lines.extend(render_c_defines(spec.frozen_enumerations))
    lines.append("")
    lines.extend(render_c_defines(spec.error_codes))
    lines.append("")
    for layout in spec.layouts:
        lines.extend(render_c_struct(layout))
        lines.append("")
    lines.append("#endif /* FBVBS_ABI_V1_H */")
    lines.append("")
    return "\n".join(lines)


def render_rust_bindings(spec: FrozenSpec) -> str:
    lines = [
        "// Generated from plan/fbvbs-design.md. Do not edit manually.",
        "#![allow(non_camel_case_types)]",
        "",
    ]
    lines.extend(render_rust_consts(spec.command_flags))
    lines.append("")
    lines.extend(render_rust_consts(spec.command_states))
    lines.append("")
    lines.extend(render_rust_hypercall_consts(spec))
    lines.append("")
    lines.extend(render_rust_consts(spec.frozen_enumerations))
    lines.append("")
    lines.extend(render_rust_consts(spec.error_codes))
    lines.append("")
    for layout in spec.layouts:
        lines.extend(render_rust_struct(layout))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_c_defines(values: tuple[NamedValue, ...]) -> list[str]:
    lines: list[str] = []
    for value in values:
        numeric = coerce_numeric_literal(value.value)
        name = sanitize_constant_name(value.name)
        if numeric is None or not name:
            continue
        lines.append(f"#define {name} {numeric}")
    return lines


def render_rust_consts(values: tuple[NamedValue, ...]) -> list[str]:
    lines: list[str] = []
    for value in values:
        numeric = coerce_numeric_literal(value.value)
        name = sanitize_constant_name(value.name)
        if numeric is None or not name:
            continue
        lines.append(f"pub const {name}: u64 = {numeric};")
    return lines


def sanitize_constant_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_]", "_", name)
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    return sanitized.upper()


def sanitize_hypercall_name(name: str) -> str:
    return f"FBVBS_CALL_{sanitize_constant_name(name)}"


def coerce_numeric_literal(value: str) -> str | None:
    stripped = value.strip()
    bit_match = re.fullmatch(r"bit\s+(\d+)", stripped)
    if bit_match:
        return f"(1ULL << {bit_match.group(1)})"
    if re.fullmatch(r"0x[0-9A-Fa-f]+|\d+", stripped):
        return stripped
    return None


def render_c_struct(layout: CStructLayout) -> list[str]:
    lines = [f"struct {layout.name} {{"]
    for field in layout.fields:
        lines.append(f"    {field.c_type} {field.name}{render_array_suffix(field)};")
    lines.append("};")
    if layout.size_bytes is not None:
        lines.append(f"#define {sanitize_constant_name(layout.name + '_size')} {layout.size_bytes}")
    return lines


def render_c_hypercall_defines(spec: FrozenSpec) -> list[str]:
    lines: list[str] = []
    for hypercall in spec.hypercalls:
        lines.append(f"#define {sanitize_hypercall_name(hypercall.name)} {hypercall.call_id}")
    return lines


def render_rust_hypercall_consts(spec: FrozenSpec) -> list[str]:
    lines: list[str] = []
    for hypercall in spec.hypercalls:
        lines.append(f"pub const {sanitize_hypercall_name(hypercall.name)}: u64 = {hypercall.call_id};")
    return lines


def render_rust_struct(layout: CStructLayout) -> list[str]:
    lines = ["#[repr(C)]", "#[derive(Clone, Copy, Debug, Default)]", f"pub struct {layout.name} {{"]
    for field in layout.fields:
        rust_type = map_rust_type(field)
        lines.append(f"    pub {field.name}: {rust_type},")
    lines.append("}")
    if layout.size_bytes is not None:
        lines.append(f"pub const {sanitize_constant_name(layout.name + '_size')}: usize = {layout.size_bytes};")
    return lines


def render_array_suffix(field: StructField) -> str:
    return "" if field.array_length is None else f"[{field.array_length}]"


def map_rust_type(field: StructField) -> str:
    rust_type = {
        "uint8_t": "u8",
        "uint16_t": "u16",
        "uint32_t": "u32",
        "uint64_t": "u64",
    }[field.c_type]
    if field.array_length is None:
        return rust_type
    return f"[{rust_type}; {field.array_length}]"
