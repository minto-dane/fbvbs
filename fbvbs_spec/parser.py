from __future__ import annotations

import re
from dataclasses import asdict
from pathlib import Path

from .models import (
    CStructLayout,
    CallCategory,
    FrozenSpec,
    Hypercall,
    NamedRule,
    NamedValue,
    ObjectNamespace,
    PartitionTransition,
    PerformanceEntry,
    ProtectedStructure,
    Requirement,
    RequirementDefaults,
    RoadmapPhase,
    ServiceFailureImpact,
    StructField,
)
from .normalize import normalize_verification_phrase

REQUIREMENT_DEFAULTS_RE = re.compile(
    r"requirement type=`(?P<types>[^`]+)`、source sections=`(?P<sources>[^`]+)`、"
    r"target components=`(?P<targets>[^`]+)`、status=`(?P<status>[^`]+)` とする。"
    r"関連試験識別子は `(?P<test>[^`]+)`、関連証拠識別子は `(?P<evidence>[^`]+)`"
)
REQUIREMENT_RE = re.compile(
    r"`(?P<id>FBVBS-REQ-(?P<number>\d{4,}))`\s+(?P<text>.+?)"
    r"検証方法は (?P<verification>.+?) とする。$"
)
FIELD_RE = re.compile(
    r"^\s*(?P<type>uint(?:8|16|32|64)_t)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\[(?P<length>\d+)\])?\s*;\s*(?:/\*.*\*/)?$"
)
STRUCT_RE = re.compile(r"struct\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\{(?P<body>.*?)\};", re.S)

FIXED_STRUCT_NAMES = {
    "fbvbs_log_record_v1",
    "fbvbs_log_ring_header_v1",
    "fbvbs_command_page_v1",
    "fbvbs_bootstrap_page_v1",
}
TYPE_SIZES = {"uint8_t": 1, "uint16_t": 2, "uint32_t": 4, "uint64_t": 8}


def parse_spec_document(source_path: str | Path) -> FrozenSpec:
    path = Path(source_path)
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    historical_name_mapping = " ".join(extract_paragraphs(section_text(lines, "# Appendix A. Historical Name Mapping", "# Appendix B. Acronym and Term Expansion")))
    acronym_paragraphs = tuple(extract_paragraphs(section_text(lines, "# Appendix B. Acronym and Term Expansion", "# Appendix C. Minimal Binary Log Record Layout")))
    final_verification_paragraphs = tuple(extract_paragraphs(section_text(lines, "# Appendix E. Final Verification of This Specification", "# Appendix F. Proof Obligations Before Production Declaration")))
    production_obligations = tuple(extract_paragraphs(section_text(lines, "# Appendix F. Proof Obligations Before Production Declaration", "# Appendix G. Requirements Catalog")))

    requirement_defaults, requirements = parse_requirements(lines)
    partition_transitions = parse_partition_transitions(lines)
    protected_structures = parse_protected_structures(lines)
    service_failures = parse_service_failures(lines)
    performance_reference, performance_targets = parse_performance_budget(lines)
    roadmap_phases = parse_roadmap(lines)
    layouts = parse_layouts(lines)
    command_flags = parse_named_values_table(
        section_text(lines, "## D.1. Command Flags", "## D.2. Command States"),
        section="D.1",
    )
    command_states = parse_named_values_table(
        section_text(lines, "## D.2. Command States", "## D.3. Output Page Rules"),
        section="D.2",
    )
    frozen_enumerations = parse_named_values_table(
        section_text(lines, "## L.1.B. Frozen Enumerations", "追加の固定値規則は次のとおりとする。"),
        section="L.1.B",
    )
    additional_fixed_rules = parse_named_rules_table(
        section_text(lines, "追加の固定値規則は次のとおりとする。", "## L.1.C. Object ID and Handle Namespace Rules"),
        section="L.1.B.additional",
    )
    object_namespaces = parse_object_namespaces(lines)
    payload_rules, manifest_rules = parse_payload_rules(lines)
    loader_rules = parse_loader_rules(lines)
    vm_exit_layouts = parse_named_rules_table(
        section_text(lines, "## L.1.F. Fixed VM Exit Payload Layouts", "## L.2. Call ID 空間の構造"),
        section="L.1.F",
    )
    call_categories = parse_call_categories(lines)
    hypercalls = parse_hypercalls(lines)
    error_codes = parse_named_values_table(
        section_text(lines, "## L.12. エラーコード", None),
        section="L.12",
    )

    return FrozenSpec(
        source_path=str(path),
        historical_name_mapping=historical_name_mapping,
        acronym_paragraphs=acronym_paragraphs,
        final_verification_paragraphs=final_verification_paragraphs,
        production_obligations=production_obligations,
        requirement_defaults=requirement_defaults,
        requirements=requirements,
        partition_transitions=partition_transitions,
        protected_structures=protected_structures,
        service_failures=service_failures,
        performance_reference=performance_reference,
        performance_targets=performance_targets,
        roadmap_phases=roadmap_phases,
        layouts=layouts,
        command_flags=command_flags,
        command_states=command_states,
        frozen_enumerations=frozen_enumerations,
        additional_fixed_rules=additional_fixed_rules,
        object_namespaces=object_namespaces,
        payload_rules=payload_rules,
        manifest_rules=manifest_rules,
        loader_rules=loader_rules,
        vm_exit_layouts=vm_exit_layouts,
        call_categories=call_categories,
        hypercalls=hypercalls,
        error_codes=error_codes,
    )


def section_text(lines: list[str], start_heading: str, end_heading: str | None) -> list[str]:
    start = find_line(lines, start_heading)
    end = len(lines) if end_heading is None else find_line(lines, end_heading)
    return lines[start:end]


def slice_lines(lines: list[str], start_snippet: str, end_snippet: str | None) -> list[str]:
    start = find_line_containing(lines, start_snippet)
    end = len(lines) if end_snippet is None else find_line_containing(lines, end_snippet)
    return lines[start:end]


def find_line(lines: list[str], exact: str) -> int:
    for index, line in enumerate(lines):
        if line.strip() == exact:
            return index
    raise ValueError(f"heading not found: {exact}")


def find_line_containing(lines: list[str], snippet: str) -> int:
    for index, line in enumerate(lines):
        if snippet in line:
            return index
    raise ValueError(f"line containing snippet not found: {snippet}")


def extract_paragraphs(lines: list[str]) -> list[str]:
    paragraphs: list[str] = []
    current: list[str] = []
    for line in lines[1:]:
        stripped = line.strip()
        if not stripped:
            if current:
                paragraphs.append(" ".join(current))
                current = []
            continue
        if stripped.startswith("#"):
            continue
        current.append(stripped)
    if current:
        paragraphs.append(" ".join(current))
    return paragraphs


def parse_requirements(lines: list[str]) -> tuple[tuple[RequirementDefaults, ...], tuple[Requirement, ...]]:
    section = section_text(lines, "# Appendix G. Requirements Catalog", "# Appendix H. Protected Structure Catalog")
    defaults_list: list[RequirementDefaults] = []
    requirements: list[Requirement] = []
    current_subsection = ""
    current_defaults: RequirementDefaults | None = None

    for raw_line in section:
        line = raw_line.strip()
        if line.startswith("## G."):
            current_subsection = line.removeprefix("## ").strip()
            current_defaults = None
            continue
        if line.startswith("この subsection の既定 metadata は"):
            match = REQUIREMENT_DEFAULTS_RE.search(line)
            if match is None:
                raise ValueError(f"unable to parse requirement defaults: {line}")
            current_defaults = RequirementDefaults(
                subsection=current_subsection,
                requirement_types=split_csv_list(match.group("types")),
                source_sections=split_csv_list(match.group("sources")),
                target_components=split_csv_list(match.group("targets")),
                status=match.group("status").strip(),
                test_id_pattern=match.group("test").strip(),
                evidence_id_pattern=match.group("evidence").strip(),
            )
            defaults_list.append(current_defaults)
            continue
        if line.startswith("`FBVBS-REQ-"):
            if current_defaults is None:
                raise ValueError(f"requirement encountered before defaults: {line}")
            match = REQUIREMENT_RE.match(line)
            if match is None:
                raise ValueError(f"unable to parse requirement: {line}")
            requirement_id = match.group("id")
            number_text = match.group("number")
            verification_phrase = match.group("verification").strip()
            labels, classes = normalize_verification_phrase(verification_phrase)
            requirements.append(
                Requirement(
                    requirement_id=requirement_id,
                    number=int(number_text),
                    subsection=current_subsection,
                    text=match.group("text").strip(),
                    verification_phrase=verification_phrase,
                    verification_labels=labels,
                    verification_classes=classes,
                    requirement_types=current_defaults.requirement_types,
                    source_sections=current_defaults.source_sections,
                    target_components=current_defaults.target_components,
                    status=current_defaults.status,
                    test_id=current_defaults.test_id_pattern.replace("<requirement-number>", number_text),
                    evidence_id=current_defaults.evidence_id_pattern.replace("<requirement-number>", number_text),
                )
            )

    return tuple(defaults_list), tuple(requirements)


def parse_partition_transitions(lines: list[str]) -> tuple[PartitionTransition, ...]:
    table = parse_first_markdown_table(section_text(lines, "### 18.1. Legal Partition Transitions", "## 19. Capability and Ownership Model"))
    transitions: list[PartitionTransition] = []
    for row in table:
        current_states = tuple(clean_code(cell) for cell in row["現在状態"].split("/") if cell)
        transitions.append(
            PartitionTransition(
                current_states=current_states,
                trigger=clean_code(row["トリガ"]),
                next_state=clean_code(row["次状態"]),
                required_condition=row["必須条件"].strip(),
                notes=row["備考"].strip(),
            )
        )
    return tuple(transitions)


def parse_protected_structures(lines: list[str]) -> tuple[ProtectedStructure, ...]:
    structures: list[ProtectedStructure] = []
    tiers = (
        ("Tier A", "## H.2. Tier A: 起動後不変（Immutable After Boot）", "## H.3. Tier B: 制御付き更新（Controlled Update）"),
        ("Tier B", "## H.3. Tier B: 制御付き更新（Controlled Update）", "## H.4. Tier C: 保護対象外（高頻度可変、本バージョンで非保護）"),
        ("Tier C", "## H.4. Tier C: 保護対象外（高頻度可変、本バージョンで非保護）", "# Appendix I. Service Failure Impact Matrix"),
    )
    for tier_name, start, end in tiers:
        table = parse_first_markdown_table(section_text(lines, start, end))
        for row in table:
            structures.append(
                ProtectedStructure(
                    tier=tier_name,
                    structure=clean_code(row["構造体"]),
                    attack_effect=row["改竄時の攻撃効果"].strip(),
                    change_frequency=row["変更頻度"].strip(),
                    phase=row.get("Phase", "").strip() or None,
                    rationale=(row.get("根拠") or row.get("非保護の理由") or "").strip(),
                )
            )
    return tuple(structures)


def parse_service_failures(lines: list[str]) -> tuple[ServiceFailureImpact, ...]:
    table = parse_first_markdown_table(section_text(lines, "## I.3. 影響マトリクス", "## I.4. 重要な観察"))
    return tuple(
        ServiceFailureImpact(
            service=row["障害サービス"].strip(),
            stopped_function=row["停止する機能"].strip(),
            preserved_protection=row["維持される保護"].strip(),
            freebsd_impact=row["FreeBSD への影響"].strip(),
            recovery=row["回復方法"].strip(),
        )
        for row in table
    )


def parse_performance_budget(lines: list[str]) -> tuple[tuple[PerformanceEntry, ...], tuple[PerformanceEntry, ...]]:
    baseline = parse_first_markdown_table(section_text(lines, "## J.2. 基本コスト参照値", "## J.3. FBVBS 追加コスト目標"))
    targets = parse_first_markdown_table(section_text(lines, "## J.3. FBVBS 追加コスト目標", "## J.4. 性能に関する禁止事項"))
    baseline_entries = tuple(
        PerformanceEntry(
            table="baseline",
            operation=row["操作"].strip(),
            cost=row["ベースコスト（FBVBS なし）"].strip(),
            ipc_count=None,
            rationale=row["備考"].strip(),
        )
        for row in baseline
    )
    target_entries = tuple(
        PerformanceEntry(
            table="target",
            operation=clean_code(row["操作"]),
            cost=row["追加コスト目標"].strip(),
            ipc_count=row["IPC 回数"].strip(),
            rationale=row["根拠"].strip(),
        )
        for row in targets
    )
    return baseline_entries, target_entries


def parse_roadmap(lines: list[str]) -> tuple[RoadmapPhase, ...]:
    section = section_text(lines, "# Appendix K. Implementation Roadmap", "# Appendix L. Frozen Hypercall ABI Catalog")
    indices = [index for index, line in enumerate(section) if line.startswith("### Phase ")]
    phases: list[RoadmapPhase] = []
    for offset, start_index in enumerate(indices):
        end_index = indices[offset + 1] if offset + 1 < len(indices) else len(section)
        block = section[start_index:end_index]
        heading_match = re.match(r"### Phase (?P<phase>\d+): (?P<title>.+)$", block[0].strip())
        if heading_match is None:
            raise ValueError(f"unable to parse roadmap heading: {block[0]}")
        goal = ""
        deliverables: list[str] = []
        verification: list[str] = []
        current_list: list[str] | None = None
        for line in block[1:]:
            stripped = line.strip()
            if stripped.startswith("**目標:**"):
                goal = stripped.removeprefix("**目標:**").strip()
                current_list = None
            elif stripped == "**成果物:**":
                current_list = deliverables
            elif stripped in {"**検証:**", "**活動:**"}:
                current_list = verification
            elif stripped.startswith("- ") and current_list is not None:
                current_list.append(stripped.removeprefix("- ").strip())
            elif stripped.startswith("### "):
                break
        phases.append(
            RoadmapPhase(
                phase=int(heading_match.group("phase")),
                title=heading_match.group("title").strip(),
                goal=goal,
                deliverables=tuple(deliverables),
                verification=tuple(verification),
            )
        )
    return tuple(phases)


def parse_layouts(lines: list[str]) -> tuple[CStructLayout, ...]:
    layouts: list[CStructLayout] = []
    blocks = []
    for start, end in (
        ("# Appendix C. Minimal Binary Log Record Layout", "## C.1. Frozen Mirror Ring Header Layout"),
        ("## C.1. Frozen Mirror Ring Header Layout", "# Appendix D. Frozen Shared Command Page Layout"),
        ("# Appendix D. Frozen Shared Command Page Layout", "## D.1. Command Flags"),
        ("## D.4. Bootstrap Metadata Page", "# Appendix E. Final Verification of This Specification"),
    ):
        blocks.extend(extract_code_blocks(section_text(lines, start, end)))
    for block in blocks:
        for match in STRUCT_RE.finditer(block):
            name = match.group("name")
            if name in FIXED_STRUCT_NAMES:
                layouts.append(parse_c_struct(name, match.group("body")))
    return tuple(layouts)


def parse_named_values_table(lines: list[str], section: str) -> tuple[NamedValue, ...]:
    table = parse_first_markdown_table(lines)
    keys = list(table[0].keys())
    name_key = "名称" if "名称" in keys else keys[0]
    transform_bits = False
    if "値" in keys:
        value_key = "値"
    elif "ビット" in keys:
        value_key = "ビット"
        transform_bits = True
    else:
        value_key = next(key for key in keys if key != name_key)
    values: list[NamedValue] = []
    for row in table:
        raw_value = row[value_key].strip()
        if transform_bits and re.fullmatch(r"\d+", raw_value):
            raw_value = f"bit {raw_value}"
        values.append(
            NamedValue(
                name=clean_code(row[name_key]),
                value=raw_value,
                section=section,
            )
        )
    return tuple(values)


def parse_named_rules_table(lines: list[str], section: str) -> tuple[NamedRule, ...]:
    table = parse_first_markdown_table(lines)
    name_key, value_key = list(table[0].keys())
    return tuple(
        NamedRule(
            name=clean_code(row[name_key]),
            value=row[value_key].strip(),
            section=section,
        )
        for row in table
    )


def parse_object_namespaces(lines: list[str]) -> tuple[ObjectNamespace, ...]:
    table = parse_first_markdown_table(
        section_text(lines, "## L.1.C. Object ID and Handle Namespace Rules", "## L.1.D. Frozen Payload and Encoding Rules")
    )
    return tuple(
        ObjectNamespace(
            name=clean_code(row["名称"]),
            issuer=row["発行主体"].strip(),
            consumer=row["消費主体"].strip(),
            lifetime=row["生存期間"].strip(),
        )
        for row in table
    )


def parse_payload_rules(lines: list[str]) -> tuple[tuple[NamedRule, ...], tuple[str, ...]]:
    rules = parse_named_rules_table(
        slice_lines(
            lines,
            "## L.1.D. Frozen Payload and Encoding Rules",
            "`manifest_cbor` は ABI v1 で canonical CBOR map でなければならない。",
        ),
        section="L.1.D",
    )
    manifest_section = slice_lines(
        lines,
        "`manifest_cbor` は ABI v1 で canonical CBOR map でなければならない。",
        "## L.1.E. Fixed Executable Loader Rules",
    )
    manifest_rules = tuple(extract_paragraphs(manifest_section))
    return rules, manifest_rules


def parse_loader_rules(lines: list[str]) -> tuple[str, ...]:
    section = section_text(lines, "## L.1.E. Fixed Executable Loader Rules", "## L.1.F. Fixed VM Exit Payload Layouts")
    return tuple(line.strip().removeprefix("- ").strip() for line in section if line.strip().startswith("- "))


def parse_call_categories(lines: list[str]) -> tuple[CallCategory, ...]:
    table = parse_first_markdown_table(section_text(lines, "## L.2. Call ID 空間の構造", "## L.3. パーティション管理（0x0xxx）"))
    return tuple(
        CallCategory(
            category=row["カテゴリ"].strip(),
            range_text=row["範囲"].strip(),
            purpose=row["用途"].strip(),
        )
        for row in table
    )


def parse_hypercalls(lines: list[str]) -> tuple[Hypercall, ...]:
    sections = (
        ("## L.3. パーティション管理（0x0xxx）", "## L.4. メモリ管理（0x1xxx）"),
        ("## L.4. メモリ管理（0x1xxx）", "## L.5. Kernel Code Integrity Service（0x2xxx）"),
        ("## L.5. Kernel Code Integrity Service（0x2xxx）", "## L.6. Kernel State Integrity Service（0x3xxx）"),
        ("## L.6. Kernel State Integrity Service（0x3xxx）", "## L.7. Identity Key Service（0x4xxx）"),
        ("## L.7. Identity Key Service（0x4xxx）", "## L.8. Storage Key Service（0x5xxx）"),
        ("## L.8. Storage Key Service（0x5xxx）", "## L.9. Update Verification Service（0x6xxx）"),
        ("## L.9. Update Verification Service（0x6xxx）", "## L.10. bhyve VM 管理（0x7xxx）"),
        ("## L.10. bhyve VM 管理（0x7xxx）", "## L.11. 監査・診断（0x8xxx）"),
        ("## L.11. 監査・診断（0x8xxx）", "## L.12. エラーコード"),
    )
    hypercalls: list[Hypercall] = []
    for start, end in sections:
        heading = start.removeprefix("## ").strip()
        table = parse_first_markdown_table(section_text(lines, start, end))
        for row in table:
            hypercalls.append(
                Hypercall(
                    call_id=row["call_id"].strip(),
                    name=row["名称"].strip(),
                    caller=clean_code(row["呼出元"]),
                    request=row["要求本文"].strip(),
                    response=row["応答本文"].strip(),
                    semantics=row["前提条件/意味論"].strip(),
                    allowed_errors=tuple(
                        clean_code(item)
                        for item in row["許可エラー"].split(",")
                        if item.strip()
                    ),
                    section=heading,
                )
            )
    return tuple(hypercalls)


def parse_first_markdown_table(lines: list[str]) -> list[dict[str, str]]:
    table_lines = extract_first_table_lines(lines)
    header = split_table_row(table_lines[0])
    rows: list[dict[str, str]] = []
    for row_line in table_lines[2:]:
        cells = split_table_row(row_line)
        if len(cells) != len(header):
            raise ValueError(f"table width mismatch: {row_line}")
        rows.append(dict(zip(header, cells, strict=True)))
    return rows


def extract_first_table_lines(lines: list[str]) -> list[str]:
    start = None
    for index, line in enumerate(lines):
        if line.strip().startswith("|"):
            start = index
            break
    if start is None:
        raise ValueError("markdown table not found")
    table_lines: list[str] = []
    for line in lines[start:]:
        if line.strip().startswith("|"):
            table_lines.append(line.strip())
        elif table_lines:
            break
    if len(table_lines) < 2:
        raise ValueError("incomplete markdown table")
    return table_lines


def split_table_row(line: str) -> list[str]:
    content = line.strip().strip("|")
    cells: list[str] = []
    current: list[str] = []
    in_backticks = False
    for char in content:
        if char == "`":
            in_backticks = not in_backticks
            current.append(char)
            continue
        if char == "|" and not in_backticks:
            cells.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    cells.append("".join(current).strip())
    return cells


def extract_code_blocks(lines: list[str]) -> list[str]:
    blocks: list[str] = []
    inside = False
    current: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            if inside:
                blocks.append("\n".join(current))
                current = []
                inside = False
            else:
                inside = True
            continue
        if inside:
            current.append(line)
    return blocks


def parse_c_struct(name: str, body: str) -> CStructLayout:
    fields: list[StructField] = []
    for raw_line in body.splitlines():
        line = raw_line.split("/*", 1)[0].strip()
        if not line:
            continue
        match = FIELD_RE.match(line)
        if match is None:
            raise ValueError(f"unsupported field in struct {name}: {raw_line!r}")
        length = match.group("length")
        fields.append(
            StructField(
                c_type=match.group("type"),
                name=match.group("name"),
                array_length=int(length) if length else None,
            )
        )
    return CStructLayout(name=name, fields=tuple(fields), size_bytes=compute_struct_size(fields))


def compute_struct_size(fields: list[StructField]) -> int:
    offset = 0
    max_align = 1
    for field in fields:
        size = TYPE_SIZES[field.c_type]
        align = size
        max_align = max(max_align, align)
        offset = align_up(offset, align)
        offset += size * (field.array_length or 1)
    return align_up(offset, max_align)


def align_up(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def split_csv_list(value: str) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip())


def clean_code(text: str) -> str:
    return text.replace("`", "").strip()
