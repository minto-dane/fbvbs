from __future__ import annotations

import re
from dataclasses import asdict

from .models import FrozenSpec
from .normalize import PRIMARY_VERIFICATION_CLASSES


EXPECTED_REQUIREMENT_COUNT = 83
EXPECTED_HYPERCALL_COUNT = 58


def validate_spec(spec: FrozenSpec) -> list[str]:
    errors: list[str] = []
    errors.extend(validate_requirements(spec))
    errors.extend(validate_partition_states(spec))
    errors.extend(validate_hypercalls(spec))
    errors.extend(validate_layouts(spec))
    return errors


def ensure_valid(spec: FrozenSpec) -> None:
    errors = validate_spec(spec)
    if errors:
        raise ValueError("\n".join(errors))


def validate_requirements(spec: FrozenSpec) -> list[str]:
    errors: list[str] = []
    requirement_ids = [requirement.requirement_id for requirement in spec.requirements]
    if len(requirement_ids) != len(set(requirement_ids)):
        errors.append("duplicate requirement IDs detected")
    if len(spec.requirements) != EXPECTED_REQUIREMENT_COUNT:
        errors.append(
            f"expected {EXPECTED_REQUIREMENT_COUNT} requirements, found {len(spec.requirements)}"
        )
    for requirement in spec.requirements:
        unknown = set(requirement.verification_classes) - set(PRIMARY_VERIFICATION_CLASSES)
        if unknown:
            errors.append(f"{requirement.requirement_id} has unknown verification classes: {sorted(unknown)}")
        number_text = f"{requirement.number:04d}"
        if not requirement.test_id.endswith(number_text):
            errors.append(f"{requirement.requirement_id} has unexpected test ID: {requirement.test_id}")
        if not requirement.evidence_id.endswith(number_text):
            errors.append(f"{requirement.requirement_id} has unexpected evidence ID: {requirement.evidence_id}")
    return errors


def validate_partition_states(spec: FrozenSpec) -> list[str]:
    errors: list[str] = []
    rule_lookup = {rule.name: rule.value for rule in spec.additional_fixed_rules}
    state_rule = rule_lookup.get("partition state numeric assignment")
    if state_rule is None:
        return ["missing partition state numeric assignment rule"]
    state_names = set(re.findall(r"([A-Za-z]+)\s*=\s*\d+", state_rule))
    transition_states = set()
    for transition in spec.partition_transitions:
        transition_states.update(state for state in transition.current_states if state != "なし")
        transition_states.add(transition.next_state)
    if state_names != transition_states:
        errors.append(
            "partition transition states do not match frozen numeric assignment: "
            f"{sorted(state_names)} vs {sorted(transition_states)}"
        )
    if any("Destroyed" in transition.current_states for transition in spec.partition_transitions):
        errors.append("Destroyed should not appear as a transition source state")
    return errors


def validate_hypercalls(spec: FrozenSpec) -> list[str]:
    errors: list[str] = []
    call_ids = [hypercall.call_id for hypercall in spec.hypercalls]
    if len(call_ids) != len(set(call_ids)):
        errors.append("duplicate hypercall IDs detected")
    if len(spec.hypercalls) != EXPECTED_HYPERCALL_COUNT:
        errors.append(f"expected {EXPECTED_HYPERCALL_COUNT} hypercalls, found {len(spec.hypercalls)}")

    allowed_errors = {entry.name for entry in spec.error_codes}
    section_prefixes = {
        "L.3. パーティション管理（0x0xxx）": "0x0",
        "L.4. メモリ管理（0x1xxx）": "0x1",
        "L.5. Kernel Code Integrity Service（0x2xxx）": "0x2",
        "L.6. Kernel State Integrity Service（0x3xxx）": "0x3",
        "L.7. Identity Key Service（0x4xxx）": "0x4",
        "L.8. Storage Key Service（0x5xxx）": "0x5",
        "L.9. Update Verification Service（0x6xxx）": "0x6",
        "L.10. bhyve VM 管理（0x7xxx）": "0x7",
        "L.11. 監査・診断（0x8xxx）": "0x8",
    }
    for hypercall in spec.hypercalls:
        expected_prefix = section_prefixes.get(hypercall.section)
        if expected_prefix and not hypercall.call_id.lower().startswith(expected_prefix):
            errors.append(f"{hypercall.name} has call ID outside section prefix: {hypercall.call_id}")
        unknown_errors = [error for error in hypercall.allowed_errors if error not in allowed_errors]
        if unknown_errors:
            errors.append(f"{hypercall.name} references unknown error codes: {unknown_errors}")
    return errors


def validate_layouts(spec: FrozenSpec) -> list[str]:
    errors: list[str] = []
    layouts = {layout.name: layout for layout in spec.layouts}
    command_page = layouts.get("fbvbs_command_page_v1")
    if command_page is None:
        errors.append("fbvbs_command_page_v1 layout missing")
    elif command_page.size_bytes != 4096:
        errors.append(f"fbvbs_command_page_v1 expected size 4096, found {command_page.size_bytes}")

    log_ring = layouts.get("fbvbs_log_ring_header_v1")
    if log_ring is None:
        errors.append("fbvbs_log_ring_header_v1 layout missing")

    log_record = layouts.get("fbvbs_log_record_v1")
    if log_record is None:
        errors.append("fbvbs_log_record_v1 layout missing")

    bootstrap = layouts.get("fbvbs_bootstrap_page_v1")
    if bootstrap is None:
        errors.append("fbvbs_bootstrap_page_v1 layout missing")
    elif bootstrap.size_bytes and bootstrap.size_bytes > 4096:
        errors.append(f"fbvbs_bootstrap_page_v1 exceeds a page: {bootstrap.size_bytes}")

    return errors
