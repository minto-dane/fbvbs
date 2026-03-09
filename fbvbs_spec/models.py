from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RequirementDefaults:
    subsection: str
    requirement_types: tuple[str, ...]
    source_sections: tuple[str, ...]
    target_components: tuple[str, ...]
    status: str
    test_id_pattern: str
    evidence_id_pattern: str


@dataclass(frozen=True)
class Requirement:
    requirement_id: str
    number: int
    subsection: str
    text: str
    verification_phrase: str
    verification_labels: tuple[str, ...]
    verification_classes: tuple[str, ...]
    requirement_types: tuple[str, ...]
    source_sections: tuple[str, ...]
    target_components: tuple[str, ...]
    status: str
    test_id: str
    evidence_id: str


@dataclass(frozen=True)
class PartitionTransition:
    current_states: tuple[str, ...]
    trigger: str
    next_state: str
    required_condition: str
    notes: str


@dataclass(frozen=True)
class ProtectedStructure:
    tier: str
    structure: str
    attack_effect: str
    change_frequency: str
    implementation_increment: str | None
    rationale: str


@dataclass(frozen=True)
class ServiceFailureImpact:
    service: str
    stopped_function: str
    preserved_protection: str
    freebsd_impact: str
    recovery: str


@dataclass(frozen=True)
class PerformanceEntry:
    table: str
    operation: str
    cost: str
    ipc_count: str | None
    rationale: str


@dataclass(frozen=True)
class RoadmapIncrement:
    increment: int
    title: str
    goal: str
    deliverables: tuple[str, ...]
    verification: tuple[str, ...]


@dataclass(frozen=True)
class StructField:
    c_type: str
    name: str
    array_length: int | None


@dataclass(frozen=True)
class CStructLayout:
    name: str
    fields: tuple[StructField, ...]
    size_bytes: int | None


@dataclass(frozen=True)
class NamedValue:
    name: str
    value: str
    section: str


@dataclass(frozen=True)
class NamedRule:
    name: str
    value: str
    section: str


@dataclass(frozen=True)
class ObjectNamespace:
    name: str
    issuer: str
    consumer: str
    lifetime: str


@dataclass(frozen=True)
class CallCategory:
    category: str
    range_text: str
    purpose: str


@dataclass(frozen=True)
class Hypercall:
    call_id: str
    name: str
    caller: str
    request: str
    response: str
    semantics: str
    allowed_errors: tuple[str, ...]
    section: str


@dataclass(frozen=True)
class FrozenSpec:
    source_path: str
    historical_name_mapping: str
    acronym_paragraphs: tuple[str, ...]
    final_verification_paragraphs: tuple[str, ...]
    production_obligations: tuple[str, ...]
    requirement_defaults: tuple[RequirementDefaults, ...]
    requirements: tuple[Requirement, ...]
    partition_transitions: tuple[PartitionTransition, ...]
    protected_structures: tuple[ProtectedStructure, ...]
    service_failures: tuple[ServiceFailureImpact, ...]
    performance_reference: tuple[PerformanceEntry, ...]
    performance_targets: tuple[PerformanceEntry, ...]
    roadmap_increments: tuple[RoadmapIncrement, ...]
    layouts: tuple[CStructLayout, ...]
    command_flags: tuple[NamedValue, ...]
    command_states: tuple[NamedValue, ...]
    frozen_enumerations: tuple[NamedValue, ...]
    additional_fixed_rules: tuple[NamedRule, ...]
    object_namespaces: tuple[ObjectNamespace, ...]
    payload_rules: tuple[NamedRule, ...]
    manifest_rules: tuple[str, ...]
    loader_rules: tuple[str, ...]
    vm_exit_layouts: tuple[NamedRule, ...]
    call_categories: tuple[CallCategory, ...]
    hypercalls: tuple[Hypercall, ...]
    error_codes: tuple[NamedValue, ...]
