#!/usr/bin/env python3

import datetime
import json
import pathlib

import correlate_standalone_incident_artifacts as correlate


TOOL_VERSION = 1
STATE_MANIFEST_SCHEMA_VERSION = 1
SUPPORTED_PANEL_STYLES = ("mainframe-ispf-inspired",)
SUPPORTED_LOCALES = ("en", "ja")


def make_version_window(current_value: int | None) -> dict[str, int | None]:
    if current_value is None:
        return {
            "current": None,
            "minimum_accepted": None,
            "maximum_accepted": None,
        }
    return {
        "current": int(current_value),
        "minimum_accepted": int(current_value),
        "maximum_accepted": int(current_value),
    }


def _read_optional_json(path: pathlib.Path | None) -> dict | None:
    if path is None:
        return None
    return correlate.read_json(path)


def build_state_manifest(
    diagnostic_manifest: dict,
    timeline: dict,
    severity_summary: dict,
    ack_ledger: dict | None,
    origin_attestation: dict | None,
    break_glass_ledger: dict | None,
    compatibility_matrix: dict | None,
    panel_manifest: dict | None,
    evidence_pack_format_version: int | None = None,
) -> dict:
    schema_registry = diagnostic_manifest.get("schema_registry", {})
    if not isinstance(schema_registry, dict):
        raise SystemExit("diagnostic bundle manifest schema_registry must be an object")

    compatibility_summary = {
        "matrix_present": compatibility_matrix is not None,
        "matrix_schema_version": None,
        "management_abi_version": None,
        "row_count": 0,
    }
    if compatibility_matrix is not None:
        matrix_schema_version = compatibility_matrix.get("matrix_schema_version")
        summary = compatibility_matrix.get("summary", {})
        registry = compatibility_matrix.get("schema_registry", {})
        compatibility_summary = {
            "matrix_present": True,
            "matrix_schema_version": matrix_schema_version,
            "management_abi_version": registry.get("management_abi_version"),
            "row_count": int(summary.get("row_count", 0)),
        }

    return {
        "tool": {
            "name": "standalone_state_manifest.py",
            "version": TOOL_VERSION,
        },
        "state_manifest_schema_version": STATE_MANIFEST_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "compatibility_windows": {
            "management_abi_version": make_version_window(schema_registry.get("management_abi_version")),
            "health_schema_version": make_version_window(schema_registry.get("health_schema_version")),
            "audit_schema_version": make_version_window(schema_registry.get("audit_schema_version")),
            "inventory_schema_version": make_version_window(schema_registry.get("inventory_schema_version")),
            "guidance_schema_version": make_version_window(schema_registry.get("guidance_schema_version")),
            "fault_record_schema_version": make_version_window(schema_registry.get("fault_record_schema_version")),
            "diagnostic_bundle_format_version": make_version_window(
                diagnostic_manifest.get("bundle_format_version")
            ),
            "severity_summary_schema_version": make_version_window(
                severity_summary.get("summary_schema_version")
            ),
            "ack_ledger_schema_version": make_version_window(
                ack_ledger.get("ledger_schema_version") if ack_ledger is not None else None
            ),
            "origin_attestation_schema_version": make_version_window(
                origin_attestation.get("origin_attestation_schema_version") if origin_attestation is not None else None
            ),
            "break_glass_ledger_schema_version": make_version_window(
                break_glass_ledger.get("break_glass_ledger_schema_version") if break_glass_ledger is not None else None
            ),
            "compatibility_matrix_schema_version": make_version_window(
                compatibility_summary["matrix_schema_version"]
            ),
            "evidence_pack_format_version": make_version_window(evidence_pack_format_version),
        },
        "artifact_state": {
            "diagnostic_bundle_signed": bool(diagnostic_manifest.get("signed", False)),
            "diagnostic_capture_complete": bool(diagnostic_manifest.get("capture_complete", False)),
            "timeline_root_chain_sha384": timeline.get("root_chain_sha384"),
            "timeline_record_count": int(timeline.get("record_count", 0)),
            "timeline_gap_count_total": sum(
                int(session.get("gap_count", 0))
                for session in timeline.get("boot_sessions", [])
                if isinstance(session, dict)
            ),
            "severity_locale": severity_summary.get("presentation_locale"),
            "overall_severity_name": severity_summary.get("overall_severity", {}).get("name"),
            "panel_style": panel_manifest.get("style") if isinstance(panel_manifest, dict) else None,
            "panel_locale": panel_manifest.get("presentation_locale") if isinstance(panel_manifest, dict) else None,
            "ack_ledger_present": ack_ledger is not None,
            "origin_attestation_present": origin_attestation is not None,
            "break_glass_ledger_present": break_glass_ledger is not None,
            "compatibility_matrix_present": compatibility_summary["matrix_present"],
        },
        "supported_operator_console": {
            "locales": list(SUPPORTED_LOCALES),
            "panel_styles": list(SUPPORTED_PANEL_STYLES),
        },
        "migration_requirements": {
            "timeline_root_required": True,
            "signed_diagnostic_bundle_preferred": True,
            "allowed_gap_count_max": 0,
            "severity_summary_required": True,
            "compatibility_matrix_required": compatibility_matrix is not None,
        },
        "compatibility_matrix": compatibility_summary,
    }


def generate_state_manifest_from_paths(
    diagnostic_bundle_path: pathlib.Path,
    timeline_path: pathlib.Path,
    severity_path: pathlib.Path,
    ack_path: pathlib.Path | None = None,
    origin_path: pathlib.Path | None = None,
    break_glass_path: pathlib.Path | None = None,
    matrix_path: pathlib.Path | None = None,
    panel_path: pathlib.Path | None = None,
    evidence_pack_format_version: int | None = None,
) -> dict:
    diagnostic_manifest = correlate.load_diagnostic_bundle_manifest(diagnostic_bundle_path)
    timeline = correlate.read_json(timeline_path)
    severity_summary = correlate.read_json(severity_path)
    ack_ledger = _read_optional_json(ack_path)
    origin_attestation = _read_optional_json(origin_path)
    break_glass_ledger = _read_optional_json(break_glass_path)
    compatibility_matrix = _read_optional_json(matrix_path)
    panel_manifest = _read_optional_json(panel_path)
    return build_state_manifest(
        diagnostic_manifest,
        timeline,
        severity_summary,
        ack_ledger,
        origin_attestation,
        break_glass_ledger,
        compatibility_matrix,
        panel_manifest,
        evidence_pack_format_version=evidence_pack_format_version,
    )


def write_manifest(path: pathlib.Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
