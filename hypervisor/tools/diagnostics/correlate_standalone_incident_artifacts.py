#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib
import tarfile

import standalone_operator_security as security


TOOL_VERSION = 1
CORRELATION_SCHEMA_VERSION = 1
SUPPORTED_LOCALES = ("en", "ja")

TEXT = {
    "en": {
        "title": "Standalone Evidence Correlation Summary",
        "overall_severity": "Overall severity",
        "timeline_records": "Timeline records",
        "timeline_gaps": "Timeline gaps",
        "ack_count": "Acknowledgments",
        "diag_signed": "Diagnostic bundle signed",
        "warnings": "Warnings",
    },
    "ja": {
        "title": "スタンドアロン証跡 相関サマリー",
        "overall_severity": "全体重大度",
        "timeline_records": "タイムライン件数",
        "timeline_gaps": "タイムライン欠落",
        "ack_count": "確認件数",
        "diag_signed": "診断バンドル署名済み",
        "warnings": "警告",
    },
}


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def read_json(path: pathlib.Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"JSON input must be an object: {path}")
    return payload


def load_diagnostic_bundle_manifest(path: pathlib.Path) -> dict:
    with tarfile.open(path, "r:gz") as archive:
        try:
            extracted = archive.extractfile("diagnostics/diagnostic-bundle-manifest.json")
        except KeyError as exc:
            raise SystemExit("diagnostic bundle is missing diagnostics/diagnostic-bundle-manifest.json") from exc
        if extracted is None:
            raise SystemExit("unable to read diagnostic bundle manifest")
        payload = json.load(extracted)
    if not isinstance(payload, dict):
        raise SystemExit("diagnostic bundle manifest must be a JSON object")
    if payload.get("bundle_type") != "fbvbs-standalone-diagnostic":
        raise SystemExit("diagnostic bundle manifest bundle_type is not fbvbs-standalone-diagnostic")
    return payload


def build_correlation(
    diagnostic_manifest: dict,
    timeline: dict,
    severity_summary: dict,
    ack_ledger: dict | None,
    recovery_approval: dict | None,
    origin_attestation: dict | None,
    break_glass_ledger: dict | None,
    compatibility_matrix: dict | None,
    panel_manifest: dict | None,
) -> dict:
    warnings: list[str] = []
    timeline_root = str(timeline.get("root_chain_sha384", ""))
    if len(timeline_root) == 0:
        raise SystemExit("timeline JSON must contain root_chain_sha384")

    boot_sessions = timeline.get("boot_sessions", [])
    if not isinstance(boot_sessions, list):
        raise SystemExit("timeline boot_sessions must be an array")
    total_gap_count = 0
    for session in boot_sessions:
        if isinstance(session, dict):
            total_gap_count += int(session.get("gap_count", 0))

    ack_summary = {
        "present": ack_ledger is not None,
        "acknowledgment_count": 0,
        "timeline_root_matches": None,
        "latest_ack_sha384": None,
        "session_correlation_id": None,
        "unique_session_correlation_ids": [],
    }
    if ack_ledger is not None:
        ledger_root = str(ack_ledger.get("timeline_root_chain_sha384", ""))
        matches = ledger_root == timeline_root
        if not matches:
            raise SystemExit("acknowledgment ledger timeline_root_chain_sha384 does not match timeline root")
        ack_entries = ack_ledger.get("acknowledgments", [])
        if not isinstance(ack_entries, list):
            raise SystemExit("acknowledgment ledger acknowledgments must be an array")
        session_ids = sorted(
            {
                str(entry.get("session_correlation_id", ""))
                for entry in ack_entries
                if isinstance(entry, dict) and str(entry.get("session_correlation_id", ""))
            }
        )
        top_level_session_id = str(ack_ledger.get("session_correlation_id", ""))
        ack_summary = {
            "present": True,
            "acknowledgment_count": int(ack_ledger.get("acknowledgment_count", 0)),
            "timeline_root_matches": matches,
            "latest_ack_sha384": ack_ledger.get("latest_ack_sha384"),
            "session_correlation_id": top_level_session_id or None,
            "unique_session_correlation_ids": session_ids,
        }
        if not top_level_session_id:
            warnings.append("acknowledgment ledger is missing session_correlation_id")
        if len(session_ids) > 1:
            warnings.append("acknowledgment ledger contains multiple session correlation ids")
        if top_level_session_id and session_ids and top_level_session_id not in session_ids:
            warnings.append("acknowledgment ledger top-level session correlation id does not match entries")

    recovery_summary = {
        "present": recovery_approval is not None,
        "partition_id": None,
        "session_correlation_id": None,
        "timeline_root_matches": None,
    }
    if recovery_approval is not None:
        approval_root = str(recovery_approval.get("timeline_root_chain_sha384", ""))
        matches = approval_root == timeline_root
        if not matches:
            raise SystemExit("recovery approval timeline_root_chain_sha384 does not match timeline root")
        recovery_summary = {
            "present": True,
            "partition_id": int(recovery_approval.get("partition_id", 0)),
            "session_correlation_id": recovery_approval.get("session_correlation_id"),
            "timeline_root_matches": matches,
        }
        if not recovery_summary["session_correlation_id"]:
            warnings.append("recovery approval is missing session_correlation_id")

    origin_summary = {
        "present": origin_attestation is not None,
        "call_name": None,
        "operator_role": None,
        "session_correlation_id": None,
        "break_glass": None,
        "timeline_root_matches": None,
    }
    if origin_attestation is not None:
        try:
            security.validate_origin_attestation_payload(
                origin_attestation,
                pathlib.Path(__file__).resolve(),
                allow_expired=True,
                expected_timeline_root=timeline_root,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        origin_summary = {
            "present": True,
            "call_name": origin_attestation.get("call", {}).get("name"),
            "operator_role": origin_attestation.get("operator_role"),
            "session_correlation_id": origin_attestation.get("session_correlation_id"),
            "break_glass": bool(origin_attestation.get("command_context", {}).get("break_glass", False)),
            "timeline_root_matches": True,
        }
        if not origin_summary["session_correlation_id"]:
            warnings.append("origin attestation is missing session_correlation_id")

    break_glass_summary = {
        "present": break_glass_ledger is not None,
        "audit_channel": None,
        "event_count": 0,
        "session_correlation_id": None,
        "timeline_root_matches": None,
    }
    if break_glass_ledger is not None:
        try:
            security.validate_break_glass_ledger_payload(
                break_glass_ledger,
                expected_timeline_root=timeline_root,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        break_glass_summary = {
            "present": True,
            "audit_channel": break_glass_ledger.get("audit_channel"),
            "event_count": int(break_glass_ledger.get("break_glass_count", 0)),
            "session_correlation_id": break_glass_ledger.get("session_correlation_id"),
            "timeline_root_matches": True,
        }
        if break_glass_summary["audit_channel"] != "operator-break-glass":
            warnings.append("break-glass ledger audit channel is unexpected")
        if not break_glass_summary["session_correlation_id"]:
            warnings.append("break-glass ledger is missing session_correlation_id")

    unique_session_ids = set(ack_summary["unique_session_correlation_ids"])
    if ack_summary["session_correlation_id"] is not None:
        unique_session_ids.add(str(ack_summary["session_correlation_id"]))
    if recovery_summary["session_correlation_id"] is not None:
        unique_session_ids.add(str(recovery_summary["session_correlation_id"]))
    if origin_summary["session_correlation_id"] is not None:
        unique_session_ids.add(str(origin_summary["session_correlation_id"]))
    if break_glass_summary["session_correlation_id"] is not None:
        unique_session_ids.add(str(break_glass_summary["session_correlation_id"]))
    session_correlation_summary = {
        "present": len(unique_session_ids) != 0,
        "session_correlation_ids": sorted(unique_session_ids),
        "count": len(unique_session_ids),
        "consistent": len(unique_session_ids) <= 1,
    }
    if len(unique_session_ids) > 1:
        warnings.append("session correlation ids differ across operator artifacts")

    overall = severity_summary.get("overall_severity", {})
    partitions = severity_summary.get("partitions", [])
    if not isinstance(partitions, list):
        raise SystemExit("severity summary partitions must be an array")

    compatibility_summary = {"present": False, "row_count": 0, "management_abi_version": None}
    if compatibility_matrix is not None:
        matrix_summary = compatibility_matrix.get("summary", {})
        schema_registry = compatibility_matrix.get("schema_registry", {})
        compatibility_summary = {
            "present": True,
            "row_count": int(matrix_summary.get("row_count", 0)),
            "management_abi_version": schema_registry.get("management_abi_version"),
        }

    panel_summary = {"present": False, "style": None, "presentation_locale": None}
    if panel_manifest is not None:
        panel_summary = {
            "present": True,
            "style": panel_manifest.get("style"),
            "presentation_locale": panel_manifest.get("presentation_locale"),
        }
        if panel_manifest.get("presentation_locale") not in (None, severity_summary.get("presentation_locale")):
            warnings.append("panel manifest locale differs from severity summary locale")

    if not diagnostic_manifest.get("signed", False):
        warnings.append("diagnostic bundle manifest is unsigned")
    if not diagnostic_manifest.get("capture_complete", False):
        warnings.append("diagnostic bundle capture completeness was not asserted")
    if total_gap_count > 0:
        warnings.append("timeline contains sequence gaps")
    diagnostic_audit_schema_version = (
        diagnostic_manifest.get("schema_registry", {}).get("audit_schema_version")
    )
    timeline_audit_schema_version = timeline.get("audit_schema_version")
    if (
        diagnostic_audit_schema_version is not None
        and timeline_audit_schema_version is not None
        and diagnostic_audit_schema_version != timeline_audit_schema_version
    ):
        warnings.append("timeline audit schema version differs from diagnostic bundle schema registry")
    if origin_summary["present"] and origin_summary["break_glass"] and not break_glass_summary["present"]:
        warnings.append("break-glass origin attestation is present without separate break-glass ledger")
    if break_glass_summary["present"] and not origin_summary["present"]:
        warnings.append("break-glass ledger is present without origin attestation")

    correlation = {
        "tool": {
            "name": "correlate_standalone_incident_artifacts.py",
            "version": TOOL_VERSION,
        },
        "correlation_schema_version": CORRELATION_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "diagnostic_bundle": {
            "bundle_type": diagnostic_manifest.get("bundle_type"),
            "bundle_format_version": diagnostic_manifest.get("bundle_format_version"),
            "signed": bool(diagnostic_manifest.get("signed", False)),
            "capture_complete": bool(diagnostic_manifest.get("capture_complete", False)),
            "fault_record_count": int(diagnostic_manifest.get("fault_record_count", 0)),
            "guidance_count": int(diagnostic_manifest.get("guidance_count", 0)),
            "artifact_count": len(diagnostic_manifest.get("artifacts", [])),
        },
        "timeline": {
            "root_chain_sha384": timeline_root,
            "audit_schema_version": timeline_audit_schema_version,
            "record_count": int(timeline.get("record_count", 0)),
            "boot_session_count": len(boot_sessions),
            "gap_count_total": total_gap_count,
            "input_file_count": len(timeline.get("input_files", [])),
        },
        "schema_versions": {
            "diagnostic_bundle_audit_schema_version": diagnostic_audit_schema_version,
            "timeline_audit_schema_version": timeline_audit_schema_version,
        },
        "severity_summary": {
            "presentation_locale": severity_summary.get("presentation_locale"),
            "overall_severity": overall,
            "partition_count": len(partitions),
            "top_partition_ids": [
                int(row.get("partition_id", 0))
                for row in partitions[:8]
                if isinstance(row, dict)
            ],
        },
        "operator_acknowledgment": ack_summary,
        "recovery_approval": recovery_summary,
        "origin_attestation": origin_summary,
        "break_glass": break_glass_summary,
        "session_correlation": session_correlation_summary,
        "compatibility_matrix": compatibility_summary,
        "panel_manifest": panel_summary,
        "warnings": warnings,
    }
    return correlation


def build_markdown(correlation: dict, locale: str) -> str:
    text = TEXT[locale]
    overall = correlation["severity_summary"]["overall_severity"]
    lines = [
        f"# {text['title']}",
        "",
        f"- {text['overall_severity']}: {overall.get('name', 'UNKNOWN')} ({overall.get('value', 'n/a')})",
        f"- {text['timeline_records']}: {correlation['timeline']['record_count']}",
        f"- {text['timeline_gaps']}: {correlation['timeline']['gap_count_total']}",
        f"- {text['ack_count']}: {correlation['operator_acknowledgment']['acknowledgment_count']}",
        f"- {text['diag_signed']}: {correlation['diagnostic_bundle']['signed']}",
        "",
        f"## {text['warnings']}",
        "",
    ]
    if correlation["warnings"]:
        for warning in correlation["warnings"]:
            lines.append(f"- {warning}")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Correlate standalone diagnostic bundle, incident timeline, severity summary, and optional operator artifacts."
    )
    parser.add_argument("--diagnostic-bundle", required=True, help="Standalone diagnostic bundle tar.gz")
    parser.add_argument("--timeline", required=True, help="Sealed incident timeline JSON")
    parser.add_argument("--severity-summary", required=True, help="operator-console-severity-summary.json")
    parser.add_argument("--ack-ledger", help="Optional operator acknowledgment ledger JSON")
    parser.add_argument("--recovery-approval", help="Optional recovery approval JSON")
    parser.add_argument("--origin-attestation", help="Optional command origin attestation JSON")
    parser.add_argument("--break-glass-ledger", help="Optional dedicated break-glass audit ledger JSON")
    parser.add_argument("--compatibility-matrix", help="Optional operator-tooling-compatibility-matrix.json")
    parser.add_argument("--panel-manifest", help="Optional ocs-panel-manifest.json")
    parser.add_argument("--locale", choices=SUPPORTED_LOCALES, default="en", help="Presentation locale for Markdown")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    output_dir = resolve_user_path(hypervisor_dir, args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    diagnostic_bundle = resolve_user_path(hypervisor_dir, args.diagnostic_bundle)
    timeline_path = resolve_user_path(hypervisor_dir, args.timeline)
    severity_path = resolve_user_path(hypervisor_dir, args.severity_summary)
    if not diagnostic_bundle.is_file():
        raise SystemExit(f"missing diagnostic bundle: {diagnostic_bundle}")
    if not timeline_path.is_file():
        raise SystemExit(f"missing timeline: {timeline_path}")
    if not severity_path.is_file():
        raise SystemExit(f"missing severity summary: {severity_path}")

    ack_ledger = None
    if args.ack_ledger is not None:
        ack_path = resolve_user_path(hypervisor_dir, args.ack_ledger)
        if not ack_path.is_file():
            raise SystemExit(f"missing acknowledgment ledger: {ack_path}")
        ack_ledger = read_json(ack_path)

    recovery_approval = None
    if args.recovery_approval is not None:
        approval_path = resolve_user_path(hypervisor_dir, args.recovery_approval)
        if not approval_path.is_file():
            raise SystemExit(f"missing recovery approval: {approval_path}")
        recovery_approval = read_json(approval_path)

    origin_attestation = None
    if args.origin_attestation is not None:
        origin_path = resolve_user_path(hypervisor_dir, args.origin_attestation)
        if not origin_path.is_file():
            raise SystemExit(f"missing origin attestation: {origin_path}")
        origin_attestation = read_json(origin_path)

    break_glass_ledger = None
    if args.break_glass_ledger is not None:
        break_glass_path = resolve_user_path(hypervisor_dir, args.break_glass_ledger)
        if not break_glass_path.is_file():
            raise SystemExit(f"missing break-glass ledger: {break_glass_path}")
        break_glass_ledger = read_json(break_glass_path)

    compatibility = None
    if args.compatibility_matrix is not None:
        matrix_path = resolve_user_path(hypervisor_dir, args.compatibility_matrix)
        if not matrix_path.is_file():
            raise SystemExit(f"missing compatibility matrix: {matrix_path}")
        compatibility = read_json(matrix_path)

    panel_manifest = None
    if args.panel_manifest is not None:
        panel_path = resolve_user_path(hypervisor_dir, args.panel_manifest)
        if not panel_path.is_file():
            raise SystemExit(f"missing panel manifest: {panel_path}")
        panel_manifest = read_json(panel_path)

    correlation = build_correlation(
        load_diagnostic_bundle_manifest(diagnostic_bundle),
        read_json(timeline_path),
        read_json(severity_path),
        ack_ledger,
        recovery_approval,
        origin_attestation,
        break_glass_ledger,
        compatibility,
        panel_manifest,
    )

    json_path = output_dir / "standalone-evidence-correlation.json"
    md_path = output_dir / "standalone-evidence-correlation.md"
    json_path.write_text(json.dumps(correlation, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(build_markdown(correlation, args.locale), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
