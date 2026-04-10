#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib
import tarfile
import tempfile

import correlate_standalone_incident_artifacts as correlate
import export_diagnostic_bundle as diag_bundle
import standalone_state_manifest as state_manifest


PACK_FORMAT_VERSION = 1
TOOL_VERSION = 1


def resolve_allowed_input_path(
    base_dir: pathlib.Path,
    raw_path: str,
    allowed_roots: list[pathlib.Path],
) -> pathlib.Path:
    resolved = diag_bundle.resolve_user_path(base_dir, raw_path)
    if not resolved.exists():
        return resolved
    if diag_bundle.has_symlink_component(resolved):
        raise SystemExit(f"refusing symlink-backed evidence input: {resolved}")
    if not any(diag_bundle.path_is_within_root(resolved, root) for root in allowed_roots):
        raise SystemExit(
            "evidence input is outside allowed roots:\n"
            f"{resolved}\n"
            "pass --allow-input-root for an explicit collection root"
        )
    return resolved


def make_artifact(
    source: pathlib.Path,
    archive_path: str,
    kind: str,
    allowed_roots: list[pathlib.Path],
) -> dict:
    return {
        "source": source,
        "archive_path": archive_path,
        "kind": kind,
        "source_root_index": diag_bundle.root_index_for_path(source, allowed_roots),
        "source_path": diag_bundle.relative_source_path(source, allowed_roots),
    }


def build_manifest(
    artifacts: list[dict],
    correlation_summary: dict,
    signature_metadata: dict,
    note: str | None,
    capture_complete: bool,
    forensic_preservation: dict | None,
) -> dict:
    entries = []
    for artifact in artifacts:
        path = artifact["source"]
        entries.append(
            {
                "archive_path": artifact["archive_path"],
                "logical_name": artifact["archive_path"].split("/")[-1],
                "source_root_index": artifact["source_root_index"],
                "source_path": artifact["source_path"],
                "kind": artifact["kind"],
                "sha384": diag_bundle.file_sha384(path),
                "size_bytes": path.stat().st_size,
            }
        )
    collection_warnings = list(correlation_summary.get("warnings", []))
    if not capture_complete:
        collection_warnings.append(
            "evidence pack completeness not asserted; operator must verify artifact coverage"
        )
    return {
        "bundle_type": "fbvbs-standalone-evidence-pack",
        "pack_format_version": PACK_FORMAT_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "bundle_root": "evidence",
        "tool": {
            "name": "generate_standalone_evidence_pack.py",
            "version": TOOL_VERSION,
        },
        "signed": bool(signature_metadata["signed"]),
        "note": note,
        "capture_complete": capture_complete,
        "session_correlation_id": correlation_summary.get("operator_acknowledgment", {}).get("session_correlation_id"),
        "collection_warnings": collection_warnings,
        "signature": signature_metadata,
        "correlation_summary": correlation_summary,
        "forensic_preservation": forensic_preservation,
        "artifacts": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a standalone evidence pack from diagnostic, timeline, operator, and UI artifacts."
    )
    parser.add_argument("--output", required=True, help="Output tar.gz evidence pack path")
    parser.add_argument("--diagnostic-bundle", required=True, help="Standalone diagnostic bundle tar.gz")
    parser.add_argument("--timeline", required=True, help="Sealed incident timeline JSON")
    parser.add_argument("--severity-summary", required=True, help="operator-console-severity-summary.json")
    parser.add_argument("--ack-ledger", help="Optional operator acknowledgment ledger JSON")
    parser.add_argument("--recovery-approval", help="Optional recovery approval JSON")
    parser.add_argument("--origin-attestation", help="Optional command origin attestation JSON")
    parser.add_argument("--break-glass-ledger", help="Optional dedicated break-glass audit ledger JSON")
    parser.add_argument("--compatibility-matrix", help="Optional operator-tooling-compatibility-matrix.json")
    parser.add_argument("--panel-manifest", help="Optional ocs-panel-manifest.json")
    parser.add_argument("--include", action="append", default=[], help="Optional extra evidence artifact")
    parser.add_argument("--locale", choices=correlate.SUPPORTED_LOCALES, default="en", help="Locale for correlation markdown")
    parser.add_argument("--note", help="Optional operator note recorded in manifest")
    parser.add_argument("--capture-complete", action="store_true", help="Assert that the supplied artifacts represent a complete evidence pack")
    parser.add_argument(
        "--forensic-preservation-mode",
        action="store_true",
        help="Enable forensic preservation mode; requires capture-complete and a signing key",
    )
    parser.add_argument("--signing-key", help="PEM private key for detached manifest signature")
    parser.add_argument("--signing-cert", help="Optional PEM certificate to include alongside signature")
    parser.add_argument("--allow-input-root", action="append", default=[], help="Explicitly allow evidence inputs from this root in addition to the repository")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    repo_root = hypervisor_dir.parent
    output_path = diag_bundle.resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    allowed_roots = [repo_root.resolve()]
    allowed_roots.extend(
        diag_bundle.resolve_user_path(repo_root, raw_root).resolve() for raw_root in args.allow_input_root
    )

    diagnostic_bundle_path = resolve_allowed_input_path(hypervisor_dir, args.diagnostic_bundle, allowed_roots)
    timeline_path = resolve_allowed_input_path(hypervisor_dir, args.timeline, allowed_roots)
    severity_path = resolve_allowed_input_path(hypervisor_dir, args.severity_summary, allowed_roots)
    ack_path = resolve_allowed_input_path(hypervisor_dir, args.ack_ledger, allowed_roots) if args.ack_ledger else None
    recovery_path = resolve_allowed_input_path(hypervisor_dir, args.recovery_approval, allowed_roots) if args.recovery_approval else None
    origin_path = resolve_allowed_input_path(hypervisor_dir, args.origin_attestation, allowed_roots) if args.origin_attestation else None
    break_glass_path = resolve_allowed_input_path(hypervisor_dir, args.break_glass_ledger, allowed_roots) if args.break_glass_ledger else None
    matrix_path = resolve_allowed_input_path(hypervisor_dir, args.compatibility_matrix, allowed_roots) if args.compatibility_matrix else None
    panel_path = resolve_allowed_input_path(hypervisor_dir, args.panel_manifest, allowed_roots) if args.panel_manifest else None
    extra_paths = [resolve_allowed_input_path(hypervisor_dir, item, allowed_roots) for item in args.include]

    if args.signing_key is not None:
        signing_key = resolve_allowed_input_path(hypervisor_dir, args.signing_key, allowed_roots)
    else:
        signing_key = None
    if args.signing_cert is not None:
        signing_cert = resolve_allowed_input_path(hypervisor_dir, args.signing_cert, allowed_roots)
    else:
        signing_cert = None

    if args.forensic_preservation_mode:
        if not args.capture_complete:
            raise SystemExit("forensic preservation mode requires --capture-complete")
        if signing_key is None:
            raise SystemExit("forensic preservation mode requires --signing-key")

    required = [diagnostic_bundle_path, timeline_path, severity_path]
    missing = [str(path) for path in required if not path.is_file()]
    for optional_path in [ack_path, recovery_path, origin_path, break_glass_path, matrix_path, panel_path, signing_key, signing_cert]:
        if optional_path is not None and not optional_path.is_file():
            missing.append(str(optional_path))
    missing.extend(str(path) for path in extra_paths if not path.is_file())
    if missing:
        raise SystemExit("missing evidence pack inputs:\n" + "\n".join(missing))

    diagnostic_manifest = correlate.load_diagnostic_bundle_manifest(diagnostic_bundle_path)
    correlation_summary = correlate.build_correlation(
        diagnostic_manifest,
        correlate.read_json(timeline_path),
        correlate.read_json(severity_path),
        correlate.read_json(ack_path) if ack_path is not None else None,
        correlate.read_json(recovery_path) if recovery_path is not None else None,
        correlate.read_json(origin_path) if origin_path is not None else None,
        correlate.read_json(break_glass_path) if break_glass_path is not None else None,
        correlate.read_json(matrix_path) if matrix_path is not None else None,
        correlate.read_json(panel_path) if panel_path is not None else None,
    )

    artifacts = [
        make_artifact(diagnostic_bundle_path, "evidence/diagnostic-bundle.tar.gz", "diagnostic-bundle", allowed_roots),
        make_artifact(timeline_path, "evidence/timeline-sealed.json", "timeline-sealed", allowed_roots),
        make_artifact(severity_path, "evidence/operator-console-severity-summary.json", "severity-summary", allowed_roots),
    ]
    if ack_path is not None:
        artifacts.append(make_artifact(ack_path, "evidence/operator-ack-ledger.json", "operator-ack-ledger", allowed_roots))
    if recovery_path is not None:
        artifacts.append(make_artifact(recovery_path, "evidence/recovery-approval.json", "recovery-approval", allowed_roots))
    if origin_path is not None:
        artifacts.append(make_artifact(origin_path, "evidence/origin-attestation.json", "origin-attestation", allowed_roots))
    if break_glass_path is not None:
        artifacts.append(make_artifact(break_glass_path, "evidence/break-glass-ledger.json", "break-glass-ledger", allowed_roots))
    if matrix_path is not None:
        artifacts.append(make_artifact(matrix_path, "evidence/operator-tooling-compatibility-matrix.json", "compatibility-matrix", allowed_roots))
    if panel_path is not None:
        artifacts.append(make_artifact(panel_path, "ui/ocs-panel-manifest.json", "panel-manifest", allowed_roots))
    artifacts.extend(
        make_artifact(path, f"evidence/extra-{index:02d}-{path.name}", "extra", allowed_roots)
        for index, path in enumerate(extra_paths)
    )
    if signing_cert is not None:
        artifacts.append(
            make_artifact(signing_cert, "evidence/evidence-pack-signer.pem", "signing-certificate", allowed_roots)
        )

    signature_metadata = {
        "signed": signing_key is not None,
        "manifest_path": "evidence/standalone-evidence-pack-manifest.json",
        "signature_path": None,
        "signature_algorithm": None,
        "public_key_fingerprint_sha384": None,
        "verification_hint": None,
        "certificate_path": None,
        "certificate_fingerprint_sha384": None,
        "certificate_subject": None,
    }
    if signing_key is not None:
        signature_metadata.update(
            {
                "signature_path": "evidence/standalone-evidence-pack-manifest.sig",
                "signature_algorithm": "openssl-dgst-sha384",
                "public_key_fingerprint_sha384": diag_bundle.public_key_sha384(signing_key),
                "verification_hint": (
                    "openssl dgst -sha384 -verify <public-key.pem> "
                    "-signature evidence/standalone-evidence-pack-manifest.sig "
                    "evidence/standalone-evidence-pack-manifest.json"
                ),
            }
        )
        if signing_cert is not None:
            signature_metadata.update(
                {
                    "certificate_path": "evidence/evidence-pack-signer.pem",
                    "certificate_fingerprint_sha384": diag_bundle.certificate_sha384(signing_cert),
                    "certificate_subject": diag_bundle.certificate_subject(signing_cert),
                }
            )

    with tempfile.TemporaryDirectory(prefix="fbvbs-evidence-pack-") as temp_dir_raw:
        temp_dir = pathlib.Path(temp_dir_raw)
        manifest_path = temp_dir / "standalone-evidence-pack-manifest.json"
        correlation_json_path = temp_dir / "standalone-evidence-correlation.json"
        correlation_md_path = temp_dir / "standalone-evidence-correlation.md"
        signature_path = temp_dir / "standalone-evidence-pack-manifest.sig"
        forensic_path = temp_dir / "forensic-preservation.json"
        state_manifest_path = temp_dir / "standalone-state-manifest.json"

        correlation_json_path.write_text(
            json.dumps(correlation_summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        correlation_md_path.write_text(
            correlate.build_markdown(correlation_summary, args.locale),
            encoding="utf-8",
        )

        if args.forensic_preservation_mode:
            forensic_preservation = {
                "enabled": True,
                "mode": "append-only-preservation",
                "retention_lock_required": True,
                "operator_mutation_allowed": False,
                "recommended_storage_class": "immutable-evidence-tier",
                "time_source_integrity_required": True,
            }
            forensic_path.write_text(
                json.dumps(forensic_preservation, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        else:
            forensic_preservation = None

        state_payload = state_manifest.build_state_manifest(
            diagnostic_manifest,
            correlate.read_json(timeline_path),
            correlate.read_json(severity_path),
            correlate.read_json(ack_path) if ack_path is not None else None,
            correlate.read_json(origin_path) if origin_path is not None else None,
            correlate.read_json(break_glass_path) if break_glass_path is not None else None,
            correlate.read_json(matrix_path) if matrix_path is not None else None,
            correlate.read_json(panel_path) if panel_path is not None else None,
            evidence_pack_format_version=PACK_FORMAT_VERSION,
        )
        state_manifest.write_manifest(state_manifest_path, state_payload)

        generated_artifacts = [
            {
                "source": correlation_json_path,
                "archive_path": "evidence/standalone-evidence-correlation.json",
                "kind": "correlation-summary",
                "source_root_index": -1,
                "source_path": "generated/standalone-evidence-correlation.json",
            },
            {
                "source": correlation_md_path,
                "archive_path": "docs/standalone-evidence-correlation.md",
                "kind": "correlation-markdown",
                "source_root_index": -1,
                "source_path": "generated/standalone-evidence-correlation.md",
            },
            {
                "source": state_manifest_path,
                "archive_path": "evidence/standalone-state-manifest.json",
                "kind": "state-manifest",
                "source_root_index": -1,
                "source_path": "generated/standalone-state-manifest.json",
            },
        ]
        if args.forensic_preservation_mode:
            generated_artifacts.append(
                {
                    "source": forensic_path,
                    "archive_path": "evidence/forensic-preservation.json",
                    "kind": "forensic-preservation",
                    "source_root_index": -1,
                    "source_path": "generated/forensic-preservation.json",
                }
            )

        manifest = build_manifest(
            artifacts + generated_artifacts,
            correlation_summary,
            signature_metadata,
            args.note,
            args.capture_complete,
            forensic_preservation,
        )
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        if signing_key is not None:
            diag_bundle.sign_manifest(manifest_path, signature_path, signing_key)

        index_lines = ["FBVBS standalone evidence pack", ""]
        with tarfile.open(output_path, "w:gz") as archive:
            for artifact in artifacts:
                diag_bundle.add_file(archive, artifact["source"], artifact["archive_path"], index_lines)
            diag_bundle.add_file(
                archive,
                correlation_json_path,
                "evidence/standalone-evidence-correlation.json",
                index_lines,
            )
            diag_bundle.add_file(
                archive,
                correlation_md_path,
                "docs/standalone-evidence-correlation.md",
                index_lines,
            )
            diag_bundle.add_file(
                archive,
                state_manifest_path,
                "evidence/standalone-state-manifest.json",
                index_lines,
            )
            if args.forensic_preservation_mode:
                diag_bundle.add_file(
                    archive,
                    forensic_path,
                    "evidence/forensic-preservation.json",
                    index_lines,
                )
            diag_bundle.add_file(
                archive,
                manifest_path,
                "evidence/standalone-evidence-pack-manifest.json",
                index_lines,
            )
            if signing_key is not None:
                diag_bundle.add_file(
                    archive,
                    signature_path,
                    "evidence/standalone-evidence-pack-manifest.sig",
                    index_lines,
                )

    index_path = output_path.with_suffix("").with_suffix(".index.txt")
    index_path.write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    print(json.dumps({"bundle": str(output_path), "index": str(index_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
