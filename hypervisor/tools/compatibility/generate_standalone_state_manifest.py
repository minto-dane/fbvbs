#!/usr/bin/env python3

import argparse
import json
import pathlib

import correlate_standalone_incident_artifacts as correlate
import standalone_state_manifest as state_manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a standalone state manifest from evidence and operator artifacts."
    )
    parser.add_argument("--diagnostic-bundle", required=True, help="Standalone diagnostic bundle tar.gz")
    parser.add_argument("--timeline", required=True, help="Sealed incident timeline JSON")
    parser.add_argument("--severity-summary", required=True, help="operator-console-severity-summary.json")
    parser.add_argument("--output", required=True, help="Output standalone-state-manifest.json path")
    parser.add_argument("--ack-ledger", help="Optional operator acknowledgment ledger JSON")
    parser.add_argument("--origin-attestation", help="Optional command origin attestation JSON")
    parser.add_argument("--break-glass-ledger", help="Optional dedicated break-glass audit ledger JSON")
    parser.add_argument("--compatibility-matrix", help="Optional operator-tooling-compatibility-matrix.json")
    parser.add_argument("--panel-manifest", help="Optional ocs-panel-manifest.json")
    parser.add_argument("--evidence-pack-format-version", type=int, help="Optional evidence pack format version")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    output_path = correlate.resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = state_manifest.generate_state_manifest_from_paths(
        diagnostic_bundle_path=correlate.resolve_user_path(hypervisor_dir, args.diagnostic_bundle),
        timeline_path=correlate.resolve_user_path(hypervisor_dir, args.timeline),
        severity_path=correlate.resolve_user_path(hypervisor_dir, args.severity_summary),
        ack_path=correlate.resolve_user_path(hypervisor_dir, args.ack_ledger) if args.ack_ledger else None,
        origin_path=correlate.resolve_user_path(hypervisor_dir, args.origin_attestation) if args.origin_attestation else None,
        break_glass_path=correlate.resolve_user_path(hypervisor_dir, args.break_glass_ledger) if args.break_glass_ledger else None,
        matrix_path=correlate.resolve_user_path(hypervisor_dir, args.compatibility_matrix) if args.compatibility_matrix else None,
        panel_path=correlate.resolve_user_path(hypervisor_dir, args.panel_manifest) if args.panel_manifest else None,
        evidence_pack_format_version=args.evidence_pack_format_version,
    )
    state_manifest.write_manifest(output_path, payload)
    print(json.dumps({"state_manifest": str(output_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
