#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib

import standalone_service_plane as service_plane


TOOL_VERSION = 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Issue a fail-closed service identity attestation for standalone service partitions."
    )
    parser.add_argument("--service-profile", required=True, help="Service profile name")
    parser.add_argument("--service-instance-id", required=True, help="Unique service instance identifier")
    parser.add_argument("--session-correlation-id", required=True, help="Administrative session correlation identifier")
    parser.add_argument("--partition-id", type=int, required=True, help="Service partition identifier")
    parser.add_argument("--service-kind", help="Optional ABI service kind macro name")
    parser.add_argument("--measurement-epoch", type=int, default=0, help="Optional measurement epoch")
    parser.add_argument("--image-digest-sha384", required=True, help="Service image digest")
    parser.add_argument("--signer-identity", required=True, help="Service signer or workload identity")
    parser.add_argument("--valid-hours", type=int, default=8, help="Validity window in hours")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()

    if args.valid_hours <= 0:
        raise SystemExit("valid-hours must be positive")

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    output_path = service_plane.resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    row = service_plane.service_profile_row(script_path, args.service_profile)
    service_kind = None
    if args.service_kind is not None:
        for entry in row["service_kind_choices"]:
            if entry["name"] == args.service_kind:
                service_kind = entry
                break
        if service_kind is None:
            raise SystemExit("service-kind is not allowed for the selected service profile")
    elif row["service_kind_choices"]:
        service_kind = row["service_kind_choices"][0]

    issued_utc = datetime.datetime.now(datetime.timezone.utc)
    expires_utc = issued_utc + datetime.timedelta(hours=args.valid_hours)
    payload = {
        "tool": {"name": "issue_service_identity_attestation.py", "version": TOOL_VERSION},
        "service_identity_attestation_schema_version": service_plane.SERVICE_IDENTITY_ATTESTATION_SCHEMA_VERSION,
        "issued_utc": issued_utc.isoformat(),
        "expires_utc": expires_utc.isoformat(),
        "service_profile": args.service_profile,
        "service_instance_id": args.service_instance_id,
        "session_correlation_id": args.session_correlation_id,
        "partition_id": args.partition_id,
        "measurement_epoch": args.measurement_epoch,
        "service_kind": service_kind,
        "required_capabilities": row["required_capabilities"],
        "capability_mask": row["required_capability_mask"],
        "access_policy_sha384": row["access_policy_sha384"],
        "peer_policy_sha384": row["peer_policy_sha384"],
        "service_identity": {
            "image_digest_sha384": args.image_digest_sha384,
            "signer_identity": args.signer_identity,
        },
    }
    payload["service_identity_attestation_sha384"] = service_plane.sha384_bytes(
        service_plane.canonical_json_bytes(
            {k: v for k, v in payload.items() if k != "service_identity_attestation_sha384"}
        )
    )
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
