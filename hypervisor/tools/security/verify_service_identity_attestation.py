#!/usr/bin/env python3

import argparse
import pathlib

import standalone_service_plane as service_plane


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a standalone service identity attestation."
    )
    parser.add_argument("--input", required=True, help="Service identity attestation JSON")
    parser.add_argument("--service-profile", help="Expected service profile")
    parser.add_argument("--session-correlation-id", help="Expected administrative session correlation identifier")
    parser.add_argument("--allow-expired", action="store_true", help="Allow expired attestations")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    input_path = service_plane.resolve_user_path(hypervisor_dir, args.input)
    if not input_path.is_file():
        raise SystemExit(f"missing service identity attestation: {input_path}")

    payload = service_plane.read_json(input_path)
    try:
        service_plane.validate_service_identity_attestation_payload(
            payload,
            script_path,
            allow_expired=args.allow_expired,
            expected_service_profile=args.service_profile,
            expected_session_correlation_id=args.session_correlation_id,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Verified {input_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
