#!/usr/bin/env python3

import argparse
import pathlib

import standalone_service_plane as service_plane


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the append-only standalone service lifecycle audit ledger."
    )
    parser.add_argument("--input", required=True, help="Service lifecycle ledger JSON")
    parser.add_argument("--service-profile", help="Expected service profile")
    parser.add_argument("--session-correlation-id", help="Expected administrative session correlation identifier")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    input_path = service_plane.resolve_user_path(hypervisor_dir, args.input)
    if not input_path.is_file():
        raise SystemExit(f"missing service lifecycle ledger: {input_path}")

    payload = service_plane.read_json(input_path)
    try:
        service_plane.validate_service_lifecycle_ledger_payload(
            payload,
            script_path,
            expected_service_profile=args.service_profile,
            expected_session_correlation_id=args.session_correlation_id,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Verified {input_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
