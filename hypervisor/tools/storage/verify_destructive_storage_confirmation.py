#!/usr/bin/env python3

import argparse
import pathlib

import standalone_storage_policy as storage_policy


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a fail-closed destructive storage operation confirmation artifact."
    )
    parser.add_argument("--input", required=True, help="Confirmation JSON")
    parser.add_argument("--operation", help="Expected destructive storage operation")
    parser.add_argument("--session-correlation-id", help="Expected administrative session correlation identifier")
    parser.add_argument("--allow-expired", action="store_true", help="Allow expired confirmations")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    input_path = storage_policy.resolve_user_path(hypervisor_dir, args.input)
    if not input_path.is_file():
        raise SystemExit(f"missing destructive storage confirmation: {input_path}")

    payload = storage_policy.read_json(input_path)
    try:
        storage_policy.validate_destructive_confirmation_payload(
            payload,
            allow_expired=args.allow_expired,
            expected_operation=args.operation,
            expected_session_correlation_id=args.session_correlation_id,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Verified {input_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
