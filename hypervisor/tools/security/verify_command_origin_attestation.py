#!/usr/bin/env python3

import argparse
import pathlib

import standalone_operator_security as security


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a standalone command origin attestation."
    )
    parser.add_argument("--input", required=True, help="Origin attestation JSON")
    parser.add_argument("--call", help="Expected call macro name")
    parser.add_argument("--operator-role", help="Expected operator role")
    parser.add_argument("--session-correlation-id", help="Expected administrative session correlation identifier")
    parser.add_argument("--timeline-root-sha384", help="Expected incident timeline root chain SHA-384")
    parser.add_argument("--allow-expired", action="store_true", help="Allow expired attestations during verification")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    input_path = security.resolve_user_path(hypervisor_dir, args.input)
    if not input_path.is_file():
        raise SystemExit(f"missing origin attestation: {input_path}")

    payload = security.read_json(input_path)
    try:
        security.validate_origin_attestation_payload(
            payload,
            script_path,
            allow_expired=args.allow_expired,
            expected_call_name=args.call,
            expected_operator_role=args.operator_role,
            expected_session_correlation_id=args.session_correlation_id,
            expected_timeline_root=args.timeline_root_sha384,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Verified {input_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
