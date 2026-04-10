#!/usr/bin/env python3

import argparse
import pathlib

import standalone_operator_security as security


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a standalone break-glass audit ledger."
    )
    parser.add_argument("--input", required=True, help="Break-glass ledger JSON")
    parser.add_argument("--timeline-root-sha384", help="Expected timeline root chain SHA-384")
    parser.add_argument("--session-correlation-id", help="Expected administrative session correlation identifier")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    input_path = security.resolve_user_path(hypervisor_dir, args.input)
    if not input_path.is_file():
        raise SystemExit(f"missing break-glass ledger: {input_path}")

    payload = security.read_json(input_path)
    try:
        security.validate_break_glass_ledger_payload(
            payload,
            expected_timeline_root=args.timeline_root_sha384,
            expected_session_correlation_id=args.session_correlation_id,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    print(f"Verified {input_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
