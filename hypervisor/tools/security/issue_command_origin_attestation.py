#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib

import standalone_operator_security as security


TOOL_VERSION = 1
ORIGIN_ATTESTATION_SCHEMA_VERSION = 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Issue a fail-closed standalone command origin attestation."
    )
    parser.add_argument("--call", required=True, help="Standalone call macro name")
    parser.add_argument("--operator-id", required=True, help="Operator identity string")
    parser.add_argument("--operator-role", required=True, help="Operator role name")
    parser.add_argument("--session-correlation-id", required=True, help="Administrative session correlation identifier")
    parser.add_argument("--origin-transport", required=True, choices=tuple(security.TRANSPORT_TO_CONSOLES.keys()), help="Origin transport class")
    parser.add_argument("--origin-console", required=True, help="Origin console/profile name")
    parser.add_argument("--host-callsite", required=True, help="Host callsite macro name")
    parser.add_argument("--locale", choices=("en", "ja"), default="en", help="Presentation locale")
    parser.add_argument("--partition-id", type=int, help="Optional target partition identifier")
    parser.add_argument("--justification", default="", help="Operator justification or ticket summary")
    parser.add_argument("--timeline-root-sha384", help="Optional sealed incident timeline root")
    parser.add_argument("--valid-hours", type=int, default=4, help="Validity window in hours")
    parser.add_argument("--break-glass", action="store_true", help="Mark the command as break-glass operation")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()

    if args.valid_hours <= 0:
        raise SystemExit("valid-hours must be positive")
    if not args.operator_id:
        raise SystemExit("operator-id must be non-empty")
    if not args.session_correlation_id:
        raise SystemExit("session-correlation-id must be non-empty")

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    output_path = security.resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    row = security.privilege_row_by_call(script_path, args.call)
    if args.operator_role not in security.ROLE_CATALOG:
        raise SystemExit(f"unknown operator role: {args.operator_role}")
    if args.operator_role not in row["authorization"]["allowed_roles"]:
        raise SystemExit("operator role is not authorized for the requested call")
    security.validate_transport_console(args.origin_transport, args.origin_console)
    host_callsite = security.validate_host_callsite(script_path, args.host_callsite)

    if args.break_glass and not row["authorization"]["break_glass_eligible"]:
        raise SystemExit("requested call is not eligible for break-glass operation")
    if args.break_glass and not args.justification:
        raise SystemExit("break-glass origin attestation requires justification")
    if args.break_glass and not args.timeline_root_sha384:
        raise SystemExit("break-glass origin attestation requires timeline-root-sha384")

    issued_utc = datetime.datetime.now(datetime.timezone.utc)
    expires_utc = issued_utc + datetime.timedelta(hours=args.valid_hours)
    payload = {
        "tool": {
            "name": "issue_command_origin_attestation.py",
            "version": TOOL_VERSION,
        },
        "origin_attestation_schema_version": ORIGIN_ATTESTATION_SCHEMA_VERSION,
        "issued_utc": issued_utc.isoformat(),
        "expires_utc": expires_utc.isoformat(),
        "operator_id": args.operator_id,
        "operator_role": args.operator_role,
        "session_correlation_id": args.session_correlation_id,
        "call": row["call"],
        "operation": row["operation"],
        "authorization": row["authorization"],
        "approval_required": row["approval_required"],
        "origin": {
            "transport": args.origin_transport,
            "console": args.origin_console,
            "locale": args.locale,
            "host_callsite": host_callsite,
        },
        "command_context": {
            "partition_id": args.partition_id,
            "break_glass": args.break_glass,
            "justification": args.justification,
            "timeline_root_chain_sha384": args.timeline_root_sha384,
        },
    }
    payload["origin_attestation_sha384"] = security.sha384_bytes(
        security.canonical_json_bytes({k: v for k, v in payload.items() if k != "origin_attestation_sha384"})
    )
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
