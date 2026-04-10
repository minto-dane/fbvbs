#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib

import standalone_operator_security as security


TOOL_VERSION = 1
BREAK_GLASS_LEDGER_SCHEMA_VERSION = 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Append a break-glass operator action to the dedicated standalone audit ledger."
    )
    parser.add_argument("--origin-attestation", required=True, help="Origin attestation JSON")
    parser.add_argument("--timeline-seal", required=True, help="Sealed incident timeline JSON")
    parser.add_argument("--severity-summary", required=True, help="Operator console severity summary JSON")
    parser.add_argument("--ack-ledger", required=True, help="Operator acknowledgment ledger JSON")
    parser.add_argument("--ticket-id", required=True, help="Emergency ticket or approval identifier")
    parser.add_argument("--operator-id", required=True, help="Operator identity string")
    parser.add_argument("--output", required=True, help="Break-glass ledger JSON")
    parser.add_argument("--previous-ledger", help="Existing break-glass ledger to append to")
    parser.add_argument("--note", default="", help="Optional short operator note")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    origin_path = security.resolve_user_path(hypervisor_dir, args.origin_attestation)
    timeline_path = security.resolve_user_path(hypervisor_dir, args.timeline_seal)
    severity_path = security.resolve_user_path(hypervisor_dir, args.severity_summary)
    ack_path = security.resolve_user_path(hypervisor_dir, args.ack_ledger)
    output_path = security.resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not origin_path.is_file():
        raise SystemExit(f"missing origin attestation: {origin_path}")
    if not timeline_path.is_file():
        raise SystemExit(f"missing timeline seal: {timeline_path}")
    if not severity_path.is_file():
        raise SystemExit(f"missing severity summary: {severity_path}")
    if not ack_path.is_file():
        raise SystemExit(f"missing acknowledgment ledger: {ack_path}")

    timeline = security.read_json(timeline_path)
    severity = security.read_json(severity_path)
    ack_ledger = security.read_json(ack_path)
    timeline_root = str(timeline.get("root_chain_sha384", ""))
    if not timeline_root:
        raise SystemExit("timeline seal must contain root_chain_sha384")

    origin_payload = security.read_json(origin_path)
    try:
        origin_info = security.validate_origin_attestation_payload(
            origin_payload,
            script_path,
            expected_timeline_root=timeline_root,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if not origin_info["break_glass"]:
        raise SystemExit("origin attestation is not marked as break-glass")
    if str(origin_payload.get("operator_id", "")) != args.operator_id:
        raise SystemExit("operator-id does not match origin attestation operator_id")

    if str(ack_ledger.get("timeline_root_chain_sha384", "")) != timeline_root:
        raise SystemExit("ack ledger timeline_root_chain_sha384 does not match timeline root")
    session_correlation_id = str(ack_ledger.get("session_correlation_id", ""))
    if not session_correlation_id:
        raise SystemExit("ack ledger must contain session_correlation_id")
    if int(ack_ledger.get("acknowledgment_count", 0)) <= 0:
        raise SystemExit("break-glass audit requires at least one operator acknowledgment")
    if session_correlation_id != origin_info["session_correlation_id"]:
        raise SystemExit("origin attestation session_correlation_id does not match acknowledgment ledger")

    partition_id = origin_payload.get("command_context", {}).get("partition_id")
    if partition_id is not None:
        matched_partition = None
        for row in severity.get("partitions", []):
            if isinstance(row, dict) and int(row.get("partition_id", -1)) == int(partition_id):
                matched_partition = row
                break
        if matched_partition is None:
            raise SystemExit("break-glass partition_id is not present in severity summary")

    if args.previous_ledger is not None:
        previous_path = security.resolve_user_path(hypervisor_dir, args.previous_ledger)
        if not previous_path.is_file():
            raise SystemExit(f"missing previous break-glass ledger: {previous_path}")
        ledger = security.read_json(previous_path)
        try:
            security.validate_break_glass_ledger_payload(
                ledger,
                expected_timeline_root=timeline_root,
                expected_session_correlation_id=session_correlation_id,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        events = list(ledger.get("break_glass_events", []))
    else:
        events = []

    previous_hash = events[-1]["break_glass_sha384"] if events else "0" * 96
    event = {
        "break_glass_sequence": len(events) + 1,
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "operator_id": args.operator_id,
        "operator_role": origin_payload.get("operator_role"),
        "ticket_id": args.ticket_id,
        "note": args.note,
        "timeline_root_chain_sha384": timeline_root,
        "session_correlation_id": session_correlation_id,
        "latest_ack_sha384": ack_ledger.get("latest_ack_sha384"),
        "audit_event": "FBVBS_EVENT_OPERATOR_BREAK_GLASS",
        "call": origin_info["authorization_row"]["call"],
        "operation": origin_info["authorization_row"]["operation"],
        "origin_attestation_sha384": origin_payload.get("origin_attestation_sha384"),
        "justification": origin_payload.get("command_context", {}).get("justification"),
        "partition_id": partition_id,
        "previous_break_glass_sha384": previous_hash,
    }
    event["break_glass_sha384"] = security.sha384_bytes(
        security.canonical_json_bytes({k: v for k, v in event.items() if k != "break_glass_sha384"})
    )
    events.append(event)

    ledger = {
        "tool": {
            "name": "record_break_glass_audit.py",
            "version": TOOL_VERSION,
        },
        "break_glass_ledger_schema_version": BREAK_GLASS_LEDGER_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "audit_channel": "operator-break-glass",
        "timeline_root_chain_sha384": timeline_root,
        "session_correlation_id": session_correlation_id,
        "break_glass_count": len(events),
        "latest_break_glass_sha384": events[-1]["break_glass_sha384"],
        "break_glass_events": events,
    }
    output_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
