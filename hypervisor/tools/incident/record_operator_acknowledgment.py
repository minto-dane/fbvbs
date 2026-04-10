#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import pathlib


TOOL_VERSION = 1
LEDGER_SCHEMA_VERSION = 1


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha384_bytes(payload: bytes) -> str:
    digest = hashlib.sha384()
    digest.update(payload)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Append an operator acknowledgment to a standalone incident ledger."
    )
    parser.add_argument("--timeline-seal", required=True, help="Sealed incident timeline JSON")
    parser.add_argument("--severity-summary", required=True, help="Operator console severity summary JSON")
    parser.add_argument("--operator-id", required=True, help="Operator identity string")
    parser.add_argument("--session-correlation-id", required=True, help="Administrative session correlation identifier")
    parser.add_argument("--action", required=True, help="Acknowledgment action code")
    parser.add_argument("--note", default="", help="Optional short operator note")
    parser.add_argument("--output", required=True, help="Acknowledgment ledger JSON")
    parser.add_argument("--previous-ledger", help="Existing acknowledgment ledger to append to")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    timeline_path = resolve_user_path(hypervisor_dir, args.timeline_seal)
    severity_path = resolve_user_path(hypervisor_dir, args.severity_summary)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not timeline_path.is_file():
        raise SystemExit(f"missing timeline seal: {timeline_path}")
    if not severity_path.is_file():
        raise SystemExit(f"missing severity summary: {severity_path}")

    if args.previous_ledger is not None:
        previous_path = resolve_user_path(hypervisor_dir, args.previous_ledger)
        if not previous_path.is_file():
            raise SystemExit(f"missing previous ledger: {previous_path}")
        ledger = json.loads(previous_path.read_text(encoding="utf-8"))
        acknowledgments = ledger.get("acknowledgments", [])
        if not isinstance(acknowledgments, list):
            raise SystemExit("previous acknowledgment ledger must contain acknowledgments array")
        previous_session_id = str(ledger.get("session_correlation_id", ""))
        if previous_session_id and previous_session_id != args.session_correlation_id:
            raise SystemExit("previous acknowledgment ledger session_correlation_id does not match")
    else:
        acknowledgments = []

    timeline = json.loads(timeline_path.read_text(encoding="utf-8"))
    severity = json.loads(severity_path.read_text(encoding="utf-8"))
    timeline_root_hash = str(timeline.get("root_chain_sha384", ""))
    if len(timeline_root_hash) == 0:
        raise SystemExit("timeline seal must contain root_chain_sha384")

    previous_ack_hash = acknowledgments[-1]["ack_sha384"] if acknowledgments else "0" * 96
    entry = {
        "ack_sequence": len(acknowledgments) + 1,
        "acknowledged_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "operator_id": args.operator_id,
        "session_correlation_id": args.session_correlation_id,
        "action": args.action,
        "note": args.note,
        "timeline_root_chain_sha384": timeline_root_hash,
        "severity_name": str(
            severity.get("overall_severity", {}).get(
                "name",
                severity.get("overall_severity_name", "UNKNOWN"),
            )
        ),
        "previous_ack_sha384": previous_ack_hash,
    }
    entry["ack_sha384"] = sha384_bytes(canonical_json_bytes(entry))
    acknowledgments.append(entry)

    ledger = {
        "tool": {
            "name": "record_operator_acknowledgment.py",
            "version": TOOL_VERSION,
        },
        "ledger_schema_version": LEDGER_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "timeline_root_chain_sha384": timeline_root_hash,
        "session_correlation_id": args.session_correlation_id,
        "acknowledgment_count": len(acknowledgments),
        "latest_ack_sha384": acknowledgments[-1]["ack_sha384"],
        "acknowledgments": acknowledgments,
    }
    output_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
