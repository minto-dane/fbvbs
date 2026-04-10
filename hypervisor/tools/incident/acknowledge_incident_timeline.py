#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib

from seal_incident_timeline import canonical_json_bytes, resolve_user_path, sha384_bytes


TOOL_VERSION = 1
ACK_SCHEMA_VERSION = 1


def verify_timeline_root(timeline: dict) -> str:
    records = timeline.get("records")
    record_chain = timeline.get("record_chain")
    if not isinstance(records, list) or not isinstance(record_chain, list):
        raise SystemExit("sealed incident timeline must contain records and record_chain sections")
    if len(records) != len(record_chain):
        raise SystemExit("sealed incident timeline record chain length mismatch")

    previous_hash = "0" * 96
    for index, record in enumerate(records):
        chain_entry = record_chain[index]
        if not isinstance(record, dict):
            raise SystemExit("sealed incident timeline records must be objects")
        if not isinstance(chain_entry, dict):
            raise SystemExit("sealed incident timeline chain entries must be objects")
        if chain_entry.get("previous_chain_sha384") != previous_hash:
            raise SystemExit("sealed incident timeline previous chain hash mismatch")
        record_hash = sha384_bytes(canonical_json_bytes(record))
        if chain_entry.get("record_sha384") != record_hash:
            raise SystemExit("sealed incident timeline record_sha384 mismatch")
        chain_hash = sha384_bytes((previous_hash + record_hash).encode("ascii"))
        if chain_entry.get("chain_sha384") != chain_hash:
            raise SystemExit("sealed incident timeline chain_sha384 mismatch")
        previous_hash = chain_hash

    if timeline.get("root_chain_sha384") != previous_hash:
        raise SystemExit("sealed incident timeline root hash mismatch")
    return previous_hash


def read_json(path: pathlib.Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"sealed incident timeline JSON must be an object: {path}")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create an operator acknowledgment artifact for a sealed incident timeline."
    )
    parser.add_argument("--timeline", required=True, help="Sealed incident timeline JSON")
    parser.add_argument("--operator-id", required=True, help="Operator identifier")
    parser.add_argument("--session-correlation-id", required=True, help="Administrative session correlation identifier")
    parser.add_argument("--acknowledgment-id", required=True, help="Acknowledgment identifier")
    parser.add_argument("--decision", required=True, help="Acknowledgment decision label")
    parser.add_argument("--note", default="", help="Optional operator note")
    parser.add_argument("--output", required=True, help="Acknowledgment JSON output")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    timeline_path = resolve_user_path(hypervisor_dir, args.timeline)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    timeline = read_json(timeline_path)
    timeline_root = verify_timeline_root(timeline)
    boot_sessions = timeline.get("boot_sessions", [])
    gap_count = sum(int(session.get("gap_count", 0)) for session in boot_sessions if isinstance(session, dict))
    ack = {
        "tool": {
            "name": "acknowledge_incident_timeline.py",
            "version": TOOL_VERSION,
        },
        "schema_version": ACK_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "acknowledgment_id": args.acknowledgment_id,
        "operator_id": args.operator_id,
        "session_correlation_id": args.session_correlation_id,
        "decision": args.decision,
        "note": args.note,
        "timeline_root_sha384": timeline_root,
        "timeline_record_count": int(timeline.get("record_count", len(timeline.get("records", [])))),
        "timeline_gap_count": gap_count,
        "boot_ids": [
            session.get("boot_id")
            for session in boot_sessions
            if isinstance(session, dict) and session.get("boot_id") is not None
        ],
    }
    output_path.write_text(json.dumps(ack, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
