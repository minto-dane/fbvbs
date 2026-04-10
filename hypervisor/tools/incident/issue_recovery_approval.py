#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import pathlib


TOOL_VERSION = 1
RECOVERY_APPROVAL_SCHEMA_VERSION = 1


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def read_json(path: pathlib.Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"JSON input must be an object: {path}")
    return payload


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha384_bytes(payload: bytes) -> str:
    digest = hashlib.sha384()
    digest.update(payload)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Issue a fail-closed operator recovery approval bound to timeline, severity, and acknowledgment ledger."
    )
    parser.add_argument("--timeline-seal", required=True, help="Sealed incident timeline JSON")
    parser.add_argument("--severity-summary", required=True, help="Operator console severity summary JSON")
    parser.add_argument("--ack-ledger", required=True, help="Operator acknowledgment ledger JSON")
    parser.add_argument("--partition-id", required=True, type=int, help="Partition approved for recovery")
    parser.add_argument("--operator-id", required=True, help="Operator identity string")
    parser.add_argument("--reason", required=True, help="Short operator rationale for recovery approval")
    parser.add_argument("--approval-window-hours", type=int, default=4, help="Approval lifetime in hours")
    parser.add_argument("--output", required=True, help="Recovery approval JSON")
    args = parser.parse_args()

    if args.approval_window_hours <= 0:
        raise SystemExit("approval-window-hours must be positive")

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    timeline = read_json(resolve_user_path(hypervisor_dir, args.timeline_seal))
    severity = read_json(resolve_user_path(hypervisor_dir, args.severity_summary))
    ledger = read_json(resolve_user_path(hypervisor_dir, args.ack_ledger))
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    timeline_root = str(timeline.get("root_chain_sha384", ""))
    if not timeline_root:
        raise SystemExit("timeline seal must contain root_chain_sha384")
    if str(ledger.get("timeline_root_chain_sha384", "")) != timeline_root:
        raise SystemExit("ack ledger timeline_root_chain_sha384 does not match timeline root")
    if int(ledger.get("acknowledgment_count", 0)) <= 0:
        raise SystemExit("recovery approval requires at least one operator acknowledgment")
    session_correlation_id = str(ledger.get("session_correlation_id", ""))
    if not session_correlation_id:
        raise SystemExit("ack ledger must contain session_correlation_id")

    matching_partition = None
    for row in severity.get("partitions", []):
        if isinstance(row, dict) and int(row.get("partition_id", -1)) == args.partition_id:
            matching_partition = row
            break
    if matching_partition is None:
        raise SystemExit(f"partition not present in severity summary: {args.partition_id}")

    health_name = str(matching_partition.get("health_state", {}).get("name", "UNKNOWN"))
    if health_name == "HEALTHY":
        raise SystemExit("recovery approval is only valid for non-healthy partitions")

    approved_utc = datetime.datetime.now(datetime.timezone.utc)
    expires_utc = approved_utc + datetime.timedelta(hours=args.approval_window_hours)
    approval = {
        "tool": {
            "name": "issue_recovery_approval.py",
            "version": TOOL_VERSION,
        },
        "recovery_approval_schema_version": RECOVERY_APPROVAL_SCHEMA_VERSION,
        "approved_utc": approved_utc.isoformat(),
        "expires_utc": expires_utc.isoformat(),
        "approval_window_hours": args.approval_window_hours,
        "operator_id": args.operator_id,
        "session_correlation_id": session_correlation_id,
        "partition_id": args.partition_id,
        "reason": args.reason,
        "action": "recover-approved",
        "timeline_root_chain_sha384": timeline_root,
        "latest_ack_sha384": ledger.get("latest_ack_sha384"),
        "severity_name": str(matching_partition.get("severity", {}).get("name", "UNKNOWN")),
        "health_name": health_name,
        "fault_code": int(matching_partition.get("fault_code", 0)),
        "quarantine_reason": int(matching_partition.get("quarantine_reason", 0)),
    }
    approval["approval_sha384"] = sha384_bytes(
        canonical_json_bytes({k: v for k, v in approval.items() if k != "approval_sha384"})
    )
    output_path.write_text(json.dumps(approval, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
