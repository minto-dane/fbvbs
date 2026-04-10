#!/usr/bin/env python3

import argparse
import json
import pathlib

import standalone_storage_policy as storage_policy


TOOL_VERSION = 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify that storage attach/detach audit events match current vdisk attachment state."
    )
    parser.add_argument("--inventory", required=True, help="Storage inventory JSON")
    parser.add_argument("--audit-events", required=True, help="Storage audit events JSON")
    parser.add_argument("--output", required=True, help="Output report JSON")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    inventory_path = storage_policy.resolve_user_path(hypervisor_dir, args.inventory)
    audit_path = storage_policy.resolve_user_path(hypervisor_dir, args.audit_events)
    output_path = storage_policy.resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    inventory = storage_policy.read_json(inventory_path)
    audit_payload = storage_policy.read_json(audit_path)
    symbols = storage_policy.load_symbols(script_path)
    events = audit_payload.get("events", [])
    vdisks = inventory.get("vdisks", [])
    if not isinstance(events, list) or not isinstance(vdisks, list):
        raise SystemExit("inventory must contain vdisks array and audit input must contain events array")

    normalized_events = [
        storage_policy.normalize_storage_audit_event(event, symbols)
        for event in events
        if isinstance(event, dict)
    ]

    findings = []
    summaries = []
    for vdisk in vdisks:
        if not isinstance(vdisk, dict):
            continue
        vdisk_id = int(vdisk.get("vdisk_id", 0))
        current_attachment = int(vdisk.get("attached_partition_id", 0))
        relevant_events = [event for event in normalized_events if int(event["target_id"]) == vdisk_id]
        latest_success = None
        for event in relevant_events:
            if int(event["status"]) == 0 and event["operation_name"] in ("attach-vdisk", "detach-vdisk"):
                latest_success = event
        derived_state = storage_policy.infer_vdisk_state(vdisk)
        if current_attachment != 0:
            if latest_success is None or latest_success["operation_name"] != "attach-vdisk":
                findings.append(
                    {
                        "kind": "missing-attach-audit",
                        "vdisk_id": vdisk_id,
                        "attached_partition_id": current_attachment,
                    }
                )
            elif int(latest_success["related_id"]) != current_attachment:
                findings.append(
                    {
                        "kind": "attach-target-mismatch",
                        "vdisk_id": vdisk_id,
                        "attached_partition_id": current_attachment,
                        "audit_partition_id": int(latest_success["related_id"]),
                    }
                )
        elif latest_success is not None and latest_success["operation_name"] == "attach-vdisk":
            findings.append(
                {
                    "kind": "missing-detach-audit",
                    "vdisk_id": vdisk_id,
                    "audit_partition_id": int(latest_success["related_id"]),
                }
            )

        summaries.append(
            {
                "vdisk_id": vdisk_id,
                "pool_id": int(vdisk.get("pool_id", 0)),
                "owner_partition_id": int(vdisk.get("owner_partition_id", 0)),
                "attached_partition_id": current_attachment,
                "derived_state": derived_state,
                "event_count": len(relevant_events),
                "latest_successful_event": latest_success,
            }
        )

    report = {
        "tool": {"name": "verify_storage_attach_detach_audit.py", "version": TOOL_VERSION},
        "storage_audit_consistency_schema_version": storage_policy.STORAGE_AUDIT_CONSISTENCY_SCHEMA_VERSION,
        "vdisk_count": len(summaries),
        "violation_count": len(findings),
        "vdisk_summaries": summaries,
        "findings": findings,
    }
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output_path), "violation_count": len(findings)}, indent=2, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
