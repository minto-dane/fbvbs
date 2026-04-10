#!/usr/bin/env python3

import argparse
import json
import pathlib

import standalone_storage_policy as storage_policy


TOOL_VERSION = 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate storage evidence trail artifacts from inventory, audit consistency, and confirmations."
    )
    parser.add_argument("--inventory", required=True, help="Storage inventory JSON")
    parser.add_argument("--audit-report", required=True, help="Output of verify_storage_attach_detach_audit.py")
    parser.add_argument("--confirmation", action="append", default=[], help="Optional destructive storage confirmation JSON")
    parser.add_argument("--output-dir", required=True, help="Directory to write evidence trail artifacts")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    inventory_path = storage_policy.resolve_user_path(hypervisor_dir, args.inventory)
    audit_path = storage_policy.resolve_user_path(hypervisor_dir, args.audit_report)
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    inventory = storage_policy.read_json(inventory_path)
    audit_report = storage_policy.read_json(audit_path)
    confirmations = []
    for raw_path in args.confirmation:
        confirmation_path = storage_policy.resolve_user_path(hypervisor_dir, raw_path)
        payload = storage_policy.read_json(confirmation_path)
        storage_policy.validate_destructive_confirmation_payload(payload)
        confirmations.append(payload)

    confirmations_by_target = {
        (item["target_kind"], int(item["target_id"])): item for item in confirmations
    }
    summaries_by_vdisk = {
        int(row["vdisk_id"]): row for row in audit_report.get("vdisk_summaries", []) if isinstance(row, dict)
    }

    vdisk_trails = []
    warnings = []
    for vdisk in inventory.get("vdisks", []):
        if not isinstance(vdisk, dict):
            continue
        vdisk_id = int(vdisk.get("vdisk_id", 0))
        summary = summaries_by_vdisk.get(vdisk_id, {})
        confirmation = confirmations_by_target.get(("vdisk", vdisk_id))
        current_state = storage_policy.infer_vdisk_state(vdisk)
        if confirmation is None and current_state == "RELEASE_PENDING":
            warnings.append(f"vdisk {vdisk_id} is release_pending without destructive confirmation")
        vdisk_trails.append(
            {
                "vdisk_id": vdisk_id,
                "pool_id": int(vdisk.get("pool_id", 0)),
                "owner_partition_id": int(vdisk.get("owner_partition_id", 0)),
                "attached_partition_id": int(vdisk.get("attached_partition_id", 0)),
                "current_state": current_state,
                "latest_successful_event": summary.get("latest_successful_event"),
                "event_count": int(summary.get("event_count", 0)),
                "destructive_confirmation_sha384": (
                    confirmation["storage_confirmation_sha384"] if confirmation is not None else None
                ),
            }
        )

    pool_trails = []
    for pool in inventory.get("pools", []):
        if not isinstance(pool, dict):
            continue
        pool_id = int(pool.get("pool_id", 0))
        confirmation = confirmations_by_target.get(("pool", pool_id))
        if confirmation is None and int(pool.get("allocated_bytes", 0)) == 0 and int(pool.get("vdisk_count", 0)) == 0:
            warnings.append(f"pool {pool_id} is empty but has no destructive confirmation artifact")
        pool_trails.append(
            {
                "pool_id": pool_id,
                "capacity_bytes": int(pool.get("capacity_bytes", 0)),
                "allocated_bytes": int(pool.get("allocated_bytes", 0)),
                "vdisk_count": int(pool.get("vdisk_count", 0)),
                "destructive_confirmation_sha384": (
                    confirmation["storage_confirmation_sha384"] if confirmation is not None else None
                ),
            }
        )

    payload = {
        "tool": {"name": "generate_storage_evidence_trail.py", "version": TOOL_VERSION},
        "storage_evidence_trail_schema_version": storage_policy.STORAGE_EVIDENCE_TRAIL_SCHEMA_VERSION,
        "inventory_sha384": storage_policy.sha384_bytes(storage_policy.canonical_json_bytes(inventory)),
        "audit_report_sha384": storage_policy.sha384_bytes(storage_policy.canonical_json_bytes(audit_report)),
        "confirmation_count": len(confirmations),
        "warning_count": len(warnings),
        "warnings": warnings,
        "pool_trails": pool_trails,
        "vdisk_trails": vdisk_trails,
    }
    json_path = output_dir / "storage-evidence-trail.json"
    md_path = output_dir / "storage-evidence-trail.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# Storage Evidence Trail",
        "",
        f"- schema version: `{payload['storage_evidence_trail_schema_version']}`",
        f"- warnings: `{payload['warning_count']}`",
        "",
        "| Vdisk | State | Latest Successful Event | Confirmation |",
        "| --- | --- | --- | --- |",
    ]
    for row in vdisk_trails:
        latest = row["latest_successful_event"]["operation_name"] if row["latest_successful_event"] else "-"
        confirmation = row["destructive_confirmation_sha384"] or "-"
        lines.append(
            f"| `{row['vdisk_id']}` | `{row['current_state']}` | `{latest}` | `{confirmation}` |"
        )
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 1 if warnings else 0


if __name__ == "__main__":
    raise SystemExit(main())
