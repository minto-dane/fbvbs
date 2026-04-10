#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib

import standalone_operator_security as operator_security
import standalone_storage_policy as storage_policy


TOOL_VERSION = 1


def find_target(inventory: dict, operation: str, target_id: int) -> tuple[str, dict]:
    if operation == "destroy-pool":
        for pool in inventory.get("pools", []):
            if isinstance(pool, dict) and int(pool.get("pool_id", 0)) == target_id:
                return "pool", pool
        raise SystemExit("target pool_id not found in inventory")
    if operation == "destroy-vdisk":
        for vdisk in inventory.get("vdisks", []):
            if isinstance(vdisk, dict) and int(vdisk.get("vdisk_id", 0)) == target_id:
                return "vdisk", vdisk
        raise SystemExit("target vdisk_id not found in inventory")
    raise SystemExit("unsupported destructive storage operation")


def build_preconditions(target_kind: str, target: dict) -> dict[str, object]:
    if target_kind == "pool":
        empty = int(target.get("allocated_bytes", 0)) == 0 and int(target.get("vdisk_count", 0)) == 0
        if not empty:
            raise SystemExit("destroy-pool confirmation requires empty pool")
        return {"pool_empty": True, "allocated_bytes": 0, "vdisk_count": 0}
    attached = int(target.get("attached_partition_id", 0)) == 0
    if not attached:
        raise SystemExit("destroy-vdisk confirmation requires detached vdisk")
    return {
        "vdisk_detached": True,
        "owner_partition_id": int(target.get("owner_partition_id", 0)),
        "attached_partition_id": 0,
        "derived_state": storage_policy.infer_vdisk_state(target),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Issue a fail-closed destructive storage operation confirmation artifact."
    )
    parser.add_argument("--operation", required=True, choices=tuple(storage_policy.STORAGE_OPERATION_TO_CALL.keys()), help="Destructive storage operation")
    parser.add_argument("--target-id", required=True, type=int, help="Pool or vdisk identifier")
    parser.add_argument("--operator-id", required=True, help="Operator identity string")
    parser.add_argument("--operator-role", required=True, help="Operator role name")
    parser.add_argument("--session-correlation-id", required=True, help="Administrative session correlation identifier")
    parser.add_argument("--inventory", required=True, help="Storage inventory JSON")
    parser.add_argument("--origin-attestation", help="Optional command origin attestation JSON")
    parser.add_argument("--justification", required=True, help="Short destructive operation justification")
    parser.add_argument("--valid-hours", type=int, default=2, help="Validity window in hours")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()

    if args.valid_hours <= 0:
        raise SystemExit("valid-hours must be positive")
    if args.operator_role != "storage-admin":
        raise SystemExit("destructive storage confirmation requires operator-role storage-admin")

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    inventory_path = storage_policy.resolve_user_path(hypervisor_dir, args.inventory)
    output_path = storage_policy.resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not inventory_path.is_file():
        raise SystemExit(f"missing inventory: {inventory_path}")
    inventory = storage_policy.read_json(inventory_path)
    target_kind, target = find_target(inventory, args.operation, args.target_id)
    preconditions = build_preconditions(target_kind, target)
    inventory_sha384 = storage_policy.sha384_bytes(storage_policy.canonical_json_bytes(inventory))

    call_name = storage_policy.STORAGE_OPERATION_TO_CALL[args.operation]
    if args.origin_attestation is not None:
        origin_path = operator_security.resolve_user_path(hypervisor_dir, args.origin_attestation)
        if not origin_path.is_file():
            raise SystemExit(f"missing origin attestation: {origin_path}")
        origin_payload = operator_security.read_json(origin_path)
        try:
            operator_security.validate_origin_attestation_payload(
                origin_payload,
                script_path,
                expected_call_name=call_name,
                expected_operator_role=args.operator_role,
                expected_session_correlation_id=args.session_correlation_id,
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        origin_hash = origin_payload["origin_attestation_sha384"]
    else:
        origin_hash = None

    issued_utc = datetime.datetime.now(datetime.timezone.utc)
    expires_utc = issued_utc + datetime.timedelta(hours=args.valid_hours)
    payload = {
        "tool": {"name": "issue_destructive_storage_confirmation.py", "version": TOOL_VERSION},
        "destructive_storage_confirmation_schema_version": storage_policy.DESTRUCTIVE_STORAGE_CONFIRMATION_SCHEMA_VERSION,
        "issued_utc": issued_utc.isoformat(),
        "expires_utc": expires_utc.isoformat(),
        "operation": args.operation,
        "call": {"name": call_name},
        "target_kind": target_kind,
        "target_id": args.target_id,
        "operator_id": args.operator_id,
        "operator_role": args.operator_role,
        "session_correlation_id": args.session_correlation_id,
        "justification": args.justification,
        "inventory_sha384": inventory_sha384,
        "preconditions": preconditions,
        "origin_attestation_sha384": origin_hash,
    }
    payload["storage_confirmation_sha384"] = storage_policy.sha384_bytes(
        storage_policy.canonical_json_bytes(
            {k: v for k, v in payload.items() if k != "storage_confirmation_sha384"}
        )
    )
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
