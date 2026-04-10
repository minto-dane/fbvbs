#!/usr/bin/env python3

import argparse
import json
import pathlib


TOOL_VERSION = 1
REPORT_SCHEMA_VERSION = 1


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


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate teardown postconditions for a partition.")
    parser.add_argument("--input", required=True, help="Teardown evidence JSON")
    parser.add_argument("--partition-id", required=True, type=int, help="Partition identifier to validate")
    parser.add_argument("--output", required=True, help="Output report JSON")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    input_path = resolve_user_path(hypervisor_dir, args.input)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = read_json(input_path)

    violations = []
    for key in ("memory_objects", "shared_objects", "memory_mappings", "attached_vdisks"):
        value = payload.get(key, [])
        if not isinstance(value, list):
            raise SystemExit(f"{key} must be an array")

    for row in payload.get("memory_objects", []):
        if isinstance(row, dict) and int(row.get("owner_partition_id", 0)) == args.partition_id:
            violations.append({"kind": "memory-object", "object_id": int(row.get("object_id", 0))})
    for row in payload.get("shared_objects", []):
        if isinstance(row, dict) and int(row.get("owner_partition_id", 0)) == args.partition_id:
            violations.append({"kind": "shared-object", "object_id": int(row.get("object_id", 0))})
    for row in payload.get("memory_mappings", []):
        if not isinstance(row, dict):
            continue
        if int(row.get("owner_partition_id", 0)) == args.partition_id or int(row.get("target_partition_id", 0)) == args.partition_id:
            violations.append({"kind": "memory-mapping", "mapping_id": int(row.get("mapping_id", 0))})
    for row in payload.get("attached_vdisks", []):
        if isinstance(row, dict) and int(row.get("vm_partition_id", 0)) == args.partition_id:
            violations.append({"kind": "attached-vdisk", "vdisk_id": int(row.get("vdisk_id", 0))})

    report = {
        "tool": {"name": "validate_teardown_postconditions.py", "version": TOOL_VERSION},
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "partition_id": args.partition_id,
        "allowed": len(violations) == 0,
        "violation_count": len(violations),
        "violations": violations,
    }
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output_path), "allowed": report["allowed"]}, indent=2))
    return 0 if report["allowed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
