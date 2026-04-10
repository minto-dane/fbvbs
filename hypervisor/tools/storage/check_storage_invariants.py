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
    parser = argparse.ArgumentParser(description="Check storage pool and vdisk invariants.")
    parser.add_argument("--input", required=True, help="Storage inventory JSON")
    parser.add_argument("--output", required=True, help="Output report JSON")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    payload = read_json(resolve_user_path(hypervisor_dir, args.input))
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    pools = payload.get("pools", [])
    vdisks = payload.get("vdisks", [])
    if not isinstance(pools, list) or not isinstance(vdisks, list):
        raise SystemExit("input must contain pools and vdisks arrays")

    by_pool = {int(pool.get("pool_id", 0)): pool for pool in pools if isinstance(pool, dict)}
    findings = []
    for pool_id, pool in by_pool.items():
        pool_vdisks = [row for row in vdisks if isinstance(row, dict) and int(row.get("pool_id", 0)) == pool_id]
        total_size = sum(int(row.get("size_bytes", 0)) for row in pool_vdisks)
        attached_count = sum(1 for row in pool_vdisks if int(row.get("attached_vm_partition_id", 0)) != 0)
        if total_size != int(pool.get("allocated_bytes", 0)):
            findings.append({"kind": "allocated-bytes-mismatch", "pool_id": pool_id})
        if len(pool_vdisks) != int(pool.get("vdisk_count", 0)):
            findings.append({"kind": "vdisk-count-mismatch", "pool_id": pool_id})
        if total_size > int(pool.get("capacity_bytes", 0)):
            findings.append({"kind": "capacity-overflow", "pool_id": pool_id})
        if int(pool.get("granularity_bytes", 0)) != 0:
            for row in pool_vdisks:
                if int(row.get("size_bytes", 0)) % int(pool.get("granularity_bytes", 1)) != 0:
                    findings.append({"kind": "granularity-mismatch", "pool_id": pool_id, "vdisk_id": int(row.get("vdisk_id", 0))})
        if int(pool.get("attached_vdisk_count", attached_count)) != attached_count:
            findings.append({"kind": "attached-count-mismatch", "pool_id": pool_id})

    report = {
        "tool": {"name": "check_storage_invariants.py", "version": TOOL_VERSION},
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "pool_count": len(by_pool),
        "vdisk_count": len(vdisks),
        "violation_count": len(findings),
        "findings": findings,
    }
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output_path), "violation_count": len(findings)}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
