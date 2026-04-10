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
    parser = argparse.ArgumentParser(description="Detect stale memory mappings across partition boundaries.")
    parser.add_argument("--input", required=True, help="Mapping inventory JSON")
    parser.add_argument("--output", required=True, help="Output report JSON")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    input_path = resolve_user_path(hypervisor_dir, args.input)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = read_json(input_path)

    partitions = payload.get("partitions", [])
    mappings = payload.get("memory_mappings", [])
    if not isinstance(partitions, list) or not isinstance(mappings, list):
        raise SystemExit("input must contain partitions and memory_mappings arrays")

    partition_state = {}
    for row in partitions:
        if not isinstance(row, dict):
            raise SystemExit("partition entries must be objects")
        partition_state[int(row.get("partition_id", 0))] = {
            "occupied": bool(row.get("occupied", False)),
            "state": str(row.get("state_name", "")),
        }

    findings = []
    for mapping in mappings:
        if not isinstance(mapping, dict):
            raise SystemExit("mapping entries must be objects")
        owner_id = int(mapping.get("owner_partition_id", 0))
        target_id = int(mapping.get("target_partition_id", 0))
        reasons = []
        owner = partition_state.get(owner_id)
        target = partition_state.get(target_id)
        if owner is None or not owner["occupied"]:
            reasons.append("owner-missing")
        elif owner["state"] == "DESTROYED":
            reasons.append("owner-destroyed")
        if target_id != 0:
            if target is None or not target["occupied"]:
                reasons.append("target-missing")
            elif target["state"] == "DESTROYED":
                reasons.append("target-destroyed")
        if bool(mapping.get("revoked", False)) and bool(mapping.get("active", False)):
            reasons.append("revoked-but-active")
        if reasons:
            findings.append(
                {
                    "mapping_id": int(mapping.get("mapping_id", 0)),
                    "owner_partition_id": owner_id,
                    "target_partition_id": target_id,
                    "reasons": reasons,
                }
            )

    report = {
        "tool": {"name": "detect_stale_mappings.py", "version": TOOL_VERSION},
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "mapping_count": len(mappings),
        "stale_mapping_count": len(findings),
        "findings": findings,
    }
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output_path), "stale_mapping_count": len(findings)}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
