#!/usr/bin/env python3

import argparse
import json
import pathlib

import generate_service_privilege_review as review


REPORT_SCHEMA_VERSION = 1
TOOL_VERSION = 1


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


def build_capability_name_table(symbols: dict[str, int]) -> dict[int, str]:
    names: dict[int, str] = {}
    for name, value in symbols.items():
        if name.startswith("FBVBS_CAP_"):
            names[int(value)] = name
    return names


def decode_mask(mask: int, name_table: dict[int, str]) -> list[str]:
    names = []
    for bit_value, name in sorted(name_table.items()):
        if mask & bit_value:
            names.append(name)
    return names


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect unused capabilities in standalone service assignments."
    )
    parser.add_argument("--input", required=True, help="Service assignment JSON")
    parser.add_argument("--output", required=True, help="Output report JSON")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    input_path = resolve_user_path(hypervisor_dir, args.input)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not input_path.is_file():
        raise SystemExit(f"missing service assignment input: {input_path}")

    payload = read_json(input_path)
    services = payload.get("services", [])
    if not isinstance(services, list):
        raise SystemExit("service assignment input must contain services array")

    review_payload = review.build_payload(script_path)
    service_rows = {
        row["service_kind"]["name"]: row
        for row in review_payload["service_roles"]
    }
    symbols = review.load_symbols(script_path)
    capability_names = build_capability_name_table(symbols)

    findings = []
    for service in services:
        if not isinstance(service, dict):
            raise SystemExit("service entry must be an object")
        service_kind = str(service.get("service_kind", ""))
        if service_kind not in service_rows:
            raise SystemExit(f"unknown service_kind in input: {service_kind}")
        row = service_rows[service_kind]
        assigned_mask = int(service.get("capability_mask", 0))
        required_mask = int(row["minimal_capability_mask"]["value"])
        unused_mask = assigned_mask & ~required_mask
        missing_mask = required_mask & ~assigned_mask
        findings.append(
            {
                "partition_id": int(service.get("partition_id", 0)),
                "service_kind": service_kind,
                "assigned_capability_mask": {
                    "value": assigned_mask,
                    "hex": f"0x{assigned_mask:016X}",
                    "names": decode_mask(assigned_mask, capability_names),
                },
                "required_capability_mask": row["minimal_capability_mask"],
                "unused_capability_mask": {
                    "value": unused_mask,
                    "hex": f"0x{unused_mask:016X}",
                    "names": decode_mask(unused_mask, capability_names),
                },
                "missing_capability_mask": {
                    "value": missing_mask,
                    "hex": f"0x{missing_mask:016X}",
                    "names": decode_mask(missing_mask, capability_names),
                },
                "compliant": unused_mask == 0 and missing_mask == 0,
            }
        )

    report = {
        "tool": {
            "name": "detect_unused_service_capabilities.py",
            "version": TOOL_VERSION,
        },
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "service_count": len(findings),
        "noncompliant_count": sum(1 for row in findings if not row["compliant"]),
        "findings": findings,
    }
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output_path), "noncompliant_count": report["noncompliant_count"]}, indent=2))
    return 1 if report["noncompliant_count"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
