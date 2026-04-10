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
    parser = argparse.ArgumentParser(description="Detect quota drift between scaling policy and observed usage.")
    parser.add_argument("--limits", required=True, help="Scaling limits JSON")
    parser.add_argument("--usage", required=True, help="Observed usage JSON")
    parser.add_argument("--output", required=True, help="Output report JSON")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    limits = read_json(resolve_user_path(hypervisor_dir, args.limits))
    usage = read_json(resolve_user_path(hypervisor_dir, args.usage))
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    checks = [
        ("vm-count", int(limits.get("runtime_max_vm_count", 0)), int(usage.get("current_vm_count", 0))),
        ("vcpu-count", int(limits.get("runtime_max_vcpus_per_vm", 0)), int(usage.get("max_vcpus_per_vm_observed", 0))),
        ("vdisk-per-vm", int(limits.get("runtime_max_vdisks_per_vm", 0)), int(usage.get("max_vdisks_per_vm_observed", 0))),
        ("vdisk-size-bytes", int(limits.get("runtime_max_vdisk_size_bytes", 0)), int(usage.get("max_vdisk_size_observed_bytes", 0))),
    ]
    findings = []
    for name, limit_value, observed in checks:
        drift = observed - limit_value
        findings.append(
            {
                "metric": name,
                "limit": limit_value,
                "observed": observed,
                "drift": drift,
                "within_limit": observed <= limit_value,
            }
        )
    report = {
        "tool": {"name": "detect_quota_drift.py", "version": TOOL_VERSION},
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "noncompliant_count": sum(1 for row in findings if not row["within_limit"]),
        "findings": findings,
    }
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output_path), "noncompliant_count": report["noncompliant_count"]}, indent=2))
    return 1 if report["noncompliant_count"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
