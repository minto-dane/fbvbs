#!/usr/bin/env python3

import argparse
import json
import pathlib


TOOL_VERSION = 1
REPORT_SCHEMA_VERSION = 1

HEALTH_BASE = {
    "HEALTHY": 95,
    "DEGRADED": 65,
    "QUARANTINED": 20,
    "RECOVERY": 55,
}
SEVERITY_PENALTY = {
    "DEBUG": 0,
    "INFO": 0,
    "NOTICE": 5,
    "WARNING": 15,
    "ERROR": 30,
    "CRITICAL": 45,
    "ALERT": 55,
}


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


def score_row(row: dict) -> dict[str, object]:
    health_name = str(row.get("health_state", {}).get("name", row.get("health_state_name", "HEALTHY")))
    severity_name = str(row.get("severity", {}).get("name", "INFO"))
    score = HEALTH_BASE.get(health_name, 50)
    score -= SEVERITY_PENALTY.get(severity_name, 10)
    score -= min(int(row.get("policy_deny_count", 0)), 20)
    score -= min(int(row.get("lockout_windows", 0)) * 5, 20)
    if int(row.get("fault_code", 0)) != 0:
        score -= 10
    if int(row.get("quarantine_reason", 0)) != 0:
        score -= 10
    score = max(0, min(100, score))
    band = "HEALTHY" if score >= 80 else ("DEGRADED" if score >= 50 else "AT_RISK")
    return {
        "partition_id": int(row.get("partition_id", 0)),
        "score": score,
        "band": band,
        "health_state": health_name,
        "severity": severity_name,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Score partition health from severity and partition telemetry.")
    parser.add_argument("--input", required=True, help="Severity summary or partition list JSON")
    parser.add_argument("--output", required=True, help="Output score report JSON")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    input_path = resolve_user_path(hypervisor_dir, args.input)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = read_json(input_path)

    rows = payload.get("partitions")
    if not isinstance(rows, list):
        rows = payload.get("entries")
    if not isinstance(rows, list):
        raise SystemExit("input must contain partitions or entries array")

    scored = [score_row(row) for row in rows if isinstance(row, dict)]
    report = {
        "tool": {"name": "score_partition_health.py", "version": TOOL_VERSION},
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "partition_count": len(scored),
        "min_score": min((row["score"] for row in scored), default=0),
        "rows": scored,
    }
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output_path), "partition_count": len(scored)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
