#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib


TOOL_VERSION = 1
MATRIX_SCHEMA_VERSION = 1


ROWS = [
    {
        "health_state": "HEALTHY",
        "fault_severity": "INFO",
        "escalation_level": "none",
        "containment_policy": "continue",
        "operator_action": "observe",
    },
    {
        "health_state": "DEGRADED",
        "fault_severity": "WARNING",
        "escalation_level": "local-retry",
        "containment_policy": "degraded-service",
        "operator_action": "review-runbook",
    },
    {
        "health_state": "QUARANTINED",
        "fault_severity": "ERROR",
        "escalation_level": "partition-fence",
        "containment_policy": "safe-stop",
        "operator_action": "acknowledge-and-assess",
    },
    {
        "health_state": "QUARANTINED",
        "fault_severity": "CRITICAL",
        "escalation_level": "partition-fence-plus-service-review",
        "containment_policy": "quarantine",
        "operator_action": "break-glass-if-required",
    },
    {
        "health_state": "RECOVERY",
        "fault_severity": "NOTICE",
        "escalation_level": "operator-confirmed-recovery",
        "containment_policy": "recovering",
        "operator_action": "validate-postconditions",
    },
]


def render_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# Fault Escalation Matrix",
        "",
        f"- schema version: `{payload['matrix_schema_version']}`",
        "",
        "| Health | Severity | Escalation | Containment | Operator Action |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in payload["rows"]:
        lines.append(
            f"| `{row['health_state']}` | `{row['fault_severity']}` | `{row['escalation_level']}` | "
            f"`{row['containment_policy']}` | `{row['operator_action']}` |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate standalone fault escalation and containment matrix.")
    parser.add_argument("--output-dir", required=True, help="Directory to write matrix artifacts")
    args = parser.parse_args()

    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "tool": {"name": "generate_fault_escalation_matrix.py", "version": TOOL_VERSION},
        "matrix_schema_version": MATRIX_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "rows": ROWS,
    }
    json_path = output_dir / "fault-escalation-matrix.json"
    md_path = output_dir / "fault-escalation-matrix.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
