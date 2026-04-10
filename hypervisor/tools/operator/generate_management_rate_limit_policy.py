#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib

import standalone_command_contracts as contracts
from generate_operator_tooling_compatibility_matrix import collect_defines, resolve_repo_root


TOOL_VERSION = 1
POLICY_SCHEMA_VERSION = 1


def build_payload(script_path: pathlib.Path) -> dict[str, object]:
    repo_root = resolve_repo_root(script_path)
    symbols = collect_defines(repo_root / "hypervisor" / "include" / "fbvbs_abi.h")
    contract_payload = contracts.build_contract_payload(script_path)
    rows = []
    for row in contract_payload["contracts"]:
        rows.append(
            {
                "call": row["call"],
                "operation": row["operation"],
                "idempotency_class": row["idempotency_class"],
                "safe_replay": row["safe_replay"],
                "rate_limit_applies": True,
                "retry_status": {"name": "RETRY_LATER", "value": int(symbols["RETRY_LATER"])},
                "deny_reason": {"name": "FBVBS_DENY_REASON_RATE_LIMIT", "value": int(symbols["FBVBS_DENY_REASON_RATE_LIMIT"])},
                "audit_event": {"name": "FBVBS_EVENT_POLICY_DENY", "value": int(symbols["FBVBS_EVENT_POLICY_DENY"])},
            }
        )
    return {
        "tool": {
            "name": "generate_management_rate_limit_policy.py",
            "version": TOOL_VERSION,
        },
        "policy_schema_version": POLICY_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "window_policy": {
            "window_calls": int(symbols["FBVBS_HYPERCALL_WINDOW_CALLS"]),
            "max_calls_per_window": int(symbols["FBVBS_HYPERCALL_MAX_CALLS_PER_WINDOW"]),
            "lockout_windows": int(symbols["FBVBS_HYPERCALL_LOCKOUT_WINDOWS"]),
            "retry_status": {"name": "RETRY_LATER", "value": int(symbols["RETRY_LATER"])},
            "deny_reason": {"name": "FBVBS_DENY_REASON_RATE_LIMIT", "value": int(symbols["FBVBS_DENY_REASON_RATE_LIMIT"])},
            "audit_event": {"name": "FBVBS_EVENT_POLICY_DENY", "value": int(symbols["FBVBS_EVENT_POLICY_DENY"])},
        },
        "summary": {
            "row_count": len(rows),
            "safe_replay_count": sum(1 for row in rows if row["safe_replay"]),
        },
        "rows": rows,
    }


def render_markdown(payload: dict[str, object]) -> str:
    window = payload["window_policy"]
    lines = [
        "# Standalone Management Command Rate Limit Policy",
        "",
        f"- schema version: `{payload['policy_schema_version']}`",
        f"- window calls: `{window['window_calls']}`",
        f"- max calls per window: `{window['max_calls_per_window']}`",
        f"- lockout windows: `{window['lockout_windows']}`",
        "",
        "| Call | Operation | Idempotency | Safe Replay | Retry Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in payload["rows"]:
        lines.append(
            f"| `{row['call']['name']}` | `{row['operation']}` | `{row['idempotency_class']}` | "
            f"`{'yes' if row['safe_replay'] else 'no'}` | `{row['retry_status']['name']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate standalone management command rate limit policy.")
    parser.add_argument("--output-dir", required=True, help="Directory to write policy artifacts")
    args = parser.parse_args()

    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = build_payload(pathlib.Path(__file__).resolve())

    json_path = output_dir / "standalone-management-rate-limit-policy.json"
    md_path = output_dir / "standalone-management-rate-limit-policy.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload) + "\n", encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
