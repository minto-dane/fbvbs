#!/usr/bin/env python3

import argparse
import datetime
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
    parser = argparse.ArgumentParser(
        description="Evaluate collector-loss and audit-backpressure operating mode for standalone deployments."
    )
    parser.add_argument("--status", required=True, help="Collector status JSON")
    parser.add_argument("--output", required=True, help="Output policy evaluation JSON")
    parser.add_argument("--spool-high-watermark-pct", type=int, default=80, help="High watermark for degraded backpressure mode")
    parser.add_argument("--spool-halt-watermark-pct", type=int, default=95, help="Critical watermark for halt mode")
    args = parser.parse_args()

    if not (0 <= args.spool_high_watermark_pct <= 100):
        raise SystemExit("spool-high-watermark-pct must be between 0 and 100")
    if not (0 <= args.spool_halt_watermark_pct <= 100):
        raise SystemExit("spool-halt-watermark-pct must be between 0 and 100")
    if args.spool_high_watermark_pct > args.spool_halt_watermark_pct:
        raise SystemExit("spool-high-watermark-pct must be <= spool-halt-watermark-pct")

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    status_path = resolve_user_path(hypervisor_dir, args.status)
    if not status_path.is_file():
        raise SystemExit(f"missing collector status JSON: {status_path}")
    status = read_json(status_path)

    collector_present = bool(status.get("collector_present", False))
    heartbeat_ok = bool(status.get("heartbeat_ok", False))
    spool_usage_pct = int(status.get("spool_usage_pct", 100))
    framing_errors = int(status.get("framing_error_count", 0))
    dropped_bytes = int(status.get("dropped_bytes", 0))

    reasons: list[str] = []
    allowed_actions = ["read-diagnostics", "export-evidence", "operator-triage"]
    mode = "NORMAL"

    if not collector_present:
        mode = "HALT_NEW_MUTATIONS"
        reasons.append("collector absent")
    elif not heartbeat_ok:
        mode = "HALT_NEW_MUTATIONS"
        reasons.append("collector heartbeat lost")
    elif spool_usage_pct >= args.spool_halt_watermark_pct:
        mode = "HALT_NEW_MUTATIONS"
        reasons.append("spool usage reached halt watermark")
    elif spool_usage_pct >= args.spool_high_watermark_pct:
        mode = "DEGRADED_BACKPRESSURE"
        reasons.append("spool usage reached high watermark")
        allowed_actions.append("drain-existing-workload")
    if framing_errors > 0:
        reasons.append("collector framing errors present")
    if dropped_bytes > 0:
        reasons.append("collector dropped bytes present")
        if mode == "NORMAL":
            mode = "DEGRADED_BACKPRESSURE"

    if mode == "HALT_NEW_MUTATIONS":
        allowed_actions = ["read-diagnostics", "export-evidence", "operator-triage", "acknowledge-incident"]

    report = {
        "tool": {"name": "evaluate_audit_collector_mode.py", "version": TOOL_VERSION},
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "mode": mode,
        "collector_present": collector_present,
        "heartbeat_ok": heartbeat_ok,
        "spool_usage_pct": spool_usage_pct,
        "framing_error_count": framing_errors,
        "dropped_bytes": dropped_bytes,
        "reasons": reasons,
        "allowed_actions": allowed_actions,
        "fail_closed": True,
    }
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
