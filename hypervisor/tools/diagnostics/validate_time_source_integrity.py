#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib


TOOL_VERSION = 1
REPORT_SCHEMA_VERSION = 1
SUPPORTED_LOCALES = ("en", "ja")

TEXT = {
    "en": {
        "title": "Time Source Integrity Report",
        "status": "Status",
        "issues": "Issues",
        "record_count": "Record count",
    },
    "ja": {
        "title": "時刻源整合性レポート",
        "status": "状態",
        "issues": "問題",
        "record_count": "レコード数",
    },
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


def build_report(timeline: dict, max_future_seconds: int) -> dict:
    records = timeline.get("records", [])
    if not isinstance(records, list):
        raise SystemExit("timeline records must be an array")
    issues: list[dict] = []
    previous_timestamp = None
    now_ns = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1_000_000_000)
    future_limit = now_ns + max_future_seconds * 1_000_000_000

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        ts = record.get("timestamp_ns")
        if ts is None:
            issues.append({"kind": "missing-timestamp", "record_index": index})
            continue
        if not isinstance(ts, int):
            issues.append({"kind": "non-integer-timestamp", "record_index": index})
            continue
        if ts < 0:
            issues.append({"kind": "negative-timestamp", "record_index": index, "timestamp_ns": ts})
        if ts > future_limit:
            issues.append({"kind": "future-skew", "record_index": index, "timestamp_ns": ts})
        if previous_timestamp is not None and ts < previous_timestamp:
            issues.append(
                {
                    "kind": "non-monotonic-timestamp",
                    "record_index": index,
                    "timestamp_ns": ts,
                    "previous_timestamp_ns": previous_timestamp,
                }
            )
        previous_timestamp = ts

    return {
        "tool": {"name": "validate_time_source_integrity.py", "version": TOOL_VERSION},
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "audit_schema_version": timeline.get("audit_schema_version", 1),
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "timeline_root_chain_sha384": timeline.get("root_chain_sha384"),
        "record_count": len(records),
        "max_future_seconds": max_future_seconds,
        "status": "ok" if not issues else "warning",
        "issue_count": len(issues),
        "issues": issues,
    }


def build_markdown(report: dict, locale: str) -> str:
    text = TEXT[locale]
    lines = [
        f"# {text['title']}",
        "",
        f"- {text['status']}: {report['status']}",
        f"- {text['record_count']}: {report['record_count']}",
        f"- {text['issues']}: {report['issue_count']}",
        "",
        "## Issues",
        "",
    ]
    if report["issues"]:
        for issue in report["issues"]:
            lines.append(f"- {issue['kind']}")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate monotonicity and future-skew policy for audit timeline timestamps."
    )
    parser.add_argument("--timeline", required=True, help="Timeline JSON")
    parser.add_argument("--max-future-seconds", type=int, default=300, help="Allowable future skew in seconds")
    parser.add_argument("--locale", choices=SUPPORTED_LOCALES, default="en", help="Markdown locale")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--fail-on-issue", action="store_true", help="Exit non-zero if issues are found")
    args = parser.parse_args()

    if args.max_future_seconds < 0:
        raise SystemExit("max-future-seconds must be non-negative")

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    timeline_path = resolve_user_path(hypervisor_dir, args.timeline)
    if not timeline_path.is_file():
        raise SystemExit(f"missing timeline: {timeline_path}")

    report = build_report(read_json(timeline_path), args.max_future_seconds)
    output_dir = resolve_user_path(hypervisor_dir, args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "time-source-integrity-report.json"
    md_path = output_dir / "time-source-integrity-report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(build_markdown(report, args.locale), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2))

    if args.fail_on_issue and report["issue_count"] > 0:
        raise SystemExit("time source integrity issues detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
