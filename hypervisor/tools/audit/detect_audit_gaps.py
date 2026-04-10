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
        "title": "Audit Gap Report",
        "gap_count": "Gap count",
        "missing_records": "Missing records",
        "boot_sessions": "Boot sessions with gaps",
    },
    "ja": {
        "title": "監査欠落レポート",
        "gap_count": "欠落数",
        "missing_records": "欠落レコード数",
        "boot_sessions": "欠落を含むブートセッション",
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


def build_report(timeline: dict) -> dict:
    boot_sessions = timeline.get("boot_sessions", [])
    if not isinstance(boot_sessions, list):
        raise SystemExit("timeline boot_sessions must be an array")
    gaps = []
    missing_record_total = 0
    for session in boot_sessions:
        if not isinstance(session, dict):
            continue
        gap_count = int(session.get("gap_count", 0))
        session_gaps = session.get("gaps", [])
        if gap_count <= 0:
            continue
        gap_missing = 0
        if isinstance(session_gaps, list):
            for gap in session_gaps:
                if isinstance(gap, dict):
                    gap_missing += int(gap.get("missing_count", 0))
        gaps.append(
            {
                "boot_id": session.get("boot_id"),
                "gap_count": gap_count,
                "missing_record_count": gap_missing,
                "gaps": session_gaps if isinstance(session_gaps, list) else [],
            }
        )
        missing_record_total += gap_missing
    return {
        "tool": {
            "name": "detect_audit_gaps.py",
            "version": TOOL_VERSION,
        },
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "audit_schema_version": timeline.get("audit_schema_version", 1),
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "timeline_root_chain_sha384": timeline.get("root_chain_sha384"),
        "record_count": int(timeline.get("record_count", 0)),
        "boot_session_count": len(boot_sessions),
        "gap_count_total": sum(int(item["gap_count"]) for item in gaps),
        "missing_record_count_total": missing_record_total,
        "boot_sessions_with_gaps": gaps,
    }


def build_markdown(report: dict, locale: str) -> str:
    text = TEXT[locale]
    lines = [
        f"# {text['title']}",
        "",
        f"- {text['gap_count']}: {report['gap_count_total']}",
        f"- {text['missing_records']}: {report['missing_record_count_total']}",
        "",
        f"## {text['boot_sessions']}",
        "",
    ]
    if report["boot_sessions_with_gaps"]:
        for session in report["boot_sessions_with_gaps"]:
            lines.append(
                f"- {session['boot_id']}: gaps={session['gap_count']} missing={session['missing_record_count']}"
            )
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Detect and summarize sequence gaps in a sealed or reconstructed incident timeline."
    )
    parser.add_argument("--timeline", required=True, help="Timeline JSON")
    parser.add_argument("--locale", choices=SUPPORTED_LOCALES, default="en", help="Markdown locale")
    parser.add_argument("--output-dir", required=True, help="Output directory")
    parser.add_argument("--fail-on-gap", action="store_true", help="Exit non-zero when gaps are present")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    timeline_path = resolve_user_path(hypervisor_dir, args.timeline)
    if not timeline_path.is_file():
        raise SystemExit(f"missing timeline: {timeline_path}")
    report = build_report(read_json(timeline_path))

    output_dir = resolve_user_path(hypervisor_dir, args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "audit-gap-report.json"
    md_path = output_dir / "audit-gap-report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(build_markdown(report, args.locale), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2))

    if args.fail_on_gap and report["gap_count_total"] > 0:
        raise SystemExit("audit gaps detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
