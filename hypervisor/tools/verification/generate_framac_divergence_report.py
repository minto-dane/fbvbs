#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib
from collections import Counter

import check_framac_stubs as stubs


TOOL_VERSION = 1
REPORT_SCHEMA_VERSION = 1


def divergence_class(finding: dict) -> str:
    if finding["category"] == "HW_STUB":
        return "hardware-dependent-only"
    if finding["risk"] == stubs.RISK_HIGH and not finding["has_sync"]:
        return "forbidden-divergence"
    if finding["category"] == "STRUCT_ZERO" and not finding["has_size_guard"]:
        return "forbidden-divergence"
    return "acceptable-stub"


def collect_findings() -> list[dict]:
    findings = []
    for root_dir in [stubs.SRC_DIR, stubs.INCLUDE_DIR]:
        root_path = pathlib.Path(root_dir)
        if not root_path.exists():
            continue
        for path in sorted(root_path.rglob("*")):
            if path.suffix not in (".c", ".h"):
                continue
            for finding in stubs.scan_file(str(path)):
                finding = dict(finding)
                finding["divergence_class"] = divergence_class(finding)
                findings.append(finding)
    return findings


def build_report() -> dict[str, object]:
    findings = collect_findings()
    by_category = Counter(f["category"] for f in findings)
    by_risk = Counter(f["risk"] for f in findings)
    by_divergence = Counter(f["divergence_class"] for f in findings)
    forbidden = [f for f in findings if f["divergence_class"] == "forbidden-divergence"]
    return {
        "tool": {
            "name": "generate_framac_divergence_report.py",
            "version": TOOL_VERSION,
        },
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {
            "total_blocks": len(findings),
            "synced_blocks": sum(1 for f in findings if f["has_sync"]),
            "category_counts": dict(sorted(by_category.items())),
            "risk_counts": dict(sorted(by_risk.items())),
            "divergence_class_counts": dict(sorted(by_divergence.items())),
            "forbidden_divergence_count": len(forbidden),
        },
        "findings": findings,
    }


def render_markdown(report: dict[str, object]) -> str:
    summary = report["summary"]
    lines = [
        "# Frama-C Divergence Report",
        "",
        f"- total blocks: `{summary['total_blocks']}`",
        f"- synced blocks: `{summary['synced_blocks']}`",
        f"- forbidden divergence count: `{summary['forbidden_divergence_count']}`",
        "",
        "| File | Line | Category | Risk | Divergence Class |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in report["findings"][:80]:
        lines.append(
            f"| `{finding['file']}` | `{finding['line']}` | `{finding['category']}` | "
            f"`{finding['risk']}` | `{finding['divergence_class']}` |"
        )
    if len(report["findings"]) > 80:
        lines.append("")
        lines.append(f"- truncated findings: {len(report['findings']) - 80}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate inventory and divergence classification report for __FRAMAC__ branches."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write report artifacts")
    parser.add_argument("--strict", action="store_true", help="Fail if forbidden divergence is present")
    args = parser.parse_args()

    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    report = build_report()

    json_path = output_dir / "framac-divergence-report.json"
    md_path = output_dir / "framac-divergence-report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))

    if args.strict and int(report["summary"]["forbidden_divergence_count"]) > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
