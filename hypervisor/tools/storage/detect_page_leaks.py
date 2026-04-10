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
    parser = argparse.ArgumentParser(description="Detect leaked pages and backing-count drift.")
    parser.add_argument("--input", required=True, help="Memory inventory JSON")
    parser.add_argument("--output", required=True, help="Output report JSON")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    payload = read_json(resolve_user_path(hypervisor_dir, args.input))
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    objects = payload.get("memory_objects", [])
    pages = payload.get("pages", [])
    if not isinstance(objects, list) or not isinstance(pages, list):
        raise SystemExit("input must contain memory_objects and pages arrays")

    page_map = {}
    for row in pages:
        if isinstance(row, dict):
            page_map[int(row.get("page_id", 0))] = row

    findings = []
    referenced_pages = set()
    for obj in objects:
        if not isinstance(obj, dict):
            continue
        backing_pages = [int(page_id) for page_id in obj.get("backing_pages", [])]
        if len(backing_pages) != int(obj.get("backing_page_count", 0)):
            findings.append({"kind": "backing-page-count-mismatch", "object_id": int(obj.get("object_id", 0))})
        for page_id in backing_pages:
            referenced_pages.add(page_id)
            page = page_map.get(page_id)
            if page is None:
                findings.append({"kind": "missing-page-record", "object_id": int(obj.get("object_id", 0)), "page_id": page_id})
            elif int(page.get("owner_object_id", 0)) != int(obj.get("object_id", 0)):
                findings.append({"kind": "owner-mismatch", "object_id": int(obj.get("object_id", 0)), "page_id": page_id})

    for page_id, row in page_map.items():
        if bool(row.get("allocated", False)) and page_id not in referenced_pages:
            findings.append({"kind": "unreferenced-allocated-page", "page_id": page_id})

    report = {
        "tool": {"name": "detect_page_leaks.py", "version": TOOL_VERSION},
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "object_count": len(objects),
        "page_count": len(page_map),
        "leak_count": len(findings),
        "findings": findings,
    }
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output_path), "leak_count": len(findings)}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
