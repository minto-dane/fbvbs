#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import pathlib
import re


TOOL_VERSION = 1
AUDIT_SCHEMA_VERSION = 1
AUDIT_LINE_PATTERN = re.compile(r"^AUDIT\s+(?P<body>.+)$")
FIELD_PATTERN = re.compile(r"([a-zA-Z_]+)=([0-9A-Fa-f]+)")


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def parse_numeric(raw_value: str, base: int) -> int:
    return int(raw_value, base)


def parse_audit_line(line: str) -> dict | None:
    match = AUDIT_LINE_PATTERN.match(line.strip())
    if match is None:
        return None
    fields = dict(FIELD_PATTERN.findall(match.group("body")))
    if "seq" not in fields or "payload" not in fields:
        return None
    uses_hex_wire_format = any(
        key in fields for key in ("boot_hi", "boot_lo", "cpu", "evt", "crc")
    )

    record: dict[str, object] = {
        "sequence": parse_numeric(fields["seq"], 16 if uses_hex_wire_format else 10),
        "payload_hex": fields["payload"].lower(),
    }
    for input_key, output_key in (
        ("boot_hi", "boot_hi"),
        ("boot_lo", "boot_lo"),
        ("ts", "timestamp_ns"),
        ("cpu", "cpu_id"),
        ("src", "source_component"),
        ("sev", "severity"),
        ("event", "event_code"),
        ("evt", "event_code"),
        ("len", "payload_length"),
        ("crc", "crc32c"),
    ):
        if input_key in fields:
            base = 10
            if uses_hex_wire_format and input_key in {
                "boot_hi",
                "boot_lo",
                "cpu",
                "src",
                "sev",
                "evt",
                "len",
                "crc",
            }:
                base = 16
            record[output_key] = parse_numeric(fields[input_key], base)

    if "boot_hi" in record and "boot_lo" in record:
        record["boot_id"] = (
            f"{record['boot_hi']:016x}:{record['boot_lo']:016x}"
        )
    else:
        record["boot_id"] = "global"
    return record


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha384_hex(payload: bytes) -> str:
    digest = hashlib.sha384()
    digest.update(payload)
    return digest.hexdigest()


def file_sha384(path: pathlib.Path) -> str:
    digest = hashlib.sha384()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_input(path: pathlib.Path) -> list[dict]:
    records: list[dict] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        record = parse_audit_line(line)
        if record is None:
            continue
        record["source_file"] = path.name
        record["source_line"] = line_number
        records.append(record)
    return records


def summarize_boot_sessions(records: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for record in records:
        grouped.setdefault(str(record["boot_id"]), []).append(record)

    sessions: list[dict] = []
    for boot_id, session_records in sorted(grouped.items()):
        ordered = sorted(session_records, key=lambda item: int(item["sequence"]))
        gaps = []
        for previous, current in zip(ordered, ordered[1:]):
            previous_sequence = int(previous["sequence"])
            current_sequence = int(current["sequence"])
            if current_sequence > previous_sequence + 1:
                gaps.append(
                    {
                        "after_sequence": previous_sequence,
                        "before_sequence": current_sequence,
                        "missing_count": current_sequence - previous_sequence - 1,
                    }
                )
        sessions.append(
            {
                "boot_id": boot_id,
                "record_count": len(ordered),
                "first_sequence": int(ordered[0]["sequence"]),
                "last_sequence": int(ordered[-1]["sequence"]),
                "gap_count": len(gaps),
                "gaps": gaps,
            }
        )
    return sessions


def seal_records(records: list[dict]) -> tuple[list[dict], str]:
    sealed_records: list[dict] = []
    previous_hash = "0" * 96

    for record in records:
        sealed = dict(record)
        sealed["previous_entry_sha384"] = None if not sealed_records else previous_hash
        digest_input = (
            b"FBVBS_TIMELINE_CHAIN_V1\0" +
            previous_hash.encode("ascii") +
            canonical_json_bytes(record)
        )
        sealed["entry_sha384"] = sha384_hex(digest_input)
        previous_hash = str(sealed["entry_sha384"])
        sealed_records.append(sealed)

    if not sealed_records:
        previous_hash = sha384_hex(b"FBVBS_TIMELINE_CHAIN_V1\0EMPTY")
    return sealed_records, previous_hash


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reconstruct a normalized incident timeline from AUDIT seq lines."
    )
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        help="Audit text file containing AUDIT seq lines; may be repeated",
    )
    parser.add_argument("--output", required=True, help="Output JSON timeline path")
    args = parser.parse_args()

    if not args.input:
        raise SystemExit("at least one --input is required")

    script_dir = pathlib.Path(__file__).resolve().parent
    output_path = resolve_user_path(script_dir.parents[1], args.output)
    input_paths = [resolve_user_path(script_dir.parents[1], item) for item in args.input]
    missing = [str(path) for path in input_paths if not path.is_file()]
    if missing:
        raise SystemExit("missing incident timeline inputs:\n" + "\n".join(missing))

    records: list[dict] = []
    input_manifests = []
    for path in input_paths:
        records.extend(parse_input(path))
        input_manifests.append(
            {
                "name": path.name,
                "sha384": file_sha384(path),
            }
        )
    records.sort(key=lambda item: (str(item["boot_id"]), int(item["sequence"])))
    sealed_records, timeline_sha384 = seal_records(records)

    output = {
        "tool": {
            "name": "reconstruct_incident_timeline.py",
            "version": TOOL_VERSION,
        },
        "audit_schema_version": AUDIT_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "input_files": [path.name for path in input_paths],
        "input_manifests": input_manifests,
        "record_count": len(sealed_records),
        "boot_sessions": summarize_boot_sessions(sealed_records),
        "sealed": True,
        "chain_algorithm": "sha384-forward-chain-v1",
        "timeline_sha384": timeline_sha384,
        "root_chain_sha384": timeline_sha384,
        "records": sealed_records,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
