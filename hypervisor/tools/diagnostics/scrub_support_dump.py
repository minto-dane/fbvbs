#!/usr/bin/env python3

import argparse
import copy
import datetime
import gzip
import io
import json
import pathlib
import re
import tarfile
import zipfile


TOOL_VERSION = 2
MAX_RECURSION_DEPTH = 4
ARCHIVE_FORMAT_TEXT = "text"
ARCHIVE_FORMAT_BINARY = "binary"
ARCHIVE_FORMAT_GZIP = "gzip"
ARCHIVE_FORMAT_TAR = "tar"
ARCHIVE_FORMAT_ZIP = "zip"
BYTE_REDACTION_RULES = (
    (
        "private_key_block",
        re.compile(
            rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        b"<REDACTED:PRIVATE_KEY>",
    ),
    (
        "bearer_token",
        re.compile(rb"(?i)(authorization\s*[:=]\s*bearer\s+)([A-Za-z0-9._~+/=-]{8,})"),
        br"\1<REDACTED:BEARER_TOKEN>",
    ),
    (
        "api_key",
        re.compile(rb"(?i)(x-api-key\s*[:=]\s*)([A-Za-z0-9._~+/=-]{8,})"),
        br"\1<REDACTED:API_KEY>",
    ),
    (
        "aws_secret_access_key",
        re.compile(rb"(?i)(aws_secret_access_key\s*[:=]\s*)([A-Za-z0-9/+=]{20,})"),
        br"\1<REDACTED:AWS_SECRET_ACCESS_KEY>",
    ),
    (
        "password_assignment",
        re.compile(rb"(?i)(password\s*[:=]\s*)(\S+)"),
        br"\1<REDACTED:PASSWORD>",
    ),
)


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def path_is_within_root(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def has_symlink_component(path: pathlib.Path) -> bool:
    current = path
    while True:
        if current.is_symlink():
            return True
        if current.parent == current:
            return False
        current = current.parent


def resolve_allowed_input_path(
    base_dir: pathlib.Path,
    raw_path: str,
    allowed_roots: list[pathlib.Path],
) -> pathlib.Path:
    resolved = resolve_user_path(base_dir, raw_path)
    if not resolved.exists():
        return resolved
    if has_symlink_component(resolved):
        raise SystemExit(f"refusing symlink-backed support dump input: {resolved}")
    if not any(path_is_within_root(resolved, root) for root in allowed_roots):
        raise SystemExit(
            "support dump input is outside allowed roots:\n"
            f"{resolved}\n"
            "pass --allow-input-root for an explicit collection root"
        )
    return resolved


def matched_root_for_path(path: pathlib.Path, allowed_roots: list[pathlib.Path]) -> pathlib.Path:
    candidates = [root for root in allowed_roots if path_is_within_root(path, root)]
    if not candidates:
        raise SystemExit(f"unable to determine collection root for {path}")
    return max(candidates, key=lambda root: len(str(root)))


def relative_source_path(path: pathlib.Path, allowed_roots: list[pathlib.Path]) -> str:
    root = matched_root_for_path(path, allowed_roots)
    return str(path.relative_to(root))


def is_probably_text(payload: bytes) -> bool:
    if b"\0" in payload:
        return False
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def classify_payload(name: str, payload: bytes) -> str:
    suffixes = pathlib.Path(name.lower()).suffixes
    if zipfile.is_zipfile(io.BytesIO(payload)):
        return ARCHIVE_FORMAT_ZIP
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*"):
            return ARCHIVE_FORMAT_TAR
    except tarfile.TarError:
        pass
    if payload.startswith(b"\x1f\x8b") and suffixes:
        return ARCHIVE_FORMAT_GZIP
    if is_probably_text(payload):
        return ARCHIVE_FORMAT_TEXT
    return ARCHIVE_FORMAT_BINARY


def merge_rule_counters(current: dict[str, int], incoming: dict[str, int]) -> dict[str, int]:
    merged = dict(current)
    for key, value in incoming.items():
        merged[key] = merged.get(key, 0) + value
    return merged


def summarize_rules(triggered_counts: dict[str, int]) -> list[str]:
    return sorted(key for key, value in triggered_counts.items() if value > 0)


def scrub_raw_bytes(payload: bytes) -> tuple[bytes, dict[str, int]]:
    scrubbed = payload
    triggered_counts: dict[str, int] = {}

    for rule_name, pattern, replacement in BYTE_REDACTION_RULES:
        scrubbed, replacements = pattern.subn(replacement, scrubbed)
        if replacements != 0:
            triggered_counts[rule_name] = triggered_counts.get(rule_name, 0) + replacements

    return scrubbed, triggered_counts


def validate_archive_member_name(name: str) -> None:
    pure = pathlib.PurePosixPath(name)
    if pure.is_absolute() or ".." in pure.parts:
        raise SystemExit(f"refusing unsafe support dump archive member path: {name}")


def scrub_gzip_payload(
    name: str,
    payload: bytes,
    depth: int,
) -> tuple[bytes, dict]:
    with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as handle:
        decompressed = handle.read()
    inner_name = pathlib.Path(name).with_suffix("").name or "payload"
    scrubbed_inner, child_report = scrub_payload(inner_name, decompressed, depth + 1)
    output = io.BytesIO()
    with gzip.GzipFile(filename=inner_name, fileobj=output, mode="wb", mtime=0) as handle:
        handle.write(scrubbed_inner)
    report = {
        "format": ARCHIVE_FORMAT_GZIP,
        "member_count": 1,
        "redaction_count": int(child_report["redaction_count"]),
        "triggered_rules": list(child_report["triggered_rules"]),
        "triggered_rule_counts": dict(child_report["triggered_rule_counts"]),
        "members": [
            {
                "name": inner_name,
                "format": child_report["format"],
                "redaction_count": int(child_report["redaction_count"]),
                "triggered_rules": list(child_report["triggered_rules"]),
            }
        ],
    }
    return output.getvalue(), report


def scrub_zip_payload(
    payload: bytes,
    depth: int,
) -> tuple[bytes, dict]:
    input_buffer = io.BytesIO(payload)
    output_buffer = io.BytesIO()
    aggregate_rules: dict[str, int] = {}
    members: list[dict] = []
    member_count = 0

    with zipfile.ZipFile(input_buffer, "r") as archive:
        with zipfile.ZipFile(output_buffer, "w", compression=zipfile.ZIP_DEFLATED) as output_archive:
            for info in archive.infolist():
                validate_archive_member_name(info.filename)
                if info.is_dir():
                    directory_info = copy.copy(info)
                    directory_info.date_time = (1980, 1, 1, 0, 0, 0)
                    directory_info.create_system = 3
                    output_archive.writestr(directory_info, b"")
                    continue
                if (info.flag_bits & 0x1) != 0:
                    raise SystemExit(
                        f"refusing encrypted support dump archive member: {info.filename}"
                    )
                member_count += 1
                member_payload = archive.read(info.filename)
                scrubbed_member, member_report = scrub_payload(
                    info.filename,
                    member_payload,
                    depth + 1,
                )
                aggregate_rules = merge_rule_counters(
                    aggregate_rules,
                    dict(member_report["triggered_rule_counts"]),
                )
                sanitized_info = copy.copy(info)
                sanitized_info.date_time = (1980, 1, 1, 0, 0, 0)
                sanitized_info.create_system = 3
                sanitized_info.external_attr = 0
                sanitized_info.comment = b""
                output_archive.writestr(sanitized_info, scrubbed_member)
                members.append(
                    {
                        "name": info.filename,
                        "format": member_report["format"],
                        "redaction_count": int(member_report["redaction_count"]),
                        "triggered_rules": list(member_report["triggered_rules"]),
                    }
                )

    report = {
        "format": ARCHIVE_FORMAT_ZIP,
        "member_count": member_count,
        "redaction_count": sum(aggregate_rules.values()),
        "triggered_rules": summarize_rules(aggregate_rules),
        "triggered_rule_counts": aggregate_rules,
        "members": members,
    }
    return output_buffer.getvalue(), report


def scrub_tar_payload(
    payload: bytes,
    original_name: str,
    depth: int,
) -> tuple[bytes, dict]:
    output_buffer = io.BytesIO()
    aggregate_rules: dict[str, int] = {}
    members: list[dict] = []
    member_count = 0
    output_mode = "w"
    lowered = original_name.lower()
    if lowered.endswith(".tar.gz") or lowered.endswith(".tgz"):
        output_mode = "w:gz"

    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
        with tarfile.open(fileobj=output_buffer, mode=output_mode) as output_archive:
            for member in archive.getmembers():
                validate_archive_member_name(member.name)
                if member.isdir():
                    directory = tarfile.TarInfo(member.name)
                    directory.type = tarfile.DIRTYPE
                    directory.mode = 0o755
                    directory.mtime = 0
                    output_archive.addfile(directory)
                    continue
                if not member.isfile():
                    raise SystemExit(
                        f"refusing unsupported support dump tar member type: {member.name}"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise SystemExit(f"unable to extract support dump tar member: {member.name}")
                member_count += 1
                member_payload = extracted.read()
                scrubbed_member, member_report = scrub_payload(
                    member.name,
                    member_payload,
                    depth + 1,
                )
                aggregate_rules = merge_rule_counters(
                    aggregate_rules,
                    dict(member_report["triggered_rule_counts"]),
                )
                tar_member = tarfile.TarInfo(member.name)
                tar_member.size = len(scrubbed_member)
                tar_member.mode = 0o644
                tar_member.mtime = 0
                output_archive.addfile(tar_member, io.BytesIO(scrubbed_member))
                members.append(
                    {
                        "name": member.name,
                        "format": member_report["format"],
                        "redaction_count": int(member_report["redaction_count"]),
                        "triggered_rules": list(member_report["triggered_rules"]),
                    }
                )

    report = {
        "format": ARCHIVE_FORMAT_TAR,
        "member_count": member_count,
        "redaction_count": sum(aggregate_rules.values()),
        "triggered_rules": summarize_rules(aggregate_rules),
        "triggered_rule_counts": aggregate_rules,
        "members": members,
    }
    return output_buffer.getvalue(), report


def scrub_payload(
    name: str,
    payload: bytes,
    depth: int = 0,
) -> tuple[bytes, dict]:
    payload_format: str

    if depth > MAX_RECURSION_DEPTH:
        raise SystemExit(f"support dump archive nesting exceeds limit at: {name}")

    payload_format = classify_payload(name, payload)
    if payload_format == ARCHIVE_FORMAT_ZIP:
        scrubbed, report = scrub_zip_payload(payload, depth)
        return scrubbed, report
    if payload_format == ARCHIVE_FORMAT_TAR:
        scrubbed, report = scrub_tar_payload(payload, name, depth)
        return scrubbed, report
    if payload_format == ARCHIVE_FORMAT_GZIP:
        scrubbed, report = scrub_gzip_payload(name, payload, depth)
        return scrubbed, report

    scrubbed, triggered_counts = scrub_raw_bytes(payload)
    report = {
        "format": payload_format,
        "member_count": 0,
        "redaction_count": sum(triggered_counts.values()),
        "triggered_rules": summarize_rules(triggered_counts),
        "triggered_rule_counts": triggered_counts,
        "members": [],
    }
    return scrubbed, report


def scrub_file(path: pathlib.Path) -> tuple[bytes, dict]:
    return scrub_payload(path.name, path.read_bytes(), 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scrub secret-like content from standalone support dump files and archives."
    )
    parser.add_argument("--output-dir", required=True, help="Directory for scrubbed outputs")
    parser.add_argument(
        "--allow-input-root",
        action="append",
        default=[],
        help="Explicitly allow support dump inputs from this root in addition to the repository",
    )
    parser.add_argument(
        "--input",
        action="append",
        default=[],
        help="Support dump file or archive to scrub; may be repeated",
    )
    parser.add_argument(
        "--report",
        help="Optional JSON report path; defaults to <output-dir>/support-dump-scrub-report.json",
    )
    args = parser.parse_args()

    if not args.input:
        raise SystemExit("at least one --input is required")

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    repo_root = hypervisor_dir.parent
    output_dir = resolve_user_path(hypervisor_dir, args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report_path = (
        resolve_user_path(hypervisor_dir, args.report)
        if args.report is not None
        else output_dir / "support-dump-scrub-report.json"
    )

    allowed_roots = [repo_root.resolve()]
    allowed_roots.extend(
        resolve_user_path(repo_root, raw_root).resolve() for raw_root in args.allow_input_root
    )
    inputs = [
        resolve_allowed_input_path(hypervisor_dir, raw_path, allowed_roots)
        for raw_path in args.input
    ]
    missing = [str(path) for path in inputs if not path.is_file()]
    if missing:
        raise SystemExit("missing support dump inputs:\n" + "\n".join(missing))

    artifacts = []
    for index, path in enumerate(inputs):
        scrubbed_payload, scrub_report = scrub_file(path)
        output_name = f"scrubbed-{index:02d}-{path.name}"
        output_path = output_dir / output_name
        output_path.write_bytes(scrubbed_payload)
        artifacts.append(
            {
                "source_path": relative_source_path(path, allowed_roots),
                "output_path": output_name,
                "format": scrub_report["format"],
                "redaction_count": int(scrub_report["redaction_count"]),
                "triggered_rules": list(scrub_report["triggered_rules"]),
                "member_count": int(scrub_report["member_count"]),
                "members": scrub_report["members"],
            }
        )

    report = {
        "tool": {
            "name": "scrub_support_dump.py",
            "version": TOOL_VERSION,
        },
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
