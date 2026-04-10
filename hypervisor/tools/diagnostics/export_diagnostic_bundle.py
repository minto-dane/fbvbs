#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile

BUNDLE_FORMAT_VERSION = 2
TOOL_VERSION = 1
REQUIRED_SCHEMA_KEYS = (
    "management_abi_version",
    "health_schema_version",
    "audit_schema_version",
    "inventory_schema_version",
    "guidance_schema_version",
    "fault_record_schema_version",
    "compatibility_flags",
)
REQUIRED_SUPPORT_DUMP_REPORT_KEYS = (
    "tool",
    "artifact_count",
    "artifacts",
)

MAX_SECRET_SCAN_BYTES = 1024 * 1024
PRIVATE_KEY_NAME_PATTERNS = (
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "private_key",
    "signing-key",
    "signing_key",
)
PRIVATE_KEY_SUFFIXES = (
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".kdbx",
)
SENSITIVE_NAME_PATTERNS = (
    ".env",
    "secret",
    "token",
    "credential",
    "passwd",
    "password",
)
SECRET_CONTENT_PATTERNS = (
    re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(rb"-----BEGIN OPENSSH PRIVATE KEY-----"),
    re.compile(rb"authorization[\"' =:]+bearer[ _-]*[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(rb"x-api-key[\"' =:]+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(rb"aws_secret_access_key[\"' =:]+[A-Za-z0-9/+=]{20,}", re.IGNORECASE),
)


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def normalize_tarinfo(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo:
    tarinfo.mtime = 0
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = ""
    tarinfo.gname = ""
    name = tarinfo.name
    if name.startswith("/"):
        name = name.lstrip("/")
    safe_parts = [part for part in name.split("/") if part and part != ".."]
    tarinfo.name = "/".join(safe_parts)
    return tarinfo


def file_sha384(path: pathlib.Path) -> str:
    digest = hashlib.sha384()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: pathlib.Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"diagnostic JSON must be an object: {path}")
    return payload


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
        raise SystemExit(f"refusing symlink-backed diagnostic input: {resolved}")
    if not any(path_is_within_root(resolved, root) for root in allowed_roots):
        raise SystemExit(
            "diagnostic input is outside allowed roots:\n"
            f"{resolved}\n"
            "pass --allow-input-root for an explicit collection root"
        )
    return resolved


def matched_root_for_path(path: pathlib.Path, allowed_roots: list[pathlib.Path]) -> pathlib.Path:
    candidates = [root for root in allowed_roots if path_is_within_root(path, root)]
    if not candidates:
        raise SystemExit(f"unable to determine collection root for {path}")
    return max(candidates, key=lambda root: len(str(root)))


def root_index_for_path(path: pathlib.Path, allowed_roots: list[pathlib.Path]) -> int:
    root = matched_root_for_path(path, allowed_roots)
    return allowed_roots.index(root)


def relative_source_path(path: pathlib.Path, allowed_roots: list[pathlib.Path]) -> str:
    root = matched_root_for_path(path, allowed_roots)
    return str(path.relative_to(root))


def sha384_bytes(payload: bytes) -> str:
    digest = hashlib.sha384()
    digest.update(payload)
    return digest.hexdigest()


def ensure_schema_registry_shape(schema_registry: dict) -> None:
    missing = [key for key in REQUIRED_SCHEMA_KEYS if key not in schema_registry]
    if missing:
        raise SystemExit(
            "schema registry JSON is missing required keys:\n" + "\n".join(missing)
        )
    if not isinstance(schema_registry["compatibility_flags"], int):
        raise SystemExit("schema registry compatibility_flags must be an integer bitmask")


def ensure_support_dump_report_shape(report: dict) -> None:
    missing = [key for key in REQUIRED_SUPPORT_DUMP_REPORT_KEYS if key not in report]
    if missing:
        raise SystemExit(
            "support dump scrub report is missing required keys:\n" + "\n".join(missing)
        )
    if not isinstance(report["artifact_count"], int):
        raise SystemExit("support dump scrub report artifact_count must be an integer")
    if not isinstance(report["artifacts"], list):
        raise SystemExit("support dump scrub report artifacts must be a list")


def ensure_openssl_available() -> None:
    if shutil.which("openssl") is None:
        raise SystemExit("openssl is required for diagnostic bundle signing")


def reject_sensitive_input(path: pathlib.Path) -> None:
    lowered_name = path.name.lower()
    if any(pattern in lowered_name for pattern in PRIVATE_KEY_NAME_PATTERNS):
        raise SystemExit(f"refusing to include likely private key material: {path}")
    if any(lowered_name.endswith(suffix) for suffix in PRIVATE_KEY_SUFFIXES):
        raise SystemExit(f"refusing to include likely secret-bearing file type: {path}")
    if any(pattern in lowered_name for pattern in SENSITIVE_NAME_PATTERNS):
        raise SystemExit(f"refusing to include likely sensitive file name: {path}")

    with path.open("rb") as handle:
        sample = handle.read(MAX_SECRET_SCAN_BYTES)
    for pattern in SECRET_CONTENT_PATTERNS:
        if pattern.search(sample) is not None:
            raise SystemExit(f"refusing to include file with secret-like content: {path}")


def reject_unscrubbed_support_dump(path: pathlib.Path) -> None:
    with path.open("rb") as handle:
        sample = handle.read(MAX_SECRET_SCAN_BYTES)
    for pattern in SECRET_CONTENT_PATTERNS:
        if pattern.search(sample) is not None:
            raise SystemExit(f"refusing to bundle unsanitized support dump content: {path}")


def make_artifact(
    source: pathlib.Path,
    archive_path: str,
    kind: str,
    allowed_roots: list[pathlib.Path],
) -> dict:
    return {
        "source": source,
        "archive_path": archive_path,
        "kind": kind,
        "source_root_index": root_index_for_path(source, allowed_roots),
        "source_path": relative_source_path(source, allowed_roots),
    }


def validate_json_artifact_consistency(
    schema_registry: dict,
    inventory_path: pathlib.Path,
    partition_list_path: pathlib.Path,
    fault_record_paths: list[pathlib.Path],
    guidance_paths: list[pathlib.Path],
) -> dict:
    measurement_epochs: set[int] = set()
    boot_ids: set[str] = set()
    schema_expectations = (
        ("inventory_schema_version", inventory_path),
        ("fault_record_schema_version", *fault_record_paths),
        ("guidance_schema_version", *guidance_paths),
    )

    for expected_key, *paths in schema_expectations:
        expected_version = schema_registry.get(expected_key)
        for path in paths:
            payload = read_json(path)
            schema_version = payload.get("schema_version")
            if schema_version is not None and expected_version is not None:
                if schema_version != expected_version:
                    raise SystemExit(
                        f"schema version mismatch for {path}: "
                        f"expected {expected_version}, got {schema_version}"
                    )

    for path in [inventory_path, partition_list_path] + fault_record_paths + guidance_paths:
        payload = read_json(path)
        measurement_epoch = payload.get("measurement_epoch")
        if measurement_epoch is not None:
            measurement_epochs.add(int(measurement_epoch))
        boot_id = payload.get("boot_id")
        if boot_id is not None:
            boot_ids.add(str(boot_id))

    if len(measurement_epochs) > 1:
        raise SystemExit("diagnostic inputs disagree on measurement_epoch")
    if len(boot_ids) > 1:
        raise SystemExit("diagnostic inputs disagree on boot_id")

    summary: dict[str, object] = {
        "measurement_epoch": next(iter(measurement_epochs), None),
        "boot_id": next(iter(boot_ids), None),
    }
    return summary


def validate_support_dump_report(
    report_path: pathlib.Path,
    support_dump_paths: list[pathlib.Path],
) -> dict:
    report = read_json(report_path)
    ensure_support_dump_report_shape(report)
    artifacts = report.get("artifacts")
    tool = report.get("tool")
    if not isinstance(tool, dict) or tool.get("name") != "scrub_support_dump.py":
        raise SystemExit("support dump scrub report must originate from scrub_support_dump.py")

    reported_outputs = {
        str(item.get("output_path"))
        for item in artifacts
        if isinstance(item, dict) and isinstance(item.get("output_path"), str)
    }
    if len(reported_outputs) != len(support_dump_paths):
        raise SystemExit(
            "support dump scrub report does not describe every bundled support dump"
        )
    if report["artifact_count"] != len(support_dump_paths):
        raise SystemExit(
            "support dump scrub report artifact_count does not match bundled support dumps"
        )
    for path in support_dump_paths:
        if path.name not in reported_outputs:
            raise SystemExit(
                "support dump scrub report is missing bundled artifact: "
                f"{path.name}"
            )
    return report


def public_key_sha384(signing_key: pathlib.Path) -> str:
    ensure_openssl_available()
    result = subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(signing_key),
            "-pubout",
            "-outform",
            "DER",
        ],
        check=True,
        capture_output=True,
    )
    return sha384_bytes(result.stdout)


def certificate_sha384(signing_cert: pathlib.Path) -> str:
    ensure_openssl_available()
    result = subprocess.run(
        [
            "openssl",
            "x509",
            "-in",
            str(signing_cert),
            "-outform",
            "DER",
        ],
        check=True,
        capture_output=True,
    )
    return sha384_bytes(result.stdout)


def certificate_subject(signing_cert: pathlib.Path) -> str | None:
    ensure_openssl_available()
    try:
        result = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(signing_cert),
                "-noout",
                "-subject",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError:
        return None
    return result.stdout.strip() or None


def build_manifest(
    artifacts: list[dict],
    schema_registry: dict,
    consistency_summary: dict,
    support_dump_summary: dict,
    signature_metadata: dict,
    note: str | None,
    capture_complete: bool,
) -> dict:
    entries = []
    fault_record_count = 0
    guidance_count = 0
    documentation_count = 0
    support_dump_count = 0
    support_dump_report_count = 0
    for artifact in artifacts:
        path = artifact["source"]
        entries.append(
            {
                "archive_path": artifact["archive_path"],
                "logical_name": artifact["archive_path"].split("/")[-1],
                "source_root_index": artifact["source_root_index"],
                "source_path": artifact["source_path"],
                "kind": artifact["kind"],
                "sha384": file_sha384(path),
                "size_bytes": path.stat().st_size,
            }
        )
        if artifact["kind"] == "fault-record":
            fault_record_count += 1
        if artifact["kind"] == "guidance":
            guidance_count += 1
        if artifact["kind"] == "documentation":
            documentation_count += 1
        if artifact["kind"] == "support-dump":
            support_dump_count += 1
        if artifact["kind"] == "support-dump-report":
            support_dump_report_count += 1

    collection_warnings: list[str] = []
    if not capture_complete:
        collection_warnings.append(
            "capture completeness not asserted; operator must verify artifact coverage"
        )

    return {
        "bundle_type": "fbvbs-standalone-diagnostic",
        "bundle_format_version": BUNDLE_FORMAT_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "bundle_root": "diagnostics",
        "tool": {
            "name": "export_diagnostic_bundle.py",
            "version": TOOL_VERSION,
        },
        "signed": bool(signature_metadata["signed"]),
        "note": note,
        "capture_complete": capture_complete,
        "missing_inputs": [],
        "collection_warnings": collection_warnings,
        "schema_registry": schema_registry,
        "collection_consistency": consistency_summary,
        "signature": signature_metadata,
        "artifacts": entries,
        "fault_record_count": fault_record_count,
        "guidance_count": guidance_count,
        "documentation_count": documentation_count,
        "support_dump_count": support_dump_count,
        "support_dump_report_count": support_dump_report_count,
        "support_dump_scrubbing": support_dump_summary,
    }


def sign_manifest(
    manifest_path: pathlib.Path,
    signature_path: pathlib.Path,
    signing_key: pathlib.Path,
) -> None:
    subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha384",
            "-sign",
            str(signing_key),
            "-out",
            str(signature_path),
            str(manifest_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def add_file(
    archive: tarfile.TarFile,
    source: pathlib.Path,
    arcname: str,
    index_lines: list[str],
) -> None:
    archive.add(source, arcname=arcname, filter=normalize_tarinfo)
    index_lines.append(arcname)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export standalone diagnostic artifacts as a normalized tar.gz bundle."
    )
    parser.add_argument("--output", required=True, help="Output tar.gz bundle path")
    parser.add_argument("--schema-registry", required=True, help="Schema registry JSON")
    parser.add_argument("--inventory", required=True, help="Inventory JSON")
    parser.add_argument("--partition-list", required=True, help="Partition list JSON")
    parser.add_argument(
        "--fault-record",
        action="append",
        default=[],
        help="Fault record JSON; may be repeated",
    )
    parser.add_argument(
        "--guidance",
        action="append",
        default=[],
        help="Reason guidance JSON; may be repeated",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=[],
        help="Additional diagnostic file to include",
    )
    parser.add_argument(
        "--doc",
        action="append",
        default=[],
        help="Additional documentation file to include",
    )
    parser.add_argument(
        "--support-dump",
        action="append",
        default=[],
        help="Scrubbed support dump artifact to include; may be repeated",
    )
    parser.add_argument(
        "--support-dump-report",
        help="JSON scrub report produced by scrub_support_dump.py for the bundled support dumps",
    )
    parser.add_argument("--note", help="Optional operator note recorded in manifest")
    parser.add_argument(
        "--allow-input-root",
        action="append",
        default=[],
        help="Explicitly allow diagnostic inputs from this root in addition to the repository",
    )
    parser.add_argument(
        "--capture-complete",
        action="store_true",
        help="Assert that the supplied artifacts represent a complete diagnostic capture",
    )
    parser.add_argument("--signing-key", help="PEM private key for detached manifest signature")
    parser.add_argument("--signing-cert", help="Optional PEM certificate to include alongside signature")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    repo_root = hypervisor_dir.parent
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    allowed_roots = [repo_root.resolve()]
    allowed_roots.extend(
        resolve_user_path(repo_root, raw_root).resolve() for raw_root in args.allow_input_root
    )

    schema_registry_path = resolve_allowed_input_path(
        hypervisor_dir, args.schema_registry, allowed_roots
    )
    inventory_path = resolve_allowed_input_path(hypervisor_dir, args.inventory, allowed_roots)
    partition_list_path = resolve_allowed_input_path(
        hypervisor_dir, args.partition_list, allowed_roots
    )
    fault_record_paths = [
        resolve_allowed_input_path(hypervisor_dir, item, allowed_roots)
        for item in args.fault_record
    ]
    guidance_paths = [
        resolve_allowed_input_path(hypervisor_dir, item, allowed_roots)
        for item in args.guidance
    ]
    extra_paths = [
        resolve_allowed_input_path(hypervisor_dir, item, allowed_roots)
        for item in args.include
    ]
    doc_paths = [resolve_allowed_input_path(repo_root, item, allowed_roots) for item in args.doc]
    support_dump_paths = [
        resolve_allowed_input_path(hypervisor_dir, item, allowed_roots)
        for item in args.support_dump
    ]
    if args.support_dump_report is not None:
        support_dump_report_path = resolve_allowed_input_path(
            hypervisor_dir, args.support_dump_report, allowed_roots
        )
    else:
        support_dump_report_path = None

    required_paths = [schema_registry_path, inventory_path, partition_list_path]
    missing = [str(path) for path in required_paths if not path.is_file()]
    missing.extend(str(path) for path in fault_record_paths if not path.is_file())
    missing.extend(str(path) for path in guidance_paths if not path.is_file())
    missing.extend(str(path) for path in extra_paths if not path.is_file())
    missing.extend(str(path) for path in doc_paths if not path.is_file())
    missing.extend(str(path) for path in support_dump_paths if not path.is_file())
    if support_dump_report_path is not None and not support_dump_report_path.is_file():
        missing.append(str(support_dump_report_path))
    if args.signing_key is not None:
        signing_key = resolve_allowed_input_path(hypervisor_dir, args.signing_key, allowed_roots)
        if not signing_key.is_file():
            missing.append(str(signing_key))
    else:
        signing_key = None
    if args.signing_cert is not None:
        signing_cert = resolve_allowed_input_path(hypervisor_dir, args.signing_cert, allowed_roots)
        if not signing_cert.is_file():
            missing.append(str(signing_cert))
    else:
        signing_cert = None
    if missing:
        raise SystemExit("missing diagnostic bundle inputs:\n" + "\n".join(missing))

    if support_dump_paths and support_dump_report_path is None:
        raise SystemExit("support dump artifacts require --support-dump-report")
    if support_dump_report_path is not None and not support_dump_paths:
        raise SystemExit("--support-dump-report requires at least one --support-dump")

    for path in extra_paths + doc_paths:
        reject_sensitive_input(path)
    for path in support_dump_paths:
        reject_unscrubbed_support_dump(path)

    schema_registry = read_json(schema_registry_path)
    ensure_schema_registry_shape(schema_registry)
    consistency_summary = validate_json_artifact_consistency(
        schema_registry,
        inventory_path,
        partition_list_path,
        fault_record_paths,
        guidance_paths,
    )
    if support_dump_report_path is not None:
        support_dump_report = validate_support_dump_report(
            support_dump_report_path,
            support_dump_paths,
        )
        support_dump_summary = {
            "scrubbed": True,
            "report_archive_path": "diagnostics/support-dump-scrub-report.json",
            "artifact_count": len(support_dump_paths),
            "tool": support_dump_report["tool"],
        }
    else:
        support_dump_summary = {
            "scrubbed": False,
            "report_archive_path": None,
            "artifact_count": 0,
            "tool": None,
        }

    artifacts = [
        make_artifact(schema_registry_path, "diagnostics/schema-registry.json", "schema-registry", allowed_roots),
        make_artifact(inventory_path, "diagnostics/inventory.json", "inventory", allowed_roots),
        make_artifact(partition_list_path, "diagnostics/partition-list.json", "partition-list", allowed_roots),
    ]
    artifacts.extend(
        make_artifact(path, f"diagnostics/fault-record-{index:02d}.json", "fault-record", allowed_roots)
        for index, path in enumerate(fault_record_paths)
    )
    artifacts.extend(
        make_artifact(path, f"diagnostics/guidance-{index:02d}.json", "guidance", allowed_roots)
        for index, path in enumerate(guidance_paths)
    )
    artifacts.extend(
        make_artifact(path, f"diagnostics/extra-{index:02d}-{path.name}", "extra", allowed_roots)
        for index, path in enumerate(extra_paths)
    )
    artifacts.extend(
        make_artifact(path, f"docs/{path.name}", "documentation", allowed_roots)
        for path in doc_paths
    )
    artifacts.extend(
        make_artifact(
            path,
            f"diagnostics/support-dump-{index:02d}-{path.name}",
            "support-dump",
            allowed_roots,
        )
        for index, path in enumerate(support_dump_paths)
    )
    if support_dump_report_path is not None:
        artifacts.append(
            make_artifact(
                support_dump_report_path,
                "diagnostics/support-dump-scrub-report.json",
                "support-dump-report",
                allowed_roots,
            )
        )
    if signing_cert is not None:
        artifacts.append(
            make_artifact(
                signing_cert,
                "diagnostics/diagnostic-bundle-signer.pem",
                "signing-certificate",
                allowed_roots,
            )
        )

    signature_metadata = {
        "signed": signing_key is not None,
        "manifest_path": "diagnostics/diagnostic-bundle-manifest.json",
        "signature_path": None,
        "signature_algorithm": None,
        "public_key_fingerprint_sha384": None,
        "verification_hint": None,
        "certificate_path": None,
        "certificate_fingerprint_sha384": None,
        "certificate_subject": None,
    }
    if signing_key is not None:
        signature_metadata.update(
            {
                "signature_path": "diagnostics/diagnostic-bundle-manifest.sig",
                "signature_algorithm": "openssl-dgst-sha384",
                "public_key_fingerprint_sha384": public_key_sha384(signing_key),
                "verification_hint": (
                    "openssl dgst -sha384 -verify <public-key.pem> "
                    "-signature diagnostics/diagnostic-bundle-manifest.sig "
                    "diagnostics/diagnostic-bundle-manifest.json"
                ),
            }
        )
        if signing_cert is not None:
            signature_metadata.update(
                {
                    "certificate_path": "diagnostics/diagnostic-bundle-signer.pem",
                    "certificate_fingerprint_sha384": certificate_sha384(signing_cert),
                    "certificate_subject": certificate_subject(signing_cert),
                }
            )

    manifest = build_manifest(
        artifacts,
        schema_registry,
        consistency_summary,
        support_dump_summary,
        signature_metadata,
        args.note,
        args.capture_complete,
    )

    index_lines = ["FBVBS standalone diagnostic bundle", ""]
    index_path = output_path.with_suffix("").with_suffix(".index.txt")

    with tempfile.TemporaryDirectory(prefix="fbvbs-diag-bundle-") as temp_dir_raw:
        temp_dir = pathlib.Path(temp_dir_raw)
        manifest_path = temp_dir / "diagnostic-bundle-manifest.json"
        signature_path = temp_dir / "diagnostic-bundle-manifest.sig"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        if signing_key is not None:
            sign_manifest(manifest_path, signature_path, signing_key)

        with tarfile.open(output_path, "w:gz") as archive:
            add_file(
                archive,
                manifest_path,
                "diagnostics/diagnostic-bundle-manifest.json",
                index_lines,
            )
            if signing_key is not None:
                add_file(
                    archive,
                    signature_path,
                    "diagnostics/diagnostic-bundle-manifest.sig",
                    index_lines,
                )
            if signing_cert is not None:
                add_file(
                    archive,
                    signing_cert,
                    "diagnostics/diagnostic-bundle-signer.pem",
                    index_lines,
                )
            add_file(
                archive,
                schema_registry_path,
                "diagnostics/schema-registry.json",
                index_lines,
            )
            add_file(
                archive,
                inventory_path,
                "diagnostics/inventory.json",
                index_lines,
            )
            add_file(
                archive,
                partition_list_path,
                "diagnostics/partition-list.json",
                index_lines,
            )
            for index, path in enumerate(fault_record_paths):
                add_file(
                    archive,
                    path,
                    f"diagnostics/fault-record-{index:02d}.json",
                    index_lines,
                )
            for index, path in enumerate(guidance_paths):
                add_file(
                    archive,
                    path,
                    f"diagnostics/guidance-{index:02d}.json",
                    index_lines,
                )
            for index, path in enumerate(extra_paths):
                add_file(
                    archive,
                    path,
                    f"diagnostics/extra-{index:02d}-{path.name}",
                    index_lines,
                )
            for path in doc_paths:
                add_file(
                    archive,
                    path,
                    f"docs/{path.name}",
                    index_lines,
                )
            for index, path in enumerate(support_dump_paths):
                add_file(
                    archive,
                    path,
                    f"diagnostics/support-dump-{index:02d}-{path.name}",
                    index_lines,
                )
            if support_dump_report_path is not None:
                add_file(
                    archive,
                    support_dump_report_path,
                    "diagnostics/support-dump-scrub-report.json",
                    index_lines,
                )

    index_path.write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    print(f"Wrote {index_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
