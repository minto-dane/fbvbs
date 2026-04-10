#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import io
import json
import pathlib
import tarfile


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


def sha384_bytes(payload: bytes) -> str:
    digest = hashlib.sha384()
    digest.update(payload)
    return digest.hexdigest()


def extract_manifest(archive: tarfile.TarFile) -> tuple[str, dict]:
    for manifest_path in (
        "diagnostics/diagnostic-bundle-manifest.json",
        "evidence/standalone-evidence-pack-manifest.json",
    ):
        try:
            handle = archive.extractfile(manifest_path)
        except KeyError:
            continue
        if handle is None:
            raise SystemExit(f"unable to read manifest: {manifest_path}")
        payload = json.load(handle)
        if not isinstance(payload, dict):
            raise SystemExit("manifest must be a JSON object")
        return manifest_path, payload
    raise SystemExit("archive does not contain a supported retention manifest")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify retained integrity of standalone diagnostic bundles and evidence packs."
    )
    parser.add_argument("--archive", required=True, help="Tar.gz archive to verify")
    parser.add_argument("--output", help="Optional JSON report path")
    parser.add_argument(
        "--fail-on-warning",
        action="store_true",
        help="Exit non-zero if warnings are present",
    )
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    archive_path = resolve_user_path(hypervisor_dir, args.archive)
    if not archive_path.is_file():
        raise SystemExit(f"missing archive: {archive_path}")

    with tarfile.open(archive_path, "r:gz") as archive:
        manifest_path, manifest = extract_manifest(archive)
        names = set(archive.getnames())
        warnings: list[str] = []
        artifact_reports = []
        for artifact in manifest.get("artifacts", []):
            if not isinstance(artifact, dict):
                raise SystemExit("manifest artifacts must be objects")
            archive_member = artifact.get("archive_path")
            expected_sha = artifact.get("sha384")
            if not isinstance(archive_member, str) or not isinstance(expected_sha, str):
                raise SystemExit("manifest artifact must contain archive_path and sha384")
            if archive_member not in names:
                raise SystemExit(f"archive is missing manifest artifact: {archive_member}")
            extracted = archive.extractfile(archive_member)
            if extracted is None:
                raise SystemExit(f"unable to read archive member: {archive_member}")
            payload = extracted.read()
            actual_sha = sha384_bytes(payload)
            if actual_sha != expected_sha:
                raise SystemExit(f"sha384 mismatch for archive member: {archive_member}")
            artifact_reports.append(
                {
                    "archive_path": archive_member,
                    "kind": artifact.get("kind"),
                    "sha384": actual_sha,
                    "size_bytes": len(payload),
                }
            )

        signature = manifest.get("signature", {})
        if manifest.get("signed", False):
            signature_path = signature.get("signature_path")
            if not isinstance(signature_path, str) or signature_path not in names:
                raise SystemExit("signed manifest is missing detached signature artifact")
        else:
            warnings.append("manifest is unsigned")
        if not manifest.get("capture_complete", False):
            warnings.append("capture/evidence completeness was not asserted")

    report = {
        "tool": {"name": "check_retention_integrity.py", "version": TOOL_VERSION},
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "archive_path": str(archive_path),
        "manifest_path": manifest_path,
        "bundle_type": manifest.get("bundle_type"),
        "artifact_count": len(artifact_reports),
        "artifacts": artifact_reports,
        "warnings": warnings,
    }

    if args.output is not None:
        output_path = resolve_user_path(hypervisor_dir, args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(json.dumps(report, indent=2, sort_keys=True))
    if args.fail_on_warning and warnings:
        raise SystemExit("retention integrity warnings detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
