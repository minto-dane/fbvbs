#!/usr/bin/env python3

import argparse
import pathlib
import tarfile


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists() or cwd_candidate.parent.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def main() -> int:
    parser = argparse.ArgumentParser(description="Bundle retained-C release evidence artifacts.")
    parser.add_argument("--build-dir", default="build", help="Path to the hypervisor build directory")
    parser.add_argument("--output", required=True, help="Path to the tar.gz bundle to create")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parent
    repo_root = hypervisor_dir.parent
    build_dir = resolve_user_path(hypervisor_dir, args.build_dir)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    build_files = [
        "fbvbs-baremetal.elf",
        "fbvbs-baremetal.iso",
        "iso-file-list.txt",
        "qemu-smoke.log",
        "qemu-smoke-summary.txt",
        "qemu-iommu-summary.txt",
        "qemu-matrix-summary.txt",
        "fuzz-smoke.txt",
        "proof-smoke.log",
        "proof-shards-summary.txt",
        "provenance.json",
        "release-readiness.json",
        "release-manifest.txt",
        "sbom.txt",
        "repro_manifest_1.sha256",
        "repro_manifest_2.sha256",
    ]
    optional_build_files = [
        "release-signatures.json",
        "release-manifest.txt.sig",
        "release-readiness.json.sig",
        "provenance.json.sig",
        "release-evidence.tar.gz.sig",
    ]
    doc_files = [
        "README.md",
        "RELEASE.md",
        "hypervisor/README.md",
        "hypervisor/compliance/retained_c_leaf_boundary.md",
        "hypervisor/compliance/security_target_outline.md",
        "hypervisor/compliance/hardware_validation_campaign.md",
        "hypervisor/compliance/deployment_profile.md",
        "hypervisor/compliance/audit_oob_collection.md",
        "hypervisor/compliance/release_promotion_model.md",
        "plan/fbvbs-design.md",
        "plan/fbvbs-comprehensive-roadmap-2026-03-20.md",
    ]

    missing: list[str] = []
    for rel in build_files:
        if not (build_dir / rel).is_file():
            missing.append(str(build_dir / rel))
    for rel in doc_files:
        if not (repo_root / rel).is_file():
            missing.append(str(repo_root / rel))
    if missing:
        raise SystemExit("missing release evidence inputs:\n" + "\n".join(missing))

    index_lines = ["FBVBS retained-C release evidence bundle", ""]
    with tarfile.open(output_path, "w:gz") as archive:
        for rel in build_files:
            full = build_dir / rel
            arc = pathlib.Path("build") / rel
            archive.add(full, arcname=str(arc))
            index_lines.append(str(arc))
        for rel in optional_build_files:
            full = build_dir / rel
            if full.is_file():
                arc = pathlib.Path("build") / rel
                archive.add(full, arcname=str(arc))
                index_lines.append(str(arc))
        qemu_logs_dir = build_dir / "qemu-smoke-logs"
        if qemu_logs_dir.is_dir():
            archive.add(qemu_logs_dir, arcname="build/qemu-smoke-logs")
            index_lines.append("build/qemu-smoke-logs/")
        for rel in doc_files:
            full = repo_root / rel
            archive.add(full, arcname=rel)
            index_lines.append(rel)

    index_path = build_dir / "release-evidence-index.txt"
    index_path.write_text("\n".join(index_lines) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    print(f"Wrote {index_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
