#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import pathlib


EXPECTED_QEMU_TERMINALS = (
    "FBVBS: hypervisor init complete",
    "FBVBS: VMX unavailable",
    "FBVBS: IOMMU detection failed",
    "FBVBS: IOMMU initialization failed",
    "FBVBS: measured boot unavailable",
)

REQUIRED_RELEASE_DOCS = (
    "README.md",
    "RELEASE.md",
    "hypervisor/README.md",
    "hypervisor/compliance/retained_c_leaf_boundary.md",
    "hypervisor/compliance/security_target_outline.md",
    "hypervisor/compliance/hardware_validation_campaign.md",
    "hypervisor/compliance/deployment_profile.md",
    "hypervisor/compliance/audit_oob_collection.md",
    "hypervisor/compliance/release_promotion_model.md",
    "plan/full-stack/fbvbs-design.md",
    "plan/overview/fbvbs-comprehensive-roadmap-2026-03-20.md",
)


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def text_contains(path: pathlib.Path, needle: str) -> bool:
    if not path.is_file():
        return False
    return needle in path.read_text(encoding="utf-8", errors="replace")


def normalized_text(path: pathlib.Path) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in text.split("\n")).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize retained-C release readiness.")
    parser.add_argument("--build-dir", default="build", help="Path to the hypervisor build directory")
    parser.add_argument("--output", required=True, help="JSON output path")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    build_dir = resolve_user_path(hypervisor_dir, args.build_dir)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    repo_root = hypervisor_dir.parent

    qemu_log = build_dir / "qemu-smoke.log"
    qemu_stage1 = build_dir / "qemu-smoke-summary.txt"
    qemu_stage3 = build_dir / "qemu-iommu-summary.txt"
    qemu_matrix = build_dir / "qemu-matrix-summary.txt"
    proof_log = build_dir / "proof-smoke.log"
    fuzz_log = build_dir / "fuzz-smoke.txt"
    repro1 = build_dir / "repro_manifest_1.sha256"
    repro2 = build_dir / "repro_manifest_2.sha256"

    artifacts = {}
    for rel_name in (
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
        "release-signatures.json",
        "sbom.txt",
        "repro_manifest_1.sha256",
        "repro_manifest_2.sha256",
    ):
        path = build_dir / rel_name
        artifacts[rel_name] = {
            "present": path.is_file(),
            "sha256": file_sha256(path) if path.is_file() else None,
        }

    qemu_ready = text_contains(qemu_log, "FBVBS: boot64 reached") and any(
        text_contains(qemu_log, terminal) for terminal in EXPECTED_QEMU_TERMINALS
    )
    qemu_stage1_ready = text_contains(qemu_stage1, "overall=PASS")
    qemu_stage3_ready = text_contains(qemu_stage3, "overall=PASS")
    qemu_matrix_ready = text_contains(qemu_matrix, "overall=PASS")
    proof_ready = text_contains(proof_log, "Running WP plugin")
    fuzz_ready = text_contains(fuzz_log, "overall=PASS")
    repro1_text = normalized_text(repro1) if repro1.is_file() else ""
    repro2_text = normalized_text(repro2) if repro2.is_file() else ""
    repro_ready = (
        repro1.is_file() and
        repro2.is_file() and
        len(repro1_text) > 0 and
        len(repro2_text) > 0 and
        repro1_text == repro2_text
    )
    docs = {
        rel_name: (repo_root / rel_name).is_file()
        for rel_name in REQUIRED_RELEASE_DOCS
    }
    docs_ready = all(docs.values())

    data = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "release_boundary": "standalone-retained-c-microhypervisor",
        "retained_c_foundation_gates": {
            "baremetal_artifacts_present": artifacts["fbvbs-baremetal.elf"]["present"] and artifacts["fbvbs-baremetal.iso"]["present"],
            "qemu_smoke": qemu_ready,
            "qemu_stage1_summary": qemu_stage1_ready,
            "qemu_stage3_iommu_emulation": qemu_stage3_ready,
            "qemu_matrix_summary": qemu_matrix_ready,
            "fuzz_smoke": fuzz_ready,
            "proof_smoke": proof_ready,
            "proof_shards_summary_present": artifacts["proof-shards-summary.txt"]["present"],
            "provenance_present": artifacts["provenance.json"]["present"],
            "signature_metadata_present": artifacts["release-signatures.json"]["present"],
            "sbom_present": artifacts["sbom.txt"]["present"],
            "reproducible_manifests_match": repro_ready,
            "operational_release_docs_present": docs_ready,
        },
        "artifacts": artifacts,
        "release_documents": docs,
        "producer_facing_release_ready": False,
        "remaining_blockers": [
            "authoritative real-hardware IOMMU validation and host-wide device/domain policy are not complete",
            "host deprivilege / VMLAUNCH handoff is not yet end-to-end release-complete",
            "full Frama-C/WP proof remains incomplete beyond proof-smoke and proof-shards evidence",
            "Intel/AMD hardware integration testing remains required beyond QEMU smoke",
            "release provenance still requires external signing and publication controls",
        ],
    }

    output_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
