#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import pathlib
import subprocess


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists() or cwd_candidate.parent.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def openssl_output(argv: list[str]) -> str:
    return subprocess.check_output(argv, text=True).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Create detached signatures for retained-C release artifacts.")
    parser.add_argument("--build-dir", default="build", help="Path to the hypervisor build directory")
    parser.add_argument("--key", required=True, help="PEM private key for detached signatures")
    parser.add_argument("--cert", help="Optional PEM certificate or public cert for metadata")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parent
    build_dir = resolve_user_path(hypervisor_dir, args.build_dir)
    key_path = resolve_user_path(hypervisor_dir, args.key)
    cert_path = resolve_user_path(hypervisor_dir, args.cert) if args.cert is not None else None

    if not key_path.is_file():
        raise SystemExit(f"signing key not found: {key_path}")
    if cert_path is not None and not cert_path.is_file():
        raise SystemExit(f"certificate not found: {cert_path}")

    targets = [
        build_dir / "release-manifest.txt",
        build_dir / "release-readiness.json",
        build_dir / "provenance.json",
        build_dir / "release-evidence.tar.gz",
    ]
    missing = [str(path) for path in targets if not path.is_file()]
    if missing:
        raise SystemExit("missing artifacts for signing:\n" + "\n".join(missing))

    metadata = {
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "algorithm": "openssl-dgst-sha256",
        "key_path": str(key_path),
        "certificate_path": str(cert_path) if cert_path is not None else None,
        "certificate_sha256": file_sha256(cert_path) if cert_path is not None else None,
        "artifacts": [],
    }

    for target in targets:
        sig_path = target.with_suffix(target.suffix + ".sig")
        subprocess.check_call([
            "openssl", "dgst", "-sha256", "-sign", str(key_path),
            "-out", str(sig_path), str(target),
        ])
        metadata["artifacts"].append({
            "path": str(target),
            "sha256": file_sha256(target),
            "signature_path": str(sig_path),
            "signature_sha256": file_sha256(sig_path),
        })

    if cert_path is not None:
        try:
            metadata["certificate_subject"] = openssl_output(
                ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject"]
            )
        except subprocess.CalledProcessError:
            metadata["certificate_subject"] = None

    output_path = build_dir / "release-signatures.json"
    output_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
