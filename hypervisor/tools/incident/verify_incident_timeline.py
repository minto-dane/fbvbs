#!/usr/bin/env python3

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess


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


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def ensure_openssl_available() -> None:
    if shutil.which("openssl") is None:
        raise SystemExit("openssl is required for incident timeline signature verification")


def verify_signature(sealed_path: pathlib.Path, signature_path: pathlib.Path, public_key: pathlib.Path) -> None:
    ensure_openssl_available()
    subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha384",
            "-verify",
            str(public_key),
            "-signature",
            str(signature_path),
            str(sealed_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a sealed incident timeline hash chain and optional detached signature."
    )
    parser.add_argument("--input", required=True, help="Sealed incident timeline JSON")
    parser.add_argument("--public-key", help="Optional PEM public key for detached signature verification")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    input_path = resolve_user_path(hypervisor_dir, args.input)
    if not input_path.is_file():
        raise SystemExit(f"missing sealed incident timeline: {input_path}")

    sealed = json.loads(input_path.read_text(encoding="utf-8"))
    records = sealed.get("records")
    chain = sealed.get("record_chain")
    if not isinstance(records, list) or not isinstance(chain, list):
        raise SystemExit("sealed incident timeline must include records and record_chain arrays")
    if len(records) != len(chain):
        raise SystemExit("incident timeline chain length mismatch")

    previous_hash = "0" * 96
    for index, record in enumerate(records):
        entry = chain[index]
        record_hash = sha384_bytes(canonical_json_bytes(record))
        expected_chain_hash = sha384_bytes((previous_hash + record_hash).encode("ascii"))
        if entry.get("index") != index:
            raise SystemExit(f"incident timeline chain index mismatch at {index}")
        if entry.get("record_sha384") != record_hash:
            raise SystemExit(f"incident timeline record hash mismatch at {index}")
        if entry.get("previous_chain_sha384") != previous_hash:
            raise SystemExit(f"incident timeline previous hash mismatch at {index}")
        if entry.get("chain_sha384") != expected_chain_hash:
            raise SystemExit(f"incident timeline chain hash mismatch at {index}")
        previous_hash = expected_chain_hash

    if sealed.get("root_chain_sha384") != previous_hash:
        raise SystemExit("incident timeline root hash mismatch")
    if int(sealed.get("record_count", -1)) != len(records):
        raise SystemExit("incident timeline record_count mismatch")

    if args.public_key is not None:
        signature_path_raw = sealed.get("signature_path")
        if not isinstance(signature_path_raw, str) or len(signature_path_raw) == 0:
            raise SystemExit("sealed incident timeline does not declare signature_path")
        signature_path = resolve_user_path(hypervisor_dir, signature_path_raw)
        public_key = resolve_user_path(hypervisor_dir, args.public_key)
        if not signature_path.is_file():
            raise SystemExit(f"missing incident timeline signature: {signature_path}")
        if not public_key.is_file():
            raise SystemExit(f"missing incident timeline public key: {public_key}")
        verify_signature(input_path, signature_path, public_key)

    print(f"Verified {input_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
