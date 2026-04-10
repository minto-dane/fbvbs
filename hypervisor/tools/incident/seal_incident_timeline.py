#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess


TOOL_VERSION = 1
SEAL_SCHEMA_VERSION = 1


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
        raise SystemExit("openssl is required for incident timeline signing")


def sign_json(
    json_path: pathlib.Path,
    signature_path: pathlib.Path,
    signing_key: pathlib.Path,
) -> None:
    ensure_openssl_available()
    subprocess.run(
        [
            "openssl",
            "dgst",
            "-sha384",
            "-sign",
            str(signing_key),
            "-out",
            str(signature_path),
            str(json_path),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def build_chain(records: list[dict]) -> list[dict]:
    chain: list[dict] = []
    previous_hash = "0" * 96

    for index, record in enumerate(records):
        record_hash = sha384_bytes(canonical_json_bytes(record))
        chain_hash = sha384_bytes((previous_hash + record_hash).encode("ascii"))
        chain.append(
            {
                "index": index,
                "sequence": int(record.get("sequence", 0)),
                "boot_id": str(record.get("boot_id", "global")),
                "record_sha384": record_hash,
                "previous_chain_sha384": previous_hash,
                "chain_sha384": chain_hash,
            }
        )
        previous_hash = chain_hash

    return chain


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seal a reconstructed incident timeline with a deterministic hash chain."
    )
    parser.add_argument("--input", required=True, help="Input timeline JSON")
    parser.add_argument("--output", required=True, help="Output sealed timeline JSON")
    parser.add_argument("--signing-key", help="Optional PEM private key for detached signature")
    parser.add_argument(
        "--signature-output",
        help="Optional detached signature output path; defaults to <output>.sig",
    )
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    input_path = resolve_user_path(hypervisor_dir, args.input)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not input_path.is_file():
        raise SystemExit(f"missing incident timeline input: {input_path}")

    timeline = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(timeline, dict):
        raise SystemExit("incident timeline JSON must be an object")
    records = timeline.get("records")
    if not isinstance(records, list):
        raise SystemExit("incident timeline JSON must contain a records array")

    chain = build_chain(records)
    sealed = {
        "tool": {
            "name": "seal_incident_timeline.py",
            "version": TOOL_VERSION,
        },
        "seal_schema_version": SEAL_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_timeline_sha384": sha384_bytes(input_path.read_bytes()),
        "record_count": len(records),
        "root_chain_sha384": chain[-1]["chain_sha384"] if chain else "0" * 96,
        "immutability": {
            "schema_version": SEAL_SCHEMA_VERSION,
            "timeline_root_sha384": chain[-1]["chain_sha384"] if chain else "0" * 96,
            "record_count": len(records),
        },
        "records": records,
        "record_chain": chain,
        "signed": args.signing_key is not None,
        "signature_path": None,
    }
    output_path.write_text(json.dumps(sealed, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.signing_key is not None:
        signing_key = resolve_user_path(hypervisor_dir, args.signing_key)
        if not signing_key.is_file():
            raise SystemExit(f"missing signing key: {signing_key}")
        signature_path = (
            resolve_user_path(hypervisor_dir, args.signature_output)
            if args.signature_output is not None
            else pathlib.Path(str(output_path) + ".sig")
        )
        sign_json(output_path, signature_path, signing_key)
        sealed["signature_path"] = str(signature_path)
        output_path.write_text(json.dumps(sealed, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
