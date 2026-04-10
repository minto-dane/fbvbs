#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import pathlib


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha384_bytes(payload: bytes) -> str:
    digest = hashlib.sha384()
    digest.update(payload)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a standalone operator recovery approval artifact."
    )
    parser.add_argument("--input", required=True, help="Recovery approval JSON")
    parser.add_argument(
        "--allow-expired",
        action="store_true",
        help="Allow expired approvals during verification",
    )
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    input_path = resolve_user_path(hypervisor_dir, args.input)
    if not input_path.is_file():
        raise SystemExit(f"missing recovery approval: {input_path}")

    approval = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(approval, dict):
        raise SystemExit("recovery approval must be a JSON object")

    expected_hash = str(approval.get("approval_sha384", ""))
    if not expected_hash:
        raise SystemExit("recovery approval must contain approval_sha384")

    recomputed = sha384_bytes(
        canonical_json_bytes({k: v for k, v in approval.items() if k != "approval_sha384"})
    )
    if recomputed != expected_hash:
        raise SystemExit("recovery approval hash mismatch")

    if str(approval.get("action", "")) != "recover-approved":
        raise SystemExit("recovery approval action must be recover-approved")
    if not approval.get("session_correlation_id"):
        raise SystemExit("recovery approval must contain session_correlation_id")
    if not approval.get("latest_ack_sha384"):
        raise SystemExit("recovery approval must reference latest_ack_sha384")
    if not approval.get("timeline_root_chain_sha384"):
        raise SystemExit("recovery approval must reference timeline_root_chain_sha384")

    expires_raw = approval.get("expires_utc")
    if not isinstance(expires_raw, str):
        raise SystemExit("recovery approval must contain expires_utc")
    expires_utc = datetime.datetime.fromisoformat(expires_raw)
    if expires_utc.tzinfo is None:
        raise SystemExit("recovery approval expires_utc must be timezone-aware")
    if not args.allow_expired and expires_utc < datetime.datetime.now(datetime.timezone.utc):
        raise SystemExit("recovery approval has expired")

    print(f"Verified {input_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
