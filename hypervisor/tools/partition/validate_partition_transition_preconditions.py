#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import json
import pathlib

import standalone_command_contracts as contracts


TOOL_VERSION = 1
VALIDATOR_SCHEMA_VERSION = 1
ACTION_TO_CALL = {
    "quiesce": "FBVBS_CALL_PARTITION_QUIESCE",
    "resume": "FBVBS_CALL_PARTITION_RESUME",
    "recover": "FBVBS_CALL_PARTITION_RECOVER",
}


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha384_bytes(payload: bytes) -> str:
    digest = hashlib.sha384()
    digest.update(payload)
    return digest.hexdigest()


def load_contract(call_macro: str) -> dict[str, object]:
    payload = contracts.build_contract_payload(pathlib.Path(__file__).resolve())
    for row in payload["contracts"]:
        if row["call"]["name"] == call_macro:
            return row
    raise SystemExit(f"missing command contract: {call_macro}")


def verify_recovery_approval(path: pathlib.Path, partition_id: int) -> dict[str, object]:
    approval = contracts.read_json(path)
    expected_hash = str(approval.get("approval_sha384", ""))
    if not expected_hash:
        raise ValueError("recovery approval must contain approval_sha384")
    recomputed = sha384_bytes(
        canonical_json_bytes({k: v for k, v in approval.items() if k != "approval_sha384"})
    )
    if recomputed != expected_hash:
        raise ValueError("recovery approval hash mismatch")
    if str(approval.get("action", "")) != "recover-approved":
        raise ValueError("recovery approval action must be recover-approved")
    if int(approval.get("partition_id", 0)) != partition_id:
        raise ValueError("recovery approval partition_id does not match validator target")

    expires_raw = approval.get("expires_utc")
    if not isinstance(expires_raw, str):
        raise ValueError("recovery approval must contain expires_utc")
    expires_utc = datetime.datetime.fromisoformat(expires_raw)
    if expires_utc.tzinfo is None:
        raise ValueError("recovery approval expires_utc must be timezone-aware")
    if expires_utc < datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("recovery approval has expired")
    return approval


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate partition transition preconditions before issuing standalone control-plane actions."
    )
    parser.add_argument("--partition-list", required=True, help="Structured partition list JSON")
    parser.add_argument("--action", required=True, choices=sorted(ACTION_TO_CALL), help="Transition action")
    parser.add_argument("--partition-id", required=True, type=int, help="Target partition identifier")
    parser.add_argument("--recovery-approval", help="Recovery approval JSON for recover action")
    parser.add_argument("--output", help="Validation result JSON")
    parser.add_argument("--output-dir", help="Directory to write a conventional result filename into")
    args = parser.parse_args()
    if bool(args.output) == bool(args.output_dir):
        raise SystemExit("specify exactly one of --output or --output-dir")

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    partition_list = contracts.read_json(contracts.resolve_user_path(hypervisor_dir, args.partition_list))
    if args.output:
        output_path = contracts.resolve_user_path(hypervisor_dir, args.output)
    else:
        output_dir = contracts.resolve_user_path(hypervisor_dir, args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"partition-transition-{args.action}-{args.partition_id}.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)

    contract = load_contract(ACTION_TO_CALL[args.action])
    entry = None
    for candidate in partition_list.get("entries", []):
        if isinstance(candidate, dict) and int(candidate.get("partition_id", -1)) == args.partition_id:
            entry = candidate
            break

    checks: list[dict[str, object]] = []
    allowed = True
    predicted_status = contract["repeat_status"]
    reason_codes: list[str] = []

    if entry is None:
        checks.append({"name": "partition-present", "passed": False, "detail": "partition missing from partition list"})
        allowed = False
        current_state_value = -1
        current_health_value = -1
        predicted_status = {"name": "NOT_FOUND", "value": 17}
        reason_codes.append("partition-not-found")
    else:
        checks.append({"name": "partition-present", "passed": True, "detail": "partition found"})
        current_state_value = int(entry.get("state", 0))
        current_health_value = int(entry.get("health_state", 0))

        allowed_values = {int(row["value"]) for row in contract["allowed_states"]}
        state_ok = current_state_value in allowed_values
        checks.append(
            {
                "name": "allowed-state",
                "passed": state_ok,
                "detail": f"state={contracts.partition_state_name(current_state_value)}",
            }
        )
        if not state_ok:
            allowed = False
            reason_codes.append("invalid-source-state")

    approval_summary = None
    if contract["approval_required"]:
        if not args.recovery_approval:
            checks.append({"name": "recovery-approval", "passed": False, "detail": "missing recovery approval"})
            allowed = False
            reason_codes.append("missing-recovery-approval")
        else:
            try:
                approval = verify_recovery_approval(
                    contracts.resolve_user_path(hypervisor_dir, args.recovery_approval),
                    args.partition_id,
                )
            except ValueError as exc:
                checks.append({"name": "recovery-approval", "passed": False, "detail": str(exc)})
                allowed = False
                reason_codes.append("invalid-recovery-approval")
            else:
                approval_summary = {
                    "operator_id": approval.get("operator_id"),
                    "expires_utc": approval.get("expires_utc"),
                }
                checks.append({"name": "recovery-approval", "passed": True, "detail": "approval verified"})

    if allowed:
        predicted_status = {"name": "OK", "value": 0}

    result = {
        "tool": {
            "name": "validate_partition_transition_preconditions.py",
            "version": TOOL_VERSION,
        },
        "validator_schema_version": VALIDATOR_SCHEMA_VERSION,
        "action": args.action,
        "partition_id": args.partition_id,
        "allowed": allowed,
        "current_state": {
            "value": current_state_value,
            "name": contracts.partition_state_name(current_state_value),
        },
        "current_health": {
            "value": current_health_value,
            "name": contracts.health_state_name(current_health_value),
        },
        "required_states": contract["allowed_states"],
        "approval_required": contract["approval_required"],
        "required_artifacts": ["recovery-approval"] if contract["approval_required"] else [],
        "approval_summary": approval_summary,
        "predicted_status": predicted_status,
        "reason_codes": reason_codes,
        "checks": checks,
    }
    payload = {
        **result,
        "result": result,
    }
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0 if allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
