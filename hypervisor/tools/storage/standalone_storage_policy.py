#!/usr/bin/env python3

import datetime
import hashlib
import json
import pathlib

from generate_operator_tooling_compatibility_matrix import (
    collect_defines,
    resolve_repo_root,
)


TOOL_VERSION = 1
STORAGE_AUTHORIZATION_SCHEMA_VERSION = 1
VDISK_LIFECYCLE_SCHEMA_VERSION = 1
STORAGE_AUDIT_CONSISTENCY_SCHEMA_VERSION = 1
DESTRUCTIVE_STORAGE_CONFIRMATION_SCHEMA_VERSION = 1
STORAGE_EVIDENCE_TRAIL_SCHEMA_VERSION = 1

ACTOR_POLICIES = {
    "host": {
        "description": "FreeBSD host control plane with full storage authority.",
        "allowed_calls": (
            "FBVBS_CALL_STORAGE_CREATE_POOL",
            "FBVBS_CALL_STORAGE_DESTROY_POOL",
            "FBVBS_CALL_STORAGE_CREATE_VDISK",
            "FBVBS_CALL_STORAGE_DESTROY_VDISK",
            "FBVBS_CALL_STORAGE_ATTACH_VDISK",
            "FBVBS_CALL_STORAGE_DETACH_VDISK",
            "FBVBS_CALL_STORAGE_GET_POOL_STATUS",
            "FBVBS_CALL_STORAGE_GET_VDISK_STATUS",
            "FBVBS_CALL_STORAGE_SET_VDISK_QOS",
        ),
        "required_capabilities": ("FBVBS_CAP_STORAGE_MANAGE",),
        "ownership_scope": "global",
        "delegation_allowed": False,
    },
    "service": {
        "description": "Dedicated storage control service operating within explicit service policy.",
        "allowed_calls": (
            "FBVBS_CALL_STORAGE_GET_POOL_STATUS",
            "FBVBS_CALL_STORAGE_GET_VDISK_STATUS",
            "FBVBS_CALL_STORAGE_ATTACH_VDISK",
            "FBVBS_CALL_STORAGE_DETACH_VDISK",
            "FBVBS_CALL_STORAGE_SET_VDISK_QOS",
        ),
        "required_capabilities": ("FBVBS_CAP_STORAGE_MANAGE",),
        "ownership_scope": "delegated-or-owned",
        "delegation_allowed": True,
    },
    "tenant": {
        "description": "Tenant owner restricted to owned vdisk status and attach/detach.",
        "allowed_calls": (
            "FBVBS_CALL_STORAGE_GET_VDISK_STATUS",
            "FBVBS_CALL_STORAGE_ATTACH_VDISK",
            "FBVBS_CALL_STORAGE_DETACH_VDISK",
        ),
        "required_capabilities": (),
        "ownership_scope": "owned-only",
        "delegation_allowed": False,
    },
}

VDISK_STATES = {
    "PROVISIONED": {
        "description": "Vdisk exists and is detached.",
        "attached": False,
        "destroy_allowed": True,
    },
    "ATTACHED": {
        "description": "Vdisk is attached to a VM partition.",
        "attached": True,
        "destroy_allowed": False,
    },
    "DETACH_PENDING": {
        "description": "Detach requested and awaiting final audit closure.",
        "attached": True,
        "destroy_allowed": False,
    },
    "RELEASE_PENDING": {
        "description": "Destroy confirmed and awaiting final teardown.",
        "attached": False,
        "destroy_allowed": True,
    },
    "QUARANTINED": {
        "description": "Corruption or safety policy violation blocks further attachment.",
        "attached": False,
        "destroy_allowed": True,
    },
    "DESTROYED": {
        "description": "Vdisk is no longer present in active inventory.",
        "attached": False,
        "destroy_allowed": False,
    },
}

VDISK_TRANSITIONS = (
    {"from": "PROVISIONED", "to": "ATTACHED", "operation": "attach-vdisk"},
    {"from": "ATTACHED", "to": "DETACH_PENDING", "operation": "detach-vdisk"},
    {"from": "DETACH_PENDING", "to": "PROVISIONED", "operation": "detach-audit-closed"},
    {"from": "PROVISIONED", "to": "RELEASE_PENDING", "operation": "destroy-confirmed"},
    {"from": "RELEASE_PENDING", "to": "DESTROYED", "operation": "destroy-vdisk"},
    {"from": "PROVISIONED", "to": "QUARANTINED", "operation": "corruption-detected"},
    {"from": "ATTACHED", "to": "QUARANTINED", "operation": "corruption-detected"},
    {"from": "DETACH_PENDING", "to": "QUARANTINED", "operation": "corruption-detected"},
)

STORAGE_OPERATION_TO_CALL = {
    "destroy-pool": "FBVBS_CALL_STORAGE_DESTROY_POOL",
    "destroy-vdisk": "FBVBS_CALL_STORAGE_DESTROY_VDISK",
}

STORAGE_AUDIT_OPERATIONS = {
    "FBVBS_STORAGE_AUDIT_OP_CREATE_POOL": "create-pool",
    "FBVBS_STORAGE_AUDIT_OP_DESTROY_POOL": "destroy-pool",
    "FBVBS_STORAGE_AUDIT_OP_CREATE_VDISK": "create-vdisk",
    "FBVBS_STORAGE_AUDIT_OP_DESTROY_VDISK": "destroy-vdisk",
    "FBVBS_STORAGE_AUDIT_OP_ATTACH_VDISK": "attach-vdisk",
    "FBVBS_STORAGE_AUDIT_OP_DETACH_VDISK": "detach-vdisk",
    "FBVBS_STORAGE_AUDIT_OP_SET_VDISK_QOS": "set-vdisk-qos",
    "FBVBS_STORAGE_AUDIT_OP_GET_POOL_STATUS": "get-pool-status",
    "FBVBS_STORAGE_AUDIT_OP_GET_VDISK_STATUS": "get-vdisk-status",
}


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def read_json(path: pathlib.Path) -> dict:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise SystemExit(f"JSON input must be an object: {path}")
    return payload


def canonical_json_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha384_bytes(payload: bytes) -> str:
    digest = hashlib.sha384()
    digest.update(payload)
    return digest.hexdigest()


def parse_iso8601_utc(value: object, field_name: str):
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be an ISO8601 string")
    parsed = datetime.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return parsed


def load_symbols(script_path: pathlib.Path) -> dict[str, int]:
    repo_root = resolve_repo_root(script_path)
    return collect_defines(repo_root / "hypervisor" / "include" / "fbvbs_abi.h")


def capability_entry(symbols: dict[str, int], macro: str) -> dict[str, object]:
    value = int(symbols[macro])
    return {"name": macro, "value": value, "hex": f"0x{value:016X}"}


def build_storage_authorization_payload(script_path: pathlib.Path) -> dict[str, object]:
    symbols = load_symbols(script_path)
    rows = []
    for actor_name, actor in ACTOR_POLICIES.items():
        capability_entries = [
            capability_entry(symbols, macro) for macro in actor["required_capabilities"]
        ]
        rows.append(
            {
                "actor": actor_name,
                "description": actor["description"],
                "allowed_calls": list(actor["allowed_calls"]),
                "required_capabilities": capability_entries,
                "ownership_scope": actor["ownership_scope"],
                "delegation_allowed": actor["delegation_allowed"],
            }
        )
    ownership_policy = {
        "owner_partition_id_authoritative": True,
        "delegation_scope": "attached_partition_only",
        "owner_change_requires_new_vdisk": True,
        "pool_granularity_must_hold": True,
    }
    return {
        "tool": {"name": "generate_storage_authorization_model.py", "version": TOOL_VERSION},
        "storage_authorization_schema_version": STORAGE_AUTHORIZATION_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "actors": rows,
        "ownership_policy": ownership_policy,
    }


def build_vdisk_lifecycle_payload() -> dict[str, object]:
    return {
        "tool": {"name": "generate_vdisk_lifecycle_model.py", "version": TOOL_VERSION},
        "vdisk_lifecycle_schema_version": VDISK_LIFECYCLE_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "states": [
            {"state": state, **details} for state, details in VDISK_STATES.items()
        ],
        "transitions": list(VDISK_TRANSITIONS),
    }


def infer_vdisk_state(vdisk: dict) -> str:
    if bool(vdisk.get("destroyed", False)):
        return "DESTROYED"
    if bool(vdisk.get("quarantined", False)):
        return "QUARANTINED"
    if bool(vdisk.get("release_pending", False)):
        return "RELEASE_PENDING"
    if bool(vdisk.get("detach_pending", False)):
        return "DETACH_PENDING"
    if int(vdisk.get("attached_partition_id", 0)) != 0 or bool(vdisk.get("attached", False)):
        return "ATTACHED"
    return "PROVISIONED"


def normalize_storage_audit_event(event: dict, symbols: dict[str, int]) -> dict[str, object]:
    operation = event.get("operation")
    operation_name = None
    if isinstance(operation, str):
        if operation in STORAGE_AUDIT_OPERATIONS:
            operation_name = STORAGE_AUDIT_OPERATIONS[operation]
    elif isinstance(operation, int):
        for macro, name in STORAGE_AUDIT_OPERATIONS.items():
            if int(symbols[macro]) == int(operation):
                operation_name = name
                break
    if operation_name is None:
        operation_name = str(operation)
    return {
        "target_id": int(event.get("target_id", 0)),
        "related_id": int(event.get("related_id", 0)),
        "requester_partition_id": int(event.get("requester_partition_id", 0)),
        "status": int(event.get("status", 0)),
        "operation_name": operation_name,
    }


def validate_destructive_confirmation_payload(
    payload: dict,
    *,
    allow_expired: bool = False,
    expected_operation: str | None = None,
    expected_session_correlation_id: str | None = None,
) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("destructive storage confirmation must be a JSON object")
    expected_hash = str(payload.get("storage_confirmation_sha384", ""))
    if not expected_hash:
        raise ValueError("storage confirmation must contain storage_confirmation_sha384")
    recomputed = sha384_bytes(
        canonical_json_bytes({k: v for k, v in payload.items() if k != "storage_confirmation_sha384"})
    )
    if recomputed != expected_hash:
        raise ValueError("storage confirmation hash mismatch")
    operation = str(payload.get("operation", ""))
    if operation not in STORAGE_OPERATION_TO_CALL:
        raise ValueError("storage confirmation operation is not supported")
    if expected_operation is not None and operation != expected_operation:
        raise ValueError("storage confirmation operation does not match expected operation")
    session_correlation_id = str(payload.get("session_correlation_id", ""))
    if not session_correlation_id:
        raise ValueError("storage confirmation must contain session_correlation_id")
    if (
        expected_session_correlation_id is not None
        and session_correlation_id != expected_session_correlation_id
    ):
        raise ValueError("storage confirmation session_correlation_id does not match expected session")
    issued_utc = parse_iso8601_utc(payload.get("issued_utc"), "issued_utc")
    expires_utc = parse_iso8601_utc(payload.get("expires_utc"), "expires_utc")
    if expires_utc <= issued_utc:
        raise ValueError("storage confirmation expires_utc must be later than issued_utc")
    if not allow_expired and expires_utc < datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("storage confirmation has expired")
    preconditions = payload.get("preconditions", {})
    if not isinstance(preconditions, dict):
        raise ValueError("storage confirmation preconditions must be an object")
    return {
        "operation": operation,
        "session_correlation_id": session_correlation_id,
        "target_kind": str(payload.get("target_kind", "")),
        "target_id": int(payload.get("target_id", 0)),
        "preconditions": preconditions,
    }


def render_storage_authorization_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# Storage Authorization Model",
        "",
        f"- schema version: `{payload['storage_authorization_schema_version']}`",
        "",
        "| Actor | Allowed Calls | Ownership Scope | Delegation |",
        "| --- | --- | --- | --- |",
    ]
    for row in payload["actors"]:
        lines.append(
            f"| `{row['actor']}` | `{','.join(row['allowed_calls'])}` | "
            f"`{row['ownership_scope']}` | "
            f"`{'yes' if row['delegation_allowed'] else 'no'}` |"
        )
    lines.append("")
    return "\n".join(lines)


def render_vdisk_lifecycle_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# Vdisk Lifecycle Model",
        "",
        f"- schema version: `{payload['vdisk_lifecycle_schema_version']}`",
        "",
        "| State | Attached | Destroy Allowed |",
        "| --- | --- | --- |",
    ]
    for row in payload["states"]:
        lines.append(
            f"| `{row['state']}` | "
            f"`{'yes' if row['attached'] else 'no'}` | "
            f"`{'yes' if row['destroy_allowed'] else 'no'}` |"
        )
    lines.append("")
    return "\n".join(lines)
