#!/usr/bin/env python3

import datetime
import json
import pathlib
from dataclasses import dataclass

from generate_operator_tooling_compatibility_matrix import (
    collect_defines,
    resolve_repo_root,
)


CONTRACTS_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class CommandContract:
    call_macro: str
    operation: str
    auth_domain: str
    auth_action: str
    operator_roles: tuple[str, ...]
    idempotency_class: str
    repeat_status_macro: str
    safe_replay: bool
    notes: tuple[str, ...]
    allowed_state_macros: tuple[str, ...] = ()
    approval_required: bool = False
    requires_origin_attestation: bool = True
    break_glass_eligible: bool = False
    separate_break_glass_audit: bool = False


STATE_NAME_BY_MACRO = {
    "FBVBS_PARTITION_STATE_CREATED": "CREATED",
    "FBVBS_PARTITION_STATE_MEASURED": "MEASURED",
    "FBVBS_PARTITION_STATE_LOADED": "LOADED",
    "FBVBS_PARTITION_STATE_RUNNABLE": "RUNNABLE",
    "FBVBS_PARTITION_STATE_RUNNING": "RUNNING",
    "FBVBS_PARTITION_STATE_QUIESCED": "QUIESCED",
    "FBVBS_PARTITION_STATE_FAULTED": "FAULTED",
    "FBVBS_PARTITION_STATE_DESTROYED": "DESTROYED",
}
STATE_NAME_BY_VALUE = {
    1: "CREATED",
    2: "MEASURED",
    3: "LOADED",
    4: "RUNNABLE",
    5: "RUNNING",
    6: "QUIESCED",
    7: "FAULTED",
    8: "DESTROYED",
}

HEALTH_NAME_BY_VALUE = {
    0: "HEALTHY",
    1: "DEGRADED",
    2: "QUARANTINED",
    3: "RECOVERY",
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


def load_symbols(script_path: pathlib.Path) -> dict[str, int]:
    repo_root = resolve_repo_root(script_path)
    header_path = repo_root / "hypervisor" / "include" / "fbvbs_abi.h"
    return collect_defines(header_path)


def build_contracts() -> list[CommandContract]:
    return [
        CommandContract(
            call_macro="FBVBS_CALL_PARTITION_GET_STATUS",
            operation="partition-get-status",
            auth_domain="partition",
            auth_action="read-status",
            operator_roles=("observer", "incident-responder"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("same visible output is returned as long as partition state does not change",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_PARTITION_QUIESCE",
            operation="partition-quiesce",
            auth_domain="partition",
            auth_action="quiesce",
            operator_roles=("incident-responder",),
            idempotency_class="single-transition",
            repeat_status_macro="INVALID_STATE",
            safe_replay=False,
            allowed_state_macros=(
                "FBVBS_PARTITION_STATE_RUNNABLE",
                "FBVBS_PARTITION_STATE_RUNNING",
            ),
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=("repeat after success fails because the partition is already QUIESCED",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_PARTITION_RESUME",
            operation="partition-resume",
            auth_domain="partition",
            auth_action="resume",
            operator_roles=("incident-responder",),
            idempotency_class="single-transition",
            repeat_status_macro="INVALID_STATE",
            safe_replay=False,
            allowed_state_macros=("FBVBS_PARTITION_STATE_QUIESCED",),
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=("repeat after success fails because the partition is RUNNABLE again",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_PARTITION_RECOVER",
            operation="partition-recover",
            auth_domain="partition",
            auth_action="recover",
            operator_roles=("incident-responder",),
            idempotency_class="single-transition",
            repeat_status_macro="INVALID_STATE",
            safe_replay=False,
            allowed_state_macros=("FBVBS_PARTITION_STATE_FAULTED",),
            approval_required=True,
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=(
                "requires recovery approval artifact bound to session correlation before transition",
                "repeat after success fails because the partition has already left FAULTED",
            ),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_DIAG_GET_PARTITION_LIST",
            operation="diag-get-partition-list",
            auth_domain="diagnostic",
            auth_action="read-partition-list",
            operator_roles=("observer", "incident-responder", "capacity-admin", "storage-admin", "ocs-operator"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("diagnostic list queries are pure reads over current state",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_DIAG_GET_REASON_GUIDANCE",
            operation="diag-get-reason-guidance",
            auth_domain="diagnostic",
            auth_action="read-guidance",
            operator_roles=("observer", "incident-responder", "capacity-admin", "storage-admin", "ocs-operator"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("guidance lookup is deterministic for a fixed input tuple",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_DIAG_GET_INVENTORY",
            operation="diag-get-inventory",
            auth_domain="diagnostic",
            auth_action="read-inventory",
            operator_roles=("observer", "incident-responder", "capacity-admin", "storage-admin", "ocs-operator"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("inventory queries are read-only snapshots",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_DIAG_GET_FAULT_RECORD",
            operation="diag-get-fault-record",
            auth_domain="diagnostic",
            auth_action="read-fault-record",
            operator_roles=("observer", "incident-responder", "capacity-admin", "storage-admin", "ocs-operator"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("fault record queries are read-only snapshots",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY",
            operation="diag-get-schema-registry",
            auth_domain="diagnostic",
            auth_action="read-schema-registry",
            operator_roles=("observer", "incident-responder", "capacity-admin", "storage-admin", "ocs-operator"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("schema registry is a compatibility read and carries no mutation",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION",
            operation="diag-negotiate-command-version",
            auth_domain="diagnostic",
            auth_action="negotiate-command-version",
            operator_roles=("observer", "incident-responder", "capacity-admin", "storage-admin", "ocs-operator"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("version negotiation is a deterministic read over command metadata",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES",
            operation="diag-negotiate-guest-features",
            auth_domain="diagnostic",
            auth_action="negotiate-guest-features",
            operator_roles=("observer", "incident-responder", "capacity-admin", "storage-admin", "ocs-operator"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("guest feature negotiation is a deterministic read over profile and runtime caps",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_DIAG_GET_SCALING_LIMITS",
            operation="diag-get-scaling-limits",
            auth_domain="scaling",
            auth_action="read-scaling-limits",
            operator_roles=("observer", "capacity-admin"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("scaling limits reads are snapshots of current runtime policy",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_DIAG_SET_SCALING_LIMITS",
            operation="diag-set-scaling-limits",
            auth_domain="scaling",
            auth_action="set-scaling-limits",
            operator_roles=("capacity-admin",),
            idempotency_class="state-convergent",
            repeat_status_macro="OK",
            safe_replay=True,
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=("repeating the same limit update converges to the same runtime configuration",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_OCS_VCD_ATTACH",
            operation="ocs-vcd-attach",
            auth_domain="ocs",
            auth_action="attach-vcd",
            operator_roles=("ocs-operator",),
            idempotency_class="owner-bind",
            repeat_status_macro="ALREADY_EXISTS",
            safe_replay=False,
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=("repeating an already successful attach returns ALREADY_EXISTS instead of mutating again",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_OCS_VCD_STATUS",
            operation="ocs-vcd-status",
            auth_domain="ocs",
            auth_action="read-vcd-status",
            operator_roles=("observer", "ocs-operator"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("status queries are snapshots of current VCD ownership",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_STORAGE_CREATE_POOL",
            operation="storage-create-pool",
            auth_domain="storage",
            auth_action="create-pool",
            operator_roles=("storage-admin",),
            idempotency_class="allocate-new-object",
            repeat_status_macro="OK",
            safe_replay=False,
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=("repeating the same request allocates another pool with a new identifier",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_STORAGE_GET_POOL_STATUS",
            operation="storage-get-pool-status",
            auth_domain="storage",
            auth_action="read-pool-status",
            operator_roles=("observer", "storage-admin"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("pool status queries are read-only snapshots",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_STORAGE_DESTROY_POOL",
            operation="storage-destroy-pool",
            auth_domain="storage",
            auth_action="destroy-pool",
            operator_roles=("storage-admin",),
            idempotency_class="single-transition",
            repeat_status_macro="NOT_FOUND",
            safe_replay=False,
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=(
                "requires confirmation artifact bound to session correlation before transition",
                "repeat after success fails because the pool has already been removed",
            ),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_STORAGE_CREATE_VDISK",
            operation="storage-create-vdisk",
            auth_domain="storage",
            auth_action="create-vdisk",
            operator_roles=("storage-admin",),
            idempotency_class="allocate-new-object",
            repeat_status_macro="OK",
            safe_replay=False,
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=("repeating the same request allocates another virtual disk with a new identifier",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_STORAGE_DESTROY_VDISK",
            operation="storage-destroy-vdisk",
            auth_domain="storage",
            auth_action="destroy-vdisk",
            operator_roles=("storage-admin",),
            idempotency_class="single-transition",
            repeat_status_macro="NOT_FOUND",
            safe_replay=False,
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=(
                "requires confirmation artifact bound to session correlation before transition",
                "repeat after success fails because the vdisk has already been removed",
            ),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_STORAGE_ATTACH_VDISK",
            operation="storage-attach-vdisk",
            auth_domain="storage",
            auth_action="attach-vdisk",
            operator_roles=("storage-admin",),
            idempotency_class="single-transition",
            repeat_status_macro="INVALID_STATE",
            safe_replay=False,
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=("repeat after success fails because the vdisk is already attached",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_STORAGE_DETACH_VDISK",
            operation="storage-detach-vdisk",
            auth_domain="storage",
            auth_action="detach-vdisk",
            operator_roles=("storage-admin",),
            idempotency_class="single-transition",
            repeat_status_macro="INVALID_STATE",
            safe_replay=False,
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=("repeat after success fails because the vdisk is already detached",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_STORAGE_GET_VDISK_STATUS",
            operation="storage-get-vdisk-status",
            auth_domain="storage",
            auth_action="read-vdisk-status",
            operator_roles=("observer", "storage-admin"),
            idempotency_class="read-only",
            repeat_status_macro="OK",
            safe_replay=True,
            notes=("virtual disk status queries are read-only snapshots",),
        ),
        CommandContract(
            call_macro="FBVBS_CALL_STORAGE_SET_VDISK_QOS",
            operation="storage-set-vdisk-qos",
            auth_domain="storage",
            auth_action="set-vdisk-qos",
            operator_roles=("storage-admin",),
            idempotency_class="state-convergent",
            repeat_status_macro="OK",
            safe_replay=True,
            break_glass_eligible=True,
            separate_break_glass_audit=True,
            notes=("repeating the same QoS update converges to the same vdisk policy",),
        ),
    ]


def encode_contract(contract: CommandContract, symbols: dict[str, int]) -> dict[str, object]:
    allowed_states = [
        {
            "name": STATE_NAME_BY_MACRO[macro],
            "value": int(symbols[macro]),
            "macro": macro,
        }
        for macro in contract.allowed_state_macros
    ]
    return {
        "call": {
            "name": contract.call_macro,
            "value": int(symbols[contract.call_macro]),
        },
        "operation": contract.operation,
        "authorization": {
            "domain": contract.auth_domain,
            "action": contract.auth_action,
            "allowed_roles": list(contract.operator_roles),
            "requires_origin_attestation": contract.requires_origin_attestation,
            "break_glass_eligible": contract.break_glass_eligible,
            "separate_break_glass_audit": contract.separate_break_glass_audit,
        },
        "idempotency_class": contract.idempotency_class,
        "safe_replay": contract.safe_replay,
        "repeat_status": {
            "name": contract.repeat_status_macro,
            "value": int(symbols[contract.repeat_status_macro]),
        },
        "approval_required": contract.approval_required,
        "allowed_states": allowed_states,
        "notes": list(contract.notes),
    }


def render_contracts_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# Standalone Command Contracts",
        "",
        f"- schema version: `{payload['contracts_schema_version']}`",
        "",
        "| Call | Domain/Action | Roles | Idempotency | Repeat Status | Safe Replay |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in payload["contracts"]:
        lines.append(
            f"| `{row['call']['name']}` | "
            f"`{row['authorization']['domain']}/{row['authorization']['action']}` | "
            f"`{','.join(row['authorization']['allowed_roles'])}` | "
            f"`{row['idempotency_class']}` | "
            f"`{row['repeat_status']['name']}` | "
            f"`{'yes' if row['safe_replay'] else 'no'}` |"
        )
    lines.append("")
    return "\n".join(lines)


def build_contract_payload(script_path: pathlib.Path) -> dict[str, object]:
    symbols = load_symbols(script_path)
    return {
        "tool": {
            "name": "generate_standalone_command_contracts.py",
            "version": 1,
        },
        "contracts_schema_version": CONTRACTS_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "contracts": [
            encode_contract(contract, symbols)
            for contract in build_contracts()
        ],
    }


def partition_state_name(value: int) -> str:
    return STATE_NAME_BY_VALUE.get(value, f"UNKNOWN_{value}")


def health_state_name(value: int) -> str:
    return HEALTH_NAME_BY_VALUE.get(value, f"UNKNOWN_{value}")
