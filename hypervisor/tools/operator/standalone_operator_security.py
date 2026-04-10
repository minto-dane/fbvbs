#!/usr/bin/env python3

import datetime
import hashlib
import json
import pathlib

import standalone_command_contracts as command_contracts


ROLE_CATALOG = {
    "observer": {
        "display_name": "Observer",
        "description": "Read-only diagnostics and status review.",
        "domains": ["diagnostic", "partition", "scaling", "storage", "ocs"],
    },
    "incident-responder": {
        "display_name": "Incident Responder",
        "description": "Partition isolation, resume, and recovery actions during incidents.",
        "domains": ["diagnostic", "partition"],
    },
    "capacity-admin": {
        "display_name": "Capacity Admin",
        "description": "Scaling and workload control updates.",
        "domains": ["diagnostic", "scaling"],
    },
    "storage-admin": {
        "display_name": "Storage Admin",
        "description": "Storage object provisioning and health review.",
        "domains": ["diagnostic", "storage"],
    },
    "ocs-operator": {
        "display_name": "OCS Operator",
        "description": "Standalone console transport control and session ownership.",
        "domains": ["diagnostic", "ocs"],
    },
}

ALLOWED_HOST_CALLSITE_MACROS = (
    "FBVBS_HOST_CALLSITE_FBVBS_PRIMARY",
    "FBVBS_HOST_CALLSITE_FBVBS_SECONDARY",
    "FBVBS_HOST_CALLSITE_VMM_PRIMARY",
    "FBVBS_HOST_CALLSITE_VMM_SECONDARY",
)

TRANSPORT_TO_CONSOLES = {
    "ocs-vcd": ("mainframe-tui",),
    "host-cli": ("operator-shell", "batch-tool"),
    "automation": ("batch-tool", "service-runner"),
    "service": ("service-runner",),
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


def load_symbols(script_path: pathlib.Path) -> dict[str, int]:
    return command_contracts.load_symbols(script_path)


def host_callsite_table(script_path: pathlib.Path) -> list[dict[str, object]]:
    symbols = load_symbols(script_path)
    return [
        {"name": macro, "value": int(symbols[macro])}
        for macro in ALLOWED_HOST_CALLSITE_MACROS
    ]


def build_privilege_rows(script_path: pathlib.Path) -> list[dict[str, object]]:
    payload = command_contracts.build_contract_payload(script_path)
    rows = []
    for contract in payload["contracts"]:
        rows.append(
            {
                "call": contract["call"],
                "operation": contract["operation"],
                "authorization": contract["authorization"],
                "approval_required": contract["approval_required"],
                "safe_replay": contract["safe_replay"],
                "idempotency_class": contract["idempotency_class"],
            }
        )
    return rows


def privilege_row_by_call(script_path: pathlib.Path, call_name: str) -> dict[str, object]:
    for row in build_privilege_rows(script_path):
        if row["call"]["name"] == call_name:
            return row
    raise ValueError(f"unknown call name: {call_name}")


def validate_transport_console(transport: str, console: str) -> None:
    allowed = TRANSPORT_TO_CONSOLES.get(transport)
    if allowed is None:
        raise ValueError(f"unsupported origin transport: {transport}")
    if console not in allowed:
        raise ValueError(
            f"origin console {console} is not allowed for transport {transport}"
        )


def validate_host_callsite(script_path: pathlib.Path, name: str, value: int | None = None) -> dict[str, object]:
    for entry in host_callsite_table(script_path):
        if entry["name"] == name:
            if value is not None and int(entry["value"]) != int(value):
                raise ValueError("origin host callsite value does not match header constant")
            return entry
    raise ValueError(f"host callsite is not in the standalone allowlist: {name}")


def parse_iso8601_utc(value: object, field_name: str) -> datetime.datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be an ISO8601 string")
    parsed = datetime.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return parsed


def validate_origin_attestation_payload(
    payload: dict,
    script_path: pathlib.Path,
    *,
    allow_expired: bool = False,
    expected_call_name: str | None = None,
    expected_operator_role: str | None = None,
    expected_session_correlation_id: str | None = None,
    expected_timeline_root: str | None = None,
) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("origin attestation must be a JSON object")

    expected_hash = str(payload.get("origin_attestation_sha384", ""))
    if not expected_hash:
        raise ValueError("origin attestation must contain origin_attestation_sha384")
    recomputed = sha384_bytes(
        canonical_json_bytes({k: v for k, v in payload.items() if k != "origin_attestation_sha384"})
    )
    if recomputed != expected_hash:
        raise ValueError("origin attestation hash mismatch")

    call = payload.get("call", {})
    if not isinstance(call, dict):
        raise ValueError("origin attestation call must be an object")
    call_name = str(call.get("name", ""))
    row = privilege_row_by_call(script_path, call_name)
    if int(call.get("value", -1)) != int(row["call"]["value"]):
        raise ValueError("origin attestation call value does not match header constant")
    if expected_call_name is not None and call_name != expected_call_name:
        raise ValueError("origin attestation call does not match expected call")
    if str(payload.get("operation", "")) != str(row["operation"]):
        raise ValueError("origin attestation operation does not match command contract")
    if payload.get("authorization") != row["authorization"]:
        raise ValueError("origin attestation authorization block does not match command contract")
    if bool(payload.get("approval_required", False)) != bool(row["approval_required"]):
        raise ValueError("origin attestation approval_required does not match command contract")

    operator_id = str(payload.get("operator_id", ""))
    if not operator_id:
        raise ValueError("origin attestation must contain operator_id")
    operator_role = str(payload.get("operator_role", ""))
    if not operator_role:
        raise ValueError("origin attestation must contain operator_role")
    if expected_operator_role is not None and operator_role != expected_operator_role:
        raise ValueError("origin attestation operator_role does not match expected role")
    if operator_role not in ROLE_CATALOG:
        raise ValueError(f"unknown operator role: {operator_role}")
    allowed_roles = row["authorization"]["allowed_roles"]
    if operator_role not in allowed_roles:
        raise ValueError("operator role is not authorized for the requested call")

    session_correlation_id = str(payload.get("session_correlation_id", ""))
    if not session_correlation_id:
        raise ValueError("origin attestation must contain session_correlation_id")
    if (
        expected_session_correlation_id is not None
        and session_correlation_id != expected_session_correlation_id
    ):
        raise ValueError("origin attestation session_correlation_id does not match expected session")

    issued_utc = parse_iso8601_utc(payload.get("issued_utc"), "issued_utc")
    expires_utc = parse_iso8601_utc(payload.get("expires_utc"), "expires_utc")
    if expires_utc <= issued_utc:
        raise ValueError("origin attestation expires_utc must be later than issued_utc")
    if not allow_expired and expires_utc < datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("origin attestation has expired")

    origin = payload.get("origin", {})
    if not isinstance(origin, dict):
        raise ValueError("origin attestation origin must be an object")
    transport = str(origin.get("transport", ""))
    console = str(origin.get("console", ""))
    validate_transport_console(transport, console)
    host_callsite = origin.get("host_callsite", {})
    if not isinstance(host_callsite, dict):
        raise ValueError("origin attestation host_callsite must be an object")
    validate_host_callsite(
        script_path,
        str(host_callsite.get("name", "")),
        int(host_callsite.get("value", 0)),
    )

    command_context = payload.get("command_context", {})
    if not isinstance(command_context, dict):
        raise ValueError("origin attestation command_context must be an object")
    timeline_root = str(command_context.get("timeline_root_chain_sha384", ""))
    if expected_timeline_root is not None and timeline_root != expected_timeline_root:
        raise ValueError("origin attestation timeline_root_chain_sha384 does not match expected timeline root")
    partition_id = command_context.get("partition_id")
    if row["authorization"]["domain"] == "partition" and partition_id is None:
        raise ValueError("partition-scoped origin attestation requires partition_id")
    break_glass = bool(command_context.get("break_glass", False))
    justification = str(command_context.get("justification", ""))
    if break_glass:
        if not row["authorization"]["break_glass_eligible"]:
            raise ValueError("origin attestation requests break-glass for a command that is not eligible")
        if not row["authorization"]["separate_break_glass_audit"]:
            raise ValueError("origin attestation requests break-glass for a command without separate audit support")
        if not justification:
            raise ValueError("origin attestation break-glass mode requires justification")

    return {
        "call_name": call_name,
        "operator_role": operator_role,
        "session_correlation_id": session_correlation_id,
        "break_glass": break_glass,
        "authorization_row": row,
        "expires_utc": expires_utc,
    }


def validate_break_glass_ledger_payload(
    payload: dict,
    *,
    expected_timeline_root: str | None = None,
    expected_session_correlation_id: str | None = None,
) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("break-glass ledger must be a JSON object")
    if payload.get("audit_channel") != "operator-break-glass":
        raise ValueError("break-glass ledger audit_channel must be operator-break-glass")
    top_level_timeline_root = str(payload.get("timeline_root_chain_sha384", ""))
    if not top_level_timeline_root:
        raise ValueError("break-glass ledger must contain timeline_root_chain_sha384")
    if expected_timeline_root is not None and top_level_timeline_root != expected_timeline_root:
        raise ValueError("break-glass ledger timeline_root_chain_sha384 does not match expected root")
    events = payload.get("break_glass_events", [])
    if not isinstance(events, list):
        raise ValueError("break-glass ledger must contain break_glass_events array")
    if int(payload.get("break_glass_count", 0)) != len(events):
        raise ValueError("break-glass ledger break_glass_count does not match event count")
    latest = str(payload.get("latest_break_glass_sha384", ""))
    if events:
        if latest != str(events[-1].get("break_glass_sha384", "")):
            raise ValueError("break-glass ledger latest_break_glass_sha384 does not match last event")
    else:
        if latest:
            raise ValueError("break-glass ledger must not set latest_break_glass_sha384 when empty")

    previous_hash = "0" * 96
    session_ids: set[str] = set()
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError("break-glass ledger event must be an object")
        expected_hash = str(event.get("break_glass_sha384", ""))
        if not expected_hash:
            raise ValueError("break-glass ledger event is missing break_glass_sha384")
        recomputed = sha384_bytes(
            canonical_json_bytes({k: v for k, v in event.items() if k != "break_glass_sha384"})
        )
        if recomputed != expected_hash:
            raise ValueError("break-glass ledger event hash mismatch")
        if int(event.get("break_glass_sequence", 0)) != index:
            raise ValueError("break-glass ledger event sequence is not contiguous")
        if str(event.get("previous_break_glass_sha384", "")) != previous_hash:
            raise ValueError("break-glass ledger event previous hash does not match chain")
        if str(event.get("audit_event", "")) != "FBVBS_EVENT_OPERATOR_BREAK_GLASS":
            raise ValueError("break-glass ledger event audit_event must be FBVBS_EVENT_OPERATOR_BREAK_GLASS")
        if expected_timeline_root is not None and str(event.get("timeline_root_chain_sha384", "")) != expected_timeline_root:
            raise ValueError("break-glass ledger event timeline root does not match expected root")
        session_id = str(event.get("session_correlation_id", ""))
        if not session_id:
            raise ValueError("break-glass ledger event must contain session_correlation_id")
        session_ids.add(session_id)
        previous_hash = expected_hash

    top_level_session = str(payload.get("session_correlation_id", ""))
    if events and not top_level_session:
        raise ValueError("break-glass ledger must contain session_correlation_id")
    if top_level_session:
        session_ids.add(top_level_session)
    if len(session_ids) > 1:
        raise ValueError("break-glass ledger contains multiple session correlation ids")
    if expected_session_correlation_id is not None and top_level_session != expected_session_correlation_id:
        raise ValueError("break-glass ledger session_correlation_id does not match expected session")

    return {
        "event_count": len(events),
        "session_correlation_id": top_level_session or (events[-1]["session_correlation_id"] if events else None),
    }
