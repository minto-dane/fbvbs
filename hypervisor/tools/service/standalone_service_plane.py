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
SERVICE_POLICY_SCHEMA_VERSION = 1
SERVICE_IDENTITY_ATTESTATION_SCHEMA_VERSION = 1
SERVICE_LIFECYCLE_LEDGER_SCHEMA_VERSION = 1
SERVICE_API_SURFACE_SCHEMA_VERSION = 1

SERVICE_PROFILE_CATALOG = {
    "storage-control": {
        "display_name": "Storage Control",
        "description": "Provisioning and lifecycle control for pools and vdisks.",
        "service_kind_choices": ("SERVICE_KIND_KCI",),
        "required_capabilities": ("FBVBS_CAP_KCI_ACCESS", "FBVBS_CAP_STORAGE_MANAGE"),
        "allowed_objects": ("storage-pool", "storage-vdisk", "storage-qos-policy"),
        "allowed_peer_profiles": ("audit-collection", "diagnostics"),
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
        "containment": {
            "max_blast_radius": "storage-plane-only",
            "auto_revoke_capabilities": ("FBVBS_CAP_STORAGE_MANAGE",),
            "quarantine_action": "freeze storage mutations and rotate service credentials",
        },
    },
    "audit-collection": {
        "display_name": "Audit Collection",
        "description": "Collection and forwarding of audit evidence only.",
        "service_kind_choices": ("SERVICE_KIND_KCI",),
        "required_capabilities": ("FBVBS_CAP_KCI_ACCESS", "FBVBS_CAP_AUDIT_DIAG"),
        "allowed_objects": ("audit-stream", "sealed-timeline", "evidence-pack-manifest"),
        "allowed_peer_profiles": ("diagnostics", "operator-console"),
        "allowed_calls": (
            "FBVBS_CALL_DIAG_GET_INVENTORY",
            "FBVBS_CALL_DIAG_GET_PARTITION_LIST",
            "FBVBS_CALL_DIAG_GET_FAULT_RECORD",
            "FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY",
        ),
        "containment": {
            "max_blast_radius": "audit-channel-only",
            "auto_revoke_capabilities": ("FBVBS_CAP_AUDIT_DIAG",),
            "quarantine_action": "stop export and preserve local append-only evidence",
        },
    },
    "attestation": {
        "display_name": "Attestation",
        "description": "Measurement verification and attestation material issuance.",
        "service_kind_choices": ("SERVICE_KIND_UVS",),
        "required_capabilities": ("FBVBS_CAP_UVS_ACCESS", "FBVBS_CAP_AUDIT_DIAG"),
        "allowed_objects": ("measurement", "attestation-report", "measurement-policy"),
        "allowed_peer_profiles": ("secret-key", "diagnostics"),
        "allowed_calls": (
            "FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES",
            "FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION",
            "FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY",
        ),
        "containment": {
            "max_blast_radius": "attestation-plane-only",
            "auto_revoke_capabilities": ("FBVBS_CAP_UVS_ACCESS",),
            "quarantine_action": "invalidate fresh reports and require new verifier session",
        },
    },
    "secret-key": {
        "display_name": "Secret/Key Custody",
        "description": "Custody for wrapped secrets and key material only.",
        "service_kind_choices": ("SERVICE_KIND_SKS",),
        "required_capabilities": ("FBVBS_CAP_SKS_ACCESS",),
        "allowed_objects": ("secret-envelope", "key-slot", "sealed-secret-log"),
        "allowed_peer_profiles": ("attestation",),
        "allowed_calls": (),
        "containment": {
            "max_blast_radius": "key-custody-only",
            "auto_revoke_capabilities": ("FBVBS_CAP_SKS_ACCESS",),
            "quarantine_action": "revoke active unwrap sessions and rotate custody epoch",
        },
    },
    "diagnostics": {
        "display_name": "Diagnostics",
        "description": "Read-only platform diagnostics and inventory review.",
        "service_kind_choices": ("SERVICE_KIND_KCI",),
        "required_capabilities": ("FBVBS_CAP_KCI_ACCESS", "FBVBS_CAP_AUDIT_DIAG"),
        "allowed_objects": ("partition-status", "fault-record", "schema-registry", "inventory"),
        "allowed_peer_profiles": ("audit-collection", "operator-console", "attestation"),
        "allowed_calls": (
            "FBVBS_CALL_DIAG_GET_PARTITION_LIST",
            "FBVBS_CALL_DIAG_GET_REASON_GUIDANCE",
            "FBVBS_CALL_DIAG_GET_INVENTORY",
            "FBVBS_CALL_DIAG_GET_FAULT_RECORD",
            "FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY",
            "FBVBS_CALL_DIAG_GET_SCALING_LIMITS",
        ),
        "containment": {
            "max_blast_radius": "diagnostic-plane-only",
            "auto_revoke_capabilities": ("FBVBS_CAP_AUDIT_DIAG",),
            "quarantine_action": "drop elevated sessions and preserve readonly diagnostics only",
        },
    },
    "operator-console": {
        "display_name": "Operator Console",
        "description": "Standalone OCS transport and presentation session ownership.",
        "service_kind_choices": ("SERVICE_KIND_OCS",),
        "required_capabilities": ("FBVBS_CAP_OCS_ACCESS", "FBVBS_CAP_AUDIT_DIAG"),
        "allowed_objects": ("ocs-session", "console-panel", "severity-summary"),
        "allowed_peer_profiles": ("diagnostics", "audit-collection"),
        "allowed_calls": (
            "FBVBS_CALL_OCS_VCD_ATTACH",
            "FBVBS_CALL_OCS_VCD_STATUS",
            "FBVBS_CALL_DIAG_GET_PARTITION_LIST",
            "FBVBS_CALL_DIAG_GET_REASON_GUIDANCE",
            "FBVBS_CALL_DIAG_GET_INVENTORY",
            "FBVBS_CALL_DIAG_GET_FAULT_RECORD",
        ),
        "containment": {
            "max_blast_radius": "ocs-session-only",
            "auto_revoke_capabilities": ("FBVBS_CAP_OCS_ACCESS",),
            "quarantine_action": "expire active console owner binding and require reattach",
        },
    },
}

LIFECYCLE_EVENTS = {
    "boot": ("instantiate", "activate"),
    "rotate": ("credential-rotate",),
    "quiesce": ("quiesce",),
    "resume": ("resume",),
    "revoke": ("revoke", "quarantine"),
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


def parse_iso8601_utc(value: object, field_name: str) -> datetime.datetime:
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


def service_kind_entry(symbols: dict[str, int], macro: str) -> dict[str, object]:
    value = int(symbols[macro])
    return {"name": macro, "value": value}


def build_service_policy_payload(script_path: pathlib.Path) -> dict[str, object]:
    symbols = load_symbols(script_path)
    profiles = []
    for profile_name, profile in SERVICE_PROFILE_CATALOG.items():
        capability_entries = [
            capability_entry(symbols, macro) for macro in profile["required_capabilities"]
        ]
        capability_mask = 0
        for entry in capability_entries:
            capability_mask |= int(entry["value"])
        access_policy = {
            "allowed_objects": list(profile["allowed_objects"]),
            "default_break_glass_bypass_allowed": False,
            "default_write_scope": [
                name for name in profile["allowed_objects"] if name.endswith("policy") or name.endswith("session")
            ],
        }
        peer_policy = {
            "allowed_peer_profiles": list(profile["allowed_peer_profiles"]),
            "mutual_attestation_required": True,
        }
        profiles.append(
            {
                "service_profile": profile_name,
                "display_name": profile["display_name"],
                "description": profile["description"],
                "service_kind_choices": [
                    service_kind_entry(symbols, macro) for macro in profile["service_kind_choices"]
                ],
                "required_capabilities": capability_entries,
                "required_capability_mask": {
                    "value": capability_mask,
                    "hex": f"0x{capability_mask:016X}",
                },
                "access_policy": access_policy,
                "access_policy_sha384": sha384_bytes(canonical_json_bytes(access_policy)),
                "peer_policy": peer_policy,
                "peer_policy_sha384": sha384_bytes(canonical_json_bytes(peer_policy)),
                "allowed_calls": list(profile["allowed_calls"]),
                "compromise_containment": profile["containment"],
            }
        )
    return {
        "tool": {"name": "generate_service_plane_policy.py", "version": TOOL_VERSION},
        "service_policy_schema_version": SERVICE_POLICY_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "service_profiles": profiles,
    }


def service_profile_row(script_path: pathlib.Path, service_profile: str) -> dict[str, object]:
    payload = build_service_policy_payload(script_path)
    for row in payload["service_profiles"]:
        if row["service_profile"] == service_profile:
            return row
    raise ValueError(f"unknown service profile: {service_profile}")


def validate_service_identity_attestation_payload(
    payload: dict,
    script_path: pathlib.Path,
    *,
    allow_expired: bool = False,
    expected_service_profile: str | None = None,
    expected_session_correlation_id: str | None = None,
) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("service identity attestation must be a JSON object")
    expected_hash = str(payload.get("service_identity_attestation_sha384", ""))
    if not expected_hash:
        raise ValueError("service identity attestation must contain service_identity_attestation_sha384")
    recomputed = sha384_bytes(
        canonical_json_bytes(
            {k: v for k, v in payload.items() if k != "service_identity_attestation_sha384"}
        )
    )
    if recomputed != expected_hash:
        raise ValueError("service identity attestation hash mismatch")

    service_profile = str(payload.get("service_profile", ""))
    row = service_profile_row(script_path, service_profile)
    if expected_service_profile is not None and service_profile != expected_service_profile:
        raise ValueError("service_profile does not match expected profile")

    issued_utc = parse_iso8601_utc(payload.get("issued_utc"), "issued_utc")
    expires_utc = parse_iso8601_utc(payload.get("expires_utc"), "expires_utc")
    if expires_utc <= issued_utc:
        raise ValueError("expires_utc must be later than issued_utc")
    if not allow_expired and expires_utc < datetime.datetime.now(datetime.timezone.utc):
        raise ValueError("service identity attestation has expired")

    service_instance_id = str(payload.get("service_instance_id", ""))
    if not service_instance_id:
        raise ValueError("service_instance_id must be non-empty")
    session_correlation_id = str(payload.get("session_correlation_id", ""))
    if not session_correlation_id:
        raise ValueError("session_correlation_id must be non-empty")
    if (
        expected_session_correlation_id is not None
        and session_correlation_id != expected_session_correlation_id
    ):
        raise ValueError("session_correlation_id does not match expected session")

    declared_service_kind = payload.get("service_kind")
    allowed_service_kinds = row["service_kind_choices"]
    if allowed_service_kinds:
        if not isinstance(declared_service_kind, dict):
            raise ValueError("service_kind must be present for this service profile")
        if declared_service_kind not in allowed_service_kinds:
            raise ValueError("service_kind is not allowed for this service profile")

    capability_mask = payload.get("capability_mask", {})
    if not isinstance(capability_mask, dict):
        raise ValueError("capability_mask must be an object")
    if int(capability_mask.get("value", -1)) != int(row["required_capability_mask"]["value"]):
        raise ValueError("capability_mask does not match service profile baseline")
    if payload.get("required_capabilities") != row["required_capabilities"]:
        raise ValueError("required_capabilities do not match service profile baseline")
    if str(payload.get("access_policy_sha384", "")) != str(row["access_policy_sha384"]):
        raise ValueError("access_policy_sha384 does not match current service profile policy")
    if str(payload.get("peer_policy_sha384", "")) != str(row["peer_policy_sha384"]):
        raise ValueError("peer_policy_sha384 does not match current service peer policy")

    service_identity = payload.get("service_identity", {})
    if not isinstance(service_identity, dict):
        raise ValueError("service_identity must be an object")
    if not str(service_identity.get("image_digest_sha384", "")):
        raise ValueError("service_identity.image_digest_sha384 must be non-empty")
    if not str(service_identity.get("signer_identity", "")):
        raise ValueError("service_identity.signer_identity must be non-empty")

    return {
        "service_profile_row": row,
        "service_profile": service_profile,
        "service_instance_id": service_instance_id,
        "session_correlation_id": session_correlation_id,
    }


def validate_service_lifecycle_ledger_payload(
    payload: dict,
    script_path: pathlib.Path,
    *,
    expected_service_profile: str | None = None,
    expected_session_correlation_id: str | None = None,
) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("service lifecycle ledger must be a JSON object")
    service_profile = str(payload.get("service_profile", ""))
    if expected_service_profile is not None and service_profile != expected_service_profile:
        raise ValueError("service lifecycle ledger service_profile does not match expected profile")
    session_correlation_id = str(payload.get("session_correlation_id", ""))
    if (
        expected_session_correlation_id is not None
        and session_correlation_id != expected_session_correlation_id
    ):
        raise ValueError("service lifecycle ledger session_correlation_id does not match expected session")
    events = payload.get("events", [])
    if not isinstance(events, list) or not events:
        raise ValueError("service lifecycle ledger must contain events")
    previous_hash = "0" * 96
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError("service lifecycle event must be an object")
        if int(event.get("sequence", 0)) != index:
            raise ValueError("service lifecycle sequence must be contiguous")
        if str(event.get("previous_event_sha384", "")) != previous_hash:
            raise ValueError("service lifecycle previous_event_sha384 mismatch")
        event_hash = str(event.get("event_sha384", ""))
        if not event_hash:
            raise ValueError("service lifecycle event must contain event_sha384")
        recomputed = sha384_bytes(
            canonical_json_bytes({k: v for k, v in event.items() if k != "event_sha384"})
        )
        if recomputed != event_hash:
            raise ValueError("service lifecycle event hash mismatch")
        event_name = str(event.get("event", ""))
        if event_name not in LIFECYCLE_EVENTS:
            raise ValueError(f"unknown lifecycle event: {event_name}")
        previous_hash = event_hash
    if str(payload.get("latest_event_sha384", "")) != previous_hash:
        raise ValueError("service lifecycle ledger latest_event_sha384 mismatch")
    return {
        "service_profile": service_profile,
        "session_correlation_id": session_correlation_id,
        "event_count": len(events),
    }


def render_policy_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# Service Plane Policy",
        "",
        f"- schema version: `{payload['service_policy_schema_version']}`",
        "",
        "| Service Profile | Kind Choices | Required Capabilities | Allowed Calls |",
        "| --- | --- | --- | --- |",
    ]
    for row in payload["service_profiles"]:
        kind_choices = ",".join(entry["name"] for entry in row["service_kind_choices"]) or "-"
        caps = ",".join(entry["name"] for entry in row["required_capabilities"])
        calls = ",".join(row["allowed_calls"]) or "(out-of-band only)"
        lines.append(
            f"| `{row['service_profile']}` | `{kind_choices}` | `{caps}` | `{calls}` |"
        )
    lines.append("")
    return "\n".join(lines)


def render_api_surface_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# Service API Surface Minimization",
        "",
        f"- schema version: `{payload['api_surface_schema_version']}`",
        f"- noncompliant count: `{payload['noncompliant_count']}`",
        "",
        "| Service Profile | Allowed Calls | Observed Violations |",
        "| --- | --- | --- |",
    ]
    violations_by_profile = {}
    for finding in payload["findings"]:
        violations_by_profile.setdefault(finding["service_profile"], []).append(
            ",".join(finding["unexpected_calls"])
        )
    for row in payload["profiles"]:
        violations = "; ".join(violations_by_profile.get(row["service_profile"], [])) or "-"
        allowed_calls = ",".join(row["allowed_calls"]) or "(out-of-band only)"
        lines.append(
            f"| `{row['service_profile']}` | `{allowed_calls}` | `{violations}` |"
        )
    lines.append("")
    return "\n".join(lines)
