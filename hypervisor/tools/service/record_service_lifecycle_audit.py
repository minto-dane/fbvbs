#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib

import standalone_service_plane as service_plane


TOOL_VERSION = 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Append a service lifecycle event to the standalone service lifecycle audit ledger."
    )
    parser.add_argument("--attestation", required=True, help="Service identity attestation JSON")
    parser.add_argument("--event", required=True, choices=tuple(service_plane.LIFECYCLE_EVENTS.keys()), help="Lifecycle event name")
    parser.add_argument("--detail", required=True, help="Lifecycle event detail")
    parser.add_argument("--output", required=True, help="Output ledger JSON")
    parser.add_argument("--previous-ledger", help="Optional previous lifecycle ledger to append to")
    args = parser.parse_args()

    if args.detail not in service_plane.LIFECYCLE_EVENTS[args.event]:
        raise SystemExit("detail is not allowed for the selected lifecycle event")

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    attestation_path = service_plane.resolve_user_path(hypervisor_dir, args.attestation)
    output_path = service_plane.resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if not attestation_path.is_file():
        raise SystemExit(f"missing service identity attestation: {attestation_path}")

    attestation = service_plane.read_json(attestation_path)
    try:
        attestation_info = service_plane.validate_service_identity_attestation_payload(
            attestation,
            script_path,
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    if args.previous_ledger is not None:
        previous_path = service_plane.resolve_user_path(hypervisor_dir, args.previous_ledger)
        if not previous_path.is_file():
            raise SystemExit(f"missing previous service lifecycle ledger: {previous_path}")
        ledger = service_plane.read_json(previous_path)
        try:
            service_plane.validate_service_lifecycle_ledger_payload(
                ledger,
                script_path,
                expected_service_profile=attestation_info["service_profile"],
                expected_session_correlation_id=attestation_info["session_correlation_id"],
            )
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        events = list(ledger.get("events", []))
    else:
        events = []

    previous_hash = events[-1]["event_sha384"] if events else "0" * 96
    event = {
        "sequence": len(events) + 1,
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": args.event,
        "detail": args.detail,
        "service_profile": attestation_info["service_profile"],
        "service_instance_id": attestation_info["service_instance_id"],
        "partition_id": int(attestation.get("partition_id", 0)),
        "session_correlation_id": attestation_info["session_correlation_id"],
        "service_identity_attestation_sha384": attestation["service_identity_attestation_sha384"],
        "previous_event_sha384": previous_hash,
    }
    event["event_sha384"] = service_plane.sha384_bytes(
        service_plane.canonical_json_bytes({k: v for k, v in event.items() if k != "event_sha384"})
    )
    events.append(event)

    ledger = {
        "tool": {"name": "record_service_lifecycle_audit.py", "version": TOOL_VERSION},
        "service_lifecycle_ledger_schema_version": service_plane.SERVICE_LIFECYCLE_LEDGER_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "service_profile": attestation_info["service_profile"],
        "service_instance_id": attestation_info["service_instance_id"],
        "session_correlation_id": attestation_info["session_correlation_id"],
        "event_count": len(events),
        "latest_event_sha384": events[-1]["event_sha384"],
        "events": events,
    }
    output_path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
