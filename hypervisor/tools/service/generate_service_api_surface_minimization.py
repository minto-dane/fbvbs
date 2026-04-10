#!/usr/bin/env python3

import argparse
import json
import pathlib

import standalone_service_plane as service_plane


TOOL_VERSION = 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate and optionally check standalone service API surface minimization."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write API surface artifacts")
    parser.add_argument("--observed", help="Optional observed service API usage JSON")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    hypervisor_dir = script_path.parent.parent
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    policy = service_plane.build_service_policy_payload(script_path)
    profiles = [
        {
            "service_profile": row["service_profile"],
            "allowed_calls": row["allowed_calls"],
            "required_capabilities": row["required_capabilities"],
        }
        for row in policy["service_profiles"]
    ]

    findings = []
    if args.observed is not None:
        observed_path = service_plane.resolve_user_path(hypervisor_dir, args.observed)
        observed_payload = service_plane.read_json(observed_path)
        services = observed_payload.get("services", [])
        if not isinstance(services, list):
            raise SystemExit("observed input must contain services array")
        by_profile = {row["service_profile"]: row for row in profiles}
        for row in services:
            if not isinstance(row, dict):
                continue
            service_profile = str(row.get("service_profile", ""))
            observed_calls = row.get("observed_calls", [])
            if service_profile not in by_profile or not isinstance(observed_calls, list):
                continue
            allowed_calls = set(by_profile[service_profile]["allowed_calls"])
            unexpected_calls = sorted(
                call for call in observed_calls if isinstance(call, str) and call not in allowed_calls
            )
            if unexpected_calls:
                findings.append(
                    {
                        "service_profile": service_profile,
                        "service_instance_id": row.get("service_instance_id"),
                        "unexpected_calls": unexpected_calls,
                    }
                )

    payload = {
        "tool": {"name": "generate_service_api_surface_minimization.py", "version": TOOL_VERSION},
        "api_surface_schema_version": service_plane.SERVICE_API_SURFACE_SCHEMA_VERSION,
        "profiles": profiles,
        "noncompliant_count": len(findings),
        "findings": findings,
    }
    json_path = output_dir / "service-api-surface-minimization.json"
    md_path = output_dir / "service-api-surface-minimization.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(service_plane.render_api_surface_markdown(payload), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
