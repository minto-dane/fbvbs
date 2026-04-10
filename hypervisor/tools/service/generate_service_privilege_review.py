#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib

from generate_operator_tooling_compatibility_matrix import collect_defines, resolve_repo_root


TOOL_VERSION = 1
REVIEW_SCHEMA_VERSION = 1

SERVICE_KIND_BASELINES = {
    "SERVICE_KIND_KCI": {
        "role_name": "kci-runtime",
        "description": "Kernel control interface service runtime.",
        "capabilities": ("FBVBS_CAP_KCI_ACCESS",),
    },
    "SERVICE_KIND_KSI": {
        "role_name": "ksi-credential",
        "description": "Credential and identity service plane role.",
        "capabilities": ("FBVBS_CAP_KSI_ACCESS",),
    },
    "SERVICE_KIND_IKS": {
        "role_name": "iks-identity",
        "description": "Identity/key mediation service plane role.",
        "capabilities": ("FBVBS_CAP_IKS_ACCESS",),
    },
    "SERVICE_KIND_SKS": {
        "role_name": "sks-secret-key",
        "description": "Secret/key custody service plane role.",
        "capabilities": ("FBVBS_CAP_SKS_ACCESS",),
    },
    "SERVICE_KIND_UVS": {
        "role_name": "uvs-attestation",
        "description": "Attestation and verification service plane role.",
        "capabilities": ("FBVBS_CAP_UVS_ACCESS",),
    },
    "SERVICE_KIND_OCS": {
        "role_name": "ocs-console",
        "description": "Operator console transport service role.",
        "capabilities": ("FBVBS_CAP_OCS_ACCESS",),
    },
}


def load_symbols(script_path: pathlib.Path) -> dict[str, int]:
    repo_root = resolve_repo_root(script_path)
    return collect_defines(repo_root / "hypervisor" / "include" / "fbvbs_abi.h")


def capability_entry(symbols: dict[str, int], macro: str) -> dict[str, object]:
    value = int(symbols[macro])
    return {"name": macro, "value": value, "hex": f"0x{value:016X}"}


def build_payload(script_path: pathlib.Path) -> dict[str, object]:
    symbols = load_symbols(script_path)
    service_rows = []
    for service_kind_macro, baseline in SERVICE_KIND_BASELINES.items():
        cap_entries = [capability_entry(symbols, macro) for macro in baseline["capabilities"]]
        minimal_mask = 0
        for entry in cap_entries:
            minimal_mask |= int(entry["value"])
        service_rows.append(
            {
                "service_kind": {
                    "name": service_kind_macro,
                    "value": int(symbols[service_kind_macro]),
                },
                "role_name": baseline["role_name"],
                "description": baseline["description"],
                "required_capabilities": cap_entries,
                "minimal_capability_mask": {
                    "value": minimal_mask,
                    "hex": f"0x{minimal_mask:016X}",
                },
            }
        )
    return {
        "tool": {
            "name": "generate_service_privilege_review.py",
            "version": TOOL_VERSION,
        },
        "review_schema_version": REVIEW_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "service_roles": service_rows,
    }


def render_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# Service Privilege Review",
        "",
        f"- schema version: `{payload['review_schema_version']}`",
        "",
        "| Service Kind | Role | Required Capabilities | Minimal Mask |",
        "| --- | --- | --- | --- |",
    ]
    for row in payload["service_roles"]:
        lines.append(
            f"| `{row['service_kind']['name']}` | `{row['role_name']}` | "
            f"`{','.join(entry['name'] for entry in row['required_capabilities'])}` | "
            f"`{row['minimal_capability_mask']['hex']}` |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate standalone service privilege review artifacts."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write review artifacts")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = build_payload(script_path)

    json_path = output_dir / "service-privilege-review.json"
    md_path = output_dir / "service-privilege-review.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
