#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib

import standalone_operator_security as security


TOOL_VERSION = 1
POLICY_SCHEMA_VERSION = 1


def build_payload(script_path: pathlib.Path) -> dict[str, object]:
    return {
        "tool": {
            "name": "generate_standalone_operator_privilege_model.py",
            "version": TOOL_VERSION,
        },
        "policy_schema_version": POLICY_SCHEMA_VERSION,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "roles": [
            {"name": name, **details}
            for name, details in sorted(security.ROLE_CATALOG.items())
        ],
        "host_callsite_allowlist": security.host_callsite_table(script_path),
        "rows": security.build_privilege_rows(script_path),
    }


def render_markdown(payload: dict[str, object]) -> str:
    lines = [
        "# Standalone Operator Privilege Model",
        "",
        f"- schema version: `{payload['policy_schema_version']}`",
        "",
        "## Roles",
        "",
    ]
    for role in payload["roles"]:
        lines.append(
            f"- `{role['name']}`: {role['description']} "
            f"(domains: `{','.join(role['domains'])}`)"
        )
    lines.extend(
        [
            "",
            "## Command Authorization",
            "",
            "| Call | Domain/Action | Allowed Roles | Origin Attestation | Break-Glass |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for row in payload["rows"]:
        auth = row["authorization"]
        lines.append(
            f"| `{row['call']['name']}` | `{auth['domain']}/{auth['action']}` | "
            f"`{','.join(auth['allowed_roles'])}` | "
            f"`{'required' if auth['requires_origin_attestation'] else 'optional'}` | "
            f"`{'separate-audit' if auth['separate_break_glass_audit'] else ('eligible' if auth['break_glass_eligible'] else 'not-eligible')}` |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate standalone operator privilege-separation policy artifacts."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write privilege model artifacts")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = build_payload(script_path)

    json_path = output_dir / "standalone-operator-privilege-model.json"
    md_path = output_dir / "standalone-operator-privilege-model.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(payload), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
