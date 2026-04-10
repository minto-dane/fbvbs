#!/usr/bin/env python3

import argparse
import json
import pathlib

import standalone_command_contracts as contracts


RULES_SCHEMA_VERSION = 1
CLASS_MAP = {
    "read-only": "deterministic-read",
    "state-convergent": "idempotent-mutation",
    "single-transition": "non-idempotent-mutation",
    "owner-bind": "non-idempotent-mutation",
    "allocate-new-object": "non-idempotent-mutation",
}
OUTCOME_MAP = {
    "OK": "same-outcome-on-repeat",
    "INVALID_STATE": "INVALID_STATE-after-success",
    "ALREADY_EXISTS": "ALREADY_EXISTS-after-success",
    "NOT_FOUND": "NOT_FOUND-after-success",
}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate standalone command idempotency rules."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write rule artifacts")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    symbols = contracts.load_symbols(script_path)
    rules = []
    for contract in contracts.build_contracts():
        encoded = contracts.encode_contract(contract, symbols)
        rules.append(
            {
                "call_macro": encoded["call"]["name"],
                "call_id": encoded["call"]["value"],
                "idempotency_class": CLASS_MAP[encoded["idempotency_class"]],
                "duplicate_outcome": OUTCOME_MAP[encoded["repeat_status"]["name"]],
                "safe_replay": bool(encoded["safe_replay"]),
                "notes": list(encoded["notes"]),
            }
        )

    payload = {
        "tool": {
            "name": "generate_standalone_command_idempotency_rules.py",
            "version": 1,
        },
        "rules_schema_version": RULES_SCHEMA_VERSION,
        "summary": {
            "row_count": len(rules),
        },
        "rules": rules,
    }

    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "standalone-command-idempotency-rules.json"
    md_path = output_dir / "standalone-command-idempotency-rules.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    lines = [
        "# Standalone Command Idempotency Rules",
        "",
        "| Call | Class | Duplicate Outcome | Safe Replay |",
        "| --- | --- | --- | --- |",
    ]
    for row in rules:
        lines.append(
            f"| `{row['call_macro']}` | `{row['idempotency_class']}` | "
            f"`{row['duplicate_outcome']}` | "
            f"`{'yes' if row['safe_replay'] else 'no'}` |"
        )
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
