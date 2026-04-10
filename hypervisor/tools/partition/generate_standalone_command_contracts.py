#!/usr/bin/env python3

import argparse
import json
import pathlib

import standalone_command_contracts as contracts


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate standalone command idempotency and transition contracts."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write contract artifacts")
    args = parser.parse_args()

    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = contracts.build_contract_payload(pathlib.Path(__file__).resolve())

    json_path = output_dir / "standalone-command-contracts.json"
    md_path = output_dir / "standalone-command-contracts.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(contracts.render_contracts_markdown(payload) + "\n", encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
