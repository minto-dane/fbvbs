#!/usr/bin/env python3

import argparse
import json
import pathlib

import standalone_storage_policy as storage_policy


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate standalone storage authorization artifacts."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write authorization artifacts")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = storage_policy.build_storage_authorization_payload(script_path)

    json_path = output_dir / "storage-authorization-model.json"
    md_path = output_dir / "storage-authorization-model.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(storage_policy.render_storage_authorization_markdown(payload), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
