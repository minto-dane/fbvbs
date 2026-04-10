#!/usr/bin/env python3

import argparse
import json
import pathlib

import standalone_storage_policy as storage_policy


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate standalone vdisk lifecycle model artifacts."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write lifecycle artifacts")
    args = parser.parse_args()

    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = storage_policy.build_vdisk_lifecycle_payload()

    json_path = output_dir / "vdisk-lifecycle-model.json"
    md_path = output_dir / "vdisk-lifecycle-model.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(storage_policy.render_vdisk_lifecycle_markdown(payload), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
