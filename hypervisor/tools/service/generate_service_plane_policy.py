#!/usr/bin/env python3

import argparse
import json
import pathlib

import standalone_service_plane as service_plane


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate standalone service plane least-privilege policy artifacts."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write policy artifacts")
    args = parser.parse_args()

    script_path = pathlib.Path(__file__).resolve()
    output_dir = pathlib.Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = service_plane.build_service_policy_payload(script_path)

    json_path = output_dir / "service-plane-policy.json"
    md_path = output_dir / "service-plane-policy.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(service_plane.render_policy_markdown(payload), encoding="utf-8")
    print(json.dumps({"json": str(json_path), "markdown": str(md_path)}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
