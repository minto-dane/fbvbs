from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .generate import generate_outputs
from .parser import parse_spec_document
from .validate import validate_spec


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="FBVBS executable-spec toolkit")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command in ("summary", "validate"):
        sub = subparsers.add_parser(command)
        sub.add_argument("--source", required=True, help="Path to fbvbs-design.md")

    generate = subparsers.add_parser("generate")
    generate.add_argument("--source", required=True, help="Path to fbvbs-design.md")
    generate.add_argument("--output", required=True, help="Output directory for generated artifacts")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate":
        spec = generate_outputs(args.source, args.output)
        print(
            json.dumps(
                {
                    "status": "ok",
                    "requirements": len(spec.requirements),
                    "hypercalls": len(spec.hypercalls),
                    "output": args.output,
                },
                ensure_ascii=False,
            )
        )
        return 0

    spec = parse_spec_document(args.source)
    errors = validate_spec(spec)

    if args.command == "summary":
        print(
            json.dumps(
                {
                    "source": spec.source_path,
                    "requirements": len(spec.requirements),
                    "requirement_subsections": len(spec.requirement_defaults),
                    "partition_transitions": len(spec.partition_transitions),
                    "protected_structures": len(spec.protected_structures),
                    "roadmap_phases": len(spec.roadmap_phases),
                    "hypercalls": len(spec.hypercalls),
                    "layouts": len(spec.layouts),
                    "validation_errors": len(errors),
                },
                ensure_ascii=False,
            )
        )
        return 0

    if errors:
        for error in errors:
            print(error)
        return 1

    print(
        json.dumps(
            {
                "status": "ok",
                "requirements": len(spec.requirements),
                "hypercalls": len(spec.hypercalls),
                "layouts": len(spec.layouts),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
