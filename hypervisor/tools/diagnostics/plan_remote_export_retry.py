#!/usr/bin/env python3

import argparse
import datetime
import json
import pathlib


TOOL_VERSION = 1
MANIFEST_SCHEMA_VERSION = 1


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Plan a fail-closed retry schedule for remote export of standalone evidence artifacts."
    )
    parser.add_argument("--archive", required=True, help="Archive planned for remote export")
    parser.add_argument("--destination", required=True, help="Logical remote destination identifier")
    parser.add_argument("--max-attempts", type=int, default=5, help="Maximum retry attempts")
    parser.add_argument("--initial-delay-seconds", type=int, default=30, help="Initial retry delay in seconds")
    parser.add_argument("--backoff-factor", type=int, default=2, help="Exponential backoff factor")
    parser.add_argument("--output", required=True, help="Retry manifest JSON")
    args = parser.parse_args()

    if args.max_attempts <= 0:
        raise SystemExit("max-attempts must be positive")
    if args.initial_delay_seconds <= 0:
        raise SystemExit("initial-delay-seconds must be positive")
    if args.backoff_factor < 1:
        raise SystemExit("backoff-factor must be at least 1")

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    archive_path = resolve_user_path(hypervisor_dir, args.archive)
    if not archive_path.is_file():
        raise SystemExit(f"missing archive: {archive_path}")
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    generated = datetime.datetime.now(datetime.timezone.utc)
    attempts = []
    delay = args.initial_delay_seconds
    next_time = generated
    for attempt in range(1, args.max_attempts + 1):
        next_time = next_time + datetime.timedelta(seconds=delay)
        attempts.append(
            {
                "attempt": attempt,
                "scheduled_utc": next_time.isoformat(),
                "delay_seconds": delay,
            }
        )
        delay *= args.backoff_factor

    manifest = {
        "tool": {"name": "plan_remote_export_retry.py", "version": TOOL_VERSION},
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_utc": generated.isoformat(),
        "archive_path": str(archive_path),
        "destination": args.destination,
        "max_attempts": args.max_attempts,
        "initial_delay_seconds": args.initial_delay_seconds,
        "backoff_factor": args.backoff_factor,
        "fail_closed": True,
        "retry_schedule": attempts,
    }
    output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
