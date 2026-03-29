#!/usr/bin/env python3

import argparse
import datetime
import json
import os
import pathlib
import platform
import shutil
import subprocess


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def command_output(argv: list[str]) -> str | None:
    try:
        return subprocess.check_output(argv, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def git_dirty(repo_root: pathlib.Path) -> bool | None:
    try:
        subprocess.check_call(
            ["git", "diff", "--quiet", "--ignore-submodules", "HEAD", "--"],
            cwd=repo_root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return False
    except subprocess.CalledProcessError:
        return True
    except OSError:
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate retained-C release provenance metadata.")
    parser.add_argument("--build-dir", default="build", help="Path to the hypervisor build directory")
    parser.add_argument("--output", required=True, help="JSON output path")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parent
    repo_root = hypervisor_dir.parent
    build_dir = resolve_user_path(hypervisor_dir, args.build_dir)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    build_dir.mkdir(parents=True, exist_ok=True)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cc = os.environ.get("CC", "gcc")
    compiler = command_output([cc, "--version"])
    if compiler is not None:
        compiler = compiler.splitlines()[0]
    elif shutil.which(cc) is None:
        compiler = None

    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_date_epoch is not None:
        try:
            generated = datetime.datetime.fromtimestamp(
                int(source_date_epoch),
                tz=datetime.timezone.utc,
            ).isoformat()
        except ValueError:
            generated = datetime.datetime.now(datetime.timezone.utc).isoformat()
    else:
        generated = datetime.datetime.now(datetime.timezone.utc).isoformat()

    data = {
        "generated_utc": generated,
        "release_boundary": "standalone-retained-c-microhypervisor",
        "repository_root": str(repo_root.resolve()),
        "hypervisor_directory": str(hypervisor_dir.resolve()),
        "build_directory": str(build_dir.resolve()),
        "git": {
            "head": command_output(["git", "rev-parse", "HEAD"]),
            "describe": command_output(["git", "describe", "--always", "--dirty", "--tags"]),
            "dirty_worktree": git_dirty(repo_root),
            "branch": os.environ.get("GITHUB_REF_NAME") or command_output(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
        },
        "build_environment": {
            "compiler": compiler,
            "python": platform.python_version(),
            "machine": platform.machine(),
            "system": platform.system(),
            "release": platform.release(),
            "source_date_epoch": source_date_epoch,
        },
        "ci": {
            "github_actions": os.environ.get("GITHUB_ACTIONS") == "true",
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "sha": os.environ.get("GITHUB_SHA"),
            "ref": os.environ.get("GITHUB_REF"),
        },
        "signing": {
            "signed": False,
            "signing_material_embedded": False,
            "operator_action_required": True,
            "note": (
                "Repository-local provenance is unsigned. Producer-facing release "
                "requires external signing and key-management controls before publication."
            ),
        },
    }

    output_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
