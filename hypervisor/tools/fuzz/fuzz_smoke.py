#!/usr/bin/env python3

import argparse
import pathlib
import subprocess
import sys


TARGETS = {
    "fuzz_command_page": "command_page",
    "fuzz_manifest": "manifest",
    "fuzz_multiboot2": "multiboot2",
    "fuzz_iommu": "iommu",
    "fuzz_log_decoder": "log_decoder",
    "fuzz_partition_loader": "partition_loader",
}


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def load_hex_seed(path: pathlib.Path) -> bytes:
    chunks = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        chunks.append("".join(line.split()))
    hex_text = "".join(chunks)
    if not hex_text:
        raise ValueError(f"{path} is empty")
    return bytes.fromhex(hex_text)


def run_seed(binary: pathlib.Path, seed_path: pathlib.Path) -> tuple[bool, str]:
    data = load_hex_seed(seed_path)
    result = subprocess.run(
        [str(binary)],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    ok = result.returncode == 0
    summary = (
        f"{binary.name} seed={seed_path.name} bytes={len(data)} "
        f"status={'PASS' if ok else 'FAIL'} rc={result.returncode}"
    )
    return ok, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run repository-local fuzz smoke seeds.")
    parser.add_argument("--build-dir", default="build", help="Path to the hypervisor build directory")
    parser.add_argument("--output", required=True, help="Summary file to write")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    build_dir = resolve_user_path(hypervisor_dir, args.build_dir)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    corpus_root = hypervisor_dir / "fuzz" / "corpus"
    lines = ["FBVBS fuzz smoke", f"build_dir={build_dir}"]
    failed = False

    for binary_name, corpus_name in TARGETS.items():
        binary = build_dir / binary_name
        corpus_dir = corpus_root / corpus_name
        if not binary.is_file():
            lines.append(f"{binary_name} status=FAIL reason=missing-binary")
            failed = True
            continue
        if not corpus_dir.is_dir():
            lines.append(f"{binary_name} status=FAIL reason=missing-corpus")
            failed = True
            continue

        seed_paths = sorted(
            path for path in corpus_dir.iterdir()
            if path.is_file() and not path.name.startswith(".")
        )
        if not seed_paths:
            lines.append(f"{binary_name} status=FAIL reason=empty-corpus")
            failed = True
            continue

        for seed_path in seed_paths:
            try:
                ok, summary = run_seed(binary, seed_path)
            except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
                ok = False
                # Sanitize exception text to prevent injection into summary
                exc_text = str(exc)
                exc_text = exc_text.replace("\n", "\\n")
                exc_text = exc_text.replace("=", "%3D")
                # Collapse consecutive whitespace
                import re
                exc_text = re.sub(r"\s+", " ", exc_text)
                summary = f"{binary_name} seed={seed_path.name} status=FAIL error={exc_text}"
            lines.append(summary)
            if not ok:
                failed = True

    lines.append(f"overall={'PASS' if not failed else 'FAIL'}")
    text = "\n".join(lines) + "\n"
    output_path.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
