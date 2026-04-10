#!/usr/bin/env python3

import argparse
import pathlib
import shutil
import subprocess
import sys


EXPECTED_TERMINALS = (
    "FBVBS: hypervisor init complete",
    "FBVBS: VMX unavailable",
    "FBVBS: IOMMU detection failed",
    "FBVBS: IOMMU initialization failed",
    "FBVBS: measured boot unavailable",
)


CASES = {
    "tcg-intel-iommu": {
        "stage": "1+3",
        "description": "QEMU/TCG boot-to-gate with Intel VT-d emulation",
        "machine": "q35,accel=tcg",
        "cpu": "qemu64,+vmx,+nx,+rdrand,+rdseed",
        "iommu_device": "intel-iommu,intremap=on,device-iotlb=on,caching-mode=on",
        "requires_kvm": False,
        "device_name": "intel-iommu",
    },
    "tcg-amd-iommu": {
        "stage": "3",
        "description": "QEMU/TCG boot-to-gate with AMD-Vi emulation",
        "machine": "q35,accel=tcg",
        "cpu": "qemu64,+svm,+nx,+rdrand,+rdseed",
        "iommu_device": "amd-iommu",
        "requires_kvm": False,
        "device_name": "amd-iommu",
    },
    "kvm-intel-iommu": {
        "stage": "2",
        "description": "Local QEMU/KVM boot-to-gate with Intel VT-d emulation",
        "machine": "q35,accel=kvm,kernel-irqchip=split",
        "cpu": "host",
        "iommu_device": "intel-iommu,intremap=on,device-iotlb=on,caching-mode=on",
        "requires_kvm": True,
        "device_name": "intel-iommu",
    },
}


def resolve_user_path(base_dir: pathlib.Path, raw_path: str) -> pathlib.Path:
    path = pathlib.Path(raw_path)
    if path.is_absolute():
        return path.resolve()
    cwd_candidate = (pathlib.Path.cwd() / path).resolve()
    if cwd_candidate.exists():
        return cwd_candidate
    return (base_dir / path).resolve()


def qemu_supports_device(qemu_bin: str, device_name: str) -> bool:
    result = subprocess.run(
        [qemu_bin, "-device", "help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return f'name "{device_name}"' in result.stdout


def kvm_is_usable() -> bool:
    if not pathlib.Path("/dev/kvm").exists():
        return False
    if shutil.which("sudo") is None:
        return False
    result = subprocess.run(
        ["sudo", "-n", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def run_case(qemu_bin: str, iso_path: pathlib.Path, logs_dir: pathlib.Path, case_name: str) -> tuple[str, pathlib.Path, str]:
    config = CASES[case_name]
    log_path = logs_dir / f"{case_name}.log"

    if not qemu_supports_device(qemu_bin, config["device_name"]):
        log_path.write_text(
            f"{case_name}: SKIP missing-qemu-device {config['device_name']}\n",
            encoding="utf-8",
        )
        return "SKIP", log_path, f"reason=missing-qemu-device:{config['device_name']}"

    if config["requires_kvm"] and not kvm_is_usable():
        log_path.write_text(
            f"{case_name}: SKIP kvm-unavailable-or-sudo-missing\n",
            encoding="utf-8",
        )
        return "SKIP", log_path, "reason=kvm-unavailable-or-sudo-missing"

    cmd = [
        qemu_bin,
        "-machine", config["machine"],
        "-m", "256",
        "-no-reboot",
        "-no-shutdown",
        "-display", "none",
        "-monitor", "none",
        "-serial", "stdio",
        "-cpu", config["cpu"],
        "-device", config["iommu_device"],
        "-cdrom", str(iso_path),
        "-boot", "d",
    ]
    if config["requires_kvm"]:
        cmd = ["sudo", "-n"] + cmd

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )
        output = result.stdout
        return_code = result.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return_code = 124
        timed_out = True

    log_path.write_text(output, encoding="utf-8")

    boot_seen = "FBVBS: boot64 reached" in output
    terminal_seen = any(needle in output for needle in EXPECTED_TERMINALS)
    if boot_seen and terminal_seen and (timed_out or return_code == 0):
        detail = "reason=expected-terminal-reached"
        if timed_out:
            detail += " timeout=20s"
        return "PASS", log_path, detail

    return "FAIL", log_path, f"rc={return_code}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the retained-C QEMU smoke matrix.")
    parser.add_argument("--build-dir", default="build", help="Path to the hypervisor build directory")
    parser.add_argument("--iso", required=True, help="Path to the Multiboot2 ISO to boot")
    parser.add_argument("--output", required=True, help="Summary file to write")
    parser.add_argument("--logs-dir", required=True, help="Directory to store per-case logs")
    parser.add_argument("--qemu-bin", default="qemu-system-x86_64", help="QEMU binary")
    parser.add_argument("--case", dest="cases", action="append", choices=sorted(CASES.keys()), help="Case to run")
    parser.add_argument("--require-pass", dest="required_pass", action="append", default=[], choices=sorted(CASES.keys()), help="Case that must PASS")
    parser.add_argument("--require-available", dest="required_available", action="append", default=[], choices=sorted(CASES.keys()), help="Case that must not SKIP")
    parser.add_argument("--alias-log", help="Optional path to copy the single-case log to")
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    hypervisor_dir = script_dir.parents[1]
    build_dir = resolve_user_path(hypervisor_dir, args.build_dir)
    iso_path = resolve_user_path(hypervisor_dir, args.iso)
    output_path = resolve_user_path(hypervisor_dir, args.output)
    logs_dir = resolve_user_path(hypervisor_dir, args.logs_dir)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    selected_cases = args.cases or list(CASES.keys())
    lines = [
        "FBVBS QEMU smoke matrix",
        f"build_dir={build_dir}",
        f"iso={iso_path}",
        f"qemu_bin={args.qemu_bin}",
    ]

    failed = False
    case_logs: dict[str, pathlib.Path] = {}
    case_status: dict[str, str] = {}

    for case_name in selected_cases:
        status, log_path, detail = run_case(args.qemu_bin, iso_path, logs_dir, case_name)
        case_logs[case_name] = log_path
        case_status[case_name] = status
        config = CASES[case_name]
        lines.append(
            f"{case_name} stage={config['stage']} status={status} "
            f"device={config['device_name']} log={log_path.name} {detail}"
        )

    for case_name in args.required_available:
        if case_status.get(case_name) == "SKIP":
            failed = True
            lines.append(f"{case_name} required_available=FAIL")

    for case_name in args.required_pass:
        if case_status.get(case_name) != "PASS":
            failed = True
            lines.append(f"{case_name} required_pass=FAIL")

    if args.alias_log:
        alias_path = resolve_user_path(hypervisor_dir, args.alias_log)
        alias_path.parent.mkdir(parents=True, exist_ok=True)
        if len(selected_cases) != 1:
            raise SystemExit("--alias-log requires exactly one --case")
        shutil.copyfile(case_logs[selected_cases[0]], alias_path)
        lines.append(f"alias_log={alias_path}")

    lines.append(f"overall={'PASS' if not failed else 'FAIL'}")
    text = "\n".join(lines) + "\n"
    output_path.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
