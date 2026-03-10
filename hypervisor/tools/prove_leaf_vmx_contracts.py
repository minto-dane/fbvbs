from __future__ import annotations

import ctypes
import itertools
import re
import subprocess
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HYPERVISOR_DIR = REPO_ROOT / "hypervisor"
ABI_HEADER = HYPERVISOR_DIR / "include" / "fbvbs_abi.h"
GENERATED_HEADER = REPO_ROOT / "generated" / "bindings" / "fbvbs_abi_v1.h"


class Vcpu(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint32),
        ("pending_interrupt_vector", ctypes.c_uint32),
        ("rip", ctypes.c_uint64),
        ("rsp", ctypes.c_uint64),
        ("rflags", ctypes.c_uint64),
        ("cr0", ctypes.c_uint64),
        ("cr3", ctypes.c_uint64),
        ("cr4", ctypes.c_uint64),
        ("pending_interrupt_delivery", ctypes.c_uint32),
        ("reserved0", ctypes.c_uint32),
    ]


class VmxCapabilities(ctypes.Structure):
    _fields_ = [
        ("vmx_supported", ctypes.c_uint32),
        ("hlat_available", ctypes.c_uint32),
        ("iommu_available", ctypes.c_uint32),
        ("mbec_available", ctypes.c_uint32),
        ("cet_available", ctypes.c_uint32),
        ("aesni_available", ctypes.c_uint32),
    ]


class VmxLeafExit(ctypes.Structure):
    _fields_ = [
        ("exit_reason", ctypes.c_uint32),
        ("cr_number", ctypes.c_uint32),
        ("msr_address", ctypes.c_uint32),
        ("port", ctypes.c_uint16),
        ("access_size", ctypes.c_uint8),
        ("is_write", ctypes.c_uint8),
        ("value", ctypes.c_uint64),
        ("guest_physical_address", ctypes.c_uint64),
    ]


def parse_integer_literal(value: str) -> int:
    sanitized = value.strip()
    sanitized = sanitized.split("/*", 1)[0].strip()
    sanitized = sanitized.strip("()")
    sanitized = re.sub(r"[uUlL]+$", "", sanitized)
    return int(sanitized, 0)


def read_defines(path: Path) -> dict[str, int]:
    defines: dict[str, int] = {}

    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.match(r"#define\s+([A-Z0-9_]+)\s+([^\s/]+)", line)
        if match is None:
            continue
        name = match.group(1)
        value = match.group(2)
        try:
            defines[name] = parse_integer_literal(value)
        except ValueError:
            continue

    return defines


def ensure_generated_header() -> None:
    if GENERATED_HEADER.exists():
        return

    subprocess.run(
        [
            "python3",
            "-m",
            "fbvbs_spec",
            "generate",
            "--source",
            str(REPO_ROOT / "plan" / "fbvbs-design.md"),
            "--output",
            str(REPO_ROOT / "generated"),
        ],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def build_shared_library(output_path: Path) -> None:
    subprocess.run(
        [
            "gcc",
            "-shared",
            "-fPIC",
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wpedantic",
            "-Wconversion",
            "-Wsign-conversion",
            "-Wstrict-prototypes",
            "-Wmissing-prototypes",
            "-Wshadow",
            "-Wundef",
            "-Iinclude",
            "-I../generated/bindings",
            "src/vmx.c",
            "-o",
            str(output_path),
        ],
        cwd=HYPERVISOR_DIR,
        check=True,
        capture_output=True,
        text=True,
    )


def as_dict(exit_record: VmxLeafExit) -> dict[str, int]:
    return {
        "exit_reason": int(exit_record.exit_reason),
        "cr_number": int(exit_record.cr_number),
        "msr_address": int(exit_record.msr_address),
        "port": int(exit_record.port),
        "access_size": int(exit_record.access_size),
        "is_write": int(exit_record.is_write),
        "value": int(exit_record.value),
        "guest_physical_address": int(exit_record.guest_physical_address),
    }


def model_exit(
    constants: dict[str, int],
    vcpu: Vcpu,
    pinned_cr0_mask: int,
    pinned_cr4_mask: int,
    intercepted_msr: int | None,
    mapped_bytes: int,
) -> dict[str, int]:
    result = {
        "exit_reason": 0,
        "cr_number": 0,
        "msr_address": 0,
        "port": 0,
        "access_size": 0,
        "is_write": 0,
        "value": 0,
        "guest_physical_address": 0,
    }

    if vcpu.pending_interrupt_delivery != 0:
        result["exit_reason"] = constants["FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT"]
        result["value"] = int(vcpu.pending_interrupt_vector)
        return result

    if pinned_cr0_mask != 0 and (int(vcpu.cr0) & pinned_cr0_mask) != pinned_cr0_mask:
        result["exit_reason"] = constants["FBVBS_VM_EXIT_REASON_CR_ACCESS"]
        result["cr_number"] = 0
        result["value"] = int(vcpu.cr0)
        return result

    if pinned_cr4_mask != 0 and (int(vcpu.cr4) & pinned_cr4_mask) != pinned_cr4_mask:
        result["exit_reason"] = constants["FBVBS_VM_EXIT_REASON_CR_ACCESS"]
        result["cr_number"] = 4
        result["value"] = int(vcpu.cr4)
        return result

    if intercepted_msr is not None:
        result["exit_reason"] = constants["FBVBS_VM_EXIT_REASON_MSR_ACCESS"]
        result["msr_address"] = intercepted_msr
        return result

    if mapped_bytes == 0:
        result["exit_reason"] = constants["FBVBS_VM_EXIT_REASON_EPT_VIOLATION"]
        return result

    if int(vcpu.rip) == constants["FBVBS_SYNTHETIC_EXIT_RIP_PIO"]:
        result["exit_reason"] = constants["FBVBS_VM_EXIT_REASON_PIO"]
        result["port"] = int(vcpu.rsp & 0xFFFF)
        result["access_size"] = 4
        result["is_write"] = int(vcpu.rflags & 0x1)
        result["value"] = int(vcpu.rflags & 0xFFFFFFFF)
        return result

    if int(vcpu.rip) == constants["FBVBS_SYNTHETIC_EXIT_RIP_MMIO"]:
        result["exit_reason"] = constants["FBVBS_VM_EXIT_REASON_MMIO"]
        result["guest_physical_address"] = int(vcpu.rsp)
        result["access_size"] = 8
        result["is_write"] = int(vcpu.rflags & 0x1)
        result["value"] = int(vcpu.rflags & 0xFFFFFFFF)
        return result

    if int(vcpu.rip) == constants["FBVBS_SYNTHETIC_EXIT_RIP_SHUTDOWN"]:
        result["exit_reason"] = constants["FBVBS_VM_EXIT_REASON_SHUTDOWN"]
        return result

    if int(vcpu.rip) == constants["FBVBS_SYNTHETIC_EXIT_RIP_FAULT"]:
        result["exit_reason"] = constants["FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT"]
        return result

    result["exit_reason"] = constants["FBVBS_VM_EXIT_REASON_HALT"]
    return result


def verify_null_contracts(lib: ctypes.CDLL, constants: dict[str, int]) -> None:
    probe = lib.fbvbs_vmx_probe
    probe.argtypes = [ctypes.POINTER(VmxCapabilities)]
    probe.restype = ctypes.c_int

    leaf_run = lib.fbvbs_vmx_leaf_run_vcpu
    leaf_run.argtypes = [
        ctypes.POINTER(VmxCapabilities),
        ctypes.POINTER(Vcpu),
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
        ctypes.c_uint64,
        ctypes.POINTER(VmxLeafExit),
    ]
    leaf_run.restype = ctypes.c_int

    if probe(None) != constants["INVALID_PARAMETER"]:
        raise AssertionError("fbvbs_vmx_probe did not reject NULL")

    caps = VmxCapabilities()
    vcpu = Vcpu()
    leaf_exit = VmxLeafExit()

    if probe(ctypes.byref(caps)) != constants["OK"]:
        raise AssertionError("fbvbs_vmx_probe failed for a valid capabilities buffer")
    if caps.vmx_supported != 1:
        raise AssertionError("fbvbs_vmx_probe no longer reports VMX on x86_64 hosts")

    if leaf_run(None, ctypes.byref(vcpu), 0, 0, None, 0, 4096, ctypes.byref(leaf_exit)) != constants["INVALID_PARAMETER"]:
        raise AssertionError("fbvbs_vmx_leaf_run_vcpu accepted NULL caps")
    if leaf_run(ctypes.byref(caps), None, 0, 0, None, 0, 4096, ctypes.byref(leaf_exit)) != constants["INVALID_PARAMETER"]:
        raise AssertionError("fbvbs_vmx_leaf_run_vcpu accepted NULL vcpu")
    if leaf_run(ctypes.byref(caps), ctypes.byref(vcpu), 0, 0, None, 0, 4096, None) != constants["INVALID_PARAMETER"]:
        raise AssertionError("fbvbs_vmx_leaf_run_vcpu accepted NULL exit buffer")
    if leaf_run(ctypes.byref(caps), ctypes.byref(vcpu), 0, 0, None, 1, 4096, ctypes.byref(leaf_exit)) != constants["INVALID_PARAMETER"]:
        raise AssertionError("fbvbs_vmx_leaf_run_vcpu accepted NULL intercepted MSR array")

    caps.vmx_supported = 0
    if leaf_run(ctypes.byref(caps), ctypes.byref(vcpu), 0, 0, None, 0, 4096, ctypes.byref(leaf_exit)) != constants["NOT_SUPPORTED_ON_PLATFORM"]:
        raise AssertionError("fbvbs_vmx_leaf_run_vcpu did not gate on vmx_supported")


def verify_exhaustive_model_equivalence(lib: ctypes.CDLL, constants: dict[str, int]) -> None:
    leaf_run = lib.fbvbs_vmx_leaf_run_vcpu
    leaf_run.argtypes = [
        ctypes.POINTER(VmxCapabilities),
        ctypes.POINTER(Vcpu),
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
        ctypes.c_uint64,
        ctypes.POINTER(VmxLeafExit),
    ]
    leaf_run.restype = ctypes.c_int

    caps = VmxCapabilities(1, 1, 1, 1, 1, 1)
    intercepted_value = ctypes.c_uint32(0xC0000080)
    checked_cases = 0

    rip_values = (
        0x1234,
        constants["FBVBS_SYNTHETIC_EXIT_RIP_PIO"],
        constants["FBVBS_SYNTHETIC_EXIT_RIP_MMIO"],
        constants["FBVBS_SYNTHETIC_EXIT_RIP_SHUTDOWN"],
        constants["FBVBS_SYNTHETIC_EXIT_RIP_FAULT"],
    )

    for (
        pending_interrupt_delivery,
        pending_interrupt_vector,
        pinned_cr0_mask,
        pinned_cr4_mask,
        intercepted_msr_count,
        mapped_bytes,
        rip,
        rsp,
        rflags,
        cr0,
        cr4,
    ) in itertools.product(
        (0, 1),
        (0, 48),
        (0, 1),
        (0, 2),
        (0, 1),
        (0, 4096),
        rip_values,
        (0, 0x3F8, 0x2000),
        (0, 1),
        (0, 1),
        (0, 2),
    ):
        vcpu = Vcpu(
            0,
            pending_interrupt_vector,
            rip,
            rsp,
            rflags,
            cr0,
            0,
            cr4,
            pending_interrupt_delivery,
            0,
        )
        leaf_exit = VmxLeafExit()
        intercepted_ptr = ctypes.byref(intercepted_value) if intercepted_msr_count != 0 else None

        status = leaf_run(
            ctypes.byref(caps),
            ctypes.byref(vcpu),
            pinned_cr0_mask,
            pinned_cr4_mask,
            intercepted_ptr,
            intercepted_msr_count,
            mapped_bytes,
            ctypes.byref(leaf_exit),
        )

        if status != constants["OK"]:
            raise AssertionError(f"unexpected status {status} in exhaustive leaf model case")

        expected = model_exit(
            constants=constants,
            vcpu=vcpu,
            pinned_cr0_mask=pinned_cr0_mask,
            pinned_cr4_mask=pinned_cr4_mask,
            intercepted_msr=0xC0000080 if intercepted_msr_count != 0 else None,
            mapped_bytes=mapped_bytes,
        )
        actual = as_dict(leaf_exit)

        if actual != expected:
            raise AssertionError(
                "leaf VMX model mismatch for case "
                f"{checked_cases}: expected {expected}, actual {actual}"
            )

        checked_cases += 1

    print(f"bounded VMX contract proof passed for {checked_cases} modeled states")


def main() -> int:
    ensure_generated_header()
    constants = read_defines(GENERATED_HEADER)
    constants.update(read_defines(ABI_HEADER))
    constants.update(read_defines(HYPERVISOR_DIR / "include" / "fbvbs_leaf_vmx.h"))

    with tempfile.TemporaryDirectory(prefix="fbvbs-vmx-proof-") as temp_dir:
        shared_object = Path(temp_dir) / "libfbvbs_vmx.so"
        build_shared_library(shared_object)
        library = ctypes.CDLL(str(shared_object))
        verify_null_contracts(library, constants)
        verify_exhaustive_model_equivalence(library, constants)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
