from __future__ import annotations

import re
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
HYPERVISOR_DIR = REPO_ROOT / "hypervisor"
MAKEFILE = HYPERVISOR_DIR / "Makefile"
VMX_SOURCE = HYPERVISOR_DIR / "src" / "vmx.c"
LEAF_HEADER = HYPERVISOR_DIR / "include" / "fbvbs_leaf_vmx.h"
LEGACY_HEADER = HYPERVISOR_DIR / "include" / "fbvbs_hypervisor.h"
COMPLIANCE_DOC = HYPERVISOR_DIR / "compliance" / "retained_c_leaf_boundary.md"

FORBIDDEN_TOKENS = (
    "malloc(",
    "calloc(",
    "realloc(",
    "free(",
    "memcpy(",
    "memmove(",
    "memset(",
    "goto ",
    "goto\t",
    "union ",
    "setjmp(",
    "longjmp(",
    "fprintf(",
    "printf(",
    "snprintf(",
    "scanf(",
    "while (",
    "while(",
    "do {",
    "do\n",
)

REQUIRED_HEADER_ASSERTS = (
    "_Static_assert(sizeof(struct fbvbs_vcpu) == 64U, \"fbvbs_vcpu ABI drift\")",
    "_Static_assert(offsetof(struct fbvbs_vcpu, rip) == 8U, \"fbvbs_vcpu.rip offset drift\")",
    "_Static_assert(offsetof(struct fbvbs_vcpu, cr4) == 48U, \"fbvbs_vcpu.cr4 offset drift\")",
    "_Static_assert(sizeof(struct fbvbs_vmx_capabilities) == 24U, \"fbvbs_vmx_capabilities ABI drift\")",
    "_Static_assert(sizeof(struct fbvbs_vmx_leaf_exit) == 32U, \"fbvbs_vmx_leaf_exit ABI drift\")",
)


def fail(message: str) -> None:
    raise SystemExit(message)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def extract_includes(content: str) -> list[str]:
    return re.findall(r'^\s*#include\s+([<"].*[>"])', content, flags=re.MULTILINE)


def extract_function_names(content: str) -> list[str]:
    return re.findall(r'^\s*int\s+(fbvbs_[a-z0-9_]+)\s*\(', content, flags=re.MULTILINE)


def main() -> int:
    makefile = read_text(MAKEFILE)
    source = read_text(VMX_SOURCE)
    leaf_header = read_text(LEAF_HEADER)
    legacy_header = read_text(LEGACY_HEADER)
    compliance_doc = read_text(COMPLIANCE_DOC)

    if "LEAF_SOURCES := src/vmx.c" not in makefile:
        fail("default retained-C source list drifted away from vmx.c-only")

    for forbidden_source in ("src/command.c", "src/partition.c", "src/security.c", "src/vm_policy.c"):
        if forbidden_source in makefile:
            fail(f"non-leaf source {forbidden_source} re-entered the default retained-C path")

    source_includes = extract_includes(source)
    if source_includes != ["<stddef.h>", "<stdint.h>", "\"fbvbs_leaf_vmx.h\""]:
        fail(f"unexpected vmx.c include boundary: {source_includes}")

    leaf_header_includes = extract_includes(leaf_header)
    if leaf_header_includes != ["<stddef.h>", "<stdint.h>", "\"fbvbs_abi.h\""]:
        fail(f"unexpected fbvbs_leaf_vmx.h include boundary: {leaf_header_includes}")

    if "#include \"fbvbs_leaf_vmx.h\"" not in legacy_header:
        fail("legacy migration header no longer reuses the dedicated leaf header")

    if "#include \"fbvbs_hypervisor.h\"" in source:
        fail("vmx.c must not include the legacy migration header")

    for token in FORBIDDEN_TOKENS:
        if token in source or token in leaf_header:
            fail(f"forbidden retained-C construct detected: {token.strip()}")

    for required_assert in REQUIRED_HEADER_ASSERTS:
        if required_assert not in leaf_header:
            fail(f"missing fixed-ABI assertion: {required_assert}")

    source_functions = extract_function_names(source)
    if source_functions != ["fbvbs_vmx_probe", "fbvbs_vmx_leaf_run_vcpu"]:
        fail(f"unexpected externally visible functions in vmx.c: {source_functions}")

    header_functions = extract_function_names(leaf_header)
    if header_functions != ["fbvbs_vmx_probe", "fbvbs_vmx_leaf_run_vcpu"]:
        fail(f"unexpected externally visible declarations in fbvbs_leaf_vmx.h: {header_functions}")

    for required_text in (
        "compiler warnings as errors",
        "GCC `-fanalyzer`",
        "bounded exhaustive proof-style contract comparison",
    ):
        if required_text not in compliance_doc:
            fail(f"missing compliance evidence text in retained_c_leaf_boundary.md: {required_text}")

    print("retained-C subset checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
