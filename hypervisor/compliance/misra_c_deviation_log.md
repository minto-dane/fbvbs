# FBVBS MISRA C:2023 Deviation Log (REQ-1000, REQ-1006)

**Document:** MISRA-DEV-001
**Date:** 2026-03-23
**Scope:** All C11 source files in hypervisor/src/ and hypervisor/include/
**Tool:** cppcheck --enable=warning,performance,portability (0 findings)
**Standard:** MISRA C:2023 (ISO/IEC 9899:2011 base)

---

## 1. Deviation Policy

FBVBS follows MISRA C:2023 guidelines with documented deviations for
bare-metal hypervisor requirements. Each deviation is:

1. **Justified** — explains why the rule cannot be followed
2. **Bounded** — identifies the exact scope (file, function, line range)
3. **Mitigated** — describes alternative assurance measures
4. **Approved** — deviation category (project-wide or per-instance)

---

## 2. Project-Wide Deviations

### DEV-001: Inline Assembly (Dir 4.3, Rule 1.2)

**Rule:** Dir 4.3 — Assembly language shall be encapsulated and isolated.
Rule 1.2 — Language extensions shall not be used.

**Deviation:** `__asm__ volatile(...)` is used for x86-64 privileged
operations that have no C-language equivalent.

**Scope:** 88 occurrences across 12 files:
- cpu_security.c (30): MSR read/write, CPUID, CR access, compiler barriers
- memory_utils.c (17): volatile memory operations, compiler barriers
- security.c (8): compiler barriers for constant-time operations
- log.c (7): spinlock acquire/release (xchg), compiler barriers
- mp_init.c (7): IPI send (xAPIC MMIO, x2APIC MSR), CPUID
- iommu_vtd.c (5): MMIO read/write model code
- idt.c (3): LIDT instruction
- vmx.c (3): VMXON/VMLAUNCH/VMRESUME
- vmcs_setup.c (2): VMCLEAR/VMPTRLD
- amd_npt.c (2): INVLPGA
- uefi_entry.c (2): CLI/HLT
- early_init.c (2): CLI/HLT, serial port I/O

**Justification:** A bare-metal hypervisor must execute privileged x86-64
instructions (VMXON, WRMSR, RDMSR, MOV CR, etc.) that are not expressible
in ISO C. These are required for VMX root operation (REQ-0002), CPU
security mitigations (REQ-0310–0321), spinlock synchronization, and
hardware register access.

**Mitigation:**
1. All asm is encapsulated in `fbvbs_asm.h` inline functions (11 categories)
   or in file-local static functions.
2. Frama-C `#ifdef __FRAMAC__` model paths provide pure C equivalents for
   formal verification (WP proves 8330/8387 goals against model paths).
3. GCC -fanalyzer validates the asm-containing compilation units.
4. Asm constraints are reviewed: output (=), input, clobber lists are
   explicit. Read-modify-write uses +m constraint (spinlock fix 2026-03-20).

### DEV-002: `_Static_assert` (Rule 1.2)

**Rule:** Rule 1.2 — Language extensions shall not be used.

**Deviation:** `_Static_assert` is a C11 feature (not an extension) used
for compile-time safety guards.

**Scope:** 21+ occurrences across 9 files (partition.c, memory.c, log.c,
page_alloc.c, idt.c, kernel.c, mp_init.c, apic.c, fuzz harnesses).

**Justification:** `_Static_assert` is ISO C11 §6.7.10, not an extension.
MISRA C:2023 targets C11/C18 and permits this. Used to guard ABI struct
sizes, buffer bounds, and cross-file type consistency.

**Mitigation:** N/A — this is a standard C11 feature, not a deviation.

### DEV-003: `void *` Pointer Casts (Rule 11.5, Rule 11.1)

**Rule:** Rule 11.5 — A conversion should not be performed from pointer
to void into pointer to object.

**Deviation:** `void *` casts are used in memory utility functions and
binary structure parsers.

**Scope:** 21 occurrences across 6 files:
- memory_utils.c (4): fbvbs_copy_memory, fbvbs_zero_memory, fbvbs_memory_is_zero
- boot_multiboot.c (1): Multiboot2 binary structure parsing (mitigated: now uses fbvbs_copy_memory for all field access)
- mp_init.c (4): ACPI MADT/SRAT binary structure parsing
- idt.c (9): IDT entry construction (address bit manipulation)
- page_alloc.c (2): physical page address ↔ pointer conversion
- kernel.c (1): model code

**Justification:** Binary hardware structures (ACPI tables, Multiboot2
info, IDT entries) require reinterpretation of byte buffers as structured
data. Physical page management requires address ↔ pointer conversion.

**Mitigation:**
1. void* functions are isolated in memory_utils.c, which is excluded from
   Frama-C WP analysis (documented in wp_verification_boundary.md).
2. boot_multiboot.c now uses fbvbs_copy_memory() for all field reads,
   eliminating alignment UB (fixed 2026-03-23).
3. All pointer casts have explicit alignment guarantees (ACPI tables are
   firmware-aligned, IDT entries are 16-byte aligned, pages are 4K-aligned).
4. GCC -fanalyzer + cppcheck validate these files.

### DEV-004: `volatile` Qualifier Usage (Rule 2.2 advisory, Dir 4.9)

**Rule:** Dir 4.9 — A function should be used in preference to a
function-like macro.

**Deviation:** `volatile` is used for:
1. Memory-mapped I/O register access (IOMMU, APIC)
2. Constant-time security operations (prevent compiler optimization)
3. Spinlock implementation (memory ordering)

**Scope:** Part of the 88 asm/volatile occurrences above.

**Justification:** `volatile` is the standard C mechanism for:
- Preventing compiler reordering of security-critical memory operations
- Ensuring MMIO writes are not optimized away
- Implementing constant-time comparisons (REQ: no timing side channels)

**Mitigation:** Each use is documented. Compiler barriers (`asm volatile
("" ::: "memory")`) are paired with volatile accesses where needed.

### DEV-005: `uintptr_t` ↔ Pointer Conversion (Rule 11.4, Rule 11.6)

**Rule:** Rule 11.4 — A conversion should not be performed between a
pointer to object and an integer type.

**Deviation:** `uintptr_t` casts are used for GPA (Guest Physical Address)
handling and physical page management.

**Scope:** command.c (dispatch_hypercall GPA resolution), security.c
(manifest GPA resolution), page_alloc.c, memory.c (EPT management).

**Justification:** The hypervisor's core function is managing physical
address spaces. GPAs arrive as uint64_t values in hypercall registers and
must be converted to pointers for memory access. This is fundamental to
hypervisor operation and cannot be avoided.

**Mitigation:**
1. GPA → pointer conversion is centralized in `#ifdef __FRAMAC__` model
   code blocks, isolated from verified paths.
2. All GPAs are validated (alignment, 52-bit bounds, ownership) before
   conversion.
3. Frama-C WP verifies the logic using abstract GPA models.

---

## 3. Per-Instance Deviations

### DEV-006: goto Statement (Rule 15.1)

**Rule:** Rule 15.1 — The goto statement should not be used.

**Deviation:** `goto halt;` in early_init.c for fatal error paths.

**Scope:** early_init.c:215,245 — `fbvbs_efi_to_hypervisor()`

**Justification:** The function has a single `halt:` label at the end
containing an infinite `cli; hlt` loop. This is the standard pattern for
bare-metal fatal error handling where no OS facilities exist. The `goto`
jumps forward only, to a single well-defined halt point.

**Mitigation:** Forward-only goto to a single label. No complex control
flow. Function is excluded from WP analysis.

### DEV-007: Recursive Include Guard Macros (Dir 4.10)

**Rule:** Dir 4.10 — Precautions shall be taken in order to prevent the
contents of a header file being included more than once.

**Status:** COMPLIANT — All headers use `#ifndef`/`#define`/`#endif` guards.

### DEV-008: Identifier Reuse Across Translation Units

**Rule:** Rule 5.3 — An identifier declared in an inner scope shall not
hide an identifier declared in an outer scope.

**Status:** COMPLIANT — `-Wshadow` is enabled with `-Werror`. Any
shadowing is a compile error.

---

## 4. Verification Evidence

| Check | Tool | Result |
|-------|------|--------|
| Warnings | GCC -Wall -Wextra -Werror -Wpedantic | 0 warnings (24 sources) |
| Static analysis (GCC) | GCC -fanalyzer | 0 findings (24 sources) |
| Static analysis (cppcheck) | cppcheck warning+perf+port | 0 findings (25 sources) |
| Formal verification | Frama-C WP Typed+Cast | 8330/8387 (99.32%) |
| Shadow detection | -Wshadow -Werror | Enforced |
| Implicit conversion | -Wconversion -Wsign-conversion -Werror | Enforced |
| Strict prototypes | -Wstrict-prototypes -Wmissing-prototypes | Enforced |
| Undefined behavior | -fno-strict-overflow -fno-strict-aliasing | Compiler hardening |

---

## 5. Approval

Deviations DEV-001 through DEV-006 are approved as project-wide deviations
for the FBVBS hypervisor. They are inherent to bare-metal x86-64 hypervisor
development and are mitigated by the formal verification, static analysis,
and testing infrastructure documented above.
