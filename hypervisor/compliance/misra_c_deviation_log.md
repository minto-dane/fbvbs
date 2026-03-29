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
   formal verification; current proof status is tracked separately in
   `wp_verification_boundary.md` and is not asserted by this deviation log.
3. GCC -fanalyzer validates the asm-containing compilation units.
4. Asm constraints are reviewed: output (=), input, clobber lists are
   explicit. Read-modify-write uses +m constraint (spinlock fix 2026-03-20).

### DEV-002: (Removed — see Section 4.1 Conformance Notes)

`_Static_assert` was originally listed here as a Rule 1.2 deviation. It is
in fact ISO C11 §6.7.10, a standard language feature, not an extension.
MISRA C:2023 targets C11/C18 and permits `_Static_assert`. This entry is
retained as a cross-reference; see Section 4.1 for the conformance record.

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

### DEV-004: `volatile` Qualifier Usage (Rule 11.8)

**Rule:** Rule 11.8 — A conversion shall not remove any const, volatile,
or _Atomic qualification from the type pointed to by a pointer.

**Deviation:** `volatile`-qualified accesses are required for:
1. Memory-mapped I/O register access (IOMMU, APIC)
2. Constant-time security operations where the compiler must not elide
   observable loads/stores
3. Spinlock implementation and memory ordering primitives

**Scope:** Part of the 88 asm/volatile occurrences above (overlaps DEV-001).

**Justification:** The hypervisor must preserve hardware-visible side
effects and ordering. `volatile` is used only where the code needs the
compiler to observe MMIO, barrier, or lock state transitions. No code
path strips `volatile` qualification from a pointer target, which is the
specific MISRA concern addressed by Rule 11.8.

**Mitigation:** Each use is documented. Compiler barriers (`asm volatile
("" ::: "memory")`) are paired with volatile accesses where needed, and
the surrounding code avoids casts that would remove `volatile`.

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

### DEV-007 and DEV-008: (Removed — see Section 4.1 Conformance Notes)

DEV-007 (Dir 4.10 include guards) and DEV-008 (Rule 5.3 identifier
shadowing) were originally listed here but are **compliant**, not
deviations. They have been relocated to Section 4.1 (Conformance Notes).

---

## 4. Verification Evidence

| Check | Tool | Result |
|-------|------|--------|
| Warnings | GCC -Wall -Wextra -Werror -Wpedantic | 0 warnings (24 sources) |
| Static analysis (GCC) | GCC -fanalyzer | 0 findings (24 sources) |
| Static analysis (cppcheck) | cppcheck warning+perf+port | 0 findings (25 sources) |
| Formal verification | Frama-C WP Typed+Cast | Available and reproducible, but current runs still report proof gaps/timeouts |
| Shadow detection | -Wshadow -Werror | Enforced |
| Implicit conversion | -Wconversion -Wsign-conversion -Werror | Enforced |
| Strict prototypes | -Wstrict-prototypes -Wmissing-prototypes | Enforced |
| Undefined behavior | -fno-strict-overflow -fno-strict-aliasing | Compiler hardening |

---

## 4.1 Conformance Notes

The following features were reviewed and found to be **conformant** with
MISRA C:2023. They are not deviations.

### `_Static_assert` (formerly DEV-002)

`_Static_assert` is ISO C11 §6.7.10, a standard language feature.
MISRA C:2023 targets C11/C18 and permits `_Static_assert`. It is used in
21+ occurrences across 9 files (partition.c, memory.c, log.c, page_alloc.c,
idt.c, kernel.c, mp_init.c, apic.c, fuzz harnesses) to guard ABI struct
sizes, buffer bounds, and cross-file type consistency. No deviation required.

### Include Guards (formerly DEV-007)

All headers use `#ifndef`/`#define`/`#endif` include guards per Dir 4.10.
This is standard conformant practice, not a deviation.

### No Identifier Shadowing (formerly DEV-008)

`-Wshadow` is enabled with `-Werror`. Any shadowing is a compile error.
This enforces Rule 5.3 compliance, not a deviation.

---

## 5. Approval

Deviations DEV-001, DEV-003, DEV-004, DEV-005, and DEV-006 are approved as
project-wide deviations for the FBVBS hypervisor. DEV-002, DEV-007, and
DEV-008 were found to be conformant and have been relocated to Section 4.1.
The remaining deviations are inherent to bare-metal x86-64 hypervisor
development and are mitigated by the static analysis, testing, and
in-progress formal verification infrastructure documented above.
