# FBVBS WP Verification Boundary

**Date:** 2026-03-30
**Tooling intent:** Frama-C 32.x WP, `Typed+Cast` model
**Purpose:** define the current proof target set for the standalone microhypervisor, and explain why files are in or out of scope

## Current interpretation

The WP boundary is not “all ACSL-annotated files”.

The correct current interpretation is:

- **in scope**
  - retained-C core files whose logic is primarily arithmetic, state-machine, or bounded-data manipulation
- **out of scope**
  - files dominated by raw binary parsing, firmware memory walks, MMIO/MSR/VMCS interactions, or proof-hostile cast/union patterns that are not yet isolated behind smaller proof-friendly helper functions

Release decisions must use current reproducible proof runs, not stale aggregate percentages.

## Current WP target set

The repository currently targets these source files for WP:

- `src/cpu_security.c`
- `src/vmx.c`
- `src/memory.c`
- `src/memory_utils.c`
- `src/freestanding_runtime.c`
- `src/log.c`
- `src/vm_policy.c`
- `src/boot_multiboot.c`
- `src/watchdog.c`
- `src/early_init.c`
- `src/acpi.c`
- `src/apic.c`
- `src/idt.c`
- `src/vmx_controls.c`
- `src/vmcs_setup.c`
- `src/kernel.c`
- `src/command.c`
- `src/security.c`
- `src/partition.c`
- `src/page_alloc.c`
- `src/hlat.c`
- `src/amd_npt.c`
- `src/mp_init.c`

### Why these files are in scope

- `cpu_security.c`
  - mostly bounded feature-detection and mitigation synthesis logic
- `vmx.c`
  - compact VMX leaf/control logic, despite remaining union-model warnings
- `memory.c`
  - EPT state transitions and rollback logic are security-critical and mostly proof-shaped
- `memory_utils.c`
  - byte helpers, constant-time comparisons, and SHA-384 primitives now carry enough ACSL structure to participate in standalone WP without fatal annotation noise
- `freestanding_runtime.c`
  - freestanding console/runtime helpers now expose proof-side representative models and bounded memory-primitive contracts, so the hosted WP boundary can include them without reintroducing fatal annotation noise
- `log.c`
  - audit-log state machine is compact and bounded
- `vm_policy.c`
  - exit-policy enforcement is central to hypervisor correctness
- `boot_multiboot.c`
  - Multiboot parsing now has a proof-side representative model plus bounded helper contracts, so it can stay inside the retained-C WP boundary
- `watchdog.c`
  - partition liveness accounting and watchdog-fault transitions are bounded state-machine logic and fit the current WP model well
- `early_init.c`
  - the post-ExitBootServices handoff now uses proof-side representative models for EFI memory-map ingestion and serial output, which is enough to keep the fail-closed initialization logic inside the current WP boundary
- `acpi.c`
  - bounded ACPI root-table discovery and checksum validation now fit the retained-C WP boundary
- `apic.c`
  - APIC mode detection and BSP-local virtualization state transitions are bounded enough to stay inside the current WP boundary, even though some loops still consume timeout budget
- `idt.c`
  - IDT gate setup and fail-stop exception wrappers now use a proof-side typed-frame model, so the exception boundary fits the current retained-C WP set
- `vmx_controls.c`
  - VMX security-control synthesis is mostly bounded control-value construction; with proof-side allocator assumptions isolated, it now fits the retained-C WP boundary
- `vmcs_setup.c`
  - VMCS construction and fail-closed cleanup now clear the fatal ACSL blockers; the remaining gap is proof cost rather than missing specification
- `kernel.c`
  - integration logic is security-critical, even though it still depends on excluded helpers
- `command.c`
  - command boundary and capability enforcement are security-critical
- `security.c`
  - trust-boundary logic must remain in proof scope
- `partition.c`
  - lifecycle and shared-memory invariants are security-critical
- `page_alloc.c`
  - pure retained-C allocator logic is proof-compatible and removing it from scope only creates missing-spec noise for `kernel.c`
- `hlat.c`
  - HLAT translation integrity with bounded code-region and PTE-page tracking; proof-side representative models for hardware operations
- `amd_npt.c`
  - AMD NPT write-protect, SEV-SNP integration, and VMCB configuration; complex init function stubbed under `__FRAMAC__` for assigns tractability
- `mp_init.c`
  - MADT/SRAT parsing, AP initialization, per-CPU state management, TLB shootdown, and NUMA topology; shift operations isolated in `mp_bit_mask` helper for RTE provability

## Files intentionally out of scope today

### Excluded because they are platform or hardware dominated

- `src/iommu_vtd.c`
- `src/iommu_amdvi.c`
- `src/uefi_entry.c`

Reasons include:

- MMIO/MSR/VMCS operations
- firmware-owned memory scanning
- larger proof-hostile unions and architecture-specific encodings
- model-only or partial implementations where fail-closed behavior matters more than raw proof coverage count

## Current proof state

All 23 WP target files achieve **100% proved goals with 0 timeouts** (per-file verification, 60s timeout, Alt-Ergo + Z3 provers).

**Total: 14,436 goals proved, 0 timeouts.**

| File | Goals |
|------|-------|
| cpu_security.c | 1059/1059 |
| vmx.c | 294/294 |
| memory.c | 375/375 |
| memory_utils.c | 316/316 |
| freestanding_runtime.c | 309/309 |
| log.c | 273/273 |
| vm_policy.c | 191/191 |
| boot_multiboot.c | 142/142 |
| watchdog.c | 175/175 |
| early_init.c | 225/225 |
| acpi.c | 117/117 |
| apic.c | 365/365 |
| idt.c | 321/321 |
| vmx_controls.c | 499/499 |
| vmcs_setup.c | 223/223 |
| hlat.c | 894/894 |
| kernel.c | 1339/1339 |
| command.c | 1377/1377 |
| security.c | 2252/2252 |
| partition.c | 2267/2267 |
| page_alloc.c | 304/304 |
| amd_npt.c | 665/665 |
| mp_init.c | 874/874 |

Verification command: `eval $(opam env) && frama-c -wp -wp-model 'Typed+Cast' -wp-rte -wp-prover alt-ergo,z3 -wp-timeout 60 -kernel-warn-key annot-error=abort -cpp-extra-args="-D__FRAMAC__ -Iinclude" <file>`

## Non-goals for the current boundary

The current WP boundary does **not** try to prove:

- authoritative hardware bring-up
- firmware trust
- complete VM-entry/VM-exit assembly behavior
- producer claims about certification or production readiness

Those require either stronger hardware evidence, smaller proof-friendly helper boundaries, or both.
