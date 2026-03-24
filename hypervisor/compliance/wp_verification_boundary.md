# FBVBS WP Verification Boundary

**Date:** 2026-03-23
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
- `src/log.c`
- `src/vm_policy.c`
- `src/kernel.c`
- `src/command.c`
- `src/security.c`
- `src/partition.c`
- `src/page_alloc.c`

### Why these files are in scope

- `cpu_security.c`
  - mostly bounded feature-detection and mitigation synthesis logic
- `vmx.c`
  - compact VMX leaf/control logic, despite remaining union-model warnings
- `memory.c`
  - EPT state transitions and rollback logic are security-critical and mostly proof-shaped
- `log.c`
  - audit-log state machine is compact and bounded
- `vm_policy.c`
  - exit-policy enforcement is central to hypervisor correctness
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

## Files intentionally out of scope today

### Excluded because they are proof-hostile byte/cast utilities

- `src/memory_utils.c`
  - raw byte-copy/zero helpers and constant-time utility patterns
- `src/boot_multiboot.c`
  - raw Multiboot2 binary parsing over attacker-controlled byte buffers
- `src/freestanding_runtime.c`
  - bare-metal-only freestanding runtime glue and serial console primitives that are outside the hosted retained-C proof boundary

These are still analyzer-tested and fuzz-tested, but they are not yet a good fit for the current WP model boundary.

### Excluded because they are platform or hardware dominated

- `src/acpi.c`
- `src/iommu_vtd.c`
- `src/iommu_amdvi.c`
- `src/early_init.c`
- `src/uefi_entry.c`
- `src/vmcs_setup.c`
- `src/vmx_controls.c`
- `src/hlat.c`
- `src/amd_npt.c`
- `src/watchdog.c`
- `src/apic.c`
- `src/idt.c`
- `src/mp_init.c`

Reasons include:

- MMIO/MSR/VMCS operations
- firmware-owned memory scanning
- AP bring-up and interrupt state
- larger proof-hostile unions and architecture-specific encodings
- model-only or partial implementations where fail-closed behavior matters more than raw proof coverage count

## Current proof state

`make -C hypervisor proof` now launches Frama-C WP successfully in this environment, but it does **not** close cleanly yet.

The current known gaps include:

- missing-spec warnings for some excluded helper interfaces
- missing/default assigns warnings
- `Typed+Cast` and union-model warnings in `vmx.c`, `vm_policy.c`, `log.c`, `partition.c`, and `kernel.c`
- proof timeouts during larger aggregate runs

So the current repository state is:

- **WP boundary defined and meaningful**
- **proof execution available**
- **proof completion still incomplete**

## Next expansion candidates

These are the most credible next candidates for incremental proof expansion after refactoring:

- proof-friendly helper subsets from `amd_npt.c`
- proof-friendly helper subsets from `hlat.c`
- bounded ACPI/MP parser helpers isolated out of `acpi.c` / `mp_init.c`
- further shrinking of typed-cast boundaries in `command.c`

## Non-goals for the current boundary

The current WP boundary does **not** try to prove:

- authoritative hardware bring-up
- firmware trust
- complete VM-entry/VM-exit assembly behavior
- producer claims about certification or production readiness

Those require either stronger hardware evidence, smaller proof-friendly helper boundaries, or both.
