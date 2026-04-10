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
- `src/platform/vmx.c`
- `src/memory.c`
- `src/memory_utils.c`
- `src/core/scaling.c`
- `src/freestanding_runtime.c`
- `src/log.c`
- `src/vm_policy.c`
- `src/platform/boot_multiboot.c`
- `src/watchdog.c`
- `src/platform/early_init.c`
- `src/platform/acpi.c`
- `src/platform/apic.c`
- `src/platform/idt.c`
- `src/platform/vmx_controls.c`
- `src/platform/vmcs_setup.c`
- `src/kernel.c`
- `src/command.c`
- `src/security.c`
- `src/partition.c`
- `src/page_alloc.c`
- `src/platform/hlat.c`
- `src/platform/amd_npt.c`
- `src/platform/mp_init.c`
- `src/storage/storage_virtualization.c`
- `src/io/vcd_virtualization.c`

### Why these files are in scope

- `cpu_security.c`
  - mostly bounded feature-detection and mitigation synthesis logic
- `vmx.c`
  - compact VMX leaf/control logic, despite remaining union-model warnings
- `memory.c`
  - EPT state transitions and rollback logic are security-critical and mostly proof-shaped
- `memory_utils.c`
  - byte helpers, constant-time comparisons, and SHA-384 primitives now carry enough ACSL structure to participate in standalone WP without fatal annotation noise
- `core/scaling.c`
  - runtime resource limit state machine and bound checks
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
- `storage/storage_virtualization.c`
  - storage pool / virtual disk lifecycle logic is verified via `__FRAMAC__` proof model for state transitions and argument contracts
- `io/vcd_virtualization.c`
  - VCD attach/status fail-closed behavior is verified via `__FRAMAC__` proof model

## Files intentionally out of scope today

### Excluded because they are platform or hardware dominated

- `src/platform/iommu_vtd.c`
- `src/platform/iommu_amdvi.c`
- `src/uefi_entry.c`

Reasons include:

- MMIO/MSR/VMCS operations
- firmware-owned memory scanning
- larger proof-hostile unions and architecture-specific encodings
- model-only or partial implementations where fail-closed behavior matters more than raw proof coverage count

## Current proof state

All 26 WP target files achieve **0 timeout / 0 missing specification blocker** in the latest `make -C hypervisor proof-shards` run.

Verification command: `make -C hypervisor proof-shards`

## Divergence inventory

`__FRAMAC__` 分岐の inventory と divergence classification は
`make -C hypervisor semantic-drift-check` で生成する
`build/verification/framac-divergence-report.json` /
`build/verification/framac-divergence-report.md` を補助証跡として扱う。

classification は次の 3 区分を使う。

- `hardware-dependent-only`
  - hardware interaction を proof-side model へ隔離したもの
- `acceptable-stub`
  - `SYNC` marker 等で production との対応が追える許容 stub
- `forbidden-divergence`
  - `SYNC` 欠落や size guard 欠落により drift が release gate を破るもの

release 判断では proof pass/fail だけでなく、この divergence report も参照する。

## Non-goals for the current boundary

The current WP boundary does **not** try to prove:

- authoritative hardware bring-up
- firmware trust
- complete VM-entry/VM-exit assembly behavior
- producer claims about certification or production readiness

Those require either stronger hardware evidence, smaller proof-friendly helper boundaries, or both.
