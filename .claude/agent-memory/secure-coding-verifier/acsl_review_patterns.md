---
name: ACSL and Security Review Patterns in FBVBS
description: Common ACSL annotation issues, page allocator leak patterns, and security findings across FBVBS hypervisor C sources
type: feedback
---

## ACSL Contract Issues Found

1. **`assigns \nothing` on functions that modify file-scope static arrays** — amd_npt.c public API functions (add_kld_module, remove_kld_module, handle_fault_exit, handle_invlpg_exit) all claim `assigns \nothing` but modify `npt_partitions[]` static array through pointers. Same pattern in hlat.c. Frama-C WP may silently accept due to Typed model not tracking the static array.

2. **`ensures \result == 0` when function can return -1** — amd_npt.c `fbvbs_npt_handle_invlpg_exit` claims result is always 0 but returns -1 on partition-not-found.

3. **Nullable pointer `assigns` and `\valid_read` for length-0** — previously found in partition.c (see prior memory).

## Page Allocator Leak Patterns

Most common bug pattern in FBVBS: multi-step page allocation where intermediate failure paths don't free earlier allocations.

- **Good pattern (hlat.c init):** Reverse-order free on each failure: if alloc N fails, free allocs N-1..0.
- **Bad pattern (iommu_vtd.c, iommu_amdvi.c):** Loop allocates pages per-unit, but failure in later steps (enable, root table set) leaks pages from current and all prior iterations.
- **CRITICAL — Bad pattern (vmx_controls.c CET):** Alloc failure returns success (fail-open). This enables CET control bits without a backing SSP page, resulting in undefined behavior on shadow stack operations and potential security bypass.

## Integer Overflow Check Consistency

- amd_npt.c `fbvbs_npt_add_code_region` correctly checks `linear_base > UINT64_MAX - size` before computing end address.
- hlat.c `fbvbs_hlat_add_region` does NOT check — computes `linear_base + size` directly, which wraps for kernel-high addresses.
- Whenever two functions implement the same semantic operation (add region), both must have the same overflow guards.

## Concurrency Considerations

- File-scope static arrays (`npt_partitions[]`, `hlat_partitions[]`) accessed from both init and runtime fault handlers — no locking documented.
- MSR bitmap static in vmx_controls.c is correctly annotated as single-threaded init path.

## Boot Integrity

- `boot_guard_active` is never set on any code path (MSR 0x13A documented but not read). Fail-closed but overly restrictive on Intel Boot Guard platforms.
- Measured boot requires DRTM + TPM + (Secure Boot OR Boot Guard) — three-factor AND gate.

## Current Release Boundary Notes

- `proof-smoke` is the bounded regression gate. It must stay free of fatal annotation/user errors, missing-spec/default-assigns regressions, incompatible-pointer-cast regressions, and Missing RTE guards.
- `proof-shards` is now the heavier repository-local proof evidence. Treat shard `status=0` as the current software-only target, but do not overclaim it as a complete end-to-end proof of the standalone release.
- QEMU evidence is now staged:
  - Stage 1: QEMU/TCG boot-to-gate smoke (`tcg-intel-iommu`)
  - Stage 2: local QEMU/KVM boot-to-gate smoke when `/dev/kvm` and passwordless `sudo` are available (`kvm-intel-iommu`)
  - Stage 3: q35 IOMMU emulation matrix (`tcg-intel-iommu` + `tcg-amd-iommu`, with optional KVM replay)
- QEMU stage evidence is useful for boot, ACPI/DMAR/IVRS parsing, fail-closed gating, and MMIO/programming order. It is not authoritative evidence for real DMA isolation, interrupt remapping, host deprivilege completion, or final producer-facing release readiness.
