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
- **Bad pattern (vmx_controls.c CET):** Alloc failure returns success (fail-open) — worse than a leak, it enables CET control bits without backing SSP page.

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
