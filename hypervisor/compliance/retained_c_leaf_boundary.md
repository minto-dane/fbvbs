# Retained C Implementation Assurance

## Scope

This document covers the retained C boundary that remains inside the microhypervisor:

- `hypervisor/src/vmx.c`
- `hypervisor/src/vm_policy.c`
- `hypervisor/src/partition.c`
- `hypervisor/src/command.c`
- `hypervisor/src/security.c`
- `hypervisor/src/memory.c`
- `hypervisor/src/memory_utils.c`
- `hypervisor/src/freestanding_runtime.c`
- `hypervisor/src/log.c`
- `hypervisor/src/watchdog.c`
- `hypervisor/src/early_init.c`
- `hypervisor/src/acpi.c`
- `hypervisor/src/apic.c`
- `hypervisor/src/idt.c`
- `hypervisor/src/vmx_controls.c`
- `hypervisor/src/vmcs_setup.c`
- `hypervisor/src/kernel.c`
- `hypervisor/src/cpu_security.c`
- `hypervisor/src/boot_multiboot.c`
- `hypervisor/src/page_alloc.c`
- `hypervisor/src/hlat.c`
- `hypervisor/src/amd_npt.c`
- `hypervisor/src/mp_init.c`

The scope is intentionally narrower than a production-assurance claim. It documents what the repository can currently show, and which features are deliberately gated off instead of being overclaimed.

## Enforced subset

The repository-enforced subset is MISRA C-oriented and CERT C-oriented:

- C11 with `-std=c11`
- warnings as errors
- conversion and sign-conversion warnings
- strict prototypes and missing-prototype warnings
- shadow and undef warnings
- GCC `-fanalyzer`
- fixed-width integer types for exported ABI structures
- `_Static_assert` layout checks on public ABI structures
- no dynamic allocation in the retained VMX leaf path
- host-side verification builds must not execute privileged MSR instructions; retained-C userspace test/coverage/fuzz paths use a bounded software MSR model while bare-metal keeps architectural MSR access

## Current machine-checkable evidence

The repository currently exposes these executable checks:

- `make -C hypervisor analyze`
  - builds all retained C sources with GCC `-fanalyzer`
- `make -C hypervisor test`
  - runs `fbvbs_leaf_boundary_tests`
  - runs `fbvbs_policy_security_tests`
  - runs `fbvbs_fault_injection_tests`
- `make -C hypervisor coverage`
  - rebuilds and runs the leaf-boundary, policy-security, and fault-injection suites with gcov instrumentation
  - emits branch/line summaries for `partition.c`, `security.c`, `command.c`, `log.c`, `vm_policy.c`, `vmx.c`, `watchdog.c`, and `memory.c`
  - rejects `0.00%` line/branch coverage regressions for the retained trust-boundary trio `command.c`, `vm_policy.c`, and `vmx.c`
  - current repository-local run: `command.c` 24.44% lines / 57.62% branches executed, `vm_policy.c` 67.34% / 59.32%, `vmx.c` 95.00% / 100.00%
  - current local snapshot: `command.c` 24.44% lines / 57.62% branches, `vm_policy.c` 67.34% / 59.32%, `vmx.c` 95.00% / 100.00%
- `make -C hypervisor frama-c-wp`
  - prefers the `opam` Frama-C installation when available
  - all 23 WP target files achieve 100% proved goals with 0 timeouts in per-file verification (14,436 / 14,436 goals, Alt-Ergo + Z3, 60s timeout)
  - verified 2026-03-30; full results table in `compliance/wp_verification_boundary.md`
- `make -C hypervisor proof-smoke`
  - bounded proof gate used by `release-hypervisor`
  - confirms that WP launches and reaches proof scheduling without fatal annotation or user errors
  - rejects regression of previously removed `No default assigns clause`, missing-spec, and incompatible-pointer-cast warning classes
- `make -C hypervisor fuzz-smoke`
  - runs the committed hex seed corpus against all repository-local standalone fuzz harnesses
  - writes a replayable summary to `build/fuzz-smoke.txt`
- `make -C hypervisor baremetal-iso`
  - builds a Multiboot2 bare-metal ELF and GRUB ISO
- `make -C hypervisor run-qemu-smoke`
  - Stage 1 repository-local evidence: boots the Multiboot2 image under QEMU/TCG with `intel-iommu` emulation and checks for retained-C init reaching either successful initialization or an explicit fail-closed platform gate
- `make -C hypervisor run-qemu-kvm-smoke`
  - Stage 2 repository-local evidence: when `/dev/kvm` and passwordless `sudo` are available, boots the same image under QEMU/KVM and checks for the same retained-C init boundary
- `make -C hypervisor run-qemu-iommu-smoke`
  - Stage 3 repository-local evidence: replays the boot-to-gate path against both q35 `intel-iommu` and q35 `amd-iommu` device emulation
- `make -C hypervisor run-qemu-matrix`
  - writes a replayable stage summary and per-case logs for Stage 1 through Stage 3 repository-local QEMU evidence

No repository-local placeholder scripts are treated as evidence.

## ACSL coverage

Externally visible retained C functions are annotated with ACSL contracts:

- `requires` for pointer validity, range constraints, and state preconditions
- `ensures` for return codes and state transitions
- `assigns` for frame conditions
- `behaviors` for multi-outcome functions
- `loop invariant`, `loop assigns`, `loop variant` for all bounded loops

Assembly wrappers in `hypervisor/include/fbvbs_asm.h` carry ACSL contracts (`assigns`, `ensures`) so that callers' frame conditions resolve without timeouts.

All 23 WP target files achieve full proof discharge under per-file Frama-C WP verification (Typed+Cast model, -wp-rte, Alt-Ergo + Z3, 60s timeout).

## Fail-Closed boundaries

The current retained C implementation either refuses success outright or narrows itself to a fixed subset until the required security evidence exists:

- `PARTITION_LOAD_IMAGE`
  - retained-C implements a fixed ELF64 `ET_EXEC` loader that materializes authoritative `image_object_id` and asserts `Loaded`
  - non-executable entry segment, non-writable stack page, executable stack page, manifest/profile mismatch, non-authoritative/missing image object are rejected fail-closed
- `VM_ASSIGN_DEVICE` and `VM_RELEASE_DEVICE`
  - passthrough is disabled because authoritative ACS validation, interrupt remapping control, and safe reset/FLR are not implemented
- `fbvbs_hypervisor_init`
  - platform initialization fails closed until IOMMU bring-up establishes runtime MMIO/programming evidence and an authoritative host device/domain policy
  - measured boot is tracked as a high-assurance condition and is surfaced through capability/state bits instead of being silently ignored
- `fbvbs_deprivilege_host`
  - VMCS preparation exists, but the final host deprivilege / `VMLAUNCH` handoff still fails closed instead of claiming a runnable VM entry path

These gates are deliberate. They reduce the chance that the retained C model accidentally claims a security property it does not yet enforce.

## Requirement traceability

| Requirement | Current repository evidence | Status |
| --- | --- | --- |
| `FBVBS-REQ-0201` | ACSL annotations, GCC `-fanalyzer`, unit tests, code review | partial |
| `FBVBS-REQ-0904` | passthrough path fails closed instead of claiming unsupported qualification | partial |
| `FBVBS-REQ-1005` | compile and static-analysis gates exist; MC/DC and independent audit do not | not yet achieved |

## Current status

The retained C repository currently demonstrates:

- analyzer-clean builds under GCC `-fanalyzer`
- unit-test and gcov coverage for leaf ABI, hypercall trust-boundary checks, VM policy exits, shared-memory accounting, fail-closed platform gates, fault injection, and selected security invariants
- machine-readable separation between audit-path readiness, retained-C foundation readiness, measured-boot-backed high-assurance readiness, and host deprivilege readiness
- retained-C primary audit sink serialization to the bare-metal FreeBSD serial/UART path, with the same sink modeled in hosted/unit-test builds through an overridable retained-C hook
- host-deprivilege readiness derived from explicit runtime state, not merely compile-time feature intent
- authoritative bare-metal retained boot-artifact binding: the host kernel is bound to immutable loaded hypervisor image bytes and the remaining seeded artifacts are bound to explicit Multiboot modules that are checked during ISO verification
- a retained-C fixed executable loader for authoritative memory-object-backed ELF64 `ET_EXEC` partition-loadable artifacts, including executable-entry and NX-stack validation
- explicit fail-closed behavior where the model cannot yet uphold the design-level guarantee
- ownerless command-page GPAs are rejected before any command-page mutation; the dispatcher resolves command pages only through authenticated partition-owned command-page slots

The retained C repository does not currently demonstrate:

- a broader executable loader profile beyond the retained-C fixed `ET_EXEC` subset (for example `ET_DYN`, runtime relocation, or service autostart orchestration)
- production-ready device passthrough qualification and teardown
- authoritative boot-integrity and IOMMU bring-up
- real DMA isolation, interrupt-remapping correctness, and final host deprivilege completion on real hardware
- production-ready host deprivilege / `VMLAUNCH` handoff

The correct interpretation is therefore: retained C prototype with per-file formal proof discharge, explicit fail-closed security gates, and documented `#ifdef __FRAMAC__` proof-model boundaries — not production-ready certification completion.
