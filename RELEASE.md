# Release Guide

This file covers producer-facing releases of the standalone microhypervisor in `hypervisor/`.

It does not claim that the wider FBVBS trusted-service stack is complete.

## Release Boundary

Included in this release boundary:

- `hypervisor/`
- root repository controls needed to build, test, verify, and archive the hypervisor

Explicitly out of scope for a standalone microhypervisor release:

- future FBVBS trusted services (KCI/KSI/IKS/SKS/UVS service partitions)
- FreeBSD frontend and bhyve/vmm integration phases
- licensing decisions

## Release Gates

Run:

```bash
make -C hypervisor release-hypervisor
```

For a longer proof run, evaluate proof status separately:

```bash
make -C hypervisor proof
```

`release-hypervisor` now includes `proof-smoke`, which confirms that WP launches and reaches proof scheduling without fatal annotation or user errors, and rejects regression of the previously removed `default assigns`, `missing specification`, and incompatible-pointer-cast warning classes.

In the current development environment, `make -C hypervisor release-hypervisor` completes successfully and archives the retained-C foundation evidence set. This is a retained-C foundation release gate, not evidence that the wider FBVBS stack or the high-assurance end-state is complete.

## Required Artifacts

- static-analysis results
- unit-test results
- fuzz-build results
- coverage outputs
  - `make -C hypervisor coverage` now runs leaf-boundary, policy-security, and fault-injection suites
  - the bounded gate rejects `0.00%` line/branch coverage regressions for `command.c`, `vm_policy.c`, and `vmx.c`
  - current repository-local run reached non-zero retained-boundary coverage for those files (`command.c` 24.44% lines / 57.62% branches executed, `vm_policy.c` 67.34% / 59.32%, `vmx.c` 95.00% / 100.00%)
  - current local snapshot: `command.c` 24.44% lines / 57.62% branches, `vm_policy.c` 67.34% / 59.32%, `vmx.c` 95.00% / 100.00%
- traceability output
- reproducibility manifests
- SBOM
- release manifest (`build/release-manifest.txt`)
- `fbvbs-baremetal.elf`
- `fbvbs-baremetal.iso`
- QEMU smoke log
- local QEMU/KVM smoke log when `/dev/kvm` and passwordless `sudo` are available

## Current Hard Blockers To Call Out Honestly

- the repository QEMU/TCG smoke and the local QEMU/KVM smoke currently validate boot-to-gate behavior, not a full VMX-capable launch path
- the retained-C foundation gate now includes Multiboot parsing, boot artifact materialization, boot catalog ingest, and FreeBSD host partition seeding before the expected fail-closed platform gate
- authoritative IOMMU bring-up is still fail-closed outside the retained-C parser/MMIO model boundary
- measured boot is surfaced as a high-assurance condition, not as a prerequisite for the retained-C foundation release path
- retained-C foundation readiness now means VMX + runtime-ready IOMMU + initialized audit path; host deprivilege remains a stricter separate gate
- host deprivilege readiness is advertised only after a completed runtime handoff, not merely because VMX exists or a build flag is enabled
- host-side unit-test / coverage / fuzz builds now use a deterministic MSR software model instead of executing privileged `RDMSR/WRMSR`; bare-metal builds still use the architectural instructions
- `PARTITION_LOAD_IMAGE` is now implemented for the retained-C fixed ELF64 `ET_EXEC` profile and requires an authoritative `image_object_id`; broader loader profiles such as `ET_DYN`, runtime relocation, and service autostart orchestration remain out of scope for this standalone release
- the bare-metal retained boot artifact set is authoritative in the release profile: the host kernel is bound to immutable loaded image bytes and the remaining seeded artifacts must be present as explicit Multiboot modules; synthetic artifact builders remain test-only and out of release scope
- host deprivilege / `VMLAUNCH` end-to-end handoff is still incomplete
- Frama-C/WP still has proof gaps, especially `vmx.c` Typed+Cast union warnings, Missing RTE guards, and timeouts

## Current Machine-Readable Platform States

- `CAP_BITMAP1_IOMMU`: runtime-ready IOMMU evidence was established
- `CAP_BITMAP1_MEASURED_BOOT`: measured boot evidence was established
- `CAP_BITMAP1_FOUNDATION_READY`: retained-C foundation gates are satisfied (VMX + runtime-ready IOMMU + initialized audit path)
- `CAP_BITMAP1_HIGH_ASSURANCE_FOUNDATION`: retained-C foundation + measured boot are satisfied
- `CAP_BITMAP1_HOST_DEPRIVILEGE`: end-to-end host deprivilege handoff is available
