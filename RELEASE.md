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

Then evaluate proof status separately:

```bash
make -C hypervisor proof
```

## Required Artifacts

- static-analysis results
- unit-test results
- fuzz-build results
- coverage outputs
- traceability output
- reproducibility manifests
- SBOM
- `fbvbs-baremetal.elf`
- `fbvbs-baremetal.iso`
- QEMU smoke log
- local QEMU/KVM smoke log when `/dev/kvm` and passwordless `sudo` are available

## Current Hard Blockers To Call Out Honestly

- the repository QEMU/TCG smoke and the local QEMU/KVM smoke currently validate boot-to-gate behavior, not a full VMX-capable launch path
- authoritative IOMMU and boot-integrity bring-up are still fail-closed
- `KCI_SET_WX` byte-backed binding is still incomplete
- `PARTITION_LOAD_IMAGE` still fails closed until the retained-C build has an authoritative image loader/materializer
- host deprivilege / `VMLAUNCH` end-to-end handoff is still incomplete
- Frama-C/WP still has proof gaps, warnings, and timeouts
