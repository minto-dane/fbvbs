# Hardware Validation Campaign

This document defines the producer-facing hardware validation campaign for the standalone retained-C microhypervisor in `hypervisor/`.

It does not claim that the wider FBVBS service stack is complete.

## Scope

This campaign is the minimum evidence set needed before calling the standalone microhypervisor release-ready on real Intel or AMD platforms.

The repository-local QEMU smoke path is necessary but not sufficient. It now has three preparatory stages:

1. Stage 1: QEMU/TCG boot-to-gate with `intel-iommu`
2. Stage 2: local QEMU/KVM boot-to-gate when `/dev/kvm` and passwordless `sudo` are available
3. Stage 3: q35 `intel-iommu` / `amd-iommu` emulation matrix for MMIO/programming-order and fail-closed replay

These stages only demonstrate boot, retained-C initialization, expected fail-closed platform gates, and emulated IOMMU programming order.

## Platforms

### Intel campaign

- CPU with VMX, EPT, INVPCID, XSAVES, IBRS/IBPB-capable microcode
- VT-d capable chipset with interrupt remapping
- Secure Boot capable firmware
- usable COM1/UART or BMC/SOL capture path

### AMD campaign

- CPU with SVM, NPT, INVLPGA/flush support as required by the build
- AMD-Vi capable platform with interrupt remapping support where available
- Secure Boot capable firmware
- usable COM1/UART or BMC/SOL capture path

## Required test matrix

### Boot and retained-C foundation

1. Boot the release ISO on target hardware.
2. Confirm the audit/OOB path captures `boot64 reached`, boot artifact materialization, boot catalog ingest, and host partition seed.
3. Confirm the system stops fail-closed if VMX/SVM, IOMMU, or measured-boot prerequisites are absent from the selected deployment profile.

### Host deprivilege handoff

1. Exercise the end-to-end `fbvbs_deprivilege_host()` path.
2. Capture evidence that `VMLAUNCH` succeeds on supported hardware and that the runtime host-deprivilege flag reflects the completed handoff.
3. Inject at least one controlled VM exit and show the handler returns through the documented exit path instead of the pre-launch fail-closed path.

### IOMMU and DMA isolation

1. Confirm DMAR/IVRS parsing against the real firmware tables.
2. Confirm translation enable, interrupt-remap enable, and fault monitoring on the target IOMMU implementation.
3. Confirm the default host-wide device/domain policy is installed before any release claim.
4. Confirm a deliberately invalid DMA configuration is rejected or faulted.
5. Preserve the MMIO programming log and resulting capability state in the evidence bundle.

### Partition lifecycle

1. Create, measure, load, and start a partition using the retained-C fixed ELF64 `ET_EXEC` profile.
2. Confirm `PARTITION_LOAD_IMAGE` rejects profile, manifest, `entry_ip`, and stack-permission mismatches.
3. Confirm destroy/unmap/write paths invalidate approved measurement state as designed.

### Audit path

1. Capture committed audit records from the primary COM1/UART or equivalent OOB collector.
2. Confirm mirror-ring records match the serialized primary path for the sampled events.
3. Preserve raw collector output with wall-clock timestamps.

## Evidence bundle

The release candidate must archive at least:

- serial/OOB capture logs
- firmware configuration export or screenshots
- CPU/IOMMU capability dump
- retained-C release manifest
- release readiness JSON
- provenance JSON
- proof logs
- fault-injection notes for any fail-closed cases

## Exit criteria

The standalone microhypervisor is not producer-facing release-ready until:

- Intel and AMD target campaigns each complete on at least one supported platform
- the host deprivilege handoff is demonstrated on real hardware
- authoritative IOMMU policy is demonstrated on real hardware
- the archived evidence is linked from the release manifest or release notes

## Current status

Repository-local QEMU evidence exists.

Real-hardware Intel/AMD validation remains a release blocker.
