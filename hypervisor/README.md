# Standalone Microhypervisor Boundary

This directory is the producer-facing retained-C microhypervisor component.

It is intentionally narrower than the full FBVBS stack:

- included here: buildable hypervisor core, bare-metal boot path, tests, fuzz harnesses, compliance notes
- not included here: future trusted service partitions, FreeBSD frontend, bhyve/vmm integration

## Main Commands

```bash
make analyze
make test
make cppcheck
make fuzz-build
make proof
make baremetal-iso
make run-qemu-smoke
make run-qemu-kvm-smoke
make release-hypervisor
```

## Current Boot Status

The bare-metal Multiboot2 image boots under both QEMU/TCG and the local QEMU/KVM smoke path through `boot64` and retained-C initialization. In the current development environment, neither path exposes usable VMX to the guest, so initialization stops fail-closed at `VMX unavailable`. On richer platforms the next expected gates are IOMMU and boot-integrity bring-up.

## Release Caveat

This directory is closer to a standalone releasable component than the rest of the FBVBS stack, but it is not yet a fully closed high-assurance release while proof gaps, authoritative hardware bring-up gaps, and the retained-C image loader/materializer gap remain.
