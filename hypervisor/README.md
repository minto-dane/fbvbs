# Standalone Microhypervisor Boundary

This directory is the producer-facing retained-C microhypervisor component.

It is intentionally narrower than the full FBVBS stack:

- included here: buildable hypervisor core, bare-metal boot path, tests, fuzz harnesses, compliance notes
- not included here: future trusted service partitions, FreeBSD frontend, bhyve/vmm integration

## Main Commands

```bash
make analyze
make test
make coverage
make cppcheck
make fuzz-build
make proof
make proof-smoke
make baremetal-iso
make run-qemu-smoke
make run-qemu-kvm-smoke
make release-manifest
make release-hypervisor
```

## Current Boot Status

The bare-metal Multiboot2 image boots under both QEMU/TCG and the local QEMU/KVM smoke path through `boot64`, boot artifact materialization, boot catalog ingest, and FreeBSD host partition seeding. In the current development environment, neither path exposes usable VMX to the guest, so initialization stops fail-closed at `VMX unavailable`. The current retained-C boot path also distinguishes:

- foundation readiness: VMX + runtime-ready IOMMU (`fbvbs_platform_foundation_ready`)
- audit runtime readiness: initialized primary/mirror audit path (`fbvbs_audit_runtime_ready`)
- high-assurance foundation readiness: foundation + measured boot (`fbvbs_platform_high_assurance_foundation_ready`)
- host deprivilege readiness: end-to-end `VMLAUNCH` handoff (`fbvbs_host_deprivilege_runtime_ready`)

At boot-artifact level, the bare-metal host kernel artifact is bound to the loaded hypervisor image bytes, and the remaining retained boot artifacts are bound to explicit Multiboot modules via `artifact:0x...` or `fbvbs.object_id=0x...` cmdlines. `make baremetal-iso verify-baremetal-iso` checks that those modules are actually present in the release ISO.

For host-side verification, the retained-C CPU security layer uses a deterministic software MSR model in userspace builds so unit tests, gcov runs, and fuzz harnesses never attempt privileged `RDMSR/WRMSR`. The bare-metal build path still uses real MSR instructions.

## Release Caveat

This directory now has a passing `make release-hypervisor` retained-C foundation gate in the current environment, but it is not yet a fully closed high-assurance release while proof gaps, authoritative hardware bring-up gaps, and host deprivilege handoff remain.

The coverage gate now includes the leaf-boundary suite in addition to policy-security and fault-injection suites, rejects zero line/branch coverage regressions for `command.c`, `vm_policy.c`, and `vmx.c`, and currently reaches 24.44%/57.62% (`command.c`), 67.34%/59.32% (`vm_policy.c`), and 95.00%/100.00% (`vmx.c`) line/branch execution in the repository-local run.
