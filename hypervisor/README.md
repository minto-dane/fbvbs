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
make fuzz-smoke
make proof
make proof-smoke
make baremetal-iso
make run-qemu-smoke
make run-qemu-kvm-smoke
make run-qemu-iommu-smoke
make run-qemu-matrix
make provenance
FBVBS_RELEASE_SIGNING_KEY=/path/to/release-key.pem make sign-release
make release-readiness
make release-manifest
make release-evidence
make release-hypervisor
```

## Current Boot Status

The bare-metal Multiboot2 image now has a staged repository-local QEMU path:

- Stage 1: `make run-qemu-smoke` runs the required QEMU/TCG boot-to-gate smoke with Intel VT-d emulation.
- Stage 2: `make run-qemu-kvm-smoke` runs the stricter local QEMU/KVM boot-to-gate smoke when `/dev/kvm` and passwordless `sudo` are available.
- Stage 3: `make run-qemu-iommu-smoke` replays the boot-to-gate path against both q35 `intel-iommu` and `amd-iommu` emulation, and `make run-qemu-matrix` bundles the full repository-local matrix with per-case logs.

In the current development environment, these paths reach `boot64`, boot artifact materialization, boot catalog ingest, and FreeBSD host partition seeding. Environments that do not expose usable VMX still stop fail-closed at `VMX unavailable`. The retained-C audit path now serializes committed records to the primary COM1/UART sink on bare-metal while keeping the mirror ring in memory. The current retained-C boot path also distinguishes:

- foundation readiness: VMX + runtime-ready IOMMU (`fbvbs_platform_foundation_ready`)
- audit runtime readiness: initialized mirror ring plus retained-C primary UART/OOB sink (`fbvbs_audit_runtime_ready`)
- high-assurance foundation readiness: foundation + measured boot (`fbvbs_platform_high_assurance_foundation_ready`)
- host deprivilege readiness: end-to-end `VMLAUNCH` handoff (`fbvbs_host_deprivilege_runtime_ready`)

At boot-artifact level, the bare-metal host kernel artifact is bound to the loaded hypervisor image bytes, and the remaining retained boot artifacts are bound to explicit Multiboot modules via `artifact:0x...` or `fbvbs.object_id=0x...` cmdlines. `make baremetal-iso verify-baremetal-iso` checks that those modules are actually present in the release ISO.

For host-side verification, the retained-C CPU security layer uses a deterministic software MSR model in userspace builds so unit tests, gcov runs, and fuzz harnesses never attempt privileged `RDMSR/WRMSR`. The bare-metal build path still uses real MSR instructions.

## Release Caveat

This directory now has a passing `make release-hypervisor` retained-C foundation gate in the current environment, and that gate now emits `provenance.json`, `release-readiness.json`, `release-evidence.tar.gz`, the staged QEMU summaries, and per-case QEMU logs. Detached signatures can be added with `make sign-release` once operator key material is available. It is still not a fully closed high-assurance release while proof gaps, authoritative hardware bring-up gaps, and host deprivilege handoff remain.

The coverage gate now includes the leaf-boundary suite in addition to policy-security and fault-injection suites, rejects zero line/branch coverage regressions for `command.c`, `vm_policy.c`, and `vmx.c`, and currently reaches 24.44%/57.62% (`command.c`), 67.34%/59.32% (`vm_policy.c`), and 95.00%/100.00% (`vmx.c`) line/branch execution in the repository-local run.
