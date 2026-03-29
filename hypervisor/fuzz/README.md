# FBVBS Fuzz Harnesses

This directory contains repository-local fuzz entry points for the retained C microhypervisor.

## Harnesses

- `fuzz_command_page.c`
  - exercises command-page parsing and dispatch preconditions
  - current limitation: single-threaded model, so inter-CPU TOCTOU is out of scope
- `fuzz_manifest.c`
  - stresses manifest/profile/artifact validation paths
- `fuzz_multiboot2.c`
  - stresses Multiboot2 tag parsing and bounds handling
- `fuzz_iommu.c`
  - stresses DMAR/IVRS table parsing and bounded IOMMU discovery logic
- `fuzz_log_decoder.c`
  - stresses audit-log ring initialization, append paths, CRC handling,
    and mirror-info queries
- `fuzz_partition_loader.c`
  - stresses the retained-C fixed ELF64 `ET_EXEC` partition loader,
    including manifest/profile binding, segment validation, and cleanup

## Current status

- The repository ships the harness sources, committed seed corpora under `fuzz/corpus/`, `make -C hypervisor fuzz-build`, and `make -C hypervisor fuzz-smoke`.
- The committed smoke corpus is intentionally small and deterministic; long-running AFL++/libFuzzer campaigns remain complementary external evidence.
- Fuzz results are supporting evidence, not a substitute for proof obligations or hardware validation.

## Usage

Build all harnesses:

```bash
cd hypervisor
make fuzz-build
make fuzz-smoke
```

The resulting binaries are placed in `hypervisor/build/`. `make fuzz-smoke` writes a replayable summary to `hypervisor/build/fuzz-smoke.txt`.
