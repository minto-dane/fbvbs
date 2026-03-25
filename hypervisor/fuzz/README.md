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

- The repository ships the harness sources and `make -C hypervisor fuzz-build`.
- Seed corpora, dictionaries, and continuous fuzzing infrastructure are not yet committed here.
- Fuzz results are supporting evidence, not a substitute for proof obligations or hardware validation.

## Usage

Build all harnesses:

```bash
cd hypervisor
make fuzz-build
```

The resulting binaries are placed in `hypervisor/build/`.
