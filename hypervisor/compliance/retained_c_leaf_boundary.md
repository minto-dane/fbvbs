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
- `hypervisor/src/log.c`
- `hypervisor/src/kernel.c`
- `hypervisor/src/cpu_security.c`
- `hypervisor/src/boot_multiboot.c`

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

## Current machine-checkable evidence

The repository currently exposes these executable checks:

- `make -C hypervisor analyze`
  - builds all retained C sources with GCC `-fanalyzer`
- `make -C hypervisor test`
  - runs `fbvbs_leaf_boundary_tests`
  - runs `fbvbs_policy_security_tests`
- `make -C hypervisor frama-c-wp`
  - runs Frama-C WP only when the WP plugin is installed
  - in the current environment this target exits with `Frama-C WP plugin is not installed in this environment.`

No repository-local placeholder scripts are treated as evidence.

## ACSL coverage

Externally visible retained C functions are annotated with ACSL contracts where practical:

- `requires` for pointer validity, range constraints, and state preconditions
- `ensures` for return codes and state transitions
- `assigns` for frame conditions
- `behaviors` for multi-outcome functions

Annotation presence does not by itself imply full proof discharge in the current environment.

## Fail-Closed boundaries

The current retained C implementation intentionally refuses success in several areas until the required security evidence exists:

- `KCI_SET_WX`
  - execute permission is not granted because artifact bytes are not yet cryptographically bound to the target GPA range in the retained C model
- `VM_ASSIGN_DEVICE` and `VM_RELEASE_DEVICE`
  - passthrough is disabled because authoritative ACS validation, interrupt remapping control, and safe reset/FLR are not implemented
- `fbvbs_hypervisor_init`
  - platform initialization fails closed until IOMMU and boot-integrity bring-up provide authoritative evidence instead of model-only detection

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
- unit-test coverage for leaf ABI, policy boundaries, shared-memory accounting, fail-closed platform gates, and selected security invariants
- explicit fail-closed behavior where the model cannot yet uphold the design-level guarantee

The retained C repository does not currently demonstrate:

- a complete Frama-C WP proof run in this environment
- production-ready `KCI_SET_WX` page binding
- production-ready device passthrough qualification and teardown
- authoritative boot-integrity and IOMMU bring-up

The correct interpretation is therefore: retained C prototype with explicit fail-closed security gates, not production-ready formal completion.
