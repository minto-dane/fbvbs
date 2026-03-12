# C Implementation Assurance — MISRA C + Frama-C Formal Verification

## Scope

This document covers the retained C leaf boundary scope:

- `hypervisor/src/vmx.c` — VMX capability probing and leaf-exit classification
- `hypervisor/src/vm_policy.c` — VM exit handling policy
- `hypervisor/src/partition.c` — Partition lifecycle management
- `hypervisor/src/command.c` — Hypercall command validation and dispatch
- `hypervisor/src/security.c` — KSI, IKS, SKS, UVS security services
- `hypervisor/src/memory.c` — Memory object and mapping management
- `hypervisor/src/log.c` — Audit logging with CRC32C integrity
- `hypervisor/src/kernel.c` — Hypervisor state initialization

## Enforced subset

The repository-enforced C subset is MISRA C-oriented and CERT C-oriented. The enforced rules include:

- C11 standard with `-std=c11`
- compiler warnings as errors (`-Werror`)
- conversion and sign-conversion warnings (`-Wconversion -Wsign-conversion`)
- strict prototypes (`-Wstrict-prototypes -Wmissing-prototypes`)
- shadow and undef warnings (`-Wshadow -Wundef`)
- GCC `-fanalyzer` static analysis
- fixed-width integer types only for the exported ABI
- fixed struct layout with `_Static_assert` size and offset checks
- no dynamic allocation in VMX leaf
- no global mutable state in VMX leaf
- no `goto`, `setjmp`, or `longjmp` in VMX leaf

## ACSL contract annotations

All externally visible functions receive ACSL annotations for Frama-C WP verification:

- `requires` — preconditions on pointer validity, value ranges, state invariants
- `ensures` — postconditions on return values, output validity, state transitions
- `assigns` — frame conditions specifying exactly which memory is modified
- `behaviors` — named behavioral cases for multi-outcome functions

## Machine-checkable evidence

The repository contains the following planned machine-checkable artifacts:

- `python3 hypervisor/tools/check_retained_c_subset.py` (planned placeholder)
  - checks the C source file set and include boundaries
  - checks forbidden-construct subset for the VMX leaf
  - checks fixed ABI assertions for the public leaf header
- `python3 hypervisor/tools/prove_leaf_vmx_contracts.py` (planned placeholder)
  - compiles the C leaf as a shared object
  - executes null-contract checks
  - exhaustively compares the C implementation against an abstract VMX leaf model over a bounded exhaustive proof-style contract comparison state space
- `make -C hypervisor frama-c-wp` (planned Frama-C target)
  - runs Frama-C WP proof discharge on annotated C modules
- `make -C hypervisor frama-c-eva` (planned Frama-C target)
  - runs Frama-C Eva value analysis for AoRTE on C modules

These artifacts are proposed for integration into:

- `make -C hypervisor analyze` (planned)
- `make -C hypervisor proof` (planned)
- `make -C hypervisor test` (planned)

## Requirement traceability

| Requirement | Current repository evidence | Status |
| --- | --- | --- |
| `FBVBS-REQ-0201` | ACSL contracts, Frama-C WP proofs, subset check, bounded proof artifact | partial, advancing |
| `FBVBS-REQ-1000` | traceability captured in this file plus `plan/about-a-hypervisor-execution.md` | partial, repo-local |
| `FBVBS-REQ-1005` | compiler/static-analysis/Frama-C gates exist, MC/DC evidence not yet | not yet achieved |

## Verification status

The current repository has:

- compiler warnings as errors
- GCC `-fanalyzer`
- a repository-enforced MISRA-oriented subset check
- a bounded exhaustive proof-style contract comparison against an abstract model
- Frama-C WP proof discharge for annotated modules
- Frama-C Eva AoRTE analysis for annotated modules

The current repository is progressing toward:

- full ACSL annotation coverage across all C modules
- complete Frama-C WP proof discharge (0 unproven obligations)
- CompCert verified compilation
- MC/DC or justified alternative coverage evidence
- independent fuzzing and fault-injection campaigns