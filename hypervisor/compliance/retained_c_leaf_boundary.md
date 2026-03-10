# Retained C Leaf Boundary Assurance

## Scope

This repository's default retained-C trust boundary is intentionally limited to:

- `hypervisor/src/vmx.c`
- `hypervisor/include/fbvbs_leaf_vmx.h`

All higher-level orchestration, policy, validation, lifecycle control, and service semantics remain on the Ada/SPARK side and must continue to converge there.

## Enforced subset

The repository-enforced retained-C subset is MISRA-oriented and CERT-C-oriented, but this document does not claim that the repository alone is a complete third-party MISRA certification package. The enforced local rules for the current leaf are:

- fixed-width integer types only for the exported ABI
- fixed struct layout with `_Static_assert` size and offset checks
- no dynamic allocation
- no recursion
- no global mutable state
- no variadic interfaces
- no libc memory helpers such as `memcpy`, `memmove`, or `memset`
- no `goto`, `union`, `setjmp`, or `longjmp`
- no signed-overflow-dependent logic
- no policy logic, capability logic, or partition lifecycle ownership
- fully initialized output objects before exit classification

## Machine-checkable evidence

The repository contains two mandatory machine-checkable artifacts for the retained-C leaf:

- `python3 hypervisor/tools/check_retained_c_subset.py`
  - checks the default retained-C file set
  - checks include boundaries
  - checks a forbidden-construct subset
  - checks fixed ABI assertions for the public leaf header
- `python3 hypervisor/tools/prove_leaf_vmx_contracts.py`
  - compiles the retained C leaf as a shared object
  - executes null-contract checks
  - exhaustively compares the C implementation against an abstract VMX leaf model over a bounded state space

These artifacts are wired into:

- `make -C hypervisor analyze`
- `make -C hypervisor proof`
- `make -C hypervisor test`

## Requirement traceability

The retained-C leaf evidence currently maps to the frozen design requirements as follows:

| Requirement | Current repository evidence | Status |
| --- | --- | --- |
| `FBVBS-REQ-0201` | scope limited to `vmx.c` + `fbvbs_leaf_vmx.h`, documented safety contract, subset check, bounded proof artifact | partial, repo-local |
| `FBVBS-REQ-1000` | traceability captured in this file plus `plan/about-a-hypervisor-execution.md` | partial, repo-local |
| `FBVBS-REQ-1005` | compiler/static-analysis gates exist, but MC/DC evidence does not yet exist | not yet achieved |

This mapping is intentionally conservative. It records only evidence that is present in the repository now.

## Safety contract

The current C leaf is allowed to do only two things:

- report synthetic VMX capability presence for the modeled host
- classify a bounded VM-exit state into a fixed exit record shape

The current C leaf is not allowed to:

- allocate or free memory
- own capability state
- inspect partition catalogs
- validate host caller identity
- mutate global hypervisor state
- perform command decoding
- own memory-mapping policy

## Verification status and limitation

The current repository now has:

- compiler warnings as errors
- GCC `-fanalyzer`
- a repository-enforced retained-C subset check
- a bounded exhaustive proof-style contract comparison against an abstract model

The current repository still does not yet have:

- an external MISRA C:2023 compliance report
- Frama-C / TrustInSoft / CBMC proof runs
- MC/DC or object-code traceability evidence
- independent coverage and fault-injection campaign results

Those remain required for any final claim that retained C is production-ready within the trusted boundary.
