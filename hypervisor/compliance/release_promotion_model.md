# Release Promotion Model

This document defines how the standalone retained-C microhypervisor moves from `dev` to a producer-facing release candidate and then to `main`.

## Branch roles

- `dev`: day-to-day integration branch
- `main`: release-candidate and publication branch for the standalone microhypervisor boundary

## Promotion flow

1. Develop and merge feature work into `dev`.
2. Freeze a release candidate from `dev`.
3. Run the full standalone retained-C release gate.
4. Review release blockers, residual risks, and hardware-validation status.
5. Promote to `main` only if the release packet is complete and approved.

## Required gates before promotion

- `make -C hypervisor analyze`
- `make -C hypervisor test`
- `make -C hypervisor cppcheck`
- `make -C hypervisor fuzz-build`
- `make -C hypervisor fuzz-smoke`
- `make -C hypervisor coverage`
- `make -C hypervisor traceability`
- `make -C hypervisor reproducible`
- `make -C hypervisor sbom`
- `make -C hypervisor provenance`
- `FBVBS_RELEASE_SIGNING_KEY=/path/to/release-key.pem make -C hypervisor sign-release`
- `make -C hypervisor proof-smoke`
- `make -C hypervisor baremetal-iso verify-baremetal-iso`
- `make -C hypervisor run-qemu-smoke`
- `make -C hypervisor run-qemu-iommu-smoke`
- `make -C hypervisor run-qemu-matrix`
- `make -C hypervisor release-readiness`
- `make -C hypervisor release-manifest`
- `make -C hypervisor release-evidence`

Run `make -C hypervisor proof` in addition when the WP boundary changed or when proof debt is being reduced.

## Mandatory review topics

- security review for every code path that can fail open
- hardware validation status against the campaign document
- audit OOB collector readiness for the target environment
- deployment-profile compatibility and unsupported-feature review
- provenance review, including the external signing step required before publication
- detached signature verification for the release packet

## Rollback and stop-ship triggers

Do not promote a release candidate if:

- the release readiness report still claims a new blocker introduced by the candidate
- the hardware validation campaign regressed or is incomplete for the intended release class
- provenance or signing evidence is missing
- release documentation and manifest disagree with the delivered artifacts

## Current status

The repository can generate a retained-C release evidence bundle and machine-readable readiness report.

External signing and real-hardware validation still gate final producer-facing publication.
