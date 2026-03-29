# Contributing

This repository is split between:

- `hypervisor/`
  - the standalone retained-C microhypervisor that other projects may consume directly
- `plan/`
  - the wider FBVBS stack design, roadmap, and future service phases

Changes that are intended to ship the standalone microhypervisor must keep that boundary explicit.

## Branch Model

- `dev`
  - integration branch for day-to-day development
- `main`
  - release-candidate branch for the standalone microhypervisor and audited repository state

Expected flow:

1. Branch from `dev`
2. Land through pull requests into `dev`
3. Promote from `dev` to `main` only after the release gates and document review pass

## Required Gates

Before proposing a release-facing merge, run:

```bash
make -C hypervisor analyze
make -C hypervisor test
make -C hypervisor cppcheck
make -C hypervisor fuzz-build
make -C hypervisor coverage
make -C hypervisor traceability
make -C hypervisor reproducible
make -C hypervisor sbom
make -C hypervisor provenance
make -C hypervisor run-qemu-smoke
```

Also run `make -C hypervisor proof` when changing ACSL contracts, proof targets, or code in the WP boundary. Proof gaps must be called out explicitly in the change description.

## Hypervisor/Stack Boundary

When editing:

- keep `hypervisor/` buildable and testable on its own
- avoid coupling standalone hypervisor release gates to unimplemented FBVBS service phases
- document any dependency from `hypervisor/` into future FBVBS stack components in `plan/`

## Review Expectations

- security-impacting changes need threat-oriented review notes
- fail-open behavior is not acceptable; use fail-closed defaults and document them
- update compliance and roadmap documents when repository reality changes
- do not overstate proof, fuzzing, certification, or release readiness
