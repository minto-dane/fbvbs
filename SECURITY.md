# Security Policy

## Scope

Security reports should clearly state whether the issue affects:

- the standalone microhypervisor in `hypervisor/`
- the wider FBVBS stack described under `plan/`

Please include:

- affected files and functions
- trigger conditions
- whether the issue is fail-open, fail-closed, integrity-only, availability-only, or confidentiality-impacting
- whether QEMU, host tests, or proof tooling can reproduce it

## Reporting

For suspected high-severity vulnerabilities, avoid filing a public issue first. Share a private report with the project maintainers through the repository security-contact mechanism or direct maintainer contact.

## Expectations

- security fixes must include regression coverage when practical
- repository documents must be updated if implementation reality changes
- “proof complete”, “production-ready”, or similar claims must be supported by current reproducible evidence
