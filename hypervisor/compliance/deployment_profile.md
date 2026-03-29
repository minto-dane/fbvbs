# Deployment Profile

This document records the supported producer-facing deployment profile for the standalone retained-C microhypervisor.

## Supported release profile

- x86_64 platform
- Secure Boot enabled for the UEFI path when that path is used
- fixed ELF64 `ET_EXEC` retained-C image profile
- IOMMU required
- primary audit collection through COM1/UART or an equivalent OOB serial path
- explicit acceptance that future FBVBS trusted services are out of scope for this standalone release

## Required platform properties

- VMX on Intel or SVM on AMD
- second-level translation support: EPT on Intel, NPT on AMD
- IOMMU support: VT-d on Intel or AMD-Vi on AMD
- interrupt-remapping support for the selected deployment profile
- a trustworthy external collector for the primary audit stream

## Unsupported or out-of-scope configurations

- platforms without IOMMU
- deployments without any OOB audit collector
- dynamic executable profiles such as `ET_DYN`/PIE in the retained-C loader path
- future service-partition orchestration
- device passthrough as a published release feature until authoritative teardown and validation are complete

## Residual-risk deployment restrictions

- LLC/L2/DRAM-bandwidth isolation is not yet closed with Intel CAT or SMT-aware scheduling in this retained-C release profile
- high-assurance deployments should prefer dedicated cores and SMT-off configurations where residual side-channel risk is unacceptable
- measured boot is a stronger assurance profile, not the minimum retained-C foundation gate

## Secure Boot and boot artifacts

- the Multiboot profile must keep the explicit retained boot artifacts in the ISO
- the UEFI path must use signed boot artifacts and firmware key enrollment appropriate to the operator environment
- the retained-C host-kernel artifact binding is authoritative only for the documented build profile

## Operational expectations

- archive the serial/OOB collector output for every release candidate
- keep `release-manifest.txt`, `release-readiness.json`, and `provenance.json` with the delivered artifact set
- do not advertise producer-facing release readiness until the hardware validation campaign is complete
