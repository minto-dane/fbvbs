# FBVBS Device Qualification Matrix

**Requirements:** REQ-0352 (DMA remapping), REQ-0904 (device assignment safety), REQ-1105 (passthrough qualification)

## Qualification Criteria

A device MUST satisfy Q1, Q2, and Q4-Q8 before assignment to a guest VM.
Q3 is recommended but not mandatory; devices without MSI-X may still be
assigned, but interrupt isolation is weaker.

| # | Criterion | Field | Required Value | Rationale |
|---|-----------|-------|----------------|-----------|
| Q1 | ACS Capability | `has_acs` | 1 | Prevents peer-to-peer DMA bypass between assigned devices |
| Q2 | FLR Support | `has_flr` | 1 | Required for clean device reset on reassignment or partition teardown |
| Q3 | MSI-X Capability | `has_msix` | recommended | Interrupt isolation; MSI without MSI-X may share vectors. Devices without MSI-X can still be assigned but have weaker interrupt isolation. |
| Q4 | ACS Source Validation | `acs_ctrl & ACS_SV` | Set | Validates requester ID on upstream port |
| Q5 | ACS Translation Blocking | `acs_ctrl & ACS_TB` | Set | Blocks translated requests without IOMMU |
| Q6 | ACS P2P Request Redirect | `acs_ctrl & ACS_RR` | Set | Redirects peer-to-peer through IOMMU |
| Q7 | ACS P2P Completion Redirect | `acs_ctrl & ACS_CR` | Set | Redirects completions through IOMMU |
| Q8 | Qualified Flag | `qualified` | 1 | Operator has verified device against this matrix |

## ACS Control Bits

```
ACS_SV = 0x0001  /* Source Validation */
ACS_TB = 0x0002  /* Translation Blocking */
ACS_RR = 0x0004  /* P2P Request Redirect */
ACS_CR = 0x0008  /* P2P Completion Redirect */
ACS_UF = 0x0010  /* Upstream Forwarding */
ACS_EC = 0x0020  /* P2P Egress Control */
ACS_DT = 0x0040  /* Direct Translated P2P */
```

## Qualification Process

1. **Boot-time enumeration**: The hypervisor enumerates PCI devices and populates `device_catalog` with capability flags.
2. **Operator qualification**: The operator (or automated policy) sets `qualified = 1` for devices that pass all criteria.
3. **Assignment-time check**: `vm_assign_device` enforces Q1, Q2, Q4–Q8 before proceeding. Unqualified devices are rejected with `NOT_SUPPORTED_ON_PLATFORM`.

## Phase 0A Disclaimer

Phase 0A is a planning/specification boundary: qualification is currently an
operator declaration, not an automated hardware validation path.

- PCI capability enumeration is not yet implemented, so Q1 (`has_acs`),
  Q2 (`has_flr`), and Q3 (`has_msix`) are not discovered automatically.
- ACS control register reads/programming are not yet implemented, so Q4-Q7
  (`ACS_SV`, `ACS_TB`, `ACS_RR`, `ACS_CR`) remain operator-asserted.
- FLR execution is not yet implemented, so Q2 is still a qualification
  prerequisite rather than a runtime-verified reset path.

Phase 0A therefore covers fail-closed rejection plus operator-declared
qualification. Phase 0B is the follow-on phase for automated PCI capability
verification, domain setup, and device programming.

### Phase 0A Operator-Declared Risk Model

Phase 0A does not contradict fail-closed behavior; it narrows it. The hypervisor still rejects devices by default, but any positive `qualified` assertion is presently an operator claim rather than an automated proof of Q1-Q7. That means a mistaken declaration can admit a device whose ACS/FLR/MSI-X properties are weaker than required.

Security impact when Q3 is only recommended:

- Q1, Q2, Q4-Q8 remain mandatory and are still the minimum barrier for DMA safety and reset hygiene
- Q3 weakness primarily affects interrupt isolation and cross-VM interference risk
- devices without MSI-X may share vectors or depend on coarser interrupt routing, increasing the chance of interrupt timing leakage, IRQ contention, and operational interference between trusted and untrusted workloads

Operational controls for non-MSI-X devices:

- assign non-MSI-X devices only to trusted or single-tenant guests
- pin IRQ affinity away from unrelated workloads
- use host-level IRQ routing/isolation policy and monitor interrupt rates during qualification
- document the exception in the deployment approval and risk register

Phase 0A operator support that must accompany Q8 `qualified`:

- standalone diagnostic scripts for PCI capability capture and review
- reference qualification templates for approved device classes
- operator training material and a qualification checklist retained with the release packet

Phase 0B action plan:

- automate Q1-Q7 discovery and validation in the hypervisor enumeration path
- add runtime ACS/FLR/MSI-X verification logs
- reject stale or inconsistent operator declarations once automated discovery is present
- recommended Phase 0A validation inputs: `pciconf -lvbc`, firmware/BMC inventory, platform topology notes, and any deployment-specific PCIe qualification script retained with the release evidence

## Fail-Closed Behavior

- Devices default to `qualified = 0` (unqualified)
- Missing ACS or FLR capability → assignment rejected (Phase 0B; in Phase 0A, assignment is based on the `qualified` flag)
- IOMMU unavailable → assignment rejected (separate check)
- IOMMU domain setup failure → assignment rejected (Phase 0A)

## Known Limitations (Phase 0A)

- PCI capability enumeration is not yet implemented (requires MMIO config space access)
- ACS control register programming is not yet implemented
- FLR execution path is not yet implemented
- Qualification is currently operator-declared, not automatically verified
- Q1-Q7 are therefore checked by operator declaration today; automated
  verification is deferred to Phase 0B

**Disclaimer:** In the current Phase 0A implementation, device qualification
relies entirely on operator declaration (Q8 `qualified` flag). The hypervisor
does not yet read PCI capability registers to verify Q1-Q7 automatically.
Automated PCI capability verification is planned for Phase 0B; until then,
operators bear responsibility for ensuring assigned devices meet all
qualification criteria in this matrix.

## Verification Checklist for Non-MSI-X Qualification

Before allowing a non-MSI-X device under Q3's exception path, the owner must complete:

1. Record the device class, BDF, and target VM/partition.
2. Verify Q1, Q2, Q4-Q8 manually and archive the evidence.
3. Capture interrupt telemetry during guest bring-up and steady-state I/O.
4. Verify IRQ affinity and routing do not overlap with unrelated trusted workloads.
5. Confirm there is no unexpected interrupt storm, vector sharing anomaly, or cross-guest interference.
6. Obtain operator approval and record the residual-risk acceptance.
