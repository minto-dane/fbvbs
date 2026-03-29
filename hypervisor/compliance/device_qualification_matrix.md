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
3. **Assignment-time check**: `vm_assign_device` enforces Q1-Q8 before proceeding. Unqualified devices are rejected with `NOT_SUPPORTED_ON_PLATFORM`.

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

## Fail-Closed Behavior

- Devices default to `qualified = 0` (unqualified)
- Missing ACS or FLR capability → assignment rejected
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
