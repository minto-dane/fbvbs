# FBVBS Device Qualification Matrix

**Requirements:** REQ-0352 (DMA remapping), REQ-0904 (device assignment safety)

## Qualification Criteria

A device MUST satisfy ALL of the following before assignment to a guest VM:

| # | Criterion | Field | Required Value | Rationale |
|---|-----------|-------|----------------|-----------|
| Q1 | ACS Capability | `has_acs` | 1 | Prevents peer-to-peer DMA bypass between assigned devices |
| Q2 | FLR Support | `has_flr` | 1 | Required for clean device reset on reassignment or partition teardown |
| Q3 | MSI-X Capability | `has_msix` | 1 (recommended) | Interrupt isolation; MSI without MSI-X may share vectors |
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

## Fail-Closed Behavior

- Devices default to `qualified = 0` (unqualified)
- Missing ACS or FLR capability → assignment rejected
- IOMMU unavailable → assignment rejected (separate check)
- IOMMU domain setup failure → assignment rejected (Phase 0B)

## Known Limitations (Phase 0A)

- PCI capability enumeration is not yet implemented (requires MMIO config space access)
- ACS control register programming is not yet implemented
- FLR execution path is not yet implemented
- Qualification is currently operator-declared, not automatically verified
