# FBVBS Covert Channel Analysis (REQ-1000, REQ-1103)

**Document:** CCA-001
**Date:** 2026-03-23
**Scope:** Inter-partition information flow via covert channels
**Applicable:** Common Criteria EAL5+ (AVA_VAN.5), Section 41

---

## 1. Threat Model

FBVBS enforces strict partition isolation. The threat is information
leakage between:

- **Host (FreeBSD) ↔ Guest VMs** via shared hardware resources
- **Guest VM ↔ Guest VM** via shared hardware resources
- **Trusted Service ↔ Host/Guest** via shared hardware resources

The attacker model assumes a compromised guest VM attempting to exfiltrate
secrets from the host or another guest, or to infer the presence/behavior
of other partitions.

**Scope limitation:** The shared-resource enumeration in Section 2 covers
software-visible shared resources that can be addressed by hypervisor-level
mitigations. Hardware-level microarchitectural resources not directly
observable or controllable by software (e.g., undocumented internal
buffers, power/thermal side channels, electromagnetic emanations) are
outside the scope of this analysis.

---

## 2. Channel Classification

### 2.1 Timing Channels

| Channel | Mechanism | FBVBS Mitigation | Residual Risk |
|---------|-----------|------------------|---------------|
| VMX preemption timer | Timer reload value leaks scheduling quantum | Fixed preemption tick value (FBVBS_DEFAULT_PREEMPTION_TICKS); reload is constant regardless of exit reason | **Low**: Constant reload eliminates scheduling-dependent timing variation |
| VM exit processing time | Exit handler duration varies by exit type | IBPB on every VM exit (unconditional); exit handler timing varies but is not guest-observable during exit | **Medium**: Architectural — the guest observes RDTSC delta across exit/entry |
| VERW/MDS flush timing | VERW duration depends on buffer state | VERW on VM exit when `need_verw` is set in the vuln profile; skipped only on CPUs whose profile marks the mitigation unnecessary | **Low (conditional)**: Low when `need_verw` is set; higher residual risk if the profile omits VERW on a vulnerable CPU |
| RSB fill timing | RSB fill loop count is constant | Fixed 32-entry RSB fill (PRODUCTION NOTE); not conditional | **Low**: Constant iteration count |
| Memory access timing | Cache state leaks across partitions | L1D flush on cross-partition exit (Intel MDS mitigation); IBPB clears branch predictor state | **Medium**: LLC (L3) sharing remains |

### 2.2 Cache-Based Channels

| Channel | Mechanism | FBVBS Mitigation | Residual Risk |
|---------|-----------|------------------|---------------|
| L1 data cache | L1D contents survive context switch | L1D_FLUSH on cross-partition VM exit (when `need_l1d_flush` is set in vuln profile, cpu_security.c) | **Low (conditional)**: Low when `need_l1d_flush` is set; High if a vulnerable CPU is mis-profiled and the flush is skipped |
| L1 instruction cache | L1I contents leak code layout | IBPB clears BTB/RSB; L1I flush not available in hardware | **Medium**: L1I sharing is architectural |
| L2 unified cache | Shared between logical processors | No hardware flush mechanism; SMT scheduling mitigation | **High**: Requires SMT-aware scheduling (not yet implemented) |
| LLC (L3) | Shared across all cores | Cache Allocation Technology (CAT) partitioning (not yet implemented) | **High**: LLC sharing is the primary residual channel |
| TLB | TLB entries survive VMRESUME | VPID-tagged TLBs (REQ-0341); INVVPID on context switch | **Low**: VPID provides hardware TLB isolation |

### 2.3 Branch Predictor Channels

| Channel | Mechanism | FBVBS Mitigation | Residual Risk |
|---------|-----------|------------------|---------------|
| BTB (Branch Target Buffer) | Spectre v2 style | IBPB on every VM exit (unconditional, cpu_security.c); eIBRS/AutoIBRS required (REQ-0310) | **Low**: IBPB + eIBRS provides hardware isolation |
| RSB (Return Stack Buffer) | SpectreRSB | RSB fill on VM exit (32 entries, PRODUCTION NOTE in cpu_security.c) | **Low**: RSB fill eliminates cross-domain RSB entries |
| PHT (Pattern History Table) | Spectre v1 style | LFENCE serialization (AMD, REQ-0318); bounds checks in all array accesses | **Low**: Serialization + bounds checking |
| BHB (Branch History Buffer) | BHI attacks | BHI_DIS_S when available (REQ-0312); IBPB fallback | **Low–Medium**: BHI_DIS_S covers known variants |
| PBRSB | Post-Barrier RSB | PBRSB mitigation (REQ-0313): RSB fill after IBPB on affected SKUs | **Low**: Mitigated on affected hardware |

### 2.4 Memory Bus Channels

| Channel | Mechanism | FBVBS Mitigation | Residual Risk |
|---------|-----------|------------------|---------------|
| DRAM row buffer | Row buffer hit/miss timing | None (hardware limitation) | **High**: Requires DRAM controller partitioning (not available) |
| Memory bandwidth | Contention on memory controller | None (hardware limitation) | **High**: Requires memory bandwidth allocation (not available) |
| QPI/UPI interconnect | Cross-socket traffic | NUMA-local page allocation (mp_init.c fbvbs_mp_page_alloc_local) | **Medium**: Local allocation reduces but does not eliminate cross-socket traffic |

### 2.5 Microarchitectural Data Sampling (MDS) Channels

Fully immune CPUs are CPUs whose vendor guidance, microcode level, and observed profile collectively indicate immunity to MFBDS, MLPDS, MSBDS, TAA, MMIO stale data, and RFDS. In FBVBS terms, that means the vulnerability profile built in `cpu_security.c` marks the corresponding `immune_*` bits and therefore does not require `need_verw`. Immunity must be grounded in vendor errata/CVE guidance, microcode/firmware revision, and profile-validation evidence; if there is uncertainty, the safe fallback is to set `need_verw` and execute VERW.

| Channel | Mechanism | FBVBS Mitigation | Residual Risk |
|---------|-----------|------------------|---------------|
| MFBDS (Fallout) | Store buffer leakage | VERW on VM exit when `need_verw` set (cpu_security.c) | **Low (conditional)**: Low when `need_verw` is set; High if the CPU remains vulnerable and VERW is not programmed |
| MLPDS | Load port leakage | VERW on VM exit when `need_verw` set | **Low (conditional)**: Low when `need_verw` is set; High if the CPU remains vulnerable and VERW is not programmed |
| MSBDS | Microarchitectural store buffer | VERW on VM exit when `need_verw` set | **Low (conditional)**: Low when `need_verw` is set; High if the CPU remains vulnerable and VERW is not programmed |
| TAA (TSX Async Abort) | TSX-based MDS variant | VERW on VM exit when `need_verw` set; TSX disabled via IA32_TSX_CTRL MSR intercept (REQ-0340) | **Low (conditional)**: Low when `need_verw` is set; TSX disable is an additional mitigation, but not a substitute for the conditional VERW path |
| MMIO stale data | MMIO read of stale data | VERW on VM exit when `need_verw` set (covers MMIO stale data on affected SKUs) | **Low (conditional)**: Low when `need_verw` is set; High if the CPU remains vulnerable and VERW is not programmed |
| RFDS (Register File Data Sampling) | Register file leakage | VERW on VM exit when `need_verw` set (includes RFDS via immune_rfds check, cpu_security.c:309) | **Low (conditional)**: Low when `need_verw` is set; High if the CPU remains vulnerable and VERW is not programmed |

### 2.6 IOMMU / DMA Channels

| Channel | Mechanism | FBVBS Mitigation | Residual Risk |
|---------|-----------|------------------|---------------|
| DMA side channel | Device DMA timing/contention | IOMMU domain isolation (REQ-0350); per-partition DMA page tables | **Low**: IOMMU provides hardware DMA isolation |
| Interrupt timing | Interrupt delivery timing | Interrupt remapping (REQ-0351); virtual APIC (apic.c) | **Low**: Interrupts are virtualized |
| PCIe ACS | Peer-to-peer device access | ACS capability required for passthrough (REQ-0904, device_qualification_matrix.md) | **Low**: ACS prevents peer DMA |

### 2.7 Debug Register Channels

| Channel | Mechanism | FBVBS Mitigation | Residual Risk |
|---------|-----------|------------------|---------------|
| DR0-DR3 leakage | Debug register addresses leak across partitions | DR0-DR3 zeroed after saving guest state (cpu_security.c, fix 2026-03-22) | **None**: Registers zeroed on every exit |
| DR7 manipulation | Debug control register bypass | DR7 64-bit sanitization (bits[63:32]=0, bit11=0, bit10=1, GD=0); CR4.DE pinned to prevent DR4/DR5 aliasing (vm_policy.c) | **None**: Full sanitization |
| DR6 information | Debug status register leak | DR6 reserved bits enforced (FFFF8FF0 mask); shadow values returned on guest read | **None**: Shadow value isolation |

---

## 3. Residual Risk Summary

### Conditional Low Residual Risk (hardware mitigations conditional on vulnerability profile)
- L1D cache (L1D_FLUSH when `need_l1d_flush` set; skipped on L1TF-immune CPUs)
- MDS/TAA/MMIO/RFDS (VERW when `need_verw` set; skipped on fully immune CPUs)

### Low Residual Risk (hardware mitigations unconditionally in place)
- TLB (VPID)
- Branch predictors (IBPB + eIBRS/AutoIBRS + RSB fill)
- DMA (IOMMU isolation)
- Debug registers (zeroed + sanitized + shadow)
- Preemption timer (constant reload)

### Medium Residual Risk (partial mitigation)
- L1I cache (no hardware flush)
- VM exit processing time (RDTSC observable)
- BHB (BHI_DIS_S on supported SKUs only)
- QPI/UPI contention (NUMA-local allocation reduces)

### High Residual Risk (no effective mitigation)
- LLC (L3) sharing — requires Intel CAT or AMD QoS
- L2 cache sharing — requires SMT-aware scheduling
- DRAM row buffer — requires hardware controller partitioning
- Memory bandwidth contention — requires hardware bandwidth allocation

### 3.5 CPU Profiling Assurance

The conditional mitigations in `cpu_security.c` depend on the CPU vulnerability profiling path, especially `need_l1d_flush` and `need_verw`. Profiles are determined from CPUID/MSR state and then merged into the global worst-case profile. Assurance for this mechanism therefore depends on both accurate hardware identification and conservative fallback behavior.

Validation requirements:

- cross-check the detected vendor/family/model/feature set against vendor errata and microcode guidance
- run automated test vectors that exercise the VERW and L1D_FLUSH decision paths under VM entry/exit conditions
- preserve telemetry showing when VERW or L1D_FLUSH was skipped because the profile marked the CPU immune
- on any mismatch, unknown CPU ID, or microcode uncertainty, fail safe by enabling the mitigation (`need_verw=1`, `need_l1d_flush=1`) rather than skipping it

Profile maintenance requirements:

- re-validate profiles whenever CPU microcode, firmware, or the platform model changes
- stage profile updates through reproducible tests and audit review before promotion
- roll back to the conservative profile if an updated profile cannot be justified with evidence

Claimed assurance level:

- repository-local evidence supports a design-analysis claim aligned with AVA_VAN.5-style review intent
- it is not yet a completed EAL5+ assurance claim because hardware validation and full proof closure are still open

### 3.6 VERW Profile Validation Procedure

To validate the `need_verw` gating logic:

1. Record CPUID and relevant vulnerability capability bits for the target CPU.
2. Compare the generated FBVBS profile against vendor errata and known vulnerability tables.
3. Exercise VM-exit paths in test VMs and verify that VERW executes when the profile requires it.
4. Review audit/telemetry for events where VERW was skipped; treat any unexpected skip as a release blocker.
5. Re-run this validation after firmware or microcode updates.

Recommended evidence sources and tooling:

- the profiling implementation in `hypervisor/src/cpu_security.c`
- regression coverage in `hypervisor/tests/test_policy_security.c`
- repository-local QEMU smoke and matrix runs for gate behavior, with the understanding that they do not replace real-hardware validation
- release audit telemetry showing whether the platform entered a mitigation-required or mitigation-skipped path

Expected discrepancy handling:

- if profile generation disagrees with vendor errata, microcode expectations, or observed VM-exit test vectors, raise a platform-gate alert and force the conservative path (`need_verw=1`)
- if telemetry shows VERW was skipped on a CPU that cannot be justified as fully immune, treat the build as non-release-ready until the profile is corrected and re-validated

---

## 4. Recommended Mitigations for High-Risk Channels

### 4.1 LLC Partitioning (Intel CAT / AMD QoS)
- Intel Cache Allocation Technology (CAT) via IA32_PQR_ASSOC MSR
- Assign per-partition cache ways via IA32_L3_CBM MSRs
- AMD Cache QoS: similar mechanism via MSR C001_1020
- **Implementation:** Phase 9 extension — add CAT programming to partition create

### 4.2 SMT-Aware Scheduling
- Co-schedule only same-partition vCPUs on sibling threads
- If cross-partition co-scheduling required: apply L1D_FLUSH + additional mitigations
- **Implementation:** Phase 8 extension — add SMT topology to mp_init.c scheduling

### 4.3 Core Dedication (High-Assurance Profiles)
- Pin security-sensitive partitions to dedicated physical cores
- Prevent SMT sibling sharing with other partitions
- **Implementation:** Partition creation flag (vm_flags) for core-dedicated mode

---

## 5. Analysis Methodology

This analysis follows the Common Criteria covert channel analysis
methodology (AVA_VAN.5):

1. **Enumeration:** Identify all shared hardware resources between
   partitions (cache, TLB, branch predictors, memory bus, timers, etc.)
2. **Capacity Estimation:** For each channel, assess bandwidth (bits/sec)
   based on published research:
   - LLC: ~100 Kbps (Flush+Reload), ~10 Kbps (Prime+Probe)
   - L1D: Eliminated by L1D_FLUSH
   - BTB: Eliminated by IBPB + eIBRS
   - DRAM row buffer: ~10 Kbps (DRAMA attack)
   - VM exit timing: ~1 Kbps (coarse-grained)
3. **Mitigation Assessment:** Map each channel to FBVBS mitigations
4. **Residual Risk:** Document channels where mitigation is incomplete

---

## 6. References

- Intel SDM Vol. 3, Chapter 11 (Memory Cache Control)
- Intel SDM Vol. 3, Chapter 17.12 (L1D_FLUSH)
- AMD APM Vol. 2, §15.15.7 (SEV-SNP Isolation)
- Ge et al., "A Survey of Microarchitectural Timing Attacks" (ACM Computing Surveys, 2018)
- NIST SP 800-53 Rev. 5, SC-4 (Information in Shared System Resources)
- Common Criteria Part 3, AVA_VAN.5 (Advanced Methodical Vulnerability Analysis)
