# FBVBS Security Target Outline (Common Criteria ISO 15408)

**Document:** ST-001
**Date:** 2026-03-23
**Status:** OUTLINE ONLY -- not an achieved certification claim; requires evaluator engagement and additional implementation evidence
**Applicable Standards:** ISO/IEC 15408:2022 (Common Criteria), ISO/IEC 18045:2022 (CEM)
**Scope:** Phase 9-4 (Common Criteria evaluation preparation)

---

## 1. ST Introduction

### 1.1 ST Reference

| Field | Value |
|-------|-------|
| ST Title | FBVBS Microhypervisor Security Target |
| ST Version | 0.1 (Outline) |
| TOE Reference | FBVBS v7 Microhypervisor |
| Author | FBVBS Project |
| Date | 2026-03-23 |
| CC Version | ISO/IEC 15408:2022 |
| CEM Version | ISO/IEC 18045:2022 |

### 1.2 TOE Reference

The Target of Evaluation (TOE) is the **FBVBS microhypervisor**, a
bare-metal Type-1 hypervisor for x86-64 platforms. The TOE enforces
partition isolation, code integrity, and audit logging for a FreeBSD
host operating system and its guest virtual machines.

| Attribute | Value |
|-----------|-------|
| TOE Type | Separation kernel / microhypervisor |
| Implementation Language | C11 with ACSL formal annotations |
| Source Size | ~25K SLOC (26 source files, 7 header files) |
| WP-Verification Scope | 9 files targeted; current proof status is tracked separately in `wp_verification_boundary.md` |
| Target Architecture | x86-64 (Intel VT-x + EPT, AMD-V + NPT) |
| Required Hardware | CPU with VMX/SVM, EPT/NPT, IOMMU (VT-d/AMD-Vi), optional TPM 2.0 |
| Operating Mode | VMX root (ring 0) / SVM host mode |
| Hosted OS | FreeBSD (target end state: deprivileged in VMX non-root; current retained-C boundary has not completed the handoff; retained-C boundary is the TCB boundary between FreeBSD and the hypervisor) |

The retained-C boundary has not completed the host handoff yet: the FreeBSD
host remains part of the trusted computing base, VMX non-root deprivilege is
not achieved, and host-kernel compromise remains in scope until the runtime
handoff path is finished. The current mitigation is to keep the platform
fail-closed and to gate release on VMX root lifecycle, IOMMU bring-up, and
host-handoff milestones in the roadmap.

### 1.3 TOE Overview

FBVBS operates as a firmware-loaded separation kernel between the
hardware platform and all software partitions. The current reproducible
repository evidence path is Multiboot2/GRUB under QEMU smoke; an
additional UEFI path exists in-progress but is not the primary evidence
path today. In the intended end state it boots via firmware, establishes VMX/SVM root mode, deprivileges the FreeBSD host into a
guest partition, and manages additional guest VMs and trusted service
partitions. The current retained-C repository does not yet complete that
host handoff and keeps the runtime fail-closed instead. All inter-partition
communication is mediated through a hypercall interface with capability-based
access control.

The TOE provides:

1. **Partition isolation** via hardware-enforced second-level address
   translation (EPT on Intel, NPT on AMD) and IOMMU DMA remapping
2. **Code integrity** via kernel code integrity (KCI) measurement with
   W^X enforcement through EPT/HLAT/NPT page permissions
3. **Audit logging** via a target dual-path primary + mirror design;
   the current retained-C repository implements the in-memory mirror
   ring and boot-console output, but not a full authoritative primary
   OOB sink
4. **CPU vulnerability mitigations** via per-VM-exit IBPB, VERW, RSB
   fill, L1D flush, and CR/DR pinning
5. **Device isolation** via per-partition IOMMU domains with interrupt
   remapping

### 1.4 TOE Description

The TOE consists of the following subsystems:

| Subsystem | Source Files | Function |
|-----------|-------------|----------|
| Hypercall Dispatch | command.c | 58 hypercall handlers, capability enforcement |
| Partition Management | partition.c | Lifecycle (CREATE/LOAD/MEASURE/RUN/DESTROY), vCPU management |
| Security Subsystem | security.c | Manifest validation, hash measurement, KCI page binding |
| CPU Security | cpu_security.c | Feature detection, vulnerability profiling, mitigations |
| VM Policy | vm_policy.c | CR/DR enforcement, capability masks, exit handling |
| VMX Control | vmx.c, vmcs_setup.c, vmx_controls.c | VMCS setup, VMX lifecycle, CET/MSR bitmap |
| Memory Management | memory.c, memory_utils.c, page_alloc.c | EPT map/unmap, page allocator |
| IOMMU | iommu_vtd.c, iommu_amdvi.c | DMAR/IVRS parsing, domain management |
| Translation Integrity | hlat.c, amd_npt.c | HLAT (Intel), NPT write-protect (AMD) |
| Audit Log | log.c | Ring buffer with CRC32C, spinlock synchronization |
| Boot | boot_multiboot.c, early_init.c, uefi_entry.c | Current evidence path: Multiboot2 parse + QEMU bare-metal smoke; UEFI handoff remains in progress |
| Multi-Processor | mp_init.c | MADT/SRAT parsing, AP init, IPI, TLB shootdown |
| Platform Services | idt.c, apic.c, watchdog.c | IDT, APIC virtualization, preemption timer |
| Kernel Integration | kernel.c | Hypervisor init, model code |

---

## Evidence Boundary Note

This document is a target-state Security Target outline. It mixes current repository evidence with intended Common Criteria mappings, so it must be read together with:

- `hypervisor/compliance/retained_c_leaf_boundary.md`
- `hypervisor/compliance/wp_verification_boundary.md`

Table cells below that mention completeness, coverage, or assurance packages describe target-state intent unless the cited repository evidence independently reproduces them in the current environment.

## 2. Conformance Claims

### 2.1 CC Conformance

- **CC Part 2 target mapping** -- all SFRs are drawn from ISO/IEC 15408-2:2022
- **CC Part 3 target mapping** -- the outline is written against an eventual EAL5-augmented evaluation package, but that package is not currently claimed as achieved

### 2.2 Protection Profile Conformance

| Protection Profile | Conformance |
|-------------------|-------------|
| SKPP (Separation Kernel Protection Profile, v1.03) | Target-state strict conformance claim only; not yet achieved because FCS_COP.1 is partial |
| Virtualization PP Module (NIAP, v1.1) | Demonstrable conformance target; evaluator evidence still required |

**Rationale:** FBVBS is architecturally a separation kernel -- it
partitions a single hardware platform into isolated execution
environments with controlled information flow. The SKPP is the most
directly applicable PP. The Virtualization PP Module addresses
hypervisor-specific requirements (guest VM management, virtual device
isolation) that supplement the SKPP.

### 2.3 EAL Conformance

**Target package after evidence closure: EAL5 augmented with:**

| Component | Augmentation | Rationale |
|-----------|-------------|-----------|
| AVA_VAN.5 | Advanced methodical vulnerability analysis | Covert channel analysis (CCA-001), speculative execution analysis |
| ALC_FLR.3 | Systematic flaw remediation | Reproducible builds, SBOM, fuzz regression |

**Current reality:** the repository does not yet support an achieved EAL5+ claim. Proof coverage, fuzz evidence, SBOM/provenance, hardware validation, and platform integration must be taken from the current reproducible artifacts, not from target-state package text in this outline.

### 2.4 Package Conformance

The TOE claims conformance to the following assurance packages:

- ALC_CMC.4 (Production support, automation and project management)
- ALC_DEL.1 (Delivery procedures)
- ALC_DVS.1 (Identification of security measures)
- ALC_LCD.1 (Developer-defined lifecycle model)
- ALC_TAT.2 (Compliance with implementation standards)
- ALC_FLR.3 (Systematic flaw remediation) -- augmentation

**Conformance note:** SKPP v1.03 includes FCS_COP.1 as a required SFR.
Because this outline still marks FCS_COP.1 as partial, the SKPP strict
conformance claim remains target-state only and must not be treated as
achieved until Phase 5 is complete.

---

## 3. Security Problem Definition

### 3.1 Assets

| Asset | Description | Protection Requirement |
|-------|-------------|----------------------|
| A.PARTITION_STATE | Per-partition memory, registers, VMCS | Confidentiality + Integrity |
| A.HYPERVISOR_CODE | TOE executable code and read-only data | Integrity |
| A.AUDIT_LOG | Primary and mirror audit log rings | Integrity + Availability |
| A.KEY_MATERIAL | IKS/SKS cryptographic keys (Phase 5) | Confidentiality + Integrity |
| A.MANIFEST | Partition manifests and measurement state | Integrity |
| A.IOMMU_TABLES | IOMMU page tables and interrupt remap tables | Integrity |

### 3.2 Threats

#### T.BYPASS -- Partition Isolation Bypass

An attacker operating within a guest partition attempts to access memory,
registers, or devices belonging to another partition or the hypervisor,
bypassing EPT/NPT isolation.

**Attack vectors:** EPT misconfiguration, VMCS field manipulation, hypercall
parameter injection, GPA aliasing, non-SHAREABLE object cross-mapping.

#### T.TAMPER -- Hypervisor Code/Data Modification

An attacker attempts to modify the TOE's code, data structures, or
configuration to subvert security policy enforcement.

**Attack vectors:** DMA attack on hypervisor pages, kernel rootkit modifying
CR0.WP/CR4.SMEP, VMCS host-state corruption, stack overflow.

#### T.LEAK -- Cross-Partition Information Flow

An attacker within one partition attempts to extract information from
another partition via covert channels (timing, cache, branch predictor,
microarchitectural state).

**Attack vectors:** Flush+Reload (cache), Spectre v1/v2 (branch predictor),
MDS/TAA (microarchitectural buffers), RDTSC timing, debug register
leakage.

#### T.ROLLBACK -- Downgrade Attack

An attacker attempts to load an older, vulnerable version of a partition
image or hypervisor component, bypassing security fixes.

**Attack vectors:** Manifest replay, version counter manipulation, TPM NV
index bypass.

#### T.DMA -- Device-Initiated Attack

A compromised or malicious device performs DMA operations targeting
memory belonging to a partition other than its assigned owner, or
targeting hypervisor memory.

**Attack vectors:** DMA to unprotected regions, interrupt remapping bypass,
peer-to-peer DMA between assigned devices, ACS bypass.

#### T.SPECTRE -- Speculative Execution Attack

An attacker exploits speculative execution vulnerabilities to leak data
across privilege boundaries or partition boundaries.

**Attack vectors:** Spectre v1 (bounds check bypass), Spectre v2 (branch
target injection), SpectreRSB, MDS, L1TF, RFDS, BHI, PBRSB, GDS,
Zenbleed.

### 3.3 Organizational Security Policies

#### P.AUDIT -- Audit Event Generation

The TOE shall generate audit records for all security-relevant events
including: partition lifecycle transitions, hypercall invocations,
policy violations, hardware security events, and fault conditions.

**Implementation:** log.c mirror ring plus primary UART/OOB sink,
CRC32C per-record integrity, spinlock-serialized append, event types
covering all 58 hypercall handlers and partition state transitions.

#### P.INTEGRITY -- Code and Data Integrity

The TOE shall maintain the integrity of its own code and data, and shall
enforce W^X (write XOR execute) on all managed memory regions.

**Implementation:** EPT/HLAT/NPT page permissions, KCI hash measurement
before execute permission grant, _Static_assert compile-time guards,
linker script W^X sections with guard pages.

#### P.ISOLATION -- Partition Isolation

The TOE shall enforce complete isolation between partitions such that no
partition can access memory, registers, or devices belonging to another
partition except through explicitly authorized hypercall interfaces.

**Implementation:** Per-partition EPT/NPT page tables, per-partition IOMMU
domains, capability-based hypercall access control, VPID-tagged TLBs.

### 3.4 Assumptions

#### A.PLATFORM -- Trusted Hardware Platform

The hardware platform (CPU, chipset, IOMMU, TPM) is assumed to correctly
implement the documented ISA and hardware isolation mechanisms. The CPU
correctly implements VMX/SVM, EPT/NPT, and IOMMU DMA remapping as
specified in the Intel SDM / AMD APM.

#### A.ADMIN -- Trusted Administrator

The system administrator responsible for configuring the TOE is
trusted, competent, and follows operational guidance. The administrator
is responsible for device qualification (device_qualification_matrix.md)
and partition policy configuration.

#### A.PHYSICAL -- Physical Security

The hardware platform is located in a physically secure environment.
Physical attacks (bus probing, cold boot, JTAG) are out of scope for
this evaluation.

#### A.FIRMWARE -- Trusted Firmware

The platform firmware (UEFI, microcode) is assumed to be authentic and
unmodified. Secure Boot chain of trust is assumed to be correctly
configured prior to TOE boot.

---

## 4. Security Objectives

### 4.1 Security Objectives for the TOE

#### O.ISOLATION -- Partition Memory Isolation

The TOE shall enforce memory isolation between all partitions using
hardware second-level address translation (EPT on Intel, NPT on AMD).
No partition shall be able to read, write, or execute memory belonging
to another partition or the hypervisor, except through authorized
hypercall interfaces.

**Counters:** T.BYPASS, T.LEAK
**Implemented by:** memory.c (EPT map/unmap with rollback), partition.c
(per-partition state), amd_npt.c (NPT write-protect), hlat.c (HLAT
translation integrity)

#### O.INTEGRITY -- Code and Configuration Integrity

The TOE shall protect its own code and data from modification, enforce
W^X on all managed memory, and verify code integrity via hash
measurement before granting execute permissions.

**Counters:** T.TAMPER, T.ROLLBACK
**Implemented by:** security.c (manifest validation, KCI page binding),
cpu_security.c (CR0.WP/CR4.SMEP/SMAP/DE pinning), vmcs_setup.c (VMCS
host-state protection), linker script (W^X sections + guard pages)

#### O.AUDIT -- Security Event Logging

The TOE shall generate tamper-evident audit records for all
security-relevant events, maintaining both a primary log and a mirror
log accessible to the host partition.

**Counters:** T.BYPASS (detection), T.TAMPER (detection)
**Implemented by:** log.c (mirror ring, primary UART/OOB sink, CRC32C
integrity, spinlock serialization), all hypercall handlers (event
generation on state transitions and policy violations)

The target design includes an authoritative primary OOB sink. The
current retained-C repository now serializes committed audit records to
the bare-metal COM1/UART path and maintains the in-memory mirror ring in
parallel; hosted/unit-test builds model the same sink through an
overridable retained-C hook for verification.

#### O.DMA_CONTROL -- Device DMA Isolation

The TOE shall configure IOMMU hardware to restrict DMA operations to
the memory regions assigned to the device's owning partition. Interrupt
remapping shall prevent interrupt injection attacks.

**Counters:** T.DMA
**Implemented by:** iommu_vtd.c (VT-d domain management, interrupt
remapping table), iommu_amdvi.c (AMD-Vi domain management), partition.c
(device assignment with qualification checks), device_qualification_matrix.md
(ACS/FLR/MSI-X requirements)

#### O.SPECTRE -- CPU Vulnerability Mitigations

The TOE shall apply CPU vulnerability mitigations on every VM exit/entry
transition to prevent speculative execution attacks from leaking data
across partition boundaries.

**Counters:** T.SPECTRE, T.LEAK
**Implemented by:** cpu_security.c (81-feature detection, vulnerability
profiling, IBPB/VERW/RSB fill/L1D flush), vm_policy.c (CR/DR pinning,
debug register sanitization and zeroing)

#### O.ACCESS_CONTROL -- Capability-Based Hypercall Authorization

The TOE shall enforce capability-based access control on all hypercall
operations. Each partition's capability mask restricts which operations
it may invoke, with the FreeBSD host receiving a default mask that
excludes sensitive operations.

**Counters:** T.BYPASS
**Implemented by:** command.c (capability check in dispatch_command),
vm_policy.c (capability mask definition), partition.c (per-partition
capability assignment)

### 4.2 Security Objectives for the Operational Environment

#### OE.PLATFORM -- Hardware Security Features

The operational environment shall provide an x86-64 processor with:
VMX/SVM virtualization extensions, EPT/NPT second-level paging,
IOMMU (VT-d or AMD-Vi) with interrupt remapping, and VPID/ASID support.
The processor shall correctly implement documented hardware isolation
mechanisms.

#### OE.ADMIN -- Administrator Competence

The administrator shall follow TOE operational guidance for: device
qualification, partition policy configuration, firmware update
procedures, and physical security maintenance.

#### OE.FIRMWARE -- Secure Boot Chain

The platform shall maintain a Secure Boot chain of trust from firmware
through the TOE boot image. UEFI Secure Boot or equivalent mechanism
shall verify the TOE image integrity before execution.

---

## 5. Security Functional Requirements

### 5.1 SFR Summary

| SFR | CC Component | TOE Function | Source Files |
|-----|-------------|-------------|-------------|
| FDP_IFC.2 | Complete information flow control | EPT/NPT partition isolation | memory.c, partition.c |
| FDP_IFF.1 | Simple security attributes | Capability-based access control | command.c, vm_policy.c |
| FDP_RIP.2 | Full residual information protection | Page zeroing on deallocation | page_alloc.c, partition.c |
| FIA_UID.2 | User identification before any action | Partition ID in VMCS/hypercall | command.c, vmcs_setup.c |
| FPT_SEP.3 | Complete reference monitor | VMX root/non-root separation | vmx.c, vmcs_setup.c |
| FPT_TST.1 | TSF self test | Boot integrity measurement | kernel.c, cpu_security.c |
| FPT_FLS.1 | Failure with preservation of secure state | Fail-closed partition fault | partition.c, watchdog.c |
| FPT_TDC.1 | Inter-TSF basic TSF data consistency | TOCTOU-safe field caching | command.c |
| FAU_GEN.1 | Audit data generation | Audit log for all security events | log.c |
| FAU_GEN.2 | User identity association | Partition ID in audit records | log.c, partition.c |
| FAU_STG.2 | Guarantees of audit data availability | Primary UART/OOB sink plus mirror ring | log.c |
| FAU_SAR.1 | Audit review | Mirror log readable by host | log.c |
| FCS_COP.1 | Cryptographic operation | IKS/SKS key operations | (Phase 5 -- partial retained-C SHA-384 path only) |
| FMT_SMF.1 | Specification of management functions | Hypercall management interface | command.c |
| FMT_SMR.1 | Security roles | Host partition vs. guest partition | partition.c, command.c |

### 5.2 SFR Details

#### FDP_IFC.2 -- Complete Information Flow Control

The TOE shall enforce the partition isolation information flow control
policy on all memory operations between all partitions.

**FBVBS Requirements:** REQ-0200 (microhypervisor responsibility), REQ-0202
(partition management), REQ-0203 (memory permission enforcement)

**Implementation:**
- EPT/NPT page tables provide hardware-enforced memory isolation
  (memory.c: `fbvbs_ept_map_region`, `fbvbs_ept_unmap_region`)
- GPA validation: alignment check, 52-bit upper bound, ownership
  verification (memory.c)
- Non-SHAREABLE objects reject cross-partition mapping
  (partition.c: `apply_mapping` map_count check)
- Shared memory peer_permissions ceiling enforcement
  (partition.c: `memory_map`)
- EPT rollback on partial map failure prevents quota exhaustion
  (memory.c: transactional map with saved_table_count restore)

**ACSL Evidence:** 107/117 WP goals proved in memory.c (91.45%);
1611/1633 in partition.c (98.65%). Timeouts are structural (2D assigns,
GPA-derived pointers), not security-logic gaps.

#### FDP_IFF.1 -- Simple Security Attributes

The TOE shall enforce the capability-based access control information
flow control SFP based on: partition capability mask, caller partition
ID, and hypercall call_id.

**FBVBS Requirements:** REQ-0205 (command page ABI), REQ-0206 (capability
enforcement), REQ-0210 (error codes)

**Implementation:**
- `fbvbs_required_capability_for_call` maps each call_id to a required
  capability bit (command.c, switch-based with precise ACSL ensures)
- `dispatch_command` checks caller's capability_mask before invoking
  handler (command.c)
- FreeBSD host receives FBVBS_HOST_DEFAULT_CAPABILITY_MASK (all
  capabilities except MEMORY_PERMISSION_SET)

**ACSL Evidence:** 1636/1642 WP goals proved in command.c (99.63%)

#### FDP_RIP.2 -- Full Residual Information Protection

The TOE shall ensure that all memory allocated to a partition is zeroed
upon deallocation, and that no residual data from a previous partition
is accessible to a subsequently created partition.

**FBVBS Requirements:** REQ-0203 (memory sanitization on destroy),
REQ-0903 (secure deallocation)

**Implementation:**
- `fbvbs_page_alloc` returns zero-guaranteed pages (page_alloc.c)
- `fbvbs_partition_sanitize_memory` zeroes all partition memory on
  destroy (partition.c)
- IKS/SKS key material pages zeroed via `fbvbs_zero_page_at_gpa` after
  import (security.c, `#ifndef __FRAMAC__` production path)
- DR0-DR3 zeroed after saving guest state on VM exit (cpu_security.c)

#### FIA_UID.2 -- User Identification Before Any Action

The TOE shall require identification (partition_id lookup via VMCS
association) of each partition before allowing any hypercall operation.

**FBVBS Requirements:** REQ-0205 (command page caller identification)

**Implementation:**
- `dispatch_hypercall` identifies caller via current VMCS pointer,
  resolving to partition_id (command.c)
- Partition ID is bound to VMCS at partition creation and cannot be
  modified by the guest (vmcs_setup.c)

#### FPT_SEP.3 -- Complete Reference Monitor

The TOE shall maintain a security domain for its own execution that
protects it from interference and tampering by untrusted subjects.

**FBVBS Requirements:** REQ-0002 (VMX root operation), REQ-0200
(microhypervisor responsibility)

**Implementation:**
- VMX root mode / SVM host mode provides hardware-enforced privilege
  separation (vmx.c: `fbvbs_vmx_setup`, `fbvbs_vmx_run_vcpu`)
- Hypervisor memory is not mapped in any guest EPT/NPT tables
- CR0.WP, CR4.SMEP, CR4.SMAP, CR4.DE pinned via VMCS host-state
  (cpu_security.c, vm_policy.c)
- W^X enforcement via linker script sections with guard pages (fbvbs.ld)
- IST stacks (IST1/2/3) for #DF/#NMI/#MC prevent stack corruption
  cascading to triple fault (idt.c, fbvbs.ld)

#### FPT_TST.1 -- TSF Self Test

The TOE shall provide the capability to verify the integrity of its
own code and stored data at boot time.

**FBVBS Requirements:** REQ-0400 (code integrity), REQ-0401 (hash
measurement)

**Implementation:**
- Boot integrity detection at hypervisor_init (kernel.c: `fbvbs_hypervisor_init`)
- CPU security feature detection and consistency verification
  (cpu_security.c: `fbvbs_cpu_detect_security_features`,
  `fbvbs_cpu_verify_consistency`)
- DRTM/Secure Boot detection (uefi_entry.c)
- KCI full-module measurement plus per-page digest verification before
  execute permission grant (security.c: `fbvbs_kci_verify_module`,
  `fbvbs_kci_set_wx`, `fbvbs_sha384`)

#### FPT_FLS.1 -- Failure with Preservation of Secure State

The TOE shall preserve a secure state when any of the following
failures occur: unclassified VM exit, watchdog timeout, partition fault,
double fault.

**FBVBS Requirements:** REQ-0212 (partition fault handling)

**Implementation:**
- `fbvbs_partition_fault` transitions partition to FAULTED state with
  audit log record (partition.c)
- Faulted partition retains EPT/IOMMU isolation -- memory remains
  protected (partition.c)
- Watchdog detects hung partitions via VMX preemption timer
  (watchdog.c)
- State restriction: only RUNNING/RUNNABLE/LOADED/QUIESCED partitions
  can be faulted (prevents lifecycle skip from CREATED/MEASURED)
- Double fault is idempotent (FAULTED -> FAULTED is no-op with
  INVALID_STATE)

**Test Evidence:** test_fault_injection.c -- 17 tests covering
positive/negative fault paths, double-fault idempotency, watchdog
detection.

#### FPT_TDC.1 -- Inter-TSF Basic TSF Data Consistency

The TOE shall protect against time-of-check-to-time-of-use (TOCTOU)
attacks on hypercall parameters shared with guest partitions.

**Implementation:**
- `cached_call_id`: page->call_id cached once in dispatch_hypercall
  (command.c) -- prevents auth-bypass via concurrent vCPU modification
- `cached_input_length`: page->input_length cached -- prevents
  tail-zeroing skip and buffer overread
- `cached_flags`: page->flags cached in write_response -- prevents
  unvalidated GPA write via flag flip
- `cached_output_gpa`: page->output_page_gpa cached

#### FAU_GEN.1 / FAU_GEN.2 -- Audit Data Generation

The TOE shall generate audit records for: partition lifecycle
transitions, hypercall invocations, policy violations, capability
denials, fault events, and hardware security events. Each audit record
shall include the partition_id of the subject.

**FBVBS Requirements:** REQ-0207 (audit logging), REQ-1103 (event types)

**Implementation:**
- `fbvbs_log_append` appends 272-byte records to ring buffer (log.c)
- CRC32C per-record integrity (union overlay pattern for WP
  compatibility)
- Spinlock-serialized append prevents concurrent corruption
- All 58 hypercall handlers generate audit records on state transitions
  and error paths

**ACSL Evidence:** 217/218 WP goals proved in log.c (99.54%)

#### FAU_STG.2 / FAU_SAR.1 -- Audit Storage and Review

The TOE shall maintain a primary UART/OOB audit sink and a mirror ring
in host-accessible memory, and provide the host partition read access to
the mirror log.

**Implementation:**
- Primary log path: serialized audit records emitted to the retained-C
  COM1/UART sink
- Mirror log: in-memory ring exposed through the retained-C audit APIs
- Host reads mirror via FBVBS_EVENT_PARTITION_FAULT notifications
- Log rate limiting prevents flood-induced data loss

**Residual Risk:** The retained-C repository now emits committed audit
records to the primary UART/OOB path and keeps the mirror ring for
independent review. Remaining operational risk is sink collection and
retention outside the hypervisor boundary: deployments still need a
trusted serial/OOB collector so primary evidence is preserved across host
compromise or reboot.

#### FCS_COP.1 -- Cryptographic Operation (Phase 5 dependency)

The TOE shall perform cryptographic operations (SHA-256/384 hash,
Ed25519 signature verification, AES encryption/decryption) in
accordance with specified algorithms and key sizes.

**Status:** PARTIAL. The retained C build now includes a narrow runtime
SHA-384 path used by `KCI_VERIFY_MODULE` / `KCI_SET_WX`, but the
general-purpose cryptographic suite required by this SFR (signature
verification, MAC, key derivation, encryption/decryption) remains a
Phase 5 dependency. The implemented runtime path is limited to SHA-384
measurement and per-page digest comparison for approved module state; it
does not provide the broader algorithm set required by the SFR. The
fail-closed behavior in KCI reduces exploitability of missing crypto
primitives by denying execute permissions on verification failure, but it
does not close the compliance gap.

#### FMT_SMF.1 / FMT_SMR.1 -- Management Functions and Roles

The TOE shall provide management functions through the hypercall
interface (58 operations) and distinguish between two security roles:
host partition (elevated capability mask) and guest partition (restricted
capability mask).

**Implementation:**
- Host receives FBVBS_HOST_DEFAULT_CAPABILITY_MASK at creation
  (partition.c)
- Guest partitions receive operator-assigned capability masks
- Capability enforcement is checked on every hypercall dispatch
  (command.c: `dispatch_command`)

---

## 6. TOE Summary Specification

### 6.1 SFR-to-Implementation Mapping

| SFR | Implementation | Evidence Type |
|-----|---------------|--------------|
| FDP_IFC.2 | memory.c EPT map/unmap | ACSL contracts (WP 91.45%), GCC -fanalyzer, fuzz |
| FDP_IFF.1 | command.c capability check | ACSL contracts (WP 99.63%), smoke tests |
| FDP_RIP.2 | page_alloc.c zero guarantee | GCC -fanalyzer, design analysis |
| FIA_UID.2 | command.c VMCS-based caller ID | ACSL contracts (WP 99.63%) |
| FPT_SEP.3 | vmx.c VMX root/non-root | GCC -fanalyzer, VMCS field verification |
| FPT_TST.1 | kernel.c boot integrity | ACSL contracts (WP 99.88%), design analysis |
| FPT_FLS.1 | partition.c fault handling | ACSL contracts (WP 98.65%), fault injection tests (17 tests) |
| FPT_TDC.1 | command.c TOCTOU caching | ACSL contracts (WP 99.63%), code review |
| FAU_GEN.1 | log.c audit generation | ACSL contracts (WP 99.54%) |
| FAU_STG.2 | log.c primary sink + mirror ring | ACSL contracts (WP 99.54%), design analysis |
| FCS_COP.1 | Retained C only: SHA-384 measurement + per-page digest comparison | Phase 5 dependency; fail-closed on verify failure |
| FMT_SMF.1 | command.c 58 handlers | ACSL contracts (WP 99.63%), fuzz harness |
| FMT_SMR.1 | partition.c capability mask | ACSL contracts (WP 98.65%) |

### 6.2 Security Architecture Rationale

**Domain separation:** VMX root mode provides hardware-enforced
privilege separation. The TOE executes in VMX root (ring 0); all
partitions execute in VMX non-root. The hardware guarantees that
no VMX non-root instruction can modify VMCS host state, hypervisor
page tables, or TOE code/data without causing a VM exit that transfers
control to the TOE.

**Note:** Current implementation constraint: FreeBSD host remains in VMX root (host handoff not completed; target end state is VMX non-root deprivilege). Domain separation is partial until the host deprivilege path is finished.

**Bypass protection:** The TOE is the sole entity in VMX root mode.
All sensitive operations (memory mapping, device assignment, partition
lifecycle) require hypercall mediation through the command page
interface. The capability mask restricts which operations each
partition may invoke.

**Note:** Current implementation constraint: FreeBSD host remains in VMX root (host handoff not completed). Bypass protection is partial until the host deprivilege path is finished.

**Non-bypassability:** EPT/NPT page tables are controlled exclusively
by the TOE. Guest physical addresses are translated through
hardware-enforced second-level translation. No guest can modify its
own EPT/NPT mappings.

**Tamper resistance:** The TOE's code is in W^X sections enforced by
the linker script (fbvbs.ld). Guard pages separate .text, .rodata,
.data, and .bss. CR0.WP is pinned via VMCS host-state to prevent
write-protect bypass.

---

## 7. EAL5+ Assurance Requirements

### 7.1 Development (ADV)

#### ADV_ARC.1 -- Security Architecture Description

| Requirement | Evidence | Document |
|-------------|---------|----------|
| Domain separation | VMX root/non-root architecture | This ST, Section 6.2 |
| Non-bypassability | EPT/NPT hardware enforcement | wp_verification_boundary.md |
| Tamper resistance | W^X linker script + CR pinning | fbvbs.ld, cpu_security.c |

#### ADV_FSP.5 -- Complete Semiformal Functional Specification

| Requirement | Evidence | Status |
|-------------|---------|--------|
| Semiformal spec for all TSFIs | ACSL contracts on the current WP boundary | Partial: contracts exist, but current proof runs still leave gaps and timeouts |
| Error handling specification | ACSL behavior annotations (error paths) | Partial: many error paths are specified, but proof completion is not yet closed |
| Formal notation | ACSL (ANSI/ISO C Specification Language) | Tool: Frama-C 32.0 WP plugin |

The ACSL contracts constitute a semiformal functional specification.
Each function has preconditions (`requires`), postconditions (`ensures`),
frame conditions (`assigns`), and behavioral specifications
(`behavior` blocks for success/error paths). These contracts are
machine-checked by the Frama-C WP plugin against the C implementation.

#### ADV_TDS.4 -- Semiformal Modular Design

| Requirement | Evidence | Status |
|-------------|---------|--------|
| Subsystem decomposition | 14 subsystems (Section 1.4) | Complete |
| Subsystem interaction | Hypercall dispatch + direct function calls | Complete |
| Module design | Per-file modularity with static functions | Complete |
| Semiformal description | ACSL + C header contracts | Complete |

#### ADV_IMP.1 -- Implementation Representation

| Requirement | Evidence | Status |
|-------------|---------|--------|
| Complete implementation | 24 C source files, ~21K SLOC | Complete |
| Implementation standards | MISRA C:2023 (misra_c_deviation_log.md) | 6 documented deviations |
| Correspondence to design | ACSL contracts checked against implementation | Partial: reproducible WP runs exist, but the current tree still has proof gaps |

### 7.2 Guidance (AGD)

#### AGD_OPE.1 -- Operational User Guidance

| Requirement | Document | Status |
|-------------|---------|--------|
| Device qualification | device_qualification_matrix.md | Complete |
| Capability mask configuration | fbvbs_abi.h constants | Complete |
| Deployment restrictions | deployment_profile.md | Complete |
| Partition creation procedures | This ST, Section 7.2.1 | Complete |

#### AGD_PRE.1 -- Preparative Procedures

| Requirement | Document | Status |
|-------------|---------|--------|
| Build procedures | Makefile targets | Complete |
| Platform requirements | This ST, Section 1.2 | Complete |
| Audit OOB collection | audit_oob_collection.md | Complete |
| Secure Boot configuration | This ST, Section 7.2.2 | Complete |

##### AGD_OPE.1 Partition Creation Procedure

1. Build the release image with `make -C hypervisor release-hypervisor`.
2. Verify the bare-metal artifact with `make -C hypervisor verify-baremetal-iso`.
3. Review `hypervisor/build/release-manifest.txt` and confirm the ELF, ISO,
   proof-smoke, and SBOM digests match the intended release set.
4. Boot the target in the documented hypervisor configuration and confirm
   the log reaches `FBVBS: boot64 reached`, `boot artifacts materialized`,
   and `boot catalog ingested`.
5. Create partitions using the documented hypercall flow, then verify
   `PARTITION_MEASURE`, `PARTITION_LOAD_IMAGE`, and `PARTITION_START` return
   success for the intended image object.
6. Validate the created partition by checking the audit log entries and
   confirming that the partition reaches `Loaded` or `Runnable` only when
   the manifest and image object IDs match.

##### AGD_PRE.1 Secure Boot Configuration Procedure

1. Enable Secure Boot in platform firmware, disable CSM/legacy boot, and
   enroll the FBVBS signing key material in PK/KEK/db as appropriate.
2. Sign the UEFI loader and any boot-time artifacts used by the UEFI path;
   keep dbx current so revoked keys are rejected.
3. Ensure the retained-C boot path continues to use fixed ELF64 `ET_EXEC`
   artifacts with `-fno-pic -fno-pie -no-pie` and the repository linker script.
4. Validate the Multiboot path with `grub-file --is-x86-multiboot2` and the
   UEFI path with the platform's Secure Boot verification tooling.
5. Record the signed artifact hashes and boot-time measurements in the
   release manifest and audit log evidence bundle.

### 7.3 Life-cycle Support (ALC)

#### ALC_CMC.4 -- Production Support, Automation and Project Management

| Requirement | Evidence | Status |
|-------------|---------|--------|
| Configuration management | Git version control | Complete |
| Build automation | Make-based build system | Complete |
| Release promotion model | release_promotion_model.md | Complete |
| Reproducible builds | Deterministic build + SBOM + repository-local provenance (Phase 9-3) | Partial: deterministic build and unsigned provenance exist, but external signing and publication controls remain in progress |

#### ALC_TAT.2 -- Compliance with Implementation Standards

| Requirement | Evidence | Status |
|-------------|---------|--------|
| Implementation standard | MISRA C:2023 | 6 deviations documented |
| Tool compliance | GCC 13 -Wall -Wextra -Werror -Wpedantic | 0 warnings |
| Static analysis | GCC -fanalyzer + cppcheck | 0 findings |
| Formal verification tool | Frama-C 32.0 (Germanium) | Available for WP analysis; proof completion remains open |

#### ALC_FLR.3 -- Systematic Flaw Remediation (Augmentation)

| Requirement | Evidence | Status |
|-------------|---------|--------|
| Flaw remediation procedures | Git-based patch workflow | Complete |
| Fuzz regression | 5 repository-local harnesses | Partial: buildable and reviewable, but continuous fuzzing infrastructure is not yet closed |
| SBOM | Software bill of materials (Phase 9-3) | Complete |

### 7.4 Tests (ATE)

#### ATE_COV.2 -- Analysis of Coverage

| Requirement | Evidence | Status |
|-------------|---------|--------|
| Coverage analysis | gcov branch coverage (Phase 9-1) | Partial: reproducible repository-local coverage exists, but MC/DC closure is not yet demonstrated |
| Fuzz harness coverage | fuzz_command_page, fuzz_manifest, fuzz_multiboot2, fuzz_iommu, fuzz_log_decoder | Partial: harnesses exist, but sustained campaign evidence is still missing |
| Fault injection | test_fault_injection.c (17 tests) | Complete |
| Boundary tests | fbvbs_leaf_boundary_tests, fbvbs_policy_security_tests, fbvbs_fault_injection_tests | Complete |

#### ATE_DPT.3 -- Testing: Modular Design

| Requirement | Evidence | Status |
|-------------|---------|--------|
| Subsystem-level testing | Current WP target set + unit/fault tests | Partial: proof target is defined, but WP completion is not yet closed |
| Integration testing | Fuzz harnesses exercise cross-module paths | Complete |
| Platform integration testing | QEMU smoke covers boot/init and fail-closed paths; hardware VMX/SVM, EPT/NPT, and IOMMU validation are still required | hardware_validation_campaign.md defines the release-blocking real-hardware campaign |

### 7.5 Vulnerability Assessment (AVA)

#### AVA_VAN.5 -- Advanced Methodical Vulnerability Analysis (Augmentation)

| Requirement | Evidence | Document |
|-------------|---------|----------|
| Covert channel analysis | 7 channel categories, capacity estimates | covert_channel_analysis.md (CCA-001) |
| Speculative execution analysis | 81-feature CPU detection, per-exit mitigations | cpu_security.c, vm_policy.c |
| TOCTOU analysis | 4 cached fields in dispatch path | command.c |
| Side-channel hardening | Constant-time comparisons, compiler barriers | security.c, memory_utils.c |
| Service failure impact | 6 failure domains analyzed | service_failure_impact.md (SFI-001) |
| Debug register analysis | DR0-7 sanitization, shadow values, CR4.DE pin | vm_policy.c, cpu_security.c |

**Residual Risk Assessment (from CCA-001):**
- **Low:** L1D cache, TLB, branch predictors, MDS, DMA, debug registers,
  preemption timer (hardware mitigations in place)
- **Medium:** L1I cache, VM exit timing, BHB, QPI/UPI (partial mitigation)
- **High:** LLC (L3) sharing, L2 cache, DRAM row buffer, memory bandwidth
  (require hardware features not yet programmed: Intel CAT, SMT-aware
  scheduling)

**High-risk mitigation plan:**
- LLC (L3) sharing: owner Platform Security; Phase 9 follow-on for Intel CAT
  programming, with fallback to core-dedicated deployments when CAT is
  unavailable.
- L2 cache sharing: owner Scheduler/MP Integration; Phase 8 follow-on for
  SMT-aware scheduling, with fallback to SMT-off deployment profiles on
  high-assurance systems.
- DRAM row buffer and memory bandwidth: owner Platform Security; mitigate by
  NUMA-local placement and dedicated-core profiles, with acceptance only if
  controller partitioning is unavailable and the deployment is explicitly
  approved for the residual risk.

---

## 8. Rationale

### 8.1 Threat-to-Objective Mapping

| Threat | Security Objectives |
|--------|-------------------|
| T.BYPASS | O.ISOLATION, O.ACCESS_CONTROL |
| T.TAMPER | O.INTEGRITY, O.AUDIT |
| T.LEAK | O.ISOLATION, O.SPECTRE |
| T.ROLLBACK | O.INTEGRITY |
| T.DMA | O.DMA_CONTROL |
| T.SPECTRE | O.SPECTRE, O.ISOLATION |

### 8.2 Objective-to-SFR Mapping

| Objective | SFRs |
|-----------|------|
| O.ISOLATION | FDP_IFC.2, FDP_RIP.2, FPT_SEP.3 |
| O.INTEGRITY | FPT_TST.1, FPT_FLS.1 |
| O.AUDIT | FAU_GEN.1, FAU_GEN.2, FAU_STG.2, FAU_SAR.1 |
| O.DMA_CONTROL | FDP_IFC.2 (IOMMU domain aspect) |
| O.SPECTRE | FDP_IFC.2 (microarchitectural aspect), FDP_RIP.2 |
| O.ACCESS_CONTROL | FDP_IFF.1, FIA_UID.2, FMT_SMF.1, FMT_SMR.1 |

### 8.3 SFR-to-Implementation Completeness

Most SFR mappings have at least repository-local design, analysis, or
test evidence, but they are not all fully closed by current formal proof
or hardware validation.

FCS_COP.1 depends on Phase 5 (Ada/SPARK cryptographic library). The
TOE is fail-closed in the absence of crypto: hash verification returns
MEASUREMENT_FAILED, execute permission is denied. That fail-closed
behavior reduces exposure, but it does not satisfy the missing FCS_COP.1
algorithms or replace the Phase 5 implementation dependency.

---

## 9. Open Items and Evaluator Notes

### 9.1 Known Gaps

| Gap | Impact | Resolution Path |
|-----|--------|----------------|
| FCS_COP.1 not implemented | retained C has only a narrow SHA-384 measurement path for KCI; the general crypto suite (signature, MAC, key derivation, encryption) is still absent, so SKPP strict conformance remains target-state only | Phase 5: Ada/SPARK crypto library |
| Audit storage primary OOB sink | Retained-C emits primary UART/OOB audit lines and mirror records, but deployment still needs authoritative external collection/retention | Bind release/deployment guidance to the serial/OOB collector and archive FAU_STG.2 evidence |
| Platform integration tests | QEMU smoke covers boot/init/fail-closed paths only; no hardware VMX/SVM, EPT/NPT, or IOMMU validation yet | Phase 4+: requires target platform |
| IOMMU MMIO access | VT-d/AMD-Vi retained-C init performs MMIO/programming work, but authoritative host device/domain policy and hardware validation are still incomplete | Complete default-deny host policy, then close the hardware validation campaign |
| Host deprivilege handoff | `VMLAUNCH` path still fails closed | vmcs_setup.c implementation completion + hardware validation |
| `KCI_SET_WX` byte binding | Implemented in retained C with full-module SHA-384 verification + approved per-page digest table; external crypto boundary and proof completion remain | Phase 5 crypto boundary tightening + WP completion |
| LLC/L2 covert channels | High residual risk | Intel CAT / SMT-aware scheduling extensions |
| Operational guidance | Partition creation and preparative procedures documented | ITSEF review and deployment validation |
| CI/CD pipeline | Repository CI exists, and repository-local provenance/evidence artifacts are generated, but external signing and hardened publication controls remain | Phase 9 hardening continuation |

### 9.2 Evaluation Readiness

| CC Class | Readiness | Notes |
|----------|----------|-------|
| ADV (Development) | MEDIUM | ACSL contracts exist and WP runs launch, but proof completion is still open |
| AGD (Guidance) | MEDIUM | Repository-local guidance now includes operational and preparative procedures, but evaluator review is still required |
| ALC (Life-cycle) | MEDIUM | Build automation, SBOM, and branch model exist; provenance and hardened release process are still maturing |
| ATE (Tests) | MEDIUM | unit/fault/fuzz build and QEMU smoke exist; hardware integration tests are still pending |
| AVA (Vulnerability) | HIGH | CCA-001 covert channel analysis + cpu_security.c vuln profiling |

### 9.3 Recommended Next Steps

1. **Engage ITSEF (IT Security Evaluation Facility)** for formal evaluation
   scoping and ST review
2. **Submit AGD documentation** (operational guidance, preparative
   procedures) for ITSEF review and validation
3. **Implement FCS_COP.1** (Phase 5 crypto) to close the last SFR gap
4. **Formalize ALC_CMC** procedures (configuration management plan,
   release process)
5. **Execute platform integration tests** on target hardware to satisfy
   ATE_DPT.3 fully
6. **Implement LLC partitioning** (Intel CAT) to reduce AVA_VAN.5
   residual risk for high-assurance deployments

---

## 10. References

| Reference | Description |
|-----------|-------------|
| ISO/IEC 15408:2022 | Common Criteria for Information Technology Security Evaluation |
| ISO/IEC 18045:2022 | Common Evaluation Methodology |
| SKPP v1.03 | Separation Kernel Protection Profile (NIAP) |
| NIAP VPP v1.1 | Virtualization Protection Profile Module |
| Intel SDM Vol. 3 | Intel 64 and IA-32 Architectures Software Developer's Manual |
| AMD APM Vol. 2 | AMD64 Architecture Programmer's Manual |
| CCA-001 | covert_channel_analysis.md (this project) |
| SFI-001 | service_failure_impact.md (this project) |
| MISRA-DEV-001 | misra_c_deviation_log.md (this project) |
| WP-BOUNDARY | wp_verification_boundary.md (this project) |
| NIST SP 800-53 Rev. 5 | Security and Privacy Controls for Information Systems |
