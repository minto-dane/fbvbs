# AMD NPT Translation Integrity Certification (REQ-1100, REQ-0302, REQ-0303, REQ-0304)

**Document:** NPT-CERT-001
**Date:** 2026-03-23
**Phase:** 9-2 (AMD Translation Integrity Pre-Production Certification)
**Scope:** `hypervisor/src/amd_npt.c` -- NPT write-protect, PTE fault handler, TLB synchronisation, SEV-SNP complement, GMET W^X
**Applicable:** FBVBS Design Spec Section 21.3 (Translation Integrity), Appendix F.1 (AMD Certification Challenge), AMD APM Vol. 2 Chapter 15 (SVM)

This document is a pre-production certification plan plus model-level design evidence. It is not a completed hardware certification report. Items described as complete below refer to repository-local design or model coverage unless explicitly backed by adversarial Zen hardware measurements.

---

## 1. Requirements

| Requirement | Title | Specification Text | Verification Method |
|-------------|-------|-------------------|---------------------|
| REQ-1100 | AMD Translation Integrity Pre-Production Certification | Production declaration requires completion of AMD translation integrity path certification. | Adversarial multiprocessor campaign |
| REQ-0302 | AMD NPT Compound Path | AMD configurations shall not claim single-mechanism guarantee equivalent to HLAT; must implement NPT write-protect, fault handling, shadow translation, and TLB synchronisation as a compound path. | Design inspection + adversarial test |
| REQ-0303 | AMD High-Assurance Certification | AMD configurations claiming high assurance must complete certification against PFN substitution, PTE tampering, TLB invalidation race, and multi-core update contention. | Adversarial multiprocessor test |
| REQ-0304 | SEV-SNP Complement Only | When SEV-SNP is used, RMP and VMPL may be used as reinforcement but shall not be the sole basis for claiming equivalence to HLAT. | Design review + documentation review |

---

## 2. Architecture Overview

On AMD platforms, FBVBS enforces kernel code integrity through a four-layer compound mechanism in `amd_npt.c`:

1. **NPT Write-Protect** (Phase 3-1): Kernel PTE pages are mapped read-only in the Nested Page Table. Any guest write to a PTE page triggers `#VMEXIT(NPT fault)`.

2. **PTE Update Trap** (Phase 3-2): The NPT fault handler (`fbvbs_npt_handle_fault`, line 554) validates each PTE modification against KCI policy before emulation. PFN substitution on executable PTEs is unconditionally rejected.

3. **TLB Synchronisation** (Phase 3-3): INVLPG and INVLPGA are intercepted (`SVM_INTERCEPT_INVLPG`, `SVM_INTERCEPT_INVLPGA`). A monotonic generation counter (`tlb_generation`) and IPI-based cross-core invalidation prevent stale TLB entries from bypassing write-protect.

4. **SEV-SNP Complement** (Phase 3-4, optional): When present, the RMP table provides hardware-enforced page ownership at the VMPL level. This complements, but does not replace, the NPT write-protect scheme.

Additionally, **GMET** (Guest Mode Execute Trap, AMD's MBEC equivalent) splits NPT execute permissions into user-mode and supervisor-mode controls, enforcing per-privilege-level W^X.

---

## 3. Test Matrix

### 3.1 PFN Swap Attack Test

**Requirement:** REQ-0303 (PFN substitution attack certification)

**Description:** A malicious guest kernel attempts to replace the physical frame number (PFN) in an executable PTE entry while preserving all other permission bits. This is the canonical PFN substitution attack: the guest tries to redirect a verified code page to attacker-controlled memory containing arbitrary code, without modifying execute permissions.

**Preconditions:**
- Partition created on AMD platform with NPT active (`nps->config.active == 1U`)
- Kernel text region registered via `fbvbs_npt_add_code_region` (line 234)
- PTE page covering kernel text write-protected via `fbvbs_npt_protect_pte_page` (line 353)
- Existing PTE has Present=1, NX=0 (executable), PFN=original

**Expected Behavior (fail-closed):**
- Guest writes a new PTE with Present=1, NX=0 (executable), PFN=attacker
- Write triggers `#VMEXIT(NPT fault)` because the PTE page is write-protected
- `fbvbs_npt_validate_pte_write` (line 498) detects `old_exec && new_exec && old_pfn != new_pfn`
- Returns `-1` (SECURITY VIOLATION, line 528)
- `fbvbs_npt_handle_fault` propagates `-1` (line 574)
- Partition is faulted; guest does not resume

**Pass Criteria:**
- `fbvbs_npt_handle_fault_exit` returns `-1` for every PFN substitution attempt
- No guest instruction executes from the attacker-supplied PFN
- Partition transitions to FAULTED state

**Implementation Evidence:**
- `fbvbs_npt_validate_pte_write`, lines 527-528: `if (old_exec && new_exec && old_pfn != new_pfn) { return -1; }`
- PFN extraction at lines 506-507: `old_pfn = (old_pte & NPT_PTE_ADDR_MASK) >> 12; new_pfn = (new_pte & NPT_PTE_ADDR_MASK) >> 12;`
- ACSL contract ensures only three return values: `ensures \result == 0 || \result == -1 || \result == -2;`

---

### 3.2 PTE Tampering Detection Test

**Requirement:** REQ-0303 (PTE tampering detection certification)

**Description:** A malicious guest attempts to modify permission bits on an executable PTE entry -- specifically, adding write permission to create a writable+executable (W+X) page, or flipping the NX bit to make a data page executable without KCI hash verification. Both attacks are subsets of PTE tampering that must be detected and rejected.

**Preconditions:**
- NPT active for partition
- Executable PTE exists (Present=1, NX=0, RW=0)
- PTE page is write-protected in NPT

**Expected Behavior (fail-closed):**

*Subcase A -- W+X violation:*
- Guest writes PTE with Present=1, NX=0, RW=1 (writable + executable)
- `fbvbs_npt_validate_pte_write` detects `new_exec && (new_pte & NPT_PTE_RW) != 0ULL`
- Returns `-1` (W+X violation, line 534)

*Subcase B -- Unauthorized execute grant:*
- Guest writes PTE with Present=1, NX=0 where the old PTE was non-executable or not present
- `fbvbs_npt_validate_pte_write` detects `!old_exec && new_exec`
- Returns `-2` (needs KCI approval, line 522)
- `fbvbs_npt_handle_fault` treats `-2` as rejection (line 581): returns `-1`
- The outer handler in `vm_policy.c` may check KCI bindings; without a valid KCI binding, the partition is faulted

*Subcase C -- Benign updates allowed:*
- Hardware-generated accessed/dirty bit updates on existing executable PTEs (same PFN, no W or NX change) return `0` (line 539)

**Pass Criteria:**
- W+X PTE modifications always rejected (`return -1`)
- New executable mappings without KCI approval always rejected (`return -2`, escalated to `-1`)
- Benign accessed/dirty updates on verified PTEs succeed (`return 0`)

**Implementation Evidence:**
- W+X check, line 533: `if (new_exec && (new_pte & NPT_PTE_RW) != 0ULL) { return -1; }`
- Execute grant check, lines 521-522: `if (!old_exec && new_exec) { return -2; }`
- GMET W^X enforcement, line 1132-1134: `if (writable && policy != GMET_POLICY_DATA_ONLY) { return 0ULL; }` (empty permissions = reject)
- GMET VMCB validation, lines 1199-1210: runtime W^X invariant check on kernel_perm, user_perm, data_perm

---

### 3.3 TLB Invalidate Race Test

**Requirement:** REQ-0303 (TLB invalidation race condition certification)

**Description:** A malicious guest exploits the window between a PTE modification (trapped and validated) and the corresponding TLB invalidation. The attack sequence is:
1. vCPU-0 writes a PTE (trapped by NPT write-protect, validated, emulated)
2. Before INVLPG propagates to vCPU-1, the guest executes from the stale TLB entry on vCPU-1
3. If the stale entry points to pre-modification code, no harm; but if the hypervisor emulated a PTE clear followed by a new mapping, the race window could allow execution from an unverified page

**Preconditions:**
- Multi-vCPU partition (vcpu_count >= 2)
- NPT active
- Both vCPUs have TLB entries for a code region
- Guest issues INVLPG on vCPU-0 targeting a code address

**Expected Behavior (fail-closed):**
- INVLPG triggers `#VMEXIT(SVM_EXIT_INVLPG)`, handled by `fbvbs_npt_handle_invlpg` (line 619)
- TLB generation counter incremented (saturating at UINT64_MAX, line 633-635)
- `pending_invlpg` counter incremented for code addresses (line 625-627)
- IPI issued to all other cores for TLB flush (PRODUCTION NOTE, line 637-640)
- Guest does not resume until all cores have acknowledged the flush
- `pending_invlpg` decremented only after acknowledgement (line 642-644)

**Serialization Invariant:**
- NPT fault handling is serialized under the BHL (Big Hypervisor Lock)
- This prevents TOCTOU on the guest PTE value between read and validation
- Without BHL, a per-partition spinlock would be required (documented at lines 425-431)

**Pass Criteria:**
- `fbvbs_npt_check_tlb_sync` (line 655) returns `-1` (stale) whenever `pending_invlpg > 0`
- No guest execution resumes with stale TLB entries for modified code pages
- TLB generation counter is monotonically increasing (saturates, never wraps)

**Implementation Evidence:**
- INVLPG intercept: `SVM_INTERCEPT_INVLPG` (line 74), `SVM_INTERCEPT_INVLPGA` (line 75)
- Generation counter saturation, line 633: `if (config->tlb_generation < UINT64_MAX)`
- Pending flush tracking, lines 624-628: increment only for code addresses via `fbvbs_npt_is_code_address`
- Sync check, lines 659-665: returns `-1` if generation stale OR pending invalidations exist
- VMCB config, lines 700-702: both INVLPG and INVLPGA intercepts set in `intercept_misc`

---

### 3.4 Multi-Core Update Contention Test

**Requirement:** REQ-0303 (multi-core PTE update serialization certification)

**Description:** Multiple vCPUs in the same partition concurrently attempt to modify different PTEs on the same write-protected PTE page. This tests the serialization of NPT fault handling: each write triggers an independent `#VMEXIT`, and the hypervisor must process them sequentially without data corruption, lost updates, or permission escalation through interleaving.

**Preconditions:**
- Multi-vCPU partition (vcpu_count >= 2)
- NPT active
- Single PTE page contains entries for both data and code regions
- vCPU-0 and vCPU-1 simultaneously write to different offsets on the same PTE page

**Expected Behavior (fail-closed):**
- Each write triggers `#VMEXIT(NPT fault)` independently on each vCPU
- The BHL serializes entry into `fbvbs_npt_handle_fault_exit` (line 990)
- vCPU-0's fault is fully processed (validate, emulate, TLB bump) before vCPU-1's begins
- No interleaving of old_pte reads and new_pte emulations across vCPUs
- Each PTE modification is validated against the post-emulation state of the page, not a stale snapshot

**Pass Criteria:**
- No PTE corruption from concurrent access
- Security validation is applied to every individual PTE write
- TLB generation increments for each modification (no lost increments)
- A security violation on one vCPU does not prevent correct handling on the other

**Implementation Evidence:**
- Serialization documented at lines 422-431: BHL guarantees sequential processing
- `fbvbs_npt_handle_fault_exit` (line 990) is the single entry point for all NPT faults
- PRODUCTION NOTE at line 589-593: PTE emulation is atomic (write-enable, write, re-protect with no guest execution in between)
- TLB generation increment at lines 585-587 occurs under BHL, preventing lost updates

**Hardware Test Requirement:** This test requires execution on Zen 2+ hardware with SVM and NPT support. The model implementation serializes inherently (single-threaded); the concurrent contention scenario can only be validated on real multi-core hardware or via a concurrency testing framework (e.g., Litmus tests for the SVM memory model).

---

### 3.5 SEV-SNP Complement Verification

**Requirement:** REQ-0304 (SEV-SNP is supplementary, not a replacement for NPT)

**Description:** Verify that SEV-SNP RMP enforcement, when available, strengthens the NPT compound path but that disabling SEV-SNP does not weaken NPT-only protection below the security baseline. The NPT write-protect mechanism must be independently sufficient.

**Preconditions:**
- Partition initialized with `fbvbs_npt_init_for_partition` (line 799)
- SEV-SNP configuration initialized via `fbvbs_sev_snp_config_init` (line 747)

**Expected Behavior:**

*Subcase A -- SEV-SNP unavailable:*
- `fbvbs_sev_snp_config_init` sets `available = 0U`, `active = 0U` (lines 749-751)
- `fbvbs_sev_snp_validate_code_page` returns `0` (pass-through, line 769)
- All NPT write-protect, PTE validation, and TLB synchronisation mechanisms remain fully operational
- Security guarantee is identical to the compound NPT path alone

*Subcase B -- SEV-SNP available and active:*
- RMP entry validation adds an additional check (PRODUCTION NOTE, lines 774-780):
  - Owner ASID matches partition
  - Page type is correct (4K or 2M)
  - VMPL permissions allow supervisor execute
- Failure to pass RMP validation rejects the operation even if NPT validation passes
- RMP provides defense-in-depth against hypervisor-level bugs in NPT emulation

*Subcase C -- Architectural independence:*
- `fbvbs_npt_init_for_partition` calls both `fbvbs_npt_config_init` and `fbvbs_sev_snp_config_init` independently (lines 826, 887)
- The NPT configuration (`nps->config`) is complete and active regardless of SEV-SNP state
- No NPT code path has a conditional dependency on `snp.active`
- VMPL levels defined (`FBVBS_VMPL_HYPERVISOR = 0`, `FBVBS_VMPL_GUEST = 1`, lines 729-730) but used only when SEV-SNP is enabled

**Pass Criteria:**
- All tests in sections 3.1-3.4 pass identically with SEV-SNP disabled
- Enabling SEV-SNP adds additional rejection paths but never weakens existing NPT checks
- No code path bypasses NPT validation based on SEV-SNP availability

**Implementation Evidence:**
- SEV-SNP initialization is isolated: `fbvbs_sev_snp_config_init` (line 747) and `fbvbs_sev_snp_validate_code_page` (line 764) are independent of NPT config
- The SEV-SNP check in `fbvbs_npt_init_for_partition` is a stack-local validation (lines 886-890) that does not modify the NPT config
- `fbvbs_sev_snp_validate_code_page` returns `0` (no-op) when `active == 0U` (line 769)
- The function is called after NPT setup is complete, not as a gate for NPT activation

---

## 4. Verification Evidence

### 4.1 Static Analysis (Complete)

| Tool | Scope | Result |
|------|-------|--------|
| GCC 13 `-fanalyzer` | All 1,248 lines of `amd_npt.c` | 0 warnings |
| cppcheck `--enable=warning,performance,portability` | All source files | 0 findings |

### 4.2 ACSL Contracts (Complete)

All functions in `amd_npt.c` have ACSL contracts specifying:

| Function | Contract Summary | Lines |
|----------|-----------------|-------|
| `fbvbs_npt_config_init` | `\valid(config); assigns *config` | 185-187 |
| `fbvbs_npt_add_code_region` | Alignment requires, overflow guard, `ensures \result == 0 \|\| \result == -1` | 227-232 |
| `fbvbs_npt_remove_code_region` | `assigns *config; ensures \result == 0 \|\| \result == -1` | 306-308 |
| `fbvbs_npt_protect_pte_page` | Alignment requires, level range, `ensures \result == 0 \|\| \result == -1` | 348-351 |
| `fbvbs_npt_is_protected_page` | `assigns \nothing; ensures \result == 0 \|\| \result == 1` | 433-435 |
| `fbvbs_npt_is_code_address` | `assigns \nothing; ensures \result == 0 \|\| \result == 1` | 458-460 |
| `fbvbs_npt_validate_pte_write` | `assigns \nothing; ensures \result == 0 \|\| \result == -1 \|\| \result == -2` | 495-496 |
| `fbvbs_npt_handle_fault` | `assigns config->tlb_generation; ensures \result == 0 \|\| \result == -1` | 550-552 |
| `fbvbs_npt_handle_invlpg` | `assigns config->tlb_generation, config->pending_invlpg; ensures \result == 0` | 615-617 |
| `fbvbs_npt_check_tlb_sync` | `assigns \nothing; ensures \result == 0 \|\| \result == -1` | 651-653 |
| `fbvbs_npt_build_vmcb_config` | `assigns *vmcb_config` | 685-687 |
| `fbvbs_sev_snp_config_init` | `assigns *config` | 744-745 |
| `fbvbs_sev_snp_validate_code_page` | `assigns \nothing; ensures \result == 0 \|\| \result == -1` | 760-762 |
| `fbvbs_gmet_npt_permissions` | W^X postcondition on return value | 1118-1123 |
| `fbvbs_gmet_build_config` | `assigns *npt_control_or; ensures \result == 0 \|\| \result == -1` | 1174-1176 |

`fbvbs_npt_validate_pte_write` is identified as a WP-compatible pure function (documented in `wp_verification_boundary.md`, line 89). Loop invariants with `loop variant` clauses are provided on all bounded loops.

### 4.3 Frama-C WP Status

`amd_npt.c` is classified as WP-excluded (platform/hardware file) in the verification boundary document. The pure validation functions (`fbvbs_npt_validate_pte_write`, `fbvbs_npt_is_protected_page`, `fbvbs_npt_is_code_address`, `fbvbs_npt_check_tlb_sync`) are candidates for incremental WP expansion as they contain no hardware interaction.

### 4.4 What Requires Hardware Testing

The following aspects cannot be verified by static analysis or formal proof and require execution on AMD Zen 2+ hardware with SVM and NPT support:

| Aspect | Reason | Required Platform |
|--------|--------|-------------------|
| NPT write-protect enforcement | Hardware must trap writes to read-only NPT entries | SVM + NPT (any Zen) |
| PTE emulation atomicity | Write-enable, write, re-protect sequence must execute without guest preemption | SVM + NPT |
| IPI-based TLB shootdown | Cross-core INVLPG acknowledgement must complete before guest resume | Multi-core Zen 2+ |
| Multi-core serialization under BHL | Concurrent NPT faults must serialize correctly | Multi-core Zen 2+ |
| SEV-SNP RMP validation | RMP table read and ASID/VMPL permission check | SEV-SNP capable (Zen 3+) |
| GMET privilege-level enforcement | Hardware must trap user/supervisor execute mismatch | GMET capable (Zen 3+) |
| VMCB NPT_CR3 population | VMRUN must use the NPT PML4 page address from VMCB | SVM + NPT |

---

## 5. NPT vs HLAT Comparison

Both Intel HLAT and AMD NPT compound path achieve the same security objective -- restricting guest kernel code execution to hash-verified pages -- but through fundamentally different mechanisms.

| Property | Intel HLAT | AMD NPT Compound Path |
|----------|-----------|----------------------|
| **Mechanism** | Single hardware feature: second linear-address translation table controlled by hypervisor | Four-layer compound: NPT write-protect + PTE trap + TLB sync + optional SEV-SNP |
| **Complexity** | Low (one VMCS pointer + one page table hierarchy) | High (fault handler, generation counter, IPI shootdown, VMCB intercepts) |
| **Hardware dependency** | 12th Gen+ Intel (Alder Lake, CPUID.7.1:EAX[5]) | Any AMD with SVM + NPT (Zen 1+); SEV-SNP requires Zen 3+; GMET requires Zen 3+ |
| **Attack surface** | Minimal (hardware enforcement) | Larger (software fault handler in TCB) |
| **W^X enforcement** | Via HLAT PTE permissions + EPT MBEC | Via NPT PTE permissions + GMET |
| **TLB management** | Hardware manages HLAT TLB entries | Software intercepts INVLPG/INVLPGA for synchronisation |
| **Formal verification** | `hlat.c`: boundary check ACSL, GCC -fanalyzer | `amd_npt.c`: validation function ACSL, GCC -fanalyzer |
| **REQ** | REQ-0301 (Intel HLAT mandatory) | REQ-0302 (AMD compound path mandatory) |

**Why both paths are needed:** FBVBS must support both Intel and AMD server platforms. Intel provides HLAT as a single hardware mechanism (REQ-0301); AMD lacks HLAT and requires the compound NPT approach (REQ-0302). The design specification explicitly prohibits claiming HLAT-equivalent single-mechanism assurance on AMD (REQ-0302) and requires pre-production adversarial testing of the compound path (REQ-1100). When available, Intel HLAT is the preferred path due to lower complexity and smaller attack surface.

---

## 6. Residual Risk

| Risk | Description | Mitigation | Acceptance |
|------|-------------|------------|------------|
| R-NPT-1 | NPT compound path is inherently more complex than Intel HLAT | ACSL contracts on all validation functions; GCC -fanalyzer; bounded loops with variants; fail-closed on all error paths | Intel HLAT preferred when available; AMD path is complementary (Roadmap R-1) |
| R-NPT-2 | PTE emulation window (write-enable, write, re-protect) is a timing-sensitive critical section | PRODUCTION NOTE documents atomicity requirement; BHL prevents guest execution during emulation | Hardware test on Zen 2+ required to validate |
| R-NPT-3 | Model code uses placeholder values for old_pte/new_pte in `fbvbs_npt_handle_fault_exit` | Production must decode guest instruction or walk page tables to obtain actual PTE values | Hardware test required |
| R-NPT-4 | SEV-SNP RMP validation is model-only (always returns 0) | Production must implement CPUID detection and RMP table reads; model validates interface | SEV-SNP is complement only (REQ-0304); NPT path is independently sufficient |
| R-NPT-5 | GMET availability is model-assumed (always available) | Production must check CPUID Fn8000_000A:EDX[24] | Fail-closed: without GMET, basic NPT W^X applies |

---

## 7. Certification Status

| Item | Status | Evidence |
|------|--------|----------|
| Design analysis | **Complete** | `amd_npt.c` implements all four compound path layers |
| ACSL contracts | **Complete** | 15 functions with requires/ensures/assigns |
| GCC -fanalyzer | **Complete** | 0 warnings |
| PFN swap attack (model) | **Complete** | `fbvbs_npt_validate_pte_write` lines 527-528 |
| PTE tampering detection (model) | **Complete** | `fbvbs_npt_validate_pte_write` lines 521-534 |
| TLB race prevention (model) | **Complete** | `fbvbs_npt_handle_invlpg` + generation counter |
| Multi-core serialization (model) | **Complete** | BHL serialization documented, single-threaded model |
| SEV-SNP complement verification | **Complete** | Architectural independence confirmed |
| GMET W^X validation | **Complete** | `fbvbs_gmet_build_config` runtime invariant check |
| Hardware measurement (Zen 2+) | **Required** | Not yet performed -- requires physical AMD server |
| Hardware measurement (SEV-SNP, Zen 3+) | **Required** | Not yet performed -- requires SEV-SNP capable server |
| Multi-core adversarial test (hardware) | **Required** | Not yet performed -- requires multi-socket AMD server |

**Overall:** Design analysis complete. Hardware measurement on Zen 2+ platform is the remaining gate for REQ-1100 certification.

---

## 8. References

- AMD Architecture Programmer's Manual, Vol. 2, Chapter 15 (Secure Virtual Machine)
- AMD APM Vol. 2, Section 15.25.5 (Guest Mode Execute Trap)
- AMD APM Vol. 2, Section 15.36 (SEV-SNP)
- FBVBS Design Specification, Section 21.3 (Translation Integrity)
- FBVBS Design Specification, Appendix F.1 (AMD Translation Integrity Certification Challenge)
- FBVBS Design Specification, Appendix G.4 (Translation Integrity Requirements)
- `hypervisor/src/amd_npt.c` -- NPT compound path implementation (1,248 lines)
- `hypervisor/src/hlat.c` -- Intel HLAT implementation (1,110 lines)
- `hypervisor/compliance/wp_verification_boundary.md` -- WP verification boundary classification
- `hypervisor/compliance/covert_channel_analysis.md` -- TLB and cache channel analysis
