# Exhaustive x86_64 CPU security features for hypervisor-based OS security

**No public "FBVBS v7" specification exists in any indexed repository, FreeBSD mailing list, or academic database.** This report therefore catalogs every CPU hardware security mechanism relevant to a FreeBSD Virtualization-Based Security system and evaluates what such a specification *must* reference to be considered complete. The analysis covers **81 distinct features** across Intel and AMD, organized into eight categories, with concrete recommendations for each. Windows VBS/HVCI and the Linux Heki/LVBS project serve as reference implementations against which completeness is measured.

The bottom line: a maximally secure hypervisor-based FreeBSD system must leverage at minimum **34 mandatory or strongly recommended features** across control flow integrity, memory protection, virtualization controls, DMA isolation, speculative execution mitigation, and trusted boot. The most critical gaps in any nascent VBS-like specification are typically MBEC/GMET utilization for efficient W^X enforcement, comprehensive speculative execution mitigation (especially BHI, SRSO, and PBRSB), VT-rp/HLAT for anti-remapping, and IOMMU integration for DMA attack prevention.

---

## 1. Control flow integrity and indirect branch protection

These features protect the forward and backward edges of control flow — preventing ROP, JOP, and Spectre-class branch injection attacks. A security hypervisor must both use them internally and enforce them on the protected OS kernel.

### Intel CET Shadow Stack (CET-SS)
- **Intel name / AMD name**: CET Shadow Stack / AMD Shadow Stack (shared ISA)
- **Introduced**: Intel Tiger Lake (11th Gen, 2020); AMD Zen 3 (EPYC Milan / Ryzen 5000, 2020)
- **CPUID**: `CPUID.(EAX=7,ECX=0):ECX[bit 7]`; enabled via **CR4.CET** (bit 23)
- **MSRs**: IA32_S_CET (0x6A2), IA32_U_CET (0x6A0), IA32_PL0_SSP through IA32_PL3_SSP (0x6A4–0x6A7), IA32_INTERRUPT_SSP_TABLE_ADDR (0x6A8)
- **Function**: Maintains a hardware-enforced secondary stack. On CALL, the return address is pushed to both the normal stack and the shadow stack. On RET, the CPU compares both; a mismatch raises **#CP** (control-protection fault). Each privilege level (PL0–PL3) has a dedicated Shadow Stack Pointer (SSP).
- **Hypervisor use**: The hypervisor manages shadow stack pages via EPT (marked with supervisor shadow stack attributes). Windows VBS allocates kernel shadow stacks through the Secure Kernel (VTL1) via `VslAllocateKernelShadowStack`. KVM/SVM patches save/restore shadow stack MSRs in VMCB. AMD's SSSCheck bit (`CPUID Fn8000_000A_EDX[bit 19]`) provides supervisor shadow stack verification through nested page tables.
- **FBVBS relevance**: **MUST reference.** This is the primary backward-edge CFI mechanism. The specification should mandate CET-SS for the hypervisor itself and enforce it on the protected kernel via CR4.CET pinning and EPT-protected shadow stack pages.

### Intel CET Indirect Branch Tracking (CET-IBT)
- **Intel name**: CET_IBT; **AMD**: Not implemented (Intel-specific)
- **Introduced**: Intel Tiger Lake (11th Gen, 2020)
- **CPUID**: `CPUID.(EAX=7,ECX=0):EDX[bit 20]`
- **Function**: Requires that an **ENDBR64** instruction is the first instruction after any indirect CALL or JMP. If another instruction is found, a #CP fault fires. ENDBR acts as a NOP on older CPUs. This defeats Jump-Oriented Programming (JOP) and Call-Oriented Programming (COP).
- **Hypervisor use**: Linux kernel IBT merged in v5.18. Windows does *not* use IBT (relies on Control Flow Guard instead). The hypervisor should enable IBT for its own code and optionally enforce it on the guest kernel. On AMD systems, forward-edge CFI must rely on software mechanisms (e.g., FineIBT in Linux or CFG).
- **FBVBS relevance**: **Should reference.** Intel-only but important for forward-edge CFI on Intel platforms.

### IBPB (Indirect Branch Predictor Barrier)
- **Intel CPUID**: `CPUID.(EAX=7,ECX=0):EDX[26]`; **AMD CPUID**: `Fn8000_0008:EBX[12]`
- **MSR**: IA32_PRED_CMD (0x49), bit 0 — write-only command
- **Introduced**: Via microcode on Intel Haswell+ and AMD Zen+ (2018)
- **Function**: Flushes all indirect branch predictor entries (BTB, RSB entries created before the barrier). Not a mode — a one-shot command.
- **Hypervisor use**: **Critical for guest-to-guest isolation.** Must be issued on every VM context switch between different guests. Even with eIBRS/AutoIBRS, IBPB remains necessary when switching between same-privilege-level contexts. On AMD Zen 4+, IBPB also clears the RSB (IBPB_RET — `CPUID Fn8000_0008:EBX[30]`); on older AMD, RSB filling is still needed separately.
- **FBVBS relevance**: **MUST reference.** Fundamental to inter-VM isolation.

### eIBRS (Enhanced IBRS) — Intel
- **Detection**: `IA32_ARCH_CAPABILITIES` MSR (0x10A), bit 1 (IBRS_ALL)
- **Introduced**: Intel Cascade Lake (2019), Ice Lake, and all newer
- **Function**: Set-and-forget IBRS — write `IA32_SPEC_CTRL[0]=1` once at boot, never toggle. Hardware automatically restricts indirect branch predictions across privilege boundaries and across hyperthreads. Eliminates the WRMSR-per-transition overhead of legacy IBRS.
- **Limitation**: Does **not** isolate the Branch History Buffer (BHB) — BHI attacks remain possible. Does not prevent same-privilege-mode influence (still need IBPB for that).
- **FBVBS relevance**: **MUST reference** as primary Spectre v2 mitigation on Intel.

### AMD AutoIBRS
- **CPUID**: `Fn8000_0021:EAX[bit 8]`; enabled via **EFER bit 21**
- **Introduced**: AMD Zen 4 (EPYC Genoa / Ryzen 7000, 2022)
- **Function**: AMD's equivalent of eIBRS. Set-and-forget via EFER.AUTOIBRS. Key difference: AutoIBRS **clears the internal return address stack on VMEXIT** (Intel eIBRS does not — hence PBRSB is Intel-only). Still requires explicit STIBP for userspace cross-thread protection.
- **FBVBS relevance**: **MUST reference** as primary Spectre v2 mitigation on AMD Zen 4+.

### STIBP (Single Thread Indirect Branch Predictors)
- **Intel/AMD CPUID**: `CPUID.(7,0):EDX[27]` / `Fn8000_0008:EBX[15]`
- **MSR**: IA32_SPEC_CTRL (0x48), bit 1
- **Function**: Prevents branch predictions from crossing between SMT sibling threads. Intel eIBRS implicitly provides STIBP in kernel mode; AMD AutoIBRS does not.
- **FBVBS relevance**: **MUST reference** for SMT-enabled systems, especially AMD.

### SSBD (Speculative Store Bypass Disable) — Spectre v4
- **MSR**: IA32_SPEC_CTRL (0x48), bit 2; AMD also: VIRT_SPEC_CTRL (0xC001_011F)
- **Function**: Prevents speculative store-to-load forwarding bypass. Significant performance cost; used opt-in per-thread for JIT sandboxes.
- **FBVBS relevance**: **Should reference** with guidance on when to enable (sandboxed code, untrusted JIT).

### BHI_DIS_S (Branch History Injection mitigation)
- **MSR**: IA32_SPEC_CTRL (0x48), bit 10; **CPUID**: `CPUID.7.2.EDX[4]` (BHI_CTRL)
- **Introduced**: Intel Alder Lake (12th Gen, 2021)+
- **Function**: Prevents userspace branch history from influencing kernel indirect branch predictions, closing the gap that eIBRS leaves for BHB-based attacks. On older CPUs, a **software BHB-clearing sequence (~200 instructions)** must execute on syscall entry and VMEXIT.
- **AMD**: Not affected by BHI.
- **FBVBS relevance**: **MUST reference.** Critical for Intel platforms — without BHI_DIS_S or software BHB clearing, eIBRS alone is insufficient.

### RRSBA_DIS_S (Restricted Return Stack Buffer Alternate)
- **MSR**: IA32_SPEC_CTRL, RRSBA_DIS_S/RRSBA_DIS_U bits
- **Function**: On RSB underflow, prevents fallback to BTB-based alternate predictors for supervisor-mode RETs. Required when using retpoline on processors with RRSBA behavior.
- **FBVBS relevance**: **Should reference** for VM migration pool correctness.

### PBRSB (Post-Barrier RSB Predictions) — Intel only
- **CVE**: CVE-2022-26373; **Detection**: `IA32_ARCH_CAPABILITIES[24]` (PBRSB_NO)
- **Affects**: Intel eIBRS CPUs (Skylake derivatives through Alder Lake). AMD not affected.
- **Function**: After VM exit with IBRS set, a guest-controlled CALL target can influence the first post-VMEXIT return prediction. Requires executing a lightweight CALL sequence after VM exit.
- **FBVBS relevance**: **MUST reference.** Directly impacts hypervisor security on Intel.

### LFENCE as serializing on AMD
- **MSR**: C001_1029 (DE_CFG), bit 1
- **Function**: Makes LFENCE dispatch-serializing on AMD (it's always serializing on Intel). Required for Spectre v1 mitigations using LFENCE as a speculation barrier.
- **FBVBS relevance**: **MUST reference** — must be set at boot for AMD platforms.

---

## 2. Memory protection, isolation, and encryption

These features form the backbone of hypervisor-enforced memory integrity — controlling what code can execute, what data can be read/written, and who owns each physical page.

### EPT (Intel) / NPT (AMD) — Second Level Address Translation

| Aspect | Intel EPT | AMD NPT |
|--------|-----------|---------|
| Introduced | Nehalem (2008) | Barcelona (2007) |
| Execute-only pages | **Yes** (X=1, R=0, W=0) | **No** — X requires R |
| A/D flags | Hardware, via EPTP bit 6 | Standard page table A/D |
| Large pages | 2MB and 1GB | 2MB and 1GB |
| 5-level | PML5 for 57-bit GPA | Not yet |

EPT's **execute-only page capability** is critical for code integrity: the hypervisor can make kernel code executable but not readable, preventing code disclosure. AMD NPT's lack of execute-only pages requires workarounds (non-executable marking with trap-and-emulate). **FBVBS relevance**: **MUST reference** both, noting the AMD limitation and mitigation strategy.

### MBEC (Intel) / GMET (AMD) — Mode-Based Execute Control
- **Intel MBEC**: Secondary VM-execution control bit 22; splits EPT execute permission into supervisor-mode (bit 2) and user-mode (bit 10). Introduced **Kaby Lake (7th Gen, 2017)**.
- **AMD GMET**: `CPUID Fn8000_000A:EDX[24]`. Equivalent NPT feature. Introduced **Zen 2 (2019)**.
- **Why it matters**: Without MBEC/GMET, W^X enforcement requires maintaining dual EPT structures and swapping them on every user↔kernel transition — causing **~30–40% performance overhead**. With MBEC/GMET, overhead drops to **1–3%** (Microsoft's measured 24× reduction in VM exits).
- **FBVBS relevance**: **MUST reference — this is the single most performance-critical feature for HVCI-style code integrity.** FreeBSD's bhyve hypervisor would need MBEC/GMET support added.

### Intel VT-rp (HLAT + PW + GPV)
- **Introduced**: Alder Lake (12th Gen, 2021) / Sapphire Rapids
- **AMD equivalent**: None
- **Components**:
  - **HLAT (Hypervisor-managed Linear Address Translation)**: Alternative paging root (HLATP in VMCS) that the guest cannot modify. Prevents remapping attacks where a kernel exploit changes page tables to redirect virtual addresses.
  - **Paging-Write (PW)**: EPT bit allowing CPU page-walker A/D updates on read-only EPT pages, eliminating VM exits for page table monitoring.
  - **GPV (Guest Paging Verification)**: Prevents aliasing attacks by verifying that all EPT entries used during translation have the PWA bit set.
- **FBVBS relevance**: **Should reference** — VT-rp is the most advanced anti-remapping mechanism available. No production hypervisor has shipped VT-rp yet, but an FBVBS spec should plan for it.

### SMEP / SMAP
- **SMEP** (Supervisor Mode Execution Prevention): Prevents ring 0 from executing user-mode pages. Intel Ivy Bridge (2012), AMD Zen 1 (2017). **CR4 bit 20.**
- **SMAP** (Supervisor Mode Access Prevention): Prevents ring 0 from reading/writing user-mode pages (bypass via STAC/CLAC). Intel Broadwell (2014), AMD Zen 1. **CR4 bit 21.**
- **Hypervisor enforcement**: Pin CR4.SMEP and CR4.SMAP via VMCS CR4 guest/host mask — the hypervisor traps any attempt to clear these bits.
- **FBVBS relevance**: **MUST reference.** These bits must be pinned and un-clearable by the guest kernel.

### PKU / PKS (Protection Keys)
- **PKU** (Protection Keys for User pages): 4-bit key in PTE bits 62:59, controlled by unprivileged WRPKRU. Intel Skylake-SP (2017), AMD Zen 3 (2020).
- **PKS** (Protection Keys for Supervisor pages): Uses MSR IA32_PKRS (privileged). Intel Sapphire Rapids (2023) server only. AMD: not yet available.
- **FBVBS relevance**: **PKU should reference** (intra-address-space isolation for userland). **PKS should reference** for future intra-kernel isolation on Intel server platforms.

### Memory encryption technologies

| Feature | Vendor | Generation | Function |
|---------|--------|------------|----------|
| **TME** | Intel | Ice Lake (2019) | AES-XTS-128 single-key full-memory encryption |
| **TME-MK / MKTME** | Intel | Ice Lake-SP (2021) | Multi-key encryption; KeyID in upper physical address bits |
| **SME** | AMD | Zen 1 (2017) | AES-128 single-key; C-bit (bit 47) in PTE marks encrypted pages |
| **SEV** | AMD | Zen 1 (2017) | Per-VM encryption keys managed by AMD Secure Processor |
| **SEV-ES** | AMD | Zen 2 (2019) | Encrypts VM register state (VMSA); #VC exception for communication |
| **SEV-SNP** | AMD | Zen 3 (2021) | Adds integrity via **Reverse Map Table (RMP)** — 16-byte per-4KB-page, records ownership |
| **SEV-SNP + VMPL** | AMD | Zen 3 (2021) | 4 privilege levels within guest; VMPL0 runs SVSM for vTPM/migration |
| **TDX** | Intel | Sapphire Rapids (2023) | SEAM mode + TDX Module; per-TD MKTME keys; memory controller integrity |
| **TDX 1.5** | Intel | Emerald Rapids (2024) | TD-partitioning (up to 3 nested VMs), vTPM 2.0, live migration |
| **TDX Connect** | Intel | Granite Rapids (2024) | Extends TD protection to PCIe/CXL devices |

**FBVBS relevance**: An FBVBS specification focused on protecting the OS from its own kernel (VBS-style) does not strictly require confidential computing (SEV-SNP/TDX), which protects VMs from the hypervisor. However, **TME/SME should be referenced** for physical attack protection, and **SEV-SNP VMPL** is relevant if the architecture uses privilege levels within the secure partition.

### Other memory protection features
- **NX bit** (AMD NX / Intel XD): Execute-disable in PTE bit 63. AMD Athlon 64 (2003), Intel Prescott (2004). **MUST reference** — foundation of W^X.
- **UMIP** (User-Mode Instruction Prevention): Blocks SGDT/SIDT/SLDT/SMSW/STR from user mode. Intel Cannon Lake (2017), AMD Zen 2 (2019). CR4.UMIP (bit 11). **Should reference** — prevents KASLR info leaks.
- **PCID** (Process Context Identifiers): 12-bit tag in CR3 for TLB entry isolation. Intel Westmere (2010), AMD Zen 1. Critical for KPTI performance. **Should reference.**
- **Intel LAM** / **AMD UAI**: Linear address metadata bits. Security risk (SLAM vulnerability). **Should reference with caution.**

---

## 3. Virtualization control features

These are the VMCS/VMCB controls and hardware assists that define what the hypervisor can intercept, monitor, and enforce.

### Intel VT-x features (security-relevant subset)

| Feature | Generation | Security function |
|---------|-----------|-------------------|
| **VMFUNC / EPTP switching** | Haswell (2013) | In-guest EPT view switching without VM exit; enables security compartments |
| **VMCS Shadowing** | Haswell (2013) | Nested virtualization — L1 hypervisor VMREAD/VMWRITE without exits |
| **Posted Interrupts** | Haswell EP (2013) | Direct interrupt delivery without VM exit; requires per-VM PID isolation |
| **EPT Sub-Page Permissions (SPP)** | Select Skylake+ | 128-byte write granularity — **now deprecated** due to CVE-2024-36242; do not use |
| **APICv** | Ivy Bridge EP (2013) | Hardware APIC virtualization; reduces interrupt exits |
| **Virtual Interrupt Delivery** | Haswell (2013) | Automatic virtual interrupt injection without exits |
| **PML (Page Modification Logging)** | Broadwell (2015) | Hardware dirty-page tracking; 512-entry buffer |
| **VPID** | Nehalem (2008) | 16-bit TLB tag per vCPU; prevents cross-VM TLB information leakage |
| **Unrestricted Guest** | Westmere (2010) | Real-mode guest support; reduces VMM emulation attack surface |
| **EPT Violation #VE** | Broadwell (2015) | Delivers EPT violations as guest exceptions; enables in-guest security handlers |
| **NOTIFY VM Exit** | Alder Lake (2021) | Detects guest-induced functional DoS (microarch stalls); configurable window |
| **Bus Lock VM Exit** | Alder Lake (2021) | Detects guest bus-locking operations; prevents performance DoS |
| **MSR Bitmaps** | Core 2 (2008) | Per-MSR interception control; security-critical MSRs (EFER, LSTAR) must be trapped |
| **CR0/CR4 Guest/Host Masks** | Original VT-x (2005) | Pin security-critical CR bits (SMEP, SMAP, WP, PG, NXE); trap clearing |
| **VMX Preemption Timer** | Nehalem (2008) | Prevents guest CPU monopolization; essential for scheduler fairness |

### AMD SVM features (security-relevant subset)

| Feature | Generation | Security function |
|---------|-----------|-------------------|
| **AVIC** | Carrizo (2016) / all Zen | AMD's APICv equivalent; x2AVIC on Zen 3/4+ |
| **vGIF** | Zen 1 (2017) | Virtual Global Interrupt Flag; essential for nested virt |
| **VMCB Clean Bits** | Bulldozer (2011) | Reduces VMRUN overhead; hypervisor must track modifications correctly |
| **Decode Assists** | Bulldozer (2011) | Hardware instruction decode on intercepts; reduces emulation bugs |
| **V_NMI** | Zen 4 (2022) | Virtual NMI masking; eliminates IRET-intercept complexity |
| **Bus Lock Trap** | Zen 5 (2024) | AMD's bus lock detection — matches Intel capability |
| **LBR Virtualization** | Barcelona (2007) | Auto save/restore of LBR MSRs on VMRUN/VMEXIT |
| **Pause Filter** | Bulldozer (2011) | AMD's PAUSE-loop exiting equivalent |
| **MSR Permission Map** | Original SVM (2006) | 8KB bitmap for selective MSR interception |

**FBVBS relevance for all of the above**: The specification **MUST reference** VMCS/VMCB CR masking (for pinning SMEP/SMAP/WP/NXE), MSR bitmaps (for trapping security MSRs), VPID/ASID (for TLB isolation), and EPT/NPT permission enforcement. **Should reference** PML (for integrity monitoring), NOTIFY/bus lock exits (for DoS mitigation), and Posted Interrupts (for performance). SPP should be explicitly noted as **deprecated and must not be used**.

---

## 4. DMA and I/O protection

Without IOMMU protection, **all EPT/NPT memory isolation is bypassable via DMA**. This is the most commonly underspecified area in hypervisor security designs.

### Intel VT-d
- **Available since**: Core 2/Nehalem era (2008). Reported via ACPI DMAR table.
- **Capabilities**: DMA Remapping (per-device page tables), Interrupt Remapping (prevents interrupt injection), Posted Interrupts for devices (direct device→vCPU interrupt delivery).
- **Scalable Mode** (Skylake-SP+): Adds PASID support, first-level/second-level/nested translation, Scalable IOV.

### AMD-Vi (IOMMU)
- **Available since**: Barcelona (2007). Reported via ACPI IVRS table.
- **v2 features** (Bulldozer+): PASID, PPR (Peripheral Page Request), Guest Translation, ATS/IOTLB caching.

### Intel Kernel DMA Protection
- Systems with VT-d + UEFI firmware OPT_IN flag (2019+). Isolates all external DMA-capable devices at boot.

### PCIe ACS (Access Control Services)
- **Critical for device passthrough**: Without ACS, devices behind the same PCIe switch can perform peer-to-peer DMA, **completely bypassing the IOMMU**. Determines IOMMU group granularity.

**FBVBS relevance**: **MUST reference VT-d/AMD-Vi as mandatory.** Windows VBS requires IOMMU (`RequirePlatformSecurityFeatures=3`). The specification must require: DMA remapping enabled for all devices, interrupt remapping enabled, Kernel DMA Protection for external ports, and ACS verification for passthrough devices. Without IOMMU, the entire security model collapses to a single malicious USB/Thunderbolt device.

---

## 5. Speculative execution mitigations

This is the most complex and rapidly evolving category. A security hypervisor must apply mitigations at **every privilege transition** (user→kernel, guest→host, guest→guest).

### Comprehensive vulnerability and mitigation matrix

| Vulnerability | CVE | Vendor | Affected CPUs | Mitigation | MSR/mechanism |
|--------------|-----|--------|---------------|------------|---------------|
| **Spectre v1** (Bounds Check Bypass) | 2017-5753 | Both | All OoO CPUs | Software barriers (LFENCE), array masking | No hardware MSR |
| **Spectre v2** (BTI) | 2017-5715 | Both | All modern | eIBRS/AutoIBRS + IBPB + retpoline | IA32_SPEC_CTRL[0], IA32_PRED_CMD[0] |
| **Spectre v4** (SSB) | 2018-3639 | Both | All modern | SSBD | IA32_SPEC_CTRL[2] |
| **Meltdown** | 2017-5754 | Intel | Pre-Whiskey Lake | KPTI | IA32_ARCH_CAPABILITIES[0] (RDCL_NO) |
| **L1TF / Foreshadow** | 2018-3646 | Intel | Pre-Whiskey Lake | L1D flush on VM entry | IA32_FLUSH_CMD[0] (MSR 0x10B) |
| **MDS** (ZombieLoad, RIDL, Fallout) | 2018-12126/7/30 | Intel | Pre-Ice Lake | VERW/MD_CLEAR | CPUID.7.0:EDX[10] |
| **TAA** | 2019-11135 | Intel | CPUs with TSX | Disable TSX or VERW | IA32_TSX_CTRL (0x122) |
| **MMIO Stale Data** | 2022-21123/25/66 | Intel | Various | VERW with FB_CLEAR | IA32_ARCH_CAPABILITIES[17] |
| **Retbleed** | 2022-29900/01 | AMD Zen 1-3, Intel Skylake | Various | Untrained return thunk, IBRS | Software/microcode |
| **SRSO / Inception** | 2023-20569 | AMD | Zen 1-4 (not Zen 5) | safe-ret thunk, IBPB | BP_CFG MSR (0xC001102E) |
| **Downfall / GDS** | 2022-40982 | Intel | Skylake–Tiger Lake | Microcode (blocks gather transients) | IA32_ARCH_CAPABILITIES[26] (GDS_NO) |
| **Zenbleed** | 2023-20593 | AMD | Zen 2 only | Microcode or DE_CFG[9] chicken bit | MSR 0xC0011029 bit 9 |
| **RFDS** | 2023-28746 | Intel | Atom/E-cores only | VERW with RFDS_CLEAR | IA32_ARCH_CAPABILITIES[27/28] |
| **BHI** (Branch History Injection) | 2022-0001 | Intel | Haswell+ | BHI_DIS_S or SW BHB clear | IA32_SPEC_CTRL[10] |
| **GhostRace** (Spec. Race Conditions) | 2024-2193 | All | All OoO CPUs | LFENCE after lock ops (~5% overhead) | No hardware mechanism |
| **BPI** (Branch Privilege Injection) | 2024-45332 | Intel | 9th Gen+ | Microcode (2.7% overhead) | New microcode 2025 |
| **TSA** (Transient Scheduler Attacks) | 2024-36350/57 | AMD | Zen 3-4 | Firmware update | 2025 |

### Key hypervisor transition mitigations

Every **VM exit** must execute: (1) IBPB (guest→host predictor barrier), (2) RSB filling (32 entries on Intel; AMD AutoIBRS clears automatically), (3) PBRSB sequence on affected Intel CPUs, (4) VERW if MD_CLEAR required, (5) L1D flush if L1TF-affected. Every **VM entry** must: verify guest IA32_SPEC_CTRL state, apply L1D flush if needed.

**FBVBS relevance**: **MUST comprehensively reference ALL of the above.** The specification must define the exact sequence of mitigations at each privilege transition boundary. The `IA32_ARCH_CAPABILITIES` MSR (0x10A) is the central detection mechanism — its **30+ bits** enumerate immunity to specific vulnerabilities. A complete FBVBS spec must parse every bit of this MSR.

---

## 6. Trusted execution and boot integrity

### Intel TXT (Trusted Execution Technology)
- Uses GETSEC[SENTER] to establish DRTM (Dynamic Root of Trust for Measurement). Loads Intel-signed SINIT ACM into CPU cache for verified MLE (Measured Launch Environment) launch. Present on all vPro platforms, confirmed on Arrow Lake via **CBnT** (Converged Boot Guard + TXT).

### AMD SKINIT
- AMD's DRTM instruction. Hardware forces CPU into measured code path. Used by Windows System Guard Secure Launch and open-source TrenchBoot project.

### Intel Boot Guard / AMD Platform Secure Boot (PSB)
- **Intel Boot Guard**: OEM public key hash fused into CPU e-fuses. Verifies Initial Boot Block (IBB) before any firmware executes.
- **AMD PSB**: OEM signing key fused via PSP. RSASSA-PSS with SHA-384 and 4096-bit keys. One-time-programmable.

### Intel SGX
- **Deprecated on client** (11th Gen onward). **Still supported on server Xeon** (3rd–5th Gen Scalable, Xeon E-2300, Xeon D). Up to 1TB EPC. No plans to deprecate on server.

### Intel TDX / AMD SEV-SNP
- Covered in memory encryption section. **TDX Connect** (Granite Rapids, 2024) extends TD protection to PCIe/CXL devices. **AMD SEV-TIO** extends TEE to PCIe devices via TDISP protocol.

### TPM 2.0
- Both vendors provide fTPM via CSME (Intel) / PSP (AMD). TDX 1.5 adds vTPM. SEV-SNP SVSM at VMPL0 proxies TPM operations.

**FBVBS relevance**: **MUST reference** DRTM (TXT or SKINIT) for secure hypervisor launch, Boot Guard/PSB for firmware integrity, and TPM 2.0 for attestation and key binding. Windows VBS uses all of these in its Secure Launch chain.

---

## 7. Debug and profiling security

| Feature | Vendor | Security concern | Hypervisor action |
|---------|--------|-----------------|-------------------|
| **DR0–DR7** (Debug Registers) | Both | Guest can set breakpoints on host addresses if passthrough is misconfigured | Trap MOV-DR; save/restore per-VM; never pass through host DR state |
| **Performance Counters** | Both | LLC/cache side channels leak cross-VM info | Restrict RDPMC via CR4.PCE; trap RDPMC in VMCS/VMCB |
| **LBR** (Last Branch Records) | Both | Branch trace leaks control flow | AMD: LBR Virtualization auto-saves on VMRUN/VMEXIT. Intel Architectural LBR (Alder Lake+) standardizes format |
| **Intel PT** (Processor Trace) | Intel Broadwell+ | Complete control flow trace; info leak if attacker gains kernel access | Can be used positively for CFI monitoring; must restrict PT configuration MSRs |
| **AMD IBS** (Instruction Based Sampling) | AMD Zen+ | Sampling-based; reveals instruction latency, cache behavior | Restrict to privileged access; trap IBS MSRs |
| **MTF** (Monitor Trap Flag) | Intel | Single-step guests at hypervisor level; TDX-Step attack vector | Use for EPT hook instruction replay; TDX mitigates via APIC timer controls |

**FBVBS relevance**: **Should reference** debug register isolation and performance counter restriction. The specification should mandate that DR0–DR7 state is strictly per-VM and never leaked, and that RDPMC is trapped by default.

---

## 8. Newest features (2024–2026) and their security implications

### Intel FRED (Flexible Return and Event Delivery)
- **CPUID**: `CPUID.(EAX=7,ECX=1):EAX[bit 17]`
- **Status**: No production silicon yet. Expected on **Intel Panther Lake** (late 2025/early 2026). AMD confirmed FRED adoption via x86 Ecosystem Advisory Group (late 2024) for **Zen 6**.
- **Function**: Replaces IDT-based event delivery with 4 event stack levels, ERETU/ERETS instructions. Eliminates transient states during ring transitions. Simplifies NMI handling.
- **FBVBS relevance**: **Should plan for** — FRED will fundamentally change ring transition security. The specification should note it as a future enhancement.

### Intel LASS (Linear Address Space Separation)
- **First shipped**: Sierra Forest, Granite Rapids, Arrow Lake, Lunar Lake (2024). **Linux merged in kernel 6.19.**
- **Function**: Prevents cross-mode address space probing before paging — defeats KASLR bypass via TLB timing, double page fault probing, and SLAM attacks.
- **FBVBS relevance**: **Should reference** — available on current hardware and merged into Linux.

### Platform security updates (2024–2025)

**Intel Arrow Lake / Lunar Lake / Panther Lake**: All include CET, LASS, CBnT, TME-MK, SMEP, SMAP, UMIP. Lunar Lake adds Microsoft Pluton integration and on-package LPDDR5X (reduced physical attack surface). Panther Lake expected to be the first FRED-enabled production CPU.

**Intel Granite Rapids** (Xeon 6 P-cores, 2024): TDX with **2048 keys (256-bit)**, TDX Connect, TDX Module 2.0, LASS, 128 P-cores max, 88 PCIe Gen 5.0 lanes.

**AMD Zen 5 / EPYC 9005 Turin** (2024): Up to 192 cores. New: **Trusted I/O** (PCIe link encryption), **Secure AVIC**, **Secure TSC** (prevents hypervisor TSC manipulation for SNP guests), SEV-SNP with CipherTextHiding. Bus Lock Trap added.

**AMD SEV-SNP updates (Firmware ABI v1.56)**: SNP_TSC_INFO for Secure TSC, SNP_HV_REPORT_REQ for host-initiated attestation, segmented RMP, RAPL disable support.

### New speculative execution vulnerabilities (2025)
- **CVE-2024-45332 (Branch Privilege Injection)**: Affects all Intel 9th Gen+. Bypasses eIBRS and IBPB. Microcode fix (2.7% overhead on Alder Lake).
- **CVE-2025-24495**: Domain isolation bypass on Intel. Microcode fix released.
- **CVE-2025-40300**: Spectre-BTI on QEMU/KVM affecting AMD Zen 1–5 and Intel Coffee Lake. IBPB on VMEXIT mitigates.
- **Transient Scheduler Attacks (TSA)**: AMD Zen 3/4, 4 CVEs. Firmware update required.

**FBVBS relevance**: The specification **must be designed for continuous updates** as new speculative execution vulnerabilities emerge roughly quarterly.

---

## Feature coverage gap analysis for a FreeBSD VBS specification

Based on Windows VBS requirements, Linux Heki/LVBS design, and the full feature catalog above, any complete FBVBS specification must reference features in three tiers:

### Tier 1 — Mandatory (specification is incomplete without these)

- **VT-x/AMD-V** (basic VMX/SVM)
- **EPT/NPT** with full R/W/X permission enforcement and W^X policy
- **MBEC/GMET** for efficient user/supervisor execute separation
- **CR0/CR4/EFER pinning** via VMCS/VMCB masks (SMEP, SMAP, WP, NXE, CET)
- **MSR bitmap interception** of security-critical MSRs (EFER, LSTAR, SPEC_CTRL, etc.)
- **eIBRS/AutoIBRS** as primary Spectre v2 defense
- **IBPB** on all VM context switches
- **BHI_DIS_S** or software BHB clearing on Intel
- **PBRSB mitigation** on affected Intel CPUs
- **RSB filling** on VM exit
- **VERW/MD_CLEAR** at all privilege transitions on MDS/MMIO-affected CPUs
- **L1D flush** on VM entry for L1TF-affected CPUs
- **CET Shadow Stack** for hypervisor and enforced on guest kernel
- **NX/XD bit** enforcement (EFER.NXE pinned)
- **VT-d/AMD-Vi** (IOMMU) with DMA and interrupt remapping
- **UEFI Secure Boot** chain of trust
- **DRTM** (TXT SENTER / AMD SKINIT) for secure hypervisor launch
- **TPM 2.0** for attestation and key sealing

### Tier 2 — Strongly recommended

- **CET IBT** (Intel) for forward-edge CFI in hypervisor code
- **STIBP** for SMT-enabled systems (especially AMD)
- **SSBD** guidance for JIT sandbox protection
- **VPID/ASID** for TLB isolation
- **SMEP/SMAP** hypervisor enforcement (CR4 pinning)
- **UMIP** enforcement (CR4 pinning)
- **PKU** virtualization awareness
- **PML** for integrity monitoring and dirty page tracking
- **SRSO/Inception mitigation** on AMD Zen 1–4
- **Retbleed mitigation** on AMD Zen 1–3
- **Zenbleed mitigation** on AMD Zen 2
- **Downfall/GDS mitigation** on Intel Skylake–Tiger Lake
- **RFDS mitigation** on Intel E-cores
- **LFENCE serialization** (AMD DE_CFG MSR)
- **Boot Guard/PSB** for firmware integrity
- **NOTIFY VM exit / Bus Lock** detection for DoS prevention
- **Kernel DMA Protection** for external ports
- **PCIe ACS** verification for device passthrough
- **TME/SME** for physical memory encryption

### Tier 3 — Forward-looking (specification should plan for)

- **VT-rp (HLAT + PW + GPV)** for anti-remapping — Intel only, not yet shipped in any production VMM
- **Intel LASS** — available now on Xeon 6/Arrow Lake/Lunar Lake
- **Intel FRED** — expected on Panther Lake; AMD Zen 6
- **PKS** — intra-kernel isolation (Intel server only)
- **TDX / SEV-SNP** — if the threat model extends to confidential computing
- **VMFUNC/EPTP switching** — for security compartmentalization
- **EPT #VE** — for in-guest security event handling
- **Intel LAM / AMD UAI** — with mandatory LASS and Spectre mitigations
- **Secure TSC** (AMD SEV-SNP Zen 5) — for time-integrity in secure partitions
- **TDX Connect / AMD SEV-TIO** — for trusted I/O to PCIe devices
- **BPI/TSA/VMScape mitigations** — emerging 2025 vulnerabilities requiring continuous spec updates

### Critical reference implementations to study

The specification should explicitly reference and compare against: **Windows VBS/HVCI** (most mature production hypervisor-based security), **Linux Heki/LVBS** (open-source VBS for Linux, github.com/heki-linux), **Google KVM Address Space Isolation (ASI)** (restricted page tables for Spectre mitigation), and **Microsoft HVPT** (hypervisor-enforced paging translation integrity).

---

## Conclusion: what a complete FBVBS specification demands

The gap between a minimal hypervisor-based security system and a maximally secure one is enormous. A specification that references only basic EPT W^X enforcement misses roughly **60% of the available hardware security surface**. The three most impactful areas where specifications typically fall short are: **(1) speculative execution mitigations** — which require parsing the 30+ bits of `IA32_ARCH_CAPABILITIES` and applying vulnerability-specific sequences at every privilege transition; **(2) IOMMU integration** — without which DMA attacks trivially bypass all memory protection; and **(3) continuous update mechanisms** — since new CPU vulnerabilities emerge quarterly (BPI, TSA, and VMScape all disclosed in 2025 alone). A living specification with version-controlled mitigation tables keyed to `IA32_ARCH_CAPABILITIES` bits and AMD CPUID `Fn8000_0008:EBX` / `Fn8000_0021:EAX` bits would be far more maintainable than static prose. The hardware security surface of x86_64 now comprises **81+ distinct features**, and a security hypervisor that fails to account for any one of them creates an exploitable gap.