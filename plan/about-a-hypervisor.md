# About a hypervisor base for FBVBS in Ada/SPARK

## Current repository decision

**FBVBS keeps Ada/SPARK as the primary implementation path.** The microhypervisor, partition manager, capability model, mapping logic, command validation, lifecycle control, and security-service semantics should converge on Ada/SPARK as the authoritative codebase.

**C is permitted only for tiny hardware-boundary leaf code** such as VMX/SVM instruction wrappers or similarly narrow interfaces where direct hardware interaction is impractical in pure SPARK. That C must not expand into policy or orchestration logic, and it is acceptable only with explicit **MISRA C compliance, static-analysis evidence, formal-verification artifacts, fixed ABI contracts, and a clearly documented safety boundary**.

### Exact retained-C boundary for this repository

The intended long-term retained-C scope is narrower than the current legacy C tree. The only acceptable persistent C boundary is:

- VMX instruction leaves such as VMXON, VMXOFF, VMPTRLD, VMLAUNCH, VMRESUME, VMREAD, VMWRITE, INVEPT, and INVVPID
- AMD SVM instruction leaves such as VMRUN, VMLOAD, VMSAVE, STGI, CLGI, and VMCB access helpers
- similarly tiny CPU/MSR/CPUID probe helpers where the interface can be reduced to fixed-width integers and a one-way safety contract

The following are **not** acceptable as retained C authority and must converge on Ada/SPARK:

- partition lifecycle logic
- capability and ownership checks
- hypercall validation and dispatch policy
- memory mapping policy
- audit and logging policy
- trusted-service semantics
- VM exit classification and higher-level run-loop policy

In the current repository, the **default retained-C acceptance path has been reduced to `hypervisor/src/vmx.c` only**, covering capability probing and synthetic leaf-exit observation, and that path now consumes a dedicated leaf-only interface in `hypervisor/include/fbvbs_leaf_vmx.h` rather than the larger legacy orchestration header. The default leaf path is now also guarded by an explicit retained-C subset check, fixed-ABI `_Static_assert` contracts, and a bounded proof-style contract artifact in `hypervisor/tools/`, rather than relying on compile warnings alone. The larger legacy C tree remains on disk as migration code, but it is no longer part of the default `make -C hypervisor analyze` / `make -C hypervisor test` retained-boundary path. Ada/SPARK owns the authoritative VM policy model via `FBVBS.VM_Policy` and `FBVBS.VM_Exit_Encoding`, and the Ada executable checks concrete exit payload semantics for interrupt, PIO, MMIO, CR, MSR, EPT, shutdown, halt, and fault cases. The Ada side now also has an explicit selected-call hypercall dispatcher (`FBVBS.Hypercall_Dispatcher`), a memory/W^X policy model (`FBVBS.Memory`), a KSI shadow-update model (`FBVBS.KSI_Shadow`), and selected diagnostic query modeling (`FBVBS.Diagnostics`) so more orchestration remains on the Ada side. The remaining work is to delete or fully replace the legacy C policy/orchestration code rather than merely excluding it from the default acceptance boundary.

**Write from scratch in Ada/SPARK, using NOVA's architecture, Muen's VMX patterns, and bhyve's BSD-licensed code as references.** No existing hypervisor satisfies all FBVBS requirements simultaneously — the best path is option **(b): reference design only, clean-room Ada/SPARK implementation** — combining the architectural blueprint of NOVA (capability-based, ~11K SLOC, deprivileged host), the proven Ada/SPARK VMX techniques from Muen (the only VMX-capable Ada/SPARK system in existence), and the BSD-licensed VMX/EPT/IOMMU code from bhyve and ACRN for implementation guidance. This approach yields a formally verifiable, BSD-licensed microhypervisor under 15K SLOC while avoiding GPL contamination. The Ada/SPARK toolchain is production-ready for this task: AdaCore's GNAT Pro provides a `x86_64-elf` bare-metal target, and Muen has already demonstrated automatic SPARK proof discharge (Silver-level AoRTE) for a VMX hypervisor kernel.

---

## The twelve candidates ranked by FBVBS fit

After evaluating every candidate across all 15+ dimensions, a clear hierarchy emerges. The table below captures the essential comparison before diving into analysis.

| Candidate | License | Lang | SLOC (core) | x86_64 VMX | Depriv. Host | Dynamic | Caps | IOMMU | Formal Verif. |
|---|---|---|---|---|---|---|---|---|---|
| **NOVA** (BlueRock) | GPLv2 | C++ | **~11.5K** | ✅ Intel+AMD | ✅ | ✅ | ✅ Full | ✅ VT-d | 🔶 Active (POPL 2026) |
| **seL4** | GPLv2 (kern) | C | ~10K | ✅ Intel | Partial | ✅ kernel / ❌ SDK | ✅ Full | ✅ (unverified) | ✅ x64 C-level |
| **Muen** | GPLv3 | **Ada/SPARK** | **~2.5K+260 ASM** | ✅ Intel | ✅ | ❌ Static | ❌ | ✅ VT-d | ✅ Silver AoRTE |
| **Bareflank/MicroV** | **MIT** | C++ | Small µkernel | ✅ Intel(+AMD) | ✅ | ✅ via MicroV | ❌ | ❌ undoc. | 🔶 Designed for |
| **ACRN** | **BSD-3** | C | ~40K | ✅ Intel only | ✅ | Hybrid | ❌ | ✅ VT-d | ❌ |
| **bhyve** | **BSD-2** | C | Moderate | ✅ Intel+AMD | ❌ Type-2 | N/A | ❌ | ✅ VT-d | ❌ |
| **Hedron** | GPLv2 | C++ | ~10-15K | ✅ Intel only | ✅ | ✅ | ✅ Full | ✅ | ❌ |
| **Genode/base-hw** | AGPLv3 | C++ | Few KLOC | ✅ (VMX since 23.10) | ✅ | ✅ Full | ✅ Full | ✅ | ❌ |
| **Jailhouse** | GPLv2 | C | **<10K** | ✅ Intel+AMD | ❌ | Partial | ❌ | ✅ | ❌ |
| **Xen** | GPLv2 | C | ~270K+ | ✅ Mature | 🔶 Disagg. | ✅ Full | ❌ (MAC) | ✅ Full | 🔶 Partial |
| **pKVM** | GPLv2 | C | ~10K (EL2) | ❌ (RFC only) | ✅ Core design | ✅ | ❌ | ✅ | 🔶 In progress |
| **CrosVM/cloud-hv** | BSD-3/Apache | Rust | ~50K+ | Via KVM | N/A | N/A | N/A | Via KVM | ❌ |

**NOVA is the architectural gold standard.** Its ~11.5K SLOC microhypervisor provides exactly what FBVBS needs: a capability-based object system with Protection Domains, Execution Contexts, Scheduling Contexts, Portals (IPC), and Semaphores. It runs the host OS in VMX non-root mode, supports dynamic partition creation/destruction, manages EPT per-partition, owns the IOMMU, and implements synchronous portal-based IPC with time donation. BlueRock Security's POPL 2026 paper ("Specifying and Verifying the NOVA Microhypervisor in Concurrent Separation Logic") demonstrates that formal verification of industrial C++ hypervisor code is achievable — and found real race conditions and semantic bugs during the process. NOVA's TCB (68KB binary on x86) sets the benchmark for what FBVBS should target.

**Muen is the indispensable Ada/SPARK reference.** It is the **only VMX-capable system ever built in Ada/SPARK**, with all SPARK proof obligations automatically discharged. Its kernel (~2,470 SPARK + ~260 ASM lines) demonstrates the exact patterns FBVBS needs: SPARK-mode specifications wrapping `SPARK_Mode => Off` bodies for VMX instructions, a custom ZFP runtime for bare-metal x86_64, EPT-based memory isolation, VT-d device passthrough, and VMX preemption timer scheduling. The critical limitation is Muen's static partitioning — all resources are assigned at build time via XML system policy, with no runtime creation or destruction. However, the Tau0 (τ₀) architecture was explicitly designed to "gradually increase flexibility," and a Subject Lifecycle Controller now exists, suggesting the conceptual path toward dynamism was always intended.

---

## Why option (b) — clean-room Ada/SPARK — is the right strategy

The four options must be evaluated against three constraints: **formal verifiability** (requires Ada/SPARK with SPARK_Mode for the kernel), **BSD licensing** (rules out GPL code in the binary), and **architectural requirements** (deprivileged host, dynamic partitions, capabilities, IOMMU).

**Option (a) — Fork and rewrite** is impractical. NOVA and seL4 are GPL. Forking Muen (GPLv3) and adding dynamic partitions would require relicensing or GPL compliance. The only BSD-licensed candidates worth forking are Bareflank (MIT, but no IOMMU or capability model) and ACRN (BSD-3, but 40K LOC Intel-only with no capability model). Neither provides a strong enough foundation to justify the overhead of a rewrite versus a fresh design informed by their code.

**Option (c) — Wrappers around existing hypervisor** breaks the formal verification story. Wrapping a C/C++ hypervisor in Ada/SPARK moves the unverified code *into* the TCB rather than eliminating it. The point of Ada/SPARK is that the kernel itself is proven free of runtime errors. A wrapper architecture would give you the worst of both worlds: the complexity of FFI bridging plus an unverified core.

**Option (d) — Rust hypervisor with Ada/SPARK trusted services** is the strongest alternative. Bareflank's MIT-licensed microkernel could theoretically serve as the VMX-root component, with Ada/SPARK trusted services in VMX non-root. However, this splits the TCB across two languages, complicates the build system, and defers formal verification of the most critical code (the VMX-root kernel). If SPARK verification is a core goal, the kernel must be in SPARK.

**Option (b) wins** because the target is achievable. Muen proves a **~2,700 SLOC Ada/SPARK VMX kernel is buildable and verifiable**. NOVA proves the target architecture (capability-based, ~11K SLOC, dynamic, deprivileged host) works in production. The gap between them — adding dynamic partition management and a capability system to a Muen-style SPARK kernel, guided by NOVA's design — is substantial but tractable. A **clean-room FBVBS kernel of 8,000–12,000 SLOC SPARK + ~500 SLOC assembly** is realistic, targeting Silver-level (AoRTE) verification initially with a path to Gold-level functional correctness proofs.

---

## The four reference pillars and what to extract from each

**Pillar 1 — NOVA: Architecture and capability model.** Study the EuroSys 2010 paper and FOSDEM 2023–2026 presentations. Extract the object model: Protection Domains containing capability spaces, Execution Contexts (threads/vCPUs) bound to Scheduling Contexts (CPU time), and Portals for synchronous cross-domain IPC with time donation. NOVA's 2023+ innovation of separating Spaces (Host Space, Guest Space, DMA Space, PIO Space, MSR Space) from Protection Domains as first-class kernel objects is particularly elegant — it allows flexible reassignment of address spaces without destroying protection domains. The ~15 hypercall interface is minimal and well-defined. NOVA's portal-based IPC achieves microsecond-scale cross-domain calls with automatic priority inheritance, which is essential for practical inter-partition communication.

**Pillar 2 — Muen: Ada/SPARK VMX implementation patterns.** Clone `git.codelabs.ch/bob/muen.git` and study `kernel/spark/` (SPARK code) and `kernel/src/` (Ada/assembly). Key packages: `SK.VMX` for VMX operations, `SK.CPU` for processor management, the ZFP runtime construction, and the assembly entry points for VM exit handling. Muen's build system (Bob Build Tool + Docker environment `codelabsch/muen-dev-env`) provides a working template for GNAT cross-compilation. The preferred FBVBS boundary pattern is still Ada/SPARK package specs with preconditions/postconditions in SPARK mode, with only the smallest possible non-SPARK leaf behind that boundary. If a C leaf is retained instead of `SPARK_Mode => Off` Ada or assembly, it must remain wrapper-only and meet the repository's MISRA/static-analysis/formal-verification rules.

**Pillar 3 — bhyve: BSD-licensed VMX/SVM/EPT/IOMMU code.** The `sys/amd64/vmm/` tree in FreeBSD is BSD-2-Clause and contains production-quality implementations of Intel VMX (`intel/vmx.c`), AMD SVM, EPT/NPT page table management, VMCS field encoding, and VT-d IOMMU integration. Since FBVBS targets FreeBSD specifically, bhyve's hardware initialization sequences, CPUID feature detection, and MSR handling are directly relevant — and legally reusable as implementation reference. Antithesis (deterministic testing company) chose bhyve specifically for its "mature, simple, well-factored, clean architecture," validating its quality as a reference implementation.

**Pillar 4 — pKVM: Deprivileged host boot protocol.** pKVM's boot-then-deprivilege pattern solves the chicken-and-egg problem elegantly: the host OS boots with full privileges (using all its existing drivers), then the hypervisor installs itself and deprivileges the host by installing stage-2/EPT page tables that restrict the host's memory access. On x86, the Intel RFC (pKVM-IA at `github.com/intel-staging/pKVM-IA`) demonstrates this for VMX: the hypervisor binary runs in VMX root mode, installs EPT for the host as an identity map with permission restrictions (not full address translation — just access control), and uses shadow VMCS/shadow EPT to let the host's KVM "think" it manages VMs directly while the hypervisor actually controls hardware. This design should inform FBVBS's FreeBSD deprivileging sequence.

---

## Ada/SPARK toolchain readiness for bare-metal x86_64

The toolchain is production-ready. **AdaCore's GNAT Pro 25** provides `x86_64-elf` as an official bare-metal target with three runtime options: `light-x86_64` (ZFP, no tasking — correct for hypervisor kernels), `light-tasking-x86_64` (Ravenscar subset), and `embedded-x86_64` (richer features). Supported processors include Sandy Bridge and newer Core/Xeon, and Goldmont and newer Atom. GNATprove operates on source code platform-independently, so all SPARK contracts and proofs work regardless of the target.

For open-source development, **FSF GNAT (from GCC) with a custom ZFP runtime** is the proven alternative. Muen, CuBitOS, and HAVK all demonstrate this approach: build GCC/GNAT as a cross-compiler for x86_64-elf, create a minimal runtime from ~11 essential Ada runtime files (`system.ads`, `s-stoele.ads/adb`, `s-atacco.ads/adb`, `s-maccod.ads`, etc.), and use compile-time restriction pragmas (`No_Exception_Handlers`, `No_Floating_Point`). Muen's Docker environment (`codelabsch/muen-dev-env`) packages this entire toolchain.

**What SPARK can verify** in a hypervisor: preconditions/postconditions on all VMX wrapper functions (valid VMCS field IDs, valid memory ranges, correct operation ordering), absence of runtime errors (buffer overflows, range violations, division by zero) in all SPARK code, data flow correctness (ensuring all VMCS fields are initialized before VMLAUNCH), type safety for hardware structures (VMCS entries, EPT entries, capability tokens), and information flow properties between partitions. **What SPARK cannot verify**: the correctness of inline assembly instructions themselves, hardware behavior (that VMWRITE actually writes to the VMCS correctly), and concurrent hardware state beyond what SPARK's concurrency model captures. The assembly TCB (~260–500 lines covering boot code, VMX instruction wrappers, context save/restore, and interrupt entry points) must be minimized and manually audited.

---

## Modern hardware extensions and FBVBS's competitive advantage

FreeBSD has **no VBS equivalent today** — no hypervisor-enforced kernel integrity, no MBEC/GMET support in bhyve, no HLAT protection, no deprivileged kernel model. This represents both a gap and an opportunity: FBVBS would make FreeBSD the first BSD operating system with virtualization-based security comparable to Windows VBS or Android pKVM.

**Intel MBEC** (available since Kaby Lake, 7th gen, 2017) and **AMD GMET** (available since Zen 2, 2019) are critical enablers that split EPT execute permissions into user-mode and supervisor-mode bits. This allows FBVBS to enforce that unsigned user-mode code cannot execute in kernel mode — the foundation of hypervisor-enforced code integrity (HVCI). Currently, only Hyper-V uses MBEC in production; the Linux Heki project has RFC patches but nothing is mainlined. FBVBS implementing MBEC/GMET would put FreeBSD ahead of mainline Linux in this capability.

**Intel HLAT** (Hypervisor-managed Linear Address Translation, part of VT-rp, available since Alder Lake 12th gen) adds a hypervisor-controlled paging structure that "locks" linear address translations, preventing a compromised kernel from remapping protected pages. Combined with **Intel CET** (shadow stacks and indirect branch tracking, available since Tiger Lake 11th gen), these form a defense-in-depth stack that only Windows currently deploys. **AMD SEV-SNP** (available since EPYC Milan 3rd gen) provides complementary confidential computing where the hypervisor itself is untrusted — FBVBS could support both models, using its own trusted hypervisor for kernel integrity enforcement while optionally supporting SEV-SNP for tenant-controlled confidential VMs.

---

## Proposed FBVBS architecture derived from research

Based on all findings, the target architecture combines NOVA's capability model with pKVM's deprivilege pattern, implemented in Muen-style Ada/SPARK:

The **FBVBS microhypervisor** (~10K SPARK + ~500 ASM) runs in VMX root Ring 0, owning all hardware virtualization resources (VMCS, EPT/NPT, IOMMU, MSRs). It implements **6 kernel object types** modeled on NOVA: Protection Domains (capability containers), Execution Contexts (threads/vCPUs), Scheduling Contexts (CPU time quanta), Memory Spaces (EPT/NPT page tables), DMA Spaces (IOMMU page tables), and Portals (IPC endpoints). All access is mediated by unforgeable capabilities stored in per-PD capability tables. The hypercall interface targets **~15 system calls** (create/destroy for each object type, plus IPC call/reply, capability delegate/revoke).

**FreeBSD runs deprivileged in VMX non-root mode** as the "host partition." At boot, a UEFI loader starts FBVBS, which initializes VMX, creates the host partition's EPT as an identity map with access-control restrictions, loads FreeBSD into the host partition, and enters VMX non-root mode. FreeBSD boots normally using its existing drivers. FBVBS intercepts security-sensitive operations (CR writes, MSR access, IOMMU configuration) via VM exits. The **host partition has no direct access to VMCS, EPT, or IOMMU configuration** — it requests resource management through hypercalls, which FBVBS validates against capability-based policy.

**Dynamic partitions** (trusted services, isolated VMs, driver domains) are created at runtime via `create_pd` / `create_ec` / `create_sc` hypercalls from authorized partitions. Each partition gets independent EPT/NPT page tables and a dedicated VMCS per vCPU. Inter-partition communication uses synchronous portal-based IPC with time donation (NOVA model) for low-latency calls, plus shared-memory channels (Muen/Jailhouse IVSHMEM model) for bulk data transfer.

---

## Conclusion

Three facts determine the strategy. First, **Muen proves Ada/SPARK VMX hypervisors work** — it is the only such system in existence, with automatic SPARK proof discharge and ~2,700 lines of verified kernel code running on Intel x86_64. Second, **NOVA proves the target architecture works** — capability-based, ~11K SLOC, deprivileged host, dynamic partitions, formally verified (in progress), deployed in production. Third, **no existing hypervisor combines both** — there is no formally verified, capability-based, dynamic, Ada/SPARK microhypervisor with a BSD-compatible license.

The critical insight is that FBVBS does not need to innovate on architecture — NOVA's design is mature and proven. It needs to innovate on **implementation language and verification**: reimplementing NOVA's architectural concepts in Ada/SPARK with SPARK contracts, targeting Silver-level (AoRTE) verification from day one. The estimated effort is **8,000–12,000 SPARK SLOC + ~500 assembly lines**, achievable by a small team using AI-assisted development (Claude Code handles Ada/SPARK fluently given Muen and CuBitOS as training examples). The build system should follow Muen's approach (FSF GNAT + custom ZFP runtime), the VMX wrappers should follow Muen's SPARK boundary pattern, and the architectural skeleton should follow NOVA's capability object model with pKVM's boot-then-deprivilege sequence. bhyve's BSD-licensed `sys/amd64/vmm/` code provides legally clean implementation reference for all Intel VMX, AMD SVM, EPT/NPT, and VT-d specifics.

FreeBSD currently stands alone among major operating systems in lacking virtualization-based security. FBVBS, built correctly, would leapfrog not just bhyve but also Linux's incomplete Heki effort — delivering a formally verified, capability-based security hypervisor with MBEC/GMET enforcement that no other open-source OS offers today.
