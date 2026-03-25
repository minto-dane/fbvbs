# FBVBS Performance Budget Analysis (REQ-1000)

**Document:** PERF-001
**Date:** 2026-03-23
**Scope:** Appendix J performance constraints, Section 48 performance discipline
**Status:** Design analysis — requires hardware measurement for final validation

---

## 1. Performance Categories (Appendix J)

### 1.1 Normal Syscall Path

**Budget:** Zero additional cost (no VMCALL insertion)

**Design Guarantee (target end state):**
- Once host deprivilege / `VMLAUNCH` is completed, FreeBSD syscalls
  execute entirely within the guest (Ring 0 in VMX non-root). No
  hypercall is issued for normal syscalls.
- EPT maps guest kernel pages with full read/write/execute as appropriate.
- HLAT/NPT protections operate at page-table level only — they do not
  intercept individual memory accesses, only PTE modifications.
- The only overhead is EPT address translation (hardware-accelerated,
  typically <1% overhead on modern CPUs with extended page table support).

**Current boundary note:** The retained-C repository has not yet
completed the end-to-end host deprivilege handoff, so this section is a
performance target, not a claim about the current runtime.

### 1.2 Tier B Read (KSI Shadow Copy Read)

**Budget:** No IPC (direct memory read)

**Design Guarantee:**
- Tier B shadow copies are mapped read-only into the host's EPT address
  space. Reading a shadow copy is a normal memory read — no VM exit, no
  IPC, no hypercall.
- Shadow copy pages are pinned in physical memory (no page-out).
- Cache performance: shadow copies are in the same NUMA domain as the
  reading CPU (fbvbs_mp_page_alloc_local).

**Verification:** EPT mapping for shadow copy pages has Read+NoWrite+NoExec
permissions. A read access completes without VM exit.

### 1.3 Tier B Modification (KSI Shadow Copy Update)

**Budget:** Microseconds (µs) to low tens of µs

**Design Guarantee:**
- Tier B updates follow the write-enable → copy → read-only cycle:
  1. Hypercall: request write-enable (VM exit + VMCALL handler + EPT permission update)
  2. Guest writes new value (no VM exit — EPT temporarily allows write)
  3. Hypercall: commit and re-protect (VM exit + VMCALL handler + EPT permission restore)
- Each VM exit costs ~500ns–1µs on modern hardware (VMRESUME fast path).
- Two VM exits per Tier B update = ~1–2µs baseline.
- EPT permission update is a PTE write + INVEPT (local) = ~100ns.

**Critical Constraint:** Multi-CPU coordination for Tier B updates
requires IPI-based TLB shootdown (fbvbs_mp_tlb_shootdown), adding
~5–10µs for cross-core synchronization.

### 1.4 Setuid/Setgid Exec Verification

**Budget:** Low tens of µs

**Design Guarantee:**
- Setuid verification requires one hypercall (VMCALL → dispatch → KSI
  lookup in setuid DB).
- Setuid DB is an in-memory array (FBVBS_MAX_SETUID_ENTRIES), searched
  by fsid+fileid. Linear scan of bounded array.
- Response is written to command page output buffer (no additional VM
  exit needed — guest polls command page status).
- Expected: 1 VM exit (~1µs) + DB lookup (~100ns) + response write
  (~100ns) = ~1.5µs per verification.

### 1.5 KLD (Kernel Loadable Module) Load

**Budget:** 100ms to sub-second

**Design Guarantee:**
- KLD load triggers multiple operations:
  1. Module hash computation (SHA-256 over module image — CPU-bound)
  2. Signature verification (Ed25519 verify — ~100µs)
  3. HLAT/NPT table update (PTE additions for new code pages)
  4. KCI binding record (GPA → artifact mapping)
  5. TLB shootdown (cross-CPU synchronization)
- The dominant cost is hash computation: SHA-256 over a typical KLD
  (10KB–1MB) takes 10µs–10ms on modern CPUs.
- HLAT table updates require page allocation + PTE writes + INVEPT.
- Total expected: 10ms–100ms for typical modules.

### 1.6 VM Exit Fast Path

**Budget:** Sub-µs (500ns–1µs)

**Design Guarantee:**
- Fast-path exits (EPT violation, I/O port, CPUID):
  1. Hardware saves guest state to VMCS (~200ns)
  2. Exit handler dispatch (switch on exit_reason) (~50ns)
  3. Security mitigations: IBPB (~200ns), VERW (~50ns if needed)
  4. Handler execution (EPT walk / I/O emulation / CPUID filter) (~100ns)
  5. VMRESUME (~200ns)
- Total: ~800ns for a typical fast-path exit.
- IBPB is the largest single cost (~200ns). This is mandatory for
  security (REQ-0311) and cannot be eliminated.

---

## 2. Prohibited Operations

| Operation | Prohibition | Enforcement |
|-----------|-------------|-------------|
| VMCALL in normal syscall path | Must not insert VMCALL into FreeBSD syscall entry/exit | No hook in MSR_LSTAR handler; syscall runs entirely in VMX non-root |
| VMCALL for Tier B read | Must not require IPC for shadow copy read | EPT maps shadow copies read-only in guest address space |
| Blocking log synchronization | Must not block guest execution for log writes | Ring buffer is lock-free for single-writer (mirror_log); spinlock only protects primary log append |
| Synchronous crypto in fast path | Must not call crypto primitives during VM exit fast path | Hash/signature operations are deferred to hypercall handlers (slow path) |

---

## 3. Measurement Plan

**Required Hardware:** x86-64 system with:
- Intel VT-x + EPT + HLAT (Ice Lake or newer) or AMD-V + NPT (Zen 2+)
- IOMMU (VT-d or AMD-Vi)
- TSC invariant (CPUID.80000007H:EDX[8] = 1)

**Methodology:**
1. RDTSC before/after each measured operation
2. Minimum of 10,000 iterations per measurement
3. Report: median, P95, P99, max
4. Baseline: native FreeBSD without FBVBS (for overhead calculation)

**Test Cases:**
1. `getpid()` syscall latency: native vs FBVBS (expect ~0% overhead)
2. Tier B read latency: mapped shadow copy read (expect 0 VM exits)
3. Tier B write latency: write-enable → write → re-protect cycle
4. Setuid exec verification: execve of setuid binary
5. KLD load: `kldload` of test module
6. VM exit round-trip: CPUID intercept (fast path baseline)
7. IBPB cost: isolated measurement of IBPB impact on exit latency

---

## 4. Risk Assessment

| Component | Risk | Mitigation |
|-----------|------|------------|
| IBPB on every exit | ~200ns per exit | Mandatory for security (REQ-0311); no alternative |
| L1D_FLUSH on cross-partition | ~100ns per cross-partition exit | Only on cross-partition exits; same-partition exits skip |
| VERW on every exit | ~50ns per exit (affected SKUs only) | Conditional on vuln profile; newer CPUs may not need |
| TLB shootdown IPI | ~5–10µs per shootdown | Batched where possible; NUMA-local allocation reduces cross-socket traffic |
| EPT walk overhead | ~1% continuous | Hardware-accelerated; no software mitigation needed |
