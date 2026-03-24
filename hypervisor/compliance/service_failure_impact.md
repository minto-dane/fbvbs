# FBVBS Service Failure Impact Analysis (REQ-1000, REQ-1103)

**Document:** SFI-001
**Date:** 2026-03-23
**Scope:** Appendix I — Service failure impact matrix
**Status:** Design analysis — requires Phase 4 (trusted services) for full validation

---

## 1. Architecture Overview

FBVBS uses a partitioned architecture with five trusted services:

```
┌─────────────────────────────────────────────────────┐
│              Microhypervisor (C11 + ACSL)           │
│  EPT/NPT │ IOMMU │ VMCS │ Audit Log │ Scheduler    │
├──────┬──────┬──────┬──────┬──────┬──────────────────┤
│ KCI  │ KSI  │ IKS  │ SKS  │ UVS  │ FreeBSD Host   │
│(SPARK)│(SPARK)│(SPARK)│(SPARK)│(SPARK)│ (deprivileged)│
└──────┴──────┴──────┴──────┴──────┴──────────────────┘
```

Each trusted service runs in its own partition with independent failure
domains. The microhypervisor enforces partition isolation via EPT/NPT
and IOMMU.

---

## 2. Failure Impact Matrix

### 2.1 Microhypervisor Failure

| Aspect | Impact |
|--------|--------|
| **Scope** | Total system halt |
| **Mechanism** | Triple fault → CPU reset, or infinite halt loop |
| **Affected** | ALL partitions (host + all guests + all services) |
| **Recovery** | Hardware reset / power cycle only |
| **Rationale** | The microhypervisor IS the TCB root. No entity can restart it. |

**Design Mitigations:**
- Formal verification (99.32% WP goals proved)
- Watchdog (NMI-based) can detect microhypervisor hangs (PRODUCTION NOTE)
- #DF (double fault) and #MC (machine check) use dedicated IST stacks
  to prevent stack corruption cascading into triple fault
- Microhypervisor code is minimal (~15K SLOC C) to reduce failure probability

### 2.2 KCI (Kernel Code Integrity) Failure

| Aspect | Impact |
|--------|--------|
| **Stopped Function** | Module signature verification, W^X enforcement |
| **Maintained Protection** | Second-level paging (EPT/NPT/HLAT) remains active |
| **Host Impact** | KLD loading blocked (fail-closed); existing loaded modules continue running |
| **Guest Impact** | None (guests don't interact with KCI) |
| **Recovery** | Partition restart via microhypervisor; re-measurement required |

**Fail-Closed Behavior:**
- If KCI is unavailable, `kci_set_wx` returns MEASUREMENT_FAILED
- No new execute permissions can be granted
- Existing code pages retain their permissions (EPT/HLAT immutable)
- Translation integrity (HLAT/NPT) continues enforcing at hardware level

### 2.3 KSI (Kernel State Integrity) Failure

| Aspect | Impact |
|--------|--------|
| **Stopped Function** | Tier B shadow copy monitoring, setuid verification |
| **Maintained Protection** | Tier A invariants (EPT read-only), EPT/HLAT/NPT |
| **Host Impact** | Setuid exec verification unavailable (fail-closed: deny all setuid transitions); Tier B write-enable requests denied |
| **Guest Impact** | None |
| **Recovery** | Partition restart; shadow copy re-initialization from live kernel state |

**Fail-Closed Behavior:**
- Tier A (immutable structures: sysent, IDT, GDT, vop_vector) remain
  EPT read-only protected — no service dependency
- Tier B (controlled-update: ucred, prison, securelevel) shadow copies
  become stale but remain read-only — no new modifications permitted
- Setuid DB lookup fails closed: all setuid transitions denied

### 2.4 IKS (Identity Key Service) Failure

| Aspect | Impact |
|--------|--------|
| **Stopped Function** | Key operations (SIGN, KEY_EXCHANGE, DERIVE) |
| **Maintained Protection** | Keys remain sealed in IKS partition memory (EPT-protected) |
| **Host Impact** | Cryptographic operations unavailable; key-dependent services degraded |
| **Guest Impact** | None (guests don't have direct IKS access) |
| **Recovery** | Partition restart; keys re-imported from sealed storage or HSM |

**Fail-Closed Behavior:**
- Key material is never exposed outside IKS partition boundary
- EPT isolation ensures IKS memory is inaccessible even if service is crashed
- No key material leakage on crash (partition memory zeroed on destroy,
  REQ-0203/REQ-0903)

### 2.5 SKS (Storage Key Service) Failure

| Aspect | Impact |
|--------|--------|
| **Stopped Function** | Disk encryption key provisioning |
| **Maintained Protection** | Already-mounted volumes remain accessible; keys in use are cached in kernel |
| **Host Impact** | New mount operations requiring key provisioning fail; unmount+remount fails |
| **Guest Impact** | Guest disk operations via virtio continue (virtio-blk doesn't use SKS) |
| **Recovery** | Partition restart; key re-derivation from HKDF + sealed master |

**Fail-Closed Behavior:**
- Disk encryption keys for already-mounted volumes are in kernel memory
  (FreeBSD GELI / ZFS layer), not in SKS — continued I/O is possible
- New key requests to SKS fail closed: mount operations return error
- Key material in SKS partition zeroed on partition destruction

### 2.6 UVS (Update Verification Service) Failure

| Aspect | Impact |
|--------|--------|
| **Stopped Function** | Update manifest verification, rollback prevention |
| **Maintained Protection** | Current system state is unaffected; no updates can be applied |
| **Host Impact** | `freebsd-update` / `pkg` operations requiring signature verification blocked |
| **Guest Impact** | None |
| **Recovery** | Partition restart; version store re-read |

**Fail-Closed Behavior:**
- No updates can be applied while UVS is down (fail-closed)
- Rollback prevention counters (TPM NV or version store) are not
  decremented — rollback protection maintained
- Current system continues running at last-verified state

---

## 3. Cross-Service Dependencies

```
KCI ──→ (none — standalone)
KSI ──→ KCI (for verifying KSI's own module integrity)
IKS ──→ (none — standalone key store)
SKS ──→ IKS (for key derivation primitives)
UVS ──→ IKS (for manifest signature verification)
```

| Service Down | Cascade Effect |
|-------------|----------------|
| KCI down | KSI cannot verify its own updates; existing KSI continues |
| KSI down | No cascade (KCI, IKS, SKS, UVS independent) |
| IKS down | SKS key derivation fails; UVS signature verification fails |
| SKS down | No cascade (mount operations fail, but I/O continues) |
| UVS down | No cascade (updates blocked, system runs at current state) |

**Worst Case:** IKS failure cascades to SKS and UVS. All three stop
functioning. However:
- FreeBSD host continues running
- All existing security protections (EPT, HLAT, IOMMU) remain active
- No new modules can be loaded, no new disks mounted, no updates applied
- This is a degraded but secure state (fail-closed)

---

## 4. Partition Fault Handling

When a trusted service partition faults:

1. **Detection:** Unclassified VM exit, watchdog timeout, or explicit
   fault trigger (fbvbs_partition_fault)
2. **State Transition:** RUNNING → FAULTED (audit log record generated)
3. **Isolation:** Faulted partition continues to occupy its EPT/IOMMU
   domains — memory isolation maintained
4. **vCPU Stop:** All vCPUs in faulted partition transition to
   VCPU_STATE_FAULTED — no scheduling
5. **Notification:** Host is notified via mirror log (FBVBS_EVENT_PARTITION_FAULT)
6. **Recovery:** Controlled restart requires explicit VM_DESTROY + VM_CREATE
   cycle (no automatic restart — prevents restart loops)

---

## 5. Verification Requirements

| Test | Method | Status |
|------|--------|--------|
| Microhypervisor fault = total halt | Injected triple fault | Design analysis only |
| KCI fault → KLD load denied | Kill KCI partition, attempt kldload | Requires Phase 4 |
| KSI fault → setuid denied | Kill KSI partition, attempt setuid exec | Requires Phase 4 |
| IKS fault → SKS/UVS cascade | Kill IKS partition, verify SKS+UVS fail | Requires Phase 4 |
| Partition fault → FAULTED state | test_fault_injection.c test 7 | ✅ Verified |
| Watchdog → hung partition faulted | test_fault_injection.c test 5 | ✅ Verified |
| Double fault → idempotent | test_fault_injection.c test 8 | ✅ Verified |
| IOMMU domain cleanup on destroy | fbvbs_partition_destroy_common | ✅ Verified (WP + test) |
| Memory zeroed on destroy | fbvbs_partition_sanitize_memory | ✅ Verified (design) |
