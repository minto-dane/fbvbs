# FBVBS Service Failure Impact Analysis (REQ-1000, REQ-1103)

**Document:** SFI-001
**Date:** 2026-03-23
**Scope:** Appendix I — Service failure impact matrix
**Status:** Design analysis — requires Phase 4 (trusted services) for full validation

---

## 1. Architecture Overview

FBVBS is designed around a partitioned architecture with five trusted services:

```
┌─────────────────────────────────────────────────────┐
│              Microhypervisor (C11 + ACSL)           │
│  EPT/NPT │ IOMMU │ VMCS │ Audit Log │ Scheduler    │
├──────┬──────┬──────┬──────┬──────┬──────────────────┤
│ KCI  │ KSI  │ IKS  │ SKS  │ UVS  │ FreeBSD Host   │
│(SPARK)│(SPARK)│(SPARK)│(SPARK)│(SPARK)│ (deprivileged)│
└──────┴──────┴──────┴──────┴──────┴──────────────────┘
```

In the intended end state, each trusted service runs in its own
partition with independent failure domains. The current retained-C
repository already implements `PARTITION_LOAD_IMAGE` for the fixed
ELF64 `ET_EXEC` profile: it reads a measured service image, validates
`image_object_id`/`entry_ip`/`initial_sp`, maps it into partition
memory, and reaches `Loaded` only on success. The path remains
fail-closed on any measurement, loader, or mapping error, and the
SPARK trusted-service payloads plus full orchestration remain future
phase work.

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
- ACSL/WP verification work-in-progress on the retained C core (current status in `wp_verification_boundary.md`)
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

**KSI Protection Tier Definitions:**
- **Tier A (immutable):** Kernel structures that must never change after
  boot (e.g., sysent, IDT, GDT, vop_vector). Protected by EPT read-only
  mappings enforced by the microhypervisor — no KSI service dependency.
- **Tier B (controlled-update):** Kernel structures that may be
  legitimately modified but only within hypervisor-supervised write-enable
  windows (e.g., ucred, prison, securelevel). KSI maintains shadow copies
  and grants/revokes write access.

**Tier B resynchronization after KSI recovery:** Each Tier B shadow copy
must carry an epoch/version stamp and integrity checksum. When KSI is
restarted, it must fetch the current kernel state, compare the live object
against the shadow copy, and either roll forward through the recorded
change log or rebuild a fresh shadow under KSI control. During this
resync, writes remain gated by a temporary write-disable window or a
short-lived hypervisor-enforced lock; the new shadow is staged and then
atomically swapped in only after checksum and epoch validation succeed.

**Fail-Closed Behavior:**
- Tier A structures remain EPT read-only protected regardless of KSI
  availability — the microhypervisor enforces this independently
- Tier B shadow copies become stale if KSI fails but remain read-only —
  no new modifications permitted without KSI to grant write-enable windows
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

**Bootstrap sequence and the KCI/KSI dependency:** KSI depends on KCI for
verifying KSI's own code integrity, which appears circular if KCI also
depends on KSI. In practice, this is resolved by the bootstrap order:
1. The microhypervisor creates and measures KCI first (using its own
   built-in measurement, not KSI).
2. KCI reaches RUNNING state before KSI is created.
3. The microhypervisor creates KSI; KCI verifies KSI's module integrity
   during KSI's load phase.
4. Once both are running, KSI uses KCI for ongoing code integrity checks
   of its own updates (not its initial load).

If KCI fails after bootstrap, KSI continues running with its existing
verified code but cannot apply updates to itself. Recovery requires
restarting KCI first (via microhypervisor VM_DESTROY + VM_CREATE), then
optionally restarting KSI to re-establish full verification.

If KCI is unavailable during KSI startup, KSI must enter a
verification-suspended initialization mode. In that mode KSI may use
cached integrity metadata or an operator-approved offline verification
token to complete a bounded self-check, but it must not transition to
RUNNING or participate in service election until KCI health checks
succeed or the operator explicitly authorizes the offline path. If both
KCI and KSI are down, the operator recovery order is: bring KCI up first,
confirm its health and audit continuity, then restart KSI in normal mode
or verification-suspended mode, and finally re-enable dependent services
only after both services pass health checks.

Offline verification token requirements:

- generated under an operator-controlled asymmetric signing key (Ed25519 or ECDSA-P256 in the current design) held in HSM/SE-backed storage where available
- scoped to a specific KSI instance, boot/session epoch, and cached-metadata hash; any token KDF or derivation context must bind those fields so the token cannot be replayed for another service instance
- short-lived, single-purpose, and usage-count bounded; expiry, nonce, and allowed-use counter must be embedded in the signed token payload
- distributed only through the operator break-glass path and retained in sealed operator storage; emergency activation requires dual-approval or equivalent multi-party authorization
- must be audited with operator identity, token identifier, reason, KCI health status, and timestamp
- must trigger misuse alerts on repeated use, use outside the approved window, or mismatch with cached metadata

Bounded self-check definition:

- the self-check covers only the KSI executable image, its configuration manifest, the cached integrity metadata set, and the Tier B shadow-copy metadata required to start in read-only monitoring mode
- the algorithm is a deterministic local verification of signed metadata, image hash, token scope, epoch, and checksum/version fields; it must not silently regenerate or "repair" missing trust roots
- acceptable residual risk is limited to temporary operation with cached metadata while KCI is unavailable; live KCI-backed code-integrity approval and service-election participation remain disabled
- on any self-check failure, token mismatch, or cache inconsistency, KSI must remain non-running and the operator must fall back to restarting KCI first

Verification-suspended exit criteria:

- KCI health endpoint responds successfully for at least 3 consecutive probes over a minimum 30-second retry window
- cached metadata or offline-token self-check completes without integrity mismatch
- the bounded self-check covers the KSI image, configuration manifest, and shadow-copy metadata set
- KSI performs one clean shadow-copy resync pass and records a success audit event before transitioning to RUNNING
- on failure, KSI remains non-running and dependent services stay disabled

## 3.1 Service Election Mechanism

Participating services: KCI, KSI, IKS, SKS, UVS.

Purpose:

- control which service instance is allowed to advertise healthy leadership in a redundant deployment
- prevent a recovering or verification-suspended instance from rejoining prematurely

Rules:

- election is triggered on service startup, fault recovery, explicit operator restart, or health degradation
- tie-breakers use deployment policy ordering and monotonically increasing instance epoch
- quorum and redundancy policy are deployment-specific, but a service may not advertise itself healthy until its mandatory health checks pass

KSI rejoin criteria:

- 3 consecutive successful probes of the KSI health endpoint and integrity-status endpoint with no checksum/epoch mismatch
- shadow-copy resync queue empty and last resync marked committed
- no outstanding verification-suspended state
- operator acknowledgement if the instance previously used an offline token
- election rejoin must be logged together with operator identity and the recovery reason when manual approval was required

| Service Down | Cascade Effect |
|-------------|----------------|
| KCI down | Existing KSI continues with last-verified code; KSI startup must enter verification-suspended mode using cached metadata or an operator-approved offline token until KCI health checks pass |
| KSI down | No cascade (KCI, IKS, SKS, UVS independent); do not rejoin election until KSI health checks pass (see Section 3.1) |
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
| KCI fault → KLD load denied | Kill KCI partition, attempt kldload | Phase 4 target: mock KCI module with retained-measurement replay and a denied-load assertion |
| KSI fault → setuid denied | Kill KSI partition, attempt setuid exec | Phase 4 target: KSI mock + setuid database fixture + expected deny result |
| IKS fault → SKS/UVS cascade | Kill IKS partition, verify SKS+UVS fail | Phase 4 target: subsystem simulation with mock key handles and cascade assertions |
| Partition fault → FAULTED state | test_fault_injection.c test 7 | ✅ Verified |
| Watchdog → hung partition faulted | test_fault_injection.c test 5 | ✅ Verified |
| Double fault → idempotent | test_fault_injection.c test 8 | ✅ Verified |
| IOMMU domain cleanup on destroy | fbvbs_partition_destroy_common | ✅ Verified (WP + test) |
| Memory zeroed on destroy | fbvbs_partition_sanitize_memory | ✅ Verified (design) |

### 5.1 Phase 4 Timeline and Interim Verification

- M1 (Owner: KCI/KSI service lead, target 2026-04-15): complete the KCI/KSI mock interfaces and
  replayable fixtures for the partition lifecycle and health-check path.
- M2 (Owner: Trusted-service verification lead, target 2026-04-29): validate KCI denial and KSI
  verification-suspended startup using unit tests with offline tokens and
  cached metadata defined in Section 3.
- M3 (Owner: IKS/SKS/UVS service lead, target 2026-05-13): validate cascade behavior with
  subsystem simulations and audit-log assertions.
- Success criteria: each mock-based test must demonstrate fail-closed
  behavior, explicit operator actions, and reproducible logs before the
  hardware-backed Phase 4 run.
- Official verification proxy approval authority: the standalone
  microhypervisor release authority together with the trusted-service
  verification lead must approve mock and static-analysis evidence before it
  is treated as the verification proxy.
- Known limitations of the proxy: mock-based tests cannot prove real timing,
  device interaction, or physical isolation properties; they only justify
  fail-closed service logic and orchestration behavior.
- Risk acceptance for schedule slip: delays beyond the dates above require
  explicit approval by the release authority, documented acceptance
  criteria, and escalation to the project security owner.
