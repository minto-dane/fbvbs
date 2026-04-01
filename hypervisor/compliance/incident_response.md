# FBVBS Incident Response Procedures (REQ-1000, REQ-1103)

**Document:** IR-001
**Date:** 2026-03-23
**Scope:** Phase 9-4 audit preparation -- incident response sequences
**Status:** Design specification -- requires operational validation with Phase 4-7 services

---

## 1. Severity Classification

| Level | Name | Condition | Example |
|-------|------|-----------|---------|
| P0 | Total System Failure | Microhypervisor fault (triple fault, infinite halt, #MC) | Hypervisor bug triggers unrecoverable state |
| P1 | Critical Security | Key material compromise, integrity violation detected | IKS signing key exposed, measured hash mismatch |
| P2 | Service Failure | Single trusted service partition fault | KSI crashes, KCI unavailable |
| P3 | Degraded Operation | Non-critical function loss, performance degradation | UVS down (updates blocked), rate limiter active |

---

## 2. Key Compromise Response (P1)

### 2.1 Detection

Key compromise may be detected by:
- External notification (vendor advisory, HSM audit log, forensic analysis)
- IKS audit log anomaly (unexpected SIGN/KEY_EXCHANGE operations)
- UVS manifest signature verification failure with valid keys
- Hash measurement mismatch on KCI-protected code pages

### 2.2 Immediate Actions

1. **Isolate affected system**: Remove from network immediately and
   document any operational constraints that prevent isolation. The FBVBS
   audit log (UART/OOB path) continues independently of network state.

2. **Preserve audit trail**: Export primary log via OOB path before any
   remediation. The primary log is independent of the mirror log (REQ-0100)
   and cannot be modified by the guest (UART output only).

3. **Identify compromised key scope**:
   - IKS partition keys: affects SIGN, KEY_EXCHANGE, DERIVE operations
   - SKS derived keys: affects disk encryption key provisioning
   - UVS signing keys: affects update manifest verification

### 2.3 Key Material Protection

FBVBS key material isolation guarantees:
- IKS partition memory is EPT-protected -- inaccessible to host or other partitions
- Key material is zeroed on partition destroy (REQ-0203, REQ-0903):
  `fbvbs_partition_sanitize_memory()` zeroes all memory objects
- No key material leakage on crash: partition memory zeroed before struct clearing
- IKS key import pages are zeroed after import (`fbvbs_zero_page_at_gpa()`)

### 2.4 Revocation Sequence

1. **Stop IKS partition**: `VM_DESTROY` the IKS partition. This:
   - Transitions to DESTROYED state
   - Zeroes all IKS memory (page-by-page via `fbvbs_partition_sanitize_memory`)
   - Releases IOMMU domains
   - Audit log records PARTITION_DESTROY event

2. **SKS cascade**: SKS depends on IKS for key derivation. Without IKS:
   - New mount operations fail (fail-closed)
   - Already-mounted volumes continue (keys cached in FreeBSD GELI/ZFS layer)
   - Operator must unmount affected volumes to purge cached keys
   - **Verification checklist**: After IKS→SKS incident response, verify that all affected volumes have been unmounted and cached keys purged. Execute automated verification script if available.

   Note: destroying the IKS partition does **not** halt the host partition
   or the hypervisor itself. The host (FreeBSD, partition 0) continues
   running; only IKS-dependent service operations are affected. A full
   hypervisor halt occurs only on P0 (unrecoverable microhypervisor fault).

3. **UVS cascade**: UVS depends on IKS for manifest signature verification.
   Without IKS:
   - No updates can be applied (fail-closed)
   - Rollback prevention counters are NOT decremented
   - Current system continues at last-verified state

4. **Key rotation**: Requires HSM ceremony:
   - Generate new signing keypair in HSM
   - Re-sign all manifests with new key
   - Re-import keys into fresh IKS partition via `VM_CREATE` + key import
   - Re-derive SKS keys from new IKS master

### 2.5 Post-Incident

- Full system re-measurement: `VM_DESTROY` + `VM_CREATE` cycle for all services
- Review audit log for unauthorized operations preceding compromise
- Update HSM access controls and ceremony procedures
- Document root cause and update threat model

---

## 3. Audit Trail Protection Under Compromise (P1/P2)

### 3.1 Log Architecture Independence (target design vs current retained-C boundary)

FBVBS uses dual-path logging (REQ-0100, REQ-0103):

```
Microhypervisor
    |
    +---> Primary Log (UART/OOB) -- target end state
    |         authoritative external observation path
    |
    +---> Mirror Log -- current retained-C implementation
              in-memory ring buffer in hypervisor state, CRC32C integrity
```

### 3.2 Integrity Guarantees

**Warning:** The following table separates current implementation status from future design goals.

| Property | Mechanism | Status |
|----------|-----------|--------|
| Primary log independence | authoritative UART/OOB sink outside guest memory | retained-C runtime: partial |
| Mirror log immutability | EPT read-only mapping (REQ-0105) | Phase 2: design |
| Record integrity | CRC32C per record | Implemented (log.c) |
| Cryptographic integrity | HMAC-SHA-256 per record (REQ-0104) | Phase 5: planned |
| Tamper evidence | Monotonic sequence counter | Implemented |
| Boot correlation | boot_id_hi/boot_id_lo per record | Implemented |
| Overflow handling | Ring buffer with oldest-overwrite | Implemented |

### 3.3 Log Preservation Procedure

1. Capture primary log output from UART/serial console
2. Export mirror log via `AUDIT_GET_MIRROR_INFO` hypercall (read-only)
3. Verify CRC32C for each record (detect corruption)
4. Verify monotonic sequence numbers (detect gaps)
5. Cross-reference primary and mirror logs (detect tampering)
6. Archive with chain-of-custody documentation

---

## 4. Recovery Sequences

### 4.1 Single Service Restart (P2, future Phase 4+ runtime)

When a trusted service partition faults in the full service-enabled design:

1. **Detection**: `FBVBS_EVENT_PARTITION_FAULT` in audit log.
   vCPUs transition to `VCPU_STATE_FAULTED` -- no scheduling.

2. **Assessment**: Identify fault cause from audit record:
   - `last_fault_code`: fault type (watchdog timeout, unclassified exit, explicit)
   - `last_fault_source_component`: which subsystem detected the fault
   - `last_fault_detail0/detail1`: context-specific diagnostic data

3. **Controlled restart**: No automatic restart (prevents restart loops).
   Requires explicit operator action:
   ```
   VM_DESTROY(partition_id)    -- zeroes memory, releases resources
   VM_CREATE(new_config)       -- fresh partition with new ID
   MEMORY_MANAGE + MAP         -- re-map service code/data
   LOAD_MANIFEST               -- re-measure service code
   VM_RUN                      -- restart service
   ```

   **Authorization:** `VM_DESTROY` and `VM_CREATE` are restricted to the
   host partition (partition ID 0); guest partitions cannot invoke these
   hypercalls. The operator must have console or management-plane access.

   **Rollback on `LOAD_MANIFEST` failure:** If `LOAD_MANIFEST` fails
   (measurement mismatch or mapping error), the operator should
   `VM_DESTROY` the partially-created partition and investigate the image
   integrity before retrying. Do not proceed to `VM_RUN` with a failed
   manifest.

   **Current boundary note:** The retained-C repository can execute the
   microhypervisor side of the `VM_DESTROY` → `VM_CREATE` →
   `MEMORY_MANAGE + MAP` → `LOAD_MANIFEST` → `VM_RUN` sequence for the
   fixed ELF64 `ET_EXEC` release profile. `PARTITION_LOAD_IMAGE` is now
   implemented and remains fail-closed only on validation or mapping
   errors; the remaining end-to-end gap is the future trusted-service
   payload/orchestration work, not the loader primitive itself.

4. **Verify service health**: After restart, verify:
   - Partition state = RUNNING
   - Service responds to health check hypercalls
   - Audit log shows successful startup sequence

### 4.2 IKS Cascade Recovery (P1)

IKS failure cascades to SKS and UVS. Recovery:

1. Restart IKS first (procedure 4.1)
2. Re-import keys from sealed storage or HSM
3. Restart SKS (depends on IKS for key derivation)
4. Restart UVS (depends on IKS for signature verification)
5. Verify full service mesh operational

**During cascade failure**:
- FreeBSD host continues running
- All EPT/HLAT/IOMMU protections remain active
- No new modules can be loaded (KCI may function independently)
- No new disks mounted, no updates applied
- This is a degraded but secure state (fail-closed)

### 4.3 Full System Recovery (P0)

Microhypervisor failure requires hardware reset:

1. **Hardware reset** / power cycle
2. **DRTM re-establishment**: SKINIT (AMD) or TXT (Intel) re-measures hypervisor
3. **Boot integrity**: TPM PCR verification of hypervisor image
4. **Hypervisor init**: `fbvbs_hypervisor_init()` runs full initialization:
   - CPU security detection + vulnerability profiling
   - CR pin activation + global mitigations
   - IOMMU initialization
   - Boot integrity measurement
5. **Service re-creation**: All partitions re-created from scratch
6. **Service re-measurement**: Full measurement of all service code
7. **Operational verification**: All services running, audit log active

---

## 5. Escalation Matrix

| Severity | First Responder | Escalation | Notification Window |
|----------|----------------|------------|-------------------|
| P0 | On-call operator | Security team + management | Immediate |
| P1 | Security team | CISO + legal (if data breach) | Within 1 hour |
| P2 | On-call operator | Security team (if repeated) | Within 4 hours |
| P3 | Monitoring system | On-call operator | Within 24 hours |

### 5.1 Escalation Triggers

- **P2 -> P1**: Same service faults 3+ times in 24 hours
- **P2 -> P1**: IKS fault (any IKS fault is potential key compromise)
- **P3 -> P2**: Rate limiter active for >1 hour (may indicate attack)
- **P3 -> P2**: Watchdog faults total exceeds threshold

### 5.2 External Notification

Required when:
- Key material may have been exposed (regulatory obligation)
- Guest data integrity cannot be assured
- Compliance framework requires incident reporting (CC, FIPS)

---

## 6. Partition Fault Handling Evidence

The fault handling subsystem is verified by `tests/test_fault_injection.c`
(18 tests):

| Test | Scenario | Verification |
|------|----------|-------------|
| 1 | Log exhaustion (UINT64_MAX sequence) | Returns RESOURCE_EXHAUSTED |
| 2 | Log ring buffer saturation | Oldest records overwritten, CRC valid |
| 3 | Rollback attack (old generation) | Rejected with INVALID_PARAMETER |
| 4 | IOMMU fail-closed | Domain setup failure -> assignment rejected |
| 5 | Watchdog timeout intervention | Consecutive timer exits -> FAULTED |
| 5b | Watchdog negative cases | Unoccupied/non-RUNNING ignored |
| 6 | Rate limiter window rotation | Drops counted, summary emitted |
| 7 | Partition fault state restrictions | RUNNING/RUNNABLE/LOADED/QUIESCED: OK |
| 8 | Double fault idempotency | FAULTED -> INVALID_STATE, original preserved |
| 9 | Multiboot parser robustness | Malformed input -> safe defaults |
| 10-14 | ID allocator, lifecycle, edge cases | Tombstone exhaustion handled |
| 15 | Partition load image validation | Rejects invalid manifest/entry_ip |
| 16 | Partition load image mapping | Rejects invalid memory permissions |
| 17 | Partition load image success | Accepts valid ELF64 ET_EXEC |
| 18 | Partition destroy idempotency | Double destroy returns INVALID_STATE |

---

## 7. Watchdog Integration

The VMX preemption timer watchdog (`watchdog.c`) provides automatic
fault detection for hung partitions:

- **Detection**: `FBVBS_WATCHDOG_MAX_CONSECUTIVE` (10) consecutive timer
  exits without voluntary exit -> partition faulted
- **Bounds check**: `partition_idx >= FBVBS_MAX_PARTITIONS` -> defensive return
- **Occupied check**: Unoccupied slots ignored
- **TOCTOU handling**: `partition_fault` return value checked -- if another
  CPU already faulted the partition, counter is reset without double-counting
- **Audit**: `FBVBS_FAULT_WATCHDOG_TIMEOUT` event logged with CPU context
