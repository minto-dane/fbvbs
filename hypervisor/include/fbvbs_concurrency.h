/*
 * FBVBS Concurrency Design (Phase 1-6)
 *
 * This header documents the locking strategy for the microhypervisor
 * and provides lock annotation macros for future enforcement.
 *
 * ================================================================
 * DESIGN DECISION: Big Hypervisor Lock + Per-CPU State
 * ================================================================
 *
 * The chosen concurrency model combines two strategies:
 *
 * 1. BIG HYPERVISOR LOCK (BHL): A single spinlock protects all
 *    mutations to g_fbvbs_hypervisor. This is simple, correct, and
 *    amenable to formal verification. The BHL is acquired on VM exit
 *    and released before VM entry.
 *
 * 2. PER-CPU STATE: CPU-local data (spec_ctrl, current vCPU, IDT
 *    state, debug registers) is accessed without locks. The CPU
 *    that owns the data is the only writer; other CPUs never read
 *    these fields.
 *
 * Rationale:
 *   - The hypervisor processes one hypercall at a time per core.
 *     Hypercalls are serialized by the VM exit → handler → VM entry
 *     cycle. The BHL serializes cross-core state mutations.
 *   - Fine-grained locking adds complexity, increases WP proof burden,
 *     and creates deadlock risk. The hypervisor's critical sections
 *     are short (microseconds), so contention is minimal.
 *   - Message passing (IPI-based) would require a per-core mailbox
 *     system — deferred to Phase 8 (multicore) if BHL contention
 *     becomes a bottleneck.
 *
 * ================================================================
 * LOCK HIERARCHY (deadlock prevention)
 * ================================================================
 *
 * Level 0 (highest priority, acquired first):
 *   NONE — Per-CPU state accessed locklessly
 *
 * Level 1:
 *   log_lock — Protects mirror_log ring buffer
 *   Acquired by: fbvbs_log_append, fbvbs_log_append_rate_limited
 *   Never held across: hypercall processing, page allocation
 *
 * Level 2:
 *   hypervisor_lock (BHL) — Protects g_fbvbs_hypervisor global state
 *   Acquired by: hypercall dispatch (VM exit handler)
 *   Released by: hypercall completion (before VM entry)
 *   Subsystems protected: partitions, memory objects, shared objects,
 *     IOMMU domains, KSI/IKS/SKS/UVS state, command trackers,
 *     artifact/device catalogs, manifest profiles, callsite tables
 *
 * Rule: A CPU holding the BHL (Level 2) may acquire log_lock (Level 1).
 * Level 2 → Level 1 is allowed.
 * Level 1 → Level 2 is forbidden (holding log_lock then acquiring BHL).
 * In practice, hypercall handlers call fbvbs_log_append while holding
 * the BHL, which acquires log_lock. This is safe because log_lock
 * is never held when the BHL is acquired.
 *
 * Rule: Exception handlers (#MC, #NMI, #DF) MUST NOT acquire the BHL.
 * They may only use log_lock for diagnostic output, and only with
 * try-lock semantics (bounded retry, not infinite spin). This is
 * already implemented: fbvbs_log_append_core uses a bounded 10000-
 * iteration spinlock that returns RESOURCE_BUSY on failure.
 *
 * ================================================================
 * PER-CPU STATE (accessed without locks)
 * ================================================================
 *
 * The following fields are per-CPU and never shared:
 *   - cpu_security.bsp_profile (BSP only; AP profiles in per-CPU array)
 *   - spec_ctrl.{host_spec_ctrl, guest_spec_ctrl}
 *   - IDT gate entries (loaded once at boot, immutable thereafter)
 *   - IST stacks (each core has its own IST stacks)
 *   - Debug registers (saved/restored per-vCPU on VM exit/entry)
 *   - APIC state (per-CPU LAPIC)
 *
 * ================================================================
 * FUTURE: Phase 8 (Multicore) considerations
 * ================================================================
 *
 * When AP initialization is added:
 *   1. Replicate per-CPU state into a per-CPU array indexed by APIC ID
 *   2. Add BHL acquisition to hypercall dispatch path
 *   3. Consider upgrading to per-partition locks if BHL contention
 *      exceeds 5% of VM exit latency
 *   4. Add \separated annotations between per-CPU arrays
 *
 * The current BSP-only model has no actual locking beyond log_lock,
 * because all operations are inherently serialized on a single core.
 * The BHL is defined here but not instantiated until Phase 8.
 */

#ifndef FBVBS_CONCURRENCY_H
#define FBVBS_CONCURRENCY_H

/* ================================================================
 * Lock annotation macros
 *
 * These are no-op macros for now. When Thread Safety Analysis or
 * a similar tool is integrated, they will be expanded to provide
 * compile-time lock-order checking.
 *
 * Usage:
 *   FBVBS_GUARDED_BY(lock) — field is protected by 'lock'
 *   FBVBS_REQUIRES(lock)   — function requires 'lock' to be held
 *   FBVBS_ACQUIRES(lock)   — function acquires 'lock'
 *   FBVBS_RELEASES(lock)   — function releases 'lock'
 *   FBVBS_NO_LOCK_REQUIRED — function is safe without any lock
 *   FBVBS_PER_CPU          — field is per-CPU, no lock needed
 * ================================================================ */

#define FBVBS_GUARDED_BY(lock)
#define FBVBS_REQUIRES(lock)
#define FBVBS_ACQUIRES(lock)
#define FBVBS_RELEASES(lock)
#define FBVBS_NO_LOCK_REQUIRED
#define FBVBS_PER_CPU

/* Lock identifiers (for documentation; not instantiated on BSP-only) */
#define FBVBS_LOCK_LOG       0U  /* Index 0: log_lock (Level 1, inner) */
#define FBVBS_LOCK_BHL       1U  /* Index 1: BHL (Level 2, outer, acquired first) */
#define FBVBS_LOCK_LEVEL_MAX 2U

#endif /* FBVBS_CONCURRENCY_H */
