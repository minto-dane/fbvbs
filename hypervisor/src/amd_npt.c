#include "fbvbs_hypervisor.h"
#include "fbvbs_asm.h"

/* ================================================================
 * AMD NPT (Nested Page Table) Translation Integrity
 *
 * On AMD platforms lacking Intel HLAT, translation integrity for
 * kernel code pages is enforced through a composite mechanism:
 *
 *   1. NPT write-protect: kernel PTE pages are mapped read-only
 *      in the NPT, so any guest attempt to modify a PTE triggers
 *      a #VMEXIT(NPT fault).
 *
 *   2. PTE update trap: the NPT fault handler validates requested
 *      PTE changes against KCI policy before applying them.
 *      Only KLD module load/unload (with prior hash verification)
 *      can modify executable code mappings.
 *
 *   3. TLB synchronisation: INVLPG/INVLPGA are intercepted to
 *      prevent stale TLB entries from bypassing write-protect.
 *      Multi-core invalidation uses IPI + sequence barrier.
 *
 *   4. SEV-SNP (optional): when present, RMP table enforcement
 *      provides hardware-level page ownership, complementing the
 *      software NPT write-protect scheme.
 *
 * This file provides the MODEL implementation. Production requires
 * actual NPT page table manipulation via physical page allocator
 * and SVM (Secure Virtual Machine) VMCB configuration.
 *
 * Requirements: REQ-0302 (AMD NPT 複合経路), REQ-0303 (AMD 高保証実証),
 *   REQ-0304 (SEV-SNP 補強のみ),
 *   REQ-1100 (AMD 翻訳整合性実証 — PRODUCTION NOTE: Phase 9 release gate)
 *
 * Reference: AMD APM Vol. 2, Chapter 15 (SVM)
 *            FBVBS Design Spec Section 21.3 (Translation Integrity)
 * ================================================================ */

/* ================================================================
 * NPT page table entry format (same as standard x86-64 PTE)
 *
 *   [0]     = Present
 *   [1]     = Read/Write
 *   [2]     = User/Supervisor
 *   [5]     = Accessed
 *   [6]     = Dirty
 *   [7]     = Page Size (PS) — 1 for 2MB/1GB pages
 *   [63]    = No-Execute (NX)
 *   [51:12] = Physical address of next level / page frame
 * ================================================================ */

#define NPT_PTE_PRESENT     (1ULL << 0)
#define NPT_PTE_RW          (1ULL << 1)
#define NPT_PTE_USER        (1ULL << 2)
#define NPT_PTE_ACCESSED    (1ULL << 5)
#define NPT_PTE_DIRTY       (1ULL << 6)
#define NPT_PTE_PS          (1ULL << 7)
#define NPT_PTE_NX          (1ULL << 63)
#define NPT_PTE_ADDR_MASK   0x000FFFFFFFFFF000ULL

#define NPT_ENTRIES_PER_TABLE  512U
#define NPT_PAGE_SIZE          4096ULL
#define NPT_LARGE_PAGE_SIZE    (2ULL * 1024ULL * 1024ULL)  /* 2MB */

/* ================================================================
 * SVM VMCB intercept bits (relevant to translation integrity)
 * ================================================================ */

/* VMCB offset 0x000: Intercept reads/writes of CRx */
#define SVM_INTERCEPT_CR0_WRITE   (1U << 16)
#define SVM_INTERCEPT_CR4_WRITE   (1U << 20)

/* VMCB offset 0x010: Miscellaneous intercepts */
#define SVM_INTERCEPT_INVLPG      (1U << 1)
#define SVM_INTERCEPT_INVLPGA     (1U << 10)
#define SVM_INTERCEPT_MSR         (1U << 28)

/* VMCB offset 0x014: Additional intercepts */
#define SVM_INTERCEPT_VMRUN       (1U << 0)
#define SVM_INTERCEPT_VMMCALL     (1U << 1)

/* NPT enable in VMCB */
#define SVM_NPT_ENABLE            (1ULL << 0)

/* #VMEXIT codes */
#define SVM_EXIT_NPT_FAULT        0x0400U
#define SVM_EXIT_INVLPG           0x006BU
#define SVM_EXIT_INVLPGA          0x00A0U
#define SVM_EXIT_CR0_WRITE        0x0010U
#define SVM_EXIT_CR4_WRITE        0x0014U

/* NPT fault error code bits */
#define NPT_FAULT_PRESENT         (1ULL << 0)
#define NPT_FAULT_WRITE           (1ULL << 1)
#define NPT_FAULT_USER            (1ULL << 2)
#define NPT_FAULT_RESERVED        (1ULL << 3)
#define NPT_FAULT_FETCH           (1ULL << 4)

/* ================================================================
 * Protected PTE page tracking
 *
 * The hypervisor tracks which guest-physical pages contain PTEs
 * for kernel code mappings. These pages are write-protected in
 * the NPT. Any write attempt triggers a #VMEXIT for validation.
 * ================================================================ */

#ifndef FBVBS_NPT_MAX_PROTECTED_PAGES
#define FBVBS_NPT_MAX_PROTECTED_PAGES  256U
#endif

#ifndef FBVBS_NPT_MAX_CODE_REGIONS
#define FBVBS_NPT_MAX_CODE_REGIONS     32U
#endif

struct fbvbs_npt_protected_page {
    uint32_t active;
    uint32_t level;           /* PT level: 1=PT, 2=PD, 3=PDPT, 4=PML4 */
    uint64_t guest_phys_addr; /* GPA of the page table page */
};

struct fbvbs_npt_code_region {
    uint32_t active;
    uint32_t flags;             /* 0=kernel text, 1=KLD module */
    uint64_t linear_base;       /* Guest virtual address */
    uint64_t size;              /* Region size in bytes */
    uint64_t module_object_id;  /* 0 for base kernel */
};

struct fbvbs_npt_config {
    uint32_t active;
    uint32_t reserved0;
    uint64_t npt_cr3;            /* Host-physical address of NPT PML4 */
    uint32_t protected_page_count;
    uint32_t code_region_count;
    struct fbvbs_npt_protected_page
        protected_pages[FBVBS_NPT_MAX_PROTECTED_PAGES];
    struct fbvbs_npt_code_region
        code_regions[FBVBS_NPT_MAX_CODE_REGIONS];
    /* TLB synchronisation state */
    uint64_t tlb_generation;     /* Monotonic generation counter */
    uint32_t pending_invlpg;     /* Count of pending TLB invalidations */
    uint32_t reserved1;
};

/* ================================================================
 * Per-partition NPT state: config + SNP + VMCB + allocated page
 *
 * NPT on AMD uses a memory-resident VMCB rather than VMWRITE.
 * We allocate a single PML4 page per partition. The PML4 page
 * is identity-mapped; its physical address becomes npt_cr3 in
 * the VMCB. Additional page table levels are built lazily by
 * the fault handler (production) or pre-populated (model).
 * ================================================================ */

struct fbvbs_npt_partition_state {
    struct fbvbs_npt_config config;
    uint64_t phys_pml4;    /* Host-physical address of NPT PML4 page */
};

static struct fbvbs_npt_partition_state npt_partitions[FBVBS_MAX_PARTITIONS];

/* Helper: find partition index by ID. Returns FBVBS_MAX_PARTITIONS if not found. */
static uint32_t npt_find_partition(
    const struct fbvbs_hypervisor_state *state,
    uint64_t partition_id)
{
    uint32_t i;

    for (i = 0; i < FBVBS_MAX_PARTITIONS; ++i) {
        if (state->partitions[i].occupied &&
            state->partitions[i].partition_id == partition_id) {
            return i;
        }
    }
    return FBVBS_MAX_PARTITIONS;
}

/* ================================================================
 * 3-1. NPT configuration initialisation
 *
 * Sets up the NPT write-protect configuration for a partition.
 * Called once during partition creation on AMD platforms.
 * ================================================================ */

/*@ requires \valid(config);
    assigns *config;
*/
static void fbvbs_npt_config_init(struct fbvbs_npt_config *config)
{
    uint32_t i;

    config->active = 0U;
    config->reserved0 = 0U;
    config->npt_cr3 = 0ULL;
    config->protected_page_count = 0U;
    config->code_region_count = 0U;
    config->tlb_generation = 1ULL;
    config->pending_invlpg = 0U;
    config->reserved1 = 0U;

    /*@ loop invariant 0 <= i <= FBVBS_NPT_MAX_PROTECTED_PAGES;
        loop assigns i, config->protected_pages[0 .. FBVBS_NPT_MAX_PROTECTED_PAGES - 1];
        loop variant FBVBS_NPT_MAX_PROTECTED_PAGES - i;
    */
    for (i = 0U; i < FBVBS_NPT_MAX_PROTECTED_PAGES; ++i) {
        config->protected_pages[i] =
            (struct fbvbs_npt_protected_page){0, 0U, 0ULL};
    }

    /*@ loop invariant 0 <= i <= FBVBS_NPT_MAX_CODE_REGIONS;
        loop assigns i, config->code_regions[0 .. FBVBS_NPT_MAX_CODE_REGIONS - 1];
        loop variant FBVBS_NPT_MAX_CODE_REGIONS - i;
    */
    for (i = 0U; i < FBVBS_NPT_MAX_CODE_REGIONS; ++i) {
        config->code_regions[i] =
            (struct fbvbs_npt_code_region){0, 0U, 0ULL, 0ULL, 0ULL};
    }
}

/* ================================================================
 * Add a verified code region to NPT protection
 *
 * Registers a virtual address range as verified kernel code.
 * The corresponding PTE pages will be write-protected in the NPT.
 * ================================================================ */

/*@ requires \valid(config);
    requires (linear_base & 4095) == 0;
    requires size > 0;
    requires (size & 4095) == 0;
    assigns *config;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_npt_add_code_region(
    struct fbvbs_npt_config *config,
    uint64_t linear_base,
    uint64_t size,
    uint32_t flags,
    uint64_t module_object_id)
{
    uint32_t i;

    if (config->code_region_count >= FBVBS_NPT_MAX_CODE_REGIONS) {
        return -1;  /* No space */
    }

    /* Reject wraparound: linear_base + size must not overflow */
    if (linear_base > UINT64_MAX - size) {
        return -1;
    }

    /* Check for overlap with existing regions */
    /*@ loop invariant 0 <= i <= FBVBS_NPT_MAX_CODE_REGIONS;
        loop assigns i;
        loop variant FBVBS_NPT_MAX_CODE_REGIONS - i;
    */
    for (i = 0U; i < FBVBS_NPT_MAX_CODE_REGIONS; ++i) {
        if (config->code_regions[i].active == 0U) {
            continue;
        }
        uint64_t r_start = config->code_regions[i].linear_base;
        uint64_t r_size = config->code_regions[i].size;

        /* Overflow-safe overlap: [linear_base, linear_base+size) ∩ [r_start, r_start+r_size)
         * Overlap iff linear_base < r_start + r_size AND r_start < linear_base + size.
         * Split by which start is larger to avoid unsigned overflow: */
        int overlaps;
        if (linear_base >= r_start) {
            overlaps = (linear_base - r_start) < r_size;
        } else {
            overlaps = (r_start - linear_base) < size;
        }
        if (overlaps) {
            return -1;  /* Overlap */
        }
    }

    /* Find a free slot */
    /*@ loop invariant 0 <= i <= FBVBS_NPT_MAX_CODE_REGIONS;
        loop assigns i;
        loop variant FBVBS_NPT_MAX_CODE_REGIONS - i;
    */
    for (i = 0U; i < FBVBS_NPT_MAX_CODE_REGIONS; ++i) {
        if (config->code_regions[i].active == 0U) {
            config->code_regions[i].active = 1U;
            config->code_regions[i].flags = flags;
            config->code_regions[i].linear_base = linear_base;
            config->code_regions[i].size = size;
            config->code_regions[i].module_object_id = module_object_id;
            config->code_region_count += 1U;
            return 0;
        }
    }

    return -1;  /* Should not reach here if count < max */
}

/* ================================================================
 * Remove a KLD module code region
 *
 * Called when a KLD module is unloaded. Removes the code region
 * and marks its PTE pages as no longer protected (the NPT
 * write-protect is lifted so the guest can reclaim the pages).
 * ================================================================ */

/*@ requires \valid(config);
    assigns *config;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_npt_remove_code_region(
    struct fbvbs_npt_config *config,
    uint64_t module_object_id)
{
    uint32_t i;

    if (module_object_id == 0ULL) {
        return -1;  /* Cannot remove base kernel */
    }

    /*@ loop invariant 0 <= i <= FBVBS_NPT_MAX_CODE_REGIONS;
        loop assigns i, config->code_regions[0 .. FBVBS_NPT_MAX_CODE_REGIONS - 1],
                     config->code_region_count;
        loop variant FBVBS_NPT_MAX_CODE_REGIONS - i;
    */
    for (i = 0U; i < FBVBS_NPT_MAX_CODE_REGIONS; ++i) {
        if (config->code_regions[i].active != 0U &&
            config->code_regions[i].module_object_id == module_object_id) {
            config->code_regions[i] =
                (struct fbvbs_npt_code_region){0, 0U, 0ULL, 0ULL, 0ULL};
            if (config->code_region_count > 0U) {
                config->code_region_count -= 1U;
            }
            return 0;
        }
    }

    return -1;  /* Not found */
}

/* ================================================================
 * Register a PTE page as write-protected
 *
 * Records that a guest-physical page contains PTEs for a code
 * region and must be write-protected in the NPT. Production code
 * would clear the RW bit in the NPT entry for this GPA.
 * ================================================================ */

/*@ requires \valid(config);
    requires (gpa & 4095) == 0;
    assigns *config;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_npt_protect_pte_page(
    struct fbvbs_npt_config *config,
    uint64_t gpa,
    uint32_t level)
{
    uint32_t i;

    if (level == 0U || level > 4U) {
        return -1;
    }

    if (config->protected_page_count >= FBVBS_NPT_MAX_PROTECTED_PAGES) {
        return -1;
    }

    /* Check for duplicate */
    /*@ loop invariant 0 <= i <= FBVBS_NPT_MAX_PROTECTED_PAGES;
        loop assigns i;
        loop variant FBVBS_NPT_MAX_PROTECTED_PAGES - i;
    */
    for (i = 0U; i < FBVBS_NPT_MAX_PROTECTED_PAGES; ++i) {
        if (config->protected_pages[i].active != 0U &&
            config->protected_pages[i].guest_phys_addr == gpa) {
            return 0;  /* Already protected */
        }
    }

    /* Find free slot */
    /*@ loop invariant 0 <= i <= FBVBS_NPT_MAX_PROTECTED_PAGES;
        loop assigns i;
        loop variant FBVBS_NPT_MAX_PROTECTED_PAGES - i;
    */
    for (i = 0U; i < FBVBS_NPT_MAX_PROTECTED_PAGES; ++i) {
        if (config->protected_pages[i].active == 0U) {
            config->protected_pages[i].active = 1U;
            config->protected_pages[i].level = level;
            config->protected_pages[i].guest_phys_addr = gpa;
            config->protected_page_count += 1U;

            /* PRODUCTION NOTE: Clear NPT_PTE_RW for the NPT entry
             * mapping this GPA. This makes any guest write to this
             * PTE page trigger a #VMEXIT(NPT fault). */

            return 0;
        }
    }

    return -1;
}

/* ================================================================
 * 3-2. NPT fault handler: PTE update validation
 *
 * Called on #VMEXIT(NPT fault) when the guest writes to a
 * write-protected PTE page. The handler:
 *
 *   1. Verifies the faulting GPA is a tracked PTE page
 *   2. Reads the guest's intended PTE modification
 *   3. Validates the modification against KCI policy:
 *      - New executable mapping: must have prior KCI hash verification
 *      - PFN change in existing executable PTE: REJECTED (REQ-0303)
 *      - Permission escalation (add W or X): REJECTED unless KCI
 *      - Non-executable mappings: allowed (data pages)
 *   4. If valid, applies the PTE change and resumes
 *   5. If invalid, injects #PF or faults the partition
 *
 * SECURITY: This is the critical path. Any bypass here allows
 * arbitrary code execution in the guest kernel.
 *
 * SERIALIZATION INVARIANT: NPT fault handling for the same GPA
 * range MUST be serialized. In single-vCPU mode this is inherent.
 * In multi-vCPU mode, concurrent PTE modifications by different
 * vCPUs to the same page are serialized because the page is
 * NPT write-protected: each write causes a #VMEXIT, and the
 * hypervisor processes these sequentially under the BHL (Big
 * Hypervisor Lock, see fbvbs_concurrency.h). Without the BHL,
 * a per-partition spinlock on the NPT protected page set would
 * be required to prevent TOCTOU on the guest PTE value.
 * ================================================================ */

/*@ requires \valid(config);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_npt_is_protected_page(
    const struct fbvbs_npt_config *config,
    uint64_t faulting_gpa)
{
    uint32_t i;
    uint64_t page_gpa = faulting_gpa & ~(NPT_PAGE_SIZE - 1ULL);

    /*@ loop invariant 0 <= i <= FBVBS_NPT_MAX_PROTECTED_PAGES;
        loop assigns i;
        loop variant FBVBS_NPT_MAX_PROTECTED_PAGES - i;
    */
    for (i = 0U; i < FBVBS_NPT_MAX_PROTECTED_PAGES; ++i) {
        if (config->protected_pages[i].active != 0U &&
            config->protected_pages[i].guest_phys_addr == page_gpa) {
            return 1;
        }
    }
    return 0;
}

/* Check if a linear address falls within a verified code region */
/*@ requires \valid_read(config);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_npt_is_code_address(
    const struct fbvbs_npt_config *config,
    uint64_t linear_addr)
{
    uint32_t i;

    /*@ loop invariant 0 <= i <= FBVBS_NPT_MAX_CODE_REGIONS;
        loop assigns i;
        loop variant FBVBS_NPT_MAX_CODE_REGIONS - i;
    */
    for (i = 0U; i < FBVBS_NPT_MAX_CODE_REGIONS; ++i) {
        if (config->code_regions[i].active == 0U) {
            continue;
        }
        uint64_t r_start = config->code_regions[i].linear_base;
        uint64_t r_size = config->code_regions[i].size;

        /* Overflow-safe containment check */
        if (linear_addr >= r_start &&
            (linear_addr - r_start) < r_size) {
            return 1;
        }
    }
    return 0;
}

/* Validate a PTE modification on a protected page.
 *
 * Returns:
 *   0  — modification allowed (non-executable data mapping)
 *  -1  — modification REJECTED (security violation)
 *  -2  — modification requires KCI approval (new code mapping)
 */
/*@ assigns \nothing;
    ensures \result == 0 || \result == -1 || \result == -2;
*/
static int fbvbs_npt_validate_pte_write(
    uint64_t old_pte,
    uint64_t new_pte)
{
    int old_present = (old_pte & NPT_PTE_PRESENT) != 0ULL;
    int new_present = (new_pte & NPT_PTE_PRESENT) != 0ULL;
    int old_exec = old_present && ((old_pte & NPT_PTE_NX) == 0ULL);
    int new_exec = new_present && ((new_pte & NPT_PTE_NX) == 0ULL);
    uint64_t old_pfn = (old_pte & NPT_PTE_ADDR_MASK) >> 12;
    uint64_t new_pfn = (new_pte & NPT_PTE_ADDR_MASK) >> 12;

    /* Case 1: Clearing a PTE — always allowed */
    if (!new_present) {
        return 0;
    }

    /* Case 2: Non-executable mapping — allowed (data pages) */
    if (!new_exec) {
        return 0;
    }

    /* Case 3: New executable mapping where none existed
     * Requires KCI hash verification before approval */
    if (!old_exec && new_exec) {
        return -2;  /* Needs KCI approval */
    }

    /* Case 4: PFN change on existing executable PTE (REQ-0303)
     * This is the PFN substitution attack — ALWAYS reject */
    if (old_exec && new_exec && old_pfn != new_pfn) {
        return -1;  /* PFN substitution: SECURITY VIOLATION */
    }

    /* Case 5: Permission change on existing executable PTE
     * Adding write permission to code page — reject (W^X) */
    if (new_exec && (new_pte & NPT_PTE_RW) != 0ULL) {
        return -1;  /* W+X violation */
    }

    /* Case 6: Same PFN, compatible permissions — allow
     * (e.g. accessed/dirty bit updates by hardware) */
    return 0;
}

/* Top-level NPT fault handler.
 *
 * Called from the SVM #VMEXIT handler when exit code == NPT_FAULT.
 *
 * Returns:
 *   0  — fault handled, resume guest
 *  -1  — security violation, fault the partition
 */
/*@ requires \valid(config);
    assigns config->tlb_generation;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_npt_handle_fault(
    struct fbvbs_npt_config *config,
    uint64_t faulting_gpa,
    uint64_t error_code,
    uint64_t old_pte,
    uint64_t new_pte)
{
    /* Only handle write faults to protected pages */
    if ((error_code & NPT_FAULT_WRITE) == 0ULL) {
        return -1;  /* Not a write fault — unexpected */
    }

    if (fbvbs_npt_is_protected_page(config, faulting_gpa) == 0) {
        return -1;  /* Write to non-tracked page — should not happen */
    }

    int result = fbvbs_npt_validate_pte_write(old_pte, new_pte);

    if (result == -1) {
        /* Security violation: PFN substitution or W+X */
        return -1;
    }

    if (result == -2) {
        /* Needs KCI approval: caller must check KCI bindings
         * before emulating the PTE write. Propagate -2 so the
         * outer handler in vm_policy.c can perform KCI binding checks. */
        return -2;
    }

    /* Allowed modification: increment TLB generation (saturating) */
    if (config->tlb_generation < UINT64_MAX) {
        config->tlb_generation += 1ULL;
    }

    /* PRODUCTION NOTE: Emulate the PTE write by temporarily
     * enabling write access to the NPT entry, writing new_pte
     * to the guest's PTE page, then re-applying write-protect.
     * This must be done atomically (no guest execution between
     * the write-enable and re-protect). */

    return 0;
}

/* ================================================================
 * 3-3. TLB synchronisation and race prevention
 *
 * INVLPG/INVLPGA interception ensures the hypervisor maintains
 * a consistent view of which TLB entries the guest believes are
 * valid. Without interception, the guest could:
 *
 *   1. Modify a PTE (trapped by NPT write-protect)
 *   2. Immediately INVLPG to flush the old TLB entry
 *   3. Race: another core still sees the old mapping
 *
 * By intercepting INVLPG, the hypervisor can:
 *   - Verify the invalidation is consistent with tracked PTEs
 *   - Enforce cross-core TLB shootdown before resuming
 *   - Increment TLB generation for audit trail
 * ================================================================ */

/*@ requires \valid(config);
    assigns config->tlb_generation, config->pending_invlpg;
    ensures \result == 0;
*/
static int fbvbs_npt_handle_invlpg(
    struct fbvbs_npt_config *config,
    uint64_t linear_addr)
{
    /* Track TLB invalidation for code addresses */
    if (fbvbs_npt_is_code_address(config, linear_addr) != 0) {
        if (config->pending_invlpg < UINT32_MAX) {
            config->pending_invlpg += 1U;
        }
    }

    /* Increment TLB generation — cross-core flush required
     * before pending_invlpg can be decremented.
     * Saturate at UINT64_MAX (fail-closed: never wrap to 0). */
    if (config->tlb_generation < UINT64_MAX) {
        config->tlb_generation += 1ULL;
    }

    /* PRODUCTION NOTE: Issue IPI to all other cores in this
     * partition to flush their TLB entries for linear_addr.
     * Wait for acknowledgement before returning.
     * Model: immediate (single-core model). */

    if (config->pending_invlpg > 0U) {
        config->pending_invlpg -= 1U;
    }

    return 0;
}

/* Multi-core TLB generation check.
 * Returns 0 if all cores are synchronised, -1 if stale. */
/*@ requires \valid_read(config);
    assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_npt_check_tlb_sync(
    const struct fbvbs_npt_config *config,
    uint64_t expected_generation)
{
    if (config->tlb_generation < expected_generation) {
        return -1;  /* Stale — should not happen */
    }
    if (config->pending_invlpg > 0U) {
        return -1;  /* Pending invalidations */
    }
    return 0;
}

/* ================================================================
 * VMCB intercept configuration for NPT write-protect
 *
 * Builds the VMCB intercept bits needed for AMD NPT translation
 * integrity. These must be OR'd into the partition's VMCB before
 * VMRUN.
 * ================================================================ */

struct fbvbs_amd_npt_vmcb_config {
    uint32_t intercept_cr;       /* CR read/write intercepts */
    uint32_t intercept_misc;     /* Miscellaneous intercepts */
    uint32_t intercept_misc2;    /* Additional intercepts */
    uint32_t reserved0;
    uint64_t npt_cr3;            /* NPT page table root */
    uint64_t npt_control;        /* NPT enable + options */
};

/*@ requires \valid(vmcb_config);
    requires \valid_read(config);
    assigns *vmcb_config;
*/
static void fbvbs_npt_build_vmcb_config(
    struct fbvbs_amd_npt_vmcb_config *vmcb_config,
    const struct fbvbs_npt_config *config)
{
    *vmcb_config = (struct fbvbs_amd_npt_vmcb_config){0, 0U, 0U, 0U,
                                                       0ULL, 0ULL};

    /* Intercept CR0/CR4 writes for pin enforcement */
    vmcb_config->intercept_cr = SVM_INTERCEPT_CR0_WRITE |
                                SVM_INTERCEPT_CR4_WRITE;

    /* Intercept INVLPG/INVLPGA for TLB synchronisation */
    vmcb_config->intercept_misc = SVM_INTERCEPT_INVLPG |
                                  SVM_INTERCEPT_INVLPGA |
                                  SVM_INTERCEPT_MSR;

    /* Intercept VMRUN/VMMCALL */
    vmcb_config->intercept_misc2 = SVM_INTERCEPT_VMRUN |
                                   SVM_INTERCEPT_VMMCALL;

    /* NPT configuration */
    vmcb_config->npt_control = SVM_NPT_ENABLE;
    vmcb_config->npt_cr3 = config->npt_cr3;
}

/* ================================================================
 * 3-4. SEV-SNP auxiliary (optional complement)
 *
 * When AMD SEV-SNP is available, the RMP (Reverse Map Table)
 * provides hardware-enforced page ownership. Each physical page
 * has an RMP entry specifying its owner ASID and page type.
 * This complements NPT write-protect by preventing the hypervisor
 * itself from being tricked into modifying guest pages without
 * proper RMP validation.
 *
 * SEV-SNP is used as a COMPLEMENT to NPT write-protect, not a
 * replacement (REQ-0304: "SEV-SNP is supplementary only").
 * ================================================================ */

/* VMPL (Virtual Machine Privilege Level) for FBVBS */
#define FBVBS_VMPL_HYPERVISOR  0U  /* VMPL 0: full control */
#define FBVBS_VMPL_GUEST       1U  /* VMPL 1: guest kernel */

/* RMP entry permissions */
#define RMP_PERM_READ          (1U << 0)
#define RMP_PERM_WRITE         (1U << 1)
#define RMP_PERM_EXEC_USER     (1U << 2)
#define RMP_PERM_EXEC_SUPER    (1U << 3)

struct fbvbs_sev_snp_config {
    uint32_t available;     /* 1 if SEV-SNP detected */
    uint32_t active;        /* 1 if SEV-SNP enabled for partition */
    uint64_t asid;          /* Guest ASID for RMP lookups */
};

/*@ requires \valid(config);
    assigns *config;
*/
static void fbvbs_sev_snp_config_init(struct fbvbs_sev_snp_config *config)
{
    config->available = 0U;
    config->active = 0U;
    config->asid = 0ULL;

    /* PRODUCTION NOTE: Check CPUID Fn8000_001F for SEV-SNP support.
     * If available, set config->available = 1.
     * Model: always unavailable. */
}

/* Validate RMP permissions for a code page.
 * Returns 0 if RMP allows execute, -1 if denied. */
/*@ requires \valid_read(config);
    assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_sev_snp_validate_code_page(
    const struct fbvbs_sev_snp_config *config,
    uint64_t guest_phys_addr)
{
    if (config->active == 0U) {
        return 0;  /* SEV-SNP not active, fall through to NPT-only */
    }

    (void)guest_phys_addr;

    /* PRODUCTION NOTE: Read the RMP entry for guest_phys_addr.
     * Verify:
     *   1. RMP entry owner ASID matches config->asid
     *   2. Page type is appropriate (4K or 2M)
     *   3. VMPL permissions allow supervisor execute
     *   4. Page is not marked immutable (unless code page)
     * Model: always return success when active. */

    return 0;
}

/* ================================================================
 * Public API: Initialise AMD NPT translation integrity
 *
 * Called during partition creation on AMD platforms (where HLAT
 * is not available). Sets up NPT write-protect, registers kernel
 * text code regions, and optionally enables SEV-SNP.
 * ================================================================ */

/*@ requires \valid(state);
    requires (kernel_text_base & 4095) == 0;
    requires kernel_text_size > 0;
    requires (kernel_text_size & 4095) == 0;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_npt_init_for_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t kernel_text_base,
    uint64_t kernel_text_size)
{
    struct fbvbs_npt_partition_state *nps;
    struct fbvbs_amd_npt_vmcb_config vmcb_config;
    uint64_t phys_pml4;
    uint64_t pte_page_gpa;
    uint32_t part_idx;
    int rc;

    /* Fail-closed: AMD must have SVM + NPT */
    if (state->vmx_caps.vmx_supported != 0U) {
        return -1;  /* Intel platform — use HLAT instead */
    }

    /* Find partition index by ID */
    part_idx = npt_find_partition(state, partition_id);
    if (part_idx >= FBVBS_MAX_PARTITIONS) {
        return -1;
    }

    nps = &npt_partitions[part_idx];

    /* Initialize NPT configuration */
    fbvbs_npt_config_init(&nps->config);

    /* Register kernel text as a code region */
    rc = fbvbs_npt_add_code_region(&nps->config,
                                   kernel_text_base,
                                   kernel_text_size,
                                   0U,     /* flags: kernel text */
                                   0ULL);  /* module_object_id: base kernel */
    if (rc != 0) {
        return -1;
    }

    /* Protect the PTE pages covering the kernel text region.
     * PRODUCTION NOTE: Walk the guest's page tables to find which
     * physical pages contain PTEs for the kernel text range, then
     * call fbvbs_npt_protect_pte_page for each. Model: protect a
     * single representative PTE page. */
    pte_page_gpa = kernel_text_base;  /* Model: use base as stand-in */
    rc = fbvbs_npt_protect_pte_page(&nps->config, pte_page_gpa, 1U);
    if (rc != 0) {
        return -1;
    }

    /* Allocate NPT PML4 page via page allocator.
     * The PML4 page is zeroed by the allocator (all entries not-present).
     * Identity-mapped: physical address == virtual address. */
    phys_pml4 = fbvbs_page_alloc();
    if (phys_pml4 == 0U) {
        return -1;
    }

    nps->phys_pml4 = phys_pml4;
    nps->config.npt_cr3 = phys_pml4;

    /* Build VMCB configuration and apply.
     * PRODUCTION NOTE: The VMCB is a memory-resident structure.
     * Production applies these fields to the partition's VMCB page
     * (allocated separately in partition creation). Model: validate
     * the VMCB config is constructed correctly. */
    fbvbs_npt_build_vmcb_config(&vmcb_config, &nps->config);

#ifndef __FRAMAC__
    /* Write NPT PML4 entries for kernel text region.
     * For the model, we populate a single PML4 entry chain
     * (PML4 → PDPT → PD → PT allocated lazily by fault handler). */
    {
        volatile uint64_t *virt_pml4 =
            (volatile uint64_t *)(uintptr_t)phys_pml4;
        /* Mark PML4 entry for kernel text as present (upper-half).
         * Full production populates all 4 levels; here we just set
         * the PML4 entry to indicate the region is managed. */
        uint32_t pml4_idx =
            (uint32_t)((kernel_text_base >> 39) & 0x1FFU);
        virt_pml4[pml4_idx] = NPT_PTE_PRESENT | NPT_PTE_RW |
                              NPT_PTE_USER | NPT_PTE_ACCESSED;
    }
#endif

    /* SEV-SNP initialisation (optional, stack-local check) */
    {
        struct fbvbs_sev_snp_config snp;
        fbvbs_sev_snp_config_init(&snp);
        /* Validate SEV-SNP code page check is callable */
        (void)fbvbs_sev_snp_validate_code_page(&snp, kernel_text_base);
    }

    nps->config.active = 1U;

    return 0;
}

/* ================================================================
 * Public API: Add KLD module code region (AMD)
 *
 * Called after KCI hash verification approves a KLD module.
 * Registers the module's code pages and write-protects their PTEs.
 * ================================================================ */

/*@ requires \valid(state);
    requires (module_base & 4095) == 0;
    requires module_size > 0;
    requires (module_size & 4095) == 0;
    assigns npt_partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == 0 || \result == -1;
*/
int fbvbs_npt_add_kld_module(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t module_object_id,
    uint64_t module_base,
    uint64_t module_size)
{
    struct fbvbs_npt_partition_state *nps;
    uint32_t part_idx;
    int rc;

    part_idx = npt_find_partition(state, partition_id);
    if (part_idx >= FBVBS_MAX_PARTITIONS) {
        return -1;
    }

    nps = &npt_partitions[part_idx];
    if (nps->config.active == 0U) {
        return -1;  /* NPT not initialized for this partition */
    }

    rc = fbvbs_npt_add_code_region(&nps->config,
                                   module_base,
                                   module_size,
                                   1U,  /* flags: KLD module */
                                   module_object_id);
    if (rc != 0) {
        return -1;
    }

    /* Protect PTE page for the module region */
    rc = fbvbs_npt_protect_pte_page(&nps->config, module_base, 1U);
    if (rc != 0) {
        return -1;
    }

    return 0;
}

/* ================================================================
 * Public API: Remove KLD module code region (AMD)
 * ================================================================ */

/*@ requires \valid(state);
    assigns npt_partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == 0 || \result == -1;
*/
int fbvbs_npt_remove_kld_module(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t module_object_id)
{
    struct fbvbs_npt_partition_state *nps;
    uint32_t part_idx;

    part_idx = npt_find_partition(state, partition_id);
    if (part_idx >= FBVBS_MAX_PARTITIONS) {
        return -1;
    }

    nps = &npt_partitions[part_idx];
    if (nps->config.active == 0U) {
        return -1;
    }

    return fbvbs_npt_remove_code_region(&nps->config, module_object_id);
}

/* ================================================================
 * Public API: Handle NPT fault (AMD)
 *
 * Called from the SVM #VMEXIT handler. Returns -1 (always reject
 * in fail-closed mode) unless the fault is a validated PTE update.
 * ================================================================ */

/*@ requires \valid(state);
    assigns npt_partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == 0 || \result == -1;
*/
int fbvbs_npt_handle_fault_exit(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t faulting_gpa,
    uint64_t error_code)
{
    struct fbvbs_npt_partition_state *nps;
    uint32_t part_idx;

    part_idx = npt_find_partition(state, partition_id);
    if (part_idx >= FBVBS_MAX_PARTITIONS) {
        return -1;
    }

    nps = &npt_partitions[part_idx];
    if (nps->config.active == 0U) {
        return -1;
    }

    /* If this is a write fault, attempt PTE validation */
    if ((error_code & NPT_FAULT_WRITE) != 0ULL) {
        /* PRODUCTION NOTE: Read old_pte from the guest's PTE page
         * and new_pte from the guest's write attempt (instruction
         * decode or page table walk). Model: use zeroes. */
        int rc = fbvbs_npt_handle_fault(&nps->config,
                                        faulting_gpa,
                                        error_code,
                                        0ULL,   /* old_pte */
                                        0ULL);  /* new_pte */
        return rc;
    }

    /* Not a write fault — security violation */
    return -1;
}

/* ================================================================
 * Public API: Handle INVLPG exit (AMD)
 * ================================================================ */

/*@ requires \valid(state);
    assigns npt_partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == 0 || \result == -1;
*/
int fbvbs_npt_handle_invlpg_exit(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t linear_addr)
{
    struct fbvbs_npt_partition_state *nps;
    uint32_t part_idx;

    part_idx = npt_find_partition(state, partition_id);
    if (part_idx >= FBVBS_MAX_PARTITIONS) {
        return -1;
    }

    nps = &npt_partitions[part_idx];
    if (nps->config.active == 0U) {
        return -1;
    }

    /* Validate TLB sync is callable */
    (void)fbvbs_npt_check_tlb_sync(&nps->config, nps->config.tlb_generation);

    return fbvbs_npt_handle_invlpg(&nps->config, linear_addr);
}

/* ================================================================
 * AMD GMET (Guest Mode Execute Trap for NPT)
 *
 * GMET is the AMD counterpart to Intel MBEC. It splits the NPT
 * execute permission into separate controls for user-mode and
 * supervisor-mode execution.
 *
 * When GMET is enabled (VMCB offset 090h bit 24):
 *   - NPT PTE bit [2] (User) is repurposed:
 *     Bit[2]=0: only supervisor execute allowed
 *     Bit[2]=1: only user execute allowed
 *   - The hardware traps on privilege-mode mismatches
 *
 * Combined with NPT write-protect, GMET provides:
 *   1. NPT write-protect prevents PTE modifications (Phase 3-1)
 *   2. GMET restricts WHO can execute (user vs supervisor)
 *   3. W^X is enforced per privilege level
 *
 * Reference: AMD APM Vol. 2, Section 15.25.5
 *            Appendix D (MBEC/GMET)
 * ================================================================ */

/* VMCB NP_ENABLE register extensions */
#define SVM_GMET_ENABLE           (1ULL << 24)

/* NPT entry permissions with GMET */
#define NPT_GMET_SUPERVISOR_EXEC  0ULL  /* Bit[2]=0: supervisor execute */
#define NPT_GMET_USER_EXEC        NPT_PTE_USER  /* Bit[2]=1: user execute */

/* GMET policy types */
#define GMET_POLICY_DATA_ONLY     0U
#define GMET_POLICY_KERNEL_CODE   1U
#define GMET_POLICY_USER_CODE     2U

struct fbvbs_gmet_config {
    uint32_t available;
    uint32_t active;
    uint64_t npt_control_or;   /* Bits to OR into VMCB NP_ENABLE */
};

/*@ requires \valid(config);
    assigns *config;
*/
static void fbvbs_gmet_init(struct fbvbs_gmet_config *config)
{
    config->available = 0U;
    config->active = 0U;
    config->npt_control_or = 0ULL;

    /* PRODUCTION NOTE: Check CPUID Fn8000_000A:EDX[24] for GMET
     * availability. Model: always available (AMD spec feature). */
    config->available = 1U;
    config->active = 1U;
    config->npt_control_or = SVM_GMET_ENABLE;
}

/* Compute NPT entry permissions for a page based on GMET policy.
 *
 * W^X enforcement: a page is NEVER both writable and executable.
 */
/*@ requires \valid_read(config);
    assigns \nothing;
    ensures \result != 0ULL ==>
        ((\result & NPT_PTE_RW) == 0ULL) ||
        (((\result & NPT_PTE_PRESENT) != 0ULL) &&
         ((\result & NPT_PTE_NX) != 0ULL));
*/
static uint64_t fbvbs_gmet_npt_permissions(
    const struct fbvbs_gmet_config *config,
    uint32_t policy,
    int writable)
{
    uint64_t perm = NPT_PTE_PRESENT;  /* Always present */

    /* W^X: reject writable code pages at the API boundary */
    if (writable && policy != GMET_POLICY_DATA_ONLY) {
        return 0ULL;  /* Invalid: W+X request → return empty permissions */
    }

    if (config->active == 0U) {
        /* Without GMET, basic NPT permissions. W^X. */
        if (writable) {
            perm |= NPT_PTE_RW | NPT_PTE_NX;
        }
        /* Executable = no NX bit, no RW bit (read + execute) */
        return perm;
    }

    /* GMET active: privilege-level-aware execute control */
    switch (policy) {
    case GMET_POLICY_KERNEL_CODE:
        /* Supervisor execute only: Bit[2]=0 (no User), no write */
        /* perm already has Present set, no RW, no NX */
        break;

    case GMET_POLICY_USER_CODE:
        /* User execute only: Bit[2]=1 (User), no write */
        perm |= NPT_GMET_USER_EXEC;
        break;

    case GMET_POLICY_DATA_ONLY:
    default:
        /* Data page: NX set, writable if requested */
        perm |= NPT_PTE_NX;
        if (writable) {
            perm |= NPT_PTE_RW;
        }
        break;
    }

    return perm;
}

/* Public API: Build GMET VMCB configuration.
 * Returns the NP_ENABLE bits and validates W^X invariant.
 */
/*@ requires \valid(npt_control_or);
    assigns *npt_control_or;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_gmet_build_config(uint64_t *npt_control_or)
{
    struct fbvbs_gmet_config config;
    uint64_t kernel_perm, user_perm, data_perm;

    fbvbs_gmet_init(&config);

    *npt_control_or = config.npt_control_or;

    if (config.active == 0U) {
        return -1;
    }

    /* Validate W^X invariant */
    kernel_perm = fbvbs_gmet_npt_permissions(&config,
                                             GMET_POLICY_KERNEL_CODE, 0);
    user_perm = fbvbs_gmet_npt_permissions(&config,
                                           GMET_POLICY_USER_CODE, 0);
    data_perm = fbvbs_gmet_npt_permissions(&config,
                                           GMET_POLICY_DATA_ONLY, 1);

    /* W^X: kernel code must not be writable */
    if ((kernel_perm & NPT_PTE_RW) != 0ULL) {
        return -1;
    }
    /* W^X: user code must not be writable */
    if ((user_perm & NPT_PTE_RW) != 0ULL) {
        return -1;
    }
    /* W^X: writable data must be NX */
    if ((data_perm & NPT_PTE_NX) == 0ULL) {
        return -1;
    }

    return 0;
}

/* ================================================================
 * Public API: Release NPT resources for a destroyed partition
 *
 * Called during partition destroy to release NPT PML4 page back
 * to the page allocator (which zeroes it on free).
 * ================================================================ */

void fbvbs_npt_cleanup_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id)
{
    struct fbvbs_npt_partition_state *nps;
    uint32_t part_idx;

    part_idx = npt_find_partition(state, partition_id);
    if (part_idx >= FBVBS_MAX_PARTITIONS) {
        return;
    }

    nps = &npt_partitions[part_idx];

    if (nps->config.active == 0U) {
        return;
    }

    /* Release allocated NPT PML4 page */
    if (nps->phys_pml4 != 0U) {
        (void)fbvbs_page_free(nps->phys_pml4);
    }

    /* Clear partition NPT state */
    *nps = (struct fbvbs_npt_partition_state){0};
}
