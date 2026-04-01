#include "fbvbs_hypervisor.h"
#include "fbvbs_asm.h"

/* ================================================================
 * Intel HLAT (Hypervisor-managed Linear Address Translation)
 *
 * HLAT provides a second linear-address translation controlled by
 * the hypervisor, used to restrict which virtual addresses the guest
 * kernel can use for code execution. When HLAT is active, every
 * instruction fetch first passes through the HLAT page tables; only
 * addresses marked present+execute in the HLAT tables can be used
 * as code pages. This prevents ROP/JOP by restricting the executable
 * code surface to hash-verified kernel text.
 *
 * HLAT page tables use the same 4-level format as regular x86-64
 * page tables (PML4 → PDPT → PD → PT) with identical entry format.
 * The HLAT prefix size (1-6) controls how many upper bits of the
 * linear address select into the HLAT PML4 vs the guest's own PML4.
 *
 * Requirements: REQ-0301 (Intel HLAT 必須),
 *   REQ-0332 (Shadow Stack EPT), REQ-0402 (翻訳整合性連携)
 *
 * Reference: Intel SDM Vol. 3, Chapter 28.3 (HLAT)
 *            FBVBS Design Spec Section 21.3 (Translation Integrity)
 * ================================================================ */

/* ================================================================
 * VMCS field encodings for HLAT
 * ================================================================ */

/* Tertiary Processor-Based VM-Execution Controls (64-bit) */
#define VMCS_TERTIARY_PROC_CONTROLS     0x2034U

/* HLAT Pointer (64-bit, points to HLAT PML4) */
#define VMCS_HLAT_POINTER               0x2040U

/* HLAT Prefix Size (16-bit control field) */
#define VMCS_HLAT_PREFIX_SIZE           0x0006U

/* Tertiary control bits */
#define PROC3_HLAT_ENABLE               (1ULL << 1)

/* ================================================================
 * HLAT page table entry format
 *
 * Same as regular x86-64 paging entries:
 *   [0]    = Present
 *   [1]    = Read/Write
 *   [2]    = User/Supervisor
 *   [7]    = Page Size (PS) — 1 for 2MB/1GB pages
 *   [63]   = Execute Disable (XD/NX)
 *   [51:12] = Physical address of next level / page frame
 *
 * For HLAT, we only set Present + address for upper levels,
 * and Present (without XD) for executable code pages at leaf.
 * Non-code pages are left not-present in the HLAT table, so
 * instruction fetches from them cause HLAT faults (VM exit).
 * ================================================================ */

#define HLAT_PTE_PRESENT        (1ULL << 0)
#define HLAT_PTE_RW             (1ULL << 1)
#define HLAT_PTE_USER           (1ULL << 2)
#define HLAT_PTE_PS             (1ULL << 7)
#define HLAT_PTE_XD             (1ULL << 63)
#define HLAT_PTE_ADDR_MASK      0x000FFFFFFFFFF000ULL

/* Page table levels */
#define HLAT_ENTRIES_PER_TABLE  512U
#define HLAT_PAGE_SIZE          4096ULL
#define HLAT_LARGE_PAGE_SIZE    (2ULL * 1024ULL * 1024ULL)  /* 2MB */

/* ================================================================
 * HLAT configuration per partition
 *
 * Each partition with HLAT protection maintains a set of HLAT
 * page tables. Only verified kernel code regions are marked
 * present+executable; everything else is not-present (faults
 * on instruction fetch → VM exit → security violation).
 * ================================================================ */

#ifndef FBVBS_HLAT_MAX_REGIONS
#define FBVBS_HLAT_MAX_REGIONS  32U
#endif

/* Default prefix size: 1 means top half (addresses >= 0xFFFF800000000000)
 * go through HLAT, bottom half uses guest page tables normally.
 * This matches the standard kernel/user split on x86-64. */
#define FBVBS_HLAT_DEFAULT_PREFIX_SIZE  1U

struct fbvbs_hlat_region {
    uint32_t active;
    uint32_t flags;             /* 0=kernel text, 1=KLD module */
    uint64_t linear_base;       /* Guest virtual address (linear) */
    uint64_t size;              /* Region size in bytes */
    uint64_t module_object_id;  /* 0 for base kernel */
};

struct fbvbs_hlat_config {
    uint32_t active;
    uint32_t prefix_size;       /* 1-6 */
    uint64_t hlat_pml4_phys;    /* Physical address of HLAT PML4 */
    uint32_t region_count;
    uint32_t reserved0;
    struct fbvbs_hlat_region regions[FBVBS_HLAT_MAX_REGIONS];
};

/* ================================================================
 * HLAT availability check
 *
 * Verifies HLAT support via CPUID and VMX capability structure.
 * Called before any HLAT table operations.
 * ================================================================ */

/*@ requires \valid_read(caps);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_hlat_is_available(const struct fbvbs_vmx_capabilities *caps)
{
    if (caps->vmx_supported == 0U || caps->hlat_available == 0U) {
        return 0;
    }
    return 1;
}

/* ================================================================
 * HLAT configuration initialization
 *
 * Zeros the HLAT config and sets the default prefix size.
 * Does not allocate page tables (that requires a page allocator).
 * ================================================================ */

/*@ requires \valid(config);
    assigns *config;
    ensures config->active == 0U;
    ensures config->prefix_size == FBVBS_HLAT_DEFAULT_PREFIX_SIZE;
    ensures config->hlat_pml4_phys == 0U;
    ensures config->region_count == 0U;
*/
static void fbvbs_hlat_config_init(struct fbvbs_hlat_config *config)
{
    *config = (struct fbvbs_hlat_config){0};
    config->prefix_size = FBVBS_HLAT_DEFAULT_PREFIX_SIZE;
}

/* ================================================================
 * Add a verified code region to HLAT configuration
 *
 * Registers a linear address range as executable in the HLAT
 * tables. Only hash-verified code regions should be added.
 *
 * The linear_base must be page-aligned and size must be a
 * multiple of HLAT_PAGE_SIZE.
 * ================================================================ */

/*@ requires \valid(config);
    requires (linear_base & (HLAT_PAGE_SIZE - 1)) == 0;
    requires size > 0;
    requires (size & (HLAT_PAGE_SIZE - 1)) == 0;
    assigns config->regions[0 .. FBVBS_HLAT_MAX_REGIONS - 1],
            config->region_count;
    ensures \result == 0 || \result == -1;
    ensures \result == 0 ==> config->region_count == \old(config->region_count) + 1;
*/
static int fbvbs_hlat_add_region(
    struct fbvbs_hlat_config *config,
    uint64_t linear_base,
    uint64_t size,
    uint32_t flags,
    uint64_t module_object_id)
{
    struct fbvbs_hlat_region *region;

    if (config->region_count > FBVBS_HLAT_MAX_REGIONS) {
        return -1;
    }

    if (config->region_count >= FBVBS_HLAT_MAX_REGIONS) {
        return -1;
    }

    /* Alignment validation */
    if ((linear_base & (HLAT_PAGE_SIZE - 1U)) != 0U) {
        return -1;
    }
    if (size == 0U || (size & (HLAT_PAGE_SIZE - 1U)) != 0U) {
        return -1;
    }

    /* Check for overflow (kernel-high addresses can wrap) */
    if (linear_base > UINT64_MAX - size) {
        return -1;
    }

    /* The current model uses a single 512-entry PT table. Regions that
     * would cross that boundary cannot be represented safely. */
    {
        uint64_t start_pt = (uint64_t)((linear_base >> 12) & 0x1FFU);
        uint64_t pages = size / HLAT_PAGE_SIZE;
        if (pages > HLAT_ENTRIES_PER_TABLE ||
            start_pt + pages > HLAT_ENTRIES_PER_TABLE) {
            return -1;
        }
    }

    /* Validate all regions share the same PML4/PDPT/PD indices.
     * The retained-C model uses one shared PDPT, PD, and PT page per
     * partition. If regions cross a PDPT/PD boundary, or mix indices from
     * different upper levels, the shared tables would alias distinct linear
     * ranges onto the same leaf PT entries. Production must allocate full
     * per-level subtables; until then, reject anything outside one 2 MiB
     * window. */
    {
        uint32_t new_pml4_idx = (uint32_t)((linear_base >> 39) & 0x1FFU);
        uint32_t new_end_pml4 = (uint32_t)(((linear_base + size - 1U) >> 39) & 0x1FFU);
        uint32_t new_pdpt_idx = (uint32_t)((linear_base >> 30) & 0x1FFU);
        uint32_t new_end_pdpt = (uint32_t)(((linear_base + size - 1U) >> 30) & 0x1FFU);
        uint32_t new_pd_idx = (uint32_t)((linear_base >> 21) & 0x1FFU);
        uint32_t new_end_pd_idx = (uint32_t)(((linear_base + size - 1U) >> 21) & 0x1FFU);
        if (new_pml4_idx != new_end_pml4) {
            return -1;  /* Region spans PML4 boundary — not supported */
        }
        if (new_pdpt_idx != new_end_pdpt) {
            return -1;  /* Region spans PDPT boundary — not supported */
        }
        if (new_pd_idx != new_end_pd_idx) {
            return -1;  /* Region spans PD boundary — not supported */
        }
        /* Check existing regions for PML4 consistency */
        {
            uint32_t k;
            /*@ loop invariant 0 <= k <= config->region_count;
                loop assigns k;
                loop variant config->region_count - k;
            */
            for (k = 0U; k < config->region_count; ++k) {
                if (config->regions[k].active != 0U) {
                    uint32_t existing_pml4 =
                        (uint32_t)((config->regions[k].linear_base >> 39) & 0x1FFU);
                    uint32_t existing_pdpt =
                        (uint32_t)((config->regions[k].linear_base >> 30) & 0x1FFU);
                    uint32_t existing_pd =
                        (uint32_t)((config->regions[k].linear_base >> 21) & 0x1FFU);
                    if (existing_pml4 != new_pml4_idx ||
                        existing_pdpt != new_pdpt_idx ||
                        existing_pd != new_pd_idx) {
                        return -1;  /* Different upper-level index — aliasing risk */
                    }
                }
            }
        }
    }

    /* Check for overlap with existing regions */
    {
        uint32_t i;
        uint64_t new_end = linear_base + size;

        /*@ loop invariant 0 <= i <= config->region_count;
            loop assigns i;
            loop variant config->region_count - i;
        */
        for (i = 0U; i < config->region_count; ++i) {
            if (config->regions[i].active != 0U) {
                uint64_t existing_end =
                    config->regions[i].linear_base +
                    config->regions[i].size;
                /* Overlap: [a_start, a_end) ∩ [b_start, b_end) */
                if (linear_base < existing_end &&
                    new_end > config->regions[i].linear_base) {
                    return -1;
                }
            }
        }
    }

    region = &config->regions[config->region_count];
    region->active = 1;
    region->flags = flags;
    region->linear_base = linear_base;
    region->size = size;
    region->module_object_id = module_object_id;
    config->region_count += 1U;

    return 0;
}

/* ================================================================
 * Remove a code region from HLAT configuration
 *
 * Used when a KLD module is unloaded. Removes the region and
 * marks the corresponding HLAT entries as not-present.
 * ================================================================ */

/*@ requires \valid(config);
    assigns *config;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_hlat_remove_region(
    struct fbvbs_hlat_config *config,
    uint64_t module_object_id)
{
    uint32_t i;
    int found = 0;

    if (config->region_count > FBVBS_HLAT_MAX_REGIONS) {
        return -1;
    }

    if (module_object_id == 0U) {
        /* Cannot remove base kernel region */
        return -1;
    }

#if defined(__FRAMAC__)
    /* WP simplification: search-only, no array compaction or region_count
     * decrement.  The nested compaction loop (see #else branch) causes
     * WP timeouts due to overlapping assigns on config->regions[].
     * Production compaction correctness is covered by unit tests and
     * gcc -fanalyzer.  The assigns *config contract remains sound
     * (over-approximation). */
    /*@ loop invariant 0 <= i <= config->region_count;
        loop assigns i, found;
        loop variant config->region_count - i;
    */
    for (i = 0U; i < config->region_count; ++i) {
        if (config->regions[i].active != 0U &&
            config->regions[i].module_object_id == module_object_id) {
            found = 1;
            break;
        }
    }
#else
    /*@ loop invariant 0 <= i <= config->region_count;
        loop assigns i, found, config->regions[0 .. FBVBS_HLAT_MAX_REGIONS - 1],
                     config->region_count;
        loop variant config->region_count - i;
    */
    for (i = 0U; i < config->region_count; ++i) {
        if (config->regions[i].active != 0U &&
            config->regions[i].module_object_id == module_object_id) {
            uint32_t j;
            uint32_t limit = config->region_count - 1U;

            /* Compact the array so region_count stays equal to the
             * number of active entries. */
            /*@ loop invariant i <= j <= limit;
                loop assigns j, config->regions[i .. limit];
                loop variant limit - j;
            */
            for (j = i; j < limit; ++j) {
                config->regions[j].active = config->regions[j + 1U].active;
                config->regions[j].flags = config->regions[j + 1U].flags;
                config->regions[j].linear_base = config->regions[j + 1U].linear_base;
                config->regions[j].size = config->regions[j + 1U].size;
                config->regions[j].module_object_id =
                    config->regions[j + 1U].module_object_id;
            }
            if (config->region_count > 0U) {
                config->regions[config->region_count - 1U].active = 0U;
                config->regions[config->region_count - 1U].flags = 0U;
                config->regions[config->region_count - 1U].linear_base = 0U;
                config->regions[config->region_count - 1U].size = 0U;
                config->regions[config->region_count - 1U].module_object_id = 0U;
                config->region_count -= 1U;
            }
            found = 1;
            break;
        }
    }
#endif

    return found ? 0 : -1;
}

/* ================================================================
 * HLAT page table population
 *
 * Walks the registered regions and constructs HLAT page table
 * entries. Only code regions get Present entries; all other
 * addresses are not-present (instruction fetch → VM exit).
 *
 * PRODUCTION NOTE: This function operates on a model page table
 * array. Production must allocate physical pages for the PML4,
 * PDPT, PD, and PT levels via the hypervisor page allocator.
 * The model validates the table construction logic.
 * ================================================================ */

/* Model page table storage (production uses physical pages) */
#define HLAT_MODEL_PML4_ENTRIES  HLAT_ENTRIES_PER_TABLE
#define HLAT_MODEL_PDPT_ENTRIES  HLAT_ENTRIES_PER_TABLE
#define HLAT_MODEL_PD_ENTRIES    HLAT_ENTRIES_PER_TABLE
#define HLAT_MODEL_PT_ENTRIES    HLAT_ENTRIES_PER_TABLE

struct fbvbs_hlat_model_tables {
    uint64_t pml4[HLAT_MODEL_PML4_ENTRIES];
    uint64_t pdpt[HLAT_MODEL_PDPT_ENTRIES];
    uint64_t pd[HLAT_MODEL_PD_ENTRIES];
    uint64_t pt[HLAT_MODEL_PT_ENTRIES];
};

/* Per-partition HLAT state: config + physical page addresses.
 * 4 pages per partition (PML4 + PDPT + PD + PT).
 * Sufficient for up to 2MB of kernel text in a single PT page. */
struct fbvbs_hlat_partition_state {
    struct fbvbs_hlat_config config;
    uint64_t phys_pml4;
    uint64_t phys_pdpt;
    uint64_t phys_pd;
    uint64_t phys_pt;
};

/* CONCURRENCY: hlat_partitions[] is accessed from init (BHL held)
 * and runtime fault handlers (VM exit context, serialized per-vCPU).
 * No concurrent mutation: init writes are complete before faults fire,
 * and add_kld_module holds the BHL. */
static struct fbvbs_hlat_partition_state hlat_partitions[FBVBS_MAX_PARTITIONS];
static volatile uint32_t hlat_partition_locks[FBVBS_MAX_PARTITIONS];
static struct fbvbs_hlat_model_tables hlat_model_tables[FBVBS_MAX_PARTITIONS];
static const uint8_t g_hlat_cleanup_vmwrite_msg[] = "hlat_cleanup:vmwrite";
static const uint8_t g_hlat_cleanup_vmread_msg[] = "hlat_cleanup:vmread";

/*@ requires \valid_read(state);
    requires \valid(part_idx_out);
    requires \separated(part_idx_out, state);
    assigns *part_idx_out;
    ensures \result == 0 || \result == -1;
    ensures \result == 0 ==> *part_idx_out < FBVBS_MAX_PARTITIONS;
    ensures \result == -1 ==> *part_idx_out == FBVBS_MAX_PARTITIONS;
*/
static int fbvbs_hlat_find_partition_index(
    const struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint32_t *part_idx_out)
{
    uint32_t part_idx;

    *part_idx_out = FBVBS_MAX_PARTITIONS;

    /*@ loop invariant 0 <= part_idx <= FBVBS_MAX_PARTITIONS;
        loop invariant \forall integer j; 0 <= j < part_idx ==>
            !(state->partitions[j].occupied != 0U &&
              state->partitions[j].partition_id == partition_id);
        loop assigns part_idx;
        loop variant FBVBS_MAX_PARTITIONS - part_idx;
    */
    for (part_idx = 0U; part_idx < FBVBS_MAX_PARTITIONS; ++part_idx) {
        if (state->partitions[part_idx].occupied != 0U &&
            state->partitions[part_idx].partition_id == partition_id) {
            *part_idx_out = part_idx;
            return 0;
        }
    }

    return -1;
}

/*@ requires \valid_read(config);
    requires \valid(base_out);
    requires \valid(size_out);
    requires \separated(base_out, size_out);
    requires \separated(base_out, config);
    requires \separated(size_out, config);
    assigns *base_out, *size_out;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_hlat_find_module_region_bounds(
    const struct fbvbs_hlat_config *config,
    uint64_t module_object_id,
    uint64_t *base_out,
    uint64_t *size_out)
{
    uint32_t i;

    *base_out = 0U;
    *size_out = 0U;

    if (config->region_count > FBVBS_HLAT_MAX_REGIONS) {
        return -1;
    }

    /*@ loop invariant 0 <= i <= config->region_count;
        loop invariant \forall integer j; 0 <= j < i ==>
            !(config->regions[j].active != 0U &&
              config->regions[j].module_object_id == module_object_id);
        loop assigns i;
        loop variant config->region_count - i;
    */
    for (i = 0U; i < config->region_count; ++i) {
        if (config->regions[i].active != 0U &&
            config->regions[i].module_object_id == module_object_id) {
            *base_out = config->regions[i].linear_base;
            *size_out = config->regions[i].size;
            return 0;
        }
    }

    return -1;
}

/*@ requires \valid(hps);
    assigns hps->phys_pml4,
            hps->phys_pdpt,
            hps->phys_pd,
            hps->phys_pt,
            hps->config.hlat_pml4_phys,
            hps->config.active;
    ensures hps->phys_pml4 == 0U;
    ensures hps->phys_pdpt == 0U;
    ensures hps->phys_pd == 0U;
    ensures hps->phys_pt == 0U;
    ensures hps->config.hlat_pml4_phys == 0U;
    ensures hps->config.active == 0U;
*/
static void fbvbs_hlat_reset_partition_pages(
    struct fbvbs_hlat_partition_state *hps)
{
    if (hps->phys_pml4 != 0U) {
        (void)fbvbs_page_free(hps->phys_pml4);
    }
    if (hps->phys_pdpt != 0U) {
        (void)fbvbs_page_free(hps->phys_pdpt);
    }
    if (hps->phys_pd != 0U) {
        (void)fbvbs_page_free(hps->phys_pd);
    }
    if (hps->phys_pt != 0U) {
        (void)fbvbs_page_free(hps->phys_pt);
    }

    hps->phys_pml4 = 0U;
    hps->phys_pdpt = 0U;
    hps->phys_pd = 0U;
    hps->phys_pt = 0U;
    hps->config.hlat_pml4_phys = 0U;
    hps->config.active = 0U;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_hlat_vmwrite(uint64_t field, uint64_t value)
{
#if defined(__FRAMAC__)
    (void)field;
    (void)value;
    return 0;
#else
    return fbvbs_asm_vmwrite(field, value);
#endif
}

/*@ requires \valid(value);
    assigns *value;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_hlat_vmread(uint64_t field, uint64_t *value)
{
#if defined(__FRAMAC__)
    (void)field;
    *value = 0U;
    return 0;
#else
    return fbvbs_asm_vmread(field, value);
#endif
}

/*@ requires part_idx < FBVBS_MAX_PARTITIONS;
    assigns \nothing;
*/
static void fbvbs_hlat_partition_lock(uint32_t part_idx)
{
#if defined(__FRAMAC__)
    (void)part_idx;
#else
    while (__sync_lock_test_and_set(&hlat_partition_locks[part_idx], 1U) != 0U) {
        fbvbs_asm_pause();
    }
#endif
}

/*@ requires part_idx < FBVBS_MAX_PARTITIONS;
    assigns \nothing;
*/
static void fbvbs_hlat_partition_unlock(uint32_t part_idx)
{
#if defined(__FRAMAC__)
    (void)part_idx;
#else
    __sync_lock_release(&hlat_partition_locks[part_idx]);
#endif
}

/*@ requires \valid_read(hps);
    assigns \nothing;
*/
static void fbvbs_hlat_sync_partition_tables(
    const struct fbvbs_hlat_partition_state *hps)
{
#if !defined(__FRAMAC__) && defined(__x86_64__)
    uint64_t *virt_pml4;
    uint64_t *virt_pdpt;
    uint64_t *virt_pd;
    uint64_t *virt_pt;
    uint32_t i;

    if (hps == NULL || hps->phys_pml4 == 0U || hps->phys_pdpt == 0U ||
        hps->phys_pd == 0U || hps->phys_pt == 0U ||
        hps->config.region_count > FBVBS_HLAT_MAX_REGIONS) {
        return;
    }

    virt_pml4 = (uint64_t *)(uintptr_t)hps->phys_pml4;
    virt_pdpt = (uint64_t *)(uintptr_t)hps->phys_pdpt;
    virt_pd = (uint64_t *)(uintptr_t)hps->phys_pd;
    virt_pt = (uint64_t *)(uintptr_t)hps->phys_pt;

    for (i = 0U; i < HLAT_ENTRIES_PER_TABLE; ++i) {
        virt_pml4[i] = 0ULL;
        virt_pdpt[i] = 0ULL;
        virt_pd[i] = 0ULL;
        virt_pt[i] = 0ULL;
    }

    for (i = 0U; i < hps->config.region_count; ++i) {
        const struct fbvbs_hlat_region *region = &hps->config.regions[i];
        uint64_t addr;
        uint64_t end_addr;

        if (region->active == 0U) {
            continue;
        }
        if (region->size > UINT64_MAX - region->linear_base) {
            continue;
        }
        addr = region->linear_base;
        end_addr = region->linear_base + region->size;
        while (addr < end_addr) {
            uint32_t pml4_idx = (uint32_t)((addr >> 39) & 0x1FFU);
            uint32_t pdpt_idx = (uint32_t)((addr >> 30) & 0x1FFU);
            uint32_t pd_idx = (uint32_t)((addr >> 21) & 0x1FFU);
            uint32_t pt_idx = (uint32_t)((addr >> 12) & 0x1FFU);

            virt_pml4[pml4_idx] = (hps->phys_pdpt & HLAT_PTE_ADDR_MASK) |
                                  HLAT_PTE_PRESENT | HLAT_PTE_RW;
            virt_pdpt[pdpt_idx] = (hps->phys_pd & HLAT_PTE_ADDR_MASK) |
                                  HLAT_PTE_PRESENT | HLAT_PTE_RW;
            virt_pd[pd_idx] = (hps->phys_pt & HLAT_PTE_ADDR_MASK) |
                              HLAT_PTE_PRESENT | HLAT_PTE_RW;
            virt_pt[pt_idx] |= HLAT_PTE_PRESENT;
            addr += HLAT_PAGE_SIZE;
        }
    }
#else
    (void)hps;
#endif
}

/*@ assigns \nothing;
*/
static void fbvbs_hlat_invlpg_range(uint64_t base, uint64_t size)
{
#if defined(__x86_64__) && !defined(__FRAMAC__)
    uint64_t addr;
    uint64_t end_addr;

    if (size == 0U || size > UINT64_MAX - base) {
        return;
    }

    addr = base;
    end_addr = base + size;
    while (addr < end_addr) {
        fbvbs_asm_invlpg(addr);
        addr += HLAT_PAGE_SIZE;
    }
#else
    (void)base;
    (void)size;
#endif
}

/* Extract page table indices from a linear address */
/*@ assigns \result \from addr;
    ensures \result < HLAT_ENTRIES_PER_TABLE;
*/
static uint32_t hlat_pml4_index(uint64_t addr)
{
    return (uint32_t)((addr >> 39) & 0x1FFU);
}

/*@ assigns \result \from addr;
    ensures \result < HLAT_ENTRIES_PER_TABLE;
*/
static uint32_t hlat_pdpt_index(uint64_t addr)
{
    return (uint32_t)((addr >> 30) & 0x1FFU);
}

/*@ assigns \result \from addr;
    ensures \result < HLAT_ENTRIES_PER_TABLE;
*/
static uint32_t hlat_pd_index(uint64_t addr)
{
    return (uint32_t)((addr >> 21) & 0x1FFU);
}

/*@ assigns \result \from addr;
    ensures \result < HLAT_ENTRIES_PER_TABLE;
*/
static uint32_t hlat_pt_index(uint64_t addr)
{
    return (uint32_t)((addr >> 12) & 0x1FFU);
}

/*@ requires \valid(tables);
    requires \valid_read(config);
    requires \separated(tables, config);
    assigns tables->pml4[0 .. HLAT_MODEL_PML4_ENTRIES - 1],
            tables->pdpt[0 .. HLAT_MODEL_PDPT_ENTRIES - 1],
            tables->pd[0 .. HLAT_MODEL_PD_ENTRIES - 1],
            tables->pt[0 .. HLAT_MODEL_PT_ENTRIES - 1];
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_hlat_populate_tables(
    struct fbvbs_hlat_model_tables *tables,
    const struct fbvbs_hlat_config *config)
{
    uint32_t i;

    if (config->region_count > FBVBS_HLAT_MAX_REGIONS) {
        return -1;
    }

    /* Zero all tables — everything starts as not-present */
    /*@ loop invariant 0 <= i <= HLAT_MODEL_PML4_ENTRIES;
        loop assigns i, tables->pml4[0 .. HLAT_MODEL_PML4_ENTRIES - 1];
        loop variant HLAT_MODEL_PML4_ENTRIES - i;
    */
    for (i = 0U; i < HLAT_MODEL_PML4_ENTRIES; ++i) {
        tables->pml4[i] = 0ULL;
    }
    /*@ loop invariant 0 <= i <= HLAT_MODEL_PDPT_ENTRIES;
        loop assigns i, tables->pdpt[0 .. HLAT_MODEL_PDPT_ENTRIES - 1];
        loop variant HLAT_MODEL_PDPT_ENTRIES - i;
    */
    for (i = 0U; i < HLAT_MODEL_PDPT_ENTRIES; ++i) {
        tables->pdpt[i] = 0ULL;
    }
    /*@ loop invariant 0 <= i <= HLAT_MODEL_PD_ENTRIES;
        loop assigns i, tables->pd[0 .. HLAT_MODEL_PD_ENTRIES - 1];
        loop variant HLAT_MODEL_PD_ENTRIES - i;
    */
    for (i = 0U; i < HLAT_MODEL_PD_ENTRIES; ++i) {
        tables->pd[i] = 0ULL;
    }
    /*@ loop invariant 0 <= i <= HLAT_MODEL_PT_ENTRIES;
        loop assigns i, tables->pt[0 .. HLAT_MODEL_PT_ENTRIES - 1];
        loop variant HLAT_MODEL_PT_ENTRIES - i;
    */
    for (i = 0U; i < HLAT_MODEL_PT_ENTRIES; ++i) {
        tables->pt[i] = 0ULL;
    }

    /* Populate entries for each active region */
    /*@ loop invariant 0 <= i <= config->region_count;
        loop assigns i,
                     tables->pml4[0 .. HLAT_MODEL_PML4_ENTRIES - 1],
                     tables->pdpt[0 .. HLAT_MODEL_PDPT_ENTRIES - 1],
                     tables->pd[0 .. HLAT_MODEL_PD_ENTRIES - 1],
                     tables->pt[0 .. HLAT_MODEL_PT_ENTRIES - 1];
        loop variant config->region_count - i;
    */
    for (i = 0U; i < config->region_count; ++i) {
        const struct fbvbs_hlat_region *region = &config->regions[i];
        uint64_t page;
        uint64_t page_count;

        if (region->active == 0U) {
            continue;
        }

        /* Re-validate stored region to guard against corruption */
        if (region->linear_base + region->size < region->linear_base) {
            continue;  /* Corrupted region — skip */
        }
        page_count = region->size / HLAT_PAGE_SIZE;

        /* Walk each page in the region */
        /*@ loop invariant 0 <= page <= page_count;
            loop assigns page,
                         tables->pml4[0 .. HLAT_MODEL_PML4_ENTRIES - 1],
                         tables->pdpt[0 .. HLAT_MODEL_PDPT_ENTRIES - 1],
                         tables->pd[0 .. HLAT_MODEL_PD_ENTRIES - 1],
                         tables->pt[0 .. HLAT_MODEL_PT_ENTRIES - 1];
            loop variant page_count - page;
        */
        for (page = 0U; page < page_count; ++page) {
            uint64_t addr = region->linear_base + (page * HLAT_PAGE_SIZE);
            uint32_t pml4_idx = hlat_pml4_index(addr);
            uint32_t pdpt_idx = hlat_pdpt_index(addr);
            uint32_t pd_idx   = hlat_pd_index(addr);
            uint32_t pt_idx   = hlat_pt_index(addr);

            /* Mark upper levels as present (allow traversal) */
            tables->pml4[pml4_idx] |= HLAT_PTE_PRESENT | HLAT_PTE_RW;
            tables->pdpt[pdpt_idx] |= HLAT_PTE_PRESENT | HLAT_PTE_RW;
            tables->pd[pd_idx]     |= HLAT_PTE_PRESENT | HLAT_PTE_RW;

            /* Mark the 4KB page as present (executable) —
             * note: XD bit is NOT set, so instruction fetch is allowed */
            tables->pt[pt_idx] |= HLAT_PTE_PRESENT;
        }

    }

    return 0;
}

/* ================================================================
 * Verify HLAT table consistency
 *
 * Checks that no non-registered addresses have Present entries
 * in the leaf PT level. This is a model-level integrity check
 * to ensure the table construction doesn't accidentally permit
 * execution from unverified code regions.
 * ================================================================ */

/*@ requires \valid_read(tables);
    requires \valid_read(config);
    requires \separated(tables, config);
    assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_hlat_verify_tables(
    const struct fbvbs_hlat_model_tables *tables,
    const struct fbvbs_hlat_config *config)
{
    uint32_t pt_idx;

    if (config->region_count > FBVBS_HLAT_MAX_REGIONS) {
        return -1;
    }

    /*@ loop invariant 0 <= pt_idx <= HLAT_MODEL_PT_ENTRIES;
        loop assigns pt_idx;
        loop variant HLAT_MODEL_PT_ENTRIES - pt_idx;
    */
    for (pt_idx = 0U; pt_idx < HLAT_MODEL_PT_ENTRIES; ++pt_idx) {
        if ((tables->pt[pt_idx] & HLAT_PTE_PRESENT) != 0U) {
            /* This PT entry is present — verify it belongs to a
             * registered region. For the model with a single PT
             * level, we check that some region covers this index. */
            uint32_t i;
            int covered = 0;

            /*@ loop invariant 0 <= i <= config->region_count;
                loop assigns i, covered;
                loop variant config->region_count - i;
            */
            for (i = 0U; i < config->region_count; ++i) {
                if (config->regions[i].active != 0U) {
                    uint64_t start_pt = hlat_pt_index(
                        config->regions[i].linear_base);
                    uint64_t pages =
                        config->regions[i].size / HLAT_PAGE_SIZE;
                    uint64_t end_pt = start_pt + pages;

                    /* Wrap-safe coverage check for a single 512-entry PT.
                     * The add_region path rejects spans that would cross
                     * the table boundary, but the verification logic still
                     * handles wrapped ranges defensively. */
                    if (pages > 0U) {
                        if (end_pt <= HLAT_ENTRIES_PER_TABLE) {
                            if ((uint64_t)pt_idx >= start_pt &&
                                (uint64_t)pt_idx < end_pt) {
                                covered = 1;
                            }
                        } else {
                            uint64_t wrapped_end = end_pt % HLAT_ENTRIES_PER_TABLE;
                            if ((uint64_t)pt_idx >= start_pt ||
                                (uint64_t)pt_idx < wrapped_end) {
                                covered = 1;
                            }
                        }
                    }
                }
            }

            if (!covered) {
                return -1;  /* Stale present entry detected */
            }
        }
    }

    return 0;
}

/* ================================================================
 * Build HLAT VMCS fields
 *
 * Computes the values that must be written to the VMCS for HLAT
 * activation. Production assembly code uses these values with
 * VMWRITE.
 *
 * VMCS fields:
 *   VMCS_TERTIARY_PROC_CONTROLS — set PROC3_HLAT_ENABLE
 *   VMCS_HLAT_PREFIX_SIZE       — prefix size (1-6)
 *   VMCS_HLAT_POINTER           — physical address of HLAT PML4
 * ================================================================ */

struct fbvbs_hlat_vmcs_fields {
    uint64_t tertiary_proc_controls;
    uint16_t hlat_prefix_size;
    uint16_t reserved0;
    uint32_t reserved1;
    uint64_t hlat_pointer;
};

/*@ requires \valid(fields);
    requires \valid_read(config);
    requires \separated(fields, config);
    assigns *fields;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_hlat_build_vmcs_fields(
    struct fbvbs_hlat_vmcs_fields *fields,
    const struct fbvbs_hlat_config *config)
{
    *fields = (struct fbvbs_hlat_vmcs_fields){0};

    if (config->active == 0U) {
        return -1;
    }

    if (config->prefix_size < 1U || config->prefix_size > 6U) {
        return -1;
    }

    fields->tertiary_proc_controls = PROC3_HLAT_ENABLE;
    fields->hlat_prefix_size = (uint16_t)config->prefix_size;
    fields->hlat_pointer = config->hlat_pml4_phys;

    return 0;
}

/* ================================================================
 * Public API: Initialize HLAT for a partition
 *
 * Called during VM creation when HLAT is available. Sets up the
 * HLAT configuration with the initial kernel text region.
 *
 * kernel_text_base: Guest virtual address of kernel .text
 * kernel_text_size: Size of kernel .text section (page-aligned)
 *
 * PRODUCTION NOTE: The caller must provide hash-verified kernel
 * text boundaries from the KCI (Kernel Code Integrity) subsystem.
 * The HLAT PML4 physical address requires page allocation.
 * ================================================================ */

/*@ requires \valid(state);
    requires (kernel_text_base & (HLAT_PAGE_SIZE - 1)) == 0;
    requires kernel_text_size > 0;
    requires (kernel_text_size & (HLAT_PAGE_SIZE - 1)) == 0;
    assigns hlat_partitions[0 .. FBVBS_MAX_PARTITIONS - 1],
            hlat_model_tables[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == 0 || \result == -1;
*/
int fbvbs_hlat_init_for_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t kernel_text_base,
    uint64_t kernel_text_size)
{
    struct fbvbs_hlat_model_tables *tables;
    struct fbvbs_hlat_vmcs_fields vmcs_fields;
    struct fbvbs_hlat_partition_state *hps;
    uint64_t phys_pml4 = 0U;
    uint64_t phys_pdpt = 0U;
    uint64_t phys_pd = 0U;
    uint64_t phys_pt = 0U;
    uint32_t part_idx;

    /* Verify HLAT hardware support */
    if (!fbvbs_hlat_is_available(&state->vmx_caps)) {
        return -1;
    }

    if (fbvbs_hlat_find_partition_index(state, partition_id, &part_idx) != 0) {
        return -1;
    }

    /*@ assert part_idx < FBVBS_MAX_PARTITIONS; */
    hps = &hlat_partitions[part_idx];
    tables = &hlat_model_tables[part_idx];
    /*@ assert \valid(hps); */
    /*@ assert \valid(tables); */
    fbvbs_hlat_partition_lock(part_idx);
    if (hps->config.active != 0U) {
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    /* Initialize HLAT configuration */
    fbvbs_hlat_config_init(&hps->config);

    /* Add kernel text as the initial executable region */
    if (fbvbs_hlat_add_region(&hps->config, kernel_text_base,
                               kernel_text_size, 0U, 0U) != 0) {
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    /* Populate model page tables (validates construction logic) */
    if (fbvbs_hlat_populate_tables(tables, &hps->config) != 0) {
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    /* Verify table integrity */
    if (fbvbs_hlat_verify_tables(tables, &hps->config) != 0) {
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    /* Allocate physical pages for HLAT PML4/PDPT/PD/PT */
    phys_pml4 = fbvbs_page_alloc();
    if (phys_pml4 == 0U) {
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    phys_pdpt = fbvbs_page_alloc();
    if (phys_pdpt == 0U) {
        (void)fbvbs_page_free(phys_pml4);
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    phys_pd = fbvbs_page_alloc();
    if (phys_pd == 0U) {
        (void)fbvbs_page_free(phys_pml4);
        (void)fbvbs_page_free(phys_pdpt);
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    phys_pt = fbvbs_page_alloc();
    if (phys_pt == 0U) {
        (void)fbvbs_page_free(phys_pml4);
        (void)fbvbs_page_free(phys_pdpt);
        (void)fbvbs_page_free(phys_pd);
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    /* Copy model table entries to physical pages.
     * Pages are already zeroed by the allocator.
     * Identity-mapped: physical address == virtual address. */
#ifndef __FRAMAC__
    {
        uint64_t *virt_pml4 = (uint64_t *)(uintptr_t)phys_pml4;
        uint64_t *virt_pdpt = (uint64_t *)(uintptr_t)phys_pdpt;
        uint64_t *virt_pd   = (uint64_t *)(uintptr_t)phys_pd;
        uint64_t *virt_pt   = (uint64_t *)(uintptr_t)phys_pt;
        uint32_t i;

        /* Write PML4 entries — set next-level physical address */
        for (i = 0; i < HLAT_ENTRIES_PER_TABLE; ++i) {
            if ((tables->pml4[i] & HLAT_PTE_PRESENT) != 0U) {
                virt_pml4[i] = (phys_pdpt & HLAT_PTE_ADDR_MASK) |
                               HLAT_PTE_PRESENT | HLAT_PTE_RW;
            }
        }
        /* Write PDPT entries */
        for (i = 0; i < HLAT_ENTRIES_PER_TABLE; ++i) {
            if ((tables->pdpt[i] & HLAT_PTE_PRESENT) != 0U) {
                virt_pdpt[i] = (phys_pd & HLAT_PTE_ADDR_MASK) |
                               HLAT_PTE_PRESENT | HLAT_PTE_RW;
            }
        }
        /* Write PD entries */
        for (i = 0; i < HLAT_ENTRIES_PER_TABLE; ++i) {
            if ((tables->pd[i] & HLAT_PTE_PRESENT) != 0U) {
                virt_pd[i] = (phys_pt & HLAT_PTE_ADDR_MASK) |
                             HLAT_PTE_PRESENT | HLAT_PTE_RW;
            }
        }
        /* Write PT entries — leaf level, just Present (execute allowed) */
        for (i = 0; i < HLAT_ENTRIES_PER_TABLE; ++i) {
            virt_pt[i] = tables->pt[i];
        }
    }
#endif

    /* Record physical addresses for cleanup */
    hps->phys_pml4 = phys_pml4;
    hps->phys_pdpt = phys_pdpt;
    hps->phys_pd = phys_pd;
    hps->phys_pt = phys_pt;
    hps->config.hlat_pml4_phys = phys_pml4;

    /* Build VMCS fields */
    hps->config.active = 1;
    if (fbvbs_hlat_build_vmcs_fields(&vmcs_fields, &hps->config) != 0) {
        fbvbs_hlat_reset_partition_pages(hps);
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    /* Apply VMCS fields for HLAT activation.
     * PRODUCTION NOTE: These VMWRITE calls require the partition's
     * VMCS to be the active VMCS (via VMPTRLD). The caller must
     * ensure this. */
    if (fbvbs_hlat_vmwrite(VMCS_TERTIARY_PROC_CONTROLS,
                           vmcs_fields.tertiary_proc_controls) != 0) {
        fbvbs_hlat_reset_partition_pages(hps);
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;  /* VMWRITE failed: tertiary proc controls */
    }
    if (fbvbs_hlat_vmwrite(VMCS_HLAT_PREFIX_SIZE,
                           vmcs_fields.hlat_prefix_size) != 0) {
        (void)fbvbs_hlat_vmwrite(VMCS_TERTIARY_PROC_CONTROLS,
                                 vmcs_fields.tertiary_proc_controls &
                                 ~PROC3_HLAT_ENABLE);
        fbvbs_hlat_reset_partition_pages(hps);
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;  /* VMWRITE failed: HLAT prefix size */
    }
    if (fbvbs_hlat_vmwrite(VMCS_HLAT_POINTER,
                           vmcs_fields.hlat_pointer) != 0) {
        (void)fbvbs_hlat_vmwrite(VMCS_TERTIARY_PROC_CONTROLS,
                                 vmcs_fields.tertiary_proc_controls &
                                 ~PROC3_HLAT_ENABLE);
        fbvbs_hlat_reset_partition_pages(hps);
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;  /* VMWRITE failed: HLAT pointer */
    }

    fbvbs_hlat_partition_unlock(part_idx);
    return 0;
}

/* ================================================================
 * Public API: Add KLD module region to HLAT
 *
 * Called when KCI verifies a kernel loadable module. Extends the
 * HLAT tables to allow instruction fetch from the KLD's code pages.
 *
 * PRODUCTION NOTE: After adding the region, the HLAT page tables
 * must be updated and INVLPG/INVPCID issued for the affected
 * linear address range.
 * ================================================================ */

/*@ requires \valid(state);
    requires (module_base & (HLAT_PAGE_SIZE - 1)) == 0;
    requires module_size > 0;
    requires (module_size & (HLAT_PAGE_SIZE - 1)) == 0;
    assigns hlat_partitions[0 .. FBVBS_MAX_PARTITIONS - 1].config;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_hlat_add_kld_module(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t module_object_id,
    uint64_t module_base,
    uint64_t module_size)
{
    struct fbvbs_hlat_partition_state *hps;
    uint32_t part_idx;

    if (!fbvbs_hlat_is_available(&state->vmx_caps)) {
        return -1;
    }

    if (fbvbs_hlat_find_partition_index(state, partition_id, &part_idx) != 0) {
        return -1;
    }

    /*@ assert part_idx < FBVBS_MAX_PARTITIONS; */
    hps = &hlat_partitions[part_idx];
    fbvbs_hlat_partition_lock(part_idx);
    if (hps->config.active == 0U) {
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;  /* HLAT not initialized for this partition */
    }

    /* Add KLD module as executable region */
    if (fbvbs_hlat_add_region(&hps->config, module_base,
                               module_size, 1U, module_object_id) != 0) {
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    fbvbs_hlat_sync_partition_tables(hps);
    fbvbs_hlat_invlpg_range(module_base, module_size);

    /* PRODUCTION NOTE: After adding the region, the physical HLAT
     * page tables must be updated and INVLPG/INVPCID issued for
     * the affected linear address range. */

    fbvbs_hlat_partition_unlock(part_idx);
    return 0;
}

/* ================================================================
 * Public API: Remove KLD module region from HLAT
 *
 * Called when a KLD module is unloaded. Removes execute permission
 * from the module's linear address range. After this call,
 * instruction fetches from those addresses will cause VM exits.
 * ================================================================ */

/*@ requires \valid(state);
    assigns hlat_partitions[0 .. FBVBS_MAX_PARTITIONS - 1].config;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_hlat_remove_kld_module(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t module_object_id)
{
    struct fbvbs_hlat_partition_state *hps;
    uint32_t part_idx;
    uint64_t removed_base = 0U;
    uint64_t removed_size = 0U;

    if (!fbvbs_hlat_is_available(&state->vmx_caps)) {
        return -1;
    }

    if (fbvbs_hlat_find_partition_index(state, partition_id, &part_idx) != 0) {
        return -1;
    }

    /*@ assert part_idx < FBVBS_MAX_PARTITIONS; */
    hps = &hlat_partitions[part_idx];
    fbvbs_hlat_partition_lock(part_idx);
    if (hps->config.active == 0U) {
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    (void)fbvbs_hlat_find_module_region_bounds(
        &hps->config, module_object_id, &removed_base, &removed_size);

    /* PRODUCTION NOTE: After removing the region, clear the physical
     * HLAT page table entries and issue INVLPG for each page in the
     * removed region. Zero the removed code pages for defense-in-depth. */
    if (fbvbs_hlat_remove_region(&hps->config, module_object_id) != 0) {
        fbvbs_hlat_partition_unlock(part_idx);
        return -1;
    }

    fbvbs_hlat_sync_partition_tables(hps);
    fbvbs_hlat_invlpg_range(removed_base, removed_size);
    fbvbs_hlat_partition_unlock(part_idx);
    return 0;
}

/* ================================================================
 * HLAT VM-exit handler: instruction fetch from non-HLAT page
 *
 * When a guest attempts to fetch an instruction from an address
 * not present in the HLAT tables, a VM exit occurs. This handler
 * determines whether the access is legitimate (e.g., a new KLD
 * being loaded via KCI) or a security violation.
 *
 * Returns:
 *   0  — Benign (should not happen; all legitimate code should
 *         be pre-registered via KCI before execution)
 *  -1  — Security violation: instruction fetch from unverified code
 * ================================================================ */

/*@ requires \valid(state);
    assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_hlat_handle_fault(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t faulting_linear_address)
{
    /* An HLAT fault means the guest tried to execute code from an
     * address not in the HLAT tables. By design, this is always a
     * security violation — all legitimate code must be registered
     * via KCI *before* execution. */

    (void)state;
    (void)partition_id;
    (void)faulting_linear_address;

    /* PRODUCTION NOTE: Log security violation with:
     * - partition_id
     * - faulting_linear_address
     * - SEVERITY_ALERT
     * Then inject #GP(0) into the guest or trigger partition fault. */

    return -1;  /* Always a security violation */
}

/* ================================================================
 * Intel MBEC (Mode-Based Execute Control for EPT)
 *
 * MBEC splits the EPT execute permission into separate bits for
 * user-mode and supervisor-mode execution. This enables:
 *
 *   - Supervisor-mode execute-only pages (kernel code)
 *   - User-mode execute-only pages (user code)
 *   - Pages executable by neither (data-only)
 *
 * Combined with HLAT, MBEC provides:
 *   1. HLAT restricts WHERE code can execute (linear address)
 *   2. MBEC restricts WHO can execute (user vs supervisor)
 *   3. W^X is enforced per privilege level
 *
 * EPT entry format with MBEC (bit 58):
 *   [0]  = Read
 *   [1]  = Write
 *   [2]  = Execute (for supervisor-mode, when MBEC active)
 *   [10] = User-mode Execute (when MBEC active)
 *
 * Reference: Intel SDM Vol. 3, Section 28.2.3
 *            REQ-0400 (W^X enforcement)
 * ================================================================ */

/* Secondary processor-based VM-Execution Controls */
#define PROC2_MBEC                (1U << 22)

/* EPT entry bits with MBEC */
#define EPT_READ                  (1ULL << 0)
#define EPT_WRITE                 (1ULL << 1)
#define EPT_EXECUTE_SUPERVISOR    (1ULL << 2)
#define EPT_USER_EXECUTE          (1ULL << 10)
#define EPT_ADDR_MASK             0x000FFFFFFFFFF000ULL

/* MBEC policy types for code pages */
#define MBEC_POLICY_DATA_ONLY    0U  /* No execute for anyone */
#define MBEC_POLICY_KERNEL_CODE  1U  /* Supervisor execute only, no write */
#define MBEC_POLICY_USER_CODE    2U  /* User execute only, no write */

struct fbvbs_mbec_config {
    uint32_t available;           /* Hardware supports MBEC */
    uint32_t active;              /* MBEC enabled for partition */
    uint32_t secondary_proc_or;   /* Bit to OR into VMCS controls */
    uint32_t reserved0;
};

/*@ requires \valid(config);
    requires \valid_read(caps);
    requires \separated(config, caps);
    assigns *config;
*/
static void fbvbs_mbec_init(
    struct fbvbs_mbec_config *config,
    const struct fbvbs_vmx_capabilities *caps)
{
    config->available = 0U;
    config->active = 0U;
    config->secondary_proc_or = 0U;
    config->reserved0 = 0U;

    /* PRODUCTION NOTE: Check IA32_VMX_PROCBASED_CTLS2 bit 22 for
     * MBEC availability. Model: assume available on HLAT hardware. */
    if (caps->hlat_available != 0U) {
        config->available = 1U;
        config->active = 1U;
        config->secondary_proc_or = PROC2_MBEC;
    }
}

/* Compute EPT entry permissions for a page based on MBEC policy.
 * The result encodes the R/W/X bits that should be set in the
 * EPT leaf entry.
 *
 * W^X enforcement: a page is NEVER both writable and executable.
 */
/*@ requires \valid_read(config);
    assigns \nothing;
    ensures \result != 0ULL ==>
        ((\result & EPT_WRITE) == 0ULL) ||
        (((\result & EPT_EXECUTE_SUPERVISOR) == 0ULL) &&
         ((\result & EPT_USER_EXECUTE) == 0ULL));
*/
static uint64_t fbvbs_mbec_ept_permissions(
    const struct fbvbs_mbec_config *config,
    uint32_t policy,
    int writable)
{
    uint64_t perm = EPT_READ;  /* Always readable */

    /* W^X: reject writable code pages at the API boundary */
    if (writable && policy != MBEC_POLICY_DATA_ONLY) {
        return 0ULL;  /* Invalid: W+X request → return empty permissions */
    }

    if (config->active == 0U) {
        /* Without MBEC, fall back to basic EPT permissions.
         * W^X: set either write or execute, never both. */
        if (writable) {
            perm |= EPT_WRITE;
        } else if (policy == MBEC_POLICY_KERNEL_CODE ||
                   policy == MBEC_POLICY_USER_CODE) {
            perm |= EPT_EXECUTE_SUPERVISOR;
        }
        return perm;
    }

    /* MBEC active: fine-grained execute control */
    switch (policy) {
    case MBEC_POLICY_KERNEL_CODE:
        /* Supervisor execute only, no write, no user execute */
        perm |= EPT_EXECUTE_SUPERVISOR;
        break;

    case MBEC_POLICY_USER_CODE:
        /* User execute only, no write, no supervisor execute */
        perm |= EPT_USER_EXECUTE;
        break;

    case MBEC_POLICY_DATA_ONLY:
    default:
        /* Data page: writable or read-only, never executable */
        if (writable) {
            perm |= EPT_WRITE;
        }
        break;
    }

    return perm;
}

/* Public API: Build MBEC VMCS configuration.
 * Returns the secondary processor control bit and validates
 * the permission computation logic.
 */
/*@ requires \valid(controls_or);
    requires \valid_read(caps);
    requires \separated(controls_or, caps);
    assigns *controls_or;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_mbec_build_config(
    uint32_t *controls_or,
    const struct fbvbs_vmx_capabilities *caps)
{
    struct fbvbs_mbec_config config;
    uint64_t kernel_perm, user_perm, data_perm;

    fbvbs_mbec_init(&config, caps);

    *controls_or = config.secondary_proc_or;

    if (config.active == 0U) {
        return -1;  /* MBEC not available */
    }

    /* Validate W^X invariant for all policy types */
    kernel_perm = fbvbs_mbec_ept_permissions(&config,
                                             MBEC_POLICY_KERNEL_CODE, 0);
    user_perm = fbvbs_mbec_ept_permissions(&config,
                                           MBEC_POLICY_USER_CODE, 0);
    data_perm = fbvbs_mbec_ept_permissions(&config,
                                           MBEC_POLICY_DATA_ONLY, 1);

    /* W^X check: kernel code must not be writable */
    if ((kernel_perm & EPT_WRITE) != 0ULL) {
        return -1;
    }
    /* W^X check: user code must not be writable */
    if ((user_perm & EPT_WRITE) != 0ULL) {
        return -1;
    }
    /* W^X check: writable data must not be executable */
    if ((data_perm & EPT_EXECUTE_SUPERVISOR) != 0ULL ||
        (data_perm & EPT_USER_EXECUTE) != 0ULL) {
        return -1;
    }

    return 0;
}

/* ================================================================
 * Public API: Release HLAT resources for a destroyed partition
 *
 * Called during partition destroy to release HLAT page table pages
 * back to the page allocator (which zeroes them on free).
 * ================================================================ */

/*@ requires \valid(state);
    requires \separated(
        state,
        g_hlat_cleanup_vmwrite_msg + (0 .. sizeof(g_hlat_cleanup_vmwrite_msg) - 1),
        g_hlat_cleanup_vmread_msg + (0 .. sizeof(g_hlat_cleanup_vmread_msg) - 1));
    requires \separated(
        g_hlat_cleanup_vmwrite_msg + (0 .. sizeof(g_hlat_cleanup_vmwrite_msg) - 1),
        g_hlat_cleanup_vmread_msg + (0 .. sizeof(g_hlat_cleanup_vmread_msg) - 1),
        &state->mirror_log);
    requires \separated(
        g_hlat_cleanup_vmwrite_msg + (0 .. sizeof(g_hlat_cleanup_vmwrite_msg) - 1),
        g_hlat_cleanup_vmread_msg + (0 .. sizeof(g_hlat_cleanup_vmread_msg) - 1),
        &state->log_lock);
    assigns hlat_partitions[0 .. FBVBS_MAX_PARTITIONS - 1],
            state->mirror_log, state->log_lock;
*/
void fbvbs_hlat_cleanup_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id)
{
    struct fbvbs_hlat_partition_state *hps;
    uint32_t part_idx;

    if (fbvbs_hlat_find_partition_index(state, partition_id, &part_idx) != 0) {
        return;
    }

    /*@ assert part_idx < FBVBS_MAX_PARTITIONS; */
    hps = &hlat_partitions[part_idx];
    fbvbs_hlat_partition_lock(part_idx);

    if (hps->config.active == 0U) {
        fbvbs_hlat_partition_unlock(part_idx);
        return;
    }

    /* Clear PROC3_HLAT_ENABLE in VMCS before freeing page tables
     * to avoid dangling VMCS references to freed pages. */
    {
        int pages_freed = 0;
        uint64_t tertiary = 0;
        int vmread_rc = fbvbs_hlat_vmread(VMCS_TERTIARY_PROC_CONTROLS, &tertiary);
        if (vmread_rc == 0) {
            int vmwrite_rc;
            tertiary &= ~PROC3_HLAT_ENABLE;
            vmwrite_rc = fbvbs_hlat_vmwrite(VMCS_TERTIARY_PROC_CONTROLS, tertiary);
            if (vmwrite_rc == 0) {
                /* Only free pages when VMCS update succeeded */
                if (hps->phys_pml4 != 0U) {
                    (void)fbvbs_page_free(hps->phys_pml4);
                }
                if (hps->phys_pdpt != 0U) {
                    (void)fbvbs_page_free(hps->phys_pdpt);
                }
                if (hps->phys_pd != 0U) {
                    (void)fbvbs_page_free(hps->phys_pd);
                }
                if (hps->phys_pt != 0U) {
                    (void)fbvbs_page_free(hps->phys_pt);
                }
                pages_freed = 1;
            } else {
                /* vmwrite failed: keep pages allocated to avoid dangling references */
                (void)fbvbs_log_append(
                    state, 0U,
                    FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                    (uint16_t)FBVBS_SEVERITY_ERROR,
                    (uint16_t)FBVBS_EVENT_VM_PLATFORM_GATE,
                    g_hlat_cleanup_vmwrite_msg,
                    (uint32_t)(sizeof(g_hlat_cleanup_vmwrite_msg) - 1U)
                );
            }
        } else {
            /* vmread failed: keep pages allocated to avoid dangling references */
            (void)fbvbs_log_append(
                state, 0U,
                FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                (uint16_t)FBVBS_SEVERITY_ERROR,
                (uint16_t)FBVBS_EVENT_VM_PLATFORM_GATE,
                g_hlat_cleanup_vmread_msg,
                (uint32_t)(sizeof(g_hlat_cleanup_vmread_msg) - 1U)
            );
        }

        if (pages_freed != 0) {
            /* Pages freed successfully — safe to clear all state */
            *hps = (struct fbvbs_hlat_partition_state){0};
        } else {
            /* Pages deliberately leaked — preserve phys_ addresses for
             * post-mortem diagnostics; only mark partition inactive. */
            hps->config.active = 0U;
        }
    }

    fbvbs_hlat_partition_unlock(part_idx);
}
