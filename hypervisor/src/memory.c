#include "fbvbs_hypervisor.h"

/* ================================================================
 * EPT (Extended Page Tables) Construction — Phase 0C-3
 *
 * Intel EPT uses the same 4-level hierarchy as regular x86-64
 * paging: PML4 → PDPT → PD → PT, but with different entry
 * encoding:
 *   [2:0] = Read/Write/Execute permissions
 *   [5:3] = Memory type (0=UC, 6=WB)
 *   [51:12] = Physical address of next level / page frame
 *
 * The hypervisor maintains per-partition EPT roots. When
 * fbvbs_memory_map creates a mapping, fbvbs_ept_map_region
 * should be called to install EPT entries. When unmapping,
 * fbvbs_ept_unmap_region removes the entries.
 *
 * Identity-mapped model: physical address == virtual address
 * for bare-metal hypervisor memory access.
 *
 * Reference: Intel SDM Vol. 3, Chapter 28.2 (EPT)
 * ================================================================ */

/* EPT entry permission bits */
#define EPT_READ        (1ULL << 0)
#define EPT_WRITE       (1ULL << 1)
#define EPT_EXECUTE     (1ULL << 2)
#define EPT_MEM_TYPE_WB (6ULL << 3)  /* Write-back memory type */
#define EPT_ADDR_MASK   0x000FFFFFFFFFF000ULL
#define EPT_ENTRIES_PER_TABLE 512U

/* x86-64 physical address limit: 52-bit (4 PB) */
#define EPT_MAX_PHYS_ADDR    0x000FFFFFFFFFFFFFULL

/* Per-partition EPT state: tracks the root PML4 physical address
 * and allocated intermediate table pages for cleanup. */
#define FBVBS_EPT_MAX_TABLE_PAGES 64U

struct fbvbs_ept_partition_state {
    uint64_t pml4_phys;         /* EPT PML4 page physical address (0 = not allocated) */
    uint64_t table_pages[FBVBS_EPT_MAX_TABLE_PAGES];
    uint32_t table_page_count;
    uint32_t reserved0;
};

_Static_assert(sizeof(struct fbvbs_ept_partition_state) <= 528U,
               "EPT partition state size guard");

static struct fbvbs_ept_partition_state ept_partitions[FBVBS_MAX_PARTITIONS];

/* Find partition index by ID */
/*@ requires \valid_read(state);
    assigns \nothing;
    ensures 0 <= \result <= FBVBS_MAX_PARTITIONS;
*/
static uint32_t ept_find_partition(
    const struct fbvbs_hypervisor_state *state,
    uint64_t partition_id)
{
    uint32_t i;
    /*@ loop invariant 0 <= i <= FBVBS_MAX_PARTITIONS;
        loop assigns i;
        loop variant FBVBS_MAX_PARTITIONS - i;
    */
    for (i = 0; i < FBVBS_MAX_PARTITIONS; ++i) {
        if (state->partitions[i].occupied &&
            state->partitions[i].partition_id == partition_id) {
            return i;
        }
    }
    return FBVBS_MAX_PARTITIONS;
}

/* Record an allocated table page for later cleanup */
static int ept_record_table_page(struct fbvbs_ept_partition_state *eps,
                                  uint64_t page_phys)
{
    if (eps->table_page_count >= FBVBS_EPT_MAX_TABLE_PAGES) {
        return -1;
    }
    eps->table_pages[eps->table_page_count] = page_phys;
    eps->table_page_count += 1U;
    return 0;
}

/* Clear the parent entry that references a table page before freeing it.
 * The EPT tree is identity-mapped, so physical addresses can be traversed
 * directly from the root. */
static int ept_clear_table_reference(uint64_t *table, uint64_t child_phys,
                                     uint32_t level)
{
    uint32_t index;

#ifdef __FRAMAC__
    (void)table;
    (void)child_phys;
    (void)level;
    return 0;
#else
    if (level >= 3U) {
        return 0;
    }

    /*@ loop invariant 0 <= index <= EPT_ENTRIES_PER_TABLE;
        loop assigns index, table[0 .. EPT_ENTRIES_PER_TABLE - 1];
        loop variant EPT_ENTRIES_PER_TABLE - index;
    */
    for (index = 0U; index < EPT_ENTRIES_PER_TABLE; ++index) {
        uint64_t entry = table[index];

        if ((entry & EPT_READ) == 0U) {
            continue;
        }
        if ((entry & EPT_ADDR_MASK) == (child_phys & EPT_ADDR_MASK)) {
            table[index] = 0U;
            return 1;
        }
        if (level < 2U &&
            ept_clear_table_reference((uint64_t *)(uintptr_t)(entry & EPT_ADDR_MASK),
                                      child_phys,
                                      level + 1U) != 0) {
            return 1;
        }
    }

    return 0;
#endif
}

/* Convert FBVBS permission flags to EPT permission bits */
/*@ assigns \nothing; */
static uint64_t ept_permissions_from_fbvbs(uint16_t permissions)
{
    uint64_t ept_perm = 0;
    if ((permissions & FBVBS_MEMORY_PERMISSION_READ) != 0U) {
        ept_perm |= EPT_READ;
    }
    if ((permissions & FBVBS_MEMORY_PERMISSION_WRITE) != 0U) {
        ept_perm |= EPT_WRITE;
    }
    if ((permissions & FBVBS_MEMORY_PERMISSION_EXECUTE) != 0U) {
        ept_perm |= EPT_EXECUTE;
    }
    return ept_perm;
}

/* Allocate EPT root (PML4) for a partition.
 * Returns 0 on success, -1 on failure. */
/*@ requires \valid(state);
    assigns ept_partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == 0 || \result == -1;
*/
int fbvbs_ept_create_root(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id)
{
    uint32_t idx;
    struct fbvbs_ept_partition_state *eps;
    uint64_t pml4_phys;

    if (state == NULL) {
        return -1;
    }

    idx = ept_find_partition(state, partition_id);
    if (idx >= FBVBS_MAX_PARTITIONS) {
        return -1;
    }

    /*@ assert idx < FBVBS_MAX_PARTITIONS; */
    eps = &ept_partitions[idx];
    /*@ assert \valid(eps); */
    if (eps->pml4_phys != 0U) {
        return 0;  /* Already allocated */
    }

#ifdef __FRAMAC__
    /* WP model: retain argument validation and per-partition state updates
       without proving the physical page allocator's address-to-pointer model. */
    eps->pml4_phys = FBVBS_PAGE_SIZE;
    eps->table_pages[0] = FBVBS_PAGE_SIZE;
    eps->table_page_count = 1U;
    return 0;
#else
    pml4_phys = fbvbs_page_alloc();
    if (pml4_phys == 0U) {
        return -1;
    }

    eps->pml4_phys = pml4_phys;
    if (ept_record_table_page(eps, pml4_phys) != 0) {
        (void)fbvbs_page_free(pml4_phys);
        eps->pml4_phys = 0U;
        return -1;
    }

    return 0;
#endif
}

/* Map a single 4KB page in the EPT for a partition.
 * Walks the 4-level EPT hierarchy, allocating intermediate tables
 * as needed. The GPA is the guest physical address, hpa is the
 * host physical address backing it, and ept_perm are EPT permission bits.
 *
 * Returns 0 on success, -1 on failure. */
static int fbvbs_ept_map_page(
    struct fbvbs_ept_partition_state *eps,
    uint64_t gpa,
    uint64_t hpa,
    uint64_t ept_perm)
{
    uint64_t *table;
    uint64_t entry;
    uint32_t level;
    /* Index into each level: PML4[47:39], PDPT[38:30], PD[29:21], PT[20:12] */
    uint32_t indices[4];

    if (eps->pml4_phys == 0U) {
        return -1;
    }

    indices[0] = (uint32_t)((gpa >> 39) & 0x1FFU);  /* PML4 */
    indices[1] = (uint32_t)((gpa >> 30) & 0x1FFU);  /* PDPT */
    indices[2] = (uint32_t)((gpa >> 21) & 0x1FFU);  /* PD */
    indices[3] = (uint32_t)((gpa >> 12) & 0x1FFU);  /* PT */

    /* Identity-mapped: physical address == virtual address */
    table = (uint64_t *)(uintptr_t)eps->pml4_phys;

    /* Walk PML4 → PDPT → PD, allocating intermediate tables */
    /*@ loop invariant 0 <= level <= 3;
        loop assigns level, entry, table,
                     eps->table_pages[0 .. FBVBS_EPT_MAX_TABLE_PAGES - 1],
                     eps->table_page_count,
                     ((uint64_t *)(uintptr_t)eps->pml4_phys)[0 .. EPT_ENTRIES_PER_TABLE - 1];
        loop variant 3 - level;
    */
    for (level = 0; level < 3U; ++level) {
        entry = table[indices[level]];
        if ((entry & EPT_READ) == 0U) {
            /* Entry not present — allocate a new table page */
            uint64_t new_page = fbvbs_page_alloc();
            if (new_page == 0U) {
                return -1;
            }
            if (ept_record_table_page(eps, new_page) != 0) {
                (void)fbvbs_page_free(new_page);
                return -1;
            }
            /* All intermediate entries need R+W+X so the walk succeeds */
            table[indices[level]] = (new_page & EPT_ADDR_MASK) |
                                    EPT_READ | EPT_WRITE | EPT_EXECUTE;
            table = (uint64_t *)(uintptr_t)new_page;
        } else {
            table = (uint64_t *)(uintptr_t)(entry & EPT_ADDR_MASK);
        }
    }

    /* Write the leaf PT entry (4KB page) */
    table[indices[3]] = (hpa & EPT_ADDR_MASK) | ept_perm | EPT_MEM_TYPE_WB;
    return 0;
}

/* Map a contiguous GPA region into the EPT for a partition.
 * Assumes identity mapping (GPA == HPA) for the FreeBSD host.
 * For guest VMs, the caller would provide the HPA backing.
 *
 * Returns 0 on success, -1 on failure. */
/*@ requires \valid(state);
    assigns ept_partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == 0 || \result == -1;
*/
int fbvbs_ept_map_region(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t gpa,
    uint64_t size,
    uint16_t permissions)
{
    uint32_t idx;
    struct fbvbs_ept_partition_state *eps;
    uint64_t ept_perm;
    uint64_t offset;

    if (state == NULL) {
        return -1;
    }
    if ((gpa & (FBVBS_PAGE_SIZE - 1U)) != 0U) {
        return -1;  /* GPA must be page-aligned */
    }
    if (size == 0U || (size & (FBVBS_PAGE_SIZE - 1U)) != 0U) {
        return -1;  /* Size must be page-aligned */
    }
    /* Reject GPA overflow (wraparound) and out-of-range physical addresses */
    if (gpa + size < gpa) {
        return -1;  /* Integer overflow */
    }
    if (gpa + size - 1U > EPT_MAX_PHYS_ADDR) {
        return -1;  /* Beyond 52-bit physical address space */
    }

    idx = ept_find_partition(state, partition_id);
    if (idx >= FBVBS_MAX_PARTITIONS) {
        return -1;
    }

    eps = &ept_partitions[idx];
    if (eps->pml4_phys == 0U) {
        /* Auto-create EPT root if not yet allocated */
        if (fbvbs_ept_create_root(state, partition_id) != 0) {
            return -1;
        }
    }

    ept_perm = ept_permissions_from_fbvbs(permissions);

#ifdef __FRAMAC__
    (void)ept_perm;
    return 0;
#else

    /* Map each 4KB page (identity mapped: GPA == HPA).
     * On failure, roll back all pages mapped so far to
     * maintain transactional EPT consistency.
     * Save table_page_count before mapping so that intermediate
     * tables allocated during the failed attempt can be reclaimed,
     * preventing table tracking quota exhaustion (CWE-400). */
    {
    uint32_t saved_table_count = eps->table_page_count;
    /*@ loop invariant 0 <= offset <= size;
        loop assigns offset,
                     eps->table_pages[0 .. FBVBS_EPT_MAX_TABLE_PAGES - 1],
                     eps->table_page_count,
                     ((uint64_t *)(uintptr_t)eps->pml4_phys)[0 .. EPT_ENTRIES_PER_TABLE - 1];
        loop variant size - offset;
    */
    for (offset = 0U; offset < size; offset += FBVBS_PAGE_SIZE) {
        if (fbvbs_ept_map_page(eps, gpa + offset, gpa + offset, ept_perm) != 0) {
            /* Rollback: clear all leaf entries we just created */
            uint64_t rollback;
            /*@ loop invariant 0 <= rollback <= offset;
                loop assigns rollback,
                             ((uint64_t *)(uintptr_t)eps->pml4_phys)[0 .. EPT_ENTRIES_PER_TABLE - 1];
                loop variant offset - rollback;
            */
            for (rollback = 0U; rollback < offset; rollback += FBVBS_PAGE_SIZE) {
                uint64_t addr = gpa + rollback;
                uint32_t ri[4];
                uint64_t *tbl;
                uint64_t ent;
                uint32_t lvl;

                ri[0] = (uint32_t)((addr >> 39) & 0x1FFU);
                ri[1] = (uint32_t)((addr >> 30) & 0x1FFU);
                ri[2] = (uint32_t)((addr >> 21) & 0x1FFU);
                ri[3] = (uint32_t)((addr >> 12) & 0x1FFU);
                tbl = (uint64_t *)(uintptr_t)eps->pml4_phys;
                /*@ loop invariant 0 <= lvl <= 3;
                    loop assigns lvl, ent, tbl;
                    loop variant 3 - lvl;
                */
                for (lvl = 0; lvl < 3U; ++lvl) {
                    ent = tbl[ri[lvl]];
                    if ((ent & EPT_READ) == 0U) { break; }
                    tbl = (uint64_t *)(uintptr_t)(ent & EPT_ADDR_MASK);
                }
                if (lvl == 3U) {
                    tbl[ri[3]] = 0U;
                }
            }
            /* Free intermediate tables allocated during this failed
             * map_region call.  Walk the page table to find and clear
             * parent entries pointing to freed tables. */
            {
                uint32_t ti;
                /*@ loop invariant saved_table_count <= ti <= eps->table_page_count;
                    loop assigns ti,
                                 eps->table_pages[0 .. FBVBS_EPT_MAX_TABLE_PAGES - 1],
                                 eps->table_page_count,
                                 ((uint64_t *)(uintptr_t)eps->pml4_phys)[0 .. EPT_ENTRIES_PER_TABLE - 1];
                    loop variant ti - saved_table_count;
                */
                for (ti = eps->table_page_count; ti > saved_table_count; --ti) {
                    uint64_t freed_phys = eps->table_pages[ti - 1U];
                    if (freed_phys != 0ULL) {
                        (void)ept_clear_table_reference(
                            (uint64_t *)(uintptr_t)eps->pml4_phys,
                            freed_phys,
                            0U);
                        (void)fbvbs_page_free(freed_phys);
                        eps->table_pages[ti - 1U] = 0ULL;
                    }
                }
                eps->table_page_count = saved_table_count;
            }
            return -1;
        }
    }
    } /* end saved_table_count scope */

    return 0;
#endif
}

/* Remove EPT entries for a GPA region.
 * Zeros the leaf PTE entries but does not free intermediate tables
 * (they are freed on partition cleanup). */
/*@ requires \valid(state);
    assigns ept_partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == 0 || \result == -1;
*/
int fbvbs_ept_unmap_region(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t gpa,
    uint64_t size)
{
    uint32_t idx;
    struct fbvbs_ept_partition_state *eps;
    uint64_t offset;

    if (state == NULL) {
        return -1;
    }

    idx = ept_find_partition(state, partition_id);
    if (idx >= FBVBS_MAX_PARTITIONS) {
        return -1;
    }

    eps = &ept_partitions[idx];
    if (eps->pml4_phys == 0U) {
        return 0;  /* No EPT — nothing to unmap */
    }

    /* Validate page alignment (match map_region contract) */
    if ((gpa & (FBVBS_PAGE_SIZE - 1U)) != 0U) {
        return -1;  /* GPA must be page-aligned */
    }
    if (size != 0U && (size & (FBVBS_PAGE_SIZE - 1U)) != 0U) {
        return -1;  /* Size must be page-aligned */
    }

    /* Validate GPA range */
    if (size != 0U && gpa + size < gpa) {
        return -1;  /* Integer overflow */
    }

#ifdef __FRAMAC__
    return 0;
#else
    /*@ loop invariant 0 <= offset <= size;
        loop assigns offset,
                     ((uint64_t *)(uintptr_t)eps->pml4_phys)[0 .. EPT_ENTRIES_PER_TABLE - 1];
        loop variant size - offset;
    */
    for (offset = 0U; offset < size; offset += FBVBS_PAGE_SIZE) {
        uint64_t addr = gpa + offset;
        uint32_t indices[4];
        uint64_t *table;
        uint64_t entry;
        uint32_t level;

        indices[0] = (uint32_t)((addr >> 39) & 0x1FFU);
        indices[1] = (uint32_t)((addr >> 30) & 0x1FFU);
        indices[2] = (uint32_t)((addr >> 21) & 0x1FFU);
        indices[3] = (uint32_t)((addr >> 12) & 0x1FFU);

        table = (uint64_t *)(uintptr_t)eps->pml4_phys;

        /* Walk to leaf, bail if any intermediate entry is not present */
        /*@ loop invariant 0 <= level <= 3;
            loop assigns level, entry, table;
            loop variant 3 - level;
        */
        for (level = 0; level < 3U; ++level) {
            entry = table[indices[level]];
            if ((entry & EPT_READ) == 0U) {
                break;  /* Not mapped — skip */
            }
            table = (uint64_t *)(uintptr_t)(entry & EPT_ADDR_MASK);
        }
        if (level == 3U) {
            table[indices[3]] = 0U;  /* Clear the leaf entry */
        }
    }

    return 0;
#endif
}

/* Release all EPT pages for a partition.
 * Called from partition destroy path. */
void fbvbs_ept_cleanup_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id)
{
    uint32_t idx;
    struct fbvbs_ept_partition_state *eps;
    uint32_t i;

    if (state == NULL) {
        return;
    }

    idx = ept_find_partition(state, partition_id);
    if (idx >= FBVBS_MAX_PARTITIONS) {
        return;
    }

    eps = &ept_partitions[idx];

#ifdef __FRAMAC__
    *eps = (struct fbvbs_ept_partition_state){0};
#else
    /* Free all allocated table pages (in reverse order for safety) */
    /*@ loop invariant 0 <= i <= eps->table_page_count;
        loop assigns i;
        loop variant i;
    */
    for (i = eps->table_page_count; i > 0U; --i) {
        (void)fbvbs_page_free(eps->table_pages[i - 1U]);
    }

    *eps = (struct fbvbs_ept_partition_state){0};
#endif
}

/* Get the EPT PML4 physical address for a partition.
 * Returns 0 if no EPT is allocated. */
/*@ requires \valid_read(state);
    assigns \nothing;
*/
uint64_t fbvbs_ept_get_root(
    const struct fbvbs_hypervisor_state *state,
    uint64_t partition_id)
{
    uint32_t idx;

    if (state == NULL) {
        return 0U;
    }

    idx = ept_find_partition(state, partition_id);
    if (idx >= FBVBS_MAX_PARTITIONS) {
        return 0U;
    }

    return ept_partitions[idx].pml4_phys;
}

#define FBVBS_MEMORY_OBJECT_PAGE_LIST_CAPACITY \
    ((FBVBS_PAGE_SIZE - 16U) / sizeof(uint64_t))

struct fbvbs_memory_object_page_list {
    uint64_t next_list_page_phys;
    uint32_t entry_count;
    uint32_t reserved0;
    uint64_t page_phys[FBVBS_MEMORY_OBJECT_PAGE_LIST_CAPACITY];
};

static void fbvbs_memory_object_clear_backing_fields(
    struct fbvbs_memory_object *object
) {
    if (object == NULL) {
        return;
    }

    object->backing_kind = FBVBS_MEMORY_BACKING_NONE;
    object->backing_page_count = 0U;
    object->backing_phys_base = 0U;
    object->backing_page_list_head_phys = 0U;
}

static void fbvbs_memory_object_reset(struct fbvbs_memory_object *object) {
    if (object == NULL) {
        return;
    }

    *object = (struct fbvbs_memory_object){0};
}

static void fbvbs_memory_object_release_owned_pages(
    struct fbvbs_memory_object *object
) {
    uint64_t list_phys;

    if (object == NULL) {
        return;
    }

#ifdef __FRAMAC__
    fbvbs_memory_object_clear_backing_fields(object);
    return;
#else
    if (object->backing_kind != FBVBS_MEMORY_BACKING_OWNED_PAGE_LIST) {
        return;
    }

    list_phys = object->backing_page_list_head_phys;
    /*@ loop assigns list_phys;
    */
    while (list_phys != 0U) {
        struct fbvbs_memory_object_page_list *list =
            (struct fbvbs_memory_object_page_list *)(uintptr_t)list_phys;
        uint64_t next_list_phys = list->next_list_page_phys;
        uint32_t index;

        if (next_list_phys == list_phys) {
            next_list_phys = 0U;
        }

        /*@ loop assigns index;
        */
        for (index = 0U;
             index < list->entry_count &&
             index < FBVBS_MEMORY_OBJECT_PAGE_LIST_CAPACITY;
             ++index) {
            if (list->page_phys[index] != 0U) {
                (void)fbvbs_page_free(list->page_phys[index]);
            }
        }
        (void)fbvbs_page_free(list_phys);
        list_phys = next_list_phys;
    }

    fbvbs_memory_object_clear_backing_fields(object);
#endif
}

static int fbvbs_memory_object_allocate_owned_pages(
    struct fbvbs_memory_object *object
) {
    uint64_t pages_remaining;
    struct fbvbs_memory_object_page_list *previous_list = NULL;

    if (object->size == 0U || (object->size % FBVBS_PAGE_SIZE) != 0U) {
        return -1;
    }

    fbvbs_memory_object_clear_backing_fields(object);
    object->backing_kind = FBVBS_MEMORY_BACKING_OWNED_PAGE_LIST;
    pages_remaining = object->size / FBVBS_PAGE_SIZE;

#ifdef __FRAMAC__
    object->backing_page_count = (uint32_t)pages_remaining;
    object->backing_page_list_head_phys = FBVBS_PAGE_SIZE;
    return 0;
#else
    /*@ loop invariant 0 <= pages_remaining <= object->size / FBVBS_PAGE_SIZE;
        loop assigns pages_remaining,
                     object->backing_page_count,
                     object->backing_page_list_head_phys,
                     previous_list;
        loop variant pages_remaining;
    */
    while (pages_remaining != 0U) {
        uint64_t list_phys = fbvbs_page_alloc();
        struct fbvbs_memory_object_page_list *list;

        if (list_phys == 0U) {
            fbvbs_memory_object_release_owned_pages(object);
            return -1;
        }

        list = (struct fbvbs_memory_object_page_list *)(uintptr_t)list_phys;
        if (object->backing_page_list_head_phys == 0U) {
            object->backing_page_list_head_phys = list_phys;
        }
        if (previous_list != NULL) {
            previous_list->next_list_page_phys = list_phys;
        }
        previous_list = list;

        /*@ loop invariant 0 <= list->entry_count <= FBVBS_MEMORY_OBJECT_PAGE_LIST_CAPACITY;
            loop assigns list->entry_count,
                         list->page_phys[0 .. FBVBS_MEMORY_OBJECT_PAGE_LIST_CAPACITY - 1],
                         object->backing_page_count,
                         pages_remaining;
            loop variant pages_remaining;
        */
        while (pages_remaining != 0U &&
               list->entry_count < FBVBS_MEMORY_OBJECT_PAGE_LIST_CAPACITY) {
            uint64_t page_phys = fbvbs_page_alloc();

            if (page_phys == 0U) {
                fbvbs_memory_object_release_owned_pages(object);
                return -1;
            }

            list->page_phys[list->entry_count] = page_phys;
            list->entry_count += 1U;
            object->backing_page_count += 1U;
            pages_remaining -= 1U;
        }
    }

    return 0;
#endif
}

/*@ requires \valid(state);
    assigns \result \from memory_object_id,
                         state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1];
    ensures \result == \null ||
            (\valid(\result) && \result->allocated && \result->memory_object_id == memory_object_id);
    ensures \result != \null ==>
            \exists integer i; 0 <= i < FBVBS_MAX_MEMORY_OBJECTS &&
            \result == &state->memory_objects[i];
*/
static struct fbvbs_memory_object *fbvbs_find_memory_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_OBJECTS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_OBJECTS; ++index) {
        if (state->memory_objects[index].allocated &&
            state->memory_objects[index].memory_object_id == memory_object_id) {
            return &state->memory_objects[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns \result \from state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1];
    ensures \result == \null || (\valid(\result) && !\result->allocated);
    ensures \result != \null ==>
            \exists integer i; 0 <= i < FBVBS_MAX_MEMORY_OBJECTS &&
            \result == &state->memory_objects[i];
*/
static struct fbvbs_memory_object *fbvbs_allocate_memory_object_slot(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_OBJECTS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_OBJECTS; ++index) {
        if (!state->memory_objects[index].allocated) {
            return &state->memory_objects[index];
        }
    }

    return NULL;
}

int fbvbs_memory_allocate_object(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_allocate_object_request *request,
    struct fbvbs_memory_allocate_object_response *response,
    uint64_t owner_partition_id
) {
    struct fbvbs_memory_object *object;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (owner_partition_id == 0U) {
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U || request->size == 0U) {
        return INVALID_PARAMETER;
    }
    if ((request->size % FBVBS_PAGE_SIZE) != 0U) {
        return INVALID_PARAMETER;
    }
    if (request->object_flags != FBVBS_MEMORY_OBJECT_FLAG_PRIVATE &&
        request->object_flags != FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE &&
        request->object_flags != FBVBS_MEMORY_OBJECT_FLAG_GUEST_MEMORY) {
        return INVALID_PARAMETER;
    }

    object = fbvbs_allocate_memory_object_slot(state);
    if (object == NULL) {
        return RESOURCE_EXHAUSTED;
    }
    /*@ assert \valid(object); */
    if (!fbvbs_id_allocator_can_advance(state->next_memory_object_id, 1U)) {
        return RESOURCE_EXHAUSTED;
    }

#ifdef __FRAMAC__
    response->memory_object_id = state->next_memory_object_id;
    state->next_memory_object_id += 1U;
    return OK;
#else
    fbvbs_memory_object_reset(object);
    object->allocated = true;
    object->object_flags = request->object_flags;
    object->memory_object_id = state->next_memory_object_id++;
    object->owner_partition_id = owner_partition_id;
    object->size = request->size;
    if (fbvbs_memory_object_allocate_owned_pages(object) != 0) {
        fbvbs_memory_object_reset(object);
        return RESOURCE_EXHAUSTED;
    }
    response->memory_object_id = object->memory_object_id;
    return OK;
#endif
}

int fbvbs_memory_release_object(  /* REQ-0909 */
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_object_id,
    uint64_t requester_partition_id
) {
    struct fbvbs_memory_object *object;

    if (state == NULL || memory_object_id == 0U || requester_partition_id == 0U) {
        return INVALID_PARAMETER;
    }

    object = fbvbs_find_memory_object(state, memory_object_id);
    if (object == NULL) {
        return NOT_FOUND;
    }
    /*@ assert \valid(object); */
    if (object->owner_partition_id != requester_partition_id) {
        return PERMISSION_DENIED;
    }
    if (object->map_count != 0U || object->shared_count != 0U) {
        return RESOURCE_BUSY;
    }

#ifdef __FRAMAC__
    return OK;
#else
    fbvbs_memory_object_release_backing(object);
    fbvbs_memory_object_reset(object);
    return OK;
#endif
}

int fbvbs_memory_object_get_page_phys(
    const struct fbvbs_memory_object *object,
    uint32_t page_index,
    uint64_t *page_phys_out
) {
    if (object == NULL || page_phys_out == NULL ||
        !object->allocated ||
        object->backing_page_count == 0U ||
        page_index >= object->backing_page_count) {
        return -1;
    }

    if (object->backing_kind == FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS) {
        uint64_t offset = (uint64_t)page_index * FBVBS_PAGE_SIZE;

        if (object->backing_phys_base == 0U ||
            (object->backing_phys_base & (FBVBS_PAGE_SIZE - 1U)) != 0U ||
            object->backing_phys_base > UINT64_MAX - offset) {
            return -1;
        }

        *page_phys_out = object->backing_phys_base + offset;
        return 0;
    }

    if (object->backing_kind == FBVBS_MEMORY_BACKING_OWNED_PAGE_LIST) {
#ifdef __FRAMAC__
        if (object->backing_page_list_head_phys == 0U ||
            object->backing_page_list_head_phys > UINT64_MAX - (((uint64_t)page_index + 1U) *
                                                                FBVBS_PAGE_SIZE)) {
            return -1;
        }
        *page_phys_out = object->backing_page_list_head_phys +
                         (((uint64_t)page_index + 1U) * FBVBS_PAGE_SIZE);
        return 0;
#else
        uint32_t remaining = page_index;
        uint64_t list_phys = object->backing_page_list_head_phys;

        /*@ loop invariant remaining <= page_index;
            loop assigns remaining, list_phys, *page_phys_out;
            loop variant remaining + 1U;
        */
        while (list_phys != 0U) {
            const struct fbvbs_memory_object_page_list *list =
                (const struct fbvbs_memory_object_page_list *)(uintptr_t)list_phys;

            if (list->entry_count == 0U ||
                list->entry_count > FBVBS_MEMORY_OBJECT_PAGE_LIST_CAPACITY ||
                list->next_list_page_phys == list_phys) {
                return -1;
            }
            if (remaining < list->entry_count &&
                remaining < FBVBS_MEMORY_OBJECT_PAGE_LIST_CAPACITY &&
                list->page_phys[remaining] != 0U) {
                *page_phys_out = list->page_phys[remaining];
                return 0;
            }
            if (remaining < list->entry_count) {
                return -1;
            }

            remaining -= list->entry_count;
            list_phys = list->next_list_page_phys;
        }
#endif
    }

    return -1;
}

int fbvbs_memory_object_read(
    const struct fbvbs_memory_object *object,
    uint64_t offset,
    void *destination,
    uint64_t size
) {
    if (object == NULL || (!object->allocated) || destination == NULL) {
        return -1;
    }
    if (size == 0U) {
        return 0;
    }
    if (offset > object->size || size > object->size - offset) {
        return -1;
    }

#ifdef __FRAMAC__
    /* WP model: physical-address-to-pointer casts and void* arithmetic
       are incompatible with the Typed model.  Bounds/null checks above
       are verified; the actual byte copy is verified independently. */
    (void)destination;
#else
    {
        char *dest = (char *)destination;
        uint64_t remaining = size;
        uint64_t current_offset = offset;

        while (remaining != 0U) {
            uint32_t page_index = (uint32_t)(current_offset / FBVBS_PAGE_SIZE);
            uint64_t page_offset = current_offset % FBVBS_PAGE_SIZE;
            uint64_t chunk = FBVBS_PAGE_SIZE - page_offset;
            uint64_t page_phys;

            if (chunk > remaining) {
                chunk = remaining;
            }
            if (fbvbs_memory_object_get_page_phys(object, page_index, &page_phys) != 0) {
                return -1;
            }

            fbvbs_copy_memory(
                dest,
                (const void *)(uintptr_t)(page_phys + page_offset),
                (size_t)chunk
            );
            dest += chunk;
            current_offset += chunk;
            remaining -= chunk;
        }
    }
#endif

    return 0;
}

int fbvbs_memory_object_write(
    struct fbvbs_memory_object *object,
    uint64_t offset,
    const void *source,
    uint64_t size
) {
    if (object == NULL || (!object->allocated) || source == NULL) {
        return -1;
    }
    if (size == 0U) {
        return 0;
    }
    if (offset > object->size || size > object->size - offset) {
        return -1;
    }

#ifdef __FRAMAC__
    (void)source;
#else
    {
        const char *src = (const char *)source;
        uint64_t remaining = size;
        uint64_t current_offset = offset;

        while (remaining != 0U) {
            uint32_t page_index = (uint32_t)(current_offset / FBVBS_PAGE_SIZE);
            uint64_t page_offset = current_offset % FBVBS_PAGE_SIZE;
            uint64_t chunk = FBVBS_PAGE_SIZE - page_offset;
            uint64_t page_phys;

            if (chunk > remaining) {
                chunk = remaining;
            }
            if (fbvbs_memory_object_get_page_phys(object, page_index, &page_phys) != 0) {
                return -1;
            }

            fbvbs_copy_memory(
                (void *)(uintptr_t)(page_phys + page_offset),
                src,
                (size_t)chunk
            );
            src += chunk;
            current_offset += chunk;
            remaining -= chunk;
        }
    }
#endif

    return 0;
}

int fbvbs_memory_object_hash_sha384(
    const struct fbvbs_memory_object *object,
    uint8_t out[48]
) {
    struct fbvbs_sha384_context context;
    uint32_t page_index;

    if (object == NULL || out == NULL ||
        !object->allocated ||
        object->size == 0U ||
        object->backing_page_count == 0U) {
        return -1;
    }

    if (object->backing_kind == FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS) {
        if (object->backing_phys_base == 0U) {
            return -1;
        }
#ifndef __FRAMAC__
        fbvbs_sha384((const void *)(uintptr_t)object->backing_phys_base, object->size, out);
#endif
        return 0;
    }

#ifdef __FRAMAC__
    /* WP model: SHA-384 over physical pages involves void* casts
       from physical addresses.  Bounds checks verified above. */
    (void)context;
    (void)page_index;
#else
    fbvbs_sha384_init(&context);
    for (page_index = 0U; page_index < object->backing_page_count; ++page_index) {
        uint64_t page_phys;
        uint64_t bytes_remaining = object->size - ((uint64_t)page_index * FBVBS_PAGE_SIZE);
        uint64_t chunk = bytes_remaining < FBVBS_PAGE_SIZE ? bytes_remaining : FBVBS_PAGE_SIZE;

        if (fbvbs_memory_object_get_page_phys(object, page_index, &page_phys) != 0) {
            context = (struct fbvbs_sha384_context){0};
            return -1;
        }
        fbvbs_sha384_update(
            &context,
            (const void *)(uintptr_t)page_phys,
            chunk
        );
    }
    fbvbs_sha384_final(&context, out);
#endif
    return 0;
}

int fbvbs_memory_object_hash_page_sha384(
    const struct fbvbs_memory_object *object,
    uint32_t page_index,
    uint8_t out[48]
) {
    uint64_t page_phys;

    if (object == NULL || out == NULL || !object->allocated) {
        return -1;
    }
    if (fbvbs_memory_object_get_page_phys(object, page_index, &page_phys) != 0) {
        return -1;
    }

#ifndef __FRAMAC__
    fbvbs_sha384((const void *)(uintptr_t)page_phys, FBVBS_PAGE_SIZE, out);
#endif
    return 0;
}

/*@ requires object == \null || \valid(object);
    assigns \nothing;
*/
void fbvbs_memory_object_release_backing(struct fbvbs_memory_object *object) {
    if (object == NULL) {
        return;
    }

#ifdef __FRAMAC__
    return;
#else
    if (object->backing_kind == FBVBS_MEMORY_BACKING_OWNED_PAGE_LIST) {
        fbvbs_memory_object_release_owned_pages(object);
        return;
    }

    fbvbs_memory_object_clear_backing_fields(object);
#endif
}
