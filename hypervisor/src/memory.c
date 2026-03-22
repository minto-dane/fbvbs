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
static uint32_t ept_find_partition(
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

/* Convert FBVBS permission flags to EPT permission bits */
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

    eps = &ept_partitions[idx];
    if (eps->pml4_phys != 0U) {
        return 0;  /* Already allocated */
    }

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

    /* Map each 4KB page (identity mapped: GPA == HPA).
     * On failure, roll back all pages mapped so far to
     * maintain transactional EPT consistency. */
    for (offset = 0U; offset < size; offset += FBVBS_PAGE_SIZE) {
        if (fbvbs_ept_map_page(eps, gpa + offset, gpa + offset, ept_perm) != 0) {
            /* Rollback: clear all leaf entries we just created */
            uint64_t rollback;
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
                for (lvl = 0; lvl < 3U; ++lvl) {
                    ent = tbl[ri[lvl]];
                    if ((ent & EPT_READ) == 0U) { break; }
                    tbl = (uint64_t *)(uintptr_t)(ent & EPT_ADDR_MASK);
                }
                if (lvl == 3U) {
                    tbl[ri[3]] = 0U;
                }
            }
            return -1;
        }
    }

    return 0;
}

/* Remove EPT entries for a GPA region.
 * Zeros the leaf PTE entries but does not free intermediate tables
 * (they are freed on partition cleanup). */
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

    /* Validate GPA range */
    if (size != 0U && gpa + size < gpa) {
        return -1;  /* Integer overflow */
    }

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

    /* Free all allocated table pages (in reverse order for safety) */
    for (i = eps->table_page_count; i > 0U; --i) {
        (void)fbvbs_page_free(eps->table_pages[i - 1U]);
    }

    *eps = (struct fbvbs_ept_partition_state){0};
}

/* Get the EPT PML4 physical address for a partition.
 * Returns 0 if no EPT is allocated. */
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

/*@ requires \valid(state);
    assigns \nothing;
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
    assigns \nothing;
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

/*@ requires \valid(state) || state == \null;
    requires \valid(request) || request == \null;
    requires \valid(response) || response == \null;
    requires state != \null ==> state->next_memory_object_id > 0;
    assigns state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1],
            state->next_memory_object_id,
            *response;
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == RESOURCE_EXHAUSTED;
    ensures \result == OK ==> response->memory_object_id > 0;
*/
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
    if (!fbvbs_id_allocator_can_advance(state->next_memory_object_id, 1U)) {
        return RESOURCE_EXHAUSTED;
    }

    *object = (struct fbvbs_memory_object){0};
    object->allocated = true;
    object->object_flags = request->object_flags;
    object->memory_object_id = state->next_memory_object_id++;
    object->owner_partition_id = owner_partition_id;
    object->size = request->size;
    response->memory_object_id = object->memory_object_id;
    return OK;
}

/*@ requires \valid(state);
    assigns state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1];
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == NOT_FOUND || \result == RESOURCE_BUSY || \result == PERMISSION_DENIED;
*/
int fbvbs_memory_release_object(
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
    if (object->owner_partition_id != requester_partition_id) {
        return PERMISSION_DENIED;
    }
    if (object->map_count != 0U || object->shared_count != 0U) {
        return RESOURCE_BUSY;
    }

    *object = (struct fbvbs_memory_object){0};
    return OK;
}
