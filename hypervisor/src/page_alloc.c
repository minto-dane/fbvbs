/*
 * FBVBS Physical Page Frame Allocator (Phase 0C)
 *
 * Bitmap-based allocator for 4 KiB physical page frames.  All page table
 * construction (EPT, NPT, HLAT, IOMMU root/context/DTE, VMCS, CET shadow
 * stack) depends on this allocator.
 *
 * Design:
 *   - Static bitmap stored in BSS, sized for up to FBVBS_MAX_PHYS_PAGES.
 *   - Allocate returns a zeroed page (REQ-0203).
 *   - Free zeroes the page before returning to pool (REQ-0903).
 *   - Allocation failure = fail-closed (returns 0 = invalid PFN).
 *   - No malloc/free — bare-metal, fully static.
 *
 * PRODUCTION NOTE: The actual page zeroing uses fbvbs_zero_memory which is
 * a model function. Production must use REP STOSB or equivalent with
 * verified completion.
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

#include "fbvbs_hypervisor.h"

/* Bitmap: 1 bit per page.  For 4 GiB physical address space with 4 KiB pages,
 * we need 1M bits = 128 KiB.  We support up to FBVBS_MAX_PHYS_PAGES. */

#define PAGE_SHIFT 12U
#define PAGE_SIZE  4096U
#define BITS_PER_WORD 64U
#define BITMAP_WORDS ((FBVBS_MAX_PHYS_PAGES + BITS_PER_WORD - 1U) / BITS_PER_WORD)

_Static_assert(FBVBS_MAX_PHYS_PAGES <= (1U << 20U),
               "FBVBS_MAX_PHYS_PAGES too large for bitmap sizing");
_Static_assert(BITMAP_WORDS * sizeof(uint64_t) <= 131072U,
               "page bitmap exceeds 128 KiB");

/* Allocator state — file-scope static.
 * bitmap: bit=1 means page is FREE (available for allocation).
 * total_pages: number of pages managed.
 * free_count: number of free pages.
 * initialized: set to 1 after init completes. */
static uint64_t page_bitmap[BITMAP_WORDS];
static uint32_t total_pages;
static uint32_t free_count;
static uint32_t initialized;

/* Hint for next allocation scan — reduces average search time.
 * Reset to 0 on free to coalesce early pages. */
static uint32_t alloc_hint;

/*@ requires word_idx < BITMAP_WORDS;
    requires bit_idx < BITS_PER_WORD;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int bitmap_test(uint32_t word_idx, uint32_t bit_idx) {
    return (int)((page_bitmap[word_idx] >> bit_idx) & 1ULL);
}

/*@ requires word_idx < BITMAP_WORDS;
    requires bit_idx < BITS_PER_WORD;
    assigns page_bitmap[word_idx];
*/
static void bitmap_set(uint32_t word_idx, uint32_t bit_idx) {
    page_bitmap[word_idx] |= (1ULL << bit_idx);
}

/*@ requires word_idx < BITMAP_WORDS;
    requires bit_idx < BITS_PER_WORD;
    assigns page_bitmap[word_idx];
*/
static void bitmap_clear(uint32_t word_idx, uint32_t bit_idx) {
    page_bitmap[word_idx] &= ~(1ULL << bit_idx);
}

/*@ requires pfn < FBVBS_MAX_PHYS_PAGES;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int page_is_free(uint32_t pfn) {
    uint32_t word = pfn / (uint32_t)BITS_PER_WORD;
    uint32_t bit = pfn % (uint32_t)BITS_PER_WORD;
    return bitmap_test(word, bit);
}

/*@ requires pfn < FBVBS_MAX_PHYS_PAGES;
    assigns page_bitmap[pfn / BITS_PER_WORD];
*/
static void mark_free(uint32_t pfn) {
    uint32_t word = pfn / (uint32_t)BITS_PER_WORD;
    uint32_t bit = pfn % (uint32_t)BITS_PER_WORD;
    bitmap_set(word, bit);
}

/*@ requires pfn < FBVBS_MAX_PHYS_PAGES;
    assigns page_bitmap[pfn / BITS_PER_WORD];
*/
static void mark_allocated(uint32_t pfn) {
    uint32_t word = pfn / (uint32_t)BITS_PER_WORD;
    uint32_t bit = pfn % (uint32_t)BITS_PER_WORD;
    bitmap_clear(word, bit);
}

/*@ assigns page_bitmap[0 .. BITMAP_WORDS - 1], total_pages, free_count,
            initialized, alloc_hint;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_page_alloc_init(const struct fbvbs_memory_map_entry *map,
                          uint32_t map_count) {
    uint32_t i;
    uint32_t max_pfn = 0;

    if (map == NULL || map_count == 0U) {
        return -1;
    }

    /* Clear bitmap — all pages start as allocated (not free) */
    /*@ loop invariant 0 <= i <= BITMAP_WORDS;
        loop assigns i, page_bitmap[0 .. BITMAP_WORDS - 1];
        loop variant BITMAP_WORDS - i;
    */
    for (i = 0; i < BITMAP_WORDS; ++i) {
        page_bitmap[i] = 0ULL;
    }
    total_pages = 0;
    free_count = 0;
    alloc_hint = 0;

    /* Mark usable memory regions as free */
    /*@ loop invariant 0 <= i <= map_count;
        loop assigns i, page_bitmap[0 .. BITMAP_WORDS - 1],
                     total_pages, free_count, max_pfn;
        loop variant map_count - i;
    */
    for (i = 0; i < map_count; ++i) {
        uint64_t base = map[i].base_addr;
        uint64_t length = map[i].length;
        uint32_t type = map[i].type;
        uint64_t end;
        uint64_t start_pfn_64, end_pfn_64;
        uint32_t start_pfn, end_pfn, pfn;

        /* Only mark type=1 (usable) regions */
        if (type != 1U) {
            continue;
        }

        /* Skip regions below 1 MiB (legacy, BIOS, etc.) */
        if (base < 0x100000ULL) {
            continue;
        }

        /* Overflow-safe end computation */
        if (base > UINT64_MAX - length) {
            continue;
        }
        end = base + length;

        /* Compute PFNs as uint64_t FIRST, then clamp, then narrow.
         * Direct uint64_t→uint32_t cast before clamping can silently
         * truncate high addresses (e.g. 256TB → PFN 0), aliasing
         * distant physical memory onto the low 4GiB page pool. */
        start_pfn_64 = (base + PAGE_SIZE - 1U) >> PAGE_SHIFT;
        end_pfn_64 = end >> PAGE_SHIFT;

        /* Clamp to max supported pages BEFORE narrowing */
        if (start_pfn_64 >= FBVBS_MAX_PHYS_PAGES) {
            continue;
        }
        if (end_pfn_64 > FBVBS_MAX_PHYS_PAGES) {
            end_pfn_64 = FBVBS_MAX_PHYS_PAGES;
        }

        /* Now safe to narrow — both values < FBVBS_MAX_PHYS_PAGES */
        start_pfn = (uint32_t)start_pfn_64;
        end_pfn = (uint32_t)end_pfn_64;

        if (start_pfn >= end_pfn) {
            continue;
        }

        /*@ loop invariant start_pfn <= pfn <= end_pfn;
            loop assigns pfn, page_bitmap[0 .. BITMAP_WORDS - 1],
                         free_count;
            loop variant end_pfn - pfn;
        */
        for (pfn = start_pfn; pfn < end_pfn; ++pfn) {
            mark_free(pfn);
            if (free_count < UINT32_MAX) {
                free_count += 1U;
            }
        }

        if (end_pfn > max_pfn) {
            max_pfn = end_pfn;
        }
    }

    total_pages = max_pfn;
    initialized = 1U;

    if (free_count == 0U) {
        return -1;  /* No usable memory found — fail-closed */
    }

    return 0;
}

/* Reserve a range of pages (e.g., hypervisor own memory, IOMMU tables).
 * Prevents the allocator from handing out pages in this range. */
/*@ assigns page_bitmap[0 .. BITMAP_WORDS - 1], free_count;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_page_alloc_reserve(uint64_t phys_addr, uint64_t size) {
    uint64_t end_addr, start_pfn_64, end_pfn_64;
    uint32_t start_pfn, end_pfn, pfn;

    if (initialized != 1U) {
        return -1;
    }

    if (phys_addr > UINT64_MAX - size) {
        return -1;
    }

    /* Compute PFNs as uint64_t to prevent truncation aliasing.
     * See init() comment for the aliasing attack vector. */
    start_pfn_64 = phys_addr >> PAGE_SHIFT;
    if (start_pfn_64 >= FBVBS_MAX_PHYS_PAGES) {
        return 0;  /* Entirely above supported range — nothing to reserve */
    }

    /* Overflow-safe round-up: avoid (addr + PAGE_SIZE - 1) overflow */
    end_addr = phys_addr + size;
    end_pfn_64 = end_addr >> PAGE_SHIFT;
    if ((end_addr & (uint64_t)(PAGE_SIZE - 1U)) != 0U) {
        end_pfn_64 += 1U;
    }
    if (end_pfn_64 > FBVBS_MAX_PHYS_PAGES) {
        end_pfn_64 = FBVBS_MAX_PHYS_PAGES;
    }

    start_pfn = (uint32_t)start_pfn_64;
    end_pfn = (uint32_t)end_pfn_64;

    /*@ loop invariant start_pfn <= pfn <= end_pfn;
        loop assigns pfn, page_bitmap[0 .. BITMAP_WORDS - 1], free_count;
        loop variant end_pfn - pfn;
    */
    for (pfn = start_pfn; pfn < end_pfn; ++pfn) {
        if (page_is_free(pfn)) {
            mark_allocated(pfn);
            if (free_count > 0U) {
                free_count -= 1U;
            }
        }
    }

    return 0;
}

/* Allocate one physical page frame.
 * Returns physical address (page-aligned), or 0 on failure.
 * The page is zeroed before return (REQ-0203). */
/*@ assigns page_bitmap[0 .. BITMAP_WORDS - 1], free_count, alloc_hint;
    ensures \result == 0 || (\result % PAGE_SIZE == 0 && \result >= PAGE_SIZE);
*/
uint64_t fbvbs_page_alloc(void) {
    uint32_t pfn;
    uint32_t scanned = 0;
    uint64_t phys_addr;

    if (initialized != 1U || free_count == 0U) {
        return 0;  /* Fail-closed */
    }

    pfn = alloc_hint;
    if (pfn >= total_pages) {
        pfn = 0;
    }

    /* Linear scan from hint, wrapping around.
     * Bounded by total_pages to prevent infinite loop. */
    /*@ loop invariant 0 <= scanned <= total_pages;
        loop assigns pfn, scanned;
        loop variant total_pages - scanned;
    */
    while (scanned < total_pages) {
        if (pfn < FBVBS_MAX_PHYS_PAGES && page_is_free(pfn)) {
            break;
        }
        ++pfn;
        if (pfn >= total_pages) {
            pfn = 0;
        }
        ++scanned;
    }

    if (scanned >= total_pages || pfn >= FBVBS_MAX_PHYS_PAGES) {
        return 0;  /* No free page found — fail-closed */
    }

    mark_allocated(pfn);
    if (free_count > 0U) {
        free_count -= 1U;
    }

    /* Advance hint past this allocation */
    if (pfn + 1U < total_pages) {
        alloc_hint = pfn + 1U;
    } else {
        alloc_hint = 0U;
    }

    phys_addr = (uint64_t)pfn << PAGE_SHIFT;

    /* Zero the page before returning (REQ-0203).
     * PRODUCTION NOTE: In production, this dereferences the physical address
     * via identity mapping.  Model code uses fbvbs_zero_memory. */
#ifndef __FRAMAC__
    /* Identity-mapped: physical address == virtual address */
    fbvbs_zero_memory((void *)(uintptr_t)phys_addr, PAGE_SIZE);
#endif

    return phys_addr;
}

/* Free a physical page frame, returning it to the pool.
 * The page is zeroed before free (REQ-0903 — reuse-before-zero). */
/*@ assigns page_bitmap[0 .. BITMAP_WORDS - 1], free_count, alloc_hint;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_page_free(uint64_t phys_addr) {
    uint32_t pfn;

    if (initialized != 1U) {
        return -1;
    }

    /* Must be page-aligned */
    if ((phys_addr & (PAGE_SIZE - 1U)) != 0U) {
        return -1;
    }

    /* Reject addresses above supported range — prevents uint64_t→uint32_t
     * PFN truncation from aliasing high addresses onto low pages,
     * which would free the wrong page (potential use-after-free). */
    if (phys_addr >= ((uint64_t)FBVBS_MAX_PHYS_PAGES << PAGE_SHIFT)) {
        return -1;
    }

    pfn = (uint32_t)(phys_addr >> PAGE_SHIFT);

    if (pfn >= FBVBS_MAX_PHYS_PAGES || pfn >= total_pages) {
        return -1;
    }

    /* Double-free detection */
    if (page_is_free(pfn)) {
        return -1;  /* Already free — fail-closed, do not corrupt state */
    }

    /* Zero the page before returning to pool (REQ-0903).
     * PRODUCTION NOTE: Same identity-mapping requirement as alloc. */
#ifndef __FRAMAC__
    fbvbs_zero_memory((void *)(uintptr_t)phys_addr, PAGE_SIZE);
#endif

    mark_free(pfn);
    if (free_count < UINT32_MAX) {
        free_count += 1U;
    }

    /* Move hint to coalesce early pages */
    if (pfn < alloc_hint) {
        alloc_hint = pfn;
    }

    return 0;
}

/* Query allocator statistics. */
/*@ assigns \nothing;
    ensures \result >= 0;
*/
uint32_t fbvbs_page_alloc_free_count(void) {
    if (initialized != 1U) {
        return 0;
    }
    return free_count;
}

/*@ assigns \nothing;
    ensures \result >= 0;
*/
uint32_t fbvbs_page_alloc_total_pages(void) {
    if (initialized != 1U) {
        return 0;
    }
    return total_pages;
}
