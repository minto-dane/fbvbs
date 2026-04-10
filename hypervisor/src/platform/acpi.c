#include <stddef.h>
#include <stdint.h>

#include "fbvbs_hypervisor.h"

#define ACPI_SIG_RSDT 0x54445352U
#define ACPI_SIG_XSDT 0x54445358U

#define ACPI_RSDP_V1_SIZE 20U
#define ACPI_RSDP_SCAN_STEP 16U
#define ACPI_EBDA_PTR_PHYS 0x40EU
#define ACPI_EBDA_SCAN_BYTES 1024U
#define ACPI_BIOS_SCAN_START 0xE0000U
#define ACPI_BIOS_SCAN_END 0x100000U
#define ACPI_MAX_TABLE_SIZE 65536U

struct fbvbs_rsdp_v1 {
    uint8_t signature[8];
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
} __attribute__((packed));

struct fbvbs_rsdp_v2 {
    struct fbvbs_rsdp_v1 first_part;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t extended_checksum;
    uint8_t reserved[3];
} __attribute__((packed));

struct fbvbs_acpi_sdt_header {
    uint32_t signature;
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed));

#ifdef FBVBS_BAREMETAL_BUILD

/*@ requires \valid_read(data + (0 .. length - 1));
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_acpi_checksum_valid(const uint8_t *data, uint32_t length) {
    uint32_t index;
    uint8_t sum = 0U;

    if (data == NULL || length == 0U) {
        return 0;
    }

    /*@ loop invariant 0 <= index <= length;
        loop assigns index, sum;
        loop variant length - index;
    */
    for (index = 0U; index < length; ++index) {
        sum = (uint8_t)(sum + data[index]);
    }

    return (sum == 0U) ? 1 : 0;
}

/*@ requires \valid_read(rsdp);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_rsdp_signature_valid(const struct fbvbs_rsdp_v1 *rsdp) {
    static const uint8_t expected[8] = {
        'R', 'S', 'D', ' ', 'P', 'T', 'R', ' '
    };
    uint32_t index;

    /*@ loop invariant 0 <= index <= 8;
        loop assigns index;
        loop variant 8 - index;
    */
    for (index = 0U; index < 8U; ++index) {
        if (rsdp->signature[index] != expected[index]) {
            return 0;
        }
    }

    return 1;
}

/*@ requires rsdp == \null || \valid_read(rsdp);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_rsdp_valid(const struct fbvbs_rsdp_v1 *rsdp) {
    const struct fbvbs_rsdp_v2 *rsdp2;

    if (rsdp == NULL) {
        return 0;
    }
    if (fbvbs_rsdp_signature_valid(rsdp) == 0) {
        return 0;
    }
    if (fbvbs_acpi_checksum_valid((const uint8_t *)rsdp, ACPI_RSDP_V1_SIZE) == 0) {
        return 0;
    }

    if (rsdp->revision < 2U) {
        return 1;
    }

    rsdp2 = (const struct fbvbs_rsdp_v2 *)rsdp;
    if (rsdp2->length < sizeof(struct fbvbs_rsdp_v2) ||
        rsdp2->length > ACPI_MAX_TABLE_SIZE) {
        return 0;
    }

    return fbvbs_acpi_checksum_valid((const uint8_t *)rsdp2, rsdp2->length);
}

/*@ requires table == \null || \valid_read(table);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_acpi_table_valid(const struct fbvbs_acpi_sdt_header *table) {
    if (table == NULL) {
        return 0;
    }
    if (table->length < sizeof(struct fbvbs_acpi_sdt_header) ||
        table->length > ACPI_MAX_TABLE_SIZE) {
        return 0;
    }

    return fbvbs_acpi_checksum_valid((const uint8_t *)table, table->length);
}

/*@ assigns \nothing;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_rsdp_v1 *fbvbs_scan_rsdp_range(uintptr_t start, uintptr_t end) {
    uintptr_t address;

    if (start >= end || end - start < ACPI_RSDP_V1_SIZE) {
        return NULL;
    }

    /*@ loop invariant start <= address <= end;
        loop assigns address;
        loop variant end - address;
    */
    for (address = start; address + ACPI_RSDP_V1_SIZE <= end; address += ACPI_RSDP_SCAN_STEP) {
        const struct fbvbs_rsdp_v1 *candidate =
            (const struct fbvbs_rsdp_v1 *)(uintptr_t)address;
        if (fbvbs_rsdp_valid(candidate) != 0) {
            return candidate;
        }
    }

    return NULL;
}

/*@ assigns \nothing;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_rsdp_v1 *fbvbs_find_rsdp(void) {
    const struct fbvbs_rsdp_v1 *boot_rsdp =
        (const struct fbvbs_rsdp_v1 *)g_fbvbs_hypervisor.acpi_rsdp;
    uint16_t ebda_segment = 0U;
    uintptr_t ebda_address;
    const struct fbvbs_rsdp_v1 *candidate;

    if (fbvbs_rsdp_valid(boot_rsdp) != 0) {
        return boot_rsdp;
    }

    fbvbs_copy_memory(&ebda_segment, (const void *)(uintptr_t)ACPI_EBDA_PTR_PHYS,
                      sizeof(ebda_segment));
    ebda_address = ((uintptr_t)ebda_segment) << 4U;
    if (ebda_address != 0U) {
        candidate = fbvbs_scan_rsdp_range(ebda_address,
                                          ebda_address + ACPI_EBDA_SCAN_BYTES);
        if (candidate != NULL) {
            return candidate;
        }
    }

    return fbvbs_scan_rsdp_range(ACPI_BIOS_SCAN_START, ACPI_BIOS_SCAN_END);
}

/*@ requires root == \null || \valid_read(root);
    assigns \nothing;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_acpi_sdt_header *fbvbs_find_table_in_root(
    const struct fbvbs_acpi_sdt_header *root,
    uint32_t signature
) {
    const uint8_t *entries;
    uint32_t entry_size;
    uint32_t entry_count;
    uint32_t index;

    if (fbvbs_acpi_table_valid(root) == 0) {
        return NULL;
    }

    if (root->signature == ACPI_SIG_XSDT) {
        entry_size = 8U;
    } else if (root->signature == ACPI_SIG_RSDT) {
        entry_size = 4U;
    } else {
        return NULL;
    }

    entries = ((const uint8_t *)root) + sizeof(struct fbvbs_acpi_sdt_header);
    entry_count = (root->length - (uint32_t)sizeof(struct fbvbs_acpi_sdt_header)) / entry_size;

    /*@ loop invariant 0 <= index <= entry_count;
        loop assigns index;
        loop variant entry_count - index;
    */
    for (index = 0U; index < entry_count; ++index) {
        uintptr_t table_phys = 0U;
        const struct fbvbs_acpi_sdt_header *table;

        if (entry_size == 8U) {
            uint64_t xsdt_entry = 0U;
            fbvbs_copy_memory(&xsdt_entry, entries + (index * entry_size), sizeof(xsdt_entry));
            if (xsdt_entry == 0U || xsdt_entry > (uint64_t)UINTPTR_MAX) {
                continue;
            }
            table_phys = (uintptr_t)xsdt_entry;
        } else {
            uint32_t rsdt_entry = 0U;
            fbvbs_copy_memory(&rsdt_entry, entries + (index * entry_size), sizeof(rsdt_entry));
            if (rsdt_entry == 0U) {
                continue;
            }
            table_phys = (uintptr_t)rsdt_entry;
        }

        table = (const struct fbvbs_acpi_sdt_header *)table_phys;
        if (fbvbs_acpi_table_valid(table) == 0) {
            continue;
        }
        if (table->signature == signature) {
            return table;
        }
    }

    return NULL;
}

/*@ assigns \nothing;
*/
const void *fbvbs_acpi_find_table(uint32_t signature) {
    const struct fbvbs_rsdp_v1 *rsdp;
    const struct fbvbs_rsdp_v2 *rsdp2;
    const struct fbvbs_acpi_sdt_header *root;
    const struct fbvbs_acpi_sdt_header *table;

    rsdp = fbvbs_find_rsdp();
    if (rsdp == NULL) {
        return NULL;
    }

    if (rsdp->revision >= 2U) {
        rsdp2 = (const struct fbvbs_rsdp_v2 *)rsdp;
        if (rsdp2->xsdt_address != 0U && rsdp2->xsdt_address <= (uint64_t)UINTPTR_MAX) {
            root = (const struct fbvbs_acpi_sdt_header *)(uintptr_t)rsdp2->xsdt_address;
            table = fbvbs_find_table_in_root(root, signature);
            if (table != NULL) {
                return table;
            }
        }
    }

    if (rsdp->rsdt_address != 0U) {
        root = (const struct fbvbs_acpi_sdt_header *)(uintptr_t)rsdp->rsdt_address;
        table = fbvbs_find_table_in_root(root, signature);
        if (table != NULL) {
            return table;
        }
    }

    return NULL;
}

#else

/*@ assigns \nothing;
*/
const void *fbvbs_acpi_find_table(uint32_t signature) {
    (void)signature;
    return NULL;
}

#endif
