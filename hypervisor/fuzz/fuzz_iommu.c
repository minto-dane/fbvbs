/* FBVBS IOMMU Table Parser Fuzzer
 *
 * Phase 9-1: Continuous fuzzing of IOMMU ACPI table parsers (REQ-1004).
 *
 * Targets:
 *   - fbvbs_dmar_parse() — Intel VT-d DMAR table parser
 *   - fbvbs_ivrs_parse() — AMD-Vi IVRS table parser
 *
 * These parsers process firmware-provided ACPI tables. While firmware
 * is normally trusted, defense-in-depth requires validation against
 * malformed tables (compromised BIOS, TOCTOU on shared memory, etc).
 *
 * Build (standalone, via Makefile fuzz-build target):
 *   make -C hypervisor fuzz-build
 */

#include "fbvbs_hypervisor.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ================================================================
 * Type definitions mirrored from iommu_vtd.c and iommu_amdvi.c.
 * These are file-static in the source files but exported under
 * FUZZ_TARGET for testing.
 * ================================================================ */

/* --- Intel VT-d (from iommu_vtd.c) --- */

#ifndef FBVBS_MAX_DRHD_UNITS
#define FBVBS_MAX_DRHD_UNITS        8U
#endif
#ifndef FBVBS_MAX_RMRR_REGIONS
#define FBVBS_MAX_RMRR_REGIONS      16U
#endif
#ifndef FBVBS_MAX_DMAR_SCOPES
#define FBVBS_MAX_DMAR_SCOPES       32U
#endif
#ifndef FBVBS_MAX_DMAR_TABLE_SIZE
#define FBVBS_MAX_DMAR_TABLE_SIZE   4096U
#endif

struct acpi_table_header {
    uint32_t signature;
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    uint8_t  oem_id[6];
    uint8_t  oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
};

struct dmar_table_header {
    struct acpi_table_header header;
    uint8_t  host_address_width;
    uint8_t  flags;
    uint8_t  reserved[10];
};

struct fbvbs_drhd_unit {
    uint32_t active;
    uint32_t flags;
    uint16_t segment;
    uint16_t reserved0;
    uint32_t scope_count;
    uint64_t register_base_address;
    struct {
        uint8_t type;
        uint8_t bus;
        uint8_t dev;
        uint8_t func;
    } scopes[FBVBS_MAX_DMAR_SCOPES];
};

struct fbvbs_rmrr_region {
    uint32_t active;
    uint16_t segment;
    uint16_t reserved0;
    uint64_t base_address;
    uint64_t limit_address;
};

struct fbvbs_dmar_info {
    uint32_t valid;
    uint8_t  host_address_width;
    uint8_t  flags;
    uint16_t reserved0;
    uint32_t drhd_count;
    uint32_t rmrr_count;
    struct fbvbs_drhd_unit drhd_units[FBVBS_MAX_DRHD_UNITS];
    struct fbvbs_rmrr_region rmrr_regions[FBVBS_MAX_RMRR_REGIONS];
};

/* Extern declaration for FUZZ_TARGET-exported parser */
extern int fbvbs_dmar_parse(
    const struct dmar_table_header *table,
    uint32_t table_length,
    struct fbvbs_dmar_info *info);

/* --- AMD-Vi (from iommu_amdvi.c) --- */

#ifndef FBVBS_MAX_AMDVI_UNITS
#define FBVBS_MAX_AMDVI_UNITS       8U
#endif
#ifndef FBVBS_MAX_IVMD_REGIONS
#define FBVBS_MAX_IVMD_REGIONS      16U
#endif
#ifndef FBVBS_MAX_IVRS_TABLE_SIZE
#define FBVBS_MAX_IVRS_TABLE_SIZE   4096U
#endif

struct acpi_ivrs_table_header {
    uint32_t signature;
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    uint8_t  oem_id[6];
    uint8_t  oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
    uint32_t iv_info;
    uint64_t reserved;
};

struct fbvbs_amdvi_unit {
    uint32_t active;
    uint32_t flags;
    uint16_t device_id;
    uint16_t cap_offset;
    uint64_t mmio_base;
    uint16_t pci_segment;
    uint16_t iommu_info;
    uint32_t ef_features;
};

struct fbvbs_ivmd_region {
    uint32_t active;
    uint8_t  type;
    uint8_t  flags;
    uint16_t device_id;
    uint64_t start_address;
    uint64_t mem_length;
};

struct fbvbs_ivrs_info {
    uint32_t valid;
    uint32_t iv_info;
    uint32_t ivhd_count;
    uint32_t ivmd_count;
    struct fbvbs_amdvi_unit ivhd_units[FBVBS_MAX_AMDVI_UNITS];
    struct fbvbs_ivmd_region ivmd_regions[FBVBS_MAX_IVMD_REGIONS];
};

/* Extern declaration for FUZZ_TARGET-exported parser */
extern int fbvbs_ivrs_parse(
    const struct acpi_ivrs_table_header *table,
    uint32_t table_length,
    struct fbvbs_ivrs_info *info);

/* ================================================================
 * Fuzz entry point
 *
 * The input buffer is used as both DMAR and IVRS tables.
 * Each parser has its own signature validation, so feeding
 * one format to the other parser tests rejection paths too.
 * ================================================================ */

/* Compile-time guards: mirrored structs must match source definitions.
 * If a source struct changes size, these fire immediately. */
_Static_assert(sizeof(struct acpi_table_header) == 36,
               "acpi_table_header size mismatch with iommu_vtd.c");
_Static_assert(sizeof(struct dmar_table_header) == 48,
               "dmar_table_header size mismatch with iommu_vtd.c");
_Static_assert(sizeof(struct acpi_ivrs_table_header) == 48,
               "acpi_ivrs_table_header size mismatch with iommu_amdvi.c");
/* Output struct size guards: if the source definition grows beyond our
 * mirrored copy, the parser would write past our stack allocation. */
_Static_assert(sizeof(struct fbvbs_dmar_info) == 1616,
               "fbvbs_dmar_info size mismatch — update mirrored definition");
_Static_assert(sizeof(struct fbvbs_ivrs_info) == 656,
               "fbvbs_ivrs_info size mismatch — update mirrored definition");

static int fuzz_one_input(const uint8_t *data, size_t size)
{
    /* Test 1: DMAR parser */
    if (size >= sizeof(struct dmar_table_header)) {
        struct fbvbs_dmar_info info;
        /* Clamp to uint32_t range BEFORE cast (Finding 4) */
        uint32_t len = (size > FBVBS_MAX_DMAR_TABLE_SIZE)
                       ? FBVBS_MAX_DMAR_TABLE_SIZE : (uint32_t)size;
        /* Copy into aligned buffer to avoid UB from unaligned cast (Finding 3).
         * DMAR tables are max 4096 bytes. */
        _Alignas(8) uint8_t aligned_dmar[FBVBS_MAX_DMAR_TABLE_SIZE];
        memcpy(aligned_dmar, data, len);
        (void)fbvbs_dmar_parse(
            (const struct dmar_table_header *)aligned_dmar,
            len,
            &info);
    }

    /* Test 2: IVRS parser */
    if (size >= sizeof(struct acpi_ivrs_table_header)) {
        struct fbvbs_ivrs_info info;
        /* Clamp to uint32_t range BEFORE cast (Finding 4) */
        uint32_t len = (size > FBVBS_MAX_IVRS_TABLE_SIZE)
                       ? FBVBS_MAX_IVRS_TABLE_SIZE : (uint32_t)size;
        /* Copy into aligned buffer to avoid UB from unaligned cast (Finding 3) */
        _Alignas(8) uint8_t aligned_ivrs[FBVBS_MAX_IVRS_TABLE_SIZE];
        memcpy(aligned_ivrs, data, len);
        (void)fbvbs_ivrs_parse(
            (const struct acpi_ivrs_table_header *)aligned_ivrs,
            len,
            &info);
    }

    return 0;
}

/* Entry points */
#if defined(__AFL_HAVE_MANUAL_CONTROL) || defined(__AFL_COMPILER)
#include <unistd.h>
__AFL_FUZZ_INIT();
int main(void)
{
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        size_t len = (size_t)__AFL_FUZZ_TESTCASE_LEN;
        fuzz_one_input(buf, len);
    }
    return 0;
}
#elif defined(FUZZ_LIBFUZZER)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_one_input(data, size);
}
#else
#include <stdio.h>
int main(void)
{
    uint8_t buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n == 0) { return 1; }
    return fuzz_one_input(buf, n);
}
#endif
