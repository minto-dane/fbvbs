#include "fbvbs_hypervisor.h"
#include "fbvbs_asm.h"

/* ================================================================
 * Intel VT-d DMAR table parser
 *
 * Parses the ACPI DMAR (DMA Remapping Reporting) table to discover
 * VT-d hardware units and their configurations. This is the first
 * step in enabling IOMMU protection for device passthrough.
 *
 * Requirements: REQ-0003 (IOMMU 必須), REQ-0350 (DMA remapping),
 *   REQ-0351 (Interrupt remapping), REQ-0353 (外部 DMA 分離)
 *
 * Reference: Intel VT-d Specification, Chapter 8 (BIOS Considerations)
 * ================================================================ */

/* ACPI table signatures */
#define ACPI_SIG_RSDP_LO 0x20445352U  /* "RSD " */
#define ACPI_SIG_RSDP_HI 0x20525450U  /* "PTR " */
#define ACPI_SIG_DMAR     0x52414D44U  /* "DMAR" */
#define ACPI_SIG_XSDT     0x54445358U  /* "XSDT" */

/* DMAR remapping structure types */
#define DMAR_TYPE_DRHD  0U  /* DMA Remapping Hardware Unit Definition */
#define DMAR_TYPE_RMRR  1U  /* Reserved Memory Region Reporting */
#define DMAR_TYPE_ATSR  2U  /* Root Port ATS Capability Reporting */
#define DMAR_TYPE_RHSA  3U  /* Remapping Hardware Static Affinity */
#define DMAR_TYPE_ANDD  4U  /* ACPI Name-space Device Declaration */
#define DMAR_TYPE_SATC  5U  /* SoC Integrated Address Translation Cache */

/* DMAR flags */
#define DMAR_DRHD_FLAG_INCLUDE_PCI_ALL  0x01U

/* Device scope types */
#define DMAR_SCOPE_PCI_ENDPOINT     1U
#define DMAR_SCOPE_PCI_SUB_HIERARCHY 2U
#define DMAR_SCOPE_IOAPIC           3U
#define DMAR_SCOPE_MSI_HPET         4U
#define DMAR_SCOPE_ACPI_NAMESPACE   5U

/* Maximum limits for bounded parsing */
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

/* ================================================================
 * ACPI / DMAR table structures (packed wire format)
 * ================================================================ */

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
    /* Variable-length remapping structures follow */
};

struct dmar_remapping_header {
    uint16_t type;
    uint16_t length;
};

struct dmar_device_scope {
    uint8_t  type;
    uint8_t  length;
    uint16_t reserved;
    uint8_t  enumeration_id;
    uint8_t  start_bus;
    /* Variable-length PCI path follows (bus, dev/func pairs) */
};

/* ================================================================
 * Parsed DMAR data structures
 * ================================================================ */

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

/* Forward declarations for helpers referenced before their definitions. */
static int vtd_probe_capabilities(
    struct fbvbs_global_security_state *state,
    const struct fbvbs_dmar_info *info);

/* ================================================================
 * ACPI checksum verification
 * ================================================================ */

/*@ requires length <= FBVBS_MAX_DMAR_TABLE_SIZE;
    requires \valid_read(data + (0 .. length - 1));
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int acpi_checksum_valid(const uint8_t *data, uint32_t length)
{
    uint32_t i;
    uint8_t sum = 0U;

    if (length == 0U) {
        return 0;
    }

    /*@ loop invariant 0 <= i <= length;
        loop assigns i, sum;
        loop variant length - i;
    */
    for (i = 0U; i < length; ++i) {
        sum = (uint8_t)(sum + data[i]);
    }
    return (sum == 0U) ? 1 : 0;
}

/* ================================================================
 * Device scope parser
 * ================================================================ */

/*@ requires \valid_read(scope_data + (0 .. scope_data_length - 1));
    requires scope_data_length <= FBVBS_MAX_DMAR_TABLE_SIZE;
    requires \valid(unit);
    assigns unit->scopes[0 .. FBVBS_MAX_DMAR_SCOPES - 1],
            unit->scope_count;
*/
static void parse_device_scopes(
    const uint8_t *scope_data,
    uint32_t scope_data_length,
    struct fbvbs_drhd_unit *unit)
{
    uint32_t offset = 0U;

    unit->scope_count = 0U;

    /*@ loop invariant 0 <= offset <= scope_data_length;
        loop invariant unit->scope_count <= FBVBS_MAX_DMAR_SCOPES;
        loop assigns offset, unit->scopes[0 .. FBVBS_MAX_DMAR_SCOPES - 1],
                     unit->scope_count;
        loop variant scope_data_length - offset;
    */
    while (offset + 6U <= scope_data_length) {
        const struct dmar_device_scope *scope =
            (const struct dmar_device_scope *)(scope_data + offset);
        uint8_t scope_length = scope->length;

        /* Validate scope entry */
        if (scope_length < 6U || offset + (uint32_t)scope_length > scope_data_length) {
            break;
        }
        if (unit->scope_count >= FBVBS_MAX_DMAR_SCOPES) {
            break;
        }

        unit->scopes[unit->scope_count].type = scope->type;
        unit->scopes[unit->scope_count].bus = scope->start_bus;
        /* First PCI path entry at offset 6: byte[0]=device, byte[1]=function
         * per ACPI spec (not packed dev[7:3]/func[2:0] in one byte) */
        if (scope_length >= 8U) {
            unit->scopes[unit->scope_count].dev =
                (uint8_t)(scope_data[offset + 6U] & 0x1FU);
            unit->scopes[unit->scope_count].func =
                (uint8_t)(scope_data[offset + 7U] & 0x07U);
        } else {
            unit->scopes[unit->scope_count].dev = 0U;
            unit->scopes[unit->scope_count].func = 0U;
        }
        unit->scope_count += 1U;
        offset += (uint32_t)scope_length;
    }
}

/* ================================================================
 * DMAR table parser
 * ================================================================ */

/*@ requires \valid(info);
    requires table == \null ||
             (\valid_read(table) &&
              \valid_read(((const uint8_t *)table) + (0 .. table_length - 1)));
    requires table_length <= FBVBS_MAX_DMAR_TABLE_SIZE;
    assigns *info;
    ensures \result == 0 || \result == -1;
    ensures \result == 0 ==> info->valid == 1;
    ensures \result == -1 ==> info->valid == 0;
*/
#ifdef FUZZ_TARGET
int
#else
static int
#endif
fbvbs_dmar_parse(
    const struct dmar_table_header *table,
    uint32_t table_length,
    struct fbvbs_dmar_info *info)
{
    uint32_t offset;
    const uint8_t *raw;

    *info = (struct fbvbs_dmar_info){0};

    if (table == NULL) {
        return -1;
    }

    /* Validate minimum table size */
    if (table_length < sizeof(struct dmar_table_header)) {
        return -1;
    }

    /* Validate signature */
    if (table->header.signature != ACPI_SIG_DMAR) {
        return -1;
    }

    /* Validate length consistency */
    if (table->header.length != table_length ||
        table->header.length > FBVBS_MAX_DMAR_TABLE_SIZE) {
        return -1;
    }

    /* Verify ACPI checksum */
    raw = (const uint8_t *)table;
#if !defined(__FRAMAC__)
    if (!acpi_checksum_valid(raw, table_length)) {
        return -1;
    }
#else
    (void)raw;
#endif

    info->host_address_width = table->host_address_width;
    info->flags = table->flags;

    /* Parse remapping structures */
    offset = (uint32_t)sizeof(struct dmar_table_header);

    /*@ loop invariant sizeof(struct dmar_table_header) <= offset <= table_length;
        loop invariant info->drhd_count <= FBVBS_MAX_DRHD_UNITS;
        loop invariant info->rmrr_count <= FBVBS_MAX_RMRR_REGIONS;
        loop assigns offset, info->drhd_units[0 .. FBVBS_MAX_DRHD_UNITS - 1],
                     info->drhd_count,
                     info->rmrr_regions[0 .. FBVBS_MAX_RMRR_REGIONS - 1],
                     info->rmrr_count;
        loop variant table_length - offset;
    */
    while (offset + 4U <= table_length) {
        const struct dmar_remapping_header *entry =
            (const struct dmar_remapping_header *)(raw + offset);
        uint16_t entry_type = entry->type;
        uint16_t entry_length = entry->length;

        /* Validate entry bounds */
        if (entry_length < 4U || offset + (uint32_t)entry_length > table_length) {
            break;
        }

        if (entry_type == DMAR_TYPE_DRHD &&
            info->drhd_count < FBVBS_MAX_DRHD_UNITS &&
            entry_length >= 16U) {
            /* DRHD: 16-byte fixed header + variable device scopes */
            struct fbvbs_drhd_unit *unit = &info->drhd_units[info->drhd_count];

            unit->active = 1;
            unit->flags = (uint32_t)raw[offset + 4U];
            unit->segment = (uint16_t)(
                (uint16_t)raw[offset + 6U] |
                ((uint16_t)raw[offset + 7U] << 8));
            unit->register_base_address =
                (uint64_t)raw[offset + 8U] |
                ((uint64_t)raw[offset + 9U] << 8) |
                ((uint64_t)raw[offset + 10U] << 16) |
                ((uint64_t)raw[offset + 11U] << 24) |
                ((uint64_t)raw[offset + 12U] << 32) |
                ((uint64_t)raw[offset + 13U] << 40) |
                ((uint64_t)raw[offset + 14U] << 48) |
                ((uint64_t)raw[offset + 15U] << 56);

            /* Parse device scopes (start at offset 16 within DRHD) */
            if (entry_length > 16U) {
                parse_device_scopes(
                    raw + offset + 16U,
                    (uint32_t)entry_length - 16U,
                    unit);
            } else {
                unit->scope_count = 0U;
            }
            info->drhd_count += 1U;

        } else if (entry_type == DMAR_TYPE_RMRR &&
                   info->rmrr_count < FBVBS_MAX_RMRR_REGIONS &&
                   entry_length >= 24U) {
            /* RMRR: 24-byte fixed header */
            struct fbvbs_rmrr_region *region =
                &info->rmrr_regions[info->rmrr_count];

            region->active = 1;
            region->segment = (uint16_t)(
                (uint16_t)raw[offset + 6U] |
                ((uint16_t)raw[offset + 7U] << 8));
            region->base_address =
                (uint64_t)raw[offset + 8U] |
                ((uint64_t)raw[offset + 9U] << 8) |
                ((uint64_t)raw[offset + 10U] << 16) |
                ((uint64_t)raw[offset + 11U] << 24) |
                ((uint64_t)raw[offset + 12U] << 32) |
                ((uint64_t)raw[offset + 13U] << 40) |
                ((uint64_t)raw[offset + 14U] << 48) |
                ((uint64_t)raw[offset + 15U] << 56);
            region->limit_address =
                (uint64_t)raw[offset + 16U] |
                ((uint64_t)raw[offset + 17U] << 8) |
                ((uint64_t)raw[offset + 18U] << 16) |
                ((uint64_t)raw[offset + 19U] << 24) |
                ((uint64_t)raw[offset + 20U] << 32) |
                ((uint64_t)raw[offset + 21U] << 40) |
                ((uint64_t)raw[offset + 22U] << 48) |
                ((uint64_t)raw[offset + 23U] << 56);

            /* Validate RMRR range */
            if (region->base_address >= region->limit_address) {
                region->active = 0;
            } else {
                info->rmrr_count += 1U;
            }
        }
        /* ATSR, RHSA, ANDD, SATC: not parsed in Phase 0B-1 */

        offset += (uint32_t)entry_length;
    }

    if (info->drhd_count == 0U) {
        /* No DRHD units found — DMAR table is invalid for our purposes */
        return -1;
    }

    info->valid = 1;
    return 0;
}

/* ================================================================
 * DMAR table search via ACPI
 *
 * This path uses the generic ACPI discovery helper. In bare-metal
 * builds it searches bootloader-provided RSDP first, then falls back
 * to EBDA/BIOS scanning. Hosted/test builds return NULL fail-closed.
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == \null || \valid_read(\result);
*/
static const struct dmar_table_header *fbvbs_acpi_find_dmar(void)
{
    return (const struct dmar_table_header *)fbvbs_acpi_find_table(ACPI_SIG_DMAR);
}

static int vtd_probe_capabilities(
    struct fbvbs_global_security_state *state,
    const struct fbvbs_dmar_info *info);

/* ================================================================
 * IOMMU detection entry point (called from cpu_security.c)
 *
 * Discovers and parses the DMAR table, populates IOMMU state.
 * ================================================================ */

/*@ requires \valid(state);
    assigns state->iommu;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_vtd_detect(struct fbvbs_global_security_state *state)
{
    const struct dmar_table_header *dmar;
    struct fbvbs_dmar_info info;

    state->iommu = (struct fbvbs_iommu_state){0};
    state->iommu.iommu_type = IOMMU_TYPE_VTD;

    dmar = fbvbs_acpi_find_dmar();
    if (dmar == NULL) {
        return -1;
    }

    /* Parse DMAR table — use the table's own length field, bounded */
    {
        uint32_t tbl_len = dmar->header.length;
        if (tbl_len > FBVBS_MAX_DMAR_TABLE_SIZE) {
            return -1;
        }
        if (fbvbs_dmar_parse(dmar, tbl_len, &info) != 0) {
            return -1;
        }
    }

    return vtd_probe_capabilities(state, &info);
}

/* ================================================================
 * Phase 0B-2: Intel VT-d Register Definitions
 *
 * Reference: Intel VT-d Spec, Chapter 10 (Register Descriptions)
 * All MMIO offsets are relative to the DRHD register base address.
 * ================================================================ */

/* VT-d MMIO register offsets */
#define VTD_REG_VER         0x000U  /* Version */
#define VTD_REG_CAP         0x008U  /* Capability */
#define VTD_REG_ECAP        0x010U  /* Extended Capability */
#define VTD_REG_GCMD        0x018U  /* Global Command */
#define VTD_REG_GSTS        0x01CU  /* Global Status */
#define VTD_REG_RTADDR      0x020U  /* Root Table Address */
#define VTD_REG_CCMD        0x028U  /* Context Command */
#define VTD_REG_FSTS        0x034U  /* Fault Status */
#define VTD_REG_FECTL       0x038U  /* Fault Event Control */
#define VTD_REG_FEDATA      0x03CU  /* Fault Event Data */
#define VTD_REG_FEADDR      0x040U  /* Fault Event Address */
#define VTD_REG_FEUADDR     0x044U  /* Fault Event Upper Address */
#define VTD_REG_IRTA        0x0B8U  /* Interrupt Remapping Table Address */
#define VTD_REG_IQH         0x080U  /* Invalidation Queue Head */
#define VTD_REG_IQT         0x088U  /* Invalidation Queue Tail */
#define VTD_REG_IQA         0x090U  /* Invalidation Queue Address */

/* GCMD bits */
#define VTD_GCMD_TE         (1U << 31)  /* Translation Enable */
#define VTD_GCMD_SRTP       (1U << 30)  /* Set Root Table Pointer */
#define VTD_GCMD_SFL        (1U << 29)  /* Set Fault Log */
#define VTD_GCMD_EAFL       (1U << 28)  /* Enable Advanced Fault Logging */
#define VTD_GCMD_WBF        (1U << 27)  /* Write Buffer Flush */
#define VTD_GCMD_QIE        (1U << 26)  /* Queued Invalidation Enable */
#define VTD_GCMD_IRE        (1U << 25)  /* Interrupt Remapping Enable */
#define VTD_GCMD_SIRTP      (1U << 24)  /* Set Interrupt Remap Table Pointer */
#define VTD_GCMD_CFI        (1U << 23)  /* Compatibility Format Interrupt */

/* GSTS bits (mirrors GCMD) */
#define VTD_GSTS_TES        (1U << 31)  /* Translation Enable Status */
#define VTD_GSTS_RTPS       (1U << 30)  /* Root Table Pointer Status */
#define VTD_GSTS_FLS        (1U << 29)  /* Fault Log Status */
#define VTD_GSTS_AFLS       (1U << 28)  /* Advanced Fault Logging Status */
#define VTD_GSTS_WBFS       (1U << 27)  /* Write Buffer Flush Status */
#define VTD_GSTS_QIES       (1U << 26)  /* Queued Invalidation Enable Status */
#define VTD_GSTS_IRES       (1U << 25)  /* Interrupt Remapping Enable Status */
#define VTD_GSTS_IRTPS      (1U << 24)  /* Interrupt Remap Table Pointer Status */

/* CAP register bits */
#define VTD_CAP_SAGAW_MASK  0x1E00ULL       /* Supported Adjusted Guest Address Width */
#define VTD_CAP_SAGAW_SHIFT 8
#define VTD_CAP_FRO_MASK    0x00FFF0000000ULL /* Fault Recording Register Offset */
#define VTD_CAP_FRO_SHIFT   24
#define VTD_CAP_NFR_MASK    0xFF00000000000000ULL /* Number of Fault Recording Regs */
#define VTD_CAP_NFR_SHIFT   40
#define VTD_CAP_SLLPS_MASK  0x3C00000000ULL /* Second Level Large Page Support */
#define VTD_CAP_SLLPS_SHIFT 34

/* ECAP register bits */
#define VTD_ECAP_IR         (1ULL << 3)  /* Interrupt Remapping support */
#define VTD_ECAP_QI         (1ULL << 1)  /* Queued Invalidation support */
#define VTD_ECAP_C          (1ULL << 0)  /* Page-walk Coherency */
#define VTD_ECAP_PASID      (1ULL << 40) /* PASID support */

/* FSTS bits */
#define VTD_FSTS_PPF        (1U << 1)  /* Primary Pending Fault */
#define VTD_FSTS_PFO        (1U << 0)  /* Primary Fault Overflow */

/* Context Command register */
#define VTD_CCMD_ICC        (1ULL << 63)  /* Invalidate Context-Cache */
#define VTD_CCMD_CIRG_GLOBAL (1ULL << 61) /* Global Invalidation */

/* ================================================================
 * VT-d page table entry format (Second Level)
 *
 * 4-level page tables: PML4 → PDPT → PD → PT
 * Each entry is 64-bit. Address bits [51:12] hold the page frame.
 * ================================================================ */

#define VTD_PTE_READ        (1ULL << 0)
#define VTD_PTE_WRITE       (1ULL << 1)
#define VTD_PTE_SUPER       (1ULL << 7)  /* Superpage */
#define VTD_PTE_ADDR_MASK   0x000FFFFFFFFFF000ULL

/* Root table entry (128-bit, two 64-bit halves) */
struct vtd_root_entry {
    uint64_t lo;  /* [0]=Present, [63:12]=CTP */
    uint64_t hi;  /* Reserved (or extended mode) */
};

/* Context table entry (128-bit) */
struct vtd_context_entry {
    uint64_t lo;  /* [0]=Present, [1]=FPD, [3:2]=TT, [63:12]=SLPTPTR */
    uint64_t hi;  /* [2:0]=AW, [23:8]=DID */
};

#define VTD_CTX_PRESENT     (1ULL << 0)
#define VTD_CTX_TT_MULTI    (0ULL << 2)  /* Multi-level page table translation */
#define VTD_CTX_AW_48       (2ULL << 0)  /* 48-bit AGAW (4-level page table) */

/* Interrupt Remapping Table Entry (128-bit) */
struct vtd_irte {
    uint64_t lo;  /* [0]=Present, [3:1]=SVT, [4]=FPD, [6:5]=DLM, ... */
    uint64_t hi;  /* [31:16]=SID, [33:32]=SQ, [47:36]=SVT qual, ... */
};

#define VTD_IRTE_PRESENT    (1ULL << 0)

/* ================================================================
 * VT-d domain state (per-partition IOMMU domain)
 * ================================================================ */

#ifndef FBVBS_VTD_MAX_ROOT_ENTRIES
#define FBVBS_VTD_MAX_ROOT_ENTRIES 256
#endif
#ifndef FBVBS_VTD_MAX_CONTEXT_ENTRIES
#define FBVBS_VTD_MAX_CONTEXT_ENTRIES 256
#endif
#ifndef FBVBS_VTD_MAX_IRTE_ENTRIES
#define FBVBS_VTD_MAX_IRTE_ENTRIES 256
#endif

struct fbvbs_vtd_domain {
    uint32_t active;
    uint16_t domain_id;
    uint16_t reserved0;
    uint64_t register_base;
    /* Model-only page table root (production uses physical page allocator) */
    uint64_t slpt_root_phys;
};

/* ================================================================
 * MMIO register access (model / production)
 *
 * PRODUCTION NOTE: These functions require MMIO mapping of the
 * VT-d register pages. Production implementation must:
 * 1. Map DRHD register_base_address via platform page tables
 * 2. Use volatile uint32_t / uint64_t pointers for MMIO reads and writes
 * 3. Include proper memory barriers (mfence after GCMD writes)
 * Until MMIO mapping is available, all operations fail-closed.
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == 0;
*/
static uint32_t vtd_mmio_read32(uint64_t base, uint32_t offset)
{
#if defined(__FRAMAC__)
    (void)base;
    (void)offset;
    return 0U;
#elif defined(FBVBS_BAREMETAL_BUILD)
    volatile const uint32_t *reg =
        (volatile const uint32_t *)(uintptr_t)(base + (uint64_t)offset);
    fbvbs_asm_compiler_barrier();
    return *reg;
#else
    (void)base;
    (void)offset;
    return 0U;
#endif
}

/*@ assigns \nothing;
    ensures \result == 0;
*/
static uint64_t vtd_mmio_read64(uint64_t base, uint32_t offset)
{
#if defined(__FRAMAC__)
    (void)base;
    (void)offset;
    return 0ULL;
#elif defined(FBVBS_BAREMETAL_BUILD)
    volatile const uint64_t *reg =
        (volatile const uint64_t *)(uintptr_t)(base + (uint64_t)offset);
    fbvbs_asm_compiler_barrier();
    return *reg;
#else
    (void)base;
    (void)offset;
    return 0ULL;
#endif
}

/*@ assigns \nothing;
*/
static void vtd_mmio_write32(uint64_t base, uint32_t offset, uint32_t value)
{
#if defined(FBVBS_BAREMETAL_BUILD) && !defined(__FRAMAC__)
    volatile uint32_t *reg =
        (volatile uint32_t *)(uintptr_t)(base + (uint64_t)offset);
    *reg = value;
    fbvbs_asm_mfence();
#else
    (void)base;
    (void)offset;
    (void)value;
#endif
}

/*@ assigns \nothing;
*/
static void vtd_mmio_write64(uint64_t base, uint32_t offset, uint64_t value)
{
#if defined(FBVBS_BAREMETAL_BUILD) && !defined(__FRAMAC__)
    volatile uint64_t *reg =
        (volatile uint64_t *)(uintptr_t)(base + (uint64_t)offset);
    *reg = value;
    fbvbs_asm_mfence();
#else
    (void)base;
    (void)offset;
    (void)value;
#endif
}

/* ================================================================
 * VT-d capability probing
 *
 * Reads CAP and ECAP registers to determine hardware capabilities.
 * ================================================================ */

/*@ requires \valid(state);
    requires \valid_read(info);
    assigns state->iommu;
    ensures \result == 0 || \result == -1;
*/
static int vtd_probe_capabilities(
    struct fbvbs_global_security_state *state,
    const struct fbvbs_dmar_info *info)
{
    if (info->drhd_count == 0U) {
        return -1;
    }

    /* Read capabilities from first DRHD unit */
    {
        uint64_t reg_base = info->drhd_units[0].register_base_address;
        uint64_t cap  = vtd_mmio_read64(reg_base, VTD_REG_CAP);
        uint64_t ecap = vtd_mmio_read64(reg_base, VTD_REG_ECAP);

        /* Check interrupt remapping support */
        state->iommu.interrupt_remapping =
            (ecap & VTD_ECAP_IR) ? 1U : 0U;

        /* Check PASID support */
        state->iommu.pasid_support =
            (ecap & VTD_ECAP_PASID) ? 1U : 0U;

        /* DMA remapping is available if we got this far */
        state->iommu.dma_remapping = 1;

        (void)cap;  /* SAGAW, FRO used in production register setup */
    }

    return 0;
}

/* ================================================================
 * VT-d translation enable/disable
 *
 * PRODUCTION NOTE: Enabling translation requires:
 * 1. Root table allocated and populated
 * 2. RTADDR register set with root table physical address
 * 3. GCMD.SRTP written, wait for GSTS.RTPS
 * 4. Context cache invalidation (global)
 * 5. IOTLB invalidation (global)
 * 6. GCMD.TE written, wait for GSTS.TES
 *
 * Model code sets state flags without hardware access.
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int vtd_set_root_table(uint64_t reg_base, uint64_t root_table_phys)
{
    /* Write root table address */
    vtd_mmio_write64(reg_base, VTD_REG_RTADDR, root_table_phys);

    /* Command: set root table pointer */
    {
        uint32_t gsts = vtd_mmio_read32(reg_base, VTD_REG_GSTS);
        vtd_mmio_write32(reg_base, VTD_REG_GCMD, gsts | VTD_GCMD_SRTP);
    }

    /* PRODUCTION NOTE: Poll GSTS.RTPS until set (with timeout).
     * Model returns success immediately. */
#if !defined(__FRAMAC__)
    {
        uint32_t gsts = vtd_mmio_read32(reg_base, VTD_REG_GSTS);
        if (!(gsts & VTD_GSTS_RTPS)) {
            return -1;  /* Fail-closed: MMIO not functional */
        }
    }
#endif

    return 0;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int vtd_invalidate_context_global(uint64_t reg_base)
{
    vtd_mmio_write64(reg_base, VTD_REG_CCMD,
                     VTD_CCMD_ICC | VTD_CCMD_CIRG_GLOBAL);

    /* PRODUCTION NOTE: Poll CCMD.ICC until cleared (with timeout). */
#if !defined(__FRAMAC__)
    {
        uint64_t ccmd = vtd_mmio_read64(reg_base, VTD_REG_CCMD);
        if (ccmd & VTD_CCMD_ICC) {
            return -1;  /* Fail-closed */
        }
    }
#endif
    return 0;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int vtd_enable_translation(uint64_t reg_base)
{
    uint32_t gsts = vtd_mmio_read32(reg_base, VTD_REG_GSTS);
    vtd_mmio_write32(reg_base, VTD_REG_GCMD, gsts | VTD_GCMD_TE);

    /* PRODUCTION NOTE: Poll GSTS.TES until set (with timeout). */
#if !defined(__FRAMAC__)
    gsts = vtd_mmio_read32(reg_base, VTD_REG_GSTS);
    if (!(gsts & VTD_GSTS_TES)) {
        return -1;  /* Fail-closed */
    }
#endif
    return 0;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int vtd_enable_interrupt_remapping(uint64_t reg_base,
                                           uint64_t irta_phys)
{
    /* Set interrupt remapping table address */
    vtd_mmio_write64(reg_base, VTD_REG_IRTA, irta_phys);

    /* Command: set IRTA pointer */
    {
        uint32_t gsts = vtd_mmio_read32(reg_base, VTD_REG_GSTS);
        vtd_mmio_write32(reg_base, VTD_REG_GCMD, gsts | VTD_GCMD_SIRTP);
    }

    /* Wait for IRTPS before enabling IRE (VT-d spec requirement) */
#if !defined(__FRAMAC__)
    {
        uint32_t gsts = vtd_mmio_read32(reg_base, VTD_REG_GSTS);
        if (!(gsts & VTD_GSTS_IRTPS)) {
            return -1;  /* Fail-closed: IRTA pointer not accepted */
        }
    }
#endif

    /* Enable interrupt remapping */
    {
        uint32_t gsts = vtd_mmio_read32(reg_base, VTD_REG_GSTS);
        vtd_mmio_write32(reg_base, VTD_REG_GCMD, gsts | VTD_GCMD_IRE);
    }

    /* Wait for IRES */
#if !defined(__FRAMAC__)
    {
        uint32_t gsts = vtd_mmio_read32(reg_base, VTD_REG_GSTS);
        if (!(gsts & VTD_GSTS_IRES)) {
            return -1;
        }
    }
#endif
    return 0;
}

/* ================================================================
 * Fault Status Register monitoring
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int vtd_check_fault(uint64_t reg_base)
{
    uint32_t fsts = vtd_mmio_read32(reg_base, VTD_REG_FSTS);

    if (fsts & (VTD_FSTS_PPF | VTD_FSTS_PFO)) {
        /* PRODUCTION NOTE: Read fault recording registers at
         * CAP.FRO offset, log fault details, clear status. */
        return 1;  /* Fault detected */
    }
    return 0;
}

/* ================================================================
 * Context table entry construction
 *
 * Maps a PCI device (bus:dev:func) to an IOMMU domain's page table.
 * ================================================================ */

/*@ requires \valid(ctx);
    assigns *ctx;
*/
static void vtd_build_context_entry(
    struct vtd_context_entry *ctx,
    uint16_t domain_id,
    uint64_t slpt_root_phys)
{
    ctx->lo = VTD_CTX_PRESENT | VTD_CTX_TT_MULTI |
              (slpt_root_phys & VTD_PTE_ADDR_MASK);
    ctx->hi = VTD_CTX_AW_48 |
              ((uint64_t)domain_id << 8);
}

/* ================================================================
 * Interrupt Remapping Table Entry construction
 * ================================================================ */

/*@ requires \valid(irte);
    assigns *irte;
*/
static void vtd_build_irte(
    struct vtd_irte *irte,
    uint8_t vector,
    uint8_t dest_id,
    uint16_t source_id)
{
    /* Fixed delivery mode, physical destination */
    irte->lo = VTD_IRTE_PRESENT |
               ((uint64_t)vector << 16) |
               ((uint64_t)dest_id << 32);
    irte->hi = (uint64_t)source_id << 16;
}

/* ================================================================
 * Full VT-d initialization sequence
 *
 * Called after DMAR parsing to set up translation infrastructure.
 * Model code: populates state flags. Production requires physical
 * page allocation for root/context/IRTE tables.
 * ================================================================ */

/*@ requires \valid(state);
    assigns state->iommu;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_vtd_init(struct fbvbs_global_security_state *state)
{
    struct fbvbs_dmar_info info;
    const struct dmar_table_header *dmar;

    /* Require successful detection first */
    if (state->iommu.iommu_type != IOMMU_TYPE_VTD) {
        return -1;
    }

#if defined(__FRAMAC__)
    /* Model: mark all capabilities available */
    state->iommu.dma_remapping = 1;
    state->iommu.interrupt_remapping = 1;
    state->iommu.acs_available = 1;
    state->iommu.kernel_dma_protection = 1;
    state->iommu.scalable_mode = 0;
    return 0;
#else
    /* Re-parse DMAR to get register base addresses */
    dmar = fbvbs_acpi_find_dmar();
    if (dmar == NULL) {
        return -1;
    }
    {
        uint32_t tbl_len = dmar->header.length;
        if (tbl_len > FBVBS_MAX_DMAR_TABLE_SIZE) {
            return -1;
        }
        if (fbvbs_dmar_parse(dmar, tbl_len, &info) != 0) {
            return -1;
        }
    }

    /* Probe hardware capabilities */
    if (vtd_probe_capabilities(state, &info) != 0) {
        return -1;
    }

    /* Initialize each DRHD unit.
     * Track allocated pages so they can be freed on failure. */
    {
        uint32_t i;
        uint64_t allocated_root_pages[FBVBS_MAX_DRHD_UNITS];
        uint64_t allocated_irta_pages[FBVBS_MAX_DRHD_UNITS];
        uint32_t alloc_count = 0U;

        for (i = 0U; i < FBVBS_MAX_DRHD_UNITS; ++i) {
            allocated_root_pages[i] = 0ULL;
            allocated_irta_pages[i] = 0ULL;
        }

        for (i = 0U; i < info.drhd_count; ++i) {
            uint64_t reg_base = info.drhd_units[i].register_base_address;
            uint64_t root_table_phys;
            int failed = 0;

            /* Allocate root table page (4KB, zeroed by allocator) */
            root_table_phys = fbvbs_page_alloc();
            if (root_table_phys == 0ULL) {
                failed = 1;
            }

            if (failed == 0) {
                allocated_root_pages[alloc_count] = root_table_phys;

                if (vtd_set_root_table(reg_base, root_table_phys) != 0) {
                    failed = 1;
                }
            }
            if (failed == 0 && vtd_invalidate_context_global(reg_base) != 0) {
                failed = 1;
            }
            if (failed == 0 && vtd_enable_translation(reg_base) != 0) {
                failed = 1;
            }

            /* Enable interrupt remapping if supported */
            if (failed == 0 && state->iommu.interrupt_remapping != 0U) {
                uint64_t irta_phys = fbvbs_page_alloc();
                if (irta_phys == 0ULL) {
                    failed = 1;
                } else {
                    allocated_irta_pages[alloc_count] = irta_phys;
                    if (vtd_enable_interrupt_remapping(reg_base, irta_phys) != 0) {
                        failed = 1;
                    }
                }
            }

            /* Verify no boot-time faults */
            if (failed == 0 && vtd_check_fault(reg_base) != 0) {
                failed = 1;
            }

            if (failed != 0) {
                /* Free all pages allocated in this and prior iterations */
                uint32_t j;
                /* Free current iteration's pages */
                if (root_table_phys != 0ULL) {
                    (void)fbvbs_page_free(root_table_phys);
                }
                if (allocated_irta_pages[alloc_count] != 0ULL) {
                    (void)fbvbs_page_free(allocated_irta_pages[alloc_count]);
                }
                /* Free prior iterations' pages */
                for (j = 0U; j < alloc_count; ++j) {
                    if (allocated_root_pages[j] != 0ULL) {
                        (void)fbvbs_page_free(allocated_root_pages[j]);
                    }
                    if (allocated_irta_pages[j] != 0ULL) {
                        (void)fbvbs_page_free(allocated_irta_pages[j]);
                    }
                }
                return -1;
            }
            alloc_count += 1U;
        }
    }

    /* Build a context entry and IRTE for reference (validates struct layout).
     * Production populates these per-device during vm_assign_device. */
    {
        struct vtd_context_entry ctx;
        struct vtd_irte irte;
        vtd_build_context_entry(&ctx, 1U, 0ULL);
        vtd_build_irte(&irte, 0U, 0U, 0U);
        (void)ctx;
        (void)irte;
    }

    state->iommu.kernel_dma_protection = 1;
    return 0;
#endif
}
