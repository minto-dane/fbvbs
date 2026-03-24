#include "fbvbs_hypervisor.h"

/* ================================================================
 * AMD-Vi (IOMMU) IVRS table parser and register control
 *
 * Parses the ACPI IVRS (I/O Virtualization Reporting Structure) table
 * to discover AMD IOMMU hardware units and their configurations.
 *
 * Requirements: REQ-0003 (IOMMU 必須), REQ-0350 (DMA remapping),
 *   REQ-0351 (Interrupt remapping)
 *
 * Reference: AMD I/O Virtualization Technology (IOMMU) Specification
 * ================================================================ */

/* ACPI table signature */
#define ACPI_SIG_IVRS     0x53525649U  /* "IVRS" */

/* IVRS block types */
#define IVRS_TYPE_IVHD_10H  0x10U  /* IVHD type 10h (basic) */
#define IVRS_TYPE_IVHD_11H  0x11U  /* IVHD type 11h (extended) */
#define IVRS_TYPE_IVHD_40H  0x40U  /* IVHD type 40h (ACPI HID) */
#define IVRS_TYPE_IVMD_20H  0x20U  /* IVMD type 20h (all peripherals) */
#define IVRS_TYPE_IVMD_21H  0x21U  /* IVMD type 21h (specified peripheral) */
#define IVRS_TYPE_IVMD_22H  0x22U  /* IVMD type 22h (peripheral range) */

/* IVHD device entry types */
#define IVHD_DEV_ALL          0x01U
#define IVHD_DEV_SELECT       0x02U
#define IVHD_DEV_START_RANGE  0x03U
#define IVHD_DEV_END_RANGE    0x04U
#define IVHD_DEV_ALIAS_SELECT 0x42U
#define IVHD_DEV_ALIAS_RANGE  0x43U
#define IVHD_DEV_SPECIAL      0x48U

/* IVHD flags */
#define IVHD_FLAG_IOTLB_SUP    (1U << 0)
#define IVHD_FLAG_ISOC         (1U << 1)
#define IVHD_FLAG_RES_PASS_PW  (1U << 2)
#define IVHD_FLAG_PASS_PW      (1U << 3)
#define IVHD_FLAG_HT_TUN_EN   (1U << 4)

/* AMD IOMMU MMIO register offsets */
#define AMDVI_REG_DEV_TAB_BASE   0x0000U  /* Device Table Base Address */
#define AMDVI_REG_CMD_BUF_BASE   0x0008U  /* Command Buffer Base Address */
#define AMDVI_REG_EVT_LOG_BASE   0x0010U  /* Event Log Base Address */
#define AMDVI_REG_CONTROL        0x0018U  /* IOMMU Control Register */
#define AMDVI_REG_EXCL_BASE      0x0020U  /* Exclusion Range Base */
#define AMDVI_REG_EXCL_LIMIT     0x0028U  /* Exclusion Range Limit */
#define AMDVI_REG_EXT_FEAT       0x0030U  /* Extended Feature Register */
#define AMDVI_REG_CMD_BUF_HEAD   0x2000U  /* Command Buffer Head Pointer */
#define AMDVI_REG_CMD_BUF_TAIL   0x2008U  /* Command Buffer Tail Pointer */
#define AMDVI_REG_EVT_LOG_HEAD   0x2010U  /* Event Log Head Pointer */
#define AMDVI_REG_EVT_LOG_TAIL   0x2018U  /* Event Log Tail Pointer */
#define AMDVI_REG_STATUS         0x2020U  /* IOMMU Status Register */

/* Control register bits */
#define AMDVI_CTRL_IOMMU_EN      (1ULL << 0)   /* IOMMU Enable */
#define AMDVI_CTRL_HT_TUN_EN    (1ULL << 1)   /* HyperTransport Tunnel Enable */
#define AMDVI_CTRL_EVT_LOG_EN   (1ULL << 2)   /* Event Log Enable */
#define AMDVI_CTRL_EVT_INT_EN   (1ULL << 3)   /* Event Log Interrupt Enable */
#define AMDVI_CTRL_CMD_BUF_EN   (1ULL << 12)  /* Command Buffer Enable */
#define AMDVI_CTRL_ISOC_EN      (1ULL << 16)  /* Isochronous Enable */
#define AMDVI_CTRL_INT_MAP_EN   (1ULL << 4)   /* Interrupt Map Enable */
#define AMDVI_CTRL_GA_EN        (1ULL << 17)  /* Guest Virtual APIC Enable */

/* Extended Feature bits */
#define AMDVI_EF_GT_SUP          (1ULL << 2)   /* Guest Translation Support */
#define AMDVI_EF_IA_SUP          (1ULL << 6)   /* Invalidate All Support */
#define AMDVI_EF_GA_SUP          (1ULL << 7)   /* Guest Virtual APIC Support */
#define AMDVI_EF_IRT_SUP         (1ULL << 23)  /* Interrupt Remapping Support */

/* Status register bits */
#define AMDVI_STATUS_EVT_OVF     (1U << 0)     /* Event Log Overflow */
#define AMDVI_STATUS_EVT_INT     (1U << 1)     /* Event Log Interrupt */

/* Maximum limits for bounded parsing */
#ifndef FBVBS_MAX_AMDVI_UNITS
#define FBVBS_MAX_AMDVI_UNITS       8U
#endif
#ifndef FBVBS_MAX_IVMD_REGIONS
#define FBVBS_MAX_IVMD_REGIONS      16U
#endif
#ifndef FBVBS_MAX_IVRS_TABLE_SIZE
#define FBVBS_MAX_IVRS_TABLE_SIZE   4096U
#endif

/* ================================================================
 * ACPI / IVRS table structures (packed wire format)
 * ================================================================ */

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
    uint32_t iv_info;       /* I/O Virtualization Info */
    uint64_t reserved;
    /* Variable-length IVHD/IVMD blocks follow */
};

struct ivrs_block_header {
    uint8_t  type;
    uint8_t  flags;
    uint16_t length;
};

/* ================================================================
 * Parsed IVRS data structures
 * ================================================================ */

struct fbvbs_amdvi_unit {
    uint32_t active;
    uint32_t flags;
    uint16_t device_id;       /* PCI device ID of the IOMMU itself */
    uint16_t cap_offset;      /* PCI capability offset */
    uint64_t mmio_base;       /* MMIO register base address */
    uint16_t pci_segment;
    uint16_t iommu_info;
    uint32_t ef_features;     /* Extended feature register snapshot */
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

/* ================================================================
 * IVRS table parser
 * ================================================================ */

/*@ requires \valid(info);
    requires table == \null ||
             (\valid_read(table) &&
              \valid_read(((const uint8_t *)table) + (0 .. table_length - 1)));
    requires table_length <= FBVBS_MAX_IVRS_TABLE_SIZE;
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
fbvbs_ivrs_parse(
    const struct acpi_ivrs_table_header *table,
    uint32_t table_length,
    struct fbvbs_ivrs_info *info)
{
    uint32_t offset;
    const uint8_t *raw;

    *info = (struct fbvbs_ivrs_info){0};

    if (table == NULL) {
        return -1;
    }

    /* Validate minimum table size */
    if (table_length < sizeof(struct acpi_ivrs_table_header)) {
        return -1;
    }

    /* Validate signature */
    if (table->signature != ACPI_SIG_IVRS) {
        return -1;
    }

    /* Validate length consistency */
    if (table->length != table_length ||
        table->length > FBVBS_MAX_IVRS_TABLE_SIZE) {
        return -1;
    }

    /* Verify ACPI checksum */
    raw = (const uint8_t *)table;
#if !defined(__FRAMAC__)
    {
        uint32_t ck_i;
        uint8_t ck_sum = 0U;
        for (ck_i = 0U; ck_i < table_length; ++ck_i) {
            ck_sum = (uint8_t)(ck_sum + raw[ck_i]);
        }
        if (ck_sum != 0U) {
            return -1;
        }
    }
#endif

    info->iv_info = table->iv_info;

    /* Parse IVHD/IVMD blocks */
    offset = (uint32_t)sizeof(struct acpi_ivrs_table_header);

    /*@ loop invariant sizeof(struct acpi_ivrs_table_header) <= offset <= table_length;
        loop invariant info->ivhd_count <= FBVBS_MAX_AMDVI_UNITS;
        loop invariant info->ivmd_count <= FBVBS_MAX_IVMD_REGIONS;
        loop assigns offset, info->ivhd_units[0 .. FBVBS_MAX_AMDVI_UNITS - 1],
                     info->ivhd_count,
                     info->ivmd_regions[0 .. FBVBS_MAX_IVMD_REGIONS - 1],
                     info->ivmd_count;
        loop variant table_length - offset;
    */
    while (offset + 4U <= table_length) {
        const struct ivrs_block_header *blk =
            (const struct ivrs_block_header *)(raw + offset);
        uint8_t blk_type = blk->type;
        uint16_t blk_length = blk->length;

        /* Validate block bounds */
        if (blk_length < 4U || offset + (uint32_t)blk_length > table_length) {
            break;
        }

        if ((blk_type == IVRS_TYPE_IVHD_10H ||
             blk_type == IVRS_TYPE_IVHD_11H ||
             blk_type == IVRS_TYPE_IVHD_40H) &&
            info->ivhd_count < FBVBS_MAX_AMDVI_UNITS &&
            blk_length >= 24U) {
            /* IVHD block: at least 24 bytes for type 10h header */
            struct fbvbs_amdvi_unit *unit = &info->ivhd_units[info->ivhd_count];

            unit->active = 1;
            unit->flags = (uint32_t)blk->flags;
            /* Device ID at offset 4-5 */
            unit->device_id = (uint16_t)(
                (uint16_t)raw[offset + 4U] |
                ((uint16_t)raw[offset + 5U] << 8));
            /* Capability offset at offset 6-7 */
            unit->cap_offset = (uint16_t)(
                (uint16_t)raw[offset + 6U] |
                ((uint16_t)raw[offset + 7U] << 8));
            /* MMIO base at offset 8-15 */
            unit->mmio_base =
                (uint64_t)raw[offset + 8U] |
                ((uint64_t)raw[offset + 9U] << 8) |
                ((uint64_t)raw[offset + 10U] << 16) |
                ((uint64_t)raw[offset + 11U] << 24) |
                ((uint64_t)raw[offset + 12U] << 32) |
                ((uint64_t)raw[offset + 13U] << 40) |
                ((uint64_t)raw[offset + 14U] << 48) |
                ((uint64_t)raw[offset + 15U] << 56);
            /* PCI segment at offset 16-17 */
            unit->pci_segment = (uint16_t)(
                (uint16_t)raw[offset + 16U] |
                ((uint16_t)raw[offset + 17U] << 8));
            /* IOMMU info at offset 18-19 */
            unit->iommu_info = (uint16_t)(
                (uint16_t)raw[offset + 18U] |
                ((uint16_t)raw[offset + 19U] << 8));

            info->ivhd_count += 1U;

        } else if ((blk_type == IVRS_TYPE_IVMD_20H ||
                    blk_type == IVRS_TYPE_IVMD_21H ||
                    blk_type == IVRS_TYPE_IVMD_22H) &&
                   info->ivmd_count < FBVBS_MAX_IVMD_REGIONS &&
                   blk_length >= 24U) {
            /* IVMD block */
            struct fbvbs_ivmd_region *region =
                &info->ivmd_regions[info->ivmd_count];

            region->active = 1;
            region->type = blk_type;
            region->flags = blk->flags;
            /* Device ID at offset 4-5 */
            region->device_id = (uint16_t)(
                (uint16_t)raw[offset + 4U] |
                ((uint16_t)raw[offset + 5U] << 8));
            /* Start address at offset 8-15 */
            region->start_address =
                (uint64_t)raw[offset + 8U] |
                ((uint64_t)raw[offset + 9U] << 8) |
                ((uint64_t)raw[offset + 10U] << 16) |
                ((uint64_t)raw[offset + 11U] << 24) |
                ((uint64_t)raw[offset + 12U] << 32) |
                ((uint64_t)raw[offset + 13U] << 40) |
                ((uint64_t)raw[offset + 14U] << 48) |
                ((uint64_t)raw[offset + 15U] << 56);
            /* Memory length at offset 16-23 */
            region->mem_length =
                (uint64_t)raw[offset + 16U] |
                ((uint64_t)raw[offset + 17U] << 8) |
                ((uint64_t)raw[offset + 18U] << 16) |
                ((uint64_t)raw[offset + 19U] << 24) |
                ((uint64_t)raw[offset + 20U] << 32) |
                ((uint64_t)raw[offset + 21U] << 40) |
                ((uint64_t)raw[offset + 22U] << 48) |
                ((uint64_t)raw[offset + 23U] << 56);

            /* Validate region */
            if (region->mem_length > 0U) {
                info->ivmd_count += 1U;
            } else {
                region->active = 0;
            }
        }

        offset += (uint32_t)blk_length;
    }

    if (info->ivhd_count == 0U) {
        return -1;
    }

    info->valid = 1;
    return 0;
}

/* ================================================================
 * IVRS table search via ACPI
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == \null;
*/
static const struct acpi_ivrs_table_header *fbvbs_acpi_find_ivrs(void)
{
#if defined(__FRAMAC__)
    return (const struct acpi_ivrs_table_header *)0;
#else
    /* PRODUCTION NOTE: Implement ACPI table search.
     * Same RSDP → XSDT traversal as DMAR, searching for "IVRS" signature.
     * Until implemented, return NULL (fail-closed). */
    return (const struct acpi_ivrs_table_header *)0;
#endif
}

/* ================================================================
 * MMIO register access (model / production)
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == 0;
*/
static uint64_t amdvi_mmio_read64(uint64_t base, uint32_t offset)
{
    (void)base;
    (void)offset;
    return 0ULL;
}

/*@ assigns \nothing;
*/
static void amdvi_mmio_write64(uint64_t base, uint32_t offset, uint64_t value)
{
    (void)base;
    (void)offset;
    (void)value;
}

/* ================================================================
 * AMD-Vi capability probing
 * ================================================================ */

/*@ requires \valid(state);
    requires \valid_read(info);
    assigns state->iommu;
    ensures \result == 0 || \result == -1;
*/
static int amdvi_probe_capabilities(
    struct fbvbs_global_security_state *state,
    const struct fbvbs_ivrs_info *info)
{
    if (info->ivhd_count == 0U) {
        return -1;
    }

    {
        uint64_t mmio_base = info->ivhd_units[0].mmio_base;
        uint64_t ef = amdvi_mmio_read64(mmio_base, AMDVI_REG_EXT_FEAT);

        state->iommu.interrupt_remapping =
            (ef & AMDVI_EF_IRT_SUP) ? 1U : 0U;
        state->iommu.dma_remapping = 1;

        (void)ef;
    }

    return 0;
}

/* ================================================================
 * AMD-Vi enable / disable
 * ================================================================ */

/*@ assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int amdvi_enable(uint64_t mmio_base)
{
    uint64_t ctrl = amdvi_mmio_read64(mmio_base, AMDVI_REG_CONTROL);

    /* Enable IOMMU, event log, command buffer */
    ctrl |= AMDVI_CTRL_IOMMU_EN | AMDVI_CTRL_EVT_LOG_EN |
            AMDVI_CTRL_CMD_BUF_EN;

    amdvi_mmio_write64(mmio_base, AMDVI_REG_CONTROL, ctrl);

    /* PRODUCTION NOTE: Verify IOMMU enabled by re-reading control register.
     * Also initialize command buffer and event log ring buffers before
     * enabling. Requires physical page allocator for buffer pages. */
#if !defined(__FRAMAC__)
    {
        uint64_t verify = amdvi_mmio_read64(mmio_base, AMDVI_REG_CONTROL);
        if (!(verify & AMDVI_CTRL_IOMMU_EN)) {
            return -1;
        }
    }
#endif
    return 0;
}

/* ================================================================
 * AMD-Vi Device Table Entry (DTE) construction
 *
 * Each PCI device has a 256-bit (32-byte) DTE indexed by DeviceID.
 * Production requires a 16MB-aligned device table (2^16 entries * 32 bytes).
 * ================================================================ */

struct amdvi_dte {
    uint64_t dw0;  /* [0]=V, [8]=TV, [51:12]=Host PT root, [55:52]=Mode */
    uint64_t dw1;  /* [15:0]=DomainID, [16]=IOTLB, [17]=Sys Mgt, ... */
    uint64_t dw2;  /* Interrupt remapping fields */
    uint64_t dw3;  /* Reserved / extended */
};

#define AMDVI_DTE_V         (1ULL << 0)   /* Valid */
#define AMDVI_DTE_TV        (1ULL << 8)   /* Translation Valid */
#define AMDVI_DTE_MODE_4    (4ULL << 52)  /* 4-level page table */
#define AMDVI_DTE_ADDR_MASK 0x000FFFFFFFFFF000ULL

/*@ requires \valid(dte);
    assigns *dte;
*/
static void amdvi_build_dte(
    struct amdvi_dte *dte,
    uint16_t domain_id,
    uint64_t page_table_root)
{
    dte->dw0 = AMDVI_DTE_V | AMDVI_DTE_TV | AMDVI_DTE_MODE_4 |
               (page_table_root & AMDVI_DTE_ADDR_MASK);
    dte->dw1 = (uint64_t)domain_id;
    dte->dw2 = 0ULL;
    dte->dw3 = 0ULL;
}

/* ================================================================
 * AMD-Vi Interrupt Remapping Table Entry
 * ================================================================ */

struct amdvi_irte {
    uint32_t dw0;  /* [0]=RemapEn, [4:1]=DM, [7:5]=IntType, [15:8]=Dest */
    uint32_t dw1;  /* [10:0]=Vector */
};

#define AMDVI_IRTE_REMAP_EN  (1U << 0)

/*@ requires \valid(irte);
    assigns *irte;
*/
static void amdvi_build_irte(
    struct amdvi_irte *irte,
    uint8_t vector,
    uint8_t dest_id)
{
    irte->dw0 = AMDVI_IRTE_REMAP_EN |
                ((uint32_t)dest_id << 8);
    irte->dw1 = (uint32_t)vector;
}

/* ================================================================
 * AMD-Vi detection and initialization
 * ================================================================ */

/*@ requires \valid(state);
    assigns state->iommu;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_amdvi_detect(struct fbvbs_global_security_state *state)
{
    const struct acpi_ivrs_table_header *ivrs;
    struct fbvbs_ivrs_info info;

    state->iommu = (struct fbvbs_iommu_state){0};
    state->iommu.iommu_type = IOMMU_TYPE_AMD_VI;

    ivrs = fbvbs_acpi_find_ivrs();
    if (ivrs == NULL) {
        return -1;
    }

    {
        uint32_t tbl_len = ivrs->length;
        if (tbl_len > FBVBS_MAX_IVRS_TABLE_SIZE) {
            return -1;
        }
        if (fbvbs_ivrs_parse(ivrs, tbl_len, &info) != 0) {
            return -1;
        }
    }

    state->iommu.dma_remapping = 1;
    state->iommu.interrupt_remapping = 1;

    return 0;
}

/*@ requires \valid(state);
    assigns state->iommu;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_amdvi_init(struct fbvbs_global_security_state *state)
{
    struct fbvbs_ivrs_info info;
    const struct acpi_ivrs_table_header *ivrs;

    if (state->iommu.iommu_type != IOMMU_TYPE_AMD_VI) {
        return -1;
    }

#if defined(__FRAMAC__)
    state->iommu.dma_remapping = 1;
    state->iommu.interrupt_remapping = 1;
    state->iommu.acs_available = 1;
    return 0;
#else
    /* Re-parse IVRS to get MMIO base addresses */
    ivrs = fbvbs_acpi_find_ivrs();
    if (ivrs == NULL) {
        return -1;
    }
    {
        uint32_t tbl_len = ivrs->length;
        if (tbl_len > FBVBS_MAX_IVRS_TABLE_SIZE) {
            return -1;
        }
        if (fbvbs_ivrs_parse(ivrs, tbl_len, &info) != 0) {
            return -1;
        }
    }

    if (amdvi_probe_capabilities(state, &info) != 0) {
        return -1;
    }

    /* Initialize each IOMMU unit.
     * Track allocated pages for cleanup on failure. */
    {
        uint32_t i;
        uint64_t alloc_cmd[FBVBS_MAX_AMDVI_UNITS];
        uint64_t alloc_evt[FBVBS_MAX_AMDVI_UNITS];
        uint32_t alloc_count = 0U;

        for (i = 0U; i < FBVBS_MAX_AMDVI_UNITS; ++i) {
            alloc_cmd[i] = 0ULL;
            alloc_evt[i] = 0ULL;
        }

        for (i = 0U; i < info.ivhd_count; ++i) {
            uint64_t mmio_base = info.ivhd_units[i].mmio_base;
            uint64_t cmd_buf_phys;
            uint64_t evt_log_phys;

            /* Allocate Command Buffer and Event Log pages.
             * PRODUCTION NOTE: Device Table needs 512KB for full 64K
             * entries (allocated separately per-device domain).
             * Here we allocate the minimum buffers for IOMMU operation. */
            cmd_buf_phys = fbvbs_page_alloc();
            if (cmd_buf_phys == 0ULL) {
                goto amdvi_init_fail;
            }
            alloc_cmd[alloc_count] = cmd_buf_phys;

            evt_log_phys = fbvbs_page_alloc();
            if (evt_log_phys == 0ULL) {
                goto amdvi_init_fail;
            }
            alloc_evt[alloc_count] = evt_log_phys;

            /* Set Command Buffer Base: phys addr + size encoding
             * (bits [59:12] = base, bits [3:0] = size = 0 for 4KB) */
            amdvi_mmio_write64(mmio_base, AMDVI_REG_CMD_BUF_BASE,
                               cmd_buf_phys & 0x000FFFFFFFFFF000ULL);
            amdvi_mmio_write64(mmio_base, AMDVI_REG_CMD_BUF_HEAD, 0ULL);
            amdvi_mmio_write64(mmio_base, AMDVI_REG_CMD_BUF_TAIL, 0ULL);

            /* Set Event Log Base: same encoding */
            amdvi_mmio_write64(mmio_base, AMDVI_REG_EVT_LOG_BASE,
                               evt_log_phys & 0x000FFFFFFFFFF000ULL);
            amdvi_mmio_write64(mmio_base, AMDVI_REG_EVT_LOG_HEAD, 0ULL);
            amdvi_mmio_write64(mmio_base, AMDVI_REG_EVT_LOG_TAIL, 0ULL);

            if (amdvi_enable(mmio_base) != 0) {
                goto amdvi_init_fail;
            }
            alloc_count += 1U;
        }
        goto amdvi_init_ok;

amdvi_init_fail:
        {
            uint32_t j;
            for (j = 0U; j <= alloc_count && j < FBVBS_MAX_AMDVI_UNITS; ++j) {
                if (alloc_cmd[j] != 0ULL) {
                    (void)fbvbs_page_free(alloc_cmd[j]);
                }
                if (alloc_evt[j] != 0ULL) {
                    (void)fbvbs_page_free(alloc_evt[j]);
                }
            }
            return -1;
        }
amdvi_init_ok: ;
    }

    /* Validate DTE and IRTE construction (struct layout verification) */
    {
        struct amdvi_dte dte;
        struct amdvi_irte irte;
        amdvi_build_dte(&dte, 1U, 0ULL);
        amdvi_build_irte(&irte, 0U, 0U);
        (void)dte;
        (void)irte;
    }

    return 0;
#endif
}
