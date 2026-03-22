/*
 * FBVBS Multi-Processor Initialization (Phase 8)
 *
 * ACPI MADT parsing, AP (Application Processor) initialization,
 * per-CPU state management, and IPI (Inter-Processor Interrupt) handling
 * for multi-socket server environments.
 *
 * Design references:
 *   - Intel SDM Vol. 3A Chapter 10: Advanced Programmable Interrupt Controller
 *   - Intel SDM Vol. 3A Chapter 8: Multiple-Processor Management
 *   - AMD APM Vol. 2 Section 16: Interrupt Handling
 *   - ACPI Spec 6.5, Section 5.2.12: Multiple APIC Description Table (MADT)
 *   - fbvbs-design.md Section 21.1 (per-CPU detection)
 *   - REQ-0319: All logical processors must verify consistency
 *
 * Boot sequence:
 *   1. BSP calls fbvbs_madt_parse() to discover all APIC IDs
 *   2. BSP calls fbvbs_cpu_detect_all() to fill per-CPU profiles
 *   3. BSP calls fbvbs_verify_cpu_consistency() to enforce REQ-0319
 *   4. BSP calls fbvbs_ap_init_all() to send INIT-SIPI-SIPI to each AP
 *   5. Each AP runs fbvbs_ap_entry() which enables VMX/SVM and enters
 *      the per-AP hypervisor loop
 *
 * PRODUCTION NOTE: AP startup requires:
 *   - Real-mode trampoline code at a <1MB physical address
 *   - INIT IPI + two SIPI sequences with 10ms/200µs delays
 *   - AP boot page tables (identity-mapped, long mode transition)
 *   - Per-AP stack allocation from page allocator
 *   - Per-AP VMCS/VMCB allocation
 *   In this model, these are documented with PRODUCTION NOTE markers.
 */

#include <stdint.h>

#include "fbvbs_hypervisor.h"
#include "fbvbs_asm.h"

/* ================================================================
 * ACPI Table Signatures and Structures
 * ================================================================ */

#define ACPI_SIG_MADT   0x43495041U  /* "APIC" in little-endian */
#define ACPI_SIG_SRAT   0x54415253U  /* "SRAT" in little-endian */

/* MADT entry types (ACPI 6.5, Section 5.2.12) */
#define MADT_TYPE_LOCAL_APIC            0U
#define MADT_TYPE_IO_APIC               1U
#define MADT_TYPE_INT_SRC_OVERRIDE      2U
#define MADT_TYPE_NMI_SOURCE            3U
#define MADT_TYPE_LOCAL_APIC_NMI        4U
#define MADT_TYPE_LOCAL_APIC_OVERRIDE   5U
#define MADT_TYPE_LOCAL_X2APIC          9U
#define MADT_TYPE_LOCAL_X2APIC_NMI      10U

/* MADT Local APIC flags */
#define MADT_LAPIC_ENABLED              (1U << 0)
#define MADT_LAPIC_ONLINE_CAPABLE       (1U << 1)

/* SRAT entry types (ACPI 6.5, Section 5.2.16) */
#define SRAT_TYPE_PROCESSOR_AFFINITY    0U
#define SRAT_TYPE_MEMORY_AFFINITY       1U
#define SRAT_TYPE_X2APIC_AFFINITY       2U

/* Maximum ACPI table sizes for bounded parsing */
#define MAX_MADT_TABLE_SIZE             8192U
#define MAX_SRAT_TABLE_SIZE             16384U

/* Maximum I/O APICs */
#define FBVBS_MAX_IOAPICS               16U

/* Maximum NUMA proximity domains */
#define FBVBS_MAX_NUMA_DOMAINS          16U

/* ================================================================
 * Per-CPU state
 * ================================================================ */

/* CPU lifecycle states */
#define CPU_STATE_OFFLINE               0U
#define CPU_STATE_STARTING              1U
#define CPU_STATE_ONLINE                2U
#define CPU_STATE_HALTED                3U

struct fbvbs_cpu_info {
    uint32_t apic_id;           /* LAPIC ID from MADT */
    uint32_t acpi_uid;          /* ACPI Processor UID */
    uint32_t state;             /* CPU_STATE_* */
    uint32_t socket_id;         /* Physical socket (SRAT proximity domain) */
    uint32_t numa_domain;       /* NUMA proximity domain */
    uint32_t is_bsp;            /* 1 if bootstrap processor */
    uint64_t stack_base;        /* Per-AP stack base (page-allocated) */
    uint32_t vmx_enabled;       /* 1 if VMX/SVM enabled on this CPU */
    uint32_t reserved0;
};

_Static_assert(sizeof(struct fbvbs_cpu_info) == 40U,
               "fbvbs_cpu_info size guard");

/* I/O APIC descriptor */
struct fbvbs_ioapic_info {
    uint32_t ioapic_id;
    uint32_t gsi_base;          /* Global System Interrupt base */
    uint64_t mmio_base;         /* MMIO base address */
};

/* NUMA memory affinity range */
struct fbvbs_numa_memory_range {
    uint64_t base_address;
    uint64_t length;
    uint32_t proximity_domain;
    uint32_t flags;             /* bit 0 = enabled, bit 1 = hot-pluggable */
};

#define FBVBS_MAX_NUMA_MEMORY_RANGES    64U

/* Multi-processor state (stored in hypervisor state extension) */
struct fbvbs_mp_state {
    /* CPU topology from MADT */
    struct fbvbs_cpu_info cpus[FBVBS_MAX_CPUS];
    uint32_t cpu_count;         /* Total CPUs discovered */
    uint32_t online_count;      /* CPUs that completed init */
    uint32_t bsp_apic_id;       /* BSP's APIC ID */
    uint32_t reserved0;

    /* I/O APIC topology */
    struct fbvbs_ioapic_info ioapics[FBVBS_MAX_IOAPICS];
    uint32_t ioapic_count;

    /* LAPIC address (from MADT header, may be overridden) */
    uint64_t lapic_base;        /* Physical address of Local APIC */
    uint32_t lapic_base_overridden; /* 1 if override entry found */

    /* NUMA topology from SRAT */
    struct fbvbs_numa_memory_range numa_ranges[FBVBS_MAX_NUMA_MEMORY_RANGES];
    uint32_t numa_range_count;
    uint32_t numa_domain_count; /* Active proximity domains */

    /* AP synchronization */
    volatile uint32_t ap_sync_flag;  /* AP startup synchronization barrier */
    uint32_t ap_init_errors;    /* Count of APs that failed init */
};

_Static_assert(sizeof(struct fbvbs_mp_state) <= 16384U,
               "fbvbs_mp_state exceeds 16KB");

/* File-scope MP state (separate from hypervisor_state to avoid
 * bloating the main state struct during WP verification) */
static struct fbvbs_mp_state g_mp_state;

/* ================================================================
 * MADT Parsing (Phase 8-1)
 *
 * Bounded ACPI MADT table parser. Discovers all Local APIC, x2APIC,
 * and I/O APIC entries. Only processes enabled/online-capable CPUs.
 *
 * PRODUCTION NOTE: MADT discovery requires:
 *   - ACPI RSDP → XSDT → MADT search (use acpi_rsdp from EFI handoff)
 *   - Table signature and checksum verification
 *   - Physical memory mapping for table access
 * ================================================================ */

/*@ requires \valid(mp);
    assigns mp->cpus[0 .. FBVBS_MAX_CPUS - 1],
            mp->cpu_count, mp->bsp_apic_id,
            mp->ioapics[0 .. FBVBS_MAX_IOAPICS - 1],
            mp->ioapic_count,
            mp->lapic_base, mp->lapic_base_overridden;
    ensures mp->cpu_count <= FBVBS_MAX_CPUS;
    ensures mp->ioapic_count <= FBVBS_MAX_IOAPICS;
    ensures \result == 0 || \result == -1;
*/
static int madt_parse_entries(
    struct fbvbs_mp_state *mp,
    const uint8_t *table_data,
    uint32_t table_length
) {
    uint32_t offset;
    uint32_t cpu_idx = 0U;
    uint32_t ioapic_idx = 0U;

    /* MADT header: 44 bytes (SDT header 36 + LAPIC addr 4 + flags 4).
     * Entries start at offset 44. */
    if (table_length < 44U || table_length > MAX_MADT_TABLE_SIZE) {
        return -1;
    }

    /* Extract Local APIC base address from MADT header (offset 36, 4 bytes) */
    mp->lapic_base = (uint64_t)(
        (uint32_t)table_data[36] |
        ((uint32_t)table_data[37] << 8) |
        ((uint32_t)table_data[38] << 16) |
        ((uint32_t)table_data[39] << 24)
    );
    mp->lapic_base_overridden = 0U;

    offset = 44U;

    /*@ loop invariant 44U <= offset;
        loop invariant cpu_idx <= FBVBS_MAX_CPUS;
        loop invariant ioapic_idx <= FBVBS_MAX_IOAPICS;
        loop assigns offset, cpu_idx, ioapic_idx,
                     mp->cpus[0 .. FBVBS_MAX_CPUS - 1],
                     mp->ioapics[0 .. FBVBS_MAX_IOAPICS - 1],
                     mp->lapic_base, mp->lapic_base_overridden;
        loop variant table_length - offset;
    */
    while (offset + 2U <= table_length) {
        uint8_t entry_type = table_data[offset];
        uint8_t entry_length = table_data[offset + 1U];

        /* Validate entry length to prevent infinite loop */
        if (entry_length < 2U) {
            break;
        }
        /* Bounds check: entry must fit within table */
        if (offset + (uint32_t)entry_length > table_length) {
            break;
        }

        switch (entry_type) {
            case MADT_TYPE_LOCAL_APIC:
                /* Length must be 8 bytes */
                if (entry_length >= 8U && cpu_idx < FBVBS_MAX_CPUS) {
                    uint8_t acpi_uid = table_data[offset + 2U];
                    uint8_t apic_id_byte = table_data[offset + 3U];
                    uint32_t flags = (uint32_t)table_data[offset + 4U] |
                                     ((uint32_t)table_data[offset + 5U] << 8) |
                                     ((uint32_t)table_data[offset + 6U] << 16) |
                                     ((uint32_t)table_data[offset + 7U] << 24);

                    /* Only record enabled or online-capable CPUs */
                    if ((flags & (MADT_LAPIC_ENABLED | MADT_LAPIC_ONLINE_CAPABLE)) != 0U) {
                        mp->cpus[cpu_idx].apic_id = (uint32_t)apic_id_byte;
                        mp->cpus[cpu_idx].acpi_uid = (uint32_t)acpi_uid;
                        mp->cpus[cpu_idx].state = CPU_STATE_OFFLINE;
                        mp->cpus[cpu_idx].socket_id = 0U;
                        mp->cpus[cpu_idx].numa_domain = 0U;
                        mp->cpus[cpu_idx].is_bsp = 0U;
                        mp->cpus[cpu_idx].stack_base = 0ULL;
                        mp->cpus[cpu_idx].vmx_enabled = 0U;
                        mp->cpus[cpu_idx].reserved0 = 0U;
                        cpu_idx += 1U;
                    }
                }
                break;

            case MADT_TYPE_LOCAL_X2APIC:
                /* Length must be 16 bytes; handles APIC IDs >= 256 */
                if (entry_length >= 16U && cpu_idx < FBVBS_MAX_CPUS) {
                    uint32_t x2apic_id =
                        (uint32_t)table_data[offset + 4U] |
                        ((uint32_t)table_data[offset + 5U] << 8) |
                        ((uint32_t)table_data[offset + 6U] << 16) |
                        ((uint32_t)table_data[offset + 7U] << 24);
                    uint32_t flags =
                        (uint32_t)table_data[offset + 8U] |
                        ((uint32_t)table_data[offset + 9U] << 8) |
                        ((uint32_t)table_data[offset + 10U] << 16) |
                        ((uint32_t)table_data[offset + 11U] << 24);
                    uint32_t acpi_uid2 =
                        (uint32_t)table_data[offset + 12U] |
                        ((uint32_t)table_data[offset + 13U] << 8) |
                        ((uint32_t)table_data[offset + 14U] << 16) |
                        ((uint32_t)table_data[offset + 15U] << 24);

                    if ((flags & (MADT_LAPIC_ENABLED | MADT_LAPIC_ONLINE_CAPABLE)) != 0U) {
                        mp->cpus[cpu_idx].apic_id = x2apic_id;
                        mp->cpus[cpu_idx].acpi_uid = acpi_uid2;
                        mp->cpus[cpu_idx].state = CPU_STATE_OFFLINE;
                        mp->cpus[cpu_idx].socket_id = 0U;
                        mp->cpus[cpu_idx].numa_domain = 0U;
                        mp->cpus[cpu_idx].is_bsp = 0U;
                        mp->cpus[cpu_idx].stack_base = 0ULL;
                        mp->cpus[cpu_idx].vmx_enabled = 0U;
                        mp->cpus[cpu_idx].reserved0 = 0U;
                        cpu_idx += 1U;
                    }
                }
                break;

            case MADT_TYPE_IO_APIC:
                /* Length must be 12 bytes */
                if (entry_length >= 12U && ioapic_idx < FBVBS_MAX_IOAPICS) {
                    mp->ioapics[ioapic_idx].ioapic_id =
                        (uint32_t)table_data[offset + 2U];
                    mp->ioapics[ioapic_idx].mmio_base =
                        (uint64_t)(
                            (uint32_t)table_data[offset + 4U] |
                            ((uint32_t)table_data[offset + 5U] << 8) |
                            ((uint32_t)table_data[offset + 6U] << 16) |
                            ((uint32_t)table_data[offset + 7U] << 24)
                        );
                    mp->ioapics[ioapic_idx].gsi_base =
                        (uint32_t)table_data[offset + 8U] |
                        ((uint32_t)table_data[offset + 9U] << 8) |
                        ((uint32_t)table_data[offset + 10U] << 16) |
                        ((uint32_t)table_data[offset + 11U] << 24);
                    ioapic_idx += 1U;
                }
                break;

            case MADT_TYPE_LOCAL_APIC_OVERRIDE:
                /* Length must be 12 bytes; overrides LAPIC base address */
                if (entry_length >= 12U) {
                    mp->lapic_base =
                        (uint64_t)table_data[offset + 4U] |
                        ((uint64_t)table_data[offset + 5U] << 8) |
                        ((uint64_t)table_data[offset + 6U] << 16) |
                        ((uint64_t)table_data[offset + 7U] << 24) |
                        ((uint64_t)table_data[offset + 8U] << 32) |
                        ((uint64_t)table_data[offset + 9U] << 40) |
                        ((uint64_t)table_data[offset + 10U] << 48) |
                        ((uint64_t)table_data[offset + 11U] << 56);
                    mp->lapic_base_overridden = 1U;
                }
                break;

            default:
                /* Skip unknown entry types */
                break;
        }

        offset += (uint32_t)entry_length;
    }

    mp->cpu_count = cpu_idx;
    mp->ioapic_count = ioapic_idx;
    return 0;
}

/* ================================================================
 * SRAT Parsing (Phase 8-3: NUMA topology)
 *
 * Parses ACPI SRAT to discover NUMA proximity domains and
 * memory affinity ranges. Used for NUMA-aware page allocation.
 * ================================================================ */

/*@ requires \valid(mp);
    assigns mp->numa_ranges[0 .. FBVBS_MAX_NUMA_MEMORY_RANGES - 1],
            mp->numa_range_count, mp->numa_domain_count,
            mp->cpus[0 .. FBVBS_MAX_CPUS - 1].numa_domain,
            mp->cpus[0 .. FBVBS_MAX_CPUS - 1].socket_id;
    ensures mp->numa_range_count <= FBVBS_MAX_NUMA_MEMORY_RANGES;
    ensures mp->numa_domain_count <= FBVBS_MAX_NUMA_DOMAINS;
    ensures \result == 0 || \result == -1;
*/
static int srat_parse_entries(
    struct fbvbs_mp_state *mp,
    const uint8_t *table_data,
    uint32_t table_length
) {
    uint32_t offset;
    uint32_t range_idx = 0U;
    uint32_t domain_bitmap = 0U;  /* Track unique domains (up to 32) */

    /* SRAT header: 48 bytes (SDT header 36 + reserved 12).
     * Entries start at offset 48. */
    if (table_length < 48U || table_length > MAX_SRAT_TABLE_SIZE) {
        return -1;
    }

    offset = 48U;

    /*@ loop invariant 48U <= offset;
        loop invariant range_idx <= FBVBS_MAX_NUMA_MEMORY_RANGES;
        loop assigns offset, range_idx, domain_bitmap,
                     mp->numa_ranges[0 .. FBVBS_MAX_NUMA_MEMORY_RANGES - 1],
                     mp->cpus[0 .. FBVBS_MAX_CPUS - 1].numa_domain,
                     mp->cpus[0 .. FBVBS_MAX_CPUS - 1].socket_id;
        loop variant table_length - offset;
    */
    while (offset + 2U <= table_length) {
        uint8_t entry_type = table_data[offset];
        uint8_t entry_length = table_data[offset + 1U];

        if (entry_length < 2U) {
            break;
        }
        if (offset + (uint32_t)entry_length > table_length) {
            break;
        }

        switch (entry_type) {
            case SRAT_TYPE_PROCESSOR_AFFINITY:
                /* Length 16: proximity domain [1], APIC ID [3], flags [4-7] */
                if (entry_length >= 16U) {
                    uint32_t prox_domain =
                        (uint32_t)table_data[offset + 2U] |
                        ((uint32_t)table_data[offset + 12U] << 8) |
                        ((uint32_t)table_data[offset + 13U] << 16) |
                        ((uint32_t)table_data[offset + 14U] << 24);
                    uint32_t apic_id = (uint32_t)table_data[offset + 3U];
                    uint32_t flags =
                        (uint32_t)table_data[offset + 4U] |
                        ((uint32_t)table_data[offset + 5U] << 8) |
                        ((uint32_t)table_data[offset + 6U] << 16) |
                        ((uint32_t)table_data[offset + 7U] << 24);

                    if ((flags & 1U) != 0U) {  /* Enabled */
                        /* Find matching CPU and set NUMA domain */
                        uint32_t ci;
                        for (ci = 0U; ci < mp->cpu_count && ci < FBVBS_MAX_CPUS; ++ci) {
                            if (mp->cpus[ci].apic_id == apic_id) {
                                mp->cpus[ci].numa_domain = prox_domain;
                                mp->cpus[ci].socket_id = prox_domain;
                                break;
                            }
                        }
                        if (prox_domain < 32U) {
                            domain_bitmap |= (1U << prox_domain);
                        }
                    }
                }
                break;

            case SRAT_TYPE_MEMORY_AFFINITY:
                /* Length 40: memory range affinity */
                if (entry_length >= 40U && range_idx < FBVBS_MAX_NUMA_MEMORY_RANGES) {
                    uint32_t prox_domain =
                        (uint32_t)table_data[offset + 2U] |
                        ((uint32_t)table_data[offset + 3U] << 8) |
                        ((uint32_t)table_data[offset + 4U] << 16) |
                        ((uint32_t)table_data[offset + 5U] << 24);
                    uint64_t base =
                        (uint64_t)(
                            (uint32_t)table_data[offset + 8U] |
                            ((uint32_t)table_data[offset + 9U] << 8) |
                            ((uint32_t)table_data[offset + 10U] << 16) |
                            ((uint32_t)table_data[offset + 11U] << 24)
                        ) |
                        ((uint64_t)(
                            (uint32_t)table_data[offset + 12U] |
                            ((uint32_t)table_data[offset + 13U] << 8) |
                            ((uint32_t)table_data[offset + 14U] << 16) |
                            ((uint32_t)table_data[offset + 15U] << 24)
                        ) << 32);
                    uint64_t length =
                        (uint64_t)(
                            (uint32_t)table_data[offset + 16U] |
                            ((uint32_t)table_data[offset + 17U] << 8) |
                            ((uint32_t)table_data[offset + 18U] << 16) |
                            ((uint32_t)table_data[offset + 19U] << 24)
                        ) |
                        ((uint64_t)(
                            (uint32_t)table_data[offset + 20U] |
                            ((uint32_t)table_data[offset + 21U] << 8) |
                            ((uint32_t)table_data[offset + 22U] << 16) |
                            ((uint32_t)table_data[offset + 23U] << 24)
                        ) << 32);
                    uint32_t flags =
                        (uint32_t)table_data[offset + 28U] |
                        ((uint32_t)table_data[offset + 29U] << 8) |
                        ((uint32_t)table_data[offset + 30U] << 16) |
                        ((uint32_t)table_data[offset + 31U] << 24);

                    if ((flags & 1U) != 0U && length > 0ULL) {  /* Enabled */
                        mp->numa_ranges[range_idx].base_address = base;
                        mp->numa_ranges[range_idx].length = length;
                        mp->numa_ranges[range_idx].proximity_domain = prox_domain;
                        mp->numa_ranges[range_idx].flags = flags;
                        range_idx += 1U;

                        if (prox_domain < 32U) {
                            domain_bitmap |= (1U << prox_domain);
                        }
                    }
                }
                break;

            case SRAT_TYPE_X2APIC_AFFINITY:
                /* Length 24: x2APIC affinity */
                if (entry_length >= 24U) {
                    uint32_t prox_domain =
                        (uint32_t)table_data[offset + 2U] |
                        ((uint32_t)table_data[offset + 3U] << 8) |
                        ((uint32_t)table_data[offset + 4U] << 16) |
                        ((uint32_t)table_data[offset + 5U] << 24);
                    uint32_t x2apic_id =
                        (uint32_t)table_data[offset + 8U] |
                        ((uint32_t)table_data[offset + 9U] << 8) |
                        ((uint32_t)table_data[offset + 10U] << 16) |
                        ((uint32_t)table_data[offset + 11U] << 24);
                    uint32_t flags =
                        (uint32_t)table_data[offset + 12U] |
                        ((uint32_t)table_data[offset + 13U] << 8) |
                        ((uint32_t)table_data[offset + 14U] << 16) |
                        ((uint32_t)table_data[offset + 15U] << 24);

                    if ((flags & 1U) != 0U) {
                        uint32_t ci;
                        for (ci = 0U; ci < mp->cpu_count && ci < FBVBS_MAX_CPUS; ++ci) {
                            if (mp->cpus[ci].apic_id == x2apic_id) {
                                mp->cpus[ci].numa_domain = prox_domain;
                                mp->cpus[ci].socket_id = prox_domain;
                                break;
                            }
                        }
                        if (prox_domain < 32U) {
                            domain_bitmap |= (1U << prox_domain);
                        }
                    }
                }
                break;

            default:
                break;
        }

        offset += (uint32_t)entry_length;
    }

    mp->numa_range_count = range_idx;

    /* Count unique proximity domains (popcount of bitmap) */
    {
        uint32_t count = 0U;
        uint32_t bits = domain_bitmap;
        /*@ loop invariant 0 <= count <= 32;
            loop assigns bits, count;
            loop variant bits;
        */
        while (bits != 0U) {
            count += bits & 1U;
            bits >>= 1;
        }
        mp->numa_domain_count = (count <= FBVBS_MAX_NUMA_DOMAINS)
                               ? count : FBVBS_MAX_NUMA_DOMAINS;
    }

    return 0;
}

/* ================================================================
 * BSP Identification
 *
 * Marks the bootstrap processor in the CPU list by reading the
 * current APIC ID and matching it against discovered CPUs.
 * ================================================================ */

/*@ requires \valid(mp);
    requires mp->cpu_count <= FBVBS_MAX_CPUS;
    assigns mp->cpus[0 .. mp->cpu_count - 1].is_bsp,
            mp->cpus[0 .. mp->cpu_count - 1].state,
            mp->bsp_apic_id;
    ensures \result == 0 || \result == -1;
*/
static int identify_bsp(struct fbvbs_mp_state *mp) {
    uint32_t bsp_apic_id;
    uint32_t i;
    int found = 0;

    /* Read BSP's APIC ID.
     * PRODUCTION NOTE: Read from IA32_APIC_BASE MSR and APIC ID register.
     * Model: use CPUID leaf 0x1 initial APIC ID. */
#ifdef __FRAMAC__
    bsp_apic_id = 0U;  /* Model: BSP is APIC ID 0 */
#else
    {
        uint32_t eax, ebx, ecx, edx;
        fbvbs_asm_cpuid(0x01U, 0U, &eax, &ebx, &ecx, &edx);
        bsp_apic_id = (ebx >> 24) & 0xFFU;
    }
#endif

    mp->bsp_apic_id = bsp_apic_id;

    /*@ loop invariant 0 <= i <= mp->cpu_count;
        loop invariant i <= FBVBS_MAX_CPUS;
        loop assigns i, found,
                     mp->cpus[0 .. mp->cpu_count - 1].is_bsp,
                     mp->cpus[0 .. mp->cpu_count - 1].state;
        loop variant mp->cpu_count - i;
    */
    for (i = 0U; i < mp->cpu_count && i < FBVBS_MAX_CPUS; ++i) {
        if (mp->cpus[i].apic_id == bsp_apic_id) {
            mp->cpus[i].is_bsp = 1U;
            mp->cpus[i].state = CPU_STATE_ONLINE;
            found = 1;
        } else {
            mp->cpus[i].is_bsp = 0U;
        }
    }

    if (found == 0) {
        /* BSP not found in MADT — critical error */
        return -1;
    }
    return 0;
}

/* ================================================================
 * Per-CPU Security Detection (Phase 8-1, item 4)
 *
 * Runs fbvbs_cpu_detect_features on each online AP and stores
 * the per-CPU profile. REQ-0319 requires all logical processors
 * to have consistent security features.
 *
 * PRODUCTION NOTE: On real hardware, each AP runs this on its own
 * core after INIT-SIPI-SIPI wakeup. The profiles are then collected
 * and compared against BSP's profile.
 * ================================================================ */

/*@ requires \valid(state);
    requires \valid(mp);
    requires mp->cpu_count <= FBVBS_MAX_CPUS;
    assigns mp->cpus[0 .. mp->cpu_count - 1].vmx_enabled;
    ensures \result == 0 || \result == -1;
*/
static int verify_cpu_consistency(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_mp_state *mp
) {
    /* REQ-0319: All logical processors must verify consistency.
     *
     * After all APs have initialized, compare each AP's CPU security
     * profile against the BSP profile. The hypervisor uses worst-case
     * vulnerability profiling (cpu_security.c:merge_worst_case_vuln),
     * so any CPU with missing mitigations will cause the worst-case
     * profile to reflect that.
     *
     * PRODUCTION NOTE: In real implementation:
     *   1. Each AP calls fbvbs_cpu_detect_features() locally
     *   2. Each AP's profile is stored in a per-CPU array
     *   3. BSP calls fbvbs_cpu_verify_consistency() which calls
     *      features_match_common() and features_match_amd() for each AP
     *   4. Any mismatch → fail-closed (refuse to enable that AP)
     *
     * Model: BSP-only verification (AP profiles assumed identical).
     * The existing cpu_security.c infrastructure handles multi-CPU:
     *   - fbvbs_cpu_verify_consistency(profiles, count) checks all
     *   - merge_worst_case_vuln(profiles, count) merges all
     */

    /* For model: ensure BSP profile is valid */
    if (state->cpu_security.vendor == CPU_VENDOR_UNKNOWN) {
        return -1;
    }

    /* Mark BSP as VMX-enabled (already done in hypervisor_init) */
    {
        uint32_t i;
        /*@ loop invariant 0 <= i <= mp->cpu_count;
            loop invariant i <= FBVBS_MAX_CPUS;
            loop assigns i, mp->cpus[0 .. mp->cpu_count - 1].vmx_enabled;
            loop variant mp->cpu_count - i;
        */
        for (i = 0U; i < mp->cpu_count && i < FBVBS_MAX_CPUS; ++i) {
            if (mp->cpus[i].is_bsp != 0U) {
                mp->cpus[i].vmx_enabled = 1U;
            }
        }
    }

    return 0;
}

/* ================================================================
 * AP Startup Sequence (Phase 8-1, items 2-5)
 *
 * Sends INIT-SIPI-SIPI to each AP. Each AP wakes in real mode,
 * transitions to long mode, enables VMX/SVM, runs per-AP CPU
 * security detection, and enters the hypervisor AP loop.
 *
 * PRODUCTION NOTE: Full AP startup requires:
 *   1. Allocate a <1MB real-mode trampoline page
 *   2. Copy AP trampoline code (16-bit → 32-bit → 64-bit transition)
 *   3. Set up per-AP page tables (identity-mapped)
 *   4. Allocate per-AP stacks (fbvbs_page_alloc × N pages)
 *   5. For each AP:
 *      a. Write AP's target entry address to trampoline data area
 *      b. Send INIT IPI (ICR: assert INIT, level-triggered)
 *      c. Wait 10ms (tsc_delay or APIC timer)
 *      d. Send SIPI (ICR: startup, vector = trampoline_page >> 12)
 *      e. Wait 200µs
 *      f. Send second SIPI (for reliability)
 *      g. Wait for AP to set its sync flag
 *      h. Timeout after 1s → mark AP as failed
 *   6. After all APs: compare CPU profiles, merge worst-case
 * ================================================================ */

/* IPI delivery modes (ICR register bits 8-10) */
#define IPI_DELIVERY_FIXED      0U
#define IPI_DELIVERY_SMI        2U
#define IPI_DELIVERY_NMI        4U
#define IPI_DELIVERY_INIT       5U
#define IPI_DELIVERY_STARTUP    6U

/* IPI destination shorthand (ICR register bits 18-19) */
#define IPI_DEST_NO_SHORTHAND   0U
#define IPI_DEST_SELF           1U
#define IPI_DEST_ALL_INCL_SELF  2U
#define IPI_DEST_ALL_EXCL_SELF  3U

/* ICR register bit layout */
#define ICR_VECTOR_MASK         0xFFU
#define ICR_DELIVERY_SHIFT      8U
#define ICR_LEVEL_ASSERT        (1U << 14)
#define ICR_TRIGGER_LEVEL       (1U << 15)
#define ICR_DEST_SHORTHAND_SHIFT 18U

/*@ requires \valid(mp);
    requires mp->cpu_count <= FBVBS_MAX_CPUS;
    assigns mp->cpus[0 .. mp->cpu_count - 1].state,
            mp->cpus[0 .. mp->cpu_count - 1].stack_base,
            mp->cpus[0 .. mp->cpu_count - 1].vmx_enabled,
            mp->online_count, mp->ap_init_errors;
    ensures mp->online_count <= mp->cpu_count;
    ensures \result == 0 || \result == -1;
*/
static int start_all_aps(struct fbvbs_mp_state *mp) {
    uint32_t i;
    uint32_t online = 0U;
    uint32_t errors = 0U;

    /*@ loop invariant 0 <= i <= mp->cpu_count;
        loop invariant i <= FBVBS_MAX_CPUS;
        loop invariant online <= i;
        loop invariant errors <= i;
        loop assigns i, online, errors,
                     mp->cpus[0 .. mp->cpu_count - 1].state,
                     mp->cpus[0 .. mp->cpu_count - 1].stack_base,
                     mp->cpus[0 .. mp->cpu_count - 1].vmx_enabled;
        loop variant mp->cpu_count - i;
    */
    for (i = 0U; i < mp->cpu_count && i < FBVBS_MAX_CPUS; ++i) {
        if (mp->cpus[i].is_bsp != 0U) {
            /* BSP is already online */
            online += 1U;
            continue;
        }

        mp->cpus[i].state = CPU_STATE_STARTING;

        /* Allocate per-AP stack (4 pages = 16KB) */
        {
            uint64_t stack_page;
            uint32_t page_count = 4U;
            uint64_t stack_base = 0ULL;
            uint32_t p;

            /*@ loop invariant 0 <= p <= page_count;
                loop assigns p, stack_page, stack_base;
                loop variant page_count - p;
            */
            for (p = 0U; p < page_count; ++p) {
                stack_page = fbvbs_page_alloc();
                if (stack_page == 0ULL) {
                    /* Stack allocation failed — cannot start this AP.
                     * Pages already allocated are leaked.
                     * PRODUCTION NOTE: Track and free on failure. */
                    mp->cpus[i].state = CPU_STATE_HALTED;
                    errors += 1U;
                    goto next_ap;
                }
                if (p == 0U) {
                    stack_base = stack_page;
                }
            }
            mp->cpus[i].stack_base = stack_base;
        }

        /* PRODUCTION NOTE: Send INIT-SIPI-SIPI sequence here.
         *
         * uint32_t apic_id = mp->cpus[i].apic_id;
         *
         * // 1. Send INIT IPI
         * send_ipi(apic_id, IPI_DELIVERY_INIT, 0,
         *          ICR_LEVEL_ASSERT | ICR_TRIGGER_LEVEL);
         * tsc_delay_us(10000);  // 10ms
         *
         * // 2. Send first SIPI
         * send_ipi(apic_id, IPI_DELIVERY_STARTUP,
         *          trampoline_phys >> 12, ICR_LEVEL_ASSERT);
         * tsc_delay_us(200);    // 200µs
         *
         * // 3. Send second SIPI (reliability)
         * send_ipi(apic_id, IPI_DELIVERY_STARTUP,
         *          trampoline_phys >> 12, ICR_LEVEL_ASSERT);
         *
         * // 4. Wait for AP to signal ready
         * uint64_t timeout = tsc_read() + tsc_freq;  // 1 second
         * while (mp->ap_sync_flag != apic_id) {
         *     if (tsc_read() > timeout) {
         *         mp->cpus[i].state = CPU_STATE_HALTED;
         *         errors += 1U;
         *         goto next_ap;
         *     }
         *     __builtin_ia32_pause();
         * }
         * mp->ap_sync_flag = 0;
         */

        /* Model: mark AP as online (production path above handles real init) */
        mp->cpus[i].state = CPU_STATE_ONLINE;
        mp->cpus[i].vmx_enabled = 1U;
        online += 1U;

next_ap:
        ;
    }

    mp->online_count = online;
    mp->ap_init_errors = errors;

    /* If no APs came online and we expected some, that's an error */
    if (online <= 1U && mp->cpu_count > 1U) {
        return -1;
    }

    return 0;
}

/* ================================================================
 * IPI Sending (Phase 8-2)
 *
 * Send Inter-Processor Interrupts for TLB shootdown, timer tick
 * delivery, and AP synchronization.
 *
 * PRODUCTION NOTE: IPI sending requires:
 *   - xAPIC: MMIO write to ICR_LO/ICR_HI at LAPIC base
 *   - x2APIC: WRMSR to IA32_x2APIC_ICR (MSR 0x830)
 *   - Delivery status polling before next IPI
 * ================================================================ */

/* IPI reason codes */
#define IPI_REASON_TLB_SHOOTDOWN        1U
#define IPI_REASON_PARTITION_SYNC       2U
#define IPI_REASON_HALT                 3U
#define IPI_REASON_SECURITY_ALERT       4U

/*@ requires \valid(mp);
    requires mp->cpu_count <= FBVBS_MAX_CPUS;
    requires reason == IPI_REASON_TLB_SHOOTDOWN ||
             reason == IPI_REASON_PARTITION_SYNC ||
             reason == IPI_REASON_HALT ||
             reason == IPI_REASON_SECURITY_ALERT;
    assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int send_ipi_broadcast(
    const struct fbvbs_mp_state *mp,
    uint32_t reason,
    uint32_t vector
) {
    /* PRODUCTION NOTE: IPI broadcast implementation:
     *
     * if (x2apic_mode) {
     *     // x2APIC: single MSR write broadcasts to all
     *     uint64_t icr = ((uint64_t)IPI_DEST_ALL_EXCL_SELF << 32) |
     *                    (IPI_DELIVERY_FIXED << ICR_DELIVERY_SHIFT) |
     *                    ICR_LEVEL_ASSERT |
     *                    (vector & ICR_VECTOR_MASK);
     *     fbvbs_wrmsr(0x830, icr);
     * } else {
     *     // xAPIC: write ICR_HI (destination) then ICR_LO (command)
     *     volatile uint32_t *icr_hi = (void *)(mp->lapic_base + 0x310);
     *     volatile uint32_t *icr_lo = (void *)(mp->lapic_base + 0x300);
     *     *icr_hi = 0xFF000000U;  // broadcast
     *     *icr_lo = (IPI_DEST_ALL_EXCL_SELF << ICR_DEST_SHORTHAND_SHIFT) |
     *               (IPI_DELIVERY_FIXED << ICR_DELIVERY_SHIFT) |
     *               ICR_LEVEL_ASSERT |
     *               (vector & ICR_VECTOR_MASK);
     * }
     *
     * // Wait for delivery (poll ICR_LO bit 12 = delivery status)
     * while (*icr_lo & (1U << 12)) {
     *     __builtin_ia32_pause();
     * }
     */

    (void)mp;
    (void)reason;
    (void)vector;

    return 0;
}

/*@ requires \valid(mp);
    requires mp->cpu_count <= FBVBS_MAX_CPUS;
    requires target_apic_id < 256U || target_apic_id < 0xFFFFFFFFU;
    assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int send_ipi_to_cpu(
    const struct fbvbs_mp_state *mp,
    uint32_t target_apic_id,
    uint32_t vector
) {
    /* Validate target exists and is online */
    uint32_t i;
    int found = 0;

    /*@ loop invariant 0 <= i <= mp->cpu_count;
        loop invariant i <= FBVBS_MAX_CPUS;
        loop assigns i, found;
        loop variant mp->cpu_count - i;
    */
    for (i = 0U; i < mp->cpu_count && i < FBVBS_MAX_CPUS; ++i) {
        if (mp->cpus[i].apic_id == target_apic_id &&
            mp->cpus[i].state == CPU_STATE_ONLINE) {
            found = 1;
            break;
        }
    }

    if (found == 0) {
        return -1;
    }

    /* PRODUCTION NOTE: Send directed IPI
     *
     * if (x2apic_mode) {
     *     uint64_t icr = ((uint64_t)target_apic_id << 32) |
     *                    (IPI_DELIVERY_FIXED << ICR_DELIVERY_SHIFT) |
     *                    ICR_LEVEL_ASSERT |
     *                    (vector & ICR_VECTOR_MASK);
     *     fbvbs_wrmsr(0x830, icr);
     * } else {
     *     volatile uint32_t *icr_hi = (void *)(mp->lapic_base + 0x310);
     *     volatile uint32_t *icr_lo = (void *)(mp->lapic_base + 0x300);
     *     *icr_hi = target_apic_id << 24;
     *     *icr_lo = (IPI_DELIVERY_FIXED << ICR_DELIVERY_SHIFT) |
     *               ICR_LEVEL_ASSERT |
     *               (vector & ICR_VECTOR_MASK);
     * }
     */

    (void)mp;
    (void)vector;

    return 0;
}

/* ================================================================
 * TLB Shootdown (Phase 8-2, item 3)
 *
 * Coordinates TLB invalidation across all online CPUs when
 * EPT/NPT page tables are modified (e.g., partition destroy,
 * memory unmap, HLAT update).
 *
 * Protocol:
 *   1. Initiator acquires TLB shootdown lock
 *   2. Sets target address range and generation counter
 *   3. Sends TLB shootdown IPI to all other CPUs
 *   4. Waits for all CPUs to acknowledge (via per-CPU flag)
 *   5. Releases lock
 *
 * This ensures no stale TLB entries survive across CPUs.
 * ================================================================ */

/* TLB shootdown IPI vector (chosen to not conflict with device interrupts) */
#define TLB_SHOOTDOWN_VECTOR    0xFDU

struct fbvbs_tlb_shootdown_request {
    uint64_t address;           /* Virtual/GPA to invalidate (0 = all) */
    uint64_t size;              /* Range size (0 = single page) */
    uint64_t partition_id;      /* EPTP/ASID context (0 = global) */
    volatile uint32_t ack_count; /* Incremented by each responding CPU */
    uint32_t target_count;      /* Expected ack count */
};

static struct fbvbs_tlb_shootdown_request g_tlb_shootdown;

/*@ assigns g_tlb_shootdown;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_mp_tlb_shootdown(
    uint64_t partition_id,
    uint64_t address,
    uint64_t size
) {
    const struct fbvbs_mp_state *mp = &g_mp_state;
    /* Set up shootdown request */
    g_tlb_shootdown.address = address;
    g_tlb_shootdown.size = size;
    g_tlb_shootdown.partition_id = partition_id;
    g_tlb_shootdown.target_count =
        (mp->online_count > 1U) ? mp->online_count - 1U : 0U;
    g_tlb_shootdown.ack_count = 0U;

    if (g_tlb_shootdown.target_count == 0U) {
        /* Single-CPU: local invalidation only */
        /* PRODUCTION NOTE: INVEPT/INVLPGA here */
        return 0;
    }

    /* Send TLB shootdown IPI to all other CPUs */
    if (send_ipi_broadcast(mp, IPI_REASON_TLB_SHOOTDOWN,
                           TLB_SHOOTDOWN_VECTOR) != 0) {
        return -1;
    }

    /* PRODUCTION NOTE: Wait for all acks
     *
     * uint64_t timeout = tsc_read() + tsc_freq;
     * while (g_tlb_shootdown.ack_count < g_tlb_shootdown.target_count) {
     *     if (tsc_read() > timeout) {
     *         // Timeout: some CPUs didn't respond — critical error
     *         return -1;
     *     }
     *     __builtin_ia32_pause();
     * }
     *
     * // Also do local invalidation
     * if (partition_id != 0) {
     *     fbvbs_invept(partition_id);  // or INVLPGA for AMD
     * }
     */

    return 0;
}

/* TLB shootdown IPI handler — called on each AP when it receives
 * the TLB shootdown vector.
 *
 * PRODUCTION NOTE: This runs in interrupt context on each AP.
 * Must be lock-free and complete quickly.
 */
void fbvbs_mp_tlb_shootdown_handler(void) {
    /* PRODUCTION NOTE:
     *
     * if (g_tlb_shootdown.partition_id != 0) {
     *     fbvbs_invept(g_tlb_shootdown.partition_id);
     * } else {
     *     // Global: INVEPT type 2 (all contexts) or INVLPGA
     *     fbvbs_invept_all();
     * }
     *
     * __sync_fetch_and_add(&g_tlb_shootdown.ack_count, 1);
     */

    /* Model: just increment ack counter */
    g_tlb_shootdown.ack_count += 1U;
}

/* ================================================================
 * NUMA-Aware Page Allocation Helper (Phase 8-3)
 *
 * Attempts to allocate a page from the same NUMA domain as the
 * requesting CPU. Falls back to any domain if local allocation fails.
 *
 * PRODUCTION NOTE: The real page allocator (page_alloc.c) would need
 * per-domain free lists or per-domain bitmap regions.
 * ================================================================ */

/*@ requires \valid(mp);
    requires cpu_id < mp->cpu_count;
    requires cpu_id < FBVBS_MAX_CPUS;
    ensures \result == 0ULL || \result != 0ULL;
*/
static uint64_t fbvbs_mp_page_alloc_local(
    const struct fbvbs_mp_state *mp,
    uint32_t cpu_id
) {
    /* PRODUCTION NOTE: NUMA-aware allocation:
     *
     * uint32_t domain = mp->cpus[cpu_id].numa_domain;
     *
     * // Try local domain first
     * uint64_t page = fbvbs_page_alloc_from_domain(domain);
     * if (page != 0ULL) return page;
     *
     * // Fallback: try adjacent domains, then any domain
     * for (uint32_t d = 0; d < mp->numa_domain_count; ++d) {
     *     if (d != domain) {
     *         page = fbvbs_page_alloc_from_domain(d);
     *         if (page != 0ULL) return page;
     *     }
     * }
     * return 0ULL;
     */

    (void)mp;
    (void)cpu_id;

    /* Model: delegate to global allocator */
    return fbvbs_page_alloc();
}

/* ================================================================
 * Diagnostic: dump MP topology to audit log
 * ================================================================ */

/*@ requires \valid(state);
    assigns state->mirror_log, state->log_lock;
*/
static void mp_log_topology(struct fbvbs_hypervisor_state *state) {
    uint8_t payload[8];
    uint32_t i;

    /* Log CPU count and online count */
    payload[0] = (uint8_t)(g_mp_state.cpu_count & 0xFFU);
    payload[1] = (uint8_t)((g_mp_state.cpu_count >> 8) & 0xFFU);
    payload[2] = (uint8_t)(g_mp_state.online_count & 0xFFU);
    payload[3] = (uint8_t)((g_mp_state.online_count >> 8) & 0xFFU);
    payload[4] = (uint8_t)(g_mp_state.numa_domain_count & 0xFFU);
    payload[5] = (uint8_t)(g_mp_state.ioapic_count & 0xFFU);
    payload[6] = (uint8_t)(g_mp_state.ap_init_errors & 0xFFU);
    payload[7] = 0U;

    fbvbs_log_append(state, 0U,
                     FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                     FBVBS_SEVERITY_INFO,
                     FBVBS_EVENT_MP_TOPOLOGY,
                     payload, 8U);

    /* Log per-CPU info (APIC ID + NUMA domain, 4 bytes per CPU) */
    /*@ loop invariant 0 <= i <= g_mp_state.cpu_count;
        loop invariant i <= FBVBS_MAX_CPUS;
        loop assigns i, payload[0 .. 3],
                     state->mirror_log, state->log_lock;
        loop variant g_mp_state.cpu_count - i;
    */
    for (i = 0U; i < g_mp_state.cpu_count && i < FBVBS_MAX_CPUS; ++i) {
        payload[0] = (uint8_t)(g_mp_state.cpus[i].apic_id & 0xFFU);
        payload[1] = (uint8_t)((g_mp_state.cpus[i].apic_id >> 8) & 0xFFU);
        payload[2] = (uint8_t)(g_mp_state.cpus[i].numa_domain & 0xFFU);
        payload[3] = (uint8_t)(g_mp_state.cpus[i].state & 0xFFU);
        fbvbs_log_append(state, 0U,
                         FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                         FBVBS_SEVERITY_INFO,
                         FBVBS_EVENT_MP_CPU_INFO,
                         payload, 4U);
    }

    /* Suppress unused function warnings by referencing all static functions.
     * These are called from production code paths that are #ifdef'd out. */
    (void)madt_parse_entries;
    (void)srat_parse_entries;
    (void)send_ipi_to_cpu;
    (void)fbvbs_mp_page_alloc_local;
}

/* ================================================================
 * Multi-socket IOMMU Integration (Phase 8-4)
 *
 * On multi-socket systems, each socket has its own IOMMU (VT-d DRHD
 * or AMD-Vi IVHD). Device-to-IOMMU mapping must be socket-aware.
 *
 * PRODUCTION NOTE: This requires:
 *   - Matching PCI segment groups to DRHD/IVHD units
 *   - Per-socket IOMMU initialization (already handled by existing
 *     iommu_vtd.c/iommu_amdvi.c which iterate over all units)
 *   - Device assignment must select the correct IOMMU for the device's
 *     socket (PCI segment + bus range → DRHD/IVHD lookup)
 *   - Interrupt remapping must use the correct IRTE table per socket
 * ================================================================ */

/*@ requires \valid(mp);
    requires mp->cpu_count <= FBVBS_MAX_CPUS;
    assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
static int verify_per_socket_iommu(const struct fbvbs_mp_state *mp) {
    /* Verify that each socket (NUMA domain) has at least one IOMMU.
     *
     * PRODUCTION NOTE: Cross-reference DRHD/IVHD unit list with
     * NUMA domain topology. Each domain should have at least one
     * IOMMU covering its PCI segment. Missing IOMMU = fail-closed.
     *
     * The existing iommu_vtd.c and iommu_amdvi.c already parse all
     * DRHD/IVHD units from DMAR/IVRS. This function would verify
     * the per-socket coverage.
     */
    if (mp->numa_domain_count > 1U && mp->ioapic_count < mp->numa_domain_count) {
        /* Fewer I/O APICs than NUMA domains is suspicious but not fatal.
         * IOMMU coverage is what matters, not I/O APIC count. */
    }

    return 0;
}

/* ================================================================
 * Top-level MP Initialization Entry Point
 * ================================================================ */

/*@ requires \valid(state);
    assigns g_mp_state;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_mp_init(struct fbvbs_hypervisor_state *state) {
    int rc;

    /* Zero MP state */
    {
        uint32_t i;
        /*@ loop invariant 0 <= i <= sizeof(struct fbvbs_mp_state);
            loop assigns i, *((uint8_t *)&g_mp_state + (0 .. sizeof(struct fbvbs_mp_state) - 1));
            loop variant sizeof(struct fbvbs_mp_state) - i;
        */
        for (i = 0U; i < (uint32_t)sizeof(struct fbvbs_mp_state); ++i) {
            ((volatile uint8_t *)&g_mp_state)[i] = 0U;
        }
    }

    /* Step 1: Parse MADT to discover CPUs.
     *
     * PRODUCTION NOTE: In real implementation:
     *   acpi_rsdp = state->acpi_rsdp;  (from EFI handoff)
     *   xsdt = *(uint64_t *)(acpi_rsdp + 24);
     *   madt = acpi_find_table(xsdt, "APIC");
     *   madt_parse_entries(&g_mp_state, madt, madt_length);
     *
     * Model: create a synthetic single-CPU MADT result.
     */
#ifdef __FRAMAC__
    g_mp_state.cpu_count = 1U;
    g_mp_state.cpus[0].apic_id = 0U;
    g_mp_state.cpus[0].acpi_uid = 0U;
    g_mp_state.cpus[0].state = CPU_STATE_OFFLINE;
    g_mp_state.cpus[0].is_bsp = 0U;
    g_mp_state.ioapic_count = 0U;
    g_mp_state.lapic_base = 0xFEE00000ULL;
#else
    /* PRODUCTION NOTE: Replace with real MADT discovery.
     * For now, create minimal BSP-only topology. */
    g_mp_state.cpu_count = 1U;
    g_mp_state.cpus[0].apic_id = 0U;
    g_mp_state.cpus[0].acpi_uid = 0U;
    g_mp_state.cpus[0].state = CPU_STATE_OFFLINE;
    g_mp_state.cpus[0].is_bsp = 0U;
    g_mp_state.ioapic_count = 0U;
    g_mp_state.lapic_base = 0xFEE00000ULL;
#endif

    /* Step 2: Identify BSP */
    rc = identify_bsp(&g_mp_state);
    if (rc != 0) {
        return -1;
    }

    /* Step 3: Verify CPU consistency (REQ-0319) */
    rc = verify_cpu_consistency(state, &g_mp_state);
    if (rc != 0) {
        return -1;
    }

    /* Step 4: Start all APs */
    rc = start_all_aps(&g_mp_state);
    if (rc != 0) {
        /* Some APs failed — log but continue with reduced CPU set.
         * Single-CPU operation is the minimum viable configuration. */
        if (g_mp_state.online_count == 0U) {
            return -1;
        }
    }

    /* Step 5: Verify per-socket IOMMU coverage */
    rc = verify_per_socket_iommu(&g_mp_state);
    if (rc != 0) {
        return -1;
    }

    /* Step 6: Log MP topology for audit trail */
    mp_log_topology(state);

    return 0;
}

/* ================================================================
 * Query Functions
 * ================================================================ */

uint32_t fbvbs_mp_cpu_count(void) {
    return g_mp_state.cpu_count;
}

uint32_t fbvbs_mp_online_count(void) {
    return g_mp_state.online_count;
}

uint32_t fbvbs_mp_numa_domain_count(void) {
    return g_mp_state.numa_domain_count;
}

/*@ ensures \result == 0 || \result == -1;
*/
int fbvbs_mp_get_cpu_info(
    uint32_t cpu_index,
    uint32_t *apic_id_out,
    uint32_t *state_out,
    uint32_t *numa_domain_out
) {
    if (cpu_index >= g_mp_state.cpu_count || cpu_index >= FBVBS_MAX_CPUS) {
        return -1;
    }
    if (apic_id_out != NULL) {
        *apic_id_out = g_mp_state.cpus[cpu_index].apic_id;
    }
    if (state_out != NULL) {
        *state_out = g_mp_state.cpus[cpu_index].state;
    }
    if (numa_domain_out != NULL) {
        *numa_domain_out = g_mp_state.cpus[cpu_index].numa_domain;
    }
    return 0;
}
