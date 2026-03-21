#include "fbvbs_efi.h"
#include "fbvbs_hypervisor.h"

/* ================================================================
 * Early initialization after ExitBootServices
 *
 * This module handles the transition from UEFI to bare-metal
 * hypervisor operation. After ExitBootServices:
 *
 *   - No UEFI services are available
 *   - The hypervisor owns all physical memory
 *   - Interrupts are disabled
 *   - We must set up our own page tables, GDT, IDT
 *   - Then initialize VMX/SVM and start the hypervisor
 *
 * PRODUCTION NOTE: The actual page table setup and VMX/SVM
 * initialization requires assembly for CR writes, VMXON, etc.
 * This C module provides the logic; assembly stubs provide
 * the privileged operations.
 *
 * Reference: Intel SDM Vol. 3, Chapter 23 (VMX)
 * ================================================================ */

/* ================================================================
 * Memory map processing
 *
 * Converts the EFI memory map into a format usable by the
 * hypervisor's memory management subsystem.
 * ================================================================ */

#define FBVBS_MAX_EARLY_MMAP_ENTRIES 256

struct fbvbs_early_mmap_entry {
    uint64_t base;
    uint64_t size;
    uint32_t type;       /* 0=reserved, 1=usable, 2=ACPI, 3=runtime */
    uint32_t reserved0;
};

static struct fbvbs_early_mmap_entry g_early_mmap[FBVBS_MAX_EARLY_MMAP_ENTRIES];
static uint32_t g_early_mmap_count;

static void process_efi_memory_map(const struct fbvbs_efi_boot_info *boot_info)
{
    const uint8_t *map_ptr;
    uint32_t i;
    uint32_t count;

    g_early_mmap_count = 0;

    if (boot_info->memory_map_addr == 0 ||
        boot_info->descriptor_size == 0 ||
        boot_info->mmap_entry_count == 0) {
        return;
    }

    map_ptr = (const uint8_t *)(uintptr_t)boot_info->memory_map_addr;
    count = boot_info->mmap_entry_count;
    if (count > FBVBS_MAX_EARLY_MMAP_ENTRIES) {
        count = FBVBS_MAX_EARLY_MMAP_ENTRIES;
    }

    for (i = 0; i < count; ++i) {
        const EFI_MEMORY_DESCRIPTOR *desc =
            (const EFI_MEMORY_DESCRIPTOR *)(map_ptr + i * boot_info->descriptor_size);

        g_early_mmap[i].base = desc->physical_start;
        g_early_mmap[i].size = desc->number_of_pages * 4096ULL;

        switch (desc->type) {
        case EFI_CONVENTIONAL_MEMORY:
        case EFI_LOADER_CODE:
        case EFI_LOADER_DATA:
        case EFI_BOOT_SERVICES_CODE:
        case EFI_BOOT_SERVICES_DATA:
            g_early_mmap[i].type = 1U;  /* Usable */
            break;
        case EFI_ACPI_RECLAIM_MEMORY:
            g_early_mmap[i].type = 2U;  /* ACPI (reclaimable) */
            break;
        case EFI_RUNTIME_SERVICES_CODE:
        case EFI_RUNTIME_SERVICES_DATA:
            g_early_mmap[i].type = 3U;  /* Runtime (must preserve) */
            break;
        default:
            g_early_mmap[i].type = 0U;  /* Reserved */
            break;
        }
        g_early_mmap[i].reserved0 = 0;
    }

    g_early_mmap_count = count;
}

/* ================================================================
 * Total usable memory calculation
 * ================================================================ */

static uint64_t total_usable_memory(void)
{
    uint64_t total = 0;
    uint32_t i;

    for (i = 0; i < g_early_mmap_count; ++i) {
        if (g_early_mmap[i].type == 1U) {
            total += g_early_mmap[i].size;
        }
    }

    return total;
}

/* ================================================================
 * VMX/SVM capability check (pre-enable)
 *
 * PRODUCTION NOTE: This must read MSRs and check CPUID bits
 * before attempting VMXON/VMRUN. The model returns a placeholder.
 * ================================================================ */

#define FBVBS_VIRT_NONE  0U
#define FBVBS_VIRT_VMX   1U
#define FBVBS_VIRT_SVM   2U

static uint32_t detect_virtualization_support(void)
{
    /* PRODUCTION NOTE: Check CPUID.1:ECX[5] (VMX) and
     * CPUID.80000001:ECX[2] (SVM). Also check
     * IA32_FEATURE_CONTROL MSR lock bits for VMX. */
#if defined(__FRAMAC__)
    return FBVBS_VIRT_VMX;
#else
    return FBVBS_VIRT_NONE;  /* Fail-closed until CPUID check implemented */
#endif
}

/* ================================================================
 * Serial port output (post-ExitBootServices)
 *
 * After ExitBootServices, UEFI console is gone. Use COM1 (0x3F8)
 * for debug output. This is the only output method available until
 * the hypervisor initializes its own logging subsystem.
 * ================================================================ */

#define SERIAL_PORT_COM1  0x3F8U

static void serial_putchar(char c)
{
    /* PRODUCTION NOTE: Must check LSR transmit-empty bit before write.
     * outb(SERIAL_PORT_COM1, c) via inline asm:
     *   asm volatile ("outb %0, %1" : : "a"(c), "Nd"(SERIAL_PORT_COM1));
     */
    (void)c;
}

static void serial_print(const char *msg)
{
    while (*msg != '\0') {
        if (*msg == '\n') {
            serial_putchar('\r');
        }
        serial_putchar(*msg);
        ++msg;
    }
}

/* ================================================================
 * Page table setup for hypervisor
 *
 * PRODUCTION NOTE: After ExitBootServices, we inherit UEFI's
 * page tables. We must build our own identity-mapped page tables
 * with W^X enforcement before enabling VMX. This requires:
 *
 * 1. Allocate pages from usable memory for PML4/PDPT/PD/PT
 * 2. Identity-map all usable memory regions
 * 3. Mark code pages as RX, data pages as RW+NX
 * 4. Load CR3 with new PML4 base
 *
 * The existing boot.S has a working implementation of this for
 * the Multiboot2 path. The UEFI path needs the same logic but
 * operating on dynamically-located memory instead of static BSS.
 * ================================================================ */

static int setup_hypervisor_page_tables(
    const struct fbvbs_efi_boot_info *boot_info)
{
    (void)boot_info;

    /* PRODUCTION NOTE: Implement identity-mapped page tables here.
     * Use the EFI memory map to determine which regions to map
     * and with what permissions.
     *
     * The page table root address must be stored so it can be
     * loaded into CR3 via assembly. */

    serial_print("Page tables: pending implementation\n");
    return -1;  /* Fail-closed */
}

/* ================================================================
 * Main entry point from UEFI trampoline
 *
 * This is called after ExitBootServices, with interrupts disabled,
 * on the UEFI-allocated stack. It processes the boot information,
 * sets up the hypervisor environment, and starts the hypervisor.
 * ================================================================ */

void fbvbs_efi_to_hypervisor(struct fbvbs_efi_boot_info *boot_info)
{
    /* Validate boot info magic */
    if (boot_info == NULL || boot_info->magic != FBVBS_EFI_BOOT_MAGIC) {
        serial_print("FATAL: Invalid boot info\n");
        goto halt;
    }

    serial_print("FBVBS: Post-ExitBootServices initialization\n");

    /* Process EFI memory map */
    process_efi_memory_map(boot_info);
    serial_print("FBVBS: Memory map processed\n");

    {
        uint64_t usable = total_usable_memory();
        (void)usable;
        /* PRODUCTION NOTE: Log usable memory via serial */
    }

    /* Check virtualization support */
    {
        uint32_t virt = detect_virtualization_support();
        if (virt == FBVBS_VIRT_NONE) {
            serial_print("FATAL: No virtualization support (VMX/SVM)\n");
            goto halt;
        }
        serial_print(virt == FBVBS_VIRT_VMX ?
                     "FBVBS: Intel VMX detected\n" :
                     "FBVBS: AMD SVM detected\n");
    }

    /* Set up hypervisor page tables */
    if (setup_hypervisor_page_tables(boot_info) != 0) {
        serial_print("FATAL: Page table setup failed\n");
        goto halt;
    }

    /* PRODUCTION NOTE: At this point, the full initialization
     * sequence would be:
     *
     * 1. Load new GDT (64-bit flat model, TSS for VM exits)
     * 2. Load new IDT (minimal: #PF, #GP, #DF, NMI handlers)
     * 3. Switch to hypervisor page tables (CR3 write)
     * 4. Enable VMX (CR4.VMXE, then VMXON)
     *    or Enable SVM (EFER.SVME, then allocate HSAVE area)
     * 5. Set up initial VMCS/VMCB for the host OS (FreeBSD)
     * 6. Call fbvbs_hypervisor_init()
     * 7. Launch host OS as a deprivileged guest
     *
     * Each step requires assembly support code. The C-level
     * hypervisor init (fbvbs_hypervisor_init) is already
     * implemented and tested — only the platform glue is missing.
     */

    serial_print("FBVBS: Hypervisor initialization sequence pending\n");
    serial_print("FBVBS: Assembly platform glue required for:\n");
    serial_print("  - GDT/IDT load\n");
    serial_print("  - CR3 switch to W^X page tables\n");
    serial_print("  - VMX/SVM enable\n");
    serial_print("  - Host OS deprivilege\n");

halt:
    for (;;) {
        __asm__ volatile ("cli; hlt");
    }
}
