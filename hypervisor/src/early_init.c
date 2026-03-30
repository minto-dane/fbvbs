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
 *
 * Requirements: REQ-0001 (FreeBSD より前にロード),
 *   REQ-0002 (VMX root 取得), REQ-0006 (起動時検証)
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

/*@ requires \valid_read(msg);
    assigns \nothing;
*/
static void serial_print(const char *msg);

/*@ assigns \nothing;
*/
static void serial_print_u32(uint32_t value)
{
    char buffer[11];
    uint32_t index = 0U;

    if (value == 0U) {
        serial_print("0");
        return;
    }

    /*@
      @ loop invariant 0 <= index <= (uint32_t)sizeof(buffer);
      @ loop assigns value, index, buffer[0 .. 10];
      @ loop variant value;
      @*/
    while (value > 0U && index < (uint32_t)sizeof(buffer)) {
        buffer[index++] = (char)('0' + (value % 10U));
        value /= 10U;
    }

    /*@
      @ loop invariant 0 <= index <= (uint32_t)sizeof(buffer);
      @ loop assigns index;
      @ loop variant index;
      @*/
    while (index > 0U) {
        --index;
        {
            char ch[2];
            ch[0] = buffer[index];
            ch[1] = '\0';
            serial_print(ch);
        }
    }
}

/*@ requires \valid_read(boot_info);
    assigns g_early_mmap_count, g_early_mmap[0 .. FBVBS_MAX_EARLY_MMAP_ENTRIES - 1];
    ensures \result == 0 || \result == -1;
    ensures g_early_mmap_count <= FBVBS_MAX_EARLY_MMAP_ENTRIES;
*/
static int process_efi_memory_map(const struct fbvbs_efi_boot_info *boot_info)
{
#ifdef __FRAMAC__
    uint32_t i;
    g_early_mmap_count = 0;
    if (boot_info->memory_map_addr == 0 ||
        boot_info->descriptor_size == 0 ||
        boot_info->mmap_entry_count == 0) {
        return -1;
    }
    g_early_mmap_count = boot_info->mmap_entry_count;
    if (g_early_mmap_count > FBVBS_MAX_EARLY_MMAP_ENTRIES) {
        g_early_mmap_count = FBVBS_MAX_EARLY_MMAP_ENTRIES;
    }
    /*@
      @ loop invariant 0 <= i <= g_early_mmap_count;
      @ loop assigns i, g_early_mmap[0 .. FBVBS_MAX_EARLY_MMAP_ENTRIES - 1];
      @ loop variant g_early_mmap_count - i;
      @*/
    for (i = 0U; i < g_early_mmap_count; ++i) {
        g_early_mmap[i].base = 0U;
        g_early_mmap[i].size = 0U;
        g_early_mmap[i].type = 1U;
        g_early_mmap[i].reserved0 = 0U;
    }
    return 0;
#else
    const uint8_t *map_ptr;
    uint32_t i;
    uint32_t count;

    g_early_mmap_count = 0;
    map_ptr = (const uint8_t *)(uintptr_t)boot_info->memory_map_addr;
    count = boot_info->mmap_entry_count;
    if (count > FBVBS_MAX_EARLY_MMAP_ENTRIES) {
        serial_print("FBVBS: WARNING: EFI memory map truncated from ");
        serial_print_u32(count);
        serial_print(" to ");
        serial_print_u32(FBVBS_MAX_EARLY_MMAP_ENTRIES);
        serial_print(" entries\n");
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
    return 0;
#endif
}

/* ================================================================
 * Total usable memory calculation
 * ================================================================ */

/*@ requires g_early_mmap_count <= FBVBS_MAX_EARLY_MMAP_ENTRIES;
    assigns \nothing;
*/
static uint64_t total_usable_memory(void)
{
    uint64_t total = 0;
    uint32_t i;

    /*@
      @ loop invariant 0 <= i <= g_early_mmap_count;
      @ loop assigns i, total;
      @ loop variant g_early_mmap_count - i;
      @*/
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

/*@ assigns \nothing;
    ensures \result == FBVBS_VIRT_NONE ||
            \result == FBVBS_VIRT_VMX ||
            \result == FBVBS_VIRT_SVM;
*/
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
#define UART_LSR_OFFSET   5U
#define UART_LSR_THRE     0x20U  /* Transmit Holding Register Empty */

/*@ assigns \nothing;
*/
static void serial_putchar(char c)
{
#if defined(__x86_64__) && !defined(__FRAMAC__)
    /* Poll LSR until transmit holding register is empty */
    uint8_t lsr;
    uint32_t timeout = 100000U;
    do {
        __asm__ volatile("inb %1, %0"
                         : "=a"(lsr)
                         : "Nd"((uint16_t)(SERIAL_PORT_COM1 + UART_LSR_OFFSET)));
        if (--timeout == 0U) break;
    } while ((lsr & UART_LSR_THRE) == 0U);

    __asm__ volatile("outb %0, %1"
                     : : "a"((uint8_t)c), "Nd"((uint16_t)SERIAL_PORT_COM1));
#else
    (void)c;
#endif
}

/*@ requires \valid_read(msg);
    assigns \nothing;
*/
static void serial_print(const char *msg)
{
#ifdef __FRAMAC__
    (void)msg;
#else
    while (*msg != '\0') {
        if (*msg == '\n') {
            serial_putchar('\r');
        }
        serial_putchar(*msg);
        ++msg;
    }
#endif
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

/*@ requires \valid_read(boot_info);
    assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
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

/*@ requires boot_info == \null || \valid_read(boot_info);
    assigns g_early_mmap_count, g_early_mmap[0 .. FBVBS_MAX_EARLY_MMAP_ENTRIES - 1];
*/
void fbvbs_efi_to_hypervisor(struct fbvbs_efi_boot_info *boot_info)
{
    /* Validate boot info magic */
    if (boot_info == NULL || boot_info->magic != FBVBS_EFI_BOOT_MAGIC) {
        serial_print("FATAL: Invalid boot info\n");
        goto halt;
    }

    serial_print("FBVBS: Post-ExitBootServices initialization\n");

    /* Process EFI memory map */
    if (process_efi_memory_map(boot_info) != 0) {
        serial_print("FBVBS: ERROR: Failed to process memory map\n");
        goto halt;
    }
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
     * The repository now has assembly support for VMLAUNCH/VMRESUME,
     * but the end-to-end host handoff is still not architecturally
     * complete. The C-level hypervisor init
     * (fbvbs_hypervisor_init) is already implemented and tested;
     * the runnable deprivilege path still needs platform glue.
     */

    serial_print("FBVBS: Hypervisor initialization sequence pending\n");
    serial_print("FBVBS: Assembly platform glue required for:\n");
    serial_print("  - GDT/IDT load\n");
    serial_print("  - CR3 switch to W^X page tables\n");
    serial_print("  - VMX/SVM enable\n");
    serial_print("  - Host OS deprivilege\n");

halt:
#ifdef __FRAMAC__
    return;
#else
    for (;;) {
        __asm__ volatile ("cli; hlt");
    }
#endif
}
