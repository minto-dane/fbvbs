#include "fbvbs_efi.h"

/* ================================================================
 * FBVBS UEFI Application Entry Point
 *
 * This is the EFI_MAIN entry point for the FBVBS microhypervisor
 * when loaded as a UEFI application (.efi). It:
 *
 *   1. Obtains the EFI memory map
 *   2. Locates the ACPI RSDP from EFI configuration tables
 *   3. Allocates pages for the hypervisor stack and page tables
 *   4. Calls ExitBootServices to take ownership of the platform
 *   5. Transitions to hypervisor initialization
 *
 * After ExitBootServices, no UEFI services are available. The
 * hypervisor must operate using only its own code and the memory
 * map snapshot captured before exit.
 *
 * Reference: UEFI Specification 2.10, Chapter 7 (Boot Services)
 *
 * PRODUCTION NOTE: This file must be compiled with MS ABI
 * (gcc -mabi=ms or -target x86_64-unknown-windows) to match
 * the UEFI calling convention. The hypervisor proper uses
 * System V ABI, so a trampoline is needed at the transition.
 * ================================================================ */

/* Hypervisor stack: 64 KiB, allocated from UEFI */
#define FBVBS_HV_STACK_PAGES   16U
#define FBVBS_HV_STACK_SIZE    (FBVBS_HV_STACK_PAGES * 4096U)

/* Page table pages: PML4 + PDPT + 4×PD + 512×PT = ~518 pages */
#define FBVBS_HV_PAGETABLE_PAGES  520U

/* Maximum memory map buffer size (512 entries × ~48 bytes + headroom) */
#define FBVBS_MMAP_BUFFER_SIZE  (FBVBS_EFI_MAX_MMAP_ENTRIES * 48U + 4096U)

/* ================================================================
 * Boot-time output helpers
 * ================================================================ */

static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *g_con_out;

static void efi_print(const CHAR16 *msg)
{
    if (g_con_out != NULL && g_con_out->output_string != NULL) {
        /* Cast required: UEFI EFI_TEXT_STRING takes non-const CHAR16*.
         * The protocol does not modify the string. */
        g_con_out->output_string(g_con_out, (CHAR16 *)(uintptr_t)msg);
    }
}

static void efi_print_hex(uint64_t value)
{
    CHAR16 buf[19]; /* "0x" + 16 hex digits + null */
    static const CHAR16 hex[] = u"0123456789ABCDEF";
    int i;

    buf[0] = u'0';
    buf[1] = u'x';
    for (i = 0; i < 16; ++i) {
        buf[2 + i] = hex[(value >> (60 - i * 4)) & 0xFU];
    }
    buf[18] = u'\0';
    efi_print(buf);
}

/* ================================================================
 * GUID comparison
 * ================================================================ */

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
    return (a->data1 == b->data1 &&
            a->data2 == b->data2 &&
            a->data3 == b->data3 &&
            a->data4[0] == b->data4[0] &&
            a->data4[1] == b->data4[1] &&
            a->data4[2] == b->data4[2] &&
            a->data4[3] == b->data4[3] &&
            a->data4[4] == b->data4[4] &&
            a->data4[5] == b->data4[5] &&
            a->data4[6] == b->data4[6] &&
            a->data4[7] == b->data4[7]);
}

/* ================================================================
 * Locate ACPI 2.0 RSDP from EFI Configuration Tables
 * ================================================================ */

static uint64_t find_acpi_rsdp(EFI_SYSTEM_TABLE *system_table)
{
    EFI_GUID acpi20_guid = EFI_ACPI_20_TABLE_GUID;
    UINTN i;

    if (system_table == NULL ||
        system_table->configuration_table == NULL) {
        return 0;
    }

    /* Bound iteration to prevent OOB read from malicious firmware */
    if (system_table->number_of_table_entries > 1024U) {
        return 0;
    }

    for (i = 0; i < system_table->number_of_table_entries; ++i) {
        if (guid_equal(&system_table->configuration_table[i].vendor_guid,
                       &acpi20_guid)) {
            return (uint64_t)(uintptr_t)
                system_table->configuration_table[i].vendor_table;
        }
    }

    return 0;
}

/* ================================================================
 * Get EFI memory map
 *
 * Returns the map_key needed for ExitBootServices.
 * The memory map buffer must be pre-allocated.
 * ================================================================ */

static EFI_STATUS get_memory_map(
    EFI_BOOT_SERVICES *bs,
    uint8_t *buffer,
    UINTN buffer_size,
    UINTN *map_key_out,
    UINTN *mmap_size_out,
    UINTN *desc_size_out,
    uint32_t *desc_version_out)
{
    *mmap_size_out = buffer_size;

    return bs->get_memory_map(
        mmap_size_out,
        (EFI_MEMORY_DESCRIPTOR *)buffer,
        map_key_out,
        desc_size_out,
        desc_version_out
    );
}

/* ================================================================
 * Hypervisor entry point (called after ExitBootServices)
 *
 * PRODUCTION NOTE: This function must:
 * 1. Switch from MS ABI to System V ABI
 * 2. Set up hypervisor page tables (identity-mapped with W^X)
 * 3. Set up GDT/IDT
 * 4. Enable VMX (CR4.VMXE → VMXON)
 * 5. Call fbvbs_hypervisor_init()
 *
 * For now, this is a placeholder that demonstrates the transition.
 * The actual transition requires assembly (ABI trampoline + CR writes).
 * ================================================================ */

typedef void (*fbvbs_hv_entry_fn)(struct fbvbs_efi_boot_info *boot_info);

/* Forward declaration — implemented in early_init.c or assembly */
extern void fbvbs_efi_to_hypervisor(struct fbvbs_efi_boot_info *boot_info);

/* Weak symbol: allows linking without early_init for build testing */
__attribute__((weak))
void fbvbs_efi_to_hypervisor(struct fbvbs_efi_boot_info *boot_info)
{
    (void)boot_info;
    /* PRODUCTION NOTE: This weak stub halts. Real implementation
     * in boot/early_init.S performs ABI switch and VMX setup. */
    for (;;) {
        __asm__ volatile ("cli; hlt");
    }
}

/* ================================================================
 * EFI_MAIN — UEFI Application Entry Point
 * ================================================================ */

EFI_STATUS EFIAPI efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table)
{
    EFI_BOOT_SERVICES *bs;
    EFI_STATUS status;
    struct fbvbs_efi_boot_info boot_info;
    EFI_PHYSICAL_ADDRESS mmap_buffer_phys = 0;
    uint8_t *mmap_buffer = NULL;
    UINTN map_key = 0;
    UINTN mmap_size = 0;
    UINTN desc_size = 0;
    uint32_t desc_version = 0;
    EFI_PHYSICAL_ADDRESS stack_pages = 0;
    UINTN mmap_page_count = (FBVBS_MMAP_BUFFER_SIZE + 4095U) / 4096U;

    /* Basic validation */
    if (system_table == NULL || system_table->boot_services == NULL) {
        return EFI_INVALID_PARAMETER;
    }

    bs = system_table->boot_services;
    g_con_out = system_table->con_out;

    /* Disable watchdog timer (default 5-minute reset) */
    bs->set_watchdog_timer(0, 0, 0, (CHAR16 *)0);

    /* Clear screen and print banner */
    if (g_con_out != NULL && g_con_out->clear_screen != NULL) {
        g_con_out->clear_screen(g_con_out);
    }
    efi_print(u"FBVBS Microhypervisor UEFI Loader v0.1\r\n");
    efi_print(u"======================================\r\n\r\n");

    /* ---- Step 1: Locate ACPI RSDP ---- */
    boot_info = (struct fbvbs_efi_boot_info){0};
    boot_info.magic = FBVBS_EFI_BOOT_MAGIC;
    boot_info.acpi_rsdp = find_acpi_rsdp(system_table);

    if (boot_info.acpi_rsdp == 0) {
        efi_print(u"ERROR: ACPI 2.0 RSDP not found\r\n");
        return EFI_NOT_FOUND;
    }
    efi_print(u"ACPI RSDP: ");
    efi_print_hex(boot_info.acpi_rsdp);
    efi_print(u"\r\n");

    /* ---- Step 2: Allocate memory map buffer ---- */
    status = bs->allocate_pages(
        AllocateAnyPages,
        EFI_LOADER_DATA,
        mmap_page_count,
        &mmap_buffer_phys
    );
    if (EFI_ERROR(status)) {
        efi_print(u"ERROR: Failed to allocate memory map buffer\r\n");
        return status;
    }
    mmap_buffer = (uint8_t *)(uintptr_t)mmap_buffer_phys;

    /* ---- Step 3: Allocate hypervisor stack ---- */
    status = bs->allocate_pages(
        AllocateAnyPages,
        EFI_LOADER_DATA,
        FBVBS_HV_STACK_PAGES,
        &stack_pages
    );
    if (EFI_ERROR(status)) {
        efi_print(u"ERROR: Failed to allocate stack pages\r\n");
        bs->free_pages(mmap_buffer_phys, mmap_page_count);
        return status;
    }
    boot_info.stack_base = stack_pages;
    boot_info.stack_size = FBVBS_HV_STACK_SIZE;

    efi_print(u"Stack allocated at: ");
    efi_print_hex(stack_pages);
    efi_print(u"\r\n");

    /* ---- Step 4: Get memory map ---- */
    status = get_memory_map(
        bs, mmap_buffer, FBVBS_MMAP_BUFFER_SIZE,
        &map_key, &mmap_size, &desc_size, &desc_version
    );
    if (EFI_ERROR(status)) {
        efi_print(u"ERROR: Failed to get memory map\r\n");
        bs->free_pages(stack_pages, FBVBS_HV_STACK_PAGES);
        bs->free_pages(mmap_buffer_phys, mmap_page_count);
        return status;
    }

    /* The memory-map buffer is page-allocated so it survives the
     * ExitBootServices transition. */
    boot_info.memory_map_addr = (uint64_t)(uintptr_t)mmap_buffer;
    boot_info.memory_map_size = mmap_size;
    boot_info.descriptor_size = desc_size;
    boot_info.descriptor_version = desc_version;
    if (desc_size > 0) {
        boot_info.mmap_entry_count = (uint32_t)(mmap_size / desc_size);
    }

    efi_print(u"Memory map entries: ");
    efi_print_hex((uint64_t)boot_info.mmap_entry_count);
    efi_print(u"\r\n");

    /* ---- Step 5: Exit Boot Services ---- */
    efi_print(u"\r\nExiting boot services...\r\n");

    /* ExitBootServices may invalidate the memory map; the spec
     * requires calling GetMemoryMap again if it returns
     * EFI_INVALID_PARAMETER (stale map_key). */
    status = bs->exit_boot_services(image_handle, map_key);
    if (status == EFI_INVALID_PARAMETER) {
        /* Stale map_key: get fresh memory map and retry (UEFI spec §7.4) */
        mmap_size = FBVBS_MMAP_BUFFER_SIZE;
        status = bs->get_memory_map(
            &mmap_size,
            (EFI_MEMORY_DESCRIPTOR *)mmap_buffer,
            &map_key,
            &desc_size,
            &desc_version
        );
        if (EFI_ERROR(status)) {
            bs->free_pages(stack_pages, FBVBS_HV_STACK_PAGES);
            bs->free_pages(mmap_buffer_phys, mmap_page_count);
            return status;
        }
        boot_info.memory_map_size = mmap_size;
        boot_info.descriptor_size = desc_size;
        boot_info.descriptor_version = desc_version;
        if (desc_size > 0) {
            boot_info.mmap_entry_count = (uint32_t)(mmap_size / desc_size);
        }

        status = bs->exit_boot_services(image_handle, map_key);
        if (EFI_ERROR(status)) {
            /* Fatal: cannot exit boot services */
            bs->free_pages(stack_pages, FBVBS_HV_STACK_PAGES);
            bs->free_pages(mmap_buffer_phys, mmap_page_count);
            return status;
        }
    } else if (EFI_ERROR(status)) {
        /* Non-retryable error — propagate immediately */
        bs->free_pages(stack_pages, FBVBS_HV_STACK_PAGES);
        bs->free_pages(mmap_buffer_phys, mmap_page_count);
        return status;
    }

    /* ---- Step 6: Transition to hypervisor ---- */
    /* After ExitBootServices:
     * - No UEFI services available (bs pointer is invalid)
     * - No console output possible
     * - We own the entire platform
     * - Interrupts should be disabled
     * - Must set up our own page tables, GDT, IDT */

    fbvbs_efi_to_hypervisor(&boot_info);

    /* Should never reach here */
    for (;;) {
        __asm__ volatile ("cli; hlt");
    }

    return EFI_LOAD_ERROR;
}
