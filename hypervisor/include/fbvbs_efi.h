#ifndef FBVBS_EFI_H
#define FBVBS_EFI_H

/* ================================================================
 * Minimal UEFI type definitions for FBVBS boot loader
 *
 * This header provides only the UEFI types and structures needed
 * by the FBVBS UEFI application. It is self-contained and does not
 * depend on external EDK2 or gnu-efi headers.
 *
 * Reference: UEFI Specification 2.10, Chapters 4, 7, 8, 12
 * ================================================================ */

#include <stdint.h>
#include <stddef.h>

/* ================================================================
 * Base UEFI types
 * ================================================================ */

typedef uint64_t EFI_STATUS;
typedef void    *EFI_HANDLE;
typedef void    *EFI_EVENT;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint64_t EFI_VIRTUAL_ADDRESS;
typedef uint64_t UINTN;
typedef int64_t  INTN;
typedef uint16_t CHAR16;
typedef uint8_t  BOOLEAN;

/* EFIAPI uses the Microsoft x64 ABI for UEFI x64 via __attribute__((ms_abi)). */
#define EFIAPI __attribute__((ms_abi))

/* ================================================================
 * EFI Status codes
 * ================================================================ */

#define EFI_SUCCESS               0ULL
#define EFI_ERROR_BIT             (1ULL << 63)
#define EFI_LOAD_ERROR            (EFI_ERROR_BIT | 1ULL)
#define EFI_INVALID_PARAMETER     (EFI_ERROR_BIT | 2ULL)
#define EFI_UNSUPPORTED           (EFI_ERROR_BIT | 3ULL)
#define EFI_BAD_BUFFER_SIZE       (EFI_ERROR_BIT | 4ULL)
#define EFI_BUFFER_TOO_SMALL      (EFI_ERROR_BIT | 5ULL)
#define EFI_NOT_READY             (EFI_ERROR_BIT | 6ULL)
#define EFI_DEVICE_ERROR          (EFI_ERROR_BIT | 7ULL)
#define EFI_NOT_FOUND             (EFI_ERROR_BIT | 14ULL)
#define EFI_OUT_OF_RESOURCES      (EFI_ERROR_BIT | 9ULL)
#define EFI_SECURITY_VIOLATION    (EFI_ERROR_BIT | 26ULL)

#define EFI_ERROR(status)         ((status) & EFI_ERROR_BIT)

/* ================================================================
 * Memory types and descriptors
 * ================================================================ */

typedef uint32_t EFI_MEMORY_TYPE;

#define EFI_RESERVED_MEMORY_TYPE       0U
#define EFI_LOADER_CODE                1U
#define EFI_LOADER_DATA                2U
#define EFI_BOOT_SERVICES_CODE         3U
#define EFI_BOOT_SERVICES_DATA         4U
#define EFI_RUNTIME_SERVICES_CODE      5U
#define EFI_RUNTIME_SERVICES_DATA      6U
#define EFI_CONVENTIONAL_MEMORY        7U
#define EFI_UNUSABLE_MEMORY            8U
#define EFI_ACPI_RECLAIM_MEMORY        9U
#define EFI_ACPI_MEMORY_NVS            10U
#define EFI_MEMORY_MAPPED_IO           11U
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE 12U
#define EFI_PAL_CODE                   13U
#define EFI_PERSISTENT_MEMORY          14U

/* Memory attribute bits */
#define EFI_MEMORY_UC   0x0000000000000001ULL
#define EFI_MEMORY_WC   0x0000000000000002ULL
#define EFI_MEMORY_WT   0x0000000000000004ULL
#define EFI_MEMORY_WB   0x0000000000000008ULL
#define EFI_MEMORY_UCE  0x0000000000000010ULL
#define EFI_MEMORY_WP   0x0000000000001000ULL
#define EFI_MEMORY_RP   0x0000000000002000ULL
#define EFI_MEMORY_XP   0x0000000000004000ULL
#define EFI_MEMORY_RO   0x0000000000020000ULL
#define EFI_MEMORY_RUNTIME 0x8000000000000000ULL

typedef struct {
    uint32_t            type;
    EFI_PHYSICAL_ADDRESS physical_start;
    EFI_VIRTUAL_ADDRESS  virtual_start;
    uint64_t            number_of_pages;
    uint64_t            attribute;
} EFI_MEMORY_DESCRIPTOR;

/* ================================================================
 * EFI Table Header
 * ================================================================ */

typedef struct {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
} EFI_TABLE_HEADER;

/* ================================================================
 * GUID
 * ================================================================ */

typedef struct {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t  data4[8];
} EFI_GUID;

/* ACPI 2.0 Table GUID (for RSDP discovery) */
#define EFI_ACPI_20_TABLE_GUID \
    { 0x8868E871U, 0xE4F1U, 0x11D3U, \
      { 0xBCU, 0x22U, 0x00U, 0x80U, 0xC7U, 0x3CU, 0x88U, 0x81U } }

/* ================================================================
 * EFI Configuration Table
 * ================================================================ */

typedef struct {
    EFI_GUID vendor_guid;
    void    *vendor_table;
} EFI_CONFIGURATION_TABLE;

/* ================================================================
 * Simple Text Output Protocol (for boot messages)
 * ================================================================ */

struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

typedef EFI_STATUS (EFIAPI *EFI_TEXT_STRING)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this_proto,
    CHAR16 *string
);

typedef EFI_STATUS (EFIAPI *EFI_TEXT_CLEAR_SCREEN)(
    struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *this_proto
);

typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    void                   *reset;
    EFI_TEXT_STRING         output_string;
    void                   *test_string;
    void                   *query_mode;
    void                   *set_mode;
    void                   *set_attribute;
    EFI_TEXT_CLEAR_SCREEN   clear_screen;
    void                   *set_cursor_position;
    void                   *enable_cursor;
    void                   *mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

/* ================================================================
 * EFI Boot Services (subset used by FBVBS)
 * ================================================================ */

typedef enum {
    AllocateAnyPages,
    AllocateMaxAddress,
    AllocateAddress,
    MaxAllocateType
} EFI_ALLOCATE_TYPE;

typedef EFI_STATUS (EFIAPI *EFI_ALLOCATE_PAGES)(
    EFI_ALLOCATE_TYPE type,
    EFI_MEMORY_TYPE memory_type,
    UINTN pages,
    EFI_PHYSICAL_ADDRESS *memory
);

typedef EFI_STATUS (EFIAPI *EFI_FREE_PAGES)(
    EFI_PHYSICAL_ADDRESS memory,
    UINTN pages
);

typedef EFI_STATUS (EFIAPI *EFI_GET_MEMORY_MAP)(
    UINTN *memory_map_size,
    EFI_MEMORY_DESCRIPTOR *memory_map,
    UINTN *map_key,
    UINTN *descriptor_size,
    uint32_t *descriptor_version
);

typedef EFI_STATUS (EFIAPI *EFI_EXIT_BOOT_SERVICES)(
    EFI_HANDLE image_handle,
    UINTN map_key
);

typedef EFI_STATUS (EFIAPI *EFI_SET_WATCHDOG_TIMER)(
    UINTN timeout,
    uint64_t watchdog_code,
    UINTN data_size,
    CHAR16 *watchdog_data
);

typedef struct {
    EFI_TABLE_HEADER        hdr;
    /* Task Priority Services */
    void                   *raise_tpl;
    void                   *restore_tpl;
    /* Memory Services */
    EFI_ALLOCATE_PAGES      allocate_pages;
    EFI_FREE_PAGES          free_pages;
    EFI_GET_MEMORY_MAP      get_memory_map;
    void                   *allocate_pool;
    void                   *free_pool;
    /* Event & Timer Services */
    void                   *create_event;
    void                   *set_timer;
    void                   *wait_for_event;
    void                   *signal_event;
    void                   *close_event;
    void                   *check_event;
    /* Protocol Handler Services */
    void                   *install_protocol_interface;
    void                   *reinstall_protocol_interface;
    void                   *uninstall_protocol_interface;
    void                   *handle_protocol;
    void                   *reserved;
    void                   *register_protocol_notify;
    void                   *locate_handle;
    void                   *locate_device_path;
    void                   *install_configuration_table;
    /* Image Services */
    void                   *load_image;
    void                   *start_image;
    void                   *exit;
    void                   *unload_image;
    EFI_EXIT_BOOT_SERVICES  exit_boot_services;
    /* Miscellaneous Services */
    void                   *get_next_monotonic_count;
    void                   *stall;
    EFI_SET_WATCHDOG_TIMER  set_watchdog_timer;
    /* DriverSupport Services */
    void                   *connect_controller;
    void                   *disconnect_controller;
    /* Open and Close Protocol Services */
    void                   *open_protocol;
    void                   *close_protocol;
    void                   *open_protocol_information;
    /* Library Services */
    void                   *protocols_per_handle;
    void                   *locate_handle_buffer;
    void                   *locate_protocol;
    void                   *install_multiple_protocol_interfaces;
    void                   *uninstall_multiple_protocol_interfaces;
    /* 32-bit CRC Services */
    void                   *calculate_crc32;
    /* Miscellaneous Services */
    void                   *copy_mem;
    void                   *set_mem;
    void                   *create_event_ex;
} EFI_BOOT_SERVICES;

/* ================================================================
 * EFI System Table
 * ================================================================ */

typedef struct {
    EFI_TABLE_HEADER                  hdr;
    CHAR16                           *firmware_vendor;
    uint32_t                          firmware_revision;
    EFI_HANDLE                        console_in_handle;
    void                             *con_in;
    EFI_HANDLE                        console_out_handle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL   *con_out;
    EFI_HANDLE                        standard_error_handle;
    void                             *std_err;
    void                             *runtime_services;
    EFI_BOOT_SERVICES                *boot_services;
    UINTN                             number_of_table_entries;
    EFI_CONFIGURATION_TABLE          *configuration_table;
} EFI_SYSTEM_TABLE;

/* ================================================================
 * FBVBS EFI boot information (passed to hypervisor after ExitBootServices)
 * ================================================================ */

#define FBVBS_EFI_BOOT_MAGIC  0x0049455342564246ULL  /* "FBVBSEI\0" */

#define FBVBS_EFI_MAX_MMAP_ENTRIES 512

struct fbvbs_efi_boot_info {
    uint64_t magic;
    uint64_t acpi_rsdp;                /* ACPI 2.0 RSDP physical address */
    uint64_t memory_map_addr;
    uint64_t memory_map_size;
    uint64_t descriptor_size;
    uint32_t descriptor_version;
    uint32_t mmap_entry_count;
    uint64_t hypervisor_base;          /* Physical base of hypervisor image */
    uint64_t hypervisor_size;          /* Size of hypervisor image in bytes */
    uint64_t stack_base;               /* Allocated stack base */
    uint64_t stack_size;               /* Allocated stack size */
};

/* ================================================================
 * FBVBS EFI boot entry point (implemented in early_init.c)
 * ================================================================ */

void fbvbs_efi_to_hypervisor(struct fbvbs_efi_boot_info *boot_info);

/* UEFI application entry point */
EFI_STATUS EFIAPI efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE *system_table);

#endif /* FBVBS_EFI_H */
