#include "fbvbs_hypervisor.h"

/*@ assigns \nothing;
*/
static void fbvbs_multiboot_status(const char *message) {
#ifdef FBVBS_BAREMETAL_BUILD
    fbvbs_boot_console_puts(message);
#else
    (void)message;
#endif
}

/*@ requires \valid(destination + (0 .. FBVBS_BOOT_MODULE_CMDLINE_BYTES - 1));
    requires source_length == 0 || \valid_read(source + (0 .. source_length - 1));
    assigns destination[0 .. FBVBS_BOOT_MODULE_CMDLINE_BYTES - 1];
*/
static void fbvbs_multiboot_copy_cmdline(
    char destination[FBVBS_BOOT_MODULE_CMDLINE_BYTES],
    const uint8_t *source,
    uint32_t source_length
) {
    uint32_t index = 0U;

    if (destination == NULL) {
        return;
    }

    while (index + 1U < FBVBS_BOOT_MODULE_CMDLINE_BYTES &&
           index < source_length &&
           source[index] != 0U) {
        destination[index] = (char)source[index];
        ++index;
    }
    destination[index] = '\0';
    while (index + 1U < FBVBS_BOOT_MODULE_CMDLINE_BYTES) {
        ++index;
        destination[index] = '\0';
    }
}

/* Process Multiboot information structure.
 *
 * This function is excluded from Frama-C WP analysis because it
 * necessarily uses void* casts to parse the Multiboot2 binary
 * information structure. The function is verified by GCC -fanalyzer
 * and manual review instead.
 */
void fbvbs_process_multiboot_info(struct fbvbs_hypervisor_state *state,
                                  const void *multiboot_info,
                                  uint32_t buffer_size) {
    const uint8_t *info_bytes = (const uint8_t *)multiboot_info;
    uint32_t total_size;
    uint32_t offset;

    if (state == NULL || multiboot_info == NULL) {
        return;
    }
    if (buffer_size < 8U) {
        fbvbs_multiboot_status("FBVBS: mb2 buffer too small\n");
        return;
    }

    /* Multiboot2 information structure format:
     * [0] total_size (bytes)
     * [1] reserved
     * [2...] tags
     *
     * Use memcpy for all uint32_t reads: the pointer may not be
     * 4-byte aligned (e.g. from fuzzer input), so direct cast to
     * uint32_t* would be undefined behavior per C11 6.3.2.3p7. */
    fbvbs_copy_memory(&total_size, info_bytes, sizeof(total_size));
    offset = 8;  /* Skip total_size and reserved */

    /* Hardening: reject implausible total_size (max 64 MB).
       A Multiboot2 information structure should never be this large;
       an attacker-controlled bootloader could otherwise cause unbounded reads. */
    if (total_size < 8U || total_size > (64U * 1024U * 1024U)) {
        fbvbs_multiboot_status("FBVBS: mb2 total size invalid\n");
        return;
    }

    /* Clamp total_size to the actual buffer extent to prevent
       out-of-bounds reads if firmware provides a malformed size. */
    if (total_size > buffer_size) {
        total_size = buffer_size;
    }

    /* Initialize parsed boot metadata */
    state->acpi_rsdp = NULL;
    state->memory_map_count = 0U;
    state->boot_device = 0U;
    state->boot_partition = 0U;
    state->boot_sub_partition = 0U;
    state->boot_module_count = 0U;
    for (offset = 0U; offset < FBVBS_MAX_BOOT_MODULES; ++offset) {
        state->boot_modules[offset] = (struct fbvbs_boot_module){0};
    }
    offset = 8U;

    /* Iterate through tags */
    while (offset < total_size) {
        const uint8_t *tag_ptr;
        uint32_t type;
        uint32_t size;
        uint32_t aligned_size;

        /* Hardening: ensure at least 8 bytes remain for tag header */
        if (offset > total_size - 8U) {
            fbvbs_multiboot_status("FBVBS: mb2 truncated tag header\n");
            return;
        }

        tag_ptr = info_bytes + offset;
        fbvbs_copy_memory(&type, tag_ptr, sizeof(type));
        fbvbs_copy_memory(&size, tag_ptr + 4U, sizeof(size));

        /* Guard against zero-size tags causing infinite loop */
        if (size < 8U) {
            fbvbs_multiboot_status("FBVBS: mb2 zero/short tag\n");
            return;
        }
        /* Guard against size exceeding remaining space */
        if (size > total_size - offset) {
            fbvbs_multiboot_status("FBVBS: mb2 oversize tag\n");
            return;
        }
        /* Align to 8-byte boundary.
           Overflow-safe: size <= total_size - offset <= 64MB, so size + 7 <= 64MB + 7 */
        aligned_size = (size + 7U) & ~7U;

        switch (type) {
            case 0:  /* End tag */
                return;

            case 4:  /* Basic memory information */
                if (size >= 16) {
                    /* mem_lower and mem_upper in KB */
                    uint32_t mem_lower, mem_upper;
                    fbvbs_copy_memory(&mem_lower, tag_ptr + 8U, sizeof(mem_lower));
                    fbvbs_copy_memory(&mem_upper, tag_ptr + 12U, sizeof(mem_upper));
                    /* Store memory information if needed */
                    (void)mem_lower;
                    (void)mem_upper;
                }
                break;

            case 6:  /* Memory map */
                /* Process memory map entries */
                if (size >= 16) {
                    uint32_t entry_size, entry_version;
                    fbvbs_copy_memory(&entry_size, tag_ptr + 8U, sizeof(entry_size));
                    fbvbs_copy_memory(&entry_version, tag_ptr + 12U, sizeof(entry_version));
                    uint32_t entry_offset = offset + 16;

                    (void)entry_version;

                    /* Guard against zero or undersized entry_size.
                       Multiboot2 mmap entries are min 24 bytes (base:8 + length:8 + type:4 + reserved:4).
                       A malicious bootloader could set entry_size < 24 to cause OOB reads. */
                    if (entry_size < 24U || entry_size > size) {
                        fbvbs_multiboot_status("FBVBS: mb2 bad mmap entry size\n");
                        break;
                    }
                    while (entry_offset + entry_size <= offset + size && state->memory_map_count < 32U) {
                        const uint8_t *entry = info_bytes + entry_offset;
                        uint64_t base_addr = 0U;
                        uint64_t length = 0U;
                        uint32_t entry_type = 0U;

                        fbvbs_copy_memory(&base_addr, entry, sizeof(base_addr));
                        fbvbs_copy_memory(&length, entry + 8U, sizeof(length));
                        fbvbs_copy_memory(&entry_type, entry + 16U, sizeof(entry_type));

                        /* Store memory map entry */
                        state->memory_map[state->memory_map_count].base_addr = base_addr;
                        state->memory_map[state->memory_map_count].length = length;
                        state->memory_map[state->memory_map_count].type = entry_type;
                        state->memory_map[state->memory_map_count].reserved = 0U;
                        state->memory_map_count++;

                        entry_offset += entry_size;
                    }
                }
                break;

            case 1:  /* Command line */
                /* Process command line string */
                if (size > 8) {
                    const char *cmdline = (const char *)(info_bytes + offset + 8U);
                    (void)cmdline;
                }
                break;

            case 3:  /* Module */
                /* Process module information */
                if (size >= 16) {
                    uint32_t mod_start, mod_end;
                    fbvbs_copy_memory(&mod_start, tag_ptr + 8U, sizeof(mod_start));
                    fbvbs_copy_memory(&mod_end, tag_ptr + 12U, sizeof(mod_end));
                    const char *cmdline = (const char *)(info_bytes + offset + 16U);
                    (void)cmdline;

                    if (mod_end > mod_start &&
                        state->boot_module_count < FBVBS_MAX_BOOT_MODULES) {
                        struct fbvbs_boot_module *module =
                            &state->boot_modules[state->boot_module_count];
                        uint32_t cmdline_length = size - 16U;

                        *module = (struct fbvbs_boot_module){0};
                        module->active = true;
                        module->start_phys = (uint64_t)mod_start;
                        module->size = (uint64_t)(mod_end - mod_start);
                        fbvbs_multiboot_copy_cmdline(
                            module->cmdline,
                            tag_ptr + 16U,
                            cmdline_length
                        );
                        state->boot_module_count += 1U;
                    }
                }
                break;

            case 5:  /* Boot device */
                /* Process boot device information */
                if (size >= 20) {
                    uint32_t biosdev, partition_num, sub_partition;
                    fbvbs_copy_memory(&biosdev, tag_ptr + 8U, sizeof(biosdev));
                    fbvbs_copy_memory(&partition_num, tag_ptr + 12U, sizeof(partition_num));
                    fbvbs_copy_memory(&sub_partition, tag_ptr + 16U, sizeof(sub_partition));
                    state->boot_device = biosdev;
                    state->boot_partition = partition_num;
                    state->boot_sub_partition = sub_partition;
                }
                break;

            case 14:  /* ACPI RSDP v1 */
                if (size >= 28U && state->acpi_rsdp == NULL) {
                    state->acpi_rsdp = tag_ptr + 8U;
                }
                break;

            case 15:  /* ACPI RSDP v2+ (36-byte RSDP after 8-byte tag header) */
                if (size >= 44U) {
                    /* Prefer the newer ACPI handoff if both are present. */
                    state->acpi_rsdp = tag_ptr + 8U;
                }
                break;

            default:
                /* Unknown tag, skip */
                break;
        }

        /* Hardening: prevent offset wraparound */
        if (aligned_size > total_size - offset) {
            fbvbs_multiboot_status("FBVBS: mb2 aligned size overflow\n");
            return;
        }
        offset += aligned_size;
    }
}
