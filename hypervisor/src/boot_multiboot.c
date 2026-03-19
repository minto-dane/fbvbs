#include "fbvbs_hypervisor.h"

/* Process Multiboot information structure.
 *
 * This function is excluded from Frama-C WP analysis because it
 * necessarily uses void* casts to parse the Multiboot2 binary
 * information structure. The function is verified by GCC -fanalyzer
 * and manual review instead.
 */
void fbvbs_process_multiboot_info(struct fbvbs_hypervisor_state *state, const void *multiboot_info) {
    const uint32_t *info = (const uint32_t *)multiboot_info;
    uint32_t total_size;
    uint32_t offset;

    if (state == NULL || multiboot_info == NULL) {
        return;
    }

    /* Multiboot2 information structure format:
     * [0] total_size (bytes)
     * [1] reserved
     * [2...] tags
     */
    total_size = info[0];
    offset = 8;  /* Skip total_size and reserved */

    /* Hardening: reject implausible total_size (max 64 MB).
       A Multiboot2 information structure should never be this large;
       an attacker-controlled bootloader could otherwise cause unbounded reads. */
    if (total_size < 8U || total_size > (64U * 1024U * 1024U)) {
        return;
    }

    /* Initialize memory map count */
    state->memory_map_count = 0U;

    /* Iterate through tags */
    while (offset < total_size) {
        const uint32_t *tag;
        uint32_t type;
        uint32_t size;
        uint32_t aligned_size;

        /* Hardening: ensure at least 8 bytes remain for tag header */
        if (offset > total_size - 8U) {
            return;
        }

        tag = (const uint32_t *)((const uint8_t *)multiboot_info + offset);
        type = tag[0];
        size = tag[1];

        /* Guard against zero-size tags causing infinite loop */
        if (size < 8U) {
            return;
        }
        /* Guard against size exceeding remaining space */
        if (size > total_size - offset) {
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
                    uint32_t mem_lower = tag[2];
                    uint32_t mem_upper = tag[3];
                    /* Store memory information if needed */
                    (void)mem_lower;
                    (void)mem_upper;
                }
                break;

            case 6:  /* Memory map */
                /* Process memory map entries */
                if (size >= 16) {
                    uint32_t entry_size = tag[2];
                    uint32_t entry_version = tag[3];
                    uint32_t entry_offset = offset + 16;

                    (void)entry_version;

                    /* Guard against zero or undersized entry_size.
                       Multiboot2 mmap entries are min 24 bytes (base:8 + length:8 + type:4 + reserved:4).
                       A malicious bootloader could set entry_size < 24 to cause OOB reads. */
                    if (entry_size < 24U || entry_size > size) {
                        break;
                    }
                    while (entry_offset + entry_size <= offset + size && state->memory_map_count < 32U) {
                        /* x86_64: unaligned access is safe; would need byte reads on strict-alignment architectures */
                        const uint64_t *entry = (const uint64_t *)((const uint8_t *)multiboot_info + entry_offset);
                        uint64_t base_addr = entry[0];
                        uint64_t length = entry[1];
                        uint32_t entry_type = (uint32_t)entry[2];

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
                    const char *cmdline = (const char *)((const uint8_t *)multiboot_info + offset + 8);
                    (void)cmdline;
                }
                break;

            case 3:  /* Module */
                /* Process module information */
                if (size >= 16) {
                    uint32_t mod_start = tag[2];
                    uint32_t mod_end = tag[3];
                    const char *cmdline = (const char *)((const uint8_t *)multiboot_info + offset + 16);
                    (void)mod_start;
                    (void)mod_end;
                    (void)cmdline;
                }
                break;

            case 5:  /* Boot device */
                /* Process boot device information */
                if (size >= 20) {
                    uint32_t biosdev = tag[2];
                    uint32_t partition = tag[3];
                    uint32_t sub_partition = tag[4];
                    state->boot_device = biosdev;
                    state->boot_partition = partition;
                    state->boot_sub_partition = sub_partition;
                }
                break;

            default:
                /* Unknown tag, skip */
                break;
        }

        /* Hardening: prevent offset wraparound */
        if (aligned_size > total_size - offset) {
            return;
        }
        offset += aligned_size;
    }
}
