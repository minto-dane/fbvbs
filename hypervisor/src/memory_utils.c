#include "fbvbs_hypervisor.h"

void fbvbs_zero_memory(void *buffer, size_t length) {
    uint8_t *bytes = (uint8_t *)buffer;
    size_t index;

    /* TODO: Replace with memset_explicit/memset_s/explicit_bzero to prevent compiler optimization */
    for (index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
    /* Compiler barrier to prevent optimization */
    __asm__ volatile("" : : "r"(bytes) : "memory");
}

void fbvbs_copy_memory(void *destination, const void *source, size_t length) {
    uint8_t *dest = (uint8_t *)destination;
    const uint8_t *src = (const uint8_t *)source;
    size_t index;

    for (index = 0; index < length; ++index) {
        dest[index] = src[index];
    }
}

int fbvbs_memory_is_zero(const void *buffer, size_t length) {
    const uint8_t *bytes = (const uint8_t *)buffer;
    size_t index;

    for (index = 0; index < length; ++index) {
        if (bytes[index] != 0U) {
            return 0;
        }
    }

    return 1;
}