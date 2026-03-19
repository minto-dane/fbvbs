#include "fbvbs_hypervisor.h"

void fbvbs_zero_memory(void *buffer, size_t length) {
    uint8_t *bytes;
    size_t index;
    volatile uint8_t *volatile_bytes;

    if (buffer == NULL || length == 0U) {
        return;
    }

    bytes = (uint8_t *)buffer;

    /* Use volatile to prevent compiler optimization */
    volatile_bytes = (volatile uint8_t *)bytes;

    for (index = 0; index < length; ++index) {
        volatile_bytes[index] = 0;
    }

    /* Memory barrier to ensure all writes are visible */
    __asm__ volatile("mfence" : : : "memory");
}

void fbvbs_copy_memory(void *destination, const void *source, size_t length) {
    uint8_t *dest;
    const uint8_t *src;
    size_t index;

    if (destination == NULL || source == NULL || length == 0U) {
        return;
    }

    dest = (uint8_t *)destination;
    src = (const uint8_t *)source;

    for (index = 0; index < length; ++index) {
        dest[index] = src[index];
    }

    /* Memory barrier to ensure all writes are visible */
    __asm__ volatile("mfence" : : : "memory");
}

int fbvbs_constant_time_equals(const void *a, const void *b, size_t length) {
    const volatile uint8_t *va;
    const volatile uint8_t *vb;
    size_t index;
    uint32_t accumulator = 0U;

    if (a == NULL || b == NULL) {
        return 0;
    }

    va = (const volatile uint8_t *)a;
    vb = (const volatile uint8_t *)b;

    /* Constant-time: always iterate all bytes.
       Prevents timing side-channel that could leak partial match length. */
    for (index = 0; index < length; ++index) {
        accumulator |= (uint32_t)(va[index] ^ vb[index]);
    }

    /* Compiler barrier: prevent optimizer from short-circuiting */
    __asm__ volatile("" : "+r"(accumulator) : : "memory");

    return accumulator == 0U ? 1 : 0;
}

int fbvbs_memory_is_zero(const void *buffer, size_t length) {
    const volatile uint8_t *bytes;
    size_t index;
    uint32_t accumulator = 0U;

    if (buffer == NULL) {
        return 0;
    }

    bytes = (const volatile uint8_t *)buffer;

    /* Constant-time: always iterate all bytes to prevent
       timing side-channel leaking which byte is non-zero */
    for (index = 0; index < length; ++index) {
        accumulator |= (uint32_t)bytes[index];
    }

    /* Compiler barrier: prevent optimizer from short-circuiting */
    __asm__ volatile("" : "+r"(accumulator) : : "memory");

    return accumulator == 0U ? 1 : 0;
}

/* Zero a 4096-byte page at the given guest physical address.
 * In bare-metal: identity-maps the GPA, zeros with volatile stores, unmaps.
 * Stub: the leaf simulation model has no physical memory backing GPAs. */
void fbvbs_zero_page_at_gpa(uint64_t gpa) {
    (void)gpa;
    /* Bare-metal implementation:
     *   volatile uint8_t *page = (volatile uint8_t *)(uintptr_t)gpa;
     *   for (size_t i = 0; i < 4096; ++i) page[i] = 0;
     *   __asm__ volatile("mfence" ::: "memory");
     */
}
