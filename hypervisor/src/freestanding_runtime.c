#include <stddef.h>
#include <stdint.h>

#include "fbvbs_asm.h"
#include "fbvbs_hypervisor.h"

#define FBVBS_COM1_PORT 0x3F8U
#define FBVBS_UART_THR  0U
#define FBVBS_UART_IER  1U
#define FBVBS_UART_FCR  2U
#define FBVBS_UART_LCR  3U
#define FBVBS_UART_MCR  4U
#define FBVBS_UART_LSR  5U
#define FBVBS_UART_LSR_THRE 0x20U
#define FBVBS_UART_LCR_DLAB 0x80U
#define FBVBS_UART_BOOT_SPIN_LIMIT 1000000U

void __stack_chk_fail(void);
void *memset(void *destination, int value, size_t length);
void *memcpy(void *destination, const void *source, size_t length);
void *memmove(void *destination, const void *source, size_t length);
int memcmp(const void *lhs, const void *rhs, size_t length);

uintptr_t __stack_chk_guard;

static void fbvbs_boot_halt_forever(void) {
    for (;;) {
#if defined(__x86_64__) || defined(__i386__)
        __asm__ volatile("cli; hlt" : : : "memory");
#endif
    }
}

static uint64_t fbvbs_boot_read_tsc(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t low;
    uint32_t high;

    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
    return ((uint64_t)high << 32U) | low;
#else
    return 0U;
#endif
}

static void fbvbs_serial_init(void) {
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_IER), 0x00U);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_LCR), FBVBS_UART_LCR_DLAB);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_THR), 0x01U);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_IER), 0x00U);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_LCR), 0x03U);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_FCR), 0xC7U);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_MCR), 0x0BU);
}

static void fbvbs_serial_putchar(char ch) {
    uint32_t spins = 0U;

    while (((uint32_t)fbvbs_asm_inb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_LSR)) &
            FBVBS_UART_LSR_THRE) == 0U &&
           spins < FBVBS_UART_BOOT_SPIN_LIMIT) {
        ++spins;
    }

    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_THR), (uint8_t)ch);
}

void fbvbs_boot_console_puts(const char *message) {
    if (message == NULL) {
        return;
    }

    while (*message != '\0') {
        if (*message == '\n') {
            fbvbs_serial_putchar('\r');
        }
        fbvbs_serial_putchar(*message);
        ++message;
    }
}

__attribute__((no_stack_protector))
void fbvbs_boot_runtime_init(void) {
    uint64_t seed;

    fbvbs_serial_init();

    seed = fbvbs_boot_read_tsc() ^ 0xBADC0FFEE0DDF00DULL ^
           (uint64_t)(uintptr_t)&__stack_chk_guard;
    if (seed == 0U) {
        seed = 0x59584E4352455455ULL;
    }
    __stack_chk_guard = (uintptr_t)seed;
}

__attribute__((noreturn))
void __stack_chk_fail(void) {
    fbvbs_boot_console_puts("FATAL: stack protector violation\n");
    fbvbs_boot_halt_forever();
    __builtin_unreachable();
}

void *memset(void *destination, int value, size_t length) {
    unsigned char *bytes = (unsigned char *)destination;
    size_t index;

    if (destination == NULL) {
        return NULL;
    }

    for (index = 0U; index < length; ++index) {
        bytes[index] = (unsigned char)value;
    }

    return destination;
}

void *memcpy(void *destination, const void *source, size_t length) {
    unsigned char *dest_bytes = (unsigned char *)destination;
    const unsigned char *src_bytes = (const unsigned char *)source;
    size_t index;

    if (destination == NULL || source == NULL) {
        return destination;
    }

    for (index = 0U; index < length; ++index) {
        dest_bytes[index] = src_bytes[index];
    }

    return destination;
}

void *memmove(void *destination, const void *source, size_t length) {
    unsigned char *dest_bytes = (unsigned char *)destination;
    const unsigned char *src_bytes = (const unsigned char *)source;
    size_t index;

    if (destination == NULL || source == NULL) {
        return destination;
    }

    if (dest_bytes <= src_bytes || dest_bytes >= src_bytes + length) {
        for (index = 0U; index < length; ++index) {
            dest_bytes[index] = src_bytes[index];
        }
        return destination;
    }

    for (index = length; index > 0U; --index) {
        dest_bytes[index - 1U] = src_bytes[index - 1U];
    }

    return destination;
}

int memcmp(const void *lhs, const void *rhs, size_t length) {
    const unsigned char *left = (const unsigned char *)lhs;
    const unsigned char *right = (const unsigned char *)rhs;
    size_t index;

    if (lhs == NULL || rhs == NULL) {
        return 0;
    }

    for (index = 0U; index < length; ++index) {
        if (left[index] != right[index]) {
            return (left[index] < right[index]) ? -1 : 1;
        }
    }

    return 0;
}
