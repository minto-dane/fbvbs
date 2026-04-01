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

/*@ terminates \false;
    assigns \nothing;
*/
static void fbvbs_boot_halt_forever(void) {
#ifdef __FRAMAC__
    return;
#else
    for (;;) {
#if defined(__x86_64__) || defined(__i386__)
        __asm__ volatile("cli; hlt" : : : "memory");
#endif
    }
#endif
}

/*@ assigns \nothing;
    ensures \result == 0U || \result > 0U;
*/
static uint64_t fbvbs_boot_read_tsc(void) {
#ifdef __FRAMAC__
    return 0U;
#else
#if defined(__x86_64__) || defined(__i386__)
    uint32_t low;
    uint32_t high;

    __asm__ volatile("rdtsc" : "=a"(low), "=d"(high));
    return ((uint64_t)high << 32U) | low;
#else
    return 0U;
#endif
#endif
}

/*@ terminates \true;
    assigns \nothing;
*/
static void fbvbs_serial_init(void) {
#ifdef __FRAMAC__
    return;
#else
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_IER), 0x00U);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_LCR), FBVBS_UART_LCR_DLAB);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_THR), 0x01U);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_IER), 0x00U);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_LCR), 0x03U);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_FCR), 0xC7U);
    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_MCR), 0x0BU);
#endif
}

/*@ terminates \true;
    assigns \nothing;
*/
static void fbvbs_serial_putchar(char ch) {
#ifdef __FRAMAC__
    (void)ch;
    return;
#else
    uint32_t spins = 0U;

    while (((uint32_t)fbvbs_asm_inb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_LSR)) &
            FBVBS_UART_LSR_THRE) == 0U &&
           spins < FBVBS_UART_BOOT_SPIN_LIMIT) {
        ++spins;
    }

    fbvbs_asm_outb((uint16_t)(FBVBS_COM1_PORT + FBVBS_UART_THR), (uint8_t)ch);
#endif
}

/*@ requires message == \null || \valid_read(message);
    terminates \true;
    assigns \nothing;
*/
void fbvbs_boot_console_puts(const char *message) {
    if (message == NULL) {
        return;
    }
#ifdef __FRAMAC__
    (void)message;
#else
    while (*message != '\0') {
        if (*message == '\n') {
            fbvbs_serial_putchar('\r');
        }
        fbvbs_serial_putchar(*message);
        ++message;
    }
#endif
}

/*@ terminates \true;
    assigns __stack_chk_guard;
*/
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

/*@ terminates \false;
    assigns \nothing;
*/
__attribute__((noreturn, no_stack_protector))
void __stack_chk_fail(void) {
    fbvbs_boot_console_puts("FATAL: stack protector violation\n");
    fbvbs_boot_halt_forever();
#ifdef __FRAMAC__
    /* fbvbs_boot_halt_forever returns under __FRAMAC__; satisfy noreturn. */
    while (1) {}
#endif
    __builtin_unreachable();
}

/*@ behavior null_destination:
      assumes destination == \null;
      assigns \nothing;
      ensures \result == \null;
    behavior valid_destination:
      assumes destination != \null;
      requires \valid(((char *)destination) + (0 .. length - 1));
      assigns ((char *)destination)[0 .. length - 1];
      ensures \result == destination;
    complete behaviors;
    disjoint behaviors;
*/
void *memset(void *destination, int value, size_t length) {
    char *bytes = (char *)destination;
    size_t index;

    if (destination == NULL) {
        return NULL;
    }

    /*@
      @ loop invariant 0 <= index <= length;
      @ loop assigns index, bytes[0 .. length - 1];
      @ loop variant length - index;
      @*/
    for (index = 0U; index < length; ++index) {
        bytes[index] = (char)((unsigned char)value);
    }

    return destination;
}

/*@ behavior null_input:
      assumes destination == \null || source == \null;
      assigns \nothing;
      ensures \result == destination;
    behavior valid_input:
      assumes destination != \null && source != \null;
      requires \valid(((char *)destination) + (0 .. length - 1));
      requires \valid_read(((const char *)source) + (0 .. length - 1));
      assigns ((char *)destination)[0 .. length - 1];
      ensures \result == destination;
    complete behaviors;
    disjoint behaviors;
*/
void *memcpy(void *destination, const void *source, size_t length) {
    char *dest_bytes = (char *)destination;
    const char *src_bytes = (const char *)source;
    size_t index;

    if (destination == NULL || source == NULL) {
        return destination;
    }

    /*@
      @ loop invariant 0 <= index <= length;
      @ loop assigns index, dest_bytes[0 .. length - 1];
      @ loop variant length - index;
      @*/
    for (index = 0U; index < length; ++index) {
        dest_bytes[index] = src_bytes[index];
    }

    return destination;
}

/*@ behavior null_input:
      assumes destination == \null || source == \null;
      assigns \nothing;
      ensures \result == destination;
    behavior valid_input:
      assumes destination != \null && source != \null;
      requires \valid(((char *)destination) + (0 .. length - 1));
      requires \valid_read(((const char *)source) + (0 .. length - 1));
      assigns ((char *)destination)[0 .. length - 1];
      ensures \result == destination;
    complete behaviors;
    disjoint behaviors;
*/
void *memmove(void *destination, const void *source, size_t length) {
    char *dest_bytes = (char *)destination;
    const char *src_bytes = (const char *)source;
    size_t index;

    if (destination == NULL || source == NULL) {
        return destination;
    }

    if (dest_bytes <= src_bytes || dest_bytes >= src_bytes + length) {
        /*@
          @ loop invariant 0 <= index <= length;
          @ loop assigns index, dest_bytes[0 .. length - 1];
          @ loop variant length - index;
          @*/
        for (index = 0U; index < length; ++index) {
            dest_bytes[index] = src_bytes[index];
        }
        return destination;
    }

    /*@
      @ loop invariant 0 <= index <= length;
      @ loop assigns index, dest_bytes[0 .. length - 1];
      @ loop variant index;
      @*/
    for (index = length; index > 0U; --index) {
        dest_bytes[index - 1U] = src_bytes[index - 1U];
    }

    return destination;
}

/*@ requires lhs == \null || rhs == \null ||
              (\valid_read(((const char *)lhs) + (0 .. length - 1)) &&
               \valid_read(((const char *)rhs) + (0 .. length - 1)));
    assigns \nothing;
*/
/* Defensive NULL handling (non-standard: standard memcmp is UB on NULL).
 * Both NULL → 0 (equal).  lhs NULL only → -1.  rhs NULL only → +1.
 * Preserves antisymmetry: memcmp(a,b) == -memcmp(b,a) for NULL inputs. */
int memcmp(const void *lhs, const void *rhs, size_t length) {
    const char *left = (const char *)lhs;
    const char *right = (const char *)rhs;
    size_t index;

    if (lhs == NULL) {
        return (rhs == NULL) ? 0 : -1;
    }
    if (rhs == NULL) {
        return 1;
    }

    /*@
      @ loop invariant 0 <= index <= length;
      @ loop assigns index;
      @ loop variant length - index;
      @*/
    for (index = 0U; index < length; ++index) {
        if (left[index] != right[index]) {
            return ((uint8_t)left[index] < (uint8_t)right[index]) ? -1 : 1;
        }
    }

    return 0;
}
