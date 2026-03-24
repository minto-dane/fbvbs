/* FBVBS Multiboot2 Boot Parser Fuzzer
 *
 * Phase 9-1: Continuous fuzzing of boot-time parsers (REQ-1004).
 *
 * Target: fbvbs_parse_multiboot2 — parses Multiboot2 info structure.
 * The Multiboot2 info is provided by the bootloader and contains
 * memory map, module list, and other boot-time data. While the
 * bootloader is trusted, a compromised bootloader could provide
 * malformed data, and defense-in-depth requires validation.
 *
 * Build (standalone):
 *   gcc -g -O1 -fsanitize=address,undefined \
 *     -DFUZZ_TARGET -I../include \
 *     fuzz_multiboot2.c ../src/boot_multiboot.c \
 *     ../src/log.c ../src/memory_utils.c \
 *     -o fuzz_multiboot2
 */

#include "fbvbs_hypervisor.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Stubs for functions not included in this minimal link set.
 * Signatures must match header declarations exactly. */
uint64_t fbvbs_page_alloc(void) { return 0; }
int fbvbs_page_free(uint64_t addr) { (void)addr; return 0; }

void fbvbs_vmexit_mitigate(const struct fbvbs_vuln_profile *vuln,
                            struct fbvbs_spec_ctrl_state *spec_state,
                            uint32_t is_cross_partition)
{
    (void)vuln; (void)spec_state; (void)is_cross_partition;
}

void fbvbs_vmentry_mitigate(const struct fbvbs_vuln_profile *vuln,
                             struct fbvbs_spec_ctrl_state *spec_state)
{
    (void)vuln; (void)spec_state;
}

int fbvbs_vtd_detect(struct fbvbs_global_security_state *state)
{
    (void)state; return 0;
}

int fbvbs_amdvi_detect(struct fbvbs_global_security_state *state)
{
    (void)state; return 0;
}

#define FBVBS_MAX_MULTIBOOT_FUZZ_SIZE 65536U

static int fuzz_one_input(const uint8_t *data, size_t size)
{
    struct fbvbs_hypervisor_state state;

    memset(&state, 0, sizeof(state));

    /* Feed fuzz data as the Multiboot2 info structure.
     * The parser expects the data to start with a valid header:
     *   uint32_t total_size
     *   uint32_t reserved (0)
     * followed by a sequence of tags. We let the fuzzer explore
     * all combinations including malformed headers. */

    if (size >= 8U) {
        /* Clamp to uint32_t range before cast (prevents silent truncation
         * on 64-bit platforms with large fuzzer inputs). */
        uint32_t len = (size > FBVBS_MAX_MULTIBOOT_FUZZ_SIZE)
                       ? FBVBS_MAX_MULTIBOOT_FUZZ_SIZE : (uint32_t)size;
        /* Copy into aligned buffer: the parser internally uses memcpy-based
         * reads now, but the aligned copy provides an additional safety net
         * and matches the pattern used in fuzz_iommu.c. */
        _Alignas(8) uint8_t aligned_buf[FBVBS_MAX_MULTIBOOT_FUZZ_SIZE];
        memcpy(aligned_buf, data, len);
        fbvbs_process_multiboot_info(&state, aligned_buf, len);
    }

    return 0;
}

/* Entry points */
#if defined(__AFL_HAVE_MANUAL_CONTROL) || defined(__AFL_COMPILER)
#include <unistd.h>
__AFL_FUZZ_INIT();
int main(void)
{
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        size_t len = (size_t)__AFL_FUZZ_TESTCASE_LEN;
        fuzz_one_input(buf, len);
    }
    return 0;
}
#elif defined(FUZZ_LIBFUZZER)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_one_input(data, size);
}
#else
#include <stdio.h>
int main(void)
{
    uint8_t buf[65536];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n == 0) { return 1; }
    return fuzz_one_input(buf, n);
}
#endif
