/* FBVBS Manifest/Hash Security Parser Fuzzer
 *
 * Phase 9-1: Continuous fuzzing of security manifest parsing (REQ-1004).
 *
 * Target: fbvbs_dispatch_hypercall with MANIFEST_SET_PAGE / HASH_MEASURE_PAGE
 * call IDs. The manifest is guest-supplied and parsed at a critical trust
 * boundary. This harness feeds arbitrary bytes to find:
 *   - Buffer overflows in manifest profile/artifact parsing
 *   - Hash comparison bypasses with crafted payloads
 *   - Integer overflows in artifact count/offset calculations
 *   - State corruption from malformed manifest structures
 *
 * Build (standalone):
 *   gcc -g -O1 -fsanitize=address,undefined
 *     -DFUZZ_TARGET -I../include
 *     fuzz_manifest.c [all src .c files] -o fuzz_manifest
 */

#include "fbvbs_hypervisor.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

static struct fbvbs_hypervisor_state g_state;

static void fuzz_init_state(void)
{
    memset(&g_state, 0, sizeof(g_state));

    /* Satisfy fbvbs_state_invariant: all next_* counters must be > 0 */
    g_state.next_partition_id = 200U;
    g_state.next_memory_object_id = 1U;
    g_state.next_measurement_digest_id = 1U;
    g_state.next_shared_object_id = 1U;
    g_state.next_target_set_id = 1U;
    g_state.next_key_handle = 1U;
    g_state.next_dek_handle = 1U;
    g_state.next_manifest_set_id = 1U;
    g_state.next_iommu_domain_id = 1U;

    /* Create a VM partition in CREATED state for manifest operations */
    g_state.partitions[0].occupied = true;
    g_state.partitions[0].partition_id = 100U;
    g_state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    g_state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    g_state.partitions[0].vcpu_count = 1U;
    g_state.partitions[0].capability_mask = 0xFFFFFFFFU;

    /* Create FreeBSD host partition (caller of manifest operations) */
    g_state.partitions[1].occupied = true;
    g_state.partitions[1].partition_id = 1U;
    g_state.partitions[1].kind = PARTITION_KIND_FREEBSD_HOST;
    g_state.partitions[1].state = FBVBS_PARTITION_STATE_RUNNING;
    g_state.partitions[1].vcpu_count = 1U;
    g_state.partitions[1].vcpus[0].state = FBVBS_VCPU_STATE_RUNNING;
    g_state.partitions[1].capability_mask = FBVBS_HOST_DEFAULT_CAPABILITY_MASK;
}

static int fuzz_one_input(const uint8_t *data, size_t size)
{
    /* Reset state each iteration for reproducibility */
    fuzz_init_state();

    /* Test 1: Feed fuzz data as manifest set request body.
     * The manifest_set_page hypercall reads from command page body[]. */
    if (size >= 8U) {
        struct fbvbs_trap_registers regs;
        struct fbvbs_command_page_v1 *page;

        page = &g_state.partitions[1].command_pages[0].page;
        memset(page, 0, sizeof(*page));
        page->abi_version = 1U;
        page->call_id = 0x0032U;  /* MANIFEST_SET_PAGE */
        page->flags = 0U;

        /* Fill body with fuzz data */
        {
            size_t body_len = size;
            if (body_len > sizeof(page->body)) {
                body_len = sizeof(page->body);
            }
            memcpy(page->body, data, body_len);
            page->input_length = (uint32_t)body_len;
        }

        memset(&regs, 0, sizeof(regs));
        regs.rax = (uint64_t)(uintptr_t)page;

        (void)fbvbs_dispatch_hypercall(&g_state, &regs);
    }

    /* Test 2: Feed fuzz data as hash measure request body */
    if (size >= 48U) {
        struct fbvbs_trap_registers regs;
        struct fbvbs_command_page_v1 *page;

        page = &g_state.partitions[1].command_pages[0].page;
        memset(page, 0, sizeof(*page));
        page->abi_version = 1U;
        page->call_id = 0x0033U;  /* HASH_MEASURE_PAGE */
        page->flags = 0U;

        {
            size_t body_len = size;
            if (body_len > sizeof(page->body)) {
                body_len = sizeof(page->body);
            }
            memcpy(page->body, data, body_len);
            page->input_length = (uint32_t)body_len;
        }

        memset(&regs, 0, sizeof(regs));
        regs.rax = (uint64_t)(uintptr_t)page;

        (void)fbvbs_dispatch_hypercall(&g_state, &regs);
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
    uint8_t buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n == 0) { return 1; }
    return fuzz_one_input(buf, n);
}
#endif
