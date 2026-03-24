/* FBVBS Hypercall Command Page Fuzzer
 *
 * Phase 9-1: Continuous fuzzing of hypercall parsers (REQ-1004).
 *
 * Target: fbvbs_dispatch_hypercall — the primary trust boundary.
 * All guest-controlled input enters through the command page (4096 bytes).
 * This harness feeds arbitrary bytes into the dispatch path to find:
 *   - Buffer overflows in body[] parsing
 *   - Integer overflows in length/offset calculations
 *   - Incorrect error code returns on malformed input
 *   - State corruption from out-of-range call_id values
 *   - TOCTOU gaps (single-threaded fuzzing)
 *
 * Build (AFL++):
 *   afl-gcc-fast -g -O1 -fsanitize=address,undefined \
 *     -DFUZZ_TARGET -I../include \
 *     fuzz_command_page.c ../src/command.c ../src/partition.c \
 *     ../src/security.c ../src/vm_policy.c ../src/kernel.c \
 *     ../src/cpu_security.c ../src/vmx.c ../src/memory.c \
 *     ../src/memory_utils.c ../src/log.c ../src/boot_multiboot.c \
 *     ../src/iommu_vtd.c ../src/iommu_amdvi.c ../src/early_init.c \
 *     ../src/vmcs_setup.c ../src/hlat.c ../src/vmx_controls.c \
 *     ../src/amd_npt.c ../src/page_alloc.c ../src/watchdog.c \
 *     ../src/apic.c ../src/idt.c ../src/mp_init.c \
 *     -o fuzz_command_page
 *
 * Build (libFuzzer):
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *     -DFUZZ_TARGET -DFUZZ_LIBFUZZER -I../include \
 *     fuzz_command_page.c [same sources] \
 *     -o fuzz_command_page
 *
 * Run (AFL++):
 *   mkdir -p corpus && echo -n "" > corpus/empty
 *   afl-fuzz -i corpus -o findings ./fuzz_command_page
 *
 * Run (libFuzzer):
 *   ./fuzz_command_page corpus/
 */

#include "fbvbs_hypervisor.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Global hypervisor state for the fuzzer.
 * All real function implementations from HOST_OBJECTS are linked in —
 * no stubs needed since page_alloc.c, cpu_security.c, etc. are included. */
static struct fbvbs_hypervisor_state g_state;

static void fuzz_init_state(void)
{
    memset(&g_state, 0, sizeof(g_state));

    /* Satisfy fbvbs_state_invariant: all next_* counters must be > 0 */
    g_state.next_partition_id = 2U;  /* 1 already used by host */
    g_state.next_memory_object_id = 1U;
    g_state.next_measurement_digest_id = 1U;
    g_state.next_shared_object_id = 1U;
    g_state.next_target_set_id = 1U;
    g_state.next_key_handle = 1U;
    g_state.next_dek_handle = 1U;
    g_state.next_manifest_set_id = 1U;
    g_state.next_iommu_domain_id = 1U;

    /* Create a minimal FreeBSD host partition so dispatch has a target.
     * The command page GPA resolution in dispatch_hypercall uses:
     *   (uint64_t)(uintptr_t)&partition->command_pages[index].page
     * So we set rax = address of command_pages[0].page at runtime. */
    g_state.partitions[0].occupied = true;
    g_state.partitions[0].partition_id = 1U;
    g_state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    g_state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNING;
    g_state.partitions[0].vcpu_count = 1U;
    g_state.partitions[0].vcpus[0].state = FBVBS_VCPU_STATE_RUNNING;
    g_state.partitions[0].capability_mask = FBVBS_HOST_DEFAULT_CAPABILITY_MASK;
}

/* ================================================================
 * Fuzz entry point
 *
 * Input: arbitrary bytes from the fuzzer.
 * If input >= sizeof(page), use first sizeof(page) bytes.
 * If input < sizeof(page), pad with zeros.
 *
 * The function must never crash on any input — that's the invariant
 * we're testing. Any crash is a finding.
 * ================================================================ */

static int fuzz_one_input(const uint8_t *data, size_t size)
{
    struct fbvbs_trap_registers regs;
    struct fbvbs_command_page_v1 *page;

    /* Reset state each iteration for reproducibility */
    fuzz_init_state();

    /* Get pointer to the partition's command page in-place */
    page = &g_state.partitions[0].command_pages[0].page;

    /* Zero the page, then overlay fuzz data */
    memset(page, 0, sizeof(*page));
    if (size > sizeof(*page)) {
        size = sizeof(*page);
    }
    memcpy(page, data, size);

    /* Force ABI version to valid (otherwise dispatch rejects immediately,
     * reducing coverage of interesting code paths) */
    page->abi_version = 1U;

    /* Set up registers as if the guest issued a VMCALL.
     * RAX = address of the command page — must match the identity
     * comparison in fbvbs_find_command_page_owner(). */
    memset(&regs, 0, sizeof(regs));
    regs.rax = (uint64_t)(uintptr_t)page;

    /* Dispatch — this is the function under test.
     * Return value is always OK/error code; crashes indicate bugs. */
    (void)fbvbs_dispatch_hypercall(&g_state, &regs);

    return 0;
}

/* ================================================================
 * Entry point selection: libFuzzer vs AFL++ vs standalone
 * ================================================================ */

#if defined(__AFL_HAVE_MANUAL_CONTROL) || defined(__AFL_COMPILER)
/* AFL++ persistent mode */
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
/* libFuzzer entry point */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_one_input(data, size);
}

#else
/* Standalone: read from stdin for manual testing / crash replay */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    uint8_t buf[8192];
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    if (n == 0) {
        fprintf(stderr, "Usage: %s < testcase\n", "fuzz_command_page");
        return 1;
    }
    return fuzz_one_input(buf, n);
}
#endif
