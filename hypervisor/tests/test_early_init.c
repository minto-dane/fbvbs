/* FBVBS Early Init Unit Tests
 *
 * Requirements: REQ-1004 (継続的テスト)
 *
 * Tests early initialization helpers and platform readiness checks.
 * Uses static allocation to avoid stack overflow on large state structs.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../include/fbvbs_efi.h"
#include "../include/fbvbs_hypervisor.h"

/* Stub: audit sink */
void fbvbs_audit_primary_sink_write(const char *message) { (void)message; }

/* Use static to avoid stack overflow (struct is very large) */
static struct fbvbs_hypervisor_state g_state;

/* ================================================================
 * Test: platform_foundation_ready reports not-ready on zeroed state
 * ================================================================ */
static void test_platform_foundation_not_ready_on_zeroed_state(void) {
    memset(&g_state, 0, sizeof(g_state));
    assert(fbvbs_platform_foundation_ready(&g_state) == 0);
}

/* ================================================================
 * Test: high assurance foundation not ready without complete bringup
 * ================================================================ */
static void test_high_assurance_not_ready_without_bringup(void) {
    memset(&g_state, 0, sizeof(g_state));
    assert(fbvbs_platform_high_assurance_foundation_ready(&g_state) == 0);
}

/* ================================================================
 * Test: host deprivilege runtime not ready on fresh state
 * ================================================================ */
static void test_host_deprivilege_not_ready_on_fresh_state(void) {
    memset(&g_state, 0, sizeof(g_state));
    assert(fbvbs_host_deprivilege_runtime_ready(&g_state) == 0);
}

/* ================================================================
 * Test: audit runtime not ready on fresh state
 * ================================================================ */
static void test_audit_not_ready_on_fresh_state(void) {
    memset(&g_state, 0, sizeof(g_state));
    assert(fbvbs_audit_runtime_ready(&g_state) == 0);
}

/* ================================================================
 * Test: deprivilege rejects fresh state (no VMX, no host partition)
 * ================================================================ */
static void test_deprivilege_rejects_fresh_state(void) {
    memset(&g_state, 0, sizeof(g_state));
    assert(fbvbs_deprivilege_host(&g_state) == -1);
}

/* ================================================================
 * Test: early EFI bridge rejects null boot info
 * ================================================================ */
#ifdef FBVBS_EARLY_INIT_COVERAGE_TEST
static void test_efi_bridge_rejects_null_boot_info(void) {
    fbvbs_efi_to_hypervisor(NULL);
}

/* ================================================================
 * Test: early EFI bridge rejects invalid magic
 * ================================================================ */
static void test_efi_bridge_rejects_invalid_magic(void) {
    struct fbvbs_efi_boot_info boot_info;

    memset(&boot_info, 0, sizeof(boot_info));
    boot_info.memory_map_addr = 0x1000U;
    boot_info.descriptor_size = sizeof(uint64_t);
    boot_info.mmap_entry_count = 1U;
    fbvbs_efi_to_hypervisor(&boot_info);
}

/* ================================================================
 * Test: early EFI bridge processes minimal valid boot info
 * ================================================================ */
static void test_efi_bridge_accepts_minimal_boot_info(void) {
    struct fbvbs_efi_boot_info boot_info;

    memset(&boot_info, 0, sizeof(boot_info));
    boot_info.magic = FBVBS_EFI_BOOT_MAGIC;
    boot_info.memory_map_addr = 0x1000U;
    boot_info.descriptor_size = sizeof(uint64_t);
    boot_info.mmap_entry_count = 1U;
    fbvbs_efi_to_hypervisor(&boot_info);
}
#endif

int main(void) {
    test_platform_foundation_not_ready_on_zeroed_state();
    test_high_assurance_not_ready_without_bringup();
    test_host_deprivilege_not_ready_on_fresh_state();
    test_audit_not_ready_on_fresh_state();
    test_deprivilege_rejects_fresh_state();
#ifdef FBVBS_EARLY_INIT_COVERAGE_TEST
    test_efi_bridge_rejects_null_boot_info();
    test_efi_bridge_rejects_invalid_magic();
    test_efi_bridge_accepts_minimal_boot_info();
#endif
    return 0;
}
