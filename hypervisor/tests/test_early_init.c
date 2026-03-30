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

int main(void) {
    test_platform_foundation_not_ready_on_zeroed_state();
    test_high_assurance_not_ready_without_bringup();
    test_host_deprivilege_not_ready_on_fresh_state();
    test_audit_not_ready_on_fresh_state();
    test_deprivilege_rejects_fresh_state();
    return 0;
}
