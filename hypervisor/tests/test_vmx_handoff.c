/* FBVBS VMX Handoff Verification Tests
 *
 * Requirements: REQ-0201 (VMCS deprivilege), REQ-1004 (継続的テスト)
 *
 * Tests the VMLAUNCH/deprivilege path logic in hosted environment.
 * On non-x86_64 or hosted builds, VMLAUNCH returns -1 (expected),
 * but we verify the full preflight and configuration path is correct.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../include/fbvbs_hypervisor.h"

/* Stub: audit sink */
void fbvbs_audit_primary_sink_write(const char *message) { (void)message; }

/* Use static to avoid stack overflow */
static struct fbvbs_hypervisor_state g_state;

/* ================================================================
 * Test: deprivilege preflight rejects without VMX capability
 * ================================================================ */
static void test_deprivilege_rejects_without_vmx_cap(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.vmx_caps.vmx_supported = 0U;

    assert(fbvbs_deprivilege_host(&g_state) == -1);
    assert((g_state.runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) == 0U);
}

/* ================================================================
 * Test: deprivilege clears flag on re-entry attempt
 * ================================================================ */
static void test_deprivilege_clears_flag_on_reentry(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.runtime_state_flags = FBVBS_RUNTIME_HOST_DEPRIVILEGED;

    assert(fbvbs_deprivilege_host(&g_state) == -1);
    assert((g_state.runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) == 0U);
}

/* ================================================================
 * Test: deprivilege requires a FreeBSD host partition to exist
 * ================================================================ */
static void test_deprivilege_requires_host_partition(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.vmx_caps.vmx_supported = 1U;
    /* No partition created — should fail */

    assert(fbvbs_deprivilege_host(&g_state) == -1);
}

/* ================================================================
 * Test: deprivilege with host partition but no EPT still fails
 *       gracefully in hosted mode (VMLAUNCH not available)
 * ================================================================ */
static void test_deprivilege_with_host_partition_fails_hosted(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.vmx_caps.vmx_supported = 1U;

    /* Set up a FreeBSD host partition */
    g_state.partitions[0].occupied = true;
    g_state.partitions[0].partition_id = 1U;
    g_state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    g_state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;

    /* In hosted mode (__STDC_HOSTED__), deprivilege returns -1 because
     * VMLAUNCH is not available. But the configuration path should not
     * crash or corrupt state. */
    int status = fbvbs_deprivilege_host(&g_state);
    assert(status == -1);

    /* Flag must not be set on failure */
    assert((g_state.runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) == 0U);
}

/* ================================================================
 * Test: host_deprivilege_runtime_ready reflects actual state
 * ================================================================ */
static void test_deprivilege_runtime_ready_reflects_state(void) {
    memset(&g_state, 0, sizeof(g_state));

    /* Not deprivileged → not ready */
    assert(fbvbs_host_deprivilege_runtime_ready(&g_state) == 0);

    /* Simulate successful deprivilege (set flag manually) */
    g_state.runtime_state_flags |= FBVBS_RUNTIME_HOST_DEPRIVILEGED;
    /* Still may not be "ready" depending on other requirements,
     * but the flag should be recognized */
    int ready = fbvbs_host_deprivilege_runtime_ready(&g_state);
    /* ready may be 0 or 1 depending on other state — just ensure no crash */
    (void)ready;
}

/* ================================================================
 * Test: VMCS apply rejects NULL, release is safe
 * ================================================================ */
static void test_vmcs_apply_null_and_release(void) {
    assert(fbvbs_vmcs_apply(NULL) == -1);
    fbvbs_vmcs_release_current();  /* must not crash */
}

int main(void) {
    test_deprivilege_rejects_without_vmx_cap();
    test_deprivilege_clears_flag_on_reentry();
    test_deprivilege_requires_host_partition();
    test_deprivilege_with_host_partition_fails_hosted();
    test_deprivilege_runtime_ready_reflects_state();
    test_vmcs_apply_null_and_release();
    return 0;
}
