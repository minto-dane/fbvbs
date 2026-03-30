/* FBVBS VMCS Setup Unit Tests
 *
 * Requirements: REQ-1004 (継続的テスト), REQ-0201 (VMCS deprivilege)
 *
 * Tests the VMCS configuration builder and deprivilege preflight
 * checks. Hardware-dependent paths (VMWRITE, VMXON) are stubbed
 * for host-environment execution.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../include/fbvbs_hypervisor.h"

/* Stub: audit sink */
void fbvbs_audit_primary_sink_write(const char *message) { (void)message; }

/* ================================================================
 * Test: deprivilege_host rejects when VMX not supported
 * ================================================================ */
static void test_deprivilege_host_rejects_without_vmx(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));
    state.vmx_caps.vmx_supported = 0U;

    status = fbvbs_deprivilege_host(&state);
    assert(status == -1);
    assert((state.runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) == 0U);
}

/* ================================================================
 * Test: deprivilege_host rejects double deprivilege
 * ================================================================ */
static void test_deprivilege_host_rejects_double_deprivilege(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));
    state.runtime_state_flags = FBVBS_RUNTIME_HOST_DEPRIVILEGED;

    status = fbvbs_deprivilege_host(&state);
    assert(status == -1);
    assert((state.runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) == 0U);
}

/* ================================================================
 * Test: deprivilege_host rejects without FreeBSD host partition
 * ================================================================ */
static void test_deprivilege_host_rejects_no_host_partition(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));
    state.vmx_caps.vmx_supported = 1U;
    /* No partition marked as FREEBSD_HOST */

    status = fbvbs_deprivilege_host(&state);
    assert(status == -1);
}

/* ================================================================
 * Test: vmcs_apply rejects NULL config
 * ================================================================ */
static void test_vmcs_apply_rejects_null_config(void) {
    int status;

    status = fbvbs_vmcs_apply(NULL);
    assert(status == -1);
}

/* ================================================================
 * Test: vmcs_release is safe to call without active VMCS
 *
 * Ensures release does not crash when no VMCS is loaded.
 * ================================================================ */
static void test_vmcs_release_safe_without_active(void) {
    fbvbs_vmcs_release_current();
    /* No crash = pass */
}

int main(void) {
    test_deprivilege_host_rejects_without_vmx();
    test_deprivilege_host_rejects_double_deprivilege();
    test_deprivilege_host_rejects_no_host_partition();
    test_vmcs_apply_rejects_null_config();
    test_vmcs_release_safe_without_active();
    return 0;
}
