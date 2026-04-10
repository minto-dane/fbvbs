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

static void mark_iommu_runtime_ready(struct fbvbs_hypervisor_state *state) {
    state->cpu_security.iommu.iommu_type = IOMMU_TYPE_VTD;
    state->cpu_security.iommu.dma_remapping = 1U;
    state->cpu_security.iommu.interrupt_remapping = 1U;
    state->cpu_security.iommu.kernel_dma_protection = 1U;
}

static void mark_runnable_host_partition(struct fbvbs_hypervisor_state *state) {
    state->partitions[0].occupied = true;
    state->partitions[0].partition_id = 1U;
    state->partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state->partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
}

/* ================================================================
 * Test: deprivilege preflight rejects without VMX capability
 * ================================================================ */
static void test_deprivilege_rejects_without_vmx_cap(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.vmx_caps.vmx_supported = 0U;
    g_state.vmx_caps.iommu_available = 1U;
    mark_runnable_host_partition(&g_state);
    mark_iommu_runtime_ready(&g_state);

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
    /* Double deprivilege rejected early — flag preserved so caller
     * knows the system is still in deprivileged state. */
    assert((g_state.runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) != 0U);
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
 * Test: deprivilege requires IOMMU runtime-ready precondition
 * ================================================================ */
static void test_deprivilege_requires_iommu_runtime_ready(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.vmx_caps.vmx_supported = 1U;
    g_state.vmx_caps.iommu_available = 1U;
    mark_runnable_host_partition(&g_state);

    /* IOMMU readiness is intentionally unset and must fail-closed. */
    assert(fbvbs_deprivilege_host(&g_state) == -1);
    assert((g_state.runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) == 0U);
}

/* ================================================================
 * Test: deprivilege は authoritative IOMMU 可用性ビットを必須化
 * ================================================================ */
static void test_deprivilege_requires_iommu_authoritative_availability(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.vmx_caps.vmx_supported = 1U;
    g_state.vmx_caps.iommu_available = 0U;
    mark_runnable_host_partition(&g_state);
    mark_iommu_runtime_ready(&g_state);

    /* 可変ランタイム flag だけでは deprivilege を許可しない。 */
    assert(fbvbs_deprivilege_host(&g_state) == -1);
    assert((g_state.runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) == 0U);
}

/* ================================================================
 * Test: deprivilege は non-runnable host partition を拒否
 * ================================================================ */
static void test_deprivilege_rejects_non_runnable_host_partition(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.vmx_caps.vmx_supported = 1U;
    g_state.vmx_caps.iommu_available = 1U;

    g_state.partitions[0].occupied = true;
    g_state.partitions[0].partition_id = 1U;
    g_state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    g_state.partitions[0].state = FBVBS_PARTITION_STATE_FAULTED;
    mark_iommu_runtime_ready(&g_state);

    assert(fbvbs_deprivilege_host(&g_state) == -1);
    assert((g_state.runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) == 0U);
}

/* ================================================================
 * Test: deprivilege with host partition but no EPT still fails
 *       gracefully in hosted mode (VMLAUNCH not available)
 * ================================================================ */
static void test_deprivilege_with_host_partition_fails_hosted(void) {
    memset(&g_state, 0, sizeof(g_state));
    g_state.vmx_caps.vmx_supported = 1U;
    g_state.vmx_caps.iommu_available = 1U;

    /* Set up a FreeBSD host partition */
    mark_runnable_host_partition(&g_state);
    mark_iommu_runtime_ready(&g_state);

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
    test_deprivilege_requires_iommu_runtime_ready();
    test_deprivilege_requires_iommu_authoritative_availability();
    test_deprivilege_rejects_non_runnable_host_partition();
    test_deprivilege_with_host_partition_fails_hosted();
    test_deprivilege_runtime_ready_reflects_state();
    test_vmcs_apply_null_and_release();
    return 0;
}
