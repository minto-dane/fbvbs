/* FBVBS IOMMU Unit Tests
 *
 * Requirements: REQ-1004 (継続的テスト)
 *
 * Tests VT-d and AMD-Vi detection and initialization fail-closed
 * behavior. Actual MMIO operations are stubbed in host environment.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../include/fbvbs_cpu_security.h"
#include "../include/fbvbs_hypervisor.h"

/* Stub: audit sink */
void fbvbs_audit_primary_sink_write(const char *message) { (void)message; }

/* ================================================================
 * Test: IOMMU runtime not ready on uninitialized state
 * ================================================================ */
static void test_iommu_runtime_not_ready_on_fresh_state(void) {
    struct fbvbs_global_security_state state;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_iommu_runtime_ready(&state) == 0);
}

/* ================================================================
 * Test: VT-d init fails closed without DMAR table
 * ================================================================ */
static void test_vtd_init_fails_without_dmar(void) {
    struct fbvbs_global_security_state state;
    int status;

    memset(&state, 0, sizeof(state));
    state.iommu.iommu_type = IOMMU_TYPE_VTD;
    /* No DMAR data → init should fail */

    status = fbvbs_vtd_init(&state);
    assert(status == -1);
    assert(state.iommu.kernel_dma_protection == 0U);
}

/* ================================================================
 * Test: AMD-Vi init fails closed without IVRS table
 * ================================================================ */
static void test_amdvi_init_fails_without_ivrs(void) {
    struct fbvbs_global_security_state state;
    int status;

    memset(&state, 0, sizeof(state));
    state.iommu.iommu_type = IOMMU_TYPE_AMD_VI;
    /* No IVRS data → init should fail */

    status = fbvbs_amdvi_init(&state);
    assert(status == -1);
    assert(state.iommu.kernel_dma_protection == 0U);
}

/* ================================================================
 * Test: VT-d detect with no ACPI data reports no IOMMU
 * ================================================================ */
static void test_vtd_detect_no_acpi(void) {
    struct fbvbs_global_security_state state;
    int status;

    memset(&state, 0, sizeof(state));

    status = fbvbs_vtd_detect(&state);
    /* No DMAR → returns 0 (not found, not error) or -1 */
    assert(status <= 0);
    assert(state.iommu.iommu_type == IOMMU_TYPE_NONE ||
           state.iommu.iommu_type == IOMMU_TYPE_VTD);
}

/* ================================================================
 * Test: AMD-Vi detect with no ACPI data reports no IOMMU
 * ================================================================ */
static void test_amdvi_detect_no_acpi(void) {
    struct fbvbs_global_security_state state;
    int status;

    memset(&state, 0, sizeof(state));

    status = fbvbs_amdvi_detect(&state);
    assert(status <= 0);
}

/* ================================================================
 * Test: IOMMU runtime remains not-ready after failed init
 * ================================================================ */
static void test_iommu_not_ready_after_failed_init(void) {
    struct fbvbs_global_security_state state;

    memset(&state, 0, sizeof(state));
    state.iommu.iommu_type = IOMMU_TYPE_VTD;
    (void)fbvbs_vtd_init(&state);

    assert(fbvbs_iommu_runtime_ready(&state) == 0);

    memset(&state, 0, sizeof(state));
    state.iommu.iommu_type = IOMMU_TYPE_AMD_VI;
    (void)fbvbs_amdvi_init(&state);

    assert(fbvbs_iommu_runtime_ready(&state) == 0);
}

int main(void) {
    test_iommu_runtime_not_ready_on_fresh_state();
    test_vtd_init_fails_without_dmar();
    test_amdvi_init_fails_without_ivrs();
    test_vtd_detect_no_acpi();
    test_amdvi_detect_no_acpi();
    test_iommu_not_ready_after_failed_init();
    return 0;
}
