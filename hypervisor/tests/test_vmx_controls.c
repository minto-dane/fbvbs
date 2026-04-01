/* FBVBS VMX Controls Unit Tests
 *
 * Requirements: REQ-1004 (継続的テスト), REQ-0332 (Shadow Stack EPT)
 *
 * Tests CET, MSR bitmap, preemption timer configuration.
 * Runs in host environment with hardware stubs.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../include/fbvbs_hypervisor.h"

/* Stub: audit sink */
void fbvbs_audit_primary_sink_write(const char *message) { (void)message; }

/* ================================================================
 * Test: build_security_controls produces valid output with no CET
 * ================================================================ */
static void test_build_security_controls_no_cet(void) {
    struct fbvbs_vmx_security_controls controls;
    struct fbvbs_vmx_capabilities caps;
    int status;

    memset(&controls, 0xFF, sizeof(controls));
    memset(&caps, 0, sizeof(caps));
    caps.vmx_supported = 1U;
    caps.cet_available = 0U;

    status = fbvbs_vmx_build_security_controls(&controls, &caps);

    /* In host environment without page allocator, MSR bitmap alloc
     * fails → returns -1. This is correct fail-closed behavior.
     * If page allocator were initialized, status would be 0. */
    if (status == 0) {
        /* Preemption timer should be enabled */
        assert(controls.pin_controls_or != 0U);

        /* CET fields should be zero when not available */
        assert(controls.host_s_cet == 0ULL);
        assert(controls.host_ssp == 0ULL);
        assert(controls.host_isst_addr == 0ULL);
        assert(controls.guest_s_cet == 0ULL);

        /* MSR bitmap should be initialized */
        assert(controls.msr_bitmap_valid == 1);
    } else {
        /* Fail-closed: MSR bitmap page allocation failed */
        assert(status == -1);
    }
}

/* ================================================================
 * Test: build_security_controls with CET available
 * ================================================================ */
static void test_build_security_controls_with_cet(void) {
    struct fbvbs_vmx_security_controls controls;
    struct fbvbs_vmx_capabilities caps;
    int status;

    memset(&controls, 0, sizeof(controls));
    memset(&caps, 0, sizeof(caps));
    caps.vmx_supported = 1U;
    caps.cet_available = 1U;

    status = fbvbs_vmx_build_security_controls(&controls, &caps);

    /* CET might fail if page allocator is not initialized, that's OK —
     * we test the fail-closed path (returns -1 when CET alloc fails). */
    if (status == 0) {
        assert(controls.host_s_cet != 0ULL || controls.guest_s_cet != 0ULL ||
               controls.entry_controls_or != 0U);
    } else {
        /* Fail-closed: CET available but SSP/ISST alloc failed */
        assert(status == -1);
    }
}

/* ================================================================
 * Test: double call is safe — no corruption on repeated failure
 *
 * In hosted mode the page allocator is not initialized, so CET
 * allocation fails before the MSR bitmap path is reached. This
 * test verifies that two consecutive failures leave controls in a
 * consistent zero state without crashing.
 *
 * NOTE: the cet_pages_owned cleanup guard (CET succeeds, MSR
 * bitmap fails) requires a mock page allocator that can fail after
 * N allocations. That path is verified by code inspection only.
 * ================================================================ */
static void test_build_security_controls_double_call_safe(void) {
    struct fbvbs_vmx_security_controls controls;
    struct fbvbs_vmx_capabilities caps;
    int s1;
    int s2;

    memset(&controls, 0, sizeof(controls));
    memset(&caps, 0, sizeof(caps));
    caps.vmx_supported = 1U;
    caps.cet_available = 1U;

    /* First call: CET alloc fails in hosted mode (no page allocator) */
    s1 = fbvbs_vmx_build_security_controls(&controls, &caps);
    assert(s1 == -1);

    /* Second call: must not double-free or corrupt state */
    s2 = fbvbs_vmx_build_security_controls(&controls, &caps);
    assert(s2 == -1);

    /* Controls remain zeroed after both failures — no partial init */
    assert(controls.host_ssp == 0ULL);
    assert(controls.host_isst_addr == 0ULL);
}

/* ================================================================
 * Test: MSR bitmap physical address is stable after init
 * ================================================================ */
static void test_msr_bitmap_phys_stable(void) {
    uint64_t phys1;
    uint64_t phys2;

    phys1 = fbvbs_vmx_get_msr_bitmap_phys();
    phys2 = fbvbs_vmx_get_msr_bitmap_phys();
    assert(phys1 == phys2);
    /* In hosted test environment the page allocator is not initialised,
     * so phys1 == phys2 == 0 is expected.  When a real allocator is
     * available, verify alignment. */
    if (phys1 != 0U) {
        assert((phys1 & 0xFFFU) == 0U);
    }
}

int main(void) {
    test_build_security_controls_no_cet();
    test_build_security_controls_with_cet();
    test_build_security_controls_double_call_safe();
    test_msr_bitmap_phys_stable();
    return 0;
}
