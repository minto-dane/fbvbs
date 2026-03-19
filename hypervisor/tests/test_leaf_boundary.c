#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "../include/fbvbs_cpu_security.h"
#include "../include/fbvbs_leaf_vmx.h"

static void test_probe_rejects_null(void) {
    assert(fbvbs_vmx_probe(NULL) == INVALID_PARAMETER);
}

static void test_probe_reports_capabilities(void) {
    struct fbvbs_vmx_capabilities caps;

    assert(fbvbs_vmx_probe(&caps) == OK);
    /* VMX availability depends on hardware — just verify probe succeeds
     * and boolean fields are well-formed (0 or 1) */
    assert(caps.vmx_supported == 0U || caps.vmx_supported == 1U);
    assert(caps.hlat_available == 0U || caps.hlat_available == 1U);
    assert(caps.iommu_available == 0U);
    assert(caps.mbec_available == 0U || caps.mbec_available == 1U);
}

static void test_leaf_run_rejects_invalid_inputs(void) {
    struct fbvbs_vmx_capabilities caps = {0};
    struct fbvbs_vcpu vcpu = {0};
    struct fbvbs_vmx_leaf_exit leaf_exit;

    /* NULL pointer checks (before vmx_supported check) */
    caps.vmx_supported = 1U;
    assert(fbvbs_vmx_leaf_run_vcpu(NULL, &vcpu, 0U, 0U, 0U, 0U, NULL, 0U, 4096U, &leaf_exit) == INVALID_PARAMETER);
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, NULL, 0U, 0U, 0U, 0U, NULL, 0U, 4096U, &leaf_exit) == INVALID_PARAMETER);
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, NULL, 0U, 4096U, NULL) == INVALID_PARAMETER);
    /* NULL intercepted_msrs with count > 0 */
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, NULL, 1U, 4096U, &leaf_exit) == INVALID_PARAMETER);
    /* VMX not supported */
    caps.vmx_supported = 0U;
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, NULL, 0U, 4096U, &leaf_exit) == NOT_SUPPORTED_ON_PLATFORM);
}

static void test_leaf_run_models_expected_exit_reasons(void) {
    struct fbvbs_vmx_capabilities caps = {0};
    struct fbvbs_vcpu vcpu = {0};
    struct fbvbs_vmx_leaf_exit leaf_exit;
    uint32_t intercepted_msr = 0xC0000080U;

    /* Set VMX supported explicitly — these tests exercise simulation logic,
     * not real hardware detection */
    caps.vmx_supported = 1U;

    vcpu.pending_interrupt_delivery = 1U;
    vcpu.pending_interrupt_vector = 48U;
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, NULL, 0U, 4096U, &leaf_exit) == OK);
    assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT);
    assert(leaf_exit.detail.external_interrupt.vector == 48U);

    vcpu.pending_interrupt_delivery = 0U;
    vcpu.cr0 = 0U;
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0x1U, 0x1U, 0U, 0U, NULL, 0U, 4096U, &leaf_exit) == OK);
    assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_CR_ACCESS);
    assert(leaf_exit.detail.cr_access.cr_number == 0U);
    assert(leaf_exit.detail.cr_access.access_type == FBVBS_VM_CR_ACCESS_WRITE);
    assert(leaf_exit.detail.cr_access.value == 0U);

    vcpu.cr0 = 0x1U;
    vcpu.cr4 = CR4_PCE;
    assert(fbvbs_vmx_leaf_run_vcpu(
        &caps,
        &vcpu,
        0U,
        0U,
        CR4_PCE,
        0U,
        NULL,
        0U,
        4096U,
        &leaf_exit
    ) == OK);
    assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_CR_ACCESS);
    assert(leaf_exit.detail.cr_access.cr_number == 4U);
    assert(leaf_exit.detail.cr_access.value == CR4_PCE);

    vcpu.cr0 = 0x1U;
    vcpu.cr4 = 0U;
    vcpu.rsp = 0x1122334455667788ULL;
    vcpu.rflags = 0x1U;
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, &intercepted_msr, 1U, 4096U, &leaf_exit) == OK);
    assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_MSR_ACCESS);
    assert(leaf_exit.detail.msr_access.msr_address == 0xC0000080U);
    assert(leaf_exit.detail.msr_access.is_write == 1U);
    assert(leaf_exit.detail.msr_access.value == 0x1122334455667788ULL);

    vcpu.rsp = 0x2000U;
    vcpu.rflags = (uint64_t)FBVBS_VM_EPT_ACCESS_WRITE << FBVBS_SYNTHETIC_EPT_ACCESS_SHIFT;
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, NULL, 0U, 0U, &leaf_exit) == OK);
    assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_EPT_VIOLATION);
    assert(leaf_exit.detail.ept_violation.guest_physical_address == 0x2000U);
    assert(leaf_exit.detail.ept_violation.access_bits == FBVBS_VM_EPT_ACCESS_WRITE);

    vcpu.rip = FBVBS_SYNTHETIC_EXIT_RIP_PIO;
    vcpu.rsp = 0x3F8U;
    vcpu.rflags = 1U;
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, NULL, 0U, 4096U, &leaf_exit) == OK);
    assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_PIO);
    assert(leaf_exit.detail.pio.port == 0x03F8U);
    assert(leaf_exit.detail.pio.is_write == 1U);

    vcpu.rip = FBVBS_SYNTHETIC_EXIT_RIP_MMIO;
    vcpu.rsp = 0x2000U;
    vcpu.rflags = 0U;
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, NULL, 0U, 4096U, &leaf_exit) == OK);
    assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_MMIO);
    assert(leaf_exit.detail.mmio.guest_physical_address == 0x2000U);

    vcpu.rip = FBVBS_SYNTHETIC_EXIT_RIP_SHUTDOWN;
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, NULL, 0U, 4096U, &leaf_exit) == OK);
    assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_SHUTDOWN);

    vcpu.rip = FBVBS_SYNTHETIC_EXIT_RIP_FAULT;
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, NULL, 0U, 4096U, &leaf_exit) == OK);
    assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT);

    vcpu.rip = 0x1234U;
    assert(fbvbs_vmx_leaf_run_vcpu(&caps, &vcpu, 0U, 0U, 0U, 0U, NULL, 0U, 4096U, &leaf_exit) == OK);
    assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_HALT);
}

int main(void) {
    test_probe_rejects_null();
    test_probe_reports_capabilities();
    test_leaf_run_rejects_invalid_inputs();
    test_leaf_run_models_expected_exit_reasons();
    return 0;
}
