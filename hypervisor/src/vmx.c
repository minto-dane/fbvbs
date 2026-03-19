#include <stddef.h>
#include <stdint.h>

#include "fbvbs_leaf_vmx.h"

/*@ requires \valid(caps);
    assigns *caps;
    ensures caps->vmx_supported == 0;
    ensures caps->hlat_available == 0;
    ensures caps->iommu_available == 0;
    ensures caps->mbec_available == 0;
    ensures caps->cet_available == 0;
    ensures caps->aesni_available == 0;
*/
static void fbvbs_leaf_zero_caps(struct fbvbs_vmx_capabilities *caps) {
    caps->vmx_supported = 0U;
    caps->hlat_available = 0U;
    caps->iommu_available = 0U;
    caps->mbec_available = 0U;
    caps->cet_available = 0U;
    caps->aesni_available = 0U;
}

/*@ requires \valid(exit);
    assigns *exit;
    ensures exit->exit_reason == 0;
    ensures exit->reserved0 == 0;
*/
static void fbvbs_leaf_zero_exit(struct fbvbs_vmx_leaf_exit *exit) {
    *exit = (struct fbvbs_vmx_leaf_exit){0};
}

/*@ requires \valid_read(vcpu);
    assigns \nothing;
    ensures \result == FBVBS_VM_EPT_ACCESS_READ ||
            \result == FBVBS_VM_EPT_ACCESS_WRITE ||
            \result == FBVBS_VM_EPT_ACCESS_EXECUTE ||
            \result == (FBVBS_VM_EPT_ACCESS_READ | FBVBS_VM_EPT_ACCESS_WRITE) ||
            \result == (FBVBS_VM_EPT_ACCESS_READ | FBVBS_VM_EPT_ACCESS_EXECUTE) ||
            \result == (FBVBS_VM_EPT_ACCESS_WRITE | FBVBS_VM_EPT_ACCESS_EXECUTE) ||
            \result == (FBVBS_VM_EPT_ACCESS_READ | FBVBS_VM_EPT_ACCESS_WRITE | FBVBS_VM_EPT_ACCESS_EXECUTE);
*/
static uint32_t fbvbs_leaf_synthetic_ept_access_bits(const struct fbvbs_vcpu *vcpu) {
    uint32_t access_bits =
        (uint32_t)((vcpu->rflags >> FBVBS_SYNTHETIC_EPT_ACCESS_SHIFT) & 0x7U);

    if (access_bits == 0U) {
        return FBVBS_VM_EPT_ACCESS_READ;
    }

    return access_bits;
}

/*@ requires \valid(caps) || caps == \null;
    assigns *caps;
    behavior null_ptr:
      assumes caps == \null;
      ensures \result == INVALID_PARAMETER;
    behavior valid_ptr:
      assumes caps != \null;
      ensures \result == OK;
    complete behaviors;
    disjoint behaviors;
*/
int fbvbs_vmx_probe(struct fbvbs_vmx_capabilities *caps) {
    uint32_t eax, ebx, ecx, edx;

    if (caps == NULL) {
        return INVALID_PARAMETER;
    }

    fbvbs_leaf_zero_caps(caps);

#if defined(__x86_64__) || defined(_M_X64)
    /* CPUID leaf 1: basic feature flags */
    eax = 1U;
    ecx = 0U;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "0"(eax), "2"(ecx)
                     : "memory");

    /* Check for VMX support (CPUID.01H:ECX.VMX[bit 5]) */
    if (ecx & (1U << 5)) {
        caps->vmx_supported = 1U;
    }

    /* Check for AES-NI support (CPUID.01H:ECX.AESNI[bit 25]) */
    if (ecx & (1U << 25)) {
        caps->aesni_available = 1U;
    }

    /* Check for extended features (CPUID.07H) */
    eax = 7U;
    ecx = 0U;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "0"(eax), "2"(ecx)
                     : "memory");

    /* Check for MBEC support (CPUID.07H:ECX.MBEC[bit 6]) */
    if (ecx & (1U << 6)) {
        caps->mbec_available = 1U;
    }

    /* Check for CET support (CPUID.07H:ECX.CET[bit 7]) */
    if (ecx & (1U << 7)) {
        caps->cet_available = 1U;
    }

    /* Check for HLAT support (CPUID.(EAX=7,ECX=2):EAX[bit 5]) */
    eax = 7U;
    ecx = 2U;
    __asm__ volatile("cpuid"
                     : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                     : "0"(eax), "2"(ecx)
                     : "memory");
    if (eax & (1U << 5)) {
        caps->hlat_available = 1U;
    }

    /* IOMMU detection requires platform-specific methods (MSR/ACPI) */
    /* For now, leave as 0 (not available) */
    caps->iommu_available = 0U;
#endif

    return OK;
}

/*@ requires \valid_read(caps) || caps == \null;
    requires \valid_read(vcpu) || vcpu == \null;
    requires \valid(leaf_exit) || leaf_exit == \null;
    requires intercepted_msr_count == 0 || intercepted_msrs == \null ||
             intercepted_msr_count > FBVBS_MAX_INTERCEPTED_MSRS ||
             \valid_read(intercepted_msrs + (0 .. intercepted_msr_count - 1));
    behavior null_args:
      assumes caps == \null || vcpu == \null || leaf_exit == \null;
      assigns \nothing;
      ensures \result == INVALID_PARAMETER;
    behavior not_supported:
      assumes caps != \null && vcpu != \null && leaf_exit != \null;
      assumes caps->vmx_supported == 0;
      assigns \nothing;
      ensures \result == NOT_SUPPORTED_ON_PLATFORM;
    behavior bad_msr_count:
      assumes caps != \null && vcpu != \null && leaf_exit != \null;
      assumes caps->vmx_supported != 0;
      assumes intercepted_msr_count > FBVBS_MAX_INTERCEPTED_MSRS;
      assigns \nothing;
      ensures \result == INVALID_PARAMETER;
    behavior null_msr_array:
      assumes caps != \null && vcpu != \null && leaf_exit != \null;
      assumes caps->vmx_supported != 0;
      assumes intercepted_msr_count <= FBVBS_MAX_INTERCEPTED_MSRS;
      assumes intercepted_msr_count != 0 && intercepted_msrs == \null;
      assigns \nothing;
      ensures \result == INVALID_PARAMETER;
    behavior ok:
      assumes caps != \null && vcpu != \null && leaf_exit != \null;
      assumes caps->vmx_supported != 0;
      assumes intercepted_msr_count <= FBVBS_MAX_INTERCEPTED_MSRS;
      assumes intercepted_msr_count == 0 || intercepted_msrs != \null;
      assigns *leaf_exit;
      ensures \result == OK;
    complete behaviors;
    disjoint behaviors;
*/
int fbvbs_vmx_leaf_run_vcpu(
    const struct fbvbs_vmx_capabilities *caps,
    const struct fbvbs_vcpu *vcpu,
    uint64_t pinned_cr0_mask,
    uint64_t pinned_cr0_value,
    uint64_t pinned_cr4_mask,
    uint64_t pinned_cr4_value,
    const uint32_t *intercepted_msrs,
    uint32_t intercepted_msr_count,
    uint64_t mapped_bytes,
    struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    if (caps == NULL || vcpu == NULL || leaf_exit == NULL) {
        return INVALID_PARAMETER;
    }
    if (caps->vmx_supported == 0U) {
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    if (intercepted_msr_count > FBVBS_MAX_INTERCEPTED_MSRS) {
        return INVALID_PARAMETER;
    }
    if (intercepted_msr_count != 0U && intercepted_msrs == NULL) {
        return INVALID_PARAMETER;
    }
    fbvbs_leaf_zero_exit(leaf_exit);

    if (vcpu->pending_interrupt_delivery != 0U) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT;
        leaf_exit->detail.external_interrupt.vector = vcpu->pending_interrupt_vector;
        return OK;
    }
    if (pinned_cr0_mask != 0U && (vcpu->cr0 & pinned_cr0_mask) != pinned_cr0_value) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_CR_ACCESS;
        leaf_exit->detail.cr_access.cr_number = 0U;
        leaf_exit->detail.cr_access.access_type = FBVBS_VM_CR_ACCESS_WRITE;
        leaf_exit->detail.cr_access.value = vcpu->cr0;
        return OK;
    }
    if (pinned_cr4_mask != 0U && (vcpu->cr4 & pinned_cr4_mask) != pinned_cr4_value) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_CR_ACCESS;
        leaf_exit->detail.cr_access.cr_number = 4U;
        leaf_exit->detail.cr_access.access_type = FBVBS_VM_CR_ACCESS_WRITE;
        leaf_exit->detail.cr_access.value = vcpu->cr4;
        return OK;
    }
    if (intercepted_msr_count != 0U) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_MSR_ACCESS;
        leaf_exit->detail.msr_access.msr_address = intercepted_msrs[0];
        /* Synthetic convention: RFLAGS bit 0 selects RDMSR/WRMSR and RSP
         * carries the 64-bit value used by the policy layer tests. */
        leaf_exit->detail.msr_access.is_write = (uint32_t)(vcpu->rflags & 0x1U);
        leaf_exit->detail.msr_access.value = vcpu->rsp;
        return OK;
    }
    if (mapped_bytes == 0U) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_EPT_VIOLATION;
        /* Synthetic convention: RSP is the faulting GPA and RFLAGS bits
         * 10:8 encode the read/write/execute access bitmap. */
        leaf_exit->detail.ept_violation.guest_physical_address = vcpu->rsp;
        leaf_exit->detail.ept_violation.access_bits =
            fbvbs_leaf_synthetic_ept_access_bits(vcpu);
        return OK;
    }
    if (vcpu->rip == FBVBS_SYNTHETIC_EXIT_RIP_PIO) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_PIO;
        leaf_exit->detail.pio.port = (uint16_t)(vcpu->rsp & 0xFFFFU);
        leaf_exit->detail.pio.access_size = 4U;
        leaf_exit->detail.pio.is_write = (uint8_t)(vcpu->rflags & 0x1U);
        leaf_exit->detail.pio.value = (uint32_t)vcpu->rflags;
        return OK;
    }
    if (vcpu->rip == FBVBS_SYNTHETIC_EXIT_RIP_MMIO) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_MMIO;
        leaf_exit->detail.mmio.guest_physical_address = vcpu->rsp;
        leaf_exit->detail.mmio.access_size = 8U;
        leaf_exit->detail.mmio.is_write = (uint8_t)(vcpu->rflags & 0x1U);
        leaf_exit->detail.mmio.value = (uint32_t)vcpu->rflags;
        return OK;
    }
    if (vcpu->rip == FBVBS_SYNTHETIC_EXIT_RIP_SHUTDOWN) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_SHUTDOWN;
        return OK;
    }
    if (vcpu->rip == FBVBS_SYNTHETIC_EXIT_RIP_FAULT) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT;
        return OK;
    }

    leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_HALT;
    return OK;
}
