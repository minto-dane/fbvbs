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
    assigns exit->exit_reason, exit->cr_number, exit->msr_address,
            exit->port, exit->access_size, exit->is_write,
            exit->value, exit->guest_physical_address;
    ensures exit->exit_reason == 0;
    ensures exit->cr_number == 0;
    ensures exit->msr_address == 0;
    ensures exit->port == 0;
    ensures exit->access_size == 0;
    ensures exit->is_write == 0;
    ensures exit->value == 0;
    ensures exit->guest_physical_address == 0;
*/
static void fbvbs_leaf_zero_exit(struct fbvbs_vmx_leaf_exit *exit) {
    exit->exit_reason = 0U;
    exit->cr_number = 0U;
    exit->msr_address = 0U;
    exit->port = 0U;
    exit->access_size = 0U;
    exit->is_write = 0U;
    exit->value = 0U;
    exit->guest_physical_address = 0U;
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
    if (caps == NULL) {
        return INVALID_PARAMETER;
    }

    fbvbs_leaf_zero_caps(caps);

#if defined(__x86_64__) || defined(_M_X64)
    /* TODO: Replace compile-time assignments with runtime CPUID feature detection */
    /* For now, use conservative defaults that require runtime verification */
    caps->vmx_supported = 1U;
    caps->hlat_available = 0U;  /* Should check CPUID for HLAT support */
    caps->iommu_available = 0U;  /* Should query platform for IOMMU presence */
    caps->mbec_available = 0U;  /* Should check VMX secondary execution controls */
    caps->cet_available = 0U;  /* Should check CPUID for CET support */
    caps->aesni_available = 0U;  /* Should check CPUID for AES-NI support */
#endif

    return OK;
}

/*@ requires \valid(caps) || caps == \null;
    requires \valid(vcpu) || vcpu == \null;
    requires \valid(leaf_exit) || leaf_exit == \null;
    requires intercepted_msr_count == 0 ||
             \valid_read(intercepted_msrs + (0 .. intercepted_msr_count - 1));
    assigns *leaf_exit;
    behavior null_args:
      assumes caps == \null || vcpu == \null || leaf_exit == \null;
      ensures \result == INVALID_PARAMETER;
    behavior null_msr_array:
      assumes caps != \null && vcpu != \null && leaf_exit != \null;
      assumes intercepted_msr_count != 0 && intercepted_msrs == \null;
      ensures \result == INVALID_PARAMETER;
    behavior not_supported:
      assumes caps != \null && vcpu != \null && leaf_exit != \null;
      assumes caps->vmx_supported == 0;
      assumes intercepted_msr_count == 0 || intercepted_msrs != \null;
      ensures \result == NOT_SUPPORTED_ON_PLATFORM;
    behavior ok:
      assumes caps != \null && vcpu != \null && leaf_exit != \null;
      assumes caps->vmx_supported != 0;
      assumes intercepted_msr_count == 0 || intercepted_msrs != \null;
      ensures \result == OK;
*/
int fbvbs_vmx_leaf_run_vcpu(
    const struct fbvbs_vmx_capabilities *caps,
    const struct fbvbs_vcpu *vcpu,
    uint64_t pinned_cr0_mask,
    uint64_t pinned_cr4_mask,
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
    if (intercepted_msr_count != 0U && intercepted_msrs == NULL) {
        return INVALID_PARAMETER;
    }
    fbvbs_leaf_zero_exit(leaf_exit);

    if (vcpu->pending_interrupt_delivery != 0U) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT;
        leaf_exit->value = vcpu->pending_interrupt_vector;
        return OK;
    }
    if (pinned_cr0_mask != 0U && (vcpu->cr0 & pinned_cr0_mask) != pinned_cr0_mask) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_CR_ACCESS;
        leaf_exit->cr_number = 0U;
        leaf_exit->value = vcpu->cr0;
        return OK;
    }
    if (pinned_cr4_mask != 0U && (vcpu->cr4 & pinned_cr4_mask) != pinned_cr4_mask) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_CR_ACCESS;
        leaf_exit->cr_number = 4U;
        leaf_exit->value = vcpu->cr4;
        return OK;
    }
    if (intercepted_msr_count != 0U) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_MSR_ACCESS;
        leaf_exit->msr_address = intercepted_msrs[0];
        return OK;
    }
    if (mapped_bytes == 0U) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_EPT_VIOLATION;
        return OK;
    }
    if (vcpu->rip == FBVBS_SYNTHETIC_EXIT_RIP_PIO) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_PIO;
        leaf_exit->port = (uint16_t)(vcpu->rsp & 0xFFFFU);
        leaf_exit->access_size = 4U;
        leaf_exit->is_write = (uint8_t)(vcpu->rflags & 0x1U);
        leaf_exit->value = (uint32_t)vcpu->rflags;
        return OK;
    }
    if (vcpu->rip == FBVBS_SYNTHETIC_EXIT_RIP_MMIO) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_MMIO;
        leaf_exit->guest_physical_address = vcpu->rsp;
        leaf_exit->access_size = 8U;
        leaf_exit->is_write = (uint8_t)(vcpu->rflags & 0x1U);
        leaf_exit->value = (uint32_t)vcpu->rflags;
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