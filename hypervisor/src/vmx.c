#include <stddef.h>
#include <stdint.h>

#include "fbvbs_leaf_vmx.h"

static void fbvbs_leaf_zero_memory(void *buffer, size_t length) {
    uint8_t *bytes = (uint8_t *)buffer;
    size_t index;

    for (index = 0U; index < length; ++index) {
        bytes[index] = 0U;
    }
}

int fbvbs_vmx_probe(struct fbvbs_vmx_capabilities *caps) {
    if (caps == NULL) {
        return INVALID_PARAMETER;
    }

    fbvbs_leaf_zero_memory(caps, sizeof(*caps));

#if defined(__x86_64__) || defined(_M_X64)
    caps->vmx_supported = 1U;
    caps->hlat_available = 1U;
    caps->iommu_available = 1U;
    caps->mbec_available = 1U;
    caps->cet_available = 1U;
    caps->aesni_available = 1U;
#endif

    return OK;
}

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
    fbvbs_leaf_zero_memory(leaf_exit, sizeof(*leaf_exit));

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
