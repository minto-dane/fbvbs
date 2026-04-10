#include <stddef.h>
#include <stdint.h>

#include "fbvbs_asm.h"
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
    ensures \result != 0U;
    ensures (\result & ~0x7U) == 0U;
*/
static uint32_t fbvbs_leaf_synthetic_ept_access_bits(const struct fbvbs_vcpu *vcpu) {
    uint32_t access_bits =
        (uint32_t)((vcpu->rflags >> FBVBS_SYNTHETIC_EPT_ACCESS_SHIFT) & 0x7U);

    if (access_bits == 0U) {
        return FBVBS_VM_EPT_ACCESS_READ;
    }

    return access_bits;
}

int fbvbs_vmx_probe(struct fbvbs_vmx_capabilities *caps) {
    uint32_t eax, ebx, ecx, edx;

    if (caps == NULL) {
        return INVALID_PARAMETER;
    }

    fbvbs_leaf_zero_caps(caps);

#if defined(__x86_64__) || defined(_M_X64)
    /* CPUID leaf 1: basic feature flags */
    fbvbs_asm_cpuid(1U, 0U, &eax, &ebx, &ecx, &edx);

    /* Check for VMX support (CPUID.01H:ECX.VMX[bit 5]) */
    if (ecx & (1U << 5)) {
        caps->vmx_supported = 1U;
    }

    /* Check for AES-NI support (CPUID.01H:ECX.AESNI[bit 25]) */
    if (ecx & (1U << 25)) {
        caps->aesni_available = 1U;
    }

    /* Check for extended features (CPUID.07H) */
    fbvbs_asm_cpuid(7U, 0U, &eax, &ebx, &ecx, &edx);

    /* Check for MBEC support (CPUID.07H:ECX.MBEC[bit 6]) */
    if (ecx & (1U << 6)) {
        caps->mbec_available = 1U;
    }

    /* Check for CET support (CPUID.07H:ECX.CET[bit 7]) */
    if (ecx & (1U << 7)) {
        caps->cet_available = 1U;
    }

    /* Check for HLAT support (CPUID.(EAX=7,ECX=2):EAX[bit 5]) */
    fbvbs_asm_cpuid(7U, 2U, &eax, &ebx, &ecx, &edx);
    if (eax & (1U << 5)) {
        caps->hlat_available = 1U;
    }

    /* IOMMU detection requires platform-specific methods (MSR/ACPI) */
    /* For now, leave as 0 (not available) */
    caps->iommu_available = 0U;
#endif

    return OK;
}

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
        fbvbs_leaf_exit_set_external_interrupt(
            leaf_exit,
            vcpu->pending_interrupt_vector
        );
        return OK;
    }
    if (pinned_cr0_mask != 0U && (vcpu->cr0 & pinned_cr0_mask) != pinned_cr0_value) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_CR_ACCESS;
        fbvbs_leaf_exit_set_cr_access(
            leaf_exit,
            0U,
            FBVBS_VM_CR_ACCESS_WRITE,
            vcpu->cr0
        );
        return OK;
    }
    if (pinned_cr4_mask != 0U && (vcpu->cr4 & pinned_cr4_mask) != pinned_cr4_value) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_CR_ACCESS;
        fbvbs_leaf_exit_set_cr_access(
            leaf_exit,
            4U,
            FBVBS_VM_CR_ACCESS_WRITE,
            vcpu->cr4
        );
        return OK;
    }
    if (intercepted_msr_count != 0U) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_MSR_ACCESS;
        /* Synthetic convention: RFLAGS bit 0 selects RDMSR/WRMSR and RSP
         * carries the 64-bit value used by the policy layer tests. */
        fbvbs_leaf_exit_set_msr_access(
            leaf_exit,
            intercepted_msrs[0],
            (uint32_t)(vcpu->rflags & 0x1U),
            vcpu->rsp
        );
        return OK;
    }
    if (mapped_bytes == 0U) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_EPT_VIOLATION;
        /* Synthetic convention: RSP is the faulting GPA and RFLAGS bits
         * 10:8 encode the read/write/execute access bitmap. */
        fbvbs_leaf_exit_set_ept_violation(
            leaf_exit,
            vcpu->rsp,
            fbvbs_leaf_synthetic_ept_access_bits(vcpu)
        );
        return OK;
    }
    if (vcpu->rip == FBVBS_SYNTHETIC_EXIT_RIP_PIO) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_PIO;
        fbvbs_leaf_exit_set_pio(
            leaf_exit,
            (uint16_t)(vcpu->rsp & 0xFFFFU),
            4U,
            (uint8_t)(vcpu->rflags & 0x1U),
            (uint32_t)vcpu->rflags
        );
        return OK;
    }
    if (vcpu->rip == FBVBS_SYNTHETIC_EXIT_RIP_MMIO) {
        leaf_exit->exit_reason = FBVBS_VM_EXIT_REASON_MMIO;
        fbvbs_leaf_exit_set_mmio(
            leaf_exit,
            vcpu->rsp,
            8U,
            (uint8_t)(vcpu->rflags & 0x1U),
            (uint64_t)(uint32_t)vcpu->rflags
        );
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
