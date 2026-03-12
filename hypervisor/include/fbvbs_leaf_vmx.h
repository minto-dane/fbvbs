#ifndef FBVBS_LEAF_VMX_H
#define FBVBS_LEAF_VMX_H

#include <stddef.h>
#include <stdint.h>

#include "fbvbs_abi.h"

#define FBVBS_SYNTHETIC_EXIT_RIP_PIO 0x00000000FFF00001ULL
#define FBVBS_SYNTHETIC_EXIT_RIP_MMIO 0x00000000FFF00002ULL
#define FBVBS_SYNTHETIC_EXIT_RIP_SHUTDOWN 0x00000000FFF00003ULL
#define FBVBS_SYNTHETIC_EXIT_RIP_FAULT 0x00000000FFF00004ULL

struct fbvbs_vcpu {
    uint32_t state;
    uint32_t pending_interrupt_vector;
    uint64_t rip;
    uint64_t rsp;
    uint64_t rflags;
    uint64_t cr0;
    uint64_t cr3;
    uint64_t cr4;
    uint32_t pending_interrupt_delivery;
    uint32_t reserved0;
};

struct fbvbs_vmx_capabilities {
    uint32_t vmx_supported;
    uint32_t hlat_available;
    uint32_t iommu_available;
    uint32_t mbec_available;
    uint32_t cet_available;
    uint32_t aesni_available;
};

struct fbvbs_vmx_leaf_exit {
    uint32_t exit_reason;
    uint32_t cr_number;
    uint32_t msr_address;
    uint16_t port;
    uint8_t access_size;
    uint8_t is_write;
    uint64_t value;
    uint64_t guest_physical_address;
};

_Static_assert(sizeof(struct fbvbs_vcpu) == 64U, "fbvbs_vcpu ABI drift");
_Static_assert(offsetof(struct fbvbs_vcpu, rip) == 8U, "fbvbs_vcpu.rip offset drift");
_Static_assert(offsetof(struct fbvbs_vcpu, cr4) == 48U, "fbvbs_vcpu.cr4 offset drift");
_Static_assert(sizeof(struct fbvbs_vmx_capabilities) == 24U, "fbvbs_vmx_capabilities ABI drift");
_Static_assert(sizeof(struct fbvbs_vmx_leaf_exit) == 32U, "fbvbs_vmx_leaf_exit ABI drift");
_Static_assert(offsetof(struct fbvbs_vmx_leaf_exit, value) == 16U, "fbvbs_vmx_leaf_exit.value offset drift");
_Static_assert(
    offsetof(struct fbvbs_vmx_leaf_exit, guest_physical_address) == 24U,
    "fbvbs_vmx_leaf_exit.guest_physical_address offset drift"
);

int fbvbs_vmx_probe(struct fbvbs_vmx_capabilities *caps);

/*@ requires \valid_read(caps);
    requires \valid_read(vcpu);
    requires intercepted_msr_count <= 16;
    requires intercepted_msr_count == 0 ||
             \valid_read(intercepted_msrs + (0 .. intercepted_msr_count - 1));
    requires \valid(leaf_exit);
    assigns *leaf_exit;
    ensures \result == OK || \result == NOT_SUPPORTED_ON_PLATFORM || \result == INVALID_STATE;
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
);

#endif
