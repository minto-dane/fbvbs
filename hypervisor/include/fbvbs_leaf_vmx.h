#ifndef FBVBS_LEAF_VMX_H
#define FBVBS_LEAF_VMX_H

#include <stddef.h>
#include <stdint.h>

#include "fbvbs_abi.h"

#define FBVBS_MAX_INTERCEPTED_MSRS 16U
#define FBVBS_SYNTHETIC_EXIT_RIP_PIO 0x00000000FFF00001ULL
#define FBVBS_SYNTHETIC_EXIT_RIP_MMIO 0x00000000FFF00002ULL
#define FBVBS_SYNTHETIC_EXIT_RIP_SHUTDOWN 0x00000000FFF00003ULL
#define FBVBS_SYNTHETIC_EXIT_RIP_FAULT 0x00000000FFF00004ULL
#define FBVBS_SYNTHETIC_EPT_ACCESS_SHIFT 8U

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

struct fbvbs_vmx_leaf_external_interrupt {
    uint32_t vector;
    uint32_t reserved0;
    uint64_t reserved1;
};

struct fbvbs_vmx_leaf_cr_access {
    uint32_t cr_number;
    uint32_t access_type;
    uint64_t value;
};

struct fbvbs_vmx_leaf_msr_access {
    uint32_t msr_address;
    uint32_t is_write;
    uint64_t value;
};

struct fbvbs_vmx_leaf_pio {
    uint16_t port;
    uint8_t access_size;
    uint8_t is_write;
    uint32_t reserved0;
    uint64_t value;
};

struct fbvbs_vmx_leaf_mmio {
    uint64_t guest_physical_address;
    uint8_t access_size;
    uint8_t is_write;
    uint16_t reserved0;
    uint32_t reserved1;
    uint64_t value;
};

struct fbvbs_vmx_leaf_ept_violation {
    uint64_t guest_physical_address;
    uint32_t access_bits;
    uint32_t reserved0;
};

union fbvbs_vmx_leaf_exit_detail {
    struct fbvbs_vmx_leaf_external_interrupt external_interrupt;
    struct fbvbs_vmx_leaf_cr_access cr_access;
    struct fbvbs_vmx_leaf_msr_access msr_access;
    struct fbvbs_vmx_leaf_pio pio;
    struct fbvbs_vmx_leaf_mmio mmio;
    struct fbvbs_vmx_leaf_ept_violation ept_violation;
};

struct fbvbs_vmx_leaf_exit {
    uint32_t exit_reason;
    uint32_t reserved0;
    union fbvbs_vmx_leaf_exit_detail detail;
};

_Static_assert(sizeof(struct fbvbs_vcpu) == 64U, "fbvbs_vcpu ABI drift");
_Static_assert(offsetof(struct fbvbs_vcpu, rip) == 8U, "fbvbs_vcpu.rip offset drift");
_Static_assert(offsetof(struct fbvbs_vcpu, cr4) == 48U, "fbvbs_vcpu.cr4 offset drift");
_Static_assert(sizeof(struct fbvbs_vmx_capabilities) == 24U, "fbvbs_vmx_capabilities ABI drift");
_Static_assert(sizeof(struct fbvbs_vmx_leaf_exit) == 32U, "fbvbs_vmx_leaf_exit ABI drift");
_Static_assert(sizeof(union fbvbs_vmx_leaf_exit_detail) == 24U, "fbvbs_vmx_leaf_exit_detail ABI drift");
_Static_assert(offsetof(struct fbvbs_vmx_leaf_exit, detail) == 8U, "fbvbs_vmx_leaf_exit.detail offset drift");
_Static_assert(
    offsetof(struct fbvbs_vmx_leaf_exit, detail.mmio.value) == 24U,
    "fbvbs_vmx_leaf_exit.detail.mmio.value offset drift"
);

int fbvbs_vmx_probe(struct fbvbs_vmx_capabilities *caps);

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
);

#endif
