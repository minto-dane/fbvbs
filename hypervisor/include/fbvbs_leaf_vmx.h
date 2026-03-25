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
    /* Per-vCPU debug register state (REQ-0342: guest/host DR isolation) */
    uint64_t dr0;
    uint64_t dr1;
    uint64_t dr2;
    uint64_t dr3;
    uint64_t dr6;   /* DR6: debug status (read-only to guest except via MOV) */
    uint64_t dr7;   /* DR7: debug control — VMCS manages guest DR7 */
};

struct fbvbs_vmx_capabilities {
    uint32_t vmx_supported;
    uint32_t hlat_available;
    uint32_t iommu_available;
    uint32_t mbec_available;
    uint32_t cet_available;
    uint32_t aesni_available;
    uint32_t posted_int_available;
    uint32_t apic_virt_available;
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

struct fbvbs_vmx_leaf_dr_access {
    uint32_t dr_number;     /* DR0-DR7 */
    uint32_t access_type;   /* 0=MOV to DR, 1=MOV from DR */
    uint64_t value;         /* value being written (for MOV to DR) */
};

struct fbvbs_vmx_leaf_exit_detail {
    uint64_t word0;
    uint64_t word1;
    uint64_t word2;
};

struct fbvbs_vmx_leaf_exit {
    uint32_t exit_reason;
    uint32_t reserved0;
    struct fbvbs_vmx_leaf_exit_detail detail;
};

_Static_assert(sizeof(struct fbvbs_vcpu) == 112U, "fbvbs_vcpu ABI drift");
_Static_assert(offsetof(struct fbvbs_vcpu, rip) == 8U, "fbvbs_vcpu.rip offset drift");
_Static_assert(offsetof(struct fbvbs_vcpu, cr4) == 48U, "fbvbs_vcpu.cr4 offset drift");
_Static_assert(offsetof(struct fbvbs_vcpu, dr0) == 64U, "fbvbs_vcpu.dr0 offset drift");
_Static_assert(sizeof(struct fbvbs_vmx_capabilities) == 32U, "fbvbs_vmx_capabilities ABI drift");
_Static_assert(sizeof(struct fbvbs_vmx_leaf_exit) == 32U, "fbvbs_vmx_leaf_exit ABI drift");
_Static_assert(sizeof(struct fbvbs_vmx_leaf_exit_detail) == 24U, "fbvbs_vmx_leaf_exit_detail ABI drift");
_Static_assert(offsetof(struct fbvbs_vmx_leaf_exit, detail) == 8U, "fbvbs_vmx_leaf_exit.detail offset drift");
_Static_assert(
    offsetof(struct fbvbs_vmx_leaf_exit, detail.word2) == 24U,
    "fbvbs_vmx_leaf_exit.detail.word2 offset drift"
);

#define FBVBS_LEAF_EXIT_EXTERNAL_INTERRUPT_VECTOR(exit_ptr) \
    ((uint32_t)((exit_ptr)->detail.word0 & 0xFFFFFFFFULL))

#define FBVBS_LEAF_EXIT_CR_NUMBER(exit_ptr) \
    ((uint32_t)((exit_ptr)->detail.word0 & 0xFFFFFFFFULL))

#define FBVBS_LEAF_EXIT_CR_ACCESS_TYPE(exit_ptr) \
    ((uint32_t)(((exit_ptr)->detail.word0 >> 32) & 0xFFFFFFFFULL))

#define FBVBS_LEAF_EXIT_CR_VALUE(exit_ptr) \
    ((exit_ptr)->detail.word1)

#define FBVBS_LEAF_EXIT_MSR_ADDRESS(exit_ptr) \
    ((uint32_t)((exit_ptr)->detail.word0 & 0xFFFFFFFFULL))

#define FBVBS_LEAF_EXIT_MSR_IS_WRITE(exit_ptr) \
    ((uint32_t)(((exit_ptr)->detail.word0 >> 32) & 0xFFFFFFFFULL))

#define FBVBS_LEAF_EXIT_MSR_VALUE(exit_ptr) \
    ((exit_ptr)->detail.word1)

#define FBVBS_LEAF_EXIT_PIO_PORT(exit_ptr) \
    ((uint16_t)((exit_ptr)->detail.word0 & 0xFFFFULL))

#define FBVBS_LEAF_EXIT_PIO_ACCESS_SIZE(exit_ptr) \
    ((uint8_t)(((exit_ptr)->detail.word0 >> 16) & 0xFFULL))

#define FBVBS_LEAF_EXIT_PIO_IS_WRITE(exit_ptr) \
    ((uint8_t)(((exit_ptr)->detail.word0 >> 24) & 0xFFULL))

#define FBVBS_LEAF_EXIT_PIO_VALUE(exit_ptr) \
    ((uint32_t)((exit_ptr)->detail.word1 & 0xFFFFFFFFULL))

#define FBVBS_LEAF_EXIT_MMIO_GPA(exit_ptr) \
    ((exit_ptr)->detail.word0)

#define FBVBS_LEAF_EXIT_MMIO_ACCESS_SIZE(exit_ptr) \
    ((uint8_t)((exit_ptr)->detail.word1 & 0xFFULL))

#define FBVBS_LEAF_EXIT_MMIO_IS_WRITE(exit_ptr) \
    ((uint8_t)(((exit_ptr)->detail.word1 >> 8) & 0xFFULL))

#define FBVBS_LEAF_EXIT_MMIO_VALUE(exit_ptr) \
    ((uint32_t)((exit_ptr)->detail.word2 & 0xFFFFFFFFULL))

#define FBVBS_LEAF_EXIT_EPT_GPA(exit_ptr) \
    ((exit_ptr)->detail.word0)

#define FBVBS_LEAF_EXIT_EPT_ACCESS_BITS(exit_ptr) \
    ((uint32_t)((exit_ptr)->detail.word1 & 0xFFFFFFFFULL))

#define FBVBS_LEAF_EXIT_DR_NUMBER(exit_ptr) \
    ((uint32_t)((exit_ptr)->detail.word0 & 0xFFFFFFFFULL))

#define FBVBS_LEAF_EXIT_DR_ACCESS_TYPE(exit_ptr) \
    ((uint32_t)(((exit_ptr)->detail.word0 >> 32) & 0xFFFFFFFFULL))

#define FBVBS_LEAF_EXIT_DR_VALUE(exit_ptr) \
    ((exit_ptr)->detail.word1)

static inline void fbvbs_leaf_exit_set_external_interrupt(
    struct fbvbs_vmx_leaf_exit *leaf_exit,
    uint32_t vector
) {
    leaf_exit->detail.word0 = (uint64_t)vector;
    leaf_exit->detail.word1 = 0U;
    leaf_exit->detail.word2 = 0U;
}

static inline void fbvbs_leaf_exit_set_cr_access(
    struct fbvbs_vmx_leaf_exit *leaf_exit,
    uint32_t cr_number,
    uint32_t access_type,
    uint64_t value
) {
    leaf_exit->detail.word0 = (uint64_t)cr_number | ((uint64_t)access_type << 32);
    leaf_exit->detail.word1 = value;
    leaf_exit->detail.word2 = 0U;
}

static inline void fbvbs_leaf_exit_set_msr_access(
    struct fbvbs_vmx_leaf_exit *leaf_exit,
    uint32_t msr_address,
    uint32_t is_write,
    uint64_t value
) {
    leaf_exit->detail.word0 = (uint64_t)msr_address | ((uint64_t)is_write << 32);
    leaf_exit->detail.word1 = value;
    leaf_exit->detail.word2 = 0U;
}

static inline void fbvbs_leaf_exit_set_ept_violation(
    struct fbvbs_vmx_leaf_exit *leaf_exit,
    uint64_t guest_physical_address,
    uint32_t access_bits
) {
    leaf_exit->detail.word0 = guest_physical_address;
    leaf_exit->detail.word1 = (uint64_t)access_bits;
    leaf_exit->detail.word2 = 0U;
}

static inline void fbvbs_leaf_exit_set_pio(
    struct fbvbs_vmx_leaf_exit *leaf_exit,
    uint16_t port,
    uint8_t access_size,
    uint8_t is_write,
    uint32_t value
) {
    leaf_exit->detail.word0 = (uint64_t)port |
        ((uint64_t)access_size << 16) |
        ((uint64_t)is_write << 24);
    leaf_exit->detail.word1 = (uint64_t)value;
    leaf_exit->detail.word2 = 0U;
}

static inline void fbvbs_leaf_exit_set_mmio(
    struct fbvbs_vmx_leaf_exit *leaf_exit,
    uint64_t guest_physical_address,
    uint8_t access_size,
    uint8_t is_write,
    uint64_t value
) {
    leaf_exit->detail.word0 = guest_physical_address;
    leaf_exit->detail.word1 = (uint64_t)access_size | ((uint64_t)is_write << 8);
    leaf_exit->detail.word2 = value;
}

static inline void fbvbs_leaf_exit_set_dr_access(
    struct fbvbs_vmx_leaf_exit *leaf_exit,
    uint32_t dr_number,
    uint32_t access_type,
    uint64_t value
) {
    leaf_exit->detail.word0 = (uint64_t)dr_number | ((uint64_t)access_type << 32);
    leaf_exit->detail.word1 = value;
    leaf_exit->detail.word2 = 0U;
}

/*@ requires \valid(caps) || caps == \null;
    assigns *caps;
    behavior null_ptr:
      assumes caps == \null;
      assigns \nothing;
      ensures \result == INVALID_PARAMETER;
    behavior valid_ptr:
      assumes caps != \null;
      assigns *caps;
      ensures \result == OK;
    complete behaviors;
    disjoint behaviors;
*/
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
