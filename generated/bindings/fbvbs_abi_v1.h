/* Generated from plan/fbvbs-design.md. Do not edit manually. */
#ifndef FBVBS_ABI_V1_H
#define FBVBS_ABI_V1_H

#include <stdint.h>

#define FBVBS_CMD_FLAG_SEPARATE_OUTPUT (1ULL << 0)

#define EMPTY 0
#define READY 1
#define EXECUTING 2
#define COMPLETED 3
#define FAILED 4

#define PARTITION_KIND_TRUSTED_SERVICE 1
#define PARTITION_KIND_FREEBSD_HOST 2
#define PARTITION_KIND_GUEST_VM 3
#define SERVICE_KIND_NONE 0
#define SERVICE_KIND_KCI 1
#define SERVICE_KIND_KSI 2
#define SERVICE_KIND_IKS 3
#define SERVICE_KIND_SKS 4
#define SERVICE_KIND_UVS 5
#define PARTITION_ID_MICROHYPERVISOR 0
#define MEM_PERM_R 0x0001
#define MEM_PERM_W 0x0002
#define MEM_PERM_X 0x0004
#define KSI_CLASS_UCRED 1
#define KSI_CLASS_PRISON 2
#define KSI_CLASS_SECURELEVEL 3
#define KSI_CLASS_MAC 4
#define KSI_CLASS_CAPSICUM 5
#define KSI_CLASS_FIREWALL 6
#define KSI_CLASS_P_TEXTVP 7
#define IKS_KEY_ED25519 1
#define IKS_KEY_ECDSA_P256 2
#define IKS_KEY_RSA3072 3
#define IKS_KEY_X25519 4
#define IKS_KEY_ECDH_P256 5
#define IKS_OP_SIGN 0x0001
#define IKS_OP_KEY_EXCHANGE 0x0002
#define IKS_OP_DERIVE 0x0004
#define CR_NUMBER_CR0 0
#define CR_NUMBER_CR3 3
#define CR_NUMBER_CR4 4
#define UVS_OBJECT_KEY 1
#define UVS_OBJECT_ARTIFACT 2
#define VM_FLAG_X2APIC 0x0001
#define VM_FLAG_NESTED_VIRT_DISABLED 0x0002
#define VM_RUN_FLAG_NONE 0x0000
#define VM_REG_RIP 1
#define VM_REG_RSP 2
#define VM_REG_RFLAGS 3
#define VM_REG_CR0 4
#define VM_REG_CR3 5
#define VM_REG_CR4 6
#define VM_DELIVERY_FIXED 1
#define VM_DELIVERY_NMI 2
#define CR_ACCESS_READ 1
#define CR_ACCESS_WRITE 2
#define FAULT_CODE_PARTITION_INTERNAL 1
#define FAULT_CODE_MEASUREMENT_FAILURE 2
#define FAULT_CODE_VM_EXIT_UNCLASSIFIED 3
#define CAP_BITMAP0_MBEC_OR_GMET (1ULL << 0)
#define CAP_BITMAP0_HLAT (1ULL << 1)
#define CAP_BITMAP0_CET (1ULL << 2)
#define CAP_BITMAP0_AESNI (1ULL << 3)

#define OK 0
#define INVALID_PARAMETER 1
#define INVALID_CALLER 2
#define PERMISSION_DENIED 3
#define RESOURCE_BUSY 4
#define NOT_SUPPORTED_ON_PLATFORM 5
#define MEASUREMENT_FAILED 6
#define SIGNATURE_INVALID 7
#define ROLLBACK_DETECTED 8
#define RETRY_LATER 9
#define REVOKED 10
#define GENERATION_MISMATCH 11
#define DEPENDENCY_UNSATISFIED 12
#define CALLSITE_REJECTED 13
#define POLICY_DENIED 14
#define INTERNAL_CORRUPTION 15
#define INVALID_STATE 16
#define NOT_FOUND 17
#define ALREADY_EXISTS 18
#define RESOURCE_EXHAUSTED 19
#define BUFFER_TOO_SMALL 20
#define ABI_VERSION_UNSUPPORTED 21
#define SNAPSHOT_INCONSISTENT 22
#define FRESHNESS_FAILED 23
#define REPLAY_DETECTED 24
#define TIMEOUT 25

struct fbvbs_log_record_v1 {
    uint64_t sequence;
    uint64_t boot_id_hi;
    uint64_t boot_id_lo;
    uint64_t timestamp_counter;
    uint32_t cpu_id;
    uint32_t source_component;
    uint16_t severity;
    uint16_t event_code;
    uint32_t payload_length;
    uint8_t payload[220];
    uint32_t crc32c;
};
#define FBVBS_LOG_RECORD_V1_SIZE 272

struct fbvbs_log_ring_header_v1 {
    uint32_t abi_version;
    uint32_t total_size;
    uint32_t record_size;
    uint32_t write_offset;
    uint64_t max_readable_sequence;
    uint64_t boot_id_hi;
    uint64_t boot_id_lo;
};
#define FBVBS_LOG_RING_HEADER_V1_SIZE 40

struct fbvbs_command_page_v1 {
    uint32_t abi_version;
    uint16_t call_id;
    uint16_t flags;
    uint32_t input_length;
    uint32_t output_length_max;
    uint64_t caller_sequence;
    uint64_t caller_nonce;
    uint32_t command_state;
    uint32_t actual_output_length;
    uint64_t output_page_gpa;
    uint64_t reserved0;
    uint8_t body[4040];
};
#define FBVBS_COMMAND_PAGE_V1_SIZE 4096

struct fbvbs_bootstrap_page_v1 {
    uint32_t abi_version;
    uint32_t vcpu_count;
    uint64_t command_page_gpa[252];
};
#define FBVBS_BOOTSTRAP_PAGE_V1_SIZE 2024

#endif /* FBVBS_ABI_V1_H */
