#ifndef FBVBS_HYPERVISOR_ABI_H
#define FBVBS_HYPERVISOR_ABI_H

#include <stddef.h>
#include <stdint.h>

/* Error codes — Appendix L.12 (positive integers) */
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

#define FBVBS_ABI_VERSION 1U

#define FBVBS_LOG_RECORD_V1_SIZE 272U

/* Command state constants */
#define FBVBS_CMD_STATE_EMPTY 0U
#define FBVBS_CMD_STATE_READY 1U
#define FBVBS_CMD_STATE_EXECUTING 2U
#define FBVBS_CMD_STATE_COMPLETED 3U
#define FBVBS_CMD_STATE_FAILED 4U

#define EMPTY 0U
#define READY 1U
#define EXECUTING 2U
#define COMPLETED 3U
#define FAILED 4U

/* Command flags */
#define FBVBS_CMD_FLAG_SEPARATE_OUTPUT 0x0001U

/* Command page — Appendix D (fills one 4096-byte page) */
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

/* Bootstrap page — Appendix D.4 */
struct fbvbs_bootstrap_page_v1 {
    uint32_t abi_version;
    uint32_t vcpu_count;
    uint64_t command_page_gpa[252];
};

struct fbvbs_log_ring_header_v1 {
    uint32_t abi_version;
    uint32_t record_size;
    uint32_t total_size;
    uint32_t write_offset;
    uint64_t max_readable_sequence;
    uint64_t boot_id_hi;
    uint64_t boot_id_lo;
};

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

#define FBVBS_PAGE_SIZE 4096U
#define FBVBS_MAX_PHYSICAL_ADDRESS (UINT64_C(0xFFFFFFFFFFFFF))  /* 52-bit x86_64 physical address limit */
#define FBVBS_MAX_PARTITIONS 16U
#define FBVBS_MAX_VCPUS 4U
#define FBVBS_MAX_MEMORY_OBJECTS 32U
#define FBVBS_MAX_MEMORY_MAPPINGS 64U
#define FBVBS_MAX_SHARED_OBJECTS 32U
#define FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES 20U
#define FBVBS_MAX_DEVICE_CATALOG_ENTRIES 8U
#define FBVBS_MAX_ASSIGNED_DEVICES 8U
#define FBVBS_LOG_SLOT_COUNT 32U
#define FBVBS_MAX_COMMAND_TRACKERS 64U

/* Partition states — L.1.B */
#define FBVBS_PARTITION_STATE_CREATED 1U
#define FBVBS_PARTITION_STATE_MEASURED 2U
#define FBVBS_PARTITION_STATE_LOADED 3U
#define FBVBS_PARTITION_STATE_RUNNABLE 4U
#define FBVBS_PARTITION_STATE_RUNNING 5U
#define FBVBS_PARTITION_STATE_QUIESCED 6U
#define FBVBS_PARTITION_STATE_FAULTED 7U
#define FBVBS_PARTITION_STATE_DESTROYED 8U

/* vCPU states — L.1.B */
#define FBVBS_VCPU_STATE_CREATED 1U
#define FBVBS_VCPU_STATE_RUNNABLE 2U
#define FBVBS_VCPU_STATE_RUNNING 3U
#define FBVBS_VCPU_STATE_BLOCKED 4U
#define FBVBS_VCPU_STATE_FAULTED 5U
#define FBVBS_VCPU_STATE_DESTROYED 6U

/* Partition kinds — L.1.B */
#define PARTITION_KIND_TRUSTED_SERVICE 1U
#define PARTITION_KIND_FREEBSD_HOST 2U
#define PARTITION_KIND_GUEST_VM 3U

/* Service kinds — L.1.B (no VMM) */
#define SERVICE_KIND_NONE 0U
#define SERVICE_KIND_KCI 1U
#define SERVICE_KIND_KSI 2U
#define SERVICE_KIND_IKS 3U
#define SERVICE_KIND_SKS 4U
#define SERVICE_KIND_UVS 5U

/* Host callsite addresses */
#define FBVBS_HOST_CALLSITE_FBVBS_PRIMARY 0xFFFF800000001000ULL
#define FBVBS_HOST_CALLSITE_FBVBS_SECONDARY 0xFFFF800000001100ULL
#define FBVBS_HOST_CALLSITE_VMM_PRIMARY 0xFFFF800000002000ULL
#define FBVBS_HOST_CALLSITE_VMM_SECONDARY 0xFFFF800000002100ULL
#define FBVBS_HOST_CALLER_CLASS_NONE 0U
#define FBVBS_HOST_CALLER_CLASS_FBVBS 1U
#define FBVBS_HOST_CALLER_CLASS_VMM 2U

/* Source components — L.1.B */
#define FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR 1U
#define FBVBS_SOURCE_COMPONENT_KCI 2U
#define FBVBS_SOURCE_COMPONENT_KSI 3U
#define FBVBS_SOURCE_COMPONENT_IKS 4U
#define FBVBS_SOURCE_COMPONENT_SKS 5U
#define FBVBS_SOURCE_COMPONENT_UVS 6U
#define FBVBS_SOURCE_COMPONENT_FBVBS_FRONTEND 7U
#define FBVBS_SOURCE_COMPONENT_VMM_PATH 8U

/* Event codes — L.1.B
 * System events (0x01-0x7F) and security events (0x80-0xFF) must be
 * globally unique to prevent audit log misclassification attacks. */
#define FBVBS_EVENT_BOOT_COMPLETE 0x01U
#define FBVBS_EVENT_PARTITION_FAULT 0x02U
#define FBVBS_EVENT_VM_PLATFORM_GATE 0x03U
#define FBVBS_EVENT_VM_DEVICE_ASSIGN 0x04U
#define FBVBS_EVENT_VM_DEVICE_RELEASE 0x05U
#define FBVBS_EVENT_IOMMU_DOMAIN_CREATE 0x06U
#define FBVBS_EVENT_IOMMU_DOMAIN_RELEASE 0x07U
#define FBVBS_EVENT_SERVICE_RESTART 0x08U
/* Security events — globally unique, separated from system events */
#define FBVBS_EVENT_POLICY_DENY 0x80U
#define FBVBS_EVENT_SIGNATURE_REJECT 0x81U
#define FBVBS_EVENT_ROLLBACK_DETECT 0x82U
#define FBVBS_EVENT_DMA_DENY 0x83U
#define FBVBS_EVENT_VM_EXIT_FAIL_CLOSED 0x84U

/* Severity levels — L.1.B */
#define FBVBS_SEVERITY_DEBUG 0U
#define FBVBS_SEVERITY_INFO 1U
#define FBVBS_SEVERITY_NOTICE 2U
#define FBVBS_SEVERITY_WARNING 3U
#define FBVBS_SEVERITY_ERROR 4U
#define FBVBS_SEVERITY_CRITICAL 5U
#define FBVBS_SEVERITY_ALERT 6U

/* Platform capability bits */
#define FBVBS_PLATFORM_CAP_HLAT 1U
#define FBVBS_PLATFORM_CAP_IOMMU 2U
#define CAP_BITMAP0_MBEC_OR_GMET (1ULL << 0)
#define CAP_BITMAP0_HLAT (1ULL << 1)
#define CAP_BITMAP0_CET (1ULL << 2)
#define CAP_BITMAP0_AESNI (1ULL << 3)
#define CAP_BITMAP1_IOMMU (1ULL << 0)

/* Capability mask bits — L.1.B */
#define FBVBS_CAP_PARTITION_MANAGE (1ULL << 0)
#define FBVBS_CAP_MEMORY_MAP (1ULL << 1)
#define FBVBS_CAP_MEMORY_PERMISSION_SET (1ULL << 2)
#define FBVBS_CAP_SHARED_MEMORY_REGISTER (1ULL << 3)
#define FBVBS_CAP_KCI_ACCESS (1ULL << 4)
#define FBVBS_CAP_KSI_ACCESS (1ULL << 5)
#define FBVBS_CAP_IKS_ACCESS (1ULL << 6)
#define FBVBS_CAP_SKS_ACCESS (1ULL << 7)
#define FBVBS_CAP_UVS_ACCESS (1ULL << 8)
#define FBVBS_CAP_VM_MANAGE (1ULL << 9)
#define FBVBS_CAP_AUDIT_DIAG (1ULL << 10)

/* Default capability mask for the FreeBSD host partition.
   All capabilities except MEMORY_PERMISSION_SET (trusted services only). */
#define FBVBS_HOST_DEFAULT_CAPABILITY_MASK ( \
    FBVBS_CAP_PARTITION_MANAGE | FBVBS_CAP_MEMORY_MAP | \
    FBVBS_CAP_SHARED_MEMORY_REGISTER | FBVBS_CAP_KCI_ACCESS | \
    FBVBS_CAP_KSI_ACCESS | FBVBS_CAP_IKS_ACCESS | \
    FBVBS_CAP_SKS_ACCESS | FBVBS_CAP_UVS_ACCESS | \
    FBVBS_CAP_VM_MANAGE | FBVBS_CAP_AUDIT_DIAG)

/* UVS failure bitmap bits — L.1.B */
#define FBVBS_UVS_FAILURE_SIGNATURE 0x01U
#define FBVBS_UVS_FAILURE_REVOCATION 0x02U
#define FBVBS_UVS_FAILURE_GENERATION 0x04U
#define FBVBS_UVS_FAILURE_ROLLBACK 0x08U
#define FBVBS_UVS_FAILURE_DEPENDENCY 0x10U
#define FBVBS_UVS_FAILURE_SNAPSHOT 0x20U
#define FBVBS_UVS_FAILURE_FRESHNESS 0x40U

/* KSI credential operation classes — L.1.B */
#define FBVBS_KSI_OPERATION_EXEC_ELEVATION 1U
#define FBVBS_KSI_OPERATION_SETUID_FAMILY 2U
#define FBVBS_KSI_OPERATION_SETGID_FAMILY 3U
#define FBVBS_KSI_VALID_RUID 0x01U
#define FBVBS_KSI_VALID_EUID 0x02U
#define FBVBS_KSI_VALID_SUID 0x04U
#define FBVBS_KSI_VALID_RGID 0x08U
#define FBVBS_KSI_VALID_EGID 0x10U
#define FBVBS_KSI_VALID_SGID 0x20U

/* KSI protection classes — L.1.B */
#define KSI_CLASS_UCRED 1U
#define KSI_CLASS_PRISON 2U
#define KSI_CLASS_SECURELEVEL 3U
#define KSI_CLASS_MAC 4U
#define KSI_CLASS_CAPSICUM 5U
#define KSI_CLASS_FIREWALL 6U
#define KSI_CLASS_P_TEXTVP 7U

/* IKS key types — L.1.B */
#define IKS_KEY_ED25519 1U
#define IKS_KEY_ECDSA_P256 2U
#define IKS_KEY_RSA3072 3U
#define IKS_KEY_X25519 4U
#define IKS_KEY_ECDH_P256 5U

/* IKS allowed operations — L.1.B */
#define IKS_OP_SIGN 0x0001U
#define IKS_OP_KEY_EXCHANGE 0x0002U
#define IKS_OP_DERIVE 0x0004U

/* CR numbers — L.1.B */
#define CR_NUMBER_CR0 0U
#define CR_NUMBER_CR3 3U
#define CR_NUMBER_CR4 4U

/* UVS object types — L.1.B */
#define UVS_OBJECT_KEY 1U
#define UVS_OBJECT_ARTIFACT 2U

/* Memory object flags — L.1.B */
#define FBVBS_MEMORY_OBJECT_FLAG_PRIVATE 0x0000U
#define FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE 0x0001U
#define FBVBS_MEMORY_OBJECT_FLAG_GUEST_MEMORY 0x0002U

/* Memory permissions — L.1.B */
#define FBVBS_MEMORY_PERMISSION_READ 0x0001U
#define FBVBS_MEMORY_PERMISSION_WRITE 0x0002U
#define FBVBS_MEMORY_PERMISSION_EXECUTE 0x0004U

/* VM flags — L.1.B */
#define VM_FLAG_X2APIC 0x0001U
#define VM_FLAG_NESTED_VIRT_DISABLED 0x0002U
#define VM_RUN_FLAG_NONE 0x0000U

/* VM register IDs — L.1.B */
#define VM_REG_RIP 1U
#define VM_REG_RSP 2U
#define VM_REG_RFLAGS 3U
#define VM_REG_CR0 4U
#define VM_REG_CR3 5U
#define VM_REG_CR4 6U

/* Interrupt delivery modes */
#define FBVBS_VM_DELIVERY_FIXED 1U
#define FBVBS_VM_DELIVERY_NMI 2U

/* VM exit reasons — L.1.B */
#define FBVBS_VM_EXIT_REASON_PIO 1U
#define FBVBS_VM_EXIT_REASON_MMIO 2U
#define FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT 3U
#define FBVBS_VM_EXIT_REASON_EPT_VIOLATION 4U
#define FBVBS_VM_EXIT_REASON_CR_ACCESS 5U
#define FBVBS_VM_EXIT_REASON_MSR_ACCESS 6U
#define FBVBS_VM_EXIT_REASON_HALT 7U
#define FBVBS_VM_EXIT_REASON_SHUTDOWN 8U
#define FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT 9U

/* VM exit access types */
#define FBVBS_VM_CR_ACCESS_READ 1U
#define FBVBS_VM_CR_ACCESS_WRITE 2U
#define FBVBS_VM_MSR_ACCESS_WRITE 1U
#define FBVBS_VM_EPT_ACCESS_READ 0x1U
#define FBVBS_VM_EPT_ACCESS_WRITE 0x2U
#define FBVBS_VM_EPT_ACCESS_EXECUTE 0x4U

/* Fault codes — L.1.B */
#define FAULT_CODE_PARTITION_INTERNAL 1U
#define FAULT_CODE_MEASUREMENT_FAILURE 2U
#define FAULT_CODE_VM_EXIT_UNCLASSIFIED 3U

/* Artifact object kinds */
#define FBVBS_ARTIFACT_OBJECT_IMAGE 1U
#define FBVBS_ARTIFACT_OBJECT_MANIFEST 2U
#define FBVBS_ARTIFACT_OBJECT_MODULE 3U

/* Verdict values — L.1.B */
#define FBVBS_VERDICT_DENIED 0U
#define FBVBS_VERDICT_APPROVED 1U

/* Boolean values — L.1.B */
#define FBVBS_FALSE 0U
#define FBVBS_TRUE 1U

/* Partition flags — L.1.B */
#define PARTITION_FLAG_AUTOSTART 0x0001U

/* Recovery flags — L.1.B */
#define FBVBS_RECOVERY_RESTORE_PERSISTENT (1ULL << 0)
#define FBVBS_RECOVERY_CLEAR_VOLATILE (1ULL << 1)
#define FBVBS_RECOVERY_EXTENDED_REMEASURE (1ULL << 2)

/* Manifest component types */
#define FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE 1U
#define FBVBS_MANIFEST_COMPONENT_GUEST_BOOT 2U
#define FBVBS_MANIFEST_COMPONENT_FREEBSD_KERNEL 3U
#define FBVBS_MANIFEST_COMPONENT_FREEBSD_MODULE 4U

/* Call ID space — L.2 through L.11 */

/* Partition management (0x0xxx) — L.3 */
#define FBVBS_CALL_PARTITION_CREATE         0x0001U
#define FBVBS_CALL_PARTITION_DESTROY        0x0002U
#define FBVBS_CALL_PARTITION_GET_STATUS     0x0003U
#define FBVBS_CALL_PARTITION_QUIESCE        0x0004U
#define FBVBS_CALL_PARTITION_RESUME         0x0005U
#define FBVBS_CALL_PARTITION_MEASURE        0x0006U
#define FBVBS_CALL_PARTITION_LOAD_IMAGE     0x0007U
#define FBVBS_CALL_PARTITION_START          0x0008U
#define FBVBS_CALL_PARTITION_RECOVER        0x0009U
#define FBVBS_CALL_PARTITION_GET_FAULT_INFO 0x000AU

/* Memory management (0x1xxx) — L.4 */
#define FBVBS_CALL_MEMORY_ALLOCATE_OBJECT   0x1000U
#define FBVBS_CALL_MEMORY_MAP               0x1001U
#define FBVBS_CALL_MEMORY_UNMAP             0x1002U
#define FBVBS_CALL_MEMORY_SET_PERMISSION    0x1003U
#define FBVBS_CALL_MEMORY_REGISTER_SHARED   0x1004U
#define FBVBS_CALL_MEMORY_RELEASE_OBJECT    0x1005U
#define FBVBS_CALL_MEMORY_UNREGISTER_SHARED 0x1006U

/* Kernel Code Integrity Service (0x2xxx) — L.5 */
#define FBVBS_CALL_KCI_VERIFY_MODULE        0x2001U
#define FBVBS_CALL_KCI_SET_WX               0x2002U
#define FBVBS_CALL_KCI_PIN_CR               0x2003U
#define FBVBS_CALL_KCI_INTERCEPT_MSR        0x2004U

/* Kernel State Integrity Service (0x3xxx) — L.6 */
#define FBVBS_CALL_KSI_CREATE_TARGET_SET    0x3000U
#define FBVBS_CALL_KSI_REGISTER_TIER_A      0x3001U
#define FBVBS_CALL_KSI_REGISTER_TIER_B      0x3002U
#define FBVBS_CALL_KSI_MODIFY_TIER_B        0x3003U
#define FBVBS_CALL_KSI_REGISTER_POINTER     0x3004U
#define FBVBS_CALL_KSI_VALIDATE_SETUID      0x3005U
#define FBVBS_CALL_KSI_ALLOCATE_UCRED       0x3006U
#define FBVBS_CALL_KSI_REPLACE_TIER_B_OBJECT 0x3007U
#define FBVBS_CALL_KSI_UNREGISTER_OBJECT    0x3008U

/* Identity Key Service (0x4xxx) — L.7 */
#define FBVBS_CALL_IKS_IMPORT_KEY           0x4001U
#define FBVBS_CALL_IKS_SIGN                 0x4002U
#define FBVBS_CALL_IKS_KEY_EXCHANGE         0x4003U
#define FBVBS_CALL_IKS_DERIVE               0x4004U
#define FBVBS_CALL_IKS_DESTROY_KEY          0x4005U

/* Storage Key Service (0x5xxx) — L.8 */
#define FBVBS_CALL_SKS_IMPORT_DEK           0x5001U
#define FBVBS_CALL_SKS_DECRYPT_BATCH        0x5002U
#define FBVBS_CALL_SKS_ENCRYPT_BATCH        0x5003U
#define FBVBS_CALL_SKS_DESTROY_DEK          0x5004U

/* Update Verification Service (0x6xxx) — L.9 */
#define FBVBS_CALL_UVS_VERIFY_MANIFEST_SET  0x6001U
#define FBVBS_CALL_UVS_VERIFY_ARTIFACT      0x6002U
#define FBVBS_CALL_UVS_CHECK_REVOCATION     0x6003U

/* bhyve VM management (0x7xxx) — L.10 */
#define FBVBS_CALL_VM_CREATE                0x7001U
#define FBVBS_CALL_VM_DESTROY               0x7002U
#define FBVBS_CALL_VM_RUN                   0x7003U
#define FBVBS_CALL_VM_SET_REGISTER          0x7004U
#define FBVBS_CALL_VM_GET_REGISTER          0x7005U
#define FBVBS_CALL_VM_MAP_MEMORY            0x7006U
#define FBVBS_CALL_VM_INJECT_INTERRUPT      0x7007U
#define FBVBS_CALL_VM_ASSIGN_DEVICE         0x7008U
#define FBVBS_CALL_VM_RELEASE_DEVICE        0x7009U
#define FBVBS_CALL_VM_GET_VCPU_STATUS       0x700AU

/* Audit and diagnostics (0x8xxx) — L.11 */
#define FBVBS_CALL_AUDIT_GET_MIRROR_INFO    0x8001U
#define FBVBS_CALL_AUDIT_GET_BOOT_ID        0x8002U
#define FBVBS_CALL_DIAG_GET_PARTITION_LIST  0x8003U
#define FBVBS_CALL_DIAG_GET_CAPABILITIES    0x8004U
#define FBVBS_CALL_DIAG_GET_ARTIFACT_LIST   0x8005U
#define FBVBS_CALL_DIAG_GET_DEVICE_LIST     0x8006U

/* Request/response structs — L.3 Partition management */

struct fbvbs_partition_create_request {
    uint16_t kind;
    uint16_t flags;
    uint32_t vcpu_count;
    uint64_t memory_limit_bytes;
    uint64_t capability_mask;
    uint64_t image_object_id;
};

struct fbvbs_partition_create_response {
    uint64_t partition_id;
};

struct fbvbs_partition_id_request {
    uint64_t partition_id;
};

struct fbvbs_partition_status_response {
    uint32_t state;
    uint32_t reserved0;
    uint64_t measurement_epoch;
};

struct fbvbs_partition_measure_request {
    uint64_t partition_id;
    uint64_t image_object_id;
    uint64_t manifest_object_id;
};

struct fbvbs_partition_measure_response {
    uint64_t measurement_digest_id;
};

struct fbvbs_partition_load_image_request {
    uint64_t partition_id;
    uint64_t image_object_id;
    uint64_t entry_ip;
    uint64_t initial_sp;
};

struct fbvbs_partition_recover_request {
    uint64_t partition_id;
    uint64_t recovery_flags;
};

struct fbvbs_partition_fault_info_response {
    uint32_t fault_code;
    uint32_t source_component;
    uint64_t fault_detail0;
    uint64_t fault_detail1;
};

/* Request/response structs — L.4 Memory management */

struct fbvbs_memory_allocate_object_request {
    uint64_t size;
    uint32_t object_flags;
    uint32_t reserved0;
};

struct fbvbs_memory_allocate_object_response {
    uint64_t memory_object_id;
};

struct fbvbs_memory_map_request {
    uint64_t partition_id;
    uint64_t memory_object_id;
    uint64_t guest_physical_address;
    uint64_t size;
    uint32_t permissions;
    uint32_t reserved0;
};

struct fbvbs_memory_unmap_request {
    uint64_t partition_id;
    uint64_t guest_physical_address;
    uint64_t size;
};

struct fbvbs_memory_set_permission_request {
    uint64_t target_partition_id;
    uint64_t guest_physical_address;
    uint64_t size;
    uint32_t permissions;
    uint32_t reserved0;
};

struct fbvbs_memory_register_shared_request {
    uint64_t memory_object_id;
    uint64_t size;
    uint64_t peer_partition_id;
    uint32_t peer_permissions;
    uint32_t reserved0;
};

struct fbvbs_memory_register_shared_response {
    uint64_t shared_object_id;
};

struct fbvbs_memory_object_id_request {
    uint64_t memory_object_id;
};

struct fbvbs_shared_object_id_request {
    uint64_t shared_object_id;
};

/* Request/response structs — L.5 KCI */

struct fbvbs_kci_verify_module_request {
    uint64_t module_object_id;
    uint64_t manifest_object_id;
    uint64_t generation;
};

struct fbvbs_verdict_response {
    uint32_t verdict;
    uint32_t reserved0;
};

struct fbvbs_kci_set_wx_request {
    uint64_t module_object_id;
    uint64_t guest_physical_address;
    uint64_t file_offset;
    uint64_t size;
    uint32_t permissions;
    uint32_t reserved0;
};

struct fbvbs_kci_pin_cr_request {
    uint32_t cr_number;
    uint32_t reserved0;
    uint64_t pin_mask;
};

struct fbvbs_kci_intercept_msr_request {
    uint32_t msr_address;
    uint32_t enable;
};

/* Request/response structs — L.6 KSI */

struct fbvbs_ksi_create_target_set_request {
    uint32_t target_count;
    uint32_t reserved0;
    uint64_t target_object_ids[502];
};

struct fbvbs_ksi_target_set_response {
    uint64_t target_set_id;
};

struct fbvbs_ksi_register_tier_a_request {
    uint64_t object_id;
    uint64_t guest_physical_address;
    uint64_t size;
};

struct fbvbs_ksi_register_tier_b_request {
    uint64_t object_id;
    uint64_t guest_physical_address;
    uint64_t size;
    uint32_t protection_class;
    uint32_t reserved0;
};

struct fbvbs_ksi_modify_tier_b_request {
    uint64_t object_id;
    uint32_t patch_length;
    uint32_t reserved0;
    uint8_t patch[4008];
};

struct fbvbs_ksi_register_pointer_request {
    uint64_t pointer_object_id;
    uint64_t target_set_id;
};

struct fbvbs_ksi_validate_setuid_request {
    uint64_t fsid;
    uint64_t fileid;
    uint8_t measured_hash[64];
    uint32_t operation_class;
    uint32_t valid_mask;
    uint32_t requested_ruid;
    uint32_t requested_euid;
    uint32_t requested_suid;
    uint32_t requested_rgid;
    uint32_t requested_egid;
    uint32_t requested_sgid;
    uint64_t caller_ucred_object_id;
    uint64_t jail_context_id;
    uint64_t mac_context_id;
};

struct fbvbs_ksi_allocate_ucred_request {
    uint32_t uid;
    uint32_t gid;
    uint64_t prison_object_id;
    uint64_t template_ucred_object_id;
};

struct fbvbs_ksi_allocate_ucred_response {
    uint64_t ucred_object_id;
};

struct fbvbs_ksi_replace_tier_b_object_request {
    uint64_t old_object_id;
    uint64_t new_object_id;
    uint64_t pointer_object_id;
    uint32_t replace_flags;
    uint32_t reserved0;
};

/* Request/response structs — L.7 IKS */

struct fbvbs_iks_import_key_request {
    uint64_t key_material_page_gpa;
    uint32_t key_type;
    uint32_t allowed_ops;
    uint32_t key_length;
    uint32_t reserved0;
};

struct fbvbs_handle_response {
    uint64_t handle;
};

struct fbvbs_iks_sign_request {
    uint64_t key_handle;
    uint32_t hash_length;
    uint32_t reserved0;
    uint8_t hash[64];
};

struct fbvbs_iks_sign_response {
    uint32_t signature_length;
    uint32_t reserved0;
    uint8_t signature[4000];
};

struct fbvbs_iks_key_exchange_request {
    uint64_t key_handle;
    uint32_t peer_public_key_length;
    uint32_t derive_flags;
    uint8_t peer_public_key[3992];
};

struct fbvbs_iks_derive_request {
    uint64_t key_handle;
    uint32_t parameter_length;
    uint32_t reserved0;
    uint8_t params[3992];
};

/* Request/response structs — L.8 SKS */

struct fbvbs_sks_import_dek_request {
    uint64_t key_material_page_gpa;
    uint64_t volume_id;
    uint32_t key_length;
    uint32_t reserved0;
};

struct fbvbs_sks_batch_request {
    uint64_t dek_handle;
    uint64_t io_descriptor_page_gpa;
    uint32_t descriptor_count;
    uint32_t reserved0;
};

struct fbvbs_sks_batch_response {
    uint32_t completed_count;
    uint32_t reserved0;
};

/* Request/response structs — L.9 UVS */

struct fbvbs_uvs_verify_manifest_set_request {
    uint64_t root_manifest_gpa;
    uint32_t root_manifest_length;
    uint32_t manifest_count;
    uint64_t manifest_set_page_gpa;
};

struct fbvbs_uvs_verify_manifest_set_response {
    uint32_t verdict;
    uint32_t failure_bitmap;
    uint64_t verified_manifest_set_id;
};

struct fbvbs_uvs_verify_artifact_request {
    uint8_t artifact_hash[64];
    uint64_t verified_manifest_set_id;
    uint64_t manifest_object_id;
};

struct fbvbs_uvs_check_revocation_request {
    uint64_t object_id;
    uint32_t object_type;
    uint32_t reserved0;
};

struct fbvbs_uvs_check_revocation_response {
    uint32_t revoked;
    uint32_t reserved0;
};

/* Request/response structs — L.10 VM management */

struct fbvbs_vm_create_request {
    uint64_t memory_limit_bytes;
    uint32_t vcpu_count;
    uint32_t vm_flags;
};

struct fbvbs_vm_create_response {
    uint64_t vm_partition_id;
};

struct fbvbs_vm_vcpu_status_request {
    uint64_t vm_partition_id;
    uint32_t vcpu_id;
    uint32_t reserved0;
};

struct fbvbs_vm_vcpu_status_response {
    uint32_t vcpu_state;
    uint32_t reserved0;
};

struct fbvbs_vm_register_request {
    uint64_t vm_partition_id;
    uint32_t vcpu_id;
    uint32_t register_id;
    uint64_t value;
};

struct fbvbs_vm_register_read_request {
    uint64_t vm_partition_id;
    uint32_t vcpu_id;
    uint32_t register_id;
};

struct fbvbs_vm_register_response {
    uint64_t value;
};

struct fbvbs_vm_run_request {
    uint64_t vm_partition_id;
    uint32_t vcpu_id;
    uint32_t run_flags;
};

struct fbvbs_vm_run_response {
    uint32_t exit_reason;
    uint32_t exit_length;
    uint8_t exit_payload[4032];
};

struct fbvbs_vm_map_memory_request {
    uint64_t vm_partition_id;
    uint64_t memory_object_id;
    uint64_t guest_physical_address;
    uint64_t size;
    uint32_t permissions;
    uint32_t reserved0;
};

struct fbvbs_vm_inject_interrupt_request {
    uint64_t vm_partition_id;
    uint32_t vcpu_id;
    uint32_t vector;
    uint32_t delivery_mode;
    uint32_t reserved0;
};

struct fbvbs_vm_device_request {
    uint64_t vm_partition_id;
    uint64_t device_id;
};

/* VM exit payload structs — L.1.F */

struct fbvbs_vm_exit_external_interrupt {
    uint32_t vector;
    uint32_t reserved0;
};

struct fbvbs_vm_exit_pio {
    uint16_t port;
    uint8_t width;
    uint8_t is_write;
    uint32_t count;
    uint64_t value;
};

struct fbvbs_vm_exit_mmio {
    uint64_t guest_physical_address;
    uint8_t width;
    uint8_t is_write;
    uint16_t reserved0;
    uint32_t reserved1;
    uint64_t value;
};

struct fbvbs_vm_exit_cr_access {
    uint32_t cr_number;
    uint32_t access_type;
    uint64_t value;
};

struct fbvbs_vm_exit_msr_access {
    uint32_t msr;
    uint32_t is_write;
    uint64_t value;
};

struct fbvbs_vm_exit_ept_violation {
    uint64_t guest_physical_address;
    uint32_t access_bits;
    uint32_t reserved0;
};

struct fbvbs_vm_exit_unclassified_fault {
    uint32_t fault_code;
    uint32_t reserved0;
    uint64_t detail0;
    uint64_t detail1;
};

/* Audit event structs */

struct fbvbs_audit_partition_fault_event {
    uint64_t partition_id;
    uint32_t fault_code;
    uint32_t source_component;
    uint64_t detail0;
    uint64_t detail1;
};

struct fbvbs_audit_platform_gate_event {
    uint64_t partition_id;
    uint64_t device_id;
    uint32_t required_capability;
    uint32_t status;
};

struct fbvbs_audit_device_assignment_event {
    uint64_t partition_id;
    uint64_t device_id;
    uint64_t iommu_domain_id;
    uint32_t attached_device_count;
    uint32_t reserved0;
};

/* Audit/diag response structs — L.11 */

struct fbvbs_audit_mirror_info_response {
    uint64_t ring_gpa;
    uint32_t ring_size;
    uint32_t record_size;
};

struct fbvbs_audit_boot_id_response {
    uint64_t boot_id_hi;
    uint64_t boot_id_lo;
};

struct fbvbs_diag_capabilities_response {
    uint64_t capability_bitmap0;
    uint64_t capability_bitmap1;
};

struct fbvbs_diag_partition_entry {
    uint64_t partition_id;
    uint32_t state;
    uint16_t kind;
    uint16_t service_kind;
};

struct fbvbs_diag_partition_list_response {
    uint32_t count;
    uint32_t reserved0;
    uint8_t entries[4032];
};

struct fbvbs_artifact_catalog_entry {
    uint64_t object_id;
    uint32_t object_kind;
    uint32_t related_index;
    uint8_t payload_hash[48];
};

struct fbvbs_diag_artifact_list_response {
    uint32_t count;
    uint32_t reserved0;
    uint8_t entries[4032];
};

struct fbvbs_device_catalog_entry {
    uint64_t device_id;
    uint16_t segment;
    uint8_t bus;
    uint8_t slot_function;
};

struct fbvbs_diag_device_list_response {
    uint32_t count;
    uint32_t reserved0;
    uint8_t entries[4032];
};

/* Compile-time layout checks */
_Static_assert(sizeof(struct fbvbs_log_record_v1) == FBVBS_LOG_RECORD_V1_SIZE, "log record must be exactly FBVBS_LOG_RECORD_V1_SIZE bytes");
_Static_assert(sizeof(struct fbvbs_log_record_v1) % 8 == 0, "log record must be 8-byte aligned for atomic operations");

_Static_assert(sizeof(struct fbvbs_command_page_v1) == 4096, "command page must fill one 4096-byte page");
_Static_assert(offsetof(struct fbvbs_command_page_v1, call_id) == 4, "call_id offset");
_Static_assert(offsetof(struct fbvbs_command_page_v1, body) == 56, "body offset");

_Static_assert(sizeof(struct fbvbs_bootstrap_page_v1) == 2024, "bootstrap page size");
_Static_assert(offsetof(struct fbvbs_bootstrap_page_v1, command_page_gpa) == 8, "bootstrap command_page_gpa offset");

_Static_assert(sizeof(struct fbvbs_partition_create_request) == 32, "fbvbs_partition_create_request size mismatch");
_Static_assert(offsetof(struct fbvbs_partition_create_request, memory_limit_bytes) == 8, "fbvbs_partition_create_request layout mismatch");

_Static_assert(sizeof(struct fbvbs_partition_create_response) == 8, "fbvbs_partition_create_response size mismatch");

_Static_assert(sizeof(struct fbvbs_vm_run_response) == 4040, "fbvbs_vm_run_response size mismatch");
_Static_assert(offsetof(struct fbvbs_vm_run_response, exit_payload) == 8, "fbvbs_vm_run_response exit_payload offset mismatch");

_Static_assert(sizeof(struct fbvbs_vm_exit_pio) == 16, "fbvbs_vm_exit_pio size mismatch");
_Static_assert(sizeof(struct fbvbs_vm_exit_mmio) == 24, "fbvbs_vm_exit_mmio size mismatch");
_Static_assert(sizeof(struct fbvbs_vm_exit_msr_access) == 16, "fbvbs_vm_exit_msr_access size mismatch");
_Static_assert(sizeof(struct fbvbs_vm_exit_ept_violation) == 16, "fbvbs_vm_exit_ept_violation size mismatch");

_Static_assert(sizeof(struct fbvbs_ksi_modify_tier_b_request) == 4024, "fbvbs_ksi_modify_tier_b_request size mismatch");
_Static_assert(offsetof(struct fbvbs_ksi_modify_tier_b_request, patch) == 16, "fbvbs_ksi_modify_tier_b_request patch offset mismatch");

_Static_assert(sizeof(struct fbvbs_iks_sign_response) == 4008, "fbvbs_iks_sign_response size mismatch");
_Static_assert(offsetof(struct fbvbs_iks_sign_response, signature) == 8, "fbvbs_iks_sign_response signature offset mismatch");

_Static_assert(sizeof(struct fbvbs_iks_key_exchange_request) == 4008, "fbvbs_iks_key_exchange_request size mismatch");
_Static_assert(offsetof(struct fbvbs_iks_key_exchange_request, peer_public_key) == 16, "fbvbs_iks_key_exchange_request peer_public_key offset mismatch");

_Static_assert(sizeof(struct fbvbs_iks_derive_request) == 4008, "fbvbs_iks_derive_request size mismatch");
_Static_assert(offsetof(struct fbvbs_iks_derive_request, params) == 16, "fbvbs_iks_derive_request params offset mismatch");

_Static_assert(sizeof(struct fbvbs_diag_partition_list_response) == 4040, "fbvbs_diag_partition_list_response size mismatch");
_Static_assert(offsetof(struct fbvbs_diag_partition_list_response, entries) == 8, "fbvbs_diag_partition_list_response entries offset mismatch");

_Static_assert(sizeof(struct fbvbs_diag_artifact_list_response) == 4040, "fbvbs_diag_artifact_list_response size mismatch");
_Static_assert(offsetof(struct fbvbs_diag_artifact_list_response, entries) == 8, "fbvbs_diag_artifact_list_response entries offset mismatch");

_Static_assert(sizeof(struct fbvbs_diag_device_list_response) == 4040, "fbvbs_diag_device_list_response size mismatch");
_Static_assert(offsetof(struct fbvbs_diag_device_list_response, entries) == 8, "fbvbs_diag_device_list_response entries offset mismatch");

_Static_assert(sizeof(struct fbvbs_ksi_create_target_set_request) == 4024, "fbvbs_ksi_create_target_set_request size mismatch");
_Static_assert(offsetof(struct fbvbs_ksi_create_target_set_request, target_object_ids) == 8, "fbvbs_ksi_create_target_set_request target_object_ids offset mismatch");

#endif
