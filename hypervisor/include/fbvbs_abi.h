#ifndef FBVBS_HYPERVISOR_ABI_H
#define FBVBS_HYPERVISOR_ABI_H

#include <stdint.h>

#include "../../generated/bindings/fbvbs_abi_v1.h"

#define FBVBS_ABI_VERSION 1U
#define FBVBS_PAGE_SIZE 4096U
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

#define FBVBS_PARTITION_STATE_CREATED 1U
#define FBVBS_PARTITION_STATE_MEASURED 2U
#define FBVBS_PARTITION_STATE_LOADED 3U
#define FBVBS_PARTITION_STATE_RUNNABLE 4U
#define FBVBS_PARTITION_STATE_RUNNING 5U
#define FBVBS_PARTITION_STATE_QUIESCED 6U
#define FBVBS_PARTITION_STATE_FAULTED 7U
#define FBVBS_PARTITION_STATE_DESTROYED 8U

#define FBVBS_VCPU_STATE_CREATED 1U
#define FBVBS_VCPU_STATE_RUNNABLE 2U
#define FBVBS_VCPU_STATE_RUNNING 3U
#define FBVBS_VCPU_STATE_BLOCKED 4U
#define FBVBS_VCPU_STATE_FAULTED 5U
#define FBVBS_VCPU_STATE_DESTROYED 6U

#define FBVBS_HOST_CALLSITE_FBVBS_PRIMARY 0xFFFF800000001000ULL
#define FBVBS_HOST_CALLSITE_FBVBS_SECONDARY 0xFFFF800000001100ULL
#define FBVBS_HOST_CALLSITE_VMM_PRIMARY 0xFFFF800000002000ULL
#define FBVBS_HOST_CALLSITE_VMM_SECONDARY 0xFFFF800000002100ULL
#define FBVBS_HOST_CALLER_CLASS_NONE 0U
#define FBVBS_HOST_CALLER_CLASS_FBVBS 1U
#define FBVBS_HOST_CALLER_CLASS_VMM 2U

#define FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR 1U
#define FBVBS_EVENT_BOOT_COMPLETE 1U
#define FBVBS_EVENT_PARTITION_FAULT 2U
#define FBVBS_EVENT_VM_PLATFORM_GATE 3U
#define FBVBS_EVENT_VM_DEVICE_ASSIGN 4U
#define FBVBS_EVENT_VM_DEVICE_RELEASE 5U
#define FBVBS_EVENT_IOMMU_DOMAIN_CREATE 6U
#define FBVBS_EVENT_IOMMU_DOMAIN_RELEASE 7U

#define FBVBS_PLATFORM_CAP_HLAT 1U
#define FBVBS_PLATFORM_CAP_IOMMU 2U
#define CAP_BITMAP1_IOMMU (1ULL << 0)

#define FBVBS_UVS_FAILURE_SIGNATURE 0x01U
#define FBVBS_UVS_FAILURE_REVOCATION 0x02U
#define FBVBS_UVS_FAILURE_GENERATION 0x04U
#define FBVBS_UVS_FAILURE_ROLLBACK 0x08U
#define FBVBS_UVS_FAILURE_DEPENDENCY 0x10U
#define FBVBS_UVS_FAILURE_SNAPSHOT 0x20U
#define FBVBS_UVS_FAILURE_FRESHNESS 0x40U

#define FBVBS_KSI_OPERATION_EXEC_ELEVATION 1U
#define FBVBS_KSI_OPERATION_SETUID_FAMILY 2U
#define FBVBS_KSI_OPERATION_SETGID_FAMILY 3U
#define FBVBS_KSI_VALID_RUID 0x01U
#define FBVBS_KSI_VALID_EUID 0x02U
#define FBVBS_KSI_VALID_SUID 0x04U
#define FBVBS_KSI_VALID_RGID 0x08U
#define FBVBS_KSI_VALID_EGID 0x10U
#define FBVBS_KSI_VALID_SGID 0x20U

#define FBVBS_MEMORY_OBJECT_FLAG_PRIVATE 0x0000U
#define FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE 0x0001U
#define FBVBS_MEMORY_OBJECT_FLAG_GUEST_MEMORY 0x0002U

#define FBVBS_MEMORY_PERMISSION_READ 0x0001U
#define FBVBS_MEMORY_PERMISSION_WRITE 0x0002U
#define FBVBS_MEMORY_PERMISSION_EXECUTE 0x0004U

#define FBVBS_VM_DELIVERY_FIXED 1U
#define FBVBS_VM_DELIVERY_NMI 2U

#define FBVBS_VM_EXIT_REASON_PIO 1U
#define FBVBS_VM_EXIT_REASON_MMIO 2U
#define FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT 3U
#define FBVBS_VM_EXIT_REASON_EPT_VIOLATION 4U
#define FBVBS_VM_EXIT_REASON_CR_ACCESS 5U
#define FBVBS_VM_EXIT_REASON_MSR_ACCESS 6U
#define FBVBS_VM_EXIT_REASON_HALT 7U
#define FBVBS_VM_EXIT_REASON_SHUTDOWN 8U
#define FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT 9U

#define FBVBS_VM_CR_ACCESS_WRITE 1U
#define FBVBS_VM_MSR_ACCESS_WRITE 1U
#define FBVBS_VM_EPT_ACCESS_EXECUTE 0x4U

#define FBVBS_ARTIFACT_OBJECT_IMAGE 1U
#define FBVBS_ARTIFACT_OBJECT_MANIFEST 2U
#define FBVBS_ARTIFACT_OBJECT_MODULE 3U

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

struct fbvbs_vm_exit_external_interrupt {
    uint32_t vector;
    uint32_t reserved0;
};

struct fbvbs_vm_exit_pio {
    uint16_t port;
    uint8_t access_size;
    uint8_t is_write;
    uint32_t value;
};

struct fbvbs_vm_exit_mmio {
    uint64_t guest_physical_address;
    uint8_t access_size;
    uint8_t is_write;
    uint16_t reserved0;
    uint32_t value;
};

struct fbvbs_vm_exit_cr_access {
    uint32_t cr_number;
    uint32_t access_type;
    uint64_t value;
};

struct fbvbs_vm_exit_msr_access {
    uint32_t msr_address;
    uint32_t access_type;
    uint64_t value;
};

struct fbvbs_vm_exit_ept_violation {
    uint64_t guest_physical_address;
    uint32_t access_type;
    uint32_t reserved0;
};

struct fbvbs_vm_exit_unclassified_fault {
    uint32_t fault_code;
    uint32_t reserved0;
    uint64_t detail0;
    uint64_t detail1;
};

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

#endif
