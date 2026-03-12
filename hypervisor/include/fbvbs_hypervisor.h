#ifndef FBVBS_HYPERVISOR_H
#define FBVBS_HYPERVISOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fbvbs_abi.h"
#include "fbvbs_leaf_vmx.h"

struct fbvbs_trap_registers {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
};

#define FBVBS_MAX_HOST_CALLSITE_ENTRIES 4U
#define FBVBS_MAX_HOST_CALLSITE_TABLES 2U
#define FBVBS_MAX_MANIFEST_PROFILES 10U
#define FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE 1U
#define FBVBS_MANIFEST_COMPONENT_GUEST_BOOT 2U
#define FBVBS_MANIFEST_COMPONENT_FREEBSD_KERNEL 3U
#define FBVBS_MANIFEST_COMPONENT_FREEBSD_MODULE 4U

struct fbvbs_memory_mapping {
    bool active;
    uint8_t reserved0;
    uint16_t permissions;
    uint32_t reserved1;
    uint64_t memory_object_id;
    uint64_t guest_physical_address;
    uint64_t size;
};

struct fbvbs_aligned_command_page {
    struct fbvbs_command_page_v1 page;
} __attribute__((aligned(FBVBS_PAGE_SIZE)));

struct fbvbs_shared_registration {
    bool active;
    uint8_t reserved0;
    uint16_t peer_permissions;
    uint32_t reserved1;
    uint64_t shared_object_id;
    uint64_t memory_object_id;
    uint64_t size;
    uint64_t peer_partition_id;
};

struct fbvbs_partition {
    bool occupied;
    bool tombstone;
    uint64_t partition_id;
    uint16_t kind;
    uint16_t service_kind;
    uint32_t state;
    uint32_t vcpu_count;
    uint32_t vm_flags;
    uint32_t reserved0;
    uint64_t memory_limit_bytes;
    uint64_t capability_mask;
    uint64_t image_object_id;
    uint64_t manifest_object_id;
    uint64_t measurement_epoch;
    uint64_t measurement_digest_id;
    uint64_t mapped_bytes;
    uint64_t entry_ip;
    uint64_t initial_sp;
    uint32_t last_fault_code;
    uint32_t last_fault_source_component;
    uint64_t last_fault_detail0;
    uint64_t last_fault_detail1;
    uint32_t assigned_device_count;
    uint32_t reserved1;
    uint64_t iommu_domain_id;
    uint64_t assigned_devices[FBVBS_MAX_ASSIGNED_DEVICES];
    struct fbvbs_bootstrap_page_v1 bootstrap_page;
    struct fbvbs_aligned_command_page command_pages[FBVBS_MAX_VCPUS];
    struct fbvbs_vcpu vcpus[FBVBS_MAX_VCPUS];
    struct fbvbs_memory_mapping mappings[FBVBS_MAX_MEMORY_MAPPINGS];
};

struct fbvbs_log_storage {
    struct fbvbs_log_ring_header_v1 header;
    struct fbvbs_log_record_v1 records[FBVBS_LOG_SLOT_COUNT];
};

struct fbvbs_host_callsite_table {
    bool active;
    uint8_t caller_class;
    uint16_t count;
    uint32_t reserved0;
    uint64_t manifest_object_id;
    uint64_t load_base;
    uint64_t allowed_offsets[FBVBS_MAX_HOST_CALLSITE_ENTRIES];
    uint64_t relocated_callsites[FBVBS_MAX_HOST_CALLSITE_ENTRIES];
};

struct fbvbs_manifest_profile {
    bool active;
    uint8_t component_type;
    uint8_t caller_class;
    uint8_t allowed_callsite_count;
    uint16_t service_kind;
    uint16_t vcpu_count;
    uint32_t reserved0;
    uint64_t object_id;
    uint64_t manifest_object_id;
    uint64_t memory_limit_bytes;
    uint64_t capability_mask;
    uint64_t entry_ip;
    uint64_t initial_sp;
    uint64_t load_base;
    uint64_t allowed_callsite_offsets[FBVBS_MAX_HOST_CALLSITE_ENTRIES];
};

struct fbvbs_memory_object {
    bool allocated;
    uint32_t object_flags;
    uint64_t memory_object_id;
    uint64_t size;
    uint32_t map_count;
    uint32_t shared_count;
};

struct fbvbs_ksi_target_set {
    bool active;
    uint32_t target_count;
    uint64_t target_set_id;
    uint64_t target_object_ids[8];
};

struct fbvbs_ksi_object {
    bool active;
    bool tier_b;
    bool pointer_registered;
    bool retired;
    uint32_t protection_class;
    uint64_t object_id;
    uint64_t guest_physical_address;
    uint64_t size;
    uint64_t target_set_id;
};

struct fbvbs_iks_key {
    bool active;
    uint32_t key_type;
    uint32_t allowed_ops;
    uint32_t key_length;
    uint64_t key_handle;
};

struct fbvbs_sks_dek {
    bool active;
    uint32_t key_length;
    uint64_t dek_handle;
    uint64_t volume_id;
};

#define FBVBS_MAX_METADATA_MANIFESTS 8U
#define FBVBS_METADATA_ROLE_ROOT 1U
#define FBVBS_METADATA_ROLE_TARGETS 2U
#define FBVBS_METADATA_ROLE_SNAPSHOT 3U
#define FBVBS_METADATA_ROLE_TIMESTAMP 4U
#define FBVBS_METADATA_ROLE_REVOCATION 5U
#define FBVBS_METADATA_FLAG_SIGNATURE_VALID 0x0001U
#define FBVBS_METADATA_FLAG_REVOKED 0x0002U

struct fbvbs_metadata_manifest {
    uint64_t object_id;
    uint64_t generation;
    uint64_t expected_generation;
    uint64_t minimum_generation;
    uint64_t timestamp_seconds;
    uint64_t expires_at_seconds;
    uint64_t dependency_object_id;
    uint32_t role;
    uint32_t flags;
    uint8_t snapshot_id[32];
};

struct fbvbs_metadata_set_page {
    uint32_t count;
    uint32_t reserved0;
    uint64_t manifest_gpas[FBVBS_MAX_METADATA_MANIFESTS];
};

struct fbvbs_uvs_manifest_set {
    bool active;
    uint32_t manifest_count;
    uint32_t failure_bitmap;
    uint32_t reserved0;
    uint64_t verified_manifest_set_id;
    uint64_t root_manifest_gpa;
    uint64_t manifest_set_page_gpa;
    uint8_t snapshot_id[32];
};

struct fbvbs_uvs_artifact_approval {
    bool active;
    uint8_t reserved0[7];
    uint64_t verified_manifest_set_id;
    uint64_t artifact_object_id;
    uint64_t manifest_object_id;
    uint8_t artifact_hash[48];
};

struct fbvbs_artifact_catalog {
    uint32_t count;
    struct fbvbs_artifact_catalog_entry entries[FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES];
};

struct fbvbs_device_catalog {
    uint32_t count;
    struct fbvbs_device_catalog_entry entries[FBVBS_MAX_DEVICE_CATALOG_ENTRIES];
};

struct fbvbs_iommu_domain {
    bool active;
    uint8_t reserved0;
    uint16_t attached_device_count;
    uint32_t reserved1;
    uint64_t domain_id;
    uint64_t owner_partition_id;
};

struct fbvbs_command_tracker {
    bool active;
    bool sequence_seen;
    uint16_t reserved0;
    uint32_t reserved2;
    uint64_t page_gpa;
    uint64_t last_sequence;
    uint64_t last_nonce;
};

struct fbvbs_hypervisor_state {
    uint64_t next_partition_id;
    uint64_t next_measurement_digest_id;
    uint64_t next_memory_object_id;
    uint64_t next_shared_object_id;
    uint64_t next_target_set_id;
    uint64_t next_key_handle;
    uint64_t next_dek_handle;
    uint64_t next_manifest_set_id;
    uint64_t next_iommu_domain_id;
    uint64_t approved_module_object_id;
    uint64_t boot_id_hi;
    uint64_t boot_id_lo;
    bool trusted_clock_available;
    uint8_t reserved_clock0[7];
    uint64_t trusted_time_seconds;
    uint64_t capability_bitmap0;
    uint64_t capability_bitmap1;
    uint32_t revoked_object_count;
    uint32_t reserved_revocation0;
    uint64_t revoked_object_ids[FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES];
    struct fbvbs_manifest_profile manifest_profiles[FBVBS_MAX_MANIFEST_PROFILES];
    struct fbvbs_host_callsite_table host_callsites[FBVBS_MAX_HOST_CALLSITE_TABLES];
    struct fbvbs_vmx_capabilities vmx_caps;
    struct fbvbs_log_storage mirror_log;
    struct fbvbs_memory_object memory_objects[FBVBS_MAX_MEMORY_OBJECTS];
    struct fbvbs_shared_registration shared_objects[FBVBS_MAX_SHARED_OBJECTS];
    struct fbvbs_ksi_target_set ksi_target_sets[8];
    struct fbvbs_ksi_object ksi_objects[16];
    struct fbvbs_iks_key iks_keys[16];
    struct fbvbs_sks_dek sks_deks[16];
    struct fbvbs_uvs_manifest_set manifest_sets[8];
    struct fbvbs_uvs_artifact_approval approvals[FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES];
    uint64_t pinned_cr0_mask;
    uint64_t pinned_cr4_mask;
    uint32_t intercepted_msrs[16];
    uint32_t intercepted_msr_count;
    struct fbvbs_artifact_catalog artifact_catalog;
    struct fbvbs_device_catalog device_catalog;
    struct fbvbs_command_tracker command_trackers[FBVBS_MAX_COMMAND_TRACKERS];
    struct fbvbs_iommu_domain iommu_domains[FBVBS_MAX_PARTITIONS];
    struct fbvbs_partition partitions[FBVBS_MAX_PARTITIONS];
};

extern struct fbvbs_hypervisor_state g_fbvbs_hypervisor;

void fbvbs_zero_memory(void *buffer, size_t length);
void fbvbs_copy_memory(void *destination, const void *source, size_t length);
int fbvbs_memory_is_zero(const void *buffer, size_t length);

/*@ requires n == 0 || \valid(dest + (0 .. n - 1));
    requires n == 0 || \valid_read(src + (0 .. n - 1));
    requires n == 0 || \separated(dest + (0 .. n - 1), src + (0 .. n - 1));
    assigns dest[0 .. n - 1];
    ensures \forall integer i; 0 <= i < n ==> dest[i] == \old(src[i]);
*/
static inline void fbvbs_copy_bytes(uint8_t *dest, const uint8_t *src, size_t n) {
    size_t i;

    /*@ loop invariant 0 <= i <= n;
        loop invariant \forall integer j; 0 <= j < i ==> dest[j] == \at(src[j], Pre);
        loop assigns i, dest[0 .. n - 1];
        loop variant n - i;
    */
    for (i = 0; i < n; ++i) {
        dest[i] = src[i];
    }
}

void fbvbs_hypervisor_init(struct fbvbs_hypervisor_state *state);
void fbvbs_kernel_main(void);

uint32_t fbvbs_crc32c(const uint8_t *data, size_t length);
int fbvbs_log_init(struct fbvbs_hypervisor_state *state);
int fbvbs_log_append(
    struct fbvbs_hypervisor_state *state,
    uint32_t cpu_id,
    uint32_t source_component,
    uint16_t severity,
    uint16_t event_code,
    const uint8_t *payload,
    uint32_t payload_length
);
int fbvbs_audit_get_mirror_info(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_audit_mirror_info_response *response
);
int fbvbs_configure_host_callsite_table(
    struct fbvbs_hypervisor_state *state,
    uint8_t caller_class,
    uint64_t manifest_object_id,
    uint64_t load_base,
    const uint64_t *allowed_offsets,
    uint32_t count
);
uint64_t fbvbs_primary_host_callsite(
    const struct fbvbs_hypervisor_state *state,
    uint8_t caller_class
);
const struct fbvbs_manifest_profile *fbvbs_find_manifest_profile_for_object(
    const struct fbvbs_hypervisor_state *state,
    uint8_t component_type,
    uint64_t object_id
);
const struct fbvbs_manifest_profile *fbvbs_find_host_manifest_profile(
    const struct fbvbs_hypervisor_state *state,
    uint8_t caller_class
);
int fbvbs_ingest_boot_catalog(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_artifact_catalog_entry *artifact_entries,
    uint32_t artifact_count,
    const struct fbvbs_manifest_profile *profiles,
    uint32_t profile_count
);

int fbvbs_vmx_run_vcpu(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition,
    uint32_t vcpu_id,
    struct fbvbs_vm_run_response *response
);

int fbvbs_partition_create(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_create_request *request,
    struct fbvbs_partition_create_response *response
);
int fbvbs_partition_get_status(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    struct fbvbs_partition_status_response *response
);
int fbvbs_partition_measure(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_measure_request *request,
    struct fbvbs_partition_measure_response *response
);
int fbvbs_partition_load_image(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_load_image_request *request
);
int fbvbs_partition_start(struct fbvbs_hypervisor_state *state, uint64_t partition_id);
int fbvbs_partition_quiesce(struct fbvbs_hypervisor_state *state, uint64_t partition_id);
int fbvbs_partition_resume(struct fbvbs_hypervisor_state *state, uint64_t partition_id);
/*@ requires \valid(state);
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1],
            state->mirror_log;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == INVALID_STATE;
*/
int fbvbs_partition_fault(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint32_t fault_code,
    uint32_t source_component,
    uint64_t detail0,
    uint64_t detail1
);
int fbvbs_partition_recover(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_recover_request *request
);
int fbvbs_partition_seed_freebsd_host(struct fbvbs_hypervisor_state *state);
int fbvbs_partition_destroy(struct fbvbs_hypervisor_state *state, uint64_t partition_id);
int fbvbs_partition_get_fault_info(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    struct fbvbs_partition_fault_info_response *response
);
int fbvbs_vm_create(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_create_request *request,
    struct fbvbs_vm_create_response *response
);
int fbvbs_vm_destroy(struct fbvbs_hypervisor_state *state, uint64_t vm_partition_id);
int fbvbs_vm_get_vcpu_status(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_vcpu_status_request *request,
    struct fbvbs_vm_vcpu_status_response *response
);
int fbvbs_vm_set_register(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_register_request *request
);
int fbvbs_vm_get_register(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_register_read_request *request,
    struct fbvbs_vm_register_response *response
);
int fbvbs_vm_run(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_run_request *request,
    struct fbvbs_vm_run_response *response
);
int fbvbs_vm_map_memory(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_map_memory_request *request
);
int fbvbs_vm_inject_interrupt(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_inject_interrupt_request *request
);
int fbvbs_vm_assign_device(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_device_request *request
);
int fbvbs_vm_release_device(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_device_request *request
);
int fbvbs_memory_allocate_object(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_allocate_object_request *request,
    struct fbvbs_memory_allocate_object_response *response
);
int fbvbs_memory_map(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_map_request *request
);
int fbvbs_memory_unmap(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_unmap_request *request
);
int fbvbs_memory_set_permission(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_set_permission_request *request
);
int fbvbs_memory_register_shared(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_register_shared_request *request,
    struct fbvbs_memory_register_shared_response *response
);
int fbvbs_memory_release_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_object_id
);
int fbvbs_memory_unregister_shared(
    struct fbvbs_hypervisor_state *state,
    uint64_t shared_object_id
);
int fbvbs_kci_verify_module(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_verify_module_request *request,
    struct fbvbs_verdict_response *response
);
int fbvbs_kci_set_wx(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_set_wx_request *request
);
int fbvbs_kci_pin_cr(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_pin_cr_request *request
);
int fbvbs_kci_intercept_msr(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_intercept_msr_request *request
);
int fbvbs_ksi_create_target_set(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_create_target_set_request *request,
    struct fbvbs_ksi_target_set_response *response
);
int fbvbs_ksi_register_tier_a(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_register_tier_a_request *request
);
int fbvbs_ksi_register_tier_b(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_register_tier_b_request *request
);
int fbvbs_ksi_modify_tier_b(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_modify_tier_b_request *request
);
int fbvbs_ksi_register_pointer(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_register_pointer_request *request
);
int fbvbs_ksi_validate_setuid(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_validate_setuid_request *request,
    struct fbvbs_verdict_response *response
);
int fbvbs_ksi_allocate_ucred(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_allocate_ucred_request *request,
    struct fbvbs_ksi_allocate_ucred_response *response
);
int fbvbs_ksi_replace_tier_b_object(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_replace_tier_b_object_request *request
);
int fbvbs_ksi_unregister_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t object_id
);
int fbvbs_iks_import_key(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_import_key_request *request,
    struct fbvbs_handle_response *response
);
int fbvbs_iks_sign(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_sign_request *request,
    struct fbvbs_iks_sign_response *response
);
int fbvbs_iks_key_exchange(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_key_exchange_request *request,
    struct fbvbs_handle_response *response
);
int fbvbs_iks_derive(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_derive_request *request,
    struct fbvbs_handle_response *response
);
int fbvbs_iks_destroy_key(
    struct fbvbs_hypervisor_state *state,
    uint64_t key_handle
);
int fbvbs_sks_import_dek(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_import_dek_request *request,
    struct fbvbs_handle_response *response
);
int fbvbs_sks_decrypt_batch(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_batch_request *request,
    struct fbvbs_sks_batch_response *response
);
int fbvbs_sks_encrypt_batch(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_batch_request *request,
    struct fbvbs_sks_batch_response *response
);
int fbvbs_sks_destroy_dek(
    struct fbvbs_hypervisor_state *state,
    uint64_t dek_handle
);
int fbvbs_uvs_verify_manifest_set(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_verify_manifest_set_request *request,
    struct fbvbs_uvs_verify_manifest_set_response *response
);
int fbvbs_artifact_approval_exists(
    const struct fbvbs_hypervisor_state *state,
    uint64_t artifact_object_id,
    uint64_t manifest_object_id
);
int fbvbs_uvs_verify_artifact(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_verify_artifact_request *request,
    struct fbvbs_verdict_response *response
);
int fbvbs_uvs_check_revocation(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_check_revocation_request *request,
    struct fbvbs_uvs_check_revocation_response *response
);
int fbvbs_diag_get_partition_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_partition_list_response *response,
    uint32_t *response_length
);
int fbvbs_diag_get_capabilities(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_capabilities_response *response
);
int fbvbs_diag_get_artifact_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_artifact_list_response *response,
    uint32_t *response_length
);
int fbvbs_diag_get_device_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_device_list_response *response,
    uint32_t *response_length
);

int fbvbs_validate_trap_registers(const struct fbvbs_trap_registers *registers);
int fbvbs_dispatch_hypercall(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_trap_registers *registers
);

#endif