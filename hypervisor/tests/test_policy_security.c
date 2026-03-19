#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../include/fbvbs_cpu_security.h"
#include "../include/fbvbs_hypervisor.h"

static void test_kci_verify_module_uses_current_manifest_generation(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_verdict_response response = {0};
    struct fbvbs_kci_verify_module_request request = {0};
    struct fbvbs_metadata_manifest manifest = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) struct fbvbs_metadata_set_page page;
    } manifest_page = {0};
    int status;

    memset(&state, 0, sizeof(state));

    manifest.object_id = 0x2222U;
    manifest.generation = 7U;
    manifest.flags = FBVBS_METADATA_FLAG_SIGNATURE_VALID;

    manifest_page.page.count = 1U;
    manifest_page.page.manifest_gpas[0] = (uint64_t)(uintptr_t)&manifest;

    state.current_manifest_set_id = 1U;
    state.manifest_sets[0].active = true;
    state.manifest_sets[0].manifest_count = 1U;
    state.manifest_sets[0].verified_manifest_set_id = 1U;
    state.manifest_sets[0].manifest_set_page_gpa = (uint64_t)(uintptr_t)&manifest_page.page;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x1111U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_MODULE;
    state.artifact_catalog.entries[0].related_index = 1U;
    state.artifact_catalog.entries[1].object_id = 0x2222U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 1U;

    state.approvals[0].active = true;
    state.approvals[0].artifact_object_id = 0x1111U;
    state.approvals[0].manifest_object_id = 0x2222U;
    state.approvals[0].manifest_set_id = 1U;
    state.approvals[0].verified_manifest_set_id = 1U;

    request.module_object_id = 0x1111U;
    request.manifest_object_id = 0x2222U;
    request.generation = 6U;
    status = fbvbs_kci_verify_module(&state, &request, &response);
    assert(status == GENERATION_MISMATCH);

    request.generation = 7U;
    status = fbvbs_kci_verify_module(&state, &request, &response);
    assert(status == OK);
    assert(response.verdict == 1U);
    assert(state.approved_module_object_id == 0x1111U);
}

static void test_vm_set_register_enforces_arch_and_pin_policy(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_register_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.pinned_cr0_mask = CR0_WP;
    state.pinned_cr0_value = CR0_WP;
    state.pinned_cr4_mask = CR4_SMEP | CR4_SMAP | CR4_PCE;
    state.pinned_cr4_value = CR4_SMEP | CR4_SMAP;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x3333U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].vcpu_count = 1U;
    state.partitions[0].vcpus[0].state = FBVBS_VCPU_STATE_RUNNABLE;

    request.vm_partition_id = 0x3333U;
    request.vcpu_id = 0U;

    request.register_id = VM_REG_RFLAGS;
    request.value = 0U;
    status = fbvbs_vm_set_register(&state, &request);
    assert(status == INVALID_PARAMETER);

    request.register_id = VM_REG_CR4;
    request.value = CR4_SMEP | CR4_SMAP | CR4_PCE;
    status = fbvbs_vm_set_register(&state, &request);
    assert(status == PERMISSION_DENIED);

    request.register_id = VM_REG_CR4;
    request.value = CR4_SMEP | CR4_SMAP;
    status = fbvbs_vm_set_register(&state, &request);
    assert(status == OK);
    assert(state.partitions[0].vcpus[0].cr4 == (CR4_SMEP | CR4_SMAP));
}

static void test_log_append_fails_closed_on_sequence_wraparound(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));

    assert(fbvbs_log_init(&state) == OK);
    state.mirror_log.header.max_readable_sequence = UINT64_MAX;

    status = fbvbs_log_append(&state, 0U, 0U, 0U, 0U, NULL, 0U);
    assert(status == RESOURCE_EXHAUSTED);
    assert(state.mirror_log.header.max_readable_sequence == UINT64_MAX);
    assert(state.log_lock == 0U);
}

static void test_shared_registration_only_charges_real_mappings(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request share_request = {0};
    struct fbvbs_memory_register_shared_response share_response = {0};
    struct fbvbs_memory_map_request map_shared = {0};
    struct fbvbs_memory_map_request map_private = {0};
    int status;

    memset(&state, 0, sizeof(state));
    state.next_shared_object_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x200U;
    state.partitions[1].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[1].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[1].memory_limit_bytes = FBVBS_PAGE_SIZE * 2U;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    state.memory_objects[1].allocated = true;
    state.memory_objects[1].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[1].memory_object_id = 0x2000U;
    state.memory_objects[1].owner_partition_id = 0x200U;
    state.memory_objects[1].size = FBVBS_PAGE_SIZE;

    share_request.memory_object_id = 0x1000U;
    share_request.size = FBVBS_PAGE_SIZE;
    share_request.peer_partition_id = 0x200U;
    share_request.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_register_shared(
        &state,
        &share_request,
        &share_response,
        0x100U
    );
    assert(status == OK);
    assert(share_response.shared_object_id != 0U);
    assert(state.partitions[1].mapped_bytes == 0U);
    assert(state.memory_objects[0].shared_count == 1U);

    map_shared.partition_id = 0x200U;
    map_shared.memory_object_id = 0x1000U;
    map_shared.guest_physical_address = FBVBS_PAGE_SIZE;
    map_shared.size = FBVBS_PAGE_SIZE;
    map_shared.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &map_shared);
    status = fbvbs_memory_map(&state, &map_shared, 0x100U);
    assert(status == OK);

    map_private.partition_id = 0x200U;
    map_private.memory_object_id = 0x2000U;
    map_private.guest_physical_address = FBVBS_PAGE_SIZE * 2U;
    map_private.size = FBVBS_PAGE_SIZE;
    map_private.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &map_private, 0x200U);
    assert(status == OK);

    assert(state.partitions[1].mapped_bytes == FBVBS_PAGE_SIZE * 2U);
    assert(state.memory_objects[0].map_count == 1U);
    assert(state.memory_objects[1].map_count == 1U);

    status = fbvbs_partition_destroy(&state, 0x100U);
    assert(status == OK);
    assert(state.partitions[1].mapped_bytes == FBVBS_PAGE_SIZE);
    assert(state.memory_objects[0].map_count == 0U);
    assert(state.memory_objects[0].shared_count == 0U);
    assert(state.memory_objects[1].map_count == 1U);
    assert(!state.partitions[1].mappings[0].active);
    assert(state.partitions[1].mappings[1].active);
}

static void test_shareable_object_requires_registration_for_non_owner_mapping(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_map_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x200U;
    state.partitions[1].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[1].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[1].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    request.partition_id = 0x200U;
    request.memory_object_id = 0x1000U;
    request.guest_physical_address = FBVBS_PAGE_SIZE;
    request.size = FBVBS_PAGE_SIZE;
    request.permissions = FBVBS_MEMORY_PERMISSION_READ;

    status = fbvbs_memory_map(&state, &request, 0x100U);
    assert(status == PERMISSION_DENIED);
}

static void test_unregister_shared_rejects_live_peer_mapping(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request share_request = {0};
    struct fbvbs_memory_register_shared_response share_response = {0};
    struct fbvbs_memory_map_request map_request = {0};
    int status;

    memset(&state, 0, sizeof(state));
    state.next_shared_object_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x200U;
    state.partitions[1].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[1].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[1].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    share_request.memory_object_id = 0x1000U;
    share_request.size = FBVBS_PAGE_SIZE;
    share_request.peer_partition_id = 0x200U;
    share_request.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_register_shared(&state, &share_request, &share_response, 0x100U);
    assert(status == OK);

    map_request.partition_id = 0x200U;
    map_request.memory_object_id = 0x1000U;
    map_request.guest_physical_address = FBVBS_PAGE_SIZE;
    map_request.size = FBVBS_PAGE_SIZE;
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &map_request, 0x100U);
    assert(status == OK);

    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id);
    assert(status == RESOURCE_BUSY);
}

static void test_unregister_shared_allows_owner_mapping_when_peer_is_unmapped(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request share_request = {0};
    struct fbvbs_memory_register_shared_response share_response = {0};
    struct fbvbs_memory_map_request owner_map = {0};
    int status;

    memset(&state, 0, sizeof(state));
    state.next_shared_object_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[0].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x200U;
    state.partitions[1].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[1].state = FBVBS_PARTITION_STATE_CREATED;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    owner_map.partition_id = 0x100U;
    owner_map.memory_object_id = 0x1000U;
    owner_map.guest_physical_address = FBVBS_PAGE_SIZE;
    owner_map.size = FBVBS_PAGE_SIZE;
    owner_map.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &owner_map, 0x100U);
    assert(status == OK);

    share_request.memory_object_id = 0x1000U;
    share_request.size = FBVBS_PAGE_SIZE;
    share_request.peer_partition_id = 0x200U;
    share_request.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_register_shared(&state, &share_request, &share_response, 0x100U);
    assert(status == OK);

    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id);
    assert(status == OK);
    assert(state.memory_objects[0].shared_count == 0U);
    assert(state.partitions[0].mapped_bytes == FBVBS_PAGE_SIZE);
}

static void test_kci_set_wx_fails_closed_without_page_binding(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_kci_set_wx_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.approved_module_object_id = 0x4444U;
    request.module_object_id = 0x4444U;
    request.guest_physical_address = FBVBS_PAGE_SIZE;
    request.file_offset = 0U;
    request.size = FBVBS_PAGE_SIZE;
    request.permissions = FBVBS_MEMORY_PERMISSION_EXECUTE;

    status = fbvbs_kci_set_wx(&state, &request);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
}

static void test_platform_detection_fails_closed_without_real_bringup(void) {
    struct fbvbs_global_security_state state;

    memset(&state, 0, sizeof(state));

    state.vendor = CPU_VENDOR_INTEL;
    assert(fbvbs_iommu_detect(&state) == -1);
    assert(state.iommu.iommu_type == IOMMU_TYPE_VTD);
    assert(fbvbs_boot_integrity_detect(&state) == -1);
    assert(state.boot.secure_boot_active == 0U);
    assert(state.boot.measured_boot_active == 0U);
}

static void test_vm_device_passthrough_is_fail_closed_without_qualification(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.vmx_caps.iommu_available = 1U;
    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x5555U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.device_catalog.count = 1U;
    state.device_catalog.entries[0].device_id = 0xD000U;

    request.vm_partition_id = 0x5555U;
    request.device_id = 0xD000U;

    status = fbvbs_vm_assign_device(&state, &request);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].assigned_device_count == 0U);
}

static void test_vm_destroy_rejects_assigned_devices_without_safe_teardown(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x6666U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[0].assigned_device_count = 1U;
    state.partitions[0].assigned_devices[0] = 0xD000U;

    status = fbvbs_vm_destroy(&state, 0x6666U);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].occupied);
    assert(state.partitions[0].assigned_device_count == 1U);
}

int main(void) {
    test_kci_verify_module_uses_current_manifest_generation();
    test_vm_set_register_enforces_arch_and_pin_policy();
    test_log_append_fails_closed_on_sequence_wraparound();
    test_shared_registration_only_charges_real_mappings();
    test_shareable_object_requires_registration_for_non_owner_mapping();
    test_unregister_shared_rejects_live_peer_mapping();
    test_unregister_shared_allows_owner_mapping_when_peer_is_unmapped();
    test_kci_set_wx_fails_closed_without_page_binding();
    test_platform_detection_fails_closed_without_real_bringup();
    test_vm_device_passthrough_is_fail_closed_without_qualification();
    test_vm_destroy_rejects_assigned_devices_without_safe_teardown();
    return 0;
}
