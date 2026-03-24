/* FBVBS Policy/Security Unit Tests
 *
 * Requirements: REQ-1004 (継続的テスト), REQ-1005 (MC/DC カバレッジ)
 */
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
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } module_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));
    memset(module_page.bytes, 0x5A, sizeof(module_page.bytes));

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
    fbvbs_sha384(
        module_page.bytes,
        sizeof(module_page.bytes),
        state.artifact_catalog.entries[0].payload_hash
    );
    state.artifact_catalog.entries[1].object_id = 0x2222U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 1U;

    state.approvals[0].active = true;
    state.approvals[0].artifact_object_id = 0x1111U;
    state.approvals[0].manifest_object_id = 0x2222U;
    state.approvals[0].manifest_set_id = 1U;
    state.approvals[0].verified_manifest_set_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state.partitions[0].mapped_bytes = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].active = true;
    state.partitions[0].mappings[0].memory_object_id = 0x1111U;
    state.partitions[0].mappings[0].guest_physical_address =
        (uint64_t)(uintptr_t)module_page.bytes;
    state.partitions[0].mappings[0].size = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_READ;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x1111U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].map_count = 1U;

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

static void test_sha384_matches_known_vector(void) {
    static const uint8_t expected[48] = {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
        0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
        0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
    };
    uint8_t digest[48];

    fbvbs_sha384("abc", 3U, digest);
    assert(memcmp(digest, expected, sizeof(expected)) == 0);
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

    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id, 0x100U);
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

    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id, 0x100U);
    assert(status == OK);
    assert(state.memory_objects[0].shared_count == 0U);
    assert(state.partitions[0].mapped_bytes == FBVBS_PAGE_SIZE);
}

static void test_kci_set_wx_requires_verified_module_measurements(void) {
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
    assert(status == INVALID_STATE);
}

static void test_kci_verify_module_and_set_wx_enforce_measured_pages(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_verdict_response verify_response = {0};
    struct fbvbs_kci_verify_module_request verify_request = {0};
    struct fbvbs_kci_set_wx_request request = {0};
    struct fbvbs_metadata_manifest manifest = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) struct fbvbs_metadata_set_page page;
    } manifest_page = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } module_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));

    memset(module_page.bytes, 0xA5, sizeof(module_page.bytes));

    manifest.object_id = 0x5555U;
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
    state.artifact_catalog.entries[0].object_id = 0x4444U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_MODULE;
    state.artifact_catalog.entries[0].related_index = 1U;
    fbvbs_sha384(
        module_page.bytes,
        sizeof(module_page.bytes),
        state.artifact_catalog.entries[0].payload_hash
    );
    state.artifact_catalog.entries[1].object_id = 0x5555U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;

    state.approvals[0].active = true;
    state.approvals[0].artifact_object_id = 0x4444U;
    state.approvals[0].manifest_object_id = 0x5555U;
    state.approvals[0].manifest_set_id = 1U;
    state.approvals[0].verified_manifest_set_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state.partitions[0].mapped_bytes = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].active = true;
    state.partitions[0].mappings[0].memory_object_id = 0x4444U;
    state.partitions[0].mappings[0].guest_physical_address =
        (uint64_t)(uintptr_t)module_page.bytes;
    state.partitions[0].mappings[0].size = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_READ;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x4444U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].map_count = 1U;

    verify_request.module_object_id = 0x4444U;
    verify_request.manifest_object_id = 0x5555U;
    verify_request.generation = 7U;
    status = fbvbs_kci_verify_module(&state, &verify_request, &verify_response);
    assert(status == OK);
    assert(verify_response.verdict == 1U);
    assert(state.approved_module_object_id == 0x4444U);
    assert(state.approved_module_base_gpa ==
           (uint64_t)(uintptr_t)module_page.bytes);
    assert(state.approved_module_page_count == 1U);

    request.module_object_id = 0x4444U;
    request.guest_physical_address = (uint64_t)(uintptr_t)module_page.bytes;
    request.file_offset = 0U;
    request.size = FBVBS_PAGE_SIZE;
    request.permissions = FBVBS_MEMORY_PERMISSION_READ |
                          FBVBS_MEMORY_PERMISSION_EXECUTE;

    status = fbvbs_kci_set_wx(&state, &request);
    assert(status == OK);
    assert(state.partitions[0].mappings[0].permissions ==
           (FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_EXECUTE));
    assert(state.kci_binding_count == 1U);

    module_page.bytes[0] ^= 0xFFU;
    state.partitions[0].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_kci_set_wx(&state, &request);
    assert(status == MEASUREMENT_FAILED);
    assert(state.partitions[0].mappings[0].permissions == FBVBS_MEMORY_PERMISSION_READ);
}

static void test_kci_verified_module_is_invalidated_on_unmap(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_verdict_response verify_response = {0};
    struct fbvbs_kci_verify_module_request verify_request = {0};
    struct fbvbs_memory_unmap_request unmap_request = {0};
    struct fbvbs_metadata_manifest manifest = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) struct fbvbs_metadata_set_page page;
    } manifest_page = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } module_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));
    memset(module_page.bytes, 0x3C, sizeof(module_page.bytes));

    manifest.object_id = 0x5555U;
    manifest.generation = 9U;
    manifest.flags = FBVBS_METADATA_FLAG_SIGNATURE_VALID;
    manifest_page.page.count = 1U;
    manifest_page.page.manifest_gpas[0] = (uint64_t)(uintptr_t)&manifest;

    state.current_manifest_set_id = 1U;
    state.manifest_sets[0].active = true;
    state.manifest_sets[0].manifest_count = 1U;
    state.manifest_sets[0].verified_manifest_set_id = 1U;
    state.manifest_sets[0].manifest_set_page_gpa = (uint64_t)(uintptr_t)&manifest_page.page;
    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x4444U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_MODULE;
    state.artifact_catalog.entries[0].related_index = 1U;
    fbvbs_sha384(
        module_page.bytes,
        sizeof(module_page.bytes),
        state.artifact_catalog.entries[0].payload_hash
    );
    state.artifact_catalog.entries[1].object_id = 0x5555U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;
    state.approvals[0].active = true;
    state.approvals[0].artifact_object_id = 0x4444U;
    state.approvals[0].manifest_object_id = 0x5555U;
    state.approvals[0].manifest_set_id = 1U;
    state.approvals[0].verified_manifest_set_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state.partitions[0].mapped_bytes = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].active = true;
    state.partitions[0].mappings[0].memory_object_id = 0x4444U;
    state.partitions[0].mappings[0].guest_physical_address =
        (uint64_t)(uintptr_t)module_page.bytes;
    state.partitions[0].mappings[0].size = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_READ;
    state.memory_objects[0].allocated = true;
    state.memory_objects[0].memory_object_id = 0x4444U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].map_count = 1U;

    verify_request.module_object_id = 0x4444U;
    verify_request.manifest_object_id = 0x5555U;
    verify_request.generation = 9U;
    status = fbvbs_kci_verify_module(&state, &verify_request, &verify_response);
    assert(status == OK);
    assert(state.approved_module_object_id == 0x4444U);

    unmap_request.partition_id = 0x100U;
    unmap_request.guest_physical_address = (uint64_t)(uintptr_t)module_page.bytes;
    unmap_request.size = FBVBS_PAGE_SIZE;
    status = fbvbs_memory_unmap(&state, &unmap_request, 0x100U);
    assert(status == OK);
    assert(state.approved_module_object_id == 0U);
    assert(state.approved_module_page_count == 0U);
}

static void test_partition_load_image_fails_closed_without_materializer(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_load_image_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7777U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_MEASURED;
    state.partitions[0].image_object_id = 0x8888U;
    state.partitions[0].manifest_object_id = 0x9999U;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x8888U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_IMAGE;
    state.artifact_catalog.entries[0].related_index = 1U;
    state.artifact_catalog.entries[1].object_id = 0x9999U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;

    state.manifest_profiles[0].active = true;
    state.manifest_profiles[0].component_type =
        FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE;
    state.manifest_profiles[0].object_id = 0x8888U;
    state.manifest_profiles[0].manifest_object_id = 0x9999U;
    state.manifest_profiles[0].entry_ip = 0x100000U;
    state.manifest_profiles[0].initial_sp = 0x200000U;

    request.partition_id = 0x7777U;
    request.image_object_id = 0x8888U;
    request.entry_ip = 0x100000U;
    request.initial_sp = 0x200000U;

    status = fbvbs_partition_load_image(&state, &request);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_MEASURED);
    assert(state.partitions[0].entry_ip == 0U);
    assert(state.partitions[0].initial_sp == 0U);
}

static void test_platform_detection_fails_closed_without_real_bringup(void) {
    struct fbvbs_global_security_state state;

    /* IOMMU detection: Intel → type set, but fail-closed (no ACPI evidence). */
    memset(&state, 0, sizeof(state));
    state.vendor = CPU_VENDOR_INTEL;
    assert(fbvbs_iommu_detect(&state) == -1);
    assert(state.iommu.iommu_type == IOMMU_TYPE_VTD);

    /* IOMMU detection: AMD → type set, but fail-closed. */
    memset(&state, 0, sizeof(state));
    state.vendor = CPU_VENDOR_AMD;
    assert(fbvbs_iommu_detect(&state) == -1);
    assert(state.iommu.iommu_type == IOMMU_TYPE_AMD_VI);

    /* Boot integrity: Intel → CPUID model detects DRTM bits but
       measured boot cannot be established without platform bring-up. */
    memset(&state, 0, sizeof(state));
    state.vendor = CPU_VENDOR_INTEL;
    assert(fbvbs_boot_integrity_detect(&state) == -1);

    /* Unknown vendor must fail-closed for both. */
    memset(&state, 0, sizeof(state));
    state.vendor = CPU_VENDOR_UNKNOWN;
    assert(fbvbs_iommu_detect(&state) == -1);
    assert(fbvbs_boot_integrity_detect(&state) == -1);
}

static void test_vm_device_passthrough_is_fail_closed_without_qualification(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.cpu_security.iommu.iommu_type = IOMMU_TYPE_VTD;
    state.cpu_security.iommu.dma_remapping = 1U;
    state.cpu_security.iommu.interrupt_remapping = 1U;
    state.cpu_security.iommu.kernel_dma_protection = 1U;
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

static void test_unregister_shared_rejects_non_owner(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request share_request = {0};
    struct fbvbs_memory_register_shared_response share_response = {0};
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

    /* Non-owner (0x200) cannot unregister. */
    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id, 0x200U);
    assert(status == PERMISSION_DENIED);
    assert(state.memory_objects[0].shared_count == 1U);

    /* Owner can unregister. */
    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id, 0x100U);
    assert(status == OK);
    assert(state.memory_objects[0].shared_count == 0U);
}

static void test_unmap_rejects_unauthorized_caller(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_map_request map_request = {0};
    struct fbvbs_memory_unmap_request unmap_request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[0].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x1000U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;

    map_request.partition_id = 0x100U;
    map_request.memory_object_id = 0x1000U;
    map_request.guest_physical_address = FBVBS_PAGE_SIZE;
    map_request.size = FBVBS_PAGE_SIZE;
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &map_request, 0x100U);
    assert(status == OK);

    unmap_request.partition_id = 0x100U;
    unmap_request.guest_physical_address = FBVBS_PAGE_SIZE;
    unmap_request.size = FBVBS_PAGE_SIZE;

    /* Unauthorized third party (0x999) cannot unmap. */
    status = fbvbs_memory_unmap(&state, &unmap_request, 0x999U);
    assert(status == PERMISSION_DENIED);
    assert(state.partitions[0].mapped_bytes == FBVBS_PAGE_SIZE);

    /* Owner can unmap. */
    status = fbvbs_memory_unmap(&state, &unmap_request, 0x100U);
    assert(status == OK);
    assert(state.partitions[0].mapped_bytes == 0U);
}

static void test_broadcast_registration_authorizes_any_peer(void) {
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

    /* Broadcast registration: peer_partition_id == 0 means any peer. */
    share_request.memory_object_id = 0x1000U;
    share_request.size = FBVBS_PAGE_SIZE;
    share_request.peer_partition_id = 0U;
    share_request.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_register_shared(&state, &share_request, &share_response, 0x100U);
    assert(status == OK);

    /* Partition 0x200 can map via broadcast authorization. */
    map_request.partition_id = 0x200U;
    map_request.memory_object_id = 0x1000U;
    map_request.guest_physical_address = FBVBS_PAGE_SIZE;
    map_request.size = FBVBS_PAGE_SIZE;
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ;
    status = fbvbs_memory_map(&state, &map_request, 0x100U);
    assert(status == OK);
    assert(state.partitions[1].mapped_bytes == FBVBS_PAGE_SIZE);
}

static void test_vm_device_passthrough_stays_disabled_even_when_platform_looks_ready(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.cpu_security.iommu.iommu_type = IOMMU_TYPE_VTD;
    state.cpu_security.iommu.dma_remapping = 1U;
    state.cpu_security.iommu.interrupt_remapping = 1U;
    state.cpu_security.iommu.kernel_dma_protection = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x9000U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    state.device_catalog.count = 1U;
    state.device_catalog.entries[0].device_id = 0xD900U;
    state.device_catalog.entries[0].qualified = 1U;
    state.device_catalog.entries[0].has_flr = 1U;
    state.device_catalog.entries[0].has_acs = 1U;

    request.vm_partition_id = 0x9000U;
    request.device_id = 0xD900U;

    status = fbvbs_vm_assign_device(&state, &request);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].assigned_device_count == 0U);
    assert(state.partitions[0].iommu_domain_id == 0U);
}

static void test_vm_release_device_stays_disabled_without_safe_teardown(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x9001U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[0].assigned_device_count = 1U;
    state.partitions[0].assigned_devices[0] = 0xD901U;

    request.vm_partition_id = 0x9001U;
    request.device_id = 0xD901U;

    status = fbvbs_vm_release_device(&state, &request);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].assigned_device_count == 1U);
    assert(state.partitions[0].assigned_devices[0] == 0xD901U);
}

int main(void) {
    test_kci_verify_module_uses_current_manifest_generation();
    test_vm_set_register_enforces_arch_and_pin_policy();
    test_log_append_fails_closed_on_sequence_wraparound();
    test_sha384_matches_known_vector();
    test_shared_registration_only_charges_real_mappings();
    test_shareable_object_requires_registration_for_non_owner_mapping();
    test_unregister_shared_rejects_live_peer_mapping();
    test_unregister_shared_allows_owner_mapping_when_peer_is_unmapped();
    test_kci_set_wx_requires_verified_module_measurements();
    test_kci_verify_module_and_set_wx_enforce_measured_pages();
    test_kci_verified_module_is_invalidated_on_unmap();
    test_partition_load_image_fails_closed_without_materializer();
    test_platform_detection_fails_closed_without_real_bringup();
    test_vm_device_passthrough_is_fail_closed_without_qualification();
    test_vm_destroy_rejects_assigned_devices_without_safe_teardown();
    test_unregister_shared_rejects_non_owner();
    test_unmap_rejects_unauthorized_caller();
    test_broadcast_registration_authorizes_any_peer();
    test_vm_device_passthrough_stays_disabled_even_when_platform_looks_ready();
    test_vm_release_device_stays_disabled_without_safe_teardown();
    return 0;
}
