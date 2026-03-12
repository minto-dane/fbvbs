#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#include "../include/fbvbs_hypervisor.h"

struct aligned_command_page {
    struct fbvbs_command_page_v1 page;
} __attribute__((aligned(4096)));

struct aligned_metadata_bundle {
    struct fbvbs_metadata_set_page page;
    struct fbvbs_metadata_manifest manifests[5];
} __attribute__((aligned(4096)));

#define TEST_KCI_MODULE_MANIFEST_OBJECT_ID 0x2900U

static uint64_t g_test_command_sequence = 1U;

static void approve_artifact_pair(
    struct fbvbs_hypervisor_state *state,
    uint64_t artifact_object_id,
    uint64_t manifest_object_id
);

static void fill_snapshot_id(uint8_t snapshot_id[32], uint8_t seed) {
    uint32_t index;

    for (index = 0U; index < 32U; ++index) {
        snapshot_id[index] = (uint8_t)(seed + index);
    }
}

static void init_metadata_manifest(
    struct fbvbs_metadata_manifest *manifest,
    uint32_t role,
    uint64_t object_id,
    const uint8_t snapshot_id[32]
) {
    fbvbs_zero_memory(manifest, sizeof(*manifest));
    manifest->object_id = object_id;
    manifest->generation = 1U;
    manifest->expected_generation = 1U;
    manifest->minimum_generation = 1U;
    manifest->timestamp_seconds = 900U;
    manifest->expires_at_seconds = 1200U;
    manifest->role = role;
    manifest->flags = FBVBS_METADATA_FLAG_SIGNATURE_VALID;
    fbvbs_copy_memory(manifest->snapshot_id, snapshot_id, 32U);
}

static void prepare_valid_metadata_bundle(
    struct aligned_metadata_bundle *bundle,
    uint64_t root_manifest_object_id
) {
    static const uint32_t roles[5] = {
        FBVBS_METADATA_ROLE_ROOT,
        FBVBS_METADATA_ROLE_TARGETS,
        FBVBS_METADATA_ROLE_SNAPSHOT,
        FBVBS_METADATA_ROLE_TIMESTAMP,
        FBVBS_METADATA_ROLE_REVOCATION,
    };
    static const uint64_t object_ids[5] = {
        0U,
        0x900001U,
        0x900002U,
        0x900003U,
        0x900004U,
    };
    uint8_t snapshot_id[32];
    uint32_t index;

    fbvbs_zero_memory(bundle, sizeof(*bundle));
    fill_snapshot_id(snapshot_id, 0x40U);
    bundle->page.count = 5U;
    for (index = 0U; index < 5U; ++index) {
        uint64_t object_id = (index == 0U) ? root_manifest_object_id : object_ids[index];

        init_metadata_manifest(&bundle->manifests[index], roles[index], object_id, snapshot_id);
        bundle->page.manifest_gpas[index] = (uint64_t)(uintptr_t)&bundle->manifests[index];
    }
}

static void prepare_metadata_set_request(
    const struct aligned_metadata_bundle *bundle,
    struct fbvbs_uvs_verify_manifest_set_request *request
) {
    fbvbs_zero_memory(request, sizeof(*request));
    request->root_manifest_gpa = (uint64_t)(uintptr_t)&bundle->manifests[0];
    request->root_manifest_length = sizeof(bundle->manifests[0]);
    request->manifest_count = bundle->page.count;
    request->manifest_set_page_gpa = (uint64_t)(uintptr_t)&bundle->page;
}

static void prepare_command_page(
    struct aligned_command_page *aligned_page,
    uint16_t call_id,
    uint32_t input_length,
    uint32_t output_length_max
) {
    fbvbs_zero_memory(aligned_page, sizeof(*aligned_page));
    aligned_page->page.abi_version = FBVBS_ABI_VERSION;
    aligned_page->page.call_id = call_id;
    aligned_page->page.input_length = input_length;
    aligned_page->page.output_length_max = output_length_max;
    aligned_page->page.caller_sequence = g_test_command_sequence++;
    aligned_page->page.caller_nonce = aligned_page->page.caller_sequence ^ 0xFB0001234ULL;
    aligned_page->page.command_state = READY;
}

static void prepare_trap_registers(
    struct fbvbs_trap_registers *registers,
    struct fbvbs_command_page_v1 *page
) {
    registers->rax = (uint64_t)(uintptr_t)page;
    registers->rbx = 0U;
    registers->rcx = 0U;
    registers->rdx = 0U;
}

static struct fbvbs_command_page_v1 *prepare_partition_command_page(
    struct fbvbs_partition *partition,
    uint32_t vcpu_id,
    uint16_t call_id,
    uint32_t input_length,
    uint32_t output_length_max
) {
    struct fbvbs_command_page_v1 *page = &partition->command_pages[vcpu_id].page;

    fbvbs_zero_memory(page, sizeof(*page));
    page->abi_version = FBVBS_ABI_VERSION;
    page->call_id = call_id;
    page->input_length = input_length;
    page->output_length_max = output_length_max;
    page->caller_sequence = g_test_command_sequence++;
    page->caller_nonce = page->caller_sequence ^ 0xFB0001234ULL;
    page->command_state = READY;
    return page;
}

static const struct fbvbs_log_record_v1 *get_log_record(
    const struct fbvbs_hypervisor_state *state,
    uint64_t sequence
) {
    assert(sequence != 0U);
    assert(sequence <= state->mirror_log.header.max_readable_sequence);
    return &state->mirror_log.records[(sequence - 1U) % FBVBS_LOG_SLOT_COUNT];
}

static void test_mirror_log_header_and_wraparound(void) {
    struct fbvbs_hypervisor_state state;
    uint8_t payload[220];
    const struct fbvbs_log_record_v1 *record;
    uint32_t index;

    fbvbs_zero_memory(&state, sizeof(state));
    state.boot_id_hi = 0x1122334455667788ULL;
    state.boot_id_lo = 0x8877665544332211ULL;
    for (index = 0U; index < sizeof(payload); ++index) {
        payload[index] = (uint8_t)index;
    }

    assert(fbvbs_log_init(&state) == OK);
    assert(state.mirror_log.header.abi_version == FBVBS_ABI_VERSION);
    assert(state.mirror_log.header.total_size == sizeof(state.mirror_log));
    assert(state.mirror_log.header.record_size == FBVBS_LOG_RECORD_V1_SIZE);
    assert(state.mirror_log.header.write_offset == 0U);
    assert(state.mirror_log.header.max_readable_sequence == 0U);
    assert(state.mirror_log.header.boot_id_hi == state.boot_id_hi);
    assert(state.mirror_log.header.boot_id_lo == state.boot_id_lo);

    for (index = 0U; index < FBVBS_LOG_SLOT_COUNT + 1U; ++index) {
        assert(fbvbs_log_append(
            &state,
            index,
            FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
            1U,
            (uint16_t)(FBVBS_EVENT_BOOT_COMPLETE + index),
            payload,
            sizeof(payload)
        ) == OK);
    }

    assert(state.mirror_log.header.max_readable_sequence == FBVBS_LOG_SLOT_COUNT + 1U);
    assert(state.mirror_log.header.write_offset == 0U);
    record = get_log_record(&state, FBVBS_LOG_SLOT_COUNT + 1U);
    assert(record->sequence == FBVBS_LOG_SLOT_COUNT + 1U);
    assert(record->cpu_id == FBVBS_LOG_SLOT_COUNT);
    assert(record->payload_length == sizeof(payload));
    assert(record->crc32c == fbvbs_crc32c(record, offsetof(struct fbvbs_log_record_v1, crc32c)));
}

static void test_log_append_rejects_invalid_inputs(void) {
    struct fbvbs_hypervisor_state state;
    uint8_t payload[221];

    fbvbs_zero_memory(&state, sizeof(state));
    assert(fbvbs_log_init(NULL) == INVALID_PARAMETER);
    assert(fbvbs_log_append(NULL, 0U, 0U, 0U, 0U, NULL, 0U) == INVALID_PARAMETER);
    assert(fbvbs_log_init(&state) == OK);
    assert(fbvbs_log_append(&state, 0U, 0U, 0U, 0U, NULL, 1U) == INVALID_PARAMETER);
    assert(fbvbs_log_append(&state, 0U, 0U, 0U, 0U, payload, sizeof(payload)) == INVALID_PARAMETER);
}

static struct fbvbs_partition *find_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id
) {
    uint32_t index;

    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        if ((state->partitions[index].occupied || state->partitions[index].tombstone) &&
            state->partitions[index].partition_id == partition_id) {
            return &state->partitions[index];
        }
    }

    return NULL;
}

static struct fbvbs_partition *find_host_partition(struct fbvbs_hypervisor_state *state) {
    struct fbvbs_partition *host_partition = find_partition(state, 1U);

    assert(host_partition != NULL);
    assert(host_partition->kind == PARTITION_KIND_FREEBSD_HOST);
    return host_partition;
}

static struct fbvbs_manifest_profile *find_manifest_profile(
    struct fbvbs_hypervisor_state *state,
    uint8_t component_type,
    uint64_t object_id
) {
    uint32_t index;

    for (index = 0U; index < FBVBS_MAX_MANIFEST_PROFILES; ++index) {
        struct fbvbs_manifest_profile *profile = &state->manifest_profiles[index];

        if (profile->active &&
            profile->component_type == component_type &&
            profile->object_id == object_id) {
            return profile;
        }
    }

    return NULL;
}

static uint32_t manifest_profile_count(const struct fbvbs_hypervisor_state *state) {
    uint32_t index;
    uint32_t count = 0U;

    for (index = 0U; index < FBVBS_MAX_MANIFEST_PROFILES; ++index) {
        if (state->manifest_profiles[index].active) {
            count++;
        }
    }

    return count;
}

static struct fbvbs_command_page_v1 *prepare_host_command_page(
    struct fbvbs_hypervisor_state *state,
    uint16_t call_id,
    uint32_t input_length,
    uint32_t output_length_max
) {
    return prepare_partition_command_page(
        find_host_partition(state),
        0U,
        call_id,
        input_length,
        output_length_max
    );
}

static uint64_t host_callsite_for_call(
    const struct fbvbs_hypervisor_state *state,
    uint16_t call_id
) {
    switch (call_id) {
        case FBVBS_CALL_VM_CREATE:
        case FBVBS_CALL_VM_DESTROY:
        case FBVBS_CALL_VM_RUN:
        case FBVBS_CALL_VM_SET_REGISTER:
        case FBVBS_CALL_VM_GET_REGISTER:
        case FBVBS_CALL_VM_MAP_MEMORY:
        case FBVBS_CALL_VM_INJECT_INTERRUPT:
        case FBVBS_CALL_VM_ASSIGN_DEVICE:
        case FBVBS_CALL_VM_RELEASE_DEVICE:
        case FBVBS_CALL_VM_GET_VCPU_STATUS:
            return fbvbs_primary_host_callsite(state, FBVBS_HOST_CALLER_CLASS_VMM);
        default:
            return fbvbs_primary_host_callsite(state, FBVBS_HOST_CALLER_CLASS_FBVBS);
    }
}

static struct fbvbs_command_page_v1 *prepare_host_dispatch_page(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_trap_registers *registers,
    uint16_t call_id,
    uint32_t input_length,
    uint32_t output_length_max
) {
    struct fbvbs_partition *host_partition = find_host_partition(state);
    struct fbvbs_command_page_v1 *page = prepare_host_command_page(
        state,
        call_id,
        input_length,
        output_length_max
    );

    host_partition->vcpus[0].rip = host_callsite_for_call(state, call_id);
    prepare_trap_registers(registers, page);
    return page;
}

static uint64_t test_profile_image_object_id(uint64_t memory_limit_bytes, uint64_t capability_mask) {
    if (memory_limit_bytes == FBVBS_PAGE_SIZE * 2U && capability_mask == 0x3FU) {
        return 0x1000U;
    }
    if (memory_limit_bytes == FBVBS_PAGE_SIZE * 2U && capability_mask == 0x1U) {
        return 0x1100U;
    }
    if (memory_limit_bytes == FBVBS_PAGE_SIZE * 3U && capability_mask == 0x1U) {
        return 0x1200U;
    }
    if (memory_limit_bytes == FBVBS_PAGE_SIZE * 4U && capability_mask == 0x1U) {
        return 0x1300U;
    }

    assert(!"unsupported trusted-service test profile");
    return 0U;
}

static uint64_t test_profile_manifest_object_id(uint64_t image_object_id) {
    switch (image_object_id) {
        case 0x1000U:
            return 0x2000U;
        case 0x1100U:
            return 0x2100U;
        case 0x1200U:
            return 0x2200U;
        case 0x1300U:
            return 0x2300U;
        case 0x1600U:
            return 0x2600U;
        default:
            assert(!"unsupported trusted-service manifest profile");
            return 0U;
    }
}

static uint64_t test_profile_entry_ip(uint64_t image_object_id) {
    switch (image_object_id) {
        case 0x1000U:
            return 0x400000U;
        case 0x1100U:
            return 0x401000U;
        case 0x1200U:
            return 0x402000U;
        case 0x1300U:
            return 0x403000U;
        case 0x1600U:
            return 0x404000U;
        default:
            assert(!"unsupported trusted-service entry profile");
            return 0U;
    }
}

static uint64_t test_profile_initial_sp(uint64_t image_object_id) {
    switch (image_object_id) {
        case 0x1000U:
            return 0x800000U;
        case 0x1100U:
            return 0x801000U;
        case 0x1200U:
            return 0x802000U;
        case 0x1300U:
            return 0x803000U;
        case 0x1600U:
            return 0x804000U;
        default:
            assert(!"unsupported trusted-service stack profile");
            return 0U;
    }
}

static uint64_t test_service_image_object_id(uint16_t service_kind) {
    switch (service_kind) {
        case SERVICE_KIND_KCI:
            return 0x1000U;
        case SERVICE_KIND_KSI:
            return 0x1100U;
        case SERVICE_KIND_IKS:
            return 0x1200U;
        case SERVICE_KIND_SKS:
            return 0x1300U;
        case SERVICE_KIND_UVS:
            return 0x1600U;
        default:
            assert(!"unsupported service kind");
            return 0U;
    }
}

static uint64_t test_service_memory_limit_bytes(uint16_t service_kind) {
    switch (service_kind) {
        case SERVICE_KIND_KCI:
            return FBVBS_PAGE_SIZE * 2U;
        case SERVICE_KIND_KSI:
            return FBVBS_PAGE_SIZE * 2U;
        case SERVICE_KIND_IKS:
            return FBVBS_PAGE_SIZE * 3U;
        case SERVICE_KIND_SKS:
            return FBVBS_PAGE_SIZE * 4U;
        case SERVICE_KIND_UVS:
            return FBVBS_PAGE_SIZE * 5U;
        default:
            assert(!"unsupported service memory profile");
            return 0U;
    }
}

static uint64_t test_service_capability_mask(uint16_t service_kind) {
    return (service_kind == SERVICE_KIND_KCI) ? 0x3FU : 0x1U;
}

static uint64_t test_guest_image_object_id(void) {
    return 0x1400U;
}

static uint64_t test_guest_manifest_object_id(uint64_t image_object_id) {
    switch (image_object_id) {
        case 0x1400U:
            return 0x2400U;
        case 0x1500U:
            return 0x2500U;
        default:
            assert(!"unsupported guest manifest profile");
            return 0U;
    }
}

static uint64_t test_guest_entry_ip(uint64_t image_object_id) {
    switch (image_object_id) {
        case 0x1400U:
            return 0x500000U;
        case 0x1500U:
            return 0x501000U;
        default:
            assert(!"unsupported guest entry profile");
            return 0U;
    }
}

static void test_partition_lifecycle(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 0x3FU,
        .image_object_id = 0x1000U,
    };
    struct fbvbs_partition_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;
    struct fbvbs_partition_load_image_request load;
    struct fbvbs_partition_status_response status;
    struct fbvbs_partition_recover_request recover;
    struct fbvbs_partition_fault_info_response fault_info;
    const struct fbvbs_log_record_v1 *fault_record;
    struct fbvbs_audit_partition_fault_event fault_event;
    struct fbvbs_partition *partition;

    fbvbs_hypervisor_init(&state);
    assert(fbvbs_partition_create(&state, &create, &created) == OK);

    measure.partition_id = created.partition_id;
    measure.image_object_id = create.image_object_id;
    measure.manifest_object_id = test_profile_manifest_object_id(create.image_object_id);
    approve_artifact_pair(&state, measure.image_object_id, measure.manifest_object_id);
    assert(fbvbs_partition_measure(&state, &measure, &measured) == OK);

    load.partition_id = created.partition_id;
    load.image_object_id = create.image_object_id;
    load.entry_ip = test_profile_entry_ip(create.image_object_id);
    load.initial_sp = test_profile_initial_sp(create.image_object_id);
    assert(fbvbs_partition_load_image(&state, &load) == OK);
    assert(fbvbs_partition_start(&state, created.partition_id) == OK);
    partition = find_partition(&state, created.partition_id);
    assert(partition != NULL);
    assert(partition->vcpus[0].rip == test_profile_entry_ip(create.image_object_id));
    assert(partition->vcpus[0].rsp == test_profile_initial_sp(create.image_object_id));
    assert(partition->vcpus[0].cr0 == 0x80010033U);
    assert(partition->vcpus[0].cr4 == 0x000006F0U);
    assert(fbvbs_partition_quiesce(&state, created.partition_id) == OK);
    assert(fbvbs_partition_resume(&state, created.partition_id) == OK);
    assert(fbvbs_partition_resume(&state, created.partition_id) == INVALID_STATE);

    assert(fbvbs_partition_fault(
        &state,
        created.partition_id,
        FAULT_CODE_PARTITION_INTERNAL,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        0xAAU,
        0xBBU
    ) == OK);
    assert(fbvbs_partition_get_fault_info(&state, created.partition_id, &fault_info) == OK);
    assert(fault_info.fault_code == FAULT_CODE_PARTITION_INTERNAL);
    assert(fault_info.fault_detail0 == 0xAAU);
    assert(fault_info.fault_detail1 == 0xBBU);
    fault_record = get_log_record(&state, 2U);
    assert(fault_record->event_code == FBVBS_EVENT_PARTITION_FAULT);
    assert(fault_record->payload_length == sizeof(fault_event));
    fbvbs_copy_memory(&fault_event, fault_record->payload, sizeof(fault_event));
    assert(fault_event.partition_id == created.partition_id);
    assert(fault_event.fault_code == FAULT_CODE_PARTITION_INTERNAL);
    assert(fault_event.source_component == FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR);
    assert(fault_event.detail0 == 0xAAU);
    assert(fault_event.detail1 == 0xBBU);

    recover.partition_id = created.partition_id;
    recover.recovery_flags = 0U;
    assert(fbvbs_partition_recover(&state, &recover) == OK);
    assert(partition->vcpus[0].state == FBVBS_VCPU_STATE_RUNNABLE);
    assert(partition->vcpus[0].cr0 == 0x80010033U);
    assert(partition->vcpus[0].cr4 == 0x000006F0U);
    assert(fbvbs_partition_get_status(&state, created.partition_id, &status) == OK);
    assert(status.state == FBVBS_PARTITION_STATE_RUNNABLE);
    assert(fbvbs_partition_destroy(&state, created.partition_id) == OK);
    assert(fbvbs_partition_get_status(&state, created.partition_id, &status) == OK);
    assert(status.state == FBVBS_PARTITION_STATE_DESTROYED);
}

static void test_dispatch_rejects_unzeroed_tail(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 1U,
        .image_object_id = 0x1100U,
    };

    fbvbs_hypervisor_init(&state);
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_PARTITION_CREATE,
        sizeof(create),
        sizeof(struct fbvbs_partition_create_response)
    );
    fbvbs_copy_memory(page->body, &create, sizeof(create));
    page->body[sizeof(create)] = 1U;

    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_PARAMETER);
    assert(page->command_state == FAILED);
}

static void test_dispatch_rejects_replayed_sequence(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 1U,
        .image_object_id = 0x1100U,
    };
    uint64_t accepted_sequence;

    fbvbs_hypervisor_init(&state);
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_PARTITION_CREATE,
        sizeof(create),
        sizeof(struct fbvbs_partition_create_response)
    );
    fbvbs_copy_memory(page->body, &create, sizeof(create));
    accepted_sequence = page->caller_sequence;
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_PARTITION_CREATE,
        sizeof(create),
        sizeof(struct fbvbs_partition_create_response)
    );
    page->caller_sequence = accepted_sequence;
    fbvbs_copy_memory(page->body, &create, sizeof(create));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == REPLAY_DETECTED);
    assert(page->command_state == FAILED);
}

static void test_dispatch_rejects_nonzero_actual_output_length(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;

    fbvbs_hypervisor_init(&state);
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_AUDIT_GET_BOOT_ID, 0U, 0U);
    page->actual_output_length = 8U;
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_PARAMETER);
    assert(page->command_state == FAILED);
}

static void test_dispatch_creates_partition_and_reports_status(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 1U,
        .image_object_id = 0x1100U,
    };
    struct fbvbs_partition_create_response created;
    struct fbvbs_partition_status_response status;

    fbvbs_hypervisor_init(&state);
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_PARTITION_CREATE,
        sizeof(create),
        sizeof(created)
    );
    fbvbs_copy_memory(page->body, &create, sizeof(create));

    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&created, page->body, sizeof(created));
    assert(created.partition_id != 0U);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_PARTITION_GET_STATUS,
        sizeof(struct fbvbs_partition_id_request),
        sizeof(status)
    );
    ((struct fbvbs_partition_id_request *)page->body)->partition_id = created.partition_id;

    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&status, page->body, sizeof(status));
    assert(status.state == FBVBS_PARTITION_STATE_CREATED);
}

static void test_partition_create_rejects_manifest_profile_mismatch(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 4U,
        .capability_mask = 0x1U,
        .image_object_id = 0x1100U,
    };
    struct fbvbs_partition_create_response created;

    fbvbs_hypervisor_init(&state);
    assert(fbvbs_partition_create(&state, &create, &created) == INVALID_PARAMETER);
}

static void test_partition_measure_rejects_non_derived_manifest(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 0x1U,
        .image_object_id = 0x1100U,
    };
    struct fbvbs_partition_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;

    fbvbs_hypervisor_init(&state);
    assert(fbvbs_partition_create(&state, &create, &created) == OK);

    measure.partition_id = created.partition_id;
    measure.image_object_id = create.image_object_id;
    measure.manifest_object_id = 0x2200U;
    assert(fbvbs_partition_measure(&state, &measure, &measured) == MEASUREMENT_FAILED);
}

static void test_partition_measure_requires_uvs_approval(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 0x3FU,
        .image_object_id = 0x1000U,
    };
    struct fbvbs_partition_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;

    fbvbs_hypervisor_init(&state);
    assert(fbvbs_partition_create(&state, &create, &created) == OK);

    measure.partition_id = created.partition_id;
    measure.image_object_id = create.image_object_id;
    measure.manifest_object_id = test_profile_manifest_object_id(create.image_object_id);
    assert(fbvbs_partition_measure(&state, &measure, &measured) == SIGNATURE_INVALID);

    approve_artifact_pair(&state, measure.image_object_id, measure.manifest_object_id);
    assert(fbvbs_partition_measure(&state, &measure, &measured) == OK);
}

static void test_uvs_manifest_set_detects_metadata_failures(void) {
    struct fbvbs_hypervisor_state state;
    struct aligned_metadata_bundle bundle;
    struct fbvbs_uvs_verify_manifest_set_request request;
    struct fbvbs_uvs_verify_manifest_set_response response;

    fbvbs_hypervisor_init(&state);

    prepare_valid_metadata_bundle(&bundle, 0x2000U);
    prepare_metadata_set_request(&bundle, &request);
    assert(fbvbs_uvs_verify_manifest_set(&state, &request, &response) == OK);
    assert(response.verdict == 1U);
    assert(response.failure_bitmap == 0U);
    assert(response.verified_manifest_set_id != 0U);

    prepare_valid_metadata_bundle(&bundle, 0x2000U);
    bundle.manifests[0].flags |= FBVBS_METADATA_FLAG_REVOKED;
    prepare_metadata_set_request(&bundle, &request);
    assert(fbvbs_uvs_verify_manifest_set(&state, &request, &response) == REVOKED);
    assert(response.verdict == 0U);
    assert(response.failure_bitmap == FBVBS_UVS_FAILURE_REVOCATION);
    assert(response.verified_manifest_set_id == 0U);

    prepare_valid_metadata_bundle(&bundle, 0x2000U);
    bundle.manifests[1].expected_generation = 2U;
    prepare_metadata_set_request(&bundle, &request);
    assert(fbvbs_uvs_verify_manifest_set(&state, &request, &response) == GENERATION_MISMATCH);
    assert(response.failure_bitmap == FBVBS_UVS_FAILURE_GENERATION);

    prepare_valid_metadata_bundle(&bundle, 0x2000U);
    bundle.manifests[1].minimum_generation = 2U;
    prepare_metadata_set_request(&bundle, &request);
    assert(fbvbs_uvs_verify_manifest_set(&state, &request, &response) == ROLLBACK_DETECTED);
    assert(response.failure_bitmap == FBVBS_UVS_FAILURE_ROLLBACK);

    prepare_valid_metadata_bundle(&bundle, 0x2000U);
    bundle.manifests[2].dependency_object_id = 0xDEADBEEFU;
    prepare_metadata_set_request(&bundle, &request);
    assert(fbvbs_uvs_verify_manifest_set(&state, &request, &response) == DEPENDENCY_UNSATISFIED);
    assert(response.failure_bitmap == FBVBS_UVS_FAILURE_DEPENDENCY);

    prepare_valid_metadata_bundle(&bundle, 0x2000U);
    bundle.manifests[4].snapshot_id[0] ^= 0xFFU;
    prepare_metadata_set_request(&bundle, &request);
    assert(fbvbs_uvs_verify_manifest_set(&state, &request, &response) == SNAPSHOT_INCONSISTENT);
    assert(response.failure_bitmap == FBVBS_UVS_FAILURE_SNAPSHOT);

    prepare_valid_metadata_bundle(&bundle, 0x2000U);
    bundle.manifests[3].expires_at_seconds = 600U;
    prepare_metadata_set_request(&bundle, &request);
    assert(fbvbs_uvs_verify_manifest_set(&state, &request, &response) == FRESHNESS_FAILED);
    assert(response.failure_bitmap == FBVBS_UVS_FAILURE_FRESHNESS);
}

static void test_dispatch_uvs_manifest_set_failure_returns_structured_body(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct aligned_metadata_bundle bundle;
    struct fbvbs_uvs_verify_manifest_set_request request;
    struct fbvbs_uvs_verify_manifest_set_response response;

    fbvbs_hypervisor_init(&state);
    prepare_valid_metadata_bundle(&bundle, 0x2000U);
    bundle.manifests[0].flags |= FBVBS_METADATA_FLAG_REVOKED;
    prepare_metadata_set_request(&bundle, &request);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_UVS_VERIFY_MANIFEST_SET,
        sizeof(request),
        sizeof(response)
    );
    fbvbs_copy_memory(page->body, &request, sizeof(request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == REVOKED);
    assert(page->actual_output_length == sizeof(response));
    fbvbs_copy_memory(&response, page->body, sizeof(response));
    assert(response.verdict == 0U);
    assert(response.failure_bitmap == FBVBS_UVS_FAILURE_REVOCATION);
    assert(response.verified_manifest_set_id == 0U);
}

static void test_uvs_check_revocation_reports_recorded_objects(void) {
    struct fbvbs_hypervisor_state state;
    struct aligned_metadata_bundle bundle;
    struct fbvbs_uvs_verify_manifest_set_request verify_manifest_set;
    struct fbvbs_uvs_verify_manifest_set_response manifest_set_response;
    struct fbvbs_uvs_check_revocation_request check_revocation = {
        .object_id = 0x2000U,
        .object_type = 1U,
        .reserved0 = 0U,
    };
    struct fbvbs_uvs_check_revocation_response response;

    fbvbs_hypervisor_init(&state);
    prepare_valid_metadata_bundle(&bundle, 0x2000U);
    bundle.manifests[0].flags |= FBVBS_METADATA_FLAG_REVOKED;
    prepare_metadata_set_request(&bundle, &verify_manifest_set);
    assert(fbvbs_uvs_verify_manifest_set(&state, &verify_manifest_set, &manifest_set_response) == REVOKED);
    assert(fbvbs_uvs_check_revocation(&state, &check_revocation, &response) == OK);
    assert(response.revoked == 1U);
}

static void test_partition_load_rejects_manifest_profile_mismatch(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 0x1U,
        .image_object_id = 0x1100U,
    };
    struct fbvbs_partition_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;
    struct fbvbs_partition_load_image_request load;

    fbvbs_hypervisor_init(&state);
    assert(fbvbs_partition_create(&state, &create, &created) == OK);

    measure.partition_id = created.partition_id;
    measure.image_object_id = create.image_object_id;
    measure.manifest_object_id = test_profile_manifest_object_id(create.image_object_id);
    approve_artifact_pair(&state, measure.image_object_id, measure.manifest_object_id);
    assert(fbvbs_partition_measure(&state, &measure, &measured) == OK);

    load.partition_id = created.partition_id;
    load.image_object_id = create.image_object_id;
    load.entry_ip = test_profile_entry_ip(create.image_object_id);
    load.initial_sp = test_profile_initial_sp(create.image_object_id) + FBVBS_PAGE_SIZE;
    assert(fbvbs_partition_load_image(&state, &load) == MEASUREMENT_FAILED);
}

static void test_guest_vm_measure_rejects_trusted_service_artifact(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_create_request create = {
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 3U,
        .vcpu_count = 1U,
        .vm_flags = VM_FLAG_NESTED_VIRT_DISABLED,
    };
    struct fbvbs_vm_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;

    fbvbs_hypervisor_init(&state);
    assert(fbvbs_vm_create(&state, &create, &created) == OK);

    measure.partition_id = created.vm_partition_id;
    measure.image_object_id = 0x1000U;
    measure.manifest_object_id = 0x2000U;
    assert(fbvbs_partition_measure(&state, &measure, &measured) == MEASUREMENT_FAILED);
}

static void test_guest_vm_load_uses_manifest_entry_and_requires_stack(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_create_request create = {
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 3U,
        .vcpu_count = 1U,
        .vm_flags = VM_FLAG_NESTED_VIRT_DISABLED,
    };
    struct fbvbs_vm_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;
    struct fbvbs_partition_load_image_request load;
    struct fbvbs_partition *partition;

    fbvbs_hypervisor_init(&state);
    assert(fbvbs_vm_create(&state, &create, &created) == OK);

    measure.partition_id = created.vm_partition_id;
    measure.image_object_id = test_guest_image_object_id();
    measure.manifest_object_id = test_guest_manifest_object_id(measure.image_object_id);
    approve_artifact_pair(&state, measure.image_object_id, measure.manifest_object_id);
    assert(fbvbs_partition_measure(&state, &measure, &measured) == OK);

    load.partition_id = created.vm_partition_id;
    load.image_object_id = measure.image_object_id;
    load.entry_ip = 0U;
    load.initial_sp = 0U;
    assert(fbvbs_partition_load_image(&state, &load) == INVALID_PARAMETER);

    load.initial_sp = 0x900000U;
    assert(fbvbs_partition_load_image(&state, &load) == OK);
    partition = find_partition(&state, created.vm_partition_id);
    assert(partition != NULL);
    assert(partition->entry_ip == test_guest_entry_ip(load.image_object_id));
    assert(partition->initial_sp == load.initial_sp);
}

static void test_trusted_service_load_allows_manifest_defaults(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 0x1U,
        .image_object_id = 0x1100U,
    };
    struct fbvbs_partition_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;
    struct fbvbs_partition_load_image_request load;
    struct fbvbs_partition *partition;

    fbvbs_hypervisor_init(&state);
    assert(fbvbs_partition_create(&state, &create, &created) == OK);

    measure.partition_id = created.partition_id;
    measure.image_object_id = create.image_object_id;
    measure.manifest_object_id = test_profile_manifest_object_id(create.image_object_id);
    approve_artifact_pair(&state, measure.image_object_id, measure.manifest_object_id);
    assert(fbvbs_partition_measure(&state, &measure, &measured) == OK);

    load.partition_id = created.partition_id;
    load.image_object_id = create.image_object_id;
    load.entry_ip = 0U;
    load.initial_sp = 0U;
    assert(fbvbs_partition_load_image(&state, &load) == OK);
    partition = find_partition(&state, created.partition_id);
    assert(partition != NULL);
    assert(partition->entry_ip == test_profile_entry_ip(create.image_object_id));
    assert(partition->initial_sp == test_profile_initial_sp(create.image_object_id));
}

static void test_manifest_profiles_drive_partition_create_and_load(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_artifact_catalog_entry catalog_entries[FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES];
    struct fbvbs_manifest_profile profiles[FBVBS_MAX_MANIFEST_PROFILES];
    struct fbvbs_manifest_profile *profile;
    uint32_t profile_count;
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 0x3FU,
        .image_object_id = 0x1000U,
    };
    struct fbvbs_partition_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;
    struct fbvbs_partition_load_image_request load;
    struct fbvbs_partition *partition;

    fbvbs_hypervisor_init(&state);
    profile_count = manifest_profile_count(&state);
    fbvbs_copy_memory(catalog_entries, state.artifact_catalog.entries, sizeof(catalog_entries));
    fbvbs_copy_memory(profiles, state.manifest_profiles, sizeof(profiles));
    profile = find_manifest_profile(&state, FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE, create.image_object_id);
    assert(profile != NULL);
    profiles[profile - state.manifest_profiles].memory_limit_bytes = FBVBS_PAGE_SIZE * 6U;
    profiles[profile - state.manifest_profiles].entry_ip = 0x600000U;
    profiles[profile - state.manifest_profiles].initial_sp = 0xA00000U;
    assert(fbvbs_ingest_boot_catalog(
        &state,
        catalog_entries,
        state.artifact_catalog.count,
        profiles,
        profile_count
    ) == OK);
    profile = find_manifest_profile(&state, FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE, create.image_object_id);
    assert(profile != NULL);

    assert(fbvbs_partition_create(&state, &create, &created) == INVALID_PARAMETER);

    create.memory_limit_bytes = profile->memory_limit_bytes;
    assert(fbvbs_partition_create(&state, &create, &created) == OK);

    measure.partition_id = created.partition_id;
    measure.image_object_id = create.image_object_id;
    measure.manifest_object_id = profile->manifest_object_id;
    approve_artifact_pair(&state, measure.image_object_id, measure.manifest_object_id);
    assert(fbvbs_partition_measure(&state, &measure, &measured) == OK);

    load.partition_id = created.partition_id;
    load.image_object_id = create.image_object_id;
    load.entry_ip = 0U;
    load.initial_sp = 0U;
    assert(fbvbs_partition_load_image(&state, &load) == OK);
    partition = find_partition(&state, created.partition_id);
    assert(partition != NULL);
    assert(partition->entry_ip == profile->entry_ip);
    assert(partition->initial_sp == profile->initial_sp);
}

static void test_boot_catalog_ingestion_rejects_invalid_related_index(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_artifact_catalog_entry catalog_entries[FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES];
    struct fbvbs_manifest_profile profiles[FBVBS_MAX_MANIFEST_PROFILES];
    uint64_t original_primary_callsite;
    uint32_t profile_count;

    fbvbs_hypervisor_init(&state);
    profile_count = manifest_profile_count(&state);
    fbvbs_copy_memory(catalog_entries, state.artifact_catalog.entries, sizeof(catalog_entries));
    fbvbs_copy_memory(profiles, state.manifest_profiles, sizeof(profiles));
    original_primary_callsite = fbvbs_primary_host_callsite(&state, FBVBS_HOST_CALLER_CLASS_FBVBS);

    catalog_entries[0].related_index = 4U;
    assert(fbvbs_ingest_boot_catalog(
        &state,
        catalog_entries,
        state.artifact_catalog.count,
        profiles,
        profile_count
    ) == INVALID_PARAMETER);
    assert(state.artifact_catalog.entries[0].related_index == 1U);
    assert(fbvbs_primary_host_callsite(&state, FBVBS_HOST_CALLER_CLASS_FBVBS) == original_primary_callsite);
}

static void test_dispatch_memory_allocate_and_release(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_memory_allocate_object_request allocate = {
        .size = FBVBS_PAGE_SIZE,
        .object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE,
        .reserved0 = 0U,
    };
    struct fbvbs_memory_allocate_object_response allocated;
    struct fbvbs_memory_object_id_request release;

    fbvbs_hypervisor_init(&state);
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_MEMORY_ALLOCATE_OBJECT,
        sizeof(allocate),
        sizeof(allocated)
    );
    fbvbs_copy_memory(page->body, &allocate, sizeof(allocate));

    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&allocated, page->body, sizeof(allocated));
    assert(allocated.memory_object_id != 0U);

    release.memory_object_id = allocated.memory_object_id;
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_MEMORY_RELEASE_OBJECT,
        sizeof(release),
        0U
    );
    fbvbs_copy_memory(page->body, &release, sizeof(release));

    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
}

static uint64_t create_trusted_service_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_limit_bytes,
    uint64_t capability_mask
) {
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = memory_limit_bytes,
        .capability_mask = capability_mask,
        .image_object_id = 0U,
    };
    struct fbvbs_partition_create_response created;

    create.image_object_id = test_profile_image_object_id(memory_limit_bytes, capability_mask);
    assert(fbvbs_partition_create(state, &create, &created) == OK);
    return created.partition_id;
}

static void approve_artifact_pair(
    struct fbvbs_hypervisor_state *state,
    uint64_t artifact_object_id,
    uint64_t manifest_object_id
) {
    struct aligned_metadata_bundle metadata_bundle;
    struct fbvbs_uvs_verify_manifest_set_request verify_manifest_set;
    struct fbvbs_uvs_verify_manifest_set_response manifest_set_response;
    struct fbvbs_uvs_verify_artifact_request verify_artifact;
    struct fbvbs_verdict_response verdict;
    const struct fbvbs_artifact_catalog_entry *artifact_entry = NULL;
    uint32_t index;

    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        if (state->artifact_catalog.entries[index].object_id == artifact_object_id) {
            artifact_entry = &state->artifact_catalog.entries[index];
            break;
        }
    }
    assert(artifact_entry != NULL);

    prepare_valid_metadata_bundle(&metadata_bundle, manifest_object_id);
    prepare_metadata_set_request(&metadata_bundle, &verify_manifest_set);
    assert(fbvbs_uvs_verify_manifest_set(state, &verify_manifest_set, &manifest_set_response) == OK);
    fbvbs_zero_memory(&verify_artifact, sizeof(verify_artifact));
    fbvbs_copy_memory(verify_artifact.artifact_hash, artifact_entry->payload_hash, 48U);
    verify_artifact.verified_manifest_set_id = manifest_set_response.verified_manifest_set_id;
    verify_artifact.manifest_object_id = manifest_object_id;
    assert(fbvbs_uvs_verify_artifact(state, &verify_artifact, &verdict) == OK);
    assert(verdict.verdict == 1U);
}

static uint64_t create_measured_service_partition(
    struct fbvbs_hypervisor_state *state,
    uint16_t service_kind
) {
    struct fbvbs_partition_create_request create = {
        .kind = PARTITION_KIND_TRUSTED_SERVICE,
        .flags = 0U,
        .vcpu_count = 1U,
        .memory_limit_bytes = test_service_memory_limit_bytes(service_kind),
        .capability_mask = test_service_capability_mask(service_kind),
        .image_object_id = test_service_image_object_id(service_kind),
    };
    struct fbvbs_partition_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;

    assert(fbvbs_partition_create(state, &create, &created) == OK);
    measure.partition_id = created.partition_id;
    measure.image_object_id = create.image_object_id;
    measure.manifest_object_id = test_profile_manifest_object_id(create.image_object_id);
    approve_artifact_pair(state, measure.image_object_id, measure.manifest_object_id);
    assert(fbvbs_partition_measure(state, &measure, &measured) == OK);
    return created.partition_id;
}

static uint64_t create_runnable_vm_with_vcpus(
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_limit_bytes,
    uint32_t vcpu_count
);

static uint64_t create_runnable_vm(
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_limit_bytes
) {
    return create_runnable_vm_with_vcpus(state, memory_limit_bytes, 1U);
}

static uint64_t create_runnable_vm_with_vcpus(
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_limit_bytes,
    uint32_t vcpu_count
) {
    struct fbvbs_vm_create_request create = {
        .memory_limit_bytes = memory_limit_bytes,
        .vcpu_count = vcpu_count,
        .vm_flags = VM_FLAG_NESTED_VIRT_DISABLED,
    };
    struct fbvbs_vm_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;
    struct fbvbs_partition_load_image_request load;
    uint64_t image_object_id = test_guest_image_object_id();

    assert(fbvbs_vm_create(state, &create, &created) == OK);
    measure.partition_id = created.vm_partition_id;
    measure.image_object_id = image_object_id;
    measure.manifest_object_id = test_guest_manifest_object_id(image_object_id);
    approve_artifact_pair(state, measure.image_object_id, measure.manifest_object_id);
    assert(fbvbs_partition_measure(state, &measure, &measured) == OK);
    load.partition_id = created.vm_partition_id;
    load.image_object_id = image_object_id;
    load.entry_ip = test_guest_entry_ip(image_object_id);
    load.initial_sp = 0x800000U;
    assert(fbvbs_partition_load_image(state, &load) == OK);
    assert(fbvbs_partition_start(state, created.vm_partition_id) == OK);
    return created.vm_partition_id;
}

static uint64_t allocate_memory_object(
    struct fbvbs_hypervisor_state *state,
    uint32_t object_flags
) {
    struct fbvbs_memory_allocate_object_request request = {
        .size = FBVBS_PAGE_SIZE,
        .object_flags = object_flags,
        .reserved0 = 0U,
    };
    struct fbvbs_memory_allocate_object_response response;

    assert(fbvbs_memory_allocate_object(state, &request, &response) == OK);
    return response.memory_object_id;
}

static void test_dispatch_memory_mapping_and_shared_calls(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_memory_map_request map_request;
    struct fbvbs_memory_set_permission_request set_permission;
    struct fbvbs_memory_register_shared_request register_shared;
    struct fbvbs_memory_register_shared_response shared_response;
    struct fbvbs_memory_unmap_request unmap_request;
    struct fbvbs_shared_object_id_request unregister_request;
    struct fbvbs_memory_object_id_request release_request;
    struct fbvbs_partition *partition;
    uint64_t partition_id;
    uint64_t memory_object_id;

    fbvbs_hypervisor_init(&state);
    partition_id = create_trusted_service_partition(&state, FBVBS_PAGE_SIZE * 4U, 1U);
    partition = find_partition(&state, partition_id);
    assert(partition != NULL);
    memory_object_id = allocate_memory_object(&state, FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE);

    map_request.partition_id = partition_id;
    map_request.memory_object_id = memory_object_id;
    map_request.guest_physical_address = 0x9000U;
    map_request.size = FBVBS_PAGE_SIZE;
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;
    map_request.reserved0 = 0U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_MEMORY_MAP, sizeof(map_request), 0U);
    fbvbs_copy_memory(page->body, &map_request, sizeof(map_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    map_request.permissions = FBVBS_MEMORY_PERMISSION_WRITE | FBVBS_MEMORY_PERMISSION_EXECUTE;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_MEMORY_MAP, sizeof(map_request), 0U);
    fbvbs_copy_memory(page->body, &map_request, sizeof(map_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_PARAMETER);
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;

    set_permission.target_partition_id = partition_id;
    set_permission.guest_physical_address = map_request.guest_physical_address;
    set_permission.size = map_request.size;
    set_permission.permissions = FBVBS_MEMORY_PERMISSION_READ;
    set_permission.reserved0 = 0U;
    page = prepare_partition_command_page(
        partition,
        0U,
        FBVBS_CALL_MEMORY_SET_PERMISSION,
        sizeof(set_permission),
        0U
    );
    fbvbs_copy_memory(page->body, &set_permission, sizeof(set_permission));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_MEMORY_SET_PERMISSION,
        sizeof(set_permission),
        0U
    );
    fbvbs_copy_memory(page->body, &set_permission, sizeof(set_permission));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_CALLER);

    set_permission.permissions = FBVBS_MEMORY_PERMISSION_WRITE | FBVBS_MEMORY_PERMISSION_EXECUTE;
    page = prepare_partition_command_page(
        partition,
        0U,
        FBVBS_CALL_MEMORY_SET_PERMISSION,
        sizeof(set_permission),
        0U
    );
    fbvbs_copy_memory(page->body, &set_permission, sizeof(set_permission));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_PARAMETER);
    set_permission.permissions = FBVBS_MEMORY_PERMISSION_READ;

    register_shared.memory_object_id = memory_object_id;
    register_shared.size = FBVBS_PAGE_SIZE;
    register_shared.peer_partition_id = partition_id;
    register_shared.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    register_shared.reserved0 = 0U;
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_MEMORY_REGISTER_SHARED,
        sizeof(register_shared),
        sizeof(shared_response)
    );
    fbvbs_copy_memory(page->body, &register_shared, sizeof(register_shared));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&shared_response, page->body, sizeof(shared_response));
    assert(shared_response.shared_object_id != 0U);
    assert(partition->mapped_bytes == FBVBS_PAGE_SIZE * 4U);

    unregister_request.shared_object_id = shared_response.shared_object_id;
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_MEMORY_UNREGISTER_SHARED,
        sizeof(unregister_request),
        0U
    );
    fbvbs_copy_memory(page->body, &unregister_request, sizeof(unregister_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == RESOURCE_BUSY);

    unmap_request.partition_id = partition_id;
    unmap_request.guest_physical_address = map_request.guest_physical_address;
    unmap_request.size = map_request.size;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_MEMORY_UNMAP, sizeof(unmap_request), 0U);
    fbvbs_copy_memory(page->body, &unmap_request, sizeof(unmap_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_MEMORY_UNREGISTER_SHARED,
        sizeof(unregister_request),
        0U
    );
    fbvbs_copy_memory(page->body, &unregister_request, sizeof(unregister_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    assert(partition->mapped_bytes == FBVBS_PAGE_SIZE * 2U);

    release_request.memory_object_id = memory_object_id;
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_MEMORY_RELEASE_OBJECT,
        sizeof(release_request),
        0U
    );
    fbvbs_copy_memory(page->body, &release_request, sizeof(release_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
}

static void test_shared_registration_charges_peer_limit_and_reserved_peer_zero(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request register_shared;
    struct fbvbs_memory_register_shared_response shared_response;
    struct fbvbs_partition *peer_partition;
    uint64_t peer_partition_id;
    uint64_t memory_object_id;

    fbvbs_hypervisor_init(&state);
    peer_partition_id = create_trusted_service_partition(&state, FBVBS_PAGE_SIZE * 2U, 1U);
    peer_partition = find_partition(&state, peer_partition_id);
    assert(peer_partition != NULL);
    memory_object_id = allocate_memory_object(&state, FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE);

    register_shared.memory_object_id = memory_object_id;
    register_shared.size = FBVBS_PAGE_SIZE;
    register_shared.peer_partition_id = peer_partition_id;
    register_shared.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    register_shared.reserved0 = 0U;
    assert(fbvbs_memory_register_shared(&state, &register_shared, &shared_response) == RESOURCE_EXHAUSTED);
    assert(peer_partition->mapped_bytes == FBVBS_PAGE_SIZE * 2U);

    register_shared.peer_partition_id = 0U;
    assert(fbvbs_memory_register_shared(&state, &register_shared, &shared_response) == OK);
    assert(fbvbs_memory_unregister_shared(&state, shared_response.shared_object_id) == OK);
}

static void test_dispatch_vm_register_and_status_calls(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_vm_create_request create = {
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 3U,
        .vcpu_count = 2U,
        .vm_flags = VM_FLAG_NESTED_VIRT_DISABLED,
    };
    struct fbvbs_vm_create_response created;
    struct fbvbs_partition_measure_request measure;
    struct fbvbs_partition_measure_response measured;
    struct fbvbs_partition_load_image_request load;
    struct fbvbs_vm_vcpu_status_request status_request;
    struct fbvbs_vm_vcpu_status_response status;
    struct fbvbs_vm_register_request set_register;
    struct fbvbs_vm_register_read_request get_register;
    struct fbvbs_vm_register_response register_value;

    fbvbs_hypervisor_init(&state);
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_CREATE, sizeof(create), sizeof(created));
    fbvbs_copy_memory(page->body, &create, sizeof(create));

    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&created, page->body, sizeof(created));
    assert(created.vm_partition_id != 0U);

    measure.partition_id = created.vm_partition_id;
    measure.image_object_id = test_guest_image_object_id();
    measure.manifest_object_id = test_guest_manifest_object_id(measure.image_object_id);
    approve_artifact_pair(&state, measure.image_object_id, measure.manifest_object_id);
    assert(fbvbs_partition_measure(&state, &measure, &measured) == OK);

    load.partition_id = created.vm_partition_id;
    load.image_object_id = measure.image_object_id;
    load.entry_ip = test_guest_entry_ip(load.image_object_id);
    load.initial_sp = 0x800000U;
    assert(fbvbs_partition_load_image(&state, &load) == OK);
    assert(fbvbs_partition_start(&state, created.vm_partition_id) == OK);

    status_request.vm_partition_id = created.vm_partition_id;
    status_request.vcpu_id = 0U;
    status_request.reserved0 = 0U;
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_VM_GET_VCPU_STATUS,
        sizeof(status_request),
        sizeof(status)
    );
    fbvbs_copy_memory(page->body, &status_request, sizeof(status_request));

    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&status, page->body, sizeof(status));
    assert(status.vcpu_state == FBVBS_VCPU_STATE_RUNNABLE);

    set_register.vm_partition_id = created.vm_partition_id;
    set_register.vcpu_id = 0U;
    set_register.register_id = VM_REG_RIP;
    set_register.value = 0x401000U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_SET_REGISTER, sizeof(set_register), 0U);
    fbvbs_copy_memory(page->body, &set_register, sizeof(set_register));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    get_register.vm_partition_id = created.vm_partition_id;
    get_register.vcpu_id = 0U;
    get_register.register_id = VM_REG_RIP;
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_VM_GET_REGISTER,
        sizeof(get_register),
        sizeof(register_value)
    );
    fbvbs_copy_memory(page->body, &get_register, sizeof(get_register));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&register_value, page->body, sizeof(register_value));
    assert(register_value.value == 0x401000U);
}

static void test_dispatch_vm_run_memory_and_device_calls(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_vm_run_request run_request;
    struct fbvbs_vm_run_response run_response;
    struct fbvbs_vm_inject_interrupt_request inject_request;
    struct fbvbs_partition_fault_info_response fault_info;
    struct fbvbs_partition_recover_request recover_request;
    struct fbvbs_vm_exit_mmio mmio_exit;
    struct fbvbs_vm_exit_pio pio_exit;
    struct fbvbs_vm_vcpu_status_request status_request;
    struct fbvbs_vm_vcpu_status_response status_response;
    struct fbvbs_vm_map_memory_request map_request;
    struct fbvbs_vm_register_request set_register;
    struct fbvbs_vm_device_request device_request;
    struct fbvbs_vm_exit_cr_access cr_access_exit;
    struct fbvbs_vm_exit_external_interrupt interrupt_exit;
    struct fbvbs_vm_exit_msr_access msr_access_exit;
    struct fbvbs_partition *vm_partition = NULL;
    uint64_t vm_partition_id;
    uint64_t guest_memory_object_id;
    uint32_t index;

    fbvbs_hypervisor_init(&state);
    vm_partition_id = create_runnable_vm(&state, FBVBS_PAGE_SIZE * 4U);
    guest_memory_object_id = allocate_memory_object(&state, FBVBS_MEMORY_OBJECT_FLAG_GUEST_MEMORY);
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        if (state.partitions[index].occupied && state.partitions[index].partition_id == vm_partition_id) {
            vm_partition = &state.partitions[index];
            break;
        }
    }
    assert(vm_partition != NULL);

    map_request.vm_partition_id = vm_partition_id;
    map_request.memory_object_id = guest_memory_object_id;
    map_request.guest_physical_address = 0x200000U;
    map_request.size = FBVBS_PAGE_SIZE;
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;
    map_request.reserved0 = 0U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_MAP_MEMORY, sizeof(map_request), 0U);
    fbvbs_copy_memory(page->body, &map_request, sizeof(map_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    device_request.vm_partition_id = vm_partition_id;
    device_request.device_id = 0xD000U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_ASSIGN_DEVICE, sizeof(device_request), 0U);
    fbvbs_copy_memory(page->body, &device_request, sizeof(device_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    run_request.vm_partition_id = vm_partition_id;
    run_request.vcpu_id = 0U;
    run_request.run_flags = VM_RUN_FLAG_NONE;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_RUN, sizeof(run_request), sizeof(run_response));
    fbvbs_copy_memory(page->body, &run_request, sizeof(run_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&run_response, page->body, sizeof(run_response));
    assert(run_response.exit_reason == FBVBS_VM_EXIT_REASON_HALT);
    assert(run_response.exit_length == 0U);

    status_request.vm_partition_id = vm_partition_id;
    status_request.vcpu_id = 0U;
    status_request.reserved0 = 0U;
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_VM_GET_VCPU_STATUS,
        sizeof(status_request),
        sizeof(status_response)
    );
    fbvbs_copy_memory(page->body, &status_request, sizeof(status_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&status_response, page->body, sizeof(status_response));
    assert(status_response.vcpu_state == FBVBS_VCPU_STATE_BLOCKED);

    inject_request.vm_partition_id = vm_partition_id;
    inject_request.vcpu_id = 0U;
    inject_request.vector = 32U;
    inject_request.delivery_mode = FBVBS_VM_DELIVERY_FIXED;
    inject_request.reserved0 = 0U;
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_VM_INJECT_INTERRUPT,
        sizeof(inject_request),
        0U
    );
    fbvbs_copy_memory(page->body, &inject_request, sizeof(inject_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_RUN, sizeof(run_request), sizeof(run_response));
    fbvbs_copy_memory(page->body, &run_request, sizeof(run_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&run_response, page->body, sizeof(run_response));
    assert(run_response.exit_reason == FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT);
    assert(run_response.exit_length == sizeof(interrupt_exit));
    fbvbs_copy_memory(&interrupt_exit, run_response.exit_payload, sizeof(interrupt_exit));
    assert(interrupt_exit.vector == 32U);

    state.pinned_cr0_mask = 0x1U;
    vm_partition->vcpus[0].cr0 = 0U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_RUN, sizeof(run_request), sizeof(run_response));
    fbvbs_copy_memory(page->body, &run_request, sizeof(run_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&run_response, page->body, sizeof(run_response));
    assert(run_response.exit_reason == FBVBS_VM_EXIT_REASON_CR_ACCESS);
    assert(run_response.exit_length == sizeof(cr_access_exit));
    fbvbs_copy_memory(&cr_access_exit, run_response.exit_payload, sizeof(cr_access_exit));
    assert(cr_access_exit.cr_number == 0U);
    assert(cr_access_exit.access_type == FBVBS_VM_CR_ACCESS_WRITE);

    state.pinned_cr0_mask = 0U;
    state.intercepted_msrs[0] = 0xC0000080U;
    state.intercepted_msr_count = 1U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_RUN, sizeof(run_request), sizeof(run_response));
    fbvbs_copy_memory(page->body, &run_request, sizeof(run_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&run_response, page->body, sizeof(run_response));
    assert(run_response.exit_reason == FBVBS_VM_EXIT_REASON_MSR_ACCESS);
    assert(run_response.exit_length == sizeof(msr_access_exit));
    fbvbs_copy_memory(&msr_access_exit, run_response.exit_payload, sizeof(msr_access_exit));
    assert(msr_access_exit.msr_address == 0xC0000080U);
    assert(msr_access_exit.access_type == FBVBS_VM_MSR_ACCESS_WRITE);
    state.intercepted_msr_count = 0U;

    {
        struct fbvbs_vmx_leaf_exit leaf_exit;
        struct fbvbs_vcpu leaf_vcpu = vm_partition->vcpus[0];

        leaf_vcpu.rip = FBVBS_SYNTHETIC_EXIT_RIP_PIO;
        leaf_vcpu.rsp = 0x3F8U;
        leaf_vcpu.rflags = 0x1U;
        assert(
            fbvbs_vmx_leaf_run_vcpu(
                &state.vmx_caps,
                &leaf_vcpu,
                0U,
                0U,
                NULL,
                0U,
                vm_partition->mapped_bytes,
                &leaf_exit
            ) == OK
        );
        assert(leaf_exit.exit_reason == FBVBS_VM_EXIT_REASON_PIO);
        assert(leaf_exit.port == 0x03F8U);
        assert(leaf_exit.access_size == 4U);
        assert(leaf_exit.is_write == 1U);
    }

    set_register.vm_partition_id = vm_partition_id;
    set_register.vcpu_id = 0U;
    set_register.register_id = VM_REG_RSP;
    set_register.value = 0x3F8U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_SET_REGISTER, sizeof(set_register), 0U);
    fbvbs_copy_memory(page->body, &set_register, sizeof(set_register));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    set_register.register_id = VM_REG_RFLAGS;
    set_register.value = 0x1235U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_SET_REGISTER, sizeof(set_register), 0U);
    fbvbs_copy_memory(page->body, &set_register, sizeof(set_register));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    set_register.register_id = VM_REG_RIP;
    set_register.value = FBVBS_SYNTHETIC_EXIT_RIP_PIO;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_SET_REGISTER, sizeof(set_register), 0U);
    fbvbs_copy_memory(page->body, &set_register, sizeof(set_register));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_RUN, sizeof(run_request), sizeof(run_response));
    fbvbs_copy_memory(page->body, &run_request, sizeof(run_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&run_response, page->body, sizeof(run_response));
    assert(run_response.exit_reason == FBVBS_VM_EXIT_REASON_PIO);
    assert(run_response.exit_length == sizeof(pio_exit));
    fbvbs_copy_memory(&pio_exit, run_response.exit_payload, sizeof(pio_exit));
    assert(pio_exit.port == 0x03F8U);
    assert(pio_exit.is_write == 1U);

    set_register.register_id = VM_REG_RSP;
    set_register.value = 0x200000U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_SET_REGISTER, sizeof(set_register), 0U);
    fbvbs_copy_memory(page->body, &set_register, sizeof(set_register));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    set_register.register_id = VM_REG_RFLAGS;
    set_register.value = 0x44U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_SET_REGISTER, sizeof(set_register), 0U);
    fbvbs_copy_memory(page->body, &set_register, sizeof(set_register));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    set_register.register_id = VM_REG_RIP;
    set_register.value = FBVBS_SYNTHETIC_EXIT_RIP_MMIO;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_SET_REGISTER, sizeof(set_register), 0U);
    fbvbs_copy_memory(page->body, &set_register, sizeof(set_register));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_RUN, sizeof(run_request), sizeof(run_response));
    fbvbs_copy_memory(page->body, &run_request, sizeof(run_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&run_response, page->body, sizeof(run_response));
    assert(run_response.exit_reason == FBVBS_VM_EXIT_REASON_MMIO);
    assert(run_response.exit_length == sizeof(mmio_exit));
    fbvbs_copy_memory(&mmio_exit, run_response.exit_payload, sizeof(mmio_exit));
    assert(mmio_exit.guest_physical_address == 0x200000U);
    assert(mmio_exit.is_write == 0U);

    set_register.register_id = VM_REG_RIP;
    set_register.value = FBVBS_SYNTHETIC_EXIT_RIP_SHUTDOWN;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_SET_REGISTER, sizeof(set_register), 0U);
    fbvbs_copy_memory(page->body, &set_register, sizeof(set_register));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_RUN, sizeof(run_request), sizeof(run_response));
    fbvbs_copy_memory(page->body, &run_request, sizeof(run_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&run_response, page->body, sizeof(run_response));
    assert(run_response.exit_reason == FBVBS_VM_EXIT_REASON_SHUTDOWN);
    assert(run_response.exit_length == 0U);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_VM_GET_VCPU_STATUS,
        sizeof(status_request),
        sizeof(status_response)
    );
    fbvbs_copy_memory(page->body, &status_request, sizeof(status_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&status_response, page->body, sizeof(status_response));
    assert(status_response.vcpu_state == FBVBS_VCPU_STATE_RUNNABLE);

    set_register.register_id = VM_REG_RIP;
    set_register.value = FBVBS_SYNTHETIC_EXIT_RIP_FAULT;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_SET_REGISTER, sizeof(set_register), 0U);
    fbvbs_copy_memory(page->body, &set_register, sizeof(set_register));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_RUN, sizeof(run_request), sizeof(run_response));
    fbvbs_copy_memory(page->body, &run_request, sizeof(run_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&run_response, page->body, sizeof(run_response));
    assert(run_response.exit_reason == FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_VM_GET_VCPU_STATUS,
        sizeof(status_request),
        sizeof(status_response)
    );
    fbvbs_copy_memory(page->body, &status_request, sizeof(status_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&status_response, page->body, sizeof(status_response));
    assert(status_response.vcpu_state == FBVBS_VCPU_STATE_FAULTED);

    assert(fbvbs_partition_get_fault_info(&state, vm_partition_id, &fault_info) == OK);
    assert(fault_info.fault_code == FAULT_CODE_VM_EXIT_UNCLASSIFIED);
    assert(fault_info.fault_detail0 == 0U);

    recover_request.partition_id = vm_partition_id;
    recover_request.recovery_flags = 0U;
    assert(fbvbs_partition_recover(&state, &recover_request) == OK);

    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_RELEASE_DEVICE, sizeof(device_request), 0U);
    fbvbs_copy_memory(page->body, &device_request, sizeof(device_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
}

static void test_multi_vcpu_partition_state_aggregation(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_run_request run_request;
    struct fbvbs_vm_run_response run_response;
    struct fbvbs_vm_inject_interrupt_request inject_request;
    struct fbvbs_vm_vcpu_status_request status_request;
    struct fbvbs_vm_vcpu_status_response status_response;
    struct fbvbs_vm_map_memory_request map_request;
    struct fbvbs_vm_register_request set_register;
    struct fbvbs_partition_fault_info_response fault_info;
    struct fbvbs_partition *vm_partition;
    uint64_t vm_partition_id;
    uint64_t guest_memory_object_id;

    fbvbs_hypervisor_init(&state);
    vm_partition_id = create_runnable_vm_with_vcpus(&state, FBVBS_PAGE_SIZE * 5U, 2U);
    guest_memory_object_id = allocate_memory_object(&state, FBVBS_MEMORY_OBJECT_FLAG_GUEST_MEMORY);
    vm_partition = find_partition(&state, vm_partition_id);
    assert(vm_partition != NULL);

    map_request.vm_partition_id = vm_partition_id;
    map_request.memory_object_id = guest_memory_object_id;
    map_request.guest_physical_address = 0x210000U;
    map_request.size = FBVBS_PAGE_SIZE;
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;
    map_request.reserved0 = 0U;
    assert(fbvbs_vm_map_memory(&state, &map_request) == OK);

    run_request.vm_partition_id = vm_partition_id;
    run_request.vcpu_id = 0U;
    run_request.run_flags = VM_RUN_FLAG_NONE;
    assert(fbvbs_vm_run(&state, &run_request, &run_response) == OK);
    assert(run_response.exit_reason == FBVBS_VM_EXIT_REASON_HALT);
    assert(vm_partition->state == FBVBS_PARTITION_STATE_RUNNABLE);

    status_request.vm_partition_id = vm_partition_id;
    status_request.reserved0 = 0U;
    status_request.vcpu_id = 0U;
    assert(fbvbs_vm_get_vcpu_status(&state, &status_request, &status_response) == OK);
    assert(status_response.vcpu_state == FBVBS_VCPU_STATE_BLOCKED);
    status_request.vcpu_id = 1U;
    assert(fbvbs_vm_get_vcpu_status(&state, &status_request, &status_response) == OK);
    assert(status_response.vcpu_state == FBVBS_VCPU_STATE_RUNNABLE);

    inject_request.vm_partition_id = vm_partition_id;
    inject_request.vcpu_id = 0U;
    inject_request.vector = 48U;
    inject_request.delivery_mode = FBVBS_VM_DELIVERY_FIXED;
    inject_request.reserved0 = 0U;
    assert(fbvbs_vm_inject_interrupt(&state, &inject_request) == OK);
    assert(vm_partition->state == FBVBS_PARTITION_STATE_RUNNABLE);
    status_request.vcpu_id = 0U;
    assert(fbvbs_vm_get_vcpu_status(&state, &status_request, &status_response) == OK);
    assert(status_response.vcpu_state == FBVBS_VCPU_STATE_RUNNABLE);

    set_register.vm_partition_id = vm_partition_id;
    set_register.vcpu_id = 1U;
    set_register.register_id = VM_REG_RIP;
    set_register.value = FBVBS_SYNTHETIC_EXIT_RIP_FAULT;
    assert(fbvbs_vm_set_register(&state, &set_register) == OK);

    run_request.vcpu_id = 1U;
    assert(fbvbs_vm_run(&state, &run_request, &run_response) == OK);
    assert(run_response.exit_reason == FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT);
    assert(vm_partition->state == FBVBS_PARTITION_STATE_FAULTED);

    status_request.vcpu_id = 0U;
    assert(fbvbs_vm_get_vcpu_status(&state, &status_request, &status_response) == OK);
    assert(status_response.vcpu_state == FBVBS_VCPU_STATE_FAULTED);
    status_request.vcpu_id = 1U;
    assert(fbvbs_vm_get_vcpu_status(&state, &status_request, &status_response) == OK);
    assert(status_response.vcpu_state == FBVBS_VCPU_STATE_FAULTED);

    assert(fbvbs_partition_get_fault_info(&state, vm_partition_id, &fault_info) == OK);
    assert(fault_info.fault_code == FAULT_CODE_VM_EXIT_UNCLASSIFIED);
    assert(fault_info.fault_detail0 == 1U);
}

static void test_platform_capability_gates(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    const struct fbvbs_log_record_v1 *record;
    struct fbvbs_audit_platform_gate_event platform_gate_event;
    struct fbvbs_vm_create_request create = {
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .vcpu_count = 1U,
        .vm_flags = VM_FLAG_NESTED_VIRT_DISABLED,
    };
    struct fbvbs_vm_device_request device_request;
    uint64_t vm_partition_id;

    fbvbs_hypervisor_init(&state);
    state.vmx_caps.hlat_available = 0U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_CREATE, sizeof(create), 0U);
    fbvbs_copy_memory(page->body, &create, sizeof(create));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == NOT_SUPPORTED_ON_PLATFORM);
    record = get_log_record(&state, 2U);
    assert(record->event_code == FBVBS_EVENT_VM_PLATFORM_GATE);
    fbvbs_copy_memory(&platform_gate_event, record->payload, sizeof(platform_gate_event));
    assert(platform_gate_event.required_capability == FBVBS_PLATFORM_CAP_HLAT);
    assert(platform_gate_event.partition_id == 0U);

    fbvbs_hypervisor_init(&state);
    vm_partition_id = create_runnable_vm(&state, FBVBS_PAGE_SIZE * 2U);
    state.vmx_caps.iommu_available = 0U;
    device_request.vm_partition_id = vm_partition_id;
    device_request.device_id = 0xD000U;
    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_VM_ASSIGN_DEVICE, sizeof(device_request), 0U);
    fbvbs_copy_memory(page->body, &device_request, sizeof(device_request));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == NOT_SUPPORTED_ON_PLATFORM);
    record = get_log_record(&state, 2U);
    assert(record->event_code == FBVBS_EVENT_VM_PLATFORM_GATE);
    fbvbs_copy_memory(&platform_gate_event, record->payload, sizeof(platform_gate_event));
    assert(platform_gate_event.partition_id == vm_partition_id);
    assert(platform_gate_event.device_id == 0xD000U);
    assert(platform_gate_event.required_capability == FBVBS_PLATFORM_CAP_IOMMU);
}

static void test_iommu_domain_lifecycle_logs(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request device_request;
    struct fbvbs_partition *partition = NULL;
    const struct fbvbs_log_record_v1 *record;
    struct fbvbs_audit_device_assignment_event domain_event;
    struct fbvbs_audit_device_assignment_event assignment_event;
    uint64_t vm_partition_id;
    uint64_t domain_id;
    uint32_t index;

    fbvbs_hypervisor_init(&state);
    vm_partition_id = create_runnable_vm(&state, FBVBS_PAGE_SIZE * 2U);
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        if (state.partitions[index].occupied && state.partitions[index].partition_id == vm_partition_id) {
            partition = &state.partitions[index];
            break;
        }
    }
    assert(partition != NULL);

    device_request.vm_partition_id = vm_partition_id;
    device_request.device_id = 0xD000U;
    assert(fbvbs_vm_assign_device(&state, &device_request) == OK);
    assert(partition->iommu_domain_id != 0U);
    assert(partition->assigned_device_count == 1U);
    domain_id = partition->iommu_domain_id;

    record = get_log_record(&state, 2U);
    assert(record->event_code == FBVBS_EVENT_IOMMU_DOMAIN_CREATE);
    fbvbs_copy_memory(&domain_event, record->payload, sizeof(domain_event));
    assert(domain_event.partition_id == vm_partition_id);
    assert(domain_event.iommu_domain_id == domain_id);
    assert(domain_event.attached_device_count == 0U);

    record = get_log_record(&state, 3U);
    assert(record->event_code == FBVBS_EVENT_VM_DEVICE_ASSIGN);
    fbvbs_copy_memory(&assignment_event, record->payload, sizeof(assignment_event));
    assert(assignment_event.partition_id == vm_partition_id);
    assert(assignment_event.device_id == 0xD000U);
    assert(assignment_event.iommu_domain_id == domain_id);
    assert(assignment_event.attached_device_count == 1U);

    assert(fbvbs_vm_release_device(&state, &device_request) == OK);
    assert(partition->iommu_domain_id == 0U);
    assert(partition->assigned_device_count == 0U);

    record = get_log_record(&state, 4U);
    assert(record->event_code == FBVBS_EVENT_VM_DEVICE_RELEASE);
    fbvbs_copy_memory(&assignment_event, record->payload, sizeof(assignment_event));
    assert(assignment_event.device_id == 0xD000U);
    assert(assignment_event.iommu_domain_id == domain_id);
    assert(assignment_event.attached_device_count == 0U);

    record = get_log_record(&state, 5U);
    assert(record->event_code == FBVBS_EVENT_IOMMU_DOMAIN_RELEASE);
    fbvbs_copy_memory(&domain_event, record->payload, sizeof(domain_event));
    assert(domain_event.partition_id == vm_partition_id);
    assert(domain_event.iommu_domain_id == domain_id);
    assert(domain_event.attached_device_count == 0U);
}

static void test_vm_destroy_releases_iommu_domain(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request device_request;
    const struct fbvbs_log_record_v1 *record;
    struct fbvbs_partition *partition = NULL;
    uint64_t vm_partition_id;
    uint64_t domain_id;
    uint32_t index;

    fbvbs_hypervisor_init(&state);
    vm_partition_id = create_runnable_vm(&state, FBVBS_PAGE_SIZE * 2U);
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        if (state.partitions[index].occupied && state.partitions[index].partition_id == vm_partition_id) {
            partition = &state.partitions[index];
            break;
        }
    }
    assert(partition != NULL);

    device_request.vm_partition_id = vm_partition_id;
    device_request.device_id = 0xD000U;
    assert(fbvbs_vm_assign_device(&state, &device_request) == OK);
    domain_id = partition->iommu_domain_id;
    assert(domain_id != 0U);

    assert(fbvbs_vm_destroy(&state, vm_partition_id) == OK);
    assert(partition->state == FBVBS_PARTITION_STATE_DESTROYED);
    assert(partition->iommu_domain_id == 0U);

    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        assert(!state.iommu_domains[index].active || state.iommu_domains[index].domain_id != domain_id);
    }

    record = get_log_record(&state, 4U);
    assert(record->event_code == FBVBS_EVENT_VM_DEVICE_RELEASE);
    record = get_log_record(&state, 5U);
    assert(record->event_code == FBVBS_EVENT_IOMMU_DOMAIN_RELEASE);
}

static void test_partition_destroy_releases_attached_resources(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_register_shared_request register_shared;
    struct fbvbs_memory_register_shared_response shared_response;
    struct fbvbs_vm_map_memory_request vm_map;
    uint64_t trusted_partition_id;
    uint64_t peer_partition_id;
    uint64_t vm_partition_id;
    uint64_t shared_object_id;
    uint64_t guest_memory_object_id;

    fbvbs_hypervisor_init(&state);

    trusted_partition_id = create_trusted_service_partition(&state, FBVBS_PAGE_SIZE * 2U, 1U);
    peer_partition_id = create_trusted_service_partition(&state, FBVBS_PAGE_SIZE * 3U, 1U);
    shared_object_id = allocate_memory_object(&state, FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE);

    register_shared.memory_object_id = shared_object_id;
    register_shared.size = FBVBS_PAGE_SIZE;
    register_shared.peer_partition_id = peer_partition_id;
    register_shared.peer_permissions = FBVBS_MEMORY_PERMISSION_READ;
    register_shared.reserved0 = 0U;
    assert(fbvbs_memory_register_shared(&state, &register_shared, &shared_response) == OK);
    assert(state.memory_objects[0].shared_count == 1U);
    assert(fbvbs_partition_destroy(&state, peer_partition_id) == OK);
    assert(state.memory_objects[0].shared_count == 0U);
    assert(fbvbs_memory_release_object(&state, shared_object_id) == OK);

    vm_partition_id = create_runnable_vm(&state, FBVBS_PAGE_SIZE * 3U);
    guest_memory_object_id = allocate_memory_object(&state, FBVBS_MEMORY_OBJECT_FLAG_GUEST_MEMORY);
    vm_map.vm_partition_id = vm_partition_id;
    vm_map.memory_object_id = guest_memory_object_id;
    vm_map.guest_physical_address = 0x300000U;
    vm_map.size = FBVBS_PAGE_SIZE;
    vm_map.permissions = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;
    vm_map.reserved0 = 0U;
    assert(fbvbs_vm_map_memory(&state, &vm_map) == OK);
    assert(fbvbs_memory_release_object(&state, guest_memory_object_id) == RESOURCE_BUSY);
    assert(fbvbs_vm_destroy(&state, vm_partition_id) == OK);
    assert(fbvbs_memory_release_object(&state, guest_memory_object_id) == OK);
    assert(trusted_partition_id != 0U);
}

static void test_partition_command_page_binds_service_identity(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_diag_partition_list_response partition_list;
    struct fbvbs_diag_partition_entry entry;
    struct fbvbs_kci_verify_module_request verify_module = {
        .module_object_id = 0x3000U,
        .manifest_object_id = TEST_KCI_MODULE_MANIFEST_OBJECT_ID,
        .generation = 1U,
    };
    struct fbvbs_ksi_create_target_set_request create_target_set;
    struct fbvbs_partition *partition;
    struct fbvbs_command_page_v1 *page;
    uint64_t partition_id;

    fbvbs_hypervisor_init(&state);
    partition_id = create_measured_service_partition(&state, SERVICE_KIND_KCI);
    partition = find_partition(&state, partition_id);
    assert(partition != NULL);
    assert(((uint64_t)(uintptr_t)&partition->command_pages[0].page % FBVBS_PAGE_SIZE) == 0U);
    assert(partition->service_kind == SERVICE_KIND_KCI);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_DIAG_GET_PARTITION_LIST,
        0U,
        sizeof(partition_list)
    );
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&partition_list, page->body, sizeof(partition_list));
    fbvbs_copy_memory(&entry, &partition_list.entries[sizeof(entry)], sizeof(entry));
    assert(entry.partition_id == partition_id);
    assert(entry.service_kind == SERVICE_KIND_KCI);

    approve_artifact_pair(&state, verify_module.module_object_id, verify_module.manifest_object_id);
    page = prepare_partition_command_page(
        partition,
        0U,
        FBVBS_CALL_KCI_VERIFY_MODULE,
        sizeof(verify_module),
        sizeof(struct fbvbs_verdict_response)
    );
    fbvbs_copy_memory(page->body, &verify_module, sizeof(verify_module));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    fbvbs_zero_memory(&create_target_set, sizeof(create_target_set));
    create_target_set.target_count = 1U;
    create_target_set.target_object_ids[0] = 0x11000U;
    page = prepare_partition_command_page(
        partition,
        0U,
        FBVBS_CALL_KSI_CREATE_TARGET_SET,
        sizeof(create_target_set),
        sizeof(struct fbvbs_ksi_target_set_response)
    );
    fbvbs_copy_memory(page->body, &create_target_set, sizeof(create_target_set));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_CALLER);
}

static void test_fixed_host_partition_bootstrap_and_diag(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_partition *host_partition;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_diag_partition_list_response response;
    struct fbvbs_diag_partition_entry entry;

    fbvbs_hypervisor_init(&state);
    host_partition = find_host_partition(&state);
    assert(host_partition->state == FBVBS_PARTITION_STATE_RUNNABLE);
    assert(host_partition->bootstrap_page.vcpu_count == 1U);
    assert(host_partition->bootstrap_page.command_page_gpa[0] ==
           (uint64_t)(uintptr_t)&host_partition->command_pages[0].page);

    page = prepare_partition_command_page(
        host_partition,
        0U,
        FBVBS_CALL_DIAG_GET_PARTITION_LIST,
        0U,
        sizeof(response)
    );
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&response, page->body, sizeof(response));
    assert(response.count >= 1U);
    fbvbs_copy_memory(&entry, response.entries, sizeof(entry));
    assert(entry.partition_id == 1U);
    assert(entry.kind == PARTITION_KIND_FREEBSD_HOST);
    assert(entry.state == FBVBS_PARTITION_STATE_RUNNABLE);
}

static void test_host_only_calls_require_owned_host_command_page(void) {
    struct fbvbs_hypervisor_state state;
    struct aligned_command_page aligned_page;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_partition *trusted_partition;
    uint64_t trusted_partition_id;

    fbvbs_hypervisor_init(&state);

    prepare_command_page(
        &aligned_page,
        FBVBS_CALL_DIAG_GET_CAPABILITIES,
        0U,
        sizeof(struct fbvbs_diag_capabilities_response)
    );
    prepare_trap_registers(&registers, &aligned_page.page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_CALLER);
    assert(aligned_page.page.command_state == FAILED);

    trusted_partition_id = create_trusted_service_partition(&state, FBVBS_PAGE_SIZE * 2U, 1U);
    trusted_partition = find_partition(&state, trusted_partition_id);
    assert(trusted_partition != NULL);

    page = prepare_partition_command_page(
        trusted_partition,
        0U,
        FBVBS_CALL_AUDIT_GET_BOOT_ID,
        0U,
        sizeof(struct fbvbs_audit_boot_id_response)
    );
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_CALLER);
    assert(page->command_state == FAILED);
}

static void test_host_callsites_reject_wrong_frontend_rip(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_partition *host_partition;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_vm_create_request vm_create = {
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 4U,
        .vcpu_count = 1U,
        .vm_flags = VM_FLAG_NESTED_VIRT_DISABLED,
    };
    struct fbvbs_kci_verify_module_request verify_module = {
        .module_object_id = 0x3000U,
        .manifest_object_id = TEST_KCI_MODULE_MANIFEST_OBJECT_ID,
        .generation = 1U,
    };

    fbvbs_hypervisor_init(&state);
    host_partition = find_host_partition(&state);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_AUDIT_GET_BOOT_ID,
        0U,
        sizeof(struct fbvbs_audit_boot_id_response)
    );
    host_partition->vcpus[0].rip = FBVBS_HOST_CALLSITE_VMM_PRIMARY;
    assert(fbvbs_dispatch_hypercall(&state, &registers) == CALLSITE_REJECTED);
    assert(page->command_state == FAILED);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_VM_CREATE,
        sizeof(vm_create),
        sizeof(struct fbvbs_vm_create_response)
    );
    fbvbs_copy_memory(page->body, &vm_create, sizeof(vm_create));
    host_partition->vcpus[0].rip = FBVBS_HOST_CALLSITE_FBVBS_PRIMARY;
    assert(fbvbs_dispatch_hypercall(&state, &registers) == CALLSITE_REJECTED);
    assert(page->command_state == FAILED);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_KCI_VERIFY_MODULE,
        sizeof(verify_module),
        sizeof(struct fbvbs_verdict_response)
    );
    fbvbs_copy_memory(page->body, &verify_module, sizeof(verify_module));
    host_partition->vcpus[0].rip = FBVBS_HOST_CALLSITE_VMM_PRIMARY;
    assert(fbvbs_dispatch_hypercall(&state, &registers) == CALLSITE_REJECTED);
    assert(page->command_state == FAILED);
}

static void test_manifest_derived_host_callsites_relocate(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition *host_partition;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_vm_create_request vm_create = {
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 4U,
        .vcpu_count = 1U,
        .vm_flags = VM_FLAG_NESTED_VIRT_DISABLED,
    };
    static const uint64_t fbvbs_offsets[] = {0x3000U, 0x3100U};
    static const uint64_t vmm_offsets[] = {0x4000U, 0x4100U};

    fbvbs_hypervisor_init(&state);
    host_partition = find_host_partition(&state);
    assert(fbvbs_configure_host_callsite_table(
        &state,
        FBVBS_HOST_CALLER_CLASS_FBVBS,
        0xF101U,
        0xFFFF800000000000ULL,
        fbvbs_offsets,
        2U
    ) == OK);
    assert(fbvbs_configure_host_callsite_table(
        &state,
        FBVBS_HOST_CALLER_CLASS_VMM,
        0xF102U,
        0xFFFF800000000000ULL,
        vmm_offsets,
        2U
    ) == OK);
    assert(fbvbs_primary_host_callsite(&state, FBVBS_HOST_CALLER_CLASS_FBVBS) == 0xFFFF800000003000ULL);
    assert(fbvbs_primary_host_callsite(&state, FBVBS_HOST_CALLER_CLASS_VMM) == 0xFFFF800000004000ULL);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_AUDIT_GET_BOOT_ID,
        0U,
        sizeof(struct fbvbs_audit_boot_id_response)
    );
    assert(host_partition->vcpus[0].rip == 0xFFFF800000003000ULL);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_VM_CREATE,
        sizeof(vm_create),
        sizeof(struct fbvbs_vm_create_response)
    );
    fbvbs_copy_memory(page->body, &vm_create, sizeof(vm_create));
    assert(host_partition->vcpus[0].rip == 0xFFFF800000004000ULL);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_AUDIT_GET_BOOT_ID,
        0U,
        sizeof(struct fbvbs_audit_boot_id_response)
    );
    host_partition->vcpus[0].rip = FBVBS_HOST_CALLSITE_FBVBS_PRIMARY;
    assert(fbvbs_dispatch_hypercall(&state, &registers) == CALLSITE_REJECTED);
}

static void test_separate_output_requires_reserved_shared_mapping(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition *host_partition;
    struct fbvbs_memory_allocate_object_request allocate = {
        .size = FBVBS_PAGE_SIZE,
        .object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE,
    };
    struct fbvbs_memory_allocate_object_response allocated;
    struct fbvbs_memory_map_request map_request;
    struct fbvbs_memory_register_shared_request share_request;
    struct fbvbs_memory_register_shared_response shared;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct aligned_command_page output_page;
    struct fbvbs_diag_capabilities_response *response;

    fbvbs_hypervisor_init(&state);
    host_partition = find_host_partition(&state);
    assert(fbvbs_memory_allocate_object(&state, &allocate, &allocated) == OK);

    map_request.partition_id = host_partition->partition_id;
    map_request.memory_object_id = allocated.memory_object_id;
    map_request.guest_physical_address = (uint64_t)(uintptr_t)&output_page;
    map_request.size = FBVBS_PAGE_SIZE;
    map_request.permissions = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;
    map_request.reserved0 = 0U;
    assert(fbvbs_memory_map(&state, &map_request) == OK);

    page = prepare_partition_command_page(
        host_partition,
        0U,
        FBVBS_CALL_DIAG_GET_CAPABILITIES,
        0U,
        sizeof(*response)
    );
    page->flags = FBVBS_CMD_FLAG_SEPARATE_OUTPUT;
    page->output_page_gpa = (uint64_t)(uintptr_t)&output_page;
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_PARAMETER);

    share_request.memory_object_id = allocated.memory_object_id;
    share_request.size = FBVBS_PAGE_SIZE;
    share_request.peer_partition_id = 0U;
    share_request.peer_permissions = FBVBS_MEMORY_PERMISSION_WRITE;
    share_request.reserved0 = 0U;
    assert(fbvbs_memory_register_shared(&state, &share_request, &shared) == OK);

    fbvbs_zero_memory(&output_page, sizeof(output_page));
    page = prepare_partition_command_page(
        host_partition,
        0U,
        FBVBS_CALL_DIAG_GET_CAPABILITIES,
        0U,
        sizeof(*response)
    );
    page->flags = FBVBS_CMD_FLAG_SEPARATE_OUTPUT;
    page->output_page_gpa = (uint64_t)(uintptr_t)&output_page;
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    response = (struct fbvbs_diag_capabilities_response *)&output_page;
    assert(response->capability_bitmap0 == state.capability_bitmap0);
    assert(response->capability_bitmap1 == state.capability_bitmap1);
}

static void test_host_dispatch_security_service_calls(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_kci_verify_module_request verify_module = {
        .module_object_id = 0x3000U,
        .manifest_object_id = TEST_KCI_MODULE_MANIFEST_OBJECT_ID,
        .generation = 1U,
    };
    struct fbvbs_verdict_response verdict;
    struct fbvbs_ksi_create_target_set_request create_target_set;
    struct fbvbs_ksi_target_set_response target_set;
    struct fbvbs_iks_import_key_request import_key = {
        .key_material_page_gpa = 0x24000U,
        .key_type = IKS_KEY_ED25519,
        .allowed_ops = IKS_OP_SIGN,
        .key_length = 32U,
        .reserved0 = 0U,
    };
    struct fbvbs_handle_response key_handle;
    struct fbvbs_sks_import_dek_request import_dek = {
        .key_material_page_gpa = 0x25000U,
        .volume_id = 7U,
        .key_length = 32U,
        .reserved0 = 0U,
    };
    struct fbvbs_handle_response dek_handle;
    struct aligned_metadata_bundle metadata_bundle;
    struct fbvbs_uvs_verify_manifest_set_request verify_manifest_set;
    struct fbvbs_uvs_verify_manifest_set_response manifest_set_response;

    fbvbs_hypervisor_init(&state);
    approve_artifact_pair(&state, verify_module.module_object_id, verify_module.manifest_object_id);
    prepare_valid_metadata_bundle(&metadata_bundle, 0x2000U);
    prepare_metadata_set_request(&metadata_bundle, &verify_manifest_set);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_KCI_VERIFY_MODULE,
        sizeof(verify_module),
        sizeof(verdict)
    );
    fbvbs_copy_memory(page->body, &verify_module, sizeof(verify_module));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&verdict, page->body, sizeof(verdict));
    assert(verdict.verdict == 1U);

    fbvbs_zero_memory(&create_target_set, sizeof(create_target_set));
    create_target_set.target_count = 1U;
    create_target_set.target_object_ids[0] = 0x11000U;
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_KSI_CREATE_TARGET_SET,
        sizeof(create_target_set),
        sizeof(target_set)
    );
    fbvbs_copy_memory(page->body, &create_target_set, sizeof(create_target_set));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&target_set, page->body, sizeof(target_set));
    assert(target_set.target_set_id != 0U);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_IKS_IMPORT_KEY,
        sizeof(import_key),
        sizeof(key_handle)
    );
    fbvbs_copy_memory(page->body, &import_key, sizeof(import_key));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&key_handle, page->body, sizeof(key_handle));
    assert(key_handle.handle != 0U);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_SKS_IMPORT_DEK,
        sizeof(import_dek),
        sizeof(dek_handle)
    );
    fbvbs_copy_memory(page->body, &import_dek, sizeof(import_dek));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&dek_handle, page->body, sizeof(dek_handle));
    assert(dek_handle.handle != 0U);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_UVS_VERIFY_MANIFEST_SET,
        sizeof(verify_manifest_set),
        sizeof(manifest_set_response)
    );
    fbvbs_copy_memory(page->body, &verify_manifest_set, sizeof(verify_manifest_set));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&manifest_set_response, page->body, sizeof(manifest_set_response));
    assert(manifest_set_response.verdict == 1U);
    assert(manifest_set_response.verified_manifest_set_id != 0U);
}

static void test_kci_verify_module_requires_uvs_approval(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_kci_verify_module_request verify_module = {
        .module_object_id = 0x3000U,
        .manifest_object_id = TEST_KCI_MODULE_MANIFEST_OBJECT_ID,
        .generation = 1U,
    };
    struct fbvbs_verdict_response verdict;

    fbvbs_hypervisor_init(&state);
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_KCI_VERIFY_MODULE,
        sizeof(verify_module),
        sizeof(verdict)
    );
    fbvbs_copy_memory(page->body, &verify_module, sizeof(verify_module));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == SIGNATURE_INVALID);

    approve_artifact_pair(&state, verify_module.module_object_id, verify_module.manifest_object_id);
    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_KCI_VERIFY_MODULE,
        sizeof(verify_module),
        sizeof(verdict)
    );
    fbvbs_copy_memory(page->body, &verify_module, sizeof(verify_module));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&verdict, page->body, sizeof(verdict));
    assert(verdict.verdict == 1U);
}

static void test_uvs_verify_artifact_requires_manifest_membership(void) {
    struct fbvbs_hypervisor_state state;
    struct aligned_metadata_bundle bundle;
    struct fbvbs_uvs_verify_manifest_set_request verify_manifest_set;
    struct fbvbs_uvs_verify_manifest_set_response manifest_set_response;
    struct fbvbs_uvs_verify_artifact_request verify_artifact;
    struct fbvbs_verdict_response verdict;
    const struct fbvbs_artifact_catalog_entry *artifact_entry = NULL;
    uint32_t index;

    fbvbs_hypervisor_init(&state);
    for (index = 0U; index < state.artifact_catalog.count; ++index) {
        if (state.artifact_catalog.entries[index].object_id == 0x1000U) {
            artifact_entry = &state.artifact_catalog.entries[index];
            break;
        }
    }
    assert(artifact_entry != NULL);
    prepare_valid_metadata_bundle(&bundle, 0x2000U);
    prepare_metadata_set_request(&bundle, &verify_manifest_set);
    assert(fbvbs_uvs_verify_manifest_set(&state, &verify_manifest_set, &manifest_set_response) == OK);

    fbvbs_zero_memory(&verify_artifact, sizeof(verify_artifact));
    fbvbs_copy_memory(verify_artifact.artifact_hash, artifact_entry->payload_hash, 48U);
    verify_artifact.verified_manifest_set_id = manifest_set_response.verified_manifest_set_id;
    verify_artifact.manifest_object_id = 0x2100U;
    assert(fbvbs_uvs_verify_artifact(&state, &verify_artifact, &verdict) == NOT_FOUND);
}

static void test_ksi_validate_setuid_enforces_operation_policy(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_ksi_register_tier_b_request register_prison = {
        .object_id = 0x14000U,
        .guest_physical_address = 0x14000U,
        .size = FBVBS_PAGE_SIZE,
        .protection_class = KSI_CLASS_PRISON,
        .reserved0 = 0U,
    };
    struct fbvbs_ksi_register_tier_b_request register_mac = {
        .object_id = 0x15000U,
        .guest_physical_address = 0x15000U,
        .size = FBVBS_PAGE_SIZE,
        .protection_class = KSI_CLASS_MAC,
        .reserved0 = 0U,
    };
    struct fbvbs_ksi_allocate_ucred_request allocate_ucred = {
        .uid = 1000U,
        .gid = 1000U,
        .prison_object_id = 0x14000U,
        .template_ucred_object_id = 0U,
    };
    struct fbvbs_ksi_allocate_ucred_response ucred;
    struct fbvbs_ksi_validate_setuid_request validate_setuid;
    struct fbvbs_verdict_response verdict;

    fbvbs_hypervisor_init(&state);
    assert(fbvbs_ksi_register_tier_b(&state, &register_prison) == OK);
    assert(fbvbs_ksi_register_tier_b(&state, &register_mac) == OK);
    assert(fbvbs_ksi_allocate_ucred(&state, &allocate_ucred, &ucred) == OK);

    fbvbs_zero_memory(&validate_setuid, sizeof(validate_setuid));
    validate_setuid.operation_class = FBVBS_KSI_OPERATION_SETUID_FAMILY;
    validate_setuid.valid_mask = FBVBS_KSI_VALID_EUID;
    validate_setuid.caller_ucred_object_id = ucred.ucred_object_id;
    assert(fbvbs_ksi_validate_setuid(&state, &validate_setuid, &verdict) == OK);
    assert(verdict.verdict == 1U);

    validate_setuid.valid_mask = FBVBS_KSI_VALID_EGID;
    assert(fbvbs_ksi_validate_setuid(&state, &validate_setuid, &verdict) == POLICY_DENIED);

    validate_setuid.operation_class = FBVBS_KSI_OPERATION_SETGID_FAMILY;
    validate_setuid.valid_mask = FBVBS_KSI_VALID_EUID;
    assert(fbvbs_ksi_validate_setuid(&state, &validate_setuid, &verdict) == POLICY_DENIED);

    fbvbs_zero_memory(&validate_setuid, sizeof(validate_setuid));
    validate_setuid.operation_class = FBVBS_KSI_OPERATION_EXEC_ELEVATION;
    validate_setuid.fsid = 1U;
    validate_setuid.fileid = 2U;
    validate_setuid.valid_mask = FBVBS_KSI_VALID_EUID;
    validate_setuid.caller_ucred_object_id = ucred.ucred_object_id;
    validate_setuid.jail_context_id = register_prison.object_id;
    validate_setuid.mac_context_id = register_mac.object_id;
    validate_setuid.measured_hash[0] = 0x33U;
    validate_setuid.measured_hash[47] = 0xCCU;
    assert(fbvbs_ksi_validate_setuid(&state, &validate_setuid, &verdict) == OK);
    assert(verdict.verdict == 1U);

    validate_setuid.jail_context_id = 0xDEADBEEFU;
    assert(fbvbs_ksi_validate_setuid(&state, &validate_setuid, &verdict) == NOT_FOUND);
}

static void test_dispatch_security_service_calls(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_partition *kci_partition;
    struct fbvbs_partition *ksi_partition;
    struct fbvbs_partition *iks_partition;
    struct fbvbs_partition *sks_partition;
    struct fbvbs_partition *uvs_partition;
    struct fbvbs_kci_verify_module_request verify_module = {
        .module_object_id = 0x3000U,
        .manifest_object_id = TEST_KCI_MODULE_MANIFEST_OBJECT_ID,
        .generation = 1U,
    };
    struct fbvbs_verdict_response verdict;
    struct fbvbs_kci_set_wx_request set_wx = {
        .module_object_id = 0x3000U,
        .guest_physical_address = 0x4000U,
        .file_offset = 0U,
        .size = FBVBS_PAGE_SIZE,
        .permissions = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_EXECUTE,
        .reserved0 = 0U,
    };
    struct fbvbs_kci_pin_cr_request pin_cr = {
        .cr_number = 0U,
        .reserved0 = 0U,
        .pin_mask = 0x1U,
    };
    struct fbvbs_kci_intercept_msr_request intercept_msr = {
        .msr_address = 0xC0000080U,
        .enable = 1U,
    };
    struct fbvbs_ksi_create_target_set_request create_target_set;
    struct fbvbs_ksi_target_set_response target_set;
    struct fbvbs_ksi_register_tier_a_request register_tier_a = {
        .object_id = 0x10000U,
        .guest_physical_address = 0x10000U,
        .size = FBVBS_PAGE_SIZE,
    };
    struct fbvbs_ksi_register_tier_b_request register_tier_b = {
        .object_id = 0x11000U,
        .guest_physical_address = 0x11000U,
        .size = FBVBS_PAGE_SIZE,
        .protection_class = KSI_CLASS_UCRED,
        .reserved0 = 0U,
    };
    struct fbvbs_ksi_register_tier_a_request register_pointer_object = {
        .object_id = 0x12000U,
        .guest_physical_address = 0x12000U,
        .size = FBVBS_PAGE_SIZE,
    };
    struct fbvbs_ksi_modify_tier_b_request modify_tier_b;
    struct fbvbs_ksi_register_pointer_request register_pointer;
    struct fbvbs_ksi_allocate_ucred_request allocate_ucred = {
        .uid = 1000U,
        .gid = 1000U,
        .prison_object_id = 0x10000U,
        .template_ucred_object_id = 0U,
    };
    struct fbvbs_ksi_allocate_ucred_response ucred;
    struct fbvbs_ksi_validate_setuid_request validate_setuid;
    struct fbvbs_ksi_register_tier_b_request register_new_tier_b = {
        .object_id = 0x13000U,
        .guest_physical_address = 0x13000U,
        .size = FBVBS_PAGE_SIZE,
        .protection_class = KSI_CLASS_UCRED,
        .reserved0 = 0U,
    };
    struct fbvbs_ksi_replace_tier_b_object_request replace_tier_b = {
        .old_object_id = 0x11000U,
        .new_object_id = 0x13000U,
        .pointer_object_id = 0x12000U,
        .replace_flags = 0U,
        .reserved0 = 0U,
    };
    struct fbvbs_memory_object_id_request unregister_object = {.memory_object_id = 0U};
    struct fbvbs_iks_import_key_request import_sign_key = {
        .key_material_page_gpa = 0x20000U,
        .key_type = IKS_KEY_ED25519,
        .allowed_ops = IKS_OP_SIGN | IKS_OP_DERIVE,
        .key_length = 32U,
        .reserved0 = 0U,
    };
    struct fbvbs_iks_import_key_request import_exchange_key = {
        .key_material_page_gpa = 0x20100U,
        .key_type = IKS_KEY_X25519,
        .allowed_ops = IKS_OP_KEY_EXCHANGE | IKS_OP_DERIVE,
        .key_length = 32U,
        .reserved0 = 0U,
    };
    struct fbvbs_handle_response sign_key_handle;
    struct fbvbs_handle_response exchange_key_handle;
    struct fbvbs_iks_sign_request sign_request;
    struct fbvbs_iks_sign_response sign_response;
    struct fbvbs_iks_key_exchange_request key_exchange;
    struct fbvbs_handle_response derived_secret;
    struct fbvbs_iks_derive_request derive_request;
    struct fbvbs_handle_response derived_key;
    struct fbvbs_sks_import_dek_request import_dek = {
        .key_material_page_gpa = 0x21000U,
        .volume_id = 1U,
        .key_length = 32U,
        .reserved0 = 0U,
    };
    struct fbvbs_handle_response dek_handle;
    struct fbvbs_sks_batch_request batch_request;
    struct fbvbs_sks_batch_response batch_response;
    struct aligned_metadata_bundle metadata_bundle;
    struct fbvbs_uvs_verify_manifest_set_request verify_manifest_set;
    struct fbvbs_uvs_verify_manifest_set_response manifest_set_response;
    struct fbvbs_uvs_verify_artifact_request verify_artifact;
    struct fbvbs_uvs_check_revocation_request check_revocation = {
        .object_id = 0x1000U,
        .object_type = 1U,
        .reserved0 = 0U,
    };
    struct fbvbs_uvs_check_revocation_response revocation_response;

    fbvbs_hypervisor_init(&state);
    kci_partition = find_partition(&state, create_measured_service_partition(&state, SERVICE_KIND_KCI));
    ksi_partition = find_partition(&state, create_measured_service_partition(&state, SERVICE_KIND_KSI));
    iks_partition = find_partition(&state, create_measured_service_partition(&state, SERVICE_KIND_IKS));
    sks_partition = find_partition(&state, create_measured_service_partition(&state, SERVICE_KIND_SKS));
    uvs_partition = find_partition(&state, create_measured_service_partition(&state, SERVICE_KIND_UVS));
    assert(kci_partition != NULL && ksi_partition != NULL && iks_partition != NULL &&
           sks_partition != NULL && uvs_partition != NULL);
    approve_artifact_pair(&state, verify_module.module_object_id, verify_module.manifest_object_id);
    prepare_valid_metadata_bundle(&metadata_bundle, 0x2000U);
    prepare_metadata_set_request(&metadata_bundle, &verify_manifest_set);

    page = prepare_partition_command_page(
        kci_partition,
        0U,
        FBVBS_CALL_KCI_VERIFY_MODULE,
        sizeof(verify_module),
        sizeof(verdict)
    );
    fbvbs_copy_memory(page->body, &verify_module, sizeof(verify_module));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&verdict, page->body, sizeof(verdict));
    assert(verdict.verdict == 1U);

    page = prepare_partition_command_page(kci_partition, 0U, FBVBS_CALL_KCI_SET_WX, sizeof(set_wx), 0U);
    fbvbs_copy_memory(page->body, &set_wx, sizeof(set_wx));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(kci_partition, 0U, FBVBS_CALL_KCI_PIN_CR, sizeof(pin_cr), 0U);
    fbvbs_copy_memory(page->body, &pin_cr, sizeof(pin_cr));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(kci_partition, 0U, FBVBS_CALL_KCI_INTERCEPT_MSR, sizeof(intercept_msr), 0U);
    fbvbs_copy_memory(page->body, &intercept_msr, sizeof(intercept_msr));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    fbvbs_zero_memory(&create_target_set, sizeof(create_target_set));
    create_target_set.target_count = 2U;
    create_target_set.target_object_ids[0] = 0x11000U;
    create_target_set.target_object_ids[1] = 0x13000U;
    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_CREATE_TARGET_SET,
        sizeof(create_target_set),
        sizeof(target_set)
    );
    fbvbs_copy_memory(page->body, &create_target_set, sizeof(create_target_set));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&target_set, page->body, sizeof(target_set));
    assert(target_set.target_set_id != 0U);

    page = prepare_partition_command_page(ksi_partition, 0U, FBVBS_CALL_KSI_REGISTER_TIER_A, sizeof(register_tier_a), 0U);
    fbvbs_copy_memory(page->body, &register_tier_a, sizeof(register_tier_a));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(ksi_partition, 0U, FBVBS_CALL_KSI_REGISTER_TIER_B, sizeof(register_tier_b), 0U);
    fbvbs_copy_memory(page->body, &register_tier_b, sizeof(register_tier_b));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_REGISTER_TIER_A,
        sizeof(register_pointer_object),
        0U
    );
    fbvbs_copy_memory(page->body, &register_pointer_object, sizeof(register_pointer_object));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    fbvbs_zero_memory(&modify_tier_b, sizeof(modify_tier_b));
    modify_tier_b.object_id = register_tier_b.object_id;
    modify_tier_b.patch_length = 1U;
    modify_tier_b.patch[0] = 1U;
    page = prepare_partition_command_page(ksi_partition, 0U, FBVBS_CALL_KSI_MODIFY_TIER_B, sizeof(modify_tier_b), 0U);
    fbvbs_copy_memory(page->body, &modify_tier_b, sizeof(modify_tier_b));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    register_pointer.pointer_object_id = register_pointer_object.object_id;
    register_pointer.target_set_id = target_set.target_set_id;
    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_REGISTER_POINTER,
        sizeof(register_pointer),
        0U
    );
    fbvbs_copy_memory(page->body, &register_pointer, sizeof(register_pointer));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_ALLOCATE_UCRED,
        sizeof(allocate_ucred),
        sizeof(ucred)
    );
    fbvbs_copy_memory(page->body, &allocate_ucred, sizeof(allocate_ucred));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&ucred, page->body, sizeof(ucred));
    assert(ucred.ucred_object_id != 0U);

    fbvbs_zero_memory(&validate_setuid, sizeof(validate_setuid));
    validate_setuid.operation_class = FBVBS_KSI_OPERATION_SETUID_FAMILY;
    validate_setuid.valid_mask = 1U;
    validate_setuid.caller_ucred_object_id = ucred.ucred_object_id;
    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_VALIDATE_SETUID,
        sizeof(validate_setuid),
        sizeof(verdict)
    );
    fbvbs_copy_memory(page->body, &validate_setuid, sizeof(validate_setuid));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&verdict, page->body, sizeof(verdict));
    assert(verdict.verdict == 1U);

    page = prepare_partition_command_page(ksi_partition, 0U, FBVBS_CALL_KSI_REGISTER_TIER_B, sizeof(register_new_tier_b), 0U);
    fbvbs_copy_memory(page->body, &register_new_tier_b, sizeof(register_new_tier_b));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_REPLACE_TIER_B_OBJECT,
        sizeof(replace_tier_b),
        0U
    );
    fbvbs_copy_memory(page->body, &replace_tier_b, sizeof(replace_tier_b));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(
        iks_partition,
        0U,
        FBVBS_CALL_IKS_IMPORT_KEY,
        sizeof(import_sign_key),
        sizeof(sign_key_handle)
    );
    fbvbs_copy_memory(page->body, &import_sign_key, sizeof(import_sign_key));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&sign_key_handle, page->body, sizeof(sign_key_handle));
    assert(sign_key_handle.handle != 0U);

    page = prepare_partition_command_page(
        iks_partition,
        0U,
        FBVBS_CALL_IKS_IMPORT_KEY,
        sizeof(import_exchange_key),
        sizeof(exchange_key_handle)
    );
    fbvbs_copy_memory(page->body, &import_exchange_key, sizeof(import_exchange_key));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&exchange_key_handle, page->body, sizeof(exchange_key_handle));
    assert(exchange_key_handle.handle != 0U);

    fbvbs_zero_memory(&sign_request, sizeof(sign_request));
    sign_request.key_handle = sign_key_handle.handle;
    sign_request.hash_length = 48U;
    sign_request.hash[0] = 0xAAU;
    sign_request.hash[47] = 0x55U;
    page = prepare_partition_command_page(iks_partition, 0U, FBVBS_CALL_IKS_SIGN, sizeof(sign_request), sizeof(sign_response));
    fbvbs_copy_memory(page->body, &sign_request, sizeof(sign_request));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&sign_response, page->body, sizeof(sign_response));
    assert(sign_response.signature_length == 64U);

    fbvbs_zero_memory(&key_exchange, sizeof(key_exchange));
    key_exchange.key_handle = exchange_key_handle.handle;
    key_exchange.peer_public_key_length = 32U;
    key_exchange.peer_public_key[0] = 0x11U;
    page = prepare_partition_command_page(
        iks_partition,
        0U,
        FBVBS_CALL_IKS_KEY_EXCHANGE,
        sizeof(key_exchange),
        sizeof(derived_secret)
    );
    fbvbs_copy_memory(page->body, &key_exchange, sizeof(key_exchange));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&derived_secret, page->body, sizeof(derived_secret));
    assert(derived_secret.handle != 0U);

    fbvbs_zero_memory(&derive_request, sizeof(derive_request));
    derive_request.key_handle = exchange_key_handle.handle;
    derive_request.parameter_length = 16U;
    derive_request.params[0] = 0x22U;
    page = prepare_partition_command_page(
        iks_partition,
        0U,
        FBVBS_CALL_IKS_DERIVE,
        sizeof(derive_request),
        sizeof(derived_key)
    );
    fbvbs_copy_memory(page->body, &derive_request, sizeof(derive_request));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&derived_key, page->body, sizeof(derived_key));
    assert(derived_key.handle != 0U);

    page = prepare_partition_command_page(iks_partition, 0U, FBVBS_CALL_IKS_DESTROY_KEY, sizeof(sign_key_handle), 0U);
    fbvbs_copy_memory(page->body, &sign_key_handle, sizeof(sign_key_handle));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(iks_partition, 0U, FBVBS_CALL_IKS_DESTROY_KEY, sizeof(exchange_key_handle), 0U);
    fbvbs_copy_memory(page->body, &exchange_key_handle, sizeof(exchange_key_handle));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(sks_partition, 0U, FBVBS_CALL_SKS_IMPORT_DEK, sizeof(import_dek), sizeof(dek_handle));
    fbvbs_copy_memory(page->body, &import_dek, sizeof(import_dek));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&dek_handle, page->body, sizeof(dek_handle));
    assert(dek_handle.handle != 0U);

    batch_request.dek_handle = dek_handle.handle;
    batch_request.io_descriptor_page_gpa = 0x24000U;
    batch_request.descriptor_count = 2U;
    batch_request.reserved0 = 0U;
    page = prepare_partition_command_page(
        sks_partition,
        0U,
        FBVBS_CALL_SKS_DECRYPT_BATCH,
        sizeof(batch_request),
        sizeof(batch_response)
    );
    fbvbs_copy_memory(page->body, &batch_request, sizeof(batch_request));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&batch_response, page->body, sizeof(batch_response));
    assert(batch_response.completed_count == 2U);

    page = prepare_partition_command_page(
        sks_partition,
        0U,
        FBVBS_CALL_SKS_ENCRYPT_BATCH,
        sizeof(batch_request),
        sizeof(batch_response)
    );
    fbvbs_copy_memory(page->body, &batch_request, sizeof(batch_request));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(sks_partition, 0U, FBVBS_CALL_SKS_DESTROY_DEK, sizeof(dek_handle), 0U);
    fbvbs_copy_memory(page->body, &dek_handle, sizeof(dek_handle));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(
        uvs_partition,
        0U,
        FBVBS_CALL_UVS_VERIFY_MANIFEST_SET,
        sizeof(verify_manifest_set),
        sizeof(manifest_set_response)
    );
    fbvbs_copy_memory(page->body, &verify_manifest_set, sizeof(verify_manifest_set));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&manifest_set_response, page->body, sizeof(manifest_set_response));
    assert(manifest_set_response.verdict == 1U);
    assert(manifest_set_response.verified_manifest_set_id != 0U);

    fbvbs_zero_memory(&verify_artifact, sizeof(verify_artifact));
    verify_artifact.artifact_hash[0] = 0x11U;
    verify_artifact.artifact_hash[47] = 0xEEU;
    verify_artifact.verified_manifest_set_id = manifest_set_response.verified_manifest_set_id;
    verify_artifact.manifest_object_id = 0x2000U;
    page = prepare_partition_command_page(
        uvs_partition,
        0U,
        FBVBS_CALL_UVS_VERIFY_ARTIFACT,
        sizeof(verify_artifact),
        sizeof(verdict)
    );
    fbvbs_copy_memory(page->body, &verify_artifact, sizeof(verify_artifact));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&verdict, page->body, sizeof(verdict));
    assert(verdict.verdict == 1U);

    unregister_object.memory_object_id = ucred.ucred_object_id;
    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_UNREGISTER_OBJECT,
        sizeof(unregister_object),
        0U
    );
    fbvbs_copy_memory(page->body, &unregister_object, sizeof(unregister_object));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(
        uvs_partition,
        0U,
        FBVBS_CALL_UVS_CHECK_REVOCATION,
        sizeof(check_revocation),
        sizeof(revocation_response)
    );
    fbvbs_copy_memory(page->body, &check_revocation, sizeof(check_revocation));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&revocation_response, page->body, sizeof(revocation_response));
    assert(revocation_response.revoked == 0U);
}

static void test_dispatch_security_service_fail_closed_paths(void) {
    struct fbvbs_hypervisor_state state;
    struct aligned_command_page aligned_page;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_partition *kci_partition;
    struct fbvbs_partition *ksi_partition;
    struct fbvbs_partition *iks_partition;
    struct fbvbs_partition *uvs_partition;
    struct fbvbs_kci_set_wx_request set_wx = {
        .module_object_id = 0x3000U,
        .guest_physical_address = 0x4000U,
        .file_offset = 0U,
        .size = FBVBS_PAGE_SIZE,
        .permissions = FBVBS_MEMORY_PERMISSION_READ |
            FBVBS_MEMORY_PERMISSION_WRITE |
            FBVBS_MEMORY_PERMISSION_EXECUTE,
        .reserved0 = 0U,
    };
    struct fbvbs_ksi_register_tier_b_request register_tier_b = {
        .object_id = 0x11000U,
        .guest_physical_address = 0x11000U,
        .size = FBVBS_PAGE_SIZE,
        .protection_class = KSI_CLASS_UCRED,
        .reserved0 = 0U,
    };
    struct fbvbs_ksi_create_target_set_request create_target_set;
    struct fbvbs_ksi_target_set_response target_set;
    struct fbvbs_ksi_register_tier_a_request register_pointer_object = {
        .object_id = 0x12000U,
        .guest_physical_address = 0x12000U,
        .size = FBVBS_PAGE_SIZE,
    };
    struct fbvbs_ksi_register_pointer_request register_pointer;
    struct fbvbs_memory_object_id_request unregister_object = {.memory_object_id = 0x11000U};
    struct fbvbs_iks_import_key_request import_bad_key = {
        .key_material_page_gpa = 0x20000U,
        .key_type = IKS_KEY_ED25519,
        .allowed_ops = IKS_OP_SIGN | IKS_OP_KEY_EXCHANGE,
        .key_length = 32U,
        .reserved0 = 0U,
    };
    struct aligned_metadata_bundle metadata_bundle;
    struct fbvbs_uvs_verify_manifest_set_request verify_manifest_set;
    struct fbvbs_uvs_verify_manifest_set_response manifest_set_response;
    struct fbvbs_uvs_verify_artifact_request verify_artifact;

    fbvbs_hypervisor_init(&state);
    kci_partition = find_partition(&state, create_measured_service_partition(&state, SERVICE_KIND_KCI));
    ksi_partition = find_partition(&state, create_measured_service_partition(&state, SERVICE_KIND_KSI));
    iks_partition = find_partition(&state, create_measured_service_partition(&state, SERVICE_KIND_IKS));
    uvs_partition = find_partition(&state, create_measured_service_partition(&state, SERVICE_KIND_UVS));
    assert(kci_partition != NULL && ksi_partition != NULL && iks_partition != NULL && uvs_partition != NULL);
    prepare_valid_metadata_bundle(&metadata_bundle, 0x2000U);
    prepare_metadata_set_request(&metadata_bundle, &verify_manifest_set);

    prepare_command_page(&aligned_page, FBVBS_CALL_KCI_SET_WX, sizeof(set_wx), 0U);
    fbvbs_copy_memory(aligned_page.page.body, &set_wx, sizeof(set_wx));
    prepare_trap_registers(&registers, &aligned_page.page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_CALLER);

    page = prepare_partition_command_page(kci_partition, 0U, FBVBS_CALL_KCI_SET_WX, sizeof(set_wx), 0U);
    fbvbs_copy_memory(page->body, &set_wx, sizeof(set_wx));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_STATE);

    page = prepare_partition_command_page(ksi_partition, 0U, FBVBS_CALL_KSI_REGISTER_TIER_B, sizeof(register_tier_b), 0U);
    fbvbs_copy_memory(page->body, &register_tier_b, sizeof(register_tier_b));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    fbvbs_zero_memory(&create_target_set, sizeof(create_target_set));
    create_target_set.target_count = 1U;
    create_target_set.target_object_ids[0] = register_tier_b.object_id;
    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_CREATE_TARGET_SET,
        sizeof(create_target_set),
        sizeof(target_set)
    );
    fbvbs_copy_memory(page->body, &create_target_set, sizeof(create_target_set));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&target_set, page->body, sizeof(target_set));

    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_REGISTER_TIER_A,
        sizeof(register_pointer_object),
        0U
    );
    fbvbs_copy_memory(page->body, &register_pointer_object, sizeof(register_pointer_object));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    register_pointer.pointer_object_id = register_pointer_object.object_id;
    register_pointer.target_set_id = target_set.target_set_id;
    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_REGISTER_POINTER,
        sizeof(register_pointer),
        0U
    );
    fbvbs_copy_memory(page->body, &register_pointer, sizeof(register_pointer));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);

    page = prepare_partition_command_page(
        ksi_partition,
        0U,
        FBVBS_CALL_KSI_UNREGISTER_OBJECT,
        sizeof(unregister_object),
        0U
    );
    fbvbs_copy_memory(page->body, &unregister_object, sizeof(unregister_object));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == RESOURCE_BUSY);

    page = prepare_partition_command_page(iks_partition, 0U, FBVBS_CALL_IKS_IMPORT_KEY, sizeof(import_bad_key), 0U);
    fbvbs_copy_memory(page->body, &import_bad_key, sizeof(import_bad_key));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == INVALID_PARAMETER);

    page = prepare_partition_command_page(
        uvs_partition,
        0U,
        FBVBS_CALL_UVS_VERIFY_MANIFEST_SET,
        sizeof(verify_manifest_set),
        sizeof(manifest_set_response)
    );
    fbvbs_copy_memory(page->body, &verify_manifest_set, sizeof(verify_manifest_set));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&manifest_set_response, page->body, sizeof(manifest_set_response));

    fbvbs_zero_memory(&verify_artifact, sizeof(verify_artifact));
    verify_artifact.artifact_hash[0] = 0x55U;
    verify_artifact.verified_manifest_set_id = manifest_set_response.verified_manifest_set_id;
    verify_artifact.manifest_object_id = 0x2000U;
    page = prepare_partition_command_page(
        uvs_partition,
        0U,
        FBVBS_CALL_UVS_VERIFY_ARTIFACT,
        sizeof(verify_artifact),
        0U
    );
    fbvbs_copy_memory(page->body, &verify_artifact, sizeof(verify_artifact));
    prepare_trap_registers(&registers, page);
    assert(fbvbs_dispatch_hypercall(&state, &registers) == DEPENDENCY_UNSATISFIED);
}

static void test_dispatch_diagnostic_calls(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_trap_registers registers;
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_audit_mirror_info_response mirror_info;
    struct fbvbs_diag_capabilities_response capabilities;
    struct fbvbs_diag_artifact_list_response artifact_response;
    struct fbvbs_diag_device_list_response device_response;
    struct fbvbs_artifact_catalog_entry artifact_entry;
    struct fbvbs_device_catalog_entry device_entry;

    fbvbs_hypervisor_init(&state);

    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_AUDIT_GET_MIRROR_INFO, 0U, sizeof(mirror_info));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&mirror_info, page->body, sizeof(mirror_info));
    assert(mirror_info.ring_gpa == 0U);  /* mirror_log is not guest-accessible */
    assert(mirror_info.ring_size == sizeof(state.mirror_log));
    assert(mirror_info.record_size == FBVBS_LOG_RECORD_V1_SIZE);

    page = prepare_host_dispatch_page(&state, &registers, FBVBS_CALL_DIAG_GET_CAPABILITIES, 0U, sizeof(capabilities));
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&capabilities, page->body, sizeof(capabilities));
    assert(capabilities.capability_bitmap0 == state.capability_bitmap0);
    assert(capabilities.capability_bitmap1 == state.capability_bitmap1);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_DIAG_GET_ARTIFACT_LIST,
        0U,
        sizeof(artifact_response)
    );
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&artifact_response, page->body, sizeof(artifact_response));
    assert(artifact_response.count == 20U);
    fbvbs_copy_memory(&artifact_entry, artifact_response.entries, sizeof(artifact_entry));
    assert(artifact_entry.object_id == 0x1000U);
    assert(artifact_entry.object_kind == FBVBS_ARTIFACT_OBJECT_IMAGE);
    fbvbs_copy_memory(
        &artifact_entry,
        &artifact_response.entries[(artifact_response.count - 1U) * sizeof(artifact_entry)],
        sizeof(artifact_entry)
    );
    assert(artifact_entry.object_id == 0x2900U);
    assert(artifact_entry.object_kind == FBVBS_ARTIFACT_OBJECT_MANIFEST);

    page = prepare_host_dispatch_page(
        &state,
        &registers,
        FBVBS_CALL_DIAG_GET_DEVICE_LIST,
        0U,
        sizeof(device_response)
    );
    assert(fbvbs_dispatch_hypercall(&state, &registers) == OK);
    fbvbs_copy_memory(&device_response, page->body, sizeof(device_response));
    assert(device_response.count == 1U);
    fbvbs_copy_memory(&device_entry, device_response.entries, sizeof(device_entry));
    assert(device_entry.device_id == 0xD000U);
    assert(device_entry.bus == 2U);
}

int main(void) {
    test_partition_lifecycle();
    test_mirror_log_header_and_wraparound();
    test_log_append_rejects_invalid_inputs();
    test_dispatch_rejects_unzeroed_tail();
    test_dispatch_rejects_replayed_sequence();
    test_dispatch_rejects_nonzero_actual_output_length();
    test_dispatch_creates_partition_and_reports_status();
    test_partition_create_rejects_manifest_profile_mismatch();
    test_partition_measure_rejects_non_derived_manifest();
    test_partition_measure_requires_uvs_approval();
    test_uvs_manifest_set_detects_metadata_failures();
    test_dispatch_uvs_manifest_set_failure_returns_structured_body();
    test_uvs_check_revocation_reports_recorded_objects();
    test_partition_load_rejects_manifest_profile_mismatch();
    test_guest_vm_measure_rejects_trusted_service_artifact();
    test_guest_vm_load_uses_manifest_entry_and_requires_stack();
    test_trusted_service_load_allows_manifest_defaults();
    test_manifest_profiles_drive_partition_create_and_load();
    test_boot_catalog_ingestion_rejects_invalid_related_index();
    test_dispatch_memory_allocate_and_release();
    test_dispatch_memory_mapping_and_shared_calls();
    test_shared_registration_charges_peer_limit_and_reserved_peer_zero();
    test_dispatch_vm_register_and_status_calls();
    test_dispatch_vm_run_memory_and_device_calls();
    test_multi_vcpu_partition_state_aggregation();
    test_platform_capability_gates();
    test_iommu_domain_lifecycle_logs();
    test_vm_destroy_releases_iommu_domain();
    test_partition_destroy_releases_attached_resources();
    test_partition_command_page_binds_service_identity();
    test_fixed_host_partition_bootstrap_and_diag();
    test_host_only_calls_require_owned_host_command_page();
    test_host_callsites_reject_wrong_frontend_rip();
    test_manifest_derived_host_callsites_relocate();
    test_host_dispatch_security_service_calls();
    test_kci_verify_module_requires_uvs_approval();
    test_uvs_verify_artifact_requires_manifest_membership();
    test_ksi_validate_setuid_enforces_operation_policy();
    test_separate_output_requires_reserved_shared_mapping();
    test_dispatch_security_service_calls();
    test_dispatch_security_service_fail_closed_paths();
    test_dispatch_diagnostic_calls();
    return 0;
}