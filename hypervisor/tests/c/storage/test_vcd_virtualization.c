#include <assert.h>
#include <string.h>

#include "../include/fbvbs_hypervisor.h"

static struct fbvbs_vcd_rx_ring_page g_rx_ring0 __attribute__((aligned(FBVBS_PAGE_SIZE)));
static struct fbvbs_vcd_tx_ring_page g_tx_ring0 __attribute__((aligned(FBVBS_PAGE_SIZE)));
static struct fbvbs_vcd_rx_ring_page g_rx_ring1 __attribute__((aligned(FBVBS_PAGE_SIZE)));
static struct fbvbs_vcd_tx_ring_page g_tx_ring1 __attribute__((aligned(FBVBS_PAGE_SIZE)));

static void init_ocs_partition(
    struct fbvbs_hypervisor_state *state,
    uint32_t slot,
    uint64_t partition_id,
    uint64_t capability_mask
)
{
    state->partitions[slot] = (struct fbvbs_partition){0};
    state->partitions[slot].occupied = true;
    state->partitions[slot].partition_id = partition_id;
    state->partitions[slot].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state->partitions[slot].service_kind = SERVICE_KIND_OCS;
    state->partitions[slot].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state->partitions[slot].vcpu_count = 1U;
    state->partitions[slot].capability_mask = capability_mask;
}

static void init_mapping(
    struct fbvbs_partition *partition,
    uint32_t slot,
    uint64_t gpa,
    uint64_t size,
    uint16_t permissions,
    uint64_t object_id
)
{
    partition->mappings[slot] = (struct fbvbs_memory_mapping){0};
    partition->mappings[slot].active = true;
    partition->mappings[slot].permissions = permissions;
    partition->mappings[slot].memory_object_id = object_id;
    partition->mappings[slot].guest_physical_address = gpa;
    partition->mappings[slot].size = size;
}

static void attach_vcd_for_partition(
    struct fbvbs_hypervisor_state *state,
    uint32_t slot,
    uint64_t partition_id,
    struct fbvbs_vcd_rx_ring_page *rx_ring,
    struct fbvbs_vcd_tx_ring_page *tx_ring
)
{
    struct fbvbs_ocs_vcd_attach_request request;
    uint64_t perms;
    int status;

    memset(rx_ring, 0, sizeof(*rx_ring));
    memset(tx_ring, 0, sizeof(*tx_ring));
    init_ocs_partition(state, slot, partition_id, FBVBS_CAP_OCS_ACCESS);
    perms = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;
    init_mapping(
        &state->partitions[slot],
        0U,
        (uint64_t)(uintptr_t)rx_ring,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xC000U + slot * 2U
    );
    init_mapping(
        &state->partitions[slot],
        1U,
        (uint64_t)(uintptr_t)tx_ring,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xC001U + slot * 2U
    );
    request = (struct fbvbs_ocs_vcd_attach_request){
        .rx_ring_gpa = (uint64_t)(uintptr_t)rx_ring,
        .tx_ring_gpa = (uint64_t)(uintptr_t)tx_ring,
    };
    status = fbvbs_ocs_vcd_attach(state, &request, partition_id);
    assert(status == OK);
}

static void enqueue_ocs_message(
    struct fbvbs_vcd_rx_ring_page *ring,
    const struct fbvbs_ocs_message_header *header,
    const void *payload
)
{
    if (ring->header.read_index == ring->header.write_index) {
        ring->header.read_index = 0U;
        ring->header.write_index = 0U;
    }
    assert(ring->header.write_index + (uint32_t)sizeof(*header) + header->payload_length <=
           FBVBS_VCD_RX_RING_SIZE);
    memcpy(ring->buffer + ring->header.write_index, header, sizeof(*header));
    ring->header.write_index += (uint32_t)sizeof(*header);
    if (header->payload_length != 0U && payload != NULL) {
        memcpy(
            ring->buffer + ring->header.write_index,
            payload,
            header->payload_length
        );
        ring->header.write_index += header->payload_length;
    }
}

static void read_ocs_response(
    struct fbvbs_vcd_tx_ring_page *ring,
    struct fbvbs_ocs_message_header *header,
    void *payload,
    uint32_t payload_size
)
{
    memcpy(header, ring->buffer + ring->header.read_index, sizeof(*header));
    ring->header.read_index += (uint32_t)sizeof(*header);
    if (header->payload_length != 0U) {
        assert(header->payload_length <= payload_size);
        memcpy(payload, ring->buffer + ring->header.read_index, header->payload_length);
        ring->header.read_index += header->payload_length;
    }
    if (ring->header.read_index == ring->header.write_index) {
        ring->header.read_index = 0U;
        ring->header.write_index = 0U;
    }
}

static void test_vcd_attach_and_status_success(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_ocs_vcd_attach_request request;
    struct fbvbs_ocs_vcd_status_response response;
    uint64_t perms;
    int status;

    memset(&state, 0, sizeof(state));
    memset(&g_rx_ring0, 0, sizeof(g_rx_ring0));
    memset(&g_tx_ring0, 0, sizeof(g_tx_ring0));

    init_ocs_partition(&state, 0U, 0x7001U, FBVBS_CAP_OCS_ACCESS);

    perms = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;
    init_mapping(
        &state.partitions[0],
        0U,
        (uint64_t)(uintptr_t)&g_rx_ring0,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB000U
    );
    init_mapping(
        &state.partitions[0],
        1U,
        (uint64_t)(uintptr_t)&g_tx_ring0,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB001U
    );

    request = (struct fbvbs_ocs_vcd_attach_request){
        .rx_ring_gpa = (uint64_t)(uintptr_t)&g_rx_ring0,
        .tx_ring_gpa = (uint64_t)(uintptr_t)&g_tx_ring0,
    };

    status = fbvbs_ocs_vcd_attach(&state, &request, 0x7001U);
    assert(status == OK);
    assert(state.vcd.active);
    assert(state.vcd.owner_partition_id == 0x7001U);
    assert(g_rx_ring0.header.magic == FBVBS_VCD_RING_MAGIC);
    assert(g_rx_ring0.header.size == FBVBS_VCD_RX_RING_SIZE);
    assert(g_tx_ring0.header.magic == FBVBS_VCD_RING_MAGIC);
    assert(g_tx_ring0.header.size == FBVBS_VCD_TX_RING_SIZE);

    response = (struct fbvbs_ocs_vcd_status_response){0};
    status = fbvbs_ocs_vcd_status(&state, &response, 0x7001U);
    assert(status == OK);
    assert(response.active == 1U);
    assert(response.owner_partition_id == 0x7001U);
    assert(response.rx_ring_gpa == request.rx_ring_gpa);
    assert(response.tx_ring_gpa == request.tx_ring_gpa);
}

static void test_vcd_rejects_invalid_callers_and_caps(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_ocs_vcd_attach_request request;
    uint64_t perms;
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0] = (struct fbvbs_partition){0};
    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7100U;
    state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state.partitions[0].service_kind = SERVICE_KIND_NONE;
    state.partitions[0].capability_mask = FBVBS_CAP_OCS_ACCESS;

    request = (struct fbvbs_ocs_vcd_attach_request){
        .rx_ring_gpa = (uint64_t)(uintptr_t)&g_rx_ring0,
        .tx_ring_gpa = (uint64_t)(uintptr_t)&g_tx_ring0,
    };
    status = fbvbs_ocs_vcd_attach(&state, &request, 0x7100U);
    assert(status == INVALID_CALLER);

    memset(&state, 0, sizeof(state));
    init_ocs_partition(&state, 0U, 0x7101U, 0U);
    perms = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;
    init_mapping(
        &state.partitions[0],
        0U,
        (uint64_t)(uintptr_t)&g_rx_ring0,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB100U
    );
    init_mapping(
        &state.partitions[0],
        1U,
        (uint64_t)(uintptr_t)&g_tx_ring0,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB101U
    );
    status = fbvbs_ocs_vcd_attach(&state, &request, 0x7101U);
    assert(status == PERMISSION_DENIED);

    memset(&state, 0, sizeof(state));
    init_ocs_partition(&state, 0U, 0x7102U, FBVBS_CAP_OCS_ACCESS);
    state.partitions[0].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;
    init_mapping(
        &state.partitions[0],
        0U,
        (uint64_t)(uintptr_t)&g_rx_ring0,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB102U
    );
    init_mapping(
        &state.partitions[0],
        1U,
        (uint64_t)(uintptr_t)&g_tx_ring0,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB103U
    );
    status = fbvbs_ocs_vcd_attach(&state, &request, 0x7102U);
    assert(status == PERMISSION_DENIED);
}

static void test_vcd_owner_mismatch_denies_without_teardown(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_ocs_vcd_attach_request request;
    struct fbvbs_ocs_vcd_status_response response;
    uint64_t perms;
    int status;

    memset(&state, 0, sizeof(state));
    init_ocs_partition(&state, 0U, 0x7201U, FBVBS_CAP_OCS_ACCESS);
    init_ocs_partition(&state, 1U, 0x7202U, FBVBS_CAP_OCS_ACCESS);

    perms = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;
    init_mapping(
        &state.partitions[0],
        0U,
        (uint64_t)(uintptr_t)&g_rx_ring0,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB200U
    );
    init_mapping(
        &state.partitions[0],
        1U,
        (uint64_t)(uintptr_t)&g_tx_ring0,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB201U
    );

    request = (struct fbvbs_ocs_vcd_attach_request){
        .rx_ring_gpa = (uint64_t)(uintptr_t)&g_rx_ring0,
        .tx_ring_gpa = (uint64_t)(uintptr_t)&g_tx_ring0,
    };

    status = fbvbs_ocs_vcd_attach(&state, &request, 0x7201U);
    assert(status == OK);

    response = (struct fbvbs_ocs_vcd_status_response){0};
    status = fbvbs_ocs_vcd_status(&state, &response, 0x7202U);
    assert(status == PERMISSION_DENIED);
    assert(state.vcd.active);
    assert(state.vcd.owner_partition_id == 0x7201U);
    assert(state.vcd.corruption_count == 1U);

    status = fbvbs_ocs_vcd_status(&state, &response, 0x7201U);
    assert(status == OK);
    assert(response.active == 1U);
    assert(response.owner_partition_id == 0x7201U);
}

static void test_vcd_owner_mismatch_audit_is_not_rate_limited(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_ocs_vcd_status_response response;
    const struct fbvbs_log_record_v1 *record;
    uint32_t event_class;
    uint64_t seq_before;
    int status;

    memset(&state, 0, sizeof(state));
    attach_vcd_for_partition(&state, 0U, 0x7211U, &g_rx_ring0, &g_tx_ring0);
    init_ocs_partition(&state, 1U, 0x7212U, FBVBS_CAP_OCS_ACCESS);

    event_class = ((uint32_t)FBVBS_EVENT_VCD_STATE_CHANGE >> 4U) &
        (FBVBS_RATE_LIMIT_CLASSES - 1U);
    state.log_rate_window_sequence = state.mirror_log.header.max_readable_sequence;
    state.log_rate_counts[event_class] = FBVBS_RATE_LIMIT_THRESHOLD;

    seq_before = state.mirror_log.header.max_readable_sequence;
    response = (struct fbvbs_ocs_vcd_status_response){0};
    status = fbvbs_ocs_vcd_status(&state, &response, 0x7212U);
    assert(status == PERMISSION_DENIED);
    assert(state.mirror_log.header.max_readable_sequence == seq_before + 1U);

    record = &state.mirror_log.records[
        (state.mirror_log.header.max_readable_sequence - 1U) % FBVBS_LOG_SLOT_COUNT
    ];
    assert(record->event_code == FBVBS_EVENT_VCD_STATE_CHANGE);
    assert(((const struct fbvbs_audit_vcd_event *)(const void *)record->payload)->operation ==
           FBVBS_VCD_AUDIT_OP_OWNER_MISMATCH);
}

static void test_vcd_attach_rejects_mapping_errors_and_reuse(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_ocs_vcd_attach_request request0;
    struct fbvbs_ocs_vcd_attach_request request1;
    uint64_t perms;
    int status;

    memset(&state, 0, sizeof(state));
    init_ocs_partition(&state, 0U, 0x7301U, FBVBS_CAP_OCS_ACCESS);
    init_ocs_partition(&state, 1U, 0x7302U, FBVBS_CAP_OCS_ACCESS);

    request0 = (struct fbvbs_ocs_vcd_attach_request){
        .rx_ring_gpa = (uint64_t)(uintptr_t)&g_rx_ring0,
        .tx_ring_gpa = (uint64_t)(uintptr_t)&g_tx_ring0,
    };

    status = fbvbs_ocs_vcd_attach(&state, &request0, 0x7301U);
    assert(status == INVALID_PARAMETER);

    perms = FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE;
    init_mapping(
        &state.partitions[0],
        0U,
        (uint64_t)(uintptr_t)&g_rx_ring0,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB300U
    );
    init_mapping(
        &state.partitions[0],
        1U,
        (uint64_t)(uintptr_t)&g_tx_ring0,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB301U
    );

    status = fbvbs_ocs_vcd_attach(&state, &request0, 0x7301U);
    assert(status == OK);

    status = fbvbs_ocs_vcd_attach(&state, &request0, 0x7301U);
    assert(status == ALREADY_EXISTS);

    request1 = (struct fbvbs_ocs_vcd_attach_request){
        .rx_ring_gpa = (uint64_t)(uintptr_t)&g_rx_ring1,
        .tx_ring_gpa = (uint64_t)(uintptr_t)&g_tx_ring1,
    };

    init_mapping(
        &state.partitions[1],
        0U,
        (uint64_t)(uintptr_t)&g_rx_ring1,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB302U
    );
    init_mapping(
        &state.partitions[1],
        1U,
        (uint64_t)(uintptr_t)&g_tx_ring1,
        FBVBS_PAGE_SIZE,
        (uint16_t)perms,
        0xB303U
    );

    status = fbvbs_ocs_vcd_attach(&state, &request1, 0x7302U);
    assert(status == PERMISSION_DENIED);
}

static void test_ocs_runtime_hello_and_summary_commands(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_ocs_message_header request;
    struct fbvbs_ocs_message_header response_header;
    struct fbvbs_ocs_hello_response hello;
    struct fbvbs_ocs_system_summary_response system_summary;
    struct fbvbs_ocs_partition_summary_response partition_summary;
    struct fbvbs_ocs_scaling_summary_response scaling_summary;
    struct fbvbs_ocs_storage_summary_response storage_summary;
    struct fbvbs_ocs_help_response help;
    int status;

    memset(&state, 0, sizeof(state));
    attach_vcd_for_partition(&state, 0U, 0x7401U, &g_rx_ring0, &g_tx_ring0);

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x7402U;
    state.partitions[1].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[1].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[1].health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;

    state.partitions[2].occupied = true;
    state.partitions[2].partition_id = 0x7403U;
    state.partitions[2].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[2].service_kind = SERVICE_KIND_OCS;
    state.partitions[2].health_state = FBVBS_PARTITION_HEALTH_RECOVERY;

    state.scaling_limits.max_vm_count_runtime = 16U;
    state.scaling_limits.max_vcpus_per_vm_runtime = 8U;
    state.scaling_limits.max_host_cpu_count_runtime = 32U;
    state.scaling_limits.max_vdisks_per_vm_runtime = 4U;
    state.scaling_limits.max_memory_per_vm_runtime_bytes = 0x20000000ULL;
    state.scaling_limits.max_vdisk_size_runtime_bytes = 0x40000000ULL;

    state.storage_pools[0].active = true;
    state.virtual_disks[0].active = true;
    state.virtual_disks[0].attached = true;

    request = (struct fbvbs_ocs_message_header){
        .magic = FBVBS_OCS_MESSAGE_MAGIC,
        .opcode = FBVBS_OCS_OPCODE_HELLO,
        .status = 0U,
        .payload_length = 0U,
        .reserved0 = 0U,
        .session_id = 0U,
        .sequence = 1U,
    };
    enqueue_ocs_message(&g_rx_ring0, &request, NULL);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&hello, 0, sizeof(hello));
    read_ocs_response(&g_tx_ring0, &response_header, &hello, (uint32_t)sizeof(hello));
    assert(response_header.status == OK);
    assert(hello.protocol_version == FBVBS_OCS_PROTOCOL_VERSION);
    assert(hello.owner_partition_id == 0x7401U);
    assert(hello.session_id != 0U);
    assert(state.ocs_runtime.active);
    assert(state.ocs_runtime.command_count == 1U);

    request = (struct fbvbs_ocs_message_header){
        .magic = FBVBS_OCS_MESSAGE_MAGIC,
        .opcode = FBVBS_OCS_OPCODE_GET_SYSTEM_SUMMARY,
        .status = 0U,
        .payload_length = 0U,
        .reserved0 = 0U,
        .session_id = hello.session_id,
        .sequence = 2U,
    };
    enqueue_ocs_message(&g_rx_ring0, &request, NULL);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&system_summary, 0, sizeof(system_summary));
    read_ocs_response(
        &g_tx_ring0,
        &response_header,
        &system_summary,
        (uint32_t)sizeof(system_summary)
    );
    assert(system_summary.occupied_partition_count == 3U);
    assert(system_summary.quarantined_partition_count == 1U);
    assert(system_summary.recovery_partition_count == 1U);
    assert(system_summary.active_vcd == 1U);
    assert(system_summary.session_active == 1U);

    request.opcode = FBVBS_OCS_OPCODE_GET_PARTITION_SUMMARY;
    request.sequence = 3U;
    enqueue_ocs_message(&g_rx_ring0, &request, NULL);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&partition_summary, 0, sizeof(partition_summary));
    read_ocs_response(
        &g_tx_ring0,
        &response_header,
        &partition_summary,
        (uint32_t)sizeof(partition_summary)
    );
    assert(partition_summary.occupied_partition_count == 3U);
    assert(partition_summary.guest_vm_count == 1U);
    assert(partition_summary.service_partition_count == 2U);
    assert(partition_summary.faulted_partition_count == 1U);

    request.opcode = FBVBS_OCS_OPCODE_GET_SCALING_SUMMARY;
    request.sequence = 4U;
    enqueue_ocs_message(&g_rx_ring0, &request, NULL);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&scaling_summary, 0, sizeof(scaling_summary));
    read_ocs_response(
        &g_tx_ring0,
        &response_header,
        &scaling_summary,
        (uint32_t)sizeof(scaling_summary)
    );
    assert(scaling_summary.runtime_max_vm_count == 16U);
    assert(scaling_summary.runtime_max_vcpus_per_vm == 8U);
    assert(scaling_summary.runtime_max_vdisk_size_bytes == 0x40000000ULL);

    request.opcode = FBVBS_OCS_OPCODE_GET_STORAGE_SUMMARY;
    request.sequence = 5U;
    enqueue_ocs_message(&g_rx_ring0, &request, NULL);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&storage_summary, 0, sizeof(storage_summary));
    read_ocs_response(
        &g_tx_ring0,
        &response_header,
        &storage_summary,
        (uint32_t)sizeof(storage_summary)
    );
    assert(storage_summary.active_pool_count == 1U);
    assert(storage_summary.active_vdisk_count == 1U);
    assert(storage_summary.attached_vdisk_count == 1U);

    request.opcode = FBVBS_OCS_OPCODE_GET_HELP;
    request.sequence = 6U;
    enqueue_ocs_message(&g_rx_ring0, &request, NULL);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&help, 0, sizeof(help));
    read_ocs_response(&g_tx_ring0, &response_header, &help, (uint32_t)sizeof(help));
    assert(help.supported_opcode_count == 9U);
    assert(help.supported_opcodes[0] == FBVBS_OCS_OPCODE_HELLO);
    assert(help.supported_opcodes[5] == FBVBS_OCS_OPCODE_GET_HELP);
    assert(help.supported_opcodes[8] == FBVBS_OCS_OPCODE_RECOVER_PARTITION);
    assert(state.ocs_runtime.command_count == 6U);
}

static void test_ocs_runtime_partition_control_commands(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_ocs_message_header request;
    struct fbvbs_ocs_message_header response_header;
    struct fbvbs_ocs_hello_response hello;
    struct fbvbs_ocs_partition_control_response control;
    struct fbvbs_partition_id_request partition_request;
    struct fbvbs_partition_recover_request recover_request;
    int status;

    memset(&state, 0, sizeof(state));
    attach_vcd_for_partition(&state, 0U, 0x7701U, &g_rx_ring0, &g_tx_ring0);
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;

    state.partitions[1].occupied = true;
    state.partitions[1].partition_id = 0x7702U;
    state.partitions[1].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[1].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state.partitions[1].health_state = FBVBS_PARTITION_HEALTH_HEALTHY;
    state.partitions[1].manifest_object_id = 0x9000U;
    state.partitions[1].image_object_id = 0x9001U;
    state.partitions[1].entry_ip = 0x1000U;
    state.partitions[1].initial_sp = 0x2000U;

    request = (struct fbvbs_ocs_message_header){
        .magic = FBVBS_OCS_MESSAGE_MAGIC,
        .opcode = FBVBS_OCS_OPCODE_HELLO,
        .status = 0U,
        .payload_length = 0U,
        .reserved0 = 0U,
        .session_id = 0U,
        .sequence = 20U,
    };
    enqueue_ocs_message(&g_rx_ring0, &request, NULL);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&hello, 0, sizeof(hello));
    read_ocs_response(&g_tx_ring0, &response_header, &hello, (uint32_t)sizeof(hello));

    partition_request = (struct fbvbs_partition_id_request){
        .partition_id = 0x7702U,
    };
    request.opcode = FBVBS_OCS_OPCODE_QUIESCE_PARTITION;
    request.session_id = hello.session_id;
    request.sequence = 21U;
    request.payload_length = (uint32_t)sizeof(partition_request);
    enqueue_ocs_message(&g_rx_ring0, &request, &partition_request);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&control, 0, sizeof(control));
    read_ocs_response(&g_tx_ring0, &response_header, &control, (uint32_t)sizeof(control));
    assert(response_header.status == OK);
    assert(control.partition_id == 0x7702U);
    assert(control.partition_state == FBVBS_PARTITION_STATE_QUIESCED);
    assert(control.health_state == FBVBS_PARTITION_HEALTH_DEGRADED);

    request.opcode = FBVBS_OCS_OPCODE_RESUME_PARTITION;
    request.sequence = 22U;
    enqueue_ocs_message(&g_rx_ring0, &request, &partition_request);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&control, 0, sizeof(control));
    read_ocs_response(&g_tx_ring0, &response_header, &control, (uint32_t)sizeof(control));
    assert(control.partition_state == FBVBS_PARTITION_STATE_RUNNABLE);
    assert(control.health_state == FBVBS_PARTITION_HEALTH_HEALTHY);

    status = fbvbs_partition_fault(&state, 0x7702U, 0x55U, FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0U, 0U);
    assert(status == OK);

    recover_request = (struct fbvbs_partition_recover_request){
        .partition_id = 0x7702U,
        .recovery_flags = 0U,
        .session_correlation_id = hello.session_id,
        .confirmation_nonce = 23U,
        .approval_expires_utc = 3600U,
        .reserved0 = 0U,
        .reserved1 = 0U,
    };
    {
        struct {
            uint64_t partition_id;
            uint64_t session_correlation_id;
            uint64_t confirmation_nonce;
        } ledger_seed = {
            .partition_id = recover_request.partition_id,
            .session_correlation_id = recover_request.session_correlation_id,
            .confirmation_nonce = recover_request.confirmation_nonce,
        };
        fbvbs_sha384(
            &ledger_seed,
            (uint64_t)sizeof(ledger_seed),
            recover_request.approval_ledger_digest
        );
    }
    fbvbs_partition_compute_recovery_approval_digest(
        &state,
        recover_request.partition_id,
        recover_request.recovery_flags,
        recover_request.session_correlation_id,
        recover_request.confirmation_nonce,
        recover_request.approval_expires_utc,
        recover_request.approval_ledger_digest,
        recover_request.recovery_approval_digest
    );
    request.opcode = FBVBS_OCS_OPCODE_RECOVER_PARTITION;
    request.sequence = 23U;
    request.payload_length = (uint32_t)sizeof(recover_request);
    enqueue_ocs_message(&g_rx_ring0, &request, &recover_request);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&control, 0, sizeof(control));
    read_ocs_response(&g_tx_ring0, &response_header, &control, (uint32_t)sizeof(control));
    assert(control.partition_state == FBVBS_PARTITION_STATE_RUNNABLE);
    assert(control.health_state == FBVBS_PARTITION_HEALTH_RECOVERY);
    assert(control.quarantine_reason == 0U);
    assert(control.fault_code == 0U);
}

static void test_ocs_runtime_rejects_invalid_session_and_replay(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_ocs_message_header request;
    struct fbvbs_ocs_message_header response_header;
    struct fbvbs_ocs_hello_response hello;
    int status;

    memset(&state, 0, sizeof(state));
    attach_vcd_for_partition(&state, 0U, 0x7501U, &g_rx_ring0, &g_tx_ring0);

    request = (struct fbvbs_ocs_message_header){
        .magic = FBVBS_OCS_MESSAGE_MAGIC,
        .opcode = FBVBS_OCS_OPCODE_HELLO,
        .status = 0U,
        .payload_length = 0U,
        .reserved0 = 0U,
        .session_id = 0U,
        .sequence = 10U,
    };
    enqueue_ocs_message(&g_rx_ring0, &request, NULL);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    memset(&hello, 0, sizeof(hello));
    read_ocs_response(&g_tx_ring0, &response_header, &hello, (uint32_t)sizeof(hello));

    request.opcode = FBVBS_OCS_OPCODE_GET_SYSTEM_SUMMARY;
    request.session_id = hello.session_id ^ 0x55U;
    request.sequence = 11U;
    enqueue_ocs_message(&g_rx_ring0, &request, NULL);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    read_ocs_response(&g_tx_ring0, &response_header, NULL, 0U);
    assert(response_header.status == (uint16_t)INVALID_STATE);

    request.session_id = hello.session_id;
    request.sequence = 10U;
    enqueue_ocs_message(&g_rx_ring0, &request, NULL);
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == OK);
    read_ocs_response(&g_tx_ring0, &response_header, NULL, 0U);
    assert(response_header.status == (uint16_t)REPLAY_DETECTED);
}

static void test_ocs_runtime_detects_ring_corruption(void)
{
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));
    attach_vcd_for_partition(&state, 0U, 0x7601U, &g_rx_ring0, &g_tx_ring0);

    g_rx_ring0.header.magic = 0U;
    status = fbvbs_ocs_runtime_poll(&state);
    assert(status == INTERNAL_CORRUPTION);
    assert(state.vcd.corruption_count == 1U);
}

int main(void)
{
    test_vcd_attach_and_status_success();
    test_vcd_rejects_invalid_callers_and_caps();
    test_vcd_owner_mismatch_denies_without_teardown();
    test_vcd_owner_mismatch_audit_is_not_rate_limited();
    test_vcd_attach_rejects_mapping_errors_and_reuse();
    test_ocs_runtime_hello_and_summary_commands();
    test_ocs_runtime_partition_control_commands();
    test_ocs_runtime_rejects_invalid_session_and_replay();
    test_ocs_runtime_detects_ring_corruption();
    return 0;
}
