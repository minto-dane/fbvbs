#include "fbvbs_hypervisor.h"

#include <string.h>

static void fbvbs_vcd_state_lock(volatile uint32_t *lock)
{
#ifdef __FRAMAC__
    if (lock != NULL) {
        *lock = 1U;
    }
    return;
#else
    while (__sync_lock_test_and_set(lock, 1U) != 0U) {
        /* busy wait */
    }
#endif
}

static void fbvbs_vcd_state_unlock(volatile uint32_t *lock)
{
#ifndef __FRAMAC__
    __sync_lock_release(lock);
#else
    if (lock != NULL) {
        *lock = 0U;
    }
#endif
}

static struct fbvbs_vcd_rx_ring_page *fbvbs_vcd_rx_ring(
    struct fbvbs_hypervisor_state *state
)
{
    if (state == NULL || state->vcd.rx_ring_gpa == 0U) {
        return NULL;
    }
    return (struct fbvbs_vcd_rx_ring_page *)(uintptr_t)state->vcd.rx_ring_gpa;
}

static struct fbvbs_vcd_tx_ring_page *fbvbs_vcd_tx_ring(
    struct fbvbs_hypervisor_state *state
)
{
    if (state == NULL || state->vcd.tx_ring_gpa == 0U) {
        return NULL;
    }
    return (struct fbvbs_vcd_tx_ring_page *)(uintptr_t)state->vcd.tx_ring_gpa;
}

static void fbvbs_vcd_ring_init(struct fbvbs_vcd_ring_header *header, uint32_t size)
{
    if (header == NULL) {
        return;
    }
    header->write_index = 0U;
    header->read_index = 0U;
    header->size = size;
    header->magic = FBVBS_VCD_RING_MAGIC;
}

static uint32_t fbvbs_vcd_ring_used(const struct fbvbs_vcd_ring_header *header)
{
    uint32_t write_index;
    uint32_t read_index;

    if (header == NULL || header->size == 0U) {
        return 0U;
    }
    write_index = header->write_index;
    read_index = header->read_index;
    if (write_index >= read_index) {
        return write_index - read_index;
    }
    return header->size - read_index + write_index;
}

static uint32_t fbvbs_vcd_ring_free(const struct fbvbs_vcd_ring_header *header)
{
    if (header == NULL || header->size == 0U) {
        return 0U;
    }
    return (header->size - 1U) - fbvbs_vcd_ring_used(header);
}

static void fbvbs_vcd_ring_copy_out(
    const struct fbvbs_vcd_ring_header *header,
    const uint8_t *buffer,
    uint32_t start_index,
    uint8_t *output,
    uint32_t length
)
{
    uint32_t index;

    for (index = 0U; index < length; ++index) {
        output[index] = buffer[(start_index + index) % header->size];
    }
}

static void fbvbs_vcd_ring_copy_in(
    struct fbvbs_vcd_ring_header *header,
    uint8_t *buffer,
    const uint8_t *input,
    uint32_t length
)
{
    uint32_t index;
    uint32_t write_index;

    if (header == NULL || buffer == NULL || input == NULL) {
        return;
    }
    write_index = header->write_index;
    for (index = 0U; index < length; ++index) {
        buffer[(write_index + index) % header->size] = input[index];
    }
    header->write_index = (write_index + length) % header->size;
}

static int fbvbs_vcd_read_message(
    struct fbvbs_vcd_rx_ring_page *ring,
    struct fbvbs_ocs_message_header *header,
    uint8_t *payload,
    uint32_t payload_capacity
)
{
    uint32_t used;
    uint32_t message_size;
    uint32_t start_index;

    if (ring == NULL || header == NULL || payload == NULL) {
        return INVALID_PARAMETER;
    }
    used = fbvbs_vcd_ring_used(&ring->header);
    if (used < sizeof(*header)) {
        return NOT_FOUND;
    }
    start_index = ring->header.read_index;
    fbvbs_vcd_ring_copy_out(
        &ring->header,
        ring->buffer,
        start_index,
        (uint8_t *)(void *)header,
        (uint32_t)sizeof(*header)
    );
    if (header->magic != FBVBS_OCS_MESSAGE_MAGIC) {
        return INTERNAL_CORRUPTION;
    }
    if (header->payload_length > payload_capacity) {
        return BUFFER_TOO_SMALL;
    }
    message_size = (uint32_t)sizeof(*header) + header->payload_length;
    if (used < message_size) {
        return NOT_FOUND;
    }
    fbvbs_vcd_ring_copy_out(
        &ring->header,
        ring->buffer,
        (start_index + (uint32_t)sizeof(*header)) % ring->header.size,
        payload,
        header->payload_length
    );
    ring->header.read_index = (start_index + message_size) % ring->header.size;
    return OK;
}

static int fbvbs_vcd_write_message(
    struct fbvbs_vcd_tx_ring_page *ring,
    const struct fbvbs_ocs_message_header *header,
    const void *payload
)
{
    uint32_t message_size;

    if (ring == NULL || header == NULL) {
        return INVALID_PARAMETER;
    }
    message_size = (uint32_t)sizeof(*header) + header->payload_length;
    if (fbvbs_vcd_ring_free(&ring->header) < message_size) {
        return RESOURCE_BUSY;
    }
    fbvbs_vcd_ring_copy_in(
        &ring->header,
        ring->buffer,
        (const uint8_t *)(const void *)header,
        (uint32_t)sizeof(*header)
    );
    if (header->payload_length != 0U && payload != NULL) {
        fbvbs_vcd_ring_copy_in(
            &ring->header,
            ring->buffer,
            (const uint8_t *)payload,
            header->payload_length
        );
    }
    return OK;
}

static int fbvbs_ocs_runtime_summarize_system(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_ocs_system_summary_response *response
)
{
    struct fbvbs_diag_inventory_response inventory = {0};
    int status;

    if (state == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_inventory(state, &inventory);
    if (status != OK) {
        return status;
    }
    *response = (struct fbvbs_ocs_system_summary_response){
        .occupied_partition_count = inventory.occupied_partition_count,
        .healthy_partition_count = inventory.healthy_partition_count,
        .degraded_partition_count = inventory.degraded_partition_count,
        .quarantined_partition_count = inventory.quarantined_partition_count,
        .recovery_partition_count = inventory.recovery_partition_count,
        .active_vcd = state->vcd.active ? 1U : 0U,
        .session_active = state->ocs_runtime.active ? 1U : 0U,
        .reserved0 = 0U,
    };
    return OK;
}

static int fbvbs_ocs_runtime_summarize_partitions(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_ocs_partition_summary_response *response
)
{
    uint32_t index;

    if (state == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    *response = (struct fbvbs_ocs_partition_summary_response){0};
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        const struct fbvbs_partition *partition = &state->partitions[index];
        if (!partition->occupied) {
            continue;
        }
        response->occupied_partition_count += 1U;
        if (partition->kind == PARTITION_KIND_GUEST_VM) {
            response->guest_vm_count += 1U;
        }
        if (partition->kind == PARTITION_KIND_TRUSTED_SERVICE) {
            response->service_partition_count += 1U;
        }
        if (partition->state == FBVBS_PARTITION_STATE_FAULTED) {
            response->faulted_partition_count += 1U;
        }
        if (partition->health_state == FBVBS_PARTITION_HEALTH_QUARANTINED) {
            response->quarantined_partition_count += 1U;
        }
        if (partition->health_state == FBVBS_PARTITION_HEALTH_RECOVERY) {
            response->recovery_partition_count += 1U;
        }
    }
    return OK;
}

static int fbvbs_ocs_runtime_summarize_scaling(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_ocs_scaling_summary_response *response
)
{
    if (state == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    *response = (struct fbvbs_ocs_scaling_summary_response){
        .runtime_max_vm_count = state->scaling_limits.max_vm_count_runtime,
        .runtime_max_vcpus_per_vm = state->scaling_limits.max_vcpus_per_vm_runtime,
        .runtime_max_host_cpu_count = state->scaling_limits.max_host_cpu_count_runtime,
        .runtime_max_vdisks_per_vm = state->scaling_limits.max_vdisks_per_vm_runtime,
        .runtime_max_memory_per_vm_bytes = state->scaling_limits.max_memory_per_vm_runtime_bytes,
        .runtime_max_vdisk_size_bytes = state->scaling_limits.max_vdisk_size_runtime_bytes,
    };
    return OK;
}

static int fbvbs_ocs_runtime_summarize_storage(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_ocs_storage_summary_response *response
)
{
    uint32_t index;

    if (state == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    *response = (struct fbvbs_ocs_storage_summary_response){0};
    for (index = 0U; index < FBVBS_MAX_STORAGE_POOLS; ++index) {
        if (state->storage_pools[index].active) {
            response->active_pool_count += 1U;
        }
    }
    for (index = 0U; index < FBVBS_MAX_VIRTUAL_DISKS; ++index) {
        if (!state->virtual_disks[index].active) {
            continue;
        }
        response->active_vdisk_count += 1U;
        if (state->virtual_disks[index].attached) {
            response->attached_vdisk_count += 1U;
        }
    }
    return OK;
}

static void fbvbs_ocs_runtime_build_help(
    struct fbvbs_ocs_help_response *response
)
{
    static const uint16_t k_supported_opcodes[] = {
        FBVBS_OCS_OPCODE_HELLO,
        FBVBS_OCS_OPCODE_GET_SYSTEM_SUMMARY,
        FBVBS_OCS_OPCODE_GET_PARTITION_SUMMARY,
        FBVBS_OCS_OPCODE_GET_SCALING_SUMMARY,
        FBVBS_OCS_OPCODE_GET_STORAGE_SUMMARY,
        FBVBS_OCS_OPCODE_GET_HELP,
        FBVBS_OCS_OPCODE_QUIESCE_PARTITION,
        FBVBS_OCS_OPCODE_RESUME_PARTITION,
        FBVBS_OCS_OPCODE_RECOVER_PARTITION,
    };
    uint32_t index;

    if (response == NULL) {
        return;
    }
    *response = (struct fbvbs_ocs_help_response){0};
    response->supported_opcode_count = (uint32_t)(
        sizeof(k_supported_opcodes) / sizeof(k_supported_opcodes[0])
    );
    for (index = 0U; index < response->supported_opcode_count; ++index) {
        response->supported_opcodes[index] = k_supported_opcodes[index];
    }
}

static int fbvbs_ocs_runtime_control_partition(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ocs_message_header *request,
    const uint8_t *request_payload,
    struct fbvbs_ocs_partition_control_response *response
)
{
    struct fbvbs_partition_status_response status_response = {0};
    struct fbvbs_partition_recover_request recover_request = {0};
    struct fbvbs_partition_id_request partition_request = {0};
    int status;

    if (state == NULL || request == NULL || request_payload == NULL ||
        response == NULL) {
        return INVALID_PARAMETER;
    }

    switch (request->opcode) {
        case FBVBS_OCS_OPCODE_QUIESCE_PARTITION:
        case FBVBS_OCS_OPCODE_RESUME_PARTITION:
            if (request->payload_length != sizeof(partition_request)) {
                return INVALID_PARAMETER;
            }
            memcpy(&partition_request, request_payload, sizeof(partition_request));
            if (request->opcode == FBVBS_OCS_OPCODE_QUIESCE_PARTITION) {
                status = fbvbs_partition_quiesce(state, partition_request.partition_id);
            } else {
                status = fbvbs_partition_resume(state, partition_request.partition_id);
            }
            if (status != OK) {
                return status;
            }
            break;
        case FBVBS_OCS_OPCODE_RECOVER_PARTITION:
            if (request->payload_length != sizeof(recover_request)) {
                return INVALID_PARAMETER;
            }
            memcpy(&recover_request, request_payload, sizeof(recover_request));
            if (recover_request.session_correlation_id != request->session_id ||
                recover_request.confirmation_nonce != request->sequence) {
                return POLICY_DENIED;
            }
            partition_request.partition_id = recover_request.partition_id;
            status = fbvbs_partition_recover(state, &recover_request);
            if (status != OK) {
                return status;
            }
            break;
        default:
            return INVALID_PARAMETER;
    }

    status = fbvbs_partition_get_status(
        state,
        partition_request.partition_id,
        &status_response
    );
    if (status != OK) {
        return status;
    }

    *response = (struct fbvbs_ocs_partition_control_response){
        .partition_id = partition_request.partition_id,
        .partition_state = status_response.state,
        .health_state = status_response.health_state,
        .quarantine_reason = status_response.quarantine_reason,
        .fault_code = status_response.fault_code,
        .measurement_epoch = status_response.measurement_epoch,
    };
    return OK;
}

static int fbvbs_ocs_runtime_dispatch(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ocs_message_header *request,
    const uint8_t *request_payload,
    struct fbvbs_ocs_message_header *response_header,
    uint8_t *response_payload,
    uint32_t *response_payload_length
)
{
    int status;

    if (state == NULL || request == NULL || request_payload == NULL ||
        response_header == NULL || response_payload == NULL ||
        response_payload_length == NULL) {
        return INVALID_PARAMETER;
    }

    *response_header = (struct fbvbs_ocs_message_header){
        .magic = FBVBS_OCS_MESSAGE_MAGIC,
        .opcode = request->opcode,
        .status = OK,
        .payload_length = 0U,
        .reserved0 = 0U,
        .session_id = state->ocs_runtime.session_id,
        .sequence = request->sequence,
    };
    *response_payload_length = 0U;

    switch (request->opcode) {
        case FBVBS_OCS_OPCODE_HELLO: {
            struct fbvbs_ocs_hello_response payload = {
                .protocol_version = FBVBS_OCS_PROTOCOL_VERSION,
                .reserved0 = 0U,
                .owner_partition_id = state->vcd.owner_partition_id,
                .session_id = request->sequence ^ state->vcd.owner_partition_id ^ UINT64_C(0x4F43530000000000),
                .rx_ring_size = FBVBS_VCD_RX_RING_SIZE,
                .tx_ring_size = FBVBS_VCD_TX_RING_SIZE,
            };
            state->ocs_runtime.active = true;
            state->ocs_runtime.owner_partition_id = state->vcd.owner_partition_id;
            state->ocs_runtime.session_id = payload.session_id;
            state->ocs_runtime.last_rx_sequence = request->sequence;
            state->ocs_runtime.last_tx_sequence = request->sequence;
            state->ocs_runtime.command_count = 1U;
            state->ocs_runtime.last_status = OK;
            response_header->session_id = payload.session_id;
            response_header->payload_length = (uint32_t)sizeof(payload);
            memcpy(response_payload, &payload, sizeof(payload));
            *response_payload_length = (uint32_t)sizeof(payload);
            return OK;
        }
        case FBVBS_OCS_OPCODE_GET_SYSTEM_SUMMARY: {
            struct fbvbs_ocs_system_summary_response payload = {0};
            status = fbvbs_ocs_runtime_summarize_system(state, &payload);
            if (status != OK) {
                return status;
            }
            response_header->payload_length = (uint32_t)sizeof(payload);
            memcpy(response_payload, &payload, sizeof(payload));
            *response_payload_length = (uint32_t)sizeof(payload);
            return OK;
        }
        case FBVBS_OCS_OPCODE_GET_PARTITION_SUMMARY: {
            struct fbvbs_ocs_partition_summary_response payload = {0};
            status = fbvbs_ocs_runtime_summarize_partitions(state, &payload);
            if (status != OK) {
                return status;
            }
            response_header->payload_length = (uint32_t)sizeof(payload);
            memcpy(response_payload, &payload, sizeof(payload));
            *response_payload_length = (uint32_t)sizeof(payload);
            return OK;
        }
        case FBVBS_OCS_OPCODE_GET_SCALING_SUMMARY: {
            struct fbvbs_ocs_scaling_summary_response payload = {0};
            status = fbvbs_ocs_runtime_summarize_scaling(state, &payload);
            if (status != OK) {
                return status;
            }
            response_header->payload_length = (uint32_t)sizeof(payload);
            memcpy(response_payload, &payload, sizeof(payload));
            *response_payload_length = (uint32_t)sizeof(payload);
            return OK;
        }
        case FBVBS_OCS_OPCODE_GET_STORAGE_SUMMARY: {
            struct fbvbs_ocs_storage_summary_response payload = {0};
            status = fbvbs_ocs_runtime_summarize_storage(state, &payload);
            if (status != OK) {
                return status;
            }
            response_header->payload_length = (uint32_t)sizeof(payload);
            memcpy(response_payload, &payload, sizeof(payload));
            *response_payload_length = (uint32_t)sizeof(payload);
            return OK;
        }
        case FBVBS_OCS_OPCODE_GET_HELP: {
            struct fbvbs_ocs_help_response payload = {0};
            fbvbs_ocs_runtime_build_help(&payload);
            response_header->payload_length = (uint32_t)sizeof(payload);
            memcpy(response_payload, &payload, sizeof(payload));
            *response_payload_length = (uint32_t)sizeof(payload);
            return OK;
        }
        case FBVBS_OCS_OPCODE_QUIESCE_PARTITION:
        case FBVBS_OCS_OPCODE_RESUME_PARTITION:
        case FBVBS_OCS_OPCODE_RECOVER_PARTITION: {
            struct fbvbs_ocs_partition_control_response payload = {0};
            status = fbvbs_ocs_runtime_control_partition(
                state,
                request,
                request_payload,
                &payload
            );
            if (status != OK) {
                return status;
            }
            response_header->payload_length = (uint32_t)sizeof(payload);
            memcpy(response_payload, &payload, sizeof(payload));
            *response_payload_length = (uint32_t)sizeof(payload);
            return OK;
        }
        default:
            return INVALID_PARAMETER;
    }
}

static struct fbvbs_partition *fbvbs_find_partition_rw(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id
)
{
    uint32_t index;

    if (state == NULL || partition_id == 0U) {
        return NULL;
    }

    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        struct fbvbs_partition *partition = &state->partitions[index];

        if (partition->occupied && partition->partition_id == partition_id) {
            return partition;
        }
    }

    return NULL;
}

static int fbvbs_authorize_ocs_requester(
    struct fbvbs_hypervisor_state *state,
    uint64_t requester_partition_id,
    struct fbvbs_partition **requester_out
)
{
    struct fbvbs_partition *requester;

    if (state == NULL || requester_out == NULL || requester_partition_id == 0U) {
        return INVALID_PARAMETER;
    }

    requester = fbvbs_find_partition_rw(state, requester_partition_id);
    if (requester == NULL) {
        return PERMISSION_DENIED;
    }
    if (requester->kind != PARTITION_KIND_TRUSTED_SERVICE ||
        requester->service_kind != SERVICE_KIND_OCS) {
        return INVALID_CALLER;
    }
    if ((requester->capability_mask & FBVBS_CAP_OCS_ACCESS) == 0ULL) {
        return PERMISSION_DENIED;
    }
    if (requester->state == FBVBS_PARTITION_STATE_FAULTED ||
        requester->health_state == FBVBS_PARTITION_HEALTH_QUARANTINED) {
        return PERMISSION_DENIED;
    }

    *requester_out = requester;
    return OK;
}

static int fbvbs_ranges_overlap(
    uint64_t base_a,
    uint64_t size_a,
    uint64_t base_b,
    uint64_t size_b
)
{
    uint64_t end_a;
    uint64_t end_b;

    if (size_a == 0U || size_b == 0U) {
        return 0;
    }

    end_a = base_a + size_a;
    end_b = base_b + size_b;

    if (end_a < base_a || end_b < base_b) {
        return 1;
    }

    return !(end_a <= base_b || end_b <= base_a);
}

static const struct fbvbs_memory_mapping *fbvbs_find_owner_mapping(
    const struct fbvbs_partition *owner,
    uint64_t guest_physical_address,
    uint64_t required_size
)
{
    uint64_t required_end;
    uint32_t index;

    if (owner == NULL || required_size == 0U) {
        return NULL;
    }

    required_end = guest_physical_address + required_size;
    if (required_end < guest_physical_address) {
        return NULL;
    }

    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        const struct fbvbs_memory_mapping *mapping = &owner->mappings[index];
        uint64_t mapping_end;

        if (!mapping->active) {
            continue;
        }
        if ((mapping->permissions & FBVBS_MEMORY_PERMISSION_WRITE) == 0U) {
            continue;
        }

        mapping_end = mapping->guest_physical_address + mapping->size;
        if (mapping_end < mapping->guest_physical_address) {
            continue;
        }
        if (mapping->guest_physical_address <= guest_physical_address &&
            required_end <= mapping_end) {
            return mapping;
        }
    }

    return NULL;
}

static void fbvbs_vcd_audit_event(
    struct fbvbs_hypervisor_state *state,
    uint64_t requester_partition_id,
    uint64_t owner_partition_id,
    uint32_t operation,
    int status,
    uint32_t corruption_count
)
{
    struct fbvbs_audit_vcd_event payload;
    uint16_t severity;

    if (state == NULL) {
        return;
    }

    payload = (struct fbvbs_audit_vcd_event){
        .requester_partition_id = requester_partition_id,
        .owner_partition_id = owner_partition_id,
        .operation = operation,
        .status = (uint32_t)status,
        .corruption_count = corruption_count,
        .reserved0 = 0U,
    };

    severity = (status == OK) ? FBVBS_SEVERITY_INFO : FBVBS_SEVERITY_WARNING;

    /* 監査完全性: owner mismatch は攻撃兆候のためレート制限せず必ず記録する。 */
    if (operation == FBVBS_VCD_AUDIT_OP_OWNER_MISMATCH) {
        (void)fbvbs_log_append(
            state,
            0U,
            FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
            severity,
            FBVBS_EVENT_VCD_STATE_CHANGE,
            (const uint8_t *)&payload,
            (uint32_t)sizeof(payload)
        );
        return;
    }

    (void)fbvbs_log_append_rate_limited(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        severity,
        FBVBS_EVENT_VCD_STATE_CHANGE,
        (const uint8_t *)&payload,
        (uint32_t)sizeof(payload)
    );
}

int fbvbs_ocs_vcd_attach(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ocs_vcd_attach_request *request,
    uint64_t requester_partition_id
)
{
    struct fbvbs_partition *requester = NULL;
    uint64_t owner_snapshot = 0U;
    uint32_t corruption_snapshot = 0U;
    int lock_held = 0;
    int status;

    if (state == NULL || request == NULL ||
        request->rx_ring_gpa == 0U || request->tx_ring_gpa == 0U) {
        status = INVALID_PARAMETER;
        goto out;
    }
    if ((request->rx_ring_gpa & (FBVBS_PAGE_SIZE - 1U)) != 0U ||
        (request->tx_ring_gpa & (FBVBS_PAGE_SIZE - 1U)) != 0U) {
        status = INVALID_PARAMETER;
        goto out;
    }
    if (request->rx_ring_gpa == request->tx_ring_gpa ||
        fbvbs_ranges_overlap(
            request->rx_ring_gpa,
            FBVBS_PAGE_SIZE,
            request->tx_ring_gpa,
            FBVBS_PAGE_SIZE
        ) != 0) {
        status = INVALID_PARAMETER;
        goto out;
    }

    status = fbvbs_authorize_ocs_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }

    fbvbs_vcd_state_lock(&state->vcd_lock);
    lock_held = 1;

    if (state->vcd.active) {
        if (state->vcd.owner_partition_id == requester_partition_id) {
            status = ALREADY_EXISTS;
        } else {
            status = PERMISSION_DENIED;
        }
        owner_snapshot = state->vcd.owner_partition_id;
        corruption_snapshot = state->vcd.corruption_count;
        goto out;
    }

    if (fbvbs_find_owner_mapping(requester, request->rx_ring_gpa, FBVBS_PAGE_SIZE) == NULL ||
        fbvbs_find_owner_mapping(requester, request->tx_ring_gpa, FBVBS_PAGE_SIZE) == NULL) {
        status = INVALID_PARAMETER;
        owner_snapshot = state->vcd.owner_partition_id;
        corruption_snapshot = state->vcd.corruption_count;
        goto out;
    }

    state->vcd.active = true;
    state->vcd.owner_partition_id = requester_partition_id;
    state->vcd.rx_ring_gpa = request->rx_ring_gpa;
    state->vcd.tx_ring_gpa = request->tx_ring_gpa;
    state->ocs_runtime = (struct fbvbs_ocs_runtime_state){0};
    fbvbs_vcd_ring_init(&fbvbs_vcd_rx_ring(state)->header, FBVBS_VCD_RX_RING_SIZE);
    fbvbs_vcd_ring_init(&fbvbs_vcd_tx_ring(state)->header, FBVBS_VCD_TX_RING_SIZE);

    owner_snapshot = state->vcd.owner_partition_id;
    corruption_snapshot = state->vcd.corruption_count;

    status = OK;

out:
    if (lock_held != 0) {
        fbvbs_vcd_state_unlock(&state->vcd_lock);
    }
    if (state != NULL) {
        fbvbs_vcd_audit_event(
            state,
            requester_partition_id,
            owner_snapshot,
            FBVBS_VCD_AUDIT_OP_ATTACH,
            status,
            corruption_snapshot
        );
    }
    return status;
}

int fbvbs_ocs_vcd_status(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_ocs_vcd_status_response *response,
    uint64_t requester_partition_id
)
{
    struct fbvbs_partition *requester = NULL;
    uint64_t owner_snapshot = 0U;
    uint32_t corruption_snapshot = 0U;
    uint32_t audit_op = FBVBS_VCD_AUDIT_OP_STATUS;
    int lock_held = 0;
    int status;

    if (state == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_authorize_ocs_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }

    fbvbs_vcd_state_lock(&state->vcd_lock);
    lock_held = 1;

    if (!state->vcd.active) {
        status = INVALID_STATE;
        owner_snapshot = state->vcd.owner_partition_id;
        corruption_snapshot = state->vcd.corruption_count;
        goto out;
    }

    if (state->vcd.owner_partition_id != requester_partition_id) {
        owner_snapshot = state->vcd.owner_partition_id;
        if (state->vcd.corruption_count != UINT32_MAX) {
            state->vcd.corruption_count += 1U;
        }
        corruption_snapshot = state->vcd.corruption_count;
        audit_op = FBVBS_VCD_AUDIT_OP_OWNER_MISMATCH;
        status = PERMISSION_DENIED;
        goto out;
    }

    *response = (struct fbvbs_ocs_vcd_status_response){0};
    response->active = state->vcd.active ? 1U : 0U;
    response->corruption_count = state->vcd.corruption_count;
    response->owner_partition_id = state->vcd.owner_partition_id;
    response->rx_ring_gpa = state->vcd.rx_ring_gpa;
    response->tx_ring_gpa = state->vcd.tx_ring_gpa;
    owner_snapshot = state->vcd.owner_partition_id;
    corruption_snapshot = state->vcd.corruption_count;
    status = OK;

out:
    if (lock_held != 0) {
        fbvbs_vcd_state_unlock(&state->vcd_lock);
    }
    fbvbs_vcd_audit_event(
        state,
        requester_partition_id,
        owner_snapshot,
        audit_op,
        status,
        corruption_snapshot
    );
    return status;
}

int fbvbs_ocs_runtime_poll(struct fbvbs_hypervisor_state *state)
{
    struct fbvbs_vcd_rx_ring_page *rx_ring;
    struct fbvbs_vcd_tx_ring_page *tx_ring;
    struct fbvbs_ocs_message_header request = {0};
    struct fbvbs_ocs_message_header response_header = {0};
    uint8_t request_payload[FBVBS_VCD_RX_RING_SIZE] = {0};
    uint8_t response_payload[FBVBS_VCD_TX_RING_SIZE] = {0};
    uint32_t response_payload_length = 0U;
    int status;

    if (state == NULL) {
        return INVALID_PARAMETER;
    }
    if (!state->vcd.active || state->vcd.owner_partition_id == 0U) {
        return INVALID_STATE;
    }

    rx_ring = fbvbs_vcd_rx_ring(state);
    tx_ring = fbvbs_vcd_tx_ring(state);
    if (rx_ring == NULL || tx_ring == NULL) {
        return INVALID_STATE;
    }
    if (rx_ring->header.magic != FBVBS_VCD_RING_MAGIC ||
        tx_ring->header.magic != FBVBS_VCD_RING_MAGIC ||
        rx_ring->header.size != FBVBS_VCD_RX_RING_SIZE ||
        tx_ring->header.size != FBVBS_VCD_TX_RING_SIZE) {
        if (state->vcd.corruption_count != UINT32_MAX) {
            state->vcd.corruption_count += 1U;
        }
        return INTERNAL_CORRUPTION;
    }

    status = fbvbs_vcd_read_message(
        rx_ring,
        &request,
        request_payload,
        (uint32_t)sizeof(request_payload)
    );
    if (status == NOT_FOUND) {
        return OK;
    }
    if (status != OK) {
        if (state->vcd.corruption_count != UINT32_MAX) {
            state->vcd.corruption_count += 1U;
        }
        return status;
    }

    if (request.opcode != FBVBS_OCS_OPCODE_HELLO) {
        if (!state->ocs_runtime.active ||
            request.session_id != state->ocs_runtime.session_id) {
            status = INVALID_STATE;
        } else if (request.sequence <= state->ocs_runtime.last_rx_sequence) {
            status = REPLAY_DETECTED;
        } else {
            status = fbvbs_ocs_runtime_dispatch(
                state,
                &request,
                request_payload,
                &response_header,
                response_payload,
                &response_payload_length
            );
        }
    } else {
        status = fbvbs_ocs_runtime_dispatch(
            state,
            &request,
            request_payload,
            &response_header,
            response_payload,
            &response_payload_length
        );
    }

    if (status != OK) {
        response_header = (struct fbvbs_ocs_message_header){
            .magic = FBVBS_OCS_MESSAGE_MAGIC,
            .opcode = request.opcode,
            .status = (uint16_t)status,
            .payload_length = 0U,
            .reserved0 = 0U,
            .session_id = state->ocs_runtime.session_id,
            .sequence = request.sequence,
        };
        response_payload_length = 0U;
    } else {
        response_header.status = OK;
        response_header.payload_length = response_payload_length;
        if (request.opcode != FBVBS_OCS_OPCODE_HELLO) {
            state->ocs_runtime.last_rx_sequence = request.sequence;
            state->ocs_runtime.last_tx_sequence = request.sequence;
            state->ocs_runtime.command_count += 1U;
            state->ocs_runtime.last_status = OK;
        }
    }

    status = fbvbs_vcd_write_message(tx_ring, &response_header, response_payload);
    if (status != OK && state->vcd.corruption_count != UINT32_MAX) {
        state->vcd.corruption_count += 1U;
    }
    return status;
}
