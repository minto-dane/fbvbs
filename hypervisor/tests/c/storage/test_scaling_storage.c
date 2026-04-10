#include <assert.h>
#include <string.h>

#include "../include/fbvbs_hypervisor.h"

static void init_host_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id
)
{
    state->partitions[0] = (struct fbvbs_partition){0};
    state->partitions[0].occupied = true;
    state->partitions[0].partition_id = partition_id;
    state->partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state->partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state->partitions[0].vcpu_count = 1U;
    state->partitions[0].capability_mask = FBVBS_HOST_DEFAULT_CAPABILITY_MASK;
    state->trusted_clock_available = true;
    if (state->trusted_time_seconds == 0U) {
        state->trusted_time_seconds = 1000U;
    }
}

static void init_guest_partition(
    struct fbvbs_hypervisor_state *state,
    uint32_t slot,
    uint64_t partition_id,
    uint32_t vcpu_count
)
{
    assert(slot < FBVBS_MAX_PARTITIONS);

    state->partitions[slot] = (struct fbvbs_partition){0};
    state->partitions[slot].occupied = true;
    state->partitions[slot].partition_id = partition_id;
    state->partitions[slot].kind = PARTITION_KIND_GUEST_VM;
    state->partitions[slot].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state->partitions[slot].vcpu_count = vcpu_count;
}

static void init_service_partition(
    struct fbvbs_hypervisor_state *state,
    uint32_t slot,
    uint64_t partition_id,
    uint16_t service_kind,
    uint64_t capability_mask
)
{
    assert(slot < FBVBS_MAX_PARTITIONS);

    state->partitions[slot] = (struct fbvbs_partition){0};
    state->partitions[slot].occupied = true;
    state->partitions[slot].partition_id = partition_id;
    state->partitions[slot].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state->partitions[slot].service_kind = service_kind;
    state->partitions[slot].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state->partitions[slot].vcpu_count = 1U;
    state->partitions[slot].capability_mask = capability_mask;
}

static struct fbvbs_storage_vdisk_destroy_request make_vdisk_destroy_request(
    const struct fbvbs_hypervisor_state *state,
    uint64_t requester_partition_id,
    uint64_t vdisk_id,
    uint64_t session_correlation_id,
    uint64_t confirmation_nonce
)
{
    struct fbvbs_storage_vdisk_destroy_request request = {
        .vdisk_id = vdisk_id,
        .session_correlation_id = session_correlation_id,
        .confirmation_nonce = confirmation_nonce,
        .confirmation_expires_utc = (state != NULL && state->trusted_time_seconds != 0U)
            ? state->trusted_time_seconds + 3600U
            : 3600U,
        .reserved0 = 0U,
        .reserved1 = 0U,
    };

    fbvbs_storage_compute_confirmation_digest(
        state,
        FBVBS_STORAGE_CONFIRMATION_OP_DESTROY_VDISK,
        requester_partition_id,
        vdisk_id,
        session_correlation_id,
        confirmation_nonce,
        request.confirmation_expires_utc,
        request.confirmation_digest
    );
    return request;
}

static struct fbvbs_storage_pool_destroy_request make_pool_destroy_request(
    const struct fbvbs_hypervisor_state *state,
    uint64_t requester_partition_id,
    uint64_t pool_id,
    uint64_t session_correlation_id,
    uint64_t confirmation_nonce
)
{
    struct fbvbs_storage_pool_destroy_request request = {
        .pool_id = pool_id,
        .session_correlation_id = session_correlation_id,
        .confirmation_nonce = confirmation_nonce,
        .confirmation_expires_utc = (state != NULL && state->trusted_time_seconds != 0U)
            ? state->trusted_time_seconds + 3600U
            : 3600U,
        .reserved0 = 0U,
        .reserved1 = 0U,
    };

    fbvbs_storage_compute_confirmation_digest(
        state,
        FBVBS_STORAGE_CONFIRMATION_OP_DESTROY_POOL,
        requester_partition_id,
        pool_id,
        session_correlation_id,
        confirmation_nonce,
        request.confirmation_expires_utc,
        request.confirmation_digest
    );
    return request;
}

static struct fbvbs_partition_recover_request make_partition_recover_request(
    const struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t recovery_flags,
    uint64_t session_correlation_id,
    uint64_t confirmation_nonce
)
{
    struct {
        uint64_t partition_id;
        uint64_t session_correlation_id;
        uint64_t confirmation_nonce;
    } ledger_seed = {
        .partition_id = partition_id,
        .session_correlation_id = session_correlation_id,
        .confirmation_nonce = confirmation_nonce,
    };
    struct fbvbs_partition_recover_request request = {
        .partition_id = partition_id,
        .recovery_flags = recovery_flags,
        .session_correlation_id = session_correlation_id,
        .confirmation_nonce = confirmation_nonce,
        .approval_expires_utc = (state != NULL && state->trusted_time_seconds != 0U)
            ? state->trusted_time_seconds + 3600U
            : 3600U,
        .reserved0 = 0U,
        .reserved1 = 0U,
    };

    fbvbs_sha384(
        &ledger_seed,
        (uint64_t)sizeof(ledger_seed),
        request.approval_ledger_digest
    );

    fbvbs_partition_compute_recovery_approval_digest(
        state,
        partition_id,
        recovery_flags,
        session_correlation_id,
        confirmation_nonce,
        request.approval_expires_utc,
        request.approval_ledger_digest,
        request.recovery_approval_digest
    );
    return request;
}

static void test_diag_get_scaling_limits_defaults(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_diag_scaling_limits_response response;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_guest_partition(&state, 1U, 0x20U, 3U);
    init_guest_partition(&state, 2U, 0x21U, 2U);

    status = fbvbs_diag_get_scaling_limits(&state, &response);
    assert(status == OK);
    assert(response.runtime_max_vm_count == FBVBS_DEFAULT_RUNTIME_MAX_VMS);
    assert(response.runtime_max_vcpus_per_vm == FBVBS_DEFAULT_RUNTIME_MAX_VCPUS_PER_VM);
    assert(response.runtime_max_host_cpu_count == FBVBS_DEFAULT_RUNTIME_MAX_HOST_CPUS);
    assert(response.runtime_max_memory_per_vm_bytes == FBVBS_DEFAULT_RUNTIME_MAX_MEMORY_PER_VM_BYTES);
    assert(response.runtime_max_vdisk_size_bytes == FBVBS_DEFAULT_RUNTIME_MAX_VDISK_BYTES);
    assert(response.supported_max_vm_count == FBVBS_TARGET_MAX_VMS_PER_HOST);
    assert(response.supported_max_vcpus_per_vm == FBVBS_TARGET_MAX_VCPUS_PER_VM);
    assert(response.supported_max_memory_per_vm_bytes == FBVBS_TARGET_MAX_MEMORY_PER_VM_BYTES);
    assert(response.supported_max_vdisk_size_bytes == FBVBS_TARGET_MAX_VDISK_BYTES);
    assert(response.current_vm_count == 2U);
    assert(response.current_allocated_vcpu_count == 5U);
}

static void test_diag_set_scaling_limits(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_diag_set_scaling_limits_request request;
    struct fbvbs_diag_scaling_limits_response response;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_guest_partition(&state, 1U, 0x20U, 3U);
    init_guest_partition(&state, 2U, 0x21U, 2U);

    request = (struct fbvbs_diag_set_scaling_limits_request){
        .update_mask = FBVBS_SCALE_UPDATE_MAX_VDISKS_PER_VM |
                       FBVBS_SCALE_UPDATE_MAX_VDISK_SIZE_BYTES,
        .reserved0 = 0U,
        .runtime_max_vdisks_per_vm = 128U,
        .runtime_max_vdisk_size_bytes = UINT64_C(32) << 40,
    };

    response = (struct fbvbs_diag_scaling_limits_response){0};
    status = fbvbs_diag_set_scaling_limits(&state, &request, &response);
    assert(status == OK);
    assert(response.runtime_max_vdisks_per_vm == 128U);
    assert(response.runtime_max_vdisk_size_bytes == (UINT64_C(32) << 40));

    request = (struct fbvbs_diag_set_scaling_limits_request){
        .update_mask = FBVBS_SCALE_UPDATE_MAX_VM_COUNT,
        .reserved0 = 0U,
        .runtime_max_vm_count = 1U,
    };
    status = fbvbs_diag_set_scaling_limits(&state, &request, &response);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);

    request = (struct fbvbs_diag_set_scaling_limits_request){
        .update_mask = FBVBS_SCALE_UPDATE_MAX_VCPUS_PER_VM,
        .reserved0 = 0U,
        .runtime_max_vcpus_per_vm = 2U,
    };
    status = fbvbs_diag_set_scaling_limits(&state, &request, &response);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
}

static void test_storage_pool_and_vdisk_lifecycle(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    struct fbvbs_storage_pool_request pool_id_request;
    struct fbvbs_storage_vdisk_attach_request attach_request;
    struct fbvbs_storage_vdisk_request vdisk_id_request;
    struct fbvbs_storage_vdisk_destroy_request vdisk_destroy_request;
    struct fbvbs_storage_pool_destroy_request pool_destroy_request;
    struct fbvbs_storage_pool_status_response pool_status;
    struct fbvbs_storage_vdisk_status_response vdisk_status;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 4U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 40,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};

    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);
    assert(pool_response.pool_id != 0U);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(8) << 30,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 50000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 30,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};

    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == OK);
    assert(vdisk_response.vdisk_id != 0U);
    assert(state.virtual_disks[0].lifecycle_state == FBVBS_VDISK_STATE_PROVISIONED);

    attach_request = (struct fbvbs_storage_vdisk_attach_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .vm_partition_id = 0x20U,
    };
    status = fbvbs_storage_attach_vdisk(&state, &attach_request, 0x10U);
    assert(status == OK);
    assert(state.virtual_disks[0].lifecycle_state == FBVBS_VDISK_STATE_ATTACHED);

    vdisk_id_request = (struct fbvbs_storage_vdisk_request){
        .vdisk_id = vdisk_response.vdisk_id,
    };
    vdisk_status = (struct fbvbs_storage_vdisk_status_response){0};
    status = fbvbs_storage_get_vdisk_status(&state, &vdisk_id_request, &vdisk_status, 0x20U);
    assert(status == OK);
    assert(vdisk_status.owner_partition_id == 0x20U);
    assert(vdisk_status.attached == 1U);

    status = fbvbs_storage_detach_vdisk(&state, &vdisk_id_request, 0x20U);
    assert(status == OK);
    assert(state.virtual_disks[0].lifecycle_state == FBVBS_VDISK_STATE_PROVISIONED);

    vdisk_destroy_request = make_vdisk_destroy_request(
        &state,
        0x10U,
        vdisk_response.vdisk_id,
        UINT64_C(0xAA10),
        UINT64_C(0xBB10)
    );
    status = fbvbs_storage_destroy_vdisk(&state, &vdisk_destroy_request, 0x10U);
    assert(status == OK);
    assert(state.virtual_disks[0].lifecycle_state == FBVBS_VDISK_STATE_DESTROYED);

    pool_id_request = (struct fbvbs_storage_pool_request){
        .pool_id = pool_response.pool_id,
    };
    pool_status = (struct fbvbs_storage_pool_status_response){0};
    status = fbvbs_storage_get_pool_status(&state, &pool_id_request, &pool_status, 0x10U);
    assert(status == OK);
    assert(pool_status.vdisk_count == 0U);
    assert(pool_status.allocated_bytes == 0U);

    pool_destroy_request = make_pool_destroy_request(
        &state,
        0x10U,
        pool_response.pool_id,
        UINT64_C(0xAA11),
        UINT64_C(0xBB11)
    );
    status = fbvbs_storage_destroy_pool(&state, &pool_destroy_request, 0x10U);
    assert(status == OK);
}

static void test_storage_rejects_unauthorized_requester(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request request;
    struct fbvbs_storage_pool_create_response response;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_guest_partition(&state, 0U, 0x51U, 1U);

    request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    response = (struct fbvbs_storage_pool_create_response){0};

    status = fbvbs_storage_create_pool(&state, &request, &response, 0x51U);
    assert(status == PERMISSION_DENIED);
}

static void test_storage_rejects_reserved_fields(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 1U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == INVALID_PARAMETER);

    pool_request.reserved0 = 0U;
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(1) << 20,
        .flags = 0U,
        .reserved0 = 1U,
        .max_iops = 1000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};
    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == INVALID_PARAMETER);
}

static void test_storage_enforces_runtime_vdisk_limit(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    state.scaling_limits.max_vdisk_size_runtime_bytes = UINT64_C(4) << 20;

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(16) << 20,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 1000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};

    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == INVALID_PARAMETER);
}

static void test_storage_enforces_pool_granularity_for_vdisk_size(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = UINT64_C(2) << 20,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(3) << 20,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 1000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};

    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == INVALID_PARAMETER);
}

static void test_storage_vdisk_status_and_qos(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    struct fbvbs_storage_vdisk_request vdisk_status_request;
    struct fbvbs_storage_vdisk_status_response status_response;
    struct fbvbs_storage_vdisk_qos_request qos_request;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);
    init_guest_partition(&state, 2U, 0x22U, 1U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(2) << 40,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(12) << 30,
        .flags = 0x12U,
        .reserved0 = 0U,
        .max_iops = 10000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(2) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};
    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == OK);

    vdisk_status_request = (struct fbvbs_storage_vdisk_request){
        .vdisk_id = vdisk_response.vdisk_id,
    };
    status_response = (struct fbvbs_storage_vdisk_status_response){0};
    status = fbvbs_storage_get_vdisk_status(&state, &vdisk_status_request, &status_response, 0x10U);
    assert(status == OK);
    assert(status_response.vdisk_id == vdisk_response.vdisk_id);
    assert(status_response.owner_partition_id == 0x20U);
    assert(status_response.max_iops == 10000U);

    qos_request = (struct fbvbs_storage_vdisk_qos_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .max_iops = 55000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 30,
    };
    status = fbvbs_storage_set_vdisk_qos(&state, &qos_request, 0x10U);
    assert(status == OK);

    status_response = (struct fbvbs_storage_vdisk_status_response){0};
    status = fbvbs_storage_get_vdisk_status(&state, &vdisk_status_request, &status_response, 0x10U);
    assert(status == OK);
    assert(status_response.max_iops == 55000U);
    assert(status_response.max_bandwidth_bytes_per_sec == (UINT64_C(1) << 30));

    status_response = (struct fbvbs_storage_vdisk_status_response){0};
    status = fbvbs_storage_get_vdisk_status(&state, &vdisk_status_request, &status_response, 0x22U);
    assert(status == PERMISSION_DENIED);

    status = fbvbs_storage_set_vdisk_qos(&state, &qos_request, 0x22U);
    assert(status == PERMISSION_DENIED);
}

static void test_storage_attach_rejects_non_owner_vm(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    struct fbvbs_storage_vdisk_attach_request attach_request;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);
    init_guest_partition(&state, 2U, 0x21U, 1U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(8) << 20,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 2000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};
    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == OK);

    attach_request = (struct fbvbs_storage_vdisk_attach_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .vm_partition_id = 0x21U,
    };
    status = fbvbs_storage_attach_vdisk(&state, &attach_request, 0x10U);
    assert(status == PERMISSION_DENIED);
}

static void test_faulted_tenant_owner_cannot_attach_detach_vdisk(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    struct fbvbs_storage_vdisk_attach_request attach_request;
    struct fbvbs_storage_vdisk_request vdisk_id_request;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(8) << 20,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 2000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};
    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == OK);

    state.partitions[1].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[1].health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;

    attach_request = (struct fbvbs_storage_vdisk_attach_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .vm_partition_id = 0x20U,
    };
    status = fbvbs_storage_attach_vdisk(&state, &attach_request, 0x20U);
    assert(status == PERMISSION_DENIED);

    status = fbvbs_storage_attach_vdisk(&state, &attach_request, 0x10U);
    assert(status == OK);

    vdisk_id_request = (struct fbvbs_storage_vdisk_request){
        .vdisk_id = vdisk_response.vdisk_id,
    };
    status = fbvbs_storage_detach_vdisk(&state, &vdisk_id_request, 0x20U);
    assert(status == PERMISSION_DENIED);
}

static void test_storage_service_admin_can_manage_storage(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    struct fbvbs_storage_vdisk_qos_request qos_request;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_service_partition(
        &state,
        1U,
        0x30U,
        SERVICE_KIND_KCI,
        FBVBS_CAP_KCI_ACCESS | FBVBS_CAP_STORAGE_MANAGE
    );
    init_guest_partition(&state, 2U, 0x20U, 2U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x30U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(1) << 20,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 1000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};
    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x30U);
    assert(status == OK);

    qos_request = (struct fbvbs_storage_vdisk_qos_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .max_iops = 2000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(2) << 20,
    };
    status = fbvbs_storage_set_vdisk_qos(&state, &qos_request, 0x30U);
    assert(status == OK);
}

static void test_storage_service_admin_requires_kci_access(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_service_partition(&state, 1U, 0x30U, SERVICE_KIND_KCI, FBVBS_CAP_STORAGE_MANAGE);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};

    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x30U);
    assert(status == PERMISSION_DENIED);
}

static void test_storage_quarantined_service_admin_cannot_mutate_storage(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_service_partition(
        &state,
        1U,
        0x30U,
        SERVICE_KIND_KCI,
        FBVBS_CAP_KCI_ACCESS | FBVBS_CAP_STORAGE_MANAGE
    );
    state.partitions[1].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[1].health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};

    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x30U);
    assert(status == PERMISSION_DENIED);
}

static void test_storage_corruption_quarantine_blocks_mutation(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    struct fbvbs_storage_vdisk_attach_request attach_request;
    struct fbvbs_storage_vdisk_request vdisk_id_request;
    struct fbvbs_storage_vdisk_destroy_request vdisk_destroy_request;
    struct fbvbs_storage_vdisk_qos_request qos_request;
    struct fbvbs_storage_vdisk_corruption_request corruption_request;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(1) << 20,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 1000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};
    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == OK);

    attach_request = (struct fbvbs_storage_vdisk_attach_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .vm_partition_id = 0x20U,
    };
    status = fbvbs_storage_attach_vdisk(&state, &attach_request, 0x10U);
    assert(status == OK);

    corruption_request = (struct fbvbs_storage_vdisk_corruption_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .quarantine_reason = FBVBS_STORAGE_QUARANTINE_REASON_OPERATOR_REPORTED,
        .reserved0 = 0U,
    };
    status = fbvbs_storage_report_vdisk_corruption(&state, &corruption_request, 0x10U);
    assert(status == OK);
    assert(state.virtual_disks[0].lifecycle_state == FBVBS_VDISK_STATE_QUARANTINED);
    assert(state.virtual_disks[0].attached == false);
    assert(state.virtual_disks[0].attached_partition_id == 0U);
    assert(state.virtual_disks[0].corruption_count == 1U);
    assert(state.virtual_disks[0].quarantine_reason == FBVBS_STORAGE_QUARANTINE_REASON_OPERATOR_REPORTED);

    qos_request = (struct fbvbs_storage_vdisk_qos_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .max_iops = 2000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(2) << 20,
    };
    status = fbvbs_storage_set_vdisk_qos(&state, &qos_request, 0x10U);
    assert(status == INVALID_STATE);

    vdisk_id_request = (struct fbvbs_storage_vdisk_request){
        .vdisk_id = vdisk_response.vdisk_id,
    };
    status = fbvbs_storage_detach_vdisk(&state, &vdisk_id_request, 0x10U);
    assert(status == INVALID_STATE);

    vdisk_destroy_request = make_vdisk_destroy_request(
        &state,
        0x10U,
        vdisk_response.vdisk_id,
        UINT64_C(0xAA20),
        UINT64_C(0xBB20)
    );
    status = fbvbs_storage_destroy_vdisk(&state, &vdisk_destroy_request, 0x10U);
    assert(status == OK);
    assert(state.virtual_disks[0].lifecycle_state == FBVBS_VDISK_STATE_DESTROYED);
}

static void test_storage_destroy_requires_confirmation_artifact(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    struct fbvbs_storage_vdisk_destroy_request vdisk_destroy_request;
    struct fbvbs_storage_pool_destroy_request pool_destroy_request;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(4) << 20,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 1000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};
    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == OK);

    vdisk_destroy_request = (struct fbvbs_storage_vdisk_destroy_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .session_correlation_id = 0U,
        .confirmation_nonce = 0U,
        .reserved0 = 0U,
        .reserved1 = 0U,
    };
    status = fbvbs_storage_destroy_vdisk(&state, &vdisk_destroy_request, 0x10U);
    assert(status == POLICY_DENIED);
    assert(state.virtual_disks[0].active == true);

    vdisk_destroy_request = make_vdisk_destroy_request(
        &state,
        0x10U,
        vdisk_response.vdisk_id,
        UINT64_C(0xCC10),
        UINT64_C(0xDD10)
    );
    vdisk_destroy_request.confirmation_digest[0] ^= 0xFFU;
    status = fbvbs_storage_destroy_vdisk(&state, &vdisk_destroy_request, 0x10U);
    assert(status == POLICY_DENIED);
    assert(state.virtual_disks[0].active == true);

    vdisk_destroy_request = make_vdisk_destroy_request(
        &state,
        0x10U,
        vdisk_response.vdisk_id,
        UINT64_C(0xCC11),
        UINT64_C(0xDD11)
    );
    status = fbvbs_storage_destroy_vdisk(&state, &vdisk_destroy_request, 0x10U);
    assert(status == OK);
    assert(state.virtual_disks[0].lifecycle_state == FBVBS_VDISK_STATE_DESTROYED);

    pool_destroy_request = (struct fbvbs_storage_pool_destroy_request){
        .pool_id = pool_response.pool_id,
        .session_correlation_id = UINT64_C(0xEE10),
        .confirmation_nonce = UINT64_C(0xFF10),
        .reserved0 = 0U,
        .reserved1 = 0U,
    };
    status = fbvbs_storage_destroy_pool(&state, &pool_destroy_request, 0x10U);
    assert(status == POLICY_DENIED);

    pool_destroy_request = make_pool_destroy_request(
        &state,
        0x10U,
        pool_response.pool_id,
        UINT64_C(0xEE11),
        UINT64_C(0xFF11)
    );
    status = fbvbs_storage_destroy_pool(&state, &pool_destroy_request, 0x10U);
    assert(status == OK);
}

static void test_storage_destroy_confirmation_is_single_use(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    struct fbvbs_storage_vdisk_attach_request attach_request;
    struct fbvbs_storage_vdisk_request detach_request;
    struct fbvbs_storage_vdisk_destroy_request destroy_vdisk_once;
    struct fbvbs_storage_vdisk_destroy_request destroy_vdisk_fresh;
    struct fbvbs_storage_pool_destroy_request destroy_pool_once;
    struct fbvbs_storage_pool_destroy_request destroy_pool_fresh;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(4) << 20,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 1000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};
    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == OK);

    attach_request = (struct fbvbs_storage_vdisk_attach_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .vm_partition_id = 0x20U,
    };
    status = fbvbs_storage_attach_vdisk(&state, &attach_request, 0x10U);
    assert(status == OK);

    destroy_vdisk_once = make_vdisk_destroy_request(
        &state,
        0x10U,
        vdisk_response.vdisk_id,
        UINT64_C(0xAB10),
        UINT64_C(0xCD10)
    );
    status = fbvbs_storage_destroy_vdisk(&state, &destroy_vdisk_once, 0x10U);
    assert(status == RESOURCE_BUSY);

    detach_request = (struct fbvbs_storage_vdisk_request){
        .vdisk_id = vdisk_response.vdisk_id,
    };
    status = fbvbs_storage_detach_vdisk(&state, &detach_request, 0x10U);
    assert(status == OK);

    /* 単回使用確認: 一度処理した承認トークンは成功/失敗に関わらず再利用不可。 */
    status = fbvbs_storage_destroy_vdisk(&state, &destroy_vdisk_once, 0x10U);
    assert(status == POLICY_DENIED);

    destroy_vdisk_fresh = make_vdisk_destroy_request(
        &state,
        0x10U,
        vdisk_response.vdisk_id,
        UINT64_C(0xAB11),
        UINT64_C(0xCD11)
    );
    status = fbvbs_storage_destroy_vdisk(&state, &destroy_vdisk_fresh, 0x10U);
    assert(status == OK);

    destroy_pool_once = make_pool_destroy_request(
        &state,
        0x10U,
        pool_response.pool_id,
        UINT64_C(0xAB20),
        UINT64_C(0xCD20)
    );
    status = fbvbs_storage_destroy_pool(&state, &destroy_pool_once, 0x10U);
    assert(status == OK);

    status = fbvbs_storage_destroy_pool(&state, &destroy_pool_once, 0x10U);
    assert(status == POLICY_DENIED);

    destroy_pool_fresh = make_pool_destroy_request(
        &state,
        0x10U,
        pool_response.pool_id,
        UINT64_C(0xAB21),
        UINT64_C(0xCD21)
    );
    status = fbvbs_storage_destroy_pool(&state, &destroy_pool_fresh, 0x10U);
    assert(status == NOT_FOUND);
}

static void test_storage_confirmation_table_full_fails_closed(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    struct fbvbs_storage_vdisk_attach_request attach_request;
    struct fbvbs_storage_vdisk_destroy_request destroy_request;
    uint32_t index;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(4) << 20,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 1000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};
    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == OK);

    attach_request = (struct fbvbs_storage_vdisk_attach_request){
        .vdisk_id = vdisk_response.vdisk_id,
        .vm_partition_id = 0x20U,
    };
    status = fbvbs_storage_attach_vdisk(&state, &attach_request, 0x10U);
    assert(status == OK);

    for (index = 0U; index < FBVBS_MAX_CONSUMED_CONFIRMATIONS; ++index) {
        destroy_request = make_vdisk_destroy_request(
            &state,
            0x10U,
            vdisk_response.vdisk_id,
            UINT64_C(0xCC00) + index,
            UINT64_C(0xDD00) + index
        );
        status = fbvbs_storage_destroy_vdisk(&state, &destroy_request, 0x10U);
        assert(status == RESOURCE_BUSY);
    }

    destroy_request = make_vdisk_destroy_request(
        &state,
        0x10U,
        vdisk_response.vdisk_id,
        UINT64_C(0xCC80),
        UINT64_C(0xDD80)
    );
    status = fbvbs_storage_destroy_vdisk(&state, &destroy_request, 0x10U);
    assert(status == RESOURCE_EXHAUSTED);
}

static void test_storage_destroy_requires_trusted_clock(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_storage_pool_create_request pool_request;
    struct fbvbs_storage_pool_create_response pool_response;
    struct fbvbs_storage_vdisk_create_request vdisk_request;
    struct fbvbs_storage_vdisk_create_response vdisk_response;
    struct fbvbs_storage_vdisk_destroy_request destroy_vdisk;
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 2U);

    pool_request = (struct fbvbs_storage_pool_create_request){
        .capacity_bytes = UINT64_C(1) << 30,
        .granularity_bytes = FBVBS_PAGE_SIZE,
        .flags = 0U,
        .reserved0 = 0U,
    };
    pool_response = (struct fbvbs_storage_pool_create_response){0};
    status = fbvbs_storage_create_pool(&state, &pool_request, &pool_response, 0x10U);
    assert(status == OK);

    vdisk_request = (struct fbvbs_storage_vdisk_create_request){
        .pool_id = pool_response.pool_id,
        .owner_partition_id = 0x20U,
        .size_bytes = UINT64_C(4) << 20,
        .flags = 0U,
        .reserved0 = 0U,
        .max_iops = 1000U,
        .max_bandwidth_bytes_per_sec = UINT64_C(1) << 20,
    };
    vdisk_response = (struct fbvbs_storage_vdisk_create_response){0};
    status = fbvbs_storage_create_vdisk(&state, &vdisk_request, &vdisk_response, 0x10U);
    assert(status == OK);

    destroy_vdisk = make_vdisk_destroy_request(
        &state,
        0x10U,
        vdisk_response.vdisk_id,
        UINT64_C(0xAC10),
        UINT64_C(0xBC10)
    );

    state.trusted_clock_available = false;
    status = fbvbs_storage_destroy_vdisk(&state, &destroy_vdisk, 0x10U);
    assert(status == POLICY_DENIED);
}

static void test_partition_recover_rejects_stale_approval_replay(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition *partition;
    struct fbvbs_partition_recover_request recover0;
    struct fbvbs_partition_recover_request recover1;
    int status;

    memset(&state, 0, sizeof(state));
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;

    partition = &state.partitions[0];
    *partition = (struct fbvbs_partition){0};
    partition->occupied = true;
    partition->partition_id = 0x9001U;
    partition->kind = PARTITION_KIND_GUEST_VM;
    partition->state = FBVBS_PARTITION_STATE_FAULTED;
    partition->health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;
    partition->vcpu_count = 1U;
    partition->manifest_object_id = 0x5001U;
    partition->image_object_id = 0x6001U;
    partition->entry_ip = 0x400000U;
    partition->initial_sp = 0x800000U;

    recover0 = make_partition_recover_request(
        &state,
        partition->partition_id,
        0U,
        UINT64_C(0x9100),
        UINT64_C(0x9200)
    );
    status = fbvbs_partition_recover(&state, &recover0);
    assert(status == OK);

    partition->state = FBVBS_PARTITION_STATE_FAULTED;
    partition->health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;

    recover1 = make_partition_recover_request(
        &state,
        partition->partition_id,
        0U,
        UINT64_C(0x9101),
        UINT64_C(0x9201)
    );
    status = fbvbs_partition_recover(&state, &recover1);
    assert(status == OK);

    partition->state = FBVBS_PARTITION_STATE_FAULTED;
    partition->health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;

    /* stale approval 再投入は拒否されるべき。 */
    status = fbvbs_partition_recover(&state, &recover0);
    assert(status == POLICY_DENIED);
}

static void test_memory_object_lifecycle_transitions(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_map_request map_request;
    struct fbvbs_memory_unmap_request unmap_request;
    struct fbvbs_memory_register_shared_request share_request;
    struct fbvbs_memory_register_shared_response share_response;
    static uint8_t backing_page[FBVBS_PAGE_SIZE] __attribute__((aligned(FBVBS_PAGE_SIZE)));
    int status;

    memset(&state, 0, sizeof(state));
    status = fbvbs_scaling_init(&state);
    assert(status == OK);
    state.next_shared_object_id = 1U;

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 1U);
    state.partitions[1].memory_limit_bytes = UINT64_C(2) * FBVBS_PAGE_SIZE;

    state.memory_objects[0] = (struct fbvbs_memory_object){0};
    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x7001U;
    state.memory_objects[0].owner_partition_id = 0x20U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)backing_page;
    fbvbs_memory_object_refresh_lifecycle_state(&state.memory_objects[0]);

    assert(state.memory_objects[0].lifecycle_state == FBVBS_MEMORY_OBJECT_STATE_ALLOCATED);

    map_request = (struct fbvbs_memory_map_request){
        .partition_id = 0x20U,
        .memory_object_id = 0x7001U,
        .guest_physical_address = UINT64_C(0x400000),
        .size = FBVBS_PAGE_SIZE,
        .permissions = FBVBS_MEMORY_PERMISSION_READ,
        .reserved0 = 0U,
    };
    status = fbvbs_memory_map(&state, &map_request, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].map_count == 1U);
    assert(state.memory_objects[0].lifecycle_state == FBVBS_MEMORY_OBJECT_STATE_MAPPED);

    share_request = (struct fbvbs_memory_register_shared_request){
        .memory_object_id = 0x7001U,
        .peer_partition_id = 0x10U,
        .size = FBVBS_PAGE_SIZE,
        .peer_permissions = FBVBS_MEMORY_PERMISSION_READ,
        .reserved0 = 0U,
    };
    share_response = (struct fbvbs_memory_register_shared_response){0};
    status = fbvbs_memory_register_shared(&state, &share_request, &share_response, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].shared_count == 1U);
    assert(state.memory_objects[0].lifecycle_state == FBVBS_MEMORY_OBJECT_STATE_MAPPED);

    unmap_request = (struct fbvbs_memory_unmap_request){
        .partition_id = 0x20U,
        .guest_physical_address = UINT64_C(0x400000),
        .size = FBVBS_PAGE_SIZE,
    };
    status = fbvbs_memory_unmap(&state, &unmap_request, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].map_count == 0U);
    assert(state.memory_objects[0].lifecycle_state == FBVBS_MEMORY_OBJECT_STATE_SHARED);

    status = fbvbs_memory_unregister_shared(&state, share_response.shared_object_id, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].shared_count == 0U);
    assert(state.memory_objects[0].lifecycle_state == FBVBS_MEMORY_OBJECT_STATE_ALLOCATED);

    status = fbvbs_memory_release_object(&state, 0x7001U, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].allocated == false);
    assert(state.memory_objects[0].lifecycle_state == FBVBS_MEMORY_OBJECT_STATE_RELEASED);
}

static void test_memory_corruption_quarantine_blocks_mapping(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_map_request map_request;
    const struct fbvbs_log_record_v1 *record;
    static uint8_t backing_page[FBVBS_PAGE_SIZE] __attribute__((aligned(FBVBS_PAGE_SIZE)));
    uint64_t seq_before;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    init_guest_partition(&state, 1U, 0x20U, 1U);
    state.partitions[1].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.memory_objects[0] = (struct fbvbs_memory_object){0};
    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x7002U;
    state.memory_objects[0].owner_partition_id = 0x20U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 0U;
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)backing_page;
    fbvbs_memory_object_refresh_lifecycle_state(&state.memory_objects[0]);

    map_request = (struct fbvbs_memory_map_request){
        .partition_id = 0x20U,
        .memory_object_id = 0x7002U,
        .guest_physical_address = UINT64_C(0x500000),
        .size = FBVBS_PAGE_SIZE,
        .permissions = FBVBS_MEMORY_PERMISSION_READ,
        .reserved0 = 0U,
    };

    seq_before = state.mirror_log.header.max_readable_sequence;
    status = fbvbs_memory_map(&state, &map_request, 0x20U);
    assert(status == INTERNAL_CORRUPTION);
    assert(state.memory_objects[0].lifecycle_state == FBVBS_MEMORY_OBJECT_STATE_QUARANTINED);
    assert(state.memory_objects[0].corruption_count == 1U);
    assert(state.memory_objects[0].quarantine_reason == FBVBS_MEMORY_QUARANTINE_REASON_INVARIANT);

    assert(state.mirror_log.header.max_readable_sequence == seq_before + 1U);
    record = &state.mirror_log.records[(state.mirror_log.header.max_readable_sequence - 1U) % FBVBS_LOG_SLOT_COUNT];
    assert(record->event_code == FBVBS_EVENT_MEMORY_CORRUPTION);

    status = fbvbs_memory_release_object(&state, 0x7002U, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].allocated == false);
}

static void test_memory_quarantine_allows_cleanup_paths(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_unmap_request unmap_request;
    int status;

    memset(&state, 0, sizeof(state));

    init_host_partition(&state, 0x10U);
    init_guest_partition(&state, 1U, 0x20U, 1U);
    state.partitions[1].memory_limit_bytes = FBVBS_PAGE_SIZE;
    state.partitions[1].mapped_bytes = FBVBS_PAGE_SIZE;
    state.partitions[1].mappings[0].active = true;
    state.partitions[1].mappings[0].memory_object_id = 0x7003U;
    state.partitions[1].mappings[0].guest_physical_address = UINT64_C(0x600000);
    state.partitions[1].mappings[0].size = FBVBS_PAGE_SIZE;
    state.partitions[1].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_READ;

    state.memory_objects[0] = (struct fbvbs_memory_object){0};
    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE;
    state.memory_objects[0].memory_object_id = 0x7003U;
    state.memory_objects[0].owner_partition_id = 0x20U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].map_count = 1U;
    state.memory_objects[0].shared_count = 1U;
    state.memory_objects[0].lifecycle_state = FBVBS_MEMORY_OBJECT_STATE_QUARANTINED;
    state.memory_objects[0].corruption_count = 1U;
    state.memory_objects[0].quarantine_reason = FBVBS_MEMORY_QUARANTINE_REASON_INVARIANT;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_OWNED_PAGE_LIST;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_page_list_head_phys = UINT64_C(0x123);

    state.shared_objects[0] = (struct fbvbs_shared_registration){0};
    state.shared_objects[0].active = true;
    state.shared_objects[0].shared_object_id = 0x9001U;
    state.shared_objects[0].memory_object_id = 0x7003U;
    state.shared_objects[0].owner_partition_id = 0x20U;
    state.shared_objects[0].peer_partition_id = 0x10U;
    state.shared_objects[0].size = FBVBS_PAGE_SIZE;
    state.shared_objects[0].peer_permissions = FBVBS_MEMORY_PERMISSION_READ;

    unmap_request = (struct fbvbs_memory_unmap_request){
        .partition_id = 0x20U,
        .guest_physical_address = UINT64_C(0x600000),
        .size = FBVBS_PAGE_SIZE,
    };
    status = fbvbs_memory_unmap(&state, &unmap_request, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].map_count == 0U);

    status = fbvbs_memory_unregister_shared(&state, 0x9001U, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].shared_count == 0U);

    status = fbvbs_memory_release_object(&state, 0x7003U, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].allocated == false);
}

static void test_memory_hash_requires_full_backing_pages(void)
{
    struct fbvbs_memory_object object;
    uint8_t digest[48];
    static uint8_t backing[FBVBS_PAGE_SIZE * 2U] __attribute__((aligned(FBVBS_PAGE_SIZE)));
    int status;

    memset(&object, 0, sizeof(object));
    memset(digest, 0, sizeof(digest));
    object.allocated = true;
    object.memory_object_id = 0x7101U;
    object.owner_partition_id = 0x20U;
    object.size = FBVBS_PAGE_SIZE * 2U;
    object.backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    object.backing_phys_base = (uint64_t)(uintptr_t)backing;
    object.backing_page_count = 1U;
    fbvbs_memory_object_refresh_lifecycle_state(&object);

    status = fbvbs_memory_object_hash_sha384(&object, digest);
    assert(status == -1);

    object.backing_page_count = 2U;
    status = fbvbs_memory_object_hash_sha384(&object, digest);
    assert(status == 0);
}

static void test_memory_owned_page_list_cycle_is_rejected(void)
{
    struct test_memory_page_list {
        uint64_t next_list_page_phys;
        uint32_t entry_count;
        uint32_t reserved0;
        uint64_t page_phys[(FBVBS_PAGE_SIZE - 16U) / sizeof(uint64_t)];
    };
    struct fbvbs_memory_object object;
    static uint8_t list_a_page[FBVBS_PAGE_SIZE] __attribute__((aligned(FBVBS_PAGE_SIZE)));
    static uint8_t list_b_page[FBVBS_PAGE_SIZE] __attribute__((aligned(FBVBS_PAGE_SIZE)));
    struct test_memory_page_list *list_a;
    struct test_memory_page_list *list_b;
    uint64_t page_phys;
    int status;

    memset(&object, 0, sizeof(object));
    memset(list_a_page, 0, sizeof(list_a_page));
    memset(list_b_page, 0, sizeof(list_b_page));
    list_a = (struct test_memory_page_list *)(void *)list_a_page;
    list_b = (struct test_memory_page_list *)(void *)list_b_page;

    object.allocated = true;
    object.memory_object_id = 0x7102U;
    object.owner_partition_id = 0x20U;
    object.size = FBVBS_PAGE_SIZE * 3U;
    object.backing_kind = FBVBS_MEMORY_BACKING_OWNED_PAGE_LIST;
    object.backing_page_count = 3U;
    object.backing_page_list_head_phys = (uint64_t)(uintptr_t)list_a;
    fbvbs_memory_object_refresh_lifecycle_state(&object);

    list_a->entry_count = 1U;
    list_a->page_phys[0] = UINT64_C(0x1000);
    list_a->next_list_page_phys = (uint64_t)(uintptr_t)list_b;

    list_b->entry_count = 1U;
    list_b->page_phys[0] = UINT64_C(0x2000);
    list_b->next_list_page_phys = (uint64_t)(uintptr_t)list_a;

    status = fbvbs_memory_object_get_page_phys(&object, 2U, &page_phys);
    assert(status == -1);
}

static void test_memory_release_zeroizes_external_backing(void)
{
    struct fbvbs_hypervisor_state state;
    static uint8_t backing[FBVBS_PAGE_SIZE] __attribute__((aligned(FBVBS_PAGE_SIZE)));
    uint32_t i;
    int status;

    memset(&state, 0, sizeof(state));
    init_guest_partition(&state, 1U, 0x20U, 1U);

    for (i = 0U; i < FBVBS_PAGE_SIZE; ++i) {
        backing[i] = 0xA5U;
    }

    state.memory_objects[0] = (struct fbvbs_memory_object){0};
    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x7103U;
    state.memory_objects[0].owner_partition_id = 0x20U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)backing;
    fbvbs_memory_object_refresh_lifecycle_state(&state.memory_objects[0]);

    status = fbvbs_memory_release_object(&state, 0x7103U, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].allocated == false);

    for (i = 0U; i < FBVBS_PAGE_SIZE; ++i) {
        assert(backing[i] == 0U);
    }
}

static void test_memory_map_non_owner_cannot_trigger_quarantine(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_memory_map_request map_request;
    static uint8_t backing_page[FBVBS_PAGE_SIZE] __attribute__((aligned(FBVBS_PAGE_SIZE)));
    int status;

    memset(&state, 0, sizeof(state));
    init_guest_partition(&state, 1U, 0x20U, 1U);
    init_guest_partition(&state, 2U, 0x30U, 1U);
    state.partitions[1].memory_limit_bytes = FBVBS_PAGE_SIZE;

    state.memory_objects[0] = (struct fbvbs_memory_object){0};
    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x7104U;
    state.memory_objects[0].owner_partition_id = 0x20U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 0U; /* malformed on purpose */
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)backing_page;
    fbvbs_memory_object_refresh_lifecycle_state(&state.memory_objects[0]);

    map_request = (struct fbvbs_memory_map_request){
        .partition_id = 0x20U,
        .memory_object_id = 0x7104U,
        .guest_physical_address = UINT64_C(0x700000),
        .size = FBVBS_PAGE_SIZE,
        .permissions = FBVBS_MEMORY_PERMISSION_READ,
        .reserved0 = 0U,
    };
    status = fbvbs_memory_map(&state, &map_request, 0x30U);
    assert(status == PERMISSION_DENIED);
    assert(state.memory_objects[0].lifecycle_state == FBVBS_MEMORY_OBJECT_STATE_ALLOCATED);
    assert(state.memory_objects[0].corruption_count == 0U);
}

static void test_memory_release_logs_corruption_on_validate_failure(void)
{
    struct fbvbs_hypervisor_state state;
    const struct fbvbs_log_record_v1 *record;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);
    init_guest_partition(&state, 1U, 0x20U, 1U);

    state.memory_objects[0] = (struct fbvbs_memory_object){0};
    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x7105U;
    state.memory_objects[0].owner_partition_id = 0x20U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_OWNED_PAGE_LIST;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_page_list_head_phys = UINT64_C(0x123);
    fbvbs_memory_object_refresh_lifecycle_state(&state.memory_objects[0]);

    status = fbvbs_memory_release_object(&state, 0x7105U, 0x20U);
    assert(status == OK);
    assert(state.memory_objects[0].allocated == false);
    record = &state.mirror_log.records[
        (state.mirror_log.header.max_readable_sequence - 1U) % FBVBS_LOG_SLOT_COUNT
    ];
    assert(record->event_code == FBVBS_EVENT_MEMORY_CORRUPTION);
}

static void test_service_partition_lifecycle_audits_are_emitted(void)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_measure_request measure_request;
    struct fbvbs_partition_measure_response measure_response;
    struct fbvbs_partition_recover_request recover_request;
    struct fbvbs_partition *partition;
    const struct fbvbs_log_record_v1 *record;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;
    state.next_measurement_digest_id = 1U;

    partition = &state.partitions[0];
    *partition = (struct fbvbs_partition){0};
    partition->occupied = true;
    partition->partition_id = 0x41U;
    partition->kind = PARTITION_KIND_TRUSTED_SERVICE;
    partition->state = FBVBS_PARTITION_STATE_CREATED;
    partition->image_object_id = 0x1000U;
    partition->entry_ip = 0x400000U;
    partition->vcpu_count = 1U;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x1000U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_IMAGE;
    state.artifact_catalog.entries[0].related_index = 1U;
    state.artifact_catalog.entries[1].object_id = 0x2000U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;

    state.approvals[0].active = true;
    state.approvals[0].artifact_object_id = 0x1000U;
    state.approvals[0].manifest_object_id = 0x2000U;
    state.approvals[0].manifest_set_id = 1U;
    state.current_manifest_set_id = 1U;

    state.manifest_profiles[0] = (struct fbvbs_manifest_profile){0};
    state.manifest_profiles[0].active = true;
    state.manifest_profiles[0].component_type = FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE;
    state.manifest_profiles[0].service_kind = SERVICE_KIND_KCI;
    state.manifest_profiles[0].object_id = 0x1000U;
    state.manifest_profiles[0].manifest_object_id = 0x2000U;
    state.manifest_profiles[0].vcpu_count = 1U;
    state.manifest_profiles[0].memory_limit_bytes = FBVBS_PAGE_SIZE;
    state.manifest_profiles[0].entry_ip = 0x400000U;
    state.manifest_profiles[0].initial_sp = 0x800000U;

    measure_request = (struct fbvbs_partition_measure_request){
        .partition_id = 0x41U,
        .image_object_id = 0x1000U,
        .manifest_object_id = 0x2000U,
    };
    measure_response = (struct fbvbs_partition_measure_response){0};
    status = fbvbs_partition_measure(&state, &measure_request, &measure_response);
    assert(status == OK);
    record = &state.mirror_log.records[(state.mirror_log.header.max_readable_sequence - 1U) % FBVBS_LOG_SLOT_COUNT];
    assert(record->event_code == FBVBS_EVENT_SERVICE_RESTART);
    assert(((const struct fbvbs_audit_service_lifecycle_event *)(const void *)record->payload)->operation ==
           FBVBS_SERVICE_AUDIT_OP_MEASURE);

    partition->state = FBVBS_PARTITION_STATE_LOADED;
    status = fbvbs_partition_start(&state, 0x41U);
    assert(status == OK);
    record = &state.mirror_log.records[(state.mirror_log.header.max_readable_sequence - 1U) % FBVBS_LOG_SLOT_COUNT];
    assert(((const struct fbvbs_audit_service_lifecycle_event *)(const void *)record->payload)->operation ==
           FBVBS_SERVICE_AUDIT_OP_START);

    status = fbvbs_partition_quiesce(&state, 0x41U);
    assert(status == OK);
    status = fbvbs_partition_resume(&state, 0x41U);
    assert(status == OK);
    status = fbvbs_partition_fault(&state, 0x41U, 7U, FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0U, 0U);
    assert(status == OK);
    recover_request = make_partition_recover_request(
        &state,
        0x41U,
        FBVBS_RECOVERY_BREAK_GLASS,
        UINT64_C(0x4101),
        UINT64_C(0x5101)
    );
    recover_request.approval_expires_utc = state.trusted_time_seconds + 600U;
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
    status = fbvbs_partition_recover(&state, &recover_request);
    assert(status == OK);
    record = &state.mirror_log.records[(state.mirror_log.header.max_readable_sequence - 1U) % FBVBS_LOG_SLOT_COUNT];
    assert(((const struct fbvbs_audit_service_lifecycle_event *)(const void *)record->payload)->operation ==
           FBVBS_SERVICE_AUDIT_OP_RECOVER);
    assert((((const struct fbvbs_audit_service_lifecycle_event *)(const void *)record->payload)->recovery_flags &
            FBVBS_RECOVERY_BREAK_GLASS) != 0U);
    partition->state = FBVBS_PARTITION_STATE_QUIESCED;
    status = fbvbs_partition_destroy(&state, 0x41U);
    assert(status == OK);
    record = &state.mirror_log.records[(state.mirror_log.header.max_readable_sequence - 1U) % FBVBS_LOG_SLOT_COUNT];
    assert(((const struct fbvbs_audit_service_lifecycle_event *)(const void *)record->payload)->operation ==
           FBVBS_SERVICE_AUDIT_OP_DESTROY);
}

int main(void)
{
    test_diag_get_scaling_limits_defaults();
    test_diag_set_scaling_limits();
    test_storage_pool_and_vdisk_lifecycle();
    test_storage_rejects_unauthorized_requester();
    test_storage_rejects_reserved_fields();
    test_storage_enforces_runtime_vdisk_limit();
    test_storage_enforces_pool_granularity_for_vdisk_size();
    test_storage_vdisk_status_and_qos();
    test_storage_attach_rejects_non_owner_vm();
    test_faulted_tenant_owner_cannot_attach_detach_vdisk();
    test_storage_service_admin_can_manage_storage();
    test_storage_service_admin_requires_kci_access();
    test_storage_quarantined_service_admin_cannot_mutate_storage();
    test_storage_corruption_quarantine_blocks_mutation();
    test_storage_destroy_requires_confirmation_artifact();
    test_storage_destroy_confirmation_is_single_use();
    test_storage_destroy_requires_trusted_clock();
    test_storage_confirmation_table_full_fails_closed();
    test_partition_recover_rejects_stale_approval_replay();
    test_memory_object_lifecycle_transitions();
    test_memory_corruption_quarantine_blocks_mapping();
    test_memory_quarantine_allows_cleanup_paths();
    test_memory_hash_requires_full_backing_pages();
    test_memory_owned_page_list_cycle_is_rejected();
    test_memory_release_zeroizes_external_backing();
    test_memory_map_non_owner_cannot_trigger_quarantine();
    test_memory_release_logs_corruption_on_validate_failure();
    test_service_partition_lifecycle_audits_are_emitted();
    return 0;
}
