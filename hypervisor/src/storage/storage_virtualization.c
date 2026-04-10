#include "fbvbs_hypervisor.h"

static void fbvbs_storage_state_lock(volatile uint32_t *lock)
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

static void fbvbs_storage_state_unlock(volatile uint32_t *lock)
{
#ifndef __FRAMAC__
    __sync_lock_release(lock);
#else
    if (lock != NULL) {
        *lock = 0U;
    }
#endif
}

static int fbvbs_is_power_of_two_u64(uint64_t value)
{
    return (value != 0U) && ((value & (value - 1U)) == 0U);
}

struct fbvbs_storage_confirmation_material {
    uint64_t operation;
    uint64_t requester_partition_id;
    uint64_t target_id;
    uint64_t session_correlation_id;
    uint64_t confirmation_nonce;
    uint64_t confirmation_expires_utc;
    uint64_t boot_id_hi;
    uint64_t boot_id_lo;
};

void fbvbs_storage_compute_confirmation_digest(
    const struct fbvbs_hypervisor_state *state,
    uint32_t operation,
    uint64_t requester_partition_id,
    uint64_t target_id,
    uint64_t session_correlation_id,
    uint64_t confirmation_nonce,
    uint64_t confirmation_expires_utc,
    uint8_t out_digest[48]
)
{
    struct fbvbs_storage_confirmation_material material = {
        .operation = operation,
        .requester_partition_id = requester_partition_id,
        .target_id = target_id,
        .session_correlation_id = session_correlation_id,
        .confirmation_nonce = confirmation_nonce,
        .confirmation_expires_utc = confirmation_expires_utc,
        .boot_id_hi = (state != NULL) ? state->boot_id_hi : 0U,
        .boot_id_lo = (state != NULL) ? state->boot_id_lo : 0U,
    };

    if (out_digest == NULL) {
        return;
    }

    fbvbs_sha384(&material, (uint64_t)sizeof(material), out_digest);
}

static int fbvbs_storage_validate_destructive_confirmation(
    const struct fbvbs_hypervisor_state *state,
    uint32_t operation,
    uint64_t requester_partition_id,
    uint64_t target_id,
    uint64_t session_correlation_id,
    uint64_t confirmation_nonce,
    uint64_t confirmation_expires_utc,
    const uint8_t confirmation_digest[48]
)
{
    uint8_t expected_digest[48];

    if (state == NULL || !state->trusted_clock_available) {
        return POLICY_DENIED;
    }
    if (session_correlation_id == 0U || confirmation_nonce == 0U ||
        confirmation_expires_utc == 0U || confirmation_digest == NULL) {
        return POLICY_DENIED;
    }
    if (state->trusted_time_seconds >= confirmation_expires_utc) {
        return POLICY_DENIED;
    }
    if (fbvbs_memory_is_zero(confirmation_digest, 48U) != 0) {
        return POLICY_DENIED;
    }

    fbvbs_storage_compute_confirmation_digest(
        state,
        operation,
        requester_partition_id,
        target_id,
        session_correlation_id,
        confirmation_nonce,
        confirmation_expires_utc,
        expected_digest
    );

    if (fbvbs_constant_time_equals(expected_digest, confirmation_digest, 48U) == 0) {
        return POLICY_DENIED;
    }

    return OK;
}

static int fbvbs_confirmation_was_consumed_locked(
    const struct fbvbs_hypervisor_state *state,
    uint32_t operation,
    uint64_t requester_partition_id,
    uint64_t target_id,
    uint64_t session_correlation_id,
    uint64_t confirmation_nonce
)
{
    uint32_t index;

    if (state == NULL) {
        return 0;
    }

    for (index = 0U; index < FBVBS_MAX_CONSUMED_CONFIRMATIONS; ++index) {
        const struct fbvbs_consumed_confirmation *entry =
            &state->consumed_confirmations[index];

        if (!entry->active) {
            continue;
        }
        if (state->trusted_clock_available &&
            entry->expires_utc != 0U &&
            state->trusted_time_seconds >= entry->expires_utc) {
            continue;
        }
        if (entry->operation == operation &&
            entry->requester_partition_id == requester_partition_id &&
            entry->target_id == target_id &&
            entry->session_correlation_id == session_correlation_id &&
            entry->confirmation_nonce == confirmation_nonce) {
            return 1;
        }
    }

    return 0;
}

static int fbvbs_confirmation_consume_locked(
    struct fbvbs_hypervisor_state *state,
    uint32_t operation,
    uint64_t requester_partition_id,
    uint64_t target_id,
    uint64_t session_correlation_id,
    uint64_t confirmation_nonce,
    uint64_t confirmation_expires_utc
)
{
    uint32_t slot = 0U;
    uint32_t offset;
    int found_slot = 0;

    if (state == NULL || confirmation_expires_utc == 0U) {
        return INVALID_PARAMETER;
    }
    if (!state->trusted_clock_available) {
        return POLICY_DENIED;
    }

    for (offset = 0U; offset < FBVBS_MAX_CONSUMED_CONFIRMATIONS; ++offset) {
        struct fbvbs_consumed_confirmation *entry;

        slot = (state->consumed_confirmation_cursor + offset) %
            FBVBS_MAX_CONSUMED_CONFIRMATIONS;
        entry = &state->consumed_confirmations[slot];
        if (!entry->active ||
            (entry->expires_utc != 0U &&
             state->trusted_time_seconds >= entry->expires_utc)) {
            found_slot = 1;
            break;
        }
    }

    if (found_slot == 0) {
        return RESOURCE_EXHAUSTED;
    }

    state->consumed_confirmations[slot] = (struct fbvbs_consumed_confirmation){
        .active = true,
        .operation = operation,
        .requester_partition_id = requester_partition_id,
        .target_id = target_id,
        .session_correlation_id = session_correlation_id,
        .confirmation_nonce = confirmation_nonce,
        .expires_utc = confirmation_expires_utc,
    };

    state->consumed_confirmation_cursor =
        (slot + 1U) % FBVBS_MAX_CONSUMED_CONFIRMATIONS;
    return OK;
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

static int fbvbs_resolve_storage_requester(
    struct fbvbs_hypervisor_state *state,
    uint64_t requester_partition_id,
    const struct fbvbs_partition **requester_out
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

    *requester_out = requester;
    return OK;
}

static int fbvbs_storage_requester_is_admin(
    const struct fbvbs_partition *requester
)
{
    const uint64_t required_service_caps =
        FBVBS_CAP_KCI_ACCESS | FBVBS_CAP_STORAGE_MANAGE;

    if (requester == NULL) {
        return 0;
    }
    if (requester->kind == PARTITION_KIND_FREEBSD_HOST) {
        return (requester->capability_mask & FBVBS_CAP_STORAGE_MANAGE) != 0ULL;
    }
    if (requester->kind != PARTITION_KIND_TRUSTED_SERVICE ||
        requester->service_kind != SERVICE_KIND_KCI) {
        return 0;
    }
    if ((requester->capability_mask & required_service_caps) != required_service_caps) {
        return 0;
    }
    if (requester->state == FBVBS_PARTITION_STATE_FAULTED ||
        requester->health_state == FBVBS_PARTITION_HEALTH_QUARANTINED) {
        return 0;
    }
    return 1;
}

static int fbvbs_storage_requester_is_owner_tenant(
    const struct fbvbs_partition *requester,
    const struct fbvbs_virtual_disk *vdisk
)
{
    if (requester == NULL || vdisk == NULL) {
        return 0;
    }
    if (requester->state == FBVBS_PARTITION_STATE_FAULTED ||
        requester->health_state == FBVBS_PARTITION_HEALTH_QUARANTINED) {
        return 0;
    }
    return requester->kind == PARTITION_KIND_GUEST_VM &&
           requester->partition_id == vdisk->owner_partition_id;
}

static void fbvbs_storage_set_vdisk_state(
    struct fbvbs_virtual_disk *vdisk,
    uint32_t lifecycle_state
)
{
    if (vdisk == NULL) {
        return;
    }

    vdisk->lifecycle_state = lifecycle_state;
    vdisk->attached = (lifecycle_state == FBVBS_VDISK_STATE_ATTACHED ||
                       lifecycle_state == FBVBS_VDISK_STATE_DETACH_PENDING);
    if (!vdisk->attached) {
        vdisk->attached_partition_id = 0U;
    }
}

static void fbvbs_storage_mark_vdisk_quarantined(
    struct fbvbs_virtual_disk *vdisk,
    uint32_t quarantine_reason
)
{
    if (vdisk == NULL || !vdisk->active) {
        return;
    }

    if (vdisk->corruption_count != UINT32_MAX) {
        vdisk->corruption_count += 1U;
    }
    vdisk->quarantine_reason =
        (quarantine_reason == 0U)
            ? FBVBS_STORAGE_QUARANTINE_REASON_METADATA_INVARIANT
            : quarantine_reason;
    fbvbs_storage_set_vdisk_state(vdisk, FBVBS_VDISK_STATE_QUARANTINED);
}

static int fbvbs_storage_revalidate_requester_locked(
    struct fbvbs_hypervisor_state *state,
    uint64_t requester_partition_id,
    const struct fbvbs_partition **requester_out
)
{
    return fbvbs_resolve_storage_requester(state, requester_partition_id, requester_out);
}

static int fbvbs_storage_validate_vdisk_invariants(
    struct fbvbs_virtual_disk *vdisk
)
{
    int expect_attached;

    if (vdisk == NULL || !vdisk->active) {
        return NOT_FOUND;
    }

    switch (vdisk->lifecycle_state) {
        case FBVBS_VDISK_STATE_PROVISIONED:
        case FBVBS_VDISK_STATE_QUARANTINED:
        case FBVBS_VDISK_STATE_RELEASE_PENDING:
            expect_attached = 0;
            break;
        case FBVBS_VDISK_STATE_ATTACHED:
        case FBVBS_VDISK_STATE_DETACH_PENDING:
            expect_attached = 1;
            break;
        default:
            fbvbs_storage_mark_vdisk_quarantined(
                vdisk,
                FBVBS_STORAGE_QUARANTINE_REASON_METADATA_INVARIANT
            );
            return INTERNAL_CORRUPTION;
    }

    if (expect_attached != 0) {
        if (!vdisk->attached || vdisk->attached_partition_id == 0U) {
            fbvbs_storage_mark_vdisk_quarantined(
                vdisk,
                FBVBS_STORAGE_QUARANTINE_REASON_METADATA_INVARIANT
            );
            return INTERNAL_CORRUPTION;
        }
        return OK;
    }

    if (vdisk->attached || vdisk->attached_partition_id != 0U) {
        fbvbs_storage_mark_vdisk_quarantined(
            vdisk,
            FBVBS_STORAGE_QUARANTINE_REASON_METADATA_INVARIANT
        );
        return INTERNAL_CORRUPTION;
    }
    return OK;
}

static struct fbvbs_storage_pool *fbvbs_find_storage_pool(
    struct fbvbs_hypervisor_state *state,
    uint64_t pool_id
)
{
    uint32_t index;

    if (state == NULL || pool_id == 0U) {
        return NULL;
    }

    for (index = 0U; index < FBVBS_MAX_STORAGE_POOLS; ++index) {
        struct fbvbs_storage_pool *pool = &state->storage_pools[index];

        if (pool->active && pool->pool_id == pool_id) {
            return pool;
        }
    }

    return NULL;
}

static struct fbvbs_storage_pool *fbvbs_allocate_storage_pool_slot(
    struct fbvbs_hypervisor_state *state
)
{
    uint32_t index;

    if (state == NULL) {
        return NULL;
    }

    for (index = 0U; index < FBVBS_MAX_STORAGE_POOLS; ++index) {
        if (!state->storage_pools[index].active) {
            return &state->storage_pools[index];
        }
    }

    return NULL;
}

static struct fbvbs_virtual_disk *fbvbs_find_virtual_disk(
    struct fbvbs_hypervisor_state *state,
    uint64_t vdisk_id
)
{
    uint32_t index;

    if (state == NULL || vdisk_id == 0U) {
        return NULL;
    }

    for (index = 0U; index < FBVBS_MAX_VIRTUAL_DISKS; ++index) {
        struct fbvbs_virtual_disk *vdisk = &state->virtual_disks[index];

        if (vdisk->active && vdisk->vdisk_id == vdisk_id) {
            return vdisk;
        }
    }

    return NULL;
}

static struct fbvbs_virtual_disk *fbvbs_allocate_virtual_disk_slot(
    struct fbvbs_hypervisor_state *state
)
{
    uint32_t index;

    if (state == NULL) {
        return NULL;
    }

    for (index = 0U; index < FBVBS_MAX_VIRTUAL_DISKS; ++index) {
        if (!state->virtual_disks[index].active) {
            return &state->virtual_disks[index];
        }
    }

    return NULL;
}

static uint32_t fbvbs_count_vm_vdisks(
    const struct fbvbs_hypervisor_state *state,
    uint64_t owner_partition_id
)
{
    uint32_t index;
    uint32_t count = 0U;

    if (state == NULL || owner_partition_id == 0U) {
        return 0U;
    }

    for (index = 0U; index < FBVBS_MAX_VIRTUAL_DISKS; ++index) {
        const struct fbvbs_virtual_disk *vdisk = &state->virtual_disks[index];

        if (vdisk->active && vdisk->owner_partition_id == owner_partition_id) {
            if (count == UINT32_MAX) {
                return UINT32_MAX;
            }
            count += 1U;
        }
    }

    return count;
}

static int fbvbs_storage_requester_can_manage_vdisk(
    const struct fbvbs_partition *requester,
    const struct fbvbs_virtual_disk *vdisk
)
{
    if (requester == NULL || vdisk == NULL) {
        return 0;
    }

    if (fbvbs_storage_requester_is_admin(requester)) {
        return 1;
    }

    return fbvbs_storage_requester_is_owner_tenant(requester, vdisk);
}

static void fbvbs_storage_audit_event(
    struct fbvbs_hypervisor_state *state,
    uint64_t requester_partition_id,
    uint64_t target_id,
    uint64_t related_id,
    uint32_t operation,
    int status
)
{
    struct fbvbs_audit_storage_event payload;
    uint16_t severity;
    uint16_t event_code;

    if (state == NULL) {
        return;
    }

    payload = (struct fbvbs_audit_storage_event){
        .requester_partition_id = requester_partition_id,
        .target_id = target_id,
        .related_id = related_id,
        .operation = operation,
        .status = (uint32_t)status,
    };

    severity = (status == OK) ? FBVBS_SEVERITY_INFO : FBVBS_SEVERITY_WARNING;
    event_code = (operation == FBVBS_STORAGE_AUDIT_OP_CREATE_POOL ||
                  operation == FBVBS_STORAGE_AUDIT_OP_DESTROY_POOL ||
                  operation == FBVBS_STORAGE_AUDIT_OP_GET_POOL_STATUS)
                     ? FBVBS_EVENT_STORAGE_POOL_CHANGE
                     : FBVBS_EVENT_STORAGE_VDISK_CHANGE;

    (void)fbvbs_log_append_rate_limited(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        severity,
        event_code,
        (const uint8_t *)&payload,
        (uint32_t)sizeof(payload)
    );
}

int fbvbs_storage_create_pool(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_storage_pool_create_request *request,
    struct fbvbs_storage_pool_create_response *response,
    uint64_t requester_partition_id
)
{
    const struct fbvbs_partition *requester = NULL;
    struct fbvbs_storage_pool *pool;
    uint64_t pool_id = 0U;
    uint16_t generation;
    int status;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_resolve_storage_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            0U,
            0U,
            FBVBS_STORAGE_AUDIT_OP_CREATE_POOL,
            status
        );
        return status;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            0U,
            0U,
            FBVBS_STORAGE_AUDIT_OP_CREATE_POOL,
            PERMISSION_DENIED
        );
        return PERMISSION_DENIED;
    }

    if (request->capacity_bytes == 0U ||
        request->capacity_bytes > FBVBS_TARGET_MAX_MEMORY_PER_VM_BYTES) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            0U,
            0U,
            FBVBS_STORAGE_AUDIT_OP_CREATE_POOL,
            INVALID_PARAMETER
        );
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            0U,
            0U,
            FBVBS_STORAGE_AUDIT_OP_CREATE_POOL,
            INVALID_PARAMETER
        );
        return INVALID_PARAMETER;
    }
    if (request->granularity_bytes < FBVBS_PAGE_SIZE ||
        !fbvbs_is_power_of_two_u64(request->granularity_bytes) ||
        request->granularity_bytes > request->capacity_bytes) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            0U,
            0U,
            FBVBS_STORAGE_AUDIT_OP_CREATE_POOL,
            INVALID_PARAMETER
        );
        return INVALID_PARAMETER;
    }

    fbvbs_storage_state_lock(&state->storage_lock);

    status = fbvbs_storage_revalidate_requester_locked(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        status = PERMISSION_DENIED;
        goto out;
    }

    pool = fbvbs_allocate_storage_pool_slot(state);
    if (pool == NULL) {
        status = RESOURCE_EXHAUSTED;
        goto out;
    }
    if (!fbvbs_id_allocator_can_advance(state->next_storage_pool_id, 1U)) {
        status = RESOURCE_EXHAUSTED;
        goto out;
    }

    generation = (uint16_t)(pool->generation + 1U);
    if (generation == 0U) {
        generation = 1U;
    }

    *pool = (struct fbvbs_storage_pool){0};
    pool->active = true;
    pool->generation = generation;
    pool->flags = request->flags;
    pool->pool_id = state->next_storage_pool_id;
    state->next_storage_pool_id += 1U;
    pool->capacity_bytes = request->capacity_bytes;
    pool->allocated_bytes = 0U;
    pool->granularity_bytes = request->granularity_bytes;
    pool->vdisk_count = 0U;

    response->pool_id = pool->pool_id;
    pool_id = pool->pool_id;
    status = OK;

out:
    fbvbs_storage_state_unlock(&state->storage_lock);
    fbvbs_storage_audit_event(
        state,
        requester_partition_id,
        pool_id,
        0U,
        FBVBS_STORAGE_AUDIT_OP_CREATE_POOL,
        status
    );
    return status;
}

int fbvbs_storage_destroy_pool(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_storage_pool_destroy_request *request,
    uint64_t requester_partition_id
)
{
    const struct fbvbs_partition *requester = NULL;
    struct fbvbs_storage_pool *pool;
    int status;

    if (state == NULL || request == NULL || request->pool_id == 0U) {
        if (state != NULL) {
            fbvbs_storage_audit_event(
                state,
                requester_partition_id,
                (request == NULL) ? 0U : request->pool_id,
                0U,
                FBVBS_STORAGE_AUDIT_OP_DESTROY_POOL,
                INVALID_PARAMETER
            );
        }
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U || request->reserved1 != 0U) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->pool_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_DESTROY_POOL,
            INVALID_PARAMETER
        );
        return INVALID_PARAMETER;
    }

    status = fbvbs_storage_validate_destructive_confirmation(
        state,
        FBVBS_STORAGE_CONFIRMATION_OP_DESTROY_POOL,
        requester_partition_id,
        request->pool_id,
        request->session_correlation_id,
        request->confirmation_nonce,
        request->confirmation_expires_utc,
        request->confirmation_digest
    );
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->pool_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_DESTROY_POOL,
            status
        );
        return status;
    }

    status = fbvbs_resolve_storage_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->pool_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_DESTROY_POOL,
            status
        );
        return status;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->pool_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_DESTROY_POOL,
            PERMISSION_DENIED
        );
        return PERMISSION_DENIED;
    }

    fbvbs_storage_state_lock(&state->storage_lock);

    status = fbvbs_storage_revalidate_requester_locked(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        status = PERMISSION_DENIED;
        goto out;
    }

    if (fbvbs_confirmation_was_consumed_locked(
            state,
            FBVBS_STORAGE_CONFIRMATION_OP_DESTROY_POOL,
            requester_partition_id,
            request->pool_id,
            request->session_correlation_id,
            request->confirmation_nonce) != 0) {
        status = POLICY_DENIED;
        goto out;
    }
    status = fbvbs_confirmation_consume_locked(
        state,
        FBVBS_STORAGE_CONFIRMATION_OP_DESTROY_POOL,
        requester_partition_id,
        request->pool_id,
        request->session_correlation_id,
        request->confirmation_nonce,
        request->confirmation_expires_utc
    );
    if (status != OK) {
        goto out;
    }

    pool = fbvbs_find_storage_pool(state, request->pool_id);
    if (pool == NULL) {
        status = NOT_FOUND;
        goto out;
    }
    if (pool->vdisk_count != 0U || pool->allocated_bytes != 0U) {
        status = RESOURCE_BUSY;
        goto out;
    }

    pool->active = false;
    status = OK;

out:
    fbvbs_storage_state_unlock(&state->storage_lock);
    fbvbs_storage_audit_event(
        state,
        requester_partition_id,
        request->pool_id,
        0U,
        FBVBS_STORAGE_AUDIT_OP_DESTROY_POOL,
        status
    );
    return status;
}

int fbvbs_storage_create_vdisk(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_storage_vdisk_create_request *request,
    struct fbvbs_storage_vdisk_create_response *response,
    uint64_t requester_partition_id
)
{
    const struct fbvbs_partition *requester = NULL;
    struct fbvbs_partition *owner_partition;
    struct fbvbs_storage_pool *pool;
    struct fbvbs_virtual_disk *vdisk;
    uint64_t created_vdisk_id = 0U;
    uint16_t generation;
    uint32_t owner_vdisk_count;
    int status;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_resolve_storage_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            0U,
            request->pool_id,
            FBVBS_STORAGE_AUDIT_OP_CREATE_VDISK,
            status
        );
        return status;
    }
    if (request->reserved0 != 0U) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            0U,
            request->pool_id,
            FBVBS_STORAGE_AUDIT_OP_CREATE_VDISK,
            INVALID_PARAMETER
        );
        return INVALID_PARAMETER;
    }

    if (!fbvbs_storage_requester_is_admin(requester)) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            0U,
            request->pool_id,
            FBVBS_STORAGE_AUDIT_OP_CREATE_VDISK,
            PERMISSION_DENIED
        );
        return PERMISSION_DENIED;
    }

    fbvbs_storage_state_lock(&state->storage_lock);

    status = fbvbs_storage_revalidate_requester_locked(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        status = PERMISSION_DENIED;
        goto out;
    }

    if (request->size_bytes == 0U ||
        request->size_bytes > state->scaling_limits.max_vdisk_size_runtime_bytes ||
        request->size_bytes > FBVBS_TARGET_MAX_VDISK_BYTES) {
        status = INVALID_PARAMETER;
        goto out;
    }

    owner_partition = fbvbs_find_partition_rw(state, request->owner_partition_id);
    if (owner_partition == NULL || owner_partition->kind != PARTITION_KIND_GUEST_VM) {
        status = INVALID_PARAMETER;
        goto out;
    }

    owner_vdisk_count = fbvbs_count_vm_vdisks(state, request->owner_partition_id);
    if (owner_vdisk_count >= state->scaling_limits.max_vdisks_per_vm_runtime) {
        status = RESOURCE_EXHAUSTED;
        goto out;
    }

    pool = fbvbs_find_storage_pool(state, request->pool_id);
    if (pool == NULL) {
        status = NOT_FOUND;
        goto out;
    }
    if (pool->granularity_bytes < FBVBS_PAGE_SIZE ||
        !fbvbs_is_power_of_two_u64(pool->granularity_bytes)) {
        status = INTERNAL_CORRUPTION;
        goto out;
    }
    if ((request->size_bytes % pool->granularity_bytes) != 0U) {
        status = INVALID_PARAMETER;
        goto out;
    }
    if (pool->allocated_bytes > pool->capacity_bytes) {
        status = INTERNAL_CORRUPTION;
        goto out;
    }
    if (request->size_bytes > pool->capacity_bytes - pool->allocated_bytes) {
        status = RESOURCE_EXHAUSTED;
        goto out;
    }
    if (pool->vdisk_count == UINT32_MAX) {
        status = RESOURCE_EXHAUSTED;
        goto out;
    }

    vdisk = fbvbs_allocate_virtual_disk_slot(state);
    if (vdisk == NULL) {
        status = RESOURCE_EXHAUSTED;
        goto out;
    }
    if (!fbvbs_id_allocator_can_advance(state->next_vdisk_id, 1U)) {
        status = RESOURCE_EXHAUSTED;
        goto out;
    }

    generation = (uint16_t)(vdisk->generation + 1U);
    if (generation == 0U) {
        generation = 1U;
    }

    *vdisk = (struct fbvbs_virtual_disk){0};
    vdisk->active = true;
    vdisk->generation = generation;
    vdisk->flags = request->flags;
    vdisk->vdisk_id = state->next_vdisk_id;
    state->next_vdisk_id += 1U;
    vdisk->pool_id = request->pool_id;
    vdisk->owner_partition_id = request->owner_partition_id;
    vdisk->size_bytes = request->size_bytes;
    vdisk->max_iops = request->max_iops;
    vdisk->max_bandwidth_bytes_per_sec = request->max_bandwidth_bytes_per_sec;
    fbvbs_storage_set_vdisk_state(vdisk, FBVBS_VDISK_STATE_PROVISIONED);

    pool->allocated_bytes += request->size_bytes;
    pool->vdisk_count += 1U;

    response->vdisk_id = vdisk->vdisk_id;
    created_vdisk_id = vdisk->vdisk_id;
    status = OK;

out:
    fbvbs_storage_state_unlock(&state->storage_lock);
    fbvbs_storage_audit_event(
        state,
        requester_partition_id,
        created_vdisk_id,
        request->pool_id,
        FBVBS_STORAGE_AUDIT_OP_CREATE_VDISK,
        status
    );
    return status;
}

int fbvbs_storage_destroy_vdisk(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_storage_vdisk_destroy_request *request,
    uint64_t requester_partition_id
)
{
    const struct fbvbs_partition *requester = NULL;
    struct fbvbs_virtual_disk *vdisk;
    struct fbvbs_storage_pool *pool;
    uint64_t pool_id_for_audit = 0U;
    uint16_t generation;
    int status;

    if (state == NULL || request == NULL || request->vdisk_id == 0U) {
        if (state != NULL) {
            fbvbs_storage_audit_event(
                state,
                requester_partition_id,
                (request == NULL) ? 0U : request->vdisk_id,
                0U,
                FBVBS_STORAGE_AUDIT_OP_DESTROY_VDISK,
                INVALID_PARAMETER
            );
        }
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U || request->reserved1 != 0U) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_DESTROY_VDISK,
            INVALID_PARAMETER
        );
        return INVALID_PARAMETER;
    }

    status = fbvbs_storage_validate_destructive_confirmation(
        state,
        FBVBS_STORAGE_CONFIRMATION_OP_DESTROY_VDISK,
        requester_partition_id,
        request->vdisk_id,
        request->session_correlation_id,
        request->confirmation_nonce,
        request->confirmation_expires_utc,
        request->confirmation_digest
    );
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_DESTROY_VDISK,
            status
        );
        return status;
    }

    status = fbvbs_resolve_storage_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_DESTROY_VDISK,
            status
        );
        return status;
    }

    fbvbs_storage_state_lock(&state->storage_lock);

    status = fbvbs_storage_revalidate_requester_locked(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        status = PERMISSION_DENIED;
        goto out;
    }

    if (fbvbs_confirmation_was_consumed_locked(
            state,
            FBVBS_STORAGE_CONFIRMATION_OP_DESTROY_VDISK,
            requester_partition_id,
            request->vdisk_id,
            request->session_correlation_id,
            request->confirmation_nonce) != 0) {
        status = POLICY_DENIED;
        goto out;
    }
    status = fbvbs_confirmation_consume_locked(
        state,
        FBVBS_STORAGE_CONFIRMATION_OP_DESTROY_VDISK,
        requester_partition_id,
        request->vdisk_id,
        request->session_correlation_id,
        request->confirmation_nonce,
        request->confirmation_expires_utc
    );
    if (status != OK) {
        goto out;
    }

    vdisk = fbvbs_find_virtual_disk(state, request->vdisk_id);
    if (vdisk == NULL) {
        status = NOT_FOUND;
        goto out;
    }
    status = fbvbs_storage_validate_vdisk_invariants(vdisk);
    if (status != OK) {
        goto out;
    }
    if (vdisk->attached) {
        status = RESOURCE_BUSY;
        goto out;
    }
    if (vdisk->lifecycle_state != FBVBS_VDISK_STATE_PROVISIONED &&
        vdisk->lifecycle_state != FBVBS_VDISK_STATE_QUARANTINED) {
        status = INVALID_STATE;
        goto out;
    }

    pool = fbvbs_find_storage_pool(state, vdisk->pool_id);
    pool_id_for_audit = vdisk->pool_id;
    if (pool == NULL || !pool->active) {
        fbvbs_storage_mark_vdisk_quarantined(
            vdisk,
            FBVBS_STORAGE_QUARANTINE_REASON_METADATA_INVARIANT
        );
        status = INTERNAL_CORRUPTION;
        goto out;
    }
    if (pool->allocated_bytes < vdisk->size_bytes || pool->vdisk_count == 0U) {
        fbvbs_storage_mark_vdisk_quarantined(
            vdisk,
            FBVBS_STORAGE_QUARANTINE_REASON_METADATA_INVARIANT
        );
        status = INTERNAL_CORRUPTION;
        goto out;
    }

    pool->allocated_bytes -= vdisk->size_bytes;
    pool->vdisk_count -= 1U;

    fbvbs_storage_set_vdisk_state(vdisk, FBVBS_VDISK_STATE_RELEASE_PENDING);

    generation = (uint16_t)(vdisk->generation + 1U);
    if (generation == 0U) {
        generation = 1U;
    }
    *vdisk = (struct fbvbs_virtual_disk){0};
    vdisk->generation = generation;
    vdisk->lifecycle_state = FBVBS_VDISK_STATE_DESTROYED;

    status = OK;

out:
    fbvbs_storage_state_unlock(&state->storage_lock);
    fbvbs_storage_audit_event(
        state,
        requester_partition_id,
        request->vdisk_id,
        pool_id_for_audit,
        FBVBS_STORAGE_AUDIT_OP_DESTROY_VDISK,
        status
    );
    return status;
}

int fbvbs_storage_attach_vdisk(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_storage_vdisk_attach_request *request,
    uint64_t requester_partition_id
)
{
    const struct fbvbs_partition *requester = NULL;
    struct fbvbs_partition *partition;
    struct fbvbs_virtual_disk *vdisk;
    int status;

    if (state == NULL || request == NULL || request->vdisk_id == 0U ||
        request->vm_partition_id == 0U) {
        if (state != NULL) {
            fbvbs_storage_audit_event(
                state,
                requester_partition_id,
                (request == NULL) ? 0U : request->vdisk_id,
                (request == NULL) ? 0U : request->vm_partition_id,
                FBVBS_STORAGE_AUDIT_OP_ATTACH_VDISK,
                INVALID_PARAMETER
            );
        }
        return INVALID_PARAMETER;
    }

    status = fbvbs_resolve_storage_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            request->vm_partition_id,
            FBVBS_STORAGE_AUDIT_OP_ATTACH_VDISK,
            status
        );
        return status;
    }

    fbvbs_storage_state_lock(&state->storage_lock);

    status = fbvbs_storage_revalidate_requester_locked(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }

    vdisk = fbvbs_find_virtual_disk(state, request->vdisk_id);
    if (vdisk == NULL) {
        status = NOT_FOUND;
        goto out;
    }
    if (!fbvbs_storage_requester_is_admin(requester) &&
        !fbvbs_storage_requester_is_owner_tenant(requester, vdisk)) {
        status = PERMISSION_DENIED;
        goto out;
    }
    status = fbvbs_storage_validate_vdisk_invariants(vdisk);
    if (status != OK) {
        goto out;
    }
    if (vdisk->lifecycle_state != FBVBS_VDISK_STATE_PROVISIONED || vdisk->attached) {
        status = INVALID_STATE;
        goto out;
    }

    partition = fbvbs_find_partition_rw(state, request->vm_partition_id);
    if (partition == NULL) {
        status = NOT_FOUND;
        goto out;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        status = INVALID_PARAMETER;
        goto out;
    }
    if (partition->partition_id != vdisk->owner_partition_id) {
        status = PERMISSION_DENIED;
        goto out;
    }

    vdisk->attached_partition_id = request->vm_partition_id;
    fbvbs_storage_set_vdisk_state(vdisk, FBVBS_VDISK_STATE_ATTACHED);
    status = OK;

out:
    fbvbs_storage_state_unlock(&state->storage_lock);
    fbvbs_storage_audit_event(
        state,
        requester_partition_id,
        request->vdisk_id,
        request->vm_partition_id,
        FBVBS_STORAGE_AUDIT_OP_ATTACH_VDISK,
        status
    );
    return status;
}

int fbvbs_storage_detach_vdisk(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_storage_vdisk_request *request,
    uint64_t requester_partition_id
)
{
    const struct fbvbs_partition *requester = NULL;
    struct fbvbs_virtual_disk *vdisk;
    int status;

    if (state == NULL || request == NULL || request->vdisk_id == 0U) {
        if (state != NULL) {
            fbvbs_storage_audit_event(
                state,
                requester_partition_id,
                (request == NULL) ? 0U : request->vdisk_id,
                0U,
                FBVBS_STORAGE_AUDIT_OP_DETACH_VDISK,
                INVALID_PARAMETER
            );
        }
        return INVALID_PARAMETER;
    }

    status = fbvbs_resolve_storage_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_DETACH_VDISK,
            status
        );
        return status;
    }

    fbvbs_storage_state_lock(&state->storage_lock);

    status = fbvbs_storage_revalidate_requester_locked(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }

    vdisk = fbvbs_find_virtual_disk(state, request->vdisk_id);
    if (vdisk == NULL) {
        status = NOT_FOUND;
        goto out;
    }
    if (!fbvbs_storage_requester_can_manage_vdisk(requester, vdisk)) {
        status = PERMISSION_DENIED;
        goto out;
    }
    status = fbvbs_storage_validate_vdisk_invariants(vdisk);
    if (status != OK) {
        goto out;
    }
    if (vdisk->lifecycle_state != FBVBS_VDISK_STATE_ATTACHED || !vdisk->attached) {
        status = INVALID_STATE;
        goto out;
    }

    fbvbs_storage_set_vdisk_state(vdisk, FBVBS_VDISK_STATE_DETACH_PENDING);
    fbvbs_storage_set_vdisk_state(vdisk, FBVBS_VDISK_STATE_PROVISIONED);
    status = OK;

out:
    fbvbs_storage_state_unlock(&state->storage_lock);
    fbvbs_storage_audit_event(
        state,
        requester_partition_id,
        request->vdisk_id,
        0U,
        FBVBS_STORAGE_AUDIT_OP_DETACH_VDISK,
        status
    );
    return status;
}

int fbvbs_storage_get_pool_status(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_storage_pool_request *request,
    struct fbvbs_storage_pool_status_response *response,
    uint64_t requester_partition_id
)
{
    const struct fbvbs_partition *requester = NULL;
    const struct fbvbs_storage_pool *pool;
    int status;

    if (state == NULL || request == NULL || response == NULL || request->pool_id == 0U) {
        if (state != NULL) {
            fbvbs_storage_audit_event(
                state,
                requester_partition_id,
                (request == NULL) ? 0U : request->pool_id,
                0U,
                FBVBS_STORAGE_AUDIT_OP_GET_POOL_STATUS,
                INVALID_PARAMETER
            );
        }
        return INVALID_PARAMETER;
    }

    status = fbvbs_resolve_storage_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->pool_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_GET_POOL_STATUS,
            status
        );
        return status;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->pool_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_GET_POOL_STATUS,
            PERMISSION_DENIED
        );
        return PERMISSION_DENIED;
    }

    fbvbs_storage_state_lock(&state->storage_lock);

    status = fbvbs_storage_revalidate_requester_locked(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        status = PERMISSION_DENIED;
        goto out;
    }

    pool = fbvbs_find_storage_pool(state, request->pool_id);
    if (pool == NULL) {
        status = NOT_FOUND;
        goto out;
    }

    *response = (struct fbvbs_storage_pool_status_response){0};
    response->pool_id = pool->pool_id;
    response->capacity_bytes = pool->capacity_bytes;
    response->allocated_bytes = pool->allocated_bytes;
    response->vdisk_count = pool->vdisk_count;
    response->flags = pool->flags;
    status = OK;

out:
    fbvbs_storage_state_unlock(&state->storage_lock);
    fbvbs_storage_audit_event(
        state,
        requester_partition_id,
        request->pool_id,
        0U,
        FBVBS_STORAGE_AUDIT_OP_GET_POOL_STATUS,
        status
    );
    return status;
}

int fbvbs_storage_get_vdisk_status(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_storage_vdisk_request *request,
    struct fbvbs_storage_vdisk_status_response *response,
    uint64_t requester_partition_id
)
{
    const struct fbvbs_partition *requester = NULL;
    struct fbvbs_virtual_disk *vdisk;
    int status;

    if (state == NULL || request == NULL || response == NULL || request->vdisk_id == 0U) {
        if (state != NULL) {
            fbvbs_storage_audit_event(
                state,
                requester_partition_id,
                (request == NULL) ? 0U : request->vdisk_id,
                0U,
                FBVBS_STORAGE_AUDIT_OP_GET_VDISK_STATUS,
                INVALID_PARAMETER
            );
        }
        return INVALID_PARAMETER;
    }

    status = fbvbs_resolve_storage_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_GET_VDISK_STATUS,
            status
        );
        return status;
    }

    fbvbs_storage_state_lock(&state->storage_lock);

    status = fbvbs_storage_revalidate_requester_locked(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }

    vdisk = fbvbs_find_virtual_disk(state, request->vdisk_id);
    if (vdisk == NULL) {
        status = NOT_FOUND;
        goto out;
    }
    if (!fbvbs_storage_requester_can_manage_vdisk(requester, vdisk)) {
        status = PERMISSION_DENIED;
        goto out;
    }
    status = fbvbs_storage_validate_vdisk_invariants(vdisk);
    if (status != OK) {
        goto out;
    }

    *response = (struct fbvbs_storage_vdisk_status_response){0};
    response->vdisk_id = vdisk->vdisk_id;
    response->pool_id = vdisk->pool_id;
    response->owner_partition_id = vdisk->owner_partition_id;
    response->attached_partition_id = vdisk->attached_partition_id;
    response->size_bytes = vdisk->size_bytes;
    response->max_iops = vdisk->max_iops;
    response->max_bandwidth_bytes_per_sec = vdisk->max_bandwidth_bytes_per_sec;
    response->flags = vdisk->flags;
    response->generation = vdisk->generation;
    response->active = vdisk->active ? 1U : 0U;
    response->attached = vdisk->attached ? 1U : 0U;
    status = OK;

out:
    fbvbs_storage_state_unlock(&state->storage_lock);
    fbvbs_storage_audit_event(
        state,
        requester_partition_id,
        request->vdisk_id,
        0U,
        FBVBS_STORAGE_AUDIT_OP_GET_VDISK_STATUS,
        status
    );
    return status;
}

int fbvbs_storage_set_vdisk_qos(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_storage_vdisk_qos_request *request,
    uint64_t requester_partition_id
)
{
    const struct fbvbs_partition *requester = NULL;
    struct fbvbs_virtual_disk *vdisk;
    int status;

    if (state == NULL || request == NULL || request->vdisk_id == 0U) {
        if (state != NULL) {
            fbvbs_storage_audit_event(
                state,
                requester_partition_id,
                (request == NULL) ? 0U : request->vdisk_id,
                0U,
                FBVBS_STORAGE_AUDIT_OP_SET_VDISK_QOS,
                INVALID_PARAMETER
            );
        }
        return INVALID_PARAMETER;
    }

    status = fbvbs_resolve_storage_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_SET_VDISK_QOS,
            status
        );
        return status;
    }

    if (!fbvbs_storage_requester_is_admin(requester)) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_SET_VDISK_QOS,
            PERMISSION_DENIED
        );
        return PERMISSION_DENIED;
    }
    fbvbs_storage_state_lock(&state->storage_lock);

    status = fbvbs_storage_revalidate_requester_locked(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        status = PERMISSION_DENIED;
        goto out;
    }

    vdisk = fbvbs_find_virtual_disk(state, request->vdisk_id);
    if (vdisk == NULL) {
        status = NOT_FOUND;
        goto out;
    }
    if (!fbvbs_storage_requester_can_manage_vdisk(requester, vdisk)) {
        status = PERMISSION_DENIED;
        goto out;
    }
    status = fbvbs_storage_validate_vdisk_invariants(vdisk);
    if (status != OK) {
        goto out;
    }
    if (vdisk->lifecycle_state == FBVBS_VDISK_STATE_QUARANTINED ||
        vdisk->lifecycle_state == FBVBS_VDISK_STATE_RELEASE_PENDING ||
        vdisk->lifecycle_state == FBVBS_VDISK_STATE_DESTROYED) {
        status = INVALID_STATE;
        goto out;
    }

    vdisk->max_iops = request->max_iops;
    vdisk->max_bandwidth_bytes_per_sec = request->max_bandwidth_bytes_per_sec;
    status = OK;

out:
    fbvbs_storage_state_unlock(&state->storage_lock);
    fbvbs_storage_audit_event(
        state,
        requester_partition_id,
        request->vdisk_id,
        0U,
        FBVBS_STORAGE_AUDIT_OP_SET_VDISK_QOS,
        status
    );
    return status;
}

int fbvbs_storage_report_vdisk_corruption(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_storage_vdisk_corruption_request *request,
    uint64_t requester_partition_id
)
{
    const struct fbvbs_partition *requester = NULL;
    struct fbvbs_virtual_disk *vdisk;
    uint32_t quarantine_reason;
    int status;

    if (state == NULL || request == NULL || request->vdisk_id == 0U) {
        if (state != NULL) {
            fbvbs_storage_audit_event(
                state,
                requester_partition_id,
                (request == NULL) ? 0U : request->vdisk_id,
                0U,
                FBVBS_STORAGE_AUDIT_OP_QUARANTINE_VDISK,
                INVALID_PARAMETER
            );
        }
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_QUARANTINE_VDISK,
            INVALID_PARAMETER
        );
        return INVALID_PARAMETER;
    }

    status = fbvbs_resolve_storage_requester(state, requester_partition_id, &requester);
    if (status != OK) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_QUARANTINE_VDISK,
            status
        );
        return status;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        fbvbs_storage_audit_event(
            state,
            requester_partition_id,
            request->vdisk_id,
            0U,
            FBVBS_STORAGE_AUDIT_OP_QUARANTINE_VDISK,
            PERMISSION_DENIED
        );
        return PERMISSION_DENIED;
    }

    quarantine_reason = request->quarantine_reason;
    if (quarantine_reason == 0U) {
        quarantine_reason = FBVBS_STORAGE_QUARANTINE_REASON_OPERATOR_REPORTED;
    }

    fbvbs_storage_state_lock(&state->storage_lock);

    status = fbvbs_storage_revalidate_requester_locked(state, requester_partition_id, &requester);
    if (status != OK) {
        goto out;
    }
    if (!fbvbs_storage_requester_is_admin(requester)) {
        status = PERMISSION_DENIED;
        goto out;
    }

    vdisk = fbvbs_find_virtual_disk(state, request->vdisk_id);
    if (vdisk == NULL) {
        status = NOT_FOUND;
        goto out;
    }

    fbvbs_storage_mark_vdisk_quarantined(vdisk, quarantine_reason);
    status = OK;

out:
    fbvbs_storage_state_unlock(&state->storage_lock);
    fbvbs_storage_audit_event(
        state,
        requester_partition_id,
        request->vdisk_id,
        0U,
        FBVBS_STORAGE_AUDIT_OP_QUARANTINE_VDISK,
        status
    );
    return status;
}
