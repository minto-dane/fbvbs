#include "fbvbs_hypervisor.h"

/*@ requires \valid(lock);
    assigns *lock;
*/
static void fbvbs_scaling_storage_lock(volatile uint32_t *lock)
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

/*@ requires \valid(lock);
    assigns *lock;
*/
static void fbvbs_scaling_storage_unlock(volatile uint32_t *lock)
{
#ifndef __FRAMAC__
    __sync_lock_release(lock);
#else
    if (lock != NULL) {
        *lock = 0U;
    }
#endif
}

/* Count currently active guest VM partitions. */
/*@ requires state == \null || \valid_read(state);
    assigns \nothing;
*/
static uint32_t fbvbs_count_active_vms(const struct fbvbs_hypervisor_state *state)
{
    uint32_t count = 0U;
    uint32_t index;

    if (state == NULL) {
        return 0U;
    }

    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        const struct fbvbs_partition *partition = &state->partitions[index];

        if (!partition->occupied) {
            continue;
        }
        if (partition->kind != PARTITION_KIND_GUEST_VM) {
            continue;
        }
        if (count == UINT32_MAX) {
            break;
        }
        count += 1U;
    }

    return count;
}

/* Count the currently configured vCPU budget across active guest VMs. */
/*@ requires state == \null || \valid_read(state);
    assigns \nothing;
*/
static uint32_t fbvbs_count_allocated_vcpus(const struct fbvbs_hypervisor_state *state)
{
    uint32_t total = 0U;
    uint32_t index;

    if (state == NULL) {
        return 0U;
    }

    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        const struct fbvbs_partition *partition = &state->partitions[index];

        if (!partition->occupied || partition->kind != PARTITION_KIND_GUEST_VM) {
            continue;
        }
        if (partition->vcpu_count > UINT32_MAX - total) {
            return UINT32_MAX;
        }
        total += partition->vcpu_count;
    }

    return total;
}

/*@ requires state == \null || \valid_read(state);
    assigns \nothing;
*/
static uint32_t fbvbs_count_active_storage_pools(const struct fbvbs_hypervisor_state *state)
{
    uint32_t count = 0U;
    uint32_t index;

    if (state == NULL) {
        return 0U;
    }

    for (index = 0U; index < FBVBS_MAX_STORAGE_POOLS; ++index) {
        if (state->storage_pools[index].active) {
            if (count == UINT32_MAX) {
                return UINT32_MAX;
            }
            count += 1U;
        }
    }

    return count;
}

/*@ requires state == \null || \valid_read(state);
    assigns \nothing;
*/
static uint32_t fbvbs_count_active_vdisks(const struct fbvbs_hypervisor_state *state)
{
    uint32_t count = 0U;
    uint32_t index;

    if (state == NULL) {
        return 0U;
    }

    for (index = 0U; index < FBVBS_MAX_VIRTUAL_DISKS; ++index) {
        if (state->virtual_disks[index].active) {
            if (count == UINT32_MAX) {
                return UINT32_MAX;
            }
            count += 1U;
        }
    }

    return count;
}

/*@ requires state == \null || \valid_read(state);
    assigns \nothing;
*/
static uint32_t fbvbs_max_vdisks_per_vm_allocated(const struct fbvbs_hypervisor_state *state)
{
    uint32_t max_count = 0U;
    uint32_t partition_index;

    if (state == NULL) {
        return 0U;
    }

    for (partition_index = 0U; partition_index < FBVBS_MAX_PARTITIONS; ++partition_index) {
        const struct fbvbs_partition *partition = &state->partitions[partition_index];
        uint32_t count = 0U;
        uint32_t vdisk_index;

        if (!partition->occupied || partition->kind != PARTITION_KIND_GUEST_VM) {
            continue;
        }

        for (vdisk_index = 0U; vdisk_index < FBVBS_MAX_VIRTUAL_DISKS; ++vdisk_index) {
            const struct fbvbs_virtual_disk *vdisk = &state->virtual_disks[vdisk_index];

            if (vdisk->active && vdisk->owner_partition_id == partition->partition_id) {
                if (count != UINT32_MAX) {
                    count += 1U;
                }
            }
        }

        if (count > max_count) {
            max_count = count;
        }
    }

    return max_count;
}

/*@ requires state == \null || \valid_read(state);
    assigns \nothing;
*/
static uint64_t fbvbs_max_vdisk_size_bytes(const struct fbvbs_hypervisor_state *state)
{
    uint64_t max_size = 0U;
    uint32_t index;

    if (state == NULL) {
        return 0U;
    }

    for (index = 0U; index < FBVBS_MAX_VIRTUAL_DISKS; ++index) {
        const struct fbvbs_virtual_disk *vdisk = &state->virtual_disks[index];

        if (vdisk->active && vdisk->size_bytes > max_size) {
            max_size = vdisk->size_bytes;
        }
    }

    return max_size;
}

/*@ requires state == \null || \valid_read(state);
    requires limits == \null || \valid_read(limits);
    assigns \nothing;
*/
static int fbvbs_validate_scaling_runtime_limits(
    const struct fbvbs_hypervisor_state *state,
    const struct fbvbs_scaling_runtime_limits *limits
)
{
    uint32_t max_vdisks_in_use;
    uint64_t max_vdisk_size_in_use;

    if (state == NULL || limits == NULL) {
        return INVALID_PARAMETER;
    }

    if (limits->max_vm_count_runtime == 0U ||
        limits->max_vcpus_per_vm_runtime == 0U ||
        limits->max_host_cpu_count_runtime == 0U ||
        limits->max_vdisks_per_vm_runtime == 0U ||
        limits->max_memory_per_vm_runtime_bytes == 0U ||
        limits->max_vdisk_size_runtime_bytes == 0U) {
        return INVALID_PARAMETER;
    }

    if (limits->max_vm_count_runtime > FBVBS_TARGET_MAX_VMS_PER_HOST ||
        limits->max_vcpus_per_vm_runtime > FBVBS_TARGET_MAX_VCPUS_PER_VM ||
        limits->max_host_cpu_count_runtime > FBVBS_TARGET_MAX_HOST_CPUS ||
        limits->max_vdisks_per_vm_runtime > FBVBS_TARGET_MAX_VDISKS_PER_VM ||
        limits->max_memory_per_vm_runtime_bytes > FBVBS_TARGET_MAX_MEMORY_PER_VM_BYTES ||
        limits->max_vdisk_size_runtime_bytes > FBVBS_TARGET_MAX_VDISK_BYTES) {
        return INVALID_PARAMETER;
    }

    max_vdisks_in_use = fbvbs_max_vdisks_per_vm_allocated(state);
    max_vdisk_size_in_use = fbvbs_max_vdisk_size_bytes(state);

    if (limits->max_vdisks_per_vm_runtime < max_vdisks_in_use ||
        limits->max_vdisk_size_runtime_bytes < max_vdisk_size_in_use) {
        return INVALID_PARAMETER;
    }

    return OK;
}

int fbvbs_scaling_init(struct fbvbs_hypervisor_state *state)
{
    if (state == NULL) {
        return INVALID_PARAMETER;
    }

    state->next_storage_pool_id = UINT64_C(0x800000);
    state->next_vdisk_id = UINT64_C(0x900000);

    state->scaling_limits.max_vm_count_runtime = FBVBS_DEFAULT_RUNTIME_MAX_VMS;
    state->scaling_limits.max_vcpus_per_vm_runtime = FBVBS_DEFAULT_RUNTIME_MAX_VCPUS_PER_VM;
    state->scaling_limits.max_host_cpu_count_runtime = FBVBS_DEFAULT_RUNTIME_MAX_HOST_CPUS;
    state->scaling_limits.max_vdisks_per_vm_runtime = FBVBS_DEFAULT_RUNTIME_MAX_VDISKS_PER_VM;
    state->scaling_limits.max_memory_per_vm_runtime_bytes = FBVBS_DEFAULT_RUNTIME_MAX_MEMORY_PER_VM_BYTES;
    state->scaling_limits.max_vdisk_size_runtime_bytes = FBVBS_DEFAULT_RUNTIME_MAX_VDISK_BYTES;

    return OK;
}

/* Build a consistent scaling snapshot while storage_lock is held. */
/*@ requires \valid_read(state);
    requires \valid(response);
    assigns *response;
*/
static void fbvbs_fill_scaling_limits_response_locked(
    const struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_scaling_limits_response *response
)
{
    *response = (struct fbvbs_diag_scaling_limits_response){0};

    response->runtime_max_vm_count = state->scaling_limits.max_vm_count_runtime;
    response->runtime_max_vcpus_per_vm = state->scaling_limits.max_vcpus_per_vm_runtime;
    response->runtime_max_host_cpu_count = state->scaling_limits.max_host_cpu_count_runtime;
    response->runtime_max_vdisks_per_vm = state->scaling_limits.max_vdisks_per_vm_runtime;
    response->runtime_max_memory_per_vm_bytes = state->scaling_limits.max_memory_per_vm_runtime_bytes;
    response->runtime_max_vdisk_size_bytes = state->scaling_limits.max_vdisk_size_runtime_bytes;

    response->supported_max_vm_count = FBVBS_TARGET_MAX_VMS_PER_HOST;
    response->supported_max_vcpus_per_vm = FBVBS_TARGET_MAX_VCPUS_PER_VM;
    response->supported_max_host_cpu_count = FBVBS_TARGET_MAX_HOST_CPUS;
    response->supported_max_vdisks_per_vm = FBVBS_TARGET_MAX_VDISKS_PER_VM;
    response->supported_max_memory_per_vm_bytes = FBVBS_TARGET_MAX_MEMORY_PER_VM_BYTES;
    response->supported_max_vdisk_size_bytes = FBVBS_TARGET_MAX_VDISK_BYTES;

    response->current_vm_count = fbvbs_count_active_vms(state);
    response->current_allocated_vcpu_count = fbvbs_count_allocated_vcpus(state);
    response->current_storage_pool_count = fbvbs_count_active_storage_pools(state);
    response->current_vdisk_count = fbvbs_count_active_vdisks(state);
}

int fbvbs_diag_get_scaling_limits(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_scaling_limits_response *response
)
{
    if (state == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    fbvbs_scaling_storage_lock(&state->storage_lock);
    fbvbs_fill_scaling_limits_response_locked(state, response);
    fbvbs_scaling_storage_unlock(&state->storage_lock);

    return OK;
}

int fbvbs_diag_set_scaling_limits(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_diag_set_scaling_limits_request *request,
    struct fbvbs_diag_scaling_limits_response *response
)
{
    struct fbvbs_scaling_runtime_limits new_limits;
    uint32_t allowed_mask;
    uint32_t supported_runtime_update_mask;
    int status;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    allowed_mask = FBVBS_SCALE_UPDATE_MAX_VM_COUNT |
                   FBVBS_SCALE_UPDATE_MAX_VCPUS_PER_VM |
                   FBVBS_SCALE_UPDATE_MAX_HOST_CPU_COUNT |
                   FBVBS_SCALE_UPDATE_MAX_VDISKS_PER_VM |
                   FBVBS_SCALE_UPDATE_MAX_MEMORY_PER_VM_BYTES |
                   FBVBS_SCALE_UPDATE_MAX_VDISK_SIZE_BYTES;

    supported_runtime_update_mask = FBVBS_SCALE_UPDATE_MAX_VDISKS_PER_VM |
                                    FBVBS_SCALE_UPDATE_MAX_VDISK_SIZE_BYTES;

    if (request->reserved0 != 0U || (request->update_mask & ~allowed_mask) != 0U) {
        return INVALID_PARAMETER;
    }
    if ((request->update_mask & ~supported_runtime_update_mask) != 0U) {
        return NOT_SUPPORTED_ON_PLATFORM;
    }

    fbvbs_scaling_storage_lock(&state->storage_lock);

    new_limits = state->scaling_limits;

    if ((request->update_mask & FBVBS_SCALE_UPDATE_MAX_VM_COUNT) != 0U) {
        new_limits.max_vm_count_runtime = request->runtime_max_vm_count;
    }
    if ((request->update_mask & FBVBS_SCALE_UPDATE_MAX_VCPUS_PER_VM) != 0U) {
        new_limits.max_vcpus_per_vm_runtime = request->runtime_max_vcpus_per_vm;
    }
    if ((request->update_mask & FBVBS_SCALE_UPDATE_MAX_HOST_CPU_COUNT) != 0U) {
        new_limits.max_host_cpu_count_runtime = request->runtime_max_host_cpu_count;
    }
    if ((request->update_mask & FBVBS_SCALE_UPDATE_MAX_VDISKS_PER_VM) != 0U) {
        new_limits.max_vdisks_per_vm_runtime = request->runtime_max_vdisks_per_vm;
    }
    if ((request->update_mask & FBVBS_SCALE_UPDATE_MAX_MEMORY_PER_VM_BYTES) != 0U) {
        new_limits.max_memory_per_vm_runtime_bytes = request->runtime_max_memory_per_vm_bytes;
    }
    if ((request->update_mask & FBVBS_SCALE_UPDATE_MAX_VDISK_SIZE_BYTES) != 0U) {
        new_limits.max_vdisk_size_runtime_bytes = request->runtime_max_vdisk_size_bytes;
    }

    status = fbvbs_validate_scaling_runtime_limits(state, &new_limits);
    if (status != OK) {
        fbvbs_scaling_storage_unlock(&state->storage_lock);
        return status;
    }

    state->scaling_limits = new_limits;
    fbvbs_fill_scaling_limits_response_locked(state, response);
    status = OK;

    fbvbs_scaling_storage_unlock(&state->storage_lock);
    return status;
}
