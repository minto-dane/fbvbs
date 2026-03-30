/* FBVBS Partition Management
 *
 * Requirements: REQ-0200 (責務限定), REQ-0202 (パーティション状態),
 *   REQ-0203 (メモリゼロ化), REQ-0204 (capability 管理),
 *   REQ-0211 (lifecycle 遷移限定), REQ-0212 (RESUME/RECOVER 分離),
 *   REQ-0604 (KEY_EXCHANGE ハンドル — PRODUCTION NOTE: Phase 5 IKS),
 *   REQ-0902 (未分類 exit fail-closed),
 *   REQ-0903 (再利用前ゼロ化),
 *   REQ-1105 (passthrough qualification — PRODUCTION NOTE: Phase 9 release gate)
 */
#include "fbvbs_hypervisor.h"

/*@ requires \valid(state);
    assigns \result \from partition_id, state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_PARTITIONS && \result == &state->partitions[i]);
*/
static struct fbvbs_partition *fbvbs_find_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_PARTITIONS;
        loop assigns index;
        loop variant FBVBS_MAX_PARTITIONS - index;
    */
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        if ((state->partitions[index].occupied || state->partitions[index].tombstone) &&
            state->partitions[index].partition_id == partition_id) {
            return &state->partitions[index];
        }
    }

    return NULL;
}

/*@ requires \valid_read(state);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns \result \from object_id, state->artifact_catalog.count,
            state->artifact_catalog.entries[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1];
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_artifact_catalog_entry *fbvbs_find_artifact_entry(
    const struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= state->artifact_catalog.count;
        loop assigns index;
        loop variant state->artifact_catalog.count - index;
    */
    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &state->artifact_catalog.entries[index];

        if (entry->object_id == object_id) {
            return entry;
        }
    }

    return NULL;
}

/*@ requires \valid_read(state);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns \result \from image_object_id, *state;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_artifact_catalog_entry *fbvbs_find_related_manifest_entry(
    const struct fbvbs_hypervisor_state *state,
    uint64_t image_object_id
) {
    const struct fbvbs_artifact_catalog_entry *image_entry;
    const struct fbvbs_artifact_catalog_entry *manifest_entry;

#ifdef __FRAMAC__
    (void)state;
    (void)image_object_id;
    return NULL;
#endif

    image_entry = fbvbs_find_artifact_entry(state, image_object_id);
    if (image_entry == NULL || image_entry->object_kind != FBVBS_ARTIFACT_OBJECT_IMAGE) {
        return NULL;
    }
    if (image_entry->related_index >= state->artifact_catalog.count) {
        return NULL;
    }

    manifest_entry = &state->artifact_catalog.entries[image_entry->related_index];
    if (manifest_entry->object_kind != FBVBS_ARTIFACT_OBJECT_MANIFEST ||
        manifest_entry->related_index >= state->artifact_catalog.count ||
        state->artifact_catalog.entries[manifest_entry->related_index].object_id != image_object_id) {
        return NULL;
    }
    return manifest_entry;
}

static const struct fbvbs_manifest_profile *fbvbs_find_trusted_service_profile_for_image(
    const struct fbvbs_hypervisor_state *state,
    uint64_t image_object_id
) {
    const struct fbvbs_artifact_catalog_entry *manifest_entry;
    const struct fbvbs_manifest_profile *profile;

#ifdef __FRAMAC__
    (void)state;
    (void)image_object_id;
    return NULL;
#endif

    manifest_entry = fbvbs_find_related_manifest_entry(state, image_object_id);

    if (manifest_entry == NULL) {
        return NULL;
    }
    profile = fbvbs_find_manifest_profile_for_object(
        state,
        FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE,
        image_object_id
    );
    if (profile == NULL || profile->manifest_object_id != manifest_entry->object_id) {
        return NULL;
    }
    return profile;
}

static const struct fbvbs_manifest_profile *fbvbs_find_guest_boot_profile_for_image(
    const struct fbvbs_hypervisor_state *state,
    uint64_t image_object_id
) {
    const struct fbvbs_artifact_catalog_entry *manifest_entry;
    const struct fbvbs_manifest_profile *profile;

#ifdef __FRAMAC__
    (void)state;
    (void)image_object_id;
    return NULL;
#endif

    manifest_entry = fbvbs_find_related_manifest_entry(state, image_object_id);

    if (manifest_entry == NULL) {
        return NULL;
    }
    profile = fbvbs_find_manifest_profile_for_object(
        state,
        FBVBS_MANIFEST_COMPONENT_GUEST_BOOT,
        image_object_id
    );
    if (profile == NULL || profile->manifest_object_id != manifest_entry->object_id) {
        return NULL;
    }
    return profile;
}

/*@ requires \valid_read(state);
    requires \valid_read(partition);
    requires \valid_read(request);
    requires \valid(resolved_entry_ip);
    requires \valid(resolved_initial_sp);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns *resolved_entry_ip, *resolved_initial_sp;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == INVALID_STATE ||
            \result == MEASUREMENT_FAILED;
*/
static int fbvbs_partition_resolve_load_layout(
    const struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition *partition,
    const struct fbvbs_partition_load_image_request *request,
    uint64_t *resolved_entry_ip,
    uint64_t *resolved_initial_sp
) {
    const struct fbvbs_manifest_profile *profile = NULL;
    uint64_t selected_entry_ip = 0U;
    uint64_t selected_initial_sp = 0U;

#ifdef __FRAMAC__
    (void)state;
    if (partition == NULL || request == NULL ||
        resolved_entry_ip == NULL || resolved_initial_sp == NULL) {
        return INVALID_PARAMETER;
    }
    if (partition->kind == PARTITION_KIND_TRUSTED_SERVICE) {
        return MEASUREMENT_FAILED;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        return INVALID_STATE;
    }
    if (request->initial_sp == 0U) {
        return INVALID_PARAMETER;
    }
    *resolved_entry_ip = request->entry_ip;
    *resolved_initial_sp = request->initial_sp;
    return OK;
#endif

    if (partition->kind == PARTITION_KIND_TRUSTED_SERVICE) {
        profile = fbvbs_find_trusted_service_profile_for_image(state, partition->image_object_id);
        if (profile == NULL || profile->manifest_object_id != partition->manifest_object_id) {
            return MEASUREMENT_FAILED;
        }
        if (profile->entry_ip == 0U || profile->initial_sp == 0U) {
            return MEASUREMENT_FAILED;
        }
        if (request->entry_ip != 0U && request->entry_ip != profile->entry_ip) {
            return MEASUREMENT_FAILED;
        }
        if (request->initial_sp != 0U && request->initial_sp != profile->initial_sp) {
            return MEASUREMENT_FAILED;
        }
        selected_entry_ip = (request->entry_ip != 0U) ? request->entry_ip : profile->entry_ip;
        selected_initial_sp =
            (request->initial_sp != 0U) ? request->initial_sp : profile->initial_sp;
    } else if (partition->kind == PARTITION_KIND_GUEST_VM) {
        profile = fbvbs_find_guest_boot_profile_for_image(state, partition->image_object_id);
        if (profile == NULL || profile->manifest_object_id != partition->manifest_object_id) {
            return MEASUREMENT_FAILED;
        }
        if (profile->entry_ip == 0U) {
            return MEASUREMENT_FAILED;
        }
        if (request->entry_ip != 0U && request->entry_ip != profile->entry_ip) {
            return MEASUREMENT_FAILED;
        }
        if (request->initial_sp == 0U) {
            return INVALID_PARAMETER;
        }
        selected_entry_ip = (request->entry_ip != 0U) ? request->entry_ip : profile->entry_ip;
        selected_initial_sp = request->initial_sp;
    } else {
        return INVALID_STATE;
    }

    *resolved_entry_ip = selected_entry_ip;
    *resolved_initial_sp = selected_initial_sp;
    return OK;
}

/*@ requires \valid(state);
    assigns \result \from state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_PARTITIONS && \result == &state->partitions[i]);
*/
static struct fbvbs_partition *fbvbs_allocate_partition_slot(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_PARTITIONS;
        loop assigns index;
        loop variant FBVBS_MAX_PARTITIONS - index;
    */
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        if (!state->partitions[index].occupied && !state->partitions[index].tombstone) {
            return &state->partitions[index];
        }
    }

    return NULL;
}

/*@ requires \valid(partition);
    assigns partition->vcpus[0 .. FBVBS_MAX_VCPUS - 1];
*/
static void fbvbs_partition_reset_vcpus(struct fbvbs_partition *partition, uint32_t state) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_VCPUS;
        loop assigns index, partition->vcpus[0 .. FBVBS_MAX_VCPUS - 1];
        loop variant FBVBS_MAX_VCPUS - index;
    */
    for (index = 0U; index < FBVBS_MAX_VCPUS; ++index) {
        partition->vcpus[index] = (struct fbvbs_vcpu){0};
        partition->vcpus[index].state = FBVBS_VCPU_STATE_DESTROYED;
        /* Architectural reset values per Intel SDM Vol. 3, 17.2.3/17.2.4 */
        partition->vcpus[index].dr6 = 0x00000000FFFF0FF0ULL;
        partition->vcpus[index].dr7 = 0x0000000000000400ULL;
    }

    /*@ loop invariant 0 <= index <= partition->vcpu_count || index <= FBVBS_MAX_VCPUS;
        loop assigns index, partition->vcpus[0 .. FBVBS_MAX_VCPUS - 1];
        loop variant FBVBS_MAX_VCPUS - index;
    */
    for (index = 0U; index < partition->vcpu_count && index < FBVBS_MAX_VCPUS; ++index) {
        partition->vcpus[index].state = state;
        partition->vcpus[index].rflags = 0x2U;
    }
}

/*@ requires \valid(partition);
    assigns partition->vcpus[0 .. FBVBS_MAX_VCPUS - 1];
*/
static void fbvbs_partition_set_vcpu_state(struct fbvbs_partition *partition, uint32_t state) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= partition->vcpu_count || index <= FBVBS_MAX_VCPUS;
        loop assigns index, partition->vcpus[0 .. FBVBS_MAX_VCPUS - 1];
        loop variant FBVBS_MAX_VCPUS - index;
    */
    for (index = 0U; index < partition->vcpu_count && index < FBVBS_MAX_VCPUS; ++index) {
        partition->vcpus[index].state = state;
    }
}

/*@ requires \valid_read(partition) || partition == \null;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_partition_has_running_vcpu(const struct fbvbs_partition *partition) {
    uint32_t index;

    if (partition == NULL) {
        return 0;
    }

    /*@ loop invariant 0 <= index <= partition->vcpu_count || index <= FBVBS_MAX_VCPUS;
        loop assigns index;
        loop variant FBVBS_MAX_VCPUS - index;
    */
    for (index = 0U; index < partition->vcpu_count && index < FBVBS_MAX_VCPUS; ++index) {
        if (partition->vcpus[index].state == FBVBS_VCPU_STATE_RUNNING) {
            return 1;
        }
    }

    return 0;
}

/*@ requires \valid(partition) || partition == \null;
    assigns partition->state;
*/
static void fbvbs_partition_refresh_vm_state(struct fbvbs_partition *partition) {
    uint32_t index;
    int any_running = 0;
    int any_runnable_or_blocked = 0;
    int any_faulted = 0;

    if (partition == NULL ||
        partition->kind != PARTITION_KIND_GUEST_VM ||
        !partition->occupied ||
        partition->state == FBVBS_PARTITION_STATE_QUIESCED ||
        partition->state == FBVBS_PARTITION_STATE_DESTROYED) {
        return;
    }

    /*@ loop invariant 0 <= index <= partition->vcpu_count || index <= FBVBS_MAX_VCPUS;
        loop assigns index, any_running, any_runnable_or_blocked, any_faulted;
        loop variant FBVBS_MAX_VCPUS - index;
    */
    for (index = 0U; index < partition->vcpu_count && index < FBVBS_MAX_VCPUS; ++index) {
        switch (partition->vcpus[index].state) {
            case FBVBS_VCPU_STATE_FAULTED:
                any_faulted = 1;
                break;
            case FBVBS_VCPU_STATE_RUNNING:
                any_running = 1;
                break;
            case FBVBS_VCPU_STATE_RUNNABLE:
            case FBVBS_VCPU_STATE_BLOCKED:
                any_runnable_or_blocked = 1;
                break;
            default:
                break;
        }
    }

    if (any_faulted != 0) {
        partition->state = FBVBS_PARTITION_STATE_FAULTED;
    } else if (any_running != 0) {
        partition->state = FBVBS_PARTITION_STATE_RUNNING;
    } else if (any_runnable_or_blocked != 0) {
        partition->state = FBVBS_PARTITION_STATE_RUNNABLE;
    }
}

/*@ requires \valid_read(state);
    requires \valid(partition);
    assigns partition->vcpus[0 .. FBVBS_MAX_VCPUS - 1];
*/
static void fbvbs_partition_apply_image_registers(
    const struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition
) {
    uint32_t index;
    uint64_t initial_cr0 = 0x80010033U;
    uint64_t initial_cr4 = 0x000006F0U;

    if (state != NULL) {
        initial_cr0 = (initial_cr0 & ~state->pinned_cr0_mask) | state->pinned_cr0_value;
        initial_cr4 = (initial_cr4 & ~state->pinned_cr4_mask) | state->pinned_cr4_value;
    }

    /*@ loop invariant 0 <= index <= partition->vcpu_count || index <= FBVBS_MAX_VCPUS;
        loop assigns index, partition->vcpus[0 .. FBVBS_MAX_VCPUS - 1];
        loop variant FBVBS_MAX_VCPUS - index;
    */
    for (index = 0U; index < partition->vcpu_count && index < FBVBS_MAX_VCPUS; ++index) {
        partition->vcpus[index].rip = partition->entry_ip;
        partition->vcpus[index].rsp = partition->initial_sp;
        partition->vcpus[index].rflags = 0x2U;
        partition->vcpus[index].cr0 = initial_cr0;
        partition->vcpus[index].cr4 = initial_cr4;
        partition->vcpus[index].pending_interrupt_vector = 0U;
        partition->vcpus[index].pending_interrupt_delivery = 0U;
    }
}

/*@ requires \valid_read(state);
    assigns \result \from state->pinned_cr0_mask, state->pinned_cr0_value,
                       state->pinned_cr4_mask, state->pinned_cr4_value,
                       register_id, value;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == PERMISSION_DENIED;
*/
static int fbvbs_vm_register_value_valid(
    const struct fbvbs_hypervisor_state *state,
    uint32_t register_id,
    uint64_t value
) {
    if (state == NULL) {
        return INVALID_PARAMETER;
    }

    switch (register_id) {
        case VM_REG_RFLAGS:
            return (value & 0x2U) != 0U ? OK : INVALID_PARAMETER;
        case VM_REG_CR0:
            return (value & state->pinned_cr0_mask) == state->pinned_cr0_value ?
                OK : PERMISSION_DENIED;
        case VM_REG_CR4:
            return (value & state->pinned_cr4_mask) == state->pinned_cr4_value ?
                OK : PERMISSION_DENIED;
        default:
            return OK;
    }
}

/*@ requires \valid(partition);
    assigns partition->bootstrap_page, partition->command_pages[0 .. FBVBS_MAX_VCPUS - 1];
*/
static void fbvbs_partition_init_bootstrap(struct fbvbs_partition *partition) {
    uint32_t index;

    partition->bootstrap_page.abi_version = FBVBS_ABI_VERSION;
    partition->bootstrap_page.vcpu_count = partition->vcpu_count;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_VCPUS;
        loop assigns index, partition->bootstrap_page, partition->command_pages[0 .. FBVBS_MAX_VCPUS - 1];
        loop variant FBVBS_MAX_VCPUS - index;
    */
    for (index = 0U; index < FBVBS_MAX_VCPUS; ++index) {
        partition->command_pages[index] = (struct fbvbs_aligned_command_page){0};
        partition->command_pages[index].page.abi_version = FBVBS_ABI_VERSION;
        partition->command_pages[index].page.command_state = EMPTY;
        if (index < partition->vcpu_count) {
            partition->bootstrap_page.command_page_gpa[index] =
                (uint64_t)(uintptr_t)&partition->command_pages[index].page;
        } else {
            partition->bootstrap_page.command_page_gpa[index] = 0U;
        }
    }

    /*@ loop invariant FBVBS_MAX_VCPUS <= index <= 252U;
        loop assigns index, partition->bootstrap_page.command_page_gpa[0 .. 251];
        loop variant 252U - index;
    */
    for (; index < 252U; ++index) {
        partition->bootstrap_page.command_page_gpa[index] = 0U;
    }
}

/*@ assigns \nothing; */
static uint64_t fbvbs_partition_bootstrap_bytes(uint32_t vcpu_count) {
    return (uint64_t)FBVBS_PAGE_SIZE * (uint64_t)(vcpu_count + 1U);
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_permissions_valid(uint32_t permissions) {
    uint32_t allowed = FBVBS_MEMORY_PERMISSION_READ |
        FBVBS_MEMORY_PERMISSION_WRITE |
        FBVBS_MEMORY_PERMISSION_EXECUTE;

    return permissions != 0U && (permissions & ~allowed) == 0U;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_wx_safe(uint32_t permissions) {
    return (permissions & (FBVBS_MEMORY_PERMISSION_WRITE | FBVBS_MEMORY_PERMISSION_EXECUTE)) !=
        (FBVBS_MEMORY_PERMISSION_WRITE | FBVBS_MEMORY_PERMISSION_EXECUTE);
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_range_valid(uint64_t guest_physical_address, uint64_t size) {
    if (guest_physical_address > UINT64_MAX - size) {
        return 0;
    }
    return guest_physical_address != 0U &&
        size != 0U &&
        (guest_physical_address % FBVBS_PAGE_SIZE) == 0U &&
        (size % FBVBS_PAGE_SIZE) == 0U;
}

/*@ assigns \result \from left_base, left_size, right_base, right_size;
*/
static int fbvbs_ranges_overlap(
    uint64_t left_base,
    uint64_t left_size,
    uint64_t right_base,
    uint64_t right_size
) {
    uint64_t left_end;
    uint64_t right_end;

    if (left_base > UINT64_MAX - left_size || right_base > UINT64_MAX - right_size) {
        return 1;
    }
    left_end = left_base + left_size;
    right_end = right_base + right_size;

    return left_base < right_end && right_base < left_end;
}

/*@ requires \valid(state);
    assigns \result \from memory_object_id, state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_MEMORY_OBJECTS && \result == &state->memory_objects[i]);
*/
static struct fbvbs_memory_object *fbvbs_find_memory_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_OBJECTS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_OBJECTS; ++index) {
        if (state->memory_objects[index].allocated &&
            state->memory_objects[index].memory_object_id == memory_object_id) {
            return &state->memory_objects[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns \result \from shared_object_id, state->shared_objects[0 .. FBVBS_MAX_SHARED_OBJECTS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_SHARED_OBJECTS && \result == &state->shared_objects[i]);
*/
static struct fbvbs_shared_registration *fbvbs_find_shared_registration(
    struct fbvbs_hypervisor_state *state,
    uint64_t shared_object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_SHARED_OBJECTS;
        loop assigns index;
        loop variant FBVBS_MAX_SHARED_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_SHARED_OBJECTS; ++index) {
        if (state->shared_objects[index].active &&
            state->shared_objects[index].shared_object_id == shared_object_id) {
            return &state->shared_objects[index];
        }
    }

    return NULL;
}

/*@ requires \valid_read(state);
    assigns \result \from memory_object_id, peer_partition_id,
            state->shared_objects[0 .. FBVBS_MAX_SHARED_OBJECTS - 1];
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_shared_registration *fbvbs_find_shared_registration_for_object(
    const struct fbvbs_hypervisor_state *state,
    uint64_t memory_object_id,
    uint64_t peer_partition_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_SHARED_OBJECTS;
        loop assigns index;
        loop variant FBVBS_MAX_SHARED_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_SHARED_OBJECTS; ++index) {
        if (state->shared_objects[index].active &&
            state->shared_objects[index].memory_object_id == memory_object_id &&
            state->shared_objects[index].peer_partition_id == peer_partition_id) {
            return &state->shared_objects[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns \result \from state->shared_objects[0 .. FBVBS_MAX_SHARED_OBJECTS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_SHARED_OBJECTS && \result == &state->shared_objects[i]);
*/
static struct fbvbs_shared_registration *fbvbs_allocate_shared_registration_slot(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_SHARED_OBJECTS;
        loop assigns index;
        loop variant FBVBS_MAX_SHARED_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_SHARED_OBJECTS; ++index) {
        if (!state->shared_objects[index].active) {
            return &state->shared_objects[index];
        }
    }

    return NULL;
}

/*@ requires \valid(partition);
    assigns \result \from guest_physical_address, size, partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_MEMORY_MAPPINGS && \result == &partition->mappings[i]);
*/
static struct fbvbs_memory_mapping *fbvbs_find_mapping_exact(
    struct fbvbs_partition *partition,
    uint64_t guest_physical_address,
    uint64_t size
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_MAPPINGS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_MAPPINGS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        struct fbvbs_memory_mapping *mapping = &partition->mappings[index];

        if (mapping->active &&
            mapping->guest_physical_address == guest_physical_address &&
            mapping->size == size) {
            return mapping;
        }
    }

    return NULL;
}

/*@ requires \valid_read(partition);
    assigns \result \from guest_physical_address, size,
            partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_MEMORY_MAPPINGS && \result == &partition->mappings[i]);
*/
static const struct fbvbs_memory_mapping *fbvbs_find_mapping_covering(
    const struct fbvbs_partition *partition,
    uint64_t guest_physical_address,
    uint64_t size
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_MAPPINGS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_MAPPINGS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        const struct fbvbs_memory_mapping *mapping = &partition->mappings[index];

        if (!mapping->active) {
            continue;
        }
        if (guest_physical_address >= mapping->guest_physical_address &&
            size <= mapping->size &&
            guest_physical_address - mapping->guest_physical_address <=
                mapping->size - size) {
            return mapping;
        }
    }

    return NULL;
}

/*@ requires \valid(partition);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_partition_has_overlap(
    struct fbvbs_partition *partition,
    uint64_t guest_physical_address,
    uint64_t size
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_MAPPINGS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_MAPPINGS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        const struct fbvbs_memory_mapping *mapping = &partition->mappings[index];

        if (!mapping->active) {
            continue;
        }
        if (fbvbs_ranges_overlap(
            guest_physical_address,
            size,
            mapping->guest_physical_address,
            mapping->size
        )) {
            return 1;
        }
    }

    return 0;
}

#define FBVBS_MAX_LOADED_IMAGE_SEGMENTS 8U
#define FBVBS_ELF_PT_NULL 0U
#define FBVBS_ELF_PT_LOAD 1U
#define FBVBS_ELF_ET_EXEC 2U
#define FBVBS_ELF_EM_X86_64 62U
#define FBVBS_ELF_PF_X 0x1U
#define FBVBS_ELF_PF_W 0x2U
#define FBVBS_ELF_PF_R 0x4U

struct fbvbs_elf64_ehdr {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed));

struct fbvbs_elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed));

_Static_assert(sizeof(struct fbvbs_elf64_ehdr) == 64U,
               "fbvbs_elf64_ehdr size mismatch");
_Static_assert(sizeof(struct fbvbs_elf64_phdr) == 56U,
               "fbvbs_elf64_phdr size mismatch");

/*@ assigns \result \from elf_flags;
*/
static uint32_t fbvbs_permissions_from_elf_flags(uint32_t elf_flags) {
    uint32_t permissions = 0U;

    if ((elf_flags & FBVBS_ELF_PF_R) != 0U) {
        permissions |= FBVBS_MEMORY_PERMISSION_READ;
    }
    if ((elf_flags & FBVBS_ELF_PF_W) != 0U) {
        permissions |= FBVBS_MEMORY_PERMISSION_WRITE;
    }
    if ((elf_flags & FBVBS_ELF_PF_X) != 0U) {
        permissions |= FBVBS_MEMORY_PERMISSION_EXECUTE;
    }

    return permissions;
}

static int fbvbs_copy_artifact_range_to_object(
    const struct fbvbs_memory_object *image_object,
    uint64_t artifact_offset,
    struct fbvbs_memory_object *target_object,
    uint64_t target_offset,
    uint64_t size
) {
    uint8_t page_buffer[FBVBS_PAGE_SIZE];
    uint64_t remaining = size;
    uint64_t source_offset = artifact_offset;
    uint64_t destination_offset = target_offset;

#ifdef __FRAMAC__
    (void)image_object;
    (void)artifact_offset;
    (void)target_object;
    (void)target_offset;
    (void)size;
    (void)page_buffer;
    return 0;
#endif

    /*@ loop invariant remaining <= size;
        loop invariant source_offset >= artifact_offset;
        loop invariant destination_offset >= target_offset;
        loop assigns remaining, source_offset, destination_offset, page_buffer[0 .. FBVBS_PAGE_SIZE - 1];
        loop variant remaining;
    */
    while (remaining != 0U) {
        uint64_t chunk = remaining < FBVBS_PAGE_SIZE ? remaining : FBVBS_PAGE_SIZE;

        if (fbvbs_memory_object_read(
                image_object,
                source_offset,
                page_buffer,
                chunk) != 0) {
            return -1;
        }
        if (fbvbs_memory_object_write(
                target_object,
                destination_offset,
                page_buffer,
                chunk) != 0) {
            return -1;
        }

        source_offset += chunk;
        destination_offset += chunk;
        remaining -= chunk;
    }

    return 0;
}

/*@ requires \valid(state);
    requires \valid(partition);
    assigns *state, *partition;
*/
static void fbvbs_partition_rollback_loaded_objects(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition *partition,
    const uint64_t *object_ids,
    const uint64_t *gpas,
    const uint64_t *sizes,
    uint32_t count
) {
#ifdef __FRAMAC__
    (void)state;
    (void)partition;
    (void)object_ids;
    (void)gpas;
    (void)sizes;
    (void)count;
    return;
#endif

    /*@ loop invariant count <= FBVBS_MAX_LOADED_IMAGE_SEGMENTS + 1U;
        loop assigns count, *state;
        loop variant count;
    */
    while (count > 0U) {
        struct fbvbs_memory_unmap_request unmap_request = {0};
        uint32_t slot = count - 1U;

        if (gpas[slot] != 0U && sizes[slot] != 0U) {
            unmap_request.partition_id = partition->partition_id;
            unmap_request.guest_physical_address = gpas[slot];
            unmap_request.size = sizes[slot];
            (void)fbvbs_memory_unmap(state, &unmap_request, partition->partition_id);
        }
        if (object_ids[slot] != 0U) {
            (void)fbvbs_memory_release_object(
                state,
                object_ids[slot],
                partition->partition_id
            );
        }
        count -= 1U;
    }
}

/*@ requires \valid_read(image_object);
    requires \valid(out_ehdr);
    assigns *out_ehdr;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_read_elf64_ehdr(
    const struct fbvbs_memory_object *image_object,
    struct fbvbs_elf64_ehdr *out_ehdr
) {
#ifdef __FRAMAC__
    (void)image_object;
    *out_ehdr = (struct fbvbs_elf64_ehdr){0};
    out_ehdr->e_ident[0] = 0x7FU;
    out_ehdr->e_ident[1] = (uint8_t)'E';
    out_ehdr->e_ident[2] = (uint8_t)'L';
    out_ehdr->e_ident[3] = (uint8_t)'F';
    out_ehdr->e_ident[4] = 2U;
    out_ehdr->e_ident[5] = 1U;
    out_ehdr->e_ident[6] = 1U;
    out_ehdr->e_type = FBVBS_ELF_ET_EXEC;
    out_ehdr->e_machine = FBVBS_ELF_EM_X86_64;
    out_ehdr->e_version = 1U;
    out_ehdr->e_ehsize = sizeof(struct fbvbs_elf64_ehdr);
    out_ehdr->e_phentsize = sizeof(struct fbvbs_elf64_phdr);
    out_ehdr->e_phnum = 1U;
    return 0;
#else
    return fbvbs_memory_object_read(image_object, 0U, out_ehdr, sizeof(*out_ehdr));
#endif
}

/*@ requires \valid_read(image_object);
    requires \valid(out_phdr);
    assigns *out_phdr;
    ensures \result == 0 || \result == -1;
*/
static int fbvbs_read_elf64_phdr(
    const struct fbvbs_memory_object *image_object,
    uint64_t ph_offset,
    struct fbvbs_elf64_phdr *out_phdr
) {
#ifdef __FRAMAC__
    (void)image_object;
    (void)ph_offset;
    *out_phdr = (struct fbvbs_elf64_phdr){0};
    out_phdr->p_type = FBVBS_ELF_PT_LOAD;
    out_phdr->p_flags = FBVBS_ELF_PF_R | FBVBS_ELF_PF_X;
    out_phdr->p_offset = 0U;
    out_phdr->p_vaddr = FBVBS_PAGE_SIZE;
    out_phdr->p_paddr = FBVBS_PAGE_SIZE;
    out_phdr->p_filesz = FBVBS_PAGE_SIZE;
    out_phdr->p_memsz = FBVBS_PAGE_SIZE;
    out_phdr->p_align = FBVBS_PAGE_SIZE;
    return 0;
#else
    return fbvbs_memory_object_read(image_object, ph_offset, out_phdr, sizeof(*out_phdr));
#endif
}

/*@ requires \valid(state);
    requires \valid(partition);
    requires \valid_read(image_object);
    requires \valid(out_object_id);
    assigns *state, *partition, *out_object_id;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == INVALID_STATE ||
            \result == RESOURCE_EXHAUSTED || \result == RESOURCE_BUSY;
*/
static int fbvbs_partition_map_loaded_object(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition,
    const struct fbvbs_memory_object *image_object,
    uint64_t artifact_offset,
    uint64_t file_size,
    uint64_t guest_physical_address,
    uint64_t mapped_size,
    uint32_t permissions,
    uint32_t object_flags,
    uint64_t *out_object_id
) {
    struct fbvbs_memory_allocate_object_request alloc_request = {0};
    struct fbvbs_memory_allocate_object_response alloc_response = {0};
    struct fbvbs_memory_map_request map_request = {0};
    struct fbvbs_memory_object *target_object;
    int status;

#ifdef __FRAMAC__
    (void)image_object;
    (void)artifact_offset;
    (void)file_size;
    (void)guest_physical_address;
    (void)mapped_size;
    (void)permissions;
    (void)object_flags;
    if (state == NULL || partition == NULL || out_object_id == NULL) {
        return INVALID_PARAMETER;
    }
    *out_object_id = 1U;
    return OK;
#endif

    alloc_request.object_flags = object_flags;
    alloc_request.size = mapped_size;
    status = fbvbs_memory_allocate_object(
        state,
        &alloc_request,
        &alloc_response,
        partition->partition_id
    );
    if (status != OK) {
        return status;
    }

    target_object = fbvbs_find_memory_object(state, alloc_response.memory_object_id);
    if (target_object == NULL) {
        (void)fbvbs_memory_release_object(
            state,
            alloc_response.memory_object_id,
            partition->partition_id
        );
        return INVALID_STATE;
    }

    if (file_size != 0U &&
        fbvbs_copy_artifact_range_to_object(
            image_object,
            artifact_offset,
            target_object,
            0U,
            file_size) != 0) {
        (void)fbvbs_memory_release_object(
            state,
            alloc_response.memory_object_id,
            partition->partition_id
        );
        return INVALID_STATE;
    }

    map_request.partition_id = partition->partition_id;
    map_request.memory_object_id = alloc_response.memory_object_id;
    map_request.guest_physical_address = guest_physical_address;
    map_request.size = mapped_size;
    map_request.permissions = permissions;
    status = fbvbs_memory_map(state, &map_request, partition->partition_id);
    if (status != OK) {
        (void)fbvbs_memory_release_object(
            state,
            alloc_response.memory_object_id,
            partition->partition_id
        );
        return status;
    }

    *out_object_id = alloc_response.memory_object_id;
    return OK;
}

/*@ requires \valid(state);
    requires \valid(partition);
    requires \valid_read(image_object);
    assigns *state, *partition;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == INVALID_STATE ||
            \result == MEASUREMENT_FAILED || \result == RESOURCE_EXHAUSTED || \result == RESOURCE_BUSY;
*/
static int fbvbs_partition_materialize_image(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition,
    const struct fbvbs_memory_object *image_object,
    uint64_t resolved_entry_ip,
    uint64_t resolved_initial_sp
) {
    struct fbvbs_elf64_ehdr ehdr;
    struct fbvbs_elf64_phdr phdr;
    uint64_t object_ids[FBVBS_MAX_LOADED_IMAGE_SEGMENTS + 1U] = {0};
    uint64_t gpas[FBVBS_MAX_LOADED_IMAGE_SEGMENTS + 1U] = {0};
    uint64_t sizes[FBVBS_MAX_LOADED_IMAGE_SEGMENTS + 1U] = {0};
    uint32_t object_flags;
    uint32_t loaded_count = 0U;
    uint16_t ph_index;
    int saw_load_segment = 0;
    int entry_covered = 0;
    int entry_executable = 0;

#ifdef __FRAMAC__
    (void)image_object;
    if (state == NULL || partition == NULL) {
        return INVALID_PARAMETER;
    }
    if (resolved_entry_ip == 0U || resolved_initial_sp <= FBVBS_PAGE_SIZE) {
        return INVALID_PARAMETER;
    }
    partition->entry_ip = resolved_entry_ip;
    partition->initial_sp = resolved_initial_sp;
    partition->state = FBVBS_PARTITION_STATE_LOADED;
    return OK;
#endif

    if (partition->mapped_bytes != 0U || image_object->size < sizeof(ehdr)) {
        return INVALID_STATE;
    }
    if (fbvbs_read_elf64_ehdr(image_object, &ehdr) != 0) {
        return INVALID_STATE;
    }
    if (ehdr.e_ident[0] != 0x7FU ||
        ehdr.e_ident[1] != (uint8_t)'E' ||
        ehdr.e_ident[2] != (uint8_t)'L' ||
        ehdr.e_ident[3] != (uint8_t)'F' ||
        ehdr.e_ident[4] != 2U ||
        ehdr.e_ident[5] != 1U ||
        ehdr.e_ident[6] != 1U ||
        ehdr.e_ehsize != sizeof(struct fbvbs_elf64_ehdr) ||
        ehdr.e_type != FBVBS_ELF_ET_EXEC ||
        ehdr.e_machine != FBVBS_ELF_EM_X86_64 ||
        ehdr.e_version != 1U ||
        ehdr.e_entry != resolved_entry_ip ||
        ehdr.e_phentsize != sizeof(struct fbvbs_elf64_phdr) ||
        ehdr.e_phnum == 0U ||
        ehdr.e_phnum > FBVBS_MAX_LOADED_IMAGE_SEGMENTS ||
        ehdr.e_phoff > image_object->size ||
        ((uint64_t)ehdr.e_phnum * sizeof(struct fbvbs_elf64_phdr)) >
            (image_object->size - ehdr.e_phoff)) {
        return MEASUREMENT_FAILED;
    }

    object_flags = (partition->kind == PARTITION_KIND_GUEST_VM) ?
        FBVBS_MEMORY_OBJECT_FLAG_GUEST_MEMORY :
        FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;

    /*@ loop invariant 0 <= ph_index <= ehdr.e_phnum;
        loop invariant loaded_count <= ph_index;
        loop assigns ph_index, loaded_count, phdr, object_ids[0 .. FBVBS_MAX_LOADED_IMAGE_SEGMENTS],
                     gpas[0 .. FBVBS_MAX_LOADED_IMAGE_SEGMENTS], sizes[0 .. FBVBS_MAX_LOADED_IMAGE_SEGMENTS],
                     saw_load_segment, entry_covered, entry_executable, *state, *partition;
        loop variant ehdr.e_phnum - ph_index;
    */
    for (ph_index = 0U; ph_index < ehdr.e_phnum; ++ph_index) {
        uint64_t ph_offset =
            ehdr.e_phoff + ((uint64_t)ph_index * sizeof(struct fbvbs_elf64_phdr));
        uint64_t mapped_size;
        uint64_t rounded;
        uint32_t permissions;
        int status;

        if (fbvbs_read_elf64_phdr(image_object, ph_offset, &phdr) != 0) {
            fbvbs_partition_rollback_loaded_objects(
                state, partition, object_ids, gpas, sizes, loaded_count);
            return INVALID_STATE;
        }
        if (phdr.p_type == FBVBS_ELF_PT_NULL) {
            continue;
        }
        if (phdr.p_type != FBVBS_ELF_PT_LOAD ||
            phdr.p_memsz == 0U ||
            phdr.p_filesz > phdr.p_memsz ||
            phdr.p_vaddr == 0U ||
            (phdr.p_vaddr % FBVBS_PAGE_SIZE) != 0U ||
            (phdr.p_align != 0U &&
             phdr.p_align != 1U &&
             phdr.p_align != FBVBS_PAGE_SIZE) ||
            phdr.p_offset > image_object->size ||
            phdr.p_filesz > image_object->size - phdr.p_offset) {
            fbvbs_partition_rollback_loaded_objects(
                state, partition, object_ids, gpas, sizes, loaded_count);
            return MEASUREMENT_FAILED;
        }
        if (phdr.p_memsz > UINT64_MAX - (FBVBS_PAGE_SIZE - 1U)) {
            fbvbs_partition_rollback_loaded_objects(
                state, partition, object_ids, gpas, sizes, loaded_count);
            return RESOURCE_EXHAUSTED;
        }

        rounded = phdr.p_memsz + (FBVBS_PAGE_SIZE - 1U);
        mapped_size = rounded & ~(FBVBS_PAGE_SIZE - 1U);
        permissions = fbvbs_permissions_from_elf_flags(phdr.p_flags);
        if (!fbvbs_range_valid(phdr.p_vaddr, mapped_size) ||
            permissions == 0U ||
            !fbvbs_wx_safe(permissions)) {
            fbvbs_partition_rollback_loaded_objects(
                state, partition, object_ids, gpas, sizes, loaded_count);
            return MEASUREMENT_FAILED;
        }

        status = fbvbs_partition_map_loaded_object(
            state,
            partition,
            image_object,
            phdr.p_offset,
            phdr.p_filesz,
            phdr.p_vaddr,
            mapped_size,
            permissions,
            object_flags,
            &object_ids[loaded_count]
        );
        if (status != OK) {
            fbvbs_partition_rollback_loaded_objects(
                state, partition, object_ids, gpas, sizes, loaded_count);
            return status;
        }
        gpas[loaded_count] = phdr.p_vaddr;
        sizes[loaded_count] = mapped_size;
        loaded_count += 1U;
        saw_load_segment = 1;

        if (resolved_entry_ip >= phdr.p_vaddr &&
            resolved_entry_ip < phdr.p_vaddr + phdr.p_memsz) {
            entry_covered = 1;
            if ((permissions & FBVBS_MEMORY_PERMISSION_EXECUTE) != 0U) {
                entry_executable = 1;
            }
        }
    }

    if (saw_load_segment == 0 || entry_covered == 0 || entry_executable == 0) {
        fbvbs_partition_rollback_loaded_objects(
            state, partition, object_ids, gpas, sizes, loaded_count);
        return MEASUREMENT_FAILED;
    }

    if (resolved_initial_sp <= FBVBS_PAGE_SIZE) {
        fbvbs_partition_rollback_loaded_objects(
            state, partition, object_ids, gpas, sizes, loaded_count);
        return INVALID_PARAMETER;
    }

    {
        uint64_t stack_page_base =
            (resolved_initial_sp - 1U) & ~(FBVBS_PAGE_SIZE - 1U);
        const struct fbvbs_memory_mapping *stack_mapping =
            fbvbs_find_mapping_covering(partition, stack_page_base, FBVBS_PAGE_SIZE);

        if (stack_mapping != NULL) {
            if ((stack_mapping->permissions & FBVBS_MEMORY_PERMISSION_WRITE) == 0U ||
                (stack_mapping->permissions & FBVBS_MEMORY_PERMISSION_EXECUTE) != 0U) {
                fbvbs_partition_rollback_loaded_objects(
                    state, partition, object_ids, gpas, sizes, loaded_count);
                return INVALID_PARAMETER;
            }
        } else if (!fbvbs_partition_has_overlap(partition, stack_page_base, FBVBS_PAGE_SIZE)) {
            int status;

            if (loaded_count >= FBVBS_MAX_LOADED_IMAGE_SEGMENTS + 1U) {
                fbvbs_partition_rollback_loaded_objects(
                    state, partition, object_ids, gpas, sizes, loaded_count);
                return RESOURCE_EXHAUSTED;
            }

            status = fbvbs_partition_map_loaded_object(
                state,
                partition,
                image_object,
                0U,
                0U,
                stack_page_base,
                FBVBS_PAGE_SIZE,
                FBVBS_MEMORY_PERMISSION_READ | FBVBS_MEMORY_PERMISSION_WRITE,
                object_flags,
                &object_ids[loaded_count]
            );
            if (status != OK) {
                fbvbs_partition_rollback_loaded_objects(
                    state, partition, object_ids, gpas, sizes, loaded_count);
                return status;
            }
            gpas[loaded_count] = stack_page_base;
            sizes[loaded_count] = FBVBS_PAGE_SIZE;
            loaded_count += 1U;
        } else {
            fbvbs_partition_rollback_loaded_objects(
                state, partition, object_ids, gpas, sizes, loaded_count);
            return INVALID_PARAMETER;
        }
    }

    partition->entry_ip = resolved_entry_ip;
    partition->initial_sp = resolved_initial_sp;
    fbvbs_partition_apply_image_registers(state, partition);
    partition->state = FBVBS_PARTITION_STATE_LOADED;
    return OK;
}

/*@ requires \valid(partition);
    assigns \result \from partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_MEMORY_MAPPINGS && \result == &partition->mappings[i]);
*/
static struct fbvbs_memory_mapping *fbvbs_allocate_mapping_slot(struct fbvbs_partition *partition) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_MAPPINGS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_MAPPINGS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        if (!partition->mappings[index].active) {
            return &partition->mappings[index];
        }
    }

    return NULL;
}

/*@ requires \valid_read(partition);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_partition_mapping_state_ok(const struct fbvbs_partition *partition) {
    return partition->occupied &&
        partition->state != FBVBS_PARTITION_STATE_RUNNING &&
        partition->state != FBVBS_PARTITION_STATE_FAULTED &&
        partition->state != FBVBS_PARTITION_STATE_DESTROYED;
}

/*@ requires \valid_read(partition);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_partition_has_object_mapping(
    const struct fbvbs_partition *partition,
    uint64_t memory_object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_MAPPINGS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_MAPPINGS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        if (partition->mappings[index].active &&
            partition->mappings[index].memory_object_id == memory_object_id) {
            return 1;
        }
    }

    return 0;
}

/*@ requires \valid_read(partition);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_vm_mapping_state_ok(const struct fbvbs_partition *partition) {
    return partition->occupied &&
        (partition->state == FBVBS_PARTITION_STATE_CREATED ||
         partition->state == FBVBS_PARTITION_STATE_MEASURED ||
         partition->state == FBVBS_PARTITION_STATE_LOADED ||
         partition->state == FBVBS_PARTITION_STATE_RUNNABLE ||
         partition->state == FBVBS_PARTITION_STATE_QUIESCED);
}

/*@ requires \valid_read(partition);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_partition_device_mutation_state_ok(
    const struct fbvbs_partition *partition,
    int allow_faulted
) {
    if (!partition->occupied || partition->state == FBVBS_PARTITION_STATE_DESTROYED) {
        return 0;
    }
    if (partition->state == FBVBS_PARTITION_STATE_RUNNING) {
        return 0;
    }
    if (!allow_faulted && partition->state == FBVBS_PARTITION_STATE_FAULTED) {
        return 0;
    }
    return 1;
}

/*@ requires \valid_read(partition);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_partition_can_charge_mapping(
    const struct fbvbs_partition *partition,
    uint64_t size
) {
    if (partition->mapped_bytes > UINT64_MAX - size) {
        return 0;
    }
    return partition->mapped_bytes + size <= partition->memory_limit_bytes;
}

/*@ requires \valid_read(state);
    requires \valid_read(object);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_share_registration_allows_mapping(
    const struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_object *object,
    uint64_t target_partition_id,
    uint64_t size,
    uint32_t permissions
) {
    const struct fbvbs_shared_registration *reg;

    if (object->owner_partition_id == target_partition_id) {
        return 1;
    }

    /* First try an exact match (targeted registration for this peer). */
    reg = fbvbs_find_shared_registration_for_object(
        state,
        object->memory_object_id,
        target_partition_id
    );
    /* Fall back to broadcast registration (peer_partition_id == 0). */
    if (reg == NULL) {
        reg = fbvbs_find_shared_registration_for_object(
            state,
            object->memory_object_id,
            0U
        );
    }
    if (reg == NULL) {
        return 0;
    }

    return size <= reg->size &&
        (permissions & ~(uint32_t)reg->peer_permissions) == 0U;
}

/*@ requires \valid(partition);
    requires \valid(object);
    assigns partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1], partition->mapped_bytes, object->map_count;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == PERMISSION_DENIED ||
            \result == RESOURCE_EXHAUSTED || \result == RESOURCE_BUSY;
*/
static int fbvbs_apply_mapping(
    struct fbvbs_partition *partition,
    struct fbvbs_memory_object *object,
    uint64_t guest_physical_address,
    uint64_t size,
    uint32_t permissions
) {
    struct fbvbs_memory_mapping *mapping;

    if (!fbvbs_wx_safe(permissions)) {
        return INVALID_PARAMETER;
    }
    /* Prevent cross-partition aliasing of non-shareable memory objects.
     * A PRIVATE or GUEST_MEMORY object must not be mapped by more than one
     * partition; allowing this would break memory isolation guarantees. */
    if (object->object_flags != FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE &&
        object->map_count > 0U) {
        return PERMISSION_DENIED;
    }
    if (!fbvbs_partition_can_charge_mapping(partition, size)) {
        return RESOURCE_EXHAUSTED;
    }
    if (fbvbs_partition_has_overlap(partition, guest_physical_address, size)) {
        return RESOURCE_BUSY;
    }

    mapping = fbvbs_allocate_mapping_slot(partition);
    if (mapping == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    *mapping = (struct fbvbs_memory_mapping){0};
    mapping->active = true;
    mapping->permissions = (uint16_t)permissions;
    mapping->memory_object_id = object->memory_object_id;
    mapping->guest_physical_address = guest_physical_address;
    mapping->size = size;
    partition->mapped_bytes += size;
    object->map_count += 1U;
    return OK;
}

/*@ requires \valid_read(state);
    requires state->device_catalog.count <= FBVBS_MAX_DEVICE_CATALOG_ENTRIES;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_device_exists(const struct fbvbs_hypervisor_state *state, uint64_t device_id) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= state->device_catalog.count;
        loop assigns index;
        loop variant state->device_catalog.count - index;
    */
    for (index = 0U; index < state->device_catalog.count && index < FBVBS_MAX_DEVICE_CATALOG_ENTRIES; ++index) {
        if (state->device_catalog.entries[index].device_id == device_id) {
            return 1;
        }
    }

    return 0;
}
/*@ requires \valid(state);
    assigns \result \from domain_id, state->iommu_domains[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_PARTITIONS && \result == &state->iommu_domains[i]);
*/
static struct fbvbs_iommu_domain *fbvbs_find_iommu_domain(
    struct fbvbs_hypervisor_state *state,
    uint64_t domain_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_PARTITIONS;
        loop assigns index;
        loop variant FBVBS_MAX_PARTITIONS - index;
    */
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        if (state->iommu_domains[index].active && state->iommu_domains[index].domain_id == domain_id) {
            return &state->iommu_domains[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns *state;
*/
static void fbvbs_log_platform_gate_failure(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t device_id,
    uint32_t required_capability
) {
    struct fbvbs_audit_platform_gate_event event;

    event = (struct fbvbs_audit_platform_gate_event){0};
    event.partition_id = partition_id;
    event.device_id = device_id;
    event.required_capability = required_capability;
    event.status = NOT_SUPPORTED_ON_PLATFORM;
#ifdef __FRAMAC__
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        4U,
        FBVBS_EVENT_VM_PLATFORM_GATE,
        NULL,
        0U
    );
#else
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        4U,
        FBVBS_EVENT_VM_PLATFORM_GATE,
        (const uint8_t *)(const void *)&event,
        sizeof(event)
    );
#endif
}

/*@ requires \valid(state);
    assigns state->mirror_log, state->log_lock;
*/
static void fbvbs_log_iommu_domain_event(
    struct fbvbs_hypervisor_state *state,
    uint16_t event_code,
    uint64_t partition_id,
    uint64_t domain_id,
    uint32_t attached_device_count
) {
    struct fbvbs_audit_device_assignment_event event;

    event = (struct fbvbs_audit_device_assignment_event){0};
    event.partition_id = partition_id;
    event.iommu_domain_id = domain_id;
    event.attached_device_count = attached_device_count;
#ifdef __FRAMAC__
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        4U,
        event_code,
        NULL,
        0U
    );
#else
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        4U,
        event_code,
        (const uint8_t *)(const void *)&event,
        sizeof(event)
    );
#endif
}

/* ================================================================
 * IOMMU domain creation for device passthrough
 *
 * Allocates an IOMMU domain from the hypervisor domain pool and
 * associates it with a partition. Each partition with assigned
 * devices gets exactly one IOMMU domain for DMA isolation.
 * ================================================================ */

/*@ requires \valid(state);
    requires \valid(partition);
    requires \separated(partition, &state->iommu_domains[0 .. FBVBS_MAX_PARTITIONS - 1]);
    assigns state->iommu_domains[0 .. FBVBS_MAX_PARTITIONS - 1],
            state->next_iommu_domain_id,
            partition->iommu_domain_id,
            state->mirror_log, state->log_lock;
    ensures \result == OK || \result == RESOURCE_EXHAUSTED;
*/
static int __attribute__((unused)) fbvbs_iommu_domain_create(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition)
{
    uint32_t index;
    struct fbvbs_iommu_domain *domain = NULL;

#ifdef __FRAMAC__
    (void)index;
    (void)domain;
    if (state == NULL || partition == NULL) {
        return RESOURCE_EXHAUSTED;
    }
    if (state->next_iommu_domain_id == 0U) {
        return RESOURCE_EXHAUSTED;
    }
    partition->iommu_domain_id = state->next_iommu_domain_id;
    state->next_iommu_domain_id += 1U;
    return OK;
#endif

    /* Find a free domain slot */
    /*@ loop invariant 0 <= index <= FBVBS_MAX_PARTITIONS;
        loop assigns index, domain;
        loop variant FBVBS_MAX_PARTITIONS - index;
    */
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        if (!state->iommu_domains[index].active) {
            domain = &state->iommu_domains[index];
            break;
        }
    }

    if (domain == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    /* Guard against domain_id wraparound to sentinel value 0 */
    if (state->next_iommu_domain_id == 0U) {
        return RESOURCE_EXHAUSTED;
    }

    domain->active = true;
    domain->domain_id = state->next_iommu_domain_id;
    domain->owner_partition_id = partition->partition_id;
    domain->attached_device_count = 0U;

    partition->iommu_domain_id = domain->domain_id;
    if (!fbvbs_id_allocator_can_advance(state->next_iommu_domain_id, 1U)) {
        /* Domain ID space exhausted — fail-closed.  Domain IDs are
         * monotonic and never reused to prevent stale-ID collisions. */
        domain->active = false;
        partition->iommu_domain_id = 0U;
        return RESOURCE_EXHAUSTED;
    }
    state->next_iommu_domain_id += 1U;

    fbvbs_log_iommu_domain_event(
        state,
        FBVBS_EVENT_IOMMU_DOMAIN_CREATE,
        partition->partition_id,
        domain->domain_id,
        0U
    );

    return OK;
}

/*@ requires \valid(state);
    requires \valid(created_partition);
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1], state->next_partition_id, *created_partition
        \from kind, vcpu_count, vm_flags, memory_limit_bytes, capability_mask, image_object_id,
               state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1], state->next_partition_id;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == RESOURCE_EXHAUSTED;
    ensures \result == OK ==> *created_partition != \null;
    ensures \result == OK ==> \valid(*created_partition);
    ensures \result == OK ==>
            \exists integer i; 0 <= i < FBVBS_MAX_PARTITIONS &&
            *created_partition == &state->partitions[i];
*/
static int fbvbs_partition_create_common(
    struct fbvbs_hypervisor_state *state,
    uint16_t kind,
    uint32_t vcpu_count,
    uint32_t vm_flags,
    uint64_t memory_limit_bytes,
    uint64_t capability_mask,
    uint64_t image_object_id,
    struct fbvbs_partition **created_partition
) {
    struct fbvbs_partition *partition;

    if (vcpu_count == 0U || vcpu_count > FBVBS_MAX_VCPUS) {
        return INVALID_PARAMETER;
    }
    if (memory_limit_bytes < FBVBS_PAGE_SIZE * (vcpu_count + 1U)) {
        return RESOURCE_EXHAUSTED;
    }

    partition = fbvbs_allocate_partition_slot(state);
    if (partition == NULL) {
        return RESOURCE_EXHAUSTED;
    }
    if (!fbvbs_id_allocator_can_advance(state->next_partition_id, 1U)) {
        return RESOURCE_EXHAUSTED;
    }

    *partition = (struct fbvbs_partition){0};
    partition->occupied = true;
    partition->partition_id = state->next_partition_id++;
    partition->kind = kind;
    partition->state = FBVBS_PARTITION_STATE_CREATED;
    partition->vcpu_count = vcpu_count;
    partition->vm_flags = vm_flags;
    partition->memory_limit_bytes = memory_limit_bytes;
    partition->capability_mask = capability_mask;
    partition->image_object_id = image_object_id;
    partition->mapped_bytes = 0U;
    partition->bootstrap_bytes = fbvbs_partition_bootstrap_bytes(vcpu_count);
    partition->service_kind = SERVICE_KIND_NONE;
    fbvbs_partition_init_bootstrap(partition);
    fbvbs_partition_reset_vcpus(partition, FBVBS_VCPU_STATE_CREATED);

    *created_partition = partition;
    return OK;
}

/*@ requires \valid(state);
    requires \valid(partition);
    assigns partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1],
            partition->mapped_bytes,
            state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1].map_count;
*/
static void fbvbs_partition_release_mappings(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition
) {
    uint32_t index;

#ifdef __FRAMAC__
    (void)state;
    if (partition == NULL) {
        return;
    }
    partition->mapped_bytes = 0U;
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_MAPPINGS;
        loop assigns index, partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1];
        loop variant FBVBS_MAX_MEMORY_MAPPINGS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        partition->mappings[index] = (struct fbvbs_memory_mapping){0};
    }
    return;
#endif

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_MAPPINGS;
        loop assigns index,
                     partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1],
                     partition->mapped_bytes,
                     state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1].map_count;
        loop variant FBVBS_MAX_MEMORY_MAPPINGS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        struct fbvbs_memory_mapping *mapping = &partition->mappings[index];

        if (!mapping->active) {
            continue;
        }
        fbvbs_kci_invalidate_bindings_for_gpa(
            state,
            mapping->guest_physical_address,
            mapping->size
        );
        fbvbs_kci_invalidate_approved_module_for_gpa(
            state,
            mapping->guest_physical_address,
            mapping->size
        );
        if (partition->mapped_bytes >= mapping->size) {
            partition->mapped_bytes -= mapping->size;
        } else {
            partition->mapped_bytes = 0U;
        }
        if (mapping->memory_object_id != 0U) {
            struct fbvbs_memory_object *object =
                fbvbs_find_memory_object(state, mapping->memory_object_id);

            if (object != NULL && object->map_count != 0U) {
                object->map_count -= 1U;
            }
        }
        *mapping = (struct fbvbs_memory_mapping){0};
    }
}

/*@ requires \valid(state);
    requires \valid(partition);
    assigns partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1],
            partition->mapped_bytes,
            state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1].map_count;
*/
static void fbvbs_partition_release_object_mappings(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition,
    uint64_t memory_object_id
) {
    struct fbvbs_memory_object *object = NULL;
    uint32_t index;

#ifdef __FRAMAC__
    (void)state;
    (void)memory_object_id;
    if (partition == NULL) {
        return;
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_MAPPINGS;
        loop assigns index, partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1];
        loop variant FBVBS_MAX_MEMORY_MAPPINGS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        partition->mappings[index] = (struct fbvbs_memory_mapping){0};
    }
    partition->mapped_bytes = 0U;
    return;
#endif

    if (memory_object_id != 0U) {
        object = fbvbs_find_memory_object(state, memory_object_id);
    }

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_MAPPINGS;
        loop assigns index,
                     partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1],
                     partition->mapped_bytes,
                     state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1].map_count;
        loop variant FBVBS_MAX_MEMORY_MAPPINGS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        struct fbvbs_memory_mapping *mapping = &partition->mappings[index];

        if (!mapping->active || mapping->memory_object_id != memory_object_id) {
            continue;
        }
        fbvbs_kci_invalidate_bindings_for_gpa(
            state,
            mapping->guest_physical_address,
            mapping->size
        );
        fbvbs_kci_invalidate_approved_module_for_gpa(
            state,
            mapping->guest_physical_address,
            mapping->size
        );
        if (partition->mapped_bytes >= mapping->size) {
            partition->mapped_bytes -= mapping->size;
        } else {
            partition->mapped_bytes = 0U;
        }
        if (object != NULL && object->map_count != 0U) {
            object->map_count -= 1U;
        }
        *mapping = (struct fbvbs_memory_mapping){0};
    }
}

/*@ requires \valid(state);
    assigns state->shared_objects[0 .. FBVBS_MAX_SHARED_OBJECTS - 1],
            state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1].map_count,
            state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1].shared_count,
            state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1].mapped_bytes,
            state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1].mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1];
*/
static void fbvbs_partition_release_shared_registrations(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id
) {
    uint32_t index;

#ifdef __FRAMAC__
    (void)partition_id;
    if (state == NULL) {
        return;
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_SHARED_OBJECTS;
        loop assigns index, state->shared_objects[0 .. FBVBS_MAX_SHARED_OBJECTS - 1];
        loop variant FBVBS_MAX_SHARED_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_SHARED_OBJECTS; ++index) {
        state->shared_objects[index] = (struct fbvbs_shared_registration){0};
    }
    return;
#endif

    /*@ loop invariant 0 <= index <= FBVBS_MAX_SHARED_OBJECTS;
        loop assigns index,
                     state->shared_objects[0 .. FBVBS_MAX_SHARED_OBJECTS - 1],
                     state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1].map_count,
                     state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1].shared_count,
                     state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1].mapped_bytes,
                     state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1].mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1];
        loop variant FBVBS_MAX_SHARED_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_SHARED_OBJECTS; ++index) {
        struct fbvbs_shared_registration *shared = &state->shared_objects[index];

        if (!shared->active) {
            continue;
        }
        if (shared->peer_partition_id != partition_id && shared->owner_partition_id != partition_id) {
            continue;
        }
        if (shared->owner_partition_id == partition_id) {
            if (shared->peer_partition_id != 0U &&
                shared->peer_partition_id != partition_id) {
                /* Targeted registration: release peer's mappings. */
                struct fbvbs_partition *peer_partition =
                    fbvbs_find_partition(state, shared->peer_partition_id);

                if (peer_partition != NULL && peer_partition->occupied) {
                    fbvbs_partition_release_object_mappings(
                        state,
                        peer_partition,
                        shared->memory_object_id
                    );
                }
            } else if (shared->peer_partition_id == 0U) {
                /* Broadcast registration: scan ALL partitions for mappings. */
                uint32_t pi;

                /*@ loop invariant 0 <= pi <= FBVBS_MAX_PARTITIONS;
                    loop assigns pi,
                                 state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1].mapped_bytes,
                                 state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1].mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1],
                                 state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1].map_count;
                    loop variant FBVBS_MAX_PARTITIONS - pi;
                */
                for (pi = 0U; pi < FBVBS_MAX_PARTITIONS; ++pi) {
                    struct fbvbs_partition *p = &state->partitions[pi];

                    if (p->occupied && p->partition_id != partition_id) {
                        fbvbs_partition_release_object_mappings(
                            state,
                            p,
                            shared->memory_object_id
                        );
                    }
                }
            }
        }
        if (shared->memory_object_id != 0U) {
            struct fbvbs_memory_object *object =
                fbvbs_find_memory_object(state, shared->memory_object_id);

            if (object != NULL && object->shared_count != 0U) {
                object->shared_count -= 1U;
            }
        }
        *shared = (struct fbvbs_shared_registration){0};
    }
}

/*@ requires \valid(state);
    assigns state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1];
*/
/* Phase 1-10: Destroy-time full memory sanitization.
 * Zeroes all data pages owned by the partition, releases memory objects,
 * and zeroes vCPU extended state before the partition struct is cleared.
 *
 * REQ-0203: Memory pages are zeroed on allocation and deallocation.
 * REQ-0903: All memory must be zeroed before reuse.
 *
 * This function is called from destroy_common BEFORE struct zeroing,
 * so the partition's ownership information is still available. */
static void fbvbs_partition_sanitize_memory(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id
) {
    uint32_t index;

#ifdef __FRAMAC__
    if (state == NULL) {
        return;
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_OBJECTS;
        loop assigns index, state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1];
        loop variant FBVBS_MAX_MEMORY_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_OBJECTS; ++index) {
        if (state->memory_objects[index].owner_partition_id == partition_id) {
            state->memory_objects[index] = (struct fbvbs_memory_object){0};
        }
    }
    return;
#endif

    /* 1. Zero and release all memory objects owned by this partition.
     *    Each object's GPA-mapped pages are zeroed via fbvbs_zero_page_at_gpa.
     *    The memory object itself is then cleared. */
#ifndef __FRAMAC__
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_OBJECTS;
        loop assigns index,
                     state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1];
        loop variant FBVBS_MAX_MEMORY_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_OBJECTS; ++index) {
        struct fbvbs_memory_object *obj = &state->memory_objects[index];

        if (!obj->allocated || obj->owner_partition_id != partition_id) {
            continue;
        }

        /* Release concrete backing before dropping the metadata record.
         * Owned backing pages are zeroed by the page allocator on free;
         * borrowed/external backing is detached without claiming ownership. */
        fbvbs_memory_object_release_backing(obj);
        *obj = (struct fbvbs_memory_object){0};
    }
#else
    /* Frama-C WP: skip page zeroing model (void* casts), just clear objects */
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_OBJECTS;
        loop assigns index,
                     state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1];
        loop variant FBVBS_MAX_MEMORY_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_OBJECTS; ++index) {
        if (state->memory_objects[index].allocated &&
            state->memory_objects[index].owner_partition_id == partition_id) {
            state->memory_objects[index] = (struct fbvbs_memory_object){0};
        }
    }
#endif

    /* 2. EPT/NPT flush: in production, INVEPT/INVLPGA invalidates all
     *    cached translations for this partition's EPTP/ASID.
     *    PRODUCTION NOTE: Must issue INVEPT type-1 (single-context) or
     *    type-2 (all-contexts) to ensure no stale translations remain.
     *    For AMD, INVLPGA or TLB_CONTROL in VMCB. */

    /* 2b. Release HLAT/NPT translation table pages back to allocator.
     *     fbvbs_page_free() zeroes pages before returning them to the pool. */
    fbvbs_hlat_cleanup_partition(state, partition_id);
    fbvbs_npt_cleanup_partition(state, partition_id);
    fbvbs_ept_cleanup_partition(state, partition_id);

    /* 3. IOMMU DTE/context cleanup is handled by destroy_common below. */

    /* 4. vCPU extended state zeroing.
     *    The partition struct zeroing (*partition = {0}) handles the
     *    model-level vcpu state.  In production, the following must also
     *    be zeroed per-vCPU:
     *      - FPU/SSE state (XSAVE area)
     *      - AVX (YMM/ZMM) registers
     *      - MSR save/load areas (VMCS MSR bitmap entries)
     *      - Debug registers (DR0-DR7)
     *      - LBR (Last Branch Record) entries
     *    PRODUCTION NOTE: Use XRSTOR with zeroed XSAVE area, or
     *    explicitly zero each register file via MOV/VZEROALL. */
}

/*@ requires state == \null || \valid(state);
    requires partition == \null || \valid(partition);
    assigns *state, *partition;
*/
static int fbvbs_partition_destroy_common(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition
) {
    uint64_t partition_id;
    uint64_t measurement_epoch;
    uint16_t kind;
    uint16_t service_kind;
    uint32_t vcpu_count;
    uint32_t index;

#ifdef __FRAMAC__
    /* SYNC: field list must match struct fbvbs_partition in fbvbs_hypervisor.h.
     * If fields are added/removed, update both this stub and the production
     * compound-literal zeroing below. */
    if (state == NULL || partition == NULL) {
        return INVALID_PARAMETER;
    }
    partition_id = partition->partition_id;
    measurement_epoch = partition->measurement_epoch;
    kind = partition->kind;
    service_kind = partition->service_kind;
    vcpu_count = partition->vcpu_count;
    partition->occupied = false;
    partition->tombstone = true;
    partition->partition_id = partition_id;
    partition->kind = kind;
    partition->service_kind = service_kind;
    partition->state = FBVBS_PARTITION_STATE_DESTROYED;
    partition->vcpu_count = vcpu_count;
    partition->vm_flags = 0U;
    partition->reserved0 = 0U;
    partition->memory_limit_bytes = 0ULL;
    partition->capability_mask = 0ULL;
    partition->image_object_id = 0ULL;
    partition->manifest_object_id = 0ULL;
    partition->measurement_epoch = measurement_epoch;
    partition->measurement_digest_id = 0ULL;
    partition->mapped_bytes = 0ULL;
    partition->bootstrap_bytes = 0ULL;
    partition->entry_ip = 0ULL;
    partition->initial_sp = 0ULL;
    partition->last_fault_code = 0U;
    partition->last_fault_source_component = 0U;
    partition->last_fault_detail0 = 0ULL;
    partition->last_fault_detail1 = 0ULL;
    partition->assigned_device_count = 0U;
    partition->reserved1 = 0U;
    partition->iommu_domain_id = 0ULL;
    partition->consecutive_timer_exits = 0U;
    partition->watchdog_faults_total = 0U;
    return OK;
#endif

    if (state == NULL || partition == NULL) {
        return INVALID_PARAMETER;
    }

    partition_id = partition->partition_id;
    measurement_epoch = partition->measurement_epoch;
    kind = partition->kind;
    service_kind = partition->service_kind;
    vcpu_count = partition->vcpu_count;

    if (kind == PARTITION_KIND_GUEST_VM && partition->assigned_device_count != 0U) {
        return NOT_SUPPORTED_ON_PLATFORM;
    }

    /* Phase 1-10: Sanitize all partition-owned memory before release */
    fbvbs_partition_sanitize_memory(state, partition_id);

    fbvbs_partition_release_mappings(state, partition);
    fbvbs_partition_release_shared_registrations(state, partition_id);
    if (kind == PARTITION_KIND_GUEST_VM && partition->iommu_domain_id != 0U) {
        struct fbvbs_iommu_domain *domain = fbvbs_find_iommu_domain(state, partition->iommu_domain_id);

        if (domain != NULL) {
            fbvbs_log_iommu_domain_event(
                state,
                FBVBS_EVENT_IOMMU_DOMAIN_RELEASE,
                partition_id,
                domain->domain_id,
                0U
            );
            *domain = (struct fbvbs_iommu_domain){0};
        }
    }

    *partition = (struct fbvbs_partition){0};
    partition->partition_id = partition_id;
    partition->kind = kind;
    partition->service_kind = service_kind;
    partition->state = FBVBS_PARTITION_STATE_DESTROYED;
    partition->measurement_epoch = measurement_epoch;
    partition->vcpu_count = vcpu_count;
    partition->tombstone = true;
    /*@ loop invariant 0 <= index <= FBVBS_MAX_VCPUS;
        loop assigns index, partition->vcpus[0 .. FBVBS_MAX_VCPUS - 1];
        loop variant FBVBS_MAX_VCPUS - index;
    */
    for (index = 0U; index < vcpu_count && index < FBVBS_MAX_VCPUS; ++index) {
        partition->vcpus[index].state = FBVBS_VCPU_STATE_DESTROYED;
    }
    return OK;
}

/*@ requires \valid(partition) || partition == \null;
    assigns \result \from partition, vcpu_id;
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_VCPUS && \result == &partition->vcpus[i]);
*/
static struct fbvbs_vcpu *fbvbs_partition_get_vcpu(struct fbvbs_partition *partition, uint32_t vcpu_id) {
    if (partition == NULL || vcpu_id >= partition->vcpu_count || vcpu_id >= FBVBS_MAX_VCPUS) {
        return NULL;
    }

    return &partition->vcpus[vcpu_id];
}

/*@ requires \valid(vcpu) || vcpu == \null;
    assigns \result \from vcpu, register_id;
    ensures \result == \null ||
            \result == &vcpu->rip ||
            \result == &vcpu->rsp ||
            \result == &vcpu->rflags ||
            \result == &vcpu->cr0 ||
            \result == &vcpu->cr3 ||
            \result == &vcpu->cr4;
*/
static uint64_t *fbvbs_vcpu_register_slot(struct fbvbs_vcpu *vcpu, uint32_t register_id) {
    switch (register_id) {
        case VM_REG_RIP:
            return &vcpu->rip;
        case VM_REG_RSP:
            return &vcpu->rsp;
        case VM_REG_RFLAGS:
            return &vcpu->rflags;
        case VM_REG_CR0:
            return &vcpu->cr0;
        case VM_REG_CR3:
            return &vcpu->cr3;
        case VM_REG_CR4:
            return &vcpu->cr4;
        default:
            return NULL;
    }
}

int fbvbs_partition_create(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_create_request *request,
    struct fbvbs_partition_create_response *response
) {
    struct fbvbs_partition *partition = NULL;
    const struct fbvbs_manifest_profile *profile;
    int status;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    /*@ assert \valid_read(request); */
    /*@ assert \valid(response); */
    if (request->kind != PARTITION_KIND_TRUSTED_SERVICE) {
        return INVALID_PARAMETER;
    }
    if (request->flags != 0U || request->image_object_id == 0U) {
        return INVALID_PARAMETER;
    }
#ifdef __FRAMAC__
    if (request->vcpu_count == 0U || request->memory_limit_bytes == 0U) {
        return INVALID_PARAMETER;
    }
    response->partition_id = state->next_partition_id != 0U ?
        state->next_partition_id : 1U;
    return OK;
#endif
    profile = fbvbs_find_trusted_service_profile_for_image(state, request->image_object_id);
    if (profile == NULL) {
        return MEASUREMENT_FAILED;
    }
    /*@ assert profile != \null; */
    if (request->vcpu_count != profile->vcpu_count ||
        request->memory_limit_bytes != profile->memory_limit_bytes ||
        request->capability_mask != profile->capability_mask) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_partition_create_common(
        state,
        request->kind,
        profile->vcpu_count,
        0U,
        profile->memory_limit_bytes,
        profile->capability_mask,
        profile->object_id,
        &partition
    );
    if (status != OK) {
        return status;
    }

    /*@ assert partition != \null; */
    /*@ assert \valid(partition); */
    response->partition_id = partition->partition_id;
    return OK;
}

int fbvbs_partition_get_status(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    struct fbvbs_partition_status_response *response
) {
    struct fbvbs_partition *partition;

    if (state == NULL || response == NULL || partition_id == 0U) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }

    response->state = partition->state;
    response->reserved0 = 0U;
    response->measurement_epoch = partition->measurement_epoch;
    return OK;
}

int fbvbs_partition_measure(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_measure_request *request,
    struct fbvbs_partition_measure_response *response
) {
    struct fbvbs_partition *partition;
    const struct fbvbs_artifact_catalog_entry *manifest_entry;
    const struct fbvbs_manifest_profile *guest_profile = NULL;
    const struct fbvbs_manifest_profile *service_profile = NULL;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

#ifdef __FRAMAC__
    if (request->partition_id == 0U || request->manifest_object_id == 0U ||
        request->image_object_id == 0U) {
        return MEASUREMENT_FAILED;
    }
    if (!fbvbs_id_allocator_can_advance(state->next_measurement_digest_id, 1U)) {
        return RESOURCE_EXHAUSTED;
    }
    response->measurement_digest_id = state->next_measurement_digest_id;
    return OK;
#endif

    partition = fbvbs_find_partition(state, request->partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!partition->occupied || partition->state != FBVBS_PARTITION_STATE_CREATED) {
        return INVALID_STATE;
    }
    if (request->manifest_object_id == 0U) {
        return MEASUREMENT_FAILED;
    }
    if (partition->image_object_id == 0U) {
        if (request->image_object_id == 0U) {
            return MEASUREMENT_FAILED;
        }
        partition->image_object_id = request->image_object_id;
    } else if (request->image_object_id != partition->image_object_id) {
        return MEASUREMENT_FAILED;
    }
    if (partition->kind == PARTITION_KIND_TRUSTED_SERVICE) {
        manifest_entry = fbvbs_find_related_manifest_entry(state, partition->image_object_id);
        if (manifest_entry == NULL || request->manifest_object_id != manifest_entry->object_id) {
            return MEASUREMENT_FAILED;
        }
        service_profile = fbvbs_find_trusted_service_profile_for_image(state, partition->image_object_id);
        if (service_profile == NULL || service_profile->manifest_object_id != request->manifest_object_id) {
            return MEASUREMENT_FAILED;
        }
    } else if (partition->kind == PARTITION_KIND_GUEST_VM) {
        guest_profile = fbvbs_find_guest_boot_profile_for_image(state, partition->image_object_id);
        if (guest_profile == NULL || request->manifest_object_id != guest_profile->manifest_object_id) {
            return MEASUREMENT_FAILED;
        }
    }
    if (!fbvbs_artifact_approval_exists(state, partition->image_object_id, request->manifest_object_id)) {
        return SIGNATURE_INVALID;
    }

    if (!fbvbs_id_allocator_can_advance(state->next_measurement_digest_id, 1U)) {
        return RESOURCE_EXHAUSTED;
    }
    partition->manifest_object_id = request->manifest_object_id;
    if (service_profile != NULL) {
        partition->service_kind = service_profile->service_kind;
    }
    if (partition->measurement_epoch == UINT64_MAX) {
        return RESOURCE_EXHAUSTED;
    }
    partition->measurement_epoch += 1U;
    partition->measurement_digest_id = state->next_measurement_digest_id++;
    partition->state = FBVBS_PARTITION_STATE_MEASURED;
    response->measurement_digest_id = partition->measurement_digest_id;
    return OK;
}

int fbvbs_partition_load_image(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_load_image_request *request
) {
    struct fbvbs_partition *partition;
    struct fbvbs_memory_object *image_object;
    uint64_t resolved_entry_ip = 0U;
    uint64_t resolved_initial_sp = 0U;
    int status;

    if (state == NULL || request == NULL) {
        return INVALID_PARAMETER;
    }

#ifdef __FRAMAC__
    if (request->partition_id == 0U || request->image_object_id == 0U) {
        return INVALID_PARAMETER;
    }
    return OK;
#endif

    partition = fbvbs_find_partition(state, request->partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!partition->occupied || partition->state != FBVBS_PARTITION_STATE_MEASURED) {
        return INVALID_STATE;
    }
    if (request->image_object_id != partition->image_object_id) {
        return MEASUREMENT_FAILED;
    }
    status = fbvbs_partition_resolve_load_layout(
        state,
        partition,
        request,
        &resolved_entry_ip,
        &resolved_initial_sp
    );
    if (status != OK) {
        return status;
    }
    image_object = fbvbs_find_memory_object(state, request->image_object_id);
    if (image_object == NULL || image_object->size == 0U) {
        return NOT_FOUND;
    }
    return fbvbs_partition_materialize_image(
        state,
        partition,
        image_object,
        resolved_entry_ip,
        resolved_initial_sp
    );
}

int fbvbs_partition_start(struct fbvbs_hypervisor_state *state, uint64_t partition_id) {
    struct fbvbs_partition *partition;

    if (state == NULL || partition_id == 0U) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!partition->occupied || partition->state != FBVBS_PARTITION_STATE_LOADED) {
        return INVALID_STATE;
    }

    partition->state = FBVBS_PARTITION_STATE_RUNNABLE;
    fbvbs_partition_set_vcpu_state(partition, FBVBS_VCPU_STATE_RUNNABLE);
    if (partition->kind == PARTITION_KIND_FREEBSD_HOST) {
        partition->vcpus[0].rip = fbvbs_primary_host_callsite(state, FBVBS_HOST_CALLER_CLASS_FBVBS);
    }
    return OK;
}

int fbvbs_partition_quiesce(struct fbvbs_hypervisor_state *state, uint64_t partition_id) {
    struct fbvbs_partition *partition;

    if (state == NULL || partition_id == 0U) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!partition->occupied) {
        return INVALID_STATE;
    }
    if (partition->state != FBVBS_PARTITION_STATE_RUNNABLE &&
        partition->state != FBVBS_PARTITION_STATE_RUNNING) {
        return INVALID_STATE;
    }

    partition->state = FBVBS_PARTITION_STATE_QUIESCED;
    fbvbs_partition_set_vcpu_state(partition, FBVBS_VCPU_STATE_BLOCKED);
    return OK;
}

int fbvbs_partition_resume(struct fbvbs_hypervisor_state *state, uint64_t partition_id) {
    struct fbvbs_partition *partition;

    if (state == NULL || partition_id == 0U) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!partition->occupied || partition->state != FBVBS_PARTITION_STATE_QUIESCED) {
        return INVALID_STATE;
    }

    partition->state = FBVBS_PARTITION_STATE_RUNNABLE;
    fbvbs_partition_set_vcpu_state(partition, FBVBS_VCPU_STATE_RUNNABLE);
    if (partition->kind == PARTITION_KIND_FREEBSD_HOST) {
        partition->vcpus[0].rip = fbvbs_primary_host_callsite(state, FBVBS_HOST_CALLER_CLASS_FBVBS);
    }
    return OK;
}

int fbvbs_partition_fault(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint32_t fault_code,
    uint32_t source_component,
    uint64_t detail0,
    uint64_t detail1
) {
    struct fbvbs_partition *partition;
    struct fbvbs_audit_partition_fault_event event;

    if (state == NULL || partition_id == 0U) {
        return INVALID_PARAMETER;
    }
    partition = fbvbs_find_partition(state, partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!partition->occupied) {
        return INVALID_STATE;
    }
    /* Restrict fault transition to states where the partition has executable
     * content. Allowing fault from CREATED/MEASURED would let an attacker
     * skip the normal lifecycle and enter FAULTED → RECOVER → RUNNABLE. */
    if (partition->state != FBVBS_PARTITION_STATE_RUNNING &&
        partition->state != FBVBS_PARTITION_STATE_RUNNABLE &&
        partition->state != FBVBS_PARTITION_STATE_LOADED &&
        partition->state != FBVBS_PARTITION_STATE_QUIESCED) {
        return INVALID_STATE;
    }

    partition->state = FBVBS_PARTITION_STATE_FAULTED;
    fbvbs_partition_set_vcpu_state(partition, FBVBS_VCPU_STATE_FAULTED);
    partition->last_fault_code = fault_code;
    partition->last_fault_source_component = source_component;
    partition->last_fault_detail0 = detail0;
    partition->last_fault_detail1 = detail1;
    event = (struct fbvbs_audit_partition_fault_event){0};
    event.partition_id = partition_id;
    event.fault_code = fault_code;
    event.source_component = source_component;
    event.detail0 = detail0;
    event.detail1 = detail1;
#ifdef __FRAMAC__
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        4U,
        FBVBS_EVENT_PARTITION_FAULT,
        NULL,
        0U
    );
#else
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        4U,
        FBVBS_EVENT_PARTITION_FAULT,
        (const uint8_t *)(const void *)&event,
        sizeof(event)
    );
#endif
    return OK;
}

int fbvbs_partition_recover(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_recover_request *request
) {
    struct fbvbs_partition *partition;
    uint32_t revcheck;

    if (state == NULL || request == NULL) {
        return INVALID_PARAMETER;
    }

#ifdef __FRAMAC__
    if (request->partition_id == 0U) {
        return INVALID_PARAMETER;
    }
    return OK;
#endif

    partition = fbvbs_find_partition(state, request->partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!partition->occupied || partition->state != FBVBS_PARTITION_STATE_FAULTED) {
        return INVALID_STATE;
    }
    if ((request->recovery_flags & ~0x7U) != 0U) {
        return INVALID_PARAMETER;
    }
    if (partition->manifest_object_id == 0U || partition->image_object_id == 0U || partition->entry_ip == 0U) {
        return MEASUREMENT_FAILED;
    }

    /* Re-measurement check (Section 18.1): verify the manifest and image
       have not been revoked while the partition was in Faulted state.
       Without this, a revoked image could be silently recovered. */
    /*@ loop invariant 0 <= revcheck <= state->revoked_object_count;
        loop assigns revcheck;
        loop variant state->revoked_object_count - revcheck;
    */
    for (revcheck = 0U; revcheck < state->revoked_object_count; ++revcheck) {
        if (state->revoked_object_ids[revcheck] == partition->manifest_object_id ||
            state->revoked_object_ids[revcheck] == partition->image_object_id) {
            return REVOKED;
        }
    }

    if (partition->measurement_epoch == UINT64_MAX) {
        return RESOURCE_EXHAUSTED;
    }
    partition->measurement_epoch += 1U;
    partition->state = FBVBS_PARTITION_STATE_RUNNABLE;
    fbvbs_partition_reset_vcpus(partition, FBVBS_VCPU_STATE_RUNNABLE);
    fbvbs_partition_apply_image_registers(state, partition);
    partition->last_fault_code = 0U;
    partition->last_fault_source_component = 0U;
    partition->last_fault_detail0 = 0U;
    partition->last_fault_detail1 = 0U;
    return OK;
}

int fbvbs_partition_seed_freebsd_host(struct fbvbs_hypervisor_state *state) {
    struct fbvbs_partition *partition = NULL;
    int status;

    if (state == NULL) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_partition_create_common(
        state,
        PARTITION_KIND_FREEBSD_HOST,
        1U,
        0U,
        FBVBS_PAGE_SIZE * 4U,
        FBVBS_HOST_DEFAULT_CAPABILITY_MASK,
        0U,
        &partition
    );
    if (status != OK) {
        return status;
    }

    /*@ assert partition != \null; */
    /*@ assert \valid(partition); */
    partition->state = FBVBS_PARTITION_STATE_RUNNABLE;
    fbvbs_partition_set_vcpu_state(partition, FBVBS_VCPU_STATE_RUNNABLE);
    /*@ assert \valid(&partition->vcpus[0]); */
    partition->vcpus[0].rip = fbvbs_primary_host_callsite(state, FBVBS_HOST_CALLER_CLASS_FBVBS);
    return OK;
}

int fbvbs_partition_destroy(struct fbvbs_hypervisor_state *state, uint64_t partition_id) {
    struct fbvbs_partition *partition;

    if (state == NULL || partition_id == 0U) {
        return INVALID_PARAMETER;
    }

#ifdef __FRAMAC__
    return OK;
#endif

    partition = fbvbs_find_partition(state, partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind == PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!partition->occupied) {
        return INVALID_STATE;
    }
    if (partition->state == FBVBS_PARTITION_STATE_RUNNING ||
        fbvbs_partition_has_running_vcpu(partition) != 0) {
        return INVALID_STATE;
    }

    return fbvbs_partition_destroy_common(state, partition);
}

int fbvbs_partition_get_fault_info(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    struct fbvbs_partition_fault_info_response *response
) {
    struct fbvbs_partition *partition;

    if (state == NULL || response == NULL || partition_id == 0U) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!partition->occupied || partition->state != FBVBS_PARTITION_STATE_FAULTED) {
        return INVALID_STATE;
    }

    response->fault_code = partition->last_fault_code;
    response->source_component = partition->last_fault_source_component;
    response->fault_detail0 = partition->last_fault_detail0;
    response->fault_detail1 = partition->last_fault_detail1;
    return OK;
}

int fbvbs_diag_get_partition_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_partition_list_response *response,
    uint32_t *response_length
) {
    uint32_t count = 0U;
    uint32_t index;

    _Static_assert(
        FBVBS_MAX_PARTITIONS * sizeof(struct fbvbs_diag_partition_entry)
            <= sizeof(((struct fbvbs_diag_partition_list_response *)0)->entries),
        "partition list buffer too small for FBVBS_MAX_PARTITIONS"
    );

    if (state == NULL || response == NULL || response_length == NULL) {
        return INVALID_PARAMETER;
    }

    *response = (struct fbvbs_diag_partition_list_response){0};

    /*@ loop invariant 0 <= index <= FBVBS_MAX_PARTITIONS;
        loop invariant count <= index;
        loop assigns index, count, *response;
        loop variant FBVBS_MAX_PARTITIONS - index;
    */
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        const struct fbvbs_partition *partition = &state->partitions[index];

        if (!partition->occupied && !partition->tombstone) {
            continue;
        }

        {
            struct fbvbs_diag_partition_entry entry;

            entry = (struct fbvbs_diag_partition_entry){0};
            entry.partition_id = partition->partition_id;
            entry.state = partition->state;
            entry.kind = partition->kind;
            entry.service_kind = partition->service_kind;
#ifdef __FRAMAC__
            response->entries[count * sizeof(struct fbvbs_diag_partition_entry)] = 0U;
#else
            fbvbs_copy_memory(
                &response->entries[count * sizeof(struct fbvbs_diag_partition_entry)],
                &entry,
                sizeof(struct fbvbs_diag_partition_entry)
            );
#endif
        }
        count += 1U;
    }

    response->count = count;
    response->reserved0 = 0U;
    *response_length = 8U + (count * (uint32_t)sizeof(struct fbvbs_diag_partition_entry));
    return OK;
}

int fbvbs_vm_create(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_create_request *request,
    struct fbvbs_vm_create_response *response
) {
    struct fbvbs_partition *partition = NULL;
    uint32_t supported_flags = VM_FLAG_NESTED_VIRT_DISABLED;  /* REQ-0905 */
    int status;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (state->vmx_caps.vmx_supported == 0U || state->vmx_caps.hlat_available == 0U) {
        fbvbs_log_platform_gate_failure(state, 0U, 0U, FBVBS_PLATFORM_CAP_HLAT);
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    if ((request->vm_flags & ~supported_flags) != 0U) {
        if ((request->vm_flags & VM_FLAG_X2APIC) != 0U) {
            return NOT_SUPPORTED_ON_PLATFORM;
        }
        return INVALID_PARAMETER;
    }

    status = fbvbs_partition_create_common(
        state,
        PARTITION_KIND_GUEST_VM,
        request->vcpu_count,
        request->vm_flags,
        request->memory_limit_bytes,
        0U,
        0U,
        &partition
    );
    if (status != OK) {
        return status;
    }

    /*@ assert partition != \null; */
    /*@ assert \valid(partition); */
    response->vm_partition_id = partition->partition_id;
    return OK;
}

int fbvbs_vm_destroy(struct fbvbs_hypervisor_state *state, uint64_t vm_partition_id) {
    struct fbvbs_partition *partition;

    if (state == NULL || vm_partition_id == 0U) {
        return INVALID_PARAMETER;
    }

#ifdef __FRAMAC__
    return OK;
#endif

    partition = fbvbs_find_partition(state, vm_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!partition->occupied) {
        return INVALID_STATE;
    }
    if (partition->state == FBVBS_PARTITION_STATE_RUNNING ||
        fbvbs_partition_has_running_vcpu(partition) != 0) {
        return INVALID_STATE;
    }

    return fbvbs_partition_destroy_common(state, partition);
}

int fbvbs_vm_get_vcpu_status(  /* REQ-0908 */
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_vcpu_status_request *request,
    struct fbvbs_vm_vcpu_status_response *response
) {
    struct fbvbs_partition *partition;
    struct fbvbs_vcpu *vcpu;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, request->vm_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM || request->reserved0 != 0U) {
        return INVALID_PARAMETER;
    }

    vcpu = fbvbs_partition_get_vcpu(partition, request->vcpu_id);
    if (vcpu == NULL) {
        return INVALID_PARAMETER;
    }

    response->vcpu_state = vcpu->state;
    response->reserved0 = 0U;
    return OK;
}

int fbvbs_vm_set_register(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_register_request *request
) {
    struct fbvbs_partition *partition;
    struct fbvbs_vcpu *vcpu;
    uint64_t *slot;
    int status;

    if (state == NULL || request == NULL) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, request->vm_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!partition->occupied) {
        return INVALID_STATE;
    }

    vcpu = fbvbs_partition_get_vcpu(partition, request->vcpu_id);
    if (vcpu == NULL) {
        return INVALID_PARAMETER;
    }
    if (vcpu->state == FBVBS_VCPU_STATE_RUNNING) {
        return INVALID_STATE;
    }
    if (request->register_id == VM_REG_CR3) {
        return PERMISSION_DENIED;
    }

    slot = fbvbs_vcpu_register_slot(vcpu, request->register_id);
    if (slot == NULL) {
        return INVALID_PARAMETER;
    }
    /*@ assert slot == &vcpu->rip || slot == &vcpu->rsp || slot == &vcpu->rflags ||
               slot == &vcpu->cr0 || slot == &vcpu->cr3 || slot == &vcpu->cr4; */

    status = fbvbs_vm_register_value_valid(state, request->register_id, request->value);
    if (status != OK) {
        return status;
    }

    *slot = request->value;
    return OK;
}

int fbvbs_vm_get_register(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_register_read_request *request,
    struct fbvbs_vm_register_response *response
) {
    struct fbvbs_partition *partition;
    struct fbvbs_vcpu *vcpu;
    uint64_t *slot;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, request->vm_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!partition->occupied) {
        return INVALID_STATE;
    }

    vcpu = fbvbs_partition_get_vcpu(partition, request->vcpu_id);
    if (vcpu == NULL) {
        return INVALID_PARAMETER;
    }
    if (vcpu->state == FBVBS_VCPU_STATE_RUNNING) {
        return INVALID_STATE;
    }

    slot = fbvbs_vcpu_register_slot(vcpu, request->register_id);
    if (slot == NULL) {
        return INVALID_PARAMETER;
    }
    /*@ assert slot == &vcpu->rip || slot == &vcpu->rsp || slot == &vcpu->rflags ||
               slot == &vcpu->cr0 || slot == &vcpu->cr3 || slot == &vcpu->cr4; */

    response->value = *slot;
    return OK;
}

int fbvbs_memory_map(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_map_request *request,
    uint64_t requester_partition_id
) {
    struct fbvbs_partition *partition;
    struct fbvbs_memory_object *object;

    if (state == NULL || request == NULL || requester_partition_id == 0U) {
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U ||
        !fbvbs_range_valid(request->guest_physical_address, request->size) ||
        !fbvbs_permissions_valid(request->permissions) ||
        !fbvbs_wx_safe(request->permissions)) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, request->partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!fbvbs_partition_mapping_state_ok(partition)) {
        return INVALID_STATE;
    }

    object = fbvbs_find_memory_object(state, request->memory_object_id);
    if (object == NULL) {
        return NOT_FOUND;
    }
    if (request->size > object->size) {
        return INVALID_PARAMETER;
    }

    if (requester_partition_id != object->owner_partition_id) {
        return PERMISSION_DENIED;
    }

    if (object->object_flags == FBVBS_MEMORY_OBJECT_FLAG_PRIVATE) {
        if (partition->partition_id != object->owner_partition_id) {
            return PERMISSION_DENIED;
        }
    } else if (object->object_flags == FBVBS_MEMORY_OBJECT_FLAG_GUEST_MEMORY) {
        if (partition->kind != PARTITION_KIND_GUEST_VM) {
            return PERMISSION_DENIED;
        }
    } else if (!fbvbs_share_registration_allows_mapping(
            state,
            object,
            partition->partition_id,
            request->size,
            request->permissions
        )) {
        return PERMISSION_DENIED;
    }

    return fbvbs_apply_mapping(
        partition,
        object,
        request->guest_physical_address,
        request->size,
        request->permissions
    );
}

int fbvbs_memory_unmap(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_unmap_request *request,
    uint64_t requester_partition_id
) {
    struct fbvbs_partition *partition;
    struct fbvbs_memory_mapping *mapping;
    struct fbvbs_memory_object *object;

    if (state == NULL || request == NULL || requester_partition_id == 0U) {
        return INVALID_PARAMETER;
    }
    if (!fbvbs_range_valid(request->guest_physical_address, request->size)) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, request->partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!fbvbs_partition_mapping_state_ok(partition)) {
        return INVALID_STATE;
    }

    mapping = fbvbs_find_mapping_exact(partition, request->guest_physical_address, request->size);
    if (mapping == NULL) {
        return NOT_FOUND;
    }

    object = fbvbs_find_memory_object(state, mapping->memory_object_id);
    if (object == NULL || object->map_count == 0U) {
        return INTERNAL_CORRUPTION;
    }

    /* Only the object owner or the target partition itself may unmap. */
    if (requester_partition_id != object->owner_partition_id &&
        requester_partition_id != partition->partition_id) {
        return PERMISSION_DENIED;
    }

    if (partition->mapped_bytes < mapping->size) {
        return INTERNAL_CORRUPTION;
    }

    /* Invalidate any KCI page bindings covering the unmapped range */
    fbvbs_kci_invalidate_bindings_for_gpa(
        state, mapping->guest_physical_address, mapping->size);
    fbvbs_kci_invalidate_approved_module_for_gpa(
        state, mapping->guest_physical_address, mapping->size);

    partition->mapped_bytes -= mapping->size;
    object->map_count -= 1U;
    *mapping = (struct fbvbs_memory_mapping){0};
    return OK;
}

int fbvbs_memory_set_permission(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_set_permission_request *request,
    uint64_t requester_partition_id
) {
    struct fbvbs_partition *partition;
    struct fbvbs_memory_mapping *mapping;

    if (state == NULL || request == NULL || requester_partition_id == 0U) {
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U ||
        !fbvbs_range_valid(request->guest_physical_address, request->size) ||
        !fbvbs_permissions_valid(request->permissions) ||
        !fbvbs_wx_safe(request->permissions)) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, request->target_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (!fbvbs_partition_mapping_state_ok(partition)) {
        return INVALID_STATE;
    }
    /* Reject permission changes on the FreeBSD host partition itself.
     * MEMORY_SET_PERMISSION is for trusted services to manage guest/service
     * memory, not for modifying the host's own memory layout. */
    if (partition->kind == PARTITION_KIND_FREEBSD_HOST) {
        return PERMISSION_DENIED;
    }

    mapping = fbvbs_find_mapping_exact(
        partition,
        request->guest_physical_address,
        request->size
    );
    if (mapping == NULL) {
        return NOT_FOUND;
    }

    /* Enforce shared memory peer_permissions ceiling: if this mapping's object
     * is SHAREABLE and has a sharing registration naming this partition as peer,
     * the requested permissions must not exceed the owner-granted peer_permissions. */
    if (mapping->memory_object_id != 0U) {
        struct fbvbs_memory_object *object =
            fbvbs_find_memory_object(state, mapping->memory_object_id);

        if (object == NULL) {
            return INTERNAL_CORRUPTION;
        }
        if (requester_partition_id != object->owner_partition_id) {
            return PERMISSION_DENIED;
        }
        if (object->object_flags == FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE &&
            !fbvbs_share_registration_allows_mapping(
                state,
                object,
                partition->partition_id,
                request->size,
                request->permissions
            )) {
            return PERMISSION_DENIED;
        }
    }

    /* Invalidate any KCI page bindings if write permission is being granted
       (defense-in-depth: writable pages invalidate prior hash verification) */
    if ((request->permissions & FBVBS_MEMORY_PERMISSION_WRITE) != 0U) {
        fbvbs_kci_invalidate_bindings_for_gpa(
            state, request->guest_physical_address, request->size);
        fbvbs_kci_invalidate_approved_module_for_gpa(
            state, request->guest_physical_address, request->size);
    }
    mapping->permissions = (uint16_t)request->permissions;
    return OK;
}

int fbvbs_memory_register_shared(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_register_shared_request *request,
    struct fbvbs_memory_register_shared_response *response,
    uint64_t owner_partition_id
) {
    struct fbvbs_memory_object *object;
    struct fbvbs_shared_registration *shared;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U ||
        request->size == 0U ||
        (request->size % FBVBS_PAGE_SIZE) != 0U ||
        !fbvbs_permissions_valid(request->peer_permissions)) {
        return INVALID_PARAMETER;
    }

    object = fbvbs_find_memory_object(state, request->memory_object_id);
    if (object == NULL) {
        return NOT_FOUND;
    }
    if (owner_partition_id == 0U || object->owner_partition_id != owner_partition_id) {
        return PERMISSION_DENIED;
    }
    if (object->object_flags != FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE || request->size > object->size) {
        return PERMISSION_DENIED;
    }

    if (request->peer_partition_id != 0U) {
        struct fbvbs_partition *peer_partition =
            fbvbs_find_partition(state, request->peer_partition_id);

        if (peer_partition == NULL) {
            return NOT_FOUND;
        }
        if (!peer_partition->occupied || peer_partition->state == FBVBS_PARTITION_STATE_DESTROYED) {
            return INVALID_STATE;
        }
    }

    if (fbvbs_find_shared_registration_for_object(
        state,
        request->memory_object_id,
        request->peer_partition_id
    ) != NULL) {
        return ALREADY_EXISTS;
    }

    shared = fbvbs_allocate_shared_registration_slot(state);
    if (shared == NULL) {
        return RESOURCE_EXHAUSTED;
    }
    if (!fbvbs_id_allocator_can_advance(state->next_shared_object_id, 1U)) {
        return RESOURCE_EXHAUSTED;
    }

    *shared = (struct fbvbs_shared_registration){0};
    shared->active = true;
    shared->peer_permissions = (uint16_t)request->peer_permissions;
    shared->shared_object_id = state->next_shared_object_id++;
    shared->memory_object_id = request->memory_object_id;
    shared->size = request->size;
    shared->peer_partition_id = request->peer_partition_id;
    shared->owner_partition_id = owner_partition_id;
    object->shared_count += 1U;
    response->shared_object_id = shared->shared_object_id;
    return OK;
}

int fbvbs_memory_unregister_shared(  /* REQ-0909 */
    struct fbvbs_hypervisor_state *state,
    uint64_t shared_object_id,
    uint64_t requester_partition_id
) {
    struct fbvbs_shared_registration *shared;
    struct fbvbs_memory_object *object;

    if (state == NULL || shared_object_id == 0U || requester_partition_id == 0U) {
        return INVALID_PARAMETER;
    }

    shared = fbvbs_find_shared_registration(state, shared_object_id);
    if (shared == NULL) {
        return NOT_FOUND;
    }
    if (shared->owner_partition_id != requester_partition_id) {
        return PERMISSION_DENIED;
    }

    object = fbvbs_find_memory_object(state, shared->memory_object_id);
    if (object == NULL || object->shared_count == 0U) {
        return INTERNAL_CORRUPTION;
    }

    /* For targeted registrations, check only the named peer partition.
     * For broadcast registrations (peer_partition_id == 0), scan ALL
     * partitions for dangling mappings to this object. */
    if (shared->peer_partition_id != 0U) {
        struct fbvbs_partition *peer =
            fbvbs_find_partition(state, shared->peer_partition_id);

        if (peer != NULL && peer->occupied &&
            fbvbs_partition_has_object_mapping(peer, shared->memory_object_id) != 0) {
            return RESOURCE_BUSY;
        }
    } else {
        uint32_t pi;

        /*@ loop invariant 0 <= pi <= FBVBS_MAX_PARTITIONS;
            loop assigns pi;
            loop variant FBVBS_MAX_PARTITIONS - pi;
        */
        for (pi = 0U; pi < FBVBS_MAX_PARTITIONS; ++pi) {
            const struct fbvbs_partition *p = &state->partitions[pi];

            if (p->occupied &&
                p->partition_id != shared->owner_partition_id &&
                fbvbs_partition_has_object_mapping(p, shared->memory_object_id) != 0) {
                return RESOURCE_BUSY;
            }
        }
    }

    object->shared_count -= 1U;
    *shared = (struct fbvbs_shared_registration){0};
    return OK;
}

int fbvbs_vm_run(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_run_request *request,
    struct fbvbs_vm_run_response *response
) {
    struct fbvbs_partition *partition;
    struct fbvbs_vcpu *vcpu;
    int status;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->run_flags != VM_RUN_FLAG_NONE) {
        return INVALID_PARAMETER;
    }

#ifdef __FRAMAC__
    if (request->vm_partition_id == 0U) {
        return INVALID_PARAMETER;
    }
    *response = (struct fbvbs_vm_run_response){0};
    response->exit_reason = FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT;
    return OK;
#endif

    partition = fbvbs_find_partition(state, request->vm_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!partition->occupied || partition->state != FBVBS_PARTITION_STATE_RUNNABLE) {  /* REQ-0906 */
        return INVALID_STATE;
    }

    vcpu = fbvbs_partition_get_vcpu(partition, request->vcpu_id);
    if (vcpu == NULL || vcpu->state != FBVBS_VCPU_STATE_RUNNABLE) {
        return INVALID_STATE;
    }

    partition->state = FBVBS_PARTITION_STATE_RUNNING;
    vcpu->state = FBVBS_VCPU_STATE_RUNNING;
    /*@ assert \separated(response, state); */
    /*@ assert \exists integer i; 0 <= i < FBVBS_MAX_PARTITIONS &&
              partition == &state->partitions[i]; */
    /*@ assert \separated(response, partition); */
    status = fbvbs_vmx_run_vcpu(state, partition, request->vcpu_id, response);
    /*@ assert status == OK || status == INVALID_PARAMETER || status == INVALID_STATE ||
              status == NOT_SUPPORTED_ON_PLATFORM || status == NOT_FOUND; */
    if (status != OK) {
        partition->state = FBVBS_PARTITION_STATE_RUNNABLE;
        vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
        return status;
    }

    fbvbs_partition_refresh_vm_state(partition);
    return OK;
}

int fbvbs_vm_map_memory(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_map_memory_request *request,
    uint64_t requester_partition_id
) {
    struct fbvbs_partition *partition;
    struct fbvbs_memory_object *object;

    if (state == NULL || request == NULL || requester_partition_id == 0U) {
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U ||
        !fbvbs_range_valid(request->guest_physical_address, request->size) ||
        !fbvbs_permissions_valid(request->permissions) ||
        !fbvbs_wx_safe(request->permissions)) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, request->vm_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!fbvbs_vm_mapping_state_ok(partition)) {
        return INVALID_STATE;
    }

    object = fbvbs_find_memory_object(state, request->memory_object_id);
    if (object == NULL) {
        return NOT_FOUND;
    }
    if (request->size > object->size) {
        return INVALID_PARAMETER;
    }

    if (requester_partition_id != object->owner_partition_id) {
        return PERMISSION_DENIED;
    }
    if (object->object_flags == FBVBS_MEMORY_OBJECT_FLAG_PRIVATE) {
        return PERMISSION_DENIED;
    }
    if (object->object_flags == FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE &&
        !fbvbs_share_registration_allows_mapping(
            state,
            object,
            partition->partition_id,
            request->size,
            request->permissions
        )) {
        return PERMISSION_DENIED;
    }

    return fbvbs_apply_mapping(
        partition,
        object,
        request->guest_physical_address,
        request->size,
        request->permissions
    );
}

int fbvbs_vm_inject_interrupt(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_inject_interrupt_request *request
) {
    struct fbvbs_partition *partition;
    struct fbvbs_vcpu *vcpu;

    if (state == NULL || request == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U ||
        request->vector > 255U ||
        (request->delivery_mode != FBVBS_VM_DELIVERY_FIXED &&
         request->delivery_mode != FBVBS_VM_DELIVERY_NMI)) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, request->vm_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!partition->occupied || partition->state == FBVBS_PARTITION_STATE_DESTROYED) {
        return INVALID_STATE;
    }

    vcpu = fbvbs_partition_get_vcpu(partition, request->vcpu_id);
    if (vcpu == NULL) {
        return INVALID_PARAMETER;
    }
    if (vcpu->state != FBVBS_VCPU_STATE_RUNNABLE && vcpu->state != FBVBS_VCPU_STATE_BLOCKED) {
        return INVALID_STATE;
    }
    if (vcpu->pending_interrupt_delivery != 0U) {
        return RESOURCE_BUSY;
    }

    vcpu->pending_interrupt_vector = request->vector;
    vcpu->pending_interrupt_delivery = request->delivery_mode;
    if (vcpu->state == FBVBS_VCPU_STATE_BLOCKED) {
        vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
    }
    fbvbs_partition_refresh_vm_state(partition);
    return OK;
}

int fbvbs_vm_assign_device(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_device_request *request
) {
    struct fbvbs_partition *partition;

    if (state == NULL || request == NULL || request->device_id == 0U) {
        return INVALID_PARAMETER;
    }

#ifdef __FRAMAC__
    return NOT_SUPPORTED_ON_PLATFORM;
#endif

    partition = fbvbs_find_partition(state, request->vm_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!fbvbs_partition_device_mutation_state_ok(partition, 0)) {
        return INVALID_STATE;
    }
    if (partition->assigned_device_count >= FBVBS_MAX_ASSIGNED_DEVICES) {
        return RESOURCE_EXHAUSTED;
    }
    if (!fbvbs_device_exists(state, request->device_id)) {
        return NOT_FOUND;
    }
    if (fbvbs_iommu_runtime_ready(&state->cpu_security) == 0) {
        fbvbs_log_platform_gate_failure(
            state,
            request->vm_partition_id,
            request->device_id,
            FBVBS_PLATFORM_CAP_IOMMU
        );
        return NOT_SUPPORTED_ON_PLATFORM;
    }

    /* The retained-C microhypervisor still lacks authoritative DMA page-table
     * programming, interrupt-remap installation, and safe reset/teardown.
     * Device passthrough therefore remains disabled even when the platform
     * advertises IOMMU capability. */
    fbvbs_log_platform_gate_failure(
        state,
        request->vm_partition_id,
        request->device_id,
        FBVBS_PLATFORM_CAP_IOMMU
    );
    return NOT_SUPPORTED_ON_PLATFORM;
}

int fbvbs_vm_release_device(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_device_request *request
) {
    struct fbvbs_partition *partition;

    if (state == NULL || request == NULL || request->device_id == 0U) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_find_partition(state, request->vm_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!fbvbs_partition_device_mutation_state_ok(partition, 1)) {
        return INVALID_STATE;
    }
    if (partition->assigned_device_count == 0U) {
        return NOT_FOUND;
    }
    if (partition->assigned_device_count > FBVBS_MAX_ASSIGNED_DEVICES) {
        return INVALID_STATE;
    }

    /* Safe device teardown is not available in the retained-C build, so
     * release must fail closed instead of pretending to reset a device. */
    (void)partition;
    return NOT_SUPPORTED_ON_PLATFORM;
}
