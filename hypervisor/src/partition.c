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

/*@ requires \valid_read(state);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns \result \from image_object_id, *state;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_manifest_profile *fbvbs_find_trusted_service_profile_for_image(
    const struct fbvbs_hypervisor_state *state,
    uint64_t image_object_id
) {
    const struct fbvbs_artifact_catalog_entry *manifest_entry =
        fbvbs_find_related_manifest_entry(state, image_object_id);
    const struct fbvbs_manifest_profile *profile;

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

/*@ requires \valid_read(state);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns \result \from image_object_id, *state;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_manifest_profile *fbvbs_find_guest_boot_profile_for_image(
    const struct fbvbs_hypervisor_state *state,
    uint64_t image_object_id
) {
    const struct fbvbs_artifact_catalog_entry *manifest_entry =
        fbvbs_find_related_manifest_entry(state, image_object_id);
    const struct fbvbs_manifest_profile *profile;

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

/*@ requires \valid(partition);
    assigns partition->vcpus[0 .. FBVBS_MAX_VCPUS - 1];
*/
static void fbvbs_partition_apply_image_registers(struct fbvbs_partition *partition) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= partition->vcpu_count || index <= FBVBS_MAX_VCPUS;
        loop assigns index, partition->vcpus[0 .. FBVBS_MAX_VCPUS - 1];
        loop variant FBVBS_MAX_VCPUS - index;
    */
    for (index = 0U; index < partition->vcpu_count && index < FBVBS_MAX_VCPUS; ++index) {
        partition->vcpus[index].rip = partition->entry_ip;
        partition->vcpus[index].rsp = partition->initial_sp;
        partition->vcpus[index].rflags = 0x2U;
        partition->vcpus[index].cr0 = 0x80010033U;
        partition->vcpus[index].cr4 = 0x000006F0U;
        partition->vcpus[index].pending_interrupt_vector = 0U;
        partition->vcpus[index].pending_interrupt_delivery = 0U;
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

/*@ requires \valid(state);
    assigns \result \from memory_object_id, peer_partition_id, state->shared_objects[0 .. FBVBS_MAX_SHARED_OBJECTS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_SHARED_OBJECTS && \result == &state->shared_objects[i]);
*/
static struct fbvbs_shared_registration *fbvbs_find_shared_registration_for_object(
    struct fbvbs_hypervisor_state *state,
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

/*@ requires \valid(partition);
    assigns \result \from guest_physical_address, size, partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_MEMORY_MAPPINGS && \result == &partition->mappings[i]);
*/
static struct fbvbs_memory_mapping *fbvbs_find_mapping_covering(
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
        uint64_t mapping_end;
        uint64_t requested_end;

        if (!mapping->active) {
            continue;
        }
        mapping_end = mapping->guest_physical_address + mapping->size;
        requested_end = guest_physical_address + size;
        if (mapping->guest_physical_address <= guest_physical_address && mapping_end >= requested_end) {
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

/*@ requires \valid(partition);
    requires \valid(object);
    assigns partition->mappings[0 .. FBVBS_MAX_MEMORY_MAPPINGS - 1], partition->mapped_bytes, object->map_count;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == RESOURCE_EXHAUSTED || \result == RESOURCE_BUSY;
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

/*@ requires \valid_read(partition);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_partition_has_device(
    const struct fbvbs_partition *partition,
    uint64_t device_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= partition->assigned_device_count || index <= FBVBS_MAX_ASSIGNED_DEVICES;
        loop assigns index;
        loop variant FBVBS_MAX_ASSIGNED_DEVICES - index;
    */
    for (index = 0U; index < partition->assigned_device_count && index < FBVBS_MAX_ASSIGNED_DEVICES; ++index) {
        if (partition->assigned_devices[index] == device_id) {
            return 1;
        }
    }

    return 0;
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

/*@ requires \valid_read(state);
    requires \valid_read(owner);
    requires state->device_catalog.count <= FBVBS_MAX_DEVICE_CATALOG_ENTRIES;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_device_assigned_elsewhere(
    const struct fbvbs_hypervisor_state *state,
    uint64_t device_id,
    const struct fbvbs_partition *owner
) {
    uint32_t partition_index;

    /*@ loop invariant 0 <= partition_index <= FBVBS_MAX_PARTITIONS;
        loop assigns partition_index;
        loop variant FBVBS_MAX_PARTITIONS - partition_index;
    */
    for (partition_index = 0U; partition_index < FBVBS_MAX_PARTITIONS; ++partition_index) {
        const struct fbvbs_partition *partition = &state->partitions[partition_index];

        if (partition == owner || !partition->occupied) {
            continue;
        }
        if (fbvbs_partition_has_device(partition, device_id)) {
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
    assigns \result \from state->iommu_domains[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_PARTITIONS && \result == &state->iommu_domains[i]);
*/
static struct fbvbs_iommu_domain *fbvbs_allocate_iommu_domain_slot(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_PARTITIONS;
        loop assigns index;
        loop variant FBVBS_MAX_PARTITIONS - index;
    */
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        if (!state->iommu_domains[index].active) {
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
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        4U,
        FBVBS_EVENT_VM_PLATFORM_GATE,
        (const uint8_t *)&event,
        sizeof(event)
    );
}

/*@ requires \valid(state);
    requires \valid_read(partition);
    assigns *state;
*/
static void fbvbs_log_device_assignment_event(
    struct fbvbs_hypervisor_state *state,
    uint16_t event_code,
    const struct fbvbs_partition *partition,
    uint64_t device_id
) {
    struct fbvbs_audit_device_assignment_event event;

    event = (struct fbvbs_audit_device_assignment_event){0};
    event.partition_id = partition->partition_id;
    event.device_id = device_id;
    event.iommu_domain_id = partition->iommu_domain_id;
    event.attached_device_count = partition->assigned_device_count;
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        4U,
        event_code,
        (const uint8_t *)&event,
        sizeof(event)
    );
}

/*@ requires \valid(state);
    assigns *state;
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
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        4U,
        event_code,
        (const uint8_t *)&event,
        sizeof(event)
    );
}

/*@ requires \valid(state);
    requires \valid(partition);
    assigns state->iommu_domains[0 .. FBVBS_MAX_PARTITIONS - 1], state->next_iommu_domain_id,
            partition->iommu_domain_id;
    ensures \result == OK || \result == INTERNAL_CORRUPTION || \result == RESOURCE_EXHAUSTED;
*/
static int fbvbs_partition_attach_iommu_domain(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition
) {
    struct fbvbs_iommu_domain *domain;

    if (partition->iommu_domain_id != 0U) {
        domain = fbvbs_find_iommu_domain(state, partition->iommu_domain_id);
        if (domain == NULL || domain->owner_partition_id != partition->partition_id) {
            return INTERNAL_CORRUPTION;
        }
        return OK;
    }

    domain = fbvbs_allocate_iommu_domain_slot(state);
    if (domain == NULL) {
        return RESOURCE_EXHAUSTED;
    }
    *domain = (struct fbvbs_iommu_domain){0};
    domain->active = true;
    domain->domain_id = state->next_iommu_domain_id++;
    domain->owner_partition_id = partition->partition_id;
    partition->iommu_domain_id = domain->domain_id;
    return OK;
}

/*@ requires \valid(partition);
    requires partition->assigned_device_count <= FBVBS_MAX_ASSIGNED_DEVICES;
    requires index < partition->assigned_device_count;
    assigns partition->assigned_devices[0 .. FBVBS_MAX_ASSIGNED_DEVICES - 1], partition->assigned_device_count;
*/
static void fbvbs_partition_remove_assigned_device_at(
    struct fbvbs_partition *partition,
    uint32_t index
) {
    uint32_t tail_index;

    /*@ loop invariant index + 1U <= tail_index <= partition->assigned_device_count;
        loop assigns tail_index, partition->assigned_devices[0 .. FBVBS_MAX_ASSIGNED_DEVICES - 1];
        loop variant partition->assigned_device_count - tail_index;
    */
    for (tail_index = index + 1U; tail_index < partition->assigned_device_count; ++tail_index) {
        partition->assigned_devices[tail_index - 1U] = partition->assigned_devices[tail_index];
    }
    partition->assigned_device_count -= 1U;
    partition->assigned_devices[partition->assigned_device_count] = 0U;
}

/*@ requires \valid(state);
    requires \valid(partition);
    requires \valid(released_domain_id);
    assigns partition->assigned_devices[0 .. FBVBS_MAX_ASSIGNED_DEVICES - 1], partition->assigned_device_count,
            partition->iommu_domain_id, state->iommu_domains[0 .. FBVBS_MAX_PARTITIONS - 1], *released_domain_id;
    ensures \result == OK || \result == INTERNAL_CORRUPTION || \result == NOT_FOUND;
*/
static int fbvbs_partition_release_device_common(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition,
    uint64_t device_id,
    uint64_t *released_domain_id
) {
    struct fbvbs_iommu_domain *domain;
    uint32_t index;

    *released_domain_id = 0U;

    if (partition->assigned_device_count > FBVBS_MAX_ASSIGNED_DEVICES) {
        return INTERNAL_CORRUPTION;
    }

    /*@ loop invariant 0 <= index <= partition->assigned_device_count || index <= FBVBS_MAX_ASSIGNED_DEVICES;
        loop invariant partition->assigned_device_count <= FBVBS_MAX_ASSIGNED_DEVICES;
        loop assigns index, partition->assigned_devices[0 .. FBVBS_MAX_ASSIGNED_DEVICES - 1],
                     partition->assigned_device_count, partition->iommu_domain_id,
                     state->iommu_domains[0 .. FBVBS_MAX_PARTITIONS - 1], *released_domain_id;
        loop variant FBVBS_MAX_ASSIGNED_DEVICES - index;
    */
    for (index = 0U; index < partition->assigned_device_count && index < FBVBS_MAX_ASSIGNED_DEVICES; ++index) {
        if (partition->assigned_devices[index] == device_id) {
            domain = fbvbs_find_iommu_domain(state, partition->iommu_domain_id);
            if (domain == NULL || domain->owner_partition_id != partition->partition_id ||
                domain->attached_device_count == 0U) {
                return INTERNAL_CORRUPTION;
            }

            /*@ assert index < partition->assigned_device_count; */
            fbvbs_partition_remove_assigned_device_at(partition, index);
            domain->attached_device_count = (uint16_t)(domain->attached_device_count - 1U);
            if (domain->attached_device_count == 0U) {
                uint64_t domain_id = domain->domain_id;

                *released_domain_id = domain_id;
                *domain = (struct fbvbs_iommu_domain){0};
                partition->iommu_domain_id = 0U;
            }
            return OK;
        }
    }

    return NOT_FOUND;
}

static void fbvbs_partition_release_all_devices(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition
) {
    while (partition->assigned_device_count != 0U) {
        uint64_t device_id = partition->assigned_devices[partition->assigned_device_count - 1U];
        uint64_t released_domain_id;

        if (fbvbs_partition_release_device_common(
                state,
                partition,
                device_id,
                &released_domain_id
            ) != OK) {
            break;
        }
    }
}

/*@ requires \valid(state);
    requires \valid(created_partition);
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1], state->next_partition_id, *created_partition
        \from kind, vcpu_count, vm_flags, memory_limit_bytes, capability_mask, image_object_id,
               state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1], state->next_partition_id;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == RESOURCE_EXHAUSTED;
    ensures \result == OK ==> *created_partition != \null;
    ensures \result == OK ==> \valid(*created_partition);
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

static void fbvbs_partition_release_mappings(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition
) {
    uint32_t index;

    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        struct fbvbs_memory_mapping *mapping = &partition->mappings[index];

        if (!mapping->active) {
            continue;
        }
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

static void fbvbs_partition_release_shared_registrations(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id
) {
    uint32_t index;

    for (index = 0U; index < FBVBS_MAX_SHARED_OBJECTS; ++index) {
        struct fbvbs_shared_registration *shared = &state->shared_objects[index];

        /* Clean up registrations where this partition is either the owner or peer */
        if (!shared->active) {
            continue;
        }
        if (shared->peer_partition_id != partition_id && shared->owner_partition_id != partition_id) {
            continue;
        }
        if (shared->memory_object_id != 0U) {
            struct fbvbs_memory_object *object =
                fbvbs_find_memory_object(state, shared->memory_object_id);

            if (object != NULL && object->shared_count != 0U) {
                object->shared_count -= 1U;
            }
        }
        if (shared->peer_partition_id != 0U && shared->peer_partition_id != partition_id) {
            struct fbvbs_partition *peer_partition =
                fbvbs_find_partition(state, shared->peer_partition_id);

            if (peer_partition != NULL) {
                if (peer_partition->mapped_bytes >= shared->size) {
                    peer_partition->mapped_bytes -= shared->size;
                } else {
                    peer_partition->mapped_bytes = 0U;
                }
            }
        }
        if (shared->owner_partition_id != 0U && shared->owner_partition_id != partition_id) {
            struct fbvbs_partition *owner_partition =
                fbvbs_find_partition(state, shared->owner_partition_id);

            if (owner_partition != NULL) {
                if (owner_partition->mapped_bytes >= shared->size) {
                    owner_partition->mapped_bytes -= shared->size;
                } else {
                    owner_partition->mapped_bytes = 0U;
                }
            }
        }
        *shared = (struct fbvbs_shared_registration){0};
    }
}

/*@ requires \valid(state);
    requires \valid(partition);
    assigns *state;
    ensures \result == OK || \result == INVALID_STATE;
*/
static int fbvbs_partition_destroy_common(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition
) {
    uint64_t partition_id = partition->partition_id;
    uint64_t measurement_epoch = partition->measurement_epoch;
    uint16_t kind = partition->kind;
    uint16_t service_kind = partition->service_kind;
    uint32_t vcpu_count = partition->vcpu_count;
    uint32_t index;

    fbvbs_partition_release_mappings(state, partition);
    fbvbs_partition_release_shared_registrations(state, partition_id);
    if (kind == PARTITION_KIND_GUEST_VM && partition->assigned_device_count != 0U) {
        fbvbs_partition_release_all_devices(state, partition);
    }
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    requires state == \null || state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1], state->next_partition_id, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == MEASUREMENT_FAILED || \result == RESOURCE_EXHAUSTED;
*/
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
    response->partition_id = partition->partition_id;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND;
*/
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    requires state == \null || state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1], state->next_measurement_digest_id, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == INVALID_STATE ||
            \result == MEASUREMENT_FAILED || \result == SIGNATURE_INVALID;
*/
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

    partition->manifest_object_id = request->manifest_object_id;
    if (service_profile != NULL) {
        partition->service_kind = service_profile->service_kind;
    }
    partition->measurement_epoch += 1U;
    partition->measurement_digest_id = state->next_measurement_digest_id++;
    partition->state = FBVBS_PARTITION_STATE_MEASURED;
    response->measurement_digest_id = partition->measurement_digest_id;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires state == \null || state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == INVALID_STATE ||
            \result == MEASUREMENT_FAILED;
*/
int fbvbs_partition_load_image(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_load_image_request *request
) {
    struct fbvbs_partition *partition;
    const struct fbvbs_manifest_profile *profile = NULL;
    const struct fbvbs_manifest_profile *guest_profile = NULL;
    uint64_t resolved_entry_ip;
    uint64_t resolved_initial_sp;

    if (state == NULL || request == NULL) {
        return INVALID_PARAMETER;
    }

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
    resolved_entry_ip = request->entry_ip;
    resolved_initial_sp = request->initial_sp;
    if (partition->kind == PARTITION_KIND_TRUSTED_SERVICE) {
        profile = fbvbs_find_trusted_service_profile_for_image(state, partition->image_object_id);
        if (profile == NULL) {
            return MEASUREMENT_FAILED;
        }
        if (resolved_entry_ip == 0U) {
            resolved_entry_ip = profile->entry_ip;
        }
        if (resolved_initial_sp == 0U) {
            resolved_initial_sp = profile->initial_sp;
        }
        if (resolved_entry_ip != profile->entry_ip ||
            resolved_initial_sp != profile->initial_sp) {
            return MEASUREMENT_FAILED;
        }
    } else if (partition->kind == PARTITION_KIND_GUEST_VM) {
        guest_profile = fbvbs_find_guest_boot_profile_for_image(state, partition->image_object_id);
        if (guest_profile == NULL) {
            return MEASUREMENT_FAILED;
        }
        if (resolved_entry_ip == 0U) {
            resolved_entry_ip = guest_profile->entry_ip;
        }
        if (resolved_entry_ip != guest_profile->entry_ip) {
            return MEASUREMENT_FAILED;
        }
        if (resolved_initial_sp == 0U) {
            return INVALID_PARAMETER;
        }
    } else if (resolved_entry_ip == 0U) {
        return MEASUREMENT_FAILED;
    }

    partition->entry_ip = resolved_entry_ip;
    partition->initial_sp = resolved_initial_sp;
    fbvbs_partition_apply_image_registers(partition);
    partition->state = FBVBS_PARTITION_STATE_LOADED;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == INVALID_STATE;
*/
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

/*@ requires \valid(state) || state == \null;
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == INVALID_STATE;
*/
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

/*@ requires \valid(state) || state == \null;
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == INVALID_STATE;
*/
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
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        4U,
        FBVBS_EVENT_PARTITION_FAULT,
        (const uint8_t *)&event,
        sizeof(event)
    );
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == INVALID_STATE || \result == MEASUREMENT_FAILED;
*/
int fbvbs_partition_recover(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_recover_request *request
) {
    struct fbvbs_partition *partition;

    if (state == NULL || request == NULL) {
        return INVALID_PARAMETER;
    }

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

    partition->measurement_epoch += 1U;
    partition->state = FBVBS_PARTITION_STATE_RUNNABLE;
    fbvbs_partition_reset_vcpus(partition, FBVBS_VCPU_STATE_RUNNABLE);
    fbvbs_partition_apply_image_registers(partition);
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
        0U,
        0U,
        &partition
    );
    if (status != OK) {
        return status;
    }

    partition->state = FBVBS_PARTITION_STATE_RUNNABLE;
    fbvbs_partition_set_vcpu_state(partition, FBVBS_VCPU_STATE_RUNNABLE);
    partition->vcpus[0].rip = fbvbs_primary_host_callsite(state, FBVBS_HOST_CALLER_CLASS_FBVBS);
    return OK;
}

int fbvbs_partition_destroy(struct fbvbs_hypervisor_state *state, uint64_t partition_id) {
    struct fbvbs_partition *partition = fbvbs_find_partition(state, partition_id);

    if (state == NULL || partition_id == 0U) {
        return INVALID_PARAMETER;
    }
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind == PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!partition->occupied) {
        return INVALID_STATE;
    }

    return fbvbs_partition_destroy_common(state, partition);
}

/*@ requires \valid(state) || state == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == INVALID_STATE;
*/
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
    struct fbvbs_diag_partition_entry entry;

    if (state == NULL || response == NULL || response_length == NULL) {
        return INVALID_PARAMETER;
    }

    *response = (struct fbvbs_diag_partition_list_response){0};

    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        const struct fbvbs_partition *partition = &state->partitions[index];

        if (!partition->occupied && !partition->tombstone) {
            continue;
        }
        if ((sizeof(entry) * (count + 1U)) > sizeof(response->entries)) {
            return BUFFER_TOO_SMALL;
        }

        entry.partition_id = partition->partition_id;
        entry.state = partition->state;
        entry.kind = partition->kind;
        entry.service_kind = partition->service_kind;
        fbvbs_copy_bytes(
            &response->entries[count * sizeof(entry)],
            (const uint8_t *)&entry,
            sizeof(entry)
        );
        count += 1U;
    }

    response->count = count;
    response->reserved0 = 0U;
    *response_length = 8U + (count * (uint32_t)sizeof(entry));
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns *state, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_SUPPORTED_ON_PLATFORM ||
            \result == RESOURCE_EXHAUSTED;
*/
int fbvbs_vm_create(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_create_request *request,
    struct fbvbs_vm_create_response *response
) {
    struct fbvbs_partition *partition = NULL;
    uint32_t supported_flags = VM_FLAG_NESTED_VIRT_DISABLED;
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
    response->vm_partition_id = partition->partition_id;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    assigns *state;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == INVALID_STATE;
*/
int fbvbs_vm_destroy(struct fbvbs_hypervisor_state *state, uint64_t vm_partition_id) {
    struct fbvbs_partition *partition;

    if (state == NULL || vm_partition_id == 0U) {
        return INVALID_PARAMETER;
    }

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

    return fbvbs_partition_destroy_common(state, partition);
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND;
*/
int fbvbs_vm_get_vcpu_status(
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == INVALID_STATE || \result == PERMISSION_DENIED;
*/
int fbvbs_vm_set_register(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_register_request *request
) {
    struct fbvbs_partition *partition;
    struct fbvbs_vcpu *vcpu;
    uint64_t *slot;

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

    *slot = request->value;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == INVALID_STATE;
*/
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns *state;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == INVALID_STATE || \result == RESOURCE_EXHAUSTED || \result == RESOURCE_BUSY;
*/
int fbvbs_memory_map(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_map_request *request
) {
    struct fbvbs_partition *partition;
    struct fbvbs_memory_object *object;

    if (state == NULL || request == NULL) {
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

    return fbvbs_apply_mapping(
        partition,
        object,
        request->guest_physical_address,
        request->size,
        request->permissions
    );
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns *state;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == INVALID_STATE || \result == INTERNAL_CORRUPTION;
*/
int fbvbs_memory_unmap(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_unmap_request *request
) {
    struct fbvbs_partition *partition;
    struct fbvbs_memory_mapping *mapping;
    struct fbvbs_memory_object *object;

    if (state == NULL || request == NULL) {
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

    partition->mapped_bytes -= mapping->size;
    object->map_count -= 1U;
    *mapping = (struct fbvbs_memory_mapping){0};
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns *state;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == INVALID_STATE || \result == PERMISSION_DENIED;
*/
int fbvbs_memory_set_permission(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_set_permission_request *request
) {
    struct fbvbs_partition *partition;
    struct fbvbs_memory_mapping *mapping;

    if (state == NULL || request == NULL) {
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
    if (partition->capability_mask == 0U) {
        return PERMISSION_DENIED;
    }

    mapping = fbvbs_find_mapping_covering(
        partition,
        request->guest_physical_address,
        request->size
    );
    if (mapping == NULL) {
        return NOT_FOUND;
    }

    mapping->permissions = (uint16_t)request->permissions;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns *state, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == PERMISSION_DENIED || \result == RESOURCE_EXHAUSTED || \result == ALREADY_EXISTS ||
            \result == INVALID_STATE;
*/
int fbvbs_memory_register_shared(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_register_shared_request *request,
    struct fbvbs_memory_register_shared_response *response
) {
    struct fbvbs_memory_object *object;
    struct fbvbs_partition *peer_partition = NULL;
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
    if (object->object_flags != FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE || request->size > object->size) {
        return PERMISSION_DENIED;
    }

    if (request->peer_partition_id != 0U) {
        peer_partition = fbvbs_find_partition(state, request->peer_partition_id);
        if (peer_partition == NULL) {
            return NOT_FOUND;
        }
        if (!peer_partition->occupied || peer_partition->state == FBVBS_PARTITION_STATE_DESTROYED) {
            return INVALID_STATE;
        }
        if (!fbvbs_partition_can_charge_mapping(peer_partition, request->size)) {
            return RESOURCE_EXHAUSTED;
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

    *shared = (struct fbvbs_shared_registration){0};
    shared->active = true;
    shared->peer_permissions = (uint16_t)request->peer_permissions;
    shared->shared_object_id = state->next_shared_object_id++;
    shared->memory_object_id = request->memory_object_id;
    shared->size = request->size;
    shared->peer_partition_id = request->peer_partition_id;
    object->shared_count += 1U;
    if (peer_partition != NULL) {
        peer_partition->mapped_bytes += request->size;
    }
    response->shared_object_id = shared->shared_object_id;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    assigns *state;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == INTERNAL_CORRUPTION || \result == RESOURCE_BUSY;
*/
int fbvbs_memory_unregister_shared(
    struct fbvbs_hypervisor_state *state,
    uint64_t shared_object_id
) {
    struct fbvbs_shared_registration *shared;
    struct fbvbs_memory_object *object;
    struct fbvbs_partition *peer_partition = NULL;

    if (state == NULL || shared_object_id == 0U) {
        return INVALID_PARAMETER;
    }

    shared = fbvbs_find_shared_registration(state, shared_object_id);
    if (shared == NULL) {
        return NOT_FOUND;
    }

    object = fbvbs_find_memory_object(state, shared->memory_object_id);
    if (object == NULL || object->shared_count == 0U) {
        return INTERNAL_CORRUPTION;
    }
    if (object->map_count != 0U) {
        return RESOURCE_BUSY;
    }

    if (shared->peer_partition_id != 0U) {
        peer_partition = fbvbs_find_partition(state, shared->peer_partition_id);
        if (peer_partition == NULL) {
            return INTERNAL_CORRUPTION;
        }
        if (peer_partition->mapped_bytes >= shared->size) {
            peer_partition->mapped_bytes -= shared->size;
        } else {
            peer_partition->mapped_bytes = 0U;
        }
    }
    object->shared_count -= 1U;
    *shared = (struct fbvbs_shared_registration){0};
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns *state, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == INVALID_STATE || \result == NOT_SUPPORTED_ON_PLATFORM;
*/
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

    partition = fbvbs_find_partition(state, request->vm_partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->kind != PARTITION_KIND_GUEST_VM) {
        return INVALID_PARAMETER;
    }
    if (!partition->occupied || partition->state != FBVBS_PARTITION_STATE_RUNNABLE) {
        return INVALID_STATE;
    }

    vcpu = fbvbs_partition_get_vcpu(partition, request->vcpu_id);
    if (vcpu == NULL || vcpu->state != FBVBS_VCPU_STATE_RUNNABLE) {
        return INVALID_STATE;
    }

    partition->state = FBVBS_PARTITION_STATE_RUNNING;
    vcpu->state = FBVBS_VCPU_STATE_RUNNING;
    status = fbvbs_vmx_run_vcpu(state, partition, request->vcpu_id, response);
    if (status != OK) {
        partition->state = FBVBS_PARTITION_STATE_RUNNABLE;
        vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
        return status;
    }

    fbvbs_partition_refresh_vm_state(partition);
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns *state;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == INVALID_STATE || \result == RESOURCE_EXHAUSTED || \result == RESOURCE_BUSY;
*/
int fbvbs_vm_map_memory(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_map_memory_request *request
) {
    struct fbvbs_partition *partition;
    struct fbvbs_memory_object *object;

    if (state == NULL || request == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U ||
        !fbvbs_range_valid(request->guest_physical_address, request->size) ||
        !fbvbs_permissions_valid(request->permissions)) {
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

    return fbvbs_apply_mapping(
        partition,
        object,
        request->guest_physical_address,
        request->size,
        request->permissions
    );
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == INVALID_STATE || \result == RESOURCE_BUSY;
*/
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires state == \null || state->device_catalog.count <= FBVBS_MAX_DEVICE_CATALOG_ENTRIES;
    assigns *state;
*/
int fbvbs_vm_assign_device(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_device_request *request
) {
    struct fbvbs_partition *partition;
    uint64_t previous_domain_id;
    int status;

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
    if (!fbvbs_partition_device_mutation_state_ok(partition, 0)) {
        return INVALID_STATE;
    }
    if (partition->assigned_device_count > FBVBS_MAX_ASSIGNED_DEVICES) {
        return INVALID_STATE;
    }
    if (!fbvbs_device_exists(state, request->device_id)) {
        return NOT_FOUND;
    }
    if (state->vmx_caps.iommu_available == 0U) {
        fbvbs_log_platform_gate_failure(
            state,
            request->vm_partition_id,
            request->device_id,
            FBVBS_PLATFORM_CAP_IOMMU
        );
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    if (fbvbs_partition_has_device(partition, request->device_id) ||
        fbvbs_device_assigned_elsewhere(state, request->device_id, partition)) {
        return RESOURCE_BUSY;
    }
    if (partition->assigned_device_count >= FBVBS_MAX_ASSIGNED_DEVICES) {
        return RESOURCE_BUSY;
    }
    previous_domain_id = partition->iommu_domain_id;
    status = fbvbs_partition_attach_iommu_domain(state, partition);
    if (status != OK) {
        return status;
    }
    if (previous_domain_id == 0U) {
        fbvbs_log_iommu_domain_event(
            state,
            FBVBS_EVENT_IOMMU_DOMAIN_CREATE,
            partition->partition_id,
            partition->iommu_domain_id,
            0U
        );
    }

    {
        uint32_t assigned_index = partition->assigned_device_count;

        if (assigned_index >= FBVBS_MAX_ASSIGNED_DEVICES) {
            return INTERNAL_CORRUPTION;
        }
        partition->assigned_devices[assigned_index] = request->device_id;
        partition->assigned_device_count = assigned_index + 1U;
    }
    {
        struct fbvbs_iommu_domain *domain = fbvbs_find_iommu_domain(state, partition->iommu_domain_id);

        if (domain == NULL || domain->owner_partition_id != partition->partition_id) {
            partition->assigned_device_count -= 1U;
            partition->assigned_devices[partition->assigned_device_count] = 0U;
            return INTERNAL_CORRUPTION;
        }
        domain->attached_device_count = (uint16_t)(domain->attached_device_count + 1U);
    }
    fbvbs_log_device_assignment_event(state, FBVBS_EVENT_VM_DEVICE_ASSIGN, partition, request->device_id);
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires state == \null || state->device_catalog.count <= FBVBS_MAX_DEVICE_CATALOG_ENTRIES;
    assigns *state;
*/
int fbvbs_vm_release_device(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_device_request *request
) {
    struct fbvbs_partition *partition;
    uint64_t released_domain_id;
    uint32_t index;

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
    if (partition->assigned_device_count > FBVBS_MAX_ASSIGNED_DEVICES) {
        return INVALID_STATE;
    }

    /*@ loop invariant 0 <= index <= partition->assigned_device_count || index <= FBVBS_MAX_ASSIGNED_DEVICES;
        loop assigns index;
        loop variant FBVBS_MAX_ASSIGNED_DEVICES - index;
    */
    for (index = 0U; index < partition->assigned_device_count && index < FBVBS_MAX_ASSIGNED_DEVICES; ++index) {
        if (partition->assigned_devices[index] == request->device_id) {
            int release_status = fbvbs_partition_release_device_common(
                state,
                partition,
                request->device_id,
                &released_domain_id
            );

            if (release_status != OK) {
                return release_status == NOT_FOUND ? INTERNAL_CORRUPTION : release_status;
            }
            fbvbs_log_device_assignment_event(
                state,
                FBVBS_EVENT_VM_DEVICE_RELEASE,
                partition,
                request->device_id
            );
            if (released_domain_id != 0U) {
                fbvbs_log_iommu_domain_event(
                    state,
                    FBVBS_EVENT_IOMMU_DOMAIN_RELEASE,
                    partition->partition_id,
                    released_domain_id,
                    0U
                );
            }
            return OK;
        }
    }

    return NOT_FOUND;
}