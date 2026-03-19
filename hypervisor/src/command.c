#include "fbvbs_hypervisor.h"

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_is_page_aligned(uint64_t value) {
    return (value & (FBVBS_PAGE_SIZE - 1U)) == 0U;
}

/*@ requires \valid_read(page) || page == \null;
    assigns \nothing;
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == ABI_VERSION_UNSUPPORTED || \result == RESOURCE_BUSY;
    behavior null_page:
      assumes page == \null;
      ensures \result == INVALID_PARAMETER;
*/
static int fbvbs_validate_command_page(const struct fbvbs_command_page_v1 *page) {
    uint16_t reserved_flags;
    uint32_t index;

    if (page == NULL) {
        return INVALID_PARAMETER;
    }

    reserved_flags = (uint16_t)(page->flags & (uint16_t)(~FBVBS_CMD_FLAG_SEPARATE_OUTPUT));
    if (page->abi_version != FBVBS_ABI_VERSION) {
        return ABI_VERSION_UNSUPPORTED;
    }
    if (page->reserved0 != 0U) {
        return INVALID_PARAMETER;
    }
    if (page->actual_output_length != 0U) {
        return INVALID_PARAMETER;
    }
    if (page->input_length > sizeof(page->body)) {
        return INVALID_PARAMETER;
    }
    /*@ loop invariant page->input_length <= index <= sizeof(page->body);
        loop invariant \forall integer i; (integer)page->input_length <= i < (integer)index ==> page->body[i] == 0U;
        loop assigns index;
        loop variant sizeof(page->body) - index;
    */
    for (index = page->input_length; index < sizeof(page->body); ++index) {
        if (page->body[index] != 0U) {
            return INVALID_PARAMETER;
        }
    }
    if (reserved_flags != 0U) {
        return INVALID_PARAMETER;
    }
    if ((page->flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) == 0U && page->output_page_gpa != 0U) {
        return INVALID_PARAMETER;
    }
    if ((page->flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) != 0U && !fbvbs_is_page_aligned(page->output_page_gpa)) {
        return INVALID_PARAMETER;
    }
    if (page->command_state == EXECUTING) {
        return RESOURCE_BUSY;
    }
    if (page->command_state != READY) {
        return INVALID_PARAMETER;
    }

    return OK;
}

/*@ requires \valid(state);
    assigns \result \from page_gpa, state->command_trackers[0 .. FBVBS_MAX_COMMAND_TRACKERS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_COMMAND_TRACKERS &&
             \result == &state->command_trackers[i]);
*/
static struct fbvbs_command_tracker *fbvbs_find_command_tracker(
    struct fbvbs_hypervisor_state *state,
    uint64_t page_gpa
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_COMMAND_TRACKERS;
        loop assigns index;
        loop variant FBVBS_MAX_COMMAND_TRACKERS - index;
    */
    for (index = 0U; index < FBVBS_MAX_COMMAND_TRACKERS; ++index) {
        if (state->command_trackers[index].active &&
            state->command_trackers[index].page_gpa == page_gpa) {
            return &state->command_trackers[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns state->command_trackers[0 .. FBVBS_MAX_COMMAND_TRACKERS - 1],
            \result \from page_gpa, state->command_trackers[0 .. FBVBS_MAX_COMMAND_TRACKERS - 1];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < FBVBS_MAX_COMMAND_TRACKERS &&
             \result == &state->command_trackers[i]);
*/
static struct fbvbs_command_tracker *fbvbs_get_command_tracker(
    struct fbvbs_hypervisor_state *state,
    uint64_t page_gpa
) {
    struct fbvbs_command_tracker *tracker;
    uint32_t index;

    tracker = fbvbs_find_command_tracker(state, page_gpa);
    if (tracker != NULL) {
        return tracker;
    }

    /*@ loop invariant 0 <= index <= FBVBS_MAX_COMMAND_TRACKERS;
        loop assigns index, state->command_trackers[0 .. FBVBS_MAX_COMMAND_TRACKERS - 1];
        loop variant FBVBS_MAX_COMMAND_TRACKERS - index;
    */
    for (index = 0U; index < FBVBS_MAX_COMMAND_TRACKERS; ++index) {
        if (!state->command_trackers[index].active) {
            state->command_trackers[index] = (struct fbvbs_command_tracker){0};
            state->command_trackers[index].active = true;
            state->command_trackers[index].page_gpa = page_gpa;
            return &state->command_trackers[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    requires \valid_read(page);
    assigns state->command_trackers[0 .. FBVBS_MAX_COMMAND_TRACKERS - 1];
    ensures \result == OK || \result == RESOURCE_EXHAUSTED || \result == REPLAY_DETECTED;
*/
static int fbvbs_validate_command_sequence(
    struct fbvbs_hypervisor_state *state,
    uint64_t page_gpa,
    const struct fbvbs_command_page_v1 *page
) {
    struct fbvbs_command_tracker *tracker;

    tracker = fbvbs_get_command_tracker(state, page_gpa);
    if (tracker == NULL) {
        return RESOURCE_EXHAUSTED;
    }
    if (tracker->sequence_seen && page->caller_sequence <= tracker->last_sequence) {
        return REPLAY_DETECTED;
    }

    tracker->sequence_seen = true;
    tracker->last_sequence = page->caller_sequence;
    tracker->last_nonce = page->caller_nonce;
    return OK;
}

/*@ requires \valid(state);
    requires \valid(vcpu_id);
    assigns *vcpu_id, \result \from page_gpa, state->partitions[0 .. FBVBS_MAX_PARTITIONS - 1];
    ensures \result == \null || \valid(\result);
*/
static struct fbvbs_partition *fbvbs_find_command_page_owner(
    struct fbvbs_hypervisor_state *state,
    uint64_t page_gpa,
    uint32_t *vcpu_id
) {
    uint32_t partition_index;

    /*@ loop invariant 0 <= partition_index <= FBVBS_MAX_PARTITIONS;
        loop assigns partition_index, *vcpu_id;
        loop variant FBVBS_MAX_PARTITIONS - partition_index;
    */
    for (partition_index = 0U; partition_index < FBVBS_MAX_PARTITIONS; ++partition_index) {
        struct fbvbs_partition *partition = &state->partitions[partition_index];
        uint32_t index;

        if (!partition->occupied) {
            continue;
        }
        /*@ loop invariant 0 <= index <= FBVBS_MAX_VCPUS;
            loop assigns index, *vcpu_id;
            loop variant FBVBS_MAX_VCPUS - index;
        */
        for (index = 0U; index < partition->vcpu_count && index < FBVBS_MAX_VCPUS; ++index) {
            if ((uint64_t)(uintptr_t)&partition->command_pages[index].page == page_gpa) {
                *vcpu_id = index;
                return partition;
            }
        }
    }

    return NULL;
}

/*@ assigns \nothing;
    ensures \result == SERVICE_KIND_NONE ||
            \result == SERVICE_KIND_KCI ||
            \result == SERVICE_KIND_KSI ||
            \result == SERVICE_KIND_IKS ||
            \result == SERVICE_KIND_SKS ||
            \result == SERVICE_KIND_UVS;
*/
static uint16_t fbvbs_service_kind_for_call(uint16_t call_id) {
    switch (call_id) {
        case FBVBS_CALL_KCI_VERIFY_MODULE:
        case FBVBS_CALL_KCI_SET_WX:
        case FBVBS_CALL_KCI_PIN_CR:
        case FBVBS_CALL_KCI_INTERCEPT_MSR:
            return SERVICE_KIND_KCI;
        case FBVBS_CALL_KSI_CREATE_TARGET_SET:
        case FBVBS_CALL_KSI_REGISTER_TIER_A:
        case FBVBS_CALL_KSI_REGISTER_TIER_B:
        case FBVBS_CALL_KSI_MODIFY_TIER_B:
        case FBVBS_CALL_KSI_REGISTER_POINTER:
        case FBVBS_CALL_KSI_VALIDATE_SETUID:
        case FBVBS_CALL_KSI_ALLOCATE_UCRED:
        case FBVBS_CALL_KSI_REPLACE_TIER_B_OBJECT:
        case FBVBS_CALL_KSI_UNREGISTER_OBJECT:
            return SERVICE_KIND_KSI;
        case FBVBS_CALL_IKS_IMPORT_KEY:
        case FBVBS_CALL_IKS_SIGN:
        case FBVBS_CALL_IKS_KEY_EXCHANGE:
        case FBVBS_CALL_IKS_DERIVE:
        case FBVBS_CALL_IKS_DESTROY_KEY:
            return SERVICE_KIND_IKS;
        case FBVBS_CALL_SKS_IMPORT_DEK:
        case FBVBS_CALL_SKS_DECRYPT_BATCH:
        case FBVBS_CALL_SKS_ENCRYPT_BATCH:
        case FBVBS_CALL_SKS_DESTROY_DEK:
            return SERVICE_KIND_SKS;
        case FBVBS_CALL_UVS_VERIFY_MANIFEST_SET:
        case FBVBS_CALL_UVS_VERIFY_ARTIFACT:
        case FBVBS_CALL_UVS_CHECK_REVOCATION:
            return SERVICE_KIND_UVS;
        default:
            return SERVICE_KIND_NONE;
    }
}

/*@ assigns \nothing;
    ensures \result == 0ULL || \result != 0ULL;
*/
static uint64_t fbvbs_required_capability_for_call(uint16_t call_id) {
    switch (call_id) {
        case FBVBS_CALL_PARTITION_CREATE:
        case FBVBS_CALL_PARTITION_DESTROY:
        case FBVBS_CALL_PARTITION_GET_STATUS:
        case FBVBS_CALL_PARTITION_QUIESCE:
        case FBVBS_CALL_PARTITION_RESUME:
        case FBVBS_CALL_PARTITION_MEASURE:
        case FBVBS_CALL_PARTITION_LOAD_IMAGE:
        case FBVBS_CALL_PARTITION_START:
        case FBVBS_CALL_PARTITION_RECOVER:
        case FBVBS_CALL_PARTITION_GET_FAULT_INFO:
            return FBVBS_CAP_PARTITION_MANAGE;
        case FBVBS_CALL_MEMORY_ALLOCATE_OBJECT:
        case FBVBS_CALL_MEMORY_MAP:
        case FBVBS_CALL_MEMORY_UNMAP:
        case FBVBS_CALL_MEMORY_RELEASE_OBJECT:
            return FBVBS_CAP_MEMORY_MAP;
        case FBVBS_CALL_MEMORY_SET_PERMISSION:
            return FBVBS_CAP_MEMORY_PERMISSION_SET;
        case FBVBS_CALL_MEMORY_REGISTER_SHARED:
        case FBVBS_CALL_MEMORY_UNREGISTER_SHARED:
            return FBVBS_CAP_SHARED_MEMORY_REGISTER;
        case FBVBS_CALL_KCI_VERIFY_MODULE:
        case FBVBS_CALL_KCI_SET_WX:
        case FBVBS_CALL_KCI_PIN_CR:
        case FBVBS_CALL_KCI_INTERCEPT_MSR:
            return FBVBS_CAP_KCI_ACCESS;
        case FBVBS_CALL_KSI_CREATE_TARGET_SET:
        case FBVBS_CALL_KSI_REGISTER_TIER_A:
        case FBVBS_CALL_KSI_REGISTER_TIER_B:
        case FBVBS_CALL_KSI_MODIFY_TIER_B:
        case FBVBS_CALL_KSI_REGISTER_POINTER:
        case FBVBS_CALL_KSI_VALIDATE_SETUID:
        case FBVBS_CALL_KSI_ALLOCATE_UCRED:
        case FBVBS_CALL_KSI_REPLACE_TIER_B_OBJECT:
        case FBVBS_CALL_KSI_UNREGISTER_OBJECT:
            return FBVBS_CAP_KSI_ACCESS;
        case FBVBS_CALL_IKS_IMPORT_KEY:
        case FBVBS_CALL_IKS_SIGN:
        case FBVBS_CALL_IKS_KEY_EXCHANGE:
        case FBVBS_CALL_IKS_DERIVE:
        case FBVBS_CALL_IKS_DESTROY_KEY:
            return FBVBS_CAP_IKS_ACCESS;
        case FBVBS_CALL_SKS_IMPORT_DEK:
        case FBVBS_CALL_SKS_DECRYPT_BATCH:
        case FBVBS_CALL_SKS_ENCRYPT_BATCH:
        case FBVBS_CALL_SKS_DESTROY_DEK:
            return FBVBS_CAP_SKS_ACCESS;
        case FBVBS_CALL_UVS_VERIFY_MANIFEST_SET:
        case FBVBS_CALL_UVS_VERIFY_ARTIFACT:
        case FBVBS_CALL_UVS_CHECK_REVOCATION:
            return FBVBS_CAP_UVS_ACCESS;
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
            return FBVBS_CAP_VM_MANAGE;
        case FBVBS_CALL_AUDIT_GET_MIRROR_INFO:
        case FBVBS_CALL_AUDIT_GET_BOOT_ID:
        case FBVBS_CALL_DIAG_GET_PARTITION_LIST:
        case FBVBS_CALL_DIAG_GET_CAPABILITIES:
        case FBVBS_CALL_DIAG_GET_ARTIFACT_LIST:
        case FBVBS_CALL_DIAG_GET_DEVICE_LIST:
            return FBVBS_CAP_AUDIT_DIAG;
        default:
            return 0ULL;
    }
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_is_host_partition_call(uint16_t call_id) {
    switch (call_id) {
        case FBVBS_CALL_PARTITION_CREATE:
        case FBVBS_CALL_PARTITION_DESTROY:
        case FBVBS_CALL_PARTITION_GET_STATUS:
        case FBVBS_CALL_PARTITION_QUIESCE:
        case FBVBS_CALL_PARTITION_RESUME:
        case FBVBS_CALL_PARTITION_MEASURE:
        case FBVBS_CALL_PARTITION_LOAD_IMAGE:
        case FBVBS_CALL_PARTITION_START:
        case FBVBS_CALL_PARTITION_RECOVER:
        case FBVBS_CALL_PARTITION_GET_FAULT_INFO:
        case FBVBS_CALL_MEMORY_ALLOCATE_OBJECT:
        case FBVBS_CALL_MEMORY_MAP:
        case FBVBS_CALL_MEMORY_UNMAP:
        case FBVBS_CALL_MEMORY_REGISTER_SHARED:
        case FBVBS_CALL_MEMORY_RELEASE_OBJECT:
        case FBVBS_CALL_MEMORY_UNREGISTER_SHARED:
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
        case FBVBS_CALL_AUDIT_GET_MIRROR_INFO:
        case FBVBS_CALL_AUDIT_GET_BOOT_ID:
        case FBVBS_CALL_DIAG_GET_PARTITION_LIST:
        case FBVBS_CALL_DIAG_GET_CAPABILITIES:
        case FBVBS_CALL_DIAG_GET_ARTIFACT_LIST:
        case FBVBS_CALL_DIAG_GET_DEVICE_LIST:
            return 1;
        default:
            return 0;
    }
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_is_vm_partition_call(uint16_t call_id) {
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
            return 1;
        default:
            return 0;
    }
}

/*@ assigns \result \from call_id;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_is_service_call(uint16_t call_id) {
    return fbvbs_service_kind_for_call(call_id) != SERVICE_KIND_NONE;
}

/*@ requires count == 0U || \valid_read(table + (0 .. count - 1));
    assigns \result \from observed_rip, count, table[0 .. count - 1];
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_rip_allowed(uint64_t observed_rip, const uint64_t *table, uint32_t count) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= count;
        loop assigns index;
        loop variant count - index;
    */
    for (index = 0U; index < count; ++index) {
        if (table[index] == observed_rip) {
            return 1;
        }
    }

    return 0;
}

/*@ assigns \result \from call_id;
    ensures \result == FBVBS_HOST_CALLER_CLASS_NONE ||
            \result == FBVBS_HOST_CALLER_CLASS_FBVBS ||
            \result == FBVBS_HOST_CALLER_CLASS_VMM;
*/
static uint8_t fbvbs_host_caller_class_for_call(uint16_t call_id) {
    if (fbvbs_is_vm_partition_call(call_id)) {
        return FBVBS_HOST_CALLER_CLASS_VMM;
    }
    if (fbvbs_is_host_partition_call(call_id) || fbvbs_is_service_call(call_id)) {
        return FBVBS_HOST_CALLER_CLASS_FBVBS;
    }

    return FBVBS_HOST_CALLER_CLASS_NONE;
}

/*@ requires \valid_read(state);
    assigns \result \from caller_class, state->host_callsites[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1];
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_host_callsite_table *fbvbs_find_host_callsite_table(
    const struct fbvbs_hypervisor_state *state,
    uint8_t caller_class
) {
    uint32_t index;

    if (state == NULL || caller_class == FBVBS_HOST_CALLER_CLASS_NONE) {
        return NULL;
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_HOST_CALLSITE_TABLES;
        loop assigns index;
        loop variant FBVBS_MAX_HOST_CALLSITE_TABLES - index;
    */
    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        if (state->host_callsites[index].active &&
            state->host_callsites[index].caller_class == caller_class) {
            return &state->host_callsites[index];
        }
    }
    return NULL;
}

/*@ requires \valid_read(state);
    assigns \result \from state, call_id, observed_rip,
            state->host_callsites[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1];
    ensures \result == OK || \result == CALLSITE_REJECTED;
*/
static int fbvbs_validate_host_callsite(
    const struct fbvbs_hypervisor_state *state,
    uint16_t call_id,
    uint64_t observed_rip
) {
    const struct fbvbs_host_callsite_table *table;
    uint8_t caller_class = fbvbs_host_caller_class_for_call(call_id);

    if (caller_class == FBVBS_HOST_CALLER_CLASS_NONE) {
        return OK;
    }
    table = fbvbs_find_host_callsite_table(state, caller_class);
    if (table == NULL || table->count == 0U || table->count > FBVBS_MAX_HOST_CALLSITE_ENTRIES) {
        return CALLSITE_REJECTED;
    }
    return fbvbs_rip_allowed(observed_rip, table->relocated_callsites, table->count) ? OK : CALLSITE_REJECTED;
}

/*@ requires \valid_read(state);
    requires \valid(owner) || owner == \null;
    assigns \result \from state, owner, call_id, observed_rip,
            state->host_callsites[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1];
    ensures \result == OK || \result == INVALID_CALLER || \result == CALLSITE_REJECTED ||
            \result == PERMISSION_DENIED;
*/
static int fbvbs_validate_caller_for_call(
    const struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *owner,
    uint16_t call_id,
    uint64_t observed_rip
) {
    uint16_t service_kind;
    uint64_t required_cap;

    /* Reject unowned command pages unconditionally: a NULL owner means the
       command page is not associated with any partition and must not be
       allowed to issue any call, including host-level ones. */
    if (owner == NULL) {
        return PERMISSION_DENIED;
    }

    /* Default-deny: reject unknown call_ids that have no capability mapping.
       This prevents new call_ids added to the dispatch switch from being
       accessible without explicit authorization if the capability table
       is not updated. */
    required_cap = fbvbs_required_capability_for_call(call_id);
    if (required_cap == 0ULL) {
        return INVALID_CALLER;
    }

    /* Enforce capability_mask: the calling partition must have the required
       capability bit set. This is checked for all partition kinds. */
    if ((owner->capability_mask & required_cap) == 0ULL) {
        return PERMISSION_DENIED;
    }

    if (call_id == FBVBS_CALL_MEMORY_SET_PERMISSION) {
        if (owner->kind != PARTITION_KIND_TRUSTED_SERVICE) {
            return INVALID_CALLER;
        }
        return OK;
    }

    service_kind = fbvbs_service_kind_for_call(call_id);
    if (service_kind != SERVICE_KIND_NONE) {
        if (owner->kind == PARTITION_KIND_FREEBSD_HOST) {
            return fbvbs_validate_host_callsite(state, call_id, observed_rip);
        }
        if (owner->kind != PARTITION_KIND_TRUSTED_SERVICE) {
            return INVALID_CALLER;
        }
        if (owner->service_kind != service_kind) {
            return INVALID_CALLER;
        }
        return OK;
    }

    if (fbvbs_is_host_partition_call(call_id) &&
        owner->kind != PARTITION_KIND_FREEBSD_HOST) {
        return INVALID_CALLER;
    }
    if (owner->kind == PARTITION_KIND_FREEBSD_HOST) {
        return fbvbs_validate_host_callsite(state, call_id, observed_rip);
    }

    return OK;
}

/*@ requires \valid_read(registers) || registers == \null;
    assigns \nothing;
    ensures \result == OK || \result == INVALID_PARAMETER;
    behavior null_args:
      assumes registers == \null;
      ensures \result == INVALID_PARAMETER;
*/
int fbvbs_validate_trap_registers(const struct fbvbs_trap_registers *registers) {
    if (registers == NULL) {
        return INVALID_PARAMETER;
    }
    if (registers->rbx != 0U || registers->rcx != 0U || registers->rdx != 0U) {
        return INVALID_PARAMETER;
    }
    if (!fbvbs_is_page_aligned(registers->rax)) {
        return INVALID_PARAMETER;
    }
    return OK;
}

/*@ requires \valid(page);
    requires \valid(registers);
    assigns *page, *registers;
    ensures page->actual_output_length == actual_output_length;
    ensures registers->rax == (uint64_t)(uint32_t)status;
    ensures registers->rbx == page->command_state;
    ensures registers->rcx == actual_output_length;
    ensures registers->rdx == 0U;
*/
static void fbvbs_finish_trap(
    struct fbvbs_command_page_v1 *page,
    struct fbvbs_trap_registers *registers,
    int status,
    uint32_t actual_output_length
) {
    page->actual_output_length = actual_output_length;
    page->command_state = (status == OK) ? COMPLETED : FAILED;
    registers->rax = (uint64_t)(uint32_t)status;
    registers->rbx = page->command_state;
    registers->rcx = actual_output_length;
    registers->rdx = 0U;
}

/*@ requires \valid_read(owner) || owner == \null;
    assigns \result \from owner, guest_physical_address, required_size;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_memory_mapping *fbvbs_find_owner_mapping(
    const struct fbvbs_partition *owner,
    uint64_t guest_physical_address,
    uint64_t required_size
) {
    uint64_t required_end;
    uint32_t index;

    if (owner == NULL) {
        return NULL;
    }
    required_end = guest_physical_address + required_size;
    if (required_end < guest_physical_address) {
        return NULL;
    }

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_MAPPINGS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_MAPPINGS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_MAPPINGS; ++index) {
        const struct fbvbs_memory_mapping *mapping = &owner->mappings[index];
        uint64_t mapping_end;

        if (!mapping->active) {
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

/*@ requires \valid_read(state);
    assigns \result \from state, memory_object_id,
            state->shared_objects[0 .. FBVBS_MAX_SHARED_OBJECTS - 1];
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_shared_registration *fbvbs_find_reserved_output_registration(
    const struct fbvbs_hypervisor_state *state,
    uint64_t memory_object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_SHARED_OBJECTS;
        loop assigns index;
        loop variant FBVBS_MAX_SHARED_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_SHARED_OBJECTS; ++index) {
        const struct fbvbs_shared_registration *registration = &state->shared_objects[index];

        if (!registration->active) {
            continue;
        }
        if (registration->memory_object_id != memory_object_id ||
            registration->peer_partition_id != 0U) {
            continue;
        }
        if ((registration->peer_permissions & FBVBS_MEMORY_PERMISSION_WRITE) == 0U ||
            registration->size < FBVBS_PAGE_SIZE) {
            continue;
        }
        return registration;
    }

    return NULL;
}

/*@ requires \valid_read(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns page->actual_output_length \from state, owner, *page, required_length;
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == INVALID_CALLER || \result == BUFFER_TOO_SMALL;
    ensures \result == OK && (page->flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) == 0U ==>
            required_length <= sizeof(page->body);
    ensures \result == OK && (page->flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) != 0U ==>
            required_length <= FBVBS_PAGE_SIZE;
*/
static int fbvbs_select_output_buffer(
    const struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition *owner,
    struct fbvbs_command_page_v1 *page,
    uint32_t required_length
) {
    if ((page->flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) != 0U) {
        const struct fbvbs_memory_mapping *mapping;
        const struct fbvbs_shared_registration *registration;

        if (page->output_page_gpa == 0U || !fbvbs_is_page_aligned(page->output_page_gpa)) {
            return INVALID_PARAMETER;
        }
        if (owner == NULL) {
            return INVALID_CALLER;
        }
        if (required_length > FBVBS_PAGE_SIZE || page->output_length_max < required_length) {
            page->actual_output_length = required_length;
            return BUFFER_TOO_SMALL;
        }
        mapping = fbvbs_find_owner_mapping(owner, page->output_page_gpa, FBVBS_PAGE_SIZE);
        if (mapping == NULL || (mapping->permissions & FBVBS_MEMORY_PERMISSION_WRITE) == 0U) {
            return INVALID_PARAMETER;
        }
        registration = fbvbs_find_reserved_output_registration(state, mapping->memory_object_id);
        if (registration == NULL) {
            return INVALID_PARAMETER;
        }
        return OK;
    }

    if (required_length > sizeof(page->body) || page->output_length_max < required_length) {
        page->actual_output_length = required_length;
        return BUFFER_TOO_SMALL;
    }

    return OK;
}

/*@ requires length == 0U || \valid(buffer + (0 .. length - 1));
    requires length == 0U || \valid_read(response + (0 .. length - 1));
    requires length == 0U || \separated(buffer + (0 .. length - 1), response + (0 .. length - 1));
    assigns buffer[0 .. length - 1];
    ensures \forall integer i; 0 <= i < length ==> buffer[i] == response[i];
*/
static void fbvbs_write_output_bytes(
    uint8_t *buffer,
    const uint8_t *response,
    uint32_t length
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= length;
        loop invariant \forall integer i; 0 <= i < index ==> buffer[i] == 0U;
        loop assigns index, buffer[0 .. length - 1];
        loop variant length - index;
    */
    for (index = 0U; index < length; ++index) {
        buffer[index] = 0U;
    }

    /*@ loop invariant 0 <= index <= length;
        loop invariant \forall integer i; 0 <= i < index ==> buffer[i] == response[i];
        loop assigns index, buffer[0 .. length - 1];
        loop variant length - index;
    */
    for (index = 0U; index < length; ++index) {
        buffer[index] = response[index];
    }
}

/*@ requires \valid_read(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == INVALID_CALLER || \result == BUFFER_TOO_SMALL;
*/
static int fbvbs_write_response(
    const struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition *owner,
    struct fbvbs_command_page_v1 *page,
    const uint8_t *response,
    uint32_t response_length
) {
    int status;

    status = fbvbs_select_output_buffer(state, owner, page, response_length);
    if (status != OK) {
        return status;
    }

#ifdef __FRAMAC__
    /* WP model: the byte copy involves two Typed-model-incompatible casts:
       1. response comes from (const uint8_t *)&struct_var (cross-type)
       2. GPA path uses (uint8_t *)(uintptr_t)output_page_gpa (GPA cast)
       The assigns clause covers page->body and actual_output_length.
       Copy correctness is verified independently in write_output_bytes. */
    (void)response;
#else
    if (response_length > 0U) {
        if ((page->flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) != 0U) {
            uint8_t *output_page = (uint8_t *)(uintptr_t)page->output_page_gpa;

            fbvbs_write_output_bytes(output_page, response, response_length);
        } else {
            fbvbs_write_output_bytes(page->body, response, response_length);
        }
    }
#endif

    page->actual_output_length = response_length;
    return OK;
}

/* ---- Per-command handler functions ----
 *
 * Each handler is independently verified by Frama-C WP.
 * Common contract: state and page are valid (established by dispatch preamble).
 */

#define HANDLER_CONTRACT \
    "requires \\valid(state);\n" \
    "requires \\valid(page);\n" \
    "requires \\valid_read(owner) || owner == \\null;\n" \
    "assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];\n"

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_partition_create(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_partition_create_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_partition_create_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_partition_create(state, (const struct fbvbs_partition_create_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_destroy(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_destroy(state, ((const struct fbvbs_partition_id_request *)page->body)->partition_id);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_partition_get_status(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_partition_status_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_partition_get_status(state, ((const struct fbvbs_partition_id_request *)page->body)->partition_id, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_quiesce(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_quiesce(state, ((const struct fbvbs_partition_id_request *)page->body)->partition_id);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_resume(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_resume(state, ((const struct fbvbs_partition_id_request *)page->body)->partition_id);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_partition_measure(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_partition_measure_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_partition_measure_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_partition_measure(state, (const struct fbvbs_partition_measure_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_load_image(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_partition_load_image_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_load_image(state, (const struct fbvbs_partition_load_image_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_start(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_start(state, ((const struct fbvbs_partition_id_request *)page->body)->partition_id);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_recover(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_partition_recover_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_recover(state, (const struct fbvbs_partition_recover_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_partition_get_fault_info(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_partition_fault_info_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_partition_get_fault_info(state, ((const struct fbvbs_partition_id_request *)page->body)->partition_id, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_memory_allocate_object(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_memory_allocate_object_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_memory_allocate_object_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_memory_allocate_object(
        state,
        (const struct fbvbs_memory_allocate_object_request *)page->body,
        &response,
        owner != NULL ? owner->partition_id : 0U
    );
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_memory_map(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    if (page->input_length != sizeof(struct fbvbs_memory_map_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_memory_map(
        state,
        (const struct fbvbs_memory_map_request *)page->body,
        owner != NULL ? owner->partition_id : 0U
    );
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_memory_unmap(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_memory_unmap_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_memory_unmap(state, (const struct fbvbs_memory_unmap_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_memory_set_permission(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    if (page->input_length != sizeof(struct fbvbs_memory_set_permission_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_memory_set_permission(
        state,
        (const struct fbvbs_memory_set_permission_request *)page->body,
        owner != NULL ? owner->partition_id : 0U
    );
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_memory_register_shared(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_memory_register_shared_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_memory_register_shared_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_memory_register_shared(state, (const struct fbvbs_memory_register_shared_request *)page->body, &response,
        owner != NULL ? owner->partition_id : 0U);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_memory_release_object(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    if (page->input_length != sizeof(struct fbvbs_memory_object_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_memory_release_object(
        state,
        ((const struct fbvbs_memory_object_id_request *)page->body)->memory_object_id,
        owner != NULL ? owner->partition_id : 0U
    );
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_memory_unregister_shared(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_shared_object_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_memory_unregister_shared(state, ((const struct fbvbs_shared_object_id_request *)page->body)->shared_object_id);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_kci_verify_module(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_verdict_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_kci_verify_module_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_kci_verify_module(state, (const struct fbvbs_kci_verify_module_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_kci_set_wx(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_kci_set_wx_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_kci_set_wx(state, (const struct fbvbs_kci_set_wx_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_kci_pin_cr(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_kci_pin_cr_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_kci_pin_cr(state, (const struct fbvbs_kci_pin_cr_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_kci_intercept_msr(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_kci_intercept_msr_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_kci_intercept_msr(state, (const struct fbvbs_kci_intercept_msr_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_ksi_create_target_set(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_ksi_target_set_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_ksi_create_target_set_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_ksi_create_target_set(state, (const struct fbvbs_ksi_create_target_set_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_register_tier_a(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_ksi_register_tier_a_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_register_tier_a(state, (const struct fbvbs_ksi_register_tier_a_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_register_tier_b(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_ksi_register_tier_b_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_register_tier_b(state, (const struct fbvbs_ksi_register_tier_b_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_modify_tier_b(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_ksi_modify_tier_b_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_modify_tier_b(state, (const struct fbvbs_ksi_modify_tier_b_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_register_pointer(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_ksi_register_pointer_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_register_pointer(state, (const struct fbvbs_ksi_register_pointer_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_ksi_validate_setuid(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_verdict_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_ksi_validate_setuid_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_ksi_validate_setuid(state, (const struct fbvbs_ksi_validate_setuid_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_ksi_allocate_ucred(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_ksi_allocate_ucred_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_ksi_allocate_ucred_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_ksi_allocate_ucred(state, (const struct fbvbs_ksi_allocate_ucred_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_replace_tier_b_object(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_ksi_replace_tier_b_object_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_replace_tier_b_object(state, (const struct fbvbs_ksi_replace_tier_b_object_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_unregister_object(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_memory_object_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_unregister_object(state, ((const struct fbvbs_memory_object_id_request *)page->body)->memory_object_id);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_iks_import_key(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_handle_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_iks_import_key_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_iks_import_key(state, (const struct fbvbs_iks_import_key_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_iks_sign(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_iks_sign_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_iks_sign_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_iks_sign(state, (const struct fbvbs_iks_sign_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_iks_key_exchange(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_handle_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_iks_key_exchange_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_iks_key_exchange(state, (const struct fbvbs_iks_key_exchange_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_iks_derive(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_handle_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_iks_derive_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_iks_derive(state, (const struct fbvbs_iks_derive_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_iks_destroy_key(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_handle_response)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_iks_destroy_key(state, ((const struct fbvbs_handle_response *)page->body)->handle);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_sks_import_dek(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_handle_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_sks_import_dek_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_sks_import_dek(state, (const struct fbvbs_sks_import_dek_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_sks_decrypt_batch(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_sks_batch_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_sks_batch_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_sks_decrypt_batch(state, (const struct fbvbs_sks_batch_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_sks_encrypt_batch(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_sks_batch_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_sks_batch_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_sks_encrypt_batch(state, (const struct fbvbs_sks_batch_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_sks_destroy_dek(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_handle_response)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_sks_destroy_dek(state, ((const struct fbvbs_handle_response *)page->body)->handle);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_uvs_verify_manifest_set(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_uvs_verify_manifest_set_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_uvs_verify_manifest_set_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_uvs_verify_manifest_set(state, (const struct fbvbs_uvs_verify_manifest_set_request *)page->body, &response);
    if (status == OK || status == SIGNATURE_INVALID || status == REVOKED ||
        status == GENERATION_MISMATCH || status == ROLLBACK_DETECTED ||
        status == DEPENDENCY_UNSATISFIED || status == SNAPSHOT_INCONSISTENT ||
        status == FRESHNESS_FAILED) {
        int write_status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
        if (write_status != OK) {
            status = write_status;
        }
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_uvs_verify_artifact(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_verdict_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_uvs_verify_artifact_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_uvs_verify_artifact(state, (const struct fbvbs_uvs_verify_artifact_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_uvs_check_revocation(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_uvs_check_revocation_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_uvs_check_revocation_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_uvs_check_revocation(state, (const struct fbvbs_uvs_check_revocation_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_vm_create(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_vm_create_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_vm_create_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_vm_create(state, (const struct fbvbs_vm_create_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_destroy(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_destroy(state, ((const struct fbvbs_partition_id_request *)page->body)->partition_id);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_vm_run(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_vm_run_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_vm_run_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_vm_run(state, (const struct fbvbs_vm_run_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_set_register(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_vm_register_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_set_register(state, (const struct fbvbs_vm_register_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_vm_get_register(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_vm_register_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_vm_register_read_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_vm_get_register(state, (const struct fbvbs_vm_register_read_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_map_memory(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    if (page->input_length != sizeof(struct fbvbs_vm_map_memory_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_map_memory(
        state,
        (const struct fbvbs_vm_map_memory_request *)page->body,
        owner != NULL ? owner->partition_id : 0U
    );
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_inject_interrupt(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_vm_inject_interrupt_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_inject_interrupt(state, (const struct fbvbs_vm_inject_interrupt_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_assign_device(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_vm_device_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_assign_device(state, (const struct fbvbs_vm_device_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_release_device(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    (void)owner;
    if (page->input_length != sizeof(struct fbvbs_vm_device_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_release_device(state, (const struct fbvbs_vm_device_request *)page->body);
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_vm_get_vcpu_status(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_vm_vcpu_status_response response = {0};
    int status;

    if (page->input_length != sizeof(struct fbvbs_vm_vcpu_status_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_vm_get_vcpu_status(state, (const struct fbvbs_vm_vcpu_status_request *)page->body, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_audit_get_mirror_info(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_audit_mirror_info_response response = {0};
    int status;

    if (page->input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_audit_get_mirror_info(state, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_audit_get_boot_id(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_audit_boot_id_response response = {0};

    if (page->input_length != 0U) {
        return INVALID_PARAMETER;
    }
    response.boot_id_hi = state->boot_id_hi;
    response.boot_id_lo = state->boot_id_lo;
    return fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_partition_list(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_diag_partition_list_response response = {0};
    uint32_t response_length = 0U;
    int status;

    if (page->input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_partition_list(state, &response, &response_length);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, response_length);
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_capabilities(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_diag_capabilities_response response = {0};
    int status;

    if (page->input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_capabilities(state, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, sizeof(response));
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_artifact_list(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_diag_artifact_list_response response = {0};
    uint32_t response_length = 0U;
    int status;

    if (page->input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_artifact_list(state, &response, &response_length);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, response_length);
    }
    return status;
}

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_device_list(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page) {
    struct fbvbs_diag_device_list_response response = {0};
    uint32_t response_length = 0U;
    int status;

    if (page->input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_device_list(state, &response, &response_length);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, (const uint8_t *)&response, response_length);
    }
    return status;
}

/* ---- Command dispatch (page is a parameter => assigns can reference it) ---- */

/*@ requires fbvbs_state_invariant(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, *page;
*/
static int fbvbs_dispatch_command(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition *owner,
    struct fbvbs_command_page_v1 *page
) {
    int status;

    /* Atomic READY -> EXECUTING transition to prevent TOCTOU race.
       Two vCPUs issuing the same command page GPA simultaneously will
       both pass validation, but only one will win the CAS here. */
#ifdef __FRAMAC__
    if (page->command_state != READY) {
        return RESOURCE_BUSY;
    }
    page->command_state = EXECUTING;
#else
    {
        uint32_t expected = READY;
        if (!__atomic_compare_exchange_n(
            &page->command_state, &expected, EXECUTING,
            0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            return RESOURCE_BUSY;
        }
    }
#endif
    page->actual_output_length = 0U;

    switch (page->call_id) {
        case FBVBS_CALL_PARTITION_CREATE:
            status = handle_partition_create(state, owner, page);
            break;
        case FBVBS_CALL_PARTITION_DESTROY:
            status = handle_partition_destroy(state, owner, page);
            break;
        case FBVBS_CALL_PARTITION_GET_STATUS:
            status = handle_partition_get_status(state, owner, page);
            break;
        case FBVBS_CALL_PARTITION_QUIESCE:
            status = handle_partition_quiesce(state, owner, page);
            break;
        case FBVBS_CALL_PARTITION_RESUME:
            status = handle_partition_resume(state, owner, page);
            break;
        case FBVBS_CALL_PARTITION_MEASURE:
            status = handle_partition_measure(state, owner, page);
            break;
        case FBVBS_CALL_PARTITION_LOAD_IMAGE:
            status = handle_partition_load_image(state, owner, page);
            break;
        case FBVBS_CALL_PARTITION_START:
            status = handle_partition_start(state, owner, page);
            break;
        case FBVBS_CALL_PARTITION_RECOVER:
            status = handle_partition_recover(state, owner, page);
            break;
        case FBVBS_CALL_PARTITION_GET_FAULT_INFO:
            status = handle_partition_get_fault_info(state, owner, page);
            break;
        case FBVBS_CALL_MEMORY_ALLOCATE_OBJECT:
            status = handle_memory_allocate_object(state, owner, page);
            break;
        case FBVBS_CALL_MEMORY_MAP:
            status = handle_memory_map(state, owner, page);
            break;
        case FBVBS_CALL_MEMORY_UNMAP:
            status = handle_memory_unmap(state, owner, page);
            break;
        case FBVBS_CALL_MEMORY_SET_PERMISSION:
            status = handle_memory_set_permission(state, owner, page);
            break;
        case FBVBS_CALL_MEMORY_REGISTER_SHARED:
            status = handle_memory_register_shared(state, owner, page);
            break;
        case FBVBS_CALL_MEMORY_RELEASE_OBJECT:
            status = handle_memory_release_object(state, owner, page);
            break;
        case FBVBS_CALL_MEMORY_UNREGISTER_SHARED:
            status = handle_memory_unregister_shared(state, owner, page);
            break;
        case FBVBS_CALL_KCI_VERIFY_MODULE:
            status = handle_kci_verify_module(state, owner, page);
            break;
        case FBVBS_CALL_KCI_SET_WX:
            status = handle_kci_set_wx(state, owner, page);
            break;
        case FBVBS_CALL_KCI_PIN_CR:
            status = handle_kci_pin_cr(state, owner, page);
            break;
        case FBVBS_CALL_KCI_INTERCEPT_MSR:
            status = handle_kci_intercept_msr(state, owner, page);
            break;
        case FBVBS_CALL_KSI_CREATE_TARGET_SET:
            status = handle_ksi_create_target_set(state, owner, page);
            break;
        case FBVBS_CALL_KSI_REGISTER_TIER_A:
            status = handle_ksi_register_tier_a(state, owner, page);
            break;
        case FBVBS_CALL_KSI_REGISTER_TIER_B:
            status = handle_ksi_register_tier_b(state, owner, page);
            break;
        case FBVBS_CALL_KSI_MODIFY_TIER_B:
            status = handle_ksi_modify_tier_b(state, owner, page);
            break;
        case FBVBS_CALL_KSI_REGISTER_POINTER:
            status = handle_ksi_register_pointer(state, owner, page);
            break;
        case FBVBS_CALL_KSI_VALIDATE_SETUID:
            status = handle_ksi_validate_setuid(state, owner, page);
            break;
        case FBVBS_CALL_KSI_ALLOCATE_UCRED:
            status = handle_ksi_allocate_ucred(state, owner, page);
            break;
        case FBVBS_CALL_KSI_REPLACE_TIER_B_OBJECT:
            status = handle_ksi_replace_tier_b_object(state, owner, page);
            break;
        case FBVBS_CALL_KSI_UNREGISTER_OBJECT:
            status = handle_ksi_unregister_object(state, owner, page);
            break;
        case FBVBS_CALL_IKS_IMPORT_KEY:
            status = handle_iks_import_key(state, owner, page);
            break;
        case FBVBS_CALL_IKS_SIGN:
            status = handle_iks_sign(state, owner, page);
            break;
        case FBVBS_CALL_IKS_KEY_EXCHANGE:
            status = handle_iks_key_exchange(state, owner, page);
            break;
        case FBVBS_CALL_IKS_DERIVE:
            status = handle_iks_derive(state, owner, page);
            break;
        case FBVBS_CALL_IKS_DESTROY_KEY:
            status = handle_iks_destroy_key(state, owner, page);
            break;
        case FBVBS_CALL_SKS_IMPORT_DEK:
            status = handle_sks_import_dek(state, owner, page);
            break;
        case FBVBS_CALL_SKS_DECRYPT_BATCH:
            status = handle_sks_decrypt_batch(state, owner, page);
            break;
        case FBVBS_CALL_SKS_ENCRYPT_BATCH:
            status = handle_sks_encrypt_batch(state, owner, page);
            break;
        case FBVBS_CALL_SKS_DESTROY_DEK:
            status = handle_sks_destroy_dek(state, owner, page);
            break;
        case FBVBS_CALL_UVS_VERIFY_MANIFEST_SET:
            status = handle_uvs_verify_manifest_set(state, owner, page);
            break;
        case FBVBS_CALL_UVS_VERIFY_ARTIFACT:
            status = handle_uvs_verify_artifact(state, owner, page);
            break;
        case FBVBS_CALL_UVS_CHECK_REVOCATION:
            status = handle_uvs_check_revocation(state, owner, page);
            break;
        case FBVBS_CALL_VM_CREATE:
            status = handle_vm_create(state, owner, page);
            break;
        case FBVBS_CALL_VM_DESTROY:
            status = handle_vm_destroy(state, owner, page);
            break;
        case FBVBS_CALL_VM_RUN:
            status = handle_vm_run(state, owner, page);
            break;
        case FBVBS_CALL_VM_SET_REGISTER:
            status = handle_vm_set_register(state, owner, page);
            break;
        case FBVBS_CALL_VM_GET_REGISTER:
            status = handle_vm_get_register(state, owner, page);
            break;
        case FBVBS_CALL_VM_MAP_MEMORY:
            status = handle_vm_map_memory(state, owner, page);
            break;
        case FBVBS_CALL_VM_INJECT_INTERRUPT:
            status = handle_vm_inject_interrupt(state, owner, page);
            break;
        case FBVBS_CALL_VM_ASSIGN_DEVICE:
            status = handle_vm_assign_device(state, owner, page);
            break;
        case FBVBS_CALL_VM_RELEASE_DEVICE:
            status = handle_vm_release_device(state, owner, page);
            break;
        case FBVBS_CALL_VM_GET_VCPU_STATUS:
            status = handle_vm_get_vcpu_status(state, owner, page);
            break;
        case FBVBS_CALL_AUDIT_GET_MIRROR_INFO:
            status = handle_audit_get_mirror_info(state, owner, page);
            break;
        case FBVBS_CALL_AUDIT_GET_BOOT_ID:
            status = handle_audit_get_boot_id(state, owner, page);
            break;
        case FBVBS_CALL_DIAG_GET_PARTITION_LIST:
            status = handle_diag_get_partition_list(state, owner, page);
            break;
        case FBVBS_CALL_DIAG_GET_CAPABILITIES:
            status = handle_diag_get_capabilities(state, owner, page);
            break;
        case FBVBS_CALL_DIAG_GET_ARTIFACT_LIST:
            status = handle_diag_get_artifact_list(state, owner, page);
            break;
        case FBVBS_CALL_DIAG_GET_DEVICE_LIST:
            status = handle_diag_get_device_list(state, owner, page);
            break;
        default:
            status = NOT_SUPPORTED_ON_PLATFORM;
            break;
    }

    return status;
}

/* ---- Hypercall entry point ---- */

/*@ requires \valid(state) || state == \null;
    requires state != \null ==> fbvbs_state_invariant(state);
    requires \valid(registers) || registers == \null;
    requires state != \null && registers != \null ==> \separated(state, registers);
    assigns *state, *registers;
    behavior null_args:
      assumes state == \null || registers == \null;
      assigns \nothing;
      ensures \result == INVALID_PARAMETER;
*/
int fbvbs_dispatch_hypercall(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_trap_registers *registers
) {
    struct fbvbs_command_page_v1 *page;
    struct fbvbs_partition *owner;
    uint32_t owner_vcpu_id = 0U;
    uint64_t observed_rip = 0U;
    uint64_t page_gpa;
    int status;

    if (state == NULL || registers == NULL) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_validate_trap_registers(registers);
    if (status != OK) {
        return status;
    }

    page_gpa = registers->rax;

    /* Hardening: reject null and misaligned command page GPAs.
       Command pages are 4096-byte structures and must be page-aligned.
       An attacker could inject a misaligned GPA via registers->rax
       to force cross-page structure access or null dereference. */
    if (page_gpa == 0U || (page_gpa & (FBVBS_PAGE_SIZE - 1U)) != 0U) {
        return INVALID_PARAMETER;
    }

#ifdef __FRAMAC__
    /* WP model: resolve GPA to a typed pointer via partition lookup.
       At runtime, the GPA is directly cast to a pointer (identity-mapped).
       WP's Typed model cannot reason about GPA-derived pointers, so we
       find the command page through the partition array instead. */
    {
        uint32_t _p, _v;
        page = NULL;
        /*@ loop invariant 0 <= _p <= FBVBS_MAX_PARTITIONS;
            loop invariant page == \null || \valid(page);
            loop assigns _p, _v, page;
            loop variant FBVBS_MAX_PARTITIONS - _p;
        */
        for (_p = 0U; _p < FBVBS_MAX_PARTITIONS; ++_p) {
            if (!state->partitions[_p].occupied) continue;
            /*@ loop invariant 0 <= _v <= FBVBS_MAX_VCPUS;
                loop invariant page == \null || \valid(page);
                loop assigns _v, page;
                loop variant FBVBS_MAX_VCPUS - _v;
            */
            for (_v = 0U; _v < state->partitions[_p].vcpu_count && _v < FBVBS_MAX_VCPUS; ++_v) {
                if ((uint64_t)(uintptr_t)&state->partitions[_p].command_pages[_v].page == page_gpa) {
                    page = &state->partitions[_p].command_pages[_v].page;
                    break;
                }
            }
            if (page != NULL) break;
        }
    }
#else
    page = (struct fbvbs_command_page_v1 *)(uintptr_t)page_gpa;
#endif
    if (page == NULL) {
        return INVALID_PARAMETER;
    }
    /*@ assert \valid(page); */
    /*@ assert \valid(registers); */
    /*@ assert fbvbs_state_invariant(state); */

    status = fbvbs_validate_command_page(page);
    if (status != OK) {
        fbvbs_finish_trap(page, registers, status, page->actual_output_length);
        return status;
    }
    owner = fbvbs_find_command_page_owner(state, page_gpa, &owner_vcpu_id);
    if (owner != NULL && owner_vcpu_id < owner->vcpu_count && owner_vcpu_id < FBVBS_MAX_VCPUS) {
        observed_rip = owner->vcpus[owner_vcpu_id].rip;
    }
    status = fbvbs_validate_caller_for_call(state, owner, page->call_id, observed_rip);
    if (status != OK) {
        fbvbs_finish_trap(page, registers, status, page->actual_output_length);
        return status;
    }
    status = fbvbs_validate_command_sequence(state, page_gpa, page);
    if (status != OK) {
        fbvbs_finish_trap(page, registers, status, page->actual_output_length);
        return status;
    }

    status = fbvbs_dispatch_command(state, owner, page);
    fbvbs_finish_trap(page, registers, status, page->actual_output_length);
    return status;
}
