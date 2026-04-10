/* FBVBS Hypercall Command Dispatch
 *
 * Requirements: REQ-0205 (hypercall ABI), REQ-0206 (未使用領域ゼロ化),
 *   REQ-0207 (trap レジスタ規約), REQ-0208 (ABI version check),
 *   REQ-0209 (caller_sequence), REQ-0210 (command page 状態機械),
 *   REQ-0902 (未分類 exit fail-closed)
 */
#include "fbvbs_hypervisor.h"

/*@ assigns *lock; */
static void fbvbs_command_tracker_lock(volatile uint32_t *lock)
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

/*@ assigns *lock; */
static void fbvbs_command_tracker_unlock(volatile uint32_t *lock)
{
#ifndef __FRAMAC__
    __sync_lock_release(lock);
#else
    if (lock != NULL) {
        *lock = 0U;
    }
#endif
}

/*@ assigns *lock; */
static void fbvbs_hypercall_guard_lock(volatile uint32_t *lock)
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

/*@ assigns *lock; */
static void fbvbs_hypercall_guard_unlock(volatile uint32_t *lock)
{
#ifndef __FRAMAC__
    __sync_lock_release(lock);
#else
    if (lock != NULL) {
        *lock = 0U;
    }
#endif
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_is_policy_deny_status(int status)
{
    return (status == PERMISSION_DENIED ||
            status == INVALID_CALLER ||
            status == CALLSITE_REJECTED ||
            status == POLICY_DENIED ||
            status == INVALID_PARAMETER ||
            status == ABI_VERSION_UNSUPPORTED ||
            status == REPLAY_DETECTED);
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_is_critical_policy_deny_status(int status)
{
    return (status == INVALID_CALLER ||
            status == CALLSITE_REJECTED ||
            status == REPLAY_DETECTED ||
            status == POLICY_DENIED);
}

/*@ assigns \nothing; */
uint32_t fbvbs_policy_deny_reason_from_status(int status)
{
    switch (status) {
        case INVALID_PARAMETER:
            return FBVBS_DENY_REASON_INVALID_PARAMETER;
        case ABI_VERSION_UNSUPPORTED:
            return FBVBS_DENY_REASON_ABI_VERSION;
        case PERMISSION_DENIED:
            return FBVBS_DENY_REASON_PERMISSION;
        case INVALID_CALLER:
            return FBVBS_DENY_REASON_INVALID_CALLER;
        case CALLSITE_REJECTED:
            return FBVBS_DENY_REASON_CALLSITE;
        case POLICY_DENIED:
            return FBVBS_DENY_REASON_POLICY;
        case REPLAY_DETECTED:
            return FBVBS_DENY_REASON_REPLAY;
        case RETRY_LATER:
            return FBVBS_DENY_REASON_BUSY;
        default:
            return FBVBS_DENY_REASON_UNSPECIFIED;
    }
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_counts_as_policy_deny(uint32_t deny_reason)
{
    return deny_reason != FBVBS_DENY_REASON_BUSY;
}

static void fbvbs_note_rate_limit_retry(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *owner,
    uint64_t command_page_gpa,
    uint16_t call_id
);

/*@ assigns \nothing; */
static void fbvbs_audit_policy_deny(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition *owner,
    uint64_t command_page_gpa,
    uint16_t call_id,
    int status,
    uint32_t deny_reason,
    uint32_t deny_count_snapshot,
    uint32_t lockout_windows_snapshot
)
{
    struct fbvbs_audit_policy_deny_event event;
    uint16_t severity;

    if (state == NULL || !fbvbs_is_policy_deny_status(status)) {
        return;
    }

    severity = (status == REPLAY_DETECTED ||
                status == CALLSITE_REJECTED ||
                status == INVALID_CALLER)
        ? FBVBS_SEVERITY_ERROR
        : FBVBS_SEVERITY_WARNING;

    event = (struct fbvbs_audit_policy_deny_event){
        .partition_id = (owner != NULL) ? owner->partition_id : 0U,
        .command_page_gpa = command_page_gpa,
        .call_id = call_id,
        .status = (uint32_t)status,
        .deny_reason = deny_reason,
        .deny_count = deny_count_snapshot,
        .lockout_windows = lockout_windows_snapshot,
        .reserved0 = 0U,
    };

    (void)fbvbs_log_append_rate_limited(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        severity,
        FBVBS_EVENT_POLICY_DENY,
        (const uint8_t *)&event,
        (uint32_t)sizeof(event)
    );
}

/*@ assigns \nothing; */
static void fbvbs_note_policy_deny(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *owner,
    uint64_t command_page_gpa,
    uint16_t call_id,
    int status,
    uint32_t deny_reason
)
{
    uint32_t deny_count_snapshot = 0U;
    uint32_t critical_deny_count_snapshot = 0U;
    uint32_t lockout_windows_snapshot = 0U;
    uint64_t partition_id_snapshot = 0U;
    int should_fault_partition = 0;

    if (!fbvbs_is_policy_deny_status(status)) {
        return;
    }
    if (deny_reason == FBVBS_DENY_REASON_UNSPECIFIED) {
        deny_reason = fbvbs_policy_deny_reason_from_status(status);
    }

    if (state != NULL && owner != NULL) {
        fbvbs_hypercall_guard_lock(&state->hypercall_guard_lock);
        if (fbvbs_counts_as_policy_deny(deny_reason) != 0 &&
            owner->policy_deny_count != UINT32_MAX) {
            owner->policy_deny_count += 1U;
        }
        if (fbvbs_is_critical_policy_deny_status(status) != 0 &&
            owner->critical_policy_deny_count != UINT32_MAX) {
            owner->critical_policy_deny_count += 1U;
        }
        deny_count_snapshot = owner->policy_deny_count;
        critical_deny_count_snapshot = owner->critical_policy_deny_count;
        lockout_windows_snapshot = owner->hypercall_lockout_windows;
        partition_id_snapshot = owner->partition_id;
        if (fbvbs_is_critical_policy_deny_status(status) != 0 &&
            critical_deny_count_snapshot >= FBVBS_POLICY_DENY_THRESHOLD_FOR_FAULT &&
            owner->state != FBVBS_PARTITION_STATE_FAULTED) {
            should_fault_partition = 1;
        }
        fbvbs_hypercall_guard_unlock(&state->hypercall_guard_lock);
    }

    fbvbs_audit_policy_deny(
        state,
        owner,
        command_page_gpa,
        call_id,
        status,
        deny_reason,
        deny_count_snapshot,
        lockout_windows_snapshot
    );

    if (should_fault_partition != 0 && partition_id_snapshot != 0U) {
        int fault_status = fbvbs_partition_fault(
            state,
            partition_id_snapshot,
            FBVBS_FAULT_POLICY_DENY_THRESHOLD,
            FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
            (uint64_t)critical_deny_count_snapshot,
            (uint64_t)call_id
        );
        if (fault_status != OK && state != NULL) {
            struct fbvbs_audit_partition_fault_event failure_event;

            failure_event = (struct fbvbs_audit_partition_fault_event){0};
            failure_event.partition_id = partition_id_snapshot;
            failure_event.fault_code = FBVBS_FAULT_POLICY_DENY_THRESHOLD;
            failure_event.source_component = FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR;
            failure_event.detail0 = (uint64_t)critical_deny_count_snapshot;
            failure_event.detail1 = (uint64_t)(uint32_t)fault_status;
            (void)fbvbs_log_append(
                state,
                0U,
                FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                FBVBS_SEVERITY_CRITICAL,
                FBVBS_EVENT_PARTITION_FAULT,
                (const uint8_t *)(const void *)&failure_event,
                (uint32_t)sizeof(failure_event)
            );
        }
    }
}

/*@ assigns \nothing; */
static void fbvbs_audit_rate_limit_retry(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition *owner,
    uint64_t command_page_gpa,
    uint16_t call_id,
    uint32_t deny_count_snapshot,
    uint32_t lockout_windows_snapshot
) {
    struct fbvbs_audit_policy_deny_event event;

    if (state == NULL) {
        return;
    }

    event = (struct fbvbs_audit_policy_deny_event){
        .partition_id = (owner != NULL) ? owner->partition_id : 0U,
        .command_page_gpa = command_page_gpa,
        .call_id = call_id,
        .status = (uint32_t)RETRY_LATER,
        .deny_reason = FBVBS_DENY_REASON_RATE_LIMIT,
        .deny_count = deny_count_snapshot,
        .lockout_windows = lockout_windows_snapshot,
        .reserved0 = 0U,
    };

    (void)fbvbs_log_append_rate_limited(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        FBVBS_SEVERITY_WARNING,
        FBVBS_EVENT_POLICY_DENY,
        (const uint8_t *)&event,
        (uint32_t)sizeof(event)
    );
}

/*@ assigns \nothing; */
static void fbvbs_note_rate_limit_retry(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *owner,
    uint64_t command_page_gpa,
    uint16_t call_id
) {
    uint32_t deny_count_snapshot = 0U;
    uint32_t lockout_windows_snapshot = 0U;

    if (state != NULL && owner != NULL) {
        fbvbs_hypercall_guard_lock(&state->hypercall_guard_lock);
        if (owner->policy_deny_count != UINT32_MAX) {
            owner->policy_deny_count += 1U;
        }
        deny_count_snapshot = owner->policy_deny_count;
        lockout_windows_snapshot = owner->hypercall_lockout_windows;
        fbvbs_hypercall_guard_unlock(&state->hypercall_guard_lock);
    }

    fbvbs_audit_rate_limit_retry(
        state,
        owner,
        command_page_gpa,
        call_id,
        deny_count_snapshot,
        lockout_windows_snapshot
    );
}

/*@ requires \valid(state);
    requires \valid(owner);
    assigns state->hypercall_dispatch_counter,
            owner->hypercall_window_start,
            owner->hypercall_window_count,
            owner->hypercall_lockout_windows;
    ensures \result == OK || \result == RETRY_LATER;
*/
static int fbvbs_enforce_hypercall_abuse_guard(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *owner
)
{
    uint32_t owner_window_position;

    if (state->hypercall_dispatch_counter == UINT32_MAX) {
        state->hypercall_dispatch_counter = 1U;
    } else {
        state->hypercall_dispatch_counter += 1U;
    }

    owner_window_position = owner->hypercall_window_start;
    if (owner_window_position == UINT32_MAX ||
        owner_window_position >= FBVBS_HYPERCALL_WINDOW_CALLS) {
        owner->hypercall_window_start = 0U;
        owner->hypercall_window_count = 0U;
        if (owner->hypercall_lockout_windows != 0U) {
            owner->hypercall_lockout_windows -= 1U;
        }
    }

    owner->hypercall_window_start += 1U;

    if (owner->hypercall_lockout_windows != 0U) {
        return RETRY_LATER;
    }
    if (owner->hypercall_window_count >= FBVBS_HYPERCALL_MAX_CALLS_PER_WINDOW) {
        owner->hypercall_lockout_windows = FBVBS_HYPERCALL_LOCKOUT_WINDOWS;
        return RETRY_LATER;
    }

    owner->hypercall_window_count += 1U;
    return OK;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_is_page_aligned(uint64_t value) {
    return (value & (FBVBS_PAGE_SIZE - 1U)) == 0U;
}

/*@ requires \valid_read(page) || page == \null;
    assigns \nothing;
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == ABI_VERSION_UNSUPPORTED || \result == RETRY_LATER;
    behavior null_page:
      assumes page == \null;
      ensures \result == INVALID_PARAMETER;
*/
static int fbvbs_validate_command_page(
    const struct fbvbs_command_page_v1 *page,
    uint32_t cached_input_length
) {
    uint16_t cached_flags;
    uint64_t cached_output_gpa;
    uint16_t reserved_flags;
    uint32_t index;

    if (page == NULL) {
        return INVALID_PARAMETER;
    }

    /* TOCTOU hardening: cache flags once from guest-accessible memory.
       All subsequent flag checks use this cached copy. */
    cached_flags = page->flags;
    cached_output_gpa = page->output_page_gpa;
    reserved_flags = (uint16_t)(cached_flags & (uint16_t)(~FBVBS_CMD_FLAG_SEPARATE_OUTPUT));
    if (page->abi_version != FBVBS_ABI_VERSION) {
        return ABI_VERSION_UNSUPPORTED;
    }
    if (page->reserved0 != 0U) {
        return INVALID_PARAMETER;
    }
    if (page->actual_output_length != 0U) {
        return INVALID_PARAMETER;
    }
    if (cached_input_length > sizeof(page->body)) {
        return INVALID_PARAMETER;
    }
    /*@ loop invariant cached_input_length <= index <= sizeof(page->body);
        loop invariant \forall integer i; (integer)cached_input_length <= i < (integer)index ==> page->body[i] == 0U;
        loop assigns index;
        loop variant sizeof(page->body) - index;
    */
    for (index = cached_input_length; index < sizeof(page->body); ++index) {
        if (page->body[index] != 0U) {
            return INVALID_PARAMETER;
        }
    }
    if (reserved_flags != 0U) {
        return INVALID_PARAMETER;
    }
    if ((cached_flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) == 0U && cached_output_gpa != 0U) {
        return INVALID_PARAMETER;
    }
    if ((cached_flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) != 0U && !fbvbs_is_page_aligned(cached_output_gpa)) {
        return INVALID_PARAMETER;
    }
    if (page->command_state == EXECUTING) {
        return RETRY_LATER;
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
    assigns state->command_trackers[0 .. FBVBS_MAX_COMMAND_TRACKERS - 1];
    ensures \result == OK || \result == RESOURCE_EXHAUSTED || \result == REPLAY_DETECTED;
*/
static int fbvbs_validate_command_sequence(
    struct fbvbs_hypervisor_state *state,
    uint64_t page_gpa,
    uint64_t cached_caller_sequence,
    uint64_t cached_caller_nonce
) {
    struct fbvbs_command_tracker *tracker;

    tracker = fbvbs_get_command_tracker(state, page_gpa);
    if (tracker == NULL) {
        return RESOURCE_EXHAUSTED;
    }
    /* TOCTOU hardening: use cached copies of caller_sequence/caller_nonce
       (snapshotted once from guest-accessible memory in dispatch). */
    if (tracker->sequence_seen && cached_caller_sequence <= tracker->last_sequence) {
        return REPLAY_DETECTED;
    }

    (void)cached_caller_nonce;
    return OK;
}

/*@ requires \valid(state);
    assigns state->command_trackers[0 .. FBVBS_MAX_COMMAND_TRACKERS - 1];
    ensures \result == OK || \result == RESOURCE_EXHAUSTED || \result == REPLAY_DETECTED;
*/
static int fbvbs_commit_command_sequence(
    struct fbvbs_hypervisor_state *state,
    uint64_t page_gpa,
    uint64_t cached_caller_sequence,
    uint64_t cached_caller_nonce
) {
    struct fbvbs_command_tracker *tracker;

    tracker = fbvbs_get_command_tracker(state, page_gpa);
    if (tracker == NULL) {
        return RESOURCE_EXHAUSTED;
    }
    if (tracker->sequence_seen && cached_caller_sequence <= tracker->last_sequence) {
        return REPLAY_DETECTED;
    }

    tracker->sequence_seen = true;
    tracker->last_sequence = cached_caller_sequence;
    tracker->last_nonce = cached_caller_nonce;
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
            \result == SERVICE_KIND_UVS ||
            \result == SERVICE_KIND_OCS;
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
        case FBVBS_CALL_OCS_VCD_ATTACH:
        case FBVBS_CALL_OCS_VCD_STATUS:
            return SERVICE_KIND_OCS;
        default:
            return SERVICE_KIND_NONE;
    }
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_storage_call_allows_tenant_owner(uint16_t call_id) {
    switch (call_id) {
        case FBVBS_CALL_STORAGE_ATTACH_VDISK:
        case FBVBS_CALL_STORAGE_DETACH_VDISK:
        case FBVBS_CALL_STORAGE_GET_VDISK_STATUS:
            return 1;
        default:
            return 0;
    }
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_diag_call_allowed_for_service(
    uint16_t call_id,
    const struct fbvbs_partition *owner
) {
    if (owner == NULL || owner->kind != PARTITION_KIND_TRUSTED_SERVICE) {
        return 0;
    }

    switch (owner->service_kind) {
        case SERVICE_KIND_KCI:
            if ((owner->capability_mask & (FBVBS_CAP_KCI_ACCESS | FBVBS_CAP_AUDIT_DIAG)) !=
                (FBVBS_CAP_KCI_ACCESS | FBVBS_CAP_AUDIT_DIAG)) {
                return 0;
            }
            switch (call_id) {
                case FBVBS_CALL_DIAG_GET_PARTITION_LIST:
                case FBVBS_CALL_DIAG_GET_CAPABILITIES:
                case FBVBS_CALL_DIAG_GET_ARTIFACT_LIST:
                case FBVBS_CALL_DIAG_GET_DEVICE_LIST:
                case FBVBS_CALL_DIAG_GET_REASON_GUIDANCE:
                case FBVBS_CALL_DIAG_GET_INVENTORY:
                case FBVBS_CALL_DIAG_GET_FAULT_RECORD:
                case FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY:
                case FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION:
                case FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES:
                case FBVBS_CALL_DIAG_GET_SCALING_LIMITS:
                    return 1;
                default:
                    return 0;
            }
        case SERVICE_KIND_OCS:
            if ((owner->capability_mask & (FBVBS_CAP_OCS_ACCESS | FBVBS_CAP_AUDIT_DIAG)) !=
                (FBVBS_CAP_OCS_ACCESS | FBVBS_CAP_AUDIT_DIAG)) {
                return 0;
            }
            switch (call_id) {
                case FBVBS_CALL_DIAG_GET_PARTITION_LIST:
                case FBVBS_CALL_DIAG_GET_REASON_GUIDANCE:
                case FBVBS_CALL_DIAG_GET_INVENTORY:
                case FBVBS_CALL_DIAG_GET_FAULT_RECORD:
                    return 1;
                default:
                    return 0;
            }
        default:
            return 0;
    }
}

/*@ assigns \nothing;
    ensures \result == 0ULL ||
            \result == FBVBS_CAP_PARTITION_MANAGE ||
            \result == FBVBS_CAP_MEMORY_MAP ||
            \result == FBVBS_CAP_MEMORY_PERMISSION_SET ||
            \result == FBVBS_CAP_SHARED_MEMORY_REGISTER ||
            \result == FBVBS_CAP_KCI_ACCESS ||
            \result == FBVBS_CAP_KSI_ACCESS ||
            \result == FBVBS_CAP_IKS_ACCESS ||
            \result == FBVBS_CAP_SKS_ACCESS ||
            \result == FBVBS_CAP_UVS_ACCESS ||
            \result == FBVBS_CAP_VM_MANAGE ||
            \result == FBVBS_CAP_AUDIT_DIAG ||
            \result == FBVBS_CAP_STORAGE_MANAGE ||
            \result == FBVBS_CAP_SCALE_MANAGE ||
            \result == FBVBS_CAP_OCS_ACCESS;
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
        case FBVBS_CALL_DIAG_GET_REASON_GUIDANCE:
        case FBVBS_CALL_DIAG_GET_INVENTORY:
        case FBVBS_CALL_DIAG_GET_FAULT_RECORD:
        case FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY:
        case FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION:
        case FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES:
        case FBVBS_CALL_DIAG_GET_SCALING_LIMITS:
            return FBVBS_CAP_AUDIT_DIAG;
        case FBVBS_CALL_DIAG_SET_SCALING_LIMITS:
            return FBVBS_CAP_SCALE_MANAGE;
        case FBVBS_CALL_OCS_VCD_ATTACH:
        case FBVBS_CALL_OCS_VCD_STATUS:
            return FBVBS_CAP_OCS_ACCESS;
        case FBVBS_CALL_STORAGE_CREATE_POOL:
        case FBVBS_CALL_STORAGE_DESTROY_POOL:
        case FBVBS_CALL_STORAGE_CREATE_VDISK:
        case FBVBS_CALL_STORAGE_DESTROY_VDISK:
        case FBVBS_CALL_STORAGE_ATTACH_VDISK:
        case FBVBS_CALL_STORAGE_DETACH_VDISK:
        case FBVBS_CALL_STORAGE_GET_POOL_STATUS:
        case FBVBS_CALL_STORAGE_GET_VDISK_STATUS:
        case FBVBS_CALL_STORAGE_SET_VDISK_QOS:
        case FBVBS_CALL_STORAGE_REPORT_CORRUPTION:
            return FBVBS_CAP_STORAGE_MANAGE;
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
        case FBVBS_CALL_DIAG_GET_REASON_GUIDANCE:
        case FBVBS_CALL_DIAG_GET_INVENTORY:
        case FBVBS_CALL_DIAG_GET_FAULT_RECORD:
        case FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY:
        case FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION:
        case FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES:
        case FBVBS_CALL_DIAG_GET_SCALING_LIMITS:
        case FBVBS_CALL_DIAG_SET_SCALING_LIMITS:
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

/*@ assigns \nothing;
    ensures \result == 0 ||
            (\result & ~(FBVBS_COMMAND_CLASS_HOST_PARTITION |
                         FBVBS_COMMAND_CLASS_VM_PARTITION |
                         FBVBS_COMMAND_CLASS_SERVICE)) == 0;
*/
static uint32_t fbvbs_command_class_flags_for_call(uint16_t call_id) {
    uint32_t flags = 0U;

    if (fbvbs_is_host_partition_call(call_id) != 0) {
        flags |= FBVBS_COMMAND_CLASS_HOST_PARTITION;
    }
    if (fbvbs_is_vm_partition_call(call_id) != 0) {
        flags |= FBVBS_COMMAND_CLASS_VM_PARTITION;
    }
    if (fbvbs_is_service_call(call_id) != 0) {
        flags |= FBVBS_COMMAND_CLASS_SERVICE;
    }
    return flags;
}

/*@ requires \valid(response);
    assigns *response;
    ensures \result == OK;
*/
static int fbvbs_diag_negotiate_command_version(
    uint16_t target_call_id,
    uint32_t requested_abi_version,
    struct fbvbs_diag_command_version_response *response
) {
    struct fbvbs_diag_schema_registry_response schema_registry = {0};
    uint64_t required_capability_mask;

    *response = (struct fbvbs_diag_command_version_response){0};
    response->target_call_id = target_call_id;
    required_capability_mask = fbvbs_required_capability_for_call(target_call_id);
    if (required_capability_mask == 0ULL) {
        response->negotiation_status = FBVBS_NEGOTIATION_STATUS_UNSUPPORTED_CALL;
        return OK;
    }

    response->minimum_abi_version = FBVBS_ABI_VERSION;
    response->maximum_abi_version = FBVBS_ABI_VERSION;
    response->command_class_flags = fbvbs_command_class_flags_for_call(target_call_id);
    response->service_kind = fbvbs_service_kind_for_call(target_call_id);
    response->required_capability_mask = required_capability_mask;
    response->supported_feature_flags =
        FBVBS_COMMAND_FEATURE_CALLER_SEQUENCE_REQUIRED |
        FBVBS_COMMAND_FEATURE_CALLER_NONCE_REQUIRED |
        FBVBS_COMMAND_FEATURE_SEPARATE_OUTPUT_SUPPORTED |
        FBVBS_COMMAND_FEATURE_RESERVED_ZERO_REQUIRED |
        FBVBS_COMMAND_FEATURE_REPLAY_PROTECTION;
    response->required_feature_flags =
        FBVBS_COMMAND_FEATURE_CALLER_SEQUENCE_REQUIRED |
        FBVBS_COMMAND_FEATURE_CALLER_NONCE_REQUIRED |
        FBVBS_COMMAND_FEATURE_RESERVED_ZERO_REQUIRED |
        FBVBS_COMMAND_FEATURE_REPLAY_PROTECTION;
    if (fbvbs_is_host_partition_call(target_call_id) != 0) {
        response->supported_feature_flags |= FBVBS_COMMAND_FEATURE_HOST_CALLSITE_VALIDATION;
        response->required_feature_flags |= FBVBS_COMMAND_FEATURE_HOST_CALLSITE_VALIDATION;
    }
    if (fbvbs_diag_get_schema_registry(&schema_registry) == OK) {
        response->compatibility_flags = schema_registry.compatibility_flags;
    }

    response->negotiated_abi_version = FBVBS_ABI_VERSION;
    if (requested_abi_version == 0U) {
        response->negotiation_status = FBVBS_NEGOTIATION_STATUS_COMPATIBLE_FALLBACK;
    } else if (requested_abi_version == FBVBS_ABI_VERSION) {
        response->negotiation_status = FBVBS_NEGOTIATION_STATUS_EXACT;
    } else {
        response->negotiation_status = FBVBS_NEGOTIATION_STATUS_UNSUPPORTED_VERSION;
        response->negotiated_abi_version = 0U;
    }

    return OK;
}

/*@ requires \valid_read(state);
    assigns \nothing;
*/
static uint64_t fbvbs_guest_feature_bitmap_for_partition_kind(
    const struct fbvbs_hypervisor_state *state,
    uint16_t partition_kind
) {
    uint64_t flags;

    if (partition_kind != PARTITION_KIND_GUEST_VM) {
        return 0ULL;
    }

    flags = FBVBS_GUEST_FEATURE_VCPU_REGISTER_ACCESS |
            FBVBS_GUEST_FEATURE_MEMORY_MAP |
            FBVBS_GUEST_FEATURE_INTERRUPT_INJECTION |
            FBVBS_GUEST_FEATURE_VDISK_ATTACH;
    if ((state->capability_bitmap1 & CAP_BITMAP1_MEASURED_BOOT) != 0ULL) {
        flags |= FBVBS_GUEST_FEATURE_MEASURED_BOOT;
    }
    if ((state->capability_bitmap1 & CAP_BITMAP1_IOMMU) != 0ULL) {
        flags |= FBVBS_GUEST_FEATURE_DEVICE_ASSIGNMENT;
    }
    return flags;
}

/*@ requires \valid_read(state);
    assigns \nothing;
*/
static uint64_t fbvbs_required_guest_feature_bitmap_for_partition_kind(
    const struct fbvbs_hypervisor_state *state,
    uint16_t partition_kind
) {
    uint64_t required = 0ULL;

    if (partition_kind != PARTITION_KIND_GUEST_VM) {
        return 0ULL;
    }
    required =
        FBVBS_GUEST_FEATURE_VCPU_REGISTER_ACCESS |
        FBVBS_GUEST_FEATURE_MEMORY_MAP;
    if ((state->capability_bitmap1 & CAP_BITMAP1_MEASURED_BOOT) != 0ULL) {
        required |= FBVBS_GUEST_FEATURE_MEASURED_BOOT;
    }
    return required;
}

/*@ requires \valid_read(state);
    requires \valid(response);
    assigns *response;
    ensures \result == OK;
*/
static int fbvbs_diag_negotiate_guest_features(
    const struct fbvbs_hypervisor_state *state,
    uint16_t partition_kind,
    uint32_t requested_abi_version,
    uint64_t requested_feature_bitmap,
    struct fbvbs_diag_guest_feature_response *response
) {
    struct fbvbs_diag_schema_registry_response schema_registry = {0};
    uint64_t supported_bitmap;
    uint64_t required_bitmap;
    uint64_t negotiated_bitmap;

    *response = (struct fbvbs_diag_guest_feature_response){0};
    response->partition_kind = partition_kind;
    response->minimum_abi_version = FBVBS_ABI_VERSION;
    response->maximum_abi_version = FBVBS_ABI_VERSION;

    supported_bitmap = fbvbs_guest_feature_bitmap_for_partition_kind(state, partition_kind);
    required_bitmap = fbvbs_required_guest_feature_bitmap_for_partition_kind(state, partition_kind);
    response->supported_feature_bitmap = supported_bitmap;
    response->required_feature_bitmap = required_bitmap;
    if (fbvbs_diag_get_schema_registry(&schema_registry) == OK) {
        response->compatibility_flags = schema_registry.compatibility_flags;
    }

    if (partition_kind != PARTITION_KIND_GUEST_VM) {
        response->negotiation_status = FBVBS_NEGOTIATION_STATUS_UNSUPPORTED_PROFILE;
        return OK;
    }

    if (requested_abi_version == 0U) {
        response->negotiated_abi_version = FBVBS_ABI_VERSION;
        response->negotiation_status = FBVBS_NEGOTIATION_STATUS_COMPATIBLE_FALLBACK;
        response->negotiated_feature_bitmap = supported_bitmap;
        return OK;
    }
    if (requested_abi_version != FBVBS_ABI_VERSION) {
        response->negotiation_status = FBVBS_NEGOTIATION_STATUS_UNSUPPORTED_VERSION;
        return OK;
    }

    if (requested_feature_bitmap == 0ULL) {
        response->negotiated_abi_version = FBVBS_ABI_VERSION;
        response->negotiation_status = FBVBS_NEGOTIATION_STATUS_COMPATIBLE_FALLBACK;
        response->negotiated_feature_bitmap = supported_bitmap;
        return OK;
    }

    negotiated_bitmap = requested_feature_bitmap & supported_bitmap;
    negotiated_bitmap |= required_bitmap;
    response->denied_feature_bitmap = requested_feature_bitmap & ~supported_bitmap;
    response->negotiated_feature_bitmap = negotiated_bitmap;
    response->negotiated_abi_version = FBVBS_ABI_VERSION;
    if (response->denied_feature_bitmap != 0ULL ||
        (requested_feature_bitmap & required_bitmap) != required_bitmap) {
        response->negotiation_status = FBVBS_NEGOTIATION_STATUS_COMPATIBLE_FALLBACK;
    } else {
        response->negotiation_status = FBVBS_NEGOTIATION_STATUS_EXACT;
    }

    return OK;
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
        if (!(owner->kind == PARTITION_KIND_GUEST_VM &&
              fbvbs_storage_call_allows_tenant_owner(call_id) != 0)) {
            return PERMISSION_DENIED;
        }
    }

    if (call_id == FBVBS_CALL_MEMORY_SET_PERMISSION) {
        if (owner->kind != PARTITION_KIND_TRUSTED_SERVICE) {
            return INVALID_CALLER;
        }
        return OK;
    }

    service_kind = fbvbs_service_kind_for_call(call_id);
    if (service_kind != SERVICE_KIND_NONE) {
        if (service_kind == SERVICE_KIND_OCS &&
            owner->kind == PARTITION_KIND_FREEBSD_HOST) {
            return INVALID_CALLER;
        }
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
        if (fbvbs_diag_call_allowed_for_service(call_id, owner) != 0) {
            return OK;
        }
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
    uint64_t owner_partition_id,
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
            registration->owner_partition_id != owner_partition_id ||
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
    ensures \result == OK && (cached_flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) == 0U ==>
            required_length <= sizeof(page->body);
    ensures \result == OK && (cached_flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) != 0U ==>
            required_length <= FBVBS_PAGE_SIZE;
*/
static int fbvbs_select_output_buffer(
    const struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition *owner,
    struct fbvbs_command_page_v1 *page,
    uint32_t required_length,
    uint64_t cached_output_gpa,
    uint16_t cached_flags
) {
    if ((cached_flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) != 0U) {
        const struct fbvbs_memory_mapping *mapping;
        const struct fbvbs_shared_registration *registration;

        if (cached_output_gpa == 0U || !fbvbs_is_page_aligned(cached_output_gpa)) {
            return INVALID_PARAMETER;
        }
        if (owner == NULL) {
            return INVALID_CALLER;
        }
        if (required_length > FBVBS_PAGE_SIZE || page->output_length_max < required_length) {
            page->actual_output_length = required_length;
            return BUFFER_TOO_SMALL;
        }
        mapping = fbvbs_find_owner_mapping(owner, cached_output_gpa, FBVBS_PAGE_SIZE);
        if (mapping == NULL || (mapping->permissions & FBVBS_MEMORY_PERMISSION_WRITE) == 0U) {
            return INVALID_PARAMETER;
        }
        registration = fbvbs_find_reserved_output_registration(
            state,
            owner->partition_id,
            mapping->memory_object_id
        );
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
        loop invariant \forall integer i; 0 <= i < index ==> buffer[i] == response[i];
        loop assigns index, buffer[0 .. length - 1];
        loop variant length - index;
    */
    for (index = 0U; index < length; ++index) {
        buffer[index] = response[index];
    }
}

/*@ requires \valid_read(page);
    requires request_size == 0U ||
             \valid(((uint8_t *)destination) + (0 .. request_size - 1));
    requires request_size <= sizeof(page->body);
    requires request_size == 0U ||
             \separated(((uint8_t *)destination) + (0 .. request_size - 1),
                        page->body + (0 .. request_size - 1));
    assigns ((uint8_t *)destination)[0 .. request_size - 1];
*/
static void fbvbs_read_request_bytes(
    const struct fbvbs_command_page_v1 *page,
    void *destination,
    uint32_t request_size
) {
    fbvbs_copy_memory(destination, page->body, request_size);
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
    const void *response,
    uint32_t response_length
) {
    int status;
    /* TOCTOU hardening: cache output_page_gpa and flags once from
       guest-accessible memory.  A concurrent vCPU could mutate these
       fields between validation (select_output_buffer) and use (the
       write below).  Both paths use these cached copies. */
    uint64_t cached_output_gpa = page->output_page_gpa;
    uint16_t cached_flags = page->flags;

    status = fbvbs_select_output_buffer(state, owner, page, response_length,
                                        cached_output_gpa, cached_flags);
    if (status != OK) {
        return status;
    }

    const uint8_t *response_bytes = (const uint8_t *)response;

    if (response_length > 0U) {
        if ((cached_flags & FBVBS_CMD_FLAG_SEPARATE_OUTPUT) != 0U) {
            uint8_t *output_page = (uint8_t *)(uintptr_t)cached_output_gpa;

            fbvbs_write_output_bytes(output_page, response_bytes, response_length);
        } else {
            fbvbs_write_output_bytes(page->body, response_bytes, response_length);
        }
    }

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

#define FBVBS_READ_REQUEST(type, name) \
    type name = (type){0}; \
    fbvbs_read_request_bytes(page, &name, (uint32_t)sizeof(name))

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_partition_create(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_create_request, request);
    struct fbvbs_partition_create_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_partition_create_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_partition_create(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_destroy(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_id_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_destroy(state, request.partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_partition_get_status(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_id_request, request);
    struct fbvbs_partition_status_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_partition_get_status(state, request.partition_id, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_quiesce(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_id_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_quiesce(state, request.partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_resume(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_id_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_resume(state, request.partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_partition_measure(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_measure_request, request);
    struct fbvbs_partition_measure_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_partition_measure_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_partition_measure(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_load_image(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_load_image_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_partition_load_image_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_load_image(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_start(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_id_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_partition_start(state, request.partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_partition_recover(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_recover_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_partition_recover_request)) {
        return INVALID_PARAMETER;
    }
    if (request.session_correlation_id != page->caller_sequence ||
        request.confirmation_nonce != page->caller_nonce) {
        return POLICY_DENIED;
    }
    return fbvbs_partition_recover(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_partition_get_fault_info(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_id_request, request);
    struct fbvbs_partition_fault_info_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_partition_get_fault_info(state, request.partition_id, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_memory_allocate_object(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_memory_allocate_object_request, request);
    struct fbvbs_memory_allocate_object_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_memory_allocate_object_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_memory_allocate_object(
        state,
        &request,
        &response,
        owner != NULL ? owner->partition_id : 0U
    );
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_memory_map(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_memory_map_request, request);
    if (cached_input_length != sizeof(struct fbvbs_memory_map_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_memory_map(
        state,
        &request,
        owner != NULL ? owner->partition_id : 0U
    );
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_memory_unmap(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_memory_unmap_request, request);
    if (cached_input_length != sizeof(struct fbvbs_memory_unmap_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_memory_unmap(
        state,
        &request,
        owner != NULL ? owner->partition_id : 0U
    );
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_memory_set_permission(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_memory_set_permission_request, request);
    if (cached_input_length != sizeof(struct fbvbs_memory_set_permission_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_memory_set_permission(
        state,
        &request,
        owner != NULL ? owner->partition_id : 0U
    );
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_memory_register_shared(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_memory_register_shared_request, request);
    struct fbvbs_memory_register_shared_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_memory_register_shared_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_memory_register_shared(
        state,
        &request,
        &response,
        owner != NULL ? owner->partition_id : 0U
    );
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_memory_release_object(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_memory_object_id_request, request);
    if (cached_input_length != sizeof(struct fbvbs_memory_object_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_memory_release_object(
        state,
        request.memory_object_id,
        owner != NULL ? owner->partition_id : 0U
    );
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_memory_unregister_shared(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_shared_object_id_request, request);
    if (cached_input_length != sizeof(struct fbvbs_shared_object_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_memory_unregister_shared(
        state,
        request.shared_object_id,
        owner != NULL ? owner->partition_id : 0U
    );
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_kci_verify_module(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_kci_verify_module_request, request);
    struct fbvbs_verdict_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_kci_verify_module_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_kci_verify_module(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_kci_set_wx(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_kci_set_wx_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_kci_set_wx_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_kci_set_wx(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_kci_pin_cr(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_kci_pin_cr_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_kci_pin_cr_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_kci_pin_cr(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_kci_intercept_msr(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_kci_intercept_msr_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_kci_intercept_msr_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_kci_intercept_msr(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_ksi_create_target_set(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_ksi_create_target_set_request, request);
    struct fbvbs_ksi_target_set_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_ksi_create_target_set_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_ksi_create_target_set(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_register_tier_a(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_ksi_register_tier_a_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_ksi_register_tier_a_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_register_tier_a(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_register_tier_b(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_ksi_register_tier_b_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_ksi_register_tier_b_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_register_tier_b(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_modify_tier_b(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_ksi_modify_tier_b_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_ksi_modify_tier_b_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_modify_tier_b(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_register_pointer(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_ksi_register_pointer_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_ksi_register_pointer_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_register_pointer(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_ksi_validate_setuid(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_ksi_validate_setuid_request, request);
    struct fbvbs_verdict_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_ksi_validate_setuid_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_ksi_validate_setuid(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_ksi_allocate_ucred(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_ksi_allocate_ucred_request, request);
    struct fbvbs_ksi_allocate_ucred_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_ksi_allocate_ucred_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_ksi_allocate_ucred(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_replace_tier_b_object(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_ksi_replace_tier_b_object_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_ksi_replace_tier_b_object_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_replace_tier_b_object(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ksi_unregister_object(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_memory_object_id_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_memory_object_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_ksi_unregister_object(state, request.memory_object_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_iks_import_key(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_iks_import_key_request, request);
    struct fbvbs_handle_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_iks_import_key_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_iks_import_key(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_iks_sign(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_iks_sign_request, request);
    struct fbvbs_iks_sign_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_iks_sign_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_iks_sign(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_iks_key_exchange(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_iks_key_exchange_request, request);
    struct fbvbs_handle_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_iks_key_exchange_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_iks_key_exchange(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_iks_derive(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_iks_derive_request, request);
    struct fbvbs_handle_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_iks_derive_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_iks_derive(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_iks_destroy_key(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_handle_response, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_handle_response)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_iks_destroy_key(state, request.handle);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_sks_import_dek(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_sks_import_dek_request, request);
    struct fbvbs_handle_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_sks_import_dek_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_sks_import_dek(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_sks_decrypt_batch(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_sks_batch_request, request);
    struct fbvbs_sks_batch_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_sks_batch_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_sks_decrypt_batch(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_sks_encrypt_batch(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_sks_batch_request, request);
    struct fbvbs_sks_batch_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_sks_batch_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_sks_encrypt_batch(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_sks_destroy_dek(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_handle_response, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_handle_response)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_sks_destroy_dek(state, request.handle);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_uvs_verify_manifest_set(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_uvs_verify_manifest_set_request, request);
    struct fbvbs_uvs_verify_manifest_set_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_uvs_verify_manifest_set_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_uvs_verify_manifest_set(state, &request, &response);
    if (status == OK || status == SIGNATURE_INVALID || status == REVOKED ||
        status == GENERATION_MISMATCH || status == ROLLBACK_DETECTED ||
        status == DEPENDENCY_UNSATISFIED || status == SNAPSHOT_INCONSISTENT ||
        status == FRESHNESS_FAILED) {
        int write_status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
        if (write_status != OK) {
            status = write_status;
        }
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_uvs_verify_artifact(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_uvs_verify_artifact_request, request);
    struct fbvbs_verdict_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_uvs_verify_artifact_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_uvs_verify_artifact(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_uvs_check_revocation(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_uvs_check_revocation_request, request);
    struct fbvbs_uvs_check_revocation_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_uvs_check_revocation_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_uvs_check_revocation(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_vm_create(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_vm_create_request, request);
    struct fbvbs_vm_create_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_vm_create_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_vm_create(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_destroy(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_id_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_destroy(state, request.partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_vm_run(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_vm_run_request, request);
    struct fbvbs_vm_run_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_vm_run_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_vm_run(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_set_register(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_vm_register_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_vm_register_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_set_register(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_vm_get_register(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_vm_register_read_request, request);
    struct fbvbs_vm_register_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_vm_register_read_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_vm_get_register(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_map_memory(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_vm_map_memory_request, request);
    if (cached_input_length != sizeof(struct fbvbs_vm_map_memory_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_map_memory(
        state,
        &request,
        owner != NULL ? owner->partition_id : 0U
    );
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_inject_interrupt(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_vm_inject_interrupt_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_vm_inject_interrupt_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_inject_interrupt(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_assign_device(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_vm_device_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_vm_device_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_assign_device(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_vm_release_device(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_vm_device_request, request);
    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_vm_device_request)) {
        return INVALID_PARAMETER;
    }
    return fbvbs_vm_release_device(state, &request);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_vm_get_vcpu_status(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_vm_vcpu_status_request, request);
    struct fbvbs_vm_vcpu_status_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_vm_vcpu_status_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_vm_get_vcpu_status(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_audit_get_mirror_info(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_audit_mirror_info_response response = {0};
    int status;

    if (cached_input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_audit_get_mirror_info(state, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_audit_get_boot_id(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_audit_boot_id_response response = {0};

    if (cached_input_length != 0U) {
        return INVALID_PARAMETER;
    }
    response.boot_id_hi = state->boot_id_hi;
    response.boot_id_lo = state->boot_id_lo;
    return fbvbs_write_response(state, owner, page, &response, sizeof(response));
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_partition_list(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_diag_partition_list_response response = {0};
    uint32_t response_length = 0U;
    int status;

    if (cached_input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_partition_list(state, &response, &response_length);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, response_length);
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_capabilities(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_diag_capabilities_response response = {0};
    int status;

    if (cached_input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_capabilities(state, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_artifact_list(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_diag_artifact_list_response response = {0};
    uint32_t response_length = 0U;
    int status;

    if (cached_input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_artifact_list(state, &response, &response_length);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, response_length);
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_device_list(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_diag_device_list_response response = {0};
    uint32_t response_length = 0U;
    int status;

    if (cached_input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_device_list(state, &response, &response_length);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, response_length);
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_scaling_limits(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_diag_scaling_limits_response response = {0};
    int status;

    if (cached_input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_scaling_limits(state, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_reason_guidance(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_diag_reason_guidance_request, request);
    struct fbvbs_diag_reason_guidance_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_diag_reason_guidance_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_reason_guidance(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_inventory(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_diag_inventory_response response = {0};
    int status;

    if (cached_input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_inventory(state, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_fault_record(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_partition_id_request, request);
    struct fbvbs_diag_fault_record_response response = {0};
    int status;

    if (cached_input_length != sizeof(struct fbvbs_partition_id_request)) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_fault_record(state, request.partition_id, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_get_schema_registry(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_diag_schema_registry_response response = {0};
    int status;

    (void)state;
    if (cached_input_length != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_get_schema_registry(&response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_negotiate_command_version(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_diag_command_version_request, request);
    struct fbvbs_diag_command_version_response response = {0};
    int status;

    (void)state;
    if (cached_input_length != sizeof(struct fbvbs_diag_command_version_request)) {
        return INVALID_PARAMETER;
    }
    if (request.reserved0 != 0U || request.reserved1 != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_negotiate_command_version(
        request.target_call_id,
        request.requested_abi_version,
        &response
    );
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_negotiate_guest_features(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_diag_guest_feature_request, request);
    struct fbvbs_diag_guest_feature_response response = {0};
    int status;

    (void)owner;
    if (cached_input_length != sizeof(struct fbvbs_diag_guest_feature_request)) {
        return INVALID_PARAMETER;
    }
    if (request.reserved0 != 0U) {
        return INVALID_PARAMETER;
    }
    status = fbvbs_diag_negotiate_guest_features(
        state,
        request.partition_kind,
        request.requested_abi_version,
        request.requested_feature_bitmap,
        &response
    );
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_diag_set_scaling_limits(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_diag_set_scaling_limits_request, request);
    struct fbvbs_diag_scaling_limits_response response = {0};
    int status;

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != sizeof(struct fbvbs_diag_set_scaling_limits_request)) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_diag_set_scaling_limits(state, &request, &response);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_ocs_vcd_attach(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_ocs_vcd_attach_request, request);

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != sizeof(struct fbvbs_ocs_vcd_attach_request)) {
        return INVALID_PARAMETER;
    }

    return fbvbs_ocs_vcd_attach(state, &request, owner->partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_ocs_vcd_status(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_ocs_vcd_status_response response = {0};
    int status;

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != 0U) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_ocs_vcd_status(state, &response, owner->partition_id);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_storage_create_pool(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_storage_pool_create_request, request);
    struct fbvbs_storage_pool_create_response response = {0};
    int status;

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != sizeof(struct fbvbs_storage_pool_create_request)) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_storage_create_pool(state, &request, &response, owner->partition_id);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_storage_destroy_pool(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_storage_pool_destroy_request request = {0};

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length == sizeof(struct fbvbs_storage_pool_destroy_request)) {
        fbvbs_read_request_bytes(page, &request, (uint32_t)sizeof(request));
        if (request.reserved0 != 0U || request.reserved1 != 0U) {
            return INVALID_PARAMETER;
        }
        if (request.session_correlation_id != page->caller_sequence ||
            request.confirmation_nonce != page->caller_nonce) {
            return POLICY_DENIED;
        }
    } else if (cached_input_length == sizeof(struct fbvbs_storage_pool_request)) {
        struct fbvbs_storage_pool_request legacy_request = {0};

        fbvbs_read_request_bytes(page, &legacy_request, (uint32_t)sizeof(legacy_request));
        request.pool_id = legacy_request.pool_id;
        request.session_correlation_id = page->caller_sequence;
        request.confirmation_nonce = page->caller_nonce;
    } else {
        return INVALID_PARAMETER;
    }

    return fbvbs_storage_destroy_pool(state, &request, owner->partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_storage_create_vdisk(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_storage_vdisk_create_request, request);
    struct fbvbs_storage_vdisk_create_response response = {0};
    int status;

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != sizeof(struct fbvbs_storage_vdisk_create_request)) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_storage_create_vdisk(state, &request, &response, owner->partition_id);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_storage_destroy_vdisk(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    struct fbvbs_storage_vdisk_destroy_request request = {0};

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length == sizeof(struct fbvbs_storage_vdisk_destroy_request)) {
        fbvbs_read_request_bytes(page, &request, (uint32_t)sizeof(request));
        if (request.reserved0 != 0U || request.reserved1 != 0U) {
            return INVALID_PARAMETER;
        }
        if (request.session_correlation_id != page->caller_sequence ||
            request.confirmation_nonce != page->caller_nonce) {
            return POLICY_DENIED;
        }
    } else if (cached_input_length == sizeof(struct fbvbs_storage_vdisk_request)) {
        struct fbvbs_storage_vdisk_request legacy_request = {0};

        fbvbs_read_request_bytes(page, &legacy_request, (uint32_t)sizeof(legacy_request));
        request.vdisk_id = legacy_request.vdisk_id;
        request.session_correlation_id = page->caller_sequence;
        request.confirmation_nonce = page->caller_nonce;
    } else {
        return INVALID_PARAMETER;
    }

    return fbvbs_storage_destroy_vdisk(state, &request, owner->partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_storage_attach_vdisk(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_storage_vdisk_attach_request, request);

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != sizeof(struct fbvbs_storage_vdisk_attach_request)) {
        return INVALID_PARAMETER;
    }

    return fbvbs_storage_attach_vdisk(state, &request, owner->partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_storage_detach_vdisk(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_storage_vdisk_request, request);

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != sizeof(struct fbvbs_storage_vdisk_request)) {
        return INVALID_PARAMETER;
    }

    return fbvbs_storage_detach_vdisk(state, &request, owner->partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_storage_get_pool_status(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_storage_pool_request, request);
    struct fbvbs_storage_pool_status_response response = {0};
    int status;

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != sizeof(struct fbvbs_storage_pool_request)) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_storage_get_pool_status(state, &request, &response, owner->partition_id);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->actual_output_length, page->body[0 .. sizeof(page->body) - 1];
*/
static int handle_storage_get_vdisk_status(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_storage_vdisk_request, request);
    struct fbvbs_storage_vdisk_status_response response = {0};
    int status;

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != sizeof(struct fbvbs_storage_vdisk_request)) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_storage_get_vdisk_status(state, &request, &response, owner->partition_id);
    if (status == OK) {
        status = fbvbs_write_response(state, owner, page, &response, sizeof(response));
    }
    return status;
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_storage_set_vdisk_qos(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_storage_vdisk_qos_request, request);

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != sizeof(struct fbvbs_storage_vdisk_qos_request)) {
        return INVALID_PARAMETER;
    }

    return fbvbs_storage_set_vdisk_qos(state, &request, owner->partition_id);
}

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state;
*/
static int handle_storage_report_corruption(struct fbvbs_hypervisor_state *state, const struct fbvbs_partition *owner, struct fbvbs_command_page_v1 *page, uint32_t cached_input_length) {
    FBVBS_READ_REQUEST(struct fbvbs_storage_vdisk_corruption_request, request);

    if (owner == NULL) {
        return PERMISSION_DENIED;
    }
    if (cached_input_length != sizeof(struct fbvbs_storage_vdisk_corruption_request)) {
        return INVALID_PARAMETER;
    }

    return fbvbs_storage_report_vdisk_corruption(state, &request, owner->partition_id);
}

/* ---- Command dispatch (page is a parameter => assigns can reference it) ---- */

/*@ requires \valid(state);
    requires \valid(page);
    requires \valid_read(owner) || owner == \null;
    assigns *state, page->command_state, page->actual_output_length,
            page->body[0 .. sizeof(page->body) - 1];
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == INVALID_CALLER || \result == BUFFER_TOO_SMALL ||
            \result == RESOURCE_BUSY || \result == RETRY_LATER || \result == PERMISSION_DENIED ||
            \result == NOT_SUPPORTED_ON_PLATFORM || \result == RESOURCE_EXHAUSTED ||
            \result == REPLAY_DETECTED;
*/
static int fbvbs_dispatch_command(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition *owner,
    struct fbvbs_command_page_v1 *page,
    uint16_t cached_call_id,         /* TOCTOU: cached from page->call_id */
    uint32_t cached_input_length     /* TOCTOU: cached from page->input_length */
) {
    int status;
    uint64_t required_cap;

    /* Defense-in-depth capability check using the same switch-based
     * function as validate_caller_for_call.  Uses cached_call_id to
     * prevent TOCTOU — a concurrent vCPU could modify page->call_id
     * between the authorization check and the dispatch switch below. */
    required_cap = fbvbs_required_capability_for_call(cached_call_id);
    if (required_cap != 0ULL && owner != NULL &&
                (owner->capability_mask & required_cap) == 0ULL &&
                !(owner->kind == PARTITION_KIND_GUEST_VM &&
                    fbvbs_storage_call_allows_tenant_owner(cached_call_id) != 0)) {
        return PERMISSION_DENIED;
    }

    /* Atomic READY -> EXECUTING transition to prevent TOCTOU race.
       Two vCPUs issuing the same command page GPA simultaneously will
       both pass validation, but only one will win the CAS here. */
#ifdef __FRAMAC__
    if (page->command_state != READY) {
        return RETRY_LATER;
    }
    page->command_state = EXECUTING;
#else
    {
        uint32_t expected = READY;
        if (!__atomic_compare_exchange_n(
            &page->command_state, &expected, EXECUTING,
            0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            return RETRY_LATER;
        }
    }
#endif
    page->actual_output_length = 0U;

    switch (cached_call_id) {
        case FBVBS_CALL_PARTITION_CREATE:
            status = handle_partition_create(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_PARTITION_DESTROY:
            status = handle_partition_destroy(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_PARTITION_GET_STATUS:
            status = handle_partition_get_status(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_PARTITION_QUIESCE:
            status = handle_partition_quiesce(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_PARTITION_RESUME:
            status = handle_partition_resume(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_PARTITION_MEASURE:
            status = handle_partition_measure(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_PARTITION_LOAD_IMAGE:
            status = handle_partition_load_image(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_PARTITION_START:
            status = handle_partition_start(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_PARTITION_RECOVER:
            status = handle_partition_recover(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_PARTITION_GET_FAULT_INFO:
            status = handle_partition_get_fault_info(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_MEMORY_ALLOCATE_OBJECT:
            status = handle_memory_allocate_object(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_MEMORY_MAP:
            status = handle_memory_map(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_MEMORY_UNMAP:
            status = handle_memory_unmap(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_MEMORY_SET_PERMISSION:
            status = handle_memory_set_permission(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_MEMORY_REGISTER_SHARED:
            status = handle_memory_register_shared(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_MEMORY_RELEASE_OBJECT:
            status = handle_memory_release_object(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_MEMORY_UNREGISTER_SHARED:
            status = handle_memory_unregister_shared(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KCI_VERIFY_MODULE:
            status = handle_kci_verify_module(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KCI_SET_WX:
            status = handle_kci_set_wx(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KCI_PIN_CR:
            status = handle_kci_pin_cr(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KCI_INTERCEPT_MSR:
            status = handle_kci_intercept_msr(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KSI_CREATE_TARGET_SET:
            status = handle_ksi_create_target_set(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KSI_REGISTER_TIER_A:
            status = handle_ksi_register_tier_a(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KSI_REGISTER_TIER_B:
            status = handle_ksi_register_tier_b(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KSI_MODIFY_TIER_B:
            status = handle_ksi_modify_tier_b(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KSI_REGISTER_POINTER:
            status = handle_ksi_register_pointer(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KSI_VALIDATE_SETUID:
            status = handle_ksi_validate_setuid(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KSI_ALLOCATE_UCRED:
            status = handle_ksi_allocate_ucred(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KSI_REPLACE_TIER_B_OBJECT:
            status = handle_ksi_replace_tier_b_object(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_KSI_UNREGISTER_OBJECT:
            status = handle_ksi_unregister_object(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_IKS_IMPORT_KEY:
            status = handle_iks_import_key(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_IKS_SIGN:
            status = handle_iks_sign(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_IKS_KEY_EXCHANGE:
            status = handle_iks_key_exchange(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_IKS_DERIVE:
            status = handle_iks_derive(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_IKS_DESTROY_KEY:
            status = handle_iks_destroy_key(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_SKS_IMPORT_DEK:
            status = handle_sks_import_dek(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_SKS_DECRYPT_BATCH:
            status = handle_sks_decrypt_batch(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_SKS_ENCRYPT_BATCH:
            status = handle_sks_encrypt_batch(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_SKS_DESTROY_DEK:
            status = handle_sks_destroy_dek(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_UVS_VERIFY_MANIFEST_SET:
            status = handle_uvs_verify_manifest_set(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_UVS_VERIFY_ARTIFACT:
            status = handle_uvs_verify_artifact(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_UVS_CHECK_REVOCATION:
            status = handle_uvs_check_revocation(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_VM_CREATE:
            status = handle_vm_create(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_VM_DESTROY:
            status = handle_vm_destroy(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_VM_RUN:
            status = handle_vm_run(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_VM_SET_REGISTER:
            status = handle_vm_set_register(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_VM_GET_REGISTER:
            status = handle_vm_get_register(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_VM_MAP_MEMORY:
            status = handle_vm_map_memory(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_VM_INJECT_INTERRUPT:
            status = handle_vm_inject_interrupt(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_VM_ASSIGN_DEVICE:
            status = handle_vm_assign_device(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_VM_RELEASE_DEVICE:
            status = handle_vm_release_device(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_VM_GET_VCPU_STATUS:
            status = handle_vm_get_vcpu_status(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_AUDIT_GET_MIRROR_INFO:
            status = handle_audit_get_mirror_info(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_AUDIT_GET_BOOT_ID:
            status = handle_audit_get_boot_id(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_GET_PARTITION_LIST:
            status = handle_diag_get_partition_list(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_GET_CAPABILITIES:
            status = handle_diag_get_capabilities(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_GET_ARTIFACT_LIST:
            status = handle_diag_get_artifact_list(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_GET_DEVICE_LIST:
            status = handle_diag_get_device_list(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_GET_SCALING_LIMITS:
            status = handle_diag_get_scaling_limits(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_GET_REASON_GUIDANCE:
            status = handle_diag_get_reason_guidance(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_GET_INVENTORY:
            status = handle_diag_get_inventory(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_GET_FAULT_RECORD:
            status = handle_diag_get_fault_record(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_NEGOTIATE_COMMAND_VERSION:
            status = handle_diag_negotiate_command_version(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_NEGOTIATE_GUEST_FEATURES:
            status = handle_diag_negotiate_guest_features(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_GET_SCHEMA_REGISTRY:
            status = handle_diag_get_schema_registry(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_DIAG_SET_SCALING_LIMITS:
            status = handle_diag_set_scaling_limits(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_OCS_VCD_ATTACH:
            status = handle_ocs_vcd_attach(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_OCS_VCD_STATUS:
            status = handle_ocs_vcd_status(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_STORAGE_CREATE_POOL:
            status = handle_storage_create_pool(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_STORAGE_DESTROY_POOL:
            status = handle_storage_destroy_pool(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_STORAGE_CREATE_VDISK:
            status = handle_storage_create_vdisk(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_STORAGE_DESTROY_VDISK:
            status = handle_storage_destroy_vdisk(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_STORAGE_ATTACH_VDISK:
            status = handle_storage_attach_vdisk(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_STORAGE_DETACH_VDISK:
            status = handle_storage_detach_vdisk(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_STORAGE_GET_POOL_STATUS:
            status = handle_storage_get_pool_status(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_STORAGE_GET_VDISK_STATUS:
            status = handle_storage_get_vdisk_status(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_STORAGE_SET_VDISK_QOS:
            status = handle_storage_set_vdisk_qos(state, owner, page, cached_input_length);
            break;
        case FBVBS_CALL_STORAGE_REPORT_CORRUPTION:
            status = handle_storage_report_corruption(state, owner, page, cached_input_length);
            break;
        default:
            status = NOT_SUPPORTED_ON_PLATFORM;
            break;
    }

    return status;
}

/* ---- Hypercall entry point ---- */

/*@ requires \valid(state);
    requires \valid(registers);
    assigns *state, *registers,
            state->command_trackers[0 .. FBVBS_MAX_COMMAND_TRACKERS - 1];
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == PERMISSION_DENIED || \result == RESOURCE_BUSY || \result == RETRY_LATER ||
            \result == REPLAY_DETECTED || \result == RESOURCE_EXHAUSTED ||
            \result == NOT_SUPPORTED_ON_PLATFORM || \result == INVALID_CALLER ||
            \result == BUFFER_TOO_SMALL || \result == ABI_VERSION_UNSUPPORTED;
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
    bool finish_trap = false;

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

    owner = fbvbs_find_command_page_owner(state, page_gpa, &owner_vcpu_id);
    if (owner == NULL || owner_vcpu_id >= owner->vcpu_count ||
        owner_vcpu_id >= FBVBS_MAX_VCPUS) {
        fbvbs_audit_policy_deny(
            state,
            NULL,
            page_gpa,
            0U,
            PERMISSION_DENIED,
            FBVBS_DENY_REASON_PERMISSION,
            0U,
            0U
        );
        return PERMISSION_DENIED;
    }
    /* Resolve the page through the authenticated partition slot rather than
       by casting the guest-provided GPA. This prevents any dereference of an
       unowned GPA and keeps the runtime path aligned with the WP model. */
    page = &owner->command_pages[owner_vcpu_id].page;
    /* TOCTOU hardening: snapshot call_id and input_length once from
       guest-accessible memory.  A concurrent vCPU could modify these
       fields between validation and use.  All subsequent checks must
       use these cached copies, never re-read from page->*. */
    {
        uint16_t cached_call_id = page->call_id;
        uint32_t cached_input_length = page->input_length;
        uint64_t cached_caller_sequence = page->caller_sequence;
        uint64_t cached_caller_nonce = page->caller_nonce;
        bool policy_deny_noted = false;

        status = fbvbs_validate_command_page(page, cached_input_length);
        if (status != OK) {
            if (status != RETRY_LATER) {
                fbvbs_note_policy_deny(
                    state,
                    owner,
                    page_gpa,
                    cached_call_id,
                    status,
                    FBVBS_DENY_REASON_UNSPECIFIED
                );
                policy_deny_noted = true;
            }
            if (status == RETRY_LATER) {
                registers->rax = (uint64_t)(uint32_t)status;
                registers->rbx = page->command_state;
                registers->rcx = page->actual_output_length;
                registers->rdx = 0U;
                finish_trap = false;
            } else {
                finish_trap = true;
            }
            goto finish;
        }

        fbvbs_hypercall_guard_lock(&state->hypercall_guard_lock);
        status = fbvbs_enforce_hypercall_abuse_guard(state, owner);
        fbvbs_hypercall_guard_unlock(&state->hypercall_guard_lock);
        if (status != OK) {
            if (status == RETRY_LATER) {
                fbvbs_note_rate_limit_retry(state, owner, page_gpa, cached_call_id);
            } else {
                fbvbs_note_policy_deny(
                    state,
                    owner,
                    page_gpa,
                    cached_call_id,
                    status,
                    FBVBS_DENY_REASON_UNSPECIFIED
                );
            }
            policy_deny_noted = true;
            if (status == RETRY_LATER) {
                registers->rax = (uint64_t)(uint32_t)status;
                registers->rbx = page->command_state;
                registers->rcx = page->actual_output_length;
                registers->rdx = 0U;
                finish_trap = false;
            } else {
                finish_trap = true;
            }
            goto finish;
        }

        if (owner != NULL && owner_vcpu_id < owner->vcpu_count && owner_vcpu_id < FBVBS_MAX_VCPUS) {
            observed_rip = owner->vcpus[owner_vcpu_id].rip;
        }
        status = fbvbs_validate_caller_for_call(state, owner, cached_call_id, observed_rip);
        if (status != OK) {
            fbvbs_note_policy_deny(
                state, owner, page_gpa, cached_call_id, status, FBVBS_DENY_REASON_UNSPECIFIED
            );
            policy_deny_noted = true;
            finish_trap = true;
            goto finish;
        }

        fbvbs_command_tracker_lock(&state->command_tracker_lock);
        status = fbvbs_validate_command_sequence(state, page_gpa,
                                                cached_caller_sequence,
                                                cached_caller_nonce);
        if (status != OK) {
            fbvbs_command_tracker_unlock(&state->command_tracker_lock);
            fbvbs_note_policy_deny(
                state, owner, page_gpa, cached_call_id, status, FBVBS_DENY_REASON_UNSPECIFIED
            );
            policy_deny_noted = true;
            finish_trap = true;
            goto finish;
        }

        fbvbs_command_tracker_unlock(&state->command_tracker_lock);

        status = fbvbs_dispatch_command(state, owner, page, cached_call_id,
                                        cached_input_length);
        if (status == RETRY_LATER) {
            /* Keep the command page state untouched when another vCPU is
               already executing this page. */
            registers->rax = (uint64_t)(uint32_t)status;
            registers->rbx = page->command_state;
            registers->rcx = page->actual_output_length;
            registers->rdx = 0U;
            finish_trap = false;
        } else {
            fbvbs_command_tracker_lock(&state->command_tracker_lock);
            {
                int sequence_status = fbvbs_commit_command_sequence(
                    state,
                    page_gpa,
                    cached_caller_sequence,
                    cached_caller_nonce
                );
                fbvbs_command_tracker_unlock(&state->command_tracker_lock);
                if (sequence_status != OK) {
                    status = sequence_status;
                    fbvbs_note_policy_deny(
                        state,
                        owner,
                        page_gpa,
                        cached_call_id,
                        status,
                        FBVBS_DENY_REASON_UNSPECIFIED
                    );
                    policy_deny_noted = true;
                }
            }
            finish_trap = true;
        }

        if (!policy_deny_noted && status != OK && status != RETRY_LATER) {
            fbvbs_note_policy_deny(
                state, owner, page_gpa, cached_call_id, status, FBVBS_DENY_REASON_UNSPECIFIED
            );
        }
    }
finish:
    if (finish_trap) {
        fbvbs_finish_trap(page, registers, status, page->actual_output_length);
    }
    return status;
}
