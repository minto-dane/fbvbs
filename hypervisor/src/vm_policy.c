#include "fbvbs_hypervisor.h"

/*@ requires \valid(vcpu);
    requires \valid(response);
    requires \valid_read(leaf_exit);
    requires \separated(vcpu, response, leaf_exit);
    assigns *vcpu, *response;
    ensures vcpu->state == FBVBS_VCPU_STATE_RUNNABLE;
    ensures response->exit_reason == FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT;
*/
static void fbvbs_vmx_external_interrupt_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    union {
        struct fbvbs_vm_exit_external_interrupt s;
        uint8_t bytes[sizeof(struct fbvbs_vm_exit_external_interrupt)];
    } payload;

    payload.s = (struct fbvbs_vm_exit_external_interrupt){0};
    payload.s.vector = (uint32_t)leaf_exit->value;
    payload.s.reserved0 = 0U;
    fbvbs_copy_bytes(response->exit_payload, payload.bytes, sizeof(payload.s));
    response->exit_reason = FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT;
    response->exit_length = (uint32_t)sizeof(payload.s);
    vcpu->pending_interrupt_delivery = 0U;
    vcpu->pending_interrupt_vector = 0U;
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

/*@ requires \valid(vcpu);
    requires \valid(response);
    requires \valid_read(leaf_exit);
    requires \separated(vcpu, response, leaf_exit);
    assigns *vcpu, *response;
    ensures vcpu->state == FBVBS_VCPU_STATE_RUNNABLE;
    ensures response->exit_reason == FBVBS_VM_EXIT_REASON_CR_ACCESS;
*/
static void fbvbs_vmx_cr_access_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    union {
        struct fbvbs_vm_exit_cr_access s;
        uint8_t bytes[sizeof(struct fbvbs_vm_exit_cr_access)];
    } payload;

    payload.s = (struct fbvbs_vm_exit_cr_access){0};
    payload.s.cr_number = leaf_exit->cr_number;
    payload.s.access_type = FBVBS_VM_CR_ACCESS_WRITE;
    payload.s.value = leaf_exit->value;
    fbvbs_copy_bytes(response->exit_payload, payload.bytes, sizeof(payload.s));
    response->exit_reason = FBVBS_VM_EXIT_REASON_CR_ACCESS;
    response->exit_length = (uint32_t)sizeof(payload.s);
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

/*@ requires \valid(vcpu);
    requires \valid(response);
    requires \valid_read(leaf_exit);
    requires \separated(vcpu, response, leaf_exit);
    assigns *vcpu, *response;
    ensures vcpu->state == FBVBS_VCPU_STATE_RUNNABLE;
    ensures response->exit_reason == FBVBS_VM_EXIT_REASON_PIO;
*/
static void fbvbs_vmx_pio_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    union {
        struct fbvbs_vm_exit_pio s;
        uint8_t bytes[sizeof(struct fbvbs_vm_exit_pio)];
    } payload;

    payload.s = (struct fbvbs_vm_exit_pio){0};
    payload.s.port = leaf_exit->port;
    payload.s.access_size = leaf_exit->access_size;
    payload.s.is_write = leaf_exit->is_write;
    payload.s.value = (uint32_t)leaf_exit->value;
    fbvbs_copy_bytes(response->exit_payload, payload.bytes, sizeof(payload.s));
    response->exit_reason = FBVBS_VM_EXIT_REASON_PIO;
    response->exit_length = (uint32_t)sizeof(payload.s);
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

/*@ requires \valid(vcpu);
    requires \valid(response);
    requires \valid_read(leaf_exit);
    requires \separated(vcpu, response, leaf_exit);
    assigns *vcpu, *response;
    ensures vcpu->state == FBVBS_VCPU_STATE_RUNNABLE;
    ensures response->exit_reason == FBVBS_VM_EXIT_REASON_MMIO;
*/
static void fbvbs_vmx_mmio_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    union {
        struct fbvbs_vm_exit_mmio s;
        uint8_t bytes[sizeof(struct fbvbs_vm_exit_mmio)];
    } payload;

    payload.s = (struct fbvbs_vm_exit_mmio){0};
    payload.s.guest_physical_address = leaf_exit->guest_physical_address;
    payload.s.access_size = leaf_exit->access_size;
    payload.s.is_write = leaf_exit->is_write;
    payload.s.reserved0 = 0U;
    payload.s.value = (uint32_t)leaf_exit->value;
    fbvbs_copy_bytes(response->exit_payload, payload.bytes, sizeof(payload.s));
    response->exit_reason = FBVBS_VM_EXIT_REASON_MMIO;
    response->exit_length = (uint32_t)sizeof(payload.s);
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

/*@ requires \valid(vcpu);
    requires \valid(response);
    requires \valid_read(leaf_exit);
    requires \separated(vcpu, response, leaf_exit);
    assigns *vcpu, *response;
    ensures vcpu->state == FBVBS_VCPU_STATE_RUNNABLE;
    ensures response->exit_reason == FBVBS_VM_EXIT_REASON_MSR_ACCESS;
*/
static void fbvbs_vmx_msr_access_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    union {
        struct fbvbs_vm_exit_msr_access s;
        uint8_t bytes[sizeof(struct fbvbs_vm_exit_msr_access)];
    } payload;

    payload.s = (struct fbvbs_vm_exit_msr_access){0};
    payload.s.msr_address = leaf_exit->msr_address;
    payload.s.access_type = FBVBS_VM_MSR_ACCESS_WRITE;
    payload.s.value = 0U;
    fbvbs_copy_bytes(response->exit_payload, payload.bytes, sizeof(payload.s));
    response->exit_reason = FBVBS_VM_EXIT_REASON_MSR_ACCESS;
    response->exit_length = (uint32_t)sizeof(payload.s);
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

/*@ requires \valid(state);
    requires \valid(partition);
    requires vcpu_id < partition->vcpu_count;
    requires vcpu_id < FBVBS_MAX_VCPUS;
    requires \valid(response);
    requires \separated(state, response);
    requires \separated(partition, response);
    assigns *state, *partition, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND;
    ensures response->exit_reason == FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT;
*/
static int fbvbs_vmx_unclassified_fault_exit(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition,
    uint32_t vcpu_id,
    struct fbvbs_vm_run_response *response
) {
    union {
        struct fbvbs_vm_exit_unclassified_fault s;
        uint8_t bytes[sizeof(struct fbvbs_vm_exit_unclassified_fault)];
    } payload;

    payload.s = (struct fbvbs_vm_exit_unclassified_fault){0};
    payload.s.fault_code = FAULT_CODE_VM_EXIT_UNCLASSIFIED;
    payload.s.reserved0 = 0U;
    payload.s.detail0 = vcpu_id;
    payload.s.detail1 = partition->vcpus[vcpu_id].rip;
    fbvbs_copy_bytes(response->exit_payload, payload.bytes, sizeof(payload.s));
    response->exit_reason = FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT;
    response->exit_length = (uint32_t)sizeof(payload.s);
    return fbvbs_partition_fault(
        state,
        partition->partition_id,
        payload.s.fault_code,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        payload.s.detail0,
        payload.s.detail1
    );
}

/*@ requires \valid(vcpu);
    requires \valid(response);
    requires \valid_read(leaf_exit);
    requires \separated(vcpu, response, leaf_exit);
    assigns *vcpu, *response;
    ensures vcpu->state == FBVBS_VCPU_STATE_RUNNABLE;
    ensures response->exit_reason == FBVBS_VM_EXIT_REASON_EPT_VIOLATION;
*/
static void fbvbs_vmx_ept_violation_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    union {
        struct fbvbs_vm_exit_ept_violation s;
        uint8_t bytes[sizeof(struct fbvbs_vm_exit_ept_violation)];
    } payload;

    payload.s = (struct fbvbs_vm_exit_ept_violation){0};
    payload.s.guest_physical_address = leaf_exit->guest_physical_address;
    payload.s.access_type = FBVBS_VM_EPT_ACCESS_EXECUTE;
    payload.s.reserved0 = 0U;
    fbvbs_copy_bytes(response->exit_payload, payload.bytes, sizeof(payload.s));
    response->exit_reason = FBVBS_VM_EXIT_REASON_EPT_VIOLATION;
    response->exit_length = (uint32_t)sizeof(payload.s);
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

/*@ requires \valid(state) || state == \null;
    requires \valid(partition) || partition == \null;
    requires \valid(response) || response == \null;
    requires partition != \null ==> partition->vcpu_count <= FBVBS_MAX_VCPUS;
    requires state != \null ==> state->intercepted_msr_count <= 16;
    requires \separated(state, response);
    assigns *state, *partition, *response;
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == INVALID_STATE || \result == NOT_SUPPORTED_ON_PLATFORM ||
            \result == NOT_FOUND;
    behavior null_args:
      assumes state == \null || partition == \null || response == \null;
      ensures \result == INVALID_PARAMETER;
    behavior bad_vcpu:
      assumes state != \null && partition != \null && response != \null;
      assumes vcpu_id >= partition->vcpu_count;
      ensures \result == INVALID_PARAMETER;
*/
int fbvbs_vmx_run_vcpu(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition,
    uint32_t vcpu_id,
    struct fbvbs_vm_run_response *response
) {
    struct fbvbs_vcpu *vcpu;
    struct fbvbs_vmx_leaf_exit leaf_exit;
    int status;

    if (state == NULL || partition == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (partition->vcpu_count > FBVBS_MAX_VCPUS) {
        return INVALID_STATE;
    }
    if (vcpu_id >= partition->vcpu_count) {
        return INVALID_PARAMETER;
    }

    /*@ assert vcpu_id < partition->vcpu_count; */
    /*@ assert partition->vcpu_count <= FBVBS_MAX_VCPUS; */
    /*@ assert vcpu_id < FBVBS_MAX_VCPUS; */
    vcpu = &partition->vcpus[vcpu_id];
    /*@ assert \valid_read(vcpu); */
    /*@ assert state->intercepted_msr_count <= 16; */
    /*@ assert state->intercepted_msr_count == 0 ||
              \valid_read(state->intercepted_msrs + (0 .. state->intercepted_msr_count - 1)); */
    *response = (struct fbvbs_vm_run_response){0};
    status = fbvbs_vmx_leaf_run_vcpu(
        &state->vmx_caps,
        vcpu,
        state->pinned_cr0_mask,
        state->pinned_cr4_mask,
        state->intercepted_msrs,
        state->intercepted_msr_count,
        partition->mapped_bytes,
        &leaf_exit
    );
    if (status != OK) {
        return status;
    }

    switch (leaf_exit.exit_reason) {
        case FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT:
            fbvbs_vmx_external_interrupt_exit(vcpu, response, &leaf_exit);
            return OK;
        case FBVBS_VM_EXIT_REASON_CR_ACCESS:
            fbvbs_vmx_cr_access_exit(vcpu, response, &leaf_exit);
            return OK;
        case FBVBS_VM_EXIT_REASON_PIO:
            fbvbs_vmx_pio_exit(vcpu, response, &leaf_exit);
            return OK;
        case FBVBS_VM_EXIT_REASON_MMIO:
            fbvbs_vmx_mmio_exit(vcpu, response, &leaf_exit);
            return OK;
        case FBVBS_VM_EXIT_REASON_MSR_ACCESS:
            fbvbs_vmx_msr_access_exit(vcpu, response, &leaf_exit);
            return OK;
        case FBVBS_VM_EXIT_REASON_EPT_VIOLATION:
            fbvbs_vmx_ept_violation_exit(vcpu, response, &leaf_exit);
            return OK;
        case FBVBS_VM_EXIT_REASON_SHUTDOWN:
            response->exit_reason = FBVBS_VM_EXIT_REASON_SHUTDOWN;
            response->exit_length = 0U;
            vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
            return OK;
        case FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT:
            /*@ assert vcpu_id < FBVBS_MAX_VCPUS; */
            return fbvbs_vmx_unclassified_fault_exit(state, partition, vcpu_id, response);
        case FBVBS_VM_EXIT_REASON_HALT:
            response->exit_reason = FBVBS_VM_EXIT_REASON_HALT;
            response->exit_length = 0U;
            vcpu->state = FBVBS_VCPU_STATE_BLOCKED;
            return OK;
        default:
            return INVALID_STATE;
    }
}