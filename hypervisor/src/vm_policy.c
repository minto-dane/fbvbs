#include "fbvbs_hypervisor.h"

static void fbvbs_vmx_external_interrupt_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    struct fbvbs_vm_exit_external_interrupt payload;

    payload.vector = (uint32_t)leaf_exit->value;
    payload.reserved0 = 0U;
    response->exit_reason = FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT;
    response->exit_length = (uint32_t)sizeof(payload);
    fbvbs_copy_memory(response->exit_payload, &payload, sizeof(payload));
    vcpu->pending_interrupt_delivery = 0U;
    vcpu->pending_interrupt_vector = 0U;
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

static void fbvbs_vmx_cr_access_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    struct fbvbs_vm_exit_cr_access payload;

    payload.cr_number = leaf_exit->cr_number;
    payload.access_type = FBVBS_VM_CR_ACCESS_WRITE;
    payload.value = leaf_exit->value;
    response->exit_reason = FBVBS_VM_EXIT_REASON_CR_ACCESS;
    response->exit_length = (uint32_t)sizeof(payload);
    fbvbs_copy_memory(response->exit_payload, &payload, sizeof(payload));
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

static void fbvbs_vmx_pio_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    struct fbvbs_vm_exit_pio payload;

    payload.port = leaf_exit->port;
    payload.access_size = leaf_exit->access_size;
    payload.is_write = leaf_exit->is_write;
    payload.value = (uint32_t)leaf_exit->value;
    response->exit_reason = FBVBS_VM_EXIT_REASON_PIO;
    response->exit_length = (uint32_t)sizeof(payload);
    fbvbs_copy_memory(response->exit_payload, &payload, sizeof(payload));
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

static void fbvbs_vmx_mmio_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    struct fbvbs_vm_exit_mmio payload;

    payload.guest_physical_address = leaf_exit->guest_physical_address;
    payload.access_size = leaf_exit->access_size;
    payload.is_write = leaf_exit->is_write;
    payload.reserved0 = 0U;
    payload.value = (uint32_t)leaf_exit->value;
    response->exit_reason = FBVBS_VM_EXIT_REASON_MMIO;
    response->exit_length = (uint32_t)sizeof(payload);
    fbvbs_copy_memory(response->exit_payload, &payload, sizeof(payload));
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

static void fbvbs_vmx_msr_access_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    struct fbvbs_vm_exit_msr_access payload;

    payload.msr_address = leaf_exit->msr_address;
    payload.access_type = FBVBS_VM_MSR_ACCESS_WRITE;
    payload.value = 0U;
    response->exit_reason = FBVBS_VM_EXIT_REASON_MSR_ACCESS;
    response->exit_length = (uint32_t)sizeof(payload);
    fbvbs_copy_memory(response->exit_payload, &payload, sizeof(payload));
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

static int fbvbs_vmx_unclassified_fault_exit(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition,
    uint32_t vcpu_id,
    struct fbvbs_vm_run_response *response
) {
    struct fbvbs_vm_exit_unclassified_fault payload;

    payload.fault_code = FAULT_CODE_VM_EXIT_UNCLASSIFIED;
    payload.reserved0 = 0U;
    payload.detail0 = vcpu_id;
    payload.detail1 = partition->vcpus[vcpu_id].rip;
    response->exit_reason = FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT;
    response->exit_length = (uint32_t)sizeof(payload);
    fbvbs_copy_memory(response->exit_payload, &payload, sizeof(payload));
    return fbvbs_partition_fault(
        state,
        partition->partition_id,
        payload.fault_code,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        payload.detail0,
        payload.detail1
    );
}

static void fbvbs_vmx_ept_violation_exit(
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    struct fbvbs_vm_exit_ept_violation payload;

    payload.guest_physical_address = leaf_exit->guest_physical_address;
    payload.access_type = FBVBS_VM_EPT_ACCESS_EXECUTE;
    payload.reserved0 = 0U;
    response->exit_reason = FBVBS_VM_EXIT_REASON_EPT_VIOLATION;
    response->exit_length = (uint32_t)sizeof(payload);
    fbvbs_copy_memory(response->exit_payload, &payload, sizeof(payload));
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

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
    if (vcpu_id >= partition->vcpu_count) {
        return INVALID_PARAMETER;
    }

    vcpu = &partition->vcpus[vcpu_id];
    fbvbs_zero_memory(response, sizeof(*response));
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
