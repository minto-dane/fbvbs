/* FBVBS VM Exit Policy Engine
 *
 * Requirements: REQ-0300 (CR ピン留め), REQ-0342 (DR 分離),
 *   REQ-0343 (RDPMC インターセプト), REQ-0345 (UMIP),
 *   REQ-0800 (FreeBSD 統合基盤 — PRODUCTION NOTE: Phase 7),
 *   REQ-0801 (非信頼 ABI 変換層 — PRODUCTION NOTE: Phase 7),
 *   REQ-0802 (介入点 — PRODUCTION NOTE: Phase 7),
 *   REQ-0803 (mac(9) 十分性 — PRODUCTION NOTE: Phase 7),
 *   REQ-0804 (vmm(4) boot-time 介入 — PRODUCTION NOTE: Phase 7),
 *   REQ-0900 (bhyve 互換 — PRODUCTION NOTE: Phase 8),
 *   REQ-0901 (libvmmapi 互換 — PRODUCTION NOTE: Phase 8),
 *   REQ-0902 (未分類 exit fail-closed),
 *   REQ-1101 (FreeBSD 介入点十分性 — PRODUCTION NOTE: Phase 9 release gate)
 */
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
    struct fbvbs_vm_exit_external_interrupt payload;

    payload = (struct fbvbs_vm_exit_external_interrupt){0};
    payload.vector = leaf_exit->detail.external_interrupt.vector;
    payload.reserved0 = 0U;
    fbvbs_copy_bytes(response->exit_payload, (const uint8_t *)&payload, sizeof(payload));
    response->exit_reason = FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT;
    response->exit_length = (uint32_t)sizeof(payload);
    vcpu->pending_interrupt_delivery = 0U;
    vcpu->pending_interrupt_vector = 0U;
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

/*@ requires \valid(state);
    requires \valid(vcpu);
    requires \valid(response);
    requires \valid_read(leaf_exit);
    requires \separated(vcpu, response, leaf_exit);
    assigns *vcpu, *response, state->mirror_log, state->log_lock,
            state->log_rate_counts[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
            state->log_rate_dropped[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
            state->log_rate_window_sequence;
    ensures vcpu->state == FBVBS_VCPU_STATE_RUNNABLE;
    ensures response->exit_reason == FBVBS_VM_EXIT_REASON_CR_ACCESS;
*/
static void fbvbs_vmx_cr_access_exit(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    struct fbvbs_vm_exit_cr_access payload;
    uint64_t requested = leaf_exit->detail.cr_access.value;
    uint32_t cr_num = leaf_exit->detail.cr_access.cr_number;

    /* Update shadow CR state and enforce pinning.  The shadow must
     * always reflect the guest's requested value (or enforced value
     * when pins are active).  Without this unconditional update, a
     * guest CR write with pin mask == 0 would be silently lost and
     * the hypervisor's model would diverge from the hardware state. */
    if (cr_num == 0U) {
        vcpu->cr0 = requested;
        if (state->pinned_cr0_mask != 0U) {
            uint64_t enforced = (requested & ~state->pinned_cr0_mask) |
                                state->pinned_cr0_value;
            if (enforced != requested) {
                fbvbs_log_append_rate_limited(state, 0U,
                                 FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                                 FBVBS_SEVERITY_WARNING,
                                 FBVBS_EVENT_CR_PIN_VIOLATION,
                                 (const uint8_t *)0, 0U);
                vcpu->cr0 = enforced;
            }
        }
    } else if (cr_num == 4U) {
        vcpu->cr4 = requested;
        if (state->pinned_cr4_mask != 0U) {
            uint64_t enforced = (requested & ~state->pinned_cr4_mask) |
                                state->pinned_cr4_value;
            if (enforced != requested) {
                fbvbs_log_append_rate_limited(state, 0U,
                                 FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                                 FBVBS_SEVERITY_WARNING,
                                 FBVBS_EVENT_CR_PIN_VIOLATION,
                                 (const uint8_t *)0, 0U);
                vcpu->cr4 = enforced;
            }
        }
    }

    payload = (struct fbvbs_vm_exit_cr_access){0};
    payload.cr_number = cr_num;
    payload.access_type = leaf_exit->detail.cr_access.access_type;
    /* Report the enforced value (after pin enforcement), not the
     * raw requested value, so the VMM observes the actual CR state. */
    if (cr_num == 0U) {
        payload.value = vcpu->cr0;
    } else if (cr_num == 4U) {
        payload.value = vcpu->cr4;
    } else {
        payload.value = requested;
    }
    fbvbs_copy_bytes(response->exit_payload, (const uint8_t *)&payload, sizeof(payload));
    response->exit_reason = FBVBS_VM_EXIT_REASON_CR_ACCESS;
    response->exit_length = (uint32_t)sizeof(payload);
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
    struct fbvbs_vm_exit_pio payload;

    payload = (struct fbvbs_vm_exit_pio){0};
    payload.port = leaf_exit->detail.pio.port;
    payload.width = leaf_exit->detail.pio.access_size;
    payload.is_write = leaf_exit->detail.pio.is_write;
    /* Leaf simulation: single-rep only; bare-metal uses ECX for REP count */
    payload.count = 1U;
    payload.value = leaf_exit->detail.pio.value;
    fbvbs_copy_bytes(response->exit_payload, (const uint8_t *)&payload, sizeof(payload));
    response->exit_reason = FBVBS_VM_EXIT_REASON_PIO;
    response->exit_length = (uint32_t)sizeof(payload);
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
    struct fbvbs_vm_exit_mmio payload;

    payload = (struct fbvbs_vm_exit_mmio){0};
    payload.guest_physical_address = leaf_exit->detail.mmio.guest_physical_address;
    payload.width = leaf_exit->detail.mmio.access_size;
    payload.is_write = leaf_exit->detail.mmio.is_write;
    payload.reserved0 = 0U;
    payload.reserved1 = 0U;
    payload.value = leaf_exit->detail.mmio.value;
    fbvbs_copy_bytes(response->exit_payload, (const uint8_t *)&payload, sizeof(payload));
    response->exit_reason = FBVBS_VM_EXIT_REASON_MMIO;
    response->exit_length = (uint32_t)sizeof(payload);
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
    struct fbvbs_vm_exit_msr_access payload;

    payload = (struct fbvbs_vm_exit_msr_access){0};
    payload.msr = leaf_exit->detail.msr_access.msr_address;
    payload.is_write = leaf_exit->detail.msr_access.is_write;
    payload.value = leaf_exit->detail.msr_access.value;
    fbvbs_copy_bytes(response->exit_payload, (const uint8_t *)&payload, sizeof(payload));
    response->exit_reason = FBVBS_VM_EXIT_REASON_MSR_ACCESS;
    response->exit_length = (uint32_t)sizeof(payload);
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

/*@ requires \valid(state);
    requires \valid(partition);
    requires vcpu_id < partition->vcpu_count;
    requires vcpu_id < FBVBS_MAX_VCPUS;
    requires \valid(response);
    assigns *state, *partition, *response;
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == NOT_FOUND || \result == INVALID_STATE;
    ensures response->exit_reason == FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT;
*/
static int fbvbs_vmx_unclassified_fault_exit(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition,
    uint32_t vcpu_id,
    struct fbvbs_vm_run_response *response
) {
    struct fbvbs_vm_exit_unclassified_fault payload;

    payload = (struct fbvbs_vm_exit_unclassified_fault){0};
    payload.fault_code = FAULT_CODE_VM_EXIT_UNCLASSIFIED;
    payload.reserved0 = 0U;
    payload.detail0 = vcpu_id;
    payload.detail1 = partition->vcpus[vcpu_id].rip;
    fbvbs_copy_bytes(response->exit_payload, (const uint8_t *)&payload, sizeof(payload));
    response->exit_reason = FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT;
    response->exit_length = (uint32_t)sizeof(payload);
    return fbvbs_partition_fault(
        state,
        partition->partition_id,
        payload.fault_code,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        payload.detail0,
        payload.detail1
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
    struct fbvbs_vm_exit_ept_violation payload;

    payload = (struct fbvbs_vm_exit_ept_violation){0};
    payload.guest_physical_address = leaf_exit->detail.ept_violation.guest_physical_address;
    payload.access_bits = leaf_exit->detail.ept_violation.access_bits;
    payload.reserved0 = 0U;
    fbvbs_copy_bytes(response->exit_payload, (const uint8_t *)&payload, sizeof(payload));
    response->exit_reason = FBVBS_VM_EXIT_REASON_EPT_VIOLATION;
    response->exit_length = (uint32_t)sizeof(payload);
    vcpu->state = FBVBS_VCPU_STATE_RUNNABLE;
}

/* ================================================================
 * Debug register access handler (REQ-0342)
 *
 * When MOV_DR_EXITING is set in primary proc controls, any guest
 * MOV to/from DR0-DR7 causes a VM exit. We maintain per-vCPU
 * shadow copies of DR0-DR3, DR6, DR7 and never expose the host's
 * debug registers to the guest.
 *
 * DR4/DR5 alias DR6/DR7 when CR4.DE=0. With CR4.DE=1 (our pinned
 * configuration), MOV DR4/DR5 cause #UD instead.
 *
 * Guest DR writes update per-vCPU shadow state (vcpu->drN) only.
 * VMCS_GUEST_DR7 is NOT updated on guest DR7 writes because
 * MOV_DR_EXITING is active: the guest never directly accesses
 * hardware DRs — all MOV DRx cause VM exit, and this handler
 * returns shadow values from vcpu->drN on reads. This means
 * guest debug breakpoints are shadow-only (do not fire on
 * hardware), which is the correct security posture — guest
 * debugging capability is denied. fbvbs_debug_save_guest resets
 * hardware DR7 to 0x400 (breakpoints disabled) after each
 * VM exit.
 * ================================================================ */

/*@ requires \valid(state);
    requires \valid(vcpu);
    requires \valid(response);
    requires \valid_read(leaf_exit);
    requires \separated(vcpu, response, leaf_exit);
    assigns vcpu->state, vcpu->dr0, vcpu->dr1, vcpu->dr2, vcpu->dr3,
            vcpu->dr6, vcpu->dr7,
            response->exit_reason, response->exit_length,
            response->exit_payload[0 .. 15],
            state->mirror_log, state->log_lock,
            state->log_rate_counts[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
            state->log_rate_dropped[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
            state->log_rate_window_sequence;

    behavior invalid_access:
      assumes leaf_exit->detail.dr_access.access_type > 1U;
      assigns vcpu->state,
              response->exit_reason, response->exit_length,
              state->mirror_log, state->log_lock,
              state->log_rate_counts[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
              state->log_rate_dropped[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
              state->log_rate_window_sequence;
      ensures vcpu->state == FBVBS_VCPU_STATE_FAULTED;

    behavior write_dr:
      assumes leaf_exit->detail.dr_access.access_type == 0U;
      assigns vcpu->state, vcpu->dr0, vcpu->dr1, vcpu->dr2, vcpu->dr3,
              vcpu->dr6, vcpu->dr7,
              response->exit_reason, response->exit_length,
              response->exit_payload[0 .. 15],
              state->mirror_log, state->log_lock,
              state->log_rate_counts[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
              state->log_rate_dropped[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
              state->log_rate_window_sequence;
      ensures vcpu->state == FBVBS_VCPU_STATE_RUNNABLE;

    behavior read_dr:
      assumes leaf_exit->detail.dr_access.access_type == 1U;
      assigns vcpu->state,
              response->exit_reason, response->exit_length,
              response->exit_payload[0 .. 15],
              state->mirror_log, state->log_lock,
              state->log_rate_counts[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
              state->log_rate_dropped[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
              state->log_rate_window_sequence;
      ensures vcpu->state == FBVBS_VCPU_STATE_RUNNABLE;

    complete behaviors;
    disjoint behaviors;
*/
static void fbvbs_vmx_dr_access_exit(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_vcpu *vcpu,
    struct fbvbs_vm_run_response *response,
    const struct fbvbs_vmx_leaf_exit *leaf_exit
) {
    struct fbvbs_vm_exit_dr_access payload;
    uint32_t dr_num = leaf_exit->detail.dr_access.dr_number;
    uint32_t is_read = leaf_exit->detail.dr_access.access_type; /* 0=write, 1=read */
    uint64_t value = leaf_exit->detail.dr_access.value;

    /* Validate access_type is 0 (write) or 1 (read).
     * Invalid values indicate hardware/firmware anomaly — fault the vCPU
     * and report a defined exit reason rather than silently returning OK
     * with zeroed exit_reason (CWE-394). */
    if (is_read > 1U) {
        fbvbs_log_append_rate_limited(state, 0U,
                         FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                         FBVBS_SEVERITY_ALERT,
                         FBVBS_EVENT_DR_ACCESS_INTERCEPT,
                         (const uint8_t *)0, 0U);
        response->exit_reason = FBVBS_VM_EXIT_REASON_DR_ACCESS;
        response->exit_length = 0U;
        vcpu->state = FBVBS_VCPU_STATE_FAULTED;
        return;
    }

    /* Handle MOV to DR (guest write) — update shadow state */
    if (is_read == 0U) {
        switch (dr_num) {
            case 0U: vcpu->dr0 = value; break;
            case 1U: vcpu->dr1 = value; break;
            case 2U: vcpu->dr2 = value; break;
            case 3U: vcpu->dr3 = value; break;
            case 4U: /* Fall through — DR4 aliases DR6 when CR4.DE=0 */
            case 6U:
                /* DR6: enforce reserved bits per Intel SDM Vol. 3, 17.2.3.
                 * Bits [63:32] = 0. Bit 15 = 1 (no RTM). Bits [11:4] = 1.
                 * Bits [31:16] = 1 (reserved). Guest-writable: bits [14:12]
                 * (BD, BS, BT) and bits [3:0] (B0-B3). */
                vcpu->dr6 = (value & 0x000000000000700FULL) | 0x00000000FFFF8FF0ULL;
                break;
            case 5U: /* Fall through — DR5 aliases DR7 when CR4.DE=0 */
            case 7U:
                /* DR7: enforce reserved bits per Intel SDM Vol. 3, 17.2.4.
                 * Bits [63:32] = 0 (reserved). Bit 13 (GD) = 0 to prevent
                 * recursive #DB. Bit 11 = 0 (reserved). Bit 10 = 1
                 * (reserved, must be 1). Bits 9:8 = 0 (reserved).
                 * Bits [31:16] = condition fields (R/W, LEN) — guest controlled.
                 * Bits [7:0] = L0-L3,G0-G3 enables — guest controlled. */
                vcpu->dr7 = (value & 0x00000000FFFF00FFULL) | 0x0000000000000400ULL;
                break;
            default:
                /* DR4/DR5 with CR4.DE=1 cause #UD, should not reach VMX.
                 * If somehow reached, ignore silently. */
                break;
        }
    } else {
        /* MOV from DR (guest read): return shadow values, NOT the leaf
         * value, to prevent host debug register information leaks. */
        switch (dr_num) {
            case 0U: value = vcpu->dr0; break;
            case 1U: value = vcpu->dr1; break;
            case 2U: value = vcpu->dr2; break;
            case 3U: value = vcpu->dr3; break;
            case 4U: /* Fall through — DR4 aliases DR6 */
            case 6U: value = vcpu->dr6; break;
            case 5U: /* Fall through — DR5 aliases DR7 */
            case 7U: value = vcpu->dr7; break;
            default: value = 0U; break;
        }
    }

    /* Log the DR access for audit trail. Rate-limited because a guest
     * loop on MOV DR could generate millions of exits per second. */
    fbvbs_log_append_rate_limited(state, 0U,
                     FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                     FBVBS_SEVERITY_INFO,
                     FBVBS_EVENT_DR_ACCESS_INTERCEPT,
                     (const uint8_t *)0, 0U);

    payload = (struct fbvbs_vm_exit_dr_access){0};
    payload.dr_number = dr_num;
    payload.access_type = (is_read != 0U) ? FBVBS_VM_CR_ACCESS_READ
                                          : FBVBS_VM_CR_ACCESS_WRITE;
    payload.value = value;
    fbvbs_copy_bytes(response->exit_payload, (const uint8_t *)&payload, sizeof(payload));
    response->exit_reason = FBVBS_VM_EXIT_REASON_DR_ACCESS;
    response->exit_length = (uint32_t)sizeof(payload);
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
    /*@ assert \valid(vcpu); */
    /*@ assert \separated(vcpu, response); */
    *response = (struct fbvbs_vm_run_response){0};

    /* VM entry mitigations (Section 21.3): L1D flush + restore guest SPEC_CTRL.
     * Must execute immediately before VM entry to minimize the window where
     * fill buffers or L1D contain host data visible to speculation. */
    fbvbs_vmentry_mitigate(
        &state->cpu_security.worst_case_vuln, &state->spec_ctrl);

    status = fbvbs_vmx_leaf_run_vcpu(
        &state->vmx_caps,
        vcpu,
        state->pinned_cr0_mask,
        state->pinned_cr0_value,
        state->pinned_cr4_mask,
        state->pinned_cr4_value,
        state->intercepted_msrs,
        state->intercepted_msr_count,
        partition->mapped_bytes,
        &leaf_exit
    );

    /* VM exit mitigations (Section 21.2): IBPB + RSB fill + PBRSB + BHB clear
     * + save/restore SPEC_CTRL + VERW.  Unconditional IBPB (is_cross_partition=1)
     * for government-level isolation — cross-partition tracking is inherently
     * racy under SMT and insufficient against nation-state adversaries. */
    fbvbs_vmexit_mitigate(
        &state->cpu_security.worst_case_vuln, &state->spec_ctrl, 1U);

    if (status != OK) {
        return status;
    }

    /*@ assert \separated(vcpu, response, &leaf_exit); */
    switch (leaf_exit.exit_reason) {
        case FBVBS_VM_EXIT_REASON_EXTERNAL_INTERRUPT:
            fbvbs_vmx_external_interrupt_exit(vcpu, response, &leaf_exit);
            return OK;
        case FBVBS_VM_EXIT_REASON_CR_ACCESS:
            fbvbs_vmx_cr_access_exit(state, vcpu, response, &leaf_exit);
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
        case FBVBS_VM_EXIT_REASON_DR_ACCESS:
            fbvbs_vmx_dr_access_exit(state, vcpu, response, &leaf_exit);
            return OK;
        case FBVBS_VM_EXIT_REASON_EPT_VIOLATION:
            fbvbs_vmx_ept_violation_exit(vcpu, response, &leaf_exit);
            return OK;
        case FBVBS_VM_EXIT_REASON_SHUTDOWN:
            response->exit_reason = FBVBS_VM_EXIT_REASON_SHUTDOWN;
            response->exit_length = 0U;
            vcpu->state = FBVBS_VCPU_STATE_FAULTED;
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
            response->exit_reason = FBVBS_VM_EXIT_REASON_UNCLASSIFIED_FAULT;
            response->exit_length = 0U;
            vcpu->state = FBVBS_VCPU_STATE_FAULTED;
            return INVALID_STATE;
    }
}
