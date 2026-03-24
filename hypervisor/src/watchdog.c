/*
 * FBVBS Watchdog / Liveness Monitor (Phase 1-9)
 *
 * Tracks consecutive VMX preemption timer exits per partition.
 * If a partition consumes FBVBS_WATCHDOG_MAX_CONSECUTIVE full time
 * slices without a voluntary VM exit, we declare the guest hung and
 * fault the partition (fail-safe halt per Section 49).
 *
 * Design:
 *   - on_timer_exit: increments counter, checks threshold, faults if exceeded
 *   - on_voluntary_exit: resets counter (guest is alive)
 *   - Faulting uses partition_fault path (audit log + state transition)
 *   - No panic: the hypervisor continues running; only the offending
 *     partition is halted
 *
 * The VMX preemption timer value is configured in vmx_controls.c
 * (FBVBS_DEFAULT_PREEMPTION_TICKS ~10ms at 2GHz). So the default
 * hang detection window is ~100ms (10 * 10ms).
 */

#include <stdint.h>

#include "fbvbs_hypervisor.h"

/* Watchdog expiry payload: 8 bytes packed as partition_idx + count */
#define WATCHDOG_PAYLOAD_SIZE 8U

/*@ requires \valid(state);
    requires partition_idx < FBVBS_MAX_PARTITIONS;
    assigns state->partitions[partition_idx].consecutive_timer_exits,
            state->partitions[partition_idx].watchdog_faults_total,
            state->partitions[partition_idx].state,
            state->partitions[partition_idx].last_fault_code,
            state->partitions[partition_idx].last_fault_source_component,
            state->partitions[partition_idx].last_fault_detail0,
            state->partitions[partition_idx].last_fault_detail1,
            state->mirror_log, state->log_lock;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_watchdog_on_timer_exit(
    struct fbvbs_hypervisor_state *state,
    uint32_t partition_idx)
{
    struct fbvbs_partition *part;
    uint32_t count;

    part = &state->partitions[partition_idx];

    /* Only monitor occupied, running partitions */
    if (!part->occupied || part->state != FBVBS_PARTITION_STATE_RUNNING) {
        return 0;
    }

    /* Increment with saturation */
    if (part->consecutive_timer_exits < UINT32_MAX) {
        part->consecutive_timer_exits += 1U;
    }
    count = part->consecutive_timer_exits;

    if (count < FBVBS_WATCHDOG_MAX_CONSECUTIVE) {
        return 0;  /* Not yet exceeded — guest gets more time */
    }

    /* Threshold exceeded — guest is hung. Log and fault. */
    {
        uint8_t payload[WATCHDOG_PAYLOAD_SIZE];
        payload[0] = (uint8_t)(partition_idx & 0xFFU);
        payload[1] = (uint8_t)((partition_idx >> 8U) & 0xFFU);
        payload[2] = (uint8_t)((partition_idx >> 16U) & 0xFFU);
        payload[3] = (uint8_t)((partition_idx >> 24U) & 0xFFU);
        payload[4] = (uint8_t)(count & 0xFFU);
        payload[5] = (uint8_t)((count >> 8U) & 0xFFU);
        payload[6] = (uint8_t)((count >> 16U) & 0xFFU);
        payload[7] = (uint8_t)((count >> 24U) & 0xFFU);
        (void)fbvbs_log_append(
            state, 0U,
            FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
            (uint16_t)FBVBS_SEVERITY_ALERT,
            (uint16_t)FBVBS_EVENT_WATCHDOG_EXPIRY,
            payload, WATCHDOG_PAYLOAD_SIZE
        );
    }

    /* Fault the partition — fail-safe halt, not panic.
     * partition_fault transitions to FAULTED state with audit record.
     * If it returns non-OK (e.g., INVALID_STATE because another CPU
     * faulted the partition between our state check and this call),
     * skip the counter increment — the fault didn't happen from us. */
    {
        int fault_status = fbvbs_partition_fault(
            state,
            part->partition_id,
            FBVBS_FAULT_WATCHDOG_TIMEOUT,
            FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
            (uint64_t)count,
            (uint64_t)partition_idx
        );
        if (fault_status != 0) {
            /* Partition was already faulted/destroyed by another path.
             * Reset counter but don't increment fault total. */
            part->consecutive_timer_exits = 0U;
            return 1;
        }
    }

    /* Track total watchdog faults for diagnostics */
    if (part->watchdog_faults_total < UINT32_MAX) {
        part->watchdog_faults_total += 1U;
    }

    /* Reset counter so recovered partition gets a fresh window */
    part->consecutive_timer_exits = 0U;

    return 1;  /* 1 = partition was faulted */
}

/*@ requires \valid(state);
    requires partition_idx < FBVBS_MAX_PARTITIONS;
    assigns state->partitions[partition_idx].consecutive_timer_exits;
*/
void fbvbs_watchdog_on_voluntary_exit(
    struct fbvbs_hypervisor_state *state,
    uint32_t partition_idx)
{
    struct fbvbs_partition *part;

    if (partition_idx >= FBVBS_MAX_PARTITIONS) {
        return;  /* Defensive: out-of-bounds index */
    }

    part = &state->partitions[partition_idx];

    /* Only reset counter for occupied partitions — writing to an
     * unoccupied slot is a logic error at the call site. */
    if (!part->occupied) {
        return;
    }

    part->consecutive_timer_exits = 0U;
}
