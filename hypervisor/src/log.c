#include <stddef.h>

#include "fbvbs_hypervisor.h"

static const uint32_t FBVBS_CRC32C_POLY = 0x82F63B78U;

union fbvbs_log_record_bytes {
    struct fbvbs_log_record_v1 record;
    uint8_t bytes[sizeof(struct fbvbs_log_record_v1)];
};

/*@ requires length == 0 || \valid_read(data + (0 .. length - 1));
    assigns \nothing;
*/
uint32_t fbvbs_crc32c(const uint8_t *data, size_t length) {
    uint32_t crc = 0xFFFFFFFFU;
    size_t index;
    uint32_t bit;

    /*@ loop invariant 0 <= index <= length;
        loop assigns index, crc, bit;
        loop variant length - index;
    */
    for (index = 0; index < length; ++index) {
        crc ^= data[index];
        /*@ loop invariant 0 <= bit <= 8;
            loop assigns bit, crc;
            loop variant 8 - bit;
        */
        for (bit = 0; bit < 8U; ++bit) {
            uint32_t mask = (uint32_t)(-(int32_t)(crc & 1U));
            crc = (crc >> 1U) ^ (FBVBS_CRC32C_POLY & mask);
        }
    }

    return ~crc;
}

/*@ requires \valid(state) || state == \null;
    assigns state->mirror_log;
    behavior null_ptr:
      assumes state == \null;
      ensures \result == INVALID_PARAMETER;
    behavior valid_ptr:
      assumes state != \null;
      ensures \result == OK;
      ensures state->mirror_log.header.abi_version == FBVBS_ABI_VERSION;
      ensures state->mirror_log.header.record_size == FBVBS_LOG_RECORD_V1_SIZE;
      ensures state->mirror_log.header.write_offset == 0;
      ensures state->mirror_log.header.max_readable_sequence == 0;
    complete behaviors;
    disjoint behaviors;
*/
int fbvbs_log_init(struct fbvbs_hypervisor_state *state) {
    if (state == NULL) {
        return INVALID_PARAMETER;
    }

    state->mirror_log = (struct fbvbs_log_storage){0};
    state->mirror_log.header.abi_version = FBVBS_ABI_VERSION;
    state->mirror_log.header.total_size = (uint32_t)sizeof(state->mirror_log);
    state->mirror_log.header.record_size = FBVBS_LOG_RECORD_V1_SIZE;
    state->mirror_log.header.write_offset = 0U;
    state->mirror_log.header.max_readable_sequence = 0U;
    state->mirror_log.header.boot_id_hi = state->boot_id_hi;
    state->mirror_log.header.boot_id_lo = state->boot_id_lo;
    return OK;
}

/*@ requires \valid(log);
    requires \valid(lock);
    requires \separated(log, lock);
    requires payload_length <= 220;
    requires payload_length == 0 || \valid_read(payload + (0 .. payload_length - 1));
    requires payload_length == 0 || \separated(payload + (0 .. payload_length - 1), log);
    assigns *log, *lock;
    ensures \result == OK || \result == RESOURCE_BUSY || \result == RESOURCE_EXHAUSTED;
*/
static int fbvbs_log_append_core(
    struct fbvbs_log_storage *log,
    volatile uint32_t *lock,
    uint64_t boot_id_hi,
    uint64_t boot_id_lo,
    uint32_t cpu_id,
    uint32_t source_component,
    uint16_t severity,
    uint16_t event_code,
    const uint8_t *payload,
    uint32_t payload_length
) {
    uint64_t sequence;
    uint32_t slot_index;
    struct fbvbs_log_record_v1 *record;

#ifdef __FRAMAC__
    /* WP model: spinlock always succeeds immediately */
    *lock = 1U;
#else
    {
        uint32_t lock_val;
        uint32_t spin_count = 0U;
        /* Acquire spinlock with bounded retry to prevent livelock.
         * 10000 iterations is ~10us on modern CPUs at 1GHz+. */
        do {
            __asm__ volatile("xchgl %0, %1"
                             : "=r"(lock_val), "=m"(*lock)
                             : "0"(1U)
                             : "memory");
            if (lock_val == 0U) {
                break;
            }
            ++spin_count;
            __asm__ volatile("pause" : : : "memory");
        } while (spin_count < 10000U);
        if (lock_val != 0U) {
            /* Lock acquisition failed — signal to caller rather than deadlocking.
             * Callers can take compensating action (e.g. retry or flag lost records). */
            return RESOURCE_BUSY;
        }
    }
#endif

    if (log->header.max_readable_sequence == UINT64_MAX) {
#ifdef __FRAMAC__
        *lock = 0U;
#else
        __asm__ volatile("movl %0, %1"
                         :
                         : "r"(0U), "m"(*lock)
                         : "memory");
#endif
        return RESOURCE_EXHAUSTED;
    }

    sequence = log->header.max_readable_sequence + 1U;
    slot_index = (uint32_t)((sequence - 1U) % FBVBS_LOG_SLOT_COUNT);
    /*@ assert slot_index < FBVBS_LOG_SLOT_COUNT; */
    record = &log->records[slot_index];
    /*@ assert \valid(record); */

    *record = (struct fbvbs_log_record_v1){0};
    record->sequence = sequence;
    record->boot_id_hi = boot_id_hi;
    record->boot_id_lo = boot_id_lo;
    record->timestamp_counter = sequence;
    record->cpu_id = cpu_id;
    record->source_component = source_component;
    record->severity = severity;
    record->event_code = event_code;
    record->payload_length = payload_length;

    if (payload_length > 0U && payload != NULL) {
        fbvbs_copy_bytes(record->payload, payload, payload_length);
    }

    {
        union fbvbs_log_record_bytes crc_overlay;
        size_t crc_len = offsetof(struct fbvbs_log_record_v1, crc32c);
        crc_overlay.record = *record;
        record->crc32c = fbvbs_crc32c(crc_overlay.bytes, crc_len);
    }

#ifdef __FRAMAC__
    /* WP model: direct field writes (atomic on real hardware) */
    log->header.max_readable_sequence = sequence;
    log->header.write_offset = slot_index * FBVBS_LOG_RECORD_V1_SIZE;
    *lock = 0U;
#else
    /* Use atomic write for max_readable_sequence (x86_64 aligned uint64_t writes are atomic) */
    __asm__ volatile("movq %1, %0"
                     : "=m"(log->header.max_readable_sequence)
                     : "r"(sequence)
                     : "memory");

    /* Use atomic write for write_offset (x86_64 aligned uint32_t writes are atomic) */
    __asm__ volatile("movl %1, %0"
                     : "=m"(log->header.write_offset)
                     : "r"(slot_index * FBVBS_LOG_RECORD_V1_SIZE)
                     : "memory");

    /* Release spinlock */
    __asm__ volatile("movl %0, %1"
                     :
                     : "r"(0U), "m"(*lock)
                     : "memory");
#endif

    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires payload_length != 0 && payload != \null ==>
             \valid_read(payload + (0 .. payload_length - 1));
    requires payload_length != 0 && payload != \null && state != \null ==>
             \separated(payload + (0 .. payload_length - 1), &state->mirror_log);
    assigns state->mirror_log, state->log_lock;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == RESOURCE_BUSY ||
                      \result == RESOURCE_EXHAUSTED;
    behavior null_state:
      assumes state == \null;
      assigns \nothing;
      ensures \result == INVALID_PARAMETER;
    behavior overflow_payload:
      assumes state != \null;
      assumes payload_length > 220;
      assigns \nothing;
      ensures \result == INVALID_PARAMETER;
    behavior null_payload:
      assumes state != \null;
      assumes payload_length <= 220;
      assumes payload_length != 0;
      assumes payload == \null;
      assigns \nothing;
      ensures \result == INVALID_PARAMETER;
    behavior ok:
      assumes state != \null;
      assumes payload_length <= 220;
      assumes payload_length == 0 || payload != \null;
      assigns state->mirror_log, state->log_lock;
      ensures \result == OK || \result == RESOURCE_BUSY || \result == RESOURCE_EXHAUSTED;
    complete behaviors;
    disjoint behaviors;
*/
int fbvbs_log_append(
    struct fbvbs_hypervisor_state *state,
    uint32_t cpu_id,
    uint32_t source_component,
    uint16_t severity,
    uint16_t event_code,
    const uint8_t *payload,
    uint32_t payload_length
) {
    if (state == NULL ||
        payload_length > sizeof(state->mirror_log.records[0].payload) ||
        (payload_length != 0U && payload == NULL)) {
        return INVALID_PARAMETER;
    }

    return fbvbs_log_append_core(
        &state->mirror_log, &state->log_lock,
        state->boot_id_hi, state->boot_id_lo,
        cpu_id, source_component, severity, event_code,
        payload, payload_length
    );
}

/*@ requires \valid(state) || state == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    behavior null_args:
      assumes state == \null || response == \null;
      ensures \result == INVALID_PARAMETER;
    behavior valid_args:
      assumes state != \null && response != \null;
      ensures \result == OK;
      ensures response->record_size == FBVBS_LOG_RECORD_V1_SIZE;
    complete behaviors;
    disjoint behaviors;
*/
int fbvbs_audit_get_mirror_info(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_audit_mirror_info_response *response
) {
    if (state == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    /* Return 0 for ring_gpa as mirror_log is not guest-accessible (embedded in hypervisor state).
     * Callers expecting a guest-accessible GPA should map mirror_log to guest memory first. */
    response->ring_gpa = 0U;
    response->ring_size = (uint32_t)sizeof(state->mirror_log);
    response->record_size = FBVBS_LOG_RECORD_V1_SIZE;
    return OK;
}
