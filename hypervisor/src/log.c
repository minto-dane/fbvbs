/* FBVBS Audit Log Subsystem
 *
 * Requirements: REQ-0005 (一次ログ経路), REQ-0100 (一次/ミラー分離),
 *   REQ-0101 (OOB 経路), REQ-0102 (ミラー非根拠),
 *   REQ-0103 (レコード形式 fbvbs_log_record_v1),
 *   REQ-0104 (CRC のみ不可 HMAC — PRODUCTION NOTE: Phase 5 crypto),
 *   REQ-0105 (ミラー read-only EPT), REQ-0106 (early boot/panic),
 *   REQ-0107 (リングバッファ形式),
 *   REQ-1103 (一次ログ経路運用性 — PRODUCTION NOTE: Phase 9 release gate)
 */

#include <stddef.h>
#include <stdint.h>

#include "fbvbs_hypervisor.h"

/* Guard: max slot_index * record_size must fit in uint32_t for write_offset */
_Static_assert((uint64_t)(FBVBS_LOG_SLOT_COUNT - 1U) * FBVBS_LOG_RECORD_V1_SIZE <= UINT32_MAX,
               "write_offset must fit in uint32_t");
_Static_assert((FBVBS_RATE_LIMIT_CLASSES & (FBVBS_RATE_LIMIT_CLASSES - 1U)) == 0U,
               "FBVBS_RATE_LIMIT_CLASSES must be a power of 2");

static const uint32_t FBVBS_CRC32C_POLY = 0x82F63B78U;
#define FBVBS_AUDIT_PRIMARY_LINE_MAX 768U

union fbvbs_log_record_bytes {
    struct fbvbs_log_record_v1 record;
    uint8_t bytes[sizeof(struct fbvbs_log_record_v1)];
};

#ifndef __FRAMAC__
__attribute__((weak))
void fbvbs_audit_primary_sink_write(const char *message) {
#ifdef FBVBS_BAREMETAL_BUILD
    fbvbs_boot_console_puts(message);
#else
    (void)message;
#endif
}

/*@ requires \valid(buffer + (0 .. capacity - 1));
    requires \valid(used);
    requires *used < capacity;
    assigns buffer[0 .. capacity - 1], *used;
*/
static void fbvbs_audit_line_append_char(
    char *buffer,
    uint32_t *used,
    uint32_t capacity,
    char ch
) {
    if (*used + 1U >= capacity) {
        return;
    }
    buffer[*used] = ch;
    *used += 1U;
    buffer[*used] = '\0';
}

/*@ requires \valid(buffer + (0 .. capacity - 1));
    requires \valid(used);
    assigns buffer[0 .. capacity - 1], *used;
*/
static void fbvbs_audit_line_append_text(
    char *buffer,
    uint32_t *used,
    uint32_t capacity,
    const char *text
) {
    if (text == NULL) {
        return;
    }
    while (*text != '\0') {
        fbvbs_audit_line_append_char(buffer, used, capacity, *text);
        ++text;
    }
}

/*@ requires \valid(buffer + (0 .. capacity - 1));
    requires \valid(used);
    assigns buffer[0 .. capacity - 1], *used;
*/
static void fbvbs_audit_line_append_hex(
    char *buffer,
    uint32_t *used,
    uint32_t capacity,
    uint64_t value,
    uint32_t digits
) {
    static const char hex_digits[16] = "0123456789ABCDEF";
    uint32_t nibble;

    if (digits == 0U) {
        return;
    }

    for (nibble = 0U; nibble < digits; ++nibble) {
        uint32_t shift = (digits - 1U - nibble) * 4U;
        uint32_t index = (uint32_t)((value >> shift) & 0x0FU);
        fbvbs_audit_line_append_char(
            buffer, used, capacity, hex_digits[index]
        );
    }
}

/* NOTE: This function has an external side effect via fbvbs_audit_primary_sink_write
 * (serial/platform I/O).  WP excludes this branch (#ifndef __FRAMAC__), so the
 * ACSL contract below is not verified and serves only as documentation. */
/*@ requires \valid_read(record);
    assigns \nothing;
*/
static void fbvbs_emit_primary_sink_record(
    const struct fbvbs_log_record_v1 *record
) {
    char line[FBVBS_AUDIT_PRIMARY_LINE_MAX];
    const uint32_t line_capacity = FBVBS_AUDIT_PRIMARY_LINE_MAX;
    uint32_t used = 0U;
    uint32_t index;

    if (record == NULL) {
        return;
    }

    line[0] = '\0';
    fbvbs_audit_line_append_text(line, &used, line_capacity, "AUDIT seq=");
    fbvbs_audit_line_append_hex(line, &used, line_capacity, record->sequence, 16U);
    fbvbs_audit_line_append_text(line, &used, line_capacity, " boot_hi=");
    fbvbs_audit_line_append_hex(line, &used, line_capacity, record->boot_id_hi, 16U);
    fbvbs_audit_line_append_text(line, &used, line_capacity, " boot_lo=");
    fbvbs_audit_line_append_hex(line, &used, line_capacity, record->boot_id_lo, 16U);
    fbvbs_audit_line_append_text(line, &used, line_capacity, " cpu=");
    fbvbs_audit_line_append_hex(line, &used, line_capacity, record->cpu_id, 8U);
    fbvbs_audit_line_append_text(line, &used, line_capacity, " src=");
    fbvbs_audit_line_append_hex(line, &used, line_capacity, record->source_component, 8U);
    fbvbs_audit_line_append_text(line, &used, line_capacity, " sev=");
    fbvbs_audit_line_append_hex(line, &used, line_capacity, record->severity, 4U);
    fbvbs_audit_line_append_text(line, &used, line_capacity, " evt=");
    fbvbs_audit_line_append_hex(line, &used, line_capacity, record->event_code, 4U);
    fbvbs_audit_line_append_text(line, &used, line_capacity, " len=");
    fbvbs_audit_line_append_hex(line, &used, line_capacity, record->payload_length, 8U);
    fbvbs_audit_line_append_text(line, &used, line_capacity, " crc=");
    fbvbs_audit_line_append_hex(line, &used, line_capacity, record->crc32c, 8U);
    fbvbs_audit_line_append_text(line, &used, line_capacity, " payload=");

    for (index = 0U;
         index < record->payload_length && index < sizeof(record->payload);
        ++index) {
        fbvbs_audit_line_append_hex(
            line, &used, line_capacity, record->payload[index], 2U
        );
    }
    fbvbs_audit_line_append_char(line, &used, line_capacity, '\n');
    fbvbs_audit_primary_sink_write(line);
}
#else
/*@ assigns \nothing; */
void fbvbs_audit_primary_sink_write(const char *message) {
    (void)message;
}

/*@ requires \valid_read(record);
    assigns \nothing;
*/
static void fbvbs_emit_primary_sink_record(
    const struct fbvbs_log_record_v1 *record
) {
    (void)record;
}
#endif

/*@ requires \valid(lock);
    assigns *lock;
    ensures \result == OK || \result == RESOURCE_BUSY;
*/
static int fbvbs_log_spinlock_acquire(volatile uint32_t *lock) {
#ifdef __FRAMAC__
    *lock = 1U;
    return OK;
#else
    uint32_t lock_val;
    uint32_t spin_count = 0U;

    do {
        __asm__ volatile("xchgl %0, %1"
                         : "=r"(lock_val), "+m"(*lock)
                         : "0"(1U)
                         : "memory");
        if (lock_val == 0U) {
            return OK;
        }
        ++spin_count;
        __asm__ volatile("pause" : : : "memory");
    } while (spin_count < 10000U);

    return RESOURCE_BUSY;
#endif
}

/*@ requires \valid(lock);
    assigns *lock;
*/
static void fbvbs_log_spinlock_release(volatile uint32_t *lock) {
#ifdef __FRAMAC__
    *lock = 0U;
#else
    __asm__ volatile("movl %1, %0"
                     : "=m"(*lock)
                     : "r"(0U)
                     : "memory");
#endif
}

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
    state->runtime_state_flags |= FBVBS_RUNTIME_AUDIT_PRIMARY_OOB;
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
    struct fbvbs_log_record_v1 sink_record;

    if (fbvbs_log_spinlock_acquire(lock) != OK) {
        return RESOURCE_BUSY;
    }

    if (log->header.max_readable_sequence == UINT64_MAX) {
        fbvbs_log_spinlock_release(lock);
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
        uint8_t crc_bytes[offsetof(struct fbvbs_log_record_v1, crc32c)];
        size_t crc_len = offsetof(struct fbvbs_log_record_v1, crc32c);

#ifdef __FRAMAC__
        (void)crc_bytes;
        (void)crc_len;
        record->crc32c = 0U;
#else
        fbvbs_copy_bytes(crc_bytes, (const uint8_t *)(const void *)record, crc_len);
        record->crc32c = fbvbs_crc32c(crc_bytes, crc_len);
#endif
    }

#ifdef __FRAMAC__
    /* WP model: direct field writes (atomic on real hardware) */
    log->header.max_readable_sequence = sequence;
    log->header.write_offset = slot_index * FBVBS_LOG_RECORD_V1_SIZE;
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

#endif

    sink_record = *record;
    fbvbs_log_spinlock_release(lock);
    fbvbs_emit_primary_sink_record(&sink_record);

    return OK;
}

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

#ifdef __FRAMAC__
    (void)cpu_id;
    (void)source_component;
    (void)severity;
    (void)event_code;
    (void)payload;
    (void)payload_length;
    return OK;
#else
    return fbvbs_log_append_core(
        &state->mirror_log, &state->log_lock,
        state->boot_id_hi, state->boot_id_lo,
        cpu_id, source_component, severity, event_code,
        payload, payload_length
    );
#endif
}

/* Phase 0A-5: Log rate limiting.
 *
 * Events are classified into 16 classes by event_code >> 4.
 * Each class has a counter that resets every FBVBS_LOG_SLOT_COUNT appends
 * (one window = one full ring buffer rotation).
 *
 * When a class exceeds FBVBS_RATE_LIMIT_THRESHOLD in one window, subsequent
 * events of that class are silently dropped and a RATE_LIMIT_SUMMARY event
 * is emitted when the window rotates.
 *
 * Exempt from rate limiting:
 *   - SEVERITY_CRITICAL and SEVERITY_ALERT (corruption, key zeroize, etc.)
 *   - RATE_LIMIT_SUMMARY events themselves (prevents recursion)
 */

/* CONCURRENCY: Rate-limit state is protected by state->log_lock.
 * Summary records are emitted only after releasing the lock so they
 * can safely reuse fbvbs_log_append without recursive lock acquisition.
 * Exception handlers (#MC/#NMI/#DF) call fbvbs_log_append directly,
 * bypassing rate limiting entirely. */
int fbvbs_log_append_rate_limited(
    struct fbvbs_hypervisor_state *state,
    uint32_t cpu_id,
    uint32_t source_component,
    uint16_t severity,
    uint16_t event_code,
    const uint8_t *payload,
    uint32_t payload_length
) {
    uint32_t dropped_snapshot[FBVBS_RATE_LIMIT_CLASSES];
    uint32_t ci;
    uint32_t event_class;
    uint64_t current_seq;
    uint32_t emit_summary = 0U;
    uint32_t prior_count = 0U;
    int result;

    if (state == NULL) {
        return INVALID_PARAMETER;
    }

#ifdef __FRAMAC__
    return fbvbs_log_append(state, cpu_id, source_component,
                            severity, event_code, payload, payload_length);
#else
    /*@ loop invariant 0 <= ci <= FBVBS_RATE_LIMIT_CLASSES;
        loop assigns ci, dropped_snapshot[0 .. FBVBS_RATE_LIMIT_CLASSES - 1];
        loop variant FBVBS_RATE_LIMIT_CLASSES - ci;
    */
    for (ci = 0U; ci < FBVBS_RATE_LIMIT_CLASSES; ++ci) {
        dropped_snapshot[ci] = 0U;
    }

    if (fbvbs_log_spinlock_acquire(&state->log_lock) != OK) {
        return RESOURCE_BUSY;
    }

    current_seq = state->mirror_log.header.max_readable_sequence;
    if (current_seq >= state->log_rate_window_sequence + FBVBS_LOG_SLOT_COUNT) {
        /*@ loop invariant 0 <= ci <= FBVBS_RATE_LIMIT_CLASSES;
            loop assigns ci, emit_summary,
                    dropped_snapshot[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
                    state->log_rate_counts[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
                    state->log_rate_dropped[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
                    state->log_rate_window_sequence;
            loop variant FBVBS_RATE_LIMIT_CLASSES - ci;
        */
        for (ci = 0U; ci < FBVBS_RATE_LIMIT_CLASSES; ++ci) {
            dropped_snapshot[ci] = state->log_rate_dropped[ci];
            if (dropped_snapshot[ci] != 0U) {
                emit_summary = 1U;
            }
            state->log_rate_counts[ci] = 0U;
            state->log_rate_dropped[ci] = 0U;
        }
        state->log_rate_window_sequence = current_seq;
    }

    /* Exempt: CRITICAL/ALERT severity, and RATE_LIMIT_SUMMARY itself */
    if (severity >= FBVBS_SEVERITY_CRITICAL ||
        event_code == FBVBS_EVENT_RATE_LIMIT_SUMMARY) {
        fbvbs_log_spinlock_release(&state->log_lock);
        if (emit_summary != 0U) {
            /*@ loop invariant 0 <= ci <= FBVBS_RATE_LIMIT_CLASSES;
                loop assigns ci, state->mirror_log, state->log_lock;
                loop variant FBVBS_RATE_LIMIT_CLASSES - ci;
            */
            for (ci = 0U; ci < FBVBS_RATE_LIMIT_CLASSES; ++ci) {
                if (dropped_snapshot[ci] != 0U) {
                    uint8_t summary[8];
                    summary[0] = (uint8_t)(ci & 0xFFU);
                    summary[1] = (uint8_t)((ci >> 8U) & 0xFFU);
                    summary[2] = 0U;
                    summary[3] = 0U;
                    summary[4] = (uint8_t)(dropped_snapshot[ci] & 0xFFU);
                    summary[5] = (uint8_t)((dropped_snapshot[ci] >> 8U) & 0xFFU);
                    summary[6] = (uint8_t)((dropped_snapshot[ci] >> 16U) & 0xFFU);
                    summary[7] = (uint8_t)((dropped_snapshot[ci] >> 24U) & 0xFFU);
                    (void)fbvbs_log_append(
                        state, cpu_id,
                        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                        (uint16_t)FBVBS_SEVERITY_WARNING,
                        (uint16_t)FBVBS_EVENT_RATE_LIMIT_SUMMARY,
                        summary, 8U
                    );
                }
            }
        }
        return fbvbs_log_append(state, cpu_id, source_component,
                                severity, event_code, payload, payload_length);
    }

    /* Rate limit check */
    event_class = ((uint32_t)event_code >> 4U) & (FBVBS_RATE_LIMIT_CLASSES - 1U);
    /*@ assert event_class < FBVBS_RATE_LIMIT_CLASSES; */

    if (state->log_rate_counts[event_class] >= FBVBS_RATE_LIMIT_THRESHOLD) {
        /* Drop this event, increment dropped counter with saturation */
        if (state->log_rate_dropped[event_class] < UINT32_MAX) {
            state->log_rate_dropped[event_class] += 1U;
        }
        fbvbs_log_spinlock_release(&state->log_lock);
        return OK;  /* Silently dropped — not an error for caller */
    }

    prior_count = state->log_rate_counts[event_class];
    if (state->log_rate_counts[event_class] < UINT32_MAX) {
        state->log_rate_counts[event_class] += 1U;
    }
    uint64_t saved_window_sequence = state->log_rate_window_sequence;
    fbvbs_log_spinlock_release(&state->log_lock);

    if (emit_summary != 0U) {
        /*@ loop invariant 0 <= ci <= FBVBS_RATE_LIMIT_CLASSES;
            loop assigns ci, state->mirror_log, state->log_lock;
            loop variant FBVBS_RATE_LIMIT_CLASSES - ci;
        */
        for (ci = 0U; ci < FBVBS_RATE_LIMIT_CLASSES; ++ci) {
            if (dropped_snapshot[ci] != 0U) {
                uint8_t summary[8];
                summary[0] = (uint8_t)(ci & 0xFFU);
                summary[1] = (uint8_t)((ci >> 8U) & 0xFFU);
                summary[2] = 0U;
                summary[3] = 0U;
                summary[4] = (uint8_t)(dropped_snapshot[ci] & 0xFFU);
                summary[5] = (uint8_t)((dropped_snapshot[ci] >> 8U) & 0xFFU);
                summary[6] = (uint8_t)((dropped_snapshot[ci] >> 16U) & 0xFFU);
                summary[7] = (uint8_t)((dropped_snapshot[ci] >> 24U) & 0xFFU);
                (void)fbvbs_log_append(
                    state, cpu_id,
                    FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
                    (uint16_t)FBVBS_SEVERITY_WARNING,
                    (uint16_t)FBVBS_EVENT_RATE_LIMIT_SUMMARY,
                    summary, 8U
                );
            }
        }
    }

    result = fbvbs_log_append(state, cpu_id, source_component,
                              severity, event_code, payload, payload_length);
    if (result != OK) {
        if (fbvbs_log_spinlock_acquire(&state->log_lock) == OK) {
            if (saved_window_sequence == state->log_rate_window_sequence) {
                state->log_rate_counts[event_class] = prior_count;
            }
            fbvbs_log_spinlock_release(&state->log_lock);
        }
    }
    return result;
#endif
}

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
