#include <stddef.h>

#include "fbvbs_hypervisor.h"

static const uint32_t FBVBS_CRC32C_POLY = 0x82F63B78U;

uint32_t fbvbs_crc32c(const void *data, size_t length) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFU;
    size_t index;
    uint32_t bit;

    for (index = 0; index < length; ++index) {
        crc ^= bytes[index];
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

    fbvbs_zero_memory(&state->mirror_log, sizeof(state->mirror_log));
    state->mirror_log.header.abi_version = FBVBS_ABI_VERSION;
    state->mirror_log.header.total_size = (uint32_t)sizeof(state->mirror_log);
    state->mirror_log.header.record_size = FBVBS_LOG_RECORD_V1_SIZE;
    state->mirror_log.header.write_offset = 0U;
    state->mirror_log.header.max_readable_sequence = 0U;
    state->mirror_log.header.boot_id_hi = state->boot_id_hi;
    state->mirror_log.header.boot_id_lo = state->boot_id_lo;
    return OK;
}

int fbvbs_log_append(
    struct fbvbs_hypervisor_state *state,
    uint32_t cpu_id,
    uint32_t source_component,
    uint16_t severity,
    uint16_t event_code,
    const void *payload,
    uint32_t payload_length
) {
    uint64_t sequence;
    uint32_t slot_index;
    struct fbvbs_log_record_v1 *record;

    if (state == NULL ||
        payload_length > sizeof(state->mirror_log.records[0].payload) ||
        (payload_length != 0U && payload == NULL)) {
        return INVALID_PARAMETER;
    }

    sequence = state->mirror_log.header.max_readable_sequence + 1U;
    slot_index = (uint32_t)((sequence - 1U) % FBVBS_LOG_SLOT_COUNT);
    record = &state->mirror_log.records[slot_index];

    fbvbs_zero_memory(record, sizeof(*record));
    record->sequence = sequence;
    record->boot_id_hi = state->boot_id_hi;
    record->boot_id_lo = state->boot_id_lo;
    record->timestamp_counter = sequence;
    record->cpu_id = cpu_id;
    record->source_component = source_component;
    record->severity = severity;
    record->event_code = event_code;
    record->payload_length = payload_length;

    if (payload_length > 0U && payload != NULL) {
        fbvbs_copy_memory(record->payload, payload, payload_length);
    }

    record->crc32c = fbvbs_crc32c(record, offsetof(struct fbvbs_log_record_v1, crc32c));
    state->mirror_log.header.max_readable_sequence = sequence;
    state->mirror_log.header.write_offset = slot_index * FBVBS_LOG_RECORD_V1_SIZE;

    return OK;
}

int fbvbs_audit_get_mirror_info(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_audit_mirror_info_response *response
) {
    if (state == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    response->ring_gpa = (uint64_t)(uintptr_t)&state->mirror_log;
    response->ring_size = (uint32_t)sizeof(state->mirror_log);
    response->record_size = FBVBS_LOG_RECORD_V1_SIZE;
    return OK;
}
