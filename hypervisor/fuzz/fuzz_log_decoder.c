/* FBVBS Audit Log Decoder Fuzzer
 *
 * Phase 9-1: Continuous fuzzing of log record parsing (REQ-1004).
 *
 * Target: fbvbs_crc32c, fbvbs_log_init, fbvbs_log_append,
 *   fbvbs_log_append_rate_limited, fbvbs_audit_get_mirror_info.
 * The log subsystem processes records at a trust boundary between
 * the microhypervisor and the host mirror reader. This harness feeds
 * arbitrary bytes to find:
 *   - CRC32C computation errors with crafted input
 *   - Ring buffer index overflows in log_append_core
 *   - Rate limiter counter overflow / window rotation bugs
 *   - Spinlock acquisition edge cases
 *   - Payload length validation bypasses
 *
 * Build (standalone):
 *   gcc -g -O1 -fsanitize=address,undefined
 *     -DFUZZ_TARGET -I../include
 *     fuzz_log_decoder.c ../src/log.c ../src/memory_utils.c -o fuzz_log_decoder
 *
 * Build (AFL++):
 *   afl-gcc-fast -g -O1 -fsanitize=address,undefined
 *     -DFUZZ_TARGET -I../include
 *     fuzz_log_decoder.c ../src/log.c ../src/memory_utils.c -o fuzz_log_decoder
 */

#include "fbvbs_hypervisor.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

_Static_assert(sizeof(struct fbvbs_log_record_v1) == FBVBS_LOG_RECORD_V1_SIZE,
               "log record size mismatch — update mirrored definition");

_Static_assert(sizeof(struct fbvbs_log_storage) ==
               sizeof(struct fbvbs_log_ring_header_v1) +
               FBVBS_LOG_SLOT_COUNT * sizeof(struct fbvbs_log_record_v1),
               "log storage size mismatch");

/* External declarations */
extern uint32_t fbvbs_crc32c(const uint8_t *data, size_t length);
extern int fbvbs_log_init(struct fbvbs_hypervisor_state *state);
extern int fbvbs_log_append(
    struct fbvbs_hypervisor_state *state,
    uint32_t cpu_id,
    uint32_t source_component,
    uint16_t severity,
    uint16_t event_code,
    const uint8_t *payload,
    uint32_t payload_length);
extern int fbvbs_log_append_rate_limited(
    struct fbvbs_hypervisor_state *state,
    uint32_t cpu_id,
    uint32_t source_component,
    uint16_t severity,
    uint16_t event_code,
    const uint8_t *payload,
    uint32_t payload_length);
extern int fbvbs_audit_get_mirror_info(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_audit_mirror_info_response *response);

static struct fbvbs_hypervisor_state g_state;

static void fuzz_reset_state(void)
{
    memset(&g_state, 0, sizeof(g_state));
    g_state.boot_id_hi = 0x1234567890ABCDEFULL;
    g_state.boot_id_lo = 0xFEDCBA0987654321ULL;
    (void)fbvbs_log_init(&g_state);
}

static int fuzz_one_input(const uint8_t *data, size_t size)
{
    uint32_t cpu_id;
    uint32_t source_component;
    uint16_t severity;
    uint16_t event_code;
    uint32_t payload_length;
    uint32_t action;

    if (size < 16U) {
        return 0;
    }

    fuzz_reset_state();

    /* Parse fuzz input into log parameters */
    memcpy(&action, data, 4U);
    memcpy(&cpu_id, data + 4U, 4U);
    memcpy(&severity, data + 8U, 2U);
    memcpy(&event_code, data + 10U, 2U);
    memcpy(&payload_length, data + 12U, 4U);
    data += 16U;
    size -= 16U;

    source_component = cpu_id & 0x7U; /* 0..7 valid component IDs */

    switch (action & 0x7U) {
    case 0U:
        /* Exercise fbvbs_log_append with fuzzer-controlled payload */
        {
            uint32_t safe_length = (size > 0U) ? ((payload_length > (uint32_t)size) ? (uint32_t)size : payload_length) : 0U;
            (void)fbvbs_log_append(
                &g_state, cpu_id, source_component,
                severity, event_code,
                data, safe_length);
        }
        break;

    case 1U:
        /* Exercise rate-limited append with multiple records to
         * stress the rate limiter window rotation and drop counters */
        {
            uint32_t i;
            uint32_t count = (payload_length & 0x3FU) + 1U; /* 1..64 records */
            for (i = 0; i < count; ++i) {
                uint16_t ev = (uint16_t)(event_code + (uint16_t)(i & 0xFFU));
                (void)fbvbs_log_append_rate_limited(
                    &g_state, cpu_id, source_component,
                    severity, ev,
                    data, (uint32_t)((size > 220U) ? 220U : size));
            }
        }
        break;

    case 2U:
        /* Exercise CRC32C with arbitrary data */
        (void)fbvbs_crc32c(data, size);
        break;

    case 3U:
        /* Fill the ring buffer completely, then append more to test wrap */
        {
            uint32_t i;
            for (i = 0; i < FBVBS_LOG_SLOT_COUNT + 4U; ++i) {
                (void)fbvbs_log_append(
                    &g_state, i, 0U,
                    severity, event_code,
                    data, (uint32_t)((size > 220U) ? 220U : size));
            }
        }
        break;

    case 4U:
        /* Exercise NULL / boundary parameter cases */
        (void)fbvbs_log_append(NULL, cpu_id, source_component,
                               severity, event_code, data, payload_length);
        (void)fbvbs_log_append(&g_state, cpu_id, source_component,
                               severity, event_code, NULL, 1U);
        (void)fbvbs_log_append(&g_state, cpu_id, source_component,
                               severity, event_code, data, 221U);
        (void)fbvbs_log_init(NULL);
        {
            struct fbvbs_audit_mirror_info_response resp;
            (void)fbvbs_audit_get_mirror_info(NULL, &resp);
            (void)fbvbs_audit_get_mirror_info(&g_state, NULL);
            (void)fbvbs_audit_get_mirror_info(&g_state, &resp);
        }
        break;

    case 5U:
        /* Stress the sequence counter near UINT64_MAX to test exhaustion */
        g_state.mirror_log.header.max_readable_sequence = UINT64_MAX - 2U;
        (void)fbvbs_log_append(&g_state, cpu_id, source_component,
                               severity, event_code,
                               data, (uint32_t)((size > 220U) ? 220U : size));
        (void)fbvbs_log_append(&g_state, cpu_id, source_component,
                               severity, event_code,
                               data, (uint32_t)((size > 220U) ? 220U : size));
        /* This one should return RESOURCE_EXHAUSTED */
        (void)fbvbs_log_append(&g_state, cpu_id, source_component,
                               severity, event_code,
                               data, (uint32_t)((size > 220U) ? 220U : size));
        break;

    case 6U:
        /* CRC verification: write a record, then verify CRC matches */
        {
            uint32_t rec_payload_len = (uint32_t)((size > 220U) ? 220U : size);
            (void)fbvbs_log_append(&g_state, cpu_id, source_component,
                                   severity, event_code,
                                   data, rec_payload_len);
            /* Read back and verify CRC */
            if (g_state.mirror_log.header.max_readable_sequence > 0U) {
                uint32_t slot = (uint32_t)(
                    (g_state.mirror_log.header.max_readable_sequence - 1U)
                    % FBVBS_LOG_SLOT_COUNT);
                struct fbvbs_log_record_v1 *rec =
                    &g_state.mirror_log.records[slot];
                union {
                    struct fbvbs_log_record_v1 record;
                    uint8_t bytes[sizeof(struct fbvbs_log_record_v1)];
                } overlay;
                size_t crc_len = offsetof(struct fbvbs_log_record_v1, crc32c);
                uint32_t computed;
                overlay.record = *rec;
                computed = fbvbs_crc32c(overlay.bytes, crc_len);
                /* CRC must match what was stored */
                if (computed != rec->crc32c) {
                    __builtin_trap();
                }
            }
        }
        break;

    default:
        /* Exercise rate limiter with CRITICAL severity (exempt from limits) */
        (void)fbvbs_log_append_rate_limited(
            &g_state, cpu_id, source_component,
            (uint16_t)FBVBS_SEVERITY_CRITICAL, event_code,
            data, (uint32_t)((size > 220U) ? 220U : size));
        break;
    }

    return 0;
}

/* ---------- Harness entry points ---------- */

#ifdef FUZZ_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_one_input(data, size);
}

#elif defined(FUZZ_TARGET)

#ifdef __AFL_FUZZ_TESTCASE_LEN
/* AFL++ persistent mode */
__AFL_FUZZ_INIT();
int main(void)
{
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(100000)) {
        unsigned int len = __AFL_FUZZ_TESTCASE_LEN;
        fuzz_one_input(buf, (size_t)len);
    }
    return 0;
}
#else
/* Standalone: read from stdin or file argument */
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t buf[65536];
    size_t n;

    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            perror(argv[1]);
            return 1;
        }
    } else {
        f = stdin;
    }

    n = fread(buf, 1, sizeof(buf), f);
    if (argc > 1) {
        fclose(f);
    }

    return fuzz_one_input(buf, n);
}
#endif /* __AFL_FUZZ_TESTCASE_LEN */

#endif /* FUZZ_LIBFUZZER / FUZZ_TARGET */
