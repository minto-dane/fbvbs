/* FBVBS Fault Injection Tests (Phase 9-1, Section 44)
 *
 * Deterministic tests for fail-closed behavior under fault conditions:
 *   1. Log ring buffer overflow — sequence exhaustion
 *   2. Log ring buffer saturation — all slots filled
 *   3. Rollback attack — stale manifest generation rejection
 *   4. DMA fault — IOMMU domain inconsistency fail-closed
 *   5. vCPU stuck — watchdog preemption timer intervention
 *   6. Interrupt storm — rate limiter drops + CRITICAL/ALERT exempt
 *   7. Partition fault state restriction — only valid source states
 *   8. Partition fault cascading — double-fault stays FAULTED
 *   9. Log rate limiter window rotation — summary emission
 *  10. Watchdog voluntary exit reset — counter clears on I/O exit
 *
 * Requirements: REQ-1004 (継続的ファジング/テスト), REQ-1005 (MC/DC カバレッジ)
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../include/fbvbs_cpu_security.h"
#include "../include/fbvbs_hypervisor.h"

static struct fbvbs_partition_recover_request make_partition_recover_request(
    const struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t recovery_flags,
    uint64_t session_correlation_id,
    uint64_t confirmation_nonce
)
{
    struct {
        uint64_t partition_id;
        uint64_t session_correlation_id;
        uint64_t confirmation_nonce;
    } ledger_seed = {
        .partition_id = partition_id,
        .session_correlation_id = session_correlation_id,
        .confirmation_nonce = confirmation_nonce,
    };
    struct fbvbs_partition_recover_request request = {
        .partition_id = partition_id,
        .recovery_flags = recovery_flags,
        .session_correlation_id = session_correlation_id,
        .confirmation_nonce = confirmation_nonce,
        .approval_expires_utc = (state != NULL && state->trusted_time_seconds != 0U)
            ? state->trusted_time_seconds + 3600U
            : 3600U,
        .reserved0 = 0U,
        .reserved1 = 0U,
    };

    fbvbs_sha384(
        &ledger_seed,
        (uint64_t)sizeof(ledger_seed),
        request.approval_ledger_digest
    );

    fbvbs_partition_compute_recovery_approval_digest(
        state,
        partition_id,
        recovery_flags,
        session_correlation_id,
        confirmation_nonce,
        request.approval_expires_utc,
        request.approval_ledger_digest,
        request.recovery_approval_digest
    );
    return request;
}

/* --- 1. Log ring buffer overflow: sequence exhaustion --- */
static void test_log_sequence_exhaustion_fails_closed(void) {
    struct fbvbs_hypervisor_state state;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;

    /* Set sequence counter to near-max */
    state.mirror_log.header.max_readable_sequence = UINT64_MAX - 1U;

    /* First append should succeed (sequence UINT64_MAX - 1 -> UINT64_MAX) */
    int status = fbvbs_log_append(&state, 0U, 0U, 0U, 0U, NULL, 0U);
    assert(status == OK);
    assert(state.mirror_log.header.max_readable_sequence == UINT64_MAX);

    /* Second append must fail closed — no wraparound allowed */
    status = fbvbs_log_append(&state, 0U, 0U, 0U, 0U, NULL, 0U);
    assert(status == RESOURCE_EXHAUSTED);
    assert(state.mirror_log.header.max_readable_sequence == UINT64_MAX);
}

/* --- 2. Log ring buffer saturation --- */
static void test_log_ring_saturation_overwrites_oldest(void) {
    struct fbvbs_hypervisor_state state;
    uint32_t i;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;

    /* Fill all slots + 1 to trigger wraparound */
    for (i = 0; i < FBVBS_LOG_SLOT_COUNT + 1U; i++) {
        uint8_t payload[4];
        payload[0] = (uint8_t)(i & 0xFFU);
        payload[1] = (uint8_t)((i >> 8U) & 0xFFU);
        payload[2] = 0U;
        payload[3] = 0U;
        int status = fbvbs_log_append(
            &state, 0U, FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
            (uint16_t)FBVBS_SEVERITY_INFO, (uint16_t)FBVBS_EVENT_BOOT_COMPLETE,
            payload, 4U
        );
        assert(status == OK);
    }

    /* Verify sequence count matches writes */
    assert(state.mirror_log.header.max_readable_sequence == FBVBS_LOG_SLOT_COUNT + 1U);

    /* The ring wraps — slot 0 now contains entry FBVBS_LOG_SLOT_COUNT (0-indexed).
     * The oldest entry (sequence 1) was overwritten.
     * Verify the newest entry has the expected sequence. */
    uint32_t newest_slot = (FBVBS_LOG_SLOT_COUNT) % FBVBS_LOG_SLOT_COUNT;
    assert(state.mirror_log.records[newest_slot].sequence ==
           FBVBS_LOG_SLOT_COUNT + 1U);
}

/* --- 3. Rollback attack: stale manifest generation rejection --- */
static void test_rollback_stale_manifest_generation_rejected(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_verdict_response response = {0};
    struct fbvbs_kci_verify_module_request request = {0};
    struct fbvbs_metadata_manifest manifest = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) struct fbvbs_metadata_set_page page;
    } manifest_page = {0};
    struct {
        _Alignas(FBVBS_PAGE_SIZE) uint8_t bytes[FBVBS_PAGE_SIZE];
    } module_page = {{0}};
    int status;

    memset(&state, 0, sizeof(state));
    memset(module_page.bytes, 0xC3, sizeof(module_page.bytes));

    /* Set up manifest with generation 10 */
    manifest.object_id = 0xAAAAU;
    manifest.generation = 10U;
    manifest.flags = FBVBS_METADATA_FLAG_SIGNATURE_VALID;

    manifest_page.page.count = 1U;
    manifest_page.page.manifest_gpas[0] = (uint64_t)(uintptr_t)&manifest;

    state.current_manifest_set_id = 1U;
    state.manifest_sets[0].active = true;
    state.manifest_sets[0].manifest_count = 1U;
    state.manifest_sets[0].verified_manifest_set_id = 1U;
    state.manifest_sets[0].manifest_set_page_gpa =
        (uint64_t)(uintptr_t)&manifest_page.page;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0xBBBBU;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_MODULE;
    state.artifact_catalog.entries[0].related_index = 1U;
    fbvbs_sha384(
        module_page.bytes,
        sizeof(module_page.bytes),
        state.artifact_catalog.entries[0].payload_hash
    );
    state.artifact_catalog.entries[1].object_id = 0xAAAAU;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 1U;

    state.approvals[0].active = true;
    state.approvals[0].artifact_object_id = 0xBBBBU;
    state.approvals[0].manifest_object_id = 0xAAAAU;
    state.approvals[0].manifest_set_id = 1U;
    state.approvals[0].verified_manifest_set_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x100U;
    state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    state.partitions[0].mapped_bytes = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].active = true;
    state.partitions[0].mappings[0].memory_object_id = 0xBBBBU;
    state.partitions[0].mappings[0].guest_physical_address =
        (uint64_t)(uintptr_t)module_page.bytes;
    state.partitions[0].mappings[0].size = FBVBS_PAGE_SIZE;
    state.partitions[0].mappings[0].permissions = FBVBS_MEMORY_PERMISSION_READ;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0xBBBBU;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = FBVBS_PAGE_SIZE;
    state.memory_objects[0].map_count = 1U;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count = 1U;
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)module_page.bytes;

    /* Attempt with OLDER generation (rollback attempt) */
    request.module_object_id = 0xBBBBU;
    request.manifest_object_id = 0xAAAAU;
    request.generation = 5U;  /* Older than current 10 */
    status = fbvbs_kci_verify_module(&state, &request, &response);
    assert(status == GENERATION_MISMATCH);

    /* Attempt with FUTURE generation (also rejected) */
    request.generation = 999U;
    status = fbvbs_kci_verify_module(&state, &request, &response);
    assert(status == GENERATION_MISMATCH);

    /* Correct generation succeeds */
    request.generation = 10U;
    status = fbvbs_kci_verify_module(&state, &request, &response);
    assert(status == OK);
    assert(response.verdict == 1U);
}

/* --- 4. DMA fault: IOMMU domain mismatch fail-closed --- */
static void test_device_assign_without_iommu_fails_closed(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7777U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.device_catalog.count = 1U;
    state.device_catalog.entries[0].device_id = 0xD001U;

    request.vm_partition_id = 0x7777U;
    request.device_id = 0xD001U;

    /* Without IOMMU, device passthrough must be denied */
    status = fbvbs_vm_assign_device(&state, &request);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].assigned_device_count == 0U);
}

static void test_device_assign_with_iommu_but_no_qualification_fails_closed(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_device_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));

    /* IOMMU available but device not qualified */
    state.cpu_security.iommu.iommu_type = IOMMU_TYPE_VTD;
    state.cpu_security.iommu.dma_remapping = 1U;
    state.cpu_security.iommu.interrupt_remapping = 1U;
    state.cpu_security.iommu.kernel_dma_protection = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7777U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.device_catalog.count = 1U;
    state.device_catalog.entries[0].device_id = 0xD001U;

    request.vm_partition_id = 0x7777U;
    request.device_id = 0xD001U;

    /* With IOMMU but no qualification, still denied */
    status = fbvbs_vm_assign_device(&state, &request);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].assigned_device_count == 0U);
}

/* --- 5. vCPU stuck: watchdog preemption timer intervention --- */
static void test_watchdog_faults_hung_partition(void) {
    struct fbvbs_hypervisor_state state;
    uint32_t i;
    int faulted;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x8888U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNING;
    state.partitions[0].vcpu_count = 1U;

    /* Simulate preemption timer exits below threshold */
    for (i = 0; i < FBVBS_WATCHDOG_MAX_CONSECUTIVE - 1U; i++) {
        faulted = fbvbs_watchdog_on_timer_exit(&state, 0U);
        assert(faulted == 0);
        assert(state.partitions[0].state == FBVBS_PARTITION_STATE_RUNNING);
    }

    /* The Nth exit exceeds threshold — partition must be faulted */
    faulted = fbvbs_watchdog_on_timer_exit(&state, 0U);
    assert(faulted == 1);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_FAULTED);
    assert(state.partitions[0].watchdog_faults_total == 1U);
    assert(state.partitions[0].consecutive_timer_exits == 0U);
}

/* --- 5b. Watchdog negative cases: unoccupied and non-running --- */
static void test_watchdog_ignores_unoccupied_and_nonrunning(void) {
    struct fbvbs_hypervisor_state state;
    int faulted;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    /* Case 1: unoccupied slot — must return 0, no state change */
    state.partitions[0].occupied = false;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNING;
    faulted = fbvbs_watchdog_on_timer_exit(&state, 0U);
    assert(faulted == 0);
    assert(state.partitions[0].consecutive_timer_exits == 0U);

    /* Case 2: occupied but FAULTED — must return 0 */
    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7777U;
    state.partitions[0].state = FBVBS_PARTITION_STATE_FAULTED;
    faulted = fbvbs_watchdog_on_timer_exit(&state, 0U);
    assert(faulted == 0);
    assert(state.partitions[0].consecutive_timer_exits == 0U);

    /* Case 3: occupied but DESTROYED — must return 0 */
    state.partitions[0].state = FBVBS_PARTITION_STATE_DESTROYED;
    faulted = fbvbs_watchdog_on_timer_exit(&state, 0U);
    assert(faulted == 0);

    /* Case 4: voluntary exit on unoccupied slot — no-op (defensive) */
    state.partitions[1].occupied = false;
    fbvbs_watchdog_on_voluntary_exit(&state, 1U);
    assert(state.partitions[1].consecutive_timer_exits == 0U);
}

/* --- 6. Interrupt storm: rate limiter + CRITICAL/ALERT exemption --- */
static void test_rate_limiter_drops_excess_and_exempts_critical(void) {
    struct fbvbs_hypervisor_state state;
    uint32_t i;
    int status;
    uint32_t event_class;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    /* Compute which rate class POLICY_DENY falls into */
    event_class = ((uint32_t)FBVBS_EVENT_POLICY_DENY >> 4U) &
                  (FBVBS_RATE_LIMIT_CLASSES - 1U);

    /* Fill rate limit for one event class via direct counter set
     * (avoids window rotation complexity from 100 actual writes) */
    state.log_rate_counts[event_class] = FBVBS_RATE_LIMIT_THRESHOLD;

    uint64_t seq_before = state.mirror_log.header.max_readable_sequence;

    /* INFO event in saturated class should be silently dropped */
    status = fbvbs_log_append_rate_limited(
        &state, 0U, FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        (uint16_t)FBVBS_SEVERITY_INFO,
        (uint16_t)FBVBS_EVENT_POLICY_DENY,
        NULL, 0U
    );
    assert(status == OK);  /* Returns OK but doesn't write */
    assert(state.mirror_log.header.max_readable_sequence == seq_before);
    assert(state.log_rate_dropped[event_class] == 1U);

    /* Drop counter increments on each suppressed event */
    for (i = 0; i < 5U; i++) {
        (void)fbvbs_log_append_rate_limited(
            &state, 0U, FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
            (uint16_t)FBVBS_SEVERITY_INFO,
            (uint16_t)FBVBS_EVENT_POLICY_DENY,
            NULL, 0U
        );
    }
    assert(state.log_rate_dropped[event_class] == 6U);
    assert(state.mirror_log.header.max_readable_sequence == seq_before);

    /* CRITICAL severity is EXEMPT from rate limiting */
    status = fbvbs_log_append_rate_limited(
        &state, 0U, FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        (uint16_t)FBVBS_SEVERITY_CRITICAL,
        (uint16_t)FBVBS_EVENT_POLICY_DENY,
        NULL, 0U
    );
    assert(status == OK);
    assert(state.mirror_log.header.max_readable_sequence == seq_before + 1U);

    /* ALERT severity is also EXEMPT */
    status = fbvbs_log_append_rate_limited(
        &state, 0U, FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        (uint16_t)FBVBS_SEVERITY_ALERT,
        (uint16_t)FBVBS_EVENT_WATCHDOG_EXPIRY,
        NULL, 0U
    );
    assert(status == OK);
    assert(state.mirror_log.header.max_readable_sequence == seq_before + 2U);
}

/* --- 7. Partition fault state restriction --- */
static void test_partition_fault_rejects_invalid_source_states(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    /* CREATED state — cannot fault (lifecycle skip) */
    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x9000U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;

    status = fbvbs_partition_fault(
        &state, 0x9000U, 1U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0U, 0U
    );
    assert(status == INVALID_STATE);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_CREATED);

    /* MEASURED state — cannot fault (lifecycle skip) */
    state.partitions[0].state = FBVBS_PARTITION_STATE_MEASURED;
    status = fbvbs_partition_fault(
        &state, 0x9000U, 1U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0U, 0U
    );
    assert(status == INVALID_STATE);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_MEASURED);

    /* DESTROYED state — cannot fault */
    state.partitions[0].state = FBVBS_PARTITION_STATE_DESTROYED;
    status = fbvbs_partition_fault(
        &state, 0x9000U, 1U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0U, 0U
    );
    assert(status == INVALID_STATE);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_DESTROYED);

    /* RUNNING state — CAN fault */
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNING;
    status = fbvbs_partition_fault(
        &state, 0x9000U, 1U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0U, 0U
    );
    assert(status == OK);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_FAULTED);
    assert(state.partitions[0].health_state == FBVBS_PARTITION_HEALTH_QUARANTINED);
    assert(state.partitions[0].quarantine_reason == 1U);

    /* RUNNABLE state — CAN fault */
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNABLE;
    status = fbvbs_partition_fault(
        &state, 0x9000U, 2U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0U, 0U
    );
    assert(status == OK);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_FAULTED);
    assert(state.partitions[0].health_state == FBVBS_PARTITION_HEALTH_QUARANTINED);
    assert(state.partitions[0].quarantine_reason == 2U);

    /* LOADED state — CAN fault */
    state.partitions[0].state = FBVBS_PARTITION_STATE_LOADED;
    status = fbvbs_partition_fault(
        &state, 0x9000U, 3U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0U, 0U
    );
    assert(status == OK);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_FAULTED);
    assert(state.partitions[0].health_state == FBVBS_PARTITION_HEALTH_QUARANTINED);
    assert(state.partitions[0].quarantine_reason == 3U);

    /* QUIESCED state — CAN fault */
    state.partitions[0].state = FBVBS_PARTITION_STATE_QUIESCED;
    status = fbvbs_partition_fault(
        &state, 0x9000U, 4U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0U, 0U
    );
    assert(status == OK);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_FAULTED);
    assert(state.partitions[0].health_state == FBVBS_PARTITION_HEALTH_QUARANTINED);
    assert(state.partitions[0].quarantine_reason == 4U);
}

/* --- 8. Double-fault: already-FAULTED partition stays FAULTED --- */
static void test_partition_double_fault_is_idempotent(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xA000U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNING;

    /* First fault */
    status = fbvbs_partition_fault(
        &state, 0xA000U, 1U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0x11U, 0x22U
    );
    assert(status == OK);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_FAULTED);
    assert(state.partitions[0].health_state == FBVBS_PARTITION_HEALTH_QUARANTINED);
    assert(state.partitions[0].quarantine_reason == 1U);
    assert(state.partitions[0].last_fault_code == 1U);

    /* Second fault — FAULTED is NOT in the allowed source states
     * (RUNNING/RUNNABLE/LOADED/QUIESCED), so this must return INVALID_STATE.
     * The original fault_code must be preserved (audit evidence). */
    status = fbvbs_partition_fault(
        &state, 0xA000U, 2U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0x33U, 0x44U
    );
    assert(status == INVALID_STATE);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_FAULTED);
    assert(state.partitions[0].health_state == FBVBS_PARTITION_HEALTH_QUARANTINED);
    assert(state.partitions[0].quarantine_reason == 1U);
    assert(state.partitions[0].last_fault_code == 1U);  /* Original preserved */
}

static void test_partition_status_tracks_health_across_fault_and_recover(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_status_response response = {0};
    struct fbvbs_partition_recover_request request = {0};
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xA100U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNING;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_HEALTHY;
    state.partitions[0].vcpu_count = 1U;
    state.partitions[0].vcpus[0].state = FBVBS_VCPU_STATE_RUNNING;
    state.partitions[0].manifest_object_id = 0x101U;
    state.partitions[0].image_object_id = 0x102U;
    state.partitions[0].entry_ip = 0x400000U;
    state.partitions[0].initial_sp = 0x800000U;
    state.partitions[0].measurement_epoch = 7U;

    status = fbvbs_partition_fault(
        &state, 0xA100U, 0x44U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0x11U, 0x22U
    );
    assert(status == OK);

    status = fbvbs_partition_get_status(&state, 0xA100U, &response);
    assert(status == OK);
    assert(response.state == FBVBS_PARTITION_STATE_FAULTED);
    assert(response.health_state == FBVBS_PARTITION_HEALTH_QUARANTINED);
    assert(response.measurement_epoch == 7U);
    assert(response.fault_code == 0x44U);
    assert(response.quarantine_reason == 0x44U);

    request = make_partition_recover_request(
        &state,
        0xA100U,
        0U,
        UINT64_C(0xA100),
        UINT64_C(0xB100)
    );
    status = fbvbs_partition_recover(&state, &request);
    assert(status == OK);
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_RUNNABLE);
    assert(state.partitions[0].health_state == FBVBS_PARTITION_HEALTH_RECOVERY);
    assert(state.partitions[0].quarantine_reason == 0U);
    assert(state.partitions[0].vcpus[0].state == FBVBS_VCPU_STATE_RUNNABLE);

    memset(&response, 0, sizeof(response));
    status = fbvbs_partition_get_status(&state, 0xA100U, &response);
    assert(status == OK);
    assert(response.state == FBVBS_PARTITION_STATE_RUNNABLE);
    assert(response.health_state == FBVBS_PARTITION_HEALTH_RECOVERY);
    assert(response.measurement_epoch == 8U);
    assert(response.fault_code == 0U);
    assert(response.quarantine_reason == 0U);
}

static void test_partition_fault_info_returns_structured_record(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_fault_info_response response = {0};
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xA200U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNING;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_HEALTHY;
    state.partitions[0].vcpu_count = 1U;
    state.partitions[0].manifest_object_id = 0x201U;
    state.partitions[0].image_object_id = 0x202U;
    state.partitions[0].entry_ip = 0x400000U;
    state.partitions[0].initial_sp = 0x900000U;
    state.partitions[0].measurement_epoch = 12U;

    status = fbvbs_partition_fault(
        &state, 0xA200U, FBVBS_FAULT_POLICY_DENY_THRESHOLD,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0x55U, 0x66U
    );
    assert(status == OK);

    status = fbvbs_partition_get_fault_info(&state, 0xA200U, &response);
    assert(status == OK);
    assert(response.fault_code == FBVBS_FAULT_POLICY_DENY_THRESHOLD);
    assert(response.source_component == FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR);
    assert(response.health_state == FBVBS_PARTITION_HEALTH_QUARANTINED);
    assert(response.severity == FBVBS_SEVERITY_ALERT);
    assert(response.runbook_code == FBVBS_RUNBOOK_PARTITION_RECOVERY);
    assert(response.deny_reason == FBVBS_DENY_REASON_POLICY);
    assert(response.quarantine_reason == FBVBS_FAULT_POLICY_DENY_THRESHOLD);
    assert(response.fault_detail0 == 0x55U);
    assert(response.fault_detail1 == 0x66U);
    assert(response.measurement_epoch == 12U);
    assert((response.recommended_recovery_flags & FBVBS_RECOVERY_CLEAR_VOLATILE) != 0ULL);
    assert((response.recommended_action_flags & FBVBS_GUIDANCE_ACTION_RECOVER_PARTITION) != 0ULL);
}

static void test_partition_recover_rejects_missing_approval_digest(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_recover_request request;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xA201U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;
    state.partitions[0].manifest_object_id = 0x301U;
    state.partitions[0].image_object_id = 0x302U;
    state.partitions[0].entry_ip = 0x400000U;
    state.partitions[0].initial_sp = 0x900000U;

    request = (struct fbvbs_partition_recover_request){
        .partition_id = 0xA201U,
        .recovery_flags = 0U,
        .session_correlation_id = UINT64_C(0xA201),
        .confirmation_nonce = UINT64_C(0xB201),
        .reserved0 = 0U,
        .reserved1 = 0U,
    };
    status = fbvbs_partition_recover(&state, &request);
    assert(status == POLICY_DENIED);
}

static void test_partition_recover_replay_session_nonce_is_denied(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_recover_request request;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xA202U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;
    state.partitions[0].manifest_object_id = 0x401U;
    state.partitions[0].image_object_id = 0x402U;
    state.partitions[0].entry_ip = 0x400000U;
    state.partitions[0].initial_sp = 0x900000U;

    request = make_partition_recover_request(
        &state,
        0xA202U,
        0U,
        UINT64_C(0xA202),
        UINT64_C(0xB202)
    );

    status = fbvbs_partition_recover(&state, &request);
    assert(status == OK);

    state.partitions[0].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;
    status = fbvbs_partition_recover(&state, &request);
    assert(status == POLICY_DENIED);
}

static void test_partition_recover_requires_quarantined_health_state(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_recover_request request;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);
    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xA203U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_DEGRADED;
    state.partitions[0].manifest_object_id = 0x501U;
    state.partitions[0].image_object_id = 0x502U;
    state.partitions[0].entry_ip = 0x400000U;
    state.partitions[0].initial_sp = 0x900000U;

    request = make_partition_recover_request(
        &state,
        0xA203U,
        0U,
        UINT64_C(0xA203),
        UINT64_C(0xB203)
    );
    status = fbvbs_partition_recover(&state, &request);
    assert(status == INVALID_STATE);
}

static void test_partition_recover_rejects_expired_approval(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_recover_request request;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    state.trusted_clock_available = true;
    state.trusted_time_seconds = 7200U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xA204U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;
    state.partitions[0].manifest_object_id = 0x601U;
    state.partitions[0].image_object_id = 0x602U;
    state.partitions[0].entry_ip = 0x400000U;
    state.partitions[0].initial_sp = 0x900000U;

    request = make_partition_recover_request(
        &state,
        0xA204U,
        0U,
        UINT64_C(0xA204),
        UINT64_C(0xB204)
    );
    request.approval_expires_utc = state.trusted_time_seconds - 1U;
    fbvbs_partition_compute_recovery_approval_digest(
        &state,
        request.partition_id,
        request.recovery_flags,
        request.session_correlation_id,
        request.confirmation_nonce,
        request.approval_expires_utc,
        request.approval_ledger_digest,
        request.recovery_approval_digest
    );

    status = fbvbs_partition_recover(&state, &request);
    assert(status == POLICY_DENIED);
}

static void test_partition_recover_break_glass_requires_short_ttl(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_recover_request request;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    state.trusted_clock_available = true;
    state.trusted_time_seconds = 1000U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xA206U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;
    state.partitions[0].manifest_object_id = 0x801U;
    state.partitions[0].image_object_id = 0x802U;
    state.partitions[0].entry_ip = 0x400000U;
    state.partitions[0].initial_sp = 0x900000U;

    request = make_partition_recover_request(
        &state,
        0xA206U,
        FBVBS_RECOVERY_BREAK_GLASS,
        UINT64_C(0xA206),
        UINT64_C(0xB206)
    );
    request.approval_expires_utc = state.trusted_time_seconds + 3600U;
    fbvbs_partition_compute_recovery_approval_digest(
        &state,
        request.partition_id,
        request.recovery_flags,
        request.session_correlation_id,
        request.confirmation_nonce,
        request.approval_expires_utc,
        request.approval_ledger_digest,
        request.recovery_approval_digest
    );

    status = fbvbs_partition_recover(&state, &request);
    assert(status == POLICY_DENIED);
}

static void test_partition_recover_requires_trusted_clock(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_recover_request request;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    state.trusted_clock_available = false;
    state.trusted_time_seconds = 1000U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xA205U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_FAULTED;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;
    state.partitions[0].manifest_object_id = 0x701U;
    state.partitions[0].image_object_id = 0x702U;
    state.partitions[0].entry_ip = 0x400000U;
    state.partitions[0].initial_sp = 0x900000U;

    request = make_partition_recover_request(
        &state,
        0xA205U,
        0U,
        UINT64_C(0xA205),
        UINT64_C(0xB205)
    );

    status = fbvbs_partition_recover(&state, &request);
    assert(status == POLICY_DENIED);
}

static void test_diagnostic_health_views_stay_consistent(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_status_response status_response = {0};
    struct fbvbs_partition_fault_info_response fault_info = {0};
    struct fbvbs_diag_partition_list_response partition_list = {0};
    struct fbvbs_diag_partition_entry list_entry = {0};
    struct fbvbs_diag_fault_record_response fault_record = {0};
    struct fbvbs_diag_inventory_response inventory = {0};
    uint32_t response_length = 0U;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xA300U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNING;
    state.partitions[0].health_state = FBVBS_PARTITION_HEALTH_HEALTHY;
    state.partitions[0].vcpu_count = 1U;
    state.partitions[0].measurement_epoch = 3U;
    state.partitions[0].manifest_object_id = 0x301U;
    state.partitions[0].image_object_id = 0x302U;
    state.partitions[0].entry_ip = 0x400000U;
    state.partitions[0].initial_sp = 0x900000U;

    status = fbvbs_partition_fault(
        &state, 0xA300U, FBVBS_FAULT_WATCHDOG_TIMEOUT,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0x77U, 0x88U
    );
    assert(status == OK);

    assert(fbvbs_partition_get_status(&state, 0xA300U, &status_response) == OK);
    assert(fbvbs_partition_get_fault_info(&state, 0xA300U, &fault_info) == OK);
    assert(fbvbs_diag_get_partition_list(&state, &partition_list, &response_length) == OK);
    assert(fbvbs_diag_get_fault_record(&state, 0xA300U, &fault_record) == OK);
    assert(fbvbs_diag_get_inventory(&state, &inventory) == OK);

    memcpy(&list_entry, &partition_list.entries[0], sizeof(list_entry));
    assert(status_response.state == FBVBS_PARTITION_STATE_FAULTED);
    assert(status_response.health_state == FBVBS_PARTITION_HEALTH_QUARANTINED);
    assert(status_response.fault_code == FBVBS_FAULT_WATCHDOG_TIMEOUT);
    assert(status_response.quarantine_reason == FBVBS_FAULT_WATCHDOG_TIMEOUT);
    assert(status_response.lockout_windows == 0U);
    assert(status_response.policy_deny_count == 0U);

    assert(fault_info.health_state == status_response.health_state);
    assert(fault_info.fault_code == status_response.fault_code);
    assert(fault_info.quarantine_reason == status_response.quarantine_reason);

    assert(list_entry.partition_id == 0xA300U);
    assert(list_entry.state == status_response.state);
    assert(list_entry.health_state == status_response.health_state);
    assert(list_entry.fault_code == status_response.fault_code);
    assert(list_entry.quarantine_reason == status_response.quarantine_reason);
    assert(list_entry.lockout_windows == status_response.lockout_windows);
    assert(list_entry.policy_deny_count == status_response.policy_deny_count);

    assert(fault_record.partition_id == 0xA300U);
    assert(fault_record.partition_state == status_response.state);
    assert(fault_record.health_state == status_response.health_state);
    assert(fault_record.fault_code == status_response.fault_code);
    assert(fault_record.quarantine_reason == status_response.quarantine_reason);

    assert(inventory.occupied_partition_count == 1U);
    assert(inventory.quarantined_partition_count == 1U);
    assert(inventory.healthy_partition_count == 0U);
}

/* --- 9. Rate limiter window rotation with summary emission --- */
static void test_rate_limiter_emits_summary_on_window_rotation(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    /* Set up drops directly (avoids window rotation from 100+ writes) */
    uint32_t event_class = ((uint32_t)FBVBS_EVENT_POLICY_DENY >> 4U) &
                           (FBVBS_RATE_LIMIT_CLASSES - 1U);
    state.log_rate_counts[event_class] = FBVBS_RATE_LIMIT_THRESHOLD;
    state.log_rate_dropped[event_class] = 5U;

    /* Advance sequence past window boundary to trigger rotation */
    state.mirror_log.header.max_readable_sequence =
        state.log_rate_window_sequence + FBVBS_LOG_SLOT_COUNT;

    uint64_t seq_before = state.mirror_log.header.max_readable_sequence;

    /* This call triggers window rotation (emits summary) then the new event.
     * Use same event code so the new count goes to the same class. */
    status = fbvbs_log_append_rate_limited(
        &state, 0U, FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        (uint16_t)FBVBS_SEVERITY_INFO,
        (uint16_t)FBVBS_EVENT_POLICY_DENY,
        NULL, 0U
    );
    assert(status == OK);

    /* Window should have rotated: drop counts reset, new event counted */
    assert(state.log_rate_dropped[event_class] == 0U);
    assert(state.log_rate_counts[event_class] == 1U);

    /* Summary + new event were written; sequence advanced by at least 2 */
    assert(state.mirror_log.header.max_readable_sequence >= seq_before + 2U);
}

/* --- 10. Watchdog voluntary exit resets counter --- */
static void test_watchdog_voluntary_exit_resets_counter(void) {
    struct fbvbs_hypervisor_state state;
    uint32_t i;
    int faulted;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xB000U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNING;

    /* Accumulate timer exits near threshold */
    for (i = 0; i < FBVBS_WATCHDOG_MAX_CONSECUTIVE - 2U; i++) {
        faulted = fbvbs_watchdog_on_timer_exit(&state, 0U);
        assert(faulted == 0);
    }
    assert(state.partitions[0].consecutive_timer_exits ==
           FBVBS_WATCHDOG_MAX_CONSECUTIVE - 2U);

    /* Guest does I/O (voluntary exit) — counter resets */
    fbvbs_watchdog_on_voluntary_exit(&state, 0U);
    assert(state.partitions[0].consecutive_timer_exits == 0U);

    /* Now needs full threshold again before fault */
    for (i = 0; i < FBVBS_WATCHDOG_MAX_CONSECUTIVE - 1U; i++) {
        faulted = fbvbs_watchdog_on_timer_exit(&state, 0U);
        assert(faulted == 0);
    }
    assert(state.partitions[0].state == FBVBS_PARTITION_STATE_RUNNING);
}

/* --- 11. Partition fault on non-existent partition --- */
static void test_partition_fault_nonexistent_returns_not_found(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));
    assert(fbvbs_log_init(&state) == OK);

    status = fbvbs_partition_fault(
        &state, 0xDEADU, 1U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR, 0U, 0U
    );
    assert(status == NOT_FOUND);
}

/* --- 12. VM destroy with assigned devices is blocked --- */
static void test_vm_destroy_blocked_with_assigned_devices(void) {
    struct fbvbs_hypervisor_state state;
    int status;

    memset(&state, 0, sizeof(state));

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0xC000U;
    state.partitions[0].kind = PARTITION_KIND_GUEST_VM;
    state.partitions[0].state = FBVBS_PARTITION_STATE_CREATED;
    state.partitions[0].assigned_device_count = 1U;
    state.partitions[0].assigned_devices[0] = 0xD002U;

    /* Destroy must be blocked — devices need safe teardown first */
    status = fbvbs_vm_destroy(&state, 0xC000U);
    assert(status == NOT_SUPPORTED_ON_PLATFORM);
    assert(state.partitions[0].occupied);
    assert(state.partitions[0].assigned_device_count == 1U);
}

/* --- 13. ID allocator exhaustion: monotonic IDs reject at UINT64_MAX --- */
static void test_id_allocator_exhaustion_is_fail_closed(void) {
    /* can_advance with next_id near max must fail */
    assert(fbvbs_id_allocator_can_advance(UINT64_MAX, 1U) == 0);
    assert(fbvbs_id_allocator_can_advance(UINT64_MAX - 1U, 2U) == 0);
    assert(fbvbs_id_allocator_can_advance(UINT64_MAX - 1U, 1U) == 1);

    /* Zero step or zero next_id must fail (invariant violation) */
    assert(fbvbs_id_allocator_can_advance(0U, 1U) == 0);
    assert(fbvbs_id_allocator_can_advance(1U, 0U) == 0);

    /* Normal operation succeeds */
    assert(fbvbs_id_allocator_can_advance(1U, 1U) == 1);
    assert(fbvbs_id_allocator_can_advance(1000U, 100U) == 1);
}

/* --- 14. ID allocator create/destroy cycle stress --- */
static void test_id_allocator_create_destroy_cycle(void) {
    struct fbvbs_hypervisor_state state;
    struct fbvbs_vm_create_request request = {0};
    struct fbvbs_vm_create_response response = {0};
    uint32_t cycle;
    int status;

    memset(&state, 0, sizeof(state));
    state.next_partition_id = 200U;
    state.next_memory_object_id = 1U;
    state.next_measurement_digest_id = 1U;
    state.next_shared_object_id = 1U;
    state.next_target_set_id = 1U;
    state.next_key_handle = 1U;
    state.next_dek_handle = 1U;
    state.next_manifest_set_id = 1U;
    state.next_iommu_domain_id = 1U;

    /* Platform capabilities required for VM create */
    state.vmx_caps.vmx_supported = 1U;
    state.vmx_caps.hlat_available = 1U;

    /* Create host partition for caller context */
    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 1U;
    state.partitions[0].kind = PARTITION_KIND_FREEBSD_HOST;
    state.partitions[0].state = FBVBS_PARTITION_STATE_RUNNING;
    state.partitions[0].capability_mask = FBVBS_HOST_DEFAULT_CAPABILITY_MASK;

    request.vcpu_count = 1U;
    request.memory_limit_bytes = FBVBS_PAGE_SIZE * 2U;  /* >= PAGE_SIZE * (vcpu_count+1) */

    /* Rapid create/destroy cycles — IDs must be monotonically increasing.
     * Destroyed partitions leave tombstones (slot not reusable), so we can
     * create at most FBVBS_MAX_PARTITIONS - 1 VMs (slot 0 = host). */
    uint32_t max_cycles = FBVBS_MAX_PARTITIONS - 1U;
    for (cycle = 0; cycle < max_cycles; cycle++) {
        uint64_t prev_next_id = state.next_partition_id;
        memset(&response, 0, sizeof(response));

        status = fbvbs_vm_create(&state, &request, &response);
        assert(status == OK);
        assert(response.vm_partition_id == prev_next_id);
        assert(state.next_partition_id == prev_next_id + 1U);

        status = fbvbs_vm_destroy(&state, response.vm_partition_id);
        assert(status == OK);
    }

    /* After max_cycles, next_partition_id = 200 + max_cycles */
    assert(state.next_partition_id == 200U + max_cycles);

    /* One more create must fail: all slots are tombstoned */
    memset(&response, 0, sizeof(response));
    status = fbvbs_vm_create(&state, &request, &response);
    assert(status == RESOURCE_EXHAUSTED);

    /* IDs are never reused — tombstones occupy slots but IDs advance */
}

/* --- 15. Multiboot parser: malformed input robustness --- */
static void test_multiboot_parser_rejects_malformed_input(void) {
    struct fbvbs_hypervisor_state state;
    uint8_t buf[64];

    memset(&state, 0, sizeof(state));

    /* All zeros — total_size = 0, rejected (< 8) */
    memset(buf, 0, sizeof(buf));
    fbvbs_process_multiboot_info(&state, buf, sizeof(buf));
    assert(state.memory_map_count == 0U);

    /* total_size = 7, rejected (< 8) */
    memset(buf, 0, sizeof(buf));
    buf[0] = 7; buf[1] = 0; buf[2] = 0; buf[3] = 0;
    fbvbs_process_multiboot_info(&state, buf, sizeof(buf));
    assert(state.memory_map_count == 0U);

    /* total_size = 0xFFFFFFFF, rejected (> 64MB) */
    memset(buf, 0xFF, sizeof(buf));
    fbvbs_process_multiboot_info(&state, buf, sizeof(buf));
    assert(state.memory_map_count == 0U);

    /* NULL pointers */
    fbvbs_process_multiboot_info(NULL, buf, sizeof(buf));
    fbvbs_process_multiboot_info(&state, NULL, sizeof(buf));

    /* buffer_size < 8 */
    fbvbs_process_multiboot_info(&state, buf, 4U);
    assert(state.memory_map_count == 0U);

    /* Valid header but end tag immediately */
    memset(buf, 0, sizeof(buf));
    buf[0] = 16; /* total_size = 16 */
    /* Tag at offset 8: type=0 (end), size=8 */
    buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;  /* type = 0 */
    buf[12] = 8; buf[13] = 0; buf[14] = 0; buf[15] = 0; /* size = 8 */
    state.memory_map_count = 99U;  /* Should be reset to 0 */
    fbvbs_process_multiboot_info(&state, buf, sizeof(buf));
    assert(state.memory_map_count == 0U);
}

int main(void) {
    test_log_sequence_exhaustion_fails_closed();
    test_log_ring_saturation_overwrites_oldest();
    test_rollback_stale_manifest_generation_rejected();
    test_device_assign_without_iommu_fails_closed();
    test_device_assign_with_iommu_but_no_qualification_fails_closed();
    test_watchdog_faults_hung_partition();
    test_watchdog_ignores_unoccupied_and_nonrunning();
    test_rate_limiter_drops_excess_and_exempts_critical();
    test_partition_fault_rejects_invalid_source_states();
    test_partition_double_fault_is_idempotent();
    test_partition_status_tracks_health_across_fault_and_recover();
    test_partition_fault_info_returns_structured_record();
    test_partition_recover_rejects_missing_approval_digest();
    test_partition_recover_replay_session_nonce_is_denied();
    test_partition_recover_requires_quarantined_health_state();
    test_partition_recover_rejects_expired_approval();
    test_partition_recover_break_glass_requires_short_ttl();
    test_partition_recover_requires_trusted_clock();
    test_diagnostic_health_views_stay_consistent();
    test_rate_limiter_emits_summary_on_window_rotation();
    test_watchdog_voluntary_exit_resets_counter();
    test_partition_fault_nonexistent_returns_not_found();
    test_vm_destroy_blocked_with_assigned_devices();
    test_id_allocator_exhaustion_is_fail_closed();
    test_id_allocator_create_destroy_cycle();
    test_multiboot_parser_rejects_malformed_input();
    return 0;
}
