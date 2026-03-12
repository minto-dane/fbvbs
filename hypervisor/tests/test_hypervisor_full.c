#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../include/fbvbs_hypervisor.h"

static struct fbvbs_hypervisor_state test_state;

static void reset_state(void) {
    fbvbs_hypervisor_init(&test_state);
}

/* Seed an artifact approval directly into the state for testing. */
static void seed_approval(uint64_t artifact_object_id, uint64_t manifest_object_id) {
    uint32_t i;

    for (i = 0U; i < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; ++i) {
        if (!test_state.approvals[i].active) {
            test_state.approvals[i].active = true;
            test_state.approvals[i].artifact_object_id = artifact_object_id;
            test_state.approvals[i].manifest_object_id = manifest_object_id;
            return;
        }
    }
}

static void test_init_sets_boot_id(void) {
    reset_state();
    assert(test_state.boot_id_hi != 0U);
    assert(test_state.boot_id_lo != 0U);
}

static void test_init_probes_vmx(void) {
    reset_state();
    assert(test_state.vmx_caps.vmx_supported == 1U);
}

static void test_init_seeds_log(void) {
    reset_state();
    assert(test_state.mirror_log.header.abi_version == FBVBS_ABI_VERSION);
    assert(test_state.mirror_log.header.record_size == FBVBS_LOG_RECORD_V1_SIZE);
    assert(test_state.mirror_log.header.max_readable_sequence == 1U);
}

static void test_log_append(void) {
    reset_state();
    uint64_t seq_before = test_state.mirror_log.header.max_readable_sequence;
    int status = fbvbs_log_append(&test_state, 0U, 1U, 2U, 3U, NULL, 0U);
    assert(status == OK);
    assert(test_state.mirror_log.header.max_readable_sequence == seq_before + 1U);
}

static void test_log_append_rejects_null(void) {
    assert(fbvbs_log_append(NULL, 0U, 0U, 0U, 0U, NULL, 0U) == INVALID_PARAMETER);
}

static void test_log_append_rejects_oversized_payload(void) {
    reset_state();
    uint8_t buf[256];
    assert(fbvbs_log_append(&test_state, 0U, 0U, 0U, 0U, buf, 256U) == INVALID_PARAMETER);
}

static void test_partition_create_trusted_service(void) {
    reset_state();
    struct fbvbs_partition_create_request request;
    struct fbvbs_partition_create_response response;

    /* Must match the boot manifest profile for image_object_id 0x1000 (KCI) */
    memset(&request, 0, sizeof(request));
    request.kind = PARTITION_KIND_TRUSTED_SERVICE;
    request.vcpu_count = 1U;
    request.memory_limit_bytes = FBVBS_PAGE_SIZE * 2U;
    request.capability_mask = 0x3FU;
    request.image_object_id = 0x1000U;

    int status = fbvbs_partition_create(&test_state, &request, &response);
    assert(status == OK);
    assert(response.partition_id != 0U);

    struct fbvbs_partition_status_response pstatus;
    status = fbvbs_partition_get_status(&test_state, response.partition_id, &pstatus);
    assert(status == OK);
    assert(pstatus.state == FBVBS_PARTITION_STATE_CREATED);
}

static void test_partition_lifecycle(void) {
    reset_state();
    struct fbvbs_partition_create_request request;
    struct fbvbs_partition_create_response response;

    /* Must match boot manifest profile for image_object_id 0x1000 (KCI) */
    memset(&request, 0, sizeof(request));
    request.kind = PARTITION_KIND_TRUSTED_SERVICE;
    request.vcpu_count = 1U;
    request.memory_limit_bytes = FBVBS_PAGE_SIZE * 2U;
    request.capability_mask = 0x3FU;
    request.image_object_id = 0x1000U;

    assert(fbvbs_partition_create(&test_state, &request, &response) == OK);
    uint64_t pid = response.partition_id;

    /* Seed artifact approval so measure can succeed */
    seed_approval(0x1000U, 0x2000U);

    /* Measure */
    struct fbvbs_partition_measure_request mreq;
    struct fbvbs_partition_measure_response mresp;
    memset(&mreq, 0, sizeof(mreq));
    mreq.partition_id = pid;
    mreq.image_object_id = 0x1000U;
    mreq.manifest_object_id = 0x2000U;
    assert(fbvbs_partition_measure(&test_state, &mreq, &mresp) == OK);

    /* Load */
    struct fbvbs_partition_load_image_request lreq;
    memset(&lreq, 0, sizeof(lreq));
    lreq.partition_id = pid;
    lreq.image_object_id = 0x1000U;
    lreq.entry_ip = 0x400000U;
    lreq.initial_sp = 0x800000U;
    assert(fbvbs_partition_load_image(&test_state, &lreq) == OK);

    /* Start */
    assert(fbvbs_partition_start(&test_state, pid) == OK);

    struct fbvbs_partition_status_response pstatus;
    assert(fbvbs_partition_get_status(&test_state, pid, &pstatus) == OK);
    assert(pstatus.state == FBVBS_PARTITION_STATE_RUNNABLE);

    /* Quiesce */
    assert(fbvbs_partition_quiesce(&test_state, pid) == OK);
    assert(fbvbs_partition_get_status(&test_state, pid, &pstatus) == OK);
    assert(pstatus.state == FBVBS_PARTITION_STATE_QUIESCED);

    /* Resume */
    assert(fbvbs_partition_resume(&test_state, pid) == OK);
    assert(fbvbs_partition_get_status(&test_state, pid, &pstatus) == OK);
    assert(pstatus.state == FBVBS_PARTITION_STATE_RUNNABLE);

    /* Destroy */
    assert(fbvbs_partition_destroy(&test_state, pid) == OK);
    assert(fbvbs_partition_get_status(&test_state, pid, &pstatus) == OK);
    assert(pstatus.state == FBVBS_PARTITION_STATE_DESTROYED);
}

static void test_partition_illegal_transitions(void) {
    reset_state();
    struct fbvbs_partition_create_request request;
    struct fbvbs_partition_create_response response;

    memset(&request, 0, sizeof(request));
    request.kind = PARTITION_KIND_TRUSTED_SERVICE;
    request.vcpu_count = 1U;
    request.memory_limit_bytes = FBVBS_PAGE_SIZE * 2U;
    request.capability_mask = 0x3FU;
    request.image_object_id = 0x1000U;

    assert(fbvbs_partition_create(&test_state, &request, &response) == OK);
    uint64_t pid = response.partition_id;

    /* Cannot start from Created (must measure and load first) */
    assert(fbvbs_partition_start(&test_state, pid) == INVALID_STATE);

    /* Cannot resume from Created */
    assert(fbvbs_partition_resume(&test_state, pid) == INVALID_STATE);

    /* Cannot quiesce from Created */
    assert(fbvbs_partition_quiesce(&test_state, pid) == INVALID_STATE);
}

static void test_vm_create_and_destroy(void) {
    reset_state();
    struct fbvbs_vm_create_request request;
    struct fbvbs_vm_create_response response;

    memset(&request, 0, sizeof(request));
    request.memory_limit_bytes = FBVBS_PAGE_SIZE * 4U;
    request.vcpu_count = 1U;
    request.vm_flags = 0U;

    int status = fbvbs_vm_create(&test_state, &request, &response);
    assert(status == OK);
    assert(response.vm_partition_id != 0U);

    status = fbvbs_vm_destroy(&test_state, response.vm_partition_id);
    assert(status == OK);
}

static void test_memory_allocate_and_release(void) {
    reset_state();
    struct fbvbs_memory_allocate_object_request request;
    struct fbvbs_memory_allocate_object_response response;

    memset(&request, 0, sizeof(request));
    request.size = FBVBS_PAGE_SIZE;
    request.object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;

    int status = fbvbs_memory_allocate_object(&test_state, &request, &response);
    assert(status == OK);
    assert(response.memory_object_id != 0U);

    status = fbvbs_memory_release_object(&test_state, response.memory_object_id);
    assert(status == OK);
}

static void test_memory_allocate_rejects_bad_size(void) {
    reset_state();
    struct fbvbs_memory_allocate_object_request request;
    struct fbvbs_memory_allocate_object_response response;

    memset(&request, 0, sizeof(request));
    request.size = 0U;
    assert(fbvbs_memory_allocate_object(&test_state, &request, &response) == INVALID_PARAMETER);

    request.size = 100U; /* not page-aligned */
    assert(fbvbs_memory_allocate_object(&test_state, &request, &response) == INVALID_PARAMETER);
}

static void test_crc32c_known_value(void) {
    /* CRC32C of empty input should be 0 */
    uint32_t crc = fbvbs_crc32c(NULL, 0U);
    assert(crc == 0U);
}

static void test_audit_get_mirror_info(void) {
    reset_state();
    struct fbvbs_audit_mirror_info_response response;

    assert(fbvbs_audit_get_mirror_info(NULL, &response) == INVALID_PARAMETER);
    assert(fbvbs_audit_get_mirror_info(&test_state, NULL) == INVALID_PARAMETER);

    int status = fbvbs_audit_get_mirror_info(&test_state, &response);
    assert(status == OK);
    assert(response.record_size == FBVBS_LOG_RECORD_V1_SIZE);
    assert(response.ring_size > 0U);
}

static void test_diag_get_capabilities(void) {
    reset_state();
    struct fbvbs_diag_capabilities_response response;

    assert(fbvbs_diag_get_capabilities(NULL, &response) == INVALID_PARAMETER);

    int status = fbvbs_diag_get_capabilities(&test_state, &response);
    assert(status == OK);
    assert(response.capability_bitmap0 != 0U);
}

static void test_diag_get_partition_list(void) {
    reset_state();
    struct fbvbs_diag_partition_list_response response;
    uint32_t response_length = 0U;

    int status = fbvbs_diag_get_partition_list(&test_state, &response, &response_length);
    assert(status == OK);
    assert(response.count >= 1U); /* at least FreeBSD host */
}

int main(void) {
    test_init_sets_boot_id();
    test_init_probes_vmx();
    test_init_seeds_log();
    test_log_append();
    test_log_append_rejects_null();
    test_log_append_rejects_oversized_payload();
    test_partition_create_trusted_service();
    test_partition_lifecycle();
    test_partition_illegal_transitions();
    test_vm_create_and_destroy();
    test_memory_allocate_and_release();
    test_memory_allocate_rejects_bad_size();
    test_crc32c_known_value();
    test_audit_get_mirror_info();
    test_diag_get_capabilities();
    test_diag_get_partition_list();
    return 0;
}
