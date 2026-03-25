/* FBVBS Partition Loader Fuzzer
 *
 * Exercises the fixed ELF64 partition-loadable image path with arbitrary
 * image bytes. The goal is to shake out malformed ELF handling, rollback
 * safety, and mapping/stack permission edge cases.
 */

#include "fbvbs_hypervisor.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FBVBS_FUZZ_LOADER_MAX_IMAGE_SIZE (FBVBS_PAGE_SIZE * 2U)

static int fuzz_one_input(const uint8_t *data, size_t size)
{
    struct fbvbs_hypervisor_state state;
    struct fbvbs_partition_load_image_request request = {0};
    struct fbvbs_memory_map_entry allocator_map = {
        .base_addr = 0x100000U,
        .length = FBVBS_PAGE_SIZE * 64U,
        .type = 1U
    };
    _Alignas(FBVBS_PAGE_SIZE) uint8_t image_bytes[FBVBS_FUZZ_LOADER_MAX_IMAGE_SIZE];
    size_t clamped_size = size;

    if (clamped_size > sizeof(image_bytes)) {
        clamped_size = sizeof(image_bytes);
    }
    if (clamped_size == 0U) {
        return 0;
    }

    memset(&state, 0, sizeof(state));
    memset(image_bytes, 0, sizeof(image_bytes));
    memcpy(image_bytes, data, clamped_size);

    (void)fbvbs_page_alloc_init(&allocator_map, 1U);

    state.next_partition_id = 1U;
    state.next_measurement_digest_id = 1U;
    state.next_memory_object_id = 0x100000U;
    state.next_shared_object_id = 1U;
    state.next_target_set_id = 1U;
    state.next_key_handle = 1U;
    state.next_dek_handle = 1U;
    state.next_manifest_set_id = 1U;
    state.next_iommu_domain_id = 1U;

    state.partitions[0].occupied = true;
    state.partitions[0].partition_id = 0x7777U;
    state.partitions[0].kind = PARTITION_KIND_TRUSTED_SERVICE;
    state.partitions[0].state = FBVBS_PARTITION_STATE_MEASURED;
    state.partitions[0].image_object_id = 0x8888U;
    state.partitions[0].manifest_object_id = 0x9999U;
    state.partitions[0].memory_limit_bytes = FBVBS_PAGE_SIZE * 4U;
    state.partitions[0].vcpu_count = 1U;

    state.artifact_catalog.count = 2U;
    state.artifact_catalog.entries[0].object_id = 0x8888U;
    state.artifact_catalog.entries[0].object_kind = FBVBS_ARTIFACT_OBJECT_IMAGE;
    state.artifact_catalog.entries[0].related_index = 1U;
    state.artifact_catalog.entries[1].object_id = 0x9999U;
    state.artifact_catalog.entries[1].object_kind = FBVBS_ARTIFACT_OBJECT_MANIFEST;
    state.artifact_catalog.entries[1].related_index = 0U;

    state.manifest_profiles[0].active = true;
    state.manifest_profiles[0].component_type =
        FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE;
    state.manifest_profiles[0].object_id = 0x8888U;
    state.manifest_profiles[0].manifest_object_id = 0x9999U;
    state.manifest_profiles[0].entry_ip = 0x100000U;
    state.manifest_profiles[0].initial_sp = 0x200000U;
    state.manifest_profiles[0].memory_limit_bytes = FBVBS_PAGE_SIZE * 4U;
    state.manifest_profiles[0].vcpu_count = 1U;
    state.manifest_profiles[0].service_kind = SERVICE_KIND_KCI;

    state.memory_objects[0].allocated = true;
    state.memory_objects[0].object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    state.memory_objects[0].memory_object_id = 0x8888U;
    state.memory_objects[0].owner_partition_id = 0x100U;
    state.memory_objects[0].size = (uint64_t)clamped_size;
    state.memory_objects[0].backing_kind = FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS;
    state.memory_objects[0].backing_page_count =
        (uint32_t)((clamped_size + FBVBS_PAGE_SIZE - 1U) / FBVBS_PAGE_SIZE);
    state.memory_objects[0].backing_phys_base = (uint64_t)(uintptr_t)image_bytes;

    request.partition_id = 0x7777U;
    request.image_object_id = 0x8888U;
    request.entry_ip = 0x100000U;
    request.initial_sp = 0x200000U;

    (void)fbvbs_partition_load_image(&state, &request);
    if (state.partitions[0].state == FBVBS_PARTITION_STATE_LOADED) {
        (void)fbvbs_partition_destroy(&state, 0x7777U);
    }

    return 0;
}

#if defined(__AFL_HAVE_MANUAL_CONTROL) || defined(__AFL_COMPILER)
#include <unistd.h>
__AFL_FUZZ_INIT();
int main(void)
{
    __AFL_INIT();
    while (__AFL_LOOP(100000)) {
        unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
        size_t len = (size_t)__AFL_FUZZ_TESTCASE_LEN;
        (void)fuzz_one_input(buf, len);
    }
    return 0;
}
#elif defined(FUZZ_LIBFUZZER)
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    return fuzz_one_input(data, size);
}
#else
#include <stdio.h>
int main(void)
{
    uint8_t buf[FBVBS_FUZZ_LOADER_MAX_IMAGE_SIZE];
    size_t n = fread(buf, 1, sizeof(buf), stdin);

    if (n == 0U) {
        return 1;
    }
    return fuzz_one_input(buf, n);
}
#endif
