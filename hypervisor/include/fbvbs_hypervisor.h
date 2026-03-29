#ifndef FBVBS_HYPERVISOR_H
#define FBVBS_HYPERVISOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fbvbs_abi.h"
#include "fbvbs_concurrency.h"
#include "fbvbs_cpu_security.h"
#include "fbvbs_leaf_vmx.h"

/* VMLAUNCH is now implemented in boot.S for bare-metal x86_64 builds.
 * Hosted and Frama-C builds use compile-time guards instead. */

/* IOMMU host policy: VT-d and AMD-Vi bring-up sequences are
 * implemented with root/context table allocation, translation
 * enable, interrupt remapping, and fault checking. */
#ifndef FBVBS_HOST_IOMMU_POLICY_IMPLEMENTED
#define FBVBS_HOST_IOMMU_POLICY_IMPLEMENTED 1
#endif

#define FBVBS_RUNTIME_HOST_DEPRIVILEGED (1U << 0)
#define FBVBS_RUNTIME_AUDIT_PRIMARY_OOB (1U << 1)

struct fbvbs_trap_registers {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
};

#define FBVBS_MAX_HOST_CALLSITE_ENTRIES 4U
#define FBVBS_MAX_HOST_CALLSITE_TABLES 2U
#define FBVBS_MAX_MANIFEST_PROFILES 10U
#define FBVBS_MAX_BOOT_MODULES 16U
#define FBVBS_BOOT_MODULE_CMDLINE_BYTES 64U

struct fbvbs_memory_mapping {
    bool active;
    uint8_t reserved0;
    uint16_t permissions;
    uint32_t reserved1;
    uint64_t memory_object_id;
    uint64_t guest_physical_address;
    uint64_t size;
};

struct fbvbs_aligned_command_page {
    struct fbvbs_command_page_v1 page;
} __attribute__((aligned(FBVBS_PAGE_SIZE)));

struct fbvbs_shared_registration {
    bool active;
    uint8_t reserved0;
    uint16_t peer_permissions;
    uint32_t reserved1;
    uint64_t shared_object_id;
    uint64_t memory_object_id;
    uint64_t size;
    uint64_t owner_partition_id;
    uint64_t peer_partition_id;
};

struct fbvbs_partition {
    bool occupied;
    bool tombstone;
    uint64_t partition_id;
    uint16_t kind;
    uint16_t service_kind;
    uint32_t state;
    uint32_t vcpu_count;
    uint32_t vm_flags;
    uint32_t reserved0;
    uint64_t memory_limit_bytes;
    uint64_t capability_mask;
    uint64_t image_object_id;
    uint64_t manifest_object_id;
    uint64_t measurement_epoch;
    uint64_t measurement_digest_id;
    uint64_t mapped_bytes;
    uint64_t bootstrap_bytes;
    uint64_t entry_ip;
    uint64_t initial_sp;
    uint32_t last_fault_code;
    uint32_t last_fault_source_component;
    uint64_t last_fault_detail0;
    uint64_t last_fault_detail1;
    uint32_t assigned_device_count;
    uint32_t reserved1;
    uint64_t iommu_domain_id;
    uint64_t assigned_devices[FBVBS_MAX_ASSIGNED_DEVICES];
    struct fbvbs_bootstrap_page_v1 bootstrap_page;
    struct fbvbs_aligned_command_page command_pages[FBVBS_MAX_VCPUS];
    struct fbvbs_vcpu vcpus[FBVBS_MAX_VCPUS];
    struct fbvbs_memory_mapping mappings[FBVBS_MAX_MEMORY_MAPPINGS];

    /* Watchdog / liveness monitoring (Phase 1-9).
     * Tracks consecutive preemption timer VM exits per partition.
     * When consecutive_timer_exits exceeds FBVBS_WATCHDOG_MAX_CONSECUTIVE,
     * the partition is faulted (fail-safe halt). */
    uint32_t consecutive_timer_exits;
    uint32_t watchdog_faults_total;
};

struct fbvbs_log_storage {
    struct fbvbs_log_ring_header_v1 header;
    struct fbvbs_log_record_v1 records[FBVBS_LOG_SLOT_COUNT];
};

struct fbvbs_host_callsite_table {
    bool active;
    uint8_t caller_class;
    uint16_t count;
    uint32_t reserved0;
    uint64_t manifest_object_id;
    uint64_t load_base;
    uint64_t allowed_offsets[FBVBS_MAX_HOST_CALLSITE_ENTRIES];
    uint64_t relocated_callsites[FBVBS_MAX_HOST_CALLSITE_ENTRIES];
};

struct fbvbs_manifest_profile {
    bool active;
    uint8_t component_type;
    uint8_t caller_class;
    uint8_t allowed_callsite_count;
    uint16_t service_kind;
    uint16_t vcpu_count;
    uint32_t reserved0;
    uint64_t object_id;
    uint64_t manifest_object_id;
    uint64_t memory_limit_bytes;
    uint64_t capability_mask;
    uint64_t entry_ip;
    uint64_t initial_sp;
    uint64_t load_base;
    uint64_t allowed_callsite_offsets[FBVBS_MAX_HOST_CALLSITE_ENTRIES];
};

struct fbvbs_boot_module {
    bool active;
    uint8_t reserved0[7];
    uint64_t start_phys;
    uint64_t size;
    char cmdline[FBVBS_BOOT_MODULE_CMDLINE_BYTES];
};

#define FBVBS_MEMORY_BACKING_NONE 0U
#define FBVBS_MEMORY_BACKING_EXTERNAL_CONTIGUOUS 1U
#define FBVBS_MEMORY_BACKING_OWNED_PAGE_LIST 2U

struct fbvbs_memory_object {
    bool allocated;
    uint8_t backing_kind;
    uint16_t reserved0;
    uint32_t object_flags;
    uint64_t memory_object_id;
    uint64_t owner_partition_id;
    uint64_t size;
    uint32_t map_count;
    uint32_t shared_count;
    uint32_t backing_page_count;
    uint32_t reserved1;
    uint64_t backing_phys_base;
    uint64_t backing_page_list_head_phys;
};

struct fbvbs_ksi_target_set {
    bool active;
    uint32_t target_count;
    uint64_t target_set_id;
    uint64_t target_object_ids[8];
};

struct fbvbs_ksi_object {
    bool active;
    bool tier_b;
    bool pointer_registered;
    bool retired;
    uint32_t protection_class;
    uint64_t object_id;
    uint64_t guest_physical_address;
    uint64_t size;
    uint64_t target_set_id;
};

struct fbvbs_iks_key {
    bool active;
    uint32_t key_type;
    uint32_t allowed_ops;
    uint32_t key_length;
    uint64_t key_handle;
};

struct fbvbs_sks_dek {
    bool active;
    uint32_t key_length;
    uint64_t dek_handle;
    uint64_t volume_id;
};

#define FBVBS_MAX_METADATA_MANIFESTS 8U
#define FBVBS_METADATA_ROLE_ROOT 1U
#define FBVBS_METADATA_ROLE_TARGETS 2U
#define FBVBS_METADATA_ROLE_SNAPSHOT 3U
#define FBVBS_METADATA_ROLE_TIMESTAMP 4U
#define FBVBS_METADATA_ROLE_REVOCATION 5U
#define FBVBS_METADATA_FLAG_SIGNATURE_VALID 0x0001U
#define FBVBS_METADATA_FLAG_REVOKED 0x0002U

struct fbvbs_metadata_manifest {
    uint64_t object_id;
    uint64_t generation;
    uint64_t expected_generation;
    uint64_t minimum_generation;
    uint64_t timestamp_seconds;
    uint64_t expires_at_seconds;
    uint64_t dependency_object_id;
    uint32_t role;
    uint32_t flags;
    uint8_t snapshot_id[32];
};

struct fbvbs_metadata_set_page {
    uint32_t count;
    uint32_t reserved0;
    uint64_t manifest_gpas[FBVBS_MAX_METADATA_MANIFESTS];
};

struct fbvbs_uvs_manifest_set {
    bool active;
    uint32_t manifest_count;
    uint32_t failure_bitmap;
    uint32_t reserved0;
    uint64_t verified_manifest_set_id;
    uint64_t root_manifest_gpa;
    uint64_t manifest_set_page_gpa;
    uint8_t snapshot_id[32];
};

struct fbvbs_uvs_artifact_approval {
    bool active;
    uint8_t reserved0[7];
    uint64_t verified_manifest_set_id;
    uint64_t manifest_set_id;
    uint64_t artifact_object_id;
    uint64_t manifest_object_id;
    uint8_t artifact_hash[48];
};

struct fbvbs_artifact_catalog {
    uint32_t count;
    struct fbvbs_artifact_catalog_entry entries[FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES];
};

struct fbvbs_device_catalog {
    uint32_t count;
    struct fbvbs_device_catalog_entry entries[FBVBS_MAX_DEVICE_CATALOG_ENTRIES];
};

struct fbvbs_iommu_domain {
    bool active;
    uint8_t reserved0;
    uint16_t attached_device_count;
    uint32_t reserved1;
    uint64_t domain_id;
    uint64_t owner_partition_id;
};

struct fbvbs_command_tracker {
    bool active;
    bool sequence_seen;
    uint16_t reserved0;
    uint32_t reserved2;
    uint64_t page_gpa;
    uint64_t last_sequence;
    uint64_t last_nonce;
};

struct fbvbs_memory_map_entry {
    uint64_t base_addr;
    uint64_t length;
    uint32_t type;
    uint32_t reserved;
};

/* KCI page binding: tracks which GPA ranges have been hash-verified
   against a measured artifact, authorizing execute permission grant.
   Bindings are invalidated when the underlying mapping changes. */
#ifndef FBVBS_MAX_KCI_PAGE_BINDINGS
#define FBVBS_MAX_KCI_PAGE_BINDINGS 64
#endif

#ifndef FBVBS_MAX_APPROVED_MODULE_PAGES
#define FBVBS_MAX_APPROVED_MODULE_PAGES 1024U
#endif

struct fbvbs_kci_page_binding {
    uint32_t active;
    uint32_t reserved0;
    uint64_t module_object_id;
    uint64_t guest_physical_address;
    uint64_t size;
    uint64_t file_offset;
    uint64_t measurement_epoch;
};

struct fbvbs_hypervisor_state {
    uint64_t next_partition_id;
    uint64_t next_measurement_digest_id;
    uint64_t next_memory_object_id;
    uint64_t next_shared_object_id;
    uint64_t next_target_set_id;
    uint64_t next_key_handle;
    uint64_t next_dek_handle;
    uint64_t next_manifest_set_id;
    uint64_t current_manifest_set_id;
    uint64_t next_iommu_domain_id;
    uint64_t approved_module_object_id;
    uint64_t approved_module_manifest_object_id;
    uint64_t approved_module_base_gpa;
    uint64_t approved_module_size;
    uint64_t boot_id_hi;
    uint64_t boot_id_lo;
    bool trusted_clock_available;
    uint8_t reserved_clock0[7];
    uint64_t trusted_time_seconds;
    uint64_t capability_bitmap0;
    uint64_t capability_bitmap1;
    uint32_t runtime_state_flags;
    uint32_t revoked_object_count;
    uint32_t reserved_revocation0;
    uint64_t revoked_object_ids[FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES];
    struct fbvbs_manifest_profile manifest_profiles[FBVBS_MAX_MANIFEST_PROFILES];
    struct fbvbs_host_callsite_table host_callsites[FBVBS_MAX_HOST_CALLSITE_TABLES];
    struct fbvbs_vmx_capabilities vmx_caps;
    struct fbvbs_log_storage mirror_log;
    struct fbvbs_memory_object memory_objects[FBVBS_MAX_MEMORY_OBJECTS];
    struct fbvbs_shared_registration shared_objects[FBVBS_MAX_SHARED_OBJECTS];
    struct fbvbs_ksi_target_set ksi_target_sets[8];
    struct fbvbs_ksi_object ksi_objects[16];
    struct fbvbs_iks_key iks_keys[16];
    struct fbvbs_sks_dek sks_deks[16];
    struct fbvbs_uvs_manifest_set manifest_sets[8];
    struct fbvbs_uvs_artifact_approval approvals[FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES];
    uint64_t pinned_cr0_mask;
    uint64_t pinned_cr0_value;
    uint64_t pinned_cr4_mask;
    uint64_t pinned_cr4_value;
    uint32_t approved_module_page_count;
    uint32_t reserved_approved_module0;
    uint8_t approved_module_hash[48];
    uint8_t approved_module_page_hashes[FBVBS_MAX_APPROVED_MODULE_PAGES][48];
    struct fbvbs_kci_page_binding kci_bindings[FBVBS_MAX_KCI_PAGE_BINDINGS];
    uint32_t kci_binding_count;
    uint32_t intercepted_msrs[FBVBS_MAX_INTERCEPTED_MSRS];
    uint32_t intercepted_msr_count;
    struct fbvbs_artifact_catalog artifact_catalog;
    struct fbvbs_device_catalog device_catalog;
    struct fbvbs_command_tracker command_trackers[FBVBS_MAX_COMMAND_TRACKERS];
    struct fbvbs_iommu_domain iommu_domains[FBVBS_MAX_PARTITIONS];
    struct fbvbs_partition partitions[FBVBS_MAX_PARTITIONS];
    const void *multiboot_info;  /* Pointer to Multiboot information structure */
    const void *acpi_rsdp;       /* Pointer to bootloader-provided ACPI RSDP copy */
    uint32_t memory_map_count;
    struct fbvbs_memory_map_entry memory_map[32];  /* Memory map from bootloader */
    uint32_t boot_device;
    uint32_t boot_partition;
    uint32_t boot_sub_partition;
    uint32_t boot_module_count;
    struct fbvbs_boot_module boot_modules[FBVBS_MAX_BOOT_MODULES];
    volatile uint32_t log_lock;  /* Spinlock for log operations */

    /* Log rate limiter (Phase 0A-5): per-event-class counters.
     * Indexed by event_code >> 4 (upper nibble), giving 16 classes.
     * When a class exceeds FBVBS_RATE_LIMIT_THRESHOLD in one window,
     * subsequent events are dropped and a summary record is emitted.
     * High-severity events (CRITICAL/ALERT) are exempt from limiting. */
    uint32_t log_rate_counts[FBVBS_RATE_LIMIT_CLASSES];
    uint32_t log_rate_dropped[FBVBS_RATE_LIMIT_CLASSES];
    uint64_t log_rate_window_sequence;  /* sequence at window start */

    /* CPU security subsystem (Section 21): per-CPU detection, vulnerability
     * profiling, and VM exit/entry mitigation state.  Initialized once at
     * boot by fbvbs_hypervisor_init, then immutable except for spec_ctrl. */
    struct fbvbs_global_security_state cpu_security;
    struct fbvbs_cpu_security_profile  bsp_profile;
    struct fbvbs_spec_ctrl_state       spec_ctrl;
};

/*@ predicate fbvbs_state_invariant(struct fbvbs_hypervisor_state *s) =
        \valid(s) &&
        s->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES &&
        s->device_catalog.count <= FBVBS_MAX_DEVICE_CATALOG_ENTRIES &&
        s->revoked_object_count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES &&
        s->intercepted_msr_count <= FBVBS_MAX_INTERCEPTED_MSRS &&
        s->next_memory_object_id > 0 &&
        s->next_partition_id > 0 &&
        s->next_measurement_digest_id > 0 &&
        s->next_shared_object_id > 0 &&
        s->next_target_set_id > 0 &&
        s->next_key_handle > 0 &&
        s->next_dek_handle > 0 &&
        s->next_manifest_set_id > 0 &&
        s->next_iommu_domain_id > 0 &&
        s->memory_map_count <= 32U &&
        s->boot_module_count <= FBVBS_MAX_BOOT_MODULES;
*/

extern struct fbvbs_hypervisor_state g_fbvbs_hypervisor;

struct fbvbs_sha384_context {
    uint64_t state[8];
    uint64_t total_length;
    uint32_t buffered_length;
    uint32_t invalid;  /* 0 = valid, 1 = invalid (error occurred) */
    uint8_t buffer[128];
};

/*@ requires length == 0 || \valid(((char *)buffer) + (0 .. length - 1));
    terminates \true;
    assigns ((char *)buffer)[0 .. length - 1];
    exits \false;
*/
void fbvbs_zero_memory(void *buffer, size_t length);
/*@ requires length == 0 || \valid(((char *)destination) + (0 .. length - 1));
    requires length == 0 || \valid_read(((char *)source) + (0 .. length - 1));
    requires length == 0 || \separated(((char *)destination) + (0 .. length - 1),
                                       ((char *)source) + (0 .. length - 1));
    terminates \true;
    assigns ((char *)destination)[0 .. length - 1];
    exits \false;
*/
void fbvbs_copy_memory(void *destination, const void *source, size_t length);
/*@ requires length == 0 || \valid_read(((char *)buffer) + (0 .. length - 1));
    terminates \true;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
    exits \false;
*/
int fbvbs_memory_is_zero(const void *buffer, size_t length);
/*@ requires length == 0 || \valid_read(((char *)a) + (0 .. length - 1));
    requires length == 0 || \valid_read(((char *)b) + (0 .. length - 1));
    terminates \true;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
    exits \false;
*/
int fbvbs_constant_time_equals(const void *a, const void *b, size_t length);
/*@ requires length == 0 || \valid_read(((char *)data) + (0 .. length - 1));
    requires \valid(out + (0 .. 47));
    terminates \true;
    assigns out[0 .. 47];
    exits \false;
*/
void fbvbs_sha384(const void *data, uint64_t length, uint8_t out[48]);
/*@ requires \valid(context);
    terminates \true;
    assigns *context;
    exits \false;
*/
void fbvbs_sha384_init(struct fbvbs_sha384_context *context);
/*@ requires \valid(context);
    requires length == 0 || \valid_read(((char *)data) + (0 .. length - 1));
    terminates \true;
    assigns *context;
    exits \false;
*/
void fbvbs_sha384_update(
    struct fbvbs_sha384_context *context,
    const void *data,
    uint64_t length
);
/*@ requires \valid(context);
    requires \valid(out + (0 .. 47));
    terminates \true;
    assigns *context, out[0 .. 47];
    exits \false;
*/
void fbvbs_sha384_final(
    struct fbvbs_sha384_context *context,
    uint8_t out[48]
);
/*@ terminates \true;
    assigns \nothing;
    exits \false;
*/
void fbvbs_zero_page_at_gpa(uint64_t gpa);
/*@ requires \valid_read(object);
    requires \valid(page_phys_out);
    terminates \true;
    assigns *page_phys_out;
    ensures \result == 0 || \result == -1;
    exits \false;
*/
int fbvbs_memory_object_get_page_phys(
    const struct fbvbs_memory_object *object,
    uint32_t page_index,
    uint64_t *page_phys_out
);
/*@ requires \valid_read(object);
    requires size == 0 || \valid(((char *)destination) + (0 .. size - 1));
    requires size == 0 || object->allocated;
    terminates \true;
    assigns ((char *)destination)[0 .. size - 1];
    ensures \result == 0 || \result == -1;
    exits \false;
*/
int fbvbs_memory_object_read(
    const struct fbvbs_memory_object *object,
    uint64_t offset,
    void *destination,
    uint64_t size
);
/*@ requires \valid(object);
    requires size == 0 || \valid_read(((char *)source) + (0 .. size - 1));
    requires size == 0 || object->allocated;
    terminates \true;
    assigns *object;
    ensures \result == 0 || \result == -1;
    exits \false;
*/
int fbvbs_memory_object_write(
    struct fbvbs_memory_object *object,
    uint64_t offset,
    const void *source,
    uint64_t size
);
/*@ requires \valid_read(object);
    requires \valid(out + (0 .. 47));
    requires object->allocated;
    terminates \true;
    assigns out[0 .. 47];
    ensures \result == 0 || \result == -1;
    exits \false;
*/
int fbvbs_memory_object_hash_sha384(
    const struct fbvbs_memory_object *object,
    uint8_t out[48]
);
/*@ requires \valid_read(object);
    requires \valid(out + (0 .. 47));
    requires object->allocated;
    terminates \true;
    assigns out[0 .. 47];
    ensures \result == 0 || \result == -1;
    exits \false;
*/
int fbvbs_memory_object_hash_page_sha384(
    const struct fbvbs_memory_object *object,
    uint32_t page_index,
    uint8_t out[48]
);
void fbvbs_memory_object_release_backing(struct fbvbs_memory_object *object);

/*@ terminates \true;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static inline int fbvbs_id_allocator_can_advance(uint64_t next_id, uint64_t step) {
    return next_id != 0U &&
        step != 0U &&
        next_id <= UINT64_MAX - step;
}

/*@ requires n == 0 || \valid(dest + (0 .. n - 1));
    requires n == 0 || \valid_read(src + (0 .. n - 1));
    requires n == 0 || \separated(dest + (0 .. n - 1), src + (0 .. n - 1));
    assigns dest[0 .. n - 1];
    ensures \forall integer i; 0 <= i < n ==> dest[i] == \old(src[i]);
*/
static inline void fbvbs_copy_bytes(uint8_t *dest, const uint8_t *src, size_t n) {
    size_t i;

    /*@ loop invariant 0 <= i <= n;
        loop invariant \forall integer j; 0 <= j < i ==> dest[j] == \at(src[j], Pre);
        loop assigns i, dest[0 .. n - 1];
        loop variant n - i;
    */
    for (i = 0; i < n; ++i) {
        dest[i] = src[i];
    }
}

int fbvbs_hypervisor_init(struct fbvbs_hypervisor_state *state);
void fbvbs_kernel_main(const void *multiboot_info);
const void *fbvbs_acpi_find_table(uint32_t signature);
void fbvbs_boot_runtime_init(void);
void fbvbs_boot_console_puts(const char *message);
void fbvbs_audit_primary_sink_write(const char *message);
/*@ requires \valid(state);
    requires multiboot_info == \null ||
             \valid_read(((const char *)multiboot_info) + (0 .. buffer_size - 1));
    terminates \true;
    assigns state->acpi_rsdp,
            state->memory_map_count,
            state->memory_map[0 .. 31],
            state->boot_device,
            state->boot_partition,
            state->boot_sub_partition,
            state->boot_module_count,
            state->boot_modules[0 .. FBVBS_MAX_BOOT_MODULES - 1]
      \from multiboot_info, buffer_size;
    exits \false;
*/
#ifdef __FRAMAC__
static inline void fbvbs_process_multiboot_info(struct fbvbs_hypervisor_state *state,
                                                const void *multiboot_info,
                                                uint32_t buffer_size) {
    uint32_t index;

    (void)multiboot_info;
    (void)buffer_size;
    if (state == NULL) {
        return;
    }

    state->acpi_rsdp = NULL;
    state->memory_map_count = 0U;
    state->boot_device = 0U;
    state->boot_partition = 0U;
    state->boot_sub_partition = 0U;
    state->boot_module_count = 0U;
    /*@ loop invariant 0 <= index <= 32U;
        loop assigns index, state->memory_map[0 .. 31];
        loop variant 32U - index;
    */
    for (index = 0U; index < 32U; ++index) {
        state->memory_map[index] = (struct fbvbs_memory_map_entry){0};
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_BOOT_MODULES;
        loop assigns index, state->boot_modules[0 .. FBVBS_MAX_BOOT_MODULES - 1];
        loop variant FBVBS_MAX_BOOT_MODULES - index;
    */
    for (index = 0U; index < FBVBS_MAX_BOOT_MODULES; ++index) {
        state->boot_modules[index] = (struct fbvbs_boot_module){0};
    }
}
#else
void fbvbs_process_multiboot_info(struct fbvbs_hypervisor_state *state,
                                  const void *multiboot_info,
                                  uint32_t buffer_size);
#endif

/*@ requires length == 0 || \valid_read(data + (0 .. length - 1));
    terminates \true;
    assigns \nothing;
    exits \false;
*/
uint32_t fbvbs_crc32c(const uint8_t *data, size_t length);
/*@ requires \valid(state);
    terminates \true;
    assigns state->mirror_log, state->runtime_state_flags;
    exits \false;
*/
int fbvbs_log_init(struct fbvbs_hypervisor_state *state);
/*@ requires \valid(state);
    requires payload_length == 0 || \valid_read(payload + (0 .. payload_length - 1));
    terminates \true;
    assigns state->mirror_log, state->log_lock;
    exits \false;
*/
int fbvbs_log_append(
    struct fbvbs_hypervisor_state *state,
    uint32_t cpu_id,
    uint32_t source_component,
    uint16_t severity,
    uint16_t event_code,
    const uint8_t *payload,
    uint32_t payload_length
);
/* Rate-limited log append: drops events exceeding per-class threshold,
 * emits RATE_LIMIT_SUMMARY on window rotation. CRITICAL/ALERT exempt. */
/*@ requires \valid(state);
    requires payload_length == 0 || \valid_read(payload + (0 .. payload_length - 1));
    terminates \true;
    assigns state->mirror_log,
            state->log_lock,
            state->log_rate_counts[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
            state->log_rate_dropped[0 .. FBVBS_RATE_LIMIT_CLASSES - 1],
            state->log_rate_window_sequence;
    exits \false;
*/
int fbvbs_log_append_rate_limited(
    struct fbvbs_hypervisor_state *state,
    uint32_t cpu_id,
    uint32_t source_component,
    uint16_t severity,
    uint16_t event_code,
    const uint8_t *payload,
    uint32_t payload_length
);
/*@ requires \valid(state);
    requires \valid(response);
    terminates \true;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER;
    exits \false;
*/
int fbvbs_audit_get_mirror_info(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_audit_mirror_info_response *response
);
/*@ requires \valid(state);
    requires count == 0 || \valid_read(allowed_offsets + (0 .. count - 1));
    terminates \true;
    assigns *state;
    exits \false;
*/
int fbvbs_configure_host_callsite_table(
    struct fbvbs_hypervisor_state *state,
    uint8_t caller_class,
    uint64_t manifest_object_id,
    uint64_t load_base,
    const uint64_t *allowed_offsets,
    uint32_t count
);
/*@ requires \valid_read(state);
    terminates \true;
    assigns \nothing;
    exits \false;
*/
uint64_t fbvbs_primary_host_callsite(
    const struct fbvbs_hypervisor_state *state,
    uint8_t caller_class
);
/*@ requires \valid_read(state);
    terminates \true;
    assigns \nothing;
    exits \false;
*/
const struct fbvbs_manifest_profile *fbvbs_find_manifest_profile_for_object(
    const struct fbvbs_hypervisor_state *state,
    uint8_t component_type,
    uint64_t object_id
);
/*@ requires \valid_read(state);
    terminates \true;
    assigns \nothing;
    exits \false;
*/
const struct fbvbs_manifest_profile *fbvbs_find_host_manifest_profile(
    const struct fbvbs_hypervisor_state *state,
    uint8_t caller_class
);
/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_host_deprivilege_runtime_ready(
    const struct fbvbs_hypervisor_state *state
);
/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_audit_runtime_ready(
    const struct fbvbs_hypervisor_state *state
);
/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_platform_foundation_ready(
    const struct fbvbs_hypervisor_state *state
);
/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_platform_high_assurance_foundation_ready(
    const struct fbvbs_hypervisor_state *state
);
/*@ requires \valid(state);
    requires artifact_count == 0 || \valid_read(artifact_entries + (0 .. artifact_count - 1));
    requires profile_count == 0 || \valid_read(profiles + (0 .. profile_count - 1));
    terminates \true;
    assigns *state;
    exits \false;
*/
int fbvbs_ingest_boot_catalog(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_artifact_catalog_entry *artifact_entries,
    uint32_t artifact_count,
    const struct fbvbs_manifest_profile *profiles,
    uint32_t profile_count
);

/*@ requires \valid(state);
    requires \valid(partition);
    requires \valid(response);
    requires \separated(response, partition);
    terminates \true;
    assigns *state, *partition, *response;
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == INVALID_STATE || \result == NOT_SUPPORTED_ON_PLATFORM ||
            \result == NOT_FOUND;
    exits \false;
*/
int fbvbs_vmx_run_vcpu(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_partition *partition,
    uint32_t vcpu_id,
    struct fbvbs_vm_run_response *response
);

/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_partition_create(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_create_request *request,
    struct fbvbs_partition_create_response *response
);
/*@ requires \valid(state); requires \valid(response);
    terminates \true; assigns *response; exits \false; */
int fbvbs_partition_get_status(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    struct fbvbs_partition_status_response *response
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_partition_measure(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_measure_request *request,
    struct fbvbs_partition_measure_response *response
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_partition_load_image(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_load_image_request *request
);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_partition_start(struct fbvbs_hypervisor_state *state, uint64_t partition_id);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_partition_quiesce(struct fbvbs_hypervisor_state *state, uint64_t partition_id);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_partition_resume(struct fbvbs_hypervisor_state *state, uint64_t partition_id);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_partition_fault(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint32_t fault_code,
    uint32_t source_component,
    uint64_t detail0,
    uint64_t detail1
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_partition_recover(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_partition_recover_request *request
);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_partition_seed_freebsd_host(struct fbvbs_hypervisor_state *state);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_partition_destroy(struct fbvbs_hypervisor_state *state, uint64_t partition_id);
/*@ requires \valid(state); requires \valid(response);
    terminates \true; assigns *response; exits \false; */
int fbvbs_partition_get_fault_info(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    struct fbvbs_partition_fault_info_response *response
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_vm_create(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_create_request *request,
    struct fbvbs_vm_create_response *response
);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_vm_destroy(struct fbvbs_hypervisor_state *state, uint64_t vm_partition_id);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *response; exits \false; */
int fbvbs_vm_get_vcpu_status(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_vcpu_status_request *request,
    struct fbvbs_vm_vcpu_status_response *response
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_vm_set_register(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_register_request *request
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *response; exits \false; */
int fbvbs_vm_get_register(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_register_read_request *request,
    struct fbvbs_vm_register_response *response
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_vm_run(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_run_request *request,
    struct fbvbs_vm_run_response *response
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_vm_map_memory(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_map_memory_request *request,
    uint64_t requester_partition_id
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_vm_inject_interrupt(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_inject_interrupt_request *request
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_vm_assign_device(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_device_request *request
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_vm_release_device(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_vm_device_request *request
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true;
    assigns state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1],
            state->next_memory_object_id,
            *response;
    exits \false; */
int fbvbs_memory_allocate_object(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_allocate_object_request *request,
    struct fbvbs_memory_allocate_object_response *response,
    uint64_t owner_partition_id
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_memory_map(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_map_request *request,
    uint64_t requester_partition_id
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_memory_unmap(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_unmap_request *request,
    uint64_t requester_partition_id
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_memory_set_permission(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_set_permission_request *request,
    uint64_t requester_partition_id
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_memory_register_shared(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_register_shared_request *request,
    struct fbvbs_memory_register_shared_response *response,
    uint64_t owner_partition_id
);
/*@ requires \valid(state); terminates \true;
    assigns state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1];
    exits \false; */
int fbvbs_memory_release_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_object_id,
    uint64_t requester_partition_id
);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_memory_unregister_shared(
    struct fbvbs_hypervisor_state *state,
    uint64_t shared_object_id,
    uint64_t requester_partition_id
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_kci_verify_module(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_verify_module_request *request,
    struct fbvbs_verdict_response *response
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_kci_set_wx(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_set_wx_request *request
);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
void fbvbs_kci_invalidate_bindings_for_gpa(
    struct fbvbs_hypervisor_state *state,
    uint64_t guest_physical_address,
    uint64_t size
);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
void fbvbs_kci_invalidate_approved_module_for_gpa(
    struct fbvbs_hypervisor_state *state,
    uint64_t guest_physical_address,
    uint64_t size
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_kci_pin_cr(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_pin_cr_request *request
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_kci_intercept_msr(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_intercept_msr_request *request
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_ksi_create_target_set(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_create_target_set_request *request,
    struct fbvbs_ksi_target_set_response *response
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_ksi_register_tier_a(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_register_tier_a_request *request
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_ksi_register_tier_b(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_register_tier_b_request *request
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_ksi_modify_tier_b(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_modify_tier_b_request *request
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_ksi_register_pointer(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_register_pointer_request *request
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_ksi_validate_setuid(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_validate_setuid_request *request,
    struct fbvbs_verdict_response *response
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_ksi_allocate_ucred(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_allocate_ucred_request *request,
    struct fbvbs_ksi_allocate_ucred_response *response
);
/*@ requires \valid(state); requires \valid_read(request);
    terminates \true; assigns *state; exits \false; */
int fbvbs_ksi_replace_tier_b_object(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_replace_tier_b_object_request *request
);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_ksi_unregister_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t object_id
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_iks_import_key(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_import_key_request *request,
    struct fbvbs_handle_response *response
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_iks_sign(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_sign_request *request,
    struct fbvbs_iks_sign_response *response
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_iks_key_exchange(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_key_exchange_request *request,
    struct fbvbs_handle_response *response
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_iks_derive(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_derive_request *request,
    struct fbvbs_handle_response *response
);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_iks_destroy_key(
    struct fbvbs_hypervisor_state *state,
    uint64_t key_handle
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_sks_import_dek(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_import_dek_request *request,
    struct fbvbs_handle_response *response
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_sks_decrypt_batch(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_batch_request *request,
    struct fbvbs_sks_batch_response *response
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_sks_encrypt_batch(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_batch_request *request,
    struct fbvbs_sks_batch_response *response
);
/*@ requires \valid(state); terminates \true; assigns *state; exits \false; */
int fbvbs_sks_destroy_dek(
    struct fbvbs_hypervisor_state *state,
    uint64_t dek_handle
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_uvs_verify_manifest_set(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_verify_manifest_set_request *request,
    struct fbvbs_uvs_verify_manifest_set_response *response
);
/*@ requires \valid_read(state);
    terminates \true;
    assigns \result \from artifact_object_id,
                         manifest_object_id,
                         state->approvals[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1];
    exits \false;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_artifact_approval_exists(
    const struct fbvbs_hypervisor_state *state,
    uint64_t artifact_object_id,
    uint64_t manifest_object_id
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_uvs_verify_artifact(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_verify_artifact_request *request,
    struct fbvbs_verdict_response *response
);
/*@ requires \valid(state); requires \valid_read(request); requires \valid(response);
    terminates \true; assigns *state, *response; exits \false; */
int fbvbs_uvs_check_revocation(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_check_revocation_request *request,
    struct fbvbs_uvs_check_revocation_response *response
);
/*@ requires \valid(state); requires \valid(response); requires \valid(response_length);
    terminates \true; assigns *response, *response_length; exits \false; */
int fbvbs_diag_get_partition_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_partition_list_response *response,
    uint32_t *response_length
);
/*@ requires \valid(state); requires \valid(response);
    terminates \true; assigns *response; exits \false; */
int fbvbs_diag_get_capabilities(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_capabilities_response *response
);
/*@ requires \valid(state); requires \valid(response); requires \valid(response_length);
    terminates \true; assigns *response, *response_length; exits \false; */
int fbvbs_diag_get_artifact_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_artifact_list_response *response,
    uint32_t *response_length
);
/*@ requires \valid(state); requires \valid(response); requires \valid(response_length);
    terminates \true; assigns *response, *response_length; exits \false; */
int fbvbs_diag_get_device_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_device_list_response *response,
    uint32_t *response_length
);
int fbvbs_validate_trap_registers(const struct fbvbs_trap_registers *registers);
int fbvbs_dispatch_hypercall(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_trap_registers *registers
);

/* ================================================================
 * VMCS setup and host deprivilege (vmcs_setup.c)
 * ================================================================ */

struct fbvbs_vmcs_config;

/*@ requires \valid_read(config);
    ensures \result == 0 || \result == -1;
*/
int fbvbs_vmcs_apply(const struct fbvbs_vmcs_config *config);
void fbvbs_vmcs_release_current(void);
void fbvbs_handle_vmexit(uint64_t *guest_gprs);

/*@ requires \valid(state);
    assigns *state;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_deprivilege_host(struct fbvbs_hypervisor_state *state);

/* ---- VMX Security Controls (vmx_controls.c) ---- */

struct fbvbs_vmx_security_controls {
    uint32_t pin_controls_or;
    uint32_t primary_proc_or;
    uint32_t secondary_proc_or;
    uint64_t tertiary_proc_or;
    uint32_t entry_controls_or;
    uint32_t exit_controls_or;
    uint32_t preemption_timer_value;
    uint32_t notify_window;
    uint64_t host_s_cet;
    uint64_t host_ssp;
    uint64_t host_isst_addr;  /* VMCS_HOST_ISST_ADDR (0x6C20) */
    uint64_t guest_s_cet;
    uint32_t msr_bitmap_valid;
    uint32_t reserved0;
};

/*@ requires \valid(controls);
    requires \valid_read(caps);
    assigns *controls;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_vmx_build_security_controls(
    struct fbvbs_vmx_security_controls *controls,
    const struct fbvbs_vmx_capabilities *caps);

/*@ assigns \result \from \nothing;
*/
uint64_t fbvbs_vmx_get_msr_bitmap_phys(void);

/* ---- HLAT (Hypervisor-managed Linear Address Translation) ---- */

/*@ requires \valid(state);
    requires (kernel_text_base & 4095) == 0;
    requires kernel_text_size > 0;
    requires (kernel_text_size & 4095) == 0;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_hlat_init_for_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t kernel_text_base,
    uint64_t kernel_text_size);

/*@ requires \valid(state);
    requires (module_base & 4095) == 0;
    requires module_size > 0;
    requires (module_size & 4095) == 0;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_hlat_add_kld_module(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t module_object_id,
    uint64_t module_base,
    uint64_t module_size);

/*@ requires \valid(state);
    ensures \result == 0 || \result == -1;
*/
int fbvbs_hlat_remove_kld_module(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t module_object_id);

/*@ requires \valid(state);
    assigns \nothing;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_hlat_handle_fault(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t faulting_linear_address);

/*@ requires \valid(state);
    terminates \true;
    assigns *state;
    exits \false;
*/
void fbvbs_hlat_cleanup_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id);

/* ---- Intel MBEC (Mode-Based Execute Control, hlat.c) ---- */

/*@ requires \valid(controls_or);
    requires \valid_read(caps);
    assigns *controls_or;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_mbec_build_config(
    uint32_t *controls_or,
    const struct fbvbs_vmx_capabilities *caps);

/* ---- AMD NPT Translation Integrity (amd_npt.c) ---- */

/*@ requires \valid(state);
    requires (kernel_text_base & 4095) == 0;
    requires kernel_text_size > 0;
    requires (kernel_text_size & 4095) == 0;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_npt_init_for_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t kernel_text_base,
    uint64_t kernel_text_size);

/*@ requires \valid(state);
    requires (module_base & 4095) == 0;
    requires module_size > 0;
    requires (module_size & 4095) == 0;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_npt_add_kld_module(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t module_object_id,
    uint64_t module_base,
    uint64_t module_size);

/*@ requires \valid(state);
    ensures \result == 0 || \result == -1;
*/
int fbvbs_npt_remove_kld_module(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t module_object_id);

/*@ requires \valid(state);
    ensures \result == 0 || \result == -1;
*/
int fbvbs_npt_handle_fault_exit(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t faulting_gpa,
    uint64_t error_code);

/*@ requires \valid(state);
    ensures \result == 0 || \result == -1;
*/
int fbvbs_npt_handle_invlpg_exit(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t linear_addr);

/*@ requires \valid(state);
    terminates \true;
    assigns *state;
    exits \false;
*/
void fbvbs_npt_cleanup_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id);

/* ---- EPT (Extended Page Tables, memory.c) ---- */

int fbvbs_ept_create_root(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id);

int fbvbs_ept_map_region(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t gpa,
    uint64_t size,
    uint16_t permissions);

int fbvbs_ept_unmap_region(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    uint64_t gpa,
    uint64_t size);

/*@ requires \valid(state);
    terminates \true;
    assigns *state;
    exits \false;
*/
void fbvbs_ept_cleanup_partition(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id);

uint64_t fbvbs_ept_get_root(
    const struct fbvbs_hypervisor_state *state,
    uint64_t partition_id);

/* ---- AMD GMET (Guest Mode Execute Trap, amd_npt.c) ---- */

/*@ requires \valid(npt_control_or);
    assigns *npt_control_or;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_gmet_build_config(uint64_t *npt_control_or);

/* Phase 1-8: RDRAND/RDSEED entropy */
int fbvbs_cpu_has_rdrand(void);
int fbvbs_cpu_has_rdseed(void);
int fbvbs_rdrand64(uint64_t *out);
int fbvbs_rdseed64(uint64_t *out);
int fbvbs_entropy_seed_boot_ids(struct fbvbs_hypervisor_state *state);

/* Phase 1-1: IDT + exception handler (idt.c) */
int fbvbs_idt_init(void);
void fbvbs_handle_de(const void *frame);
void fbvbs_handle_db(const void *frame);
void fbvbs_handle_nmi(const void *frame);
void fbvbs_handle_bp(const void *frame);
void fbvbs_handle_ud(const void *frame);
void fbvbs_handle_df(const void *frame, uint64_t error_code);
void fbvbs_handle_gp(const void *frame, uint64_t error_code);
void fbvbs_handle_pf(const void *frame, uint64_t error_code);
void fbvbs_handle_mc(const void *frame);
uint64_t fbvbs_ist_stack_top_nmi(void);
uint64_t fbvbs_ist_stack_top_df(void);
uint64_t fbvbs_ist_stack_top_mc(void);

/* Phase 1-7: xAPIC/x2APIC virtualization (apic.c) */
/*@ assigns \nothing;
    ensures \result == 0 || \result == 1 || \result == 2;
*/
int fbvbs_apic_detect_mode(void);
int fbvbs_apic_get_mode(void);

struct fbvbs_apic_virt_config {
    uint32_t secondary_proc_or;
    uint32_t pin_controls_or;
    uint32_t apic_mode;
    uint32_t reserved0;
    uint64_t apic_access_page;
};

/*@ requires \valid(config);
    requires \valid_read(caps);
    assigns *config;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_apic_build_virt_config(
    struct fbvbs_apic_virt_config *config,
    const struct fbvbs_vmx_capabilities *caps);

int fbvbs_apic_init_partition(uint32_t apic_id);
int fbvbs_apic_handle_vm_exit_eoi(void);
int fbvbs_apic_inject_vector(uint32_t vector);
int fbvbs_apic_timer_tick(void);

/* Phase 1-9: Watchdog / liveness monitor */
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
    uint32_t partition_idx);

/*@ requires \valid(state);
    requires partition_idx < FBVBS_MAX_PARTITIONS;
    assigns state->partitions[partition_idx].consecutive_timer_exits;
*/
void fbvbs_watchdog_on_voluntary_exit(
    struct fbvbs_hypervisor_state *state,
    uint32_t partition_idx);

/* Phase 0C: Physical page frame allocator */
/*@ requires map_count == 0 || \valid_read(map + (0 .. map_count - 1));
    terminates \true;
    assigns \nothing;
    exits \false;
*/
int fbvbs_page_alloc_init(const struct fbvbs_memory_map_entry *map,
                          uint32_t map_count);
/*@ terminates \true;
    assigns \nothing;
    exits \false;
*/
int fbvbs_page_alloc_reserve(uint64_t phys_addr, uint64_t size);
/*@ terminates \true;
    assigns \nothing;
    exits \false;
*/
uint64_t fbvbs_page_alloc(void);
/*@ terminates \true;
    assigns \nothing;
    exits \false;
*/
int fbvbs_page_free(uint64_t phys_addr);
/*@ terminates \true;
    assigns \nothing;
    exits \false;
*/
uint32_t fbvbs_page_alloc_free_count(void);
/*@ terminates \true;
    assigns \nothing;
    exits \false;
*/
uint32_t fbvbs_page_alloc_total_pages(void);

/* Phase 1-11: State structure size guards.
 * Hypervisor state must fit in a known region.  If struct grows beyond
 * 2 MiB something is wrong (accidental array size explosion, etc.).
 * The actual layout has guard pages around it (Phase 1-11 runtime). */
#define FBVBS_MAX_HV_STATE_SIZE (2U * 1024U * 1024U)
_Static_assert(sizeof(struct fbvbs_hypervisor_state) < FBVBS_MAX_HV_STATE_SIZE,
               "fbvbs_hypervisor_state exceeds 2 MiB — review array sizing");

/* Partition struct size guard — each partition should not exceed 64 KiB */
_Static_assert(sizeof(struct fbvbs_partition) < 65536U,
               "fbvbs_partition exceeds 64 KiB — review sub-struct sizing");

/* Log storage must fit exactly SLOT_COUNT records plus header */
_Static_assert(sizeof(struct fbvbs_log_storage) ==
               sizeof(struct fbvbs_log_ring_header_v1) +
               FBVBS_LOG_SLOT_COUNT * sizeof(struct fbvbs_log_record_v1),
               "log storage size mismatch");

/* Memory object size guard */
_Static_assert(sizeof(struct fbvbs_memory_object) <= 256U,
               "fbvbs_memory_object exceeds 256 bytes");

/* Boot module descriptor size guard */
_Static_assert(sizeof(struct fbvbs_boot_module) <= 96U,
               "fbvbs_boot_module exceeds 96 bytes");

/* IOMMU domain size guard */
_Static_assert(sizeof(struct fbvbs_iommu_domain) <= 64U,
               "fbvbs_iommu_domain exceeds 64 bytes");

/* CPU security profile size guard (includes features + vuln + CR pins + boot) */
_Static_assert(sizeof(struct fbvbs_cpu_security_profile) <= 512U,
               "fbvbs_cpu_security_profile exceeds 512 bytes");

/* VMX capabilities size guard (ABI stability) */
_Static_assert(sizeof(struct fbvbs_vmx_capabilities) == 32U,
               "fbvbs_vmx_capabilities ABI drift — update all consumers");

/* Shared registration size guard */
_Static_assert(sizeof(struct fbvbs_shared_registration) <= 64U,
               "fbvbs_shared_registration exceeds 64 bytes");

/* Command page must be exactly one page (4 KiB) */
_Static_assert(sizeof(struct fbvbs_aligned_command_page) == FBVBS_PAGE_SIZE,
               "aligned_command_page must be exactly one page");

/* Phase 1-11: Memory Layout Documentation.
 *
 * The hypervisor's global state (g_fbvbs_hypervisor) is placed in BSS.
 * At runtime, the memory layout should be:
 *
 *   [Guard page — 4 KiB, unmapped/not-present in EPT]
 *   [g_fbvbs_hypervisor — sizeof(fbvbs_hypervisor_state)]
 *   [Guard page — 4 KiB, unmapped/not-present in EPT]
 *   [Hypervisor stack — 16-64 KiB, depending on boot path]
 *   [Guard page — 4 KiB, unmapped/not-present in EPT]
 *   [IST stacks — 3 x 4 KiB for NMI, DF, MC]
 *   [Guard pages — between each IST stack]
 *
 * Guard pages prevent stack overflow and state corruption from
 * overwriting adjacent regions. The linker script must place
 * FBVBS_GUARD_PAGE_SIZE gaps around each critical region.
 *
 * PRODUCTION NOTE: The linker script (fbvbs.lds) must define:
 *   __guard_before_state, __guard_after_state,
 *   __guard_before_stack, __guard_after_stack
 * and the early_init code must mark these as not-present in the
 * hypervisor's own page tables. */
#define FBVBS_GUARD_PAGE_SIZE 4096U

/* ---- Phase 8: Multi-Processor Initialization (mp_init.c) ---- */

/*@ requires \valid(state);
    ensures \result == 0 || \result == -1;
*/
int fbvbs_mp_init(struct fbvbs_hypervisor_state *state);

uint32_t fbvbs_mp_cpu_count(void);
uint32_t fbvbs_mp_online_count(void);
uint32_t fbvbs_mp_numa_domain_count(void);
int fbvbs_mp_get_cpu_info(
    uint32_t cpu_index,
    uint32_t *apic_id_out,
    uint32_t *state_out,
    uint32_t *numa_domain_out);
int fbvbs_mp_tlb_shootdown(uint64_t partition_id,
                            uint64_t address, uint64_t size);
void fbvbs_mp_tlb_shootdown_handler(void);

#endif
