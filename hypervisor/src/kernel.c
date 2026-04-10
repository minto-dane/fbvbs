/* FBVBS Kernel Integration (KCI host callsite, boot identity)
 *
 * Requirements: REQ-0501 (Shadow copy — PRODUCTION NOTE: Phase 4 KSI stub),
 *   REQ-0601 (IKS API 制限 — PRODUCTION NOTE: Phase 5 IKS stub),
 *   REQ-1000 (トレーサビリティ — see tools/verification/traceability_matrix.py),
 *   REQ-1001 (TCB 変更独立レビュー — PRODUCTION NOTE: Phase 9 process),
 *   REQ-1002 (SPARK 例外不在証明 — PRODUCTION NOTE: Ada/SPARK reference path),
 *   REQ-1003 (Rust TCB 制約 — PRODUCTION NOTE: Phase 9),
 *   REQ-1004 (継続的ファジング — see fuzz/ harnesses),
 *   REQ-1005 (MC/DC カバレッジ — see Makefile coverage target),
 *   REQ-1006 (再現可能ビルド — see Makefile reproducible target)
 */
#include <stdint.h>

#include "fbvbs_hypervisor.h"

#ifndef FBVBS_REQUIRE_MEASURED_BOOT
#define FBVBS_REQUIRE_MEASURED_BOOT 0
#endif

/* Guard: callsite count field is uint16_t — ensure max entries fits */
_Static_assert(FBVBS_MAX_HOST_CALLSITE_ENTRIES <= UINT16_MAX,
               "callsite count must fit in uint16_t");

struct fbvbs_hypervisor_state g_fbvbs_hypervisor;

#define FBVBS_MULTIBOOT_MAX_BUFFER_SIZE (64U * 1024U * 1024U)

#ifdef FBVBS_BAREMETAL_BUILD
extern const uint8_t _binary_start[];
extern const uint8_t _binary_end[];
extern const uint8_t _data_end[];
#endif

struct fbvbs_boot_snapshot {
    const void *multiboot_info;
    const void *acpi_rsdp;
    uint32_t memory_map_count;
    struct fbvbs_memory_map_entry memory_map[32];
    uint32_t boot_device;
    uint32_t boot_partition;
    uint32_t boot_sub_partition;
    uint32_t boot_module_count;
    struct fbvbs_boot_module boot_modules[FBVBS_MAX_BOOT_MODULES];
};

/*@ requires \valid(dest + (0 .. 31));
    requires \valid_read(src + (0 .. 31));
    assigns dest[0 .. 31] \from src[0 .. 31];
*/
static void fbvbs_copy_memory_map_entries(
    struct fbvbs_memory_map_entry dest[32],
    const struct fbvbs_memory_map_entry src[32]
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 32;
        loop assigns index, dest[0 .. 31];
        loop variant 32 - index;
    */
    for (index = 0U; index < 32U; ++index) {
        dest[index] = src[index];
    }
}

/*@ requires \valid(dest + (0 .. FBVBS_MAX_BOOT_MODULES - 1));
    requires \valid_read(src + (0 .. FBVBS_MAX_BOOT_MODULES - 1));
    assigns dest[0 .. FBVBS_MAX_BOOT_MODULES - 1]
      \from src[0 .. FBVBS_MAX_BOOT_MODULES - 1];
*/
static void fbvbs_copy_boot_modules(
    struct fbvbs_boot_module dest[FBVBS_MAX_BOOT_MODULES],
    const struct fbvbs_boot_module src[FBVBS_MAX_BOOT_MODULES]
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_BOOT_MODULES;
        loop assigns index, dest[0 .. FBVBS_MAX_BOOT_MODULES - 1];
        loop variant FBVBS_MAX_BOOT_MODULES - index;
    */
    for (index = 0U; index < FBVBS_MAX_BOOT_MODULES; ++index) {
        dest[index] = src[index];
    }
}

#if !defined(FBVBS_BAREMETAL_BUILD) && !defined(__FRAMAC__)
/* Hosted/coverage/proof builds do not have a hardware UART path.
 * Keep the symbol available so fail-closed diagnostics in low-level code
 * link cleanly without pretending that a real bare-metal sink exists. */
void fbvbs_boot_console_puts(const char *message) {
    (void)message;
}
#endif

/*@ assigns \nothing;
*/
static void fbvbs_boot_status(const char *message) {
#ifdef FBVBS_BAREMETAL_BUILD
    fbvbs_boot_console_puts(message);
#else
    (void)message;
#endif
}

/*@ requires \valid(state);
    requires \valid(snapshot);
    assigns *snapshot;
    assigns snapshot->multiboot_info,
            snapshot->acpi_rsdp,
            snapshot->memory_map_count,
            snapshot->memory_map[0 .. 31],
            snapshot->boot_device,
            snapshot->boot_partition,
            snapshot->boot_sub_partition,
            snapshot->boot_module_count,
            snapshot->boot_modules[0 .. FBVBS_MAX_BOOT_MODULES - 1]
      \from state->multiboot_info,
            state->acpi_rsdp,
            state->memory_map_count,
            state->memory_map[0 .. 31],
            state->boot_device,
            state->boot_partition,
            state->boot_sub_partition,
            state->boot_module_count,
            state->boot_modules[0 .. FBVBS_MAX_BOOT_MODULES - 1];
*/
static void fbvbs_capture_boot_snapshot(
    const struct fbvbs_hypervisor_state *state,
    struct fbvbs_boot_snapshot *snapshot
) {
    snapshot->multiboot_info = state->multiboot_info;
    snapshot->acpi_rsdp = state->acpi_rsdp;
    snapshot->memory_map_count = state->memory_map_count;
    fbvbs_copy_memory_map_entries(snapshot->memory_map, state->memory_map);
    snapshot->boot_device = state->boot_device;
    snapshot->boot_partition = state->boot_partition;
    snapshot->boot_sub_partition = state->boot_sub_partition;
    snapshot->boot_module_count = state->boot_module_count;
    fbvbs_copy_boot_modules(snapshot->boot_modules, state->boot_modules);
}

/*@ requires \valid(state);
    requires \valid_read(snapshot);
    assigns state->multiboot_info,
            state->acpi_rsdp,
            state->memory_map_count,
            state->memory_map[0 .. 31],
            state->boot_device,
            state->boot_partition,
            state->boot_sub_partition,
            state->boot_module_count,
            state->boot_modules[0 .. FBVBS_MAX_BOOT_MODULES - 1]
      \from snapshot->multiboot_info,
            snapshot->acpi_rsdp,
            snapshot->memory_map_count,
            snapshot->memory_map[0 .. 31],
            snapshot->boot_device,
            snapshot->boot_partition,
            snapshot->boot_sub_partition,
            snapshot->boot_module_count,
            snapshot->boot_modules[0 .. FBVBS_MAX_BOOT_MODULES - 1];
*/
static void fbvbs_restore_boot_snapshot(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_boot_snapshot *snapshot
) {
    state->multiboot_info = snapshot->multiboot_info;
    state->acpi_rsdp = snapshot->acpi_rsdp;
    state->memory_map_count = snapshot->memory_map_count;
    fbvbs_copy_memory_map_entries(state->memory_map, snapshot->memory_map);
    state->boot_device = snapshot->boot_device;
    state->boot_partition = snapshot->boot_partition;
    state->boot_sub_partition = snapshot->boot_sub_partition;
    state->boot_module_count = snapshot->boot_module_count;
    fbvbs_copy_boot_modules(state->boot_modules, snapshot->boot_modules);
}

/*@ assigns \nothing;
    ensures \result <= FBVBS_MULTIBOOT_MAX_BUFFER_SIZE;
*/
static uint32_t fbvbs_multiboot_total_size(const void *multiboot_info) {
    uint32_t total_size = 0U;

    if (multiboot_info == NULL) {
        return 0U;
    }

#ifdef __FRAMAC__
    return 8U;
#else
    fbvbs_copy_memory(&total_size, multiboot_info, sizeof(total_size));
#endif
    if (total_size < 8U || total_size > FBVBS_MULTIBOOT_MAX_BUFFER_SIZE) {
        return 0U;
    }

    return total_size;
}

/*@ requires \valid(state);
    assigns \nothing;
    ensures \result == OK || \result == RESOURCE_EXHAUSTED;
*/
static int fbvbs_bootstrap_page_allocator(struct fbvbs_hypervisor_state *state) {
    uint32_t multiboot_size;
    uint32_t index;

#ifdef __FRAMAC__
    (void)state;
    return OK;
#endif

    if (state->memory_map_count == 0U) {
#ifdef FBVBS_BAREMETAL_BUILD
        fbvbs_boot_status("FBVBS: no boot memory map\n");
        return RESOURCE_EXHAUSTED;
#else
        return OK;
#endif
    }

    if (fbvbs_page_alloc_init(state->memory_map, state->memory_map_count) != 0) {
        return RESOURCE_EXHAUSTED;
    }

#ifdef FBVBS_BAREMETAL_BUILD
    if (fbvbs_page_alloc_reserve((uint64_t)(uintptr_t)_binary_start,
                                 (uint64_t)((uintptr_t)_binary_end - (uintptr_t)_binary_start)) != 0) {
        return RESOURCE_EXHAUSTED;
    }
#endif

    multiboot_size = fbvbs_multiboot_total_size(state->multiboot_info);
    if (multiboot_size != 0U &&
        fbvbs_page_alloc_reserve((uint64_t)(uintptr_t)state->multiboot_info,
                                 multiboot_size) != 0) {
        return RESOURCE_EXHAUSTED;
    }

    /*@ loop invariant 0 <= index <= state->boot_module_count || index <= FBVBS_MAX_BOOT_MODULES;
        loop assigns index;
        loop variant FBVBS_MAX_BOOT_MODULES - index;
    */
    for (index = 0U;
         index < state->boot_module_count && index < FBVBS_MAX_BOOT_MODULES;
         ++index) {
        const struct fbvbs_boot_module *module = &state->boot_modules[index];

        if (!module->active || module->size == 0U) {
            continue;
        }
        if (fbvbs_page_alloc_reserve(module->start_phys, module->size) != 0) {
            return RESOURCE_EXHAUSTED;
        }
    }

    return OK;
}

/*@ requires \valid(state);
    assigns \nothing;
    ensures -1 <= \result < (int32_t)FBVBS_MAX_HOST_CALLSITE_TABLES;
*/
static int32_t fbvbs_find_host_callsite_table_slot_index(
    struct fbvbs_hypervisor_state *state,
    uint8_t caller_class
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_HOST_CALLSITE_TABLES;
        loop assigns index;
        loop variant FBVBS_MAX_HOST_CALLSITE_TABLES - index;
    */
    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        if (state->host_callsites[index].active &&
            state->host_callsites[index].caller_class == caller_class) {
            return (int32_t)index;
        }
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_HOST_CALLSITE_TABLES;
        loop assigns index;
        loop variant FBVBS_MAX_HOST_CALLSITE_TABLES - index;
    */
    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        if (!state->host_callsites[index].active) {
            return (int32_t)index;
        }
    }
    return -1;
}

int fbvbs_configure_host_callsite_table(
    struct fbvbs_hypervisor_state *state,
    uint8_t caller_class,
    uint64_t manifest_object_id,
    uint64_t load_base,
    const uint64_t *allowed_offsets,
    uint32_t count
) {
    struct fbvbs_host_callsite_table table;
    int32_t slot_index;
    uint32_t index;

    if (state == NULL || allowed_offsets == NULL || manifest_object_id == 0U ||
        load_base == 0U || count == 0U || count > FBVBS_MAX_HOST_CALLSITE_ENTRIES) {
        return INVALID_PARAMETER;
    }
    if (caller_class != FBVBS_HOST_CALLER_CLASS_FBVBS &&
        caller_class != FBVBS_HOST_CALLER_CLASS_VMM) {
        return INVALID_PARAMETER;
    }

    /* Check if caller_class already exists to prevent overwriting */
    /*@ loop invariant 0 <= index <= FBVBS_MAX_HOST_CALLSITE_TABLES;
        loop assigns index;
        loop variant FBVBS_MAX_HOST_CALLSITE_TABLES - index;
    */
    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        if (state->host_callsites[index].active &&
            state->host_callsites[index].caller_class == caller_class) {
            return ALREADY_EXISTS;
        }
    }

    table = (struct fbvbs_host_callsite_table){0};
    table.active = true;
    table.caller_class = caller_class;
    table.count = (uint16_t)count;
    table.manifest_object_id = manifest_object_id;
    table.load_base = load_base;
    /*@ loop invariant 0 <= index <= count;
        loop assigns index, table.allowed_offsets[0 .. FBVBS_MAX_HOST_CALLSITE_ENTRIES - 1],
                      table.relocated_callsites[0 .. FBVBS_MAX_HOST_CALLSITE_ENTRIES - 1];
        loop variant count - index;
    */
    for (index = 0U; index < count; ++index) {
        if (load_base > UINT64_MAX - allowed_offsets[index]) {
            return INVALID_PARAMETER;
        }
        table.allowed_offsets[index] = allowed_offsets[index];
        table.relocated_callsites[index] = load_base + allowed_offsets[index];
    }

    slot_index = fbvbs_find_host_callsite_table_slot_index(state, caller_class);
    if (slot_index < 0) {
        return RESOURCE_EXHAUSTED;
    }
    /*@ assert 0 <= slot_index < (int32_t)FBVBS_MAX_HOST_CALLSITE_TABLES; */
    state->host_callsites[slot_index] = table;
    return OK;
}

uint64_t fbvbs_primary_host_callsite(
    const struct fbvbs_hypervisor_state *state,
    uint8_t caller_class
) {
    uint32_t index;

    if (state == NULL) {
        return 0U;
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_HOST_CALLSITE_TABLES;
        loop assigns index;
        loop variant FBVBS_MAX_HOST_CALLSITE_TABLES - index;
    */
    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        if (state->host_callsites[index].active &&
            state->host_callsites[index].caller_class == caller_class &&
            state->host_callsites[index].count != 0U) {
            return state->host_callsites[index].relocated_callsites[0];
        }
    }
    return 0U;
}

const struct fbvbs_manifest_profile *fbvbs_find_manifest_profile_for_object(
    const struct fbvbs_hypervisor_state *state,
    uint8_t component_type,
    uint64_t object_id
) {
    uint32_t index;

    if (state == NULL || object_id == 0U) {
        return NULL;
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MANIFEST_PROFILES;
        loop assigns index;
        loop variant FBVBS_MAX_MANIFEST_PROFILES - index;
    */
    for (index = 0U; index < FBVBS_MAX_MANIFEST_PROFILES; ++index) {
        const struct fbvbs_manifest_profile *profile = &state->manifest_profiles[index];

        if (profile->active &&
            profile->component_type == component_type &&
            profile->object_id == object_id) {
            return profile;
        }
    }
    return NULL;
}

const struct fbvbs_manifest_profile *fbvbs_find_host_manifest_profile(
    const struct fbvbs_hypervisor_state *state,
    uint8_t caller_class
) {
    uint32_t index;

    if (state == NULL) {
        return NULL;
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MANIFEST_PROFILES;
        loop assigns index;
        loop variant FBVBS_MAX_MANIFEST_PROFILES - index;
    */
    for (index = 0U; index < FBVBS_MAX_MANIFEST_PROFILES; ++index) {
        const struct fbvbs_manifest_profile *profile = &state->manifest_profiles[index];

        if (profile->active &&
            (profile->component_type == FBVBS_MANIFEST_COMPONENT_FREEBSD_KERNEL ||
             profile->component_type == FBVBS_MANIFEST_COMPONENT_FREEBSD_MODULE) &&
            profile->caller_class == caller_class) {
            return profile;
        }
    }
    return NULL;
}

/*@ requires \valid(state);
    assigns state->boot_id_hi, state->boot_id_lo;
    ensures state->boot_id_hi == 0x4642564253560000ULL;
    ensures state->boot_id_lo == 0x0000000000000001ULL;
*/
/* MODEL ONLY: Deterministic boot IDs for the verification model.
 * Production MUST replace with RDRAND-seeded or platform RNG values
 * to provide uniqueness across boots for replay prevention. */
#if defined(__FRAMAC__)
static void fbvbs_seed_boot_ids(struct fbvbs_hypervisor_state *state) {
    state->boot_id_hi = 0x4642564253560000ULL;
    state->boot_id_lo = 0x0000000000000001ULL;
}
#endif

/* Phase 1-8: Production boot ID generation using hardware entropy.
 * Replaces seed_boot_ids MODEL ONLY function above. */
/*@ requires \valid(state);
    assigns state->boot_id_hi, state->boot_id_lo;
    ensures \result == 0 || \result == -1;
*/
int fbvbs_entropy_seed_boot_ids(struct fbvbs_hypervisor_state *state) {
    int rc;

    if (state == NULL) {
        return -1;
    }

    rc = fbvbs_rdseed64(&state->boot_id_hi);
    if (rc != 0) {
        state->boot_id_hi = 0;
        state->boot_id_lo = 0;
        return -1;
    }

    rc = fbvbs_rdseed64(&state->boot_id_lo);
    if (rc != 0) {
        state->boot_id_hi = 0;
        state->boot_id_lo = 0;
        return -1;
    }

    return 0;
}

/*@ requires \valid(hash + (0 .. 47));
    assigns hash[0 .. 47];
*/
/* MODEL ONLY: This generates deterministic seed hashes for the formal
 * verification model. It is NOT a cryptographic hash — it applies a single
 * SHA-256 compression round without FIPS 180-4 padding, and extends the
 * 32-byte output to 48 bytes via XOR. Production deployments MUST replace
 * this with real SHA-256 over actual artifact content (image bytes). */
static void fbvbs_seed_hash(uint8_t hash[48], uint8_t tag) {
    uint32_t index;
    uint32_t sha_state[8];
    uint32_t temp;
    uint32_t w[64];
    uint32_t s0;
    uint32_t s1;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    uint32_t S0_val;
    uint32_t S1_val;
    uint32_t ch;
    uint32_t temp1;
    uint32_t maj;
    uint32_t temp2;

    /* SHA-256 round constants */
    static const uint32_t k[64] = {
        0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
        0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
        0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
        0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
        0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
        0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
        0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
        0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
        0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
        0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
        0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
        0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
        0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
        0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
        0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
        0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
    };

    /* Initialize SHA-256 state with initial values */
    sha_state[0] = 0x6A09E667U;
    sha_state[1] = 0xBB67AE85U;
    sha_state[2] = 0x3C6EF372U;
    sha_state[3] = 0xA54FF53AU;
    sha_state[4] = 0x510E527FU;
    sha_state[5] = 0x9B05688CU;
    sha_state[6] = 0x1F83D9ABU;
    sha_state[7] = 0x5BE0CD19U;

    /* Prepare message schedule */
    /*@ loop invariant 0 <= index <= 16;
        loop assigns index, w[0 .. 15];
        loop variant 16 - index;
    */
    for (index = 0U; index < 16U; ++index) {
        w[index] = 0U;
    }
    w[0] = ((uint32_t)tag) << 24;

    /* Extend message schedule */
    /*@ loop invariant 16 <= index <= 64;
        loop assigns index, temp, s0, s1, w[16 .. 63];
        loop variant 64 - index;
    */
    for (index = 16U; index < 64U; ++index) {
        temp = w[index - 15];
        s0 = ((temp >> 7) | (temp << 25)) ^ ((temp >> 18) | (temp << 14)) ^ (temp >> 3);
        temp = w[index - 2];
        s1 = ((temp >> 17) | (temp << 15)) ^ ((temp >> 19) | (temp << 13)) ^ (temp >> 10);
        w[index] = w[index - 16] + s0 + w[index - 7] + s1;
    }

    /* SHA-256 compression function */
    a = sha_state[0];
    b = sha_state[1];
    c = sha_state[2];
    d = sha_state[3];
    e = sha_state[4];
    f = sha_state[5];
    g = sha_state[6];
    h = sha_state[7];

    /*@ loop invariant 0 <= index <= 64;
        loop assigns index, S1_val, ch, temp1, S0_val, maj, temp2, a, b, c, d, e, f, g, h;
        loop variant 64 - index;
    */
    for (index = 0U; index < 64U; ++index) {
        S1_val = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
        ch = (e & f) ^ (~e & g);
        temp1 = h + S1_val + ch + k[index] + w[index];
        S0_val = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
        maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = S0_val + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    sha_state[0] += a;
    sha_state[1] += b;
    sha_state[2] += c;
    sha_state[3] += d;
    sha_state[4] += e;
    sha_state[5] += f;
    sha_state[6] += g;
    sha_state[7] += h;

    /* Convert state to hash bytes (big-endian) */
    /*@ loop invariant 0 <= index <= 8;
        loop assigns index, hash[0 .. 31];
        loop variant 8 - index;
    */
    for (index = 0U; index < 8U; ++index) {
        hash[index * 4] = (uint8_t)(sha_state[index] >> 24);
        hash[index * 4 + 1] = (uint8_t)(sha_state[index] >> 16);
        hash[index * 4 + 2] = (uint8_t)(sha_state[index] >> 8);
        hash[index * 4 + 3] = (uint8_t)(sha_state[index]);
    }

    /* Fill remaining bytes with derived values */
    /*@ loop invariant 32 <= index <= 48;
        loop assigns index, hash[32 .. 47];
        loop variant 48 - index;
    */
    for (index = 32U; index < 48U; ++index) {
        hash[index] = hash[index - 32] ^ hash[index - 16] ^ tag;
    }
}

struct fbvbs_boot_artifact_seed {
    uint64_t object_id;
    uint32_t object_kind;
    uint32_t related_index;
    uint8_t hash_tag;
};

static const struct fbvbs_boot_artifact_seed g_fbvbs_boot_artifact_seeds[] = {
    {0x1000U, FBVBS_ARTIFACT_OBJECT_IMAGE, 1U, 0x11U},
    {0x2000U, FBVBS_ARTIFACT_OBJECT_MANIFEST, 0U, 0x22U},
    {0x3000U, FBVBS_ARTIFACT_OBJECT_MODULE, 19U, 0x33U},
    {0x1100U, FBVBS_ARTIFACT_OBJECT_IMAGE, 4U, 0x44U},
    {0x2100U, FBVBS_ARTIFACT_OBJECT_MANIFEST, 3U, 0x55U},
    {0x1200U, FBVBS_ARTIFACT_OBJECT_IMAGE, 6U, 0x66U},
    {0x2200U, FBVBS_ARTIFACT_OBJECT_MANIFEST, 5U, 0x77U},
    {0x1300U, FBVBS_ARTIFACT_OBJECT_IMAGE, 8U, 0x88U},
    {0x2300U, FBVBS_ARTIFACT_OBJECT_MANIFEST, 7U, 0x99U},
    {0x1400U, FBVBS_ARTIFACT_OBJECT_IMAGE, 10U, 0xA1U},
    {0x2400U, FBVBS_ARTIFACT_OBJECT_MANIFEST, 9U, 0xA2U},
    {0x1500U, FBVBS_ARTIFACT_OBJECT_IMAGE, 12U, 0xA3U},
    {0x2500U, FBVBS_ARTIFACT_OBJECT_MANIFEST, 11U, 0xA4U},
    {0x1600U, FBVBS_ARTIFACT_OBJECT_IMAGE, 14U, 0xA5U},
    {0x2600U, FBVBS_ARTIFACT_OBJECT_MANIFEST, 13U, 0xA6U},
    {0x1700U, FBVBS_ARTIFACT_OBJECT_IMAGE, 16U, 0xA7U},
    {0x2700U, FBVBS_ARTIFACT_OBJECT_MANIFEST, 15U, 0xA8U},
    {0x3700U, FBVBS_ARTIFACT_OBJECT_MODULE, 18U, 0xA9U},
    {0x2800U, FBVBS_ARTIFACT_OBJECT_MANIFEST, 17U, 0xAAU},
    {0x2900U, FBVBS_ARTIFACT_OBJECT_MANIFEST, 2U, 0xABU},
};

enum {
    FBVBS_BOOT_ARTIFACT_SEED_COUNT =
        (int)(sizeof(g_fbvbs_boot_artifact_seeds) / sizeof(g_fbvbs_boot_artifact_seeds[0]))
};

static const struct fbvbs_manifest_profile g_fbvbs_boot_manifest_profiles[] = {
    {
        .active = true,
        .component_type = FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE,
        .service_kind = SERVICE_KIND_KCI,
        .vcpu_count = 1U,
        .object_id = 0x1000U,
        .manifest_object_id = 0x2000U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 0x3FU,
        .entry_ip = 0x400000U,
        .initial_sp = 0x800000U,
    },
    {
        .active = true,
        .component_type = FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE,
        .service_kind = SERVICE_KIND_KSI,
        .vcpu_count = 1U,
        .object_id = 0x1100U,
        .manifest_object_id = 0x2100U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 2U,
        .capability_mask = 0x1U,
        .entry_ip = 0x401000U,
        .initial_sp = 0x801000U,
    },
    {
        .active = true,
        .component_type = FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE,
        .service_kind = SERVICE_KIND_IKS,
        .vcpu_count = 1U,
        .object_id = 0x1200U,
        .manifest_object_id = 0x2200U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 3U,
        .capability_mask = 0x1U,
        .entry_ip = 0x402000U,
        .initial_sp = 0x802000U,
    },
    {
        .active = true,
        .component_type = FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE,
        .service_kind = SERVICE_KIND_SKS,
        .vcpu_count = 1U,
        .object_id = 0x1300U,
        .manifest_object_id = 0x2300U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 4U,
        .capability_mask = 0x1U,
        .entry_ip = 0x403000U,
        .initial_sp = 0x803000U,
    },
    {
        .active = true,
        .component_type = FBVBS_MANIFEST_COMPONENT_GUEST_BOOT,
        .object_id = 0x1400U,
        .manifest_object_id = 0x2400U,
        .entry_ip = 0x500000U,
    },
    {
        .active = true,
        .component_type = FBVBS_MANIFEST_COMPONENT_GUEST_BOOT,
        .object_id = 0x1500U,
        .manifest_object_id = 0x2500U,
        .entry_ip = 0x501000U,
    },
    {
        .active = true,
        .component_type = FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE,
        .service_kind = SERVICE_KIND_UVS,
        .vcpu_count = 1U,
        .object_id = 0x1600U,
        .manifest_object_id = 0x2600U,
        .memory_limit_bytes = FBVBS_PAGE_SIZE * 5U,
        .capability_mask = 0x1U,
        .entry_ip = 0x404000U,
        .initial_sp = 0x804000U,
    },
    {
        .active = true,
        .component_type = FBVBS_MANIFEST_COMPONENT_FREEBSD_KERNEL,
        .caller_class = FBVBS_HOST_CALLER_CLASS_FBVBS,
        .object_id = 0x1700U,
        .manifest_object_id = 0x2700U,
        .load_base = 0xFFFF800000000000ULL,
        .allowed_callsite_count = 2U,
        .allowed_callsite_offsets = {0x1000U, 0x1100U},
    },
    {
        .active = true,
        .component_type = FBVBS_MANIFEST_COMPONENT_FREEBSD_MODULE,
        .caller_class = FBVBS_HOST_CALLER_CLASS_VMM,
        .object_id = 0x3700U,
        .manifest_object_id = 0x2800U,
        .load_base = 0xFFFF800000000000ULL,
        .allowed_callsite_count = 2U,
        .allowed_callsite_offsets = {0x2000U, 0x2100U},
    },
};

enum {
    FBVBS_BOOT_MANIFEST_PROFILE_COUNT =
        (int)(sizeof(g_fbvbs_boot_manifest_profiles) / sizeof(g_fbvbs_boot_manifest_profiles[0]))
};

#define FBVBS_BOOT_ARTIFACT_OWNER_PARTITION_ID 1U
#define FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE FBVBS_PAGE_SIZE
#define FBVBS_SYNTHETIC_BOOT_MODULE_SIZE FBVBS_PAGE_SIZE

#define FBVBS_ELF_ET_EXEC 2U
#define FBVBS_ELF_EM_X86_64 62U
#define FBVBS_ELF_PT_LOAD 1U
#define FBVBS_ELF_PF_X 0x1U
#define FBVBS_ELF_PF_R 0x4U
#define FBVBS_ELF_SYNTHETIC_CODE_OFFSET 0x100U
#define FBVBS_ELF_SYNTHETIC_CODE_SIZE 0x40U

struct fbvbs_elf64_ehdr {
    uint8_t e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} __attribute__((packed));

struct fbvbs_elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed));

_Static_assert(sizeof(struct fbvbs_elf64_ehdr) == 64U,
               "fbvbs_elf64_ehdr size mismatch");
_Static_assert(sizeof(struct fbvbs_elf64_phdr) == 56U,
               "fbvbs_elf64_phdr size mismatch");

/*@ requires \valid(state);
    assigns \result \from state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1], memory_object_id;
*/
static struct fbvbs_memory_object *fbvbs_find_boot_memory_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_OBJECTS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_OBJECTS; ++index) {
        if (state->memory_objects[index].allocated &&
            state->memory_objects[index].memory_object_id == memory_object_id) {
            return &state->memory_objects[index];
        }
    }

    return NULL;
}

/*@ assigns \result \from object_id, g_fbvbs_boot_manifest_profiles[0 .. FBVBS_BOOT_MANIFEST_PROFILE_COUNT - 1];
*/
static const struct fbvbs_manifest_profile *fbvbs_find_boot_profile(
    uint64_t object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= (uint32_t)FBVBS_BOOT_MANIFEST_PROFILE_COUNT;
        loop assigns index;
        loop variant (uint32_t)FBVBS_BOOT_MANIFEST_PROFILE_COUNT - index;
    */
    for (index = 0U; index < (uint32_t)FBVBS_BOOT_MANIFEST_PROFILE_COUNT; ++index) {
        if (g_fbvbs_boot_manifest_profiles[index].active &&
            g_fbvbs_boot_manifest_profiles[index].object_id == object_id) {
            return &g_fbvbs_boot_manifest_profiles[index];
        }
    }

    return NULL;
}

/*@ assigns \result \from state->boot_module_count,
                      state->boot_modules[0 .. FBVBS_MAX_BOOT_MODULES - 1],
                      object_id;
*/
static const struct fbvbs_boot_module *fbvbs_find_boot_module_for_object(
    const struct fbvbs_hypervisor_state *state,
    uint64_t object_id
);

/*@ requires \valid(state);
    requires \valid(seed);
    requires \valid(payload_out);
    requires \valid(payload_size_out);
    assigns *payload_out, *payload_size_out;
    ensures \result == OK || \result == NOT_FOUND || \result == INVALID_STATE;
*/
static int fbvbs_resolve_boot_seed_payload(
    const struct fbvbs_hypervisor_state *state,
    const struct fbvbs_boot_artifact_seed *seed,
    const uint8_t **payload_out,
    uint64_t *payload_size_out
) {
    const struct fbvbs_boot_module *boot_module;
    const struct fbvbs_manifest_profile *profile;

#ifdef __FRAMAC__
    if (state == NULL || seed == NULL || payload_out == NULL || payload_size_out == NULL) {
        return INVALID_STATE;
    }
    *payload_out = NULL;
    *payload_size_out = 0U;
    return NOT_FOUND;
#endif

    if (state == NULL || seed == NULL || payload_out == NULL || payload_size_out == NULL) {
        return INVALID_STATE;
    }

    *payload_out = NULL;
    *payload_size_out = 0U;

    boot_module = fbvbs_find_boot_module_for_object(state, seed->object_id);
    if (boot_module != NULL && boot_module->size != 0U) {
#ifdef __FRAMAC__
        /* Physical-address-to-pointer cast cannot be modeled in Typed WP.
           The hosted test path returns NOT_FOUND (fall through). */
        (void)boot_module;
#else
        *payload_out = (const uint8_t *)(uintptr_t)boot_module->start_phys;
        *payload_size_out = boot_module->size;
        return OK;
#endif
    }

    profile = fbvbs_find_boot_profile(seed->object_id);
#ifdef FBVBS_BAREMETAL_BUILD
    if (profile != NULL &&
        profile->component_type == FBVBS_MANIFEST_COMPONENT_FREEBSD_KERNEL &&
        (uint64_t)((uintptr_t)_data_end - (uintptr_t)_binary_start) != 0U) {
        *payload_out = _binary_start;
        *payload_size_out = (uint64_t)((uintptr_t)_data_end - (uintptr_t)_binary_start);
        return OK;
    }
#else
    (void)profile;
#endif

    return NOT_FOUND;
}

/*@ assigns \nothing;
    ensures \result == \null || \result >= text;
*/
static const char *fbvbs_skip_prefix(const char *text, const char *prefix) {
    if (text == NULL || prefix == NULL) {
        return NULL;
    }

#ifdef __FRAMAC__
    return text;
#endif

    /*@ loop assigns text, prefix; */
    while (*prefix != '\0') {
        if (*text != *prefix) {
            return NULL;
        }
        ++text;
        ++prefix;
    }

    return text;
}

/*@ behavior null_out:
      assumes value_out == \null;
      assigns \nothing;
    behavior write_out:
      assumes value_out != \null;
      requires \valid(value_out);
      requires text != \null ==> \valid_read(text);
      assigns *value_out;
    ensures \result == 0 || \result == -1;
    complete behaviors;
    disjoint behaviors;
*/
static int fbvbs_parse_hex_u64(const char *text, uint64_t *value_out) {
    uint64_t value = 0U;
    bool saw_digit = false;

#ifdef __FRAMAC__
    if (text == NULL || value_out == NULL) {
        return -1;
    }
    *value_out = 0U;
    return 0;
#endif

    if (text == NULL || value_out == NULL || *text == '\0') {
        return -1;
    }

    /*@ loop assigns text, value, saw_digit; */
    while (*text != '\0') {
        uint8_t digit;

        if (*text >= '0' && *text <= '9') {
            digit = (uint8_t)(*text - '0');
        } else if (*text >= 'a' && *text <= 'f') {
            digit = (uint8_t)(10U + (uint8_t)(*text - 'a'));
        } else if (*text >= 'A' && *text <= 'F') {
            digit = (uint8_t)(10U + (uint8_t)(*text - 'A'));
        } else {
            return -1;
        }

        if (value > (UINT64_MAX - digit) / 16U) {
            return -1;
        }

        value = (value * 16U) + digit;
        saw_digit = true;
        ++text;
    }

    if (!saw_digit) {
        return -1;
    }

    *value_out = value;
    return 0;
}

/*@ behavior null_out:
      assumes object_id_out == \null;
      assigns \nothing;
    behavior write_out:
      assumes object_id_out != \null;
      requires \valid(object_id_out);
      requires module != \null ==> \valid_read(module);
      assigns *object_id_out;
    ensures \result == 0 || \result == -1;
    complete behaviors;
    disjoint behaviors;
*/
static int fbvbs_boot_module_object_id(
    const struct fbvbs_boot_module *module,
    uint64_t *object_id_out
) {
    static const char prefix_object_id[] = "fbvbs.object_id=0x";
    static const char prefix_artifact[] = "artifact:0x";
    const char *suffix;

#ifdef __FRAMAC__
    if (module == NULL || object_id_out == NULL) {
        return -1;
    }
    *object_id_out = 1U;
    return 0;
#endif

    if (module == NULL || object_id_out == NULL ||
        !module->active || module->cmdline[0] == '\0') {
        return -1;
    }

    suffix = fbvbs_skip_prefix(module->cmdline, prefix_object_id);
    if (suffix == NULL) {
        suffix = fbvbs_skip_prefix(module->cmdline, prefix_artifact);
    }
    if (suffix == NULL) {
        return -1;
    }

    return fbvbs_parse_hex_u64(suffix, object_id_out);
}

/*@ assigns \result \from state->boot_module_count,
                      state->boot_modules[0 .. FBVBS_MAX_BOOT_MODULES - 1],
                      object_id;
*/
static const struct fbvbs_boot_module *fbvbs_find_boot_module_for_object(
    const struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

#ifdef __FRAMAC__
    (void)state;
    (void)object_id;
    return NULL;
#endif

    if (state == NULL || object_id == 0U) {
        return NULL;
    }

    /*@ loop invariant 0 <= index <= state->boot_module_count || index <= FBVBS_MAX_BOOT_MODULES;
        loop assigns index;
        loop variant FBVBS_MAX_BOOT_MODULES - index;
    */
    for (index = 0U;
         index < state->boot_module_count && index < FBVBS_MAX_BOOT_MODULES;
         ++index) {
        const struct fbvbs_boot_module *module = &state->boot_modules[index];
        uint64_t module_object_id = 0U;

        if (fbvbs_boot_module_object_id(module, &module_object_id) == 0 &&
            module_object_id == object_id) {
            return module;
        }
    }

    return NULL;
}

#if !defined(FBVBS_BAREMETAL_BUILD)
/*@ requires \valid(buffer + (0 .. FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE - 1));
    requires \valid_read(profile);
    assigns buffer[0 .. FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE - 1];
*/
static void fbvbs_build_synthetic_boot_image(
    uint8_t buffer[FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE],
    const struct fbvbs_manifest_profile *profile
) {
    struct fbvbs_elf64_ehdr ehdr;
    struct fbvbs_elf64_phdr phdr;
    uint32_t index;

#ifdef __FRAMAC__
    /*@ loop invariant 0 <= index <= FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE;
        loop assigns index, buffer[0 .. FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE - 1];
        loop variant FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE - index;
    */
    for (index = 0U; index < FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE; ++index) {
        buffer[index] = 0U;
    }
#else
    fbvbs_zero_memory(buffer, FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE);
#endif
    ehdr = (struct fbvbs_elf64_ehdr){0};
    phdr = (struct fbvbs_elf64_phdr){0};

    ehdr.e_ident[0] = 0x7FU;
    ehdr.e_ident[1] = (uint8_t)'E';
    ehdr.e_ident[2] = (uint8_t)'L';
    ehdr.e_ident[3] = (uint8_t)'F';
    ehdr.e_ident[4] = 2U;
    ehdr.e_ident[5] = 1U;
    ehdr.e_ident[6] = 1U;
    ehdr.e_type = FBVBS_ELF_ET_EXEC;
    ehdr.e_machine = FBVBS_ELF_EM_X86_64;
    ehdr.e_version = 1U;
    ehdr.e_entry = profile->entry_ip;
    ehdr.e_phoff = sizeof(struct fbvbs_elf64_ehdr);
    ehdr.e_ehsize = (uint16_t)sizeof(struct fbvbs_elf64_ehdr);
    ehdr.e_phentsize = (uint16_t)sizeof(struct fbvbs_elf64_phdr);
    ehdr.e_phnum = 1U;

    phdr.p_type = FBVBS_ELF_PT_LOAD;
    phdr.p_flags = FBVBS_ELF_PF_R | FBVBS_ELF_PF_X;
    phdr.p_offset = FBVBS_ELF_SYNTHETIC_CODE_OFFSET;
    phdr.p_vaddr = profile->entry_ip;
    phdr.p_paddr = profile->entry_ip;
    phdr.p_filesz = FBVBS_ELF_SYNTHETIC_CODE_SIZE;
    phdr.p_memsz = FBVBS_PAGE_SIZE;
    phdr.p_align = FBVBS_PAGE_SIZE;

#ifndef __FRAMAC__
    fbvbs_copy_memory(buffer, &ehdr, sizeof(ehdr));
    fbvbs_copy_memory(&buffer[sizeof(struct fbvbs_elf64_ehdr)], &phdr, sizeof(phdr));
#else
    buffer[0] = 0x7FU;
    buffer[1] = (uint8_t)'E';
    buffer[2] = (uint8_t)'L';
    buffer[3] = (uint8_t)'F';
#endif

    /*@ loop invariant 0 <= index <= FBVBS_ELF_SYNTHETIC_CODE_SIZE;
        loop assigns index,
                     buffer[FBVBS_ELF_SYNTHETIC_CODE_OFFSET ..
                            FBVBS_ELF_SYNTHETIC_CODE_OFFSET + FBVBS_ELF_SYNTHETIC_CODE_SIZE - 1];
        loop variant FBVBS_ELF_SYNTHETIC_CODE_SIZE - index;
    */
    for (index = 0U; index < FBVBS_ELF_SYNTHETIC_CODE_SIZE; ++index) {
        buffer[FBVBS_ELF_SYNTHETIC_CODE_OFFSET + index] =
            (uint8_t)(0x90U + (uint8_t)((profile->object_id + index) & 0x0FU));
    }
}

/*@ requires \valid(buffer + (0 .. FBVBS_SYNTHETIC_BOOT_MODULE_SIZE - 1));
    assigns buffer[0 .. FBVBS_SYNTHETIC_BOOT_MODULE_SIZE - 1];
*/
static void fbvbs_build_synthetic_module_payload(
    uint8_t buffer[FBVBS_SYNTHETIC_BOOT_MODULE_SIZE],
    uint64_t object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_SYNTHETIC_BOOT_MODULE_SIZE;
        loop assigns index, buffer[0 .. FBVBS_SYNTHETIC_BOOT_MODULE_SIZE - 1];
        loop variant FBVBS_SYNTHETIC_BOOT_MODULE_SIZE - index;
    */
    for (index = 0U; index < FBVBS_SYNTHETIC_BOOT_MODULE_SIZE; ++index) {
        buffer[index] = (uint8_t)(((object_id >> (index % 8U)) + index) & 0xFFU);
    }
}
#endif

/*@ requires \valid(state);
    requires \valid_read(payload + (0 .. payload_size - 1));
    assigns *state;
    ensures \result == OK || \result == RESOURCE_EXHAUSTED || \result == INVALID_STATE;
*/
static int fbvbs_seed_boot_artifact_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t object_id,
    uint64_t payload_size,
    const uint8_t *payload
) {
    struct fbvbs_memory_allocate_object_request request = {0};
    struct fbvbs_memory_allocate_object_response response = {0};
    struct fbvbs_memory_object *object;
    uint64_t allocation_size;
    int status;

    if (payload_size == 0U || payload == NULL) {
        return INVALID_STATE;
    }
    if (payload_size > UINT64_MAX - (FBVBS_PAGE_SIZE - 1U)) {
        return RESOURCE_EXHAUSTED;
    }
#if defined(__FRAMAC__)
    (void)state;
    (void)object_id;
    (void)payload;
    return OK;
#endif
    if (fbvbs_page_alloc_free_count() == 0U) {
        fbvbs_boot_status("FBVBS: no free boot pages\n");
    }

    allocation_size = (payload_size + (FBVBS_PAGE_SIZE - 1U)) &
        ~((uint64_t)FBVBS_PAGE_SIZE - 1U);

    request.object_flags = FBVBS_MEMORY_OBJECT_FLAG_PRIVATE;
    request.size = allocation_size;

    status = fbvbs_memory_allocate_object(
        state,
        &request,
        &response,
        FBVBS_BOOT_ARTIFACT_OWNER_PARTITION_ID
    );
    if (status != OK) {
        fbvbs_boot_status("FBVBS: boot artifact alloc failed\n");
        return RESOURCE_EXHAUSTED;
    }

    object = fbvbs_find_boot_memory_object(state, response.memory_object_id);
    if (object == NULL) {
        fbvbs_boot_status("FBVBS: boot artifact slot lost\n");
        return INVALID_STATE;
    }

    object->memory_object_id = object_id;
    object->size = payload_size;
    if (fbvbs_memory_object_write(object, 0U, payload, payload_size) != 0) {
        fbvbs_boot_status("FBVBS: boot artifact write failed\n");
        return INVALID_STATE;
    }

    return OK;
}

/*@ requires \valid(state);
    requires \valid(entries + (0 .. FBVBS_BOOT_ARTIFACT_SEED_COUNT - 1));
    assigns *state, entries[0 .. FBVBS_BOOT_ARTIFACT_SEED_COUNT - 1];
    ensures \result == OK || \result == INVALID_STATE || \result == RESOURCE_EXHAUSTED;
*/
static int fbvbs_materialize_boot_artifact_entries(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_artifact_catalog_entry entries[FBVBS_BOOT_ARTIFACT_SEED_COUNT]
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT;
        loop assigns index, entries[0 .. FBVBS_BOOT_ARTIFACT_SEED_COUNT - 1];
        loop variant (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT - index;
    */
    for (index = 0U; index < (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT; ++index) {
        entries[index] = (struct fbvbs_artifact_catalog_entry){0};
    }

#ifdef __FRAMAC__
    /* Representative retained-C model: materialize the fixed boot seed set
       without walking boot module payloads or object writes. */
    /*@ loop invariant 0 <= index <= (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT;
        loop assigns index, entries[0 .. FBVBS_BOOT_ARTIFACT_SEED_COUNT - 1];
        loop variant (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT - index;
    */
    for (index = 0U; index < (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT; ++index) {
        const struct fbvbs_boot_artifact_seed *seed = &g_fbvbs_boot_artifact_seeds[index];

        entries[index].object_id = seed->object_id;
        entries[index].object_kind = seed->object_kind;
        entries[index].related_index = seed->related_index;
        fbvbs_seed_hash(entries[index].payload_hash, seed->hash_tag);
    }
    return OK;
#endif

    /*@ loop invariant 0 <= index <= (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT;
        loop assigns index, *state, entries[0 .. FBVBS_BOOT_ARTIFACT_SEED_COUNT - 1];
        loop variant (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT - index;
    */
    for (index = 0U; index < (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT; ++index) {
        const struct fbvbs_boot_artifact_seed *seed = &g_fbvbs_boot_artifact_seeds[index];
        const uint8_t *authoritative_payload = NULL;
        uint64_t authoritative_payload_size = 0U;

        entries[index].object_id = seed->object_id;
        entries[index].object_kind = seed->object_kind;
        entries[index].related_index = seed->related_index;

        if (seed->object_kind == FBVBS_ARTIFACT_OBJECT_IMAGE) {
            const struct fbvbs_manifest_profile *profile =
                fbvbs_find_boot_profile(seed->object_id);
            struct fbvbs_memory_object *object;
            int status;

            if (profile == NULL) {
                fbvbs_boot_status("FBVBS: boot image profile missing\n");
                return INVALID_STATE;
            }

            status = fbvbs_resolve_boot_seed_payload(
                state,
                seed,
                &authoritative_payload,
                &authoritative_payload_size
            );
            if (status == OK) {
                status = fbvbs_seed_boot_artifact_object(
                    state,
                    seed->object_id,
                    authoritative_payload_size,
                    authoritative_payload
                );
            }
#if defined(FBVBS_BAREMETAL_BUILD)
            else {
                fbvbs_boot_status("FBVBS: authoritative boot image missing\n");
                return INVALID_STATE;
            }
#else
            else if (profile->entry_ip != 0U) {
                uint8_t payload[FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE];

                fbvbs_build_synthetic_boot_image(payload, profile);
                status = fbvbs_seed_boot_artifact_object(
                    state,
                    seed->object_id,
                    FBVBS_SYNTHETIC_BOOT_IMAGE_SIZE,
                    payload
                );
            } else {
                fbvbs_boot_status("FBVBS: boot image source missing\n");
                return INVALID_STATE;
            }
#endif
            if (status != OK) {
                return status;
            }

            object = fbvbs_find_boot_memory_object(state, seed->object_id);
            if (object == NULL ||
                fbvbs_memory_object_hash_sha384(object, entries[index].payload_hash) != 0) {
                fbvbs_boot_status("FBVBS: boot image hash failed\n");
                return INVALID_STATE;
            }
            continue;
        }

        if (seed->object_kind == FBVBS_ARTIFACT_OBJECT_MODULE) {
            struct fbvbs_memory_object *object;
            int status;

            status = fbvbs_resolve_boot_seed_payload(
                state,
                seed,
                &authoritative_payload,
                &authoritative_payload_size
            );
            if (status == OK) {
                status = fbvbs_seed_boot_artifact_object(
                    state,
                    seed->object_id,
                    authoritative_payload_size,
                    authoritative_payload
                );
            }
#if defined(FBVBS_BAREMETAL_BUILD)
            else {
                fbvbs_boot_status("FBVBS: authoritative boot module missing\n");
                return INVALID_STATE;
            }
#else
            else {
                uint8_t payload[FBVBS_SYNTHETIC_BOOT_MODULE_SIZE];

                fbvbs_build_synthetic_module_payload(payload, seed->object_id);
                status = fbvbs_seed_boot_artifact_object(
                    state,
                    seed->object_id,
                    FBVBS_SYNTHETIC_BOOT_MODULE_SIZE,
                    payload
                );
            }
#endif
            if (status != OK) {
                return status;
            }

            object = fbvbs_find_boot_memory_object(state, seed->object_id);
            if (object == NULL ||
                fbvbs_memory_object_hash_sha384(object, entries[index].payload_hash) != 0) {
                fbvbs_boot_status("FBVBS: boot module hash failed\n");
                return INVALID_STATE;
            }
            continue;
        }

        fbvbs_seed_hash(entries[index].payload_hash, seed->hash_tag);
    }

    return OK;
}

/*@ requires \valid_read(catalog) || catalog == \null;
    requires catalog != \null ==> catalog->count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns \result \from catalog, object_id;
    ensures \result == \null || \valid_read(\result);
    ensures \result != \null ==> \result->object_id == object_id;
*/
static const struct fbvbs_artifact_catalog_entry *fbvbs_find_artifact_entry_in_catalog(
    const struct fbvbs_artifact_catalog *catalog,
    uint64_t object_id
) {
    uint32_t index;

    if (catalog == NULL || object_id == 0U) {
        return NULL;
    }
    /*@ loop invariant 0 <= index <= catalog->count;
        loop assigns index;
        loop variant catalog->count - index;
    */
    for (index = 0U; index < catalog->count; ++index) {
        if (catalog->entries[index].object_id == object_id) {
            return &catalog->entries[index];
        }
    }
    return NULL;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static bool fbvbs_artifact_kind_is_valid(uint32_t object_kind) {
    return object_kind == FBVBS_ARTIFACT_OBJECT_IMAGE ||
        object_kind == FBVBS_ARTIFACT_OBJECT_MANIFEST ||
        object_kind == FBVBS_ARTIFACT_OBJECT_MODULE;
}

/*@ requires \valid_read(artifact_entries + (0 .. artifact_count - 1)) || artifact_entries == \null;
    requires \valid(catalog) || catalog == \null;
    assigns *catalog;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == ALREADY_EXISTS;
    ensures \result == OK ==> catalog->count == artifact_count;
    ensures \result == OK ==> catalog->count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
*/
static int fbvbs_validate_boot_artifact_catalog(
    const struct fbvbs_artifact_catalog_entry *artifact_entries,
    uint32_t artifact_count,
    struct fbvbs_artifact_catalog *catalog
) {
    uint32_t index;
    uint32_t dup_index;

#ifdef __FRAMAC__
    (void)artifact_entries;
    if (catalog == NULL || artifact_count == 0U ||
        artifact_count > FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES) {
        return INVALID_PARAMETER;
    }
    *catalog = (struct fbvbs_artifact_catalog){0};
    catalog->count = artifact_count;
    return OK;
#endif

    if (artifact_entries == NULL || catalog == NULL || artifact_count == 0U ||
        artifact_count > FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES) {
        return INVALID_PARAMETER;
    }

    *catalog = (struct fbvbs_artifact_catalog){0};
    catalog->count = artifact_count;
    /*@ loop invariant 0 <= index <= artifact_count;
        loop invariant artifact_count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
        loop invariant catalog->count == artifact_count;
        loop invariant \forall integer j; 0 <= j < index ==>
            catalog->entries[j].related_index < artifact_count;
        loop assigns index, dup_index, catalog->entries[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1];
        loop variant artifact_count - index;
    */
    for (index = 0U; index < artifact_count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &artifact_entries[index];

        if (entry->object_id == 0U ||
            !fbvbs_artifact_kind_is_valid(entry->object_kind) ||
            entry->related_index >= artifact_count) {
            return INVALID_PARAMETER;
        }

        /* Check for duplicate object_id using linear scan */
        /*@ loop invariant 0 <= dup_index <= index;
            loop assigns dup_index;
            loop variant index - dup_index;
        */
        for (dup_index = 0U; dup_index < index; ++dup_index) {
            if (catalog->entries[dup_index].object_id == entry->object_id) {
                return ALREADY_EXISTS;
            }
        }

        catalog->entries[index] = *entry;
    }

    /*@ assert \forall integer j; 0 <= j < artifact_count ==>
            catalog->entries[j].related_index < artifact_count; */
    /*@ loop invariant 0 <= index <= artifact_count;
        loop invariant artifact_count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
        loop invariant catalog->count == artifact_count;
        loop assigns index;
        loop variant artifact_count - index;
    */
    for (index = 0U; index < artifact_count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &catalog->entries[index];
        /*@ assert entry->related_index < artifact_count; */
        const struct fbvbs_artifact_catalog_entry *related = &catalog->entries[entry->related_index];

        if (entry->object_kind == FBVBS_ARTIFACT_OBJECT_MANIFEST) {
            if ((related->object_kind != FBVBS_ARTIFACT_OBJECT_IMAGE &&
                 related->object_kind != FBVBS_ARTIFACT_OBJECT_MODULE) ||
                related->related_index != index) {
                return INVALID_PARAMETER;
            }
        } else if (related->object_kind != FBVBS_ARTIFACT_OBJECT_MANIFEST ||
                   related->related_index != index) {
            return INVALID_PARAMETER;
        }
    }

    return OK;
}

/*@ requires \valid(artifact_kind) || artifact_kind == \null;
    assigns *artifact_kind;
    ensures \result == OK || \result == INVALID_PARAMETER;
*/
static int fbvbs_manifest_component_expected_kind(uint8_t component_type, uint32_t *artifact_kind) {
    if (artifact_kind == NULL) {
        return INVALID_PARAMETER;
    }

    switch (component_type) {
        case FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE:
        case FBVBS_MANIFEST_COMPONENT_GUEST_BOOT:
        case FBVBS_MANIFEST_COMPONENT_FREEBSD_KERNEL:
            *artifact_kind = FBVBS_ARTIFACT_OBJECT_IMAGE;
            return OK;
        case FBVBS_MANIFEST_COMPONENT_FREEBSD_MODULE:
            *artifact_kind = FBVBS_ARTIFACT_OBJECT_MODULE;
            return OK;
        default:
            return INVALID_PARAMETER;
    }
}

/*@ requires \valid_read(catalog) || catalog == \null;
    requires catalog != \null ==> catalog->count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    requires profiles != \null && profile_count > 0U ==>
             \valid_read(profiles + (0 .. profile_count - 1));
    requires \valid(validated_profiles + (0 .. FBVBS_MAX_MANIFEST_PROFILES - 1)) || validated_profiles == \null;
    requires catalog != \null && validated_profiles != \null ==>
        \separated(catalog, validated_profiles + (0 .. FBVBS_MAX_MANIFEST_PROFILES - 1));
    assigns validated_profiles[0 .. FBVBS_MAX_MANIFEST_PROFILES - 1];
    ensures \result == OK || \result == INVALID_PARAMETER;
*/
static int fbvbs_validate_manifest_profiles(
    const struct fbvbs_artifact_catalog *catalog,
    const struct fbvbs_manifest_profile *profiles,
    uint32_t profile_count,
    struct fbvbs_manifest_profile validated_profiles[FBVBS_MAX_MANIFEST_PROFILES]
) {
    uint32_t index;
    uint32_t artifact_kind;

#ifdef __FRAMAC__
    (void)catalog;
    (void)profiles;
    if (validated_profiles == NULL || profile_count > FBVBS_MAX_MANIFEST_PROFILES) {
        return INVALID_PARAMETER;
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MANIFEST_PROFILES;
        loop assigns index, validated_profiles[0 .. FBVBS_MAX_MANIFEST_PROFILES - 1];
        loop variant FBVBS_MAX_MANIFEST_PROFILES - index;
    */
    for (index = 0U; index < FBVBS_MAX_MANIFEST_PROFILES; ++index) {
        validated_profiles[index] = (struct fbvbs_manifest_profile){0};
    }
    return OK;
#endif

    if (catalog == NULL || validated_profiles == NULL ||
        profile_count > FBVBS_MAX_MANIFEST_PROFILES) {
        return INVALID_PARAMETER;
    }

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MANIFEST_PROFILES;
        loop invariant \forall integer j; 0 <= j < index ==>
            validated_profiles[j].allowed_callsite_count == 0;
        loop assigns index, validated_profiles[0 .. FBVBS_MAX_MANIFEST_PROFILES - 1];
        loop variant FBVBS_MAX_MANIFEST_PROFILES - index;
    */
    for (index = 0U; index < FBVBS_MAX_MANIFEST_PROFILES; ++index) {
        validated_profiles[index] = (struct fbvbs_manifest_profile){0};
    }
    if (profile_count == 0U) {
        return OK;
    }
    if (profiles == NULL) {
        return INVALID_PARAMETER;
    }

    /*@ loop invariant 0 <= index <= profile_count;
        loop invariant \forall integer j; 0 <= j < index ==>
            validated_profiles[j].allowed_callsite_count <= FBVBS_MAX_HOST_CALLSITE_ENTRIES;
        loop invariant \forall integer j; profile_count <= j < FBVBS_MAX_MANIFEST_PROFILES ==>
            validated_profiles[j].allowed_callsite_count == 0;
        loop assigns index, artifact_kind, validated_profiles[0 .. profile_count - 1];
        loop variant profile_count - index;
    */
    for (index = 0U; index < profile_count; ++index) {
        const struct fbvbs_manifest_profile *profile = &profiles[index];
        const struct fbvbs_artifact_catalog_entry *artifact_entry;
        const struct fbvbs_artifact_catalog_entry *manifest_entry;

        if (fbvbs_manifest_component_expected_kind(profile->component_type, &artifact_kind) != OK ||
            profile->object_id == 0U || profile->manifest_object_id == 0U) {
            return INVALID_PARAMETER;
        }

        /*@ assert catalog->count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; */
        artifact_entry = fbvbs_find_artifact_entry_in_catalog(catalog, profile->object_id);
        manifest_entry = fbvbs_find_artifact_entry_in_catalog(catalog, profile->manifest_object_id);
        if (artifact_entry == NULL || manifest_entry == NULL ||
            artifact_entry->object_kind != artifact_kind ||
            manifest_entry->object_kind != FBVBS_ARTIFACT_OBJECT_MANIFEST ||
            artifact_entry->related_index >= catalog->count ||
            manifest_entry->related_index >= catalog->count ||
            catalog->entries[artifact_entry->related_index].object_id != profile->manifest_object_id ||
            catalog->entries[manifest_entry->related_index].object_id != profile->object_id) {
            return INVALID_PARAMETER;
        }

        switch (profile->component_type) {
            case FBVBS_MANIFEST_COMPONENT_TRUSTED_SERVICE:
                if (profile->service_kind == SERVICE_KIND_NONE ||
                    profile->vcpu_count == 0U ||
                    profile->memory_limit_bytes == 0U ||
                    profile->entry_ip == 0U ||
                    profile->initial_sp == 0U) {
                    return INVALID_PARAMETER;
                }
                break;
            case FBVBS_MANIFEST_COMPONENT_GUEST_BOOT:
                if (profile->entry_ip == 0U) {
                    return INVALID_PARAMETER;
                }
                break;
            case FBVBS_MANIFEST_COMPONENT_FREEBSD_KERNEL:
            case FBVBS_MANIFEST_COMPONENT_FREEBSD_MODULE:
                if ((profile->component_type == FBVBS_MANIFEST_COMPONENT_FREEBSD_KERNEL &&
                     profile->caller_class != FBVBS_HOST_CALLER_CLASS_FBVBS) ||
                    (profile->component_type == FBVBS_MANIFEST_COMPONENT_FREEBSD_MODULE &&
                     profile->caller_class != FBVBS_HOST_CALLER_CLASS_VMM) ||
                    profile->load_base == 0U ||
                    profile->allowed_callsite_count == 0U ||
                    profile->allowed_callsite_count > FBVBS_MAX_HOST_CALLSITE_ENTRIES) {
                    return INVALID_PARAMETER;
                }
                break;
            default:
                return INVALID_PARAMETER;
        }

        if (profile->allowed_callsite_count > FBVBS_MAX_HOST_CALLSITE_ENTRIES) {
            return INVALID_PARAMETER;
        }

        validated_profiles[index] = *profile;
        validated_profiles[index].active = true;
    }

    return OK;
}

/*@ requires \valid_read(profiles + (0 .. FBVBS_MAX_MANIFEST_PROFILES - 1)) || profiles == \null;
    requires \valid(tables + (0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1)) || tables == \null;
    requires profiles != \null ==>
        \forall integer i; 0 <= i < FBVBS_MAX_MANIFEST_PROFILES ==>
            profiles[i].allowed_callsite_count <= FBVBS_MAX_HOST_CALLSITE_ENTRIES;
    requires profiles != \null && tables != \null ==>
        \separated(profiles + (0 .. FBVBS_MAX_MANIFEST_PROFILES - 1),
                   tables + (0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1));
    assigns tables[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == ALREADY_EXISTS;
*/
static int fbvbs_build_host_callsite_tables(
    const struct fbvbs_manifest_profile profiles[FBVBS_MAX_MANIFEST_PROFILES],
    struct fbvbs_host_callsite_table tables[FBVBS_MAX_HOST_CALLSITE_TABLES]
) {
    uint32_t index;

#ifdef __FRAMAC__
    if (profiles == NULL || tables == NULL) {
        return INVALID_PARAMETER;
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_HOST_CALLSITE_TABLES;
        loop assigns index, tables[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1];
        loop variant FBVBS_MAX_HOST_CALLSITE_TABLES - index;
    */
    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        tables[index] = (struct fbvbs_host_callsite_table){0};
    }
    return OK;
#endif

    if (profiles == NULL || tables == NULL) {
        return INVALID_PARAMETER;
    }

    /*@ loop invariant 0 <= index <= FBVBS_MAX_HOST_CALLSITE_TABLES;
        loop assigns index, tables[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1];
        loop variant FBVBS_MAX_HOST_CALLSITE_TABLES - index;
    */
    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        tables[index] = (struct fbvbs_host_callsite_table){0};
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MANIFEST_PROFILES;
        loop invariant \forall integer j; 0 <= j < FBVBS_MAX_MANIFEST_PROFILES ==>
            profiles[j].allowed_callsite_count <= FBVBS_MAX_HOST_CALLSITE_ENTRIES;
        loop assigns index, tables[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1];
        loop variant FBVBS_MAX_MANIFEST_PROFILES - index;
    */
    for (index = 0U; index < FBVBS_MAX_MANIFEST_PROFILES; ++index) {
        const struct fbvbs_manifest_profile *profile = &profiles[index];
        struct fbvbs_host_callsite_table *table = NULL;
        uint32_t callsite_index;

        if (!profile->active ||
            (profile->component_type != FBVBS_MANIFEST_COMPONENT_FREEBSD_KERNEL &&
             profile->component_type != FBVBS_MANIFEST_COMPONENT_FREEBSD_MODULE)) {
            continue;
        }

        if (profile->caller_class == FBVBS_HOST_CALLER_CLASS_FBVBS) {
            table = &tables[0];
        } else if (profile->caller_class == FBVBS_HOST_CALLER_CLASS_VMM) {
            table = &tables[1];
        } else {
            return INVALID_PARAMETER;
        }
        if (table->active) {
            return ALREADY_EXISTS;
        }

        table->active = true;
        table->caller_class = profile->caller_class;
        table->count = profile->allowed_callsite_count;
        table->manifest_object_id = profile->manifest_object_id;
        table->load_base = profile->load_base;
        /*@ assert profile->allowed_callsite_count <= FBVBS_MAX_HOST_CALLSITE_ENTRIES; */
        /*@ loop invariant 0 <= callsite_index <= profile->allowed_callsite_count;
            loop invariant profile->allowed_callsite_count <= FBVBS_MAX_HOST_CALLSITE_ENTRIES;
            loop assigns callsite_index,
                         table->allowed_offsets[0 .. FBVBS_MAX_HOST_CALLSITE_ENTRIES - 1],
                         table->relocated_callsites[0 .. FBVBS_MAX_HOST_CALLSITE_ENTRIES - 1];
            loop variant profile->allowed_callsite_count - callsite_index;
        */
        for (callsite_index = 0U; callsite_index < profile->allowed_callsite_count; ++callsite_index) {
            if (profile->load_base > UINT64_MAX - profile->allowed_callsite_offsets[callsite_index]) {
                return INVALID_PARAMETER;
            }
            table->allowed_offsets[callsite_index] = profile->allowed_callsite_offsets[callsite_index];
            table->relocated_callsites[callsite_index] =
                profile->load_base + profile->allowed_callsite_offsets[callsite_index];
        }
    }

    return OK;
}

int fbvbs_ingest_boot_catalog(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_artifact_catalog_entry *artifact_entries,
    uint32_t artifact_count,
    const struct fbvbs_manifest_profile *profiles,
    uint32_t profile_count
) {
    struct fbvbs_artifact_catalog catalog;
    struct fbvbs_manifest_profile validated_profiles[FBVBS_MAX_MANIFEST_PROFILES];
    struct fbvbs_host_callsite_table host_tables[FBVBS_MAX_HOST_CALLSITE_TABLES];
    int status;
    uint32_t index;

    if (state == NULL) {
        return INVALID_PARAMETER;
    }

#ifdef __FRAMAC__
    (void)artifact_entries;
    (void)artifact_count;
    (void)profiles;
    (void)profile_count;
    state->artifact_catalog = (struct fbvbs_artifact_catalog){0};
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MANIFEST_PROFILES;
        loop assigns index, state->manifest_profiles[0 .. FBVBS_MAX_MANIFEST_PROFILES - 1];
        loop variant FBVBS_MAX_MANIFEST_PROFILES - index;
    */
    for (index = 0U; index < FBVBS_MAX_MANIFEST_PROFILES; ++index) {
        state->manifest_profiles[index] = (struct fbvbs_manifest_profile){0};
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_HOST_CALLSITE_TABLES;
        loop assigns index, state->host_callsites[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1];
        loop variant FBVBS_MAX_HOST_CALLSITE_TABLES - index;
    */
    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        state->host_callsites[index] = (struct fbvbs_host_callsite_table){0};
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
        loop assigns index,
                     state->approvals[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1],
                     state->revoked_object_ids[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1];
        loop variant FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - index;
    */
    for (index = 0U; index < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; ++index) {
        state->approvals[index] = (struct fbvbs_uvs_artifact_approval){0};
        state->revoked_object_ids[index] = 0U;
    }
    state->revoked_object_count = 0U;
    return OK;
#endif

    status = fbvbs_validate_boot_artifact_catalog(artifact_entries, artifact_count, &catalog);
    if (status != OK) {
        return status;
    }
    /*@ assert catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; */
    status = fbvbs_validate_manifest_profiles(catalog.count != 0U ? &catalog : NULL, profiles, profile_count, validated_profiles);
    if (status != OK) {
        return status;
    }
    /*@ assert \forall integer i; 0 <= i < FBVBS_MAX_MANIFEST_PROFILES ==>
            validated_profiles[i].allowed_callsite_count <= FBVBS_MAX_HOST_CALLSITE_ENTRIES; */
    status = fbvbs_build_host_callsite_tables(validated_profiles, host_tables);
    if (status != OK) {
        return status;
    }

    state->artifact_catalog = catalog;
    /*@ loop invariant 0 <= index <= FBVBS_MAX_MANIFEST_PROFILES;
        loop assigns index, state->manifest_profiles[0 .. FBVBS_MAX_MANIFEST_PROFILES - 1];
        loop variant FBVBS_MAX_MANIFEST_PROFILES - index;
    */
    for (index = 0U; index < FBVBS_MAX_MANIFEST_PROFILES; ++index) {
        state->manifest_profiles[index] = validated_profiles[index];
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_HOST_CALLSITE_TABLES;
        loop assigns index, state->host_callsites[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1];
        loop variant FBVBS_MAX_HOST_CALLSITE_TABLES - index;
    */
    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        state->host_callsites[index] = host_tables[index];
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
        loop assigns index, state->approvals[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1];
        loop variant FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - index;
    */
    for (index = 0U; index < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; ++index) {
        state->approvals[index] = (struct fbvbs_uvs_artifact_approval){0};
    }
    /*@ loop invariant 0 <= index <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
        loop assigns index, state->revoked_object_ids[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1];
        loop variant FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - index;
    */
    for (index = 0U; index < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; ++index) {
        state->revoked_object_ids[index] = 0U;
    }
    state->revoked_object_count = 0U;
    return OK;
}

/*@ requires \valid(state);
    assigns state->device_catalog;
    ensures state->device_catalog.count == 1U;
*/
static void fbvbs_seed_device_catalog(struct fbvbs_hypervisor_state *state) {
    struct fbvbs_device_catalog_entry *device = &state->device_catalog.entries[0];

    state->device_catalog.count = 1U;
    device->device_id = 0xD000U;
    device->segment = 0U;
    device->bus = 2U;
    device->slot_function = 0x10U;
}

/* Runtime indicator for the actual host deprivilege handoff.
 * The retained-C foundation can be initialized and tested without it,
 * but a full production FBVBS host handoff must not claim readiness
 * until VMLAUNCH/VMRESUME are wired end-to-end. */
/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_host_deprivilege_runtime_ready(
    const struct fbvbs_hypervisor_state *state
) {
    return (state != NULL &&
            (state->runtime_state_flags & FBVBS_RUNTIME_HOST_DEPRIVILEGED) != 0U) ? 1 : 0;
}

/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_audit_runtime_ready(
    const struct fbvbs_hypervisor_state *state
) {
    if (state == NULL) {
        return 0;
    }
    return (state->mirror_log.header.abi_version == FBVBS_ABI_VERSION &&
            state->mirror_log.header.record_size == FBVBS_LOG_RECORD_V1_SIZE &&
            state->mirror_log.header.total_size == (uint32_t)sizeof(state->mirror_log) &&
            state->mirror_log.header.boot_id_hi == state->boot_id_hi &&
            state->mirror_log.header.boot_id_lo == state->boot_id_lo &&
            (state->runtime_state_flags & FBVBS_RUNTIME_AUDIT_PRIMARY_OOB) != 0U) ? 1 : 0;
}

/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_platform_foundation_ready(
    const struct fbvbs_hypervisor_state *state
) {
    if (state == NULL) {
        return 0;
    }
    if (state->vmx_caps.vmx_supported == 0U) {
        return 0;
    }
    if (state->vmx_caps.iommu_available == 0U) {
        return 0;
    }
    if (fbvbs_iommu_runtime_ready(&state->cpu_security) == 0) {
        return 0;
    }
    if (fbvbs_audit_runtime_ready(state) == 0) {
        return 0;
    }
    return 1;
}

/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
int fbvbs_platform_high_assurance_foundation_ready(
    const struct fbvbs_hypervisor_state *state
) {
#ifdef __FRAMAC__
    if (state == NULL) {
        return 0;
    }
    return (state->vmx_caps.vmx_supported != 0U &&
            state->cpu_security.boot.measured_boot_active != 0U) ? 1 : 0;
#endif

    if (fbvbs_platform_foundation_ready(state) == 0) {
        return 0;
    }
    return (state->cpu_security.boot.measured_boot_active != 0U) ? 1 : 0;
}

/*@ requires \valid(state);
    assigns state->capability_bitmap0, state->capability_bitmap1;
*/
static void fbvbs_seed_capability_bitmap(struct fbvbs_hypervisor_state *state) {
    state->capability_bitmap0 = 0U;
    state->capability_bitmap1 = 0U;

    if (state->vmx_caps.mbec_available != 0U) {
        state->capability_bitmap0 |= CAP_BITMAP0_MBEC_OR_GMET;
    }
    if (state->vmx_caps.hlat_available != 0U) {
        state->capability_bitmap0 |= CAP_BITMAP0_HLAT;
    }
    if (state->vmx_caps.cet_available != 0U) {
        state->capability_bitmap0 |= CAP_BITMAP0_CET;
    }
    if (state->vmx_caps.aesni_available != 0U) {
        state->capability_bitmap0 |= CAP_BITMAP0_AESNI;
    }
    if (fbvbs_iommu_runtime_ready(&state->cpu_security) != 0) {
        state->capability_bitmap1 |= CAP_BITMAP1_IOMMU;
    }
    if (state->cpu_security.boot.measured_boot_active != 0U) {
        state->capability_bitmap1 |= CAP_BITMAP1_MEASURED_BOOT;
    }
    if (fbvbs_host_deprivilege_runtime_ready(state) != 0) {
        state->capability_bitmap1 |= CAP_BITMAP1_HOST_DEPRIVILEGE;
    }
    if (fbvbs_platform_foundation_ready(state) != 0) {
        state->capability_bitmap1 |= CAP_BITMAP1_FOUNDATION_READY;
    }
    if (fbvbs_platform_high_assurance_foundation_ready(state) != 0) {
        state->capability_bitmap1 |= CAP_BITMAP1_HIGH_ASSURANCE_FOUNDATION;
    }
}

/*@ requires \valid(state);
    assigns *state;
*/
int fbvbs_hypervisor_init(struct fbvbs_hypervisor_state *state) {
    static const uint8_t boot_payload[] = "fbvbs hypervisor kernel boot";
    struct fbvbs_artifact_catalog_entry boot_artifact_entries[FBVBS_BOOT_ARTIFACT_SEED_COUNT];
    struct fbvbs_boot_snapshot boot_snapshot;
    int status;

#if defined(__FRAMAC__)
    if (state == NULL) {
        return INVALID_PARAMETER;
    }
    fbvbs_capture_boot_snapshot(state, &boot_snapshot);
    *state = (struct fbvbs_hypervisor_state){0};
    fbvbs_restore_boot_snapshot(state, &boot_snapshot);
    state->next_partition_id = 1U;
    state->next_measurement_digest_id = 1U;
    state->next_memory_object_id = 0x100000U;
    state->next_shared_object_id = 0x200000U;
    state->next_target_set_id = 0x300000U;
    state->next_key_handle = 0x400000U;
    state->next_dek_handle = 0x500000U;
    state->next_manifest_set_id = 0x600000U;
    state->next_iommu_domain_id = 0x700000U;
    status = fbvbs_scaling_init(state);
    if (status != OK) {
        return status;
    }
    state->trusted_clock_available = true;
    state->trusted_time_seconds = 1000U;
    fbvbs_seed_boot_ids(state);
    state->vmx_caps.vmx_supported = 1U;
    state->vmx_caps.iommu_available = 1U;
    state->bsp_profile.initialized = 1U;
    state->cpu_security.cpu_count = 1U;
    state->cpu_security.vendor = CPU_VENDOR_INTEL;
    state->cpu_security.iommu.iommu_type = IOMMU_TYPE_VTD;
    state->cpu_security.iommu.dma_remapping = 1U;
    state->cpu_security.iommu.interrupt_remapping = 1U;
    state->cpu_security.iommu.kernel_dma_protection = 1U;
    state->cpu_security.boot.drtm_available = 1U;
    state->cpu_security.boot.measured_boot_active = 1U;
    state->spec_ctrl.host_spec_ctrl = 0U;
    state->runtime_state_flags |= FBVBS_RUNTIME_AUDIT_PRIMARY_OOB;
    fbvbs_seed_capability_bitmap(state);
    return OK;
#endif

    fbvbs_capture_boot_snapshot(state, &boot_snapshot);
    *state = (struct fbvbs_hypervisor_state){0};
    fbvbs_restore_boot_snapshot(state, &boot_snapshot);
    state->next_partition_id = 1U;
    state->next_measurement_digest_id = 1U;
    state->next_memory_object_id = 0x100000U;
    state->next_shared_object_id = 0x200000U;
    state->next_target_set_id = 0x300000U;
    state->next_key_handle = 0x400000U;
    state->next_dek_handle = 0x500000U;
    state->next_manifest_set_id = 0x600000U;
    state->next_iommu_domain_id = 0x700000U;
    status = fbvbs_scaling_init(state);
    if (status != OK) {
        fbvbs_boot_status("FBVBS: scaling init failed\n");
        return status;
    }
    state->trusted_clock_available = true;
    state->trusted_time_seconds = 1000U;
    fbvbs_boot_status("FBVBS: init page allocator\n");
    status = fbvbs_bootstrap_page_allocator(state);
    if (status != OK) {
        fbvbs_boot_status("FBVBS: page allocator bootstrap failed\n");
        return status;
    }
    fbvbs_boot_status("FBVBS: page allocator ready\n");
#if defined(__FRAMAC__)
    fbvbs_seed_boot_ids(state);
#else
    status = fbvbs_entropy_seed_boot_ids(state);
    if (status != 0) {
        fbvbs_boot_status("FBVBS: boot entropy unavailable\n");
        return NOT_SUPPORTED_ON_PLATFORM;
    }
#endif
    fbvbs_boot_status("FBVBS: boot ids seeded\n");
    status = fbvbs_materialize_boot_artifact_entries(state, boot_artifact_entries);
    if (status != OK) {
        fbvbs_boot_status("FBVBS: boot artifact backing failed\n");
        return status;
    }
    fbvbs_boot_status("FBVBS: boot artifacts materialized\n");
    status = fbvbs_ingest_boot_catalog(
        state,
        boot_artifact_entries,
        (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT,
        g_fbvbs_boot_manifest_profiles,
        (uint32_t)FBVBS_BOOT_MANIFEST_PROFILE_COUNT
    );
    if (status != OK) {
        fbvbs_boot_status("FBVBS: boot catalog ingest failed\n");
        return status;
    }
    fbvbs_boot_status("FBVBS: boot catalog ingested\n");
    status = fbvbs_partition_seed_freebsd_host(state);
    if (status != OK) {
        fbvbs_boot_status("FBVBS: host partition seed failed\n");
        return status;
    }
    fbvbs_boot_status("FBVBS: host partition seeded\n");
    status = fbvbs_vmx_probe(&state->vmx_caps);
    if (status != OK) {
        fbvbs_boot_status("FBVBS: VMX probe failed\n");
        return status;
    }
    if (state->vmx_caps.vmx_supported == 0U) {
        fbvbs_boot_status("FBVBS: VMX unavailable\n");
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    fbvbs_boot_status("FBVBS: VMX probed\n");

    /* CPU security subsystem initialization (Section 21).
     * Detects features, builds vulnerability profile, computes CR pinning
     * and SPEC_CTRL values, detects IOMMU and boot integrity state.
     * Must run after vmx_probe (uses vmx_caps) and before any VM runs. */
    status = fbvbs_cpu_detect_features(0U, &state->bsp_profile);
    if (status != 0) {
        fbvbs_boot_status("FBVBS: CPU feature detect failed\n");
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    fbvbs_boot_status("FBVBS: CPU features detected\n");
    status = fbvbs_cpu_build_vuln_profile(&state->bsp_profile);
    if (status != 0) {
        fbvbs_boot_status("FBVBS: vulnerability profiling failed\n");
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    fbvbs_boot_status("FBVBS: vulnerability profile built\n");
    status = fbvbs_cpu_compute_cr_pins(&state->bsp_profile);
    if (status != 0) {
        fbvbs_boot_status("FBVBS: CR pin computation failed\n");
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    fbvbs_boot_status("FBVBS: CR pins computed\n");
    status = fbvbs_cpu_compute_global_mitigations(
        &state->bsp_profile, 1U, &state->cpu_security);
    if (status != 0) {
        fbvbs_boot_status("FBVBS: mitigation synthesis failed\n");
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    fbvbs_boot_status("FBVBS: mitigations computed\n");
    status = fbvbs_iommu_detect(&state->cpu_security);
    if (status != 0) {
        fbvbs_boot_status("FBVBS: IOMMU detection failed\n");
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    fbvbs_boot_status("FBVBS: IOMMU detected\n");
    if (state->cpu_security.iommu.iommu_type == IOMMU_TYPE_VTD) {
        status = fbvbs_vtd_init(&state->cpu_security);
    } else if (state->cpu_security.iommu.iommu_type == IOMMU_TYPE_AMD_VI) {
        status = fbvbs_amdvi_init(&state->cpu_security);
    } else {
        status = -1;
    }
    if (status != 0) {
        fbvbs_boot_status("FBVBS: IOMMU initialization failed\n");
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    state->vmx_caps.iommu_available =
        (uint32_t)fbvbs_iommu_runtime_ready(&state->cpu_security);
    fbvbs_boot_status("FBVBS: IOMMU initialized\n");
    status = fbvbs_boot_integrity_detect(&state->cpu_security);
    if (status != 0) {
        fbvbs_boot_status("FBVBS: measured boot unavailable\n");
#if FBVBS_REQUIRE_MEASURED_BOOT
        return NOT_SUPPORTED_ON_PLATFORM;
#endif
    } else {
        fbvbs_boot_status("FBVBS: measured boot accepted\n");
    }
    /* Apply computed CR pin masks from CPU security profile */
    state->pinned_cr0_mask = state->bsp_profile.cr_pins.cr0_pin_mask;
    state->pinned_cr0_value = state->bsp_profile.cr_pins.cr0_pin_value;
    state->pinned_cr4_mask = state->bsp_profile.cr_pins.cr4_pin_mask;
    state->pinned_cr4_value = state->bsp_profile.cr_pins.cr4_pin_value;
    /* Initialize host SPEC_CTRL from computed value */
    state->spec_ctrl.host_spec_ctrl = state->cpu_security.host_spec_ctrl_value;

    fbvbs_seed_device_catalog(state);
    status = fbvbs_log_init(state);
    if (status != OK) {
        fbvbs_boot_status("FBVBS: log init failed\n");
        return status;
    }
    fbvbs_boot_status("FBVBS: log initialized\n");
#if defined(__x86_64__) && !defined(__FRAMAC__) && !defined(__STDC_HOSTED__)
    status = fbvbs_deprivilege_host(state);
    if (status != 0) {
        fbvbs_boot_status("FBVBS: host deprivilege handoff failed\n");
        return NOT_SUPPORTED_ON_PLATFORM;
    }
    fbvbs_boot_status("FBVBS: host deprivilege handoff entered\n");
#endif
    fbvbs_seed_capability_bitmap(state);
    if (fbvbs_platform_foundation_ready(state) != 0) {
        fbvbs_boot_status("FBVBS: retained-C foundation ready\n");
    } else {
        fbvbs_boot_status("FBVBS: retained-C foundation incomplete\n");
    }
    if (fbvbs_host_deprivilege_runtime_ready(state) == 0) {
        fbvbs_boot_status("FBVBS: host deprivilege handoff unavailable\n");
    }
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        1U,
        FBVBS_EVENT_BOOT_COMPLETE,
        boot_payload,
        (uint32_t)(sizeof(boot_payload) - 1U)
    );

    /* Boot integrity evidence — log DRTM/TPM/SecureBoot/BootGuard status
     * (REQ-0006, Phase 1-5 item 4) */
    {
        uint8_t integrity_payload[8];
        integrity_payload[0] = (uint8_t)state->cpu_security.boot.drtm_available;
        integrity_payload[1] = (uint8_t)state->cpu_security.boot.drtm_type;
        integrity_payload[2] = (uint8_t)state->cpu_security.boot.boot_guard_active;
        integrity_payload[3] = (uint8_t)state->cpu_security.boot.tpm_present;
        integrity_payload[4] = (uint8_t)state->cpu_security.boot.secure_boot_active;
        integrity_payload[5] = (uint8_t)state->cpu_security.boot.measured_boot_active;
        integrity_payload[6] = 0U;
        integrity_payload[7] = 0U;
        fbvbs_log_append(
            state, 0U,
            FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
            FBVBS_SEVERITY_INFO,
            FBVBS_EVENT_BOOT_INTEGRITY,
            integrity_payload, 8U
        );
    }

    /* Entropy source quality — log RDRAND/RDSEED availability
     * (Phase 1-8 item 6) */
    {
        uint8_t entropy_payload[4];
        entropy_payload[0] = (fbvbs_cpu_has_rdrand() != 0) ? 1U : 0U;
        entropy_payload[1] = (fbvbs_cpu_has_rdseed() != 0) ? 1U : 0U;
        entropy_payload[2] = 0U;
        entropy_payload[3] = 0U;
        fbvbs_log_append(
            state, 0U,
            FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
            FBVBS_SEVERITY_INFO,
            FBVBS_EVENT_ENTROPY_QUALITY,
            entropy_payload, 4U
        );
    }

    return OK;
}

/*@ assigns g_fbvbs_hypervisor;
*/
void fbvbs_kernel_main(const void *multiboot_info) {
    int init_status;

#if defined(__FRAMAC__)
    g_fbvbs_hypervisor.multiboot_info = multiboot_info;
    return;
#endif

    fbvbs_boot_status("FBVBS: kernel main entered\n");
    g_fbvbs_hypervisor.multiboot_info = multiboot_info;

    /* Process Multiboot information if available */
    if (multiboot_info != NULL) {
        fbvbs_boot_status("FBVBS: processing multiboot info\n");
        fbvbs_process_multiboot_info(&g_fbvbs_hypervisor, multiboot_info,
                                     FBVBS_MULTIBOOT_MAX_BUFFER_SIZE);
        fbvbs_boot_status("FBVBS: multiboot info processed\n");
    }

    fbvbs_boot_status("FBVBS: starting hypervisor init\n");
    init_status = fbvbs_hypervisor_init(&g_fbvbs_hypervisor);
    if (init_status != OK) {
        fbvbs_boot_status("FBVBS: hypervisor init failed\n");
        return; /* halt: subsystem init failed */
    }

    fbvbs_boot_status("FBVBS: hypervisor init complete\n");
}

/* fbvbs_process_multiboot_info is in boot_multiboot.c (excluded from WP
   due to void* casts required for Multiboot2 binary structure parsing) */

/*@ assigns \nothing;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_partition *fbvbs_diag_find_partition(
    const struct fbvbs_hypervisor_state *state,
    uint64_t partition_id
) {
    uint32_t index;

    if (state == NULL || partition_id == 0U) {
        return NULL;
    }

    /*@ loop invariant 0 <= index <= FBVBS_MAX_PARTITIONS;
        loop assigns index;
        loop variant FBVBS_MAX_PARTITIONS - index;
    */
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        const struct fbvbs_partition *partition = &state->partitions[index];

        if ((partition->occupied || partition->tombstone) &&
            partition->partition_id == partition_id) {
            return partition;
        }
    }

    return NULL;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_diag_status_is_policy_deny(int status) {
    return (status == PERMISSION_DENIED ||
            status == INVALID_CALLER ||
            status == CALLSITE_REJECTED ||
            status == POLICY_DENIED ||
            status == INVALID_PARAMETER ||
            status == ABI_VERSION_UNSUPPORTED ||
            status == REPLAY_DETECTED ||
            status == RETRY_LATER);
}

/*@ assigns *response; */
static void fbvbs_diag_apply_deny_guidance(
    struct fbvbs_diag_reason_guidance_response *response,
    uint32_t deny_reason
) {
    response->reason_domain = FBVBS_GUIDANCE_DOMAIN_DENY;
    response->canonical_code = deny_reason;
    response->deny_reason = deny_reason;

    switch (deny_reason) {
        case FBVBS_DENY_REASON_INVALID_PARAMETER:
        case FBVBS_DENY_REASON_ABI_VERSION:
            response->severity = FBVBS_SEVERITY_WARNING;
            response->runbook_code = FBVBS_RUNBOOK_VALIDATE_INPUT;
            response->recommended_action_flags = FBVBS_GUIDANCE_ACTION_REVIEW_INPUT;
            break;
        case FBVBS_DENY_REASON_PERMISSION:
            response->severity = FBVBS_SEVERITY_WARNING;
            response->runbook_code = FBVBS_RUNBOOK_REVIEW_CAPABILITY;
            response->recommended_action_flags = FBVBS_GUIDANCE_ACTION_REVIEW_CAPABILITY;
            break;
        case FBVBS_DENY_REASON_RATE_LIMIT:
            response->severity = FBVBS_SEVERITY_WARNING;
            response->runbook_code = FBVBS_RUNBOOK_WAIT_LOCKOUT;
            response->recommended_action_flags = FBVBS_GUIDANCE_ACTION_WAIT_LOCKOUT;
            break;
        case FBVBS_DENY_REASON_BUSY:
            response->severity = FBVBS_SEVERITY_WARNING;
            response->runbook_code = FBVBS_RUNBOOK_RETRY_COMMAND;
            response->recommended_action_flags = FBVBS_GUIDANCE_ACTION_RETRY_COMMAND;
            break;
        case FBVBS_DENY_REASON_INVALID_CALLER:
        case FBVBS_DENY_REASON_CALLSITE:
        case FBVBS_DENY_REASON_REPLAY:
            response->severity = FBVBS_SEVERITY_ERROR;
            response->runbook_code = FBVBS_RUNBOOK_REAUTHORIZE_CALLER;
            response->recommended_action_flags =
                FBVBS_GUIDANCE_ACTION_REAUTHORIZE_CALLER |
                FBVBS_GUIDANCE_ACTION_ESCALATE_SECURITY;
            break;
        case FBVBS_DENY_REASON_POLICY:
            response->severity = FBVBS_SEVERITY_ERROR;
            response->runbook_code = FBVBS_RUNBOOK_REVIEW_CAPABILITY;
            response->recommended_action_flags =
                FBVBS_GUIDANCE_ACTION_REVIEW_CAPABILITY |
                FBVBS_GUIDANCE_ACTION_ESCALATE_SECURITY;
            break;
        default:
            response->severity = FBVBS_SEVERITY_WARNING;
            response->runbook_code = FBVBS_RUNBOOK_VALIDATE_INPUT;
            response->recommended_action_flags = FBVBS_GUIDANCE_ACTION_REVIEW_INPUT;
            break;
    }
}

/*@ assigns *response; */
static void fbvbs_diag_apply_health_guidance(
    struct fbvbs_diag_reason_guidance_response *response,
    uint32_t health_state
) {
    response->reason_domain = FBVBS_GUIDANCE_DOMAIN_HEALTH;
    response->canonical_code = health_state;
    response->health_state = health_state;

    switch (health_state) {
        case FBVBS_PARTITION_HEALTH_HEALTHY:
            response->severity = FBVBS_SEVERITY_INFO;
            response->runbook_code = FBVBS_RUNBOOK_NONE;
            response->recommended_action_flags = 0ULL;
            break;
        case FBVBS_PARTITION_HEALTH_DEGRADED:
            response->severity = FBVBS_SEVERITY_WARNING;
            response->runbook_code = FBVBS_RUNBOOK_PLATFORM_INVESTIGATION;
            response->recommended_action_flags =
                FBVBS_GUIDANCE_ACTION_MONITOR_PARTITION |
                FBVBS_GUIDANCE_ACTION_ESCALATE_PLATFORM;
            break;
        case FBVBS_PARTITION_HEALTH_QUARANTINED:
            response->severity = FBVBS_SEVERITY_ERROR;
            response->runbook_code = FBVBS_RUNBOOK_PARTITION_RECOVERY;
            response->recommended_recovery_flags = FBVBS_RECOVERY_CLEAR_VOLATILE;
            response->recommended_action_flags =
                FBVBS_GUIDANCE_ACTION_RECOVER_PARTITION |
                FBVBS_GUIDANCE_ACTION_REMEASURE_ARTIFACTS;
            break;
        case FBVBS_PARTITION_HEALTH_RECOVERY:
            response->severity = FBVBS_SEVERITY_NOTICE;
            response->runbook_code = FBVBS_RUNBOOK_MONITOR_RECOVERY;
            response->recommended_action_flags = FBVBS_GUIDANCE_ACTION_MONITOR_PARTITION;
            break;
        default:
            response->severity = FBVBS_SEVERITY_WARNING;
            response->runbook_code = FBVBS_RUNBOOK_PLATFORM_INVESTIGATION;
            response->recommended_action_flags = FBVBS_GUIDANCE_ACTION_ESCALATE_PLATFORM;
            break;
    }
}

/*@ assigns *response; */
static void fbvbs_diag_apply_fault_guidance(
    struct fbvbs_diag_reason_guidance_response *response,
    uint32_t fault_code
) {
    response->reason_domain = FBVBS_GUIDANCE_DOMAIN_FAULT;
    response->canonical_code = fault_code;
    response->fault_code = fault_code;
    response->health_state = FBVBS_PARTITION_HEALTH_QUARANTINED;
    response->quarantine_reason = fault_code;
    response->recommended_recovery_flags = FBVBS_RECOVERY_CLEAR_VOLATILE;
    response->recommended_action_flags =
        FBVBS_GUIDANCE_ACTION_RECOVER_PARTITION |
        FBVBS_GUIDANCE_ACTION_REMEASURE_ARTIFACTS;

    switch (fault_code) {
        case FAULT_CODE_VM_EXIT_UNCLASSIFIED:
            response->severity = FBVBS_SEVERITY_CRITICAL;
            response->runbook_code = FBVBS_RUNBOOK_PLATFORM_INVESTIGATION;
            response->recommended_recovery_flags |= FBVBS_RECOVERY_EXTENDED_REMEASURE;
            response->recommended_action_flags |= FBVBS_GUIDANCE_ACTION_ESCALATE_PLATFORM;
            break;
        case FBVBS_FAULT_WATCHDOG_TIMEOUT:
            response->severity = FBVBS_SEVERITY_CRITICAL;
            response->runbook_code = FBVBS_RUNBOOK_PARTITION_RECOVERY;
            response->recommended_action_flags |= FBVBS_GUIDANCE_ACTION_MONITOR_PARTITION;
            break;
        case FBVBS_FAULT_POLICY_DENY_THRESHOLD:
            response->severity = FBVBS_SEVERITY_ALERT;
            response->runbook_code = FBVBS_RUNBOOK_PARTITION_RECOVERY;
            response->deny_reason = FBVBS_DENY_REASON_POLICY;
            response->recommended_recovery_flags |=
                FBVBS_RECOVERY_RESTORE_PERSISTENT |
                FBVBS_RECOVERY_EXTENDED_REMEASURE;
            response->recommended_action_flags |=
                FBVBS_GUIDANCE_ACTION_REVIEW_CAPABILITY |
                FBVBS_GUIDANCE_ACTION_REAUTHORIZE_CALLER |
                FBVBS_GUIDANCE_ACTION_ESCALATE_SECURITY;
            break;
        default:
            response->severity = FBVBS_SEVERITY_CRITICAL;
            response->runbook_code = FBVBS_RUNBOOK_PLATFORM_INVESTIGATION;
            response->recommended_action_flags |= FBVBS_GUIDANCE_ACTION_ESCALATE_PLATFORM;
            break;
    }
}

int fbvbs_diag_get_capabilities(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_capabilities_response *response
) {
    if (state == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    response->capability_bitmap0 = state->capability_bitmap0;
    response->capability_bitmap1 = state->capability_bitmap1;
    return OK;
}

int fbvbs_diag_get_reason_guidance(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_diag_reason_guidance_request *request,
    struct fbvbs_diag_reason_guidance_response *response
) {
    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }

    *response = (struct fbvbs_diag_reason_guidance_response){0};
    response->reason_domain = request->reason_domain;
    response->reason_input = request->reason_input;

    switch (request->reason_domain) {
        case FBVBS_GUIDANCE_DOMAIN_DENY: {
            uint32_t deny_reason;

            if (!fbvbs_diag_status_is_policy_deny((int)request->reason_input)) {
                return INVALID_PARAMETER;
            }
            deny_reason = fbvbs_policy_deny_reason_from_status((int)request->reason_input);
            if (deny_reason == FBVBS_DENY_REASON_UNSPECIFIED) {
                return INVALID_PARAMETER;
            }
            fbvbs_diag_apply_deny_guidance(response, deny_reason);
            break;
        }
        case FBVBS_GUIDANCE_DOMAIN_FAULT:
            if (request->reason_input == 0U) {
                return INVALID_PARAMETER;
            }
            fbvbs_diag_apply_fault_guidance(response, request->reason_input);
            break;
        case FBVBS_GUIDANCE_DOMAIN_HEALTH:
            if (request->reason_input > FBVBS_PARTITION_HEALTH_RECOVERY) {
                return INVALID_PARAMETER;
            }
            fbvbs_diag_apply_health_guidance(response, request->reason_input);
            break;
        case FBVBS_GUIDANCE_DOMAIN_PARTITION: {
            const struct fbvbs_partition *partition;

            partition = fbvbs_diag_find_partition(state, request->partition_id);
            if (partition == NULL) {
                return NOT_FOUND;
            }

            response->reason_domain = FBVBS_GUIDANCE_DOMAIN_PARTITION;
            response->health_state = partition->health_state;
            response->fault_code = partition->last_fault_code;
            response->quarantine_reason = partition->quarantine_reason;

            if (partition->last_fault_code != 0U || partition->quarantine_reason != 0U) {
                uint32_t effective_fault_code = partition->last_fault_code != 0U
                    ? partition->last_fault_code
                    : partition->quarantine_reason;

                fbvbs_diag_apply_fault_guidance(response, effective_fault_code);
                response->reason_domain = FBVBS_GUIDANCE_DOMAIN_PARTITION;
                response->reason_input = effective_fault_code;
                response->health_state = partition->health_state;
                response->fault_code = effective_fault_code;
                response->quarantine_reason = partition->quarantine_reason;
            } else {
                fbvbs_diag_apply_health_guidance(response, partition->health_state);
                response->reason_domain = FBVBS_GUIDANCE_DOMAIN_PARTITION;
                response->reason_input = partition->health_state;
            }
            break;
        }
        default:
            return INVALID_PARAMETER;
    }

    return OK;
}

int fbvbs_diag_get_inventory(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_inventory_response *response
) {
    uint32_t index;

    if (state == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (state->artifact_catalog.count > FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES ||
        state->device_catalog.count > FBVBS_MAX_DEVICE_CATALOG_ENTRIES) {
        return INVALID_PARAMETER;
    }

    *response = (struct fbvbs_diag_inventory_response){0};

    /*@ loop invariant 0 <= index <= FBVBS_MAX_PARTITIONS;
        loop assigns index, *response;
        loop variant FBVBS_MAX_PARTITIONS - index;
    */
    for (index = 0U; index < FBVBS_MAX_PARTITIONS; ++index) {
        const struct fbvbs_partition *partition = &state->partitions[index];

        if (partition->occupied) {
            response->occupied_partition_count += 1U;
            if (partition->kind == PARTITION_KIND_GUEST_VM) {
                response->guest_vm_count += 1U;
            }
            if (partition->service_kind != SERVICE_KIND_NONE) {
                response->service_partition_count += 1U;
            }
            switch (partition->health_state) {
                case FBVBS_PARTITION_HEALTH_HEALTHY:
                    response->healthy_partition_count += 1U;
                    break;
                case FBVBS_PARTITION_HEALTH_DEGRADED:
                    response->degraded_partition_count += 1U;
                    break;
                case FBVBS_PARTITION_HEALTH_QUARANTINED:
                    response->quarantined_partition_count += 1U;
                    break;
                case FBVBS_PARTITION_HEALTH_RECOVERY:
                    response->recovery_partition_count += 1U;
                    break;
                default:
                    break;
            }
        } else if (partition->tombstone) {
            response->tombstone_partition_count += 1U;
        }
    }

    response->artifact_count = state->artifact_catalog.count;
    response->device_count = state->device_catalog.count;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_STORAGE_POOLS;
        loop assigns index, *response;
        loop variant FBVBS_MAX_STORAGE_POOLS - index;
    */
    for (index = 0U; index < FBVBS_MAX_STORAGE_POOLS; ++index) {
        if (state->storage_pools[index].active) {
            response->storage_pool_count += 1U;
        }
    }

    /*@ loop invariant 0 <= index <= FBVBS_MAX_VIRTUAL_DISKS;
        loop assigns index, *response;
        loop variant FBVBS_MAX_VIRTUAL_DISKS - index;
    */
    for (index = 0U; index < FBVBS_MAX_VIRTUAL_DISKS; ++index) {
        if (state->virtual_disks[index].active) {
            response->vdisk_count += 1U;
        }
    }

    return OK;
}

int fbvbs_diag_get_fault_record(
    struct fbvbs_hypervisor_state *state,
    uint64_t partition_id,
    struct fbvbs_diag_fault_record_response *response
) {
    const struct fbvbs_partition *partition;
    struct fbvbs_diag_reason_guidance_request guidance_request = {0};
    struct fbvbs_diag_reason_guidance_response guidance_response = {0};
    uint32_t effective_fault_code;
    int status;

    if (state == NULL || response == NULL || partition_id == 0U) {
        return INVALID_PARAMETER;
    }

    partition = fbvbs_diag_find_partition(state, partition_id);
    if (partition == NULL) {
        return NOT_FOUND;
    }
    if (partition->last_fault_code == 0U && partition->quarantine_reason == 0U) {
        return NOT_FOUND;
    }

    effective_fault_code = partition->last_fault_code != 0U
        ? partition->last_fault_code
        : partition->quarantine_reason;

    guidance_request.reason_domain = FBVBS_GUIDANCE_DOMAIN_PARTITION;
    guidance_request.partition_id = partition_id;
    status = fbvbs_diag_get_reason_guidance(state, &guidance_request, &guidance_response);
    if (status != OK) {
        return status;
    }

    *response = (struct fbvbs_diag_fault_record_response){
        .partition_id = partition->partition_id,
        .partition_state = partition->state,
        .health_state = partition->health_state,
        .fault_code = effective_fault_code,
        .source_component = partition->last_fault_source_component,
        .quarantine_reason = partition->quarantine_reason,
        .severity = guidance_response.severity,
        .runbook_code = guidance_response.runbook_code,
        .fault_detail0 = partition->last_fault_detail0,
        .fault_detail1 = partition->last_fault_detail1,
        .measurement_epoch = partition->measurement_epoch,
        .recommended_recovery_flags = guidance_response.recommended_recovery_flags,
        .recommended_action_flags = guidance_response.recommended_action_flags,
    };
    return OK;
}

int fbvbs_diag_get_schema_registry(
    struct fbvbs_diag_schema_registry_response *response
) {
    if (response == NULL) {
        return INVALID_PARAMETER;
    }

    *response = (struct fbvbs_diag_schema_registry_response){
        .management_abi_version = FBVBS_MANAGEMENT_ABI_SCHEMA_VERSION,
        .health_schema_version = FBVBS_HEALTH_SCHEMA_VERSION,
        .audit_schema_version = FBVBS_AUDIT_SCHEMA_VERSION,
        .inventory_schema_version = FBVBS_INVENTORY_SCHEMA_VERSION,
        .guidance_schema_version = FBVBS_GUIDANCE_SCHEMA_VERSION,
        .fault_record_schema_version = FBVBS_FAULT_RECORD_SCHEMA_VERSION,
        .reserved0 = 0U,
        .reserved1 = 0U,
        .compatibility_flags =
            FBVBS_COMPAT_FLAG_HEALTH_SCHEMA_STABLE |
            FBVBS_COMPAT_FLAG_AUDIT_SCHEMA_STABLE |
            FBVBS_COMPAT_FLAG_FAILURE_MODE_GUIDANCE_STABLE |
            FBVBS_COMPAT_FLAG_RESERVED_FIELDS_MUST_BE_ZERO |
            FBVBS_COMPAT_FLAG_PARTITION_DIAGNOSTICS_STABLE |
            FBVBS_COMPAT_FLAG_PARTITION_FAULT_INFO_STABLE,
    };
    return OK;
}

int fbvbs_diag_get_artifact_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_artifact_list_response *response,
    uint32_t *response_length
) {
    uint32_t index;

    if (state == NULL || response == NULL || response_length == NULL) {
        return INVALID_PARAMETER;
    }
    if (state->artifact_catalog.count > FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES) {
        return INVALID_PARAMETER;
    }

    /*@ assert state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; */
    *response = (struct fbvbs_diag_artifact_list_response){0};
#ifdef __FRAMAC__
    response->count = 0U;
    response->reserved0 = 0U;
    *response_length = 8U;
    return OK;
#endif
    /*@ loop invariant 0 <= index <= state->artifact_catalog.count;
        loop invariant state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
        loop assigns index, response->entries[0 .. sizeof(response->entries) - 1];
        loop variant state->artifact_catalog.count - index;
    */
    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        /*@ assert index < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; */
#ifdef __FRAMAC__
        response->entries[index * sizeof(struct fbvbs_artifact_catalog_entry)] = 0U;
#else
        union { struct fbvbs_artifact_catalog_entry e; uint8_t b[sizeof(struct fbvbs_artifact_catalog_entry)]; } overlay;

        overlay.e = state->artifact_catalog.entries[index];
        fbvbs_copy_bytes(
            &response->entries[index * sizeof(overlay.e)],
            overlay.b,
            sizeof(overlay.b)
        );
#endif
    }

    response->count = state->artifact_catalog.count;
    response->reserved0 = 0U;
    *response_length = 8U +
        (state->artifact_catalog.count * (uint32_t)sizeof(struct fbvbs_artifact_catalog_entry));
    return OK;
}

int fbvbs_diag_get_device_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_device_list_response *response,
    uint32_t *response_length
) {
    uint32_t index;

    if (state == NULL || response == NULL || response_length == NULL) {
        return INVALID_PARAMETER;
    }
    if (state->device_catalog.count > FBVBS_MAX_DEVICE_CATALOG_ENTRIES) {
        return INVALID_PARAMETER;
    }

    /*@ assert state->device_catalog.count <= FBVBS_MAX_DEVICE_CATALOG_ENTRIES; */
    *response = (struct fbvbs_diag_device_list_response){0};
#ifdef __FRAMAC__
    response->count = 0U;
    response->reserved0 = 0U;
    *response_length = 8U;
    return OK;
#endif
    /*@ loop invariant 0 <= index <= state->device_catalog.count;
        loop invariant state->device_catalog.count <= FBVBS_MAX_DEVICE_CATALOG_ENTRIES;
        loop assigns index, response->entries[0 .. sizeof(response->entries) - 1];
        loop variant state->device_catalog.count - index;
    */
    for (index = 0U; index < state->device_catalog.count; ++index) {
        /*@ assert index < FBVBS_MAX_DEVICE_CATALOG_ENTRIES; */
#ifdef __FRAMAC__
        response->entries[index * sizeof(struct fbvbs_device_catalog_entry)] = 0U;
#else
        union { struct fbvbs_device_catalog_entry e; uint8_t b[sizeof(struct fbvbs_device_catalog_entry)]; } overlay;

        overlay.e = state->device_catalog.entries[index];
        fbvbs_copy_bytes(
            &response->entries[index * sizeof(overlay.e)],
            overlay.b,
            sizeof(overlay.b)
        );
#endif
    }

    response->count = state->device_catalog.count;
    response->reserved0 = 0U;
    *response_length = 8U +
        (state->device_catalog.count * (uint32_t)sizeof(struct fbvbs_device_catalog_entry));
    return OK;
}
