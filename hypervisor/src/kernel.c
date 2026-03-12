#include "fbvbs_hypervisor.h"

struct fbvbs_hypervisor_state g_fbvbs_hypervisor;

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

/*@ requires \valid(state) || state == \null;
    requires count == 0U ||
             (allowed_offsets != \null &&
              \valid_read(allowed_offsets + (0 .. count - 1)));
    assigns state->host_callsites[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == RESOURCE_EXHAUSTED;
    behavior invalid_args:
      assumes state == \null || allowed_offsets == \null ||
              manifest_object_id == 0U || load_base == 0U || count == 0U ||
              count > FBVBS_MAX_HOST_CALLSITE_ENTRIES ||
              (caller_class != FBVBS_HOST_CALLER_CLASS_FBVBS &&
               caller_class != FBVBS_HOST_CALLER_CLASS_VMM);
      ensures \result == INVALID_PARAMETER;
*/
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

/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    behavior null_state:
      assumes state == \null;
      ensures \result == 0U;
    behavior valid_state:
      assumes state != \null;
      ensures \result == 0U || \result >= 1U;
    complete behaviors;
    disjoint behaviors;
*/
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

/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    ensures \result == \null || \valid_read(\result);
    ensures \result != \null ==>
            \result->active &&
            \result->component_type == component_type &&
            \result->object_id == object_id;
*/
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

/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    ensures \result == \null || \valid_read(\result);
    ensures \result != \null ==>
            \result->active &&
            (\result->component_type == FBVBS_MANIFEST_COMPONENT_FREEBSD_KERNEL ||
             \result->component_type == FBVBS_MANIFEST_COMPONENT_FREEBSD_MODULE) &&
            \result->caller_class == caller_class;
*/
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
static void fbvbs_seed_boot_ids(struct fbvbs_hypervisor_state *state) {
    state->boot_id_hi = 0x4642564253560000ULL;
    state->boot_id_lo = 0x0000000000000001ULL;
}

/*@ requires \valid(hash + (0 .. 47));
    assigns hash[0 .. 47];
    ensures hash[0] == tag;
    ensures hash[47] == (uint8_t)(tag ^ 0xFFU);
*/
static void fbvbs_seed_hash(uint8_t hash[48], uint8_t tag) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 48;
        loop invariant \forall integer j; 0 <= j < index ==> hash[j] == 0;
        loop assigns index, hash[0 .. 47];
        loop variant 48 - index;
    */
    for (index = 0U; index < 48U; ++index) {
        hash[index] = 0U;
    }
    hash[0] = tag;
    hash[47] = (uint8_t)(tag ^ 0xFFU);
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

/*@ requires \valid(entries + (0 .. FBVBS_BOOT_ARTIFACT_SEED_COUNT - 1));
    assigns entries[0 .. FBVBS_BOOT_ARTIFACT_SEED_COUNT - 1];
*/
static void fbvbs_materialize_boot_artifact_entries(
    struct fbvbs_artifact_catalog_entry entries[FBVBS_BOOT_ARTIFACT_SEED_COUNT]
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_BOOT_ARTIFACT_SEED_COUNT;
        loop assigns index, entries[0 .. FBVBS_BOOT_ARTIFACT_SEED_COUNT - 1];
        loop variant FBVBS_BOOT_ARTIFACT_SEED_COUNT - index;
    */
    for (index = 0U; index < (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT; ++index) {
        entries[index] = (struct fbvbs_artifact_catalog_entry){0};
    }
    /*@ loop invariant 0 <= index <= FBVBS_BOOT_ARTIFACT_SEED_COUNT;
        loop assigns index, entries[0 .. FBVBS_BOOT_ARTIFACT_SEED_COUNT - 1];
        loop variant FBVBS_BOOT_ARTIFACT_SEED_COUNT - index;
    */
    for (index = 0U; index < (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT; ++index) {
        entries[index].object_id = g_fbvbs_boot_artifact_seeds[index].object_id;
        entries[index].object_kind = g_fbvbs_boot_artifact_seeds[index].object_kind;
        entries[index].related_index = g_fbvbs_boot_artifact_seeds[index].related_index;
        fbvbs_seed_hash(entries[index].payload_hash, g_fbvbs_boot_artifact_seeds[index].hash_tag);
    }
}

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

/*@ requires \valid_read(catalog) || catalog == \null;
    requires catalog != \null ==> catalog->count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns \nothing;
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
    uint32_t other;

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
        loop assigns index, other, *catalog;
        loop variant artifact_count - index;
    */
    for (index = 0U; index < artifact_count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &artifact_entries[index];

        if (entry->object_id == 0U ||
            !fbvbs_artifact_kind_is_valid(entry->object_kind) ||
            entry->related_index >= artifact_count) {
            return INVALID_PARAMETER;
        }
        /*@ loop invariant 0 <= other <= index;
            loop assigns other;
            loop variant index - other;
        */
        for (other = 0U; other < index; ++other) {
            if (artifact_entries[other].object_id == entry->object_id) {
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
    requires profile_count == 0U ||
             (profiles != \null && \valid_read(profiles + (0 .. profile_count - 1)));
    requires \valid(validated_profiles + (0 .. FBVBS_MAX_MANIFEST_PROFILES - 1)) || validated_profiles == \null;
    requires catalog != \null && validated_profiles != \null ==>
        \separated(catalog, validated_profiles + (0 .. FBVBS_MAX_MANIFEST_PROFILES - 1));
    assigns validated_profiles[0 .. FBVBS_MAX_MANIFEST_PROFILES - 1];
    ensures \result == OK || \result == INVALID_PARAMETER;
    ensures \result == OK ==>
        \forall integer i; 0 <= i < FBVBS_MAX_MANIFEST_PROFILES ==>
            validated_profiles[i].allowed_callsite_count <= FBVBS_MAX_HOST_CALLSITE_ENTRIES;
*/
static int fbvbs_validate_manifest_profiles(
    const struct fbvbs_artifact_catalog *catalog,
    const struct fbvbs_manifest_profile *profiles,
    uint32_t profile_count,
    struct fbvbs_manifest_profile validated_profiles[FBVBS_MAX_MANIFEST_PROFILES]
) {
    uint32_t index;
    uint32_t artifact_kind;

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
            table->allowed_offsets[callsite_index] = profile->allowed_callsite_offsets[callsite_index];
            table->relocated_callsites[callsite_index] =
                profile->load_base + profile->allowed_callsite_offsets[callsite_index];
        }
    }

    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires artifact_count == 0U ||
             (artifact_entries != \null && \valid_read(artifact_entries + (0 .. artifact_count - 1)));
    requires profile_count == 0U ||
             (profiles != \null && \valid_read(profiles + (0 .. profile_count - 1)));
    assigns state->artifact_catalog,
            state->manifest_profiles[0 .. FBVBS_MAX_MANIFEST_PROFILES - 1],
            state->host_callsites[0 .. FBVBS_MAX_HOST_CALLSITE_TABLES - 1],
            state->approvals[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1],
            state->revoked_object_ids[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1],
            state->revoked_object_count;
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == ALREADY_EXISTS;
    behavior null_state:
      assumes state == \null;
      ensures \result == INVALID_PARAMETER;
*/
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
    if (state->vmx_caps.iommu_available != 0U) {
        state->capability_bitmap1 |= CAP_BITMAP1_IOMMU;
    }
}

/*@ requires \valid(state);
    assigns *state;
*/
void fbvbs_hypervisor_init(struct fbvbs_hypervisor_state *state) {
    static const uint8_t boot_payload[] = "fbvbs hypervisor kernel boot";
    struct fbvbs_artifact_catalog_entry boot_artifact_entries[FBVBS_BOOT_ARTIFACT_SEED_COUNT];

    *state = (struct fbvbs_hypervisor_state){0};
    state->next_partition_id = 1U;
    state->next_measurement_digest_id = 1U;
    state->next_memory_object_id = 0x100000U;
    state->next_shared_object_id = 0x200000U;
    state->next_target_set_id = 0x300000U;
    state->next_key_handle = 0x400000U;
    state->next_dek_handle = 0x500000U;
    state->next_manifest_set_id = 0x600000U;
    state->next_iommu_domain_id = 0x700000U;
    state->trusted_clock_available = true;
    state->trusted_time_seconds = 1000U;
    fbvbs_seed_boot_ids(state);
    fbvbs_materialize_boot_artifact_entries(boot_artifact_entries);
    status = fbvbs_ingest_boot_catalog(
        state,
        boot_artifact_entries,
        (uint32_t)FBVBS_BOOT_ARTIFACT_SEED_COUNT,
        g_fbvbs_boot_manifest_profiles,
        (uint32_t)FBVBS_BOOT_MANIFEST_PROFILE_COUNT
    );
    if (status != OK) {
        return status;
    }
    fbvbs_partition_seed_freebsd_host(state);
    fbvbs_vmx_probe(&state->vmx_caps);
    fbvbs_seed_capability_bitmap(state);
    fbvbs_seed_device_catalog(state);
    fbvbs_log_init(state);
    fbvbs_log_append(
        state,
        0U,
        FBVBS_SOURCE_COMPONENT_MICROHYPERVISOR,
        1U,
        FBVBS_EVENT_BOOT_COMPLETE,
        boot_payload,
        (uint32_t)(sizeof(boot_payload) - 1U)
    );
}

/*@ assigns g_fbvbs_hypervisor;
*/
void fbvbs_kernel_main(void) {
    fbvbs_hypervisor_init(&g_fbvbs_hypervisor);
}

/*@ requires \valid(state) || state == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER;
    behavior null_args:
      assumes state == \null || response == \null;
      ensures \result == INVALID_PARAMETER;
    behavior valid_args:
      assumes state != \null && response != \null;
      ensures \result == OK;
    complete behaviors;
    disjoint behaviors;
*/
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

/*@ requires \valid(state) || state == \null;
    requires \valid(response) || response == \null;
    requires \valid(response_length) || response_length == \null;
    requires state != \null ==> state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    requires \separated(state, response, response_length);
    assigns *response, *response_length;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == BUFFER_TOO_SMALL;
    behavior null_args:
      assumes state == \null || response == \null || response_length == \null;
      ensures \result == INVALID_PARAMETER;
    behavior ok:
      assumes state != \null && response != \null && response_length != \null;
      assumes state->artifact_catalog.count * (uint32_t)sizeof(struct fbvbs_artifact_catalog_entry) <= sizeof(response->entries);
      ensures \result == OK;
      ensures response->count == state->artifact_catalog.count;
      ensures *response_length == 8U + state->artifact_catalog.count * (uint32_t)sizeof(struct fbvbs_artifact_catalog_entry);
    disjoint behaviors;
*/
int fbvbs_diag_get_artifact_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_artifact_list_response *response,
    uint32_t *response_length
) {
    uint32_t index;

    if (state == NULL || response == NULL || response_length == NULL) {
        return INVALID_PARAMETER;
    }

    /*@ assert state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; */
    *response = (struct fbvbs_diag_artifact_list_response){0};
    /*@ loop invariant 0 <= index <= state->artifact_catalog.count;
        loop invariant state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
        loop assigns index, response->entries[0 .. sizeof(response->entries) - 1];
        loop variant state->artifact_catalog.count - index;
    */
    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        union {
            struct fbvbs_artifact_catalog_entry s;
            uint8_t bytes[sizeof(struct fbvbs_artifact_catalog_entry)];
        } entry_copy;

        if (((index + 1U) * (uint32_t)sizeof(struct fbvbs_artifact_catalog_entry)) > sizeof(response->entries)) {
            return BUFFER_TOO_SMALL;
        }
        /*@ assert index < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; */
        entry_copy.s = state->artifact_catalog.entries[index];
        fbvbs_copy_bytes(
            &response->entries[index * sizeof(entry_copy.s)],
            entry_copy.bytes,
            sizeof(entry_copy.s)
        );
    }

    response->count = state->artifact_catalog.count;
    response->reserved0 = 0U;
    *response_length = 8U +
        (state->artifact_catalog.count * (uint32_t)sizeof(struct fbvbs_artifact_catalog_entry));
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid(response) || response == \null;
    requires \valid(response_length) || response_length == \null;
    requires state != \null ==> state->device_catalog.count <= FBVBS_MAX_DEVICE_CATALOG_ENTRIES;
    requires \separated(state, response, response_length);
    assigns *response, *response_length;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == BUFFER_TOO_SMALL;
    behavior null_args:
      assumes state == \null || response == \null || response_length == \null;
      ensures \result == INVALID_PARAMETER;
    behavior ok:
      assumes state != \null && response != \null && response_length != \null;
      assumes state->device_catalog.count * (uint32_t)sizeof(struct fbvbs_device_catalog_entry) <= sizeof(response->entries);
      ensures \result == OK;
      ensures response->count == state->device_catalog.count;
      ensures *response_length == 8U + state->device_catalog.count * (uint32_t)sizeof(struct fbvbs_device_catalog_entry);
    disjoint behaviors;
*/
int fbvbs_diag_get_device_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_device_list_response *response,
    uint32_t *response_length
) {
    uint32_t index;

    if (state == NULL || response == NULL || response_length == NULL) {
        return INVALID_PARAMETER;
    }

    /*@ assert state->device_catalog.count <= FBVBS_MAX_DEVICE_CATALOG_ENTRIES; */
    *response = (struct fbvbs_diag_device_list_response){0};
    /*@ loop invariant 0 <= index <= state->device_catalog.count;
        loop invariant state->device_catalog.count <= FBVBS_MAX_DEVICE_CATALOG_ENTRIES;
        loop assigns index, response->entries[0 .. sizeof(response->entries) - 1];
        loop variant state->device_catalog.count - index;
    */
    for (index = 0U; index < state->device_catalog.count; ++index) {
        union {
            struct fbvbs_device_catalog_entry s;
            uint8_t bytes[sizeof(struct fbvbs_device_catalog_entry)];
        } entry_copy;

        if (((index + 1U) * (uint32_t)sizeof(struct fbvbs_device_catalog_entry)) > sizeof(response->entries)) {
            return BUFFER_TOO_SMALL;
        }
        /*@ assert index < FBVBS_MAX_DEVICE_CATALOG_ENTRIES; */
        entry_copy.s = state->device_catalog.entries[index];
        fbvbs_copy_bytes(
            &response->entries[index * sizeof(entry_copy.s)],
            entry_copy.bytes,
            sizeof(entry_copy.s)
        );
    }

    response->count = state->device_catalog.count;
    response->reserved0 = 0U;
    *response_length = 8U +
        (state->device_catalog.count * (uint32_t)sizeof(struct fbvbs_device_catalog_entry));
    return OK;
}