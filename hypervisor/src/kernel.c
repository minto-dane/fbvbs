#include "fbvbs_hypervisor.h"

struct fbvbs_hypervisor_state g_fbvbs_hypervisor;

static struct fbvbs_host_callsite_table *fbvbs_find_host_callsite_table_slot(
    struct fbvbs_hypervisor_state *state,
    uint8_t caller_class
) {
    uint32_t index;

    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        if (state->host_callsites[index].active &&
            state->host_callsites[index].caller_class == caller_class) {
            return &state->host_callsites[index];
        }
    }
    for (index = 0U; index < FBVBS_MAX_HOST_CALLSITE_TABLES; ++index) {
        if (!state->host_callsites[index].active) {
            return &state->host_callsites[index];
        }
    }
    return NULL;
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
    struct fbvbs_host_callsite_table *slot;
    uint32_t index;

    if (state == NULL || allowed_offsets == NULL || manifest_object_id == 0U ||
        load_base == 0U || count == 0U || count > FBVBS_MAX_HOST_CALLSITE_ENTRIES) {
        return INVALID_PARAMETER;
    }
    if (caller_class != FBVBS_HOST_CALLER_CLASS_FBVBS &&
        caller_class != FBVBS_HOST_CALLER_CLASS_VMM) {
        return INVALID_PARAMETER;
    }

    fbvbs_zero_memory(&table, sizeof(table));
    table.active = true;
    table.caller_class = caller_class;
    table.count = (uint16_t)count;
    table.manifest_object_id = manifest_object_id;
    table.load_base = load_base;
    for (index = 0U; index < count; ++index) {
        table.allowed_offsets[index] = allowed_offsets[index];
        table.relocated_callsites[index] = load_base + allowed_offsets[index];
    }

    slot = fbvbs_find_host_callsite_table_slot(state, caller_class);
    if (slot == NULL) {
        return RESOURCE_EXHAUSTED;
    }
    *slot = table;
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

static void fbvbs_seed_boot_ids(struct fbvbs_hypervisor_state *state) {
    state->boot_id_hi = 0x4642564253560000ULL;
    state->boot_id_lo = 0x0000000000000001ULL;
}

static void fbvbs_seed_hash(uint8_t hash[48], uint8_t tag) {
    fbvbs_zero_memory(hash, 48U);
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

static void fbvbs_materialize_boot_artifact_entries(
    struct fbvbs_artifact_catalog_entry entries[sizeof(g_fbvbs_boot_artifact_seeds) / sizeof(g_fbvbs_boot_artifact_seeds[0])]
) {
    uint32_t index;

    fbvbs_zero_memory(
        entries,
        sizeof(struct fbvbs_artifact_catalog_entry) *
            (sizeof(g_fbvbs_boot_artifact_seeds) / sizeof(g_fbvbs_boot_artifact_seeds[0]))
    );
    for (index = 0U; index < (uint32_t)(sizeof(g_fbvbs_boot_artifact_seeds) / sizeof(g_fbvbs_boot_artifact_seeds[0])); ++index) {
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

static const struct fbvbs_artifact_catalog_entry *fbvbs_find_artifact_entry_in_catalog(
    const struct fbvbs_artifact_catalog *catalog,
    uint64_t object_id
) {
    uint32_t index;

    if (catalog == NULL || object_id == 0U) {
        return NULL;
    }
    for (index = 0U; index < catalog->count; ++index) {
        if (catalog->entries[index].object_id == object_id) {
            return &catalog->entries[index];
        }
    }
    return NULL;
}

static bool fbvbs_artifact_kind_is_valid(uint32_t object_kind) {
    return object_kind == FBVBS_ARTIFACT_OBJECT_IMAGE ||
        object_kind == FBVBS_ARTIFACT_OBJECT_MANIFEST ||
        object_kind == FBVBS_ARTIFACT_OBJECT_MODULE;
}

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

    fbvbs_zero_memory(catalog, sizeof(*catalog));
    catalog->count = artifact_count;
    for (index = 0U; index < artifact_count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &artifact_entries[index];

        if (entry->object_id == 0U ||
            !fbvbs_artifact_kind_is_valid(entry->object_kind) ||
            entry->related_index >= artifact_count) {
            return INVALID_PARAMETER;
        }
        for (other = 0U; other < index; ++other) {
            if (artifact_entries[other].object_id == entry->object_id) {
                return ALREADY_EXISTS;
            }
        }
        catalog->entries[index] = *entry;
    }

    for (index = 0U; index < artifact_count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &catalog->entries[index];
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

    fbvbs_zero_memory(validated_profiles, sizeof(struct fbvbs_manifest_profile) * FBVBS_MAX_MANIFEST_PROFILES);
    if (profile_count == 0U) {
        return OK;
    }
    if (profiles == NULL) {
        return INVALID_PARAMETER;
    }

    for (index = 0U; index < profile_count; ++index) {
        const struct fbvbs_manifest_profile *profile = &profiles[index];
        const struct fbvbs_artifact_catalog_entry *artifact_entry;
        const struct fbvbs_artifact_catalog_entry *manifest_entry;

        if (fbvbs_manifest_component_expected_kind(profile->component_type, &artifact_kind) != OK ||
            profile->object_id == 0U || profile->manifest_object_id == 0U) {
            return INVALID_PARAMETER;
        }

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

        validated_profiles[index] = *profile;
        validated_profiles[index].active = true;
    }

    return OK;
}

static int fbvbs_build_host_callsite_tables(
    const struct fbvbs_manifest_profile profiles[FBVBS_MAX_MANIFEST_PROFILES],
    struct fbvbs_host_callsite_table tables[FBVBS_MAX_HOST_CALLSITE_TABLES]
) {
    uint32_t index;

    if (profiles == NULL || tables == NULL) {
        return INVALID_PARAMETER;
    }

    fbvbs_zero_memory(tables, sizeof(struct fbvbs_host_callsite_table) * FBVBS_MAX_HOST_CALLSITE_TABLES);
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
        for (callsite_index = 0U; callsite_index < profile->allowed_callsite_count; ++callsite_index) {
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

    if (state == NULL) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_validate_boot_artifact_catalog(artifact_entries, artifact_count, &catalog);
    if (status != OK) {
        return status;
    }
    status = fbvbs_validate_manifest_profiles(catalog.count != 0U ? &catalog : NULL, profiles, profile_count, validated_profiles);
    if (status != OK) {
        return status;
    }
    status = fbvbs_build_host_callsite_tables(validated_profiles, host_tables);
    if (status != OK) {
        return status;
    }

    state->artifact_catalog = catalog;
    fbvbs_zero_memory(state->manifest_profiles, sizeof(state->manifest_profiles));
    fbvbs_copy_memory(state->manifest_profiles, validated_profiles, sizeof(validated_profiles));
    fbvbs_zero_memory(state->host_callsites, sizeof(state->host_callsites));
    fbvbs_copy_memory(state->host_callsites, host_tables, sizeof(host_tables));
    fbvbs_zero_memory(state->approvals, sizeof(state->approvals));
    fbvbs_zero_memory(state->revoked_object_ids, sizeof(state->revoked_object_ids));
    state->revoked_object_count = 0U;
    return OK;
}

static void fbvbs_seed_device_catalog(struct fbvbs_hypervisor_state *state) {
    struct fbvbs_device_catalog_entry *device = &state->device_catalog.entries[0];

    state->device_catalog.count = 1U;
    device->device_id = 0xD000U;
    device->segment = 0U;
    device->bus = 2U;
    device->slot_function = 0x10U;
}

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

void fbvbs_hypervisor_init(struct fbvbs_hypervisor_state *state) {
    static const uint8_t boot_payload[] = "fbvbs hypervisor kernel boot";
    struct fbvbs_artifact_catalog_entry boot_artifact_entries[
        sizeof(g_fbvbs_boot_artifact_seeds) / sizeof(g_fbvbs_boot_artifact_seeds[0])
    ];

    fbvbs_zero_memory(state, sizeof(*state));
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
    (void)fbvbs_ingest_boot_catalog(
        state,
        boot_artifact_entries,
        (uint32_t)(sizeof(g_fbvbs_boot_artifact_seeds) / sizeof(g_fbvbs_boot_artifact_seeds[0])),
        g_fbvbs_boot_manifest_profiles,
        (uint32_t)(sizeof(g_fbvbs_boot_manifest_profiles) / sizeof(g_fbvbs_boot_manifest_profiles[0]))
    );
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

void fbvbs_kernel_main(void) {
    fbvbs_hypervisor_init(&g_fbvbs_hypervisor);
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

int fbvbs_diag_get_artifact_list(
    struct fbvbs_hypervisor_state *state,
    struct fbvbs_diag_artifact_list_response *response,
    uint32_t *response_length
) {
    uint32_t index;

    if (state == NULL || response == NULL || response_length == NULL) {
        return INVALID_PARAMETER;
    }

    fbvbs_zero_memory(response, sizeof(*response));
    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &state->artifact_catalog.entries[index];

        if (((index + 1U) * (uint32_t)sizeof(*entry)) > sizeof(response->entries)) {
            return BUFFER_TOO_SMALL;
        }
        fbvbs_copy_memory(
            &response->entries[index * sizeof(*entry)],
            entry,
            sizeof(*entry)
        );
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

    fbvbs_zero_memory(response, sizeof(*response));
    for (index = 0U; index < state->device_catalog.count; ++index) {
        const struct fbvbs_device_catalog_entry *entry = &state->device_catalog.entries[index];

        if (((index + 1U) * (uint32_t)sizeof(*entry)) > sizeof(response->entries)) {
            return BUFFER_TOO_SMALL;
        }
        fbvbs_copy_memory(
            &response->entries[index * sizeof(*entry)],
            entry,
            sizeof(*entry)
        );
    }

    response->count = state->device_catalog.count;
    response->reserved0 = 0U;
    *response_length = 8U +
        (state->device_catalog.count * (uint32_t)sizeof(struct fbvbs_device_catalog_entry));
    return OK;
}
