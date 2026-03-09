#include "fbvbs_hypervisor.h"

static int fbvbs_artifact_exists(
    const struct fbvbs_hypervisor_state *state,
    uint64_t object_id,
    uint32_t expected_kind
) {
    uint32_t index;

    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &state->artifact_catalog.entries[index];

        if (entry->object_id == object_id && entry->object_kind == expected_kind) {
            return 1;
        }
    }

    return 0;
}

static const struct fbvbs_artifact_catalog_entry *fbvbs_find_artifact_entry(
    const struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        if (state->artifact_catalog.entries[index].object_id == object_id) {
            return &state->artifact_catalog.entries[index];
        }
    }

    return NULL;
}

static uint32_t fbvbs_artifact_entry_index(
    const struct fbvbs_hypervisor_state *state,
    const struct fbvbs_artifact_catalog_entry *entry
) {
    return (uint32_t)(entry - state->artifact_catalog.entries);
}

static int fbvbs_page_aligned_range(uint64_t guest_physical_address, uint64_t size) {
    return guest_physical_address != 0U &&
        size != 0U &&
        (guest_physical_address % FBVBS_PAGE_SIZE) == 0U &&
        (size % FBVBS_PAGE_SIZE) == 0U;
}

static int fbvbs_manifest_pair_valid(
    const struct fbvbs_hypervisor_state *state,
    uint64_t artifact_object_id,
    uint64_t manifest_object_id,
    uint32_t artifact_kind
) {
    const struct fbvbs_artifact_catalog_entry *artifact_entry =
        fbvbs_find_artifact_entry(state, artifact_object_id);
    const struct fbvbs_artifact_catalog_entry *manifest_entry =
        fbvbs_find_artifact_entry(state, manifest_object_id);

    if (artifact_entry == NULL || manifest_entry == NULL) {
        return 0;
    }
    if (artifact_entry->object_kind != artifact_kind ||
        manifest_entry->object_kind != FBVBS_ARTIFACT_OBJECT_MANIFEST) {
        return 0;
    }
    if (artifact_entry->related_index >= state->artifact_catalog.count) {
        return 0;
    }

    return &state->artifact_catalog.entries[artifact_entry->related_index] == manifest_entry;
}

static int fbvbs_hash_tail_zero(const uint8_t hash[64]) {
    uint32_t index;

    for (index = 48U; index < 64U; ++index) {
        if (hash[index] != 0U) {
            return 0;
        }
    }

    return 1;
}

static int fbvbs_artifact_hash_matches_manifest(
    const struct fbvbs_hypervisor_state *state,
    const uint8_t artifact_hash[64],
    uint64_t manifest_object_id
) {
    const struct fbvbs_artifact_catalog_entry *manifest_entry =
        fbvbs_find_artifact_entry(state, manifest_object_id);
    uint32_t manifest_index;
    uint32_t index;

    if (manifest_entry == NULL || manifest_entry->object_kind != FBVBS_ARTIFACT_OBJECT_MANIFEST) {
        return 0;
    }
    manifest_index = fbvbs_artifact_entry_index(state, manifest_entry);

    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &state->artifact_catalog.entries[index];
        uint32_t hash_index;
        int equal = 1;

        if (entry->object_kind == FBVBS_ARTIFACT_OBJECT_MANIFEST ||
            entry->related_index != manifest_index) {
            continue;
        }

        for (hash_index = 0U; hash_index < 48U; ++hash_index) {
            if (artifact_hash[hash_index] != entry->payload_hash[hash_index]) {
                equal = 0;
                break;
            }
        }
        if (equal != 0) {
            return 1;
        }
    }

    return 0;
}

static uint64_t fbvbs_find_artifact_object_for_hash(
    const struct fbvbs_hypervisor_state *state,
    const uint8_t artifact_hash[64],
    uint64_t manifest_object_id
) {
    const struct fbvbs_artifact_catalog_entry *manifest_entry =
        fbvbs_find_artifact_entry(state, manifest_object_id);
    uint32_t manifest_index;
    uint32_t index;

    if (manifest_entry == NULL || manifest_entry->object_kind != FBVBS_ARTIFACT_OBJECT_MANIFEST) {
        return 0U;
    }
    manifest_index = fbvbs_artifact_entry_index(state, manifest_entry);

    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &state->artifact_catalog.entries[index];
        uint32_t hash_index;
        int equal = 1;

        if (entry->object_kind == FBVBS_ARTIFACT_OBJECT_MANIFEST ||
            entry->related_index != manifest_index) {
            continue;
        }

        for (hash_index = 0U; hash_index < 48U; ++hash_index) {
            if (artifact_hash[hash_index] != entry->payload_hash[hash_index]) {
                equal = 0;
                break;
            }
        }
        if (equal != 0) {
            return entry->object_id;
        }
    }

    return 0U;
}

static int fbvbs_record_artifact_approval(
    struct fbvbs_hypervisor_state *state,
    uint64_t verified_manifest_set_id,
    uint64_t artifact_object_id,
    uint64_t manifest_object_id,
    const uint8_t artifact_hash[64]
) {
    uint32_t index;
    struct fbvbs_uvs_artifact_approval *free_slot = NULL;

    for (index = 0U; index < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; ++index) {
        struct fbvbs_uvs_artifact_approval *approval = &state->approvals[index];

        if (!approval->active) {
            if (free_slot == NULL) {
                free_slot = approval;
            }
            continue;
        }
        if (approval->artifact_object_id == artifact_object_id &&
            approval->manifest_object_id == manifest_object_id) {
            approval->verified_manifest_set_id = verified_manifest_set_id;
            fbvbs_copy_memory(approval->artifact_hash, artifact_hash, 48U);
            return OK;
        }
    }

    if (free_slot == NULL) {
        return INTERNAL_CORRUPTION;
    }

    fbvbs_zero_memory(free_slot, sizeof(*free_slot));
    free_slot->active = true;
    free_slot->verified_manifest_set_id = verified_manifest_set_id;
    free_slot->artifact_object_id = artifact_object_id;
    free_slot->manifest_object_id = manifest_object_id;
    fbvbs_copy_memory(free_slot->artifact_hash, artifact_hash, 48U);
    return OK;
}

int fbvbs_artifact_approval_exists(
    const struct fbvbs_hypervisor_state *state,
    uint64_t artifact_object_id,
    uint64_t manifest_object_id
) {
    uint32_t index;

    if (state == NULL || artifact_object_id == 0U || manifest_object_id == 0U) {
        return 0;
    }

    for (index = 0U; index < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; ++index) {
        const struct fbvbs_uvs_artifact_approval *approval = &state->approvals[index];

        if (approval->active &&
            approval->artifact_object_id == artifact_object_id &&
            approval->manifest_object_id == manifest_object_id) {
            return 1;
        }
    }

    return 0;
}

static const struct fbvbs_metadata_set_page *fbvbs_metadata_set_page_from_gpa(
    uint64_t manifest_set_page_gpa
) {
    return (const struct fbvbs_metadata_set_page *)(uintptr_t)manifest_set_page_gpa;
}

static const struct fbvbs_metadata_manifest *fbvbs_manifest_from_gpa(uint64_t manifest_gpa) {
    return (const struct fbvbs_metadata_manifest *)(uintptr_t)manifest_gpa;
}

static void fbvbs_copy_snapshot_id(uint8_t destination[32], const uint8_t source[32]) {
    uint32_t index;

    for (index = 0U; index < 32U; ++index) {
        destination[index] = source[index];
    }
}

static int fbvbs_snapshot_ids_equal(const uint8_t left[32], const uint8_t right[32]) {
    uint32_t index;

    for (index = 0U; index < 32U; ++index) {
        if (left[index] != right[index]) {
            return 0;
        }
    }

    return 1;
}

static uint32_t fbvbs_metadata_role_bit(uint32_t role) {
    switch (role) {
        case FBVBS_METADATA_ROLE_ROOT:
            return 0x01U;
        case FBVBS_METADATA_ROLE_TARGETS:
            return 0x02U;
        case FBVBS_METADATA_ROLE_SNAPSHOT:
            return 0x04U;
        case FBVBS_METADATA_ROLE_TIMESTAMP:
            return 0x08U;
        case FBVBS_METADATA_ROLE_REVOCATION:
            return 0x10U;
        default:
            return 0U;
    }
}

static int fbvbs_metadata_page_contains_object_id(
    const struct fbvbs_metadata_set_page *page,
    uint32_t count,
    uint64_t object_id
) {
    uint32_t index;

    for (index = 0U; index < count; ++index) {
        const struct fbvbs_metadata_manifest *manifest = fbvbs_manifest_from_gpa(page->manifest_gpas[index]);

        if (manifest != NULL && manifest->object_id == object_id) {
            return 1;
        }
    }

    return 0;
}

static const struct fbvbs_metadata_manifest *fbvbs_find_manifest_in_verified_set(
    const struct fbvbs_uvs_manifest_set *manifest_set,
    uint64_t manifest_object_id
) {
    const struct fbvbs_metadata_set_page *page;
    uint32_t index;

    if (manifest_set == NULL || manifest_set->manifest_set_page_gpa == 0U) {
        return NULL;
    }
    page = fbvbs_metadata_set_page_from_gpa(manifest_set->manifest_set_page_gpa);
    if (page == NULL) {
        return NULL;
    }

    for (index = 0U; index < manifest_set->manifest_count; ++index) {
        const struct fbvbs_metadata_manifest *manifest = fbvbs_manifest_from_gpa(page->manifest_gpas[index]);

        if (manifest != NULL && manifest->object_id == manifest_object_id) {
            return manifest;
        }
    }

    return NULL;
}

static void fbvbs_record_revoked_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    if (state == NULL || object_id == 0U) {
        return;
    }
    for (index = 0U; index < state->revoked_object_count; ++index) {
        if (state->revoked_object_ids[index] == object_id) {
            return;
        }
    }
    if (state->revoked_object_count < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES) {
        state->revoked_object_ids[state->revoked_object_count++] = object_id;
    }
}

static int fbvbs_is_object_revoked(
    const struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    for (index = 0U; index < state->revoked_object_count; ++index) {
        if (state->revoked_object_ids[index] == object_id) {
            return 1;
        }
    }
    return 0;
}

static int fbvbs_status_from_uvs_failure_bitmap(uint32_t failure_bitmap) {
    if ((failure_bitmap & FBVBS_UVS_FAILURE_SIGNATURE) != 0U) {
        return SIGNATURE_INVALID;
    }
    if ((failure_bitmap & FBVBS_UVS_FAILURE_REVOCATION) != 0U) {
        return REVOKED;
    }
    if ((failure_bitmap & FBVBS_UVS_FAILURE_GENERATION) != 0U) {
        return GENERATION_MISMATCH;
    }
    if ((failure_bitmap & FBVBS_UVS_FAILURE_ROLLBACK) != 0U) {
        return ROLLBACK_DETECTED;
    }
    if ((failure_bitmap & FBVBS_UVS_FAILURE_DEPENDENCY) != 0U) {
        return DEPENDENCY_UNSATISFIED;
    }
    if ((failure_bitmap & FBVBS_UVS_FAILURE_SNAPSHOT) != 0U) {
        return SNAPSHOT_INCONSISTENT;
    }
    if ((failure_bitmap & FBVBS_UVS_FAILURE_FRESHNESS) != 0U) {
        return FRESHNESS_FAILED;
    }
    return OK;
}

static int fbvbs_validate_metadata_set(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_verify_manifest_set_request *request,
    uint32_t *failure_bitmap,
    uint8_t snapshot_id[32]
) {
    const struct fbvbs_metadata_set_page *page =
        fbvbs_metadata_set_page_from_gpa(request->manifest_set_page_gpa);
    uint64_t freshness_window_end;
    uint32_t index;
    uint32_t role_mask = 0U;

    *failure_bitmap = 0U;
    if (!state->trusted_clock_available) {
        *failure_bitmap |= FBVBS_UVS_FAILURE_FRESHNESS;
        return fbvbs_status_from_uvs_failure_bitmap(*failure_bitmap);
    }
    if (page == NULL || page->reserved0 != 0U || page->count != request->manifest_count ||
        page->manifest_gpas[0] != request->root_manifest_gpa ||
        request->root_manifest_length != sizeof(struct fbvbs_metadata_manifest)) {
        return INVALID_PARAMETER;
    }
    freshness_window_end = state->trusted_time_seconds + 300U;

    for (index = 0U; index < request->manifest_count; ++index) {
        const struct fbvbs_metadata_manifest *manifest = fbvbs_manifest_from_gpa(page->manifest_gpas[index]);
        uint32_t role_bit;

        if (manifest == NULL || manifest->object_id == 0U) {
            *failure_bitmap |= FBVBS_UVS_FAILURE_SIGNATURE;
            continue;
        }
        if ((manifest->flags & FBVBS_METADATA_FLAG_SIGNATURE_VALID) == 0U) {
            *failure_bitmap |= FBVBS_UVS_FAILURE_SIGNATURE;
        }
        if ((manifest->flags & FBVBS_METADATA_FLAG_REVOKED) != 0U) {
            *failure_bitmap |= FBVBS_UVS_FAILURE_REVOCATION;
            fbvbs_record_revoked_object(state, manifest->object_id);
        }
        if (manifest->expected_generation != 0U && manifest->generation != manifest->expected_generation) {
            *failure_bitmap |= FBVBS_UVS_FAILURE_GENERATION;
        }
        if (manifest->minimum_generation != 0U && manifest->generation < manifest->minimum_generation) {
            *failure_bitmap |= FBVBS_UVS_FAILURE_ROLLBACK;
        }
        if (manifest->timestamp_seconds > freshness_window_end ||
            manifest->expires_at_seconds + 300U < state->trusted_time_seconds) {
            *failure_bitmap |= FBVBS_UVS_FAILURE_FRESHNESS;
        }
        role_bit = fbvbs_metadata_role_bit(manifest->role);
        if (role_bit == 0U || (role_mask & role_bit) != 0U) {
            *failure_bitmap |= FBVBS_UVS_FAILURE_SNAPSHOT;
        } else {
            role_mask |= role_bit;
        }
        if (index == 0U) {
            if (manifest->role != FBVBS_METADATA_ROLE_ROOT) {
                *failure_bitmap |= FBVBS_UVS_FAILURE_SNAPSHOT;
            }
            fbvbs_copy_snapshot_id(snapshot_id, manifest->snapshot_id);
        } else if (!fbvbs_snapshot_ids_equal(snapshot_id, manifest->snapshot_id)) {
            *failure_bitmap |= FBVBS_UVS_FAILURE_SNAPSHOT;
        }
    }

    for (index = 0U; index < request->manifest_count; ++index) {
        const struct fbvbs_metadata_manifest *manifest = fbvbs_manifest_from_gpa(page->manifest_gpas[index]);

        if (manifest != NULL && manifest->dependency_object_id != 0U &&
            !fbvbs_metadata_page_contains_object_id(page, request->manifest_count, manifest->dependency_object_id)) {
            *failure_bitmap |= FBVBS_UVS_FAILURE_DEPENDENCY;
        }
    }
    if (role_mask != 0x1FU) {
        *failure_bitmap |= FBVBS_UVS_FAILURE_SNAPSHOT;
    }

    return fbvbs_status_from_uvs_failure_bitmap(*failure_bitmap);
}

static struct fbvbs_ksi_target_set *fbvbs_find_target_set(
    struct fbvbs_hypervisor_state *state,
    uint64_t target_set_id
) {
    uint32_t index;

    for (index = 0U; index < 8U; ++index) {
        if (state->ksi_target_sets[index].active &&
            state->ksi_target_sets[index].target_set_id == target_set_id) {
            return &state->ksi_target_sets[index];
        }
    }

    return NULL;
}

static struct fbvbs_ksi_target_set *fbvbs_allocate_target_set(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    for (index = 0U; index < 8U; ++index) {
        if (!state->ksi_target_sets[index].active) {
            return &state->ksi_target_sets[index];
        }
    }

    return NULL;
}

static struct fbvbs_ksi_object *fbvbs_find_ksi_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    for (index = 0U; index < 16U; ++index) {
        if (state->ksi_objects[index].active && state->ksi_objects[index].object_id == object_id) {
            return &state->ksi_objects[index];
        }
    }

    return NULL;
}

static struct fbvbs_ksi_object *fbvbs_allocate_ksi_object(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    for (index = 0U; index < 16U; ++index) {
        if (!state->ksi_objects[index].active) {
            return &state->ksi_objects[index];
        }
    }

    return NULL;
}

static int fbvbs_ksi_class_valid(uint32_t protection_class) {
    return protection_class >= KSI_CLASS_UCRED && protection_class <= KSI_CLASS_P_TEXTVP;
}

static int fbvbs_target_set_contains_object(
    const struct fbvbs_ksi_target_set *target_set,
    uint64_t object_id
) {
    uint32_t index;

    for (index = 0U; index < target_set->target_count; ++index) {
        if (target_set->target_object_ids[index] == object_id) {
            return 1;
        }
    }

    return 0;
}

static int fbvbs_target_set_has_registered_target(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_target_set *target_set
) {
    uint32_t index;

    for (index = 0U; index < target_set->target_count; ++index) {
        if (fbvbs_find_ksi_object(state, target_set->target_object_ids[index]) != NULL) {
            return 1;
        }
    }

    return 0;
}

static int fbvbs_any_target_set_references_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    for (index = 0U; index < 8U; ++index) {
        if (state->ksi_target_sets[index].active &&
            fbvbs_target_set_contains_object(&state->ksi_target_sets[index], object_id)) {
            return 1;
        }
    }

    return 0;
}

static struct fbvbs_iks_key *fbvbs_find_iks_key(
    struct fbvbs_hypervisor_state *state,
    uint64_t key_handle
) {
    uint32_t index;

    for (index = 0U; index < 16U; ++index) {
        if (state->iks_keys[index].active && state->iks_keys[index].key_handle == key_handle) {
            return &state->iks_keys[index];
        }
    }

    return NULL;
}

static struct fbvbs_iks_key *fbvbs_allocate_iks_key(struct fbvbs_hypervisor_state *state) {
    uint32_t index;

    for (index = 0U; index < 16U; ++index) {
        if (!state->iks_keys[index].active) {
            return &state->iks_keys[index];
        }
    }

    return NULL;
}

static int fbvbs_iks_key_type_valid(uint32_t key_type) {
    return key_type >= IKS_KEY_ED25519 && key_type <= IKS_KEY_ECDH_P256;
}

static int fbvbs_iks_can_sign(uint32_t key_type) {
    return key_type == IKS_KEY_ED25519 ||
        key_type == IKS_KEY_ECDSA_P256 ||
        key_type == IKS_KEY_RSA3072;
}

static int fbvbs_iks_can_exchange(uint32_t key_type) {
    return key_type == IKS_KEY_X25519 || key_type == IKS_KEY_ECDH_P256;
}

static int fbvbs_iks_key_length_valid(uint32_t key_type, uint32_t key_length) {
    switch (key_type) {
        case IKS_KEY_ED25519:
        case IKS_KEY_X25519:
            return key_length == 32U;
        case IKS_KEY_ECDSA_P256:
        case IKS_KEY_ECDH_P256:
            return key_length == 32U || key_length == 121U;
        case IKS_KEY_RSA3072:
            return key_length >= 256U;
        default:
            return 0;
    }
}

static struct fbvbs_sks_dek *fbvbs_find_sks_dek(
    struct fbvbs_hypervisor_state *state,
    uint64_t dek_handle
) {
    uint32_t index;

    for (index = 0U; index < 16U; ++index) {
        if (state->sks_deks[index].active && state->sks_deks[index].dek_handle == dek_handle) {
            return &state->sks_deks[index];
        }
    }

    return NULL;
}

static struct fbvbs_sks_dek *fbvbs_allocate_sks_dek(struct fbvbs_hypervisor_state *state) {
    uint32_t index;

    for (index = 0U; index < 16U; ++index) {
        if (!state->sks_deks[index].active) {
            return &state->sks_deks[index];
        }
    }

    return NULL;
}

static struct fbvbs_uvs_manifest_set *fbvbs_find_manifest_set(
    struct fbvbs_hypervisor_state *state,
    uint64_t manifest_set_id
) {
    uint32_t index;

    for (index = 0U; index < 8U; ++index) {
        if (state->manifest_sets[index].active &&
            state->manifest_sets[index].verified_manifest_set_id == manifest_set_id) {
            return &state->manifest_sets[index];
        }
    }

    return NULL;
}

static struct fbvbs_uvs_manifest_set *fbvbs_allocate_manifest_set(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    for (index = 0U; index < 8U; ++index) {
        if (!state->manifest_sets[index].active) {
            return &state->manifest_sets[index];
        }
    }

    return NULL;
}

int fbvbs_kci_verify_module(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_verify_module_request *request,
    struct fbvbs_verdict_response *response
) {
    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->generation != 1U) {
        return GENERATION_MISMATCH;
    }
    if (!fbvbs_manifest_pair_valid(
        state,
        request->module_object_id,
        request->manifest_object_id,
        FBVBS_ARTIFACT_OBJECT_MODULE
    )) {
        return NOT_FOUND;
    }
    if (!fbvbs_artifact_approval_exists(state, request->module_object_id, request->manifest_object_id)) {
        return SIGNATURE_INVALID;
    }

    response->verdict = 1U;
    response->reserved0 = 0U;
    state->approved_module_object_id = request->module_object_id;
    return OK;
}

int fbvbs_kci_set_wx(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_set_wx_request *request
) {
    if (state == NULL || request == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U ||
        !fbvbs_page_aligned_range(request->guest_physical_address, request->size) ||
        (request->file_offset % FBVBS_PAGE_SIZE) != 0U) {
        return INVALID_PARAMETER;
    }
    if (state->approved_module_object_id != request->module_object_id) {
        return INVALID_STATE;
    }
    if ((request->permissions & FBVBS_MEMORY_PERMISSION_EXECUTE) == 0U ||
        (request->permissions & FBVBS_MEMORY_PERMISSION_WRITE) != 0U) {
        return PERMISSION_DENIED;
    }
    return OK;
}

int fbvbs_kci_pin_cr(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_pin_cr_request *request
) {
    if (state == NULL || request == NULL || request->reserved0 != 0U || request->pin_mask == 0U) {
        return INVALID_PARAMETER;
    }

    switch (request->cr_number) {
        case 0U:
            state->pinned_cr0_mask = request->pin_mask;
            return OK;
        case 4U:
            state->pinned_cr4_mask = request->pin_mask;
            return OK;
        default:
            return NOT_SUPPORTED_ON_PLATFORM;
    }
}

int fbvbs_kci_intercept_msr(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_kci_intercept_msr_request *request
) {
    uint32_t index;

    if (state == NULL || request == NULL || request->enable > 1U) {
        return INVALID_PARAMETER;
    }
    if (request->msr_address != 0xC0000080U &&
        request->msr_address != 0xC0000082U &&
        request->msr_address != 0xC0000084U) {
        return PERMISSION_DENIED;
    }

    for (index = 0U; index < state->intercepted_msr_count; ++index) {
        if (state->intercepted_msrs[index] == request->msr_address) {
            if (request->enable == 0U) {
                uint32_t tail;

                for (tail = index + 1U; tail < state->intercepted_msr_count; ++tail) {
                    state->intercepted_msrs[tail - 1U] = state->intercepted_msrs[tail];
                }
                state->intercepted_msr_count -= 1U;
            }
            return OK;
        }
    }

    if (request->enable == 0U) {
        return OK;
    }
    if (state->intercepted_msr_count >= 16U) {
        return RESOURCE_EXHAUSTED;
    }

    state->intercepted_msrs[state->intercepted_msr_count++] = request->msr_address;
    return OK;
}

int fbvbs_ksi_create_target_set(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_create_target_set_request *request,
    struct fbvbs_ksi_target_set_response *response
) {
    struct fbvbs_ksi_target_set *target_set;
    uint32_t index;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U || request->target_count == 0U || request->target_count > 8U) {
        return INVALID_PARAMETER;
    }

    target_set = fbvbs_allocate_target_set(state);
    if (target_set == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    fbvbs_zero_memory(target_set, sizeof(*target_set));
    target_set->active = true;
    target_set->target_count = request->target_count;
    target_set->target_set_id = state->next_target_set_id++;
    for (index = 0U; index < request->target_count; ++index) {
        uint32_t compare;

        if (request->target_object_ids[index] == 0U) {
            fbvbs_zero_memory(target_set, sizeof(*target_set));
            return INVALID_PARAMETER;
        }
        for (compare = 0U; compare < index; ++compare) {
            if (request->target_object_ids[compare] == request->target_object_ids[index]) {
                fbvbs_zero_memory(target_set, sizeof(*target_set));
                return ALREADY_EXISTS;
            }
        }
        target_set->target_object_ids[index] = request->target_object_ids[index];
    }
    response->target_set_id = target_set->target_set_id;
    return OK;
}

int fbvbs_ksi_register_tier_a(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_register_tier_a_request *request
) {
    struct fbvbs_ksi_object *object;

    if (state == NULL || request == NULL ||
        request->object_id == 0U ||
        request->object_id != request->guest_physical_address ||
        !fbvbs_page_aligned_range(request->guest_physical_address, request->size)) {
        return INVALID_PARAMETER;
    }
    if (fbvbs_find_ksi_object(state, request->object_id) != NULL) {
        return ALREADY_EXISTS;
    }

    object = fbvbs_allocate_ksi_object(state);
    if (object == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    fbvbs_zero_memory(object, sizeof(*object));
    object->active = true;
    object->object_id = request->object_id;
    object->guest_physical_address = request->guest_physical_address;
    object->size = request->size;
    return OK;
}

int fbvbs_ksi_register_tier_b(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_register_tier_b_request *request
) {
    struct fbvbs_ksi_object *object;

    if (state == NULL || request == NULL || request->reserved0 != 0U ||
        request->object_id == 0U ||
        request->object_id != request->guest_physical_address ||
        !fbvbs_page_aligned_range(request->guest_physical_address, request->size) ||
        !fbvbs_ksi_class_valid(request->protection_class)) {
        return INVALID_PARAMETER;
    }
    if (fbvbs_find_ksi_object(state, request->object_id) != NULL) {
        return ALREADY_EXISTS;
    }

    object = fbvbs_allocate_ksi_object(state);
    if (object == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    fbvbs_zero_memory(object, sizeof(*object));
    object->active = true;
    object->tier_b = true;
    object->object_id = request->object_id;
    object->guest_physical_address = request->guest_physical_address;
    object->size = request->size;
    object->protection_class = request->protection_class;
    return OK;
}

int fbvbs_ksi_modify_tier_b(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_modify_tier_b_request *request
) {
    struct fbvbs_ksi_object *object;

    if (state == NULL || request == NULL || request->reserved0 != 0U || request->patch_length == 0U ||
        request->patch_length > sizeof(request->patch)) {
        return INVALID_PARAMETER;
    }

    object = fbvbs_find_ksi_object(state, request->object_id);
    if (object == NULL) {
        return NOT_FOUND;
    }
    if (!object->tier_b || object->retired) {
        return INVALID_STATE;
    }
    if (request->patch_length > object->size) {
        return INVALID_PARAMETER;
    }
    return OK;
}

int fbvbs_ksi_register_pointer(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_register_pointer_request *request
) {
    struct fbvbs_ksi_object *object;
    struct fbvbs_ksi_target_set *target_set;

    if (state == NULL || request == NULL || request->pointer_object_id == 0U || request->target_set_id == 0U) {
        return INVALID_PARAMETER;
    }

    object = fbvbs_find_ksi_object(state, request->pointer_object_id);
    if (object == NULL) {
        return NOT_FOUND;
    }
    if (object->pointer_registered) {
        return ALREADY_EXISTS;
    }

    target_set = fbvbs_find_target_set(state, request->target_set_id);
    if (target_set == NULL) {
        return NOT_FOUND;
    }
    if (!fbvbs_target_set_has_registered_target(state, target_set)) {
        return NOT_FOUND;
    }

    object->pointer_registered = true;
    object->target_set_id = target_set->target_set_id;
    return OK;
}

int fbvbs_ksi_validate_setuid(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_validate_setuid_request *request,
    struct fbvbs_verdict_response *response
) {
    struct fbvbs_ksi_object *ucred;
    struct fbvbs_ksi_object *context_object;
    uint32_t uid_mask = FBVBS_KSI_VALID_RUID | FBVBS_KSI_VALID_EUID | FBVBS_KSI_VALID_SUID;
    uint32_t gid_mask = FBVBS_KSI_VALID_RGID | FBVBS_KSI_VALID_EGID | FBVBS_KSI_VALID_SGID;
    int hash_nonzero = 0;
    uint32_t index;

    if (state == NULL || request == NULL || response == NULL || request->valid_mask == 0U ||
        (request->valid_mask & ~0x3FU) != 0U) {
        return INVALID_PARAMETER;
    }
    if (!fbvbs_hash_tail_zero(request->measured_hash)) {
        return INVALID_PARAMETER;
    }
    if ((request->fsid == 0U) != (request->fileid == 0U)) {
        return INVALID_PARAMETER;
    }

    ucred = fbvbs_find_ksi_object(state, request->caller_ucred_object_id);
    if (ucred == NULL) {
        return NOT_FOUND;
    }
    if (!ucred->tier_b || ucred->protection_class != KSI_CLASS_UCRED) {
        return POLICY_DENIED;
    }

    for (index = 0U; index < 48U; ++index) {
        if (request->measured_hash[index] != 0U) {
            hash_nonzero = 1;
            break;
        }
    }

    switch (request->operation_class) {
        case FBVBS_KSI_OPERATION_EXEC_ELEVATION:
            if (request->fileid == 0U || hash_nonzero == 0) {
                return INVALID_PARAMETER;
            }
            if ((request->valid_mask & (uid_mask | gid_mask)) == 0U) {
                return INVALID_PARAMETER;
            }
            break;
        case FBVBS_KSI_OPERATION_SETUID_FAMILY:
            if (request->fileid != 0U || hash_nonzero != 0) {
                return INVALID_PARAMETER;
            }
            if ((request->valid_mask & gid_mask) != 0U) {
                return POLICY_DENIED;
            }
            if ((request->valid_mask & uid_mask) == 0U) {
                return INVALID_PARAMETER;
            }
            break;
        case FBVBS_KSI_OPERATION_SETGID_FAMILY:
            if (request->fileid != 0U || hash_nonzero != 0) {
                return INVALID_PARAMETER;
            }
            if ((request->valid_mask & uid_mask) != 0U) {
                return POLICY_DENIED;
            }
            if ((request->valid_mask & gid_mask) == 0U) {
                return INVALID_PARAMETER;
            }
            break;
        default:
            return INVALID_PARAMETER;
    }

    if (request->jail_context_id != 0U) {
        context_object = fbvbs_find_ksi_object(state, request->jail_context_id);
        if (context_object == NULL) {
            return NOT_FOUND;
        }
        if (!context_object->tier_b || context_object->protection_class != KSI_CLASS_PRISON) {
            return POLICY_DENIED;
        }
    }
    if (request->mac_context_id != 0U) {
        context_object = fbvbs_find_ksi_object(state, request->mac_context_id);
        if (context_object == NULL) {
            return NOT_FOUND;
        }
        if (!context_object->tier_b || context_object->protection_class != KSI_CLASS_MAC) {
            return POLICY_DENIED;
        }
    }

    response->verdict = 1U;
    response->reserved0 = 0U;
    return OK;
}

int fbvbs_ksi_allocate_ucred(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_allocate_ucred_request *request,
    struct fbvbs_ksi_allocate_ucred_response *response
) {
    struct fbvbs_ksi_object *object;
    struct fbvbs_ksi_object *template_object;
    uint64_t object_id;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->prison_object_id == 0U || fbvbs_find_ksi_object(state, request->prison_object_id) == NULL) {
        return NOT_FOUND;
    }
    template_object = NULL;
    if (request->template_ucred_object_id != 0U) {
        template_object = fbvbs_find_ksi_object(state, request->template_ucred_object_id);
        if (template_object == NULL) {
            return NOT_FOUND;
        }
        if (!template_object->tier_b || template_object->protection_class != KSI_CLASS_UCRED) {
            return POLICY_DENIED;
        }
    }

    object = fbvbs_allocate_ksi_object(state);
    if (object == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    object_id = state->next_memory_object_id;
    state->next_memory_object_id += FBVBS_PAGE_SIZE;
    fbvbs_zero_memory(object, sizeof(*object));
    object->active = true;
    object->tier_b = true;
    object->object_id = object_id;
    object->guest_physical_address = object_id;
    object->size = FBVBS_PAGE_SIZE;
    object->protection_class = KSI_CLASS_UCRED;
    response->ucred_object_id = object_id;
    return OK;
}

int fbvbs_ksi_replace_tier_b_object(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_replace_tier_b_object_request *request
) {
    struct fbvbs_ksi_object *old_object;
    struct fbvbs_ksi_object *new_object;
    struct fbvbs_ksi_object *pointer_object;
    struct fbvbs_ksi_target_set *target_set;

    if (state == NULL || request == NULL || request->reserved0 != 0U) {
        return INVALID_PARAMETER;
    }

    old_object = fbvbs_find_ksi_object(state, request->old_object_id);
    new_object = fbvbs_find_ksi_object(state, request->new_object_id);
    pointer_object = fbvbs_find_ksi_object(state, request->pointer_object_id);
    if (old_object == NULL || new_object == NULL || pointer_object == NULL) {
        return NOT_FOUND;
    }
    if (!old_object->tier_b || !new_object->tier_b || !pointer_object->pointer_registered) {
        return INVALID_STATE;
    }
    if (old_object->protection_class != new_object->protection_class) {
        return POLICY_DENIED;
    }

    target_set = fbvbs_find_target_set(state, pointer_object->target_set_id);
    if (target_set == NULL || !fbvbs_target_set_contains_object(target_set, new_object->object_id)) {
        return POLICY_DENIED;
    }

    old_object->retired = true;
    return OK;
}

int fbvbs_ksi_unregister_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    struct fbvbs_ksi_object *object;

    if (state == NULL || object_id == 0U) {
        return INVALID_PARAMETER;
    }

    object = fbvbs_find_ksi_object(state, object_id);
    if (object == NULL) {
        return NOT_FOUND;
    }
    if ((object->pointer_registered && !object->retired) ||
        fbvbs_any_target_set_references_object(state, object_id)) {
        return RESOURCE_BUSY;
    }

    fbvbs_zero_memory(object, sizeof(*object));
    return OK;
}

int fbvbs_iks_import_key(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_import_key_request *request,
    struct fbvbs_handle_response *response
) {
    struct fbvbs_iks_key *key;
    uint32_t allowed = IKS_OP_SIGN | IKS_OP_KEY_EXCHANGE | IKS_OP_DERIVE;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->key_material_page_gpa == 0U || request->key_length == 0U || request->reserved0 != 0U ||
        !fbvbs_iks_key_type_valid(request->key_type) || (request->allowed_ops & ~allowed) != 0U ||
        request->allowed_ops == 0U || !fbvbs_iks_key_length_valid(request->key_type, request->key_length)) {
        return INVALID_PARAMETER;
    }
    if (((request->allowed_ops & IKS_OP_SIGN) != 0U && !fbvbs_iks_can_sign(request->key_type)) ||
        ((request->allowed_ops & IKS_OP_KEY_EXCHANGE) != 0U && !fbvbs_iks_can_exchange(request->key_type))) {
        return INVALID_PARAMETER;
    }

    key = fbvbs_allocate_iks_key(state);
    if (key == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    fbvbs_zero_memory(key, sizeof(*key));
    key->active = true;
    key->key_type = request->key_type;
    key->allowed_ops = request->allowed_ops;
    key->key_length = request->key_length;
    key->key_handle = state->next_key_handle++;
    response->handle = key->key_handle;
    return OK;
}

int fbvbs_iks_sign(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_sign_request *request,
    struct fbvbs_iks_sign_response *response
) {
    struct fbvbs_iks_key *key;

    if (state == NULL || request == NULL || response == NULL || request->hash_length != 48U ||
        request->reserved0 != 0U || !fbvbs_hash_tail_zero(request->hash)) {
        return INVALID_PARAMETER;
    }

    key = fbvbs_find_iks_key(state, request->key_handle);
    if (key == NULL) {
        return NOT_FOUND;
    }
    if ((key->allowed_ops & IKS_OP_SIGN) == 0U) {
        return PERMISSION_DENIED;
    }
    if (!fbvbs_iks_can_sign(key->key_type)) {
        return POLICY_DENIED;
    }

    fbvbs_zero_memory(response, sizeof(*response));
    response->signature_length = key->key_type == IKS_KEY_RSA3072 ? 384U : 64U;
    response->signature[0] = (uint8_t)key->key_type;
    response->signature[1] = request->hash[0];
    response->signature[response->signature_length - 1U] = request->hash[47];
    return OK;
}

int fbvbs_iks_key_exchange(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_key_exchange_request *request,
    struct fbvbs_handle_response *response
) {
    struct fbvbs_iks_key *key;
    struct fbvbs_iks_key *derived;

    if (state == NULL || request == NULL || response == NULL || request->peer_public_key_length == 0U ||
        request->peer_public_key_length > sizeof(request->peer_public_key) || request->derive_flags != 0U) {
        return INVALID_PARAMETER;
    }

    key = fbvbs_find_iks_key(state, request->key_handle);
    if (key == NULL) {
        return NOT_FOUND;
    }
    if ((key->allowed_ops & IKS_OP_KEY_EXCHANGE) == 0U) {
        return PERMISSION_DENIED;
    }
    if (!fbvbs_iks_can_exchange(key->key_type)) {
        return POLICY_DENIED;
    }

    derived = fbvbs_allocate_iks_key(state);
    if (derived == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    fbvbs_zero_memory(derived, sizeof(*derived));
    derived->active = true;
    derived->key_type = key->key_type;
    derived->allowed_ops = IKS_OP_DERIVE;
    derived->key_length = key->key_length;
    derived->key_handle = state->next_key_handle++;
    response->handle = derived->key_handle;
    return OK;
}

int fbvbs_iks_derive(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_iks_derive_request *request,
    struct fbvbs_handle_response *response
) {
    struct fbvbs_iks_key *key;
    struct fbvbs_iks_key *derived;

    if (state == NULL || request == NULL || response == NULL || request->parameter_length == 0U ||
        request->parameter_length > sizeof(request->params) || request->reserved0 != 0U) {
        return INVALID_PARAMETER;
    }

    key = fbvbs_find_iks_key(state, request->key_handle);
    if (key == NULL) {
        return NOT_FOUND;
    }
    if ((key->allowed_ops & IKS_OP_DERIVE) == 0U) {
        return PERMISSION_DENIED;
    }

    derived = fbvbs_allocate_iks_key(state);
    if (derived == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    fbvbs_zero_memory(derived, sizeof(*derived));
    derived->active = true;
    derived->key_type = key->key_type;
    derived->allowed_ops = key->allowed_ops;
    derived->key_length = key->key_length;
    derived->key_handle = state->next_key_handle++;
    response->handle = derived->key_handle;
    return OK;
}

int fbvbs_iks_destroy_key(
    struct fbvbs_hypervisor_state *state,
    uint64_t key_handle
) {
    struct fbvbs_iks_key *key;

    if (state == NULL || key_handle == 0U) {
        return INVALID_PARAMETER;
    }

    key = fbvbs_find_iks_key(state, key_handle);
    if (key == NULL) {
        return NOT_FOUND;
    }

    fbvbs_zero_memory(key, sizeof(*key));
    return OK;
}

int fbvbs_sks_import_dek(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_import_dek_request *request,
    struct fbvbs_handle_response *response
) {
    struct fbvbs_sks_dek *dek;

    if (state == NULL || request == NULL || response == NULL || request->key_material_page_gpa == 0U ||
        request->volume_id == 0U || request->reserved0 != 0U ||
        (request->key_length != 16U && request->key_length != 32U)) {
        return INVALID_PARAMETER;
    }

    dek = fbvbs_allocate_sks_dek(state);
    if (dek == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    fbvbs_zero_memory(dek, sizeof(*dek));
    dek->active = true;
    dek->key_length = request->key_length;
    dek->volume_id = request->volume_id;
    dek->dek_handle = state->next_dek_handle++;
    response->handle = dek->dek_handle;
    return OK;
}

static int fbvbs_sks_batch_common(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_batch_request *request,
    struct fbvbs_sks_batch_response *response
) {
    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->io_descriptor_page_gpa == 0U || request->descriptor_count == 0U ||
        request->descriptor_count > 128U || request->reserved0 != 0U ||
        (request->io_descriptor_page_gpa % FBVBS_PAGE_SIZE) != 0U) {
        return INVALID_PARAMETER;
    }
    if (fbvbs_find_sks_dek(state, request->dek_handle) == NULL) {
        return NOT_FOUND;
    }

    response->completed_count = request->descriptor_count;
    response->reserved0 = 0U;
    return OK;
}

int fbvbs_sks_decrypt_batch(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_batch_request *request,
    struct fbvbs_sks_batch_response *response
) {
    return fbvbs_sks_batch_common(state, request, response);
}

int fbvbs_sks_encrypt_batch(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_batch_request *request,
    struct fbvbs_sks_batch_response *response
) {
    return fbvbs_sks_batch_common(state, request, response);
}

int fbvbs_sks_destroy_dek(
    struct fbvbs_hypervisor_state *state,
    uint64_t dek_handle
) {
    struct fbvbs_sks_dek *dek;

    if (state == NULL || dek_handle == 0U) {
        return INVALID_PARAMETER;
    }

    dek = fbvbs_find_sks_dek(state, dek_handle);
    if (dek == NULL) {
        return NOT_FOUND;
    }

    fbvbs_zero_memory(dek, sizeof(*dek));
    return OK;
}

int fbvbs_uvs_verify_manifest_set(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_verify_manifest_set_request *request,
    struct fbvbs_uvs_verify_manifest_set_response *response
) {
    struct fbvbs_uvs_manifest_set *manifest_set;
    uint8_t snapshot_id[32];
    uint32_t failure_bitmap = 0U;
    int status;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    fbvbs_zero_memory(response, sizeof(*response));
    if (request->root_manifest_gpa == 0U || request->root_manifest_length == 0U ||
        request->root_manifest_length > FBVBS_PAGE_SIZE ||
        request->manifest_count == 0U || request->manifest_count > 64U ||
        request->manifest_set_page_gpa == 0U ||
        (request->manifest_set_page_gpa % FBVBS_PAGE_SIZE) != 0U) {
        return INVALID_PARAMETER;
    }
    if (request->manifest_count > FBVBS_MAX_METADATA_MANIFESTS) {
        return INVALID_PARAMETER;
    }

    status = fbvbs_validate_metadata_set(state, request, &failure_bitmap, snapshot_id);
    if (status != OK) {
        response->verdict = 0U;
        response->failure_bitmap = failure_bitmap;
        response->verified_manifest_set_id = 0U;
        return status;
    }

    manifest_set = fbvbs_allocate_manifest_set(state);
    if (manifest_set == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    fbvbs_zero_memory(manifest_set, sizeof(*manifest_set));
    manifest_set->active = true;
    manifest_set->manifest_count = request->manifest_count;
    manifest_set->failure_bitmap = 0U;
    manifest_set->root_manifest_gpa = request->root_manifest_gpa;
    manifest_set->manifest_set_page_gpa = request->manifest_set_page_gpa;
    manifest_set->verified_manifest_set_id = state->next_manifest_set_id++;
    fbvbs_copy_snapshot_id(manifest_set->snapshot_id, snapshot_id);
    response->verdict = 1U;
    response->failure_bitmap = 0U;
    response->verified_manifest_set_id = manifest_set->verified_manifest_set_id;
    return OK;
}

int fbvbs_uvs_verify_artifact(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_verify_artifact_request *request,
    struct fbvbs_verdict_response *response
) {
    uint64_t artifact_object_id;
    struct fbvbs_uvs_manifest_set *manifest_set;
    const struct fbvbs_metadata_manifest *manifest;
    int status;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (!fbvbs_hash_tail_zero(request->artifact_hash)) {
        return INVALID_PARAMETER;
    }
    manifest_set = fbvbs_find_manifest_set(state, request->verified_manifest_set_id);
    if (manifest_set == NULL) {
        return NOT_FOUND;
    }
    if (!fbvbs_artifact_exists(state, request->manifest_object_id, FBVBS_ARTIFACT_OBJECT_MANIFEST)) {
        return NOT_FOUND;
    }
    manifest = fbvbs_find_manifest_in_verified_set(manifest_set, request->manifest_object_id);
    if (manifest == NULL) {
        return NOT_FOUND;
    }
    if (!fbvbs_artifact_hash_matches_manifest(state, request->artifact_hash, request->manifest_object_id)) {
        return DEPENDENCY_UNSATISFIED;
    }
    artifact_object_id = fbvbs_find_artifact_object_for_hash(
        state,
        request->artifact_hash,
        request->manifest_object_id
    );
    if (artifact_object_id == 0U) {
        return DEPENDENCY_UNSATISFIED;
    }
    status = fbvbs_record_artifact_approval(
        state,
        request->verified_manifest_set_id,
        artifact_object_id,
        request->manifest_object_id,
        request->artifact_hash
    );
    if (status != OK) {
        return status;
    }

    response->verdict = 1U;
    response->reserved0 = 0U;
    return OK;
}

int fbvbs_uvs_check_revocation(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_check_revocation_request *request,
    struct fbvbs_uvs_check_revocation_response *response
) {
    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->object_id == 0U || request->object_type == 0U || request->reserved0 != 0U) {
        return INVALID_PARAMETER;
    }
    if (!fbvbs_artifact_exists(state, request->object_id, FBVBS_ARTIFACT_OBJECT_IMAGE) &&
        !fbvbs_artifact_exists(state, request->object_id, FBVBS_ARTIFACT_OBJECT_MANIFEST) &&
        !fbvbs_artifact_exists(state, request->object_id, FBVBS_ARTIFACT_OBJECT_MODULE) &&
        fbvbs_find_iks_key(state, request->object_id) == NULL &&
        fbvbs_find_sks_dek(state, request->object_id) == NULL) {
        return NOT_FOUND;
    }

    response->revoked = fbvbs_is_object_revoked(state, request->object_id) ? 1U : 0U;
    response->reserved0 = 0U;
    return OK;
}
