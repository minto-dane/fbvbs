#include "fbvbs_hypervisor.h"

/*@ requires \valid_read(state);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_artifact_exists(
    const struct fbvbs_hypervisor_state *state,
    uint64_t object_id,
    uint32_t expected_kind
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= state->artifact_catalog.count;
        loop assigns index;
        loop variant state->artifact_catalog.count - index;
    */
    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &state->artifact_catalog.entries[index];

        if (entry->object_id == object_id && entry->object_kind == expected_kind) {
            return 1;
        }
    }

    return 0;
}

/*@ requires \valid_read(state);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns \result \from object_id, state->artifact_catalog.count,
            state->artifact_catalog.entries[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1];
    ensures \result == \null || \valid_read(\result);
    ensures \result != \null ==> \result->object_id == object_id;
    ensures \result != \null ==> \exists integer i;
            0 <= i < state->artifact_catalog.count &&
            \result == &state->artifact_catalog.entries[i];
*/
static const struct fbvbs_artifact_catalog_entry *fbvbs_find_artifact_entry(
    const struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= state->artifact_catalog.count;
        loop assigns index;
        loop variant state->artifact_catalog.count - index;
    */
    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        if (state->artifact_catalog.entries[index].object_id == object_id) {
            return &state->artifact_catalog.entries[index];
        }
    }

    return NULL;
}

/*@ requires \valid_read(state);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    requires ((const struct fbvbs_artifact_catalog_entry *)state->artifact_catalog.entries) <= entry <
             ((const struct fbvbs_artifact_catalog_entry *)state->artifact_catalog.entries) + state->artifact_catalog.count;
    assigns \result \from entry;
*/
static uint32_t fbvbs_artifact_entry_index(
    const struct fbvbs_hypervisor_state *state,
    const struct fbvbs_artifact_catalog_entry *entry
) {
    return (uint32_t)(entry - state->artifact_catalog.entries);
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_page_aligned_range(uint64_t guest_physical_address, uint64_t size) {
    return guest_physical_address != 0U &&
        size != 0U &&
        (guest_physical_address % FBVBS_PAGE_SIZE) == 0U &&
        (size % FBVBS_PAGE_SIZE) == 0U;
}

/*@ requires \valid_read(state);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
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

/*@ requires \valid_read(hash + (0 .. 63));
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_hash_tail_zero(const uint8_t hash[64]) {
    uint32_t index;

    /*@ loop invariant 48 <= index <= 64;
        loop assigns index;
        loop variant 64 - index;
    */
    for (index = 48U; index < 64U; ++index) {
        if (hash[index] != 0U) {
            return 0;
        }
    }

    return 1;
}

/*@ requires \valid(destination + (0 .. 47));
    requires \valid_read(source + (0 .. 63));
    assigns destination[0 .. 47];
*/
static void fbvbs_copy_artifact_hash_prefix(uint8_t destination[48], const uint8_t source[64]) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 48;
        loop assigns index, destination[0 .. 47];
        loop variant 48 - index;
    */
    for (index = 0U; index < 48U; ++index) {
        destination[index] = source[index];
    }
}

/*@ requires \valid(approval);
    requires \valid_read(artifact_hash + (0 .. 63));
    assigns *approval;
    ensures approval->active;
    ensures approval->verified_manifest_set_id == verified_manifest_set_id;
    ensures approval->artifact_object_id == artifact_object_id;
    ensures approval->manifest_object_id == manifest_object_id;
*/
static void fbvbs_store_artifact_approval(
    struct fbvbs_uvs_artifact_approval *approval,
    uint64_t verified_manifest_set_id,
    uint64_t artifact_object_id,
    uint64_t manifest_object_id,
    const uint8_t artifact_hash[64]
) {
    *approval = (struct fbvbs_uvs_artifact_approval){0};
    approval->active = true;
    approval->verified_manifest_set_id = verified_manifest_set_id;
    approval->artifact_object_id = artifact_object_id;
    approval->manifest_object_id = manifest_object_id;
    fbvbs_copy_artifact_hash_prefix(approval->artifact_hash, artifact_hash);
}

/*@ requires \valid_read(state);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    requires \valid_read(artifact_hash + (0 .. 63));
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
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

    /*@ loop invariant 0 <= index <= state->artifact_catalog.count;
        loop assigns index;
        loop variant state->artifact_catalog.count - index;
    */
    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &state->artifact_catalog.entries[index];
        uint32_t hash_index;
        int equal = 1;

        if (entry->object_kind == FBVBS_ARTIFACT_OBJECT_MANIFEST ||
            entry->related_index != manifest_index) {
            continue;
        }

        /*@ loop invariant 0 <= hash_index <= 48;
            loop assigns hash_index, equal;
            loop variant 48 - hash_index;
        */
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

/*@ requires \valid_read(state);
    requires state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    requires \valid_read(artifact_hash + (0 .. 63));
    assigns \nothing;
    ensures \result == 0U || \result >= 1U;
*/
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

    /*@ loop invariant 0 <= index <= state->artifact_catalog.count;
        loop assigns index;
        loop variant state->artifact_catalog.count - index;
    */
    for (index = 0U; index < state->artifact_catalog.count; ++index) {
        const struct fbvbs_artifact_catalog_entry *entry = &state->artifact_catalog.entries[index];
        uint32_t hash_index;
        int equal = 1;

        if (entry->object_kind == FBVBS_ARTIFACT_OBJECT_MANIFEST ||
            entry->related_index != manifest_index) {
            continue;
        }

        /*@ loop invariant 0 <= hash_index <= 48;
            loop assigns hash_index, equal;
            loop variant 48 - hash_index;
        */
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

/*@ requires \valid(state);
    requires \valid_read(artifact_hash + (0 .. 63));
    assigns state->approvals[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1];
    ensures \result == OK || \result == INTERNAL_CORRUPTION;
*/
static int fbvbs_record_artifact_approval(
    struct fbvbs_hypervisor_state *state,
    uint64_t verified_manifest_set_id,
    uint64_t artifact_object_id,
    uint64_t manifest_object_id,
    const uint8_t artifact_hash[64]
) {
    uint32_t index;
    uint32_t free_index = FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
        loop invariant free_index == FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES || free_index < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
        loop assigns index, free_index, state->approvals[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1];
        loop variant FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - index;
    */
    for (index = 0U; index < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; ++index) {
        struct fbvbs_uvs_artifact_approval *approval = &state->approvals[index];

        if (!approval->active) {
            if (free_index == FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES) {
                free_index = index;
            }
            continue;
        }
        if (approval->artifact_object_id == artifact_object_id &&
            approval->manifest_object_id == manifest_object_id) {
            fbvbs_store_artifact_approval(
                approval,
                verified_manifest_set_id,
                artifact_object_id,
                manifest_object_id,
                artifact_hash
            );
            return OK;
        }
    }

    if (free_index == FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES) {
        return INTERNAL_CORRUPTION;
    }

    fbvbs_store_artifact_approval(
        &state->approvals[free_index],
        verified_manifest_set_id,
        artifact_object_id,
        manifest_object_id,
        artifact_hash
    );
    return OK;
}

/*@ requires \valid_read(state) || state == \null;
    assigns \nothing;
    behavior invalid_args:
      assumes state == \null || artifact_object_id == 0U || manifest_object_id == 0U;
      ensures \result == 0;
    behavior valid_args:
      assumes state != \null && artifact_object_id != 0U && manifest_object_id != 0U;
      ensures \result == 0 || \result == 1;
    complete behaviors;
    disjoint behaviors;
*/
int fbvbs_artifact_approval_exists(
    const struct fbvbs_hypervisor_state *state,
    uint64_t artifact_object_id,
    uint64_t manifest_object_id
) {
    uint32_t index;

    if (state == NULL || artifact_object_id == 0U || manifest_object_id == 0U) {
        return 0;
    }

    /* Check if artifact is revoked */
    if (fbvbs_is_object_revoked(state, artifact_object_id)) {
        return 0;
    }

    /* Check if manifest is revoked */
    if (fbvbs_is_object_revoked(state, manifest_object_id)) {
        return 0;
    }

    /*@ loop invariant 0 <= index <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
        loop assigns index;
        loop variant FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - index;
    */
    for (index = 0U; index < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES; ++index) {
        const struct fbvbs_uvs_artifact_approval *approval = &state->approvals[index];

        if (approval->active &&
            approval->artifact_object_id == artifact_object_id &&
            approval->manifest_object_id == manifest_object_id &&
            approval->manifest_set_id == state->current_manifest_set_id) {
            return 1;
        }
    }

    return 0;
}

/*@ requires manifest_set_page_gpa == 0U ||
             \valid_read((const struct fbvbs_metadata_set_page *)(uintptr_t)manifest_set_page_gpa);
    assigns \result \from manifest_set_page_gpa;
    ensures \result == (const struct fbvbs_metadata_set_page *)(uintptr_t)manifest_set_page_gpa;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_metadata_set_page *fbvbs_metadata_set_page_from_gpa(
    uint64_t manifest_set_page_gpa
) {
    return (const struct fbvbs_metadata_set_page *)(uintptr_t)manifest_set_page_gpa;
}

/*@ requires manifest_gpa == 0U ||
             \valid_read((const struct fbvbs_metadata_manifest *)(uintptr_t)manifest_gpa);
    assigns \result \from manifest_gpa;
    ensures \result == (const struct fbvbs_metadata_manifest *)(uintptr_t)manifest_gpa;
    ensures \result == \null || \valid_read(\result);
*/
static const struct fbvbs_metadata_manifest *fbvbs_manifest_from_gpa(uint64_t manifest_gpa) {
    return (const struct fbvbs_metadata_manifest *)(uintptr_t)manifest_gpa;
}

/*@ predicate fbvbs_valid_metadata_manifest_gpa(uint64_t manifest_gpa) =
      manifest_gpa == 0U ||
      \valid_read((const struct fbvbs_metadata_manifest *)(uintptr_t)manifest_gpa);

    predicate fbvbs_valid_metadata_manifest_gpa_array(uint64_t *manifest_gpas, integer count) =
      \valid_read(manifest_gpas + (0 .. FBVBS_MAX_METADATA_MANIFESTS - 1)) &&
      0 <= count && count <= FBVBS_MAX_METADATA_MANIFESTS &&
      (\forall integer i; 0 <= i < count ==>
          fbvbs_valid_metadata_manifest_gpa(manifest_gpas[i]));

    predicate fbvbs_valid_metadata_set_page_view(struct fbvbs_metadata_set_page *page, integer count) =
      \valid_read(page) &&
      fbvbs_valid_metadata_manifest_gpa_array((uint64_t *)page->manifest_gpas, count);

    predicate fbvbs_valid_uvs_request_view(struct fbvbs_uvs_verify_manifest_set_request *request) =
      \valid_read(request) &&
      0 < request->manifest_count && request->manifest_count <= FBVBS_MAX_METADATA_MANIFESTS &&
      request->manifest_set_page_gpa != 0U &&
      fbvbs_valid_metadata_set_page_view(
          (struct fbvbs_metadata_set_page *)(uintptr_t)request->manifest_set_page_gpa,
          request->manifest_count
      );

    predicate fbvbs_valid_verified_manifest_set(struct fbvbs_uvs_manifest_set *manifest_set) =
      manifest_set == \null ||
      (\valid_read(manifest_set) &&
       manifest_set->manifest_count <= FBVBS_MAX_METADATA_MANIFESTS &&
       manifest_set->manifest_set_page_gpa != 0U &&
       fbvbs_valid_metadata_set_page_view(
           (struct fbvbs_metadata_set_page *)(uintptr_t)manifest_set->manifest_set_page_gpa,
           manifest_set->manifest_count
       ));

    lemma fbvbs_manifest_valid_from_forall:
      \forall struct fbvbs_metadata_set_page *page, integer count, integer index;
        (\forall integer i; 0 <= i < count ==> fbvbs_valid_metadata_manifest_gpa(page->manifest_gpas[i])) &&
        0 <= index < count ==>
        fbvbs_valid_metadata_manifest_gpa(page->manifest_gpas[index]);

    lemma fbvbs_manifest_array_valid_from_forall:
      \forall uint64_t *manifest_gpas, integer count, integer index;
        (\forall integer i; 0 <= i < count ==> fbvbs_valid_metadata_manifest_gpa(manifest_gpas[i])) &&
        0 <= index < count ==>
        fbvbs_valid_metadata_manifest_gpa(manifest_gpas[index]);

    lemma fbvbs_uvs_request_view_from_nonnull_disjunction:
      \forall struct fbvbs_uvs_verify_manifest_set_request *request;
        request != \null && (request == \null || fbvbs_valid_uvs_request_view(request)) ==>
        fbvbs_valid_uvs_request_view(request);
*/

/*@ requires \valid(destination + (0 .. 31));
    requires \valid_read(source + (0 .. 31));
    assigns destination[0 .. 31];
*/
static void fbvbs_copy_snapshot_id(uint8_t destination[32], const uint8_t source[32]) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 32;
        loop assigns index, destination[0 .. 31];
        loop variant 32 - index;
    */
    for (index = 0U; index < 32U; ++index) {
        destination[index] = source[index];
    }
}

/*@ requires \valid_read(left + (0 .. 31));
    requires \valid_read(right + (0 .. 31));
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_snapshot_ids_equal(const uint8_t left[32], const uint8_t right[32]) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 32;
        loop assigns index;
        loop variant 32 - index;
    */
    for (index = 0U; index < 32U; ++index) {
        if (left[index] != right[index]) {
            return 0;
        }
    }

    return 1;
}

/*@ assigns \result \from role;
*/
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

/*@ requires fbvbs_valid_metadata_manifest_gpa_array((uint64_t *)manifest_gpas, count);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_metadata_manifest_array_contains_object_id(
    const uint64_t manifest_gpas[FBVBS_MAX_METADATA_MANIFESTS],
    uint32_t count,
    uint64_t object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= count;
        loop assigns index;
        loop variant count - index;
    */
    for (index = 0U; index < count; ++index) {
        const struct fbvbs_metadata_manifest *manifest = fbvbs_manifest_from_gpa(manifest_gpas[index]);

        if (manifest != NULL && manifest->object_id == object_id) {
            return 1;
        }
    }

    return 0;
}

/*@ requires fbvbs_valid_verified_manifest_set(manifest_set);
    assigns \result \from manifest_set, manifest_object_id;
    ensures \result == \null || \valid_read(\result);
*/
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

    /*@ loop invariant 0 <= index <= manifest_set->manifest_count;
        loop assigns index;
        loop variant manifest_set->manifest_count - index;
    */
    for (index = 0U; index < manifest_set->manifest_count; ++index) {
        const struct fbvbs_metadata_manifest *manifest = fbvbs_manifest_from_gpa(page->manifest_gpas[index]);

        if (manifest != NULL && manifest->object_id == manifest_object_id) {
            return manifest;
        }
    }

    return NULL;
}

/*@ requires \valid(state) || state == \null;
    requires state == \null || state->revoked_object_count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns state->revoked_object_ids[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1], state->revoked_object_count;
*/
static void fbvbs_record_revoked_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    if (state == NULL || object_id == 0U) {
        return;
    }
    /*@ loop invariant 0 <= index <= state->revoked_object_count;
        loop assigns index;
        loop variant state->revoked_object_count - index;
    */
    for (index = 0U; index < state->revoked_object_count; ++index) {
        if (state->revoked_object_ids[index] == object_id) {
            return;
        }
    }
    if (state->revoked_object_count < FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES) {
        state->revoked_object_ids[state->revoked_object_count++] = object_id;
    }
}

/*@ requires \valid_read(state);
    requires state->revoked_object_count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_is_object_revoked(
    const struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= state->revoked_object_count;
        loop assigns index;
        loop variant state->revoked_object_count - index;
    */
    for (index = 0U; index < state->revoked_object_count; ++index) {
        if (state->revoked_object_ids[index] == object_id) {
            return 1;
        }
    }
    return 0;
}

/*@ assigns \nothing;
    ensures \result == OK || \result == SIGNATURE_INVALID || \result == REVOKED ||
            \result == GENERATION_MISMATCH || \result == ROLLBACK_DETECTED ||
            \result == DEPENDENCY_UNSATISFIED || \result == SNAPSHOT_INCONSISTENT ||
            \result == FRESHNESS_FAILED;
*/
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

/*@ requires \valid(state);
    requires \valid(failure_bitmap);
    requires \valid(snapshot_id + (0 .. 31));
    requires \valid(role_mask);
    requires manifest == \null || \valid_read(manifest);
    assigns *failure_bitmap, snapshot_id[0 .. 31],
            state->revoked_object_ids[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1],
            state->revoked_object_count, *role_mask;
*/
static void fbvbs_process_metadata_manifest(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_metadata_manifest *manifest,
    uint32_t index,
    uint64_t freshness_window_end,
    uint32_t *failure_bitmap,
    uint8_t snapshot_id[32],
    uint32_t *role_mask
) {
    uint32_t role_bit;

    if (manifest == NULL || manifest->object_id == 0U) {
        *failure_bitmap |= FBVBS_UVS_FAILURE_SIGNATURE;
        return;
    }
    if ((manifest->flags & FBVBS_METADATA_FLAG_SIGNATURE_VALID) == 0U) {
        *failure_bitmap |= FBVBS_UVS_FAILURE_SIGNATURE;
    }
    if ((manifest->flags & FBVBS_METADATA_FLAG_REVOKED) != 0U) {
        *failure_bitmap |= FBVBS_UVS_FAILURE_REVOCATION;
        if (state->revoked_object_count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES) {
            fbvbs_record_revoked_object(state, manifest->object_id);
        }
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
    if (role_bit == 0U || (*role_mask & role_bit) != 0U) {
        *failure_bitmap |= FBVBS_UVS_FAILURE_SNAPSHOT;
    } else {
        *role_mask |= role_bit;
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

/*@ requires fbvbs_valid_metadata_manifest_gpa_array((uint64_t *)manifest_gpas, count);
    requires \valid(failure_bitmap);
    requires manifest == \null || \valid_read(manifest);
    assigns *failure_bitmap;
*/
static void fbvbs_check_manifest_dependency(
    const uint64_t manifest_gpas[FBVBS_MAX_METADATA_MANIFESTS],
    uint32_t count,
    const struct fbvbs_metadata_manifest *manifest,
    uint32_t *failure_bitmap
) {
    if (manifest != NULL && manifest->dependency_object_id != 0U &&
        !fbvbs_metadata_manifest_array_contains_object_id(manifest_gpas, count, manifest->dependency_object_id)) {
        *failure_bitmap |= FBVBS_UVS_FAILURE_DEPENDENCY;
    }
}

/*@ requires fbvbs_valid_metadata_set_page_view(page, count);
    assigns \nothing;
    ensures \valid_read(page);
    ensures count <= FBVBS_MAX_METADATA_MANIFESTS;
    ensures \forall integer i; 0 <= i < count ==>
                fbvbs_valid_metadata_manifest_gpa(page->manifest_gpas[i]);
*/
static void fbvbs_require_valid_metadata_set_page_view(
    const struct fbvbs_metadata_set_page *page,
    uint32_t count
) {
    (void)page;
    (void)count;
}

/*@ requires fbvbs_valid_metadata_manifest_gpa_array((uint64_t *)manifest_gpas, count);
    requires index < count;
    assigns \nothing;
    ensures fbvbs_valid_metadata_manifest_gpa(manifest_gpas[index]);
*/
static void fbvbs_require_valid_metadata_manifest_slot(
    const uint64_t manifest_gpas[FBVBS_MAX_METADATA_MANIFESTS],
    uint32_t count,
    uint32_t index
) {
    (void)manifest_gpas;
    (void)count;
    (void)index;
}

/*@ requires fbvbs_valid_metadata_set_page_view(page, count);
    requires \valid(snapshot + (0 .. FBVBS_MAX_METADATA_MANIFESTS - 1));
    requires \forall integer i; 0 <= i < count ==> snapshot[i] == page->manifest_gpas[i];
    assigns \nothing;
    ensures fbvbs_valid_metadata_manifest_gpa_array(snapshot, count);
*/
static void fbvbs_require_valid_manifest_snapshot(
    const struct fbvbs_metadata_set_page *page,
    uint32_t count,
    uint64_t snapshot[FBVBS_MAX_METADATA_MANIFESTS]
) {
    (void)page;
    (void)count;
    (void)snapshot;
}

/*@ requires \valid(state);
    requires fbvbs_valid_metadata_manifest_gpa_array((uint64_t *)manifest_gpas, count);
    requires \valid(failure_bitmap);
    requires \valid(snapshot_id + (0 .. 31));
    requires \valid(role_mask);
    requires \separated(manifest_gpas + (0 .. FBVBS_MAX_METADATA_MANIFESTS - 1),
                        failure_bitmap, snapshot_id + (0 .. 31), role_mask,
                        state->revoked_object_ids + (0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1),
                        &state->revoked_object_count);
    assigns *failure_bitmap, snapshot_id[0 .. 31],
            state->revoked_object_ids[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1],
            state->revoked_object_count, *role_mask;
    ensures fbvbs_valid_metadata_manifest_gpa_array((uint64_t *)manifest_gpas, count);
*/
static void fbvbs_scan_metadata_manifests(
    struct fbvbs_hypervisor_state *state,
    const uint64_t manifest_gpas[FBVBS_MAX_METADATA_MANIFESTS],
    uint32_t count,
    uint64_t freshness_window_end,
    uint32_t *failure_bitmap,
    uint8_t snapshot_id[32],
    uint32_t *role_mask
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= count;
        loop invariant fbvbs_valid_metadata_manifest_gpa_array((uint64_t *)manifest_gpas, count);
        loop assigns index, *failure_bitmap, snapshot_id[0 .. 31],
                     state->revoked_object_ids[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1],
                     state->revoked_object_count, *role_mask;
        loop variant count - index;
    */
    for (index = 0U; index < count; ++index) {
        fbvbs_require_valid_metadata_manifest_slot(manifest_gpas, count, index);
        const struct fbvbs_metadata_manifest *manifest = fbvbs_manifest_from_gpa(manifest_gpas[index]);

        fbvbs_process_metadata_manifest(
            state,
            manifest,
            index,
            freshness_window_end,
            failure_bitmap,
            snapshot_id,
            role_mask
        );
    }
}

/*@ requires fbvbs_valid_metadata_manifest_gpa_array((uint64_t *)manifest_gpas, count);
    requires \valid(failure_bitmap);
    requires \separated(manifest_gpas + (0 .. FBVBS_MAX_METADATA_MANIFESTS - 1), failure_bitmap);
    assigns *failure_bitmap;
*/
static void fbvbs_scan_manifest_dependencies(
    const uint64_t manifest_gpas[FBVBS_MAX_METADATA_MANIFESTS],
    uint32_t count,
    uint32_t *failure_bitmap
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= count;
        loop assigns index, *failure_bitmap;
        loop variant count - index;
    */
    for (index = 0U; index < count; ++index) {
        fbvbs_require_valid_metadata_manifest_slot(manifest_gpas, count, index);
        const struct fbvbs_metadata_manifest *manifest = fbvbs_manifest_from_gpa(manifest_gpas[index]);

        fbvbs_check_manifest_dependency(manifest_gpas, count, manifest, failure_bitmap);
    }
}

/*@ requires \valid(state);
    requires \valid_read(request);
    requires \valid(failure_bitmap);
    requires \valid(snapshot_id + (0 .. 31));
    requires fbvbs_valid_uvs_request_view(request);
    assigns *failure_bitmap, snapshot_id[0 .. 31],
            state->revoked_object_ids[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1],
            state->revoked_object_count
        \from *state, *request;
*/
static int fbvbs_validate_metadata_set(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_verify_manifest_set_request *request,
    uint32_t *failure_bitmap,
    uint8_t snapshot_id[32]
) {
    const struct fbvbs_metadata_set_page *page =
        fbvbs_metadata_set_page_from_gpa(request->manifest_set_page_gpa);
    uint64_t manifest_gpas[FBVBS_MAX_METADATA_MANIFESTS];
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
    /*@ assert fbvbs_valid_metadata_set_page_view(page, request->manifest_count); */
    fbvbs_require_valid_metadata_set_page_view(page, request->manifest_count);
    /*@ loop invariant 0 <= index <= FBVBS_MAX_METADATA_MANIFESTS;
        loop invariant \forall integer j; 0 <= j < index ==> manifest_gpas[j] == 0U;
        loop assigns index, manifest_gpas[0 .. FBVBS_MAX_METADATA_MANIFESTS - 1];
        loop variant FBVBS_MAX_METADATA_MANIFESTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_METADATA_MANIFESTS; ++index) {
        manifest_gpas[index] = 0U;
    }
    /*@ loop invariant 0 <= index <= request->manifest_count;
        loop invariant request->manifest_count <= FBVBS_MAX_METADATA_MANIFESTS;
        loop invariant \forall integer j; 0 <= j < index ==> manifest_gpas[j] == page->manifest_gpas[j];
        loop invariant \forall integer j; request->manifest_count <= j < FBVBS_MAX_METADATA_MANIFESTS ==> manifest_gpas[j] == 0U;
        loop assigns index, manifest_gpas[0 .. FBVBS_MAX_METADATA_MANIFESTS - 1];
        loop variant request->manifest_count - index;
    */
    for (index = 0U; index < request->manifest_count; ++index) {
        manifest_gpas[index] = page->manifest_gpas[index];
    }
    fbvbs_require_valid_manifest_snapshot(page, request->manifest_count, manifest_gpas);
    freshness_window_end = state->trusted_time_seconds + 300U;
    fbvbs_scan_metadata_manifests(
        state,
        manifest_gpas,
        request->manifest_count,
        freshness_window_end,
        failure_bitmap,
        snapshot_id,
        &role_mask
    );
    fbvbs_scan_manifest_dependencies(manifest_gpas, request->manifest_count, failure_bitmap);
    if (role_mask != 0x1FU) {
        *failure_bitmap |= FBVBS_UVS_FAILURE_SNAPSHOT;
    }

    return fbvbs_status_from_uvs_failure_bitmap(*failure_bitmap);
}

/*@ requires \valid(state);
    assigns \result \from target_set_id, state->ksi_target_sets[0 .. 7];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < 8 && \result == &state->ksi_target_sets[i]);
*/
static struct fbvbs_ksi_target_set *fbvbs_find_target_set(
    struct fbvbs_hypervisor_state *state,
    uint64_t target_set_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 8;
        loop assigns index;
        loop variant 8 - index;
    */
    for (index = 0U; index < 8U; ++index) {
        if (state->ksi_target_sets[index].active &&
            state->ksi_target_sets[index].target_set_id == target_set_id) {
            return &state->ksi_target_sets[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns \result \from state->ksi_target_sets[0 .. 7];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < 8 && \result == &state->ksi_target_sets[i]);
*/
static struct fbvbs_ksi_target_set *fbvbs_allocate_target_set(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 8;
        loop assigns index;
        loop variant 8 - index;
    */
    for (index = 0U; index < 8U; ++index) {
        if (!state->ksi_target_sets[index].active) {
            return &state->ksi_target_sets[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns \result \from object_id, state->ksi_objects[0 .. 15];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < 16 && \result == &state->ksi_objects[i]);
*/
static struct fbvbs_ksi_object *fbvbs_find_ksi_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 16;
        loop assigns index;
        loop variant 16 - index;
    */
    for (index = 0U; index < 16U; ++index) {
        if (state->ksi_objects[index].active && state->ksi_objects[index].object_id == object_id) {
            return &state->ksi_objects[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns \result \from state->ksi_objects[0 .. 15];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < 16 && \result == &state->ksi_objects[i]);
*/
static struct fbvbs_ksi_object *fbvbs_allocate_ksi_object(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 16;
        loop assigns index;
        loop variant 16 - index;
    */
    for (index = 0U; index < 16U; ++index) {
        if (!state->ksi_objects[index].active) {
            return &state->ksi_objects[index];
        }
    }

    return NULL;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_ksi_class_valid(uint32_t protection_class) {
    return protection_class >= KSI_CLASS_UCRED && protection_class <= KSI_CLASS_P_TEXTVP;
}

/*@ requires \valid_read(target_set);
    requires target_set->target_count <= 8U;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_target_set_contains_object(
    const struct fbvbs_ksi_target_set *target_set,
    uint64_t object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= target_set->target_count;
        loop assigns index;
        loop variant target_set->target_count - index;
    */
    for (index = 0U; index < target_set->target_count; ++index) {
        if (target_set->target_object_ids[index] == object_id) {
            return 1;
        }
    }

    return 0;
}

/*@ requires \valid(state);
    requires \valid_read(target_set);
    requires target_set->target_count <= 8U;
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_target_set_has_registered_target(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_ksi_target_set *target_set
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= target_set->target_count;
        loop assigns index;
        loop variant target_set->target_count - index;
    */
    for (index = 0U; index < target_set->target_count; ++index) {
        if (fbvbs_find_ksi_object(state, target_set->target_object_ids[index]) != NULL) {
            return 1;
        }
    }

    return 0;
}

/*@ requires \valid(state);
    assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_any_target_set_references_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t object_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 8;
        loop assigns index;
        loop variant 8 - index;
    */
    for (index = 0U; index < 8U; ++index) {
        if (state->ksi_target_sets[index].active &&
            state->ksi_target_sets[index].target_count <= 8U &&
            fbvbs_target_set_contains_object(&state->ksi_target_sets[index], object_id)) {
            return 1;
        }
    }

    return 0;
}

/*@ requires \valid(state);
    assigns \result \from key_handle, state->iks_keys[0 .. 15];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < 16 && \result == &state->iks_keys[i]);
*/
static struct fbvbs_iks_key *fbvbs_find_iks_key(
    struct fbvbs_hypervisor_state *state,
    uint64_t key_handle
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 16;
        loop assigns index;
        loop variant 16 - index;
    */
    for (index = 0U; index < 16U; ++index) {
        if (state->iks_keys[index].active && state->iks_keys[index].key_handle == key_handle) {
            return &state->iks_keys[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns \result \from state->iks_keys[0 .. 15];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < 16 && \result == &state->iks_keys[i]);
*/
static struct fbvbs_iks_key *fbvbs_allocate_iks_key(struct fbvbs_hypervisor_state *state) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 16;
        loop assigns index;
        loop variant 16 - index;
    */
    for (index = 0U; index < 16U; ++index) {
        if (!state->iks_keys[index].active) {
            return &state->iks_keys[index];
        }
    }

    return NULL;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_iks_key_type_valid(uint32_t key_type) {
    return key_type >= IKS_KEY_ED25519 && key_type <= IKS_KEY_ECDH_P256;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_iks_can_sign(uint32_t key_type) {
    return key_type == IKS_KEY_ED25519 ||
        key_type == IKS_KEY_ECDSA_P256 ||
        key_type == IKS_KEY_RSA3072;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
static int fbvbs_iks_can_exchange(uint32_t key_type) {
    return key_type == IKS_KEY_X25519 || key_type == IKS_KEY_ECDH_P256;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1;
*/
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

/*@ requires \valid(state);
    assigns \result \from dek_handle, state->sks_deks[0 .. 15];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < 16 && \result == &state->sks_deks[i]);
*/
static struct fbvbs_sks_dek *fbvbs_find_sks_dek(
    struct fbvbs_hypervisor_state *state,
    uint64_t dek_handle
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 16;
        loop assigns index;
        loop variant 16 - index;
    */
    for (index = 0U; index < 16U; ++index) {
        if (state->sks_deks[index].active && state->sks_deks[index].dek_handle == dek_handle) {
            return &state->sks_deks[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns \result \from state->sks_deks[0 .. 15];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < 16 && \result == &state->sks_deks[i]);
*/
static struct fbvbs_sks_dek *fbvbs_allocate_sks_dek(struct fbvbs_hypervisor_state *state) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 16;
        loop assigns index;
        loop variant 16 - index;
    */
    for (index = 0U; index < 16U; ++index) {
        if (!state->sks_deks[index].active) {
            return &state->sks_deks[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns \result \from manifest_set_id, state->manifest_sets[0 .. 7];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < 8 && \result == &state->manifest_sets[i]);
    ensures \result == \null || \result->active;
*/
static struct fbvbs_uvs_manifest_set *fbvbs_find_manifest_set(
    struct fbvbs_hypervisor_state *state,
    uint64_t manifest_set_id
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 8;
        loop assigns index;
        loop variant 8 - index;
    */
    for (index = 0U; index < 8U; ++index) {
        if (state->manifest_sets[index].active &&
            state->manifest_sets[index].verified_manifest_set_id == manifest_set_id) {
            return &state->manifest_sets[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    assigns \result \from state->manifest_sets[0 .. 7];
    ensures \result == \null ||
            (\exists integer i; 0 <= i < 8 && \result == &state->manifest_sets[i]);
*/
static struct fbvbs_uvs_manifest_set *fbvbs_allocate_manifest_set(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= 8;
        loop assigns index;
        loop variant 8 - index;
    */
    for (index = 0U; index < 8U; ++index) {
        if (!state->manifest_sets[index].active) {
            return &state->manifest_sets[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    requires state == \null || state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns *state, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == GENERATION_MISMATCH ||
            \result == NOT_FOUND || \result == SIGNATURE_INVALID;
    behavior invalid_args:
      assumes state == \null || request == \null || response == \null;
      ensures \result == INVALID_PARAMETER;
*/
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns *state;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == INVALID_STATE ||
            \result == PERMISSION_DENIED;
    behavior invalid_args:
      assumes state == \null || request == \null;
      ensures \result == INVALID_PARAMETER;
*/
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns *state;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_SUPPORTED_ON_PLATFORM;
    behavior invalid_args:
      assumes state == \null || request == \null;
      ensures \result == INVALID_PARAMETER;
*/
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires state == \null || state->intercepted_msr_count <= 16U;
    assigns *state;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == PERMISSION_DENIED ||
            \result == RESOURCE_EXHAUSTED;
    behavior invalid_args:
      assumes state == \null || request == \null;
      ensures \result == INVALID_PARAMETER;
*/
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

    /*@ loop invariant 0 <= index <= state->intercepted_msr_count;
        loop invariant state->intercepted_msr_count <= 16U;
        loop assigns index, state->intercepted_msrs[0 .. 15], state->intercepted_msr_count;
        loop variant state->intercepted_msr_count - index;
    */
    for (index = 0U; index < state->intercepted_msr_count; ++index) {
        if (state->intercepted_msrs[index] == request->msr_address) {
            if (request->enable == 0U) {
                uint32_t tail;

                /*@ loop invariant index + 1 <= tail <= state->intercepted_msr_count;
                    loop invariant state->intercepted_msr_count <= 16U;
                    loop assigns tail, state->intercepted_msrs[0 .. 15];
                    loop variant state->intercepted_msr_count - tail;
                */
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns state->ksi_target_sets[0 .. 7], state->next_target_set_id, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == RESOURCE_EXHAUSTED ||
            \result == ALREADY_EXISTS;
*/
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

    *target_set = (struct fbvbs_ksi_target_set){0};
    target_set->active = true;
    target_set->target_count = request->target_count;
    target_set->target_set_id = state->next_target_set_id++;
    /*@ loop invariant 0 <= index <= request->target_count;
        loop invariant index <= 8U;
        loop assigns index, target_set->target_object_ids[0 .. 7], *target_set;
        loop variant 8U - index;
    */
    for (index = 0U; index < request->target_count && index < 8U; ++index) {
        uint32_t compare;

        if (request->target_object_ids[index] == 0U) {
            *target_set = (struct fbvbs_ksi_target_set){0};
            return INVALID_PARAMETER;
        }
        /*@ loop invariant 0 <= compare <= index;
            loop assigns compare;
            loop variant index - compare;
        */
        for (compare = 0U; compare < index; ++compare) {
            if (request->target_object_ids[compare] == request->target_object_ids[index]) {
                *target_set = (struct fbvbs_ksi_target_set){0};
                return ALREADY_EXISTS;
            }
        }
        target_set->target_object_ids[index] = request->target_object_ids[index];
    }
    response->target_set_id = target_set->target_set_id;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns state->ksi_objects[0 .. 15];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == ALREADY_EXISTS ||
            \result == RESOURCE_EXHAUSTED;
*/
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

    *object = (struct fbvbs_ksi_object){0};
    object->active = true;
    object->object_id = request->object_id;
    object->guest_physical_address = request->guest_physical_address;
    object->size = request->size;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns state->ksi_objects[0 .. 15];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == ALREADY_EXISTS ||
            \result == RESOURCE_EXHAUSTED;
*/
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

    *object = (struct fbvbs_ksi_object){0};
    object->active = true;
    object->tier_b = true;
    object->object_id = request->object_id;
    object->guest_physical_address = request->guest_physical_address;
    object->size = request->size;
    object->protection_class = request->protection_class;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns \nothing;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == INVALID_STATE;
*/
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns state->ksi_objects[0 .. 15];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == ALREADY_EXISTS || \result == INVALID_STATE;
*/
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
    if (target_set->target_count > 8U) {
        return INVALID_STATE;
    }
    if (!fbvbs_target_set_has_registered_target(state, target_set)) {
        return NOT_FOUND;
    }

    object->pointer_registered = true;
    object->target_set_id = target_set->target_set_id;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == POLICY_DENIED;
*/
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

    /*@ loop invariant 0 <= index <= 48;
        loop invariant hash_nonzero == 0 || hash_nonzero == 1;
        loop assigns index, hash_nonzero;
        loop variant 48 - index;
    */
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns state->ksi_objects[0 .. 15], state->next_memory_object_id, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == POLICY_DENIED || \result == RESOURCE_EXHAUSTED;
*/
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
    *object = (struct fbvbs_ksi_object){0};
    object->active = true;
    object->tier_b = true;
    object->object_id = object_id;
    object->guest_physical_address = object_id;
    object->size = FBVBS_PAGE_SIZE;
    object->protection_class = KSI_CLASS_UCRED;
    response->ucred_object_id = object_id;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    assigns state->ksi_objects[0 .. 15];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == INVALID_STATE || \result == POLICY_DENIED;
*/
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
    if (target_set != NULL && target_set->target_count > 8U) {
        return INVALID_STATE;
    }
    if (target_set == NULL || !fbvbs_target_set_contains_object(target_set, new_object->object_id)) {
        return POLICY_DENIED;
    }

    old_object->retired = true;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    assigns state->ksi_objects[0 .. 15];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND || \result == RESOURCE_BUSY;
*/
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

    *object = (struct fbvbs_ksi_object){0};
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns state->iks_keys[0 .. 15], state->next_key_handle, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == RESOURCE_EXHAUSTED;
*/
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

    *key = (struct fbvbs_iks_key){0};
    key->active = true;
    key->key_type = request->key_type;
    key->allowed_ops = request->allowed_ops;
    key->key_length = request->key_length;
    key->key_handle = state->next_key_handle++;
    response->handle = key->key_handle;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == PERMISSION_DENIED || \result == POLICY_DENIED;
*/
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

    *response = (struct fbvbs_iks_sign_response){0};
    response->signature_length = key->key_type == IKS_KEY_RSA3072 ? 384U : 64U;
    response->signature[0] = (uint8_t)key->key_type;
    response->signature[1] = request->hash[0];
    response->signature[response->signature_length - 1U] = request->hash[47];
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns state->iks_keys[0 .. 15], state->next_key_handle, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == PERMISSION_DENIED || \result == POLICY_DENIED || \result == RESOURCE_EXHAUSTED;
*/
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

    *derived = (struct fbvbs_iks_key){0};
    derived->active = true;
    derived->key_type = key->key_type;
    derived->allowed_ops = IKS_OP_DERIVE;
    derived->key_length = key->key_length;
    derived->key_handle = state->next_key_handle++;
    response->handle = derived->key_handle;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns state->iks_keys[0 .. 15], state->next_key_handle, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND ||
            \result == PERMISSION_DENIED || \result == RESOURCE_EXHAUSTED;
*/
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

    *derived = (struct fbvbs_iks_key){0};
    derived->active = true;
    derived->key_type = key->key_type;
    derived->allowed_ops = key->allowed_ops;
    derived->key_length = key->key_length;
    derived->key_handle = state->next_key_handle++;
    response->handle = derived->key_handle;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    assigns state->iks_keys[0 .. 15];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND;
*/
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

    *key = (struct fbvbs_iks_key){0};
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns state->sks_deks[0 .. 15], state->next_dek_handle, *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == RESOURCE_EXHAUSTED;
*/
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

    *dek = (struct fbvbs_sks_dek){0};
    dek->active = true;
    dek->key_length = request->key_length;
    dek->volume_id = request->volume_id;
    dek->dek_handle = state->next_dek_handle++;
    response->handle = dek->dek_handle;
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND;
*/
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND;
*/
int fbvbs_sks_decrypt_batch(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_batch_request *request,
    struct fbvbs_sks_batch_response *response
) {
    return fbvbs_sks_batch_common(state, request, response);
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    assigns *response;
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND;
*/
int fbvbs_sks_encrypt_batch(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_sks_batch_request *request,
    struct fbvbs_sks_batch_response *response
) {
    return fbvbs_sks_batch_common(state, request, response);
}

/*@ requires \valid(state) || state == \null;
    assigns state->sks_deks[0 .. 15];
    ensures \result == OK || \result == INVALID_PARAMETER || \result == NOT_FOUND;
*/
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

    *dek = (struct fbvbs_sks_dek){0};
    return OK;
}

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    requires state == \null || state->revoked_object_count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    requires request == \null || fbvbs_valid_uvs_request_view(request);
    assigns state->manifest_sets[0 .. 7], state->next_manifest_set_id,
            state->revoked_object_ids[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1], state->revoked_object_count,
            *response;
*/
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

    /*@ assert fbvbs_valid_uvs_request_view(request); */
    status = fbvbs_validate_metadata_set(state, request, &failure_bitmap, snapshot_id);
    if (status != OK) {
        *response = (struct fbvbs_uvs_verify_manifest_set_response){0};
        response->failure_bitmap = failure_bitmap;
        return status;
    }

    manifest_set = fbvbs_allocate_manifest_set(state);
    if (manifest_set == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    *manifest_set = (struct fbvbs_uvs_manifest_set){0};
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    requires state == \null || state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    requires state == \null ||
            (\forall integer i; 0 <= i < 8 ==>
                !state->manifest_sets[i].active ||
                fbvbs_valid_verified_manifest_set(&state->manifest_sets[i]));
    assigns state->approvals[0 .. FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES - 1], *response;
*/
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
    if (manifest_set->manifest_count > FBVBS_MAX_METADATA_MANIFESTS) {
        return INVALID_STATE;
    }
    /*@ assert fbvbs_valid_verified_manifest_set(manifest_set); */
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

/*@ requires \valid(state) || state == \null;
    requires \valid_read(request) || request == \null;
    requires \valid(response) || response == \null;
    requires state == \null || state->artifact_catalog.count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    requires state == \null || state->revoked_object_count <= FBVBS_MAX_ARTIFACT_CATALOG_ENTRIES;
    assigns *response;
*/
int fbvbs_uvs_check_revocation(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_uvs_check_revocation_request *request,
    struct fbvbs_uvs_check_revocation_response *response
) {
    int found = 0;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->object_id == 0U || request->object_type == 0U || request->reserved0 != 0U) {
        return INVALID_PARAMETER;
    }

    /* Validate object_type and perform type-specific lookup */
    switch (request->object_type) {
        case FBVBS_ARTIFACT_OBJECT_IMAGE:
            found = fbvbs_artifact_exists(state, request->object_id, FBVBS_ARTIFACT_OBJECT_IMAGE);
            break;
        case FBVBS_ARTIFACT_OBJECT_MANIFEST:
            found = fbvbs_artifact_exists(state, request->object_id, FBVBS_ARTIFACT_OBJECT_MANIFEST);
            break;
        case FBVBS_ARTIFACT_OBJECT_MODULE:
            found = fbvbs_artifact_exists(state, request->object_id, FBVBS_ARTIFACT_OBJECT_MODULE);
            break;
        default:
            /* For non-artifact types (keys, DEKs), check existence without type constraint */
            if (fbvbs_find_iks_key(state, request->object_id) != NULL ||
                fbvbs_find_sks_dek(state, request->object_id) != NULL) {
                found = 1;
            }
            break;
    }

    if (!found) {
        return NOT_FOUND;
    }

    response->revoked = fbvbs_is_object_revoked(state, request->object_id) ? 1U : 0U;
    response->reserved0 = 0U;
    return OK;
}