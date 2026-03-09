#include "fbvbs_hypervisor.h"

void fbvbs_zero_memory(void *buffer, size_t length) {
    uint8_t *bytes = (uint8_t *)buffer;
    size_t index;

    for (index = 0; index < length; ++index) {
        bytes[index] = 0;
    }
}

void fbvbs_copy_memory(void *destination, const void *source, size_t length) {
    uint8_t *dest = (uint8_t *)destination;
    const uint8_t *src = (const uint8_t *)source;
    size_t index;

    for (index = 0; index < length; ++index) {
        dest[index] = src[index];
    }
}

int fbvbs_memory_is_zero(const void *buffer, size_t length) {
    const uint8_t *bytes = (const uint8_t *)buffer;
    size_t index;

    for (index = 0; index < length; ++index) {
        if (bytes[index] != 0U) {
            return 0;
        }
    }

    return 1;
}

static struct fbvbs_memory_object *fbvbs_find_memory_object(
    struct fbvbs_hypervisor_state *state,
    uint64_t memory_object_id
) {
    uint32_t index;

    for (index = 0U; index < FBVBS_MAX_MEMORY_OBJECTS; ++index) {
        if (state->memory_objects[index].allocated &&
            state->memory_objects[index].memory_object_id == memory_object_id) {
            return &state->memory_objects[index];
        }
    }

    return NULL;
}

static struct fbvbs_memory_object *fbvbs_allocate_memory_object_slot(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    for (index = 0U; index < FBVBS_MAX_MEMORY_OBJECTS; ++index) {
        if (!state->memory_objects[index].allocated) {
            return &state->memory_objects[index];
        }
    }

    return NULL;
}

int fbvbs_memory_allocate_object(
    struct fbvbs_hypervisor_state *state,
    const struct fbvbs_memory_allocate_object_request *request,
    struct fbvbs_memory_allocate_object_response *response
) {
    struct fbvbs_memory_object *object;

    if (state == NULL || request == NULL || response == NULL) {
        return INVALID_PARAMETER;
    }
    if (request->reserved0 != 0U || request->size == 0U) {
        return INVALID_PARAMETER;
    }
    if ((request->size % FBVBS_PAGE_SIZE) != 0U) {
        return INVALID_PARAMETER;
    }
    if (request->object_flags != FBVBS_MEMORY_OBJECT_FLAG_PRIVATE &&
        request->object_flags != FBVBS_MEMORY_OBJECT_FLAG_SHAREABLE &&
        request->object_flags != FBVBS_MEMORY_OBJECT_FLAG_GUEST_MEMORY) {
        return INVALID_PARAMETER;
    }

    object = fbvbs_allocate_memory_object_slot(state);
    if (object == NULL) {
        return RESOURCE_EXHAUSTED;
    }

    fbvbs_zero_memory(object, sizeof(*object));
    object->allocated = true;
    object->object_flags = request->object_flags;
    object->memory_object_id = state->next_memory_object_id++;
    object->size = request->size;
    response->memory_object_id = object->memory_object_id;
    return OK;
}

int fbvbs_memory_release_object(struct fbvbs_hypervisor_state *state, uint64_t memory_object_id) {
    struct fbvbs_memory_object *object;

    if (state == NULL || memory_object_id == 0U) {
        return INVALID_PARAMETER;
    }

    object = fbvbs_find_memory_object(state, memory_object_id);
    if (object == NULL) {
        return NOT_FOUND;
    }
    if (object->map_count != 0U || object->shared_count != 0U) {
        return RESOURCE_BUSY;
    }

    fbvbs_zero_memory(object, sizeof(*object));
    return OK;
}
