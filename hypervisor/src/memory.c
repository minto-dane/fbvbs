#include "fbvbs_hypervisor.h"

/*@ requires \valid(state);
    assigns \nothing;
    ensures \result == \null ||
            (\valid(\result) && \result->allocated && \result->memory_object_id == memory_object_id);
    ensures \result != \null ==>
            \exists integer i; 0 <= i < FBVBS_MAX_MEMORY_OBJECTS &&
            \result == &state->memory_objects[i];
*/
static struct fbvbs_memory_object *fbvbs_find_memory_object(
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

/*@ requires \valid(state);
    assigns \nothing;
    ensures \result == \null || (\valid(\result) && !\result->allocated);
    ensures \result != \null ==>
            \exists integer i; 0 <= i < FBVBS_MAX_MEMORY_OBJECTS &&
            \result == &state->memory_objects[i];
*/
static struct fbvbs_memory_object *fbvbs_allocate_memory_object_slot(
    struct fbvbs_hypervisor_state *state
) {
    uint32_t index;

    /*@ loop invariant 0 <= index <= FBVBS_MAX_MEMORY_OBJECTS;
        loop assigns index;
        loop variant FBVBS_MAX_MEMORY_OBJECTS - index;
    */
    for (index = 0U; index < FBVBS_MAX_MEMORY_OBJECTS; ++index) {
        if (!state->memory_objects[index].allocated) {
            return &state->memory_objects[index];
        }
    }

    return NULL;
}

/*@ requires \valid(state);
    requires \valid(request);
    requires \valid(response);
    requires state->next_memory_object_id > 0;
    assigns state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1],
            state->next_memory_object_id,
            *response;
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == RESOURCE_EXHAUSTED;
    ensures \result == OK ==> response->memory_object_id > 0;
*/
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

    *object = (struct fbvbs_memory_object){0};
    object->allocated = true;
    object->object_flags = request->object_flags;
    object->memory_object_id = state->next_memory_object_id++;
    object->size = request->size;
    response->memory_object_id = object->memory_object_id;
    return OK;
}

/*@ requires \valid(state);
    assigns state->memory_objects[0 .. FBVBS_MAX_MEMORY_OBJECTS - 1];
    ensures \result == OK || \result == INVALID_PARAMETER ||
            \result == NOT_FOUND || \result == RESOURCE_BUSY;
*/
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

    *object = (struct fbvbs_memory_object){0};
    return OK;
}
