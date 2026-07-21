#include "tee-v5-proof.h"

#include <string.h>

int tee_v5_proof_record_error(struct tee_v3_pending_controller *controller,
                               uint8_t file_id, uint32_t chunk_id,
                               enum tee_v5_proof_error error,
                               uint32_t failed_segment_index)
{
    struct tee_v3_scoped_error *entry = NULL;
    size_t i;

    if (!controller || error == TEE_V5_PROOF_ERROR_NONE ||
        (controller->has_error && !controller->error_identity_valid))
        return -1;
    for (i = 0; i < TEE_V5_PROOF_ERROR_CAPACITY; i++) {
        if (controller->scoped_errors[i].valid &&
            controller->scoped_errors[i].file_id == file_id &&
            controller->scoped_errors[i].chunk_id == chunk_id) {
            entry = &controller->scoped_errors[i];
            break;
        }
        if (!entry && !controller->scoped_errors[i].valid)
            entry = &controller->scoped_errors[i];
    }
    if (!entry) return -1;
    entry->valid = true;
    entry->file_id = file_id;
    entry->chunk_id = chunk_id;
    entry->error_code = error;
    entry->failed_segment_index = failed_segment_index;
    controller->has_error = true;
    controller->last_error_code = error;
    controller->failed_segment_index = failed_segment_index;
    controller->error_identity_valid = true;
    controller->error_file_id = file_id;
    controller->error_chunk_id = chunk_id;
    return 0;
}

void tee_v5_proof_clear_error(struct tee_v3_pending_controller *controller,
                              uint8_t file_id, uint32_t chunk_id)
{
    size_t i;
    struct tee_v3_scoped_error *replacement = NULL;

    if (!controller || !controller->error_identity_valid) return;
    for (i = 0; i < TEE_V5_PROOF_ERROR_CAPACITY; i++) {
        struct tee_v3_scoped_error *entry = &controller->scoped_errors[i];
        if (entry->valid && entry->file_id == file_id &&
            entry->chunk_id == chunk_id) memset(entry, 0, sizeof(*entry));
        else if (entry->valid && !replacement) replacement = entry;
    }
    if (replacement) {
        controller->has_error = true;
        controller->error_file_id = replacement->file_id;
        controller->error_chunk_id = replacement->chunk_id;
        controller->last_error_code = replacement->error_code;
        controller->failed_segment_index = replacement->failed_segment_index;
    } else {
        controller->has_error = false;
        controller->last_error_code = TEE_V5_PROOF_ERROR_NONE;
        controller->failed_segment_index = TEE_V5_NO_FAILED_SEGMENT;
        controller->error_identity_valid = false;
    }
}
