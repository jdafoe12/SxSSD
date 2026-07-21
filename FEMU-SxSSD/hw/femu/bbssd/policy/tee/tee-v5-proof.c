#include "tee-v5-proof.h"

void tee_v5_proof_record_error(struct tee_v3_pending_controller *controller,
                               enum tee_v5_proof_error error,
                               uint32_t failed_segment_index)
{
    if (!controller) return;
    controller->has_error = error != TEE_V5_PROOF_ERROR_NONE;
    controller->last_error_code = error;
    controller->failed_segment_index = failed_segment_index;
}

void tee_v5_proof_clear_error(struct tee_v3_pending_controller *controller)
{
    if (!controller) return;
    controller->has_error = false;
    controller->last_error_code = TEE_V5_PROOF_ERROR_NONE;
    controller->failed_segment_index = TEE_V5_NO_FAILED_SEGMENT;
}
