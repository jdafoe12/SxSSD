#ifndef TEE_V5_PROOF_H
#define TEE_V5_PROOF_H

#include "tee-v3-proof.h"

#include <stdint.h>

enum tee_v5_proof_error {
    TEE_V5_PROOF_ERROR_NONE = 0,
    TEE_V5_PROOF_ERROR_HMAC_FAILURE = 1,
    TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE = 2,
    TEE_V5_PROOF_ERROR_DELETE_INTEGRITY = 3,
    TEE_V5_PROOF_ERROR_DELETE_CONFLICT = 4,
    TEE_V5_PROOF_ERROR_INTERNAL = 5
};

#define TEE_V5_NO_FAILED_SEGMENT UINT32_MAX
#define TEE_V5_PROOF_ERROR_CAPACITY TEE_V3_SCOPED_ERROR_CAPACITY

int tee_v5_proof_record_error(struct tee_v3_pending_controller *controller,
                               uint8_t file_id, uint32_t chunk_id,
                               enum tee_v5_proof_error error,
                               uint32_t failed_segment_index);
void tee_v5_proof_clear_error(struct tee_v3_pending_controller *controller,
                              uint8_t file_id, uint32_t chunk_id);

#endif
