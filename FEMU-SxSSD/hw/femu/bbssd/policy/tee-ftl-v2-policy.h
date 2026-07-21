#ifndef TEE_FTL_V2_POLICY_H
#define TEE_FTL_V2_POLICY_H

#include "tee/tee-v2-active-metadata.h"

/* V2 internal/test metadata intake. NVMe admin command intake starts in V4. */
int tee_v2_policy_set_active_metadata(
    uint8_t file_id, uint32_t chunk_id, uint64_t chunk_size_bytes,
    uint32_t segment_count, uint32_t number_coefficient,
    const struct tee_v2_hmac_group_spec *groups, uint32_t group_count);
void tee_v2_policy_clear_active_metadata(void);

#endif
