#ifndef TEE_V2_PASSIVE_METADATA_H
#define TEE_V2_PASSIVE_METADATA_H

#include "tee-v2-active-metadata.h"

#include <stdbool.h>
#include <stdint.h>

struct tee_v2_passive_metadata {
    uint8_t file_id;
    uint32_t chunk_id;
    uint64_t chunk_size_bytes;
    uint32_t segment_count;
    uint32_t number_coefficient;
    uint64_t *segment_locations;
    struct tee_v2_hmac_group_state *groups;
    uint32_t group_count;
};

int tee_v2_passive_from_active(struct tee_v2_passive_metadata *passive,
                               const struct tee_v2_active_metadata *active);
void tee_v2_passive_metadata_destroy(struct tee_v2_passive_metadata *passive);
bool tee_v2_passive_matches(const struct tee_v2_passive_metadata *passive,
                            uint8_t file_id, uint32_t chunk_id,
                            uint32_t segment_index);

#endif
