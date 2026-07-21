#ifndef TEE_V2_ACTIVE_METADATA_H
#define TEE_V2_ACTIVE_METADATA_H

#include "tee-v2-format.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TEE_V2_LOCATION_UNSET UINT64_MAX

struct tee_v2_hmac_group_spec {
    uint32_t start_segment_index;
    uint32_t group_segment_count;
    const uint8_t *expected_hmac;
};

struct tee_v2_hmac_group_state {
    uint8_t file_id;
    uint32_t chunk_id;
    uint32_t start_segment_index;
    uint32_t group_segment_count;
    uint8_t expected_hmac[TEE_V2_HMAC_SIZE];
    uint32_t arrived_count;
    bool verified;
};

struct tee_v2_active_metadata {
    struct tee_v2_format_config config;
    uint8_t file_id;
    uint32_t chunk_id;
    uint64_t chunk_size_bytes;
    uint32_t segment_count;
    uint32_t number_coefficient;
    uint64_t *segment_locations;
    uint8_t *segment_bytes;
    bool *arrived;
    bool *pending;
    struct tee_v2_hmac_group_state *groups;
    uint32_t group_count;
    uint32_t group_capacity;
};

int tee_v2_active_metadata_init(struct tee_v2_active_metadata *active,
                                const struct tee_v2_format_config *config,
                                uint8_t file_id, uint32_t chunk_id,
                                uint64_t chunk_size_bytes,
                                uint32_t segment_count,
                                uint32_t number_coefficient,
                                const struct tee_v2_hmac_group_spec *groups,
                                uint32_t group_count);
void tee_v2_active_metadata_destroy(struct tee_v2_active_metadata *active);
bool tee_v2_active_matches_segment(const struct tee_v2_active_metadata *active,
                                   const uint8_t *segment, size_t segment_size,
                                   struct tee_v2_segment_header *header_out);
int tee_v2_active_record_segment(struct tee_v2_active_metadata *active,
                                 uint32_t segment_index,
                                 uint64_t logical_location,
                                 const uint8_t *segment);
struct tee_v2_hmac_group_state *tee_v2_active_find_group(
    struct tee_v2_active_metadata *active, uint32_t segment_index);
bool tee_v2_active_complete(const struct tee_v2_active_metadata *active);

#endif
