#ifndef TEE_V2_FORMAT_H
#define TEE_V2_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TEE_V2_DEFAULT_SEGMENT_SIZE 512U
#define TEE_V2_SEGMENT_MAGIC 0xA7U
#define TEE_V2_SEGMENT_HEADER_SIZE 9U
#define TEE_V2_HMAC_SIZE 32U
#define TEE_V2_DEFAULT_HMAC_GROUP_CAPACITY 64U

struct tee_v2_format_config {
    uint32_t segment_size;
    uint32_t page_size;
    uint32_t segments_per_page;
    uint32_t hmac_group_capacity;
};

struct tee_v2_segment_header {
    uint8_t magic;
    uint8_t file_id;
    uint32_t chunk_id;
    uint32_t segment_index;
};

bool tee_v2_format_config_init(struct tee_v2_format_config *config,
                               uint32_t segment_size,
                               uint32_t page_size);
bool tee_v2_parse_segment_header(const uint8_t *segment,
                                 size_t segment_size,
                                 struct tee_v2_segment_header *header);
bool tee_v2_header_matches(const struct tee_v2_segment_header *header,
                           uint8_t file_id,
                           uint32_t chunk_id,
                           uint32_t segment_index);

#endif
