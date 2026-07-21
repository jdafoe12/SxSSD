#include "tee-v2-format.h"

bool tee_v2_format_config_init(struct tee_v2_format_config *config,
                               uint32_t segment_size,
                               uint32_t page_size)
{
    if (!config || page_size == 0) {
        return false;
    }
    if (segment_size == 0) {
        segment_size = TEE_V2_DEFAULT_SEGMENT_SIZE;
    }
    if (segment_size < TEE_V2_SEGMENT_HEADER_SIZE ||
        page_size < segment_size || page_size % segment_size != 0) {
        return false;
    }
    config->segment_size = segment_size;
    config->page_size = page_size;
    config->segments_per_page = page_size / segment_size;
    config->hmac_group_capacity = TEE_V2_DEFAULT_HMAC_GROUP_CAPACITY;
    return true;
}

bool tee_v2_parse_segment_header(const uint8_t *segment,
                                 size_t segment_size,
                                 struct tee_v2_segment_header *header)
{
    if (!segment || !header || segment_size < TEE_V2_SEGMENT_HEADER_SIZE ||
        segment[0] != TEE_V2_SEGMENT_MAGIC) {
        return false;
    }
    header->magic = segment[0];
    header->file_id = segment[1];
    header->chunk_id = (uint32_t)segment[2] |
                       ((uint32_t)segment[3] << 8) |
                       ((uint32_t)segment[4] << 16);
    header->segment_index = (uint32_t)segment[5] |
                            ((uint32_t)segment[6] << 8) |
                            ((uint32_t)segment[7] << 16) |
                            ((uint32_t)segment[8] << 24);
    return header->segment_index != 0;
}

bool tee_v2_header_matches(const struct tee_v2_segment_header *header,
                           uint8_t file_id,
                           uint32_t chunk_id,
                           uint32_t segment_index)
{
    return header && header->magic == TEE_V2_SEGMENT_MAGIC &&
           header->file_id == file_id && header->chunk_id == chunk_id &&
           header->segment_index == segment_index;
}
