#ifndef TEE_V3_READ_H
#define TEE_V3_READ_H
#include "tee-v2-passive-metadata.h"
#include <stddef.h>

enum tee_v3_query_result { TEE_V3_QUERY_OK=0, TEE_V3_QUERY_NOT_FOUND=-1, TEE_V3_QUERY_INVALID=-2 };
struct tee_v3_read_summary {
    uint64_t chunk_size_bytes;
    uint32_t segment_count;
    uint32_t number_coefficient;
    uint32_t location_item_count;
    uint32_t location_item_size;
    uint32_t location_page_count;
    uint32_t hmac_group_count;
    uint32_t hmac_group_item_size;
    uint32_t hmac_group_page_count;
};
struct tee_v3_hmac_group_item {
    uint32_t start_segment_index;
    uint32_t group_segment_count;
    uint8_t expected_hmac[TEE_V2_HMAC_SIZE];
};
bool tee_v3_normal_read_allowed(uint64_t slba, uint64_t nlb);
enum tee_v3_query_result tee_v3_read_summary(const struct tee_v2_passive_metadata *p,uint32_t page_size,struct tee_v3_read_summary *out);
enum tee_v3_query_result tee_v3_read_locations(const struct tee_v2_passive_metadata *p,uint32_t offset,uint64_t *items,size_t capacity,size_t *written);
enum tee_v3_query_result tee_v3_read_hmac_groups(const struct tee_v2_passive_metadata *p,uint32_t offset,struct tee_v3_hmac_group_item *items,size_t capacity,size_t *written);
#endif
