#ifndef TEE_V2_CACHE_H
#define TEE_V2_CACHE_H

#include "tee-v2-passive-metadata.h"
#include "tee-v1-bitmap.h"

#include <stdbool.h>
#include <stdint.h>

/* Cache contains only RAM mirrors of persisted protected/passive state. */
struct tee_v2_cache {
    struct tee_v1_bitmap protected_bitmap;
    struct tee_v2_passive_metadata *passive_records;
    uint32_t passive_count;
    uint32_t passive_capacity;
};

int tee_v2_cache_init(struct tee_v2_cache *cache, uint64_t segment_count,
                      uint32_t passive_capacity);
void tee_v2_cache_destroy(struct tee_v2_cache *cache);
int tee_v2_cache_store_passive(struct tee_v2_cache *cache,
                               const struct tee_v2_passive_metadata *passive);
struct tee_v2_passive_metadata *tee_v2_cache_find_passive(
    struct tee_v2_cache *cache, uint8_t file_id, uint32_t chunk_id);
int tee_v2_cache_mark_protected(struct tee_v2_cache *cache, uint64_t location);
int tee_v2_cache_unmark_protected(struct tee_v2_cache *cache, uint64_t location);
bool tee_v2_cache_is_protected(const struct tee_v2_cache *cache,
                               uint64_t location);

#endif
