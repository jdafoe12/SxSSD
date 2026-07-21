#include "tee-v2-cache.h"

#include <stdlib.h>
#include <string.h>

int tee_v2_cache_init(struct tee_v2_cache *cache, uint64_t segment_count,
                      uint32_t passive_capacity)
{
    if (!cache || passive_capacity == 0) return -1;
    memset(cache, 0, sizeof(*cache));
    if (tee_v1_bitmap_init(&cache->protected_bitmap, segment_count) != 0) return -1;
    cache->passive_records = calloc(passive_capacity, sizeof(*cache->passive_records));
    if (!cache->passive_records) {
        tee_v1_bitmap_destroy(&cache->protected_bitmap);
        return -1;
    }
    cache->passive_capacity = passive_capacity;
    return 0;
}

void tee_v2_cache_destroy(struct tee_v2_cache *cache)
{
    uint32_t i;
    if (!cache) return;
    for (i = 0; i < cache->passive_count; i++)
        tee_v2_passive_metadata_destroy(&cache->passive_records[i]);
    free(cache->passive_records);
    tee_v1_bitmap_destroy(&cache->protected_bitmap);
    memset(cache, 0, sizeof(*cache));
}

static int clone_passive(struct tee_v2_passive_metadata *dst,
                         const struct tee_v2_passive_metadata *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->segment_locations = malloc(sizeof(uint64_t) * src->segment_count);
    if (src->group_count)
        dst->groups = malloc(sizeof(*dst->groups) * src->group_count);
    if (!dst->segment_locations || (src->group_count && !dst->groups)) {
        tee_v2_passive_metadata_destroy(dst);
        return -1;
    }
    dst->file_id = src->file_id; dst->chunk_id = src->chunk_id;
    dst->chunk_size_bytes = src->chunk_size_bytes;
    dst->segment_count = src->segment_count;
    dst->number_coefficient = src->number_coefficient;
    dst->group_count = src->group_count;
    memcpy(dst->segment_locations, src->segment_locations,
           sizeof(uint64_t) * src->segment_count);
    if (src->group_count)
        memcpy(dst->groups, src->groups, sizeof(*dst->groups) * src->group_count);
    return 0;
}

struct tee_v2_passive_metadata *tee_v2_cache_find_passive(
    struct tee_v2_cache *cache, uint8_t file_id, uint32_t chunk_id)
{
    uint32_t i;
    if (!cache) return NULL;
    for (i = 0; i < cache->passive_count; i++)
        if (cache->passive_records[i].file_id == file_id &&
            cache->passive_records[i].chunk_id == chunk_id)
            return &cache->passive_records[i];
    return NULL;
}

int tee_v2_cache_store_passive(struct tee_v2_cache *cache,
                               const struct tee_v2_passive_metadata *passive)
{
    struct tee_v2_passive_metadata *existing;
    if (!cache || !passive || !passive->segment_count ||
        !passive->segment_locations ||
        (passive->group_count && !passive->groups))
        return -1;
    existing = tee_v2_cache_find_passive(cache, passive->file_id, passive->chunk_id);
    if (existing) {
        struct tee_v2_passive_metadata replacement;
        if (clone_passive(&replacement, passive) != 0) return -1;
        tee_v2_passive_metadata_destroy(existing);
        *existing = replacement;
        return 0;
    }
    if (cache->passive_count >= cache->passive_capacity) return -1;
    if (clone_passive(&cache->passive_records[cache->passive_count], passive) != 0)
        return -1;
    cache->passive_count++;
    return 0;
}

int tee_v2_cache_mark_protected(struct tee_v2_cache *cache, uint64_t location)
{ return cache ? tee_v1_bitmap_set(&cache->protected_bitmap, location) : -1; }
int tee_v2_cache_unmark_protected(struct tee_v2_cache *cache, uint64_t location)
{ return cache ? tee_v1_bitmap_clear(&cache->protected_bitmap, location) : -1; }
bool tee_v2_cache_is_protected(const struct tee_v2_cache *cache, uint64_t location)
{ return cache && tee_v1_bitmap_test(&cache->protected_bitmap, location); }
