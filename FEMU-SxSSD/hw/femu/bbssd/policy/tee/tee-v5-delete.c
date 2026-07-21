#include "tee-v5-delete.h"

#include <limits.h>
#include <stdbool.h>

static bool record_shape_valid(const struct tee_v2_passive_metadata *record)
{
    uint32_t i;
    uint32_t expected_start = 1;

    if (!record || record->chunk_id > 0xFFFFFFU ||
        !record->segment_count || !record->segment_locations ||
        !record->chunk_size_bytes || !record->number_coefficient ||
        record->number_coefficient > record->segment_count ||
        !record->group_count || !record->groups)
        return false;

    for (i = 0; i < record->group_count; i++) {
        const struct tee_v2_hmac_group_state *group = &record->groups[i];
        if (group->file_id != record->file_id ||
            group->chunk_id != record->chunk_id ||
            group->start_segment_index != expected_start ||
            !group->group_segment_count ||
            group->group_segment_count >
                record->segment_count - expected_start + 1U ||
            !group->verified)
            return false;
        expected_start += group->group_segment_count;
    }
    return expected_start == record->segment_count + 1U;
}

static bool target_integrity_valid(const struct tee_v2_cache *cache,
                                   const struct tee_v2_passive_metadata *record,
                                   uint32_t *failed_segment_index)
{
    uint32_t i;

    if (!record_shape_valid(record)) return false;
    for (i = 0; i < record->segment_count; i++) {
        uint64_t location = record->segment_locations[i];
        if (location >= cache->protected_bitmap.bit_count ||
            !tee_v1_bitmap_test(&cache->protected_bitmap, location)) {
            if (failed_segment_index) *failed_segment_index = i + 1U;
            return false;
        }
    }
    return true;
}

static int build_prospective(const struct tee_v2_cache *cache,
                             uint32_t delete_index,
                             struct tee_v2_cache *prospective)
{
    uint32_t i;

    if (tee_v2_cache_init(prospective, cache->protected_bitmap.bit_count,
                          cache->passive_capacity) != 0)
        return -1;
    for (i = 0; i < cache->passive_count; i++) {
        const struct tee_v2_passive_metadata *record;
        uint32_t segment;

        if (i == delete_index) continue;
        record = &cache->passive_records[i];
        if (tee_v2_cache_store_passive(prospective, record) != 0)
            goto fail;
        for (segment = 0; segment < record->segment_count; segment++) {
            uint64_t location = record->segment_locations[segment];
            if (location >= cache->protected_bitmap.bit_count ||
                tee_v2_cache_mark_protected(prospective, location) != 0)
                goto fail;
        }
    }
    return 0;

fail:
    tee_v2_cache_destroy(prospective);
    return -1;
}

enum tee_v5_delete_result tee_v5_delete_chunk(
    struct tee_v2_cache *cache, uint8_t file_id, uint32_t chunk_id,
    tee_v5_delete_persist_fn persist, void *persist_opaque,
    uint32_t *failed_segment_index)
{
    struct tee_v2_cache prospective;
    uint32_t delete_index;

    if (failed_segment_index) *failed_segment_index = UINT32_MAX;
    if (!cache || !persist || !cache->protected_bitmap.bits ||
        !cache->passive_records)
        return TEE_V5_DELETE_INTERNAL;

    for (delete_index = 0; delete_index < cache->passive_count;
         delete_index++) {
        const struct tee_v2_passive_metadata *record =
            &cache->passive_records[delete_index];
        if (record->file_id == file_id && record->chunk_id == chunk_id)
            break;
    }
    if (delete_index == cache->passive_count)
        return TEE_V5_DELETE_NOT_FOUND;
    if (!target_integrity_valid(cache, &cache->passive_records[delete_index],
                                failed_segment_index))
        return TEE_V5_DELETE_INTEGRITY;
    {
        uint32_t record_index;
        for (record_index = 0; record_index < cache->passive_count;
             record_index++) {
            if (record_index == delete_index) continue;
            if (!target_integrity_valid(
                    cache, &cache->passive_records[record_index], NULL))
                return TEE_V5_DELETE_INTEGRITY;
        }
    }
    if (build_prospective(cache, delete_index, &prospective) != 0)
        return TEE_V5_DELETE_INTERNAL;

    if (persist(persist_opaque, &prospective.protected_bitmap,
                prospective.passive_records,
                prospective.passive_count) != 0) {
        tee_v2_cache_destroy(&prospective);
        return TEE_V5_DELETE_INTERNAL;
    }

    tee_v2_cache_destroy(cache);
    *cache = prospective;
    return TEE_V5_DELETE_OK;
}
