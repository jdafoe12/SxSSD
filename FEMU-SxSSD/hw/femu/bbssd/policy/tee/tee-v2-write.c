#include "tee-v2-write.h"

#include <stdlib.h>
#include <string.h>

int tee_v2_write_context_init(struct tee_v2_write_context *write,
                              struct tee_v2_active_metadata *active,
                              struct tee_v2_cache *cache,
                              uint64_t logical_segment_count)
{
    if (!write || !cache || logical_segment_count == 0) return -1;
    memset(write, 0, sizeof(*write));
    if (tee_v1_bitmap_init(&write->pending_bitmap, logical_segment_count) != 0)
        return -1;
    write->active = active;
    write->cache = cache;
    return 0;
}

void tee_v2_write_context_destroy(struct tee_v2_write_context *write)
{
    if (!write) return;
    tee_v1_bitmap_destroy(&write->pending_bitmap);
    memset(write, 0, sizeof(*write));
}

static void clear_group_pending_bitmap(struct tee_v2_write_context *write,
                                       const uint64_t *locations,
                                       uint32_t count)
{
    uint32_t i;
    for (i = 0; i < count; i++)
        if (locations[i] != TEE_V2_LOCATION_UNSET)
            tee_v1_bitmap_clear(&write->pending_bitmap, locations[i]);
}

static enum tee_v2_write_result promote_active(struct tee_v2_write_context *write)
{
    struct tee_v2_passive_metadata passive;
    uint32_t i;
    if (tee_v2_passive_from_active(&passive, write->active) != 0)
        return TEE_V2_WRITE_ERROR;
    if (tee_v2_cache_store_passive(write->cache, &passive) != 0) {
        tee_v2_passive_metadata_destroy(&passive);
        return TEE_V2_WRITE_ERROR;
    }
    for (i = 0; i < write->active->segment_count; i++) {
        uint64_t location = write->active->segment_locations[i];
        tee_v2_cache_mark_protected(write->cache, location);
        tee_v1_bitmap_clear(&write->pending_bitmap, location);
        write->active->pending[i] = false;
    }
    tee_v2_passive_metadata_destroy(&passive);
    write->active_promoted = true;
    return TEE_V2_WRITE_CHUNK_COMPLETE;
}

enum tee_v2_write_result tee_v2_process_segment_write(
    struct tee_v2_write_context *write, uint64_t logical_location,
    const uint8_t *segment, size_t segment_size,
    struct tee_v2_passive_metadata **passive_out,
    uint32_t *segment_index_out)
{
    struct tee_v2_segment_header header;
    struct tee_v2_passive_metadata *passive;
    struct tee_v2_hmac_group_state *group;
    uint64_t *group_locations = NULL;
    enum tee_v2_hmac_result hmac_result;
    uint32_t i;

    if (passive_out) *passive_out = NULL;
    if (segment_index_out) *segment_index_out = 0;
    if (!write || !write->cache || !segment ||
        logical_location >= write->pending_bitmap.bit_count)
        return TEE_V2_WRITE_ERROR;
    if (tee_v2_cache_is_protected(write->cache, logical_location) ||
        tee_v1_bitmap_test(&write->pending_bitmap, logical_location))
        return TEE_V2_WRITE_REJECTED;
    if (!tee_v2_parse_segment_header(segment, segment_size, &header))
        return TEE_V2_WRITE_NORMAL;

    if (write->active && !write->active_promoted &&
        tee_v2_active_matches_segment(write->active, segment, segment_size,
                                      &header)) {
        int record_result = tee_v2_active_record_segment(
            write->active, header.segment_index, logical_location, segment);
        if (record_result < 0) return TEE_V2_WRITE_ERROR;
        if (record_result > 0) return TEE_V2_WRITE_REJECTED;
        if (tee_v1_bitmap_set(&write->pending_bitmap, logical_location) != 0)
            return TEE_V2_WRITE_ERROR;
        group = tee_v2_active_find_group(write->active, header.segment_index);
        if (!group) return TEE_V2_WRITE_ERROR;
        if (group->arrived_count != group->group_segment_count)
            return TEE_V2_WRITE_PENDING;
        group_locations = malloc(sizeof(uint64_t) * group->group_segment_count);
        if (!group_locations) return TEE_V2_WRITE_ERROR;
        for (i = 0; i < group->group_segment_count; i++)
            group_locations[i] = write->active->segment_locations[
                group->start_segment_index - 1 + i];
        hmac_result = tee_v2_verify_hmac_group(write->active, group,
                                               tee_v2_prototype_key,
                                               TEE_V2_PROTOTYPE_KEY_SIZE);
        if (hmac_result == TEE_V2_HMAC_FAILED) {
            clear_group_pending_bitmap(write, group_locations,
                                       group->group_segment_count);
            free(group_locations);
            return TEE_V2_WRITE_HMAC_FAILED_NORMAL;
        }
        free(group_locations);
        if (tee_v2_active_complete(write->active)) return promote_active(write);
        return hmac_result == TEE_V2_HMAC_REUSED ?
               TEE_V2_WRITE_GROUP_VERIFIED : TEE_V2_WRITE_GROUP_VERIFIED;
    }

    passive = tee_v2_cache_find_passive(write->cache, header.file_id,
                                         header.chunk_id);
    if (passive && tee_v2_passive_matches(passive, header.file_id,
                                           header.chunk_id,
                                           header.segment_index)) {
        if (passive_out) *passive_out = passive;
        if (segment_index_out) *segment_index_out = header.segment_index;
        return TEE_V2_WRITE_RELOCATION;
    }
    return TEE_V2_WRITE_NORMAL;
}
