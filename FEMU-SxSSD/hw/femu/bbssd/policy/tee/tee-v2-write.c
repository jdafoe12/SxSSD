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

bool tee_v2_write_range_allowed(const struct tee_v2_write_context *write,
                                uint64_t first_segment,
                                uint64_t segment_count)
{
    if (!write || !write->cache || segment_count == 0 ||
        first_segment >= write->pending_bitmap.bit_count ||
        segment_count > write->pending_bitmap.bit_count - first_segment)
        return false;
    return !tee_v1_bitmap_any_set(&write->cache->protected_bitmap,
                                  first_segment, segment_count) &&
           !tee_v1_bitmap_any_set(&write->pending_bitmap,
                                  first_segment, segment_count);
}

void tee_v2_write_abandon_active(struct tee_v2_write_context *write)
{
    uint32_t i;
    if (!write || !write->active) return;
    for (i = 0; i < write->active->segment_count; i++) {
        if (write->active->pending[i] &&
            write->active->segment_locations[i] != TEE_V2_LOCATION_UNSET) {
            tee_v1_bitmap_clear(&write->pending_bitmap,
                                write->active->segment_locations[i]);
            write->active->pending[i] = false;
        }
    }
    write->active = NULL;
    write->active_promoted = false;
}

enum tee_v2_write_result tee_v2_classify_segment_write(
    struct tee_v2_write_context *write, uint64_t logical_location,
    const uint8_t *segment, size_t segment_size,
    struct tee_v2_passive_metadata **passive_out,
    uint32_t *segment_index_out)
{
    struct tee_v2_segment_header header;
    struct tee_v2_passive_metadata *passive;
    if (passive_out) *passive_out = NULL;
    if (segment_index_out) *segment_index_out = 0;
    if (!write || !write->cache || !segment ||
        logical_location >= write->pending_bitmap.bit_count)
        return TEE_V2_WRITE_ERROR;
    if (!tee_v2_write_range_allowed(write, logical_location, 1))
        return TEE_V2_WRITE_REJECTED;
    if (!tee_v2_parse_segment_header(segment, segment_size, &header))
        return TEE_V2_WRITE_NORMAL;
    if (write->active && !write->active_promoted &&
        tee_v2_active_matches_segment(write->active, segment, segment_size,
                                      &header)) {
        if (write->active->arrived[header.segment_index - 1])
            return TEE_V2_WRITE_REJECTED;
        return TEE_V2_WRITE_PENDING;
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

int tee_v2_preflight_segment_request(
    struct tee_v2_write_context *write, uint64_t first_location,
    const uint8_t *segments, size_t segment_size, uint64_t segment_count,
    enum tee_v2_write_result *results,
    struct tee_v2_passive_metadata **passives,
    uint32_t *segment_indices)
{
    uint64_t i, j;
    if (!write || !segments || !segment_size || !segment_count ||
        !results || !passives || !segment_indices ||
        segment_count > SIZE_MAX / segment_size ||
        !tee_v2_write_range_allowed(write, first_location, segment_count))
        return -1;
    for (i = 0; i < segment_count; i++) {
        const uint8_t *segment = segments + (size_t)i * segment_size;
        results[i] = tee_v2_classify_segment_write(
            write, first_location + i, segment, segment_size,
            &passives[i], &segment_indices[i]);
        if (results[i] == TEE_V2_WRITE_REJECTED ||
            results[i] == TEE_V2_WRITE_ERROR)
            return -1;
        if (results[i] == TEE_V2_WRITE_PENDING) {
            struct tee_v2_segment_header current;
            if (!tee_v2_parse_segment_header(segment, segment_size, &current))
                return -1;
            for (j = 0; j < i; j++) {
                struct tee_v2_segment_header previous;
                if (results[j] != TEE_V2_WRITE_PENDING) continue;
                if (!tee_v2_parse_segment_header(
                        segments + (size_t)j * segment_size,
                        segment_size, &previous))
                    return -1;
                if (previous.file_id == current.file_id &&
                    previous.chunk_id == current.chunk_id &&
                    previous.segment_index == current.segment_index)
                    return -1;
            }
        }
    }
    return 0;
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
    enum tee_v2_write_result classification;
    struct tee_v2_segment_header header;
    struct tee_v2_hmac_group_state *group;
    uint64_t *group_locations = NULL;
    enum tee_v2_hmac_result hmac_result;
    uint32_t i;

    classification = tee_v2_classify_segment_write(
        write, logical_location, segment, segment_size,
        passive_out, segment_index_out);
    if (classification != TEE_V2_WRITE_PENDING)
        return classification;
    if (!tee_v2_parse_segment_header(segment, segment_size, &header))
        return TEE_V2_WRITE_ERROR;

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

    return TEE_V2_WRITE_NORMAL;
}
