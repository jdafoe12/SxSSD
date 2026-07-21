#include "tee-v2-active-metadata.h"

#include <stdlib.h>
#include <string.h>

static bool group_valid(const struct tee_v2_hmac_group_spec *group,
                        uint32_t segment_count)
{
    return group && group->expected_hmac && group->start_segment_index > 0 &&
           group->group_segment_count > 0 &&
           group->start_segment_index <= segment_count &&
           group->group_segment_count <=
               segment_count - group->start_segment_index + 1;
}

int tee_v2_active_metadata_init(struct tee_v2_active_metadata *active,
                                const struct tee_v2_format_config *config,
                                uint8_t file_id, uint32_t chunk_id,
                                uint64_t chunk_size_bytes,
                                uint32_t segment_count,
                                uint32_t number_coefficient,
                                const struct tee_v2_hmac_group_spec *groups,
                                uint32_t group_count)
{
    size_t bytes_size;
    uint32_t i;
    uint32_t expected_start = 1;

    if (!active || !config || chunk_id > 0xFFFFFFU ||
        segment_count == 0 || group_count == 0 ||
        !groups || group_count > config->hmac_group_capacity ||
        config->segment_size > SIZE_MAX / segment_count) {
        return -1;
    }
    memset(active, 0, sizeof(*active));
    bytes_size = (size_t)config->segment_size * segment_count;
    active->segment_locations = malloc(sizeof(uint64_t) * segment_count);
    active->segment_bytes = calloc(bytes_size, 1);
    active->arrived = calloc(segment_count, sizeof(bool));
    active->pending = calloc(segment_count, sizeof(bool));
    active->groups = calloc(group_count, sizeof(*active->groups));
    if (!active->segment_locations || !active->segment_bytes ||
        !active->arrived || !active->pending || !active->groups) {
        tee_v2_active_metadata_destroy(active);
        return -1;
    }
    for (i = 0; i < group_count; i++) {
        if (!group_valid(&groups[i], segment_count) ||
            groups[i].start_segment_index != expected_start) {
            tee_v2_active_metadata_destroy(active);
            return -1;
        }
        active->groups[i].file_id = file_id;
        active->groups[i].chunk_id = chunk_id;
        active->groups[i].start_segment_index = groups[i].start_segment_index;
        active->groups[i].group_segment_count = groups[i].group_segment_count;
        memcpy(active->groups[i].expected_hmac, groups[i].expected_hmac,
               TEE_V2_HMAC_SIZE);
        expected_start += groups[i].group_segment_count;
    }
    if (expected_start != segment_count + 1) {
        tee_v2_active_metadata_destroy(active);
        return -1;
    }
    for (i = 0; i < segment_count; i++) {
        active->segment_locations[i] = TEE_V2_LOCATION_UNSET;
    }
    active->config = *config;
    active->file_id = file_id;
    active->chunk_id = chunk_id;
    active->chunk_size_bytes = chunk_size_bytes;
    active->segment_count = segment_count;
    active->number_coefficient = number_coefficient;
    active->group_count = group_count;
    active->group_capacity = config->hmac_group_capacity;
    return 0;
}

void tee_v2_active_metadata_destroy(struct tee_v2_active_metadata *active)
{
    if (!active) return;
    free(active->segment_locations);
    free(active->segment_bytes);
    free(active->arrived);
    free(active->pending);
    free(active->groups);
    memset(active, 0, sizeof(*active));
}

int tee_v2_active_metadata_clone(struct tee_v2_active_metadata *clone,
                                 const struct tee_v2_active_metadata *active)
{
    size_t bytes_size;
    if (!clone || !active || !active->segment_count || !active->group_count)
        return -1;
    memset(clone, 0, sizeof(*clone));
    bytes_size = (size_t)active->config.segment_size * active->segment_count;
    clone->segment_locations = malloc(sizeof(uint64_t) * active->segment_count);
    clone->segment_bytes = malloc(bytes_size);
    clone->arrived = malloc(sizeof(bool) * active->segment_count);
    clone->pending = malloc(sizeof(bool) * active->segment_count);
    clone->groups = malloc(sizeof(*clone->groups) * active->group_count);
    if (!clone->segment_locations || !clone->segment_bytes ||
        !clone->arrived || !clone->pending || !clone->groups) {
        tee_v2_active_metadata_destroy(clone);
        return -1;
    }
    clone->config = active->config;
    clone->file_id = active->file_id;
    clone->chunk_id = active->chunk_id;
    clone->chunk_size_bytes = active->chunk_size_bytes;
    clone->segment_count = active->segment_count;
    clone->number_coefficient = active->number_coefficient;
    clone->group_count = active->group_count;
    clone->group_capacity = active->group_capacity;
    memcpy(clone->segment_locations, active->segment_locations,
           sizeof(uint64_t) * active->segment_count);
    memcpy(clone->segment_bytes, active->segment_bytes, bytes_size);
    memcpy(clone->arrived, active->arrived,
           sizeof(bool) * active->segment_count);
    memcpy(clone->pending, active->pending,
           sizeof(bool) * active->segment_count);
    memcpy(clone->groups, active->groups,
           sizeof(*clone->groups) * active->group_count);
    return 0;
}

bool tee_v2_active_matches_segment(const struct tee_v2_active_metadata *active,
                                   const uint8_t *segment, size_t segment_size,
                                   struct tee_v2_segment_header *header_out)
{
    struct tee_v2_segment_header header;
    if (!active || segment_size != active->config.segment_size ||
        !tee_v2_parse_segment_header(segment, segment_size, &header) ||
        header.file_id != active->file_id || header.chunk_id != active->chunk_id ||
        header.segment_index > active->segment_count) {
        return false;
    }
    if (header_out) *header_out = header;
    return true;
}

struct tee_v2_hmac_group_state *tee_v2_active_find_group(
    struct tee_v2_active_metadata *active, uint32_t segment_index)
{
    uint32_t i;
    if (!active || segment_index == 0) return NULL;
    for (i = 0; i < active->group_count; i++) {
        uint32_t start = active->groups[i].start_segment_index;
        if (segment_index >= start &&
            segment_index - start < active->groups[i].group_segment_count) {
            return &active->groups[i];
        }
    }
    return NULL;
}

int tee_v2_active_record_segment(struct tee_v2_active_metadata *active,
                                 uint32_t segment_index,
                                 uint64_t logical_location,
                                 const uint8_t *segment)
{
    struct tee_v2_hmac_group_state *group;
    struct tee_v2_segment_header header;
    uint32_t slot;
    if (!active || !segment || segment_index == 0 ||
        segment_index > active->segment_count ||
        logical_location == TEE_V2_LOCATION_UNSET ||
        !tee_v2_active_matches_segment(active, segment,
                                       active->config.segment_size, &header) ||
        header.segment_index != segment_index) return -1;
    slot = segment_index - 1;
    if (active->arrived[slot]) return 1;
    group = tee_v2_active_find_group(active, segment_index);
    if (!group) return -1;
    active->segment_locations[slot] = logical_location;
    memcpy(active->segment_bytes + (size_t)slot * active->config.segment_size,
           segment, active->config.segment_size);
    active->arrived[slot] = true;
    active->pending[slot] = true;
    group->arrived_count++;
    return 0;
}

bool tee_v2_active_complete(const struct tee_v2_active_metadata *active)
{
    uint32_t i;
    if (!active) return false;
    for (i = 0; i < active->segment_count; i++) {
        if (!active->arrived[i]) return false;
    }
    for (i = 0; i < active->group_count; i++) {
        if (!active->groups[i].verified) return false;
    }
    return true;
}
