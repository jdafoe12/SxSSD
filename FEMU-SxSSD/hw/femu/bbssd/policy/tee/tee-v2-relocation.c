#include "tee-v2-relocation.h"

#include <stdlib.h>
#include <string.h>

enum tee_v2_relocation_result tee_v2_relocate_passive_segment(
    struct tee_v2_cache *cache, const struct tee_v1_bitmap *pending_bitmap,
    struct tee_v2_passive_metadata *passive, uint32_t segment_index,
    uint64_t new_location, const uint8_t *incoming, size_t segment_size,
    tee_v2_read_segment_fn read_old, void *read_opaque,
    struct tee_v2_relocation_trace *trace)
{
    uint8_t *old_bytes;
    uint64_t old_location;
    uint32_t slot;
    if (trace) memset(trace, 0, sizeof(*trace));
    if (!cache || !pending_bitmap || !passive || !incoming || !read_old ||
        segment_index == 0 || segment_index > passive->segment_count ||
        segment_size == 0 || new_location >= pending_bitmap->bit_count)
        return TEE_V2_RELOCATION_ERROR;
    if (tee_v2_cache_is_protected(cache, new_location) ||
        tee_v1_bitmap_test(pending_bitmap, new_location))
        return TEE_V2_RELOCATION_REJECTED;
    slot = segment_index - 1;
    old_location = passive->segment_locations[slot];
    if (!tee_v2_cache_is_protected(cache, old_location))
        return TEE_V2_RELOCATION_ERROR;
    old_bytes = malloc(segment_size);
    if (!old_bytes) return TEE_V2_RELOCATION_ERROR;
    if (read_old(read_opaque, old_location, old_bytes, segment_size) != 0) {
        free(old_bytes); return TEE_V2_RELOCATION_ERROR;
    }
    if (memcmp(old_bytes, incoming, segment_size) != 0) {
        free(old_bytes); return TEE_V2_RELOCATION_CHANGED;
    }
    free(old_bytes);

    /* V2 records the required durable ordering; persistence/transactions are V4. */
    if (tee_v2_cache_mark_protected(cache, new_location) != 0)
        return TEE_V2_RELOCATION_ERROR;
    if (trace) trace->events[trace->count++] = TEE_V2_RELOCATION_MARK_NEW;
    passive->segment_locations[slot] = new_location;
    if (tee_v2_cache_unmark_protected(cache, old_location) != 0)
        return TEE_V2_RELOCATION_ERROR;
    if (trace) trace->events[trace->count++] = TEE_V2_RELOCATION_UNMARK_OLD;
    return TEE_V2_RELOCATED;
}
