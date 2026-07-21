#ifndef TEE_V2_RELOCATION_H
#define TEE_V2_RELOCATION_H

#include "tee-v2-cache.h"

#include <stddef.h>
#include <stdint.h>

enum tee_v2_relocation_result {
    TEE_V2_RELOCATED = 1,
    TEE_V2_RELOCATION_CHANGED = -1,
    TEE_V2_RELOCATION_REJECTED = -2,
    TEE_V2_RELOCATION_ERROR = -3
};

enum tee_v2_relocation_event {
    TEE_V2_RELOCATION_MARK_NEW = 1,
    TEE_V2_RELOCATION_UNMARK_OLD = 2
};

struct tee_v2_relocation_trace {
    enum tee_v2_relocation_event events[2];
    uint32_t count;
};

typedef int (*tee_v2_read_segment_fn)(void *opaque, uint64_t location,
                                      uint8_t *out, size_t size);

enum tee_v2_relocation_result tee_v2_relocate_passive_segment(
    struct tee_v2_cache *cache, const struct tee_v1_bitmap *pending_bitmap,
    struct tee_v2_passive_metadata *passive, uint32_t segment_index,
    uint64_t new_location, const uint8_t *incoming, size_t segment_size,
    tee_v2_read_segment_fn read_old, void *read_opaque,
    struct tee_v2_relocation_trace *trace);

#endif
