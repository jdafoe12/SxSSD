#ifndef TEE_V5_DELETE_H
#define TEE_V5_DELETE_H

#include "tee-v2-cache.h"

#include <stdint.h>

enum tee_v5_delete_result {
    TEE_V5_DELETE_OK = 0,
    TEE_V5_DELETE_NOT_FOUND = 1,
    TEE_V5_DELETE_INTEGRITY = 2,
    TEE_V5_DELETE_INTERNAL = 3
};

typedef int (*tee_v5_delete_persist_fn)(
    void *opaque, const struct tee_v1_bitmap *protected_bitmap,
    const struct tee_v2_passive_metadata *records, uint32_t record_count);

/*
 * Delete is transactional: persist receives the complete prospective image,
 * and the live cache is published only after persistence succeeds.
 */
enum tee_v5_delete_result tee_v5_delete_chunk(
    struct tee_v2_cache *cache, uint8_t file_id, uint32_t chunk_id,
    tee_v5_delete_persist_fn persist, void *persist_opaque,
    uint32_t *failed_segment_index);

#endif
