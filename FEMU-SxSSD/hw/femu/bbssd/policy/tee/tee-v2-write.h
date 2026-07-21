#ifndef TEE_V2_WRITE_H
#define TEE_V2_WRITE_H

#include "tee-v2-cache.h"
#include "tee-v2-hmac-group.h"

enum tee_v2_write_result {
    TEE_V2_WRITE_NORMAL = 0,
    TEE_V2_WRITE_PENDING = 1,
    TEE_V2_WRITE_GROUP_VERIFIED = 2,
    TEE_V2_WRITE_CHUNK_COMPLETE = 3,
    TEE_V2_WRITE_RELOCATION = 4,
    TEE_V2_WRITE_HMAC_FAILED_NORMAL = 5,
    TEE_V2_WRITE_REJECTED = -1,
    TEE_V2_WRITE_ERROR = -2
};

struct tee_v2_write_context {
    struct tee_v2_active_metadata *active; /* RAM working state, never cache. */
    struct tee_v2_cache *cache;
    struct tee_v1_bitmap pending_bitmap;   /* RAM working state, never cache. */
    bool active_promoted;
    int (*promotion_hook)(void *opaque,
                          const struct tee_v2_cache *cache,
                          const struct tee_v2_passive_metadata *passive);
    void *promotion_hook_opaque;
    int (*relocation_observer)(void *opaque, uint8_t file_id,
                               uint32_t chunk_id, uint32_t segment_index,
                               uint64_t old_location,
                               uint64_t new_location);
    void *relocation_observer_opaque;
    int (*operation_advance)(void *opaque, uint64_t ops);
    void *operation_advance_opaque;
    int (*relocation_cancel)(void *opaque, uint32_t count);
    void *relocation_cancel_opaque;
};

int tee_v2_write_context_init(struct tee_v2_write_context *write,
                              struct tee_v2_active_metadata *active,
                              struct tee_v2_cache *cache,
                              uint64_t logical_segment_count);
void tee_v2_write_context_destroy(struct tee_v2_write_context *write);
void tee_v2_write_set_promotion_hook(
    struct tee_v2_write_context *write,
    int (*hook)(void *, const struct tee_v2_cache *,
                const struct tee_v2_passive_metadata *),
    void *opaque);
void tee_v2_write_set_relocation_observer(
    struct tee_v2_write_context *write,
    int (*observer)(void *, uint8_t, uint32_t, uint32_t, uint64_t, uint64_t),
    void *opaque);
int tee_v2_write_observe_relocation(struct tee_v2_write_context *write,
                                    uint8_t file_id, uint32_t chunk_id,
                                    uint32_t segment_index,
                                    uint64_t old_location,
                                    uint64_t new_location);
void tee_v2_write_set_operation_advance(
    struct tee_v2_write_context *write,
    int (*advance)(void *, uint64_t), void *opaque);
int tee_v2_write_advance_operation(struct tee_v2_write_context *write,
                                   uint64_t ops);
void tee_v2_write_set_relocation_cancel(
    struct tee_v2_write_context *write,
    int (*cancel)(void *, uint32_t), void *opaque);
int tee_v2_write_cancel_relocations(struct tee_v2_write_context *write,
                                    uint32_t count);
bool tee_v2_write_range_allowed(const struct tee_v2_write_context *write,
                                uint64_t first_segment,
                                uint64_t segment_count);
bool tee_v2_write_page_range_allowed(const struct tee_v2_write_context *write,
                                     uint64_t first_segment,
                                     uint64_t segment_count,
                                     uint32_t segments_per_page);
bool tee_v2_write_can_activate_identity(struct tee_v2_write_context *write,
                                        uint8_t file_id,
                                        uint32_t chunk_id);
bool tee_v2_media_write_complete(uint64_t expected_pages,
                                 uint64_t committed_pages,
                                 uint64_t expected_bytes,
                                 uint64_t consumed_bytes);
enum tee_v2_write_result tee_v2_apply_segment_after_media(
    struct tee_v2_write_context *write, bool media_complete,
    uint64_t logical_location, const uint8_t *segment, size_t segment_size);
void tee_v2_write_abandon_active(struct tee_v2_write_context *write);
enum tee_v2_write_result tee_v2_classify_segment_write(
    struct tee_v2_write_context *write, uint64_t logical_location,
    const uint8_t *segment, size_t segment_size,
    struct tee_v2_passive_metadata **passive_out,
    uint32_t *segment_index_out);
int tee_v2_preflight_segment_request(
    struct tee_v2_write_context *write, uint64_t first_location,
    const uint8_t *segments, size_t segment_size, uint64_t segment_count,
    enum tee_v2_write_result *results,
    struct tee_v2_passive_metadata **passives,
    uint32_t *segment_indices);
enum tee_v2_write_result tee_v2_process_segment_write(
    struct tee_v2_write_context *write, uint64_t logical_location,
    const uint8_t *segment, size_t segment_size,
    struct tee_v2_passive_metadata **passive_out,
    uint32_t *segment_index_out);

#endif
