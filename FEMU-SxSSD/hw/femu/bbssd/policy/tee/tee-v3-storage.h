#ifndef TEE_V3_STORAGE_H
#define TEE_V3_STORAGE_H

#include "tee-v1-segment.h"
#include "tee-v1-bitmap.h"
#include "tee-v2-passive-metadata.h"

#include <stddef.h>

#define TEE_V3_STORAGE_MAGIC 0x3354454dU
#define TEE_V3_STORAGE_VERSION 3U

typedef int (*tee_v3_storage_write_fn)(void *opaque, const uint8_t *data,
                                       size_t size);

struct tee_v3_storage {
    uint64_t hidden_start_lba;
    uint64_t capacity_bytes;
    tee_v3_storage_write_fn write;
    void *opaque;
};

struct tee_v3_memory_backend {
    uint8_t *bytes;
    size_t capacity;
    size_t size;
};

int tee_v3_storage_init(struct tee_v3_storage *storage,
                        const struct tee_v1_segment_layout *layout,
                        tee_v3_storage_write_fn write, void *opaque);
int tee_v3_storage_persist(struct tee_v3_storage *storage,
                           const struct tee_v1_bitmap *protected_bitmap,
                           const struct tee_v2_passive_metadata *records,
                           uint32_t record_count);
int tee_v3_storage_validate_image(const uint8_t *image, size_t size);
uint32_t tee_v3_storage_image_record_count(const uint8_t *image, size_t size);
bool tee_v3_storage_image_bitmap_test(const uint8_t *image, size_t size,
                                      uint64_t bit);
uint32_t tee_v3_storage_image_group_count(const uint8_t *image, size_t size,
                                          uint32_t record);
uint32_t tee_v3_storage_image_group_start(const uint8_t *image, size_t size,
                                          uint32_t record, uint32_t group);
uint32_t tee_v3_storage_image_group_segments(const uint8_t *image, size_t size,
                                             uint32_t record, uint32_t group);
const uint8_t *tee_v3_storage_image_group_hmac(const uint8_t *image, size_t size,
                                              uint32_t record, uint32_t group);

#endif
