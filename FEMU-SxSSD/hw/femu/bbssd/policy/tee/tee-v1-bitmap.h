#ifndef TEE_V1_BITMAP_H
#define TEE_V1_BITMAP_H

#include <stdbool.h>
#include <stdint.h>

struct tee_v1_bitmap {
    uint8_t *bits;
    uint64_t bit_count;
    uint64_t byte_count;
};

int tee_v1_bitmap_init(struct tee_v1_bitmap *bitmap, uint64_t bit_count);
void tee_v1_bitmap_destroy(struct tee_v1_bitmap *bitmap);
int tee_v1_bitmap_set(struct tee_v1_bitmap *bitmap, uint64_t bit_index);
int tee_v1_bitmap_clear(struct tee_v1_bitmap *bitmap, uint64_t bit_index);
bool tee_v1_bitmap_test(const struct tee_v1_bitmap *bitmap, uint64_t bit_index);
bool tee_v1_bitmap_any_set(const struct tee_v1_bitmap *bitmap,
                           uint64_t first_bit,
                           uint64_t bit_count);

#endif
