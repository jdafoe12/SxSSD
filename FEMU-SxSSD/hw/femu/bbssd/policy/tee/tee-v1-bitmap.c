#include "tee-v1-bitmap.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static bool bitmap_range_valid(const struct tee_v1_bitmap *bitmap,
                               uint64_t first_bit,
                               uint64_t bit_count)
{
    if (!bitmap || !bitmap->bits || bit_count == 0) {
        return false;
    }

    if (first_bit >= bitmap->bit_count ||
        bit_count > bitmap->bit_count - first_bit) {
        return false;
    }

    return true;
}

int tee_v1_bitmap_init(struct tee_v1_bitmap *bitmap, uint64_t bit_count)
{
    uint64_t byte_count;

    if (!bitmap || bit_count == 0 || bit_count > UINT64_MAX - 7) {
        return -1;
    }

    byte_count = (bit_count + 7) / 8;
    bitmap->bits = calloc((size_t)byte_count, 1);
    if (!bitmap->bits) {
        return -1;
    }

    bitmap->bit_count = bit_count;
    bitmap->byte_count = byte_count;
    return 0;
}

void tee_v1_bitmap_destroy(struct tee_v1_bitmap *bitmap)
{
    if (!bitmap) {
        return;
    }

    free(bitmap->bits);
    memset(bitmap, 0, sizeof(*bitmap));
}

int tee_v1_bitmap_set(struct tee_v1_bitmap *bitmap, uint64_t bit_index)
{
    if (!bitmap || !bitmap->bits || bit_index >= bitmap->bit_count) {
        return -1;
    }

    bitmap->bits[bit_index / 8] |= (uint8_t)(1U << (bit_index % 8));
    return 0;
}

int tee_v1_bitmap_clear(struct tee_v1_bitmap *bitmap, uint64_t bit_index)
{
    if (!bitmap || !bitmap->bits || bit_index >= bitmap->bit_count) {
        return -1;
    }

    bitmap->bits[bit_index / 8] &= (uint8_t)~(1U << (bit_index % 8));
    return 0;
}

bool tee_v1_bitmap_test(const struct tee_v1_bitmap *bitmap, uint64_t bit_index)
{
    if (!bitmap || !bitmap->bits || bit_index >= bitmap->bit_count) {
        return false;
    }

    return (bitmap->bits[bit_index / 8] & (uint8_t)(1U << (bit_index % 8))) != 0;
}

bool tee_v1_bitmap_any_set(const struct tee_v1_bitmap *bitmap,
                           uint64_t first_bit,
                           uint64_t bit_count)
{
    uint64_t bit_index;

    if (!bitmap_range_valid(bitmap, first_bit, bit_count)) {
        return false;
    }

    for (bit_index = first_bit; bit_index < first_bit + bit_count; bit_index++) {
        if (tee_v1_bitmap_test(bitmap, bit_index)) {
            return true;
        }
    }

    return false;
}
