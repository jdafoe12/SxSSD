#include "../tee/tee-v3-storage.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int writes;
static int write_image(void *opaque, const uint8_t *data, size_t size)
{
    struct tee_v3_memory_backend *backend = opaque;
    writes++;
    if (size > backend->capacity) return -1;
    memcpy(backend->bytes, data, size);
    backend->size = size;
    return 0;
}

int main(void)
{
    struct tee_v1_segment_layout layout;
    struct tee_v3_storage store;
    struct tee_v3_memory_backend backend;
    struct tee_v1_bitmap bitmap;
    struct tee_v2_passive_metadata passive = {0};
    struct tee_v2_hmac_group_state group = {0};
    uint64_t locations[] = {7, 19};
    uint8_t bytes[4096] = {0};
    uint32_t i;

    assert(tee_v1_segment_layout_init(&layout, 200, 512, 8));
    backend.bytes = bytes; backend.capacity = sizeof(bytes); backend.size = 0;
    assert(tee_v3_storage_init(&store, &layout, write_image, &backend) == 0);
    assert(store.hidden_start_lba == 192 && store.capacity_bytes == 4096);
    assert(tee_v1_bitmap_init(&bitmap, layout.visible_segments) == 0);
    assert(tee_v1_bitmap_set(&bitmap, 7) == 0);
    assert(tee_v1_bitmap_set(&bitmap, 19) == 0);

    passive.file_id = 4; passive.chunk_id = 0x1234;
    passive.chunk_size_bytes = 1024; passive.segment_count = 2;
    passive.number_coefficient = 9; passive.segment_locations = locations;
    passive.group_count = 1; passive.groups = &group;
    group.file_id = 99; group.chunk_id = 99; /* RAM-only duplicates omitted. */
    group.start_segment_index = 1; group.group_segment_count = 2;
    group.arrived_count = 77; group.verified = true; /* RAM-only fields omitted. */
    for (i = 0; i < TEE_V2_HMAC_SIZE; i++) group.expected_hmac[i] = (uint8_t)i;

    assert(tee_v3_storage_persist(&store, &bitmap, &passive, 1) == 0);
    assert(writes == 1 && backend.size > bitmap.byte_count);
    assert(tee_v3_storage_validate_image(bytes, backend.size) == 0);
    assert(tee_v3_storage_image_record_count(bytes, backend.size) == 1);
    assert(tee_v3_storage_image_bitmap_test(bytes, backend.size, 7));
    assert(tee_v3_storage_image_bitmap_test(bytes, backend.size, 19));
    assert(tee_v3_storage_image_group_count(bytes, backend.size, 0) == 1);
    assert(tee_v3_storage_image_group_start(bytes, backend.size, 0, 0) == 1);
    assert(tee_v3_storage_image_group_segments(bytes, backend.size, 0, 0) == 2);
    assert(memcmp(tee_v3_storage_image_group_hmac(bytes, backend.size, 0, 0),
                  group.expected_hmac, TEE_V2_HMAC_SIZE) == 0);

    backend.capacity = 16;
    assert(tee_v3_storage_persist(&store, &bitmap, &passive, 1) != 0);
    assert(tee_v3_storage_init(&store, &layout, NULL, &backend) != 0);
    bytes[0] ^= 1;
    assert(tee_v3_storage_validate_image(bytes, backend.size) != 0);
    tee_v1_bitmap_destroy(&bitmap);
    puts("test_tee_v3_storage: PASS");
    return 0;
}
