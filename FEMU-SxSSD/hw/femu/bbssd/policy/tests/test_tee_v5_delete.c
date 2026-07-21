#include "../tee/tee-v5-delete.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_BITMAP_BITS 128U

struct persist_observer {
    int result;
    uint32_t calls;
    uint32_t expected_count;
    uint8_t deleted_file_id;
    uint32_t deleted_chunk_id;
    uint64_t expected_set[8];
    uint32_t expected_set_count;
};

struct cache_snapshot {
    uint8_t bitmap[(TEST_BITMAP_BITS + 7U) / 8U];
    uint32_t passive_count;
    uint8_t file_ids[8];
    uint32_t chunk_ids[8];
    uint32_t segment_counts[8];
    uint64_t locations[8][4];
};

static int observe_persist(void *opaque,
                           const struct tee_v1_bitmap *bitmap,
                           const struct tee_v2_passive_metadata *records,
                           uint32_t record_count)
{
    struct persist_observer *observer = opaque;
    uint32_t i;

    observer->calls++;
    assert(bitmap != NULL);
    assert(record_count == observer->expected_count);
    for (i = 0; i < record_count; i++) {
        assert(records[i].file_id != observer->deleted_file_id ||
               records[i].chunk_id != observer->deleted_chunk_id);
    }
    for (i = 0; i < observer->expected_set_count; i++)
        assert(tee_v1_bitmap_test(bitmap, observer->expected_set[i]));
    return observer->result;
}

static void add_record(struct tee_v2_cache *cache, uint8_t file_id,
                       uint32_t chunk_id, const uint64_t *locations,
                       uint32_t segment_count)
{
    struct tee_v2_passive_metadata passive;
    struct tee_v2_hmac_group_state group;
    uint32_t i;

    memset(&passive, 0, sizeof(passive));
    memset(&group, 0, sizeof(group));
    passive.file_id = file_id;
    passive.chunk_id = chunk_id;
    passive.chunk_size_bytes = (uint64_t)segment_count * 512U;
    passive.segment_count = segment_count;
    passive.number_coefficient = 2;
    passive.segment_locations = (uint64_t *)locations;
    passive.groups = &group;
    passive.group_count = 1;
    group.file_id = file_id;
    group.chunk_id = chunk_id;
    group.start_segment_index = 1;
    group.group_segment_count = segment_count;
    group.verified = true;
    assert(tee_v2_cache_store_passive(cache, &passive) == 0);
    for (i = 0; i < segment_count; i++)
        assert(tee_v2_cache_mark_protected(cache, locations[i]) == 0);
}

static void take_snapshot(const struct tee_v2_cache *cache,
                          struct cache_snapshot *snapshot)
{
    uint32_t i;

    memset(snapshot, 0, sizeof(*snapshot));
    assert(cache->protected_bitmap.byte_count <= sizeof(snapshot->bitmap));
    memcpy(snapshot->bitmap, cache->protected_bitmap.bits,
           cache->protected_bitmap.byte_count);
    snapshot->passive_count = cache->passive_count;
    assert(cache->passive_count <= 8);
    for (i = 0; i < cache->passive_count; i++) {
        const struct tee_v2_passive_metadata *record =
            &cache->passive_records[i];
        assert(record->segment_count <= 4);
        snapshot->file_ids[i] = record->file_id;
        snapshot->chunk_ids[i] = record->chunk_id;
        snapshot->segment_counts[i] = record->segment_count;
        memcpy(snapshot->locations[i], record->segment_locations,
               sizeof(uint64_t) * record->segment_count);
    }
}

static void assert_snapshot_equal(const struct tee_v2_cache *cache,
                                  const struct cache_snapshot *snapshot)
{
    uint32_t i;

    assert(cache->passive_count == snapshot->passive_count);
    assert(memcmp(cache->protected_bitmap.bits, snapshot->bitmap,
                  cache->protected_bitmap.byte_count) == 0);
    for (i = 0; i < cache->passive_count; i++) {
        const struct tee_v2_passive_metadata *record =
            &cache->passive_records[i];
        assert(record->file_id == snapshot->file_ids[i]);
        assert(record->chunk_id == snapshot->chunk_ids[i]);
        assert(record->segment_count == snapshot->segment_counts[i]);
        assert(memcmp(record->segment_locations, snapshot->locations[i],
                      sizeof(uint64_t) * record->segment_count) == 0);
    }
}

static void test_delete_position(uint32_t delete_index)
{
    static const uint64_t locations[3][2] = {{10, 11}, {20, 21}, {30, 31}};
    struct tee_v2_cache cache;
    struct persist_observer observer;
    uint32_t failed_segment = UINT32_MAX;
    uint32_t i;

    assert(tee_v2_cache_init(&cache, TEST_BITMAP_BITS, 8) == 0);
    for (i = 0; i < 3; i++)
        add_record(&cache, 7, 100 + i, locations[i], 2);
    memset(&observer, 0, sizeof(observer));
    observer.expected_count = 2;
    observer.deleted_file_id = 7;
    observer.deleted_chunk_id = 100 + delete_index;
    for (i = 0; i < 3; i++) {
        if (i == delete_index) continue;
        observer.expected_set[observer.expected_set_count++] = locations[i][0];
        observer.expected_set[observer.expected_set_count++] = locations[i][1];
    }

    assert(tee_v5_delete_chunk(&cache, 7, 100 + delete_index,
                               observe_persist, &observer,
                               &failed_segment) == TEE_V5_DELETE_OK);
    assert(observer.calls == 1);
    assert(cache.passive_count == 2);
    assert(tee_v2_cache_find_passive(&cache, 7, 100 + delete_index) == NULL);
    assert(!tee_v2_cache_is_protected(&cache, locations[delete_index][0]));
    assert(!tee_v2_cache_is_protected(&cache, locations[delete_index][1]));
    tee_v2_cache_destroy(&cache);
}

static void test_shared_location_remains_protected(void)
{
    const uint64_t first[] = {40, 41};
    const uint64_t second[] = {41, 42};
    struct tee_v2_cache cache;
    struct persist_observer observer;
    uint32_t failed_segment = UINT32_MAX;

    assert(tee_v2_cache_init(&cache, TEST_BITMAP_BITS, 4) == 0);
    add_record(&cache, 1, 10, first, 2);
    add_record(&cache, 2, 20, second, 2);
    memset(&observer, 0, sizeof(observer));
    observer.expected_count = 1;
    observer.deleted_file_id = 1;
    observer.deleted_chunk_id = 10;
    observer.expected_set[0] = 41;
    observer.expected_set[1] = 42;
    observer.expected_set_count = 2;

    assert(tee_v5_delete_chunk(&cache, 1, 10, observe_persist, &observer,
                               &failed_segment) == TEE_V5_DELETE_OK);
    assert(!tee_v2_cache_is_protected(&cache, 40));
    assert(tee_v2_cache_is_protected(&cache, 41));
    assert(tee_v2_cache_is_protected(&cache, 42));
    tee_v2_cache_destroy(&cache);
}

static void test_absent_does_not_persist_or_mutate(void)
{
    const uint64_t locations[] = {50, 51};
    struct tee_v2_cache cache;
    struct cache_snapshot before;
    struct persist_observer observer;
    uint32_t failed_segment = UINT32_MAX;

    assert(tee_v2_cache_init(&cache, TEST_BITMAP_BITS, 4) == 0);
    add_record(&cache, 3, 30, locations, 2);
    take_snapshot(&cache, &before);
    memset(&observer, 0, sizeof(observer));
    assert(tee_v5_delete_chunk(&cache, 3, 31, observe_persist, &observer,
                               &failed_segment) == TEE_V5_DELETE_NOT_FOUND);
    assert(observer.calls == 0);
    assert_snapshot_equal(&cache, &before);
    tee_v2_cache_destroy(&cache);
}

static void test_persist_failure_is_full_rollback(void)
{
    const uint64_t first[] = {60, 61};
    const uint64_t second[] = {61, 62};
    struct tee_v2_cache cache;
    struct cache_snapshot before;
    struct persist_observer observer;
    uint32_t failed_segment = UINT32_MAX;

    assert(tee_v2_cache_init(&cache, TEST_BITMAP_BITS, 4) == 0);
    add_record(&cache, 4, 40, first, 2);
    add_record(&cache, 5, 50, second, 2);
    take_snapshot(&cache, &before);
    memset(&observer, 0, sizeof(observer));
    observer.result = -1;
    observer.expected_count = 1;
    observer.deleted_file_id = 4;
    observer.deleted_chunk_id = 40;
    observer.expected_set[0] = 61;
    observer.expected_set[1] = 62;
    observer.expected_set_count = 2;

    assert(tee_v5_delete_chunk(&cache, 4, 40, observe_persist, &observer,
                               &failed_segment) == TEE_V5_DELETE_INTERNAL);
    assert(observer.calls == 1);
    assert_snapshot_equal(&cache, &before);
    tee_v2_cache_destroy(&cache);
}

static void test_integrity_failure_reports_segment_and_does_not_persist(void)
{
    const uint64_t locations[] = {70, 71};
    struct tee_v2_cache cache;
    struct cache_snapshot before;
    struct persist_observer observer;
    uint32_t failed_segment = UINT32_MAX;

    assert(tee_v2_cache_init(&cache, TEST_BITMAP_BITS, 4) == 0);
    add_record(&cache, 6, 60, locations, 2);
    assert(tee_v2_cache_unmark_protected(&cache, 71) == 0);
    take_snapshot(&cache, &before);
    memset(&observer, 0, sizeof(observer));

    assert(tee_v5_delete_chunk(&cache, 6, 60, observe_persist, &observer,
                               &failed_segment) == TEE_V5_DELETE_INTEGRITY);
    assert(observer.calls == 0);
    assert(failed_segment == 2);
    assert_snapshot_equal(&cache, &before);
    tee_v2_cache_destroy(&cache);
}

static void test_malformed_record_is_integrity_failure(void)
{
    const uint64_t locations[] = {80, 81};
    struct tee_v2_cache cache;
    struct persist_observer observer;
    uint32_t failed_segment = UINT32_MAX;

    assert(tee_v2_cache_init(&cache, TEST_BITMAP_BITS, 4) == 0);
    add_record(&cache, 8, 80, locations, 2);
    cache.passive_records[0].segment_count = 0;
    memset(&observer, 0, sizeof(observer));

    assert(tee_v5_delete_chunk(&cache, 8, 80, observe_persist, &observer,
                               &failed_segment) == TEE_V5_DELETE_INTEGRITY);
    assert(observer.calls == 0);
    assert(tee_v2_cache_find_passive(&cache, 8, 80) != NULL);
    tee_v2_cache_destroy(&cache);
}

int main(void)
{
    test_delete_position(0);
    test_delete_position(1);
    test_delete_position(2);
    test_shared_location_remains_protected();
    test_absent_does_not_persist_or_mutate();
    test_persist_failure_is_full_rollback();
    test_integrity_failure_reports_segment_and_does_not_persist();
    test_malformed_record_is_integrity_failure();
    puts("test_tee_v5_delete: PASS");
    return 0;
}
