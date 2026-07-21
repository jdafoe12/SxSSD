#include "../tee/tee-v2-cache.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct tee_v2_cache cache;
    struct tee_v2_passive_metadata passive = {0};
    uint64_t locations[2] = {10, 20};
    struct tee_v2_passive_metadata *found;

    passive.file_id = 5;
    passive.chunk_id = 6;
    passive.segment_count = 2;
    passive.segment_locations = locations;
    assert(tee_v2_cache_init(&cache, 128, 4) == 0);
    assert(tee_v2_cache_store_passive(&cache, &passive) == 0);
    locations[0] = 99;
    found = tee_v2_cache_find_passive(&cache, 5, 6);
    assert(found && found->segment_locations[0] == 10);
    assert(tee_v2_cache_mark_protected(&cache, 10) == 0);
    assert(tee_v2_cache_is_protected(&cache, 10));
    assert(!tee_v2_cache_is_protected(&cache, 11));
    assert(cache.passive_count == 1);
    tee_v2_cache_destroy(&cache);
    puts("test_tee_v2_cache: PASS");
    return 0;
}
