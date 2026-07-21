#include "../tee/tee-v2-passive-metadata.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    struct tee_v2_format_config config;
    struct tee_v2_active_metadata active;
    struct tee_v2_passive_metadata passive;
    struct tee_v2_hmac_group_spec spec;
    uint8_t expected[32] = {9};

    assert(tee_v2_format_config_init(&config, 512, 4096));
    spec = (struct tee_v2_hmac_group_spec){1, 2, expected};
    assert(tee_v2_active_metadata_init(&active, &config, 4, 99, 1006, 2,
                                       17, &spec, 1) == 0);
    assert(tee_v2_passive_from_active(&passive, &active) == -1);
    active.arrived[0] = active.arrived[1] = true;
    active.groups[0].verified = true;
    active.segment_locations[0] = 500;
    active.segment_locations[1] = 900;
    assert(tee_v2_passive_from_active(&passive, &active) == 0);
    assert(passive.file_id == 4 && passive.chunk_id == 99);
    assert(passive.chunk_size_bytes == 1006 && passive.segment_count == 2);
    assert(passive.number_coefficient == 17);
    assert(passive.segment_locations[0] == 500);
    active.segment_locations[0] = 123;
    assert(passive.segment_locations[0] == 500);
    assert(tee_v2_passive_matches(&passive, 4, 99, 2));
    assert(!tee_v2_passive_matches(&passive, 4, 100, 2));
    tee_v2_passive_metadata_destroy(&passive);
    tee_v2_active_metadata_destroy(&active);
    puts("test_tee_v2_passive_metadata: PASS");
    return 0;
}
