#include "../tee/tee-v2-active-metadata.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_rejects_ambiguous_groups_and_mismatched_record(void)
{
    struct tee_v2_format_config config;
    struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec groups[2];
    uint8_t hmac[TEE_V2_HMAC_SIZE] = {0};
    uint8_t segment[512] = {0};

    assert(tee_v2_format_config_init(&config, 512, 4096));
    groups[0] = (struct tee_v2_hmac_group_spec){1, 3, hmac};
    groups[1] = (struct tee_v2_hmac_group_spec){3, 2, hmac};
    assert(tee_v2_active_metadata_init(&active, &config, 1, 2, 2012, 4,
                                       1, groups, 2) == -1);
    groups[0] = (struct tee_v2_hmac_group_spec){1, 2, hmac};
    groups[1] = (struct tee_v2_hmac_group_spec){3, 2, hmac};
    assert(tee_v2_active_metadata_init(&active, &config, 1, 2, 2012, 4,
                                       1, groups, 2) == 0);
    segment[0] = TEE_V2_SEGMENT_MAGIC;
    segment[1] = 1;
    segment[2] = 2;
    segment[5] = 1;
    assert(tee_v2_active_record_segment(&active, 2, 10, segment) == -1);
    tee_v2_active_metadata_destroy(&active);
}

int main(void)
{
    struct tee_v2_format_config config;
    struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec groups[2];
    uint8_t hmac0[TEE_V2_HMAC_SIZE] = {1};
    uint8_t hmac1[TEE_V2_HMAC_SIZE] = {2};
    uint8_t segment[512] = {0};

    assert(tee_v2_format_config_init(&config, 512, 4096));
    groups[0] = (struct tee_v2_hmac_group_spec){1, 3, hmac0};
    groups[1] = (struct tee_v2_hmac_group_spec){4, 2, hmac1};
    assert(tee_v2_active_metadata_init(&active, &config, 7, 0x123456,
                                       2515, 5, 9, groups, 2) == 0);
    assert(active.file_id == 7 && active.chunk_id == 0x123456);
    assert(active.chunk_size_bytes == 2515 && active.segment_count == 5);
    assert(active.number_coefficient == 9 && active.group_count == 2);
    assert(active.group_capacity == TEE_V2_DEFAULT_HMAC_GROUP_CAPACITY);
    assert(active.groups[0].group_segment_count == 3);

    segment[0] = TEE_V2_SEGMENT_MAGIC;
    segment[1] = 7;
    segment[2] = 0x56; segment[3] = 0x34; segment[4] = 0x12;
    segment[5] = 2;
    assert(tee_v2_active_matches_segment(&active, segment, sizeof(segment), NULL));
    assert(tee_v2_active_record_segment(&active, 2, 44, segment) == 0);
    assert(active.arrived[1] && active.pending[1]);
    assert(active.segment_locations[1] == 44);
    assert(memcmp(active.segment_bytes + 512, segment, 512) == 0);
    assert(active.groups[0].arrived_count == 1);
    assert(tee_v2_active_record_segment(&active, 2, 45, segment) == 1);

    segment[1] = 8;
    assert(!tee_v2_active_matches_segment(&active, segment, sizeof(segment), NULL));
    tee_v2_active_metadata_destroy(&active);
    test_rejects_ambiguous_groups_and_mismatched_record();
    puts("test_tee_v2_active_metadata: PASS");
    return 0;
}
