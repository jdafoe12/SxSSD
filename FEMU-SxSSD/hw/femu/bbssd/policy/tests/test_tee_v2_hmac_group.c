#include "../tee/tee-v2-hmac-group.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void fill_segment(uint8_t *segment, uint32_t index)
{
    memset(segment, (int)index, 512);
    segment[0] = TEE_V2_SEGMENT_MAGIC;
    segment[1] = 3;
    segment[2] = 0x03; segment[3] = 0x02; segment[4] = 0x01;
    segment[5] = (uint8_t)index;
    segment[6] = (uint8_t)(index >> 8);
    segment[7] = (uint8_t)(index >> 16);
    segment[8] = (uint8_t)(index >> 24);
}

static void test_rfc4231_vector(void)
{
    static const uint8_t expected[32] = {
        0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53,
        0x5c,0xa8,0xaf,0xce,0xaf,0x0b,0xf1,0x2b,
        0x88,0x1d,0xc2,0x00,0xc9,0x83,0x3d,0xa7,
        0x26,0xe9,0x37,0x6c,0x2e,0x32,0xcf,0xf7
    };
    uint8_t key[20];
    uint8_t digest[32];
    memset(key, 0x0b, sizeof(key));
    tee_v2_hmac_sha256(key, sizeof(key), (const uint8_t *)"Hi There", 8, digest);
    assert(memcmp(digest, expected, sizeof(expected)) == 0);
}

static void test_group_larger_than_page_and_reuse(void)
{
    struct tee_v2_format_config config;
    struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec spec;
    uint8_t segments[10][512];
    uint8_t expected[32];
    uint32_t i;

    assert(tee_v2_format_config_init(&config, 512, 4096));
    for (i = 0; i < 10; i++) fill_segment(segments[i], i + 1);
    tee_v2_hmac_sha256(tee_v2_prototype_key, TEE_V2_PROTOTYPE_KEY_SIZE,
                       &segments[0][0], sizeof(segments), expected);
    spec = (struct tee_v2_hmac_group_spec){1, 10, expected};
    assert(tee_v2_active_metadata_init(&active, &config, 3, 0x010203,
                                       5030, 10, 1, &spec, 1) == 0);
    for (i = 0; i < 10; i++)
        assert(tee_v2_active_record_segment(&active, i + 1, 100 + i, segments[i]) == 0);
    assert(tee_v2_verify_hmac_group(&active, &active.groups[0],
                                    tee_v2_prototype_key,
                                    TEE_V2_PROTOTYPE_KEY_SIZE) == TEE_V2_HMAC_VERIFIED);
    assert(tee_v2_verify_hmac_group(&active, &active.groups[0],
                                    tee_v2_prototype_key,
                                    TEE_V2_PROTOTYPE_KEY_SIZE) == TEE_V2_HMAC_REUSED);
    tee_v2_active_metadata_destroy(&active);
}

static void test_failure_clears_group_working_state(void)
{
    struct tee_v2_format_config config;
    struct tee_v2_active_metadata active;
    struct tee_v2_hmac_group_spec spec;
    uint8_t bad[32] = {0};
    uint8_t segment[512];

    assert(tee_v2_format_config_init(&config, 512, 4096));
    spec = (struct tee_v2_hmac_group_spec){1, 1, bad};
    assert(tee_v2_active_metadata_init(&active, &config, 3, 0x010203,
                                       503, 1, 1, &spec, 1) == 0);
    fill_segment(segment, 1);
    assert(tee_v2_active_record_segment(&active, 1, 50, segment) == 0);
    assert(tee_v2_verify_hmac_group(&active, &active.groups[0],
                                    tee_v2_prototype_key,
                                    TEE_V2_PROTOTYPE_KEY_SIZE) == TEE_V2_HMAC_FAILED);
    assert(!active.arrived[0] && !active.pending[0]);
    assert(active.segment_locations[0] == TEE_V2_LOCATION_UNSET);
    tee_v2_active_metadata_destroy(&active);
}

int main(void)
{
    test_rfc4231_vector();
    test_group_larger_than_page_and_reuse();
    test_failure_clears_group_working_state();
    puts("test_tee_v2_hmac_group: PASS");
    return 0;
}
