#include "../tee/tee-v2-format.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_layout_configuration(void)
{
    struct tee_v2_format_config config;

    assert(tee_v2_format_config_init(&config, 0, 4096));
    assert(config.segment_size == 512);
    assert(config.page_size == 4096);
    assert(config.segments_per_page == 8);

    assert(tee_v2_format_config_init(&config, 1024, 8192));
    assert(config.segments_per_page == 8);
    assert(!tee_v2_format_config_init(&config, 512, 4000));
    assert(!tee_v2_format_config_init(&config, 8, 4096));
}

static void test_header_wire_layout_and_matching(void)
{
    struct tee_v2_segment_header header;
    uint8_t segment[512];

    memset(segment, 0xCC, sizeof(segment));
    segment[0] = TEE_V2_SEGMENT_MAGIC;
    segment[1] = 0x2A;
    segment[2] = 0x56;
    segment[3] = 0x34;
    segment[4] = 0x12;
    segment[5] = 0x78;
    segment[6] = 0x56;
    segment[7] = 0x34;
    segment[8] = 0x12;

    assert(tee_v2_parse_segment_header(segment, sizeof(segment), &header));
    assert(header.file_id == 0x2A);
    assert(header.chunk_id == 0x123456);
    assert(header.segment_index == 0x12345678);
    assert(tee_v2_header_matches(&header, 0x2A, 0x123456, 0x12345678));
    assert(!tee_v2_header_matches(&header, 0x2B, 0x123456, 0x12345678));

    segment[0] = 0xA6;
    assert(!tee_v2_parse_segment_header(segment, sizeof(segment), &header));
    assert(!tee_v2_parse_segment_header(segment, 8, &header));
}

int main(void)
{
    test_layout_configuration();
    test_header_wire_layout_and_matching();
    puts("test_tee_v2_format: PASS");
    return 0;
}
