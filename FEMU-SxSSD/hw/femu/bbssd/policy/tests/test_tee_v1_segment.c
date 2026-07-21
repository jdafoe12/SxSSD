#include "../tee/tee-v1-segment.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

static void test_segment_layout_reserves_hidden_tail(void)
{
    struct tee_v1_segment_layout layout;

    assert(tee_v1_segment_layout_init(&layout, 10000, 512, 4096));
    assert(layout.visible_lbas == 5904);
    assert(layout.hidden_start_lba == 5904);
    assert(layout.hidden_lba_count == 4096);
    assert(layout.visible_segments == 5904);
}

static void test_lba_range_maps_to_visible_segments(void)
{
    struct tee_v1_segment_layout layout;
    uint64_t first = 0;
    uint64_t count = 0;

    assert(tee_v1_segment_layout_init(&layout, 10000, 512, 4096));
    assert(tee_v1_lba_range_to_segments(&layout, 100, 8, &first, &count));
    assert(first == 100);
    assert(count == 8);

    assert(tee_v1_lba_range_to_segments(&layout, 5903, 1, &first, &count));
    assert(first == 5903);
    assert(count == 1);
}

static void test_hidden_region_is_not_user_segment_space(void)
{
    struct tee_v1_segment_layout layout;
    uint64_t first = 0;
    uint64_t count = 0;

    assert(tee_v1_segment_layout_init(&layout, 10000, 512, 4096));
    assert(!tee_v1_lba_range_to_segments(&layout, 5903, 2, &first, &count));
    assert(!tee_v1_lba_range_to_segments(&layout, 5904, 1, &first, &count));
    assert(!tee_v1_lba_range_to_segments(&layout, UINT64_MAX, 2, &first, &count));
}

int main(void)
{
    test_segment_layout_reserves_hidden_tail();
    test_lba_range_maps_to_visible_segments();
    test_hidden_region_is_not_user_segment_space();

    puts("test_tee_v1_segment: PASS");
    return 0;
}
