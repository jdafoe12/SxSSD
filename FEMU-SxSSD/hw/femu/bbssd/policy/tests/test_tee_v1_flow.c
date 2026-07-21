#include "../tee/tee-v1-bitmap.h"
#include "../tee/tee-v1-guard.h"
#include "../tee/tee-v1-segment.h"

#include <assert.h>
#include <stdio.h>

static void test_normal_write_is_pass_through(void)
{
    struct tee_v1_segment_layout layout;
    struct tee_v1_bitmap protected_bitmap;
    struct tee_v1_bitmap pending_bitmap;
    uint16_t status;

    assert(tee_v1_segment_layout_init(&layout, 10000, 512, 4096));
    assert(tee_v1_bitmap_init(&protected_bitmap, layout.visible_segments) == 0);
    assert(tee_v1_bitmap_init(&pending_bitmap, layout.visible_segments) == 0);

    status = tee_v1_check_write_allowed(&layout, &protected_bitmap,
                                        &pending_bitmap, 200, 16);
    assert(status == NVME_SUCCESS);
    assert(!tee_v1_bitmap_any_set(&protected_bitmap, 200, 16));
    assert(!tee_v1_bitmap_any_set(&pending_bitmap, 200, 16));

    tee_v1_bitmap_destroy(&protected_bitmap);
    tee_v1_bitmap_destroy(&pending_bitmap);
}

static void test_hidden_region_guard(void)
{
    struct tee_v1_segment_layout layout;

    assert(tee_v1_segment_layout_init(&layout, 10000, 512, 4096));
    assert(tee_v1_check_user_lba_range(&layout, 0, 1) == NVME_SUCCESS);
    assert(tee_v1_check_user_lba_range(&layout, 5903, 1) == NVME_SUCCESS);
    assert(tee_v1_check_user_lba_range(&layout, 5903, 2) ==
           (NVME_LBA_RANGE | NVME_DNR));
    assert(tee_v1_check_user_lba_range(&layout, 5904, 1) ==
           (NVME_LBA_RANGE | NVME_DNR));
}

int main(void)
{
    test_normal_write_is_pass_through();
    test_hidden_region_guard();

    puts("test_tee_v1_flow: PASS");
    return 0;
}
