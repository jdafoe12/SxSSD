#include "../tee/tee-v1-bitmap.h"
#include "../tee/tee-v1-guard.h"
#include "../tee/tee-v1-segment.h"

#include <assert.h>
#include <stdio.h>

static void test_write_guard_status(void)
{
    struct tee_v1_segment_layout layout;
    struct tee_v1_bitmap protected_bitmap;
    struct tee_v1_bitmap pending_bitmap;
    uint16_t status;

    assert(tee_v1_segment_layout_init(&layout, 10000, 512, 4096));
    assert(tee_v1_bitmap_init(&protected_bitmap, layout.visible_segments) == 0);
    assert(tee_v1_bitmap_init(&pending_bitmap, layout.visible_segments) == 0);

    status = tee_v1_check_write_allowed(&layout, &protected_bitmap,
                                        &pending_bitmap, 10, 4);
    assert(status == NVME_SUCCESS);

    assert(tee_v1_bitmap_set(&protected_bitmap, 12) == 0);
    status = tee_v1_check_write_allowed(&layout, &protected_bitmap,
                                        &pending_bitmap, 10, 4);
    assert(status == (NVME_INVALID_FIELD | NVME_DNR));

    assert(tee_v1_bitmap_clear(&protected_bitmap, 12) == 0);
    assert(tee_v1_bitmap_set(&pending_bitmap, 11) == 0);
    status = tee_v1_check_write_allowed(&layout, &protected_bitmap,
                                        &pending_bitmap, 10, 4);
    assert(status == (NVME_INVALID_FIELD | NVME_DNR));

    status = tee_v1_check_write_allowed(&layout, &protected_bitmap,
                                        &pending_bitmap, 5900, 5);
    assert(status == (NVME_LBA_RANGE | NVME_DNR));

    tee_v1_bitmap_destroy(&protected_bitmap);
    tee_v1_bitmap_destroy(&pending_bitmap);
}

int main(void)
{
    test_write_guard_status();

    puts("test_tee_v1_guard: PASS");
    return 0;
}
