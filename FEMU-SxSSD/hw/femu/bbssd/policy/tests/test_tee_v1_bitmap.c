#include "../tee/tee-v1-bitmap.h"

#include <assert.h>
#include <stdio.h>

static void test_bitmap_set_clear_check(void)
{
    struct tee_v1_bitmap bitmap;

    assert(tee_v1_bitmap_init(&bitmap, 130) == 0);
    assert(!tee_v1_bitmap_test(&bitmap, 0));
    assert(!tee_v1_bitmap_test(&bitmap, 129));

    assert(tee_v1_bitmap_set(&bitmap, 0) == 0);
    assert(tee_v1_bitmap_set(&bitmap, 64) == 0);
    assert(tee_v1_bitmap_set(&bitmap, 129) == 0);
    assert(tee_v1_bitmap_test(&bitmap, 0));
    assert(tee_v1_bitmap_test(&bitmap, 64));
    assert(tee_v1_bitmap_test(&bitmap, 129));

    assert(tee_v1_bitmap_any_set(&bitmap, 63, 2));
    assert(tee_v1_bitmap_any_set(&bitmap, 128, 2));
    assert(!tee_v1_bitmap_any_set(&bitmap, 1, 63));

    assert(tee_v1_bitmap_clear(&bitmap, 64) == 0);
    assert(!tee_v1_bitmap_test(&bitmap, 64));
    assert(tee_v1_bitmap_set(&bitmap, 130) < 0);

    tee_v1_bitmap_destroy(&bitmap);
}

int main(void)
{
    test_bitmap_set_clear_check();

    puts("test_tee_v1_bitmap: PASS");
    return 0;
}
