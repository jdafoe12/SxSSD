#include "../../ftl-write-status.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    int untouched[2] = {0, 0};
    ftl_init_page_program_statuses(untouched, 2);
    assert(untouched[0] != 0 && untouched[1] != 0);
    assert(!ftl_page_program_succeeded(0, untouched[0]));
    assert(ftl_page_program_succeeded(0, 0));
    assert(!ftl_page_program_succeeded(-1, 0));
    assert(!ftl_page_program_succeeded(0, 1));
    assert(!ftl_page_program_succeeded(-1, 1));
    puts("test_tee_v2_media_status: PASS");
    return 0;
}
