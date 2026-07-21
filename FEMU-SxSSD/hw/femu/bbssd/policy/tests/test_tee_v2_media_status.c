#include "../../ftl-write-status.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    assert(ftl_page_program_succeeded(0, 0));
    assert(!ftl_page_program_succeeded(-1, 0));
    assert(!ftl_page_program_succeeded(0, 1));
    assert(!ftl_page_program_succeeded(-1, 1));
    puts("test_tee_v2_media_status: PASS");
    return 0;
}
