#ifndef FEMU_FTL_WRITE_STATUS_H
#define FEMU_FTL_WRITE_STATUS_H

#include <stdbool.h>

static inline bool ftl_page_program_succeeded(int raw_write_rc,
                                              int page_status)
{
    return raw_write_rc == 0 && page_status == 0;
}

#endif
