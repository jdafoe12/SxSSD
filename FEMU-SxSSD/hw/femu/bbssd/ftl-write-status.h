#ifndef FEMU_FTL_WRITE_STATUS_H
#define FEMU_FTL_WRITE_STATUS_H

#include <stdbool.h>
#include <stddef.h>

static inline void ftl_init_page_program_statuses(int *statuses, size_t count)
{
    size_t i;
    if (!statuses) return;
    for (i = 0; i < count; i++) statuses[i] = -1;
}

static inline bool ftl_page_program_succeeded(int raw_write_rc,
                                              int page_status)
{
    return raw_write_rc == 0 && page_status == 0;
}

#endif
