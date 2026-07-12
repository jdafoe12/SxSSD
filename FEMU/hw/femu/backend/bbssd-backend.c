#include <errno.h>
#include "bbssd-backend.h"

int bbssd_backend_read_pages(SsdDramBackend *mbe, uint8_t *page_bufs,
                             const uint64_t *page_idxs, const bool *mapped,
                             uint32_t nr_pages, uint32_t page_size)
{
    uint8_t *base;
    int ret = 0;

    if (!mbe || !page_bufs || (!page_idxs && nr_pages) || !page_size) {
        return -EINVAL;
    }

    base = mbe->logical_space;
    for (uint32_t i = 0; i < nr_pages; i++) {
        uint8_t *page = page_bufs + (uint64_t)i * page_size;

        if (!mapped || !mapped[i]) {
            memset(page, 0, page_size);
            continue;
        }

        memcpy(page, base + page_idxs[i] * page_size, page_size);
    }
    return ret;
}

int bbssd_backend_write_pages(SsdDramBackend *mbe, const uint8_t *page_bufs,
                              const uint64_t *page_idxs, uint32_t nr_pages,
                              uint32_t page_size)
{
    uint8_t *base;

    if (!mbe || !page_bufs || (!page_idxs && nr_pages) || !page_size) {
        return -EINVAL;
    }

    base = mbe->logical_space;
    for (uint32_t i = 0; i < nr_pages; i++) {
        memcpy(base + page_idxs[i] * page_size,
               page_bufs + (uint64_t)i * page_size, page_size);
    }

    return 0;
}
