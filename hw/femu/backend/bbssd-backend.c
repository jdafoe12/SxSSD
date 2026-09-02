#include <errno.h>
#include <string.h>

#include "bbssd-backend.h"

static int bbssd_backend_page_offset(const SsdDramBackend *mbe,
                                     uint64_t page_index,
                                     uint32_t page_size,
                                     uint64_t *offset)
{
    uint64_t page_offset;

    if (!mbe || !mbe->logical_space || !page_size ||
        page_index > UINT64_MAX / page_size) {
        return -EINVAL;
    }

    page_offset = page_index * (uint64_t)page_size;
    if (page_offset > (uint64_t)mbe->size ||
        (uint64_t)page_size > (uint64_t)mbe->size - page_offset) {
        return -EINVAL;
    }

    *offset = page_offset;
    return 0;
}

int bbssd_backend_read_page(SsdDramBackend *mbe, uint8_t *page,
                            uint64_t page_index, uint32_t page_size)
{
    uint64_t offset;

    if (!page || bbssd_backend_page_offset(mbe, page_index, page_size,
                                            &offset) != 0) {
        return -EINVAL;
    }

    memcpy(page, (uint8_t *)mbe->logical_space + offset, page_size);
    return 0;
}

int bbssd_backend_write_page(SsdDramBackend *mbe, const uint8_t *page,
                             uint64_t page_index, uint32_t page_size)
{
    uint64_t offset;

    if (!page || bbssd_backend_page_offset(mbe, page_index, page_size,
                                            &offset) != 0) {
        return -EINVAL;
    }

    memcpy((uint8_t *)mbe->logical_space + offset, page, page_size);
    return 0;
}

int bbssd_backend_copy_page(SsdDramBackend *mbe, uint64_t source_page_index,
                            uint64_t destination_page_index,
                            uint32_t page_size)
{
    uint64_t source_offset;
    uint64_t destination_offset;

    if (bbssd_backend_page_offset(mbe, source_page_index, page_size,
                                  &source_offset) != 0 ||
        bbssd_backend_page_offset(mbe, destination_page_index, page_size,
                                  &destination_offset) != 0) {
        return -EINVAL;
    }

    memcpy((uint8_t *)mbe->logical_space + destination_offset,
           (uint8_t *)mbe->logical_space + source_offset, page_size);
    return 0;
}
