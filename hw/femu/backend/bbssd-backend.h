#ifndef __FEMU_BBSSD_BACKEND_H
#define __FEMU_BBSSD_BACKEND_H

#include "../nvme.h"
#include "./dram.h"

/* BBSSD payload storage is addressed by physical page index. */
int bbssd_backend_read_page(SsdDramBackend *mbe, uint8_t *page,
                            uint64_t page_index, uint32_t page_size);
int bbssd_backend_write_page(SsdDramBackend *mbe, const uint8_t *page,
                             uint64_t page_index, uint32_t page_size);
int bbssd_backend_copy_page(SsdDramBackend *mbe, uint64_t source_page_index,
                            uint64_t destination_page_index,
                            uint32_t page_size);

#endif
