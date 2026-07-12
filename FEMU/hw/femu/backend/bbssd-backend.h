#ifndef __FEMU_BBSSD_BACKEND_H
#define __FEMU_BBSSD_BACKEND_H

#include "../nvme.h"
#include "./dram.h"

struct ssd_stats;

typedef struct BbssdBackendSpan {
    uint64_t offset;
    uint32_t page_offset;
    uint32_t len;
    bool mapped;
} BbssdBackendSpan;

int bbssd_backend_read_pages(SsdDramBackend *mbe, uint8_t *page_bufs,
                             const uint64_t *page_idxs, const bool *mapped,
                             uint32_t nr_pages, uint32_t page_size);
int bbssd_backend_write_pages(SsdDramBackend *mbe, const uint8_t *page_bufs,
                              const uint64_t *page_idxs, uint32_t nr_pages,
                              uint32_t page_size);

#endif
