#ifndef FTL_BACKEND_H
#define FTL_BACKEND_H

#include "../nvme.h"
#include "./dram.h"

int ftl_backend_read(SsdDramBackend *mbe, NvmeRequest *req, uint64_t *lpn_list,
                     uint64_t lpn_count, uint64_t page_size);
int ftl_backend_write(SsdDramBackend *mbe, NvmeRequest *req, uint64_t *lpn_list,
                      uint64_t lpn_count, uint64_t page_size);

/* Also, need an api for direct operations on the FTL backend,
   for operations such as erase, garbage collection, wear leveling, etc.*/


#endif