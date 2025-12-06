#ifndef FTL_BACKEND_H
#define FTL_BACKEND_H

#include "../nvme.h"
#include "./dram.h"

// TODO: need to enforce an erase-before-write policy.

/* These are for serving NVMe requests directly. */
int ftl_backend_read(SsdDramBackend *mbe, NvmeRequest *req, uint64_t *lpn_list,
                     uint64_t lpn_count, uint64_t page_size);
int ftl_backend_write(SsdDramBackend *mbe, NvmeRequest *req, uint64_t *lpn_list,
                      uint64_t lpn_count, uint64_t page_size);

/* These are for direct operations on the FTL backend, without involving the host. 
*/
int ftl_backend_raw_read(SsdDramBackend *mbe, uint64_t *ppn_list,
                         uint64_t ppn_count, uint64_t page_size);
int ftl_backend_raw_write(SsdDramBackend *mbe, uint64_t *ppn_list,
                          uint64_t ppn_count, uint64_t page_size);
int ftl_backend_raw_erase(SsdDramBackend *mbe, uint64_t *pbn, uint64_t block_size);


#endif