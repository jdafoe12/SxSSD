#ifndef FTL_BACKEND_H
#define FTL_BACKEND_H

#include "../nvme.h"
#include "./dram.h"

// TODO: need to enforce an erase-before-write policy.

/* 
 * In the backend, events are generated on each operation that is exposed to the upper layer, essentially returning the status of the operation.
 * Any metadata updates or important status updates are reported.
 * The events are passed to the upper layer, where some policy may or may not be attached to a given event.
 * Regardless, the upper layer indexes into a lookup table for what to do on each event.
 * The lookup table is loaded from storage, compiled, and formed into a actual functions pointers.
 * In this case, the upper layer is a bad block manager. 
 *
 * For reads, the event is an integer for each page, indicating the number of bit errors corrected by ECC.
 *   Thus, the event is an array of integers.
 * For writes, the event is binary for each page: success or failure.
 *   Thus, the event is an array of booleans (implemented as integers).
 * For erasures, the event is binary for each block: success or failure.
 *   Thus, the event is an array of booleans (implemented as integers).
 * lower layers should be read-only, as in the uppper layer cannot change the state of the lower layer.
 * This prevents issues with the ordering of events.
 */

typedef enum FtlBackendEventType {
    FTL_BACKEND_EVENT_READ,
    FTL_BACKEND_EVENT_WRITE,
    FTL_BACKEND_EVENT_ERASE
} FtlBackendEventType;

typedef struct FtlBackendEvent {
    FtlBackendEventType type; 
    uint32_t count; 
    int *entries; /* for read, entries[i] = bit error count for page i */
                   /* for write, entries[i] = 0/1 success for page i */
                   /* for erase, entries[i] = 0/1 success for block i */
                   /* As far as I understand, this models errors closely to a real SSD.
                    * We will simply use a probabilistic model for the errors. */
                    // 0 is success. Non-zero is failure.
} FtlBackendEvent;

/* These are for serving NVMe requests directly. */
 ftl_backend_read(SsdDramBackend *mbe, NvmeRequest *req, uint64_t *lpn_list,
                     uint64_t lpn_count, uint64_t page_size, FtlBackendEvent *event);
int ftl_backend_write(SsdDramBackend *mbe, NvmeRequest *req, uint64_t *lpn_list,
                      uint64_t lpn_count, uint64_t page_size, FtlBackendEvent *event);

/* These are for direct operations on the FTL backend, without involving the host. */
int ftl_backend_raw_read(SsdDramBackend *mbe,uint8_t *buffer, uint64_t *ppn_list,
                         uint64_t ppn_count, uint64_t page_size, FtlBackendEvent *event);
int ftl_backend_raw_write(SsdDramBackend *mbe, uint8_t *buffer, uint64_t *ppn_list,
                          uint64_t ppn_count, uint64_t page_size, FtlBackendEvent *event);
int ftl_backend_raw_erase(SsdDramBackend *mbe, uint64_t *pbn, uint64_t block_size, FtlBackendEvent *event);


#endif