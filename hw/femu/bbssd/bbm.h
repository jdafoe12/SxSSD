#ifndef BBM_H
#define BBM_H

#include "../nvme.h"

// The essense of this layer is to 
// provide a pseudophysical block address layer

// Essentially, this layer is completely built on top of layer 0
// which is the FTL-backend.

// the complete FUNCTIONAL implementation of this layer is
// that it will respond to events from the backend. 
// These events are failure reports from the backend.

// The events are completely defined in the backend,
// and the pseudophysical block INTERFACE is standard.
// The extensibility, to support different policies,
// is achieved by providing specific functions that can be used to handle events.
// The policy calls this api to handle events.

// I think TABLES are key to the extensibility. 


// Should provide a lightweight read/write/erase interface which wraps the raw interface.
// The only difference is that the BBM is invoked.. This means that the operations are performed
// over the pseudophysical blocks.

// This is for the bbm backend. i.e. the "mapping engine".
// It should map from pseudophysical address to ppa. 


// IMPORTANT NOTE: we want to maintain parallelism. Thus, the "replaced" blocks should be in same (lun/channel?) as previous? 
// Something like this. double think/check.


#define BLK_BITS    (16)
#define PG_BITS     (16)
#define SEC_BITS    (8)
#define PL_BITS     (8)
#define LUN_BITS    (8)
#define CH_BITS     (7)

struct PseudoPpa { // ppa shoudl be moved to backend / BBM mapping engine layer.
    union {
        struct {
            uint64_t blk : BLK_BITS;
            uint64_t pg  : PG_BITS;
            uint64_t sec : SEC_BITS;
            uint64_t pl  : PL_BITS;
            uint64_t lun : LUN_BITS;
            uint64_t ch  : CH_BITS;
            uint64_t rsv : 1;
        } g;

        uint64_t ppa;
    };
};

struct PseudoPba {
    union {
        struct {
            uint64_t blk : BLK_BITS;  /* block within plane */
            uint64_t pl  : PL_BITS;   /* plane within LUN  */
            uint64_t lun : LUN_BITS;  /* die within chan   */
            uint64_t ch  : CH_BITS;   /* channel           */
            uint64_t rsv : (64 - BLK_BITS - PL_BITS - LUN_BITS - CH_BITS);
        } g;

        uint64_t pba;
    };
};

bbm_read(SsdDramBackend *mbe, uint8_t *buffer, uint64_t *ppn_list,
         uint64_t ppn_count, uint64_t page_size, FtlBackendEvent *event);
bbm_write(SsdDramBackend *mbe, uint8_t *buffer, uint64_t *ppn_list,
         uint64_t ppn_count, uint64_t page_size, FtlBackendEvent *event);
bbm_erase(SsdDramBackend *mbe, uint64_t *pbn, uint64_t block_size, FtlBackendEvent *event);





#endif
