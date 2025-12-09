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

bbm_read(SsdDramBackend *mbe, uint8_t *buffer, uint64_t *ppn_list,
         uint64_t ppn_count, uint64_t page_size, FtlBackendEvent *event);
bbm_write(SsdDramBackend *mbe, uint8_t *buffer, uint64_t *ppn_list,
         uint64_t ppn_count, uint64_t page_size, FtlBackendEvent *event);
bbm_erase(SsdDramBackend *mbe, uint64_t *pbn, uint64_t block_size, FtlBackendEvent *event);





#endif
