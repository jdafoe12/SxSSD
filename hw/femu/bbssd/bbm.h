#ifndef BBM_H
#define BBM_H

#include "../nvme.h"
#include "../backend/ftl-backend.h"

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




/*
 * Pseudo-physical address types are aliases of the backend physical address
 * structs. BBM is responsible for translating between pseudo and physical.
 */
typedef struct ppa PseudoPpa;
typedef struct pba PseudoPba;

/* Logical geometry (after OP/bad-block) maintained by BBM. */
struct bbm_geom {
    /* Block counts (logical, after overprovisioning) */
    uint32_t blks_per_pl_log;
    uint32_t blks_per_lun_log;
    uint32_t blks_per_ch_log;
    uint64_t tt_blks_log;

    /* Page counts (logical) */
    uint32_t pgs_per_blk;
    uint32_t pgs_per_pl;
    uint32_t pgs_per_lun;
    uint32_t pgs_per_ch;
    uint64_t tt_pgs_log;

    /* Line-level counts (for FTL striping) */
    uint32_t blks_per_line;
    uint32_t pgs_per_line;
    uint32_t tt_lines;

    /* Channel/LUN/Plane topology */
    uint32_t pls_per_lun;
    uint32_t luns_per_ch;
    uint32_t nchs;
    uint32_t tt_luns;

    uint32_t secs_per_pg;
    uint32_t secsz;
};

/* Simple BBM context tracking reserved (OP) blocks per LUN. */
struct bbm {
    /* Reserved blocks per LUN for overprovisioning */
    uint32_t reserved_per_lun;

    /* Flattened map: index = ((ch * luns_per_ch + lun) * blks_per_lun_log) + blk */
    /* Since the mapping level is blocks, a pseudoppa can be mapped by a ppa by 
     * changing only the block number. Since we keep overprovisioned blocks in each plane, 
     * this is all that needs to change. */
    struct pba *maptbl;

    /* Logical geometry (after overprovisioning) */
    struct bbm_geom *geom;
};

int bbm_init(struct bbm *ctx, const BbCtrlParams *bbp, const struct ssdparams *phys);
uint32_t bbm_blks_per_pl_log(const struct bbm *ctx);
struct pba bbm_get_maptbl_entry(const struct bbm *ctx,
                                const PseudoPba *ppba);
static inline bool bbm_is_reserved_blk(const struct bbm *ctx,
                                       uint32_t blk)
{
    return blk >= ctx->geom->blks_per_lun_log;
}

// Need raw functions and non-raw functions, like in the backend. (raw serve policies, while non-raw serve the host.)

/* These are for serving NVMe requests directly. */
int bbm_read(struct FtlBackend *fb, const struct bbm *ctx,
             struct NvmeRequest *req, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event);
int bbm_write(struct FtlBackend *fb, const struct bbm *ctx,
              struct NvmeRequest *req, PseudoPpa *ppas,
              uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event);

/* These are for direct operations on the FTL backend, without involving the host. */
int bbm_raw_read(struct FtlBackend *fb, const struct bbm *ctx,
                 uint8_t *buffer, PseudoPpa *ppas,
                 uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event);
int bbm_raw_write(struct FtlBackend *fb, const struct bbm *ctx,
                  uint8_t *buffer, PseudoPpa *ppas,
                  uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event);
int bbm_raw_erase(struct FtlBackend *fb, const struct bbm *ctx,
                  PseudoPba *pbns, uint64_t blk_count,
                  struct FtlBackendEvent *event);





#endif
