#ifndef BBM_H
#define BBM_H

#include "../nvme.h"
#include "../backend/ftl-backend.h"
#include "policy-engine-types.h"

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

struct bbm;
struct BbmPolicyAPI;
struct policy_engine;

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

/* Forward declarations */
struct BbmEvent;

/*
 * BBM Policy API - Function pointer table for BBM operations
 * 
 * This structure provides a stable interface for policies to interact with
 * the BBM layer without requiring access to internal implementation details.
 * Plugins receive this API at runtime and use it to perform BBM operations.
 * This limits the internal details that Policies need to be exposed to.
 */

 /* TODO: I need to more carefully define what is exposed via this API. 
          Some of these functions should be internal! (i.e. only exposed to bbm.c and ftl.c) */
struct BbmPolicyAPI {
    uint32_t version;  /* API version for compatibility checking */

    /*
     * Policy-visible BBM operations are intentionally commented out for now.
     * BBM remains a mechanism-owned layer; FTL and BBM code should call bbm_*()
     * directly rather than exposing raw/media-management entry points to policy.
     */
#if 0
    struct pba (*get_maptbl_entry)(const struct bbm *ctx, const PseudoPba *ppba);
    bool (*is_reserved_blk)(const struct bbm *ctx, uint32_t blk);
    int (*read)(struct FtlBackend *fb, const struct bbm *ctx,
                struct NvmeRequest *req, PseudoPpa *ppas,
                uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
    int (*write)(struct FtlBackend *fb, const struct bbm *ctx,
                 struct NvmeRequest *req, PseudoPpa *ppas,
                 uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
    int (*raw_read)(struct FtlBackend *fb, const struct bbm *ctx,
                    uint8_t *buffer, PseudoPpa *ppas,
                    uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
    int (*raw_write)(struct FtlBackend *fb, const struct bbm *ctx,
                     uint8_t *buffer, PseudoPpa *ppas,
                     uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
    int (*raw_erase)(struct FtlBackend *fb, const struct bbm *ctx,
                     PseudoPba *pbns, uint64_t blk_count, struct BbmEvent *event);
    int (*get_erase_cnt)(const struct FtlBackend *fb, const struct bbm *ctx,
                         const PseudoPba *ppba);
    int (*mark_block_bad)(struct FtlBackend *fb, const struct bbm *ctx,
                          const struct ppa *ppa);
    int (*sanitize_block)(struct FtlBackend *fb, const struct bbm *ctx,
                          const struct ppa *ppa);
    int (*remap_block)(struct FtlBackend *fb, const struct bbm *ctx,
                       const struct ppa *ppa);
    void (*mark_page_valid)(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa);
    void (*mark_page_invalid)(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa);
    void (*mark_block_free)(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa);
    int (*get_page_status)(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa);
    void (*get_block_vpc_ipc)(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa, int *vpc, int *ipc);
#endif
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

    /* Policy engine (set by FTL at init); backend and pSWD hooks live there */
    struct policy_engine *policy_engine;

    /* Generic bookkeeping for physical blocks excluded from pseudo allocation. */
    uint64_t total_phys_blks;
    uint8_t *excluded_phys_blks;
    
    /*
     * BBM policy-visible API storage is intentionally disabled for now.
     * Mechanism code should call bbm_*() directly.
     */
    /* struct BbmPolicyAPI *policy_api; */
};

int bbm_init(struct bbm *ctx, const BbCtrlParams *bbp, const struct ssdparams *phys);
uint32_t bbm_blks_per_pl_log(const struct bbm *ctx);
struct pba bbm_get_maptbl_entry(const struct bbm *ctx,
                                const PseudoPba *ppba);
static inline bool bbm_is_reserved_blk(const struct bbm *ctx,
                                       uint32_t blk)
{
    return blk >= ctx->geom->blks_per_pl_log;
}

bool bbm_is_mappable_to_host(const struct bbm *ctx, const struct pba *pba);
bool bbm_is_excluded_phys_blk(const struct bbm *ctx, const struct pba *pba);
int bbm_exclude_phys_blk_from_mapping(struct bbm *ctx, const struct pba *pba);
int bbm_include_phys_blk_in_mapping(struct bbm *ctx, const struct pba *pba);
int bbm_translate_ppa(const struct bbm *ctx, const PseudoPpa *pppa, struct ppa *out);

// Need raw functions and non-raw functions, like in the backend. (raw serve policies, while non-raw serve the host.)

enum BbmEventCmd {
    BBM_EVENT_READ,
    BBM_EVENT_WRITE,
    BBM_EVENT_ERASE,
};

enum BbmEventType {
    BBM_EVENT_POLICY_IO = 0,
    BBM_EVENT_USER_IO   = 1,
};

/* Event visible to FTL; BBM internally maps to backend events. */
/* TODO: Right now this is unused. I.e. there is no policy attachment to bbm events! */
struct BbmEvent {
    enum BbmEventCmd cmd;
    enum BbmEventType type;
    uint32_t count;
    int *status_list;    /* optional per-op status; allocated by caller if wanted */
    int64_t stime;       /* request start time */
    int64_t lat;         /* end-to-end latency as seen by BBM/FTL */
};

/* These are for serving NVMe requests directly. */
int bbm_read(struct FtlBackend *fb, const struct bbm *ctx,
             struct NvmeRequest *req, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
int bbm_write(struct FtlBackend *fb, const struct bbm *ctx,
              struct NvmeRequest *req, PseudoPpa *ppas,
              uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);

/* These are for direct operations on the FTL backend, without involving the host. */
int bbm_raw_read(struct FtlBackend *fb, const struct bbm *ctx,
                 uint8_t *buffer, PseudoPpa *ppas,
                 uint64_t ppa_count, uint64_t page_size,
                 void *oob_buf, size_t oob_offset, size_t oob_len,
                 struct BbmEvent *event);
int bbm_raw_write(struct FtlBackend *fb, const struct bbm *ctx,
                  uint8_t *buffer, PseudoPpa *ppas,
                  uint64_t ppa_count, uint64_t page_size,
                  const void *oob_buf, size_t oob_offset, size_t oob_len,
                  struct BbmEvent *event);
int bbm_raw_erase(struct FtlBackend *fb, const struct bbm *ctx,
                  PseudoPba *pbns, uint64_t blk_count,
                  struct BbmEvent *event);

/*
 * Query erase count for a *pseudo* block address.
 * BBM translates pseudo -> physical and delegates to backend.
 * Returns >= 0 on success, -1 on invalid input.
 */
int bbm_get_erase_cnt(const struct FtlBackend *fb, const struct bbm *ctx,
                      const PseudoPba *ppba);

/* Page validity: BBM translates PseudoPpa -> ppa/pba and calls backend. */
void bbm_mark_page_valid(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa);
void bbm_mark_page_invalid(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa);
void bbm_mark_block_free(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa);
int bbm_get_page_status(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa);
void bbm_get_block_vpc_ipc(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa, int *vpc, int *ipc);

/* Josh: Now, need to present an interface to the upper layer in order
 * to implement the bbm policy layer. This interface needs to be general enouph 
 * to support any concievable bbm policy.*/


void bbm_set_policy_engine(struct bbm *ctx, struct policy_engine *pe);

int bbm_mark_block_bad(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_sanitize_block(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_remap_block(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_shrink_ssd(struct FtlBackend *fb, const struct bbm *ctx);
// Need to see what is the ZNS / OCSSD strategy for BBM?

int bbm_read_retry(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_move_valid_data(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_move_all_data(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);


// I should actually have some "compiler" type thing.
// It will take conditions on function calls and translate to 
// events - so that all relevant events have the relevant functions called.

#endif
