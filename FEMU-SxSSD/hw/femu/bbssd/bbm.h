#ifndef BBM_H
#define BBM_H

#include "../nvme.h"
#include "../backend/ftl-backend.h"
#include "policy-engine-types.h"

/*
 * BBM provides the pseudo-physical address layer above the raw FTL backend.
 * It translates host/FTL addresses, maintains overprovisioned-block mappings,
 * and synchronously reports backend operations to the policy engine.
 *
 * Future remapping must preserve media parallelism by choosing a replacement
 * in an appropriate channel/LUN/plane locality.  The exact constraint remains
 * a bad-block-policy decision.
 */
typedef struct ppa PseudoPpa;
typedef struct pba PseudoPba;

struct bbm;
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

/*
 * Geometry of the physical blocks reserved from the host-visible pseudo
 * address space.  Privileged policies use this storage for controller-owned
 * artifacts such as installed policy images.
 */
struct bbm_policy_storage_geometry {
    uint32_t channels;
    uint32_t luns_per_channel;
    uint32_t planes_per_lun;
    uint32_t logical_blocks_per_plane;
    uint32_t physical_blocks_per_plane;
    uint32_t reserved_blocks_per_lun;
    uint32_t pages_per_block;
    uint32_t page_size;
};

/* Simple BBM context tracking reserved (OP) blocks per LUN. */
struct bbm {
    /* Reserved blocks per LUN for overprovisioning */
    uint32_t reserved_per_lun;

    /*
     * Block-level map indexed by (channel, LUN, logical block).  The caller's
     * plane and page coordinates remain unchanged during translation.
     */
    struct pba *maptbl;

    /* Logical geometry (after overprovisioning) */
    struct bbm_geom *geom;

    /* Policy engine (set by FTL at init); backend and pSWD hooks live there */
    struct policy_engine *policy_engine;

    /* Generic bookkeeping for physical blocks excluded from pseudo allocation. */
    uint64_t total_phys_blks;
    uint8_t *excluded_phys_blks;
};

int bbm_init(struct bbm *ctx, const BbCtrlParams *bbp,
             const struct ssdparams *phys);
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

/*
 * Controller-owned storage uses physical blocks outside the logical BBM
 * address space.  Claims are currently global reservations, matching the
 * single trusted meta-interface policy.  If privileged policies later require
 * isolation from one another, this is the point at which owner identity must
 * be added.
 */
int bbm_policy_storage_geometry(
    const struct FtlBackend *fb, const struct bbm *ctx,
    struct bbm_policy_storage_geometry *geometry);
bool bbm_policy_storage_block_valid(const struct bbm *ctx,
                                    const struct pba *block);
int bbm_policy_storage_claim(struct bbm *ctx, const struct pba *block);
int bbm_policy_storage_release(struct bbm *ctx, const struct pba *block);
int bbm_policy_storage_read(struct FtlBackend *fb, const struct bbm *ctx,
                            const struct pba *blocks, uint32_t block_count,
                            void *data, uint32_t length);
int bbm_policy_storage_write(struct FtlBackend *fb, const struct bbm *ctx,
                             const struct pba *blocks, uint32_t block_count,
                             const void *data, uint32_t length);
int bbm_policy_storage_erase(struct FtlBackend *fb, const struct bbm *ctx,
                             const struct pba *blocks, uint32_t block_count);

enum BbmEventCmd {
    BBM_EVENT_READ,
    BBM_EVENT_WRITE,
    BBM_EVENT_ERASE,
};

enum BbmEventType {
    BBM_EVENT_POLICY_IO = 0,
    BBM_EVENT_USER_IO   = 1,
};

/*
 * FTL-facing operation metadata.  BBM maps this to FtlBackendEvent and
 * synchronously dispatches the resulting backend event to policies.
 *
 * TODO(error-event): define a dedicated policy error event that carries the
 * relevant non-zero status entries without conflating them with the operation
 * notification itself.
 */
struct BbmEvent {
    enum BbmEventCmd cmd;
    enum BbmEventType type;
    uint32_t count;
    int *status_list; /* optional per-operation status storage */
    int64_t stime;    /* request start time */
    int64_t lat;      /* end-to-end latency as seen by BBM/FTL */
};

/* These are for serving NVMe requests directly. */
int bbm_read(struct FtlBackend *fb, const struct bbm *ctx,
             struct NvmeRequest *req, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);
int bbm_write(struct FtlBackend *fb, const struct bbm *ctx,
              struct NvmeRequest *req, PseudoPpa *ppas,
              uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event);

/* Direct operations on the FTL backend, without involving the host. */
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
void bbm_mark_page_valid(struct FtlBackend *fb, const struct bbm *ctx,
                         const PseudoPpa *ppa);
void bbm_mark_page_invalid(struct FtlBackend *fb, const struct bbm *ctx,
                           const PseudoPpa *ppa);
void bbm_mark_block_free(struct FtlBackend *fb, const struct bbm *ctx,
                         const PseudoPpa *ppa);
int bbm_get_page_status(struct FtlBackend *fb, const struct bbm *ctx,
                        const PseudoPpa *ppa);
void bbm_get_block_vpc_ipc(struct FtlBackend *fb, const struct bbm *ctx,
                           const PseudoPpa *ppa, int *vpc, int *ipc);

void bbm_set_policy_engine(struct bbm *ctx, struct policy_engine *pe);

/*
 * Future bad-block/error-handling mechanisms.  These are intentionally kept
 * as explicit design points even where implementation is incomplete:
 * mark/sanitize/remap, capacity shrink, read retry, and physical data moves.
 */
int bbm_mark_block_bad(struct FtlBackend *fb, const struct bbm *ctx,
                       const struct ppa *ppa);

int bbm_sanitize_block(struct FtlBackend *fb, const struct bbm *ctx,
                       const struct ppa *ppa);

int bbm_remap_block(struct FtlBackend *fb, const struct bbm *ctx,
                    const struct ppa *ppa);

int bbm_shrink_ssd(struct FtlBackend *fb, const struct bbm *ctx);

int bbm_read_retry(struct FtlBackend *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_move_valid_data(struct FtlBackend *fb, const struct bbm *ctx,
                        const struct ppa *ppa);

int bbm_move_all_data(struct FtlBackend *fb, const struct bbm *ctx,
                      const struct ppa *ppa);

#endif
