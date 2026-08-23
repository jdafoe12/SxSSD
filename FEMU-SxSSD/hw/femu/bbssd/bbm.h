/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Includes SxSSD adaptations of FEMU BBSSD FTL geometry and
 * address-management definitions.
 * SxSSD modifications by Josh Dafoe: 2025-12-16 through 2026-08-23.
 */

#ifndef BBM_H
#define BBM_H

#include "../nvme.h"
#include "raw-flash.h"

/*
 * BBM provides the pseudo-physical address layer above raw flash. It owns
 * overprovisioned-block mappings, translates addresses, and reports completed
 * operations through an optional typed callback.
 *
 * Future remapping must preserve media parallelism by choosing a replacement
 * in an appropriate channel/LUN/plane locality.  The exact constraint remains
 * a bad-block-policy decision.
 */
typedef struct ppa PseudoPpa;
typedef struct pba PseudoPba;

struct bbm;
struct BbmEvent;
struct BbmErrorEvent;
struct PswdStateTransitionEvent;

typedef void (*BbmEventNotify)(const struct BbmEvent *event, void *context);
typedef void (*BbmErrorNotify)(const struct BbmErrorEvent *event, void *context);
typedef void (*BbmPswdTransitionNotify)(
    const struct PswdStateTransitionEvent *event, void *context);

/* Stable pSWD state indexed by a pseudo-physical block. */
struct bbm_pswd_ctx {
    enum pswd_block_state state;
    uint32_t wp;
    uint32_t vpc;
    uint32_t ipc;
    bool remapping;
};

/* Logical pSWD transition.  ppba is never a raw physical address. */
struct PswdStateTransitionEvent {
    enum pswd_block_state old_state;
    enum pswd_block_state new_state;
    PseudoPba ppba;
    int erase_cnt;
    int wp;
};

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
     * Block-level map indexed by (channel, LUN, plane, logical block).
     */
    struct pba *maptbl;
    struct bbm_pswd_ctx *pswd_state;

    /* Logical geometry (after overprovisioning) */
    struct bbm_geom *geom;

    /* Operation events travel upward without coupling BBM to policy-engine. */
    BbmEventNotify event_notify;
    void *event_notify_context;
    BbmErrorNotify error_notify;
    void *error_notify_context;
    BbmPswdTransitionNotify pswd_transition_notify;
    void *pswd_transition_notify_context;

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
    const struct RawFlash *fb, const struct bbm *ctx,
    struct bbm_policy_storage_geometry *geometry);
bool bbm_policy_storage_block_valid(const struct bbm *ctx,
                                    const struct pba *block);
int bbm_policy_storage_claim(struct bbm *ctx, const struct pba *block);
int bbm_policy_storage_release(struct bbm *ctx, const struct pba *block);
int bbm_policy_storage_read(struct RawFlash *fb, const struct bbm *ctx,
                            const struct pba *blocks, uint32_t block_count,
                            void *data, uint32_t length);
int bbm_policy_storage_write(struct RawFlash *fb, const struct bbm *ctx,
                             const struct pba *blocks, uint32_t block_count,
                             const void *data, uint32_t length);
int bbm_policy_storage_erase(struct RawFlash *fb, const struct bbm *ctx,
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
 * Policy-API-facing operation metadata. BBM maps this to RawFlashEvent, then
 * reports the completed operation synchronously through event_notify.
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
    int64_t lat;      /* latency reported by raw flash */
};

/* One policy-facing primitive-operation failure. */
struct BbmErrorEvent {
    enum BbmEventCmd cmd;
    enum BbmEventType type;
    PseudoPpa pppa;
    int status;
    int64_t stime;
    int64_t lat;
};

int bbm_read(struct RawFlash *fb, struct bbm *ctx, uint8_t *buffer,
             PseudoPpa *ppas, uint64_t page_count, uint64_t page_size,
             void *oob_buf, size_t oob_offset, size_t oob_len,
             struct BbmEvent *event);
int bbm_write(struct RawFlash *fb, struct bbm *ctx,
              const uint8_t *buffer, PseudoPpa *ppas, uint64_t page_count,
              uint64_t page_size, const void *oob_buf, size_t oob_offset,
              size_t oob_len, struct BbmEvent *event);
int bbm_erase(struct RawFlash *fb, struct bbm *ctx,
              PseudoPba *blocks, uint64_t block_count,
              struct BbmEvent *event);

/*
 * Query erase count for a *pseudo* block address.
 * BBM translates pseudo -> physical and delegates to backend.
 * Returns >= 0 on success, -1 on invalid input.
 */
int bbm_get_erase_cnt(const struct RawFlash *fb, const struct bbm *ctx,
                      const PseudoPba *ppba);

/* Page validity: BBM translates PseudoPpa -> ppa/pba and calls backend. */
void bbm_mark_page_valid(struct RawFlash *fb, const struct bbm *ctx,
                         const PseudoPpa *ppa);
void bbm_mark_page_invalid(struct RawFlash *fb, const struct bbm *ctx,
                           const PseudoPpa *ppa);
void bbm_mark_block_free(struct RawFlash *fb, const struct bbm *ctx,
                         const PseudoPpa *ppa);
int bbm_get_page_status(struct RawFlash *fb, const struct bbm *ctx,
                        const PseudoPpa *ppa);
void bbm_get_block_vpc_ipc(struct RawFlash *fb, const struct bbm *ctx,
                           const PseudoPpa *ppa, int *vpc, int *ipc);

void bbm_set_event_notify(struct bbm *ctx, BbmEventNotify notify,
                          void *context);
void bbm_set_error_notify(struct bbm *ctx, BbmErrorNotify notify,
                          void *context);
void bbm_set_pswd_transition_notify(struct bbm *ctx,
                                    BbmPswdTransitionNotify notify,
                                    void *context);
int bbm_pswd_get(const struct bbm *ctx, const PseudoPba *ppba,
                 struct bbm_pswd_ctx *destination);

/*
 * Future bad-block/error-handling mechanisms.  These are intentionally kept
 * as explicit design points even where implementation is incomplete:
 * mark/sanitize/remap, capacity shrink, read retry, and physical data moves.
 */
int bbm_mark_block_bad(struct RawFlash *fb, struct bbm *ctx,
                       const PseudoPba *ppba);

int bbm_remap_block(struct RawFlash *fb, struct bbm *ctx,
                    const PseudoPba *ppba);

int bbm_shrink_ssd(struct RawFlash *fb, const struct bbm *ctx);

int bbm_read_retry(struct RawFlash *fb, const struct bbm *ctx,
                   const struct ppa *ppa);

int bbm_move_valid_data(struct RawFlash *fb, const struct bbm *ctx,
                        const struct ppa *ppa);

int bbm_move_all_data(struct RawFlash *fb, const struct bbm *ctx,
                      const struct ppa *ppa);

#endif
