// Bad block manager mapping (simple OP-aware placeholder)
#include "./bbm.h"
#include "./policy-engine.h"
#include <assert.h>

// TODO: Implement the BBM API!

static uint32_t bbm_phys_blks_per_plane(const struct bbm *ctx)
{
    return ctx->geom->blks_per_pl_log + ctx->reserved_per_lun;
}

static uint64_t bbm_phys_blk_slot_index(const struct bbm *ctx,
                                        const struct pba *pba)
{
    return ((((uint64_t)pba->g.ch * ctx->geom->luns_per_ch) + pba->g.lun)
            * ctx->geom->pls_per_lun + pba->g.pl) * bbm_phys_blks_per_plane(ctx) +
           pba->g.blk;
}

static bool bbm_valid_phys_pba(const struct bbm *ctx, const struct pba *pba)
{
    return ctx && ctx->geom && pba &&
           pba->g.ch < ctx->geom->nchs &&
           pba->g.lun < ctx->geom->luns_per_ch &&
           pba->g.pl < ctx->geom->pls_per_lun &&
           pba->g.blk < bbm_phys_blks_per_plane(ctx);
}

int bbm_init(struct bbm *ctx, const BbCtrlParams *bbp, const struct ssdparams *phys)
{
    uint32_t blks_per_pl_log;
    uint32_t blks_per_pl_phys;

    if (!ctx || !bbp || !phys) {
        return -1;
    }

    /* Allocate geometry structure */
    ctx->geom = g_malloc0(sizeof(struct bbm_geom));
    struct bbm_geom *g = ctx->geom;

    /* The configured geometry is logical/exposed. OP is added physically on top. */
    blks_per_pl_log = bbp->blks_per_pl;
    blks_per_pl_phys = phys->blks_per_pl;
    ctx->reserved_per_lun = blks_per_pl_phys - blks_per_pl_log;

    /* Populate logical geometry (after overprovisioning). */
    g->blks_per_pl_log = blks_per_pl_log;
    g->blks_per_lun_log = blks_per_pl_log * bbp->pls_per_lun;
    g->blks_per_ch_log = g->blks_per_lun_log * bbp->luns_per_ch;
    g->tt_blks_log = (uint64_t)g->blks_per_ch_log * bbp->nchs;

    g->pgs_per_blk = bbp->pgs_per_blk;
    g->pgs_per_pl  = g->pgs_per_blk * g->blks_per_pl_log;
    g->pgs_per_lun = g->pgs_per_pl * bbp->pls_per_lun;
    g->pgs_per_ch  = g->pgs_per_lun * bbp->luns_per_ch;
    g->tt_pgs_log  = (uint64_t)g->pgs_per_ch * bbp->nchs;

    g->pls_per_lun = bbp->pls_per_lun;
    g->luns_per_ch = bbp->luns_per_ch;
    g->nchs = bbp->nchs;
    g->tt_luns = bbp->luns_per_ch * bbp->nchs;

    /* Line-level geometry (for FTL striping across all LUNs) */
    g->blks_per_line = g->tt_luns;
    g->pgs_per_line = g->blks_per_line * g->pgs_per_blk;
    g->tt_lines = g->blks_per_lun_log;

    g->secs_per_pg = bbp->secs_per_pg; /* TODO: I think the bbm_geom should mosly have pointers to the backend geometry? */
    g->secsz = bbp->secsz;

    /* Allocate mapping table */
    uint64_t total_entries = (uint64_t)g->nchs * g->luns_per_ch * g->blks_per_lun_log;
    ctx->maptbl = g_malloc0(sizeof(struct pba) * total_entries);

    /* Direct mapping for now: logical blk -> same physical blk within the lun */
    /* TODO: check this logic. Intuitively it should be more simple*/ 
    for (uint32_t ch = 0; ch < g->nchs; ++ch) {
        for (uint32_t lun = 0; lun < g->luns_per_ch; ++lun) {
            uint64_t base = ((uint64_t)ch * g->luns_per_ch + lun) * g->blks_per_lun_log;
            for (uint32_t blk = 0; blk < g->blks_per_lun_log; ++blk) {
                struct pba *p = &ctx->maptbl[base + blk];
                p->g.ch = ch;
                p->g.lun = lun;
                p->g.blk = blk;
                p->g.pl = 0; /* plane is set by caller from PseudoPba */
            }
        }
    }

    ctx->policy_engine = NULL;  /* FTL sets this after policy_engine_create */
    ctx->total_phys_blks = (uint64_t)bbp->nchs * bbp->luns_per_ch *
                           bbp->pls_per_lun * bbm_phys_blks_per_plane(ctx);
    ctx->excluded_phys_blks = g_malloc0(ctx->total_phys_blks);

    /* Initialize BBM Policy API */
#if 0
    ctx->policy_api = g_malloc0(sizeof(struct BbmPolicyAPI));
    ctx->policy_api->version = 1;
    ctx->policy_api->get_maptbl_entry = bbm_get_maptbl_entry;
    ctx->policy_api->is_reserved_blk = bbm_is_reserved_blk;
    ctx->policy_api->read = bbm_read;
    ctx->policy_api->write = bbm_write;
    ctx->policy_api->raw_read = bbm_raw_read;
    ctx->policy_api->raw_write = bbm_raw_write;
    ctx->policy_api->raw_erase = bbm_raw_erase;
    ctx->policy_api->get_erase_cnt = bbm_get_erase_cnt;
    ctx->policy_api->mark_block_bad = bbm_mark_block_bad;
    ctx->policy_api->sanitize_block = bbm_sanitize_block;
    ctx->policy_api->remap_block = bbm_remap_block;
    ctx->policy_api->mark_page_valid = bbm_mark_page_valid;
    ctx->policy_api->mark_page_invalid = bbm_mark_page_invalid;
    ctx->policy_api->mark_block_free = bbm_mark_block_free;
    ctx->policy_api->get_page_status = bbm_get_page_status;
    ctx->policy_api->get_block_vpc_ipc = bbm_get_block_vpc_ipc;
#endif

    return 0;
}

uint32_t bbm_blks_per_pl_log(const struct bbm *ctx)
{
    return (ctx && ctx->geom) ? ctx->geom->blks_per_pl_log : 0;
}

bool bbm_is_mappable_to_host(const struct bbm *ctx, const struct pba *pba)
{
    return bbm_valid_phys_pba(ctx, pba) &&
           pba->g.blk < ctx->geom->blks_per_pl_log &&
           !bbm_is_excluded_phys_blk(ctx, pba);
}

bool bbm_is_excluded_phys_blk(const struct bbm *ctx, const struct pba *pba)
{
    if (!ctx || !ctx->excluded_phys_blks || !bbm_valid_phys_pba(ctx, pba)) {
        return false;
    }

    return ctx->excluded_phys_blks[bbm_phys_blk_slot_index(ctx, pba)] != 0;
}

int bbm_exclude_phys_blk_from_mapping(struct bbm *ctx, const struct pba *pba)
{
    if (!ctx || !ctx->excluded_phys_blks || !bbm_valid_phys_pba(ctx, pba)) {
        return -1;
    }

    ctx->excluded_phys_blks[bbm_phys_blk_slot_index(ctx, pba)] = 1;
    return 0;
}

int bbm_include_phys_blk_in_mapping(struct bbm *ctx, const struct pba *pba)
{
    if (!ctx || !ctx->excluded_phys_blks || !bbm_valid_phys_pba(ctx, pba)) {
        return -1;
    }

    ctx->excluded_phys_blks[bbm_phys_blk_slot_index(ctx, pba)] = 0;
    return 0;
}

struct pba bbm_get_maptbl_entry(const struct bbm *ctx,
                                const PseudoPba *ppba)
{
    assert(ctx && ctx->geom && ppba);
    uint32_t blk = ppba->g.blk;
    uint32_t ch = ppba->g.ch;
    uint32_t lun = ppba->g.lun;

    /* Reserved blocks are outside logical range; caller should not request them yet. */
    assert(blk < ctx->geom->blks_per_lun_log);
    assert(ch < ctx->geom->nchs);
    assert(lun < ctx->geom->luns_per_ch);

    uint64_t idx = ((uint64_t)ch * ctx->geom->luns_per_ch + lun) * ctx->geom->blks_per_lun_log + blk;
    struct pba out = ctx->maptbl[idx];
    /* Preserve plane from incoming pseudo address (current mapping is block-level). */
    out.g.pl = ppba->g.pl;
    return out;
}

static inline PseudoPba pseudo_ppa_to_pseudo_pba(const PseudoPpa *pppa)
{
    PseudoPba ppba = {0};
    ppba.g.ch  = pppa->g.ch;
    ppba.g.lun = pppa->g.lun;
    ppba.g.pl  = pppa->g.pl;
    ppba.g.blk = pppa->g.blk;
    return ppba;
}

static inline struct ppa bbm_translate_pseudo_ppa(const struct bbm *ctx,
                                                  const PseudoPpa *pppa)
{
    PseudoPba ppba = pseudo_ppa_to_pseudo_pba(pppa);
    struct pba pba = bbm_get_maptbl_entry(ctx, &ppba);

    struct ppa out = {0};
    out.g.ch  = pba.g.ch;
    out.g.lun = pba.g.lun;
    out.g.pl  = pba.g.pl;
    out.g.blk = pba.g.blk;
    out.g.pg  = pppa->g.pg;
    out.g.sec = pppa->g.sec;
    return out;
}

int bbm_translate_ppa(const struct bbm *ctx, const PseudoPpa *pppa, struct ppa *out)
{
    if (!ctx || !pppa || !out) {
        return -1;
    }
    *out = bbm_translate_pseudo_ppa(ctx, pppa);
    return 0;
}

/* Helpers to map BBM events to backend events */
static inline enum FtlBackendEventCmd bbm_cmd_to_backend(enum BbmEventCmd cmd)
{
    switch (cmd) {
    case BBM_EVENT_READ:  return FTL_BACKEND_EVENT_READ;
    case BBM_EVENT_WRITE: return FTL_BACKEND_EVENT_WRITE;
    case BBM_EVENT_ERASE: return FTL_BACKEND_EVENT_ERASE;
    default: return FTL_BACKEND_EVENT_READ;
    }
}

static inline enum FtlBackendEventType bbm_type_to_backend(enum BbmEventType type)
{
    return (type == BBM_EVENT_USER_IO) ? USER_IO : POLICY_IO;
}

/* Data path wrappers: translate pseudophysical -> physical and invoke backend */

int bbm_read(struct FtlBackend *fb, const struct bbm *ctx,
             struct NvmeRequest *req, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event)
{
    if (!fb || !ctx || !req || !ppas || !ppa_count || !page_size) {
        return -1;
    }

    struct ppa *phys = g_malloc0(sizeof(struct ppa) * ppa_count);
    int *bev_status = NULL;

    if (!phys) {
        return -1;
    }
    for (uint64_t i = 0; i < ppa_count; ++i) {
        phys[i] = bbm_translate_pseudo_ppa(ctx, &ppas[i]);
    }

    struct FtlBackendEvent bev = {0};
    if (event) {
        bev.cmd = bbm_cmd_to_backend(event->cmd);
        bev.type = bbm_type_to_backend(event->type);
        bev.stime = event->stime;
        /* Backend status semantics differ from BBM status. Allocate separately. */
        if (ppa_count > 0) {
            bev_status = g_malloc0(sizeof(int) * ppa_count);
            bev.status_list = bev_status;
        }
    }

    int rc = ftl_backend_read(fb, req, phys, ppa_count, page_size, event ? &bev : NULL);
    if (event) {
        if (ctx->policy_engine) {
            pe_dispatch_backend_event(ctx->policy_engine, fb, (struct bbm *)ctx, &bev);
        }
        event->lat = bev.lat;
        event->count = bev.count;
    }
    g_free(bev_status);
    g_free(phys);
    return rc;
}

int bbm_write(struct FtlBackend *fb, const struct bbm *ctx,
              struct NvmeRequest *req, PseudoPpa *ppas,
              uint64_t ppa_count, uint64_t page_size, struct BbmEvent *event)
{
    if (!fb || !ctx || !req || !ppas || !ppa_count || !page_size) {
        return -1;
    }

    struct ppa *phys = g_malloc0(sizeof(struct ppa) * ppa_count);
    int *bev_status = NULL;

    if (!phys) {
        return -1;
    }
    for (uint64_t i = 0; i < ppa_count; ++i) {
        phys[i] = bbm_translate_pseudo_ppa(ctx, &ppas[i]);
    }

    struct FtlBackendEvent bev = {0};
    if (event) {
        bev.cmd = bbm_cmd_to_backend(event->cmd);
        bev.type = bbm_type_to_backend(event->type);
        bev.stime = event->stime;
        if (ppa_count > 0) {
            bev_status = g_malloc0(sizeof(int) * ppa_count);
            bev.status_list = bev_status;
        }
    }

    int rc = ftl_backend_write(fb, req, phys, ppa_count, page_size, event ? &bev : NULL);
    if (event) {
        if (ctx->policy_engine) {
            pe_dispatch_backend_event(ctx->policy_engine, fb, (struct bbm *)ctx, &bev);
        }
        event->lat = bev.lat;
        event->count = bev.count;
    }
    g_free(bev_status);
    g_free(phys);
    return rc;
}

int bbm_raw_read(struct FtlBackend *fb, const struct bbm *ctx,
             uint8_t *buffer, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size,
             void *oob_buf, size_t oob_offset, size_t oob_len,
             struct BbmEvent *event)
{
    /* Note: buffer can be NULL for timing-only simulation (e.g., GC operations) */
    if (!fb || !ctx || !ppas || !ppa_count || !page_size) {
        return -1;
    }
    struct ppa *phys = g_malloc0(sizeof(struct ppa) * ppa_count);
    int *bev_status = NULL;

    if (!phys) {
        return -1;
    }
    for (uint64_t i = 0; i < ppa_count; ++i) {
        phys[i] = bbm_translate_pseudo_ppa(ctx, &ppas[i]);
    }
    struct FtlBackendEvent bev = {0};
    if (event) {
        bev.cmd = bbm_cmd_to_backend(event->cmd);
        bev.type = bbm_type_to_backend(event->type);
        bev.stime = event->stime;
        if (ppa_count > 0) {
            bev_status = g_malloc0(sizeof(int) * ppa_count);
            bev.status_list = bev_status;
        }
    }

    int rc = ftl_backend_raw_read(fb, buffer, phys, ppa_count, page_size,
                                  oob_buf, oob_offset, oob_len,
                                  event ? &bev : NULL);
    if (event) {
        if (ctx->policy_engine) {
            pe_dispatch_backend_event(ctx->policy_engine, fb, (struct bbm *)ctx, &bev);
        }
        event->lat = bev.lat;
        event->count = bev.count;
    }
    g_free(bev_status);
    g_free(phys);
    return rc;
}

int bbm_raw_write(struct FtlBackend *fb, const struct bbm *ctx,
             uint8_t *buffer, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size,
             const void *oob_buf, size_t oob_offset, size_t oob_len,
             struct BbmEvent *event)
{
    /* Note: buffer can be NULL for timing-only simulation (e.g., GC operations) */
    if (!fb || !ctx || !ppas || !ppa_count || !page_size) {
        return -1;
    }
    struct ppa *phys = g_malloc0(sizeof(struct ppa) * ppa_count);
    int *bev_status = NULL;

    if (!phys) {
        return -1;
    }
    for (uint64_t i = 0; i < ppa_count; ++i) {
        phys[i] = bbm_translate_pseudo_ppa(ctx, &ppas[i]);
    }
    struct FtlBackendEvent bev = {0};
    if (event) {
        bev.cmd = bbm_cmd_to_backend(event->cmd);
        bev.type = bbm_type_to_backend(event->type);
        bev.stime = event->stime;
        if (ppa_count > 0) {
            bev_status = g_malloc0(sizeof(int) * ppa_count);
            bev.status_list = bev_status;
        }
    }

    int rc = ftl_backend_raw_write(fb, buffer, phys, ppa_count, page_size,
                                   oob_buf, oob_offset, oob_len,
                                   event ? &bev : NULL);
    if (event) {
        if (ctx->policy_engine) {
            pe_dispatch_backend_event(ctx->policy_engine, fb, (struct bbm *)ctx, &bev);
        }
        event->lat = bev.lat;
        event->count = bev.count;
    }
    g_free(bev_status);
    g_free(phys);
    return rc;
}

int bbm_raw_erase(struct FtlBackend *fb, const struct bbm *ctx,
              PseudoPba *pbns, uint64_t blk_count,
              struct BbmEvent *event)
{
    if (!fb || !ctx || !pbns || !blk_count) {
        return -1;
    }
    struct pba *phys = g_malloc0(sizeof(struct pba) * blk_count);
    int *bev_status = NULL;

    if (!phys) {
        return -1;
    }
    for (uint64_t i = 0; i < blk_count; ++i) {
        phys[i] = bbm_get_maptbl_entry(ctx, &pbns[i]);
    }
    struct FtlBackendEvent bev = {0};
    if (event) {
        bev.cmd = bbm_cmd_to_backend(event->cmd);
        bev.type = bbm_type_to_backend(event->type);
        bev.stime = event->stime;
        if (blk_count > 0) {
            bev_status = g_malloc0(sizeof(int) * blk_count);
            bev.status_list = bev_status;
        }
    }

    int rc = ftl_backend_raw_erase(fb, phys, blk_count, event ? &bev : NULL);
    if (event) {
        if (ctx->policy_engine) {
            pe_dispatch_backend_event(ctx->policy_engine, fb, (struct bbm *)ctx, &bev);
        }
        event->lat = bev.lat;
        event->count = bev.count;
    }
    g_free(bev_status);
    g_free(phys);
    return rc;
}


int bbm_get_erase_cnt(const struct FtlBackend *fb, const struct bbm *ctx,
                      const PseudoPba *ppba)
{
    if (!fb || !ctx || !ctx->geom || !ctx->maptbl || !ppba) {
        return -1;
    }

    /* Translate pseudo -> physical (block-level mapping) */
    struct pba phys = bbm_get_maptbl_entry(ctx, ppba);
    return ftl_backend_get_erase_cnt(fb, &phys);
}

void bbm_mark_page_valid(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa)
{
    if (!fb || !ctx || !ppa) {
        return;
    }
    struct ppa phys = bbm_translate_pseudo_ppa(ctx, ppa);
    ftl_backend_mark_page_valid(fb, &phys);
}

void bbm_mark_page_invalid(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa)
{
    if (!fb || !ctx || !ppa) {
        return;
    }
    struct ppa phys = bbm_translate_pseudo_ppa(ctx, ppa);
    ftl_backend_mark_page_invalid(fb, &phys);
}

void bbm_mark_block_free(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa)
{
    if (!fb || !ctx || !ppa) {
        return;
    }
    PseudoPba ppba = pseudo_ppa_to_pseudo_pba(ppa);
    struct pba phys = bbm_get_maptbl_entry(ctx, &ppba);
    ftl_backend_mark_block_free(fb, &phys);
}

int bbm_get_page_status(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa)
{
    if (!fb || !ctx || !ppa) {
        return -1;
    }
    struct ppa phys = bbm_translate_pseudo_ppa(ctx, ppa);
    return ftl_backend_get_page_status(fb, &phys);
}

void bbm_get_block_vpc_ipc(struct FtlBackend *fb, const struct bbm *ctx, const PseudoPpa *ppa, int *vpc, int *ipc)
{
    if (!fb || !ctx || !ppa || !vpc || !ipc) {
        return;
    }
    PseudoPba ppba = pseudo_ppa_to_pseudo_pba(ppa);
    struct pba phys = bbm_get_maptbl_entry(ctx, &ppba);
    ftl_backend_get_block_vpc_ipc(fb, &phys, vpc, ipc);
}

void bbm_set_policy_engine(struct bbm *ctx, struct policy_engine *pe)
{
    if (ctx) {
        ctx->policy_engine = pe;
    }
}

// TODO: Add bad block checking before performing requests from the backend.

//--------------------------------------------------------------------------
// -------------------------- BBM policy interface -------------------------
//--------------------------------------------------------------------------

// various functions that will be useful to handle failures reported by the ftl backend.

// 1. Mark block bad /* note we do need to simulate a persistant bad block table. */
// 2. Attempt erasure "sanitize" the bad block. (this is good for secure deletion. See redflash by Niusen Chen, Bo Chen)
        // Note, redflash does not do the sanitization as part of bad block management. 
        // it is performed later, and attached to the "ftl_write" event. 
// 3. Remap the relevant pseudo physical address to a new physical address.
// 4. Something to shrink the SSD, effectively remapping everything else.
// 5. Read retry
// 6. Move valid data to a new physical block address. 
       // Note that this is distinct from the counterpart at a higher level, beacuse
       // This performs the operation on the physical block space,
       // while the higher level performs the operation on the pseudophysical space. 
// 7. Move all data
       // including invalid data.

// Note that failure thresholds are implemented as policy. The policy determines which 
// "events" are paid attention to. Each "status" is a unique event.
//  - that is indeed a big part of policy

// WE ALSO NEED RPC. In the secure deletion paper, an RPC is attached to the bad block management
// This RPC backlinks to the duplicate data.
// and, the backlink is inside the OOB.

// Do we need to consider read disturb management? 

/* Stub implementations for bad block management functions */
/* TODO: These need proper implementations when bad block policy is developed */

int bbm_mark_block_bad(struct FtlBackend *fb, const struct bbm *ctx,
                       const struct ppa *ppa)
{
    /* TODO: Implement bad block marking logic */
    (void)fb; (void)ctx; (void)ppa;  /* Suppress unused warnings */
    fprintf(stderr, "[BBM] bbm_mark_block_bad() not yet implemented\n");
    return 0;
}

int bbm_sanitize_block(struct FtlBackend *fb, const struct bbm *ctx,
                       const struct ppa *ppa)
{
    /* TODO: Implement block sanitization logic */
    (void)fb; (void)ctx; (void)ppa;  /* Suppress unused warnings */
    fprintf(stderr, "[BBM] bbm_sanitize_block() not yet implemented\n");
    return 0;
}

int bbm_remap_block(struct FtlBackend *fb, const struct bbm *ctx,
                    const struct ppa *ppa)
{
    /* TODO: Implement block remapping logic */
    (void)fb; (void)ctx; (void)ppa;  /* Suppress unused warnings */
    fprintf(stderr, "[BBM] bbm_remap_block() not yet implemented\n");
    return 0;
}

//--------------------------------------------------------------------------
