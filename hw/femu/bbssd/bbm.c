// Bad block manager mapping (simple OP-aware placeholder)
#include "./bbm.h"
#include <assert.h>

int bbm_init(struct bbm *ctx, const BbCtrlParams *bbp, const struct ssdparams *phys)
{
    if (!ctx || !bbp || !phys) {
        return -1;
    }

    /* Allocate geometry structure */
    ctx->geom = g_malloc0(sizeof(struct bbm_geom));
    struct bbm_geom *g = ctx->geom;

    /* Calculate overprovisioning */
    uint32_t blks_per_pl_phys = bbp->blks_per_pl;
    ctx->reserved_per_lun = (blks_per_pl_phys * bbp->op_pct) / 100;
    if (ctx->reserved_per_lun >= blks_per_pl_phys && blks_per_pl_phys > 0) {
        ctx->reserved_per_lun = blks_per_pl_phys - 1;
    }
    uint32_t blks_per_pl_log = blks_per_pl_phys - ctx->reserved_per_lun;

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
    /* TODO: check this logic. Intuitively it should be more simp*/ 
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
    return 0;
}

uint32_t bbm_blks_per_pl_log(const struct bbm *ctx)
{
    return (ctx && ctx->geom) ? ctx->geom->blks_per_pl_log : 0;
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

/* Data path wrappers: translate pseudophysical -> physical and invoke backend */

int bbm_read(struct FtlBackend *fb, const struct bbm *ctx,
             struct NvmeRequest *req, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event)
{
    if (!fb || !ctx || !req || !ppas || !ppa_count || !page_size) {
        return -1;
    }

    struct ppa *phys = g_malloc0(sizeof(struct ppa) * ppa_count);
    for (uint64_t i = 0; i < ppa_count; ++i) {
        phys[i] = bbm_translate_pseudo_ppa(ctx, &ppas[i]);
    }

    int rc = ftl_backend_read(fb, req, phys, ppa_count, page_size, event);
    g_free(phys);
    return rc;
}

int bbm_write(struct FtlBackend *fb, const struct bbm *ctx,
              struct NvmeRequest *req, PseudoPpa *ppas,
              uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event)
{
    if (!fb || !ctx || !req || !ppas || !ppa_count || !page_size) {
        return -1;
    }

    struct ppa *phys = g_malloc0(sizeof(struct ppa) * ppa_count);
    for (uint64_t i = 0; i < ppa_count; ++i) {
        phys[i] = bbm_translate_pseudo_ppa(ctx, &ppas[i]);
    }

    int rc = ftl_backend_write(fb, req, phys, ppa_count, page_size, event);
    g_free(phys);
    return rc;
}

int bbm_raw_read(struct FtlBackend *fb, const struct bbm *ctx,
             uint8_t *buffer, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event)
{
    /* Note: buffer can be NULL for timing-only simulation (e.g., GC operations) */
    if (!fb || !ctx || !ppas || !ppa_count || !page_size) {
        return -1;
    }
    struct ppa *phys = g_malloc0(sizeof(struct ppa) * ppa_count);
    for (uint64_t i = 0; i < ppa_count; ++i) {
        phys[i] = bbm_translate_pseudo_ppa(ctx, &ppas[i]);
    }
    int rc = ftl_backend_raw_read(fb, buffer, phys, ppa_count, page_size, event);
    g_free(phys);
    return rc;
}

int bbm_raw_write(struct FtlBackend *fb, const struct bbm *ctx,
              uint8_t *buffer, PseudoPpa *ppas,
              uint64_t ppa_count, uint64_t page_size, struct FtlBackendEvent *event)
{
    /* Note: buffer can be NULL for timing-only simulation (e.g., GC operations) */
    if (!fb || !ctx || !ppas || !ppa_count || !page_size) {
        return -1;
    }
    struct ppa *phys = g_malloc0(sizeof(struct ppa) * ppa_count);
    for (uint64_t i = 0; i < ppa_count; ++i) {
        phys[i] = bbm_translate_pseudo_ppa(ctx, &ppas[i]);
    }
    int rc = ftl_backend_raw_write(fb, buffer, phys, ppa_count, page_size, event);
    g_free(phys);
    return rc;
}

int bbm_raw_erase(struct FtlBackend *fb, const struct bbm *ctx,
              PseudoPba *pbns, uint64_t blk_count,
              struct FtlBackendEvent *event)
{
    if (!fb || !ctx || !pbns || !blk_count) {
        return -1;
    }
    struct pba *phys = g_malloc0(sizeof(struct pba) * blk_count);
    for (uint64_t i = 0; i < blk_count; ++i) {
        phys[i] = bbm_get_maptbl_entry(ctx, &pbns[i]);
    }
    int rc = ftl_backend_raw_erase(fb, phys, blk_count, event);
    g_free(phys);
    return rc;
}