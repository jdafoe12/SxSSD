/* Bad-block mapping and controller-owned physical-storage mechanisms. */
#include "./bbm.h"
#include <assert.h>
#include <openssl/crypto.h>

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

int bbm_init(struct bbm *ctx, const BbCtrlParams *bbp,
             const struct ssdparams *phys)
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

    /*
     * TODO(bbm-geometry): replace copied geometry with a shared read-only
     * geometry view when the backend/BBM ownership boundary is finalized.
     */
    g->secs_per_pg = bbp->secs_per_pg;
    g->secsz = bbp->secsz;

    /* Allocate mapping table */
    uint64_t total_entries =
        (uint64_t)g->nchs * g->luns_per_ch * g->blks_per_lun_log;
    ctx->maptbl = g_malloc0(sizeof(struct pba) * total_entries);

    /*
     * Initial identity mapping: logical blocks map to the same physical block
     * in their LUN.  Bad-block handling will update these entries.
     */
    for (uint32_t ch = 0; ch < g->nchs; ++ch) {
        for (uint32_t lun = 0; lun < g->luns_per_ch; ++lun) {
            uint64_t base =
                ((uint64_t)ch * g->luns_per_ch + lun) *
                g->blks_per_lun_log;
            for (uint32_t blk = 0; blk < g->blks_per_lun_log; ++blk) {
                struct pba *p = &ctx->maptbl[base + blk];
                p->g.ch = ch;
                p->g.lun = lun;
                p->g.blk = blk;
                p->g.pl = 0; /* plane is set by caller from PseudoPba */
            }
        }
    }

    ctx->event_notify = NULL;
    ctx->event_notify_context = NULL;
    ctx->total_phys_blks = (uint64_t)bbp->nchs * bbp->luns_per_ch *
                           bbp->pls_per_lun * bbm_phys_blks_per_plane(ctx);
    ctx->excluded_phys_blks = g_malloc0(ctx->total_phys_blks);

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

int bbm_policy_storage_geometry(
    const struct RawFlash *fb, const struct bbm *ctx,
    struct bbm_policy_storage_geometry *geometry)
{
    uint64_t page_size;

    if (!fb || !ctx || !ctx->geom || !geometry) {
        return -1;
    }
    page_size = (uint64_t)fb->sp.secs_per_pg * fb->sp.secsz;
    if (page_size == 0 || page_size > UINT32_MAX) {
        return -1;
    }
    *geometry = (struct bbm_policy_storage_geometry) {
        .channels = fb->sp.nchs,
        .luns_per_channel = fb->sp.luns_per_ch,
        .planes_per_lun = fb->sp.pls_per_lun,
        .logical_blocks_per_plane = ctx->geom->blks_per_pl_log,
        .physical_blocks_per_plane = fb->sp.blks_per_pl,
        .reserved_blocks_per_lun = ctx->reserved_per_lun,
        .pages_per_block = fb->sp.pgs_per_blk,
        .page_size = page_size,
    };
    return 0;
}

bool bbm_policy_storage_block_valid(const struct bbm *ctx,
                                    const struct pba *block)
{
    return bbm_valid_phys_pba(ctx, block) &&
           block->g.blk >= ctx->geom->blks_per_pl_log;
}

int bbm_policy_storage_claim(struct bbm *ctx, const struct pba *block)
{
    if (!bbm_policy_storage_block_valid(ctx, block) ||
        bbm_is_excluded_phys_blk(ctx, block)) {
        return -1;
    }
    return bbm_exclude_phys_blk_from_mapping(ctx, block);
}

int bbm_policy_storage_release(struct bbm *ctx, const struct pba *block)
{
    if (!bbm_policy_storage_block_valid(ctx, block)) {
        return -1;
    }
    return bbm_include_phys_blk_in_mapping(ctx, block);
}

static int bbm_policy_storage_pages(
    const struct RawFlash *fb, const struct bbm *ctx,
    const struct pba *blocks, uint32_t block_count, uint32_t length,
    struct ppa **pages_out, uint32_t *page_count_out, uint32_t *page_size_out)
{
    struct ppa *pages;
    uint64_t page_size_64;
    uint64_t page_count_64;
    uint32_t pages_per_block;
    uint32_t page_count;
    uint32_t page_size;
    uint32_t i;

    if (!fb || !ctx || !blocks || block_count == 0 || length == 0 ||
        !pages_out || !page_count_out || !page_size_out) {
        return -1;
    }
    for (i = 0; i < block_count; i++) {
        if (!bbm_policy_storage_block_valid(ctx, &blocks[i])) {
            return -1;
        }
    }
    page_size_64 = (uint64_t)fb->sp.secs_per_pg * fb->sp.secsz;
    pages_per_block = fb->sp.pgs_per_blk;
    if (page_size_64 == 0 || page_size_64 > UINT32_MAX ||
        pages_per_block == 0) {
        return -1;
    }
    page_size = page_size_64;
    page_count_64 = ((uint64_t)length + page_size - 1) / page_size;
    if (page_count_64 == 0 || page_count_64 > UINT32_MAX ||
        page_count_64 > (uint64_t)block_count * pages_per_block) {
        return -1;
    }
    page_count = page_count_64;
    pages = g_try_new0(struct ppa, page_count);
    if (!pages) {
        return -1;
    }
    for (i = 0; i < page_count; i++) {
        const struct pba *block = &blocks[i / pages_per_block];

        pages[i].g.ch = block->g.ch;
        pages[i].g.lun = block->g.lun;
        pages[i].g.pl = block->g.pl;
        pages[i].g.blk = block->g.blk;
        pages[i].g.pg = i % pages_per_block;
    }
    *pages_out = pages;
    *page_count_out = page_count;
    *page_size_out = page_size;
    return 0;
}

int bbm_policy_storage_read(struct RawFlash *fb, const struct bbm *ctx,
                            const struct pba *blocks, uint32_t block_count,
                            void *data, uint32_t length)
{
    struct ppa *pages = NULL;
    uint8_t *padded = NULL;
    uint32_t page_count;
    uint32_t page_size;
    size_t padded_length;
    int rc = -1;

    if (!data ||
        bbm_policy_storage_pages(fb, ctx, blocks, block_count, length, &pages,
                                 &page_count, &page_size) != 0 ||
        (size_t)page_count > SIZE_MAX / page_size) {
        return -1;
    }
    padded_length = (size_t)page_count * page_size;
    padded = g_try_malloc0(padded_length);
    if (padded &&
        raw_flash_read(fb, padded, pages, page_count, page_size,
                             NULL, 0, 0, NULL) == 0) {
        memcpy(data, padded, length);
        rc = 0;
    }
    if (padded) {
        OPENSSL_cleanse(padded, padded_length);
    }
    g_free(padded);
    g_free(pages);
    return rc;
}

int bbm_policy_storage_write(struct RawFlash *fb, const struct bbm *ctx,
                             const struct pba *blocks, uint32_t block_count,
                             const void *data, uint32_t length)
{
    struct ppa *pages = NULL;
    uint8_t *padded = NULL;
    uint32_t page_count;
    uint32_t page_size;
    size_t padded_length;
    int rc = -1;

    if (!data ||
        bbm_policy_storage_pages(fb, ctx, blocks, block_count, length, &pages,
                                 &page_count, &page_size) != 0 ||
        (size_t)page_count > SIZE_MAX / page_size) {
        return -1;
    }
    padded_length = (size_t)page_count * page_size;
    padded = g_try_malloc0(padded_length);
    if (padded) {
        memcpy(padded, data, length);
        if (raw_flash_write(fb, padded, pages, page_count, page_size,
                                  NULL, 0, 0, NULL) == 0) {
            rc = 0;
        }
        OPENSSL_cleanse(padded, padded_length);
    }
    g_free(padded);
    g_free(pages);
    return rc;
}

int bbm_policy_storage_erase(struct RawFlash *fb, const struct bbm *ctx,
                             const struct pba *blocks, uint32_t block_count)
{
    uint32_t i;

    if (!fb || !ctx || !blocks || block_count == 0) {
        return -1;
    }
    for (i = 0; i < block_count; i++) {
        if (!bbm_policy_storage_block_valid(ctx, &blocks[i])) {
            return -1;
        }
    }
    return raw_flash_erase(fb, (struct pba *)blocks, block_count, NULL);
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
static inline enum RawFlashEventCommand bbm_cmd_to_backend(enum BbmEventCmd cmd)
{
    switch (cmd) {
    case BBM_EVENT_READ:  return RAW_FLASH_EVENT_READ;
    case BBM_EVENT_WRITE: return RAW_FLASH_EVENT_WRITE;
    case BBM_EVENT_ERASE: return RAW_FLASH_EVENT_ERASE;
    default: return RAW_FLASH_EVENT_READ;
    }
}

static inline enum RawFlashEventType bbm_type_to_backend(enum BbmEventType type)
{
    return type == BBM_EVENT_USER_IO ? RAW_FLASH_IO_USER
                                     : RAW_FLASH_IO_POLICY;
}

static struct ppa *bbm_translate_pages(const struct bbm *ctx,
                                       const PseudoPpa *pages,
                                       uint64_t page_count)
{
    struct ppa *physical = g_try_new0(struct ppa, page_count);
    uint64_t i;

    if (!physical) {
        return NULL;
    }
    for (i = 0; i < page_count; i++) {
        physical[i] = bbm_translate_pseudo_ppa(ctx, &pages[i]);
    }
    return physical;
}

static struct pba *bbm_translate_blocks(const struct bbm *ctx,
                                        const PseudoPba *blocks,
                                        uint64_t block_count)
{
    struct pba *physical = g_try_new0(struct pba, block_count);
    uint64_t i;

    if (!physical) {
        return NULL;
    }
    for (i = 0; i < block_count; i++) {
        physical[i] = bbm_get_maptbl_entry(ctx, &blocks[i]);
    }
    return physical;
}

static struct RawFlashEvent *
bbm_prepare_backend_event(const struct BbmEvent *event, uint64_t count,
                          struct RawFlashEvent *backend_event)
{
    if (!event) {
        return NULL;
    }
    backend_event->cmd = bbm_cmd_to_backend(event->cmd);
    backend_event->type = bbm_type_to_backend(event->type);
    backend_event->stime = event->stime;
    backend_event->status_list = event->status_list ? event->status_list
                                                    : g_new0(int, count);
    return backend_event;
}

static void bbm_finish_backend_event(const struct bbm *ctx,
                                     struct BbmEvent *event,
                                     struct RawFlashEvent *backend_event)
{
    int *caller_status_list;

    if (!event) {
        return;
    }

    caller_status_list = event->status_list;
    event->lat = backend_event->lat;
    event->count = backend_event->count;
    event->status_list = backend_event->status_list;
    if (ctx->event_notify) {
        ctx->event_notify(event, ctx->event_notify_context);
    }
    event->status_list = caller_status_list;

    if (backend_event->status_list != caller_status_list) {
        g_free(backend_event->status_list);
    }
    backend_event->status_list = NULL;
}

int bbm_read(struct RawFlash *fb, const struct bbm *ctx,
             uint8_t *buffer, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size,
             void *oob_buf, size_t oob_offset, size_t oob_len,
             struct BbmEvent *event)
{
    struct RawFlashEvent backend_event = {0};
    struct ppa *physical;
    int rc;

    /* buffer may be NULL for timing-only simulation such as GC. */
    if (!fb || !ctx || !ppas || !ppa_count || !page_size) {
        return -1;
    }
    physical = bbm_translate_pages(ctx, ppas, ppa_count);
    if (!physical) {
        return -1;
    }
    rc = raw_flash_read(
        fb, buffer, physical, ppa_count, page_size, oob_buf, oob_offset,
        oob_len, bbm_prepare_backend_event(event, ppa_count, &backend_event));
    bbm_finish_backend_event(ctx, event, &backend_event);
    g_free(physical);
    return rc;
}

int bbm_write(struct RawFlash *fb, const struct bbm *ctx,
             const uint8_t *buffer, PseudoPpa *ppas,
             uint64_t ppa_count, uint64_t page_size,
             const void *oob_buf, size_t oob_offset, size_t oob_len,
             struct BbmEvent *event)
{
    struct RawFlashEvent backend_event = {0};
    struct ppa *physical;
    int rc;

    /* buffer may be NULL for timing-only simulation such as GC. */
    if (!fb || !ctx || !ppas || !ppa_count || !page_size) {
        return -1;
    }
    physical = bbm_translate_pages(ctx, ppas, ppa_count);
    if (!physical) {
        return -1;
    }
    rc = raw_flash_write(
        fb, buffer, physical, ppa_count, page_size, oob_buf, oob_offset,
        oob_len, bbm_prepare_backend_event(event, ppa_count, &backend_event));
    bbm_finish_backend_event(ctx, event, &backend_event);
    g_free(physical);
    return rc;
}

int bbm_erase(struct RawFlash *fb, const struct bbm *ctx,
              PseudoPba *pbns, uint64_t blk_count,
              struct BbmEvent *event)
{
    struct RawFlashEvent backend_event = {0};
    struct pba *physical;
    int rc;

    if (!fb || !ctx || !pbns || !blk_count) {
        return -1;
    }
    physical = bbm_translate_blocks(ctx, pbns, blk_count);
    if (!physical) {
        return -1;
    }
    rc = raw_flash_erase(
        fb, physical, blk_count,
        bbm_prepare_backend_event(event, blk_count, &backend_event));
    bbm_finish_backend_event(ctx, event, &backend_event);
    g_free(physical);
    return rc;
}


int bbm_get_erase_cnt(const struct RawFlash *fb, const struct bbm *ctx,
                      const PseudoPba *ppba)
{
    if (!fb || !ctx || !ctx->geom || !ctx->maptbl || !ppba) {
        return -1;
    }

    /* Translate pseudo -> physical (block-level mapping) */
    struct pba phys = bbm_get_maptbl_entry(ctx, ppba);
    return raw_flash_get_erase_cnt(fb, &phys);
}

void bbm_mark_page_valid(struct RawFlash *fb, const struct bbm *ctx, const PseudoPpa *ppa)
{
    if (!fb || !ctx || !ppa) {
        return;
    }
    struct ppa phys = bbm_translate_pseudo_ppa(ctx, ppa);
    raw_flash_mark_page_valid(fb, &phys);
}

void bbm_mark_page_invalid(struct RawFlash *fb, const struct bbm *ctx, const PseudoPpa *ppa)
{
    if (!fb || !ctx || !ppa) {
        return;
    }
    struct ppa phys = bbm_translate_pseudo_ppa(ctx, ppa);
    raw_flash_mark_page_invalid(fb, &phys);
}

void bbm_mark_block_free(struct RawFlash *fb, const struct bbm *ctx, const PseudoPpa *ppa)
{
    if (!fb || !ctx || !ppa) {
        return;
    }
    PseudoPba ppba = pseudo_ppa_to_pseudo_pba(ppa);
    struct pba phys = bbm_get_maptbl_entry(ctx, &ppba);
    raw_flash_mark_block_free(fb, &phys);
}

int bbm_get_page_status(struct RawFlash *fb, const struct bbm *ctx, const PseudoPpa *ppa)
{
    if (!fb || !ctx || !ppa) {
        return -1;
    }
    struct ppa phys = bbm_translate_pseudo_ppa(ctx, ppa);
    return raw_flash_get_page_status(fb, &phys);
}

void bbm_get_block_vpc_ipc(struct RawFlash *fb, const struct bbm *ctx, const PseudoPpa *ppa, int *vpc, int *ipc)
{
    if (!fb || !ctx || !ppa || !vpc || !ipc) {
        return;
    }
    PseudoPba ppba = pseudo_ppa_to_pseudo_pba(ppa);
    struct pba phys = bbm_get_maptbl_entry(ctx, &ppba);
    raw_flash_get_block_vpc_ipc(fb, &phys, vpc, ipc);
}

void bbm_set_event_notify(struct bbm *ctx, BbmEventNotify notify,
                          void *context)
{
    if (ctx) {
        ctx->event_notify = notify;
        ctx->event_notify_context = context;
    }
}

/*
 * TODO(error-event): add bad-block checking and a dedicated error event before
 * implementing policy-controlled thresholds.  The eventual mechanism set
 * includes persistent bad-block marking, sanitization, remapping, capacity
 * shrink, read retry, and physical valid/all-data movement.  Secure-deletion
 * policies may also need OOB reverse pointers; read-disturb handling remains a
 * separate decision.
 */

int bbm_mark_block_bad(struct RawFlash *fb, const struct bbm *ctx,
                       const struct ppa *ppa)
{
    /* TODO: Implement bad block marking logic */
    (void)fb; (void)ctx; (void)ppa;  /* Suppress unused warnings */
    fprintf(stderr, "[BBM] bbm_mark_block_bad() not yet implemented\n");
    return 0;
}

int bbm_sanitize_block(struct RawFlash *fb, const struct bbm *ctx,
                       const struct ppa *ppa)
{
    /* TODO: Implement block sanitization logic */
    (void)fb; (void)ctx; (void)ppa;  /* Suppress unused warnings */
    fprintf(stderr, "[BBM] bbm_sanitize_block() not yet implemented\n");
    return 0;
}

int bbm_remap_block(struct RawFlash *fb, const struct bbm *ctx,
                    const struct ppa *ppa)
{
    /* TODO: Implement block remapping logic */
    (void)fb; (void)ctx; (void)ppa;  /* Suppress unused warnings */
    fprintf(stderr, "[BBM] bbm_remap_block() not yet implemented\n");
    return 0;
}
