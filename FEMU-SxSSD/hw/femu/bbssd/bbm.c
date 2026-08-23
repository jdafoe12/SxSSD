/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Includes SxSSD adaptations of FEMU BBSSD FTL geometry and
 * address-management code.
 * SxSSD modifications by Josh Dafoe: 2025-12-16 through 2026-08-23.
 */

/* Bad-block mapping and controller-owned physical-storage mechanisms. */
#include "./bbm.h"
#include "policy-crypto.h"
#include <assert.h>

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

static bool bbm_valid_pseudo_pba(const struct bbm *ctx,
                                 const PseudoPba *ppba)
{
    return ctx && ctx->geom && ppba &&
           ppba->g.ch < ctx->geom->nchs &&
           ppba->g.lun < ctx->geom->luns_per_ch &&
           ppba->g.pl < ctx->geom->pls_per_lun &&
           ppba->g.blk < ctx->geom->blks_per_pl_log;
}

static uint64_t bbm_pseudo_blk_slot_index(const struct bbm *ctx,
                                           const PseudoPba *ppba)
{
    return ((((uint64_t)ppba->g.ch * ctx->geom->luns_per_ch) + ppba->g.lun)
            * ctx->geom->pls_per_lun + ppba->g.pl)
           * ctx->geom->blks_per_pl_log + ppba->g.blk;
}

static struct bbm_pswd_ctx *bbm_pswd_entry(struct bbm *ctx,
                                            const PseudoPba *ppba)
{
    if (!bbm_valid_pseudo_pba(ctx, ppba) || !ctx->pswd_state) {
        return NULL;
    }
    return &ctx->pswd_state[bbm_pseudo_blk_slot_index(ctx, ppba)];
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
    uint64_t total_entries = g->tt_blks_log;
    ctx->maptbl = g_malloc0(sizeof(struct pba) * total_entries);
    ctx->pswd_state = g_malloc0(sizeof(struct bbm_pswd_ctx) * total_entries);

    /*
     * Initial identity mapping: logical blocks map to the same physical block
     * in their LUN.  Bad-block handling will update these entries.
     */
    for (uint32_t ch = 0; ch < g->nchs; ++ch) {
        for (uint32_t lun = 0; lun < g->luns_per_ch; ++lun) {
            for (uint32_t pl = 0; pl < g->pls_per_lun; ++pl) {
                for (uint32_t blk = 0; blk < g->blks_per_pl_log; ++blk) {
                    PseudoPba ppba = {0};
                    uint64_t index;
                    struct pba *p;

                    ppba.g.ch = ch;
                    ppba.g.lun = lun;
                    ppba.g.pl = pl;
                    ppba.g.blk = blk;
                    index = bbm_pseudo_blk_slot_index(ctx, &ppba);
                    p = &ctx->maptbl[index];
                    p->g.ch = ch;
                    p->g.lun = lun;
                    p->g.pl = pl;
                    p->g.blk = blk;
                    ctx->pswd_state[index].state = PSWD_FREE;
                }
            }
        }
    }

    ctx->event_notify = NULL;
    ctx->event_notify_context = NULL;
    ctx->error_notify = NULL;
    ctx->error_notify_context = NULL;
    ctx->pswd_transition_notify = NULL;
    ctx->pswd_transition_notify_context = NULL;
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
        pe_crypto_secure_zero(padded, padded_length);
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
        pe_crypto_secure_zero(padded, padded_length);
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
    assert(bbm_valid_pseudo_pba(ctx, ppba));
    return ctx->maptbl[bbm_pseudo_blk_slot_index(ctx, ppba)];
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

static void bbm_emit_pswd_transition(struct bbm *ctx, struct RawFlash *fb,
                                     const PseudoPba *ppba,
                                     enum pswd_block_state old_state,
                                     enum pswd_block_state new_state)
{
    struct PswdStateTransitionEvent event;
    struct pba physical;

    if (!ctx || old_state == new_state) {
        return;
    }
    physical = bbm_get_maptbl_entry(ctx, ppba);
    event = (struct PswdStateTransitionEvent) {
        .old_state = old_state,
        .new_state = new_state,
        .ppba = *ppba,
        .erase_cnt = raw_flash_get_erase_cnt(fb, &physical),
        .wp = bbm_pswd_entry(ctx, ppba)->wp,
    };
    if (ctx->pswd_transition_notify) {
        ctx->pswd_transition_notify(&event, ctx->pswd_transition_notify_context);
    }
}

static void bbm_note_successful_write(struct bbm *ctx, struct RawFlash *fb,
                                      const PseudoPpa *pppa)
{
    PseudoPba ppba = pseudo_ppa_to_pseudo_pba(pppa);
    struct bbm_pswd_ctx *pswd = bbm_pswd_entry(ctx, &ppba);
    enum pswd_block_state old_state;

    if (!pswd || pswd->state == PSWD_BAD) {
        return;
    }
    old_state = pswd->state;
    if (pswd->state == PSWD_FREE) {
        pswd->state = PSWD_OPEN;
    }
    pswd->wp = MAX(pswd->wp, (uint32_t)pppa->g.pg + 1);
    if (pswd->wp >= ctx->geom->pgs_per_blk) {
        pswd->state = PSWD_CLOSED;
    }
    bbm_emit_pswd_transition(ctx, fb, &ppba, old_state, pswd->state);
}

static void bbm_note_successful_erase(struct bbm *ctx, struct RawFlash *fb,
                                      const PseudoPba *ppba)
{
    struct bbm_pswd_ctx *pswd = bbm_pswd_entry(ctx, ppba);
    enum pswd_block_state old_state;

    if (!pswd || pswd->state == PSWD_BAD) {
        return;
    }
    old_state = pswd->state;
    pswd->state = PSWD_FREE;
    pswd->wp = 0;
    pswd->vpc = 0;
    pswd->ipc = 0;
    bbm_emit_pswd_transition(ctx, fb, ppba, old_state, PSWD_FREE);
}

static void bbm_emit_errors(const struct bbm *ctx, const struct BbmEvent *event,
                            const struct RawFlashEvent *backend_event,
                            const PseudoPpa *pages,
                            const PseudoPba *blocks)
{
    uint64_t i;

    if (!ctx || !ctx->error_notify || !event || !backend_event ||
        !backend_event->status_list) {
        return;
    }
    for (i = 0; i < backend_event->count; i++) {
        struct BbmErrorEvent error;
        PseudoPba failed_pswd;
        uint64_t prior;
        bool duplicate = false;

        if (backend_event->status_list[i] == 0) {
            continue;
        }
        failed_pswd = pages ? pseudo_ppa_to_pseudo_pba(&pages[i]) : blocks[i];
        for (prior = 0; prior < i; prior++) {
            PseudoPba prior_pswd;

            if (backend_event->status_list[prior] == 0) {
                continue;
            }
            prior_pswd = pages ? pseudo_ppa_to_pseudo_pba(&pages[prior])
                               : blocks[prior];
            if (prior_pswd.g.ch == failed_pswd.g.ch &&
                prior_pswd.g.lun == failed_pswd.g.lun &&
                prior_pswd.g.pl == failed_pswd.g.pl &&
                prior_pswd.g.blk == failed_pswd.g.blk) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            continue;
        }
        error = (struct BbmErrorEvent) {
            .cmd = event->cmd,
            .type = event->type,
            .status = backend_event->status_list[i],
            .stime = event->stime,
            .lat = backend_event->lat,
        };
        if (pages) {
            error.pppa = pages[i];
        } else {
            error.pppa.g.ch = failed_pswd.g.ch;
            error.pppa.g.lun = failed_pswd.g.lun;
            error.pppa.g.pl = failed_pswd.g.pl;
            error.pppa.g.blk = failed_pswd.g.blk;
            error.pppa.g.pg = 0;
        }
        ctx->error_notify(&error, ctx->error_notify_context);
    }
}

static void bbm_finish_backend_event(struct bbm *ctx, struct RawFlash *fb,
                                     struct BbmEvent *event,
                                     struct RawFlashEvent *backend_event,
                                     const PseudoPpa *pages,
                                     const PseudoPba *blocks)
{
    int *caller_status_list;
    uint64_t i;

    if (!event) {
        return;
    }

    caller_status_list = event->status_list;
    event->lat = backend_event->lat;
    event->count = backend_event->count;
    event->status_list = backend_event->status_list;
    if (event->cmd == BBM_EVENT_WRITE && pages) {
        for (i = 0; i < backend_event->count; i++) {
            if (backend_event->status_list[i] == 0) {
                bbm_note_successful_write(ctx, fb, &pages[i]);
            }
        }
    } else if (event->cmd == BBM_EVENT_ERASE && blocks) {
        for (i = 0; i < backend_event->count; i++) {
            if (backend_event->status_list[i] == 0) {
                bbm_note_successful_erase(ctx, fb, &blocks[i]);
            }
        }
    }
    bbm_emit_errors(ctx, event, backend_event, pages, blocks);
    if (ctx->event_notify) {
        ctx->event_notify(event, ctx->event_notify_context);
    }
    event->status_list = caller_status_list;

    if (backend_event->status_list != caller_status_list) {
        g_free(backend_event->status_list);
    }
    backend_event->status_list = NULL;
}

int bbm_read(struct RawFlash *fb, struct bbm *ctx,
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
    bbm_finish_backend_event(ctx, fb, event, &backend_event, ppas, NULL);
    g_free(physical);
    return rc;
}

int bbm_write(struct RawFlash *fb, struct bbm *ctx,
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
    bbm_finish_backend_event(ctx, fb, event, &backend_event, ppas, NULL);
    g_free(physical);
    return rc;
}

int bbm_erase(struct RawFlash *fb, struct bbm *ctx,
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
    bbm_finish_backend_event(ctx, fb, event, &backend_event, NULL, pbns);
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
    PseudoPba ppba;
    struct bbm_pswd_ctx *pswd;

    if (!fb || !ctx || !ppa) {
        return;
    }
    struct ppa phys = bbm_translate_pseudo_ppa(ctx, ppa);
    raw_flash_mark_page_valid(fb, &phys);
    ppba = pseudo_ppa_to_pseudo_pba(ppa);
    pswd = bbm_pswd_entry((struct bbm *)ctx, &ppba);
    if (pswd) {
        pswd->vpc++;
    }
}

void bbm_mark_page_invalid(struct RawFlash *fb, const struct bbm *ctx, const PseudoPpa *ppa)
{
    PseudoPba ppba;
    struct bbm_pswd_ctx *pswd;

    if (!fb || !ctx || !ppa) {
        return;
    }
    struct ppa phys = bbm_translate_pseudo_ppa(ctx, ppa);
    raw_flash_mark_page_invalid(fb, &phys);
    ppba = pseudo_ppa_to_pseudo_pba(ppa);
    pswd = bbm_pswd_entry((struct bbm *)ctx, &ppba);
    if (pswd && pswd->vpc) {
        pswd->vpc--;
        pswd->ipc++;
    }
}

void bbm_mark_block_free(struct RawFlash *fb, const struct bbm *ctx, const PseudoPpa *ppa)
{
    if (!fb || !ctx || !ppa) {
        return;
    }
    PseudoPba ppba = pseudo_ppa_to_pseudo_pba(ppa);
    struct pba phys = bbm_get_maptbl_entry(ctx, &ppba);
    raw_flash_mark_block_free(fb, &phys);
    bbm_note_successful_erase((struct bbm *)ctx, fb, &ppba);
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
    struct bbm_pswd_ctx *pswd;
    PseudoPba ppba;

    if (!fb || !ctx || !ppa || !vpc || !ipc) {
        return;
    }
    (void)fb;
    ppba = pseudo_ppa_to_pseudo_pba(ppa);
    pswd = bbm_pswd_entry((struct bbm *)ctx, &ppba);
    if (!pswd) {
        return;
    }
    *vpc = pswd->vpc;
    *ipc = pswd->ipc;
}

void bbm_set_event_notify(struct bbm *ctx, BbmEventNotify notify,
                          void *context)
{
    if (ctx) {
        ctx->event_notify = notify;
        ctx->event_notify_context = context;
    }
}

void bbm_set_error_notify(struct bbm *ctx, BbmErrorNotify notify,
                          void *context)
{
    if (ctx) {
        ctx->error_notify = notify;
        ctx->error_notify_context = context;
    }
}

void bbm_set_pswd_transition_notify(struct bbm *ctx,
                                    BbmPswdTransitionNotify notify,
                                    void *context)
{
    if (ctx) {
        ctx->pswd_transition_notify = notify;
        ctx->pswd_transition_notify_context = context;
    }
}

int bbm_pswd_get(const struct bbm *ctx, const PseudoPba *ppba,
                 struct bbm_pswd_ctx *destination)
{
    const struct bbm_pswd_ctx *source;

    if (!ctx || !destination || !bbm_valid_pseudo_pba(ctx, ppba) ||
        !ctx->pswd_state) {
        return -1;
    }
    source = &ctx->pswd_state[bbm_pseudo_blk_slot_index(ctx, ppba)];
    *destination = *source;
    return 0;
}

static bool bbm_phys_block_is_mapped(const struct bbm *ctx,
                                     const struct pba *physical)
{
    uint64_t i;

    for (i = 0; i < ctx->geom->tt_blks_log; i++) {
        const struct pba *mapped = &ctx->maptbl[i];

        if (mapped->pba == physical->pba) {
            return true;
        }
    }
    return false;
}

static int bbm_find_replacement(const struct bbm *ctx, struct RawFlash *fb,
                                const PseudoPba *ppba, struct pba *result)
{
    uint32_t blk;

    for (blk = ctx->geom->blks_per_pl_log;
         blk < bbm_phys_blks_per_plane(ctx); blk++) {
        struct pba candidate = {0};

        candidate.g.ch = ppba->g.ch;
        candidate.g.lun = ppba->g.lun;
        candidate.g.pl = ppba->g.pl;
        candidate.g.blk = blk;
        if (bbm_is_excluded_phys_blk(ctx, &candidate) ||
            bbm_phys_block_is_mapped(ctx, &candidate) ||
            raw_flash_block_is_bad(fb, &candidate)) {
            continue;
        }
        *result = candidate;
        return 0;
    }
    return -1;
}

static int bbm_copy_programmed_pages(struct RawFlash *fb,
                                     const struct pba *source,
                                     const struct pba *destination,
                                     uint32_t page_count)
{
    uint64_t page_size;
    uint32_t page;

    if (!fb || !source || !destination) {
        return -1;
    }
    page_size = (uint64_t)fb->sp.secs_per_pg * fb->sp.secsz;
    if (!page_size || page_size > fb->migration_page_buf_size) {
        return -1;
    }
    for (page = 0; page < page_count; page++) {
        struct ppa source_page = {0};
        struct ppa destination_page = {0};
        int status;

        source_page.g.ch = source->g.ch;
        source_page.g.lun = source->g.lun;
        source_page.g.pl = source->g.pl;
        source_page.g.blk = source->g.blk;
        source_page.g.pg = page;
        destination_page.g.ch = destination->g.ch;
        destination_page.g.lun = destination->g.lun;
        destination_page.g.pl = destination->g.pl;
        destination_page.g.blk = destination->g.blk;
        destination_page.g.pg = page;
        status = raw_flash_get_page_status(fb, &source_page);
        if (raw_flash_read(fb, fb->migration_page_buf, &source_page, 1,
                           page_size, fb->migration_oob_buf, 0,
                           fb->oob_size_per_page, NULL) != 0 ||
            raw_flash_write(fb, fb->migration_page_buf, &destination_page, 1,
                            page_size, fb->migration_oob_buf, 0,
                            fb->oob_size_per_page, NULL) != 0) {
            return -1;
        }
        if (status == PG_VALID) {
            raw_flash_mark_page_valid(fb, &destination_page);
        } else if (status == PG_INVALID) {
            raw_flash_mark_page_valid(fb, &destination_page);
            raw_flash_mark_page_invalid(fb, &destination_page);
        }
    }
    return 0;
}

int bbm_mark_block_bad(struct RawFlash *fb, struct bbm *ctx,
                       const PseudoPba *ppba)
{
    struct bbm_pswd_ctx *pswd;
    struct pba physical;
    enum pswd_block_state old_state;

    if (!fb || !ctx || !bbm_valid_pseudo_pba(ctx, ppba) ||
        !(pswd = bbm_pswd_entry(ctx, ppba))) {
        return -1;
    }
    physical = bbm_get_maptbl_entry(ctx, ppba);
    old_state = pswd->state;
    if (raw_flash_mark_block_bad(fb, &physical) != 0) {
        return -1;
    }
    pswd->state = PSWD_BAD;
    bbm_emit_pswd_transition(ctx, fb, ppba, old_state, PSWD_BAD);
    return 0;
}

int bbm_remap_block(struct RawFlash *fb, struct bbm *ctx,
                    const PseudoPba *ppba)
{
    struct bbm_pswd_ctx *pswd;
    struct pba source;
    struct pba destination;

    if (!fb || !ctx || !bbm_valid_pseudo_pba(ctx, ppba) ||
        !(pswd = bbm_pswd_entry(ctx, ppba)) || pswd->remapping ||
        pswd->state == PSWD_BAD ||
        bbm_find_replacement(ctx, fb, ppba, &destination) != 0) {
        return -1;
    }
    source = bbm_get_maptbl_entry(ctx, ppba);
    pswd->remapping = true;
    if (pswd->wp && bbm_copy_programmed_pages(fb, &source, &destination,
                                               pswd->wp) != 0) {
        pswd->remapping = false;
        (void)bbm_mark_block_bad(fb, ctx, ppba);
        return -1;
    }

    /* The replacement becomes visible only after every programmed page copied. */
    ctx->maptbl[bbm_pseudo_blk_slot_index(ctx, ppba)] = destination;
    pswd->remapping = false;
    if (raw_flash_mark_block_bad(fb, &source) != 0) {
        return -1;
    }
    return 0;
}
