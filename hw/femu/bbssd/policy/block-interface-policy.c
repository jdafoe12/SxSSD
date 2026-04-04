#include "femu_policy.h"
#include "block-interface-policy-state.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct block_policy_context *g_block_ctx = NULL;

static inline struct block_policy_context *get_policy_ctx(struct ssd *ssd)
{
    (void)ssd;
    return g_block_ctx;
}

static PseudoPpa block_get_maptbl_ent(struct block_policy_context *ctx, uint64_t lpn)
{
    if (lpn >= ctx->tt_pgs_log) {
        PseudoPpa invalid;
        invalid.ppa = UNMAPPED_PPA;
        return invalid;
    }
    return ctx->maptbl[lpn];
}

static void block_set_maptbl_ent(struct block_policy_context *ctx, uint64_t lpn, PseudoPpa *ppa)
{
    uint64_t old_pgidx;
    uint64_t pgidx;
    uint64_t existing_lpn;

    if (lpn >= ctx->tt_pgs_log) {
        return;
    }

    if (ctx->api->mapped_ppa(&ctx->maptbl[lpn])) {
        old_pgidx = ctx->api->ppa_to_pgidx(ctx->ssd, &ctx->maptbl[lpn]);
        if (old_pgidx < ctx->tt_pgs_log) {
            ctx->rmap[old_pgidx] = INVALID_LPN;
        }
    }

    ctx->maptbl[lpn] = *ppa;

    if (ctx->api->mapped_ppa(ppa)) {
        pgidx = ctx->api->ppa_to_pgidx(ctx->ssd, ppa);
        if (pgidx < ctx->tt_pgs_log) {
            existing_lpn = ctx->rmap[pgidx];
            if (existing_lpn != INVALID_LPN && existing_lpn != lpn) {
                ctx->maptbl[existing_lpn].ppa = UNMAPPED_PPA;
            }
            ctx->rmap[pgidx] = lpn;
        }
    }
}

static uint64_t block_get_rmap_ent(struct block_policy_context *ctx, PseudoPpa *ppa)
{
    uint64_t pgidx = ctx->api->ppa_to_pgidx(ctx->ssd, ppa);
    if (pgidx >= ctx->tt_pgs_log) {
        return INVALID_LPN;
    }
    return ctx->rmap[pgidx];
}

static void block_set_rmap_ent(struct block_policy_context *ctx, uint64_t lpn, PseudoPpa *ppa)
{
    uint64_t pgidx = ctx->api->ppa_to_pgidx(ctx->ssd, ppa);
    if (pgidx >= ctx->tt_pgs_log) {
        return;
    }
    ctx->rmap[pgidx] = lpn;
}

static bool block_valid_lpn(struct block_policy_context *ctx, uint64_t lpn)
{
    return lpn < ctx->tt_pgs_log;
}

static void block_update_eswd_after_invalidate(struct block_policy_context *ctx, PseudoPpa *ppa)
{
    struct FtlPolicyAPI *api = ctx->api;
    struct ssd *ssd = ctx->ssd;
    struct eswd *e = api->get_eswd_by_ppa(ssd, ppa);
    const struct eswd_layout *layout;
    bool was_full;

    if (!e) {
        return;
    }
    if (e->id == ctx->cur_eswd_id) {
        return;
    }

    layout = api->get_eswd_layout(ssd);
    was_full = (e->vpc == (int)(layout->pgs_per_eswd - 1));

    if (was_full) {
        QTAILQ_REMOVE(&ctx->full_list, &ctx->full_pool[e->id], entry);
        ctx->full_cnt--;
        pqueue_insert(ctx->victim_pq, &ctx->victim_nodes[e->id]);
        ctx->victim_cnt++;
    } else if (ctx->victim_nodes[e->id].pos != 0) {
        pqueue_change_priority(ctx->victim_pq, e->vpc, &ctx->victim_nodes[e->id]);
    }
}

static void block_mark_page_invalid(struct block_policy_context *ctx, PseudoPpa *ppa)
{
    ctx->api->mark_page_invalid(ctx->ssd, ppa);
    block_update_eswd_after_invalidate(ctx, ppa);
}

static struct eswd *block_get_next_free_eswd(struct block_policy_context *ctx)
{
    struct eswd_free_node *node = QTAILQ_FIRST(&ctx->free_list);

    if (!node) {
        return NULL;
    }

    QTAILQ_REMOVE(&ctx->free_list, node, entry);
    ctx->free_cnt--;
    return ctx->api->get_eswd_by_id(ctx->ssd, node->eswd_id);
}

static int block_switch_to_next_eswd(struct block_policy_context *ctx)
{
    struct FtlPolicyAPI *api = ctx->api;
    struct ssd *ssd = ctx->ssd;
    uint32_t pgs_per_eswd = api->get_eswd_layout(ssd)->pgs_per_eswd;
    int vpc;
    int ipc;
    struct eswd *next;

    api->get_eswd_vpc_ipc(ssd, ctx->cur_eswd_id, &vpc, &ipc);

    if (vpc == (int)pgs_per_eswd) {
        assert(ipc == 0);
        ctx->full_pool[ctx->cur_eswd_id].eswd_id = ctx->cur_eswd_id;
        QTAILQ_INSERT_TAIL(&ctx->full_list, &ctx->full_pool[ctx->cur_eswd_id], entry);
        ctx->full_cnt++;
    } else {
        assert(vpc >= 0 && vpc < (int)pgs_per_eswd);
        assert(ipc > 0);
        pqueue_insert(ctx->victim_pq, &ctx->victim_nodes[ctx->cur_eswd_id]);
        ctx->victim_cnt++;
    }

    next = block_get_next_free_eswd(ctx);
    if (!next) {
        return -1;
    }
    ctx->cur_eswd_id = next->id;
    return 0;
}

static void block_advance_write_pointer(struct block_policy_context *ctx)
{
    struct FtlPolicyAPI *api = ctx->api;
    struct ssd *ssd = ctx->ssd;
    struct eswd *e = api->get_eswd_by_id(ssd, ctx->cur_eswd_id);
    uint32_t wp_index;
    uint32_t pgs_per_eswd;

    if (!e) {
        return;
    }

    api->eswd_increment_wp(ssd, ctx->cur_eswd_id);
    wp_index = api->get_eswd_wp_index(ssd, ctx->cur_eswd_id);
    pgs_per_eswd = api->get_eswd_layout(ssd)->pgs_per_eswd;

    if (wp_index >= pgs_per_eswd && block_switch_to_next_eswd(ctx) < 0) {
        abort();
    }
}

static PseudoPpa block_get_new_page(struct block_policy_context *ctx)
{
    struct FtlPolicyAPI *api = ctx->api;
    struct ssd *ssd = ctx->ssd;
    struct eswd *e = api->get_eswd_by_id(ssd, ctx->cur_eswd_id);
    PseudoPpa ppa;
    uint32_t wp_index;

    ppa.ppa = INVALID_PPA;
    if (!e) {
        return ppa;
    }

    wp_index = api->get_eswd_wp_index(ssd, ctx->cur_eswd_id);
    if (api->eswd_id_to_ppa(ssd, ctx->cur_eswd_id, wp_index, &ppa) != 0) {
        ppa.ppa = INVALID_PPA;
    }
    return ppa;
}

static bool block_should_gc(struct block_policy_context *ctx)
{
    return ctx->free_cnt <= ctx->api->get_gc_thres_lines(ctx->ssd);
}

static bool block_should_gc_high(struct block_policy_context *ctx)
{
    return ctx->free_cnt <= ctx->api->get_gc_thres_lines_high(ctx->ssd);
}

static struct eswd *block_select_victim_eswd(struct block_policy_context *ctx, bool force)
{
    struct eswd_victim_node *node;
    struct eswd *victim_eswd;
    uint32_t pgs_per_eswd = ctx->api->get_eswd_layout(ctx->ssd)->pgs_per_eswd;

    node = (struct eswd_victim_node *)pqueue_peek(ctx->victim_pq);
    if (!node) {
        return NULL;
    }
    victim_eswd = node->eswd;

    if (!force && victim_eswd->ipc < (int)(pgs_per_eswd / 8)) {
        return NULL;
    }

    pqueue_pop(ctx->victim_pq);
    node->pos = 0;
    ctx->victim_cnt--;
    return victim_eswd;
}

static int block_gc_select_victim(void *ctx_ptr, bool force, uint32_t *victim_id)
{
    struct block_policy_context *ctx = (struct block_policy_context *)ctx_ptr;
    struct eswd *victim = block_select_victim_eswd(ctx, force);

    if (!victim) {
        return -1;
    }
    *victim_id = victim->id;
    return 0;
}

static int block_gc_get_destination(void *ctx_ptr, uint32_t *dest_id)
{
    struct block_policy_context *ctx = (struct block_policy_context *)ctx_ptr;
    *dest_id = ctx->cur_eswd_id;
    return 0;
}

static int block_gc_on_destination_full(void *ctx_ptr, uint32_t current_dest_id, uint32_t *new_dest_id)
{
    struct block_policy_context *ctx = (struct block_policy_context *)ctx_ptr;
    if (current_dest_id != ctx->cur_eswd_id) {
        return -1;
    }
    if (block_switch_to_next_eswd(ctx) < 0) {
        return -1;
    }
    *new_dest_id = ctx->cur_eswd_id;
    return 0;
}

static bool block_gc_page_valid(uint32_t src_eswd_id, uint32_t page_index,
                                PseudoPpa *src_ppa, void *context)
{
    struct block_policy_context *ctx = (struct block_policy_context *)context;
    (void)src_eswd_id;
    (void)page_index;
    return ctx->api->get_page_status(ctx->ssd, src_ppa) == PG_VALID;
}

static void block_gc_page_migrated(uint64_t lpn, PseudoPpa *old_ppa,
                                   PseudoPpa *new_ppa, void *context)
{
    struct block_policy_context *ctx = (struct block_policy_context *)context;
    lpn = block_get_rmap_ent(ctx, old_ppa);
    if (!block_valid_lpn(ctx, lpn)) {
        return;
    }
    block_set_maptbl_ent(ctx, lpn, new_ppa);
}

static void block_gc_on_complete(void *ctx_ptr, uint32_t victim_id, int pages_moved)
{
    struct block_policy_context *ctx = (struct block_policy_context *)ctx_ptr;
    struct ssd *ssd = ctx->ssd;
    uint32_t pgs_per_eswd = ctx->api->get_eswd_layout(ssd)->pgs_per_eswd;
    int invalid_pages = (int)pgs_per_eswd - pages_moved;
    double valid_pct = (pgs_per_eswd > 0) ? (100.0 * pages_moved / pgs_per_eswd) : 0.0;
    double invalid_pct = (pgs_per_eswd > 0) ? (100.0 * invalid_pages / pgs_per_eswd) : 0.0;

    ctx->api->eswd_reset(ssd, victim_id);
    ctx->free_pool[victim_id].eswd_id = victim_id;
    QTAILQ_INSERT_TAIL(&ctx->free_list, &ctx->free_pool[victim_id], entry);
    ctx->free_cnt++;

    printf("[GC] victim_eswd=%u valid=%d invalid=%d total=%u valid%%=%.1f invalid%%=%.1f "
           "free_cnt=%d victim_cnt=%d full_cnt=%d\n",
           victim_id, pages_moved, invalid_pages, pgs_per_eswd, valid_pct, invalid_pct,
           ctx->free_cnt, ctx->victim_cnt, ctx->full_cnt);
}

static void block_gc_on_failed(void *ctx_ptr, uint32_t victim_id, int error_code)
{
    (void)ctx_ptr;
    (void)victim_id;
    (void)error_code;
}

static void block_gc_update_mapping(struct ssd *ssd, PseudoPpa *old_ppa, PseudoPpa *new_ppa)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    uint64_t lpn;

    if (!ctx) {
        return;
    }
    lpn = block_get_rmap_ent(ctx, old_ppa);
    if (!block_valid_lpn(ctx, lpn)) {
        return;
    }
    block_set_maptbl_ent(ctx, lpn, new_ppa);
}

static int block_do_gc(struct block_policy_context *ctx, bool force)
{
    struct FtlMigrationCallbacks callbacks = {
        .should_migrate = NULL,
        .select_victim = block_gc_select_victim,
        .get_destination = block_gc_get_destination,
        .is_page_valid = block_gc_page_valid,
        .on_page_migrated = block_gc_page_migrated,
        .on_complete = block_gc_on_complete,
        .on_failed = block_gc_on_failed,
        .on_destination_full = block_gc_on_destination_full,
    };

    return ctx->api->run_migration(ctx->ssd, &callbacks, ctx, force) >= 0 ? 0 : -1;
}

static bool block_resolve_read_ppa(void *ctx, struct ssd *ssd, uint64_t lpn, PseudoPpa *out)
{
    struct block_policy_context *bctx = (struct block_policy_context *)ctx;
    struct FtlPolicyAPI *api = bctx->api;
    PseudoPpa ppa = block_get_maptbl_ent(bctx, lpn);
    if (!api->mapped_ppa(&ppa) || !api->valid_ppa(ssd, &ppa)) {
        return false;
    }
    *out = ppa;
    return true;
}

static uint64_t block_policy_write(struct ssd *ssd, struct NvmeCommandEvent *event)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    struct FtlPolicyAPI *api;
    uint64_t start_lpn;
    uint64_t end_lpn;
    uint64_t lpn_cnt;
    PseudoPpa *ppa_list;
    int ppa_idx = 0;
    int r;
    uint64_t lpn;

    assert(ctx);
    api = ctx->api;
    assert(api);
    start_lpn = event->start_lpn;
    end_lpn = event->end_lpn;
    lpn_cnt = event->lpn_cnt;

    while (block_should_gc_high(ctx)) {
        r = block_do_gc(ctx, true);
        if (r == -1) {
            break;
        }
    }

    ppa_list = calloc(lpn_cnt, sizeof(PseudoPpa));
    for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
        PseudoPpa old_ppa = block_get_maptbl_ent(ctx, lpn);
        PseudoPpa new_ppa;

        if (api->mapped_ppa(&old_ppa)) {
            block_mark_page_invalid(ctx, &old_ppa);
            block_set_rmap_ent(ctx, INVALID_LPN, &old_ppa);
        }

        new_ppa = block_get_new_page(ctx);
        if (!api->valid_ppa(ssd, &new_ppa)) {
            break;
        }
        block_set_maptbl_ent(ctx, lpn, &new_ppa);
        api->mark_page_valid(ssd, &new_ppa);
        ppa_list[ppa_idx++] = new_ppa;
        block_advance_write_pointer(ctx);
    }

    lpn = api->write_user_request(ssd, event->req, ppa_list, (uint64_t)ppa_idx);
    free(ppa_list);
    return lpn;
}

static uint64_t block_policy_trim(struct ssd *ssd, struct NvmeCommandEvent *event)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    struct FtlPolicyAPI *api = ctx->api;
    const struct bbm_geom *geom = api->get_bbm_geom(ssd);
    const NvmeDsmRange *ranges;
    int nr_ranges = 0;
    uint32_t i;

    ranges = api->get_dsm_ranges(event->req, &nr_ranges);
    if (!ranges || nr_ranges == 0 || !geom) {
        return 0;
    }

    for (i = 0; i < (uint32_t)nr_ranges; i++) {
        uint64_t slba = ranges[i].slba;
        uint32_t nlb = ranges[i].nlb;
        uint64_t start_lpn;
        uint64_t end_lpn;
        uint64_t lpn;

        if (nlb == 0) {
            continue;
        }

        start_lpn = slba / geom->secs_per_pg;
        end_lpn = (slba + nlb - 1) / geom->secs_per_pg;

        for (lpn = start_lpn; lpn <= end_lpn; lpn++) {
            PseudoPpa ppa = block_get_maptbl_ent(ctx, lpn);
            if (api->mapped_ppa(&ppa)) {
                PseudoPpa invalid;
                block_mark_page_invalid(ctx, &ppa);
                invalid.ppa = UNMAPPED_PPA;
                block_set_maptbl_ent(ctx, lpn, &invalid);
            }
        }
    }

    return 0;
}

static bool default_ftl_read_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                       struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->opcode == NVME_CMD_READ;
}

static uint64_t default_ftl_read_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                          struct FtlPolicyAPI *api, void *context)
{
    (void)context;
    return api->read_user_request(ssd, event, block_resolve_read_ppa, get_policy_ctx(ssd));
}

static bool default_ftl_write_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                        struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->opcode == NVME_CMD_WRITE;
}

static uint64_t default_ftl_write_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                           struct FtlPolicyAPI *api, void *context)
{
    (void)api;
    (void)context;
    return block_policy_write(ssd, event);
}

static bool default_ftl_dsm_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                      struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->opcode == NVME_CMD_DSM;
}

static uint64_t default_ftl_dsm_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                         struct FtlPolicyAPI *api, void *context)
{
    (void)api;
    (void)context;
    return block_policy_trim(ssd, event);
}

static bool background_gc_condition(struct ssd *ssd, struct BackgroundEvent *event,
                                    struct FtlPolicyAPI *api, void *context)
{
    (void)event;
    (void)api;
    (void)context;
    return block_should_gc(get_policy_ctx(ssd));
}

static void background_gc_callback(struct ssd *ssd, struct BackgroundEvent *event,
                                   struct FtlPolicyAPI *api, void *context)
{
    (void)event;
    (void)api;
    (void)context;
    block_do_gc(get_policy_ctx(ssd), false);
}

static inline int victim_eswd_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return next > curr;
}

static inline pqueue_pri_t victim_eswd_get_pri(void *a)
{
    return (pqueue_pri_t)((struct eswd_victim_node *)a)->eswd->vpc;
}

static inline void victim_eswd_set_pri(void *a, pqueue_pri_t pri)
{
    ((struct eswd_victim_node *)a)->eswd->vpc = (int)pri;
}

static inline size_t victim_eswd_get_pos(void *a)
{
    return ((struct eswd_victim_node *)a)->pos;
}

static inline void victim_eswd_set_pos(void *a, size_t pos)
{
    ((struct eswd_victim_node *)a)->pos = pos;
}

int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    struct block_policy_context *ctx;
    struct NamespacePersonalityConfig personality = {0};
    uint32_t tt_eswds;
    uint32_t i;
    struct eswd *first;
    const struct bbm_geom *geom;
    struct eswd_config config;

    geom = api->get_bbm_geom(ssd);
    config.striping_level = ESWD_STRIPE_CHANNEL;
    config.blocks_per_eswd = geom ? geom->tt_luns : 0;

    if (api->set_eswd_config) {
        api->set_eswd_config(ssd, &config);
    }
    if (api->finalize_ftl_init && api->finalize_ftl_init(ssd) != 0) {
        return -1;
    }

    personality.csi = NVME_CSI_NVM;
    personality.nsze = api->get_total_logical_pages(ssd);
    personality.ncap = personality.nsze;
    personality.nuse = personality.ncap;
    personality.noiob = 0;
    if (api->configure_namespace_personality &&
        api->configure_namespace_personality(ssd, &personality) != 0) {
        return -1;
    }

    ctx = calloc(1, sizeof(*ctx));
    ctx->api = api;
    ctx->ssd = ssd;
    ctx->tt_pgs_log = api->get_total_logical_pages(ssd);
    ctx->maptbl = calloc(ctx->tt_pgs_log, sizeof(PseudoPpa));
    ctx->rmap = calloc(ctx->tt_pgs_log, sizeof(uint64_t));

    for (i = 0; i < ctx->tt_pgs_log; i++) {
        ctx->maptbl[i].ppa = UNMAPPED_PPA;
        ctx->rmap[i] = INVALID_LPN;
    }

    tt_eswds = api->get_total_eswds(ssd);
    QTAILQ_INIT(&ctx->free_list);
    QTAILQ_INIT(&ctx->full_list);
    ctx->free_pool = calloc(tt_eswds, sizeof(struct eswd_free_node));
    ctx->victim_nodes = calloc(tt_eswds, sizeof(struct eswd_victim_node));
    ctx->full_pool = calloc(tt_eswds, sizeof(struct eswd_full_node));
    ctx->victim_pq = pqueue_init(tt_eswds, victim_eswd_cmp_pri,
                                 victim_eswd_get_pri, victim_eswd_set_pri,
                                 victim_eswd_get_pos, victim_eswd_set_pos);

    for (i = 0; i < tt_eswds; i++) {
        struct eswd *e;
        ctx->free_pool[i].eswd_id = i;
        QTAILQ_INSERT_TAIL(&ctx->free_list, &ctx->free_pool[i], entry);
        ctx->free_cnt++;
        e = api->get_eswd_by_id(ssd, i);
        if (e) {
            ctx->victim_nodes[i].eswd = e;
        }
    }

    first = block_get_next_free_eswd(ctx);
    if (!first) {
        return -1;
    }

    ctx->cur_eswd_id = first->id;
    g_block_ctx = ctx;
    api->gc_update_mapping = block_gc_update_mapping;
    api->register_nvme_hook(ssd, NVME_CMD_READ, default_ftl_read_condition, default_ftl_read_callback, NULL);
    api->register_nvme_hook(ssd, NVME_CMD_WRITE, default_ftl_write_condition, default_ftl_write_callback, NULL);
    api->register_nvme_hook(ssd, NVME_CMD_DSM, default_ftl_dsm_condition, default_ftl_dsm_callback, NULL);
    api->register_background_hook(ssd, background_gc_condition, background_gc_callback, NULL);
    return 0;
}
