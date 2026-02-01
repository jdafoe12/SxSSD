#include "ftl.h"
#include "bbm.h"
#include "block-interface-policy-state.h"
#include <stdio.h>

static struct block_policy_context *g_block_ctx = NULL;

static inline struct block_policy_context *get_policy_ctx(struct ssd *ssd)
{
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
    if (lpn >= ctx->tt_pgs_log) {
        return;
    }
    /* Clear old rmap entry when overwriting a mapping */
    if (ctx->api->mapped_ppa(&ctx->maptbl[lpn])) {
        uint64_t old_pgidx = ppa_to_pgidx(ctx->ssd, &ctx->maptbl[lpn]);
        if (old_pgidx < ctx->tt_pgs_log) {
            ctx->rmap[old_pgidx] = INVALID_LPN;
        }
    }
    ctx->maptbl[lpn] = *ppa;
    /* Set new rmap entry (PPA -> LPN, O(1) for GC) */
    if (ctx->api->mapped_ppa(ppa)) {
        uint64_t pgidx = ppa_to_pgidx(ctx->ssd, ppa);
        if (pgidx < ctx->tt_pgs_log) {
            /* Check if this PPA already has a different LPN mapped to it (aliasing bug) */
            uint64_t existing_lpn = ctx->rmap[pgidx];
            if (existing_lpn != INVALID_LPN && existing_lpn != lpn) {
                /* Clear the stale mapping to prevent double-invalidation */
                ctx->maptbl[existing_lpn].ppa = UNMAPPED_PPA;
            }
            ctx->rmap[pgidx] = lpn;
        }
    }
}

static uint64_t block_get_rmap_ent(struct block_policy_context *ctx, PseudoPpa *ppa)
{
    uint64_t pgidx = ppa_to_pgidx(ctx->ssd, ppa);
    if (pgidx >= ctx->tt_pgs_log) {
        return INVALID_LPN;
    }
    return ctx->rmap[pgidx];
}

static void block_set_rmap_ent(struct block_policy_context *ctx, uint64_t lpn, PseudoPpa *ppa)
{
    
    uint64_t pgidx = ppa_to_pgidx(ctx->ssd, ppa);
    
    if (pgidx >= ctx->tt_pgs_log) {
        return;
    }
    ctx->rmap[pgidx] = lpn;
}

static bool block_valid_lpn(struct block_policy_context *ctx, uint64_t lpn)
{
    return (lpn < ctx->tt_pgs_log);
}


static void block_update_eswd_after_invalidate(struct block_policy_context *ctx, PseudoPpa *ppa)
{
    struct FtlPolicyAPI *api = ctx->api;
    struct ssd *ssd = ctx->ssd;
    
    struct eswd *e = api->get_eswd_by_ppa(ssd, ppa);
    
    if (!e) {
        return;  /* Shouldn't happen */
    }
    
    /* Skip if this is the current allocation eSWD */
    if (e->id == ctx->cur_eswd_id) {
        return;
    }

    const struct eswd_layout *layout = &ssd->eswd_layout;
    bool was_full = (e->vpc == (int)(layout->pgs_per_eswd - 1));
    
    /* If eSWD was in full list, move it to victim queue */
    if (was_full) {
        printf("block_update_eswd_after_invalidate: eSWD %u was full, moving to victim queue\n", e->id);
        QTAILQ_REMOVE(&ctx->full_list, &ctx->full_pool[e->id], entry);
        ctx->full_cnt--;
        pqueue_insert(ctx->victim_pq, &ctx->victim_nodes[e->id]);
        ctx->victim_cnt++;
    }
    /* If already in victim queue, update its priority (vpc changed) */
    else if (ctx->victim_nodes[e->id].pos != 0) {
       // printf("block_update_eswd_after_invalidate: eSWD %u in victim queue, updating priority vpc=%d\n", e->id, e->vpc);
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
    struct eswd_free_node *node = QTAILQ_FIRST(&ctx->free_list); // for dynamic wear leveling, should base off erase count.
    if (!node) {
        return NULL;
    }

    QTAILQ_REMOVE(&ctx->free_list, node, entry);
    ctx->free_cnt--;

    struct eswd *result = ctx->api->get_eswd_by_id(ctx->ssd, node->eswd_id);
    return result;
}

static int block_switch_to_next_eswd(struct block_policy_context *ctx)
{
    struct FtlPolicyAPI *api = ctx->api;
    struct ssd *ssd = ctx->ssd;
    uint32_t pgs_per_eswd = ssd->eswd_layout.pgs_per_eswd;
    int vpc, ipc;

    api->get_eswd_vpc_ipc(ssd, ctx->cur_eswd_id, &vpc, &ipc);

    if (vpc == (int)pgs_per_eswd) {
        ftl_assert(ipc == 0);
        ctx->full_pool[ctx->cur_eswd_id].eswd_id = ctx->cur_eswd_id;
        QTAILQ_INSERT_TAIL(&ctx->full_list, &ctx->full_pool[ctx->cur_eswd_id], entry);
        ctx->full_cnt++;
    } else {
        ftl_assert(vpc >= 0 && vpc < (int)pgs_per_eswd);
        ftl_assert(ipc > 0);
        pqueue_insert(ctx->victim_pq, &ctx->victim_nodes[ctx->cur_eswd_id]);
        ctx->victim_cnt++;
    }

    struct eswd *next = block_get_next_free_eswd(ctx);
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
    
    if (!e) {
        return;
    }

    /* Increment write pointer within eSWD */
    api->eswd_increment_wp(ssd, ctx->cur_eswd_id);
    uint32_t wp_index = api->get_eswd_wp_index(ssd, ctx->cur_eswd_id);
    uint32_t pgs_per_eswd = ssd->eswd_layout.pgs_per_eswd;

    if (wp_index >= pgs_per_eswd) {
        if (block_switch_to_next_eswd(ctx) < 0) {
            abort();
        }
    }
}

static PseudoPpa block_get_new_page(struct block_policy_context *ctx)
{
    struct FtlPolicyAPI *api = ctx->api;
    struct ssd *ssd = ctx->ssd;
    struct eswd *e = api->get_eswd_by_id(ssd, ctx->cur_eswd_id);
    PseudoPpa ppa;

    ppa.ppa = INVALID_PPA;
    if (!e) {
        return ppa;
    }

    uint32_t wp_index = api->get_eswd_wp_index(ssd, ctx->cur_eswd_id);
    if (api->eswd_id_to_ppa(ssd, ctx->cur_eswd_id, wp_index, &ppa) != 0) {
        return ppa;
    }
    return ppa;
}

static bool block_should_gc(struct block_policy_context *ctx)
{
    return (ctx->free_cnt <= ctx->ssd->fb->sp.gc_thres_lines); // TODO: The threshold should be policy specific.
}

static bool block_should_gc_high(struct block_policy_context *ctx)
{
    return (ctx->free_cnt <= ctx->ssd->fb->sp.gc_thres_lines_high); // TODO: The thresholld should be policy specific.
}

static struct eswd *block_select_victim_eswd(struct block_policy_context *ctx, bool force)
{
    struct eswd_victim_node *node;
    struct eswd *victim_eswd;
    uint32_t pgs_per_eswd = ctx->ssd->eswd_layout.pgs_per_eswd;

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
    struct FtlPolicyAPI *api = ctx->api;
    
    int status = api->bbm_api->get_page_status(ctx->ssd->fb, ctx->ssd->bbm, src_ppa);
    return (status == PG_VALID);
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
    uint32_t pgs_per_eswd = ssd->eswd_layout.pgs_per_eswd;
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
}

static void block_gc_update_mapping(struct ssd *ssd, PseudoPpa *old_ppa, PseudoPpa *new_ppa)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    if (!ctx) {
        return;
    }
    uint64_t lpn = block_get_rmap_ent(ctx, old_ppa);
    if (!block_valid_lpn(ctx, lpn)) {
        return;
    }
    block_set_maptbl_ent(ctx, lpn, new_ppa);
}

static int block_do_gc(struct block_policy_context *ctx, bool force)
{
    struct ssd *ssd = ctx->ssd;
    
    struct FtlMigrationCallbacks callbacks = {
        .should_migrate = NULL,  /* GC need already decided by block_should_gc* before block_do_gc */
        .select_victim = block_gc_select_victim,
        .get_destination = block_gc_get_destination,
        .on_destination_full = block_gc_on_destination_full,
        .is_page_valid = block_gc_page_valid,
        .on_page_migrated = block_gc_page_migrated,
        .on_complete = block_gc_on_complete,
        .on_failed = block_gc_on_failed
    };
    
    int result = ftl_run_migration(ssd, &callbacks, ctx, force); // TODO: This should be running the migration loop!
    
    return (result >= 0) ? 0 : -1;
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

static uint64_t block_policy_write(struct ssd *ssd, NvmeRequest *req)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    assert(ctx);
    assert(ctx->api);
    struct FtlPolicyAPI *api = ctx->api;
    assert(api);
    const struct ssdparams *spp = &ssd->fb->sp;
    assert(spp);

    uint64_t lba = req->slba;
    int len = req->nlb;
    uint64_t start_lpn = lba / spp->secs_per_pg;
    uint64_t end_lpn = (lba + len - 1) / spp->secs_per_pg;
    uint64_t lpn_cnt = end_lpn - start_lpn + 1;

    int r;
    while (block_should_gc_high(ctx)) {
        r = block_do_gc(ctx, true);
        if (r == -1)
            break;
    }

    PseudoPpa *ppa_list = g_malloc0(sizeof(PseudoPpa) * lpn_cnt);
    int ppa_idx = 0;

    for (uint64_t lpn = start_lpn; lpn <= end_lpn; lpn++) {
        PseudoPpa old_ppa = block_get_maptbl_ent(ctx, lpn);

        if (api->mapped_ppa(&old_ppa)) {
            block_mark_page_invalid(ctx, &old_ppa);
            block_set_rmap_ent(ctx, INVALID_LPN, &old_ppa);
        }

        /* Allocate new page */
        PseudoPpa new_ppa = block_get_new_page(ctx);
        if (!api->valid_ppa(ssd, &new_ppa)) {
            break;
        }
        block_set_maptbl_ent(ctx, lpn, &new_ppa);
        api->mark_page_valid(ssd, &new_ppa);
        ppa_list[ppa_idx++] = new_ppa;

        block_advance_write_pointer(ctx);
    }

    uint64_t lat = api->write_user_request(ssd, req, ppa_list, (uint64_t)ppa_idx);
    g_free(ppa_list);
    return lat;
}

static uint64_t block_policy_trim(struct ssd *ssd, NvmeRequest *req)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    struct FtlPolicyAPI *api = ctx->api;
    const struct ssdparams *spp = &ssd->fb->sp;
    
    if (!req->dsm_ranges || req->dsm_nr_ranges == 0) {
        return 0;
    }
    
    for (uint32_t i = 0; i < req->dsm_nr_ranges; i++) {
        uint64_t slba = req->dsm_ranges[i].slba;
        uint32_t nlb = req->dsm_ranges[i].nlb;
        
        if (nlb == 0) {
            continue;
        }
        
        uint64_t start_lpn = slba / spp->secs_per_pg;
        uint64_t end_lpn = (slba + nlb - 1) / spp->secs_per_pg;
        
        for (uint64_t lpn = start_lpn; lpn <= end_lpn; lpn++) {
            PseudoPpa ppa = block_get_maptbl_ent(ctx, lpn);
            
            if (api->mapped_ppa(&ppa)) {
                block_mark_page_invalid(ctx, &ppa);
                
                /* Clear mapping (block_set_maptbl_ent clears rmap for old PPA) */
                PseudoPpa invalid;
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
    return (event->opcode == NVME_CMD_READ);
}

static uint64_t default_ftl_read_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                          struct FtlPolicyAPI *api, void *context)
{
    return api->read_user_request(ssd, event, block_resolve_read_ppa, get_policy_ctx(ssd));
}

static bool default_ftl_write_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                        struct FtlPolicyAPI *api, void *context)
{
    return (event->opcode == NVME_CMD_WRITE);
}

static uint64_t default_ftl_write_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                           struct FtlPolicyAPI *api, void *context)
{
    return block_policy_write(ssd, event->req);
}

static bool default_ftl_dsm_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                      struct FtlPolicyAPI *api, void *context)
{
    return (event->opcode == NVME_CMD_DSM);
}

static uint64_t default_ftl_dsm_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                         struct FtlPolicyAPI *api, void *context)
{
    if (event->req->dsm_ranges && event->req->dsm_nr_ranges > 0) {
        return block_policy_trim(ssd, event->req);
    }
    return 0;
}

static bool background_gc_condition(struct ssd *ssd, struct BackgroundEvent *event,
                                    struct FtlPolicyAPI *api, void *context)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    return block_should_gc(ctx);
}

static void background_gc_callback(struct ssd *ssd, struct BackgroundEvent *event,
                                  struct FtlPolicyAPI *api, void *context)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    block_do_gc(ctx, false);
}

static inline int victim_eswd_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return (next > curr);
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

/* Apply eSWD config via API so layout is computed from policy-set config. Called from ftl.c before eswd_layout_compute. */
void block_interface_policy_apply_eswd_config(struct ssd *ssd)
{
    struct FtlPolicyAPI *api = ssd->policy_api;
    const struct bbm_geom *geom = ssd->bbm ? ssd->bbm->geom : NULL;
    uint32_t blocks_per_eswd = geom ? geom->tt_luns : 0;
    struct eswd_config config = {
        .striping_level = ESWD_STRIPE_CHANNEL,
        .blocks_per_eswd = blocks_per_eswd,  /* explicitly tt_luns */
    };
    if (api->set_eswd_config) {
        api->set_eswd_config(ssd, &config);
    }
}

int init_block_interface_policy(struct ssd *ssd)
{
    struct FtlPolicyAPI *api = ssd->policy_api;
    struct block_policy_context *ctx;
    
    ctx = g_malloc0(sizeof(struct block_policy_context));
    ctx->api = api;
    ctx->ssd = ssd;
    
    ctx->tt_pgs_log = api->get_total_logical_pages(ssd);
    ctx->maptbl = g_malloc0(sizeof(PseudoPpa) * ctx->tt_pgs_log);
    ctx->rmap = g_malloc0(sizeof(uint64_t) * ctx->tt_pgs_log);
    
    for (uint64_t i = 0; i < ctx->tt_pgs_log; i++) {
        ctx->maptbl[i].ppa = UNMAPPED_PPA;
        ctx->rmap[i] = INVALID_LPN;
    }
    
    uint32_t tt_eswds = api->get_total_eswds(ssd);
    
    QTAILQ_INIT(&ctx->free_list); // Initialize free list
    QTAILQ_INIT(&ctx->full_list); // Initialize full list
    ctx->free_pool = g_malloc0(sizeof(struct eswd_free_node) * tt_eswds); // Allocate free pool
    ctx->victim_nodes = g_malloc0(sizeof(struct eswd_victim_node) * tt_eswds); // Allocate victim nodes
    ctx->full_pool = g_malloc0(sizeof(struct eswd_full_node) * tt_eswds); // Allocate full pool
    ctx->victim_pq = pqueue_init(tt_eswds, victim_eswd_cmp_pri, // Initialize victim priority queue
                                 victim_eswd_get_pri, victim_eswd_set_pri,
                                 victim_eswd_get_pos, victim_eswd_set_pos);
    
    for (uint32_t i = 0; i < tt_eswds; i++) { // Add all eSWDs to free list
        ctx->free_pool[i].eswd_id = i;
        QTAILQ_INSERT_TAIL(&ctx->free_list, &ctx->free_pool[i], entry); // Insert eSWD into free list
        ctx->free_cnt++;
        
        struct eswd *e = api->get_eswd_by_id(ssd, i);
        if (e) {
            ctx->victim_nodes[i].eswd = e;
        }
    }
    
    // Set current allocation eSWD
    struct eswd *first = block_get_next_free_eswd(ctx);
    if (!first) {
        return -1;
    }
    ctx->cur_eswd_id = first->id;
    
    /* Store context (global only; single instance for now) */
    g_block_ctx = ctx;

    /* Register GC mapping update for legacy mechanism GC path (do_gc/gc_write_page) */
    ssd->policy_api->gc_update_mapping = block_gc_update_mapping;
    
    /* Register I/O handlers */
    ftl_register_nvme_hook(ssd, NVME_CMD_READ, default_ftl_read_condition, default_ftl_read_callback, NULL);
    ftl_register_nvme_hook(ssd, NVME_CMD_WRITE, default_ftl_write_condition, default_ftl_write_callback, NULL);
    ftl_register_nvme_hook(ssd, NVME_CMD_DSM, default_ftl_dsm_condition, default_ftl_dsm_callback, NULL);
    
    /* Register background GC */
    ftl_register_background_hook(ssd, background_gc_condition, background_gc_callback, NULL);

    return 0;
}
