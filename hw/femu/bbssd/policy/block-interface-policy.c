#include "block-interface-policy.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct block_policy_context *g_ctx = NULL;

static inline struct block_policy_context *get_policy_ctx(struct ssd *ssd)
{
    (void)ssd;
    return g_ctx;
}

static PseudoPpa get_maptbl_ent(struct block_policy_context *ctx, uint64_t lpn)
{
    if (lpn >= ctx->tt_pgs_log) {
        PseudoPpa invalid;
        invalid.ppa = UNMAPPED_PPA;
        return invalid;
    }
    return ctx->maptbl[lpn];
}

static void set_rmap_ent(struct block_policy_context *ctx, uint64_t lpn, PseudoPpa *ppa)
{
    uint64_t pgidx = ctx->api->ppa_to_pgidx(ctx->ssd, ppa);
    if (pgidx < ctx->tt_pgs_log) {
        ctx->rmap[pgidx] = lpn;
    }
}

static uint64_t get_rmap_ent(struct block_policy_context *ctx, PseudoPpa *ppa)
{
    uint64_t pgidx = ctx->api->ppa_to_pgidx(ctx->ssd, ppa);
    if (pgidx >= ctx->tt_pgs_log) {
        return INVALID_LPN;
    }
    return ctx->rmap[pgidx];
}

static void set_maptbl_ent(struct block_policy_context *ctx, uint64_t lpn, PseudoPpa *ppa)
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

static bool valid_lpn(struct block_policy_context *ctx, uint64_t lpn)
{
    return lpn < ctx->tt_pgs_log;
}

static void update_eswd_after_invalidate(struct block_policy_context *ctx, PseudoPpa *ppa)
{
    struct eswd *e = ctx->api->get_eswd_by_ppa(ctx->ssd, ppa);
    const struct eswd_layout *layout;
    bool was_full;

    if (!e || e->id == ctx->cur_eswd_id) {
        return;
    }

    layout = ctx->api->get_eswd_layout(ctx->ssd);
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

static void mark_page_invalid(struct block_policy_context *ctx, PseudoPpa *ppa)
{
    ctx->api->mark_page_invalid(ctx->ssd, ppa);
    update_eswd_after_invalidate(ctx, ppa);
}

static struct eswd *get_next_free_eswd(struct block_policy_context *ctx)
{
    struct eswd_free_node *node = QTAILQ_FIRST(&ctx->free_list);

    if (!node) {
        return NULL;
    }

    QTAILQ_REMOVE(&ctx->free_list, node, entry);
    ctx->free_cnt--;
    return ctx->api->get_eswd_by_id(ctx->ssd, node->eswd_id);
}

static int switch_to_next_eswd(struct block_policy_context *ctx)
{
    uint32_t pgs_per_eswd = ctx->api->get_eswd_layout(ctx->ssd)->pgs_per_eswd;
    int vpc;
    int ipc;
    struct eswd *next;

    ctx->api->get_eswd_vpc_ipc(ctx->ssd, ctx->cur_eswd_id, &vpc, &ipc);

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

    next = get_next_free_eswd(ctx);
    if (!next) {
        return -1;
    }
    ctx->cur_eswd_id = next->id;
    return 0;
}

static void rotate_if_full(struct block_policy_context *ctx)
{
    uint32_t wp = ctx->api->get_eswd_wp_index(ctx->ssd, ctx->cur_eswd_id);
    uint32_t pgs_per_eswd = ctx->api->get_eswd_layout(ctx->ssd)->pgs_per_eswd;

    if (wp >= pgs_per_eswd && switch_to_next_eswd(ctx) < 0) {
        abort();
    }
}

static bool should_gc(struct block_policy_context *ctx)
{
    return ctx->free_cnt <= ctx->gc_thres_eswds;
}

static bool should_gc_high(struct block_policy_context *ctx)
{
    return ctx->free_cnt <= ctx->gc_thres_eswds_high;
}

static struct eswd *select_victim_eswd(struct block_policy_context *ctx, bool force)
{
    struct eswd_victim_node *node;
    struct eswd *victim;
    uint32_t pgs_per_eswd = ctx->api->get_eswd_layout(ctx->ssd)->pgs_per_eswd;

    node = (struct eswd_victim_node *)pqueue_peek(ctx->victim_pq);
    if (!node) {
        return NULL;
    }
    victim = node->eswd;
    if (!force && victim->ipc < (int)(pgs_per_eswd / 8)) {
        return NULL;
    }

    pqueue_pop(ctx->victim_pq);
    node->pos = 0;
    ctx->victim_cnt--;
    return victim;
}

static int gc_select_victim(void *ctx_ptr, bool force, uint32_t *victim_id)
{
    struct block_policy_context *ctx = ctx_ptr;
    struct eswd *victim = select_victim_eswd(ctx, force);

    if (!victim) {
        return -1;
    }
    *victim_id = victim->id;
    return 0;
}

static int gc_get_destination(void *ctx_ptr, uint32_t *dest_id)
{
    struct block_policy_context *ctx = ctx_ptr;
    *dest_id = ctx->cur_eswd_id;
    return 0;
}

static int gc_on_destination_full(void *ctx_ptr, uint32_t current_dest_id, uint32_t *new_dest_id)
{
    struct block_policy_context *ctx = ctx_ptr;
    if (current_dest_id != ctx->cur_eswd_id) {
        return -1;
    }
    if (switch_to_next_eswd(ctx) < 0) {
        return -1;
    }
    *new_dest_id = ctx->cur_eswd_id;
    return 0;
}

static bool gc_page_valid(uint32_t src_eswd_id, uint32_t page_index,
                          PseudoPpa *src_ppa, void *context)
{
    struct block_policy_context *ctx = context;
    (void)src_eswd_id;
    (void)page_index;
    return ctx->api->get_page_status(ctx->ssd, src_ppa) == PG_VALID;
}

static void gc_page_migrated(uint64_t lpn, PseudoPpa *old_ppa,
                             PseudoPpa *new_ppa, void *context)
{
    struct block_policy_context *ctx = context;
    lpn = get_rmap_ent(ctx, old_ppa);
    if (!valid_lpn(ctx, lpn)) {
        return;
    }
    set_maptbl_ent(ctx, lpn, new_ppa);
}

static void gc_on_complete(void *ctx_ptr, uint32_t victim_id, int pages_moved)
{
    struct block_policy_context *ctx = ctx_ptr;
    uint32_t pgs_per_eswd = ctx->api->get_eswd_layout(ctx->ssd)->pgs_per_eswd;
    int invalid_pages = (int)pgs_per_eswd - pages_moved;

    ctx->api->eswd_reset(ctx->ssd, victim_id);
    ctx->free_pool[victim_id].eswd_id = victim_id;
    QTAILQ_INSERT_TAIL(&ctx->free_list, &ctx->free_pool[victim_id], entry);
    ctx->free_cnt++;

    printf("[GC] victim_eswd=%u valid=%d invalid=%d total=%u valid%%=%.1f invalid%%=%.1f "
           "free_cnt=%d victim_cnt=%d full_cnt=%d\n",
           victim_id, pages_moved, invalid_pages, pgs_per_eswd,
           pgs_per_eswd ? (100.0 * pages_moved / pgs_per_eswd) : 0.0,
           pgs_per_eswd ? (100.0 * invalid_pages / pgs_per_eswd) : 0.0,
           ctx->free_cnt, ctx->victim_cnt, ctx->full_cnt);
}

static void gc_on_failed(void *ctx_ptr, uint32_t victim_id, int error_code)
{
    (void)ctx_ptr;
    (void)victim_id;
    (void)error_code;
}

static int do_gc(struct block_policy_context *ctx, bool force)
{
    struct FtlMigrationCallbacks callbacks = {
        .should_migrate = NULL,
        .select_victim = gc_select_victim,
        .get_destination = gc_get_destination,
        .is_page_valid = gc_page_valid,
        .on_page_migrated = gc_page_migrated,
        .on_complete = gc_on_complete,
        .on_failed = gc_on_failed,
        .on_destination_full = gc_on_destination_full,
    };

    return ctx->api->run_migration(ctx->ssd, &callbacks, ctx, force) >= 0 ? 0 : -1;
}

static bool resolve_read_ppa(void *opaque, struct ssd *ssd, uint64_t lpn, PseudoPpa *out)
{
    struct block_policy_context *ctx = opaque;
    PseudoPpa ppa = get_maptbl_ent(ctx, lpn);
    (void)ssd;
    if (!ctx->api->mapped_ppa(&ppa) || !ctx->api->valid_ppa(ctx->ssd, &ppa)) {
        return false;
    }
    *out = ppa;
    return true;
}

static uint64_t block_write(struct ssd *ssd, struct NvmeCommandEvent *event)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    uint8_t *req_buf;
    uint64_t req_size = 0;
    uint64_t lat = 0;

    assert(ctx);

    while (should_gc_high(ctx)) {
        if (do_gc(ctx, true) < 0) {
            break;
        }
    }

    req_buf = ctx->api->copy_request_data(event->req, 0,
                                          (uint64_t)event->nsecs * ctx->secsz,
                                          &req_size);
    if (!req_buf || req_size < (uint64_t)event->nsecs * ctx->secsz) {
        free(req_buf);
        return 0;
    }

    for (uint64_t lpn = event->start_lpn; lpn <= event->end_lpn; lpn++) {
        uint64_t page_start_lba = lpn * ctx->secs_per_pg;
        uint64_t page_end_lba = page_start_lba + ctx->secs_per_pg;
        uint64_t write_start = event->lba > page_start_lba ? event->lba : page_start_lba;
        uint64_t write_end = (event->lba + event->nsecs) < page_end_lba ?
                             (event->lba + event->nsecs) : page_end_lba;
        uint64_t req_lba_off;
        uint64_t page_lba_off;
        uint64_t copy_lbas;
        uint64_t copy_bytes;
        uint8_t *page_buf;
        PseudoPpa old_ppa;
        PseudoPpa new_ppa;

        if (write_start >= write_end) {
            continue;
        }

        page_buf = calloc(1, (size_t)ctx->page_size);
        if (!page_buf) {
            continue;
        }

        /* RMW: read old page first so unmodified sectors are preserved */
        old_ppa = get_maptbl_ent(ctx, lpn);
        if (ctx->api->mapped_ppa(&old_ppa) && ctx->api->valid_ppa(ctx->ssd, &old_ppa)) {
            lat += ctx->api->read_page_buffer(ctx->ssd, &old_ppa, page_buf, (int64_t)event->stime);
        }

        req_lba_off = write_start - event->lba;
        page_lba_off = write_start - page_start_lba;
        copy_lbas = write_end - write_start;
        copy_bytes = copy_lbas * ctx->secsz;
        memcpy(page_buf + page_lba_off * ctx->secsz,
               req_buf + req_lba_off * ctx->secsz,
               (size_t)copy_bytes);

        new_ppa.ppa = INVALID_PPA;
        lat += ctx->api->write_seq_lbas(ctx->ssd, ctx->cur_eswd_id,
                                         page_start_lba, page_buf,
                                         (uint32_t)ctx->secs_per_pg,
                                         &new_ppa, (int64_t)event->stime);
        if (ctx->api->valid_ppa(ctx->ssd, &new_ppa)) {
            if (ctx->api->mapped_ppa(&old_ppa)) {
                mark_page_invalid(ctx, &old_ppa);
                set_rmap_ent(ctx, INVALID_LPN, &old_ppa);
            }
            set_maptbl_ent(ctx, lpn, &new_ppa);
            rotate_if_full(ctx);
        }

        free(page_buf);
    }

    free(req_buf);
    return lat;
}

static uint64_t block_trim(struct ssd *ssd, struct NvmeCommandEvent *event)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    const NvmeDsmRange *ranges;
    int nr_ranges = 0;

    ranges = ctx->api->get_dsm_ranges(event->req, &nr_ranges);
    if (!ranges || nr_ranges == 0) {
        return 0;
    }

    for (int i = 0; i < nr_ranges; i++) {
        uint64_t slba = ranges[i].slba;
        uint32_t nlb = ranges[i].nlb;
        uint64_t start_lpn;
        uint64_t end_lpn;

        if (nlb == 0) {
            continue;
        }

        start_lpn = slba / ctx->secs_per_pg;
        end_lpn = (slba + nlb - 1) / ctx->secs_per_pg;
        for (uint64_t lpn = start_lpn; lpn <= end_lpn; lpn++) {
            PseudoPpa ppa = get_maptbl_ent(ctx, lpn);
            if (ctx->api->mapped_ppa(&ppa)) {
                PseudoPpa invalid;
                mark_page_invalid(ctx, &ppa);
                invalid.ppa = UNMAPPED_PPA;
                set_maptbl_ent(ctx, lpn, &invalid);
            }
        }
    }

    return 0;
}

static bool read_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                           struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->opcode == NVME_CMD_READ;
}

static uint64_t read_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                              struct FtlPolicyAPI *api, void *context)
{
    (void)context;
    return api->read_user_request(ssd, event, resolve_read_ppa, get_policy_ctx(ssd));
}

static bool write_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                            struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->opcode == NVME_CMD_WRITE;
}

static uint64_t write_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                               struct FtlPolicyAPI *api, void *context)
{
    (void)api;
    (void)context;
    return block_write(ssd, event);
}

static bool dsm_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                          struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->opcode == NVME_CMD_DSM;
}

static uint64_t dsm_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                             struct FtlPolicyAPI *api, void *context)
{
    (void)api;
    (void)context;
    return block_trim(ssd, event);
}

static bool background_gc_condition(struct ssd *ssd, struct BackgroundEvent *event,
                                    struct FtlPolicyAPI *api, void *context)
{
    (void)event;
    (void)api;
    (void)context;
    return should_gc(get_policy_ctx(ssd));
}

static void background_gc_callback(struct ssd *ssd, struct BackgroundEvent *event,
                                   struct FtlPolicyAPI *api, void *context)
{
    (void)event;
    (void)api;
    (void)context;
    do_gc(get_policy_ctx(ssd), false);
}

static inline int victim_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr)
{
    return next > curr;
}

static inline pqueue_pri_t victim_get_pri(void *a)
{
    return (pqueue_pri_t)((struct eswd_victim_node *)a)->eswd->vpc;
}

static inline void victim_set_pri(void *a, pqueue_pri_t pri)
{
    ((struct eswd_victim_node *)a)->eswd->vpc = (int)pri;
}

static inline size_t victim_get_pos(void *a)
{
    return ((struct eswd_victim_node *)a)->pos;
}

static inline void victim_set_pos(void *a, size_t pos)
{
    ((struct eswd_victim_node *)a)->pos = pos;
}

int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    struct block_policy_context *ctx;
    struct NamespacePersonalityConfig personality = {0};
    const struct bbm_geom *geom;
    struct eswd_config config;
    uint32_t tt_eswds;

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
    if (!ctx) {
        return -1;
    }
    ctx->api = api;
    ctx->ssd = ssd;
    ctx->tt_pgs_log = api->get_total_logical_pages(ssd);
    ctx->secs_per_pg = geom ? geom->secs_per_pg : 0;
    ctx->secsz = geom ? geom->secsz : 0;
    ctx->page_size = (uint64_t)ctx->secs_per_pg * ctx->secsz;
    ctx->maptbl = calloc(ctx->tt_pgs_log, sizeof(PseudoPpa));
    ctx->rmap = calloc(ctx->tt_pgs_log, sizeof(uint64_t));
    if (!ctx->maptbl || !ctx->rmap || !ctx->secs_per_pg || !ctx->secsz) {
        return -1;
    }

    for (uint64_t i = 0; i < ctx->tt_pgs_log; i++) {
        ctx->maptbl[i].ppa = UNMAPPED_PPA;
        ctx->rmap[i] = INVALID_LPN;
    }

    tt_eswds = api->get_total_eswds(ssd);
    /* GC thresholds in eSWD units: 25% free = low watermark, 5% free = urgent */
    ctx->gc_thres_eswds      = (int)(tt_eswds / 4);
    if (ctx->gc_thres_eswds < 1) ctx->gc_thres_eswds = 1;
    ctx->gc_thres_eswds_high = (int)(tt_eswds / 20);
    if (ctx->gc_thres_eswds_high < 1) ctx->gc_thres_eswds_high = 1;

    QTAILQ_INIT(&ctx->free_list);
    QTAILQ_INIT(&ctx->full_list);
    ctx->free_pool = calloc(tt_eswds, sizeof(*ctx->free_pool));
    ctx->victim_nodes = calloc(tt_eswds, sizeof(*ctx->victim_nodes));
    ctx->full_pool = calloc(tt_eswds, sizeof(*ctx->full_pool));
    ctx->victim_pq = pqueue_init(tt_eswds, victim_cmp_pri, victim_get_pri,
                                 victim_set_pri, victim_get_pos, victim_set_pos);
    if (!ctx->free_pool || !ctx->victim_nodes || !ctx->full_pool || !ctx->victim_pq) {
        return -1;
    }

    for (uint32_t i = 0; i < tt_eswds; i++) {
        struct eswd *e;
        ctx->free_pool[i].eswd_id = i;
        QTAILQ_INSERT_TAIL(&ctx->free_list, &ctx->free_pool[i], entry);
        ctx->free_cnt++;
        e = api->get_eswd_by_id(ssd, i);
        if (e) {
            ctx->victim_nodes[i].eswd = e;
        }
    }

    {
        struct eswd *first = get_next_free_eswd(ctx);
        if (!first) {
            return -1;
        }
        ctx->cur_eswd_id = first->id;
    }

    g_ctx = ctx;
    api->register_nvme_hook(ssd, NVME_CMD_READ, read_condition, read_callback, NULL);
    api->register_nvme_hook(ssd, NVME_CMD_WRITE, write_condition, write_callback, NULL);
    api->register_nvme_hook(ssd, NVME_CMD_DSM, dsm_condition, dsm_callback, NULL);
    api->register_background_hook(ssd, background_gc_condition, background_gc_callback, NULL);
    return 0;
}
