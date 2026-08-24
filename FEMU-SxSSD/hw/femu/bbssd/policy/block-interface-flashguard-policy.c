/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "block-interface-policy.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct __attribute__((packed)) FlashguardAdminCmd {
    uint16_t opcode_flags;
    uint16_t cid;
    uint32_t nsid;
    uint64_t rsvd2;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} FlashguardAdminCmd;

static inline uint64_t policy_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static struct block_policy_context *g_ctx = NULL;
static PseudoPpa get_maptbl_ent(struct block_policy_context *ctx, uint64_t lpn);

static inline struct block_policy_context *get_policy_ctx(struct ssd *ssd)
{
    (void)ssd;
    return g_ctx;
}

static inline size_t bitmap_nbytes(uint64_t bits)
{
    return (size_t)((bits + 7) / 8);
}

static inline bool bitmap_test(const uint8_t *bitmap, uint64_t idx)
{
    return bitmap && (bitmap[idx >> 3] & (uint8_t)(1U << (idx & 7))) != 0;
}

static inline void bitmap_set(uint8_t *bitmap, uint64_t idx)
{
    if (bitmap) {
        bitmap[idx >> 3] |= (uint8_t)(1U << (idx & 7));
    }
}

static inline void bitmap_clear(uint8_t *bitmap, uint64_t idx)
{
    if (bitmap) {
        bitmap[idx >> 3] &= (uint8_t)~(1U << (idx & 7));
    }
}

static inline bool valid_pgidx(struct block_policy_context *ctx, uint64_t pgidx)
{
    return pgidx < ctx->tt_pgs_phys;
}

static uint64_t get_pgidx(struct block_policy_context *ctx, const PseudoPpa *ppa)
{
    if (!ctx || !ppa) {
        return ctx ? ctx->tt_pgs_phys : 0;
    }
    return ctx->api->ppa_to_pgidx(ctx->ssd, (PseudoPpa *)ppa);
}

static void flashguard_clear_tracking(struct block_policy_context *ctx,
                                      const PseudoPpa *ppa)
{
    uint64_t pgidx = get_pgidx(ctx, ppa);

    if (!valid_pgidx(ctx, pgidx)) {
        return;
    }
    bitmap_clear(ctx->read_bitmap, pgidx);
    bitmap_clear(ctx->retained_bitmap, pgidx);
}

static void flashguard_mark_read(struct block_policy_context *ctx, const PseudoPpa *ppa)
{
    uint64_t pgidx = get_pgidx(ctx, ppa);

    if (valid_pgidx(ctx, pgidx)) {
        bitmap_set(ctx->read_bitmap, pgidx);
    }
}

static void flashguard_set_retained(struct block_policy_context *ctx,
                                    const PseudoPpa *ppa, bool retained)
{
    uint64_t pgidx = get_pgidx(ctx, ppa);

    if (!valid_pgidx(ctx, pgidx)) {
        return;
    }
    if (retained) {
        bitmap_set(ctx->retained_bitmap, pgidx);
    } else {
        bitmap_clear(ctx->retained_bitmap, pgidx);
    }
}

static bool flashguard_is_read(struct block_policy_context *ctx, const PseudoPpa *ppa)
{
    uint64_t pgidx = get_pgidx(ctx, ppa);

    return valid_pgidx(ctx, pgidx) && bitmap_test(ctx->read_bitmap, pgidx);
}

static bool flashguard_is_retained(struct block_policy_context *ctx, const PseudoPpa *ppa)
{
    uint64_t pgidx = get_pgidx(ctx, ppa);

    return valid_pgidx(ctx, pgidx) && bitmap_test(ctx->retained_bitmap, pgidx);
}

static struct flashguard_oob *flashguard_get_shadow_oob(struct block_policy_context *ctx,
                                                        const PseudoPpa *ppa)
{
    uint64_t pgidx = get_pgidx(ctx, ppa);

    if (!valid_pgidx(ctx, pgidx) || !ctx->oob_shadow) {
        return NULL;
    }
    return &ctx->oob_shadow[pgidx];
}

static uint64_t *flashguard_get_retention_ts(struct block_policy_context *ctx,
                                             const PseudoPpa *ppa)
{
    uint64_t pgidx = get_pgidx(ctx, ppa);

    if (!valid_pgidx(ctx, pgidx) || !ctx->retention_timestamps) {
        return NULL;
    }
    return &ctx->retention_timestamps[pgidx];
}

static void flashguard_copy_oob(struct block_policy_context *ctx,
                                const PseudoPpa *src_ppa,
                                const PseudoPpa *dst_ppa)
{
    struct flashguard_oob *src = flashguard_get_shadow_oob(ctx, src_ppa);
    struct flashguard_oob *dst = flashguard_get_shadow_oob(ctx, dst_ppa);
    uint64_t *src_ts = flashguard_get_retention_ts(ctx, src_ppa);
    uint64_t *dst_ts = flashguard_get_retention_ts(ctx, dst_ppa);

    if (!src || !dst) {
        return;
    }
    *dst = *src;
    if (src_ts && dst_ts) {
        *dst_ts = *src_ts;
    }
}

static void flashguard_fill_live_oob(struct block_policy_context *ctx,
                                     uint64_t lpn,
                                     const PseudoPpa *old_ppa,
                                     struct flashguard_oob *dst)
{
    if (!dst) {
        return;
    }
    dst->lpn = lpn;
    dst->prev_ppa_raw = (old_ppa && ctx->api->mapped_ppa((PseudoPpa *)old_ppa))
        ? old_ppa->ppa
        : UNMAPPED_PPA;
    dst->retention_ts_ns = 0;
    dst->flags = 0;
    dst->reserved = 0;
}

static void flashguard_mark_retained_page(struct block_policy_context *ctx,
                                          uint64_t lpn,
                                          const PseudoPpa *ppa)
{
    uint64_t *retention_ts = flashguard_get_retention_ts(ctx, ppa);

    (void)lpn;
    if (retention_ts && *retention_ts == 0) {
        *retention_ts = policy_now_ns();
    }
    flashguard_set_retained(ctx, ppa, true);
}

static bool flashguard_retention_expired(struct block_policy_context *ctx,
                                         const PseudoPpa *ppa)
{
    uint64_t *retention_ts = flashguard_get_retention_ts(ctx, ppa);
    uint64_t now_ns;

    if (!retention_ts || !flashguard_is_retained(ctx, ppa)) {
        return false;
    }
    if (ctx->retention_window_ns == 0 || *retention_ts == 0) {
        return false;
    }
    now_ns = policy_now_ns();
    return now_ns >= *retention_ts &&
           (now_ns - *retention_ts) >= ctx->retention_window_ns;
}

static void flashguard_clear_dynamic_state(struct block_policy_context *ctx,
                                           const PseudoPpa *ppa)
{
    uint64_t *retention_ts = flashguard_get_retention_ts(ctx, ppa);

    flashguard_clear_tracking(ctx, ppa);
    if (retention_ts) {
        *retention_ts = 0;
    }
}

static void flashguard_write_oob_for_lpn(void *opaque, struct ssd *ssd, uint64_t lpn,
                                         void *oob_buf, uint32_t oob_len)
{
    struct block_policy_context *ctx = opaque;
    PseudoPpa old_ppa;
    struct flashguard_oob oob = {0};

    (void)ssd;
    if (!ctx || !oob_buf || oob_len < sizeof(oob)) {
        return;
    }
    old_ppa = get_maptbl_ent(ctx, lpn);
    flashguard_fill_live_oob(ctx, lpn,
                             ctx->api->mapped_ppa(&old_ppa) ? &old_ppa : NULL,
                             &oob);
    memcpy(oob_buf, &oob, sizeof(oob));
}

static bool flashguard_for_each_retained(
    struct block_policy_context *ctx,
    bool (*visit)(struct block_policy_context *ctx, const PseudoPpa *ppa,
                  struct flashguard_oob *oob, uint32_t ordinal, void *opaque),
    void *opaque,
    uint32_t *total_retained_out)
{
    const struct eswd_layout *layout;
    uint32_t total_retained = 0;

    if (!ctx || !visit) {
        return false;
    }

    layout = ctx->api->get_eswd_layout(ctx->ssd);
    if (!layout) {
        return false;
    }

    for (uint32_t eswd_id = 0; eswd_id < ctx->api->get_total_eswds(ctx->ssd); eswd_id++) {
        for (uint32_t page_idx = 0; page_idx < layout->pgs_per_eswd; page_idx++) {
            PseudoPpa ppa;
            struct flashguard_oob *oob;

            if (ctx->api->eswd_id_to_ppa(ctx->ssd, eswd_id, page_idx, &ppa) != 0) {
                continue;
            }
            if (!flashguard_is_retained(ctx, &ppa)) {
                continue;
            }
            oob = flashguard_get_shadow_oob(ctx, &ppa);
            if (!oob) {
                continue;
            }
            if (total_retained_out) {
                *total_retained_out = total_retained + 1;
            }
            if (!visit(ctx, &ppa, oob, total_retained, opaque)) {
                if (total_retained_out) {
                    *total_retained_out = total_retained + 1;
                }
                return true;
            }
            total_retained++;
        }
    }

    if (total_retained_out) {
        *total_retained_out = total_retained;
    }
    return true;
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
    if (pgidx < ctx->tt_pgs_phys) {
        ctx->rmap[pgidx] = lpn;
    }
}

static uint64_t get_rmap_ent(struct block_policy_context *ctx, PseudoPpa *ppa)
{
    uint64_t pgidx = ctx->api->ppa_to_pgidx(ctx->ssd, ppa);
    if (pgidx >= ctx->tt_pgs_phys) {
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
        if (old_pgidx < ctx->tt_pgs_phys) {
            ctx->rmap[old_pgidx] = INVALID_LPN;
        }
    }

    ctx->maptbl[lpn] = *ppa;

    if (ctx->api->mapped_ppa(ppa)) {
        pgidx = ctx->api->ppa_to_pgidx(ctx->ssd, ppa);
        if (pgidx < ctx->tt_pgs_phys) {
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
    flashguard_clear_dynamic_state(ctx, ppa);
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
        fprintf(stderr,
                "[block-policy] FATAL: out of free eSWDs while rotating write pointer "
                "(cur_eswd=%u free_cnt=%d victim_cnt=%d full_cnt=%d). "
                "This usually means the host filled the published namespace to the point "
                "that no overprovisioned space remained, so GC had no reclaimable victim "
                "during the initial fill phase.\n",
                ctx->cur_eswd_id, ctx->free_cnt, ctx->victim_cnt, ctx->full_cnt);
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

    if (ctx->api->get_page_status(ctx->ssd, src_ppa) != PG_VALID) {
        return false;
    }
    if (flashguard_is_retained(ctx, src_ppa) &&
        flashguard_retention_expired(ctx, src_ppa)) {
        flashguard_clear_dynamic_state(ctx, src_ppa);
        return false;
    }
    return true;
}

static void gc_page_migrated(uint64_t lpn, PseudoPpa *old_ppa,
                             PseudoPpa *new_ppa, void *context)
{
    struct block_policy_context *ctx = context;
    bool retained = flashguard_is_retained(ctx, old_ppa);
    bool was_read = flashguard_is_read(ctx, old_ppa);

    flashguard_copy_oob(ctx, old_ppa, new_ppa);
    flashguard_clear_dynamic_state(ctx, old_ppa);
    if (was_read) {
        flashguard_mark_read(ctx, new_ppa);
    }
    if (retained) {
        flashguard_set_retained(ctx, new_ppa, true);
        ctx->api->get_stats(ctx->ssd)->gc_pages_migrated++;
        return;
    }

    lpn = get_rmap_ent(ctx, old_ppa);
    if (!valid_lpn(ctx, lpn)) {
        ctx->api->get_stats(ctx->ssd)->gc_pages_migrated++;
        return;
    }
    set_maptbl_ent(ctx, lpn, new_ppa);
    ctx->api->get_stats(ctx->ssd)->gc_pages_migrated++;
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

    ctx->api->get_stats(ctx->ssd)->block_erases++;

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
    uint64_t gc_t0, gc_t1;
    int ret;

    struct ssd_stats *st = ctx->api->get_stats(ctx->ssd);
    st->gc_invocations++;
    if (force) {
        st->foreground_gc_count++;
    } else {
        st->background_gc_count++;
    }
    st->gc_active = true;

    gc_t0 = policy_now_ns();
    ret = ctx->api->run_migration(ctx->ssd, &callbacks, ctx, force) >= 0 ? 0 : -1;
    gc_t1 = policy_now_ns();

    st->gc_time_ns += (gc_t1 - gc_t0);
    st->gc_active = false;

    return ret;
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

static void block_update_mapping_after_write(void *opaque, struct ssd *ssd,
                                             uint64_t lpn,
                                             const PseudoPpa *new_ppa)
{
    struct block_policy_context *ctx = opaque;
    PseudoPpa old_ppa = get_maptbl_ent(ctx, lpn);
    PseudoPpa new_ppa_local = *new_ppa;
    bool retain_old = false;

    (void)ssd;
    if (ctx->api->mapped_ppa(&old_ppa)) {
        retain_old = flashguard_is_read(ctx, &old_ppa);
        if (retain_old) {
            flashguard_mark_retained_page(ctx, lpn, &old_ppa);
        } else {
            mark_page_invalid(ctx, &old_ppa);
        }
        set_rmap_ent(ctx, INVALID_LPN, &old_ppa);
    }
    set_maptbl_ent(ctx, lpn, &new_ppa_local);
    {
        struct flashguard_oob *new_oob = flashguard_get_shadow_oob(ctx, &new_ppa_local);
        if (new_oob) {
            flashguard_fill_live_oob(ctx, lpn,
                                     ctx->api->mapped_ppa(&old_ppa) ? &old_ppa : NULL,
                                     new_oob);
        }
    }
    flashguard_clear_dynamic_state(ctx, &new_ppa_local);
}

static uint64_t block_write(struct ssd *ssd, struct NvmeCommandEvent *event)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    const struct eswd_layout *layout = ctx->api->get_eswd_layout(ctx->ssd);
    uint8_t *req_buf;
    uint64_t req_size = 0;
    uint64_t max_lat = 0;
    uint64_t cur_lba;
    uint64_t end_lba;
    uint64_t data_off_bytes = 0;
    uint32_t pgs_per_eswd;

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

    cur_lba = event->lba;
    end_lba = event->lba + event->nsecs;
    pgs_per_eswd = layout ? layout->pgs_per_eswd : 0;

    while (cur_lba < end_lba && pgs_per_eswd > 0) {
        uint32_t wp = ctx->api->get_eswd_wp_index(ctx->ssd, ctx->cur_eswd_id);
        uint32_t avail_pages;
        uint64_t cur_lpn;
        uint64_t chunk_end_lpn;
        uint64_t chunk_end_lba;
        uint32_t chunk_nlb;
        uint64_t lat;

        if (wp >= pgs_per_eswd) {
            rotate_if_full(ctx);
            continue;
        }

        avail_pages = pgs_per_eswd - wp;
        cur_lpn = cur_lba / ctx->secs_per_pg;
        chunk_end_lpn = cur_lpn + avail_pages - 1;
        if (chunk_end_lpn > event->end_lpn) {
            chunk_end_lpn = event->end_lpn;
        }

        chunk_end_lba = (chunk_end_lpn + 1) * (uint64_t)ctx->secs_per_pg;
        if (chunk_end_lba > end_lba) {
            chunk_end_lba = end_lba;
        }
        chunk_nlb = (uint32_t)(chunk_end_lba - cur_lba);
        if (chunk_nlb == 0) {
            break;
        }

        lat = ctx->api->write_host_lbas(ctx->ssd, ctx->cur_eswd_id,
                                        cur_lba,
                                        req_buf + data_off_bytes,
                                        chunk_nlb,
                                        resolve_read_ppa, ctx,
                                        ctx->flashguard_oob_handle,
                                        flashguard_write_oob_for_lpn, ctx,
                                        block_update_mapping_after_write, ctx,
                                        (int64_t)event->stime);
        if (lat > max_lat) {
            max_lat = lat;
        }

        data_off_bytes += (uint64_t)chunk_nlb * ctx->secsz;
        cur_lba = chunk_end_lba;
        rotate_if_full(ctx);
    }

    free(req_buf);
    return max_lat;
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
                if (flashguard_is_read(ctx, &ppa)) {
                    flashguard_mark_retained_page(ctx, lpn, &ppa);
                    set_rmap_ent(ctx, INVALID_LPN, &ppa);
                } else {
                    mark_page_invalid(ctx, &ppa);
                }
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
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    uint64_t lat;

    (void)context;
    lat = api->read_user_request(ssd, event, resolve_read_ppa, ctx);
    if (ctx) {
        for (uint64_t lpn = event->start_lpn; lpn <= event->end_lpn; lpn++) {
            PseudoPpa ppa = get_maptbl_ent(ctx, lpn);
            if (ctx->api->mapped_ppa(&ppa) && ctx->api->valid_ppa(ctx->ssd, &ppa)) {
                flashguard_mark_read(ctx, &ppa);
            }
        }
    }
    return lat;
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

struct flashguard_list_walk_ctx {
    uint32_t start_index;
    uint32_t max_entries;
    uint32_t returned;
    struct flashguard_list_response *response;
};

static bool flashguard_collect_list_entry(struct block_policy_context *ctx,
                                          const PseudoPpa *ppa,
                                          struct flashguard_oob *oob,
                                          uint32_t ordinal,
                                          void *opaque)
{
    struct flashguard_list_walk_ctx *walk = opaque;
    struct flashguard_list_entry *entry;

    (void)ctx;
    if (!walk || !walk->response) {
        return false;
    }
    if (ordinal < walk->start_index) {
        return true;
    }
    if (walk->returned >= walk->max_entries) {
        return false;
    }

    entry = &walk->response->entries[walk->returned++];
    entry->ppa_raw = ppa->ppa;
    entry->lpn = oob->lpn;
    entry->prev_ppa_raw = oob->prev_ppa_raw;
    entry->retention_ts_ns = flashguard_get_retention_ts(ctx, ppa) ?
        *flashguard_get_retention_ts(ctx, ppa) : 0;
    entry->flags = FLASHGUARD_OOB_F_RETAINED;
    entry->reserved = 0;
    return true;
}

static bool admin_list_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                 struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->is_admin && event->opcode == NVME_ADM_CMD_FLASHGUARD_LIST;
}

static uint64_t admin_list_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                    struct FtlPolicyAPI *api, void *context)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    const FlashguardAdminCmd *cmd = (const FlashguardAdminCmd *)event->cmd;
    uint32_t start_index;
    uint32_t max_entries;
    uint32_t total_retained = 0;
    size_t response_len;
    struct flashguard_list_response *response;
    struct flashguard_list_walk_ctx walk = {0};

    (void)context;
    if (!ctx || !cmd || !api->write_cmd_buffer) {
        event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        return 0;
    }

    start_index = cmd->cdw10;
    max_entries = cmd->cdw11;
    if (max_entries > FLASHGUARD_LIST_MAX_ENTRIES) {
        max_entries = FLASHGUARD_LIST_MAX_ENTRIES;
    }

    response_len = sizeof(*response) +
                   (size_t)max_entries * sizeof(struct flashguard_list_entry);
    response = calloc(1, response_len);
    if (!response) {
        event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        return 0;
    }

    response->version = 1;
    walk.start_index = start_index;
    walk.max_entries = max_entries;
    walk.response = response;
    if (!flashguard_for_each_retained(ctx, flashguard_collect_list_entry,
                                      &walk, &total_retained)) {
        free(response);
        event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        return 0;
    }

    response->total_retained = total_retained;
    response->returned_entries = walk.returned;
    response->next_index = start_index + walk.returned;

    event->status = api->write_cmd_buffer(
        event, response,
        sizeof(*response) +
        (size_t)walk.returned * sizeof(struct flashguard_list_entry));
    if (event->status == NVME_SUCCESS && api->set_completion_result_u64) {
        api->set_completion_result_u64(event,
                                       ((uint64_t)response->returned_entries << 32) |
                                       response->total_retained);
    }
    free(response);
    return 0;
}

struct flashguard_read_find_ctx {
    uint64_t target_ppa_raw;
    bool found;
    PseudoPpa ppa;
    struct flashguard_oob snapshot;
};

static bool flashguard_find_entry_visitor(struct block_policy_context *ctx,
                                          const PseudoPpa *ppa,
                                          struct flashguard_oob *oob,
                                          uint32_t ordinal,
                                          void *opaque)
{
    struct flashguard_read_find_ctx *find = opaque;

    (void)ctx;
    (void)ordinal;
    if (!find) {
        return false;
    }
    if (ppa->ppa != find->target_ppa_raw) {
        return true;
    }

    find->found = true;
    find->ppa = *ppa;
    find->snapshot = *oob;
    find->snapshot.retention_ts_ns = flashguard_get_retention_ts(ctx, ppa) ?
        *flashguard_get_retention_ts(ctx, ppa) : 0;
    find->snapshot.flags = FLASHGUARD_OOB_F_RETAINED;
    return false;
}

static bool admin_read_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                                 struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    (void)context;
    return event->is_admin && event->opcode == NVME_ADM_CMD_FLASHGUARD_READ;
}

static uint64_t admin_read_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                    struct FtlPolicyAPI *api, void *context)
{
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    struct flashguard_read_request request = {0};
    struct flashguard_read_find_ctx find = {0};
    struct flashguard_read_response *response;
    size_t response_len;
    struct flashguard_oob oob = {0};

    (void)context;
    if (!ctx || !api->read_cmd_buffer || !api->write_cmd_buffer || !api->read_page_buffer) {
        event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        return 0;
    }

    event->status = api->read_cmd_buffer(event, &request, sizeof(request));
    if (event->status != NVME_SUCCESS) {
        return 0;
    }

    find.target_ppa_raw = request.ppa_raw;
    if (!flashguard_for_each_retained(ctx, flashguard_find_entry_visitor,
                                      &find, NULL) || !find.found) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }

    response_len = sizeof(*response) + ctx->page_size;
    response = calloc(1, response_len);
    if (!response) {
        event->status = NVME_INTERNAL_DEV_ERROR | NVME_DNR;
        return 0;
    }

    response->version = 1;
    response->data_len = (uint32_t)ctx->page_size;
    response->ppa_raw = find.ppa.ppa;
    response->retention_ts_ns = find.snapshot.retention_ts_ns;
    response->flags = find.snapshot.flags | FLASHGUARD_OOB_F_RETAINED;
    api->read_page_buffer(ssd, &find.ppa, response->data,
                          ctx->flashguard_oob_handle, &oob, 0);
    response->lpn = oob.lpn;
    response->prev_ppa_raw = oob.prev_ppa_raw;

    event->status = api->write_cmd_buffer(event, response, response_len);
    if (event->status == NVME_SUCCESS && api->set_completion_result_u64) {
        api->set_completion_result_u64(event, response->data_len);
    }
    free(response);
    return 0;
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
    /* Match regular FEMU: advertise the controller namespace size, not the
     * internal BBSSD geometry-derived logical page count. nsze is in 512B LBAs. */
    personality.nsze = api->get_advertised_nsze_lbas(ssd);
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
    ctx->tt_pgs_phys = geom ? geom->tt_pgs_log : 0;
    ctx->secs_per_pg = geom ? geom->secs_per_pg : 0;
    ctx->secsz = geom ? geom->secsz : 0;
    ctx->page_size = (uint64_t)ctx->secs_per_pg * ctx->secsz;
    ctx->maptbl = calloc(ctx->tt_pgs_log, sizeof(PseudoPpa));
    ctx->rmap = calloc(ctx->tt_pgs_phys, sizeof(uint64_t));
    ctx->read_bitmap = calloc(bitmap_nbytes(ctx->tt_pgs_phys), sizeof(uint8_t));
    ctx->retained_bitmap = calloc(bitmap_nbytes(ctx->tt_pgs_phys), sizeof(uint8_t));
    ctx->retention_timestamps = calloc(ctx->tt_pgs_phys, sizeof(uint64_t));
    ctx->oob_shadow = calloc(ctx->tt_pgs_phys, sizeof(struct flashguard_oob));
    ctx->retention_window_ns = FLASHGUARD_DEFAULT_RETENTION_NS;
    ctx->flashguard_oob_handle = -1;
    if (!ctx->maptbl || !ctx->rmap || !ctx->read_bitmap || !ctx->retained_bitmap ||
        !ctx->retention_timestamps || !ctx->oob_shadow ||
        !ctx->secs_per_pg || !ctx->secsz || !ctx->tt_pgs_phys) {
        return -1;
    }

    for (uint64_t i = 0; i < ctx->tt_pgs_log; i++) {
        ctx->maptbl[i].ppa = UNMAPPED_PPA;
    }
    for (uint64_t i = 0; i < ctx->tt_pgs_phys; i++) {
        ctx->rmap[i] = INVALID_LPN;
    }
    if (!api->register_oob_region ||
        api->register_oob_region(ssd, "flashguard",
                                 (uint32_t)sizeof(struct flashguard_oob),
                                 &ctx->flashguard_oob_handle) != 0) {
        return -1;
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
    api->register_admin_hook(ssd, NVME_ADM_CMD_FLASHGUARD_LIST,
                             admin_list_condition, admin_list_callback, NULL);
    api->register_admin_hook(ssd, NVME_ADM_CMD_FLASHGUARD_READ,
                             admin_read_condition, admin_read_callback, NULL);
    api->register_background_hook(ssd, background_gc_condition, background_gc_callback, NULL);
    return 0;
}
