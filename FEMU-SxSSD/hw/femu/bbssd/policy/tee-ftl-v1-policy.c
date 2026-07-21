#include "block-interface-policy.h"
#include "tee/tee-v1-guard.h"
#ifdef TEE_V2_POLICY
#include "tee-ftl-v2-policy.h"
#include "tee/tee-v2-relocation.h"
#include "tee/tee-v2-write.h"
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static struct block_policy_context *g_ctx = NULL;
static struct tee_v1_segment_layout g_v1_layout;
static struct tee_v1_bitmap g_v1_protected_bitmap;
static struct tee_v1_bitmap g_v1_pending_bitmap;
#ifdef TEE_V2_POLICY
static struct tee_v2_format_config g_v2_config;
static struct tee_v2_active_metadata g_v2_active;
static bool g_v2_active_valid;
static struct tee_v2_cache g_v2_cache;
static struct tee_v2_write_context g_v2_write;
#endif
static inline struct block_policy_context *get_policy_ctx(struct ssd *ssd) {
    (void)ssd;
    return g_ctx;
}
static PseudoPpa get_maptbl_ent(struct block_policy_context *ctx, uint64_t lpn) {
    if (lpn >= ctx->tt_pgs_log) {
        PseudoPpa invalid;
        invalid.ppa = UNMAPPED_PPA;
        return invalid;
    }
    return ctx->maptbl[lpn];
}
static void set_rmap_ent(struct block_policy_context *ctx, uint64_t lpn, PseudoPpa *ppa) {
    uint64_t pgidx = ctx->api->ppa_to_pgidx(ctx->ssd, ppa);
    if (pgidx < ctx->tt_pgs_log) {
        ctx->rmap[pgidx] = lpn;
    }
}
static uint64_t get_rmap_ent(struct block_policy_context *ctx, PseudoPpa *ppa) {
    uint64_t pgidx = ctx->api->ppa_to_pgidx(ctx->ssd, ppa);
    if (pgidx >= ctx->tt_pgs_log) {
        return INVALID_LPN;
    }
    return ctx->rmap[pgidx];
}
static void set_maptbl_ent(struct block_policy_context *ctx, uint64_t lpn, PseudoPpa *ppa) {
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
static bool valid_lpn(struct block_policy_context *ctx, uint64_t lpn) {
    return lpn < ctx->tt_pgs_log;
}
static void update_eswd_after_invalidate(struct block_policy_context *ctx, PseudoPpa *ppa) {
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
static void mark_page_invalid(struct block_policy_context *ctx, PseudoPpa *ppa) {
    ctx->api->mark_page_invalid(ctx->ssd, ppa);
    update_eswd_after_invalidate(ctx, ppa);
}
static struct eswd *get_next_free_eswd(struct block_policy_context *ctx) {
    struct eswd_free_node *node = QTAILQ_FIRST(&ctx->free_list);
    if (!node) {
        return NULL;
    }
    QTAILQ_REMOVE(&ctx->free_list, node, entry);
    ctx->free_cnt--;
    return ctx->api->get_eswd_by_id(ctx->ssd, node->eswd_id);
}
static int switch_to_next_eswd(struct block_policy_context *ctx) {
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
static void rotate_if_full(struct block_policy_context *ctx) {
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
static bool should_gc(struct block_policy_context *ctx) {
    return ctx->free_cnt <= ctx->gc_thres_eswds;
}
static bool should_gc_high(struct block_policy_context *ctx) {
    return ctx->free_cnt <= ctx->gc_thres_eswds_high;
}
static struct eswd *select_victim_eswd(struct block_policy_context *ctx, bool force) {
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
static int gc_select_victim(void *ctx_ptr, bool force, uint32_t *victim_id) {
    struct block_policy_context *ctx = ctx_ptr;
    struct eswd *victim = select_victim_eswd(ctx, force);
    if (!victim) {
        return -1;
    }
    *victim_id = victim->id;
    return 0;
}
static int gc_get_destination(void *ctx_ptr, uint32_t *dest_id) {
    struct block_policy_context *ctx = ctx_ptr;
    *dest_id = ctx->cur_eswd_id;
    return 0;
}
static int gc_on_destination_full(void *ctx_ptr, uint32_t current_dest_id, uint32_t *new_dest_id) {
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
                          PseudoPpa *src_ppa, void *context) {
    struct block_policy_context *ctx = context;
    (void)src_eswd_id;
    (void)page_index;
    return ctx->api->get_page_status(ctx->ssd, src_ppa) == PG_VALID;
}
static void gc_page_migrated(uint64_t lpn, PseudoPpa *old_ppa,
                             PseudoPpa *new_ppa, void *context) {
    struct block_policy_context *ctx = context;
    lpn = get_rmap_ent(ctx, old_ppa);
    if (!valid_lpn(ctx, lpn)) {
        return;
    }
    set_maptbl_ent(ctx, lpn, new_ppa);
}
static void gc_on_complete(void *ctx_ptr, uint32_t victim_id, int pages_moved) {
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
static void gc_on_failed(void *ctx_ptr, uint32_t victim_id, int error_code) {
    (void)ctx_ptr;
    (void)victim_id;
    (void)error_code;
}
static int do_gc(struct block_policy_context *ctx, bool force) {
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
static bool resolve_read_ppa(void *opaque, struct ssd *ssd, uint64_t lpn, PseudoPpa *out) {
    struct block_policy_context *ctx = opaque;
    PseudoPpa ppa = get_maptbl_ent(ctx, lpn);
    (void)ssd;
    if (!ctx->api->mapped_ppa(&ppa) || !ctx->api->valid_ppa(ctx->ssd, &ppa)) {
        return false;
    }
    *out = ppa;
    return true;
}
struct block_write_commit_context {
    struct block_policy_context *policy;
    uint64_t committed_pages;
};

static void block_update_mapping_after_write(void *opaque, struct ssd *ssd,
                                             uint64_t lpn,
                                             const PseudoPpa *new_ppa) {
    struct block_write_commit_context *commit = opaque;
    struct block_policy_context *ctx = commit->policy;
    PseudoPpa old_ppa = get_maptbl_ent(ctx, lpn);
    PseudoPpa new_ppa_local = *new_ppa;
    (void)ssd;
    if (ctx->api->mapped_ppa(&old_ppa)) {
        mark_page_invalid(ctx, &old_ppa);
        set_rmap_ent(ctx, INVALID_LPN, &old_ppa);
    }
    set_maptbl_ent(ctx, lpn, &new_ppa_local);
    commit->committed_pages++;
}
static uint64_t block_write_buffer(struct ssd *ssd,
                                   struct NvmeCommandEvent *event,
                                   const uint8_t *req_buf,
                                   uint64_t req_size,
                                   bool *complete) {
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    const struct eswd_layout *layout = ctx->api->get_eswd_layout(ctx->ssd);
    struct block_write_commit_context commit = { .policy = ctx };
    uint64_t max_lat = 0;
    uint64_t cur_lba;
    uint64_t end_lba;
    uint64_t data_off_bytes = 0;
    uint64_t expected_pages;
    uint32_t pgs_per_eswd;
    assert(ctx);
    if (complete) *complete = false;
    if (!req_buf || req_size != (uint64_t)event->nsecs * ctx->secsz)
        return 0;
    while (should_gc_high(ctx)) {
        if (do_gc(ctx, true) < 0) {
            break;
        }
    }
    cur_lba = event->lba;
    end_lba = event->lba + event->nsecs;
    expected_pages = (end_lba - 1) / ctx->secs_per_pg -
                     cur_lba / ctx->secs_per_pg + 1;
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
                                        -1,
                                        NULL, NULL,
                                        block_update_mapping_after_write, &commit,
                                        (int64_t)event->stime);
        if (lat > max_lat) {
            max_lat = lat;
        }
        data_off_bytes += (uint64_t)chunk_nlb * ctx->secsz;
        cur_lba = chunk_end_lba;
        rotate_if_full(ctx);
    }
    if (complete)
#ifdef TEE_V2_POLICY
        *complete = tee_v2_media_write_complete(
            expected_pages, commit.committed_pages, req_size, data_off_bytes);
#else
        *complete = expected_pages > 0 &&
                    expected_pages == commit.committed_pages &&
                    req_size > 0 && req_size == data_off_bytes;
#endif
    return max_lat;
}

static uint64_t block_write(struct ssd *ssd, struct NvmeCommandEvent *event) {
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    uint8_t *req_buf;
    uint64_t req_size = 0;
    uint64_t lat;
    bool complete;
    req_buf = ctx->api->copy_request_data(event->req, 0,
                                          (uint64_t)event->nsecs * ctx->secsz,
                                          &req_size);
    lat = block_write_buffer(ssd, event, req_buf, req_size, &complete);
    free(req_buf);
    return complete ? lat : 0;
}
static uint64_t block_trim(struct ssd *ssd, struct NvmeCommandEvent *event) {
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
                           struct FtlPolicyAPI *api, void *context) {
    (void)ssd;
    (void)api;
    (void)context;
    return event->opcode == NVME_CMD_READ;
}
static uint64_t read_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                              struct FtlPolicyAPI *api, void *context) {
    uint16_t status = tee_v1_check_user_lba_range(&g_v1_layout,
                                                  event->lba,
                                                  event->nsecs);
    if (status != NVME_SUCCESS) {
        event->status = status;
        return 0;
    }
    (void)context;
    return api->read_user_request(ssd, event, resolve_read_ppa, get_policy_ctx(ssd));
}
static bool write_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                            struct FtlPolicyAPI *api, void *context) {
    (void)ssd;
    (void)api;
    (void)context;
    return event->opcode == NVME_CMD_WRITE;
}
static uint64_t write_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                               struct FtlPolicyAPI *api, void *context) {
#ifdef TEE_V2_POLICY
    struct block_policy_context *ctx = get_policy_ctx(ssd);
    uint8_t *req_buf;
    uint64_t req_size = 0;
    uint64_t start_byte;
    uint64_t first_segment;
    uint64_t segment_count;
    uint64_t lat;
    uint64_t i;

    (void)api;
    (void)context;
    if (!ctx || !g_v2_config.segment_size) {
        event->status = NVME_INTERNAL_DEV_ERROR;
        return 0;
    }
    start_byte = event->lba * (uint64_t)ctx->secsz;
    first_segment = start_byte / g_v2_config.segment_size;
    segment_count = ((start_byte % g_v2_config.segment_size) +
                     (uint64_t)event->nsecs * ctx->secsz +
                     g_v2_config.segment_size - 1) / g_v2_config.segment_size;
    if (!tee_v2_write_range_allowed(&g_v2_write, first_segment,
                                    segment_count)) {
        event->status = NVME_INVALID_FIELD | NVME_DNR;
        return 0;
    }
    req_buf = ctx->api->copy_request_data(event->req, 0,
                                          (uint64_t)event->nsecs * ctx->secsz,
                                          &req_size);
    if (!req_buf || req_size != (uint64_t)event->nsecs * ctx->secsz) {
        free(req_buf);
        event->status = NVME_INTERNAL_DEV_ERROR;
        return 0;
    }
    if (start_byte % g_v2_config.segment_size == 0 &&
        req_size % g_v2_config.segment_size == 0) {
        uint64_t count = req_size / g_v2_config.segment_size;
        enum tee_v2_write_result *results = calloc(count, sizeof(*results));
        struct tee_v2_passive_metadata **passives = calloc(count, sizeof(*passives));
        uint32_t *indices = calloc(count, sizeof(*indices));
        uint64_t *old_locations = calloc(count, sizeof(*old_locations));
        struct tee_v2_active_metadata active_snapshot = {0};
        uint8_t *pending_snapshot = NULL;
        bool active_snapshot_valid = false;
        bool policy_apply_failed = false;
        if (!results || !passives || !indices || !old_locations) {
            free(results); free(passives); free(indices); free(old_locations);
            free(req_buf);
            event->status = NVME_INTERNAL_DEV_ERROR;
            return 0;
        }
        /* Validate the complete request without changing policy state. */
        if (tee_v2_preflight_segment_request(
                &g_v2_write, first_segment, req_buf,
                g_v2_config.segment_size, count,
                results, passives, indices) != 0) {
            free(results); free(passives); free(indices); free(old_locations);
            free(req_buf);
            event->status = NVME_INVALID_FIELD | NVME_DNR;
            return 0;
        }
        for (i = 0; i < count; i++) {
            if (results[i] == TEE_V2_WRITE_RELOCATION) {
                uint64_t old_byte;
                uint64_t old_lpn;
                size_t old_offset;
                PseudoPpa old_ppa;
                uint8_t *page = malloc((size_t)ctx->page_size);
                bool same = false;
                old_locations[i] = passives[i]->segment_locations[indices[i] - 1];
                old_byte = old_locations[i] * g_v2_config.segment_size;
                old_lpn = old_byte / ctx->page_size;
                old_offset = (size_t)(old_byte % ctx->page_size);
                old_ppa = get_maptbl_ent(ctx, old_lpn);
                if (page && old_offset + g_v2_config.segment_size <= ctx->page_size &&
                    ctx->api->mapped_ppa(&old_ppa) &&
                    ctx->api->valid_ppa(ctx->ssd, &old_ppa)) {
                    ctx->api->read_page_buffer(ctx->ssd, &old_ppa, page,
                                               -1, NULL, (int64_t)event->stime);
                    same = memcmp(page + old_offset,
                                  req_buf + i * g_v2_config.segment_size,
                                  g_v2_config.segment_size) == 0;
                }
                free(page);
                if (!same) {
                    free(results); free(passives); free(indices); free(old_locations);
                    free(req_buf);
                    event->status = NVME_INVALID_FIELD | NVME_DNR;
                    return 0;
                }
            }
        }
        for (i = 0; i < count; i++) {
            if (results[i] == TEE_V2_WRITE_PENDING) {
                if (g_v2_cache.passive_count >= g_v2_cache.passive_capacity ||
                    tee_v2_active_metadata_clone(&active_snapshot,
                                                 &g_v2_active) != 0) {
                    free(results); free(passives); free(indices); free(old_locations);
                    free(req_buf);
                    event->status = NVME_INTERNAL_DEV_ERROR;
                    return 0;
                }
                pending_snapshot = malloc((size_t)g_v2_write.pending_bitmap.byte_count);
                if (!pending_snapshot) {
                    tee_v2_active_metadata_destroy(&active_snapshot);
                    free(results); free(passives); free(indices); free(old_locations);
                    free(req_buf);
                    event->status = NVME_INTERNAL_DEV_ERROR;
                    return 0;
                }
                memcpy(pending_snapshot, g_v2_write.pending_bitmap.bits,
                       (size_t)g_v2_write.pending_bitmap.byte_count);
                active_snapshot_valid = true;
                break;
            }
        }
        {
            bool media_complete = false;
            lat = block_write_buffer(ssd, event, req_buf, req_size,
                                     &media_complete);
            if (!media_complete) {
                if (active_snapshot_valid)
                    tee_v2_active_metadata_destroy(&active_snapshot);
                free(pending_snapshot);
                free(results); free(passives); free(indices); free(old_locations);
                free(req_buf);
                event->status = NVME_INTERNAL_DEV_ERROR;
                return lat;
            }
        }
        /* Publish RAM working/persisted-style state only after the data write. */
        if (active_snapshot_valid) {
            uint32_t active_index;
            bool apply_failed = false;
            for (active_index = 1;
                 active_index <= active_snapshot.segment_count && !apply_failed;
                 active_index++) {
                for (i = 0; i < count; i++) {
                    struct tee_v2_segment_header header;
                    enum tee_v2_write_result applied;
                    if (results[i] != TEE_V2_WRITE_PENDING ||
                        !tee_v2_parse_segment_header(
                            req_buf + i * g_v2_config.segment_size,
                            g_v2_config.segment_size, &header) ||
                        header.segment_index != active_index)
                        continue;
                    applied = tee_v2_process_segment_write(
                        &g_v2_write, first_segment + i,
                        req_buf + i * g_v2_config.segment_size,
                        g_v2_config.segment_size, NULL, NULL);
                    if (applied == TEE_V2_WRITE_ERROR ||
                        applied == TEE_V2_WRITE_REJECTED) {
                        apply_failed = true;
                        break;
                    }
                }
            }
            if (apply_failed) {
                tee_v2_active_metadata_destroy(&g_v2_active);
                g_v2_active = active_snapshot;
                active_snapshot_valid = false;
                g_v2_write.active = &g_v2_active;
                g_v2_write.active_promoted = false;
                memcpy(g_v2_write.pending_bitmap.bits, pending_snapshot,
                       (size_t)g_v2_write.pending_bitmap.byte_count);
                event->status = NVME_INTERNAL_DEV_ERROR;
                policy_apply_failed = true;
            }
        }
        if (active_snapshot_valid)
            tee_v2_active_metadata_destroy(&active_snapshot);
        free(pending_snapshot);
        for (i = 0; i < count; i++) {
            if (!policy_apply_failed && results[i] == TEE_V2_WRITE_RELOCATION) {
                /* V2 records mark-new-before-unmark; durable transaction is V4. */
                tee_v2_cache_mark_protected(&g_v2_cache, first_segment + i);
                passives[i]->segment_locations[indices[i] - 1] = first_segment + i;
                tee_v2_cache_unmark_protected(&g_v2_cache, old_locations[i]);
            }
        }
        free(results); free(passives); free(indices); free(old_locations);
        free(req_buf);
        return lat;
    }
    free(req_buf);
    return block_write(ssd, event);
#else
    uint16_t status = tee_v1_check_write_allowed(&g_v1_layout,
                                                 &g_v1_protected_bitmap,
                                                 &g_v1_pending_bitmap,
                                                 event->lba,
                                                 event->nsecs);
    if (status != NVME_SUCCESS) {
        event->status = status;
        return 0;
    }
    (void)api;
    (void)context;
    return block_write(ssd, event);
#endif
}
static bool dsm_condition(struct ssd *ssd, struct NvmeCommandEvent *event,
                          struct FtlPolicyAPI *api, void *context) {
    (void)ssd;
    (void)api;
    (void)context;
    return event->opcode == NVME_CMD_DSM;
}
static uint64_t dsm_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                             struct FtlPolicyAPI *api, void *context) {
    const NvmeDsmRange *ranges;
    int nr_ranges = 0;

    ranges = api->get_dsm_ranges(event->req, &nr_ranges);
    for (int i = 0; ranges && i < nr_ranges; i++) {
        if (ranges[i].nlb == 0) {
            continue;
        }
        if (tee_v1_check_user_lba_range(&g_v1_layout,
                                        ranges[i].slba,
                                        ranges[i].nlb) != NVME_SUCCESS) {
            event->status = NVME_LBA_RANGE | NVME_DNR;
            return 0;
        }
#ifdef TEE_V2_POLICY
        {
            struct block_policy_context *ctx = get_policy_ctx(ssd);
            uint64_t start_byte = ranges[i].slba * (uint64_t)ctx->secsz;
            uint64_t first_segment = start_byte / g_v2_config.segment_size;
            uint64_t segment_count = ((start_byte % g_v2_config.segment_size) +
                                      (uint64_t)ranges[i].nlb * ctx->secsz +
                                      g_v2_config.segment_size - 1) /
                                     g_v2_config.segment_size;
            if (!tee_v2_write_page_range_allowed(
                    &g_v2_write, first_segment, segment_count,
                    g_v2_config.segments_per_page)) {
                event->status = NVME_INVALID_FIELD | NVME_DNR;
                return 0;
            }
        }
#endif
    }

    (void)api;
    (void)context;
    return block_trim(ssd, event);
}
static bool background_gc_condition(struct ssd *ssd, struct BackgroundEvent *event,
                                    struct FtlPolicyAPI *api, void *context) {
    (void)event;
    (void)api;
    (void)context;
    return should_gc(get_policy_ctx(ssd));
}
static void background_gc_callback(struct ssd *ssd, struct BackgroundEvent *event,
                                   struct FtlPolicyAPI *api, void *context) {
    (void)event;
    (void)api;
    (void)context;
    do_gc(get_policy_ctx(ssd), false);
}
static inline int victim_cmp_pri(pqueue_pri_t next, pqueue_pri_t curr) {
    return next > curr;
}
static inline pqueue_pri_t victim_get_pri(void *a) {
    return (pqueue_pri_t)((struct eswd_victim_node *)a)->eswd->vpc;
}
static inline void victim_set_pri(void *a, pqueue_pri_t pri) {
    ((struct eswd_victim_node *)a)->eswd->vpc = (int)pri;
}
static inline size_t victim_get_pos(void *a) {
    return ((struct eswd_victim_node *)a)->pos;
}
static inline void victim_set_pos(void *a, size_t pos) {
    ((struct eswd_victim_node *)a)->pos = pos;
}
int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api) {
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
    if (!tee_v1_segment_layout_init(&g_v1_layout,
                                    api->get_advertised_nsze_lbas(ssd),
                                    geom ? geom->secsz : 0,
                                    TEE_V1_DEFAULT_HIDDEN_LBAS)) {
        return -1;
    }
    personality.csi = NVME_CSI_NVM;
    personality.nsze = g_v1_layout.visible_lbas;
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
    if (tee_v1_bitmap_init(&g_v1_protected_bitmap,
                           g_v1_layout.visible_segments) != 0 ||
        tee_v1_bitmap_init(&g_v1_pending_bitmap,
                           g_v1_layout.visible_segments) != 0) {
        return -1;
    }
#ifdef TEE_V2_POLICY
    if (!tee_v2_format_config_init(&g_v2_config,
                                   TEE_V2_DEFAULT_SEGMENT_SIZE,
                                   (uint32_t)ctx->page_size) ||
        tee_v2_cache_init(&g_v2_cache, g_v1_layout.visible_segments, 64) != 0 ||
        tee_v2_write_context_init(&g_v2_write, NULL, &g_v2_cache,
                                  g_v1_layout.visible_segments) != 0) {
        return -1;
    }
#endif
    for (uint64_t i = 0; i < ctx->tt_pgs_log; i++) {
        ctx->maptbl[i].ppa = UNMAPPED_PPA;
        ctx->rmap[i] = INVALID_LPN;
    }
    tt_eswds = api->get_total_eswds(ssd);
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

#ifdef TEE_V2_POLICY
int tee_v2_policy_set_active_metadata(
    uint8_t file_id, uint32_t chunk_id, uint64_t chunk_size_bytes,
    uint32_t segment_count, uint32_t number_coefficient,
    const struct tee_v2_hmac_group_spec *groups, uint32_t group_count)
{
    if (!g_ctx) return -1;
    if (!tee_v2_write_can_activate_identity(&g_v2_write, file_id, chunk_id))
        return -1;
    if (g_v2_active_valid) {
        tee_v2_write_abandon_active(&g_v2_write);
        tee_v2_active_metadata_destroy(&g_v2_active);
    }
    if (tee_v2_active_metadata_init(&g_v2_active, &g_v2_config, file_id,
                                    chunk_id, chunk_size_bytes, segment_count,
                                    number_coefficient, groups, group_count) != 0) {
        g_v2_active_valid = false;
        g_v2_write.active = NULL;
        return -1;
    }
    g_v2_active_valid = true;
    g_v2_write.active = &g_v2_active;
    g_v2_write.active_promoted = false;
    return 0;
}

void tee_v2_policy_clear_active_metadata(void)
{
    if (g_v2_active_valid) {
        tee_v2_write_abandon_active(&g_v2_write);
        tee_v2_active_metadata_destroy(&g_v2_active);
    }
    g_v2_active_valid = false;
    g_v2_write.active = NULL;
    g_v2_write.active_promoted = false;
}
#endif
