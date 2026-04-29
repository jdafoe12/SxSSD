#include "zns-policy.h"

#include <endian.h>
#include <stdlib.h>
#include <string.h>

#ifndef cpu_to_le16
#define cpu_to_le16(x) htole16(x)
#endif
#ifndef cpu_to_le32
#define cpu_to_le32(x) htole32(x)
#endif
#ifndef cpu_to_le64
#define cpu_to_le64(x) htole64(x)
#endif
#ifndef le32_to_cpu
#define le32_to_cpu(x) le32toh(x)
#endif
#ifndef le16_to_cpu
#define le16_to_cpu(x) le16toh(x)
#endif
#ifndef le64_to_cpu
#define le64_to_cpu(x) le64toh(x)
#endif

typedef struct QEMU_PACKED ZnsPolicyNvmeCmd {
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
} ZnsPolicyNvmeCmd;

typedef struct QEMU_PACKED ZnsPolicyNvmeRwCmd {
    uint16_t opcode_flags;
    uint16_t cid;
    uint32_t nsid;
    uint64_t rsvd2;
    uint64_t mptr;
    uint64_t prp1;
    uint64_t prp2;
    uint64_t slba;
    uint16_t nlb;
    uint16_t control;
    uint32_t dsmgmt;
    uint32_t reftag;
    uint16_t apptag;
    uint16_t appmask;
} ZnsPolicyNvmeRwCmd;

static uint64_t zns_write_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                   struct FtlPolicyAPI *api, void *context);
static uint64_t zns_append_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                    struct FtlPolicyAPI *api, void *context);

static inline void zns_set_status(struct NvmeCommandEvent *event, uint16_t status)
{
    event->status = status;
}

/* Match FEMU zns.h zns_aor_inc/dec_*: only track when the corresponding limit is set. */
static inline void zns_policy_inc_active(struct zns_policy_context *ctx)
{
    if (ctx->max_active_zones != 0) {
        ctx->nr_active_zones++;
    }
}

static inline void zns_policy_dec_active(struct zns_policy_context *ctx)
{
    if (ctx->max_active_zones != 0 && ctx->nr_active_zones > 0) {
        ctx->nr_active_zones--;
    }
}

static inline void zns_policy_inc_open(struct zns_policy_context *ctx)
{
    if (ctx->max_open_zones != 0) {
        ctx->nr_open_zones++;
    }
}

static inline void zns_policy_dec_open(struct zns_policy_context *ctx)
{
    if (ctx->max_open_zones != 0 && ctx->nr_open_zones > 0) {
        ctx->nr_open_zones--;
    }
}

static inline uint64_t zns_total_lbas(const struct zns_policy_context *ctx)
{
    return (uint64_t)ctx->zone_count * ctx->zone_size_lbas;
}


// TODO: dosent eSWD do this directly. An eSWD IS a zone?
static inline struct zns_policy_zone *zns_zone_from_slba(struct zns_policy_context *ctx,
                                                         uint64_t slba)
{
    uint32_t zone_id = (uint32_t)(slba / ctx->zone_size_lbas);

    return zone_id < ctx->zone_count ? &ctx->zones[zone_id] : NULL;
}

static inline uint32_t zns_zone_wp_index(struct zns_policy_context *ctx,
                                         const struct zns_policy_zone *zone)
{
    return ctx->api->get_eswd_wp_index(ctx->ssd, zone->eswd_id);
}

static inline uint64_t zns_zone_wp_lba(struct zns_policy_context *ctx,
                                       const struct zns_policy_zone *zone)
{
    return ctx->api->eswd_get_wp_lba(ctx->ssd, zone->eswd_id);
}

static inline uint64_t zns_zone_end_lba(const struct zns_policy_zone *zone)
{
    return zone->zslba + zone->zcap;
}

static inline bool zns_zone_wp_valid(const struct zns_policy_zone *zone)
{
    return zone->state != ZNS_POLICY_ZONE_STATE_FULL &&
           zone->state != ZNS_POLICY_ZONE_STATE_READ_ONLY &&
           zone->state != ZNS_POLICY_ZONE_STATE_OFFLINE;
}

// Check if the command LBA range is within the total LBA range of the namespace
static uint16_t zns_check_bounds(struct zns_policy_context *ctx, uint64_t slba,
                                 uint32_t nlb)
{
    if (nlb == 0) {
        return NVME_SUCCESS;
    }
    if (UINT64_MAX - slba < nlb || slba + nlb > zns_total_lbas(ctx)) {
        return NVME_LBA_RANGE | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static uint16_t zns_check_read_state(const struct zns_policy_zone *zone)
{
    switch (zone->state) {
    case ZNS_POLICY_ZONE_STATE_EMPTY:
    case ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN:
    case ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN:
    case ZNS_POLICY_ZONE_STATE_CLOSED:
    case ZNS_POLICY_ZONE_STATE_READ_ONLY:
    case ZNS_POLICY_ZONE_STATE_FULL:
        return NVME_SUCCESS;
    case ZNS_POLICY_ZONE_STATE_OFFLINE:
        return NVME_ZONE_OFFLINE;
    default:
        return NVME_INVALID_FIELD;
    }
}

static uint16_t zns_check_write_state(const struct zns_policy_zone *zone)
{
    switch (zone->state) {
    case ZNS_POLICY_ZONE_STATE_EMPTY:
    case ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN:
    case ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN:
    case ZNS_POLICY_ZONE_STATE_CLOSED:
        return NVME_SUCCESS;
    case ZNS_POLICY_ZONE_STATE_FULL:
        return NVME_ZONE_FULL;
    case ZNS_POLICY_ZONE_STATE_OFFLINE:
        return NVME_ZONE_OFFLINE;
    case ZNS_POLICY_ZONE_STATE_READ_ONLY:
        return NVME_ZONE_READ_ONLY;
    default:
        return NVME_INVALID_FIELD;
    }
}

static uint16_t zns_check_aor(struct zns_policy_context *ctx, uint32_t add_active,
                              uint32_t add_open)
{
    if (ctx->max_active_zones != 0 &&
        ctx->nr_active_zones + add_active > ctx->max_active_zones) {
        return NVME_ZONE_TOO_MANY_ACTIVE | NVME_DNR;
    }
    if (ctx->max_open_zones != 0 &&
        ctx->nr_open_zones + add_open > ctx->max_open_zones) {
        return NVME_ZONE_TOO_MANY_OPEN | NVME_DNR;
    }
    return NVME_SUCCESS;
}

static void zns_close_one_implicit_zone(struct zns_policy_context *ctx)
{
    uint32_t i;

    if (ctx->max_open_zones == 0 || ctx->nr_open_zones < ctx->max_open_zones) {
        return;
    }

    for (i = 0; i < ctx->zone_count; i++) {
        if (ctx->zones[i].state == ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN) {
            ctx->zones[i].state = ZNS_POLICY_ZONE_STATE_CLOSED;
            zns_policy_dec_open(ctx);
            return;
        }
    }
}

static uint16_t zns_ensure_implicit_open(struct zns_policy_context *ctx,
                                         struct zns_policy_zone *zone)
{
    uint16_t status;

    switch (zone->state) {
    case ZNS_POLICY_ZONE_STATE_EMPTY:
        zns_close_one_implicit_zone(ctx);
        status = zns_check_aor(ctx, 1, 1);
        if (status != NVME_SUCCESS) {
            return status;
        }
        zone->state = ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN;
        zns_policy_inc_active(ctx);
        zns_policy_inc_open(ctx);
        return NVME_SUCCESS;
    case ZNS_POLICY_ZONE_STATE_CLOSED:
        zns_close_one_implicit_zone(ctx);
        status = zns_check_aor(ctx, 0, 1);
        if (status != NVME_SUCCESS) {
            return status;
        }
        zone->state = ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN;
        zns_policy_inc_open(ctx);
        return NVME_SUCCESS;
    case ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN:
    case ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN:
        return NVME_SUCCESS;
    default:
        return zns_check_write_state(zone);
    }
}

static void zns_maybe_finish_zone(struct zns_policy_context *ctx,
                                  struct zns_policy_zone *zone)
{
    if (zns_zone_wp_lba(ctx, zone) != zns_zone_end_lba(zone)) {
        return;
    }

    /* Mirror zns_finalize_zoned_write() in zns.c (fall-through cases). */
    switch (zone->state) {
    case ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN:
    case ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN:
        zns_policy_dec_open(ctx);
        /* fall through */
    case ZNS_POLICY_ZONE_STATE_CLOSED:
        zns_policy_dec_active(ctx);
        /* fall through */
    case ZNS_POLICY_ZONE_STATE_EMPTY:
        if (zone->state == ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN) {
            zone->attr |= ZNS_POLICY_ZA_FINISHED_BY_CTLR;
        }
        zone->state = ZNS_POLICY_ZONE_STATE_FULL;
        break;
    default:
        break;
    }
}


static uint64_t zns_do_write(struct zns_policy_context *ctx,
                             struct NvmeCommandEvent *event, bool append)
{
    ZnsPolicyNvmeRwCmd *rw = event->cmd;
    uint64_t cmd_slba = append ? le64_to_cpu(rw->slba) : event->lba;
    uint32_t nlb = append ? (uint32_t)le16_to_cpu(rw->nlb) + 1 : (uint32_t)event->nsecs;
    struct zns_policy_zone *zone;
    uint64_t write_slba;
    uint16_t status;
    uint64_t lat = 0;
    uint8_t *req_buf;
    uint64_t req_size = 0;
    uint64_t cur_lba;

    status = zns_check_bounds(ctx, cmd_slba, nlb);
    if (status != NVME_SUCCESS) {
        zns_set_status(event, status);
        return 0;
    }

    zone = zns_zone_from_slba(ctx, cmd_slba);
    if (!zone) {
        zns_set_status(event, NVME_LBA_RANGE | NVME_DNR);
        return 0;
    }

    status = zns_check_write_state(zone);
    if (status != NVME_SUCCESS) {
        zns_set_status(event, status | NVME_DNR);
        return 0;
    }

    write_slba = ctx->api->eswd_get_wp_lba(ctx->ssd, zone->eswd_id);

    if (append) {
        if (cmd_slba != zone->zslba) {
            zns_set_status(event, NVME_INVALID_FIELD | NVME_DNR);
            return 0;
        }
        status = ctx->api->eswd_check_seq_write(ctx->ssd, zone->eswd_id, write_slba, nlb);
    } else {
        status = ctx->api->eswd_check_seq_write(ctx->ssd, zone->eswd_id, cmd_slba, nlb);
    }
    if (status != NVME_SUCCESS) {
        zns_set_status(event, status);
        return 0;
    }

    status = zns_ensure_implicit_open(ctx, zone);
    if (status != NVME_SUCCESS) {
        zns_set_status(event, status);
        return 0;
    }

    req_buf = ctx->api->copy_request_data(event->req, 0,
                                          (uint64_t)nlb * ctx->lbasz, &req_size);
    if (!req_buf || req_size < (uint64_t)nlb * ctx->lbasz) {
        free(req_buf);
        zns_set_status(event, NVME_INTERNAL_DEV_ERROR | NVME_DNR);
        return 0;
    }

    cur_lba = append ? write_slba : cmd_slba;
    lat = ctx->api->write_seq_lbas(ctx->ssd, zone->eswd_id,
                                   cur_lba, req_buf, nlb,
                                   -1, NULL, NULL,
                                   NULL, (int64_t)event->stime);

    free(req_buf);

    if (append) {
        ctx->api->set_completion_result_u64(event, write_slba);
    }

    zns_maybe_finish_zone(ctx, zone);
    zns_set_status(event, NVME_SUCCESS);
    return lat;
}

static uint64_t zns_read_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                  struct FtlPolicyAPI *api, void *context)
{
    struct zns_policy_context *ctx = (struct zns_policy_context *)context;
    struct zns_policy_zone *zone;
    uint16_t status;
    uint64_t effective_wp;
    uint64_t page_size;
    uint64_t total_bytes;
    uint8_t *out;
    uint8_t *page_buf;
    uint64_t cur_lba;
    uint32_t remaining;
    uint64_t out_off;
    uint64_t lat = 0;

    (void)ssd;
    (void)api;

    status = zns_check_bounds(ctx, event->lba, (uint32_t)event->nsecs);
    if (status != NVME_SUCCESS) {
        zns_set_status(event, status);
        return 0;
    }

    zone = zns_zone_from_slba(ctx, event->lba);
    if (!zone) {
        zns_set_status(event, NVME_LBA_RANGE | NVME_DNR);
        return 0;
    }

    status = zns_check_read_state(zone);
    if (status != NVME_SUCCESS) {
        zns_set_status(event, status | NVME_DNR);
        return 0;
    }
    if (!ctx->cross_zone_read && event->lba + event->nsecs > zone->zslba + ctx->zone_size_lbas) {
        zns_set_status(event, NVME_ZONE_BOUNDARY_ERROR | NVME_DNR);
        return 0;
    }

    /*
     * Range check against effective WP: includes staged-but-not-yet-flushed
     * LBAs that the mechanism's wp_lba does not reflect until page flush.
     */
    effective_wp = ctx->api->eswd_get_effective_wp_lba(ctx->ssd, zone->eswd_id);
    if (event->lba + event->nsecs > effective_wp) {
        zns_set_status(event, NVME_ZONE_BOUNDARY_ERROR | NVME_DNR);
        return 0;
    }

    page_size   = (uint64_t)ctx->lbas_per_page * ctx->lbasz;
    total_bytes = (uint64_t)event->nsecs * ctx->lbasz;
    out      = calloc(1, total_bytes);
    page_buf = calloc(1, page_size);
    if (!out || !page_buf) {
        free(out);
        free(page_buf);
        zns_set_status(event, NVME_INTERNAL_DEV_ERROR | NVME_DNR);
        return 0;
    }

    cur_lba   = event->lba;
    remaining = (uint32_t)event->nsecs;
    out_off   = 0;

    while (remaining > 0) {
        uint64_t page_lba = cur_lba - (cur_lba % ctx->lbas_per_page);
        uint32_t page_off_lbas = (uint32_t)(cur_lba - page_lba);
        uint32_t chunk_lbas = ctx->lbas_per_page - page_off_lbas;
        uint64_t copy_bytes;

        if (chunk_lbas > remaining) {
            chunk_lbas = remaining;
        }
        copy_bytes = (uint64_t)chunk_lbas * ctx->lbasz;

        memset(page_buf, 0, page_size);
        lat += ctx->api->read_eswd_page(ctx->ssd, zone->eswd_id, page_lba,
                                        page_buf, (int64_t)event->stime);

        memcpy(out + out_off,
               page_buf + (size_t)page_off_lbas * ctx->lbasz,
               copy_bytes);
        out_off   += copy_bytes;
        cur_lba   += chunk_lbas;
        remaining -= chunk_lbas;
    }

    ctx->api->write_request_data(event->req, out, 0, total_bytes);
    free(out);
    free(page_buf);
    zns_set_status(event, NVME_SUCCESS);
    return lat;
}

static uint16_t zns_open_zone(struct zns_policy_context *ctx, struct zns_policy_zone *zone)
{
    uint16_t status;

    switch (zone->state) {
    case ZNS_POLICY_ZONE_STATE_EMPTY:
        zns_close_one_implicit_zone(ctx);
        status = zns_check_aor(ctx, 1, 1);
        if (status != NVME_SUCCESS) {
            return status;
        }
        zone->state = ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN;
        zns_policy_inc_active(ctx);
        zns_policy_inc_open(ctx);
        return NVME_SUCCESS;
    case ZNS_POLICY_ZONE_STATE_CLOSED:
        zns_close_one_implicit_zone(ctx);
        status = zns_check_aor(ctx, 0, 1);
        if (status != NVME_SUCCESS) {
            return status;
        }
        zone->state = ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN;
        zns_policy_inc_open(ctx);
        return NVME_SUCCESS;
    case ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN:
        zone->state = ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN;
        return NVME_SUCCESS;
    case ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN:
        return NVME_SUCCESS;
    default:
        return NVME_ZONE_INVAL_TRANSITION;
    }
}

static uint16_t zns_close_zone(struct zns_policy_context *ctx, struct zns_policy_zone *zone)
{
    switch (zone->state) {
    case ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN:
    case ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN:
        zone->state = ZNS_POLICY_ZONE_STATE_CLOSED;
        zns_policy_dec_open(ctx);
        return NVME_SUCCESS;
    case ZNS_POLICY_ZONE_STATE_CLOSED:
        return NVME_SUCCESS;
    default:
        return NVME_ZONE_INVAL_TRANSITION;
    }
}

static uint16_t zns_finish_zone(struct zns_policy_context *ctx, struct zns_policy_zone *zone)
{
    switch (zone->state) {
    case ZNS_POLICY_ZONE_STATE_EMPTY:
    case ZNS_POLICY_ZONE_STATE_CLOSED:
    case ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN:
    case ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN:
        break;
    case ZNS_POLICY_ZONE_STATE_FULL:
        return NVME_SUCCESS;
    default:
        return NVME_ZONE_INVAL_TRANSITION;
    }

    if (ctx->api->eswd_advance_wp_to_end(ctx->ssd, zone->eswd_id) != 0) {
        return NVME_INTERNAL_DEV_ERROR | NVME_DNR;
    }

    /* Mirror zns_finish_zone() in zns.c */
    switch (zone->state) {
    case ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN:
    case ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN:
        zns_policy_dec_open(ctx);
        /* fall through */
    case ZNS_POLICY_ZONE_STATE_CLOSED:
        zns_policy_dec_active(ctx);
        /* fall through */
    case ZNS_POLICY_ZONE_STATE_EMPTY:
        if (zone->state == ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN) {
            zone->attr |= ZNS_POLICY_ZA_FINISHED_BY_CTLR;
        }
        zone->state = ZNS_POLICY_ZONE_STATE_FULL;
        break;
    default:
        break;
    }
    return NVME_SUCCESS;
}

static uint16_t zns_reset_zone(struct zns_policy_context *ctx,
                               struct zns_policy_zone *zone,
                               struct NvmeCommandEvent *event,
                               uint64_t *lat_out)
{
    *lat_out = 0;

    /* Match zns_reset_zone() + zns_aio_zone_reset_cb() ordering in zns.c */
    switch (zone->state) {
    case ZNS_POLICY_ZONE_STATE_EMPTY:
        ctx->api->eswd_reset(ctx->ssd, zone->eswd_id);
        zone->attr = 0;
        return NVME_SUCCESS;
    case ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN:
    case ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN:
        zns_policy_dec_open(ctx);
        /* fall through */
    case ZNS_POLICY_ZONE_STATE_CLOSED:
        zns_policy_dec_active(ctx);
        /* fall through */
    case ZNS_POLICY_ZONE_STATE_FULL:
        break;
    default:
        return NVME_ZONE_INVAL_TRANSITION;
    }

    *lat_out = ctx->api->eswd_erase_physical(ctx->ssd, zone->eswd_id, (int64_t)event->stime);
    ctx->api->eswd_reset(ctx->ssd, zone->eswd_id);
    zone->attr = 0;
    zone->state = ZNS_POLICY_ZONE_STATE_EMPTY;
    return NVME_SUCCESS;
}

static bool zns_report_matches(uint32_t filter, const struct zns_policy_zone *zone)
{
    switch (filter) {
    case ZNS_POLICY_ZONE_REPORT_ALL:
        return true;
    case ZNS_POLICY_ZONE_REPORT_EMPTY:
        return zone->state == ZNS_POLICY_ZONE_STATE_EMPTY;
    case ZNS_POLICY_ZONE_REPORT_IMPLICITLY_OPEN:
        return zone->state == ZNS_POLICY_ZONE_STATE_IMPLICITLY_OPEN;
    case ZNS_POLICY_ZONE_REPORT_EXPLICITLY_OPEN:
        return zone->state == ZNS_POLICY_ZONE_STATE_EXPLICITLY_OPEN;
    case ZNS_POLICY_ZONE_REPORT_CLOSED:
        return zone->state == ZNS_POLICY_ZONE_STATE_CLOSED;
    case ZNS_POLICY_ZONE_REPORT_FULL:
        return zone->state == ZNS_POLICY_ZONE_STATE_FULL;
    case ZNS_POLICY_ZONE_REPORT_READ_ONLY:
        return zone->state == ZNS_POLICY_ZONE_STATE_READ_ONLY;
    case ZNS_POLICY_ZONE_REPORT_OFFLINE:
        return zone->state == ZNS_POLICY_ZONE_STATE_OFFLINE;
    default:
        return false;
    }
}

static uint64_t zns_zone_mgmt_send_callback(struct ssd *ssd,
                                            struct NvmeCommandEvent *event,
                                            struct FtlPolicyAPI *api,
                                            void *context)
{
    struct zns_policy_context *ctx = (struct zns_policy_context *)context;
    ZnsPolicyNvmeCmd *cmd = event->cmd;
    uint64_t slba = ((uint64_t)le32_to_cpu(cmd->cdw11) << 32) | le32_to_cpu(cmd->cdw10);
    uint32_t action = le32_to_cpu(cmd->cdw13) & 0xff;
    bool all = (le32_to_cpu(cmd->cdw13) & 0x100) != 0;
    uint64_t lat = 0;
    uint32_t i;

    (void)ssd;
    (void)api;

    if (!all) {
        if (zns_check_bounds(ctx, slba, 1) != NVME_SUCCESS || (slba % ctx->zone_size_lbas) != 0) {
            zns_set_status(event, NVME_INVALID_FIELD | NVME_DNR);
            return 0;
        }
    }

    for (i = 0; i < ctx->zone_count; i++) {
        struct zns_policy_zone *zone = &ctx->zones[i];
        uint16_t status = NVME_SUCCESS;
        uint64_t zone_lat = 0;

        if (!all && zone->zslba != slba) {
            continue;
        }

        switch (action) {
        case ZNS_POLICY_ZONE_ACTION_OPEN:
            status = zns_open_zone(ctx, zone);
            break;
        case ZNS_POLICY_ZONE_ACTION_CLOSE:
            status = zns_close_zone(ctx, zone);
            break;
        case ZNS_POLICY_ZONE_ACTION_FINISH:
            status = zns_finish_zone(ctx, zone);
            break;
        case ZNS_POLICY_ZONE_ACTION_RESET:
            status = zns_reset_zone(ctx, zone, event, &zone_lat);
            break;
        default:
            zns_set_status(event, NVME_INVALID_FIELD | NVME_DNR);
            return 0;
        }

        if (status != NVME_SUCCESS) {
            zns_set_status(event, status | NVME_DNR);
            return lat;
        }
        if (zone_lat > lat) {
            lat = zone_lat;
        }
        if (!all) {
            break;
        }
    }

    zns_set_status(event, NVME_SUCCESS);
    return lat;
}

static uint64_t zns_zone_mgmt_recv_callback(struct ssd *ssd,
                                            struct NvmeCommandEvent *event,
                                            struct FtlPolicyAPI *api,
                                            void *context)
{
    struct zns_policy_context *ctx = (struct zns_policy_context *)context;
    ZnsPolicyNvmeCmd *cmd = event->cmd;
    uint64_t slba = ((uint64_t)le32_to_cpu(cmd->cdw11) << 32) | le32_to_cpu(cmd->cdw10);
    uint32_t data_size = (le32_to_cpu(cmd->cdw12) + 1) << 2;
    uint32_t dw13 = le32_to_cpu(cmd->cdw13);
    uint32_t action = dw13 & 0xff;
    uint32_t filter = (dw13 >> 8) & 0xff;
    uint32_t partial = (dw13 >> 16) & 0x1;
    uint32_t zone_entry_size = sizeof(ZnsPolicyZoneDescr);
    uint32_t max_zones;
    uint32_t zone_id;
    uint64_t total_matches = 0;
    uint8_t *buf;
    uint8_t *p;
    ZnsPolicyZoneReportHeader *header;

    (void)ssd;

    if ((action != ZNS_POLICY_ZONE_REPORT &&
         action != ZNS_POLICY_ZONE_REPORT_EXTENDED) ||
        filter > ZNS_POLICY_ZONE_REPORT_OFFLINE ||
        data_size < sizeof(*header) ||
        slba >= zns_total_lbas(ctx) ||
        (slba % ctx->zone_size_lbas) != 0) {
        zns_set_status(event, NVME_INVALID_FIELD | NVME_DNR);
        return 0;
    }

    buf = calloc(1, data_size);
    if (!buf) {
        zns_set_status(event, NVME_INTERNAL_DEV_ERROR | NVME_DNR);
        return 0;
    }

    zone_id = (uint32_t)(slba / ctx->zone_size_lbas);
    max_zones = (data_size - sizeof(*header)) / zone_entry_size;
    for (uint32_t i = zone_id; i < ctx->zone_count; i++) {
        if (partial && total_matches >= max_zones) {
            break;
        }
        if (zns_report_matches(filter, &ctx->zones[i])) {
            total_matches++;
        }
    }

    header = (ZnsPolicyZoneReportHeader *)buf;
    header->nr_zones = cpu_to_le64(total_matches);
    p = buf + sizeof(*header);

    for (uint32_t i = zone_id; i < ctx->zone_count && max_zones > 0; i++) {
        ZnsPolicyZoneDescr *desc;
        struct zns_policy_zone *zone = &ctx->zones[i];

        if (!zns_report_matches(filter, zone)) {
            continue;
        }

        desc = (ZnsPolicyZoneDescr *)p;
        desc->zt = ZNS_POLICY_ZONE_TYPE_SEQ_WRITE;
        desc->zs = zone->state << 4;
        desc->za = zone->attr;
        desc->zcap = cpu_to_le64(zone->zcap);
        desc->zslba = cpu_to_le64(zone->zslba);
        desc->wp = cpu_to_le64(zns_zone_wp_valid(zone) ? zns_zone_wp_lba(ctx, zone) : ~0ULL);
        p += sizeof(*desc);
        max_zones--;
    }

    zns_set_status(event, api->write_cmd_buffer(event, buf, data_size));
    free(buf);
    return 0;
}

int init_policy(struct ssd *ssd, struct FtlPolicyAPI *api)
{
    struct zns_policy_context *ctx;
    struct eswd_config config;
    struct NamespacePersonalityConfig personality = {0};
    ZnsPolicyIdNsZoned id_ns_zoned = {0};
    ZnsPolicyIdCtrlZoned id_ctrl_zoned = {0};
    uint32_t i;

    if (!ssd || !api) {
        return -1;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        return -1;
    }

    ctx->ssd = ssd;
    ctx->api = api;
    ctx->geom = api->get_bbm_geom(ssd);
    if (!ctx->geom) {
        free(ctx);
        return -1;
    }

    config.striping_level = ESWD_STRIPE_CHANNEL;
    config.blocks_per_eswd = ctx->geom->tt_luns;
    api->set_eswd_config(ssd, &config);
    if (api->finalize_ftl_init(ssd) != 0) {
        free(ctx);
        return -1;
    }

    ctx->layout = api->get_eswd_layout(ssd);
    if (!ctx->layout) {
        free(ctx);
        return -1;
    }

    ctx->zone_count = ctx->layout->tt_eswds;
    ctx->lbas_per_page = ctx->geom->secs_per_pg;
    ctx->lbasz = ctx->geom->secsz;
    ctx->zone_size_lbas = (uint64_t)ctx->layout->pgs_per_eswd * ctx->lbas_per_page;
    ctx->zone_capacity_lbas = ctx->zone_size_lbas;
    ctx->cross_zone_read = false;

    if (ctx->zone_count == 0 || ctx->zone_size_lbas == 0) {
        free(ctx);
        return -1;
    }

    id_ns_zoned.ozcs = ctx->cross_zone_read ? cpu_to_le16(0x01) : cpu_to_le16(0x00);
    id_ns_zoned.mar = cpu_to_le32(ctx->max_active_zones ? ctx->max_active_zones - 1 : 0xffffffffu);
    id_ns_zoned.mor = cpu_to_le32(ctx->max_open_zones ? ctx->max_open_zones - 1 : 0xffffffffu);
    for (i = 0; i < 16; i++) {
        id_ns_zoned.lbafe[i].zsze = cpu_to_le64(ctx->zone_size_lbas);
        id_ns_zoned.lbafe[i].zdes = 0;
    }

    personality.csi = NVME_CSI_ZONED;
    personality.nsze = (uint64_t)ctx->zone_count * ctx->zone_size_lbas;
    personality.ncap = personality.nsze;
    personality.nuse = personality.ncap;
    personality.noiob = 1;
    personality.ns_csi_data = &id_ns_zoned;
    personality.ns_csi_data_len = sizeof(id_ns_zoned);
    personality.ctrl_csi_data = &id_ctrl_zoned;
    personality.ctrl_csi_data_len = sizeof(id_ctrl_zoned);
    if (api->configure_namespace_personality(ssd, &personality) != 0) {
        free(ctx);
        return -1;
    }

    ctx->zones = calloc(ctx->zone_count, sizeof(*ctx->zones));
    if (!ctx->zones) {
        free(ctx);
        return -1;
    }

    for (i = 0; i < ctx->zone_count; i++) {
        ctx->zones[i].eswd_id = i;
        ctx->zones[i].state = ZNS_POLICY_ZONE_STATE_EMPTY;
        ctx->zones[i].zslba = (uint64_t)i * ctx->zone_size_lbas;
        ctx->zones[i].zcap = ctx->zone_capacity_lbas;
    }

    if (api->register_nvme_hook(ssd, NVME_CMD_READ, NULL, zns_read_callback, ctx) < 0 ||
        api->register_nvme_hook(ssd, NVME_CMD_WRITE, NULL, zns_write_callback, ctx) < 0 ||
        api->register_nvme_hook(ssd, NVME_CMD_ZONE_APPEND, NULL, zns_append_callback, ctx) < 0 ||
        api->register_nvme_hook(ssd, NVME_CMD_ZONE_MGMT_SEND, NULL,
                                zns_zone_mgmt_send_callback, ctx) < 0 ||
        api->register_nvme_hook(ssd, NVME_CMD_ZONE_MGMT_RECV, NULL,
                                zns_zone_mgmt_recv_callback, ctx) < 0) {
        free(ctx->zones);
        free(ctx);
        return -1;
    }

    return 0;
}

static uint64_t zns_write_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                   struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    return zns_do_write((struct zns_policy_context *)context, event, false);
}

static uint64_t zns_append_callback(struct ssd *ssd, struct NvmeCommandEvent *event,
                                    struct FtlPolicyAPI *api, void *context)
{
    (void)ssd;
    (void)api;
    return zns_do_write((struct zns_policy_context *)context, event, true);
}
