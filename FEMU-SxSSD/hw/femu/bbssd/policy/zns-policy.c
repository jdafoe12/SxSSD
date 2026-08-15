#include "zns-policy.h"

#define ZNS_MAX_ZONES 256U

#define ZNS_PAIR_READ 1U
#define ZNS_PAIR_WRITE 2U
#define ZNS_PAIR_APPEND 3U
#define ZNS_PAIR_MGMT_SEND 4U
#define ZNS_PAIR_MGMT_RECEIVE 5U

#define ZNS_CMD_WRITE 0x01U
#define ZNS_CMD_READ 0x02U
#define ZNS_CMD_MGMT_SEND 0x79U
#define ZNS_CMD_MGMT_RECEIVE 0x7aU
#define ZNS_CMD_APPEND 0x7dU
#define ZNS_CSI_ZONED 0x02U

#define ZNS_SUCCESS 0x0000U
#define ZNS_INVALID_FIELD 0x0002U
#define ZNS_INTERNAL_ERROR 0x0006U
#define ZNS_LBA_RANGE 0x0080U
#define ZNS_BOUNDARY_ERROR 0x01b8U
#define ZNS_ZONE_FULL 0x01b9U
#define ZNS_ZONE_READ_ONLY 0x01baU
#define ZNS_ZONE_OFFLINE 0x01bbU
#define ZNS_INVALID_WRITE 0x01bcU
#define ZNS_TOO_MANY_ACTIVE 0x01bdU
#define ZNS_TOO_MANY_OPEN 0x01beU
#define ZNS_INVALID_TRANSITION 0x01bfU
#define ZNS_DNR 0x4000U

static struct zns_policy_state zns_state;
static struct zns_zone_state zns_zones[ZNS_MAX_ZONES];
/* Raw flash accepts full pages, so each zone retains one incomplete page. */
static sxs_u8 zns_page_buffers[ZNS_MAX_ZONES][SXS_WASM_MAX_PAGE_BYTES];
static sxs_u32 zns_buffered_lbas[ZNS_MAX_ZONES];
/* NVMe PRP lists describe the complete transfer, so emit reports in one call. */
static sxs_u8 zns_report_buffer[
    sizeof(struct zns_report_header) +
    ZNS_MAX_ZONES * sizeof(struct zns_report_descriptor)];

static void zns_zero(sxs_u8 *data, sxs_u32 length)
{
    for (sxs_u32 i = 0; i < length; i++) {
        data[i] = 0;
    }
}

static void zns_copy(sxs_u8 *destination, const sxs_u8 *source,
                     sxs_u32 length)
{
    for (sxs_u32 i = 0; i < length; i++) {
        destination[i] = source[i];
    }
}

static struct zns_policy_state zns_load_state(void)
{
    return zns_state;
}

static void zns_store_state(const struct zns_policy_state *state)
{
    zns_state = *state;
}

static sxs_s64 zns_load_zone(sxs_u32 zone_id, struct zns_zone_state *zone)
{
    if (!zone || zone_id >= zns_state.zone_count || zone_id >= ZNS_MAX_ZONES) {
        return -SXS_WASM_EINVAL;
    }
    *zone = zns_zones[zone_id];
    return 0;
}

static sxs_s64 zns_store_zone(sxs_u32 zone_id,
                              const struct zns_zone_state *zone)
{
    if (!zone || zone_id >= zns_state.zone_count || zone_id >= ZNS_MAX_ZONES) {
        return -SXS_WASM_EINVAL;
    }
    zns_zones[zone_id] = *zone;
    return 0;
}

static sxs_u16 zns_set_status(sxs_u16 status)
{
    sxs_completion_status_set(status);
    return status;
}

static sxs_u64 zns_total_lbas(const struct zns_policy_state *state)
{
    return (sxs_u64)state->zone_count * state->zone_size_lbas;
}

static sxs_u16 zns_check_bounds(const struct zns_policy_state *state,
                                sxs_u64 start_lba, sxs_u64 lba_count)
{
    if (lba_count == 0) {
        return ZNS_SUCCESS;
    }
    if (start_lba > ~0ULL - lba_count ||
        start_lba + lba_count > zns_total_lbas(state)) {
        return ZNS_LBA_RANGE | ZNS_DNR;
    }
    return ZNS_SUCCESS;
}

static sxs_u16 zns_read_state_status(sxs_u8 state)
{
    switch (state) {
    case ZNS_STATE_EMPTY:
    case ZNS_STATE_IMPLICITLY_OPEN:
    case ZNS_STATE_EXPLICITLY_OPEN:
    case ZNS_STATE_CLOSED:
    case ZNS_STATE_READ_ONLY:
    case ZNS_STATE_FULL:
        return ZNS_SUCCESS;
    case ZNS_STATE_OFFLINE:
        return ZNS_ZONE_OFFLINE;
    default:
        return ZNS_INVALID_FIELD;
    }
}

static sxs_u16 zns_write_state_status(sxs_u8 state)
{
    switch (state) {
    case ZNS_STATE_EMPTY:
    case ZNS_STATE_IMPLICITLY_OPEN:
    case ZNS_STATE_EXPLICITLY_OPEN:
    case ZNS_STATE_CLOSED:
        return ZNS_SUCCESS;
    case ZNS_STATE_FULL:
        return ZNS_ZONE_FULL;
    case ZNS_STATE_OFFLINE:
        return ZNS_ZONE_OFFLINE;
    case ZNS_STATE_READ_ONLY:
        return ZNS_ZONE_READ_ONLY;
    default:
        return ZNS_INVALID_FIELD;
    }
}

static sxs_u16 zns_check_limits(const struct zns_policy_state *state,
                                sxs_u32 add_active, sxs_u32 add_open)
{
    if (state->max_active_zones != 0 &&
        state->active_zones + add_active > state->max_active_zones) {
        return ZNS_TOO_MANY_ACTIVE | ZNS_DNR;
    }
    if (state->max_open_zones != 0 &&
        state->open_zones + add_open > state->max_open_zones) {
        return ZNS_TOO_MANY_OPEN | ZNS_DNR;
    }
    return ZNS_SUCCESS;
}

static sxs_s64 zns_close_one_implicit(struct zns_policy_state *state)
{
    struct zns_zone_state candidate;

    if (state->max_open_zones == 0 ||
        state->open_zones < state->max_open_zones) {
        return 0;
    }
    for (sxs_u32 id = 0; id < state->zone_count; id++) {
        if (zns_load_zone(id, &candidate) == 0 &&
            candidate.state == ZNS_STATE_IMPLICITLY_OPEN) {
            candidate.state = ZNS_STATE_CLOSED;
            if (zns_store_zone(id, &candidate) != 0) {
                return -SXS_WASM_EIO;
            }
            if (state->open_zones != 0) {
                state->open_zones--;
            }
            return 0;
        }
    }
    return 0;
}

static sxs_u16 zns_ensure_implicit_open(struct zns_policy_state *state,
                                        struct zns_zone_state *zone)
{
    sxs_u16 status;

    switch (zone->state) {
    case ZNS_STATE_EMPTY:
        if (zns_close_one_implicit(state) != 0) {
            return ZNS_INTERNAL_ERROR | ZNS_DNR;
        }
        status = zns_check_limits(state, 1, 1);
        if (status != ZNS_SUCCESS) {
            return status;
        }
        zone->state = ZNS_STATE_IMPLICITLY_OPEN;
        if (state->max_active_zones != 0) {
            state->active_zones++;
        }
        if (state->max_open_zones != 0) {
            state->open_zones++;
        }
        return ZNS_SUCCESS;
    case ZNS_STATE_CLOSED:
        if (zns_close_one_implicit(state) != 0) {
            return ZNS_INTERNAL_ERROR | ZNS_DNR;
        }
        status = zns_check_limits(state, 0, 1);
        if (status != ZNS_SUCCESS) {
            return status;
        }
        zone->state = ZNS_STATE_IMPLICITLY_OPEN;
        if (state->max_open_zones != 0) {
            state->open_zones++;
        }
        return ZNS_SUCCESS;
    case ZNS_STATE_IMPLICITLY_OPEN:
    case ZNS_STATE_EXPLICITLY_OPEN:
        return ZNS_SUCCESS;
    default:
        return zns_write_state_status(zone->state);
    }
}

static void zns_remove_open_active(struct zns_policy_state *state,
                                   sxs_u8 old_state)
{
    if ((old_state == ZNS_STATE_IMPLICITLY_OPEN ||
         old_state == ZNS_STATE_EXPLICITLY_OPEN) &&
        state->max_open_zones != 0 && state->open_zones != 0) {
        state->open_zones--;
    }
    if ((old_state == ZNS_STATE_IMPLICITLY_OPEN ||
         old_state == ZNS_STATE_EXPLICITLY_OPEN ||
         old_state == ZNS_STATE_CLOSED) &&
        state->max_active_zones != 0 && state->active_zones != 0) {
        state->active_zones--;
    }
}

static sxs_s64 zns_append_page(const struct zns_policy_state *state,
                               const struct zns_zone_state *zone,
                               const sxs_u8 *page, sxs_u64 *latency)
{
    struct sxs_page_append_request request = {
        .eswd_id = zone->eswd_id,
    };
    struct sxs_page_result result;
    sxs_u32 page_size = state->sectors_per_page * state->sector_size;

    if (sxs_page_append(&request, page, page_size, 0, 0, &result) != 0 ||
        result.status != 0) {
        return -SXS_WASM_EIO;
    }
    if (result.latency_ns > *latency) {
        *latency = result.latency_ns;
    }
    return 0;
}

static sxs_s64 zns_write_lbas(const struct zns_policy_state *state,
                              sxs_u32 zone_id,
                              struct zns_zone_state *zone,
                              sxs_u32 lba_count, sxs_u64 *latency)
{
    sxs_u8 *page = zns_page_buffers[zone_id];
    sxs_u32 buffered = zns_buffered_lbas[zone_id];
    sxs_u32 remaining = lba_count;
    sxs_u64 request_offset = 0;
    sxs_u32 page_size = state->sectors_per_page * state->sector_size;

    while (remaining != 0) {
        sxs_u32 page_offset =
            (zone->write_pointer - zone->start_lba) % state->sectors_per_page;
        sxs_u32 chunk = state->sectors_per_page - page_offset;
        sxs_u32 bytes;

        if (buffered != page_offset) {
            return -SXS_WASM_EIO;
        }
        if (chunk > remaining) {
            chunk = remaining;
        }
        if (buffered == 0) {
            zns_zero(page, page_size);
        }
        bytes = chunk * state->sector_size;
        if (sxs_request_read(request_offset,
                             page + page_offset * state->sector_size,
                             bytes) != 0) {
            return -SXS_WASM_EIO;
        }
        buffered += chunk;
        zone->write_pointer += chunk;
        zone->data_end_lba = zone->write_pointer;
        request_offset += bytes;
        remaining -= chunk;

        if (buffered == state->sectors_per_page) {
            if (zns_append_page(state, zone, page, latency) != 0) {
                return -SXS_WASM_EIO;
            }
            buffered = 0;
        }
        zns_buffered_lbas[zone_id] = buffered;
    }
    return 0;
}

static void zns_finish_if_full(struct zns_policy_state *state,
                               struct zns_zone_state *zone)
{
    if (zone->write_pointer != zone->start_lba + zone->capacity) {
        return;
    }

    if (zone->state == ZNS_STATE_EMPTY ||
        zone->state == ZNS_STATE_CLOSED ||
        zone->state == ZNS_STATE_IMPLICITLY_OPEN ||
        zone->state == ZNS_STATE_EXPLICITLY_OPEN) {
        sxs_u8 old_state = zone->state;

        zns_remove_open_active(state, old_state);
        if (old_state == ZNS_STATE_EXPLICITLY_OPEN) {
            zone->attributes |= ZNS_ZA_FINISHED_BY_CONTROLLER;
        }
        zone->state = ZNS_STATE_FULL;
    }
}

static sxs_u64 zns_write(struct sxs_policy_context *context, sxs_u32 append)
{
    struct zns_policy_state state;
    struct zns_zone_state zone;
    sxs_u64 command_lba = append ?
        ((sxs_u64)context->event.nvme.cdw11 << 32) |
             context->event.nvme.cdw10 : context->event.nvme.lba;
    sxs_u64 lba_count = append ?
        (context->event.nvme.cdw12 & 0xffffU) + 1U :
        context->event.nvme.nsecs;
    sxs_u64 write_lba;
    sxs_u64 latency = 0;
    sxs_u32 zone_id;
    sxs_u16 status;

    state = zns_load_state();
    if (lba_count > 0xffffffffULL) {
        zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
        return 0;
    }
    status = zns_check_bounds(&state, command_lba, lba_count);
    if (status != ZNS_SUCCESS) {
        zns_set_status(status);
        return 0;
    }
    zone_id = command_lba / state.zone_size_lbas;
    if (zone_id >= state.zone_count ||
        zns_load_zone(zone_id, &zone) != 0) {
        zns_set_status(ZNS_LBA_RANGE | ZNS_DNR);
        return 0;
    }
    status = zns_write_state_status(zone.state);
    if (status != ZNS_SUCCESS) {
        zns_set_status(status | ZNS_DNR);
        return 0;
    }
    write_lba = zone.write_pointer;
    if ((append && command_lba != zone.start_lba)) {
        zns_set_status(ZNS_INVALID_FIELD | ZNS_DNR);
        return 0;
    }
    if (!append && command_lba != write_lba) {
        zns_set_status(ZNS_INVALID_WRITE | ZNS_DNR);
        return 0;
    }
    if (write_lba > ~0ULL - lba_count ||
        write_lba + lba_count > zone.start_lba + zone.capacity) {
        zns_set_status(ZNS_BOUNDARY_ERROR | ZNS_DNR);
        return 0;
    }
    status = zns_ensure_implicit_open(&state, &zone);
    if (status != ZNS_SUCCESS) {
        zns_set_status(status);
        return 0;
    }

    if (zns_write_lbas(&state, zone_id, &zone, (sxs_u32)lba_count,
                       &latency) != 0) {
        zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
        return 0;
    }
    if (append) {
        sxs_completion_result_set(write_lba);
    }
    zns_finish_if_full(&state, &zone);
    if (zns_store_zone(zone_id, &zone) != 0) {
        zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
        return 0;
    }
    zns_store_state(&state);
    zns_set_status(ZNS_SUCCESS);
    return latency;
}

static sxs_u64 zns_read(struct sxs_policy_context *context)
{
    struct zns_policy_state state;
    struct zns_zone_state zone;
    sxs_u8 page[SXS_WASM_MAX_PAGE_BYTES];
    sxs_u64 end_lba;
    sxs_u64 current_lba;
    sxs_u64 output_offset = 0;
    sxs_u64 maximum_latency = 0;
    sxs_u32 zone_id;
    sxs_u16 status;

    state = zns_load_state();
    status = zns_check_bounds(&state, context->event.nvme.lba,
                              context->event.nvme.nsecs);
    if (status != ZNS_SUCCESS) {
        zns_set_status(status);
        return 0;
    }
    zone_id = context->event.nvme.lba / state.zone_size_lbas;
    if (zone_id >= state.zone_count ||
        zns_load_zone(zone_id, &zone) != 0) {
        zns_set_status(ZNS_LBA_RANGE | ZNS_DNR);
        return 0;
    }
    status = zns_read_state_status(zone.state);
    end_lba = context->event.nvme.lba + context->event.nvme.nsecs;
    if (status != ZNS_SUCCESS) {
        zns_set_status(status | ZNS_DNR);
        return 0;
    }
    if (!state.cross_zone_read &&
        end_lba > zone.start_lba + state.zone_size_lbas) {
        zns_set_status(ZNS_BOUNDARY_ERROR | ZNS_DNR);
        return 0;
    }

    current_lba = context->event.nvme.lba;
    while (current_lba < end_lba) {
        sxs_u64 page_lba = current_lba -
                           current_lba % state.sectors_per_page;
        sxs_u32 page_offset = current_lba - page_lba;
        sxs_u32 sectors = state.sectors_per_page - page_offset;
        sxs_u64 bytes;

        if (sectors > end_lba - current_lba) {
            sectors = end_lba - current_lba;
        }
        sxs_u32 page_size = state.sectors_per_page * state.sector_size;
        sxs_u32 buffered = zns_buffered_lbas[zone_id];
        sxs_u64 buffered_page_lba = zone.write_pointer - buffered;
        sxs_u64 committed_end = zone.data_end_lba;
        sxs_u64 committed_page_end = committed_end;
        sxs_u64 latency = 0;

        if (committed_page_end % state.sectors_per_page != 0) {
            committed_page_end += state.sectors_per_page -
                                  committed_page_end % state.sectors_per_page;
        }
        zns_zero(page, page_size);
        if (buffered != 0 && page_lba == buffered_page_lba) {
            zns_copy(page, zns_page_buffers[zone_id], page_size);
        } else if (page_lba < committed_page_end) {
            struct sxs_page_read_request request = {
                .ppa = sxs_eswd_to_ppa(
                    zone.eswd_id,
                    (page_lba - zone.start_lba) / state.sectors_per_page),
                .page_offset = 0,
                .length = page_size,
            };
            struct sxs_page_result result;

            if ((sxs_s64)request.ppa < 0 ||
                sxs_page_read(&request, page, page_size, 0, 0, &result) != 0 ||
                result.status != 0) {
                zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
                return 0;
            }
            latency = result.latency_ns;
        }
        bytes = (sxs_u64)sectors * state.sector_size;
        if (sxs_request_write(output_offset,
                              page + page_offset * state.sector_size,
                              bytes) != 0) {
            zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
            return 0;
        }
        if (latency > maximum_latency) {
            maximum_latency = latency;
        }
        output_offset += bytes;
        current_lba += sectors;
    }
    zns_set_status(ZNS_SUCCESS);
    return maximum_latency;
}

static sxs_u16 zns_open(struct zns_policy_state *state,
                        struct zns_zone_state *zone)
{
    sxs_u16 status;

    switch (zone->state) {
    case ZNS_STATE_EMPTY:
        if (zns_close_one_implicit(state) != 0) {
            return ZNS_INTERNAL_ERROR | ZNS_DNR;
        }
        status = zns_check_limits(state, 1, 1);
        if (status != ZNS_SUCCESS) {
            return status;
        }
        zone->state = ZNS_STATE_EXPLICITLY_OPEN;
        if (state->max_active_zones != 0) {
            state->active_zones++;
        }
        if (state->max_open_zones != 0) {
            state->open_zones++;
        }
        return ZNS_SUCCESS;
    case ZNS_STATE_CLOSED:
        if (zns_close_one_implicit(state) != 0) {
            return ZNS_INTERNAL_ERROR | ZNS_DNR;
        }
        status = zns_check_limits(state, 0, 1);
        if (status != ZNS_SUCCESS) {
            return status;
        }
        zone->state = ZNS_STATE_EXPLICITLY_OPEN;
        if (state->max_open_zones != 0) {
            state->open_zones++;
        }
        return ZNS_SUCCESS;
    case ZNS_STATE_IMPLICITLY_OPEN:
        zone->state = ZNS_STATE_EXPLICITLY_OPEN;
        return ZNS_SUCCESS;
    case ZNS_STATE_EXPLICITLY_OPEN:
        return ZNS_SUCCESS;
    default:
        return ZNS_INVALID_TRANSITION;
    }
}

static sxs_u16 zns_close(struct zns_policy_state *state,
                         struct zns_zone_state *zone)
{
    switch (zone->state) {
    case ZNS_STATE_IMPLICITLY_OPEN:
    case ZNS_STATE_EXPLICITLY_OPEN:
        zone->state = ZNS_STATE_CLOSED;
        if (state->max_open_zones != 0 && state->open_zones != 0) {
            state->open_zones--;
        }
        return ZNS_SUCCESS;
    case ZNS_STATE_CLOSED:
        return ZNS_SUCCESS;
    default:
        return ZNS_INVALID_TRANSITION;
    }
}

static sxs_u16 zns_finish(struct zns_policy_state *state, sxs_u32 zone_id,
                          struct zns_zone_state *zone, sxs_u64 *latency)
{
    sxs_u8 old_state = zone->state;

    if (old_state == ZNS_STATE_FULL) {
        return ZNS_SUCCESS;
    }
    if (old_state != ZNS_STATE_EMPTY && old_state != ZNS_STATE_CLOSED &&
        old_state != ZNS_STATE_IMPLICITLY_OPEN &&
        old_state != ZNS_STATE_EXPLICITLY_OPEN) {
        return ZNS_INVALID_TRANSITION;
    }
    *latency = 0;
    if (zns_buffered_lbas[zone_id] != 0 &&
        zns_append_page(state, zone, zns_page_buffers[zone_id], latency) != 0) {
        return ZNS_INTERNAL_ERROR | ZNS_DNR;
    }
    zns_buffered_lbas[zone_id] = 0;
    if (sxs_eswd_advance_wp(zone->eswd_id) != 0) {
        return ZNS_INTERNAL_ERROR | ZNS_DNR;
    }
    zone->write_pointer = zone->start_lba + zone->capacity;
    zns_remove_open_active(state, old_state);
    if (old_state == ZNS_STATE_EXPLICITLY_OPEN) {
        zone->attributes |= ZNS_ZA_FINISHED_BY_CONTROLLER;
    }
    zone->state = ZNS_STATE_FULL;
    return ZNS_SUCCESS;
}

static sxs_u16 zns_reset(struct zns_policy_state *state, sxs_u32 zone_id,
                         struct zns_zone_state *zone, sxs_u64 *latency)
{
    sxs_u8 old_state = zone->state;

    *latency = 0;
    if (old_state == ZNS_STATE_EMPTY) {
        if (sxs_eswd_reset(zone->eswd_id) != 0) {
            return ZNS_INTERNAL_ERROR | ZNS_DNR;
        }
        zone->attributes = 0;
        zone->write_pointer = zone->start_lba;
        zone->data_end_lba = zone->start_lba;
        zns_buffered_lbas[zone_id] = 0;
        return ZNS_SUCCESS;
    }
    if (old_state != ZNS_STATE_IMPLICITLY_OPEN &&
        old_state != ZNS_STATE_EXPLICITLY_OPEN &&
        old_state != ZNS_STATE_CLOSED && old_state != ZNS_STATE_FULL) {
        return ZNS_INVALID_TRANSITION;
    }
    zns_remove_open_active(state, old_state);
    *latency = sxs_eswd_erase(zone->eswd_id);
    if ((sxs_s64)*latency < 0 ||
        sxs_eswd_reset(zone->eswd_id) != 0) {
        return ZNS_INTERNAL_ERROR | ZNS_DNR;
    }
    zone->attributes = 0;
    zone->state = ZNS_STATE_EMPTY;
    zone->write_pointer = zone->start_lba;
    zone->data_end_lba = zone->start_lba;
    zns_buffered_lbas[zone_id] = 0;
    return ZNS_SUCCESS;
}

static sxs_u64 zns_management_send(struct sxs_policy_context *context)
{
    struct zns_policy_state state;
    sxs_u64 start_lba = ((sxs_u64)context->event.nvme.cdw11 << 32) |
                        context->event.nvme.cdw10;
    sxs_u32 action = context->event.nvme.cdw13 & 0xffU;
    sxs_u32 all = (context->event.nvme.cdw13 & 0x100U) != 0;
    sxs_u64 maximum_latency = 0;
    sxs_u32 selected_zone = 0;

    state = zns_load_state();
    if (!all) {
        if (zns_check_bounds(&state, start_lba, 1) != ZNS_SUCCESS ||
            start_lba % state.zone_size_lbas != 0) {
            zns_set_status(ZNS_INVALID_FIELD | ZNS_DNR);
            return 0;
        }
        selected_zone = start_lba / state.zone_size_lbas;
    }
    for (sxs_u32 id = 0; id < state.zone_count; id++) {
        struct zns_zone_state zone;
        sxs_u64 latency = 0;
        sxs_u16 status;

        if (!all && id != selected_zone) {
            continue;
        }
        if (zns_load_zone(id, &zone) != 0) {
            zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
            return maximum_latency;
        }
        switch (action) {
        case ZNS_ACTION_OPEN:
            status = zns_open(&state, &zone);
            break;
        case ZNS_ACTION_CLOSE:
            status = zns_close(&state, &zone);
            break;
        case ZNS_ACTION_FINISH:
            status = zns_finish(&state, id, &zone, &latency);
            break;
        case ZNS_ACTION_RESET:
            status = zns_reset(&state, id, &zone, &latency);
            break;
        default:
            zns_set_status(ZNS_INVALID_FIELD | ZNS_DNR);
            return maximum_latency;
        }
        if (status != ZNS_SUCCESS) {
            zns_set_status(status | ZNS_DNR);
            return maximum_latency;
        }
        if (zns_store_zone(id, &zone) != 0) {
            zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
            return maximum_latency;
        }
        if (latency > maximum_latency) {
            maximum_latency = latency;
        }
        if (!all) {
            break;
        }
    }
    zns_store_state(&state);
    zns_set_status(ZNS_SUCCESS);
    return maximum_latency;
}

static sxs_u32 zns_report_match(sxs_u32 filter, sxs_u8 state)
{
    switch (filter) {
    case ZNS_REPORT_ALL: return 1;
    case ZNS_REPORT_EMPTY: return state == ZNS_STATE_EMPTY;
    case ZNS_REPORT_IMPLICITLY_OPEN:
        return state == ZNS_STATE_IMPLICITLY_OPEN;
    case ZNS_REPORT_EXPLICITLY_OPEN:
        return state == ZNS_STATE_EXPLICITLY_OPEN;
    case ZNS_REPORT_CLOSED: return state == ZNS_STATE_CLOSED;
    case ZNS_REPORT_FULL: return state == ZNS_STATE_FULL;
    case ZNS_REPORT_READ_ONLY: return state == ZNS_STATE_READ_ONLY;
    case ZNS_REPORT_OFFLINE: return state == ZNS_STATE_OFFLINE;
    default: return 0;
    }
}

static sxs_u64 zns_management_receive(struct sxs_policy_context *context)
{
    struct zns_policy_state state;
    struct zns_report_header *header;
    struct zns_report_descriptor descriptor;
    sxs_u64 start_lba = ((sxs_u64)context->event.nvme.cdw11 << 32) |
                        context->event.nvme.cdw10;
    sxs_u64 data_size = ((sxs_u64)context->event.nvme.cdw12 + 1) << 2;
    sxs_u32 action = context->event.nvme.cdw13 & 0xffU;
    sxs_u32 filter = (context->event.nvme.cdw13 >> 8) & 0xffU;
    sxs_u32 partial = (context->event.nvme.cdw13 >> 16) & 1U;
    sxs_u64 matches = 0;
    sxs_u64 emitted = 0;
    sxs_u32 first_zone;
    sxs_u32 transfer_size;
    sxs_u64 maximum_descriptors;

    state = zns_load_state();
    if ((action != ZNS_REPORT && action != ZNS_REPORT_EXTENDED) ||
        filter > ZNS_REPORT_OFFLINE ||
        data_size < sizeof(struct zns_report_header) ||
        start_lba >= zns_total_lbas(&state) ||
        start_lba % state.zone_size_lbas != 0 ||
        data_size > SXS_WASM_MAX_ARTIFACT_BYTES) {
        zns_set_status(ZNS_INVALID_FIELD | ZNS_DNR);
        return 0;
    }
    first_zone = start_lba / state.zone_size_lbas;
    transfer_size = data_size < sizeof(zns_report_buffer)
                        ? (sxs_u32)data_size
                        : sizeof(zns_report_buffer);
    maximum_descriptors =
        (transfer_size - sizeof(struct zns_report_header)) /
                          sizeof(descriptor);
    for (sxs_u32 id = first_zone; id < state.zone_count; id++) {
        struct zns_zone_state zone;

        if (zns_load_zone(id, &zone) != 0) {
            zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
            return 0;
        }
        if (zns_report_match(filter, zone.state)) {
            matches++;
            if (partial && matches >= maximum_descriptors) {
                break;
            }
        }
    }
    zns_zero(zns_report_buffer, transfer_size);
    header = (struct zns_report_header *)zns_report_buffer;
    header->zone_count = matches;
    for (sxs_u32 id = first_zone;
         id < state.zone_count && emitted < maximum_descriptors; id++) {
        struct zns_zone_state zone;
        sxs_u64 write_pointer;

        if (zns_load_zone(id, &zone) != 0 ||
            !zns_report_match(filter, zone.state)) {
            continue;
        }
        zns_zero((sxs_u8 *)&descriptor, sizeof(descriptor));
        descriptor.type = ZNS_ZONE_TYPE_SEQ_WRITE;
        descriptor.state = zone.state << 4;
        descriptor.attributes = zone.attributes;
        descriptor.capacity = zone.capacity;
        descriptor.start_lba = zone.start_lba;
        write_pointer = (zone.state == ZNS_STATE_FULL ||
                         zone.state == ZNS_STATE_READ_ONLY ||
                         zone.state == ZNS_STATE_OFFLINE) ? ~0ULL :
            zone.write_pointer;
        descriptor.write_pointer = write_pointer;
        zns_copy(zns_report_buffer + sizeof(*header) +
                     emitted * sizeof(descriptor),
                 (const sxs_u8 *)&descriptor, sizeof(descriptor));
        emitted++;
    }
    if (sxs_command_write(0, zns_report_buffer, transfer_size) != 0) {
        zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
        return 0;
    }
    zns_set_status(ZNS_SUCCESS);
    return 0;
}

static sxs_s64 zns_stage_blob(sxs_u32 kind, const sxs_u8 blob[4096])
{
    return sxs_namespace_blob_stage(kind, 0, blob, 4096);
}

static sxs_u64 zns_init(void)
{
    struct sxs_geometry geometry;
    struct sxs_eswd_config eswd_config;
    struct sxs_namespace_config namespace_config;
    struct zns_policy_state state;
    sxs_u8 blob[4096];
    sxs_u64 zone_count;
    sxs_u64 zone_size;

    if (sxs_geometry_get(&geometry) != 0 || geometry.total_luns == 0 ||
        geometry.sectors_per_page == 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    zone_count = geometry.total_blocks_log / geometry.total_luns;
    zone_size = (sxs_u64)geometry.total_luns * geometry.pages_per_block *
                geometry.sectors_per_page;
    if (zone_count == 0 || zone_count > ZNS_MAX_ZONES || zone_size == 0 ||
        (sxs_u64)geometry.sectors_per_page * geometry.sector_size >
            SXS_WASM_MAX_PAGE_BYTES) {
        return SXS_WASM_ACTION_ERROR;
    }

    state = (struct zns_policy_state) {
        .zone_count = zone_count,
        .sectors_per_page = geometry.sectors_per_page,
        .sector_size = geometry.sector_size,
        .zone_size_lbas = zone_size,
    };
    zns_store_state(&state);
    for (sxs_u32 id = 0; id < state.zone_count; id++) {
        struct zns_zone_state zone = {
            .eswd_id = id,
            .state = ZNS_STATE_EMPTY,
            .start_lba = (sxs_u64)id * zone_size,
            .capacity = zone_size,
            .write_pointer = (sxs_u64)id * zone_size,
            .data_end_lba = (sxs_u64)id * zone_size,
        };

        if (zns_store_zone(id, &zone) != 0) {
            return SXS_WASM_ACTION_ERROR;
        }
    }

    eswd_config.striping_level = 0;
    eswd_config.blocks_per_eswd = geometry.total_luns;
    namespace_config.csi = ZNS_CSI_ZONED;
    namespace_config.noiob = 1;
    namespace_config.nsze = zone_count * zone_size;
    namespace_config.ncap = namespace_config.nsze;
    namespace_config.nuse = namespace_config.ncap;
    namespace_config.namespace_blob_length = 4096;
    namespace_config.controller_blob_length = 4096;
    if (sxs_eswd_config_stage(&eswd_config) != 0 ||
        sxs_namespace_config_stage(&namespace_config) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }

    zns_zero(blob, sizeof(blob));
    *(sxs_u32 *)(blob + 4) = 0xffffffffU;
    *(sxs_u32 *)(blob + 8) = 0xffffffffU;
    for (sxs_u32 format = 0; format < 16; format++) {
        *(sxs_u64 *)(blob + 2816 + format * 16) = zone_size;
    }
    if (zns_stage_blob(SXS_NAMESPACE_BLOB_NS, blob) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    zns_zero(blob, sizeof(blob));
    if (zns_stage_blob(SXS_NAMESPACE_BLOB_CTRL, blob) != 0 ||
        sxs_eswd_layout_finalize_stage() != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_IO, ZNS_CMD_READ,
                      ZNS_PAIR_READ, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_IO, ZNS_CMD_WRITE,
                      ZNS_PAIR_WRITE, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_IO, ZNS_CMD_APPEND,
                      ZNS_PAIR_APPEND, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_IO, ZNS_CMD_MGMT_SEND,
                      ZNS_PAIR_MGMT_SEND, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_IO, ZNS_CMD_MGMT_RECEIVE,
                      ZNS_PAIR_MGMT_RECEIVE, 0) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    return 0;
}

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    struct sxs_policy_context context;
    sxs_s32 result = sxs_context_get(&context);

    return result == 0 ? (sxs_s32)zns_init() : result;
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;
    sxs_s32 result = sxs_context_get(&context);

    if (result != 0 || context.pair_id != pair_id) {
        return result != 0 ? result : -SXS_WASM_EINVAL;
    }
    switch (pair_id) {
    case ZNS_PAIR_READ: return context.event.nvme.opcode == ZNS_CMD_READ;
    case ZNS_PAIR_WRITE: return context.event.nvme.opcode == ZNS_CMD_WRITE;
    case ZNS_PAIR_APPEND: return context.event.nvme.opcode == ZNS_CMD_APPEND;
    case ZNS_PAIR_MGMT_SEND:
        return context.event.nvme.opcode == ZNS_CMD_MGMT_SEND;
    case ZNS_PAIR_MGMT_RECEIVE:
        return context.event.nvme.opcode == ZNS_CMD_MGMT_RECEIVE;
    default: return 0;
    }
}

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 || context.pair_id != pair_id) {
        return SXS_WASM_ACTION_ERROR;
    }
    switch (pair_id) {
    case ZNS_PAIR_READ: return zns_read(&context);
    case ZNS_PAIR_WRITE: return zns_write(&context, 0);
    case ZNS_PAIR_APPEND: return zns_write(&context, 1);
    case ZNS_PAIR_MGMT_SEND: return zns_management_send(&context);
    case ZNS_PAIR_MGMT_RECEIVE: return zns_management_receive(&context);
    default: return SXS_WASM_ACTION_ERROR;
    }
}
