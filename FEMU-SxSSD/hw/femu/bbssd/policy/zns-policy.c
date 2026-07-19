#include "zns-policy.h"

#define ZNS_ZONE_OBJECT 1U
#define ZNS_POLICY_OBJECT 2U

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

enum zns_scratch_offset {
    ZNS_PAGE_OFFSET = 0,
    ZNS_IO_REQUEST_OFFSET = 4096,
    ZNS_IO_RESULT_OFFSET = 4160,
    ZNS_ZONE_OFFSET = 4224,
    ZNS_POLICY_OFFSET = 4288,
    ZNS_REPORT_OFFSET = 4352,
    ZNS_BLOB_DESCRIPTOR_OFFSET = 4448,
    ZNS_GEOMETRY_OFFSET = 4480,
    ZNS_ESWD_CONFIG_OFFSET = 4576,
    ZNS_NAMESPACE_CONFIG_OFFSET = 4608,
};

static void zns_zero(sxs_u8 *data, sxs_u32 length)
{
    for (sxs_u32 i = 0; i < length; i++) {
        data[i] = 0;
    }
}

static sxs_s64 zns_policy_read(struct sxs_bpf_context *context,
                               struct zns_policy_state *state)
{
    sxs_s64 result = sxs_state_read(ZNS_POLICY_OBJECT, 0, 0,
                                    ZNS_POLICY_OFFSET, sizeof(*state));

    if (result == 0) {
        *state = *(struct zns_policy_state *)(context->scratch +
                                              ZNS_POLICY_OFFSET);
    }
    return result;
}

static sxs_s64 zns_policy_write(struct sxs_bpf_context *context,
                                const struct zns_policy_state *state)
{
    *(struct zns_policy_state *)(context->scratch + ZNS_POLICY_OFFSET) =
        *state;
    return sxs_state_write(ZNS_POLICY_OBJECT, 0, 0,
                           ZNS_POLICY_OFFSET, sizeof(*state));
}

static sxs_s64 zns_zone_read(struct sxs_bpf_context *context, sxs_u32 zone_id,
                             struct zns_zone_state *zone)
{
    sxs_s64 result = sxs_state_read(ZNS_ZONE_OBJECT, zone_id, 0,
                                    ZNS_ZONE_OFFSET, sizeof(*zone));

    if (result == 0) {
        *zone = *(struct zns_zone_state *)(context->scratch + ZNS_ZONE_OFFSET);
    }
    return result;
}

static sxs_s64 zns_zone_write(struct sxs_bpf_context *context, sxs_u32 zone_id,
                              const struct zns_zone_state *zone)
{
    *(struct zns_zone_state *)(context->scratch + ZNS_ZONE_OFFSET) = *zone;
    return sxs_state_write(ZNS_ZONE_OBJECT, zone_id, 0,
                           ZNS_ZONE_OFFSET, sizeof(*zone));
}

static sxs_u16 zns_set_status(sxs_u16 status)
{
    sxs_completion_status_set(status, 0, 0, 0, 0);
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

static sxs_s64 zns_close_one_implicit(struct sxs_bpf_context *context,
                                      struct zns_policy_state *state)
{
    struct zns_zone_state candidate;

    if (state->max_open_zones == 0 ||
        state->open_zones < state->max_open_zones) {
        return 0;
    }
    for (sxs_u32 id = 0; id < state->zone_count; id++) {
        if (zns_zone_read(context, id, &candidate) == 0 &&
            candidate.state == ZNS_STATE_IMPLICITLY_OPEN) {
            candidate.state = ZNS_STATE_CLOSED;
            if (zns_zone_write(context, id, &candidate) != 0) {
                return -SXS_BPF_EIO;
            }
            if (state->open_zones != 0) {
                state->open_zones--;
            }
            return 0;
        }
    }
    return 0;
}

static sxs_u16 zns_ensure_implicit_open(struct sxs_bpf_context *context,
                                        struct zns_policy_state *state,
                                        struct zns_zone_state *zone)
{
    sxs_u16 status;

    switch (zone->state) {
    case ZNS_STATE_EMPTY:
        if (zns_close_one_implicit(context, state) != 0) {
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
        if (zns_close_one_implicit(context, state) != 0) {
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

static void zns_finish_if_full(struct zns_policy_state *state,
                               struct zns_zone_state *zone)
{
    sxs_u64 write_pointer = sxs_eswd_effective_wp_get(zone->eswd_id,
                                                       0, 0, 0, 0);

    if ((sxs_s64)write_pointer < 0 ||
        write_pointer != zone->start_lba + zone->capacity) {
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

static sxs_u64 zns_write(struct sxs_bpf_context *context, sxs_u32 append)
{
    struct zns_policy_state state;
    struct zns_zone_state zone;
    struct sxs_bpf_eswd_stage_write_request *request =
        (struct sxs_bpf_eswd_stage_write_request *)(context->scratch +
                                                     ZNS_IO_REQUEST_OFFSET);
    struct sxs_bpf_page_result *result =
        (struct sxs_bpf_page_result *)(context->scratch +
                                       ZNS_IO_RESULT_OFFSET);
    sxs_u64 command_lba = append ?
        ((sxs_u64)context->event.nvme.cdw11 << 32) |
             context->event.nvme.cdw10 : context->event.nvme.lba;
    sxs_u64 lba_count = append ?
        (context->event.nvme.cdw12 & 0xffffU) + 1U :
        context->event.nvme.nsecs;
    sxs_u64 write_lba;
    sxs_u32 zone_id;
    sxs_u16 status;

    if (zns_policy_read(context, &state) != 0 || lba_count > 0xffffffffULL) {
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
        zns_zone_read(context, zone_id, &zone) != 0) {
        zns_set_status(ZNS_LBA_RANGE | ZNS_DNR);
        return 0;
    }
    status = zns_write_state_status(zone.state);
    if (status != ZNS_SUCCESS) {
        zns_set_status(status | ZNS_DNR);
        return 0;
    }
    write_lba = sxs_eswd_effective_wp_get(zone.eswd_id, 0, 0, 0, 0);
    if ((sxs_s64)write_lba < 0 ||
        (append && command_lba != zone.start_lba)) {
        zns_set_status(ZNS_INVALID_FIELD | ZNS_DNR);
        return 0;
    }
    status = sxs_eswd_range_check(SXS_BPF_ESWD_CHECK_SEQUENTIAL_WRITE,
                                  zone.eswd_id,
                                  append ? write_lba : command_lba,
                                  lba_count, 0);
    if (status != ZNS_SUCCESS) {
        zns_set_status(status);
        return 0;
    }
    status = zns_ensure_implicit_open(context, &state, &zone);
    if (status != ZNS_SUCCESS) {
        zns_set_status(status);
        return 0;
    }

    request->eswd_id = zone.eswd_id;
    request->lba_count = lba_count;
    request->start_lba = append ? write_lba : command_lba;
    request->request_byte_offset = 0;
    request->result_offset = ZNS_IO_RESULT_OFFSET;
    request->reserved = 0;
    if (sxs_eswd_stage_write(ZNS_IO_REQUEST_OFFSET, 0, 0, 0, 0) != 0 ||
        result->status != 0) {
        zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
        return 0;
    }
    if (append) {
        sxs_completion_result_set(write_lba, 0, 0, 0, 0);
    }
    zns_finish_if_full(&state, &zone);
    if (zns_zone_write(context, zone_id, &zone) != 0 ||
        zns_policy_write(context, &state) != 0) {
        zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
        return 0;
    }
    zns_set_status(ZNS_SUCCESS);
    return result->latency_ns;
}

static sxs_u64 zns_read(struct sxs_bpf_context *context)
{
    struct zns_policy_state state;
    struct zns_zone_state zone;
    struct sxs_bpf_eswd_page_read_request *request =
        (struct sxs_bpf_eswd_page_read_request *)(context->scratch +
                                                   ZNS_IO_REQUEST_OFFSET);
    struct sxs_bpf_page_result *result =
        (struct sxs_bpf_page_result *)(context->scratch +
                                       ZNS_IO_RESULT_OFFSET);
    sxs_u64 end_lba;
    sxs_u64 current_lba;
    sxs_u64 output_offset = 0;
    sxs_u64 maximum_latency = 0;
    sxs_u64 effective_write_pointer;
    sxs_u32 zone_id;
    sxs_u16 status;

    if (zns_policy_read(context, &state) != 0) {
        zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
        return 0;
    }
    status = zns_check_bounds(&state, context->event.nvme.lba,
                              context->event.nvme.nsecs);
    if (status != ZNS_SUCCESS) {
        zns_set_status(status);
        return 0;
    }
    zone_id = context->event.nvme.lba / state.zone_size_lbas;
    if (zone_id >= state.zone_count ||
        zns_zone_read(context, zone_id, &zone) != 0) {
        zns_set_status(ZNS_LBA_RANGE | ZNS_DNR);
        return 0;
    }
    status = zns_read_state_status(zone.state);
    end_lba = context->event.nvme.lba + context->event.nvme.nsecs;
    if (status != ZNS_SUCCESS) {
        zns_set_status(status | ZNS_DNR);
        return 0;
    }
    effective_write_pointer = sxs_eswd_effective_wp_get(zone.eswd_id,
                                                         0, 0, 0, 0);
    if ((sxs_s64)effective_write_pointer < 0 ||
        (!state.cross_zone_read &&
         end_lba > zone.start_lba + state.zone_size_lbas) ||
        end_lba > effective_write_pointer) {
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
        request->eswd_id = zone.eswd_id;
        request->data_offset = ZNS_PAGE_OFFSET;
        request->page_lba = page_lba;
        request->data_length = state.sectors_per_page * state.sector_size;
        request->result_offset = ZNS_IO_RESULT_OFFSET;
        if (sxs_eswd_page_read(ZNS_IO_REQUEST_OFFSET, 0, 0, 0, 0) != 0 ||
            result->status != 0) {
            zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
            return 0;
        }
        bytes = (sxs_u64)sectors * state.sector_size;
        if (sxs_request_write(output_offset,
                              ZNS_PAGE_OFFSET + page_offset * state.sector_size,
                              bytes, 0, 0) != 0) {
            zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
            return 0;
        }
        if (result->latency_ns > maximum_latency) {
            maximum_latency = result->latency_ns;
        }
        output_offset += bytes;
        current_lba += sectors;
    }
    zns_set_status(ZNS_SUCCESS);
    return maximum_latency;
}

static sxs_u16 zns_open(struct sxs_bpf_context *context,
                        struct zns_policy_state *state,
                        struct zns_zone_state *zone)
{
    sxs_u16 status;

    switch (zone->state) {
    case ZNS_STATE_EMPTY:
        if (zns_close_one_implicit(context, state) != 0) {
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
        if (zns_close_one_implicit(context, state) != 0) {
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

static sxs_u16 zns_finish(struct zns_policy_state *state,
                          struct zns_zone_state *zone)
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
    if (sxs_eswd_advance_wp(zone->eswd_id, 0, 0, 0, 0) != 0) {
        return ZNS_INTERNAL_ERROR | ZNS_DNR;
    }
    zns_remove_open_active(state, old_state);
    if (old_state == ZNS_STATE_EXPLICITLY_OPEN) {
        zone->attributes |= ZNS_ZA_FINISHED_BY_CONTROLLER;
    }
    zone->state = ZNS_STATE_FULL;
    return ZNS_SUCCESS;
}

static sxs_u16 zns_reset(struct zns_policy_state *state,
                         struct zns_zone_state *zone, sxs_u64 *latency)
{
    sxs_u8 old_state = zone->state;

    *latency = 0;
    if (old_state == ZNS_STATE_EMPTY) {
        if (sxs_eswd_reset(zone->eswd_id, 0, 0, 0, 0) != 0) {
            return ZNS_INTERNAL_ERROR | ZNS_DNR;
        }
        zone->attributes = 0;
        return ZNS_SUCCESS;
    }
    if (old_state != ZNS_STATE_IMPLICITLY_OPEN &&
        old_state != ZNS_STATE_EXPLICITLY_OPEN &&
        old_state != ZNS_STATE_CLOSED && old_state != ZNS_STATE_FULL) {
        return ZNS_INVALID_TRANSITION;
    }
    zns_remove_open_active(state, old_state);
    *latency = sxs_eswd_erase(zone->eswd_id, 0, 0, 0, 0);
    if ((sxs_s64)*latency < 0 ||
        sxs_eswd_reset(zone->eswd_id, 0, 0, 0, 0) != 0) {
        return ZNS_INTERNAL_ERROR | ZNS_DNR;
    }
    zone->attributes = 0;
    zone->state = ZNS_STATE_EMPTY;
    return ZNS_SUCCESS;
}

static sxs_u64 zns_management_send(struct sxs_bpf_context *context)
{
    struct zns_policy_state state;
    sxs_u64 start_lba = ((sxs_u64)context->event.nvme.cdw11 << 32) |
                        context->event.nvme.cdw10;
    sxs_u32 action = context->event.nvme.cdw13 & 0xffU;
    sxs_u32 all = (context->event.nvme.cdw13 & 0x100U) != 0;
    sxs_u64 maximum_latency = 0;
    sxs_u32 selected_zone = 0;

    if (zns_policy_read(context, &state) != 0) {
        zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
        return 0;
    }
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
        if (zns_zone_read(context, id, &zone) != 0) {
            zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
            return maximum_latency;
        }
        switch (action) {
        case ZNS_ACTION_OPEN:
            status = zns_open(context, &state, &zone);
            break;
        case ZNS_ACTION_CLOSE:
            status = zns_close(&state, &zone);
            break;
        case ZNS_ACTION_FINISH:
            status = zns_finish(&state, &zone);
            break;
        case ZNS_ACTION_RESET:
            status = zns_reset(&state, &zone, &latency);
            break;
        default:
            zns_set_status(ZNS_INVALID_FIELD | ZNS_DNR);
            return maximum_latency;
        }
        if (status != ZNS_SUCCESS) {
            zns_set_status(status | ZNS_DNR);
            return maximum_latency;
        }
        if (zns_zone_write(context, id, &zone) != 0) {
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
    if (zns_policy_write(context, &state) != 0) {
        zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
        return maximum_latency;
    }
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

static sxs_u64 zns_management_receive(struct sxs_bpf_context *context)
{
    struct zns_policy_state state;
    struct zns_report_header *header =
        (struct zns_report_header *)(context->scratch + ZNS_REPORT_OFFSET);
    struct zns_report_descriptor *descriptor =
        (struct zns_report_descriptor *)(context->scratch + ZNS_REPORT_OFFSET);
    sxs_u64 start_lba = ((sxs_u64)context->event.nvme.cdw11 << 32) |
                        context->event.nvme.cdw10;
    sxs_u64 data_size = ((sxs_u64)context->event.nvme.cdw12 + 1) << 2;
    sxs_u32 action = context->event.nvme.cdw13 & 0xffU;
    sxs_u32 filter = (context->event.nvme.cdw13 >> 8) & 0xffU;
    sxs_u32 partial = (context->event.nvme.cdw13 >> 16) & 1U;
    sxs_u64 matches = 0;
    sxs_u64 emitted = 0;
    sxs_u32 first_zone;
    sxs_u64 maximum_descriptors;

    if (zns_policy_read(context, &state) != 0 ||
        (action != ZNS_REPORT && action != ZNS_REPORT_EXTENDED) ||
        filter > ZNS_REPORT_OFFLINE || data_size < sizeof(*header) ||
        start_lba >= zns_total_lbas(&state) ||
        start_lba % state.zone_size_lbas != 0 || data_size > 1024U * 1024U) {
        zns_set_status(ZNS_INVALID_FIELD | ZNS_DNR);
        return 0;
    }
    first_zone = start_lba / state.zone_size_lbas;
    maximum_descriptors = (data_size - sizeof(*header)) /
                          sizeof(*descriptor);
    for (sxs_u32 id = first_zone; id < state.zone_count; id++) {
        struct zns_zone_state zone;

        if (zns_zone_read(context, id, &zone) != 0) {
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
    zns_zero((sxs_u8 *)header, sizeof(*header));
    header->zone_count = matches;
    if (sxs_command_write(0, ZNS_REPORT_OFFSET,
                          sizeof(*header), 0, 0) != 0) {
        zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
        return 0;
    }
    for (sxs_u32 id = first_zone;
         id < state.zone_count && emitted < maximum_descriptors; id++) {
        struct zns_zone_state zone;
        sxs_u64 write_pointer;

        if (zns_zone_read(context, id, &zone) != 0 ||
            !zns_report_match(filter, zone.state)) {
            continue;
        }
        zns_zero((sxs_u8 *)descriptor, sizeof(*descriptor));
        descriptor->type = ZNS_ZONE_TYPE_SEQ_WRITE;
        descriptor->state = zone.state << 4;
        descriptor->attributes = zone.attributes;
        descriptor->capacity = zone.capacity;
        descriptor->start_lba = zone.start_lba;
        write_pointer = (zone.state == ZNS_STATE_FULL ||
                         zone.state == ZNS_STATE_READ_ONLY ||
                         zone.state == ZNS_STATE_OFFLINE) ? ~0ULL :
            sxs_eswd_effective_wp_get(zone.eswd_id, 0, 0, 0, 0);
        descriptor->write_pointer = write_pointer;
        if (sxs_command_write(sizeof(*header) +
                                  emitted * sizeof(*descriptor),
                              ZNS_REPORT_OFFSET,
                              sizeof(*descriptor), 0, 0) != 0) {
            zns_set_status(ZNS_INTERNAL_ERROR | ZNS_DNR);
            return 0;
        }
        emitted++;
    }
    zns_set_status(ZNS_SUCCESS);
    return 0;
}

static sxs_s64 zns_stage_blob(struct sxs_bpf_context *context, sxs_u32 kind)
{
    struct sxs_bpf_namespace_blob *descriptor =
        (struct sxs_bpf_namespace_blob *)(context->scratch +
                                           ZNS_BLOB_DESCRIPTOR_OFFSET);

    descriptor->kind = kind;
    descriptor->destination_offset = 0;
    descriptor->source_offset = ZNS_PAGE_OFFSET;
    descriptor->length = 4096;
    return sxs_namespace_blob_stage(ZNS_BLOB_DESCRIPTOR_OFFSET, 0, 0, 0, 0);
}

static sxs_u64 zns_init(struct sxs_bpf_context *context)
{
    struct sxs_bpf_geometry *geometry =
        (struct sxs_bpf_geometry *)(context->scratch + ZNS_GEOMETRY_OFFSET);
    struct sxs_bpf_eswd_config *eswd_config =
        (struct sxs_bpf_eswd_config *)(context->scratch +
                                        ZNS_ESWD_CONFIG_OFFSET);
    struct sxs_bpf_namespace_config *namespace_config =
        (struct sxs_bpf_namespace_config *)(context->scratch +
                                             ZNS_NAMESPACE_CONFIG_OFFSET);
    struct zns_policy_state state;
    sxs_u64 zone_count;
    sxs_u64 zone_size;

    if (sxs_geometry_get(ZNS_GEOMETRY_OFFSET, 0, 0, 0, 0) != 0 ||
        geometry->total_luns == 0 || geometry->sectors_per_page == 0) {
        return SXS_BPF_ACTION_ERROR;
    }
    zone_count = geometry->total_blocks_log / geometry->total_luns;
    zone_size = (sxs_u64)geometry->total_luns * geometry->pages_per_block *
                geometry->sectors_per_page;
    if (zone_count == 0 || zone_count > 0xffffffffULL || zone_size == 0 ||
        (sxs_u64)geometry->sectors_per_page * geometry->sector_size >
            SXS_BPF_MAX_PAGE_BYTES ||
        sxs_state_create(ZNS_ZONE_OBJECT, sizeof(struct zns_zone_state),
                         zone_count, 0, 0) != 0 ||
        sxs_state_create(ZNS_POLICY_OBJECT, sizeof(struct zns_policy_state),
                         1, 0, 0) != 0) {
        return SXS_BPF_ACTION_ERROR;
    }

    if (!(context->flags & SXS_BPF_FLAG_STATE_RESTORED)) {
        state = (struct zns_policy_state) {
            .zone_count = zone_count,
            .sectors_per_page = geometry->sectors_per_page,
            .sector_size = geometry->sector_size,
            .zone_size_lbas = zone_size,
        };
        if (zns_policy_write(context, &state) != 0) {
            return SXS_BPF_ACTION_ERROR;
        }
        for (sxs_u32 id = 0; id < state.zone_count; id++) {
            struct zns_zone_state zone = {
                .eswd_id = id,
                .state = ZNS_STATE_EMPTY,
                .start_lba = (sxs_u64)id * zone_size,
                .capacity = zone_size,
            };

            if (zns_zone_write(context, id, &zone) != 0) {
                return SXS_BPF_ACTION_ERROR;
            }
        }
    }

    eswd_config->striping_level = 0;
    eswd_config->blocks_per_eswd = geometry->total_luns;
    namespace_config->csi = ZNS_CSI_ZONED;
    namespace_config->noiob = 1;
    namespace_config->nsze = zone_count * zone_size;
    namespace_config->ncap = namespace_config->nsze;
    namespace_config->nuse = namespace_config->ncap;
    namespace_config->namespace_blob_length = 4096;
    namespace_config->controller_blob_length = 4096;
    if (sxs_eswd_config_stage(ZNS_ESWD_CONFIG_OFFSET, 0, 0, 0, 0) != 0 ||
        sxs_namespace_config_stage(ZNS_NAMESPACE_CONFIG_OFFSET,
                                   0, 0, 0, 0) != 0) {
        return SXS_BPF_ACTION_ERROR;
    }

    zns_zero(context->scratch + ZNS_PAGE_OFFSET, 4096);
    *(sxs_u32 *)(context->scratch + ZNS_PAGE_OFFSET + 4) = 0xffffffffU;
    *(sxs_u32 *)(context->scratch + ZNS_PAGE_OFFSET + 8) = 0xffffffffU;
    for (sxs_u32 format = 0; format < 16; format++) {
        *(sxs_u64 *)(context->scratch + ZNS_PAGE_OFFSET + 2816 +
                     format * 16) = zone_size;
    }
    if (zns_stage_blob(context, SXS_BPF_NAMESPACE_BLOB_NS) != 0) {
        return SXS_BPF_ACTION_ERROR;
    }
    zns_zero(context->scratch + ZNS_PAGE_OFFSET, 4096);
    if (zns_stage_blob(context, SXS_BPF_NAMESPACE_BLOB_CTRL) != 0 ||
        sxs_ftl_finalize_stage(0, 0, 0, 0, 0) != 0 ||
        sxs_subscribe(SXS_BPF_EVENT_NVME_IO, ZNS_CMD_READ,
                      ZNS_PAIR_READ, 0, 0) != 0 ||
        sxs_subscribe(SXS_BPF_EVENT_NVME_IO, ZNS_CMD_WRITE,
                      ZNS_PAIR_WRITE, 0, 0) != 0 ||
        sxs_subscribe(SXS_BPF_EVENT_NVME_IO, ZNS_CMD_APPEND,
                      ZNS_PAIR_APPEND, 0, 0) != 0 ||
        sxs_subscribe(SXS_BPF_EVENT_NVME_IO, ZNS_CMD_MGMT_SEND,
                      ZNS_PAIR_MGMT_SEND, 0, 0) != 0 ||
        sxs_subscribe(SXS_BPF_EVENT_NVME_IO, ZNS_CMD_MGMT_RECEIVE,
                      ZNS_PAIR_MGMT_RECEIVE, 0, 0) != 0) {
        return SXS_BPF_ACTION_ERROR;
    }
    return 0;
}

sxs_u64 policy_main(void *memory, sxs_u64 memory_size)
{
    struct sxs_bpf_context *context = memory;

    if (!context || memory_size != sizeof(*context) ||
        context->abi_version != SXS_BPF_ABI_VERSION ||
        context->context_size != sizeof(*context)) {
        return SXS_BPF_ACTION_ERROR;
    }
    if (context->phase == SXS_BPF_PHASE_INIT) {
        return zns_init(context);
    }
    if (context->phase == SXS_BPF_PHASE_CONDITION) {
        switch (context->pair_id) {
        case ZNS_PAIR_READ: return context->event.nvme.opcode == ZNS_CMD_READ;
        case ZNS_PAIR_WRITE: return context->event.nvme.opcode == ZNS_CMD_WRITE;
        case ZNS_PAIR_APPEND: return context->event.nvme.opcode == ZNS_CMD_APPEND;
        case ZNS_PAIR_MGMT_SEND:
            return context->event.nvme.opcode == ZNS_CMD_MGMT_SEND;
        case ZNS_PAIR_MGMT_RECEIVE:
            return context->event.nvme.opcode == ZNS_CMD_MGMT_RECEIVE;
        default: return 0;
        }
    }
    if (context->phase != SXS_BPF_PHASE_ACTION) {
        return SXS_BPF_ACTION_ERROR;
    }
    switch (context->pair_id) {
    case ZNS_PAIR_READ: return zns_read(context);
    case ZNS_PAIR_WRITE: return zns_write(context, 0);
    case ZNS_PAIR_APPEND: return zns_write(context, 1);
    case ZNS_PAIR_MGMT_SEND: return zns_management_send(context);
    case ZNS_PAIR_MGMT_RECEIVE: return zns_management_receive(context);
    default: return SXS_BPF_ACTION_ERROR;
    }
}
