#ifndef SXS_FLASHGUARD_WASM_CORE_H
#define SXS_FLASHGUARD_WASM_CORE_H

#include "policy-wasm-abi.h"

#define FLASHGUARD_OOB_OBJECT 1U

#define FLASHGUARD_PAIR_LIST 10U
#define FLASHGUARD_PAIR_READ 11U
#define FLASHGUARD_ADMIN_LIST 0xe0U
#define FLASHGUARD_ADMIN_READ 0xe1U
#define FLASHGUARD_MAX_LIST_ENTRIES 128U
#define FLASHGUARD_MAX_LOGICAL_PAGES 4194304U
#define FLASHGUARD_BITMAP_BYTES ((FLASHGUARD_MAX_LOGICAL_PAGES + 7U) / 8U)
#define FLASHGUARD_RETAINED_FLAG 1U
#define FLASHGUARD_RETENTION_NS \
    (20ULL * 24ULL * 60ULL * 60ULL * 1000000000ULL)

struct flashguard_oob {
    sxs_u64 lpn;
    sxs_u64 previous_ppa;
    sxs_u64 retention_timestamp_ns;
    sxs_u32 flags;
    sxs_u32 reserved;
};

struct flashguard_shadow {
    sxs_u64 lpn;
    sxs_u64 previous_ppa;
};

struct flashguard_settings {
    sxs_u64 physical_pages;
    sxs_u64 retention_window_ns;
    sxs_u64 retained_count;
};

static sxs_u8 flashguard_read_bitmap[FLASHGUARD_BITMAP_BYTES];
static sxs_u8 flashguard_retained_bitmap[FLASHGUARD_BITMAP_BYTES];
static sxs_u64 flashguard_timestamps[FLASHGUARD_MAX_LOGICAL_PAGES];
static struct flashguard_shadow
    flashguard_shadows[FLASHGUARD_MAX_LOGICAL_PAGES];
static sxs_u64 flashguard_retained_list[FLASHGUARD_MAX_LOGICAL_PAGES];
static sxs_u32 flashguard_retained_positions[FLASHGUARD_MAX_LOGICAL_PAGES];
static struct flashguard_settings flashguard_policy_settings;

struct __attribute__((packed)) flashguard_list_header {
    sxs_u32 version;
    sxs_u32 total_retained;
    sxs_u32 returned_entries;
    sxs_u32 next_index;
};

struct __attribute__((packed)) flashguard_list_entry {
    sxs_u64 ppa;
    sxs_u64 lpn;
    sxs_u64 previous_ppa;
    sxs_u64 retention_timestamp_ns;
    sxs_u32 flags;
    sxs_u32 reserved;
};

struct __attribute__((packed)) flashguard_read_response {
    sxs_u32 version;
    sxs_u32 data_length;
    sxs_u64 ppa;
    sxs_u64 lpn;
    sxs_u64 previous_ppa;
    sxs_u64 retention_timestamp_ns;
    sxs_u32 flags;
    sxs_u32 reserved;
};

struct block_wasm_metadata;

static sxs_s64 flashguard_init(struct sxs_policy_context *,
                               const struct sxs_geometry *,
                               const struct block_wasm_metadata *);
static sxs_u64 flashguard_condition(struct sxs_policy_context *);
static sxs_u64 flashguard_action(struct sxs_policy_context *);
static sxs_s64 flashguard_prepare_append(
    struct sxs_policy_context *, sxs_u64, sxs_u64,
    struct sxs_page_append_request *, sxs_u8 *, sxs_u32 *);
static sxs_s64 flashguard_handle_old_page(struct sxs_policy_context *,
                                           sxs_u64, sxs_u64);
static sxs_s64 flashguard_after_new_page(struct sxs_policy_context *,
                                          sxs_u64, sxs_u64, sxs_u64);
static sxs_s64 flashguard_on_page_read(struct sxs_policy_context *,
                                        sxs_u64, sxs_u64);
static sxs_u32 flashguard_gc_should_migrate(struct sxs_policy_context *,
                                             sxs_u64);
static sxs_s64 flashguard_gc_after_migrate(struct sxs_policy_context *,
                                            sxs_u64, sxs_u64, sxs_u64);
static sxs_s64 flashguard_gc_before_erase(
    struct sxs_policy_context *, sxs_u32, const struct block_wasm_metadata *);

#define BLOCK_EXTRA_INIT flashguard_init
#define BLOCK_EXTRA_CONDITION flashguard_condition
#define BLOCK_EXTRA_ACTION flashguard_action
#define BLOCK_PREPARE_APPEND flashguard_prepare_append
#define BLOCK_HANDLE_OLD_PAGE flashguard_handle_old_page
#define BLOCK_AFTER_NEW_PAGE flashguard_after_new_page
#define BLOCK_ON_PAGE_READ flashguard_on_page_read
#define BLOCK_GC_SHOULD_MIGRATE flashguard_gc_should_migrate
#define BLOCK_GC_AFTER_MIGRATE flashguard_gc_after_migrate
#define BLOCK_GC_BEFORE_ERASE flashguard_gc_before_erase

#include "block-policy-wasm-core.h"

static sxs_s64 flashguard_page_index(sxs_u64 ppa, sxs_u64 *index_out)
{
    sxs_u64 index = sxs_ppa_to_page_index(ppa);

    if ((sxs_s64)index < 0 ||
        index >= flashguard_policy_settings.physical_pages ||
        index >= FLASHGUARD_MAX_LOGICAL_PAGES) {
        return -SXS_WASM_EINVAL;
    }
    *index_out = index;
    return 0;
}

static sxs_s64 flashguard_bitmap_get(const sxs_u8 *bitmap,
                                     sxs_u64 page_index,
                                     sxs_u32 *set_out)
{
    if (!set_out || page_index >= flashguard_policy_settings.physical_pages ||
        page_index >= FLASHGUARD_MAX_LOGICAL_PAGES) {
        return -SXS_WASM_EINVAL;
    }
    *set_out = (bitmap[page_index >> 3] &
                (1U << (page_index & 7))) != 0;
    return 0;
}

static sxs_s64 flashguard_bitmap_set(sxs_u8 *bitmap, sxs_u64 page_index,
                                     sxs_u32 set)
{
    sxs_u8 *value;

    if (page_index >= flashguard_policy_settings.physical_pages ||
        page_index >= FLASHGUARD_MAX_LOGICAL_PAGES) {
        return -SXS_WASM_EINVAL;
    }
    value = &bitmap[page_index >> 3];
    if (set) {
        *value |= 1U << (page_index & 7);
    } else {
        *value &= ~(1U << (page_index & 7));
    }
    return 0;
}

static sxs_s64 flashguard_retained_add(struct sxs_policy_context *context,
                                       sxs_u64 ppa, sxs_u64 page_index)
{
    struct flashguard_settings settings;
    sxs_u32 position;
    sxs_u32 retained;

    (void)context;
    if (flashguard_bitmap_get(flashguard_retained_bitmap,
                              page_index, &retained) != 0) {
        return -SXS_WASM_EIO;
    }
    if (retained) {
        return 0;
    }
    settings = flashguard_policy_settings;
    if (settings.retained_count >= settings.physical_pages) {
        return -SXS_WASM_ENOSPC;
    }
    if (settings.retained_count >= 0xffffffffULL) {
        return -SXS_WASM_ENOSPC;
    }
    position = (sxs_u32)settings.retained_count + 1;
    flashguard_retained_list[settings.retained_count] = ppa;
    flashguard_retained_positions[page_index] = position;
    if (flashguard_bitmap_set(flashguard_retained_bitmap,
                              page_index, 1) != 0) {
        return -SXS_WASM_EIO;
    }
    settings.retained_count++;
    flashguard_policy_settings = settings;
    return 0;
}

static sxs_s64 flashguard_retained_remove(struct sxs_policy_context *context,
                                          sxs_u64 page_index)
{
    struct flashguard_settings settings;
    sxs_u32 position;
    sxs_u64 last_ppa;
    sxs_u64 last_page_index;
    sxs_u32 retained;

    (void)context;
    if (flashguard_bitmap_get(flashguard_retained_bitmap,
                              page_index, &retained) != 0) {
        return -SXS_WASM_EIO;
    }
    if (!retained) {
        return 0;
    }
    settings = flashguard_policy_settings;
    position = flashguard_retained_positions[page_index];
    if (position == 0 || position > settings.retained_count ||
        settings.retained_count == 0) {
        return -SXS_WASM_EIO;
    }
    position--;
    settings.retained_count--;
    if (position != settings.retained_count) {
        sxs_u32 moved_position = position + 1;

        last_ppa = flashguard_retained_list[settings.retained_count];
        if (flashguard_page_index(last_ppa, &last_page_index) != 0) {
            return -SXS_WASM_EIO;
        }
        flashguard_retained_list[position] = last_ppa;
        flashguard_retained_positions[last_page_index] = moved_position;
    }
    flashguard_retained_list[settings.retained_count] = 0;
    flashguard_retained_positions[page_index] = 0;
    if (flashguard_bitmap_set(flashguard_retained_bitmap,
                              page_index, 0) != 0) {
        return -SXS_WASM_EIO;
    }
    flashguard_policy_settings = settings;
    return 0;
}

static sxs_s64 flashguard_clear_tracking(struct sxs_policy_context *context,
                                         sxs_u64 page_index)
{
    if (flashguard_bitmap_set(flashguard_read_bitmap, page_index, 0) != 0 ||
        flashguard_retained_remove(context, page_index) != 0) {
        return -SXS_WASM_EIO;
    }
    flashguard_timestamps[page_index] = 0;
    return 0;
}

static sxs_s64 flashguard_init(struct sxs_policy_context *context,
                               const struct sxs_geometry *geometry,
                               const struct block_wasm_metadata *metadata)
{
    struct flashguard_settings settings = {
        .physical_pages = geometry->total_pages_log,
        .retention_window_ns = FLASHGUARD_RETENTION_NS,
    };
    (void)context;
    (void)metadata;
    if (geometry->total_pages_log == 0 ||
        geometry->total_pages_log > FLASHGUARD_MAX_LOGICAL_PAGES) {
        return -SXS_WASM_ENOSPC;
    }
    flashguard_policy_settings = settings;
    if (sxs_oob_register_stage(FLASHGUARD_OOB_OBJECT,
                               sizeof(struct flashguard_oob)) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_ADMIN, FLASHGUARD_ADMIN_LIST,
                      FLASHGUARD_PAIR_LIST, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_ADMIN, FLASHGUARD_ADMIN_READ,
                      FLASHGUARD_PAIR_READ, 0) != 0) {
        return -SXS_WASM_EPERM;
    }
    return 0;
}

static sxs_s64 flashguard_prepare_append(
    struct sxs_policy_context *context, sxs_u64 lpn, sxs_u64 old_ppa,
    struct sxs_page_append_request *request, sxs_u8 *oob_bytes,
    sxs_u32 *oob_length)
{
    struct flashguard_oob *oob = (struct flashguard_oob *)oob_bytes;

    (void)context;
    *oob = (struct flashguard_oob) {
        .lpn = lpn,
        .previous_ppa = old_ppa,
    };
    request->oob_object_id = FLASHGUARD_OOB_OBJECT;
    *oob_length = sizeof(*oob);
    return 0;
}

static sxs_s64 flashguard_handle_old_page(struct sxs_policy_context *context,
                                          sxs_u64 lpn, sxs_u64 old_ppa)
{
    sxs_u64 page_index;
    sxs_u64 timestamp;
    sxs_u32 was_read;

    (void)lpn;
    if (flashguard_page_index(old_ppa, &page_index) != 0 ||
        flashguard_bitmap_get(flashguard_read_bitmap,
                              page_index, &was_read) != 0) {
        return -SXS_WASM_EIO;
    }
    if (was_read) {
        if (flashguard_retained_add(context, old_ppa, page_index) != 0) {
            return -SXS_WASM_EIO;
        }
        timestamp = flashguard_timestamps[page_index];
        if (timestamp == 0) {
            timestamp = sxs_time_now_ns();
            flashguard_timestamps[page_index] = timestamp;
        }
        return 0;
    }
    if (sxs_page_invalidate(old_ppa) != 0) {
        return -SXS_WASM_EIO;
    }
    return flashguard_clear_tracking(context, page_index);
}

static sxs_s64 flashguard_after_new_page(struct sxs_policy_context *context,
                                         sxs_u64 lpn, sxs_u64 old_ppa,
                                         sxs_u64 new_ppa)
{
    struct flashguard_shadow shadow = {
        .lpn = lpn,
        .previous_ppa = old_ppa,
    };
    sxs_u64 page_index;

    if (flashguard_page_index(new_ppa, &page_index) != 0 ||
        flashguard_clear_tracking(context, page_index) != 0) {
        return -SXS_WASM_EIO;
    }
    flashguard_shadows[page_index] = shadow;
    return 0;
}

static sxs_s64 flashguard_on_page_read(struct sxs_policy_context *context,
                                       sxs_u64 lpn, sxs_u64 ppa)
{
    sxs_u64 page_index;

    (void)lpn;
    (void)context;
    if (flashguard_page_index(ppa, &page_index) != 0) {
        return -SXS_WASM_EIO;
    }
    return flashguard_bitmap_set(flashguard_read_bitmap, page_index, 1);
}

static sxs_u32 flashguard_gc_should_migrate(struct sxs_policy_context *context,
                                            sxs_u64 ppa)
{
    struct flashguard_settings settings;
    sxs_u64 page_index;
    sxs_u64 timestamp;
    sxs_u64 now;
    sxs_u32 retained;

    if (flashguard_page_index(ppa, &page_index) != 0 ||
        flashguard_bitmap_get(flashguard_retained_bitmap,
                              page_index, &retained) != 0 || !retained) {
        return 1;
    }
    timestamp = flashguard_timestamps[page_index];
    settings = flashguard_policy_settings;
    if (timestamp == 0 || settings.retention_window_ns == 0) {
        return 1;
    }
    now = sxs_time_now_ns();
    if (now >= timestamp && now - timestamp >= settings.retention_window_ns) {
        flashguard_clear_tracking(context, page_index);
        return 0;
    }
    return 1;
}

static sxs_s64 flashguard_gc_after_migrate(struct sxs_policy_context *context,
                                           sxs_u64 old_ppa, sxs_u64 new_ppa,
                                           sxs_u64 lpn)
{
    struct flashguard_shadow shadow;
    sxs_u64 old_index;
    sxs_u64 new_index;
    sxs_u64 timestamp;
    sxs_u32 was_read;
    sxs_u32 retained;

    (void)lpn;
    if (flashguard_page_index(old_ppa, &old_index) != 0 ||
        flashguard_page_index(new_ppa, &new_index) != 0 ||
        flashguard_bitmap_get(flashguard_read_bitmap,
                              old_index, &was_read) != 0 ||
        flashguard_bitmap_get(flashguard_retained_bitmap,
                              old_index, &retained) != 0) {
        return -SXS_WASM_EIO;
    }
    timestamp = flashguard_timestamps[old_index];
    shadow = flashguard_shadows[old_index];
    if (flashguard_clear_tracking(context, old_index) != 0 ||
        flashguard_clear_tracking(context, new_index) != 0 ||
        flashguard_bitmap_set(flashguard_read_bitmap,
                              new_index, was_read) != 0) {
        return -SXS_WASM_EIO;
    }
    flashguard_timestamps[new_index] = timestamp;
    flashguard_shadows[new_index] = shadow;
    if (retained && flashguard_retained_add(context, new_ppa, new_index) != 0) {
        return -SXS_WASM_EIO;
    }
    return 0;
}

static sxs_s64 flashguard_gc_before_erase(
    struct sxs_policy_context *context, sxs_u32 victim,
    const struct block_wasm_metadata *metadata)
{
    for (sxs_u32 page = 0; page < metadata->pages_per_eswd; page++) {
        sxs_u64 ppa;
        sxs_u64 page_index;

        ppa = sxs_eswd_to_ppa(victim, page);
        if ((sxs_s64)ppa < 0) {
            continue;
        }
        if (flashguard_page_index(ppa, &page_index) == 0 &&
            flashguard_clear_tracking(context, page_index) != 0) {
            return -SXS_WASM_EIO;
        }
    }
    return 0;
}

static sxs_s64 flashguard_get_page_record(
    struct sxs_policy_context *context, sxs_u64 ppa, sxs_u32 *retained_out,
    sxs_u64 *timestamp_out, struct flashguard_shadow *shadow_out)
{
    sxs_u64 page_index;

    (void)context;
    if (flashguard_page_index(ppa, &page_index) != 0 ||
        flashguard_bitmap_get(flashguard_retained_bitmap,
                              page_index, retained_out) != 0) {
        return -SXS_WASM_EIO;
    }
    if (!*retained_out) {
        *timestamp_out = 0;
        *shadow_out = (struct flashguard_shadow) {0};
        return 0;
    }
    *timestamp_out = flashguard_timestamps[page_index];
    *shadow_out = flashguard_shadows[page_index];
    return 0;
}

static sxs_u64 flashguard_list(struct sxs_policy_context *context)
{
    struct flashguard_settings settings;
    struct flashguard_list_header header = { .version = 1 };
    sxs_u32 start = context->event.nvme.cdw10;
    sxs_u32 maximum = context->event.nvme.cdw11;
    sxs_u64 end;

    if (maximum > FLASHGUARD_MAX_LIST_ENTRIES) {
        maximum = FLASHGUARD_MAX_LIST_ENTRIES;
    }
    settings = flashguard_policy_settings;
    if (settings.retained_count > 0xffffffffULL) {
        sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
        return 0;
    }
    header.total_retained = (sxs_u32)settings.retained_count;
    end = (sxs_u64)start + maximum;
    if (end > settings.retained_count) {
        end = settings.retained_count;
    }
    for (sxs_u64 ordinal = start; ordinal < end; ordinal++) {
        struct flashguard_shadow shadow;
        struct flashguard_list_entry entry;
        sxs_u64 ppa;
        sxs_u64 timestamp;
        sxs_u32 retained;

        ppa = flashguard_retained_list[ordinal];
        if (flashguard_get_page_record(context, ppa, &retained,
                                       &timestamp, &shadow) != 0 ||
            !retained) {
            sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
            return 0;
        }
        entry = (struct flashguard_list_entry) {
            .ppa = ppa,
            .lpn = shadow.lpn,
            .previous_ppa = shadow.previous_ppa,
            .retention_timestamp_ns = timestamp,
            .flags = FLASHGUARD_RETAINED_FLAG,
        };
        if (sxs_command_write(sizeof(header) +
                                  (sxs_u64)header.returned_entries *
                                      sizeof(entry),
                              &entry, sizeof(entry)) != 0) {
            sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
            return 0;
        }
        header.returned_entries++;
    }
    header.next_index = start + header.returned_entries;
    if (sxs_command_write(0, &header, sizeof(header)) != 0) {
        sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
        return 0;
    }
    sxs_completion_result_set(((sxs_u64)header.returned_entries << 32) |
                              header.total_retained);
    sxs_completion_status_set(BLOCK_NVME_SUCCESS);
    return 0;
}

static sxs_u64 flashguard_read_retained(struct sxs_policy_context *context)
{
    struct block_wasm_metadata metadata;
    struct sxs_page_read_request request;
    struct sxs_page_result result;
    struct flashguard_read_response response = { .version = 1 };
    struct flashguard_shadow shadow;
    struct flashguard_oob live_oob;
    sxs_u8 page[SXS_WASM_MAX_PAGE_BYTES];
    sxs_u64 ppa;
    sxs_u64 timestamp;
    sxs_u32 retained;

    if (block_read_metadata(context, &metadata) != 0 ||
        sxs_command_read(0, &ppa, sizeof(ppa)) != 0) {
        sxs_completion_status_set(BLOCK_NVME_INVALID_FIELD);
        return 0;
    }
    if (flashguard_get_page_record(context, ppa, &retained,
                                   &timestamp, &shadow) != 0 || !retained) {
        sxs_completion_status_set(BLOCK_NVME_INVALID_FIELD);
        return 0;
    }
    request = (struct sxs_page_read_request) {
        .ppa = ppa,
        .page_offset = 0,
        .length = metadata.page_size,
        .oob_object_id = FLASHGUARD_OOB_OBJECT,
    };
    if (sxs_page_read(&request, page, metadata.page_size, &live_oob,
                      sizeof(live_oob), &result) != 0 || result.status != 0) {
        sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
        return 0;
    }
    response.data_length = metadata.page_size;
    response.ppa = ppa;
    response.lpn = live_oob.lpn;
    response.previous_ppa = live_oob.previous_ppa;
    response.retention_timestamp_ns = timestamp;
    response.flags = FLASHGUARD_RETAINED_FLAG;
    if (sxs_command_write(0, &response, sizeof(response)) != 0 ||
        sxs_command_write(sizeof(response), page,
                          response.data_length) != 0) {
        sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
        return 0;
    }
    sxs_completion_result_set(response.data_length);
    sxs_completion_status_set(BLOCK_NVME_SUCCESS);
    return result.latency_ns;
}

static sxs_u64 flashguard_condition(struct sxs_policy_context *context)
{
    switch (context->pair_id) {
    case FLASHGUARD_PAIR_LIST:
        return context->event.nvme.opcode == FLASHGUARD_ADMIN_LIST;
    case FLASHGUARD_PAIR_READ:
        return context->event.nvme.opcode == FLASHGUARD_ADMIN_READ;
    default:
        return 0;
    }
}

static sxs_u64 flashguard_action(struct sxs_policy_context *context)
{
    switch (context->pair_id) {
    case FLASHGUARD_PAIR_LIST:
        return flashguard_list(context);
    case FLASHGUARD_PAIR_READ:
        return flashguard_read_retained(context);
    default:
        return SXS_WASM_ACTION_ERROR;
    }
}

#endif /* SXS_FLASHGUARD_WASM_CORE_H */
