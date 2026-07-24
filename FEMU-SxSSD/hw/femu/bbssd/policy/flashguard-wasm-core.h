#ifndef SXS_FLASHGUARD_WASM_CORE_H
#define SXS_FLASHGUARD_WASM_CORE_H

#include "policy-wasm-abi.h"

#define FLASHGUARD_READ_BITMAP_OBJECT 10U
#define FLASHGUARD_RETAINED_BITMAP_OBJECT 11U
#define FLASHGUARD_TIMESTAMP_OBJECT 12U
#define FLASHGUARD_OOB_SHADOW_OBJECT 13U
#define FLASHGUARD_SETTINGS_OBJECT 14U
#define FLASHGUARD_RETAINED_LIST_OBJECT 15U
#define FLASHGUARD_RETAINED_POSITION_OBJECT 16U
#define FLASHGUARD_OOB_OBJECT 1U

#define FLASHGUARD_PAIR_LIST 10U
#define FLASHGUARD_PAIR_READ 11U
#define FLASHGUARD_ADMIN_LIST 0xe0U
#define FLASHGUARD_ADMIN_READ 0xe1U
#define FLASHGUARD_MAX_LIST_ENTRIES 128U
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

static sxs_s64 flashguard_state_read(struct sxs_policy_context *context,
                                     sxs_u32 object_id, sxs_u64 index,
                                     void *value, sxs_u32 length)
{
    (void)context;
    return sxs_state_read(object_id, index, 0, value, length);
}

static sxs_s64 flashguard_state_write(struct sxs_policy_context *context,
                                      sxs_u32 object_id, sxs_u64 index,
                                      const void *value, sxs_u32 length)
{
    (void)context;
    return sxs_state_write(object_id, index, 0, value, length);
}

static sxs_s64 flashguard_page_index(sxs_u64 ppa, sxs_u64 *index_out)
{
    sxs_u64 index = sxs_ppa_to_page_index(ppa);

    if ((sxs_s64)index < 0) {
        return -SXS_WASM_EINVAL;
    }
    *index_out = index;
    return 0;
}

static sxs_s64 flashguard_bitmap_get(struct sxs_policy_context *context,
                                     sxs_u32 object_id, sxs_u64 page_index,
                                     sxs_u32 *set_out)
{
    sxs_u8 value;
    sxs_s64 result = flashguard_state_read(context, object_id,
                                           page_index >> 3, &value, 1);

    if (result == 0) {
        *set_out = (value & (1U << (page_index & 7))) != 0;
    }
    return result;
}

static sxs_s64 flashguard_bitmap_set(struct sxs_policy_context *context,
                                     sxs_u32 object_id, sxs_u64 page_index,
                                     sxs_u32 set)
{
    sxs_u8 value;
    sxs_s64 result = flashguard_state_read(context, object_id,
                                           page_index >> 3, &value, 1);

    if (result != 0) {
        return result;
    }
    if (set) {
        value |= 1U << (page_index & 7);
    } else {
        value &= ~(1U << (page_index & 7));
    }
    return flashguard_state_write(context, object_id, page_index >> 3,
                                  &value, 1);
}

static sxs_s64 flashguard_retained_add(struct sxs_policy_context *context,
                                       sxs_u64 ppa, sxs_u64 page_index)
{
    struct flashguard_settings settings;
    sxs_u32 position;
    sxs_u32 retained;

    if (flashguard_bitmap_get(context, FLASHGUARD_RETAINED_BITMAP_OBJECT,
                              page_index, &retained) != 0) {
        return -SXS_WASM_EIO;
    }
    if (retained) {
        return 0;
    }
    if (flashguard_state_read(context, FLASHGUARD_SETTINGS_OBJECT, 0,
                              &settings, sizeof(settings)) != 0 ||
        settings.retained_count >= settings.physical_pages) {
        return -SXS_WASM_ENOSPC;
    }
    if (settings.retained_count >= 0xffffffffULL) {
        return -SXS_WASM_ENOSPC;
    }
    position = (sxs_u32)settings.retained_count + 1;
    if (flashguard_state_write(context, FLASHGUARD_RETAINED_LIST_OBJECT,
                               settings.retained_count, &ppa,
                               sizeof(ppa)) != 0 ||
        flashguard_state_write(context, FLASHGUARD_RETAINED_POSITION_OBJECT,
                               page_index, &position,
                               sizeof(position)) != 0 ||
        flashguard_bitmap_set(context, FLASHGUARD_RETAINED_BITMAP_OBJECT,
                              page_index, 1) != 0) {
        return -SXS_WASM_EIO;
    }
    settings.retained_count++;
    return flashguard_state_write(context, FLASHGUARD_SETTINGS_OBJECT, 0,
                                  &settings, sizeof(settings));
}

static sxs_s64 flashguard_retained_remove(struct sxs_policy_context *context,
                                          sxs_u64 page_index)
{
    struct flashguard_settings settings;
    sxs_u32 position;
    sxs_u64 last_ppa;
    sxs_u64 last_page_index;
    sxs_u64 zero = 0;
    sxs_u32 zero_position = 0;
    sxs_u32 retained;

    if (flashguard_bitmap_get(context, FLASHGUARD_RETAINED_BITMAP_OBJECT,
                              page_index, &retained) != 0) {
        return -SXS_WASM_EIO;
    }
    if (!retained) {
        return 0;
    }
    if (flashguard_state_read(context, FLASHGUARD_SETTINGS_OBJECT, 0,
                              &settings, sizeof(settings)) != 0 ||
        flashguard_state_read(context,
                              FLASHGUARD_RETAINED_POSITION_OBJECT,
                              page_index, &position, sizeof(position)) != 0 ||
        position == 0 || position > settings.retained_count ||
        settings.retained_count == 0) {
        return -SXS_WASM_EIO;
    }
    position--;
    settings.retained_count--;
    if (position != settings.retained_count) {
        sxs_u32 moved_position = position + 1;

        if (flashguard_state_read(context, FLASHGUARD_RETAINED_LIST_OBJECT,
                                  settings.retained_count, &last_ppa,
                                  sizeof(last_ppa)) != 0 ||
            flashguard_page_index(last_ppa, &last_page_index) != 0 ||
            flashguard_state_write(context, FLASHGUARD_RETAINED_LIST_OBJECT,
                                   position, &last_ppa,
                                   sizeof(last_ppa)) != 0 ||
            flashguard_state_write(
                context, FLASHGUARD_RETAINED_POSITION_OBJECT,
                last_page_index, &moved_position,
                sizeof(moved_position)) != 0) {
            return -SXS_WASM_EIO;
        }
    }
    if (flashguard_state_write(context, FLASHGUARD_RETAINED_LIST_OBJECT,
                               settings.retained_count, &zero,
                               sizeof(zero)) != 0 ||
        flashguard_state_write(context,
                               FLASHGUARD_RETAINED_POSITION_OBJECT,
                               page_index, &zero_position,
                               sizeof(zero_position)) != 0 ||
        flashguard_bitmap_set(context, FLASHGUARD_RETAINED_BITMAP_OBJECT,
                              page_index, 0) != 0 ||
        flashguard_state_write(context, FLASHGUARD_SETTINGS_OBJECT, 0,
                               &settings, sizeof(settings)) != 0) {
        return -SXS_WASM_EIO;
    }
    return 0;
}

static sxs_s64 flashguard_clear_tracking(struct sxs_policy_context *context,
                                         sxs_u64 page_index)
{
    sxs_u64 zero = 0;

    if (flashguard_bitmap_set(context, FLASHGUARD_READ_BITMAP_OBJECT,
                              page_index, 0) != 0 ||
        flashguard_retained_remove(context, page_index) != 0 ||
        flashguard_state_write(context, FLASHGUARD_TIMESTAMP_OBJECT,
                               page_index, &zero, sizeof(zero)) != 0) {
        return -SXS_WASM_EIO;
    }
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
    sxs_u64 bitmap_bytes = (geometry->total_pages_log + 7) / 8;

    (void)metadata;
    if (bitmap_bytes == 0 ||
        sxs_state_create(FLASHGUARD_READ_BITMAP_OBJECT, 1,
                         bitmap_bytes, 0, 0) != 0 ||
        sxs_state_create(FLASHGUARD_RETAINED_BITMAP_OBJECT, 1,
                         bitmap_bytes, 0, 0) != 0 ||
        sxs_state_create(FLASHGUARD_TIMESTAMP_OBJECT, sizeof(sxs_u64),
                         geometry->total_pages_log, 0, 0) != 0 ||
        sxs_state_create(FLASHGUARD_OOB_SHADOW_OBJECT,
                         sizeof(struct flashguard_shadow),
                         geometry->total_pages_log, 0, 0) != 0 ||
        sxs_state_create(FLASHGUARD_RETAINED_LIST_OBJECT, sizeof(sxs_u64),
                         geometry->total_pages_log, 0, 0) != 0 ||
        sxs_state_create(FLASHGUARD_RETAINED_POSITION_OBJECT,
                         sizeof(sxs_u32), geometry->total_pages_log,
                         0, 0) != 0 ||
        sxs_state_create(FLASHGUARD_SETTINGS_OBJECT, sizeof(settings),
                         1, 0, 0) != 0) {
        return -SXS_WASM_ENOSPC;
    }
    if (!(context->flags & SXS_FLAG_STATE_RESTORED) &&
        flashguard_state_write(context, FLASHGUARD_SETTINGS_OBJECT,
                               0, &settings, sizeof(settings)) != 0) {
        return -SXS_WASM_EIO;
    }
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
        flashguard_bitmap_get(context, FLASHGUARD_READ_BITMAP_OBJECT,
                              page_index, &was_read) != 0) {
        return -SXS_WASM_EIO;
    }
    if (was_read) {
        if (flashguard_retained_add(context, old_ppa, page_index) != 0 ||
            flashguard_state_read(context, FLASHGUARD_TIMESTAMP_OBJECT,
                                  page_index, &timestamp,
                                  sizeof(timestamp)) != 0) {
            return -SXS_WASM_EIO;
        }
        if (timestamp == 0) {
            timestamp = sxs_time_now_ns();
            return flashguard_state_write(context,
                                          FLASHGUARD_TIMESTAMP_OBJECT,
                                          page_index, &timestamp,
                                          sizeof(timestamp));
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
    return flashguard_state_write(context, FLASHGUARD_OOB_SHADOW_OBJECT,
                                  page_index, &shadow, sizeof(shadow));
}

static sxs_s64 flashguard_on_page_read(struct sxs_policy_context *context,
                                       sxs_u64 lpn, sxs_u64 ppa)
{
    sxs_u64 page_index;

    (void)lpn;
    if (flashguard_page_index(ppa, &page_index) != 0) {
        return -SXS_WASM_EIO;
    }
    return flashguard_bitmap_set(context, FLASHGUARD_READ_BITMAP_OBJECT,
                                 page_index, 1);
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
        flashguard_bitmap_get(context, FLASHGUARD_RETAINED_BITMAP_OBJECT,
                              page_index, &retained) != 0 || !retained) {
        return 1;
    }
    if (flashguard_state_read(context, FLASHGUARD_TIMESTAMP_OBJECT,
                              page_index, &timestamp, sizeof(timestamp)) != 0 ||
        flashguard_state_read(context, FLASHGUARD_SETTINGS_OBJECT,
                              0, &settings, sizeof(settings)) != 0 ||
        timestamp == 0 || settings.retention_window_ns == 0) {
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
        flashguard_bitmap_get(context, FLASHGUARD_READ_BITMAP_OBJECT,
                              old_index, &was_read) != 0 ||
        flashguard_bitmap_get(context, FLASHGUARD_RETAINED_BITMAP_OBJECT,
                              old_index, &retained) != 0 ||
        flashguard_state_read(context, FLASHGUARD_TIMESTAMP_OBJECT,
                              old_index, &timestamp, sizeof(timestamp)) != 0 ||
        flashguard_state_read(context, FLASHGUARD_OOB_SHADOW_OBJECT,
                              old_index, &shadow, sizeof(shadow)) != 0 ||
        flashguard_clear_tracking(context, old_index) != 0 ||
        flashguard_clear_tracking(context, new_index) != 0 ||
        flashguard_bitmap_set(context, FLASHGUARD_READ_BITMAP_OBJECT,
                              new_index, was_read) != 0 ||
        flashguard_state_write(context, FLASHGUARD_TIMESTAMP_OBJECT,
                               new_index, &timestamp, sizeof(timestamp)) != 0 ||
        flashguard_state_write(context, FLASHGUARD_OOB_SHADOW_OBJECT,
                               new_index, &shadow, sizeof(shadow)) != 0) {
        return -SXS_WASM_EIO;
    }
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

    if (flashguard_page_index(ppa, &page_index) != 0 ||
        flashguard_bitmap_get(context, FLASHGUARD_RETAINED_BITMAP_OBJECT,
                              page_index, retained_out) != 0) {
        return -SXS_WASM_EIO;
    }
    if (!*retained_out) {
        *timestamp_out = 0;
        *shadow_out = (struct flashguard_shadow) {0};
        return 0;
    }
    if (flashguard_state_read(context, FLASHGUARD_TIMESTAMP_OBJECT,
                              page_index, timestamp_out,
                              sizeof(*timestamp_out)) != 0 ||
        flashguard_state_read(context, FLASHGUARD_OOB_SHADOW_OBJECT,
                              page_index, shadow_out,
                              sizeof(*shadow_out)) != 0) {
        return -SXS_WASM_EIO;
    }
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
    if (flashguard_state_read(context, FLASHGUARD_SETTINGS_OBJECT, 0,
                              &settings, sizeof(settings)) != 0 ||
        settings.retained_count > 0xffffffffULL) {
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

        if (flashguard_state_read(context, FLASHGUARD_RETAINED_LIST_OBJECT,
                                  ordinal, &ppa, sizeof(ppa)) != 0 ||
            flashguard_get_page_record(context, ppa, &retained,
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
