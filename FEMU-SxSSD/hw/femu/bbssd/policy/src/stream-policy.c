/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "policy-wasm-abi.h"

#define STREAM_PAIR_READ 1U
#define STREAM_PAIR_WRITE 2U
#define STREAM_PAIR_DSM 3U
#define STREAM_PAIR_BACKGROUND_GC 4U

#define STREAM_NVME_READ 0x02U
#define STREAM_NVME_WRITE 0x01U
#define STREAM_NVME_DSM 0x09U
#define STREAM_NVME_SUCCESS 0x0000U
#define STREAM_NVME_INVALID_FIELD 0x4002U
#define STREAM_NVME_INTERNAL_ERROR 0x4006U
#define STREAM_MAX_DSM_PAGES 65536ULL
#define STREAM_MAX_OOB_BYTES 256U
#define STREAM_MAX_LOGICAL_PAGES 4194304U
#define STREAM_MAX_ESWDS 256U
#define STREAM_MAX_PLACEMENT_STREAMS 4U

#ifndef STREAM_PLACEMENT_STREAMS
#define STREAM_PLACEMENT_STREAMS 1U
#endif

#if STREAM_PLACEMENT_STREAMS < 1 || \
    STREAM_PLACEMENT_STREAMS > STREAM_MAX_PLACEMENT_STREAMS
#error "STREAM_PLACEMENT_STREAMS must be between 1 and 4"
#endif

#define STREAM_UNMAPPED (~0ULL)

enum stream_eswd_class {
    STREAM_ESWD_FREE = 0,
    STREAM_ESWD_CURRENT = 1,
    STREAM_ESWD_FULL = 2,
    STREAM_ESWD_VICTIM = 3,
    STREAM_ESWD_RECLAIMING = 4,
};

struct stream_wasm_metadata {
    sxs_u64 total_logical_pages;
    sxs_u32 total_eswds;
    sxs_u32 pages_per_eswd;
    sxs_u32 sectors_per_page;
    sxs_u32 sector_size;
    sxs_u32 page_size;
    sxs_u32 current_eswds[STREAM_MAX_PLACEMENT_STREAMS];
    sxs_u32 free_eswds;
    sxs_u32 gc_low_watermark;
    sxs_u32 gc_urgent_watermark;
};

/* Zero is the unmapped encoding; mapped values are stored as value + 1. */
static sxs_u64 stream_forward_map[STREAM_MAX_LOGICAL_PAGES];
static sxs_u64 stream_reverse_map[STREAM_MAX_LOGICAL_PAGES];
static struct stream_wasm_metadata stream_metadata;
static sxs_u8 stream_eswd_classes[STREAM_MAX_ESWDS];
static sxs_u32 stream_victim_heap[STREAM_MAX_ESWDS];
static sxs_u32 stream_victim_positions[STREAM_MAX_ESWDS];
static sxs_s32 stream_victim_valid_pages[STREAM_MAX_ESWDS];
static sxs_u32 stream_victim_count;

/*
 * The stream policies classify fixed-size logical regions.  The benchmark's
 * region size equals one eSWD, so region N is assigned to stream
 * N modulo STREAM_PLACEMENT_STREAMS.  The one-stream artifact is the control
 * for this independent policy implementation.
 */
static sxs_u32 stream_placement_stream(
    const struct stream_wasm_metadata *metadata, sxs_u64 lpn)
{
    if (lpn == STREAM_UNMAPPED || metadata->pages_per_eswd == 0) {
        return 0;
    }
    return (lpn / metadata->pages_per_eswd) % STREAM_PLACEMENT_STREAMS;
}

static sxs_u32 stream_eswd_is_current(
    const struct stream_wasm_metadata *metadata, sxs_u32 eswd_id)
{
    for (sxs_u32 stream = 0; stream < STREAM_PLACEMENT_STREAMS; stream++) {
        if (metadata->current_eswds[stream] == eswd_id) {
            return 1;
        }
    }
    return 0;
}

/* Compile-time extensions preserve direct condition/action control flow. */
#ifndef STREAM_EXTRA_INIT
#define STREAM_EXTRA_INIT(context, geometry, metadata) 0
#endif
#ifndef STREAM_EXTRA_CONDITION
#define STREAM_EXTRA_CONDITION(context) 0
#endif
#ifndef STREAM_EXTRA_ACTION
#define STREAM_EXTRA_ACTION(context) SXS_WASM_ACTION_ERROR
#endif
#ifndef STREAM_PREPARE_APPEND
#define STREAM_PREPARE_APPEND(context, lpn, old_ppa, request, oob, oob_length) 0
#endif
#ifndef STREAM_HANDLE_OLD_PAGE
#define STREAM_HANDLE_OLD_PAGE(context, lpn, old_ppa) \
    sxs_page_invalidate((old_ppa))
#endif
#ifndef STREAM_AFTER_NEW_PAGE
#define STREAM_AFTER_NEW_PAGE(context, lpn, old_ppa, new_ppa) 0
#endif
#ifndef STREAM_ON_PAGE_READ
#define STREAM_ON_PAGE_READ(context, lpn, ppa) 0
#endif
#ifndef STREAM_GC_SHOULD_MIGRATE
#define STREAM_GC_SHOULD_MIGRATE(context, ppa) 1
#endif
#ifndef STREAM_GC_AFTER_MIGRATE
#define STREAM_GC_AFTER_MIGRATE(context, old_ppa, new_ppa, lpn) 0
#endif
#ifndef STREAM_GC_BEFORE_ERASE
#define STREAM_GC_BEFORE_ERASE(context, victim, metadata) 0
#endif

static void stream_bytes_zero(sxs_u8 *destination, sxs_u32 length)
{
    for (sxs_u32 i = 0; i < length; i++) {
        destination[i] = 0;
    }
}

static sxs_s64 stream_map_read(const sxs_u64 *map, sxs_u64 index,
                              sxs_u64 *value_out)
{
    sxs_u64 encoded;

    if (!value_out || index >= STREAM_MAX_LOGICAL_PAGES) {
        return -SXS_WASM_EINVAL;
    }
    encoded = map[index];
    *value_out = encoded == 0 ? STREAM_UNMAPPED : encoded - 1;
    return 0;
}

static sxs_s64 stream_map_write(sxs_u64 *map, sxs_u64 index, sxs_u64 value)
{
    if (index >= STREAM_MAX_LOGICAL_PAGES) {
        return -SXS_WASM_EINVAL;
    }
    map[index] = value == STREAM_UNMAPPED ? 0 : value + 1;
    return 0;
}

static sxs_s64 stream_state_read_class(struct sxs_policy_context *context,
                                      sxs_u32 eswd_id, sxs_u8 *class_out)
{
    (void)context;
    if (!class_out || eswd_id >= STREAM_MAX_ESWDS) {
        return -SXS_WASM_EINVAL;
    }
    *class_out = stream_eswd_classes[eswd_id];
    return 0;
}

static sxs_s64 stream_state_write_class(struct sxs_policy_context *context,
                                       sxs_u32 eswd_id, sxs_u8 value)
{
    (void)context;
    if (eswd_id >= STREAM_MAX_ESWDS) {
        return -SXS_WASM_EINVAL;
    }
    stream_eswd_classes[eswd_id] = value;
    return 0;
}

static sxs_s64 stream_read_metadata(struct sxs_policy_context *context,
                                   struct stream_wasm_metadata *metadata_out)
{
    (void)context;
    if (!metadata_out) {
        return -SXS_WASM_EINVAL;
    }
    *metadata_out = stream_metadata;
    return 0;
}

static sxs_s64 stream_write_metadata(const struct stream_wasm_metadata *metadata)
{
    if (!metadata) {
        return -SXS_WASM_EINVAL;
    }
    stream_metadata = *metadata;
    return 0;
}

static sxs_s64 stream_get_eswd(struct sxs_policy_context *context,
                              sxs_u32 eswd_id,
                              struct sxs_eswd *eswd_out)
{
    (void)context;
    return sxs_eswd_get(eswd_id, eswd_out);
}

static sxs_u32 stream_victim_less(sxs_u32 left, sxs_u32 right)
{
    if (stream_victim_valid_pages[left] != stream_victim_valid_pages[right]) {
        return stream_victim_valid_pages[left] <
               stream_victim_valid_pages[right];
    }
    return left < right;
}

static void stream_victim_swap(sxs_u32 left, sxs_u32 right)
{
    sxs_u32 temporary = stream_victim_heap[left];

    stream_victim_heap[left] = stream_victim_heap[right];
    stream_victim_heap[right] = temporary;
    stream_victim_positions[stream_victim_heap[left]] = left + 1;
    stream_victim_positions[stream_victim_heap[right]] = right + 1;
}

static void stream_victim_sift_up(sxs_u32 index)
{
    while (index > 0) {
        sxs_u32 parent = (index - 1) / 2;

        if (!stream_victim_less(stream_victim_heap[index],
                               stream_victim_heap[parent])) {
            break;
        }
        stream_victim_swap(index, parent);
        index = parent;
    }
}

static void stream_victim_sift_down(sxs_u32 index)
{
    for (;;) {
        sxs_u32 left = index * 2 + 1;
        sxs_u32 right = left + 1;
        sxs_u32 smallest = index;

        if (left < stream_victim_count &&
            stream_victim_less(stream_victim_heap[left],
                              stream_victim_heap[smallest])) {
            smallest = left;
        }
        if (right < stream_victim_count &&
            stream_victim_less(stream_victim_heap[right],
                              stream_victim_heap[smallest])) {
            smallest = right;
        }
        if (smallest == index) {
            break;
        }
        stream_victim_swap(index, smallest);
        index = smallest;
    }
}

static sxs_s64 stream_victim_remove(sxs_u32 eswd_id)
{
    sxs_u32 position;
    sxs_u32 index;

    if (eswd_id >= STREAM_MAX_ESWDS) {
        return -SXS_WASM_EINVAL;
    }
    position = stream_victim_positions[eswd_id];
    if (position == 0) {
        return 0;
    }
    index = position - 1;
    stream_victim_count--;
    stream_victim_positions[eswd_id] = 0;
    if (index == stream_victim_count) {
        return 0;
    }
    stream_victim_heap[index] = stream_victim_heap[stream_victim_count];
    stream_victim_positions[stream_victim_heap[index]] = index + 1;
    if (index > 0 &&
        stream_victim_less(stream_victim_heap[index],
                          stream_victim_heap[(index - 1) / 2])) {
        stream_victim_sift_up(index);
    } else {
        stream_victim_sift_down(index);
    }
    return 0;
}

static sxs_s64 stream_victim_update(sxs_u32 eswd_id, sxs_s32 valid_pages)
{
    sxs_u32 position;
    sxs_s32 previous;

    if (eswd_id >= STREAM_MAX_ESWDS || valid_pages < 0) {
        return -SXS_WASM_EINVAL;
    }
    position = stream_victim_positions[eswd_id];
    previous = stream_victim_valid_pages[eswd_id];
    stream_victim_valid_pages[eswd_id] = valid_pages;
    if (position == 0) {
        if (stream_victim_count >= STREAM_MAX_ESWDS) {
            return -SXS_WASM_ENOSPC;
        }
        stream_victim_heap[stream_victim_count] = eswd_id;
        stream_victim_positions[eswd_id] = stream_victim_count + 1;
        stream_victim_sift_up(stream_victim_count);
        stream_victim_count++;
        return 0;
    }
    if (valid_pages < previous) {
        stream_victim_sift_up(position - 1);
    } else if (valid_pages > previous) {
        stream_victim_sift_down(position - 1);
    }
    return 0;
}

static sxs_s64 stream_victim_refresh_eswd(
    struct sxs_policy_context *context,
    const struct stream_wasm_metadata *metadata, sxs_u32 eswd_id)
{
    struct sxs_eswd eswd;
    sxs_u8 class_value;

    if (eswd_id >= metadata->total_eswds ||
        stream_eswd_is_current(metadata, eswd_id)) {
        return 0;
    }
    if (stream_state_read_class(context, eswd_id, &class_value) != 0 ||
        stream_get_eswd(context, eswd_id, &eswd) != 0) {
        return -SXS_WASM_EIO;
    }
    if ((class_value == STREAM_ESWD_FULL ||
         class_value == STREAM_ESWD_VICTIM) &&
        eswd.invalid_page_count > 0) {
        if (stream_state_write_class(context, eswd_id,
                                    STREAM_ESWD_VICTIM) != 0) {
            return -SXS_WASM_EIO;
        }
        return stream_victim_update(eswd_id, eswd.valid_page_count);
    }
    return stream_victim_remove(eswd_id);
}

static sxs_s64 stream_victim_refresh_ppa(
    struct sxs_policy_context *context,
    const struct stream_wasm_metadata *metadata, sxs_u64 ppa)
{
    struct sxs_eswd_location location;

    if (sxs_ppa_to_eswd(ppa, &location) != 0) {
        return -SXS_WASM_EIO;
    }
    return stream_victim_refresh_eswd(context, metadata, location.eswd_id);
}

static sxs_s64 stream_find_free_eswd(struct sxs_policy_context *context,
                                    const struct stream_wasm_metadata *metadata,
                                    sxs_u32 *eswd_out)
{
    for (sxs_u32 id = 0; id < metadata->total_eswds; id++) {
        sxs_u8 class_value;

        if (stream_state_read_class(context, id, &class_value) != 0) {
            return -SXS_WASM_EIO;
        }
        if (class_value == STREAM_ESWD_FREE) {
            *eswd_out = id;
            return 0;
        }
    }
    return -SXS_WASM_ENOSPC;
}

static sxs_s64 stream_rotate_if_full(struct sxs_policy_context *context,
                                    struct stream_wasm_metadata *metadata,
                                    sxs_u32 stream)
{
    struct sxs_eswd current;
    sxs_u8 completed_class;
    sxs_u32 next;

    if (stream >= STREAM_PLACEMENT_STREAMS ||
        stream_get_eswd(context, metadata->current_eswds[stream],
                       &current) != 0) {
        return -SXS_WASM_EIO;
    }
    if (current.write_page_index < metadata->pages_per_eswd) {
        return 0;
    }
    if (stream_find_free_eswd(context, metadata, &next) != 0) {
        return -SXS_WASM_ENOSPC;
    }
    completed_class = current.invalid_page_count == 0 ? STREAM_ESWD_FULL :
                                                        STREAM_ESWD_VICTIM;
    if (stream_state_write_class(context, metadata->current_eswds[stream],
                                completed_class) != 0 ||
        (completed_class == STREAM_ESWD_VICTIM &&
         stream_victim_update(metadata->current_eswds[stream],
                             current.valid_page_count) != 0) ||
        stream_state_write_class(context, next, STREAM_ESWD_CURRENT) != 0 ||
        stream_victim_remove(next) != 0) {
        return -SXS_WASM_ENOSPC;
    }
    metadata->current_eswds[stream] = next;
    if (metadata->free_eswds == 0) {
        return -SXS_WASM_ENOSPC;
    }
    metadata->free_eswds--;
    return stream_write_metadata(metadata);
}

static sxs_s64 stream_page_read(sxs_u64 ppa, sxs_u8 *page,
                               sxs_u32 page_size, sxs_u64 *latency_out)
{
    struct sxs_page_read_request request = {
        .ppa = ppa,
        .page_offset = 0,
        .length = page_size,
        .oob_object_id = 0,
    };
    struct sxs_page_result result;
    sxs_s64 rc;

    rc = sxs_page_read(&request, page, page_size, 0, 0, &result);
    if (rc == 0 && result.status == 0) {
        *latency_out = result.latency_ns;
        return 0;
    }
    return -SXS_WASM_EIO;
}

static sxs_s64 stream_page_append(struct sxs_policy_context *context,
                                 sxs_u64 lpn, sxs_u64 old_ppa,
                                 sxs_u32 eswd_id, sxs_u32 page_size,
                                 const sxs_u8 *page,
                                 sxs_u64 *ppa_out, sxs_u64 *latency_out)
{
    struct sxs_page_append_request request = {
        .eswd_id = eswd_id,
        .oob_object_id = 0,
    };
    struct sxs_page_result result;
    sxs_u8 oob[STREAM_MAX_OOB_BYTES];
    sxs_u32 oob_length = 0;
    sxs_s64 rc;

    (void)context;
    (void)lpn;
    (void)old_ppa;
    if (STREAM_PREPARE_APPEND(context, lpn, old_ppa, &request, oob,
                             &oob_length) != 0 ||
        oob_length > sizeof(oob)) {
        return -SXS_WASM_EIO;
    }
    rc = sxs_page_append(&request, page, page_size,
                         oob_length ? oob : 0, oob_length, &result);
    if (rc == 0 && result.status == 0) {
        *ppa_out = result.ppa;
        *latency_out = result.latency_ns;
        return 0;
    }
    return -SXS_WASM_EIO;
}

static sxs_s64 stream_update_mapping(struct sxs_policy_context *context,
                                    sxs_u64 lpn, sxs_u64 old_ppa,
                                    sxs_u64 new_ppa)
{
    sxs_u64 page_index;

    (void)context;
    if (old_ppa != STREAM_UNMAPPED) {
        page_index = sxs_ppa_to_page_index(old_ppa);
        if ((sxs_s64)page_index >= 0 &&
            stream_map_write(stream_reverse_map, page_index,
                            STREAM_UNMAPPED) != 0) {
            return -SXS_WASM_EIO;
        }
    }
    if (stream_map_write(stream_forward_map, lpn, new_ppa) != 0) {
        return -SXS_WASM_EIO;
    }
    if (new_ppa != STREAM_UNMAPPED) {
        page_index = sxs_ppa_to_page_index(new_ppa);
        if ((sxs_s64)page_index < 0 ||
            stream_map_write(stream_reverse_map, page_index, lpn) != 0) {
            return -SXS_WASM_EIO;
        }
    }
    return 0;
}

static sxs_s64 stream_select_victim(struct sxs_policy_context *context,
                                   const struct stream_wasm_metadata *metadata,
                                   sxs_u32 force, sxs_u32 *victim_out)
{
    struct sxs_eswd eswd;
    sxs_u32 victim;

    if (stream_victim_count == 0) {
        return -SXS_WASM_ENOENT;
    }
    victim = stream_victim_heap[0];
    if (victim >= metadata->total_eswds ||
        stream_get_eswd(context, victim, &eswd) != 0) {
        return -SXS_WASM_EIO;
    }
    if (!force && eswd.invalid_page_count <
                  (sxs_s32)(metadata->pages_per_eswd / 8)) {
        return -SXS_WASM_ENOENT;
    }
    if (stream_victim_remove(victim) != 0) {
        return -SXS_WASM_EIO;
    }
    *victim_out = victim;
    return 0;
}

static sxs_s64 stream_gc(struct sxs_policy_context *context,
                        struct stream_wasm_metadata *metadata, sxs_u32 force)
{
    struct sxs_page_result result;
    sxs_u32 victim;

    if (stream_select_victim(context, metadata, force, &victim) != 0 ||
        stream_state_write_class(context, victim,
                                STREAM_ESWD_RECLAIMING) != 0) {
        return -SXS_WASM_ENOENT;
    }
    for (sxs_u32 page_index = 0;
         page_index < metadata->pages_per_eswd; page_index++) {
        sxs_u64 source_ppa;
        sxs_u64 source_dense_index;
        sxs_u64 lpn = STREAM_UNMAPPED;
        sxs_u32 stream;

        source_ppa = sxs_eswd_to_ppa(victim, page_index);
        if ((sxs_s64)source_ppa < 0) {
            continue;
        }
        if (sxs_page_status_get(source_ppa) != 2) {
            continue;
        }
        if (!STREAM_GC_SHOULD_MIGRATE(context, source_ppa)) {
            continue;
        }
        source_dense_index = sxs_ppa_to_page_index(source_ppa);
        if ((sxs_s64)source_dense_index >= 0) {
            stream_map_read(stream_reverse_map, source_dense_index, &lpn);
        }
        stream = stream_placement_stream(metadata, lpn);
        if (stream_rotate_if_full(context, metadata, stream) != 0) {
            return -SXS_WASM_ENOSPC;
        }
        if (sxs_page_migrate(source_ppa, metadata->current_eswds[stream],
                             &result) != 0 || result.status != 0) {
            return -SXS_WASM_EIO;
        }
        if ((sxs_s64)source_dense_index >= 0 &&
            lpn != STREAM_UNMAPPED && lpn < metadata->total_logical_pages) {
            if (stream_update_mapping(context, lpn, source_ppa,
                                     result.ppa) != 0) {
                return -SXS_WASM_EIO;
            }
        }
        if (STREAM_GC_AFTER_MIGRATE(context, source_ppa, result.ppa,
                                   lpn) != 0) {
            return -SXS_WASM_EIO;
        }
    }
    if (STREAM_GC_BEFORE_ERASE(context, victim, metadata) != 0) {
        return -SXS_WASM_EIO;
    }
    sxs_eswd_erase(victim);
    if (sxs_eswd_reset(victim) != 0 ||
        stream_state_write_class(context, victim, STREAM_ESWD_FREE) != 0) {
        return -SXS_WASM_EIO;
    }
    metadata->free_eswds++;
    if (stream_write_metadata(metadata) != 0) {
        return -SXS_WASM_EIO;
    }
    return 0;
}

static sxs_u64 stream_read_action(struct sxs_policy_context *context,
                                 struct stream_wasm_metadata *metadata)
{
    sxs_u8 page[SXS_WASM_MAX_PAGE_BYTES];
    sxs_u64 maximum_latency = 0;
    sxs_u64 end_lba = context->event.nvme.lba +
                      context->event.nvme.nsecs;
    sxs_u64 current_lba = context->event.nvme.lba;

    if (end_lba < current_lba) {
        sxs_completion_status_set(STREAM_NVME_INVALID_FIELD);
        return 0;
    }
    while (current_lba < end_lba) {
        sxs_u64 lpn = current_lba / metadata->sectors_per_page;
        sxs_u32 page_sector = current_lba % metadata->sectors_per_page;
        sxs_u32 sectors = metadata->sectors_per_page - page_sector;
        sxs_u64 ppa;
        sxs_u64 latency = 0;
        sxs_u64 host_offset;
        sxs_u64 bytes;

        if (sectors > end_lba - current_lba) {
            sectors = end_lba - current_lba;
        }
        if (lpn >= metadata->total_logical_pages ||
            stream_map_read(stream_forward_map, lpn, &ppa) != 0) {
            sxs_completion_status_set(STREAM_NVME_INVALID_FIELD);
            return 0;
        }
        stream_bytes_zero(page, metadata->page_size);
        if (ppa != STREAM_UNMAPPED &&
            sxs_ppa_validate(ppa) == 1 &&
            stream_page_read(ppa, page, metadata->page_size, &latency) != 0) {
            sxs_completion_status_set(STREAM_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (ppa != STREAM_UNMAPPED &&
            STREAM_ON_PAGE_READ(context, lpn, ppa) != 0) {
            sxs_completion_status_set(STREAM_NVME_INTERNAL_ERROR);
            return 0;
        }
        host_offset = (current_lba - context->event.nvme.lba) *
                      metadata->sector_size;
        bytes = (sxs_u64)sectors * metadata->sector_size;
        if (sxs_request_write(host_offset,
                              page + page_sector * metadata->sector_size,
                              bytes) != 0) {
            sxs_completion_status_set(STREAM_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (latency > maximum_latency) {
            maximum_latency = latency;
        }
        current_lba += sectors;
    }
    sxs_completion_status_set(STREAM_NVME_SUCCESS);
    return maximum_latency;
}

static sxs_u64 stream_write_action(struct sxs_policy_context *context,
                                  struct stream_wasm_metadata *metadata)
{
    sxs_u8 page[SXS_WASM_MAX_PAGE_BYTES];
    sxs_u64 maximum_latency = 0;
    sxs_u64 end_lba = context->event.nvme.lba +
                      context->event.nvme.nsecs;
    sxs_u64 current_lba = context->event.nvme.lba;
    sxs_u32 last_stream = 0;

    if (end_lba < current_lba) {
        sxs_completion_status_set(STREAM_NVME_INVALID_FIELD);
        return 0;
    }
    if (metadata->free_eswds <= metadata->gc_urgent_watermark) {
        stream_gc(context, metadata, 1);
    }
    while (current_lba < end_lba) {
        sxs_u64 lpn = current_lba / metadata->sectors_per_page;
        sxs_u32 page_sector = current_lba % metadata->sectors_per_page;
        sxs_u32 sectors = metadata->sectors_per_page - page_sector;
        sxs_u64 old_ppa;
        sxs_u64 new_ppa;
        sxs_u64 latency = 0;
        sxs_u64 ignored_read_latency = 0;
        sxs_u64 host_offset;
        sxs_u64 bytes;
        sxs_u32 stream;

        if (sectors > end_lba - current_lba) {
            sectors = end_lba - current_lba;
        }
        stream = stream_placement_stream(metadata, lpn);
        last_stream = stream;
        if (lpn >= metadata->total_logical_pages ||
            stream_map_read(stream_forward_map, lpn, &old_ppa) != 0 ||
            stream_rotate_if_full(context, metadata, stream) != 0) {
            sxs_completion_status_set(STREAM_NVME_INVALID_FIELD);
            return 0;
        }
        stream_bytes_zero(page, metadata->page_size);
        if (old_ppa != STREAM_UNMAPPED &&
            sxs_ppa_validate(old_ppa) == 1 &&
            stream_page_read(old_ppa, page, metadata->page_size,
                            &ignored_read_latency) != 0) {
            sxs_completion_status_set(STREAM_NVME_INTERNAL_ERROR);
            return 0;
        }
        host_offset = (current_lba - context->event.nvme.lba) *
                      metadata->sector_size;
        bytes = (sxs_u64)sectors * metadata->sector_size;
        if (sxs_request_read(host_offset,
                             page + page_sector * metadata->sector_size,
                             bytes) != 0 ||
            stream_page_append(context, lpn, old_ppa,
                              metadata->current_eswds[stream],
                              metadata->page_size, page, &new_ppa,
                              &latency) != 0) {
            sxs_completion_status_set(STREAM_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (old_ppa != STREAM_UNMAPPED) {
            if (STREAM_HANDLE_OLD_PAGE(context, lpn, old_ppa) != 0 ||
                stream_victim_refresh_ppa(context, metadata,
                                         old_ppa) != 0) {
                sxs_completion_status_set(STREAM_NVME_INTERNAL_ERROR);
                return 0;
            }
        }
        if (stream_update_mapping(context, lpn, old_ppa, new_ppa) != 0) {
            sxs_completion_status_set(STREAM_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (STREAM_AFTER_NEW_PAGE(context, lpn, old_ppa, new_ppa) != 0) {
            sxs_completion_status_set(STREAM_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (latency > maximum_latency) {
            maximum_latency = latency;
        }
        current_lba += sectors;
    }
    if (stream_rotate_if_full(context, metadata, last_stream) != 0 &&
        metadata->free_eswds == 0) {
        /* The data is committed; background GC may recover space next. */
    }
    sxs_completion_status_set(STREAM_NVME_SUCCESS);
    return maximum_latency;
}

static sxs_u64 stream_dsm_action(struct sxs_policy_context *context,
                                struct stream_wasm_metadata *metadata)
{
    struct sxs_dsm_range range;
    sxs_u64 total_pages = 0;

    /* Validate the complete request before applying any irreversible trim. */
    for (sxs_u32 range_index = 0; range_index < 256; range_index++) {
        sxs_s64 rc = sxs_dsm_range_get(range_index, &range);
        sxs_u64 end_lba;
        sxs_u64 first_lpn;
        sxs_u64 last_lpn;
        sxs_u64 pages;

        if (rc == -SXS_WASM_ENOENT) {
            break;
        }
        if (rc != 0) {
            sxs_completion_status_set(STREAM_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (range.lba_count == 0) {
            continue;
        }
        end_lba = range.start_lba + range.lba_count - 1;
        if (end_lba < range.start_lba) {
            sxs_completion_status_set(STREAM_NVME_INVALID_FIELD);
            return 0;
        }
        first_lpn = range.start_lba / metadata->sectors_per_page;
        last_lpn = end_lba / metadata->sectors_per_page;
        pages = last_lpn - first_lpn + 1;
        if (first_lpn >= metadata->total_logical_pages ||
            last_lpn >= metadata->total_logical_pages ||
            pages > STREAM_MAX_DSM_PAGES - total_pages) {
            sxs_completion_status_set(STREAM_NVME_INVALID_FIELD);
            return 0;
        }
        total_pages += pages;
    }

    for (sxs_u32 range_index = 0; range_index < 256; range_index++) {
        sxs_s64 rc = sxs_dsm_range_get(range_index, &range);
        sxs_u64 end_lba;
        sxs_u64 start_lpn;
        sxs_u64 end_lpn;

        if (rc == -SXS_WASM_ENOENT) {
            break;
        }
        if (rc != 0 || range.lba_count == 0) {
            continue;
        }
        end_lba = range.start_lba + range.lba_count - 1;
        if (end_lba < range.start_lba) {
            continue;
        }
        start_lpn = range.start_lba / metadata->sectors_per_page;
        end_lpn = end_lba / metadata->sectors_per_page;
        for (sxs_u64 lpn = start_lpn; lpn <= end_lpn; lpn++) {
            sxs_u64 ppa;

            if (lpn >= metadata->total_logical_pages ||
                stream_map_read(stream_forward_map, lpn, &ppa) != 0 ||
                ppa == STREAM_UNMAPPED) {
                continue;
            }
            if (STREAM_HANDLE_OLD_PAGE(context, lpn, ppa) != 0 ||
                stream_victim_refresh_ppa(context, metadata, ppa) != 0) {
                return SXS_WASM_ACTION_ERROR;
            }
            if (stream_update_mapping(context, lpn, ppa,
                                     STREAM_UNMAPPED) != 0) {
                return SXS_WASM_ACTION_ERROR;
            }
        }
    }
    sxs_completion_status_set(STREAM_NVME_SUCCESS);
    return 0;
}

static sxs_u64 stream_policy_init(struct sxs_policy_context *context)
{
    struct sxs_geometry geometry;
    struct stream_wasm_metadata metadata;
    struct sxs_eswd_config eswd_config;
    struct sxs_namespace_config namespace_config;
    sxs_u64 total_eswds;
    sxs_u64 page_size;

    if (sxs_geometry_get(&geometry) != 0 || geometry.total_luns == 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    total_eswds = geometry.total_blocks_log / geometry.total_luns;
    page_size = (sxs_u64)geometry.sectors_per_page * geometry.sector_size;
    if (total_eswds <= STREAM_PLACEMENT_STREAMS ||
        total_eswds > STREAM_MAX_ESWDS ||
        geometry.total_pages_log > STREAM_MAX_LOGICAL_PAGES ||
        page_size == 0 || page_size > SXS_WASM_MAX_PAGE_BYTES) {
        return SXS_WASM_ACTION_ERROR;
    }
    metadata = (struct stream_wasm_metadata) {
        .total_logical_pages = geometry.total_pages_log,
        .total_eswds = total_eswds,
        .pages_per_eswd = geometry.total_luns * geometry.pages_per_block,
        .sectors_per_page = geometry.sectors_per_page,
        .sector_size = geometry.sector_size,
        .page_size = page_size,
        .free_eswds = total_eswds - STREAM_PLACEMENT_STREAMS,
        .gc_low_watermark = total_eswds / 4 ? total_eswds / 4 : 1,
        .gc_urgent_watermark = total_eswds / 20 ? total_eswds / 20 : 1,
    };
    stream_victim_count = 0;
    for (sxs_u32 id = 0; id < STREAM_MAX_ESWDS; id++) {
        stream_victim_positions[id] = 0;
        stream_victim_valid_pages[id] = 0;
    }
    for (sxs_u32 stream = 0; stream < STREAM_PLACEMENT_STREAMS; stream++) {
        metadata.current_eswds[stream] = stream;
    }
    if (stream_write_metadata(&metadata) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    for (sxs_u32 id = 0; id < metadata.total_eswds; id++) {
        sxs_u8 class_value = id < STREAM_PLACEMENT_STREAMS ?
                             STREAM_ESWD_CURRENT : STREAM_ESWD_FREE;

        if (stream_state_write_class(context, id, class_value) != 0) {
            return SXS_WASM_ACTION_ERROR;
        }
    }

    eswd_config.striping_level = 0;
    eswd_config.blocks_per_eswd = geometry.total_luns;
    namespace_config.csi = 0;
    namespace_config.noiob = 0;
    namespace_config.nsze = geometry.total_pages_log *
                            geometry.sectors_per_page;
    namespace_config.ncap = namespace_config.nsze;
    namespace_config.nuse = namespace_config.ncap;
    namespace_config.namespace_blob_length = 0;
    namespace_config.controller_blob_length = 0;
    if (sxs_eswd_config_stage(&eswd_config) != 0 ||
        sxs_namespace_config_stage(&namespace_config) != 0 ||
        sxs_eswd_layout_finalize_stage() != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_IO, STREAM_NVME_READ,
                      STREAM_PAIR_READ, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_IO, STREAM_NVME_WRITE,
                      STREAM_PAIR_WRITE, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_IO, STREAM_NVME_DSM,
                      STREAM_PAIR_DSM, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_BACKGROUND, 0,
                      STREAM_PAIR_BACKGROUND_GC, 0) != 0 ||
        STREAM_EXTRA_INIT(context, &geometry, &metadata) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    return 0;
}

static sxs_u64 stream_policy_condition(struct sxs_policy_context *context)
{
    struct stream_wasm_metadata metadata;

    switch (context->pair_id) {
    case STREAM_PAIR_READ:
        return context->event.nvme.opcode == STREAM_NVME_READ;
    case STREAM_PAIR_WRITE:
        return context->event.nvme.opcode == STREAM_NVME_WRITE;
    case STREAM_PAIR_DSM:
        return context->event.nvme.opcode == STREAM_NVME_DSM;
    case STREAM_PAIR_BACKGROUND_GC:
        if (stream_read_metadata(context, &metadata) != 0) {
            return 0;
        }
        return metadata.free_eswds <= metadata.gc_low_watermark;
    default:
        return STREAM_EXTRA_CONDITION(context);
    }
}

static sxs_u64 stream_policy_action(struct sxs_policy_context *context)
{
    struct stream_wasm_metadata metadata;

    if (stream_read_metadata(context, &metadata) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    switch (context->pair_id) {
    case STREAM_PAIR_READ:
        return stream_read_action(context, &metadata);
    case STREAM_PAIR_WRITE:
        return stream_write_action(context, &metadata);
    case STREAM_PAIR_DSM:
        return stream_dsm_action(context, &metadata);
    case STREAM_PAIR_BACKGROUND_GC:
        stream_gc(context, &metadata, 0);
        return 0;
    default:
        return STREAM_EXTRA_ACTION(context);
    }
}

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    struct sxs_policy_context context;
    sxs_s32 result = sxs_context_get(&context);

    return result == 0 ? (sxs_s32)stream_policy_init(&context) : result;
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;
    sxs_s32 result = sxs_context_get(&context);

    if (result != 0 || context.pair_id != pair_id) {
        return result != 0 ? result : -SXS_WASM_EINVAL;
    }
    return (sxs_s32)stream_policy_condition(&context);
}

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 || context.pair_id != pair_id) {
        return SXS_WASM_ACTION_ERROR;
    }
    return stream_policy_action(&context);
}
