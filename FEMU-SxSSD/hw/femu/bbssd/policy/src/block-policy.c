/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "block-policy.h"

#define BLOCK_PAIR_READ 1U
#define BLOCK_PAIR_WRITE 2U
#define BLOCK_PAIR_DSM 3U
#define BLOCK_PAIR_BACKGROUND_GC 4U

#define BLOCK_NVME_READ 0x02U
#define BLOCK_NVME_WRITE 0x01U
#define BLOCK_NVME_DSM 0x09U
#define BLOCK_MAX_DSM_PAGES 65536ULL
#define BLOCK_MAX_OOB_BYTES 256U
#define BLOCK_MAX_LOGICAL_PAGES 4194304U
#define BLOCK_MAX_ESWDS 256U

#define BLOCK_UNMAPPED (~0ULL)

enum block_eswd_class {
    BLOCK_ESWD_FREE = 0,
    BLOCK_ESWD_CURRENT = 1,
    BLOCK_ESWD_FULL = 2,
    BLOCK_ESWD_VICTIM = 3,
    BLOCK_ESWD_RECLAIMING = 4,
};

/* Zero is the unmapped encoding; mapped values are stored as value + 1. */
static sxs_u64 block_forward_map[BLOCK_MAX_LOGICAL_PAGES];
static sxs_u64 block_reverse_map[BLOCK_MAX_LOGICAL_PAGES];
static struct block_wasm_metadata block_metadata;
static sxs_u8 block_eswd_classes[BLOCK_MAX_ESWDS];
static sxs_u32 block_victim_heap[BLOCK_MAX_ESWDS];
static sxs_u32 block_victim_positions[BLOCK_MAX_ESWDS];
static sxs_s32 block_victim_valid_pages[BLOCK_MAX_ESWDS];
static sxs_u32 block_victim_count;

static void block_bytes_zero(sxs_u8 *destination, sxs_u32 length)
{
    for (sxs_u32 i = 0; i < length; i++) {
        destination[i] = 0;
    }
}

static sxs_s64 block_map_read(const sxs_u64 *map, sxs_u64 index,
                              sxs_u64 *value_out)
{
    sxs_u64 encoded;

    if (!value_out || index >= BLOCK_MAX_LOGICAL_PAGES) {
        return -SXS_WASM_EINVAL;
    }
    encoded = map[index];
    *value_out = encoded == 0 ? BLOCK_UNMAPPED : encoded - 1;
    return 0;
}

static sxs_s64 block_map_write(sxs_u64 *map, sxs_u64 index, sxs_u64 value)
{
    if (index >= BLOCK_MAX_LOGICAL_PAGES) {
        return -SXS_WASM_EINVAL;
    }
    map[index] = value == BLOCK_UNMAPPED ? 0 : value + 1;
    return 0;
}

static sxs_s64 block_state_read_class(struct sxs_policy_context *context,
                                      sxs_u32 eswd_id, sxs_u8 *class_out)
{
    (void)context;
    if (!class_out || eswd_id >= BLOCK_MAX_ESWDS) {
        return -SXS_WASM_EINVAL;
    }
    *class_out = block_eswd_classes[eswd_id];
    return 0;
}

static sxs_s64 block_state_write_class(struct sxs_policy_context *context,
                                       sxs_u32 eswd_id, sxs_u8 value)
{
    (void)context;
    if (eswd_id >= BLOCK_MAX_ESWDS) {
        return -SXS_WASM_EINVAL;
    }
    block_eswd_classes[eswd_id] = value;
    return 0;
}

sxs_s64 block_read_metadata(struct sxs_policy_context *context,
                            struct block_wasm_metadata *metadata_out)
{
    (void)context;
    if (!metadata_out) {
        return -SXS_WASM_EINVAL;
    }
    *metadata_out = block_metadata;
    return 0;
}

static sxs_s64 block_write_metadata(const struct block_wasm_metadata *metadata)
{
    if (!metadata) {
        return -SXS_WASM_EINVAL;
    }
    block_metadata = *metadata;
    return 0;
}

static sxs_s64 block_get_eswd(struct sxs_policy_context *context,
                              sxs_u32 eswd_id,
                              struct sxs_eswd *eswd_out)
{
    (void)context;
    return sxs_eswd_get(eswd_id, eswd_out);
}

static sxs_u32 block_victim_less(sxs_u32 left, sxs_u32 right)
{
    if (block_victim_valid_pages[left] != block_victim_valid_pages[right]) {
        return block_victim_valid_pages[left] <
               block_victim_valid_pages[right];
    }
    return left < right;
}

static void block_victim_swap(sxs_u32 left, sxs_u32 right)
{
    sxs_u32 temporary = block_victim_heap[left];

    block_victim_heap[left] = block_victim_heap[right];
    block_victim_heap[right] = temporary;
    block_victim_positions[block_victim_heap[left]] = left + 1;
    block_victim_positions[block_victim_heap[right]] = right + 1;
}

static void block_victim_sift_up(sxs_u32 index)
{
    while (index > 0) {
        sxs_u32 parent = (index - 1) / 2;

        if (!block_victim_less(block_victim_heap[index],
                               block_victim_heap[parent])) {
            break;
        }
        block_victim_swap(index, parent);
        index = parent;
    }
}

static void block_victim_sift_down(sxs_u32 index)
{
    for (;;) {
        sxs_u32 left = index * 2 + 1;
        sxs_u32 right = left + 1;
        sxs_u32 smallest = index;

        if (left < block_victim_count &&
            block_victim_less(block_victim_heap[left],
                              block_victim_heap[smallest])) {
            smallest = left;
        }
        if (right < block_victim_count &&
            block_victim_less(block_victim_heap[right],
                              block_victim_heap[smallest])) {
            smallest = right;
        }
        if (smallest == index) {
            break;
        }
        block_victim_swap(index, smallest);
        index = smallest;
    }
}

static sxs_s64 block_victim_remove(sxs_u32 eswd_id)
{
    sxs_u32 position;
    sxs_u32 index;

    if (eswd_id >= BLOCK_MAX_ESWDS) {
        return -SXS_WASM_EINVAL;
    }
    position = block_victim_positions[eswd_id];
    if (position == 0) {
        return 0;
    }
    index = position - 1;
    block_victim_count--;
    block_victim_positions[eswd_id] = 0;
    if (index == block_victim_count) {
        return 0;
    }
    block_victim_heap[index] = block_victim_heap[block_victim_count];
    block_victim_positions[block_victim_heap[index]] = index + 1;
    if (index > 0 &&
        block_victim_less(block_victim_heap[index],
                          block_victim_heap[(index - 1) / 2])) {
        block_victim_sift_up(index);
    } else {
        block_victim_sift_down(index);
    }
    return 0;
}

static sxs_s64 block_victim_update(sxs_u32 eswd_id, sxs_s32 valid_pages)
{
    sxs_u32 position;
    sxs_s32 previous;

    if (eswd_id >= BLOCK_MAX_ESWDS || valid_pages < 0) {
        return -SXS_WASM_EINVAL;
    }
    position = block_victim_positions[eswd_id];
    previous = block_victim_valid_pages[eswd_id];
    block_victim_valid_pages[eswd_id] = valid_pages;
    if (position == 0) {
        if (block_victim_count >= BLOCK_MAX_ESWDS) {
            return -SXS_WASM_ENOSPC;
        }
        block_victim_heap[block_victim_count] = eswd_id;
        block_victim_positions[eswd_id] = block_victim_count + 1;
        block_victim_sift_up(block_victim_count);
        block_victim_count++;
        return 0;
    }
    if (valid_pages < previous) {
        block_victim_sift_up(position - 1);
    } else if (valid_pages > previous) {
        block_victim_sift_down(position - 1);
    }
    return 0;
}

static sxs_s64 block_victim_refresh_eswd(
    struct sxs_policy_context *context,
    const struct block_wasm_metadata *metadata, sxs_u32 eswd_id)
{
    struct sxs_eswd eswd;
    sxs_u8 class_value;

    if (eswd_id >= metadata->total_eswds ||
        eswd_id == metadata->current_eswd) {
        return 0;
    }
    if (block_state_read_class(context, eswd_id, &class_value) != 0 ||
        block_get_eswd(context, eswd_id, &eswd) != 0) {
        return -SXS_WASM_EIO;
    }
    if ((class_value == BLOCK_ESWD_FULL ||
         class_value == BLOCK_ESWD_VICTIM) &&
        eswd.invalid_page_count > 0) {
        if (block_state_write_class(context, eswd_id,
                                    BLOCK_ESWD_VICTIM) != 0) {
            return -SXS_WASM_EIO;
        }
        return block_victim_update(eswd_id, eswd.valid_page_count);
    }
    return block_victim_remove(eswd_id);
}

static sxs_s64 block_victim_refresh_ppa(
    struct sxs_policy_context *context,
    const struct block_wasm_metadata *metadata, sxs_u64 ppa)
{
    struct sxs_eswd_location location;

    if (sxs_ppa_to_eswd(ppa, &location) != 0) {
        return -SXS_WASM_EIO;
    }
    return block_victim_refresh_eswd(context, metadata, location.eswd_id);
}

static sxs_s64 block_find_free_eswd(struct sxs_policy_context *context,
                                    const struct block_wasm_metadata *metadata,
                                    sxs_u32 *eswd_out)
{
    for (sxs_u32 id = 0; id < metadata->total_eswds; id++) {
        sxs_u8 class_value;

        if (block_state_read_class(context, id, &class_value) != 0) {
            return -SXS_WASM_EIO;
        }
        if (class_value == BLOCK_ESWD_FREE) {
            *eswd_out = id;
            return 0;
        }
    }
    return -SXS_WASM_ENOSPC;
}

static sxs_s64 block_rotate_if_full(struct sxs_policy_context *context,
                                    struct block_wasm_metadata *metadata)
{
    struct sxs_eswd current;
    sxs_u8 completed_class;
    sxs_u32 next;

    if (block_get_eswd(context, metadata->current_eswd, &current) != 0) {
        return -SXS_WASM_EIO;
    }
    if (current.write_page_index < metadata->pages_per_eswd) {
        return 0;
    }
    if (block_find_free_eswd(context, metadata, &next) != 0) {
        return -SXS_WASM_ENOSPC;
    }
    completed_class = current.invalid_page_count == 0 ? BLOCK_ESWD_FULL :
                                                        BLOCK_ESWD_VICTIM;
    if (block_state_write_class(context, metadata->current_eswd,
                                completed_class) != 0 ||
        (completed_class == BLOCK_ESWD_VICTIM &&
         block_victim_update(metadata->current_eswd,
                             current.valid_page_count) != 0) ||
        block_state_write_class(context, next, BLOCK_ESWD_CURRENT) != 0 ||
        block_victim_remove(next) != 0) {
        return -SXS_WASM_ENOSPC;
    }
    metadata->current_eswd = next;
    if (metadata->free_eswds == 0) {
        return -SXS_WASM_ENOSPC;
    }
    metadata->free_eswds--;
    return block_write_metadata(metadata);
}

static sxs_s64 block_page_read(sxs_u64 ppa, sxs_u8 *page,
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

static sxs_s64 block_page_append(struct sxs_policy_context *context,
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
    sxs_u8 oob[BLOCK_MAX_OOB_BYTES];
    sxs_u32 oob_length = 0;
    sxs_s64 rc;

    (void)context;
    (void)lpn;
    (void)old_ppa;
    if (block_variant_prepare_append(context, lpn, old_ppa, &request, oob,
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

static sxs_s64 block_update_mapping(struct sxs_policy_context *context,
                                    sxs_u64 lpn, sxs_u64 old_ppa,
                                    sxs_u64 new_ppa)
{
    sxs_u64 page_index;

    (void)context;
    if (old_ppa != BLOCK_UNMAPPED) {
        page_index = sxs_ppa_to_page_index(old_ppa);
        if ((sxs_s64)page_index >= 0 &&
            block_map_write(block_reverse_map, page_index,
                            BLOCK_UNMAPPED) != 0) {
            return -SXS_WASM_EIO;
        }
    }
    if (block_map_write(block_forward_map, lpn, new_ppa) != 0) {
        return -SXS_WASM_EIO;
    }
    if (new_ppa != BLOCK_UNMAPPED) {
        page_index = sxs_ppa_to_page_index(new_ppa);
        if ((sxs_s64)page_index < 0 ||
            block_map_write(block_reverse_map, page_index, lpn) != 0) {
            return -SXS_WASM_EIO;
        }
    }
    return 0;
}

static sxs_s64 block_select_victim(struct sxs_policy_context *context,
                                   const struct block_wasm_metadata *metadata,
                                   sxs_u32 force, sxs_u32 *victim_out)
{
    struct sxs_eswd eswd;
    sxs_u32 victim;

    if (block_victim_count == 0) {
        return -SXS_WASM_ENOENT;
    }
    victim = block_victim_heap[0];
    if (victim >= metadata->total_eswds ||
        block_get_eswd(context, victim, &eswd) != 0) {
        return -SXS_WASM_EIO;
    }
    if (!force && eswd.invalid_page_count <
                  (sxs_s32)(metadata->pages_per_eswd / 8)) {
        return -SXS_WASM_ENOENT;
    }
    if (block_victim_remove(victim) != 0) {
        return -SXS_WASM_EIO;
    }
    *victim_out = victim;
    return 0;
}

static sxs_s64 block_gc(struct sxs_policy_context *context,
                        struct block_wasm_metadata *metadata, sxs_u32 force)
{
    struct sxs_page_result result;
    sxs_u32 victim;

    if (block_select_victim(context, metadata, force, &victim) != 0 ||
        block_state_write_class(context, victim,
                                BLOCK_ESWD_RECLAIMING) != 0) {
        return -SXS_WASM_ENOENT;
    }
    for (sxs_u32 page_index = 0;
         page_index < metadata->pages_per_eswd; page_index++) {
        sxs_u64 source_ppa;
        sxs_u64 source_dense_index;
        sxs_u64 lpn = BLOCK_UNMAPPED;

        source_ppa = sxs_eswd_to_ppa(victim, page_index);
        if ((sxs_s64)source_ppa < 0) {
            continue;
        }
        if (sxs_page_status_get(source_ppa) != 2) {
            continue;
        }
        if (!block_variant_gc_should_migrate(context, source_ppa)) {
            continue;
        }
        if (block_rotate_if_full(context, metadata) != 0) {
            return -SXS_WASM_ENOSPC;
        }
        if (sxs_page_migrate(source_ppa, metadata->current_eswd,
                             &result) != 0 || result.status != 0) {
            return -SXS_WASM_EIO;
        }
        source_dense_index = sxs_ppa_to_page_index(source_ppa);
        if ((sxs_s64)source_dense_index >= 0 &&
            block_map_read(block_reverse_map, source_dense_index, &lpn) == 0 &&
            lpn != BLOCK_UNMAPPED && lpn < metadata->total_logical_pages) {
            if (block_update_mapping(context, lpn, source_ppa,
                                     result.ppa) != 0) {
                return -SXS_WASM_EIO;
            }
        }
        if (block_variant_gc_after_migrate(context, source_ppa, result.ppa,
                                           lpn) != 0) {
            return -SXS_WASM_EIO;
        }
    }
    if (block_variant_gc_before_erase(context, victim, metadata) != 0) {
        return -SXS_WASM_EIO;
    }
    sxs_eswd_erase(victim);
    if (sxs_eswd_reset(victim) != 0 ||
        block_state_write_class(context, victim, BLOCK_ESWD_FREE) != 0) {
        return -SXS_WASM_EIO;
    }
    metadata->free_eswds++;
    if (block_write_metadata(metadata) != 0) {
        return -SXS_WASM_EIO;
    }
    return 0;
}

static sxs_u64 block_read_action(struct sxs_policy_context *context,
                                 struct block_wasm_metadata *metadata)
{
    sxs_u8 page[SXS_WASM_MAX_PAGE_BYTES];
    sxs_u64 maximum_latency = 0;
    sxs_u64 end_lba = context->event.nvme.lba +
                      context->event.nvme.nsecs;
    sxs_u64 current_lba = context->event.nvme.lba;

    if (end_lba < current_lba) {
        sxs_completion_status_set(BLOCK_NVME_INVALID_FIELD);
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
            block_map_read(block_forward_map, lpn, &ppa) != 0) {
            sxs_completion_status_set(BLOCK_NVME_INVALID_FIELD);
            return 0;
        }
        block_bytes_zero(page, metadata->page_size);
        if (ppa != BLOCK_UNMAPPED &&
            sxs_ppa_validate(ppa) == 1 &&
            block_page_read(ppa, page, metadata->page_size, &latency) != 0) {
            sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (ppa != BLOCK_UNMAPPED &&
            block_variant_on_page_read(context, lpn, ppa) != 0) {
            sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
            return 0;
        }
        host_offset = (current_lba - context->event.nvme.lba) *
                      metadata->sector_size;
        bytes = (sxs_u64)sectors * metadata->sector_size;
        if (sxs_request_write(host_offset,
                              page + page_sector * metadata->sector_size,
                              bytes) != 0) {
            sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (latency > maximum_latency) {
            maximum_latency = latency;
        }
        current_lba += sectors;
    }
    sxs_completion_status_set(BLOCK_NVME_SUCCESS);
    return maximum_latency;
}

static sxs_u64 block_write_action(struct sxs_policy_context *context,
                                  struct block_wasm_metadata *metadata)
{
    sxs_u8 page[SXS_WASM_MAX_PAGE_BYTES];
    sxs_u64 maximum_latency = 0;
    sxs_u64 end_lba = context->event.nvme.lba +
                      context->event.nvme.nsecs;
    sxs_u64 current_lba = context->event.nvme.lba;

    if (end_lba < current_lba) {
        sxs_completion_status_set(BLOCK_NVME_INVALID_FIELD);
        return 0;
    }
    if (metadata->free_eswds <= metadata->gc_urgent_watermark) {
        block_gc(context, metadata, 1);
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

        if (sectors > end_lba - current_lba) {
            sectors = end_lba - current_lba;
        }
        if (lpn >= metadata->total_logical_pages ||
            block_map_read(block_forward_map, lpn, &old_ppa) != 0 ||
            block_rotate_if_full(context, metadata) != 0) {
            sxs_completion_status_set(BLOCK_NVME_INVALID_FIELD);
            return 0;
        }
        block_bytes_zero(page, metadata->page_size);
        if (old_ppa != BLOCK_UNMAPPED &&
            sxs_ppa_validate(old_ppa) == 1 &&
            block_page_read(old_ppa, page, metadata->page_size,
                            &ignored_read_latency) != 0) {
            sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
            return 0;
        }
        host_offset = (current_lba - context->event.nvme.lba) *
                      metadata->sector_size;
        bytes = (sxs_u64)sectors * metadata->sector_size;
        if (sxs_request_read(host_offset,
                             page + page_sector * metadata->sector_size,
                             bytes) != 0 ||
            block_page_append(context, lpn, old_ppa,
                              metadata->current_eswd,
                              metadata->page_size, page, &new_ppa,
                              &latency) != 0) {
            sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (old_ppa != BLOCK_UNMAPPED) {
            if (block_variant_handle_old_page(context, lpn, old_ppa) != 0 ||
                block_victim_refresh_ppa(context, metadata,
                                         old_ppa) != 0) {
                sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
                return 0;
            }
        }
        if (block_update_mapping(context, lpn, old_ppa, new_ppa) != 0) {
            sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (block_variant_after_new_page(context, lpn, old_ppa, new_ppa) !=
            0) {
            sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (latency > maximum_latency) {
            maximum_latency = latency;
        }
        current_lba += sectors;
    }
    if (block_rotate_if_full(context, metadata) != 0 &&
        metadata->free_eswds == 0) {
        /* The data is committed; background GC may recover space next. */
    }
    sxs_completion_status_set(BLOCK_NVME_SUCCESS);
    return maximum_latency;
}

static sxs_u64 block_dsm_action(struct sxs_policy_context *context,
                                struct block_wasm_metadata *metadata)
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
            sxs_completion_status_set(BLOCK_NVME_INTERNAL_ERROR);
            return 0;
        }
        if (range.lba_count == 0) {
            continue;
        }
        end_lba = range.start_lba + range.lba_count - 1;
        if (end_lba < range.start_lba) {
            sxs_completion_status_set(BLOCK_NVME_INVALID_FIELD);
            return 0;
        }
        first_lpn = range.start_lba / metadata->sectors_per_page;
        last_lpn = end_lba / metadata->sectors_per_page;
        pages = last_lpn - first_lpn + 1;
        if (first_lpn >= metadata->total_logical_pages ||
            last_lpn >= metadata->total_logical_pages ||
            pages > BLOCK_MAX_DSM_PAGES - total_pages) {
            sxs_completion_status_set(BLOCK_NVME_INVALID_FIELD);
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
                block_map_read(block_forward_map, lpn, &ppa) != 0 ||
                ppa == BLOCK_UNMAPPED) {
                continue;
            }
            if (block_variant_handle_old_page(context, lpn, ppa) != 0 ||
                block_victim_refresh_ppa(context, metadata, ppa) != 0) {
                return SXS_WASM_ACTION_ERROR;
            }
            if (block_update_mapping(context, lpn, ppa,
                                     BLOCK_UNMAPPED) != 0) {
                return SXS_WASM_ACTION_ERROR;
            }
        }
    }
    sxs_completion_status_set(BLOCK_NVME_SUCCESS);
    return 0;
}

static sxs_u64 block_policy_init(struct sxs_policy_context *context)
{
    struct sxs_geometry geometry;
    struct block_wasm_metadata metadata;
    struct sxs_eswd_config eswd_config;
    struct sxs_namespace_config namespace_config;
    sxs_u64 total_eswds;
    sxs_u64 page_size;

    if (sxs_geometry_get(&geometry) != 0 || geometry.total_luns == 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    total_eswds = geometry.total_blocks_log / geometry.total_luns;
    page_size = (sxs_u64)geometry.sectors_per_page * geometry.sector_size;
    if (total_eswds < 2 || total_eswds > BLOCK_MAX_ESWDS ||
        geometry.total_pages_log > BLOCK_MAX_LOGICAL_PAGES ||
        page_size == 0 || page_size > SXS_WASM_MAX_PAGE_BYTES) {
        return SXS_WASM_ACTION_ERROR;
    }
    metadata = (struct block_wasm_metadata) {
        .total_logical_pages = geometry.total_pages_log,
        .total_eswds = total_eswds,
        .pages_per_eswd = geometry.total_luns * geometry.pages_per_block,
        .sectors_per_page = geometry.sectors_per_page,
        .sector_size = geometry.sector_size,
        .page_size = page_size,
        .current_eswd = 0,
        .free_eswds = total_eswds - 1,
        .gc_low_watermark = total_eswds / 4 ? total_eswds / 4 : 1,
        .gc_urgent_watermark = total_eswds / 20 ? total_eswds / 20 : 1,
    };
    block_victim_count = 0;
    for (sxs_u32 id = 0; id < BLOCK_MAX_ESWDS; id++) {
        block_victim_positions[id] = 0;
        block_victim_valid_pages[id] = 0;
    }
    if (block_write_metadata(&metadata) != 0 ||
        block_state_write_class(context, 0, BLOCK_ESWD_CURRENT) != 0) {
        return SXS_WASM_ACTION_ERROR;
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
        sxs_subscribe(SXS_EVENT_NVME_IO, BLOCK_NVME_READ,
                      BLOCK_PAIR_READ, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_IO, BLOCK_NVME_WRITE,
                      BLOCK_PAIR_WRITE, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_NVME_IO, BLOCK_NVME_DSM,
                      BLOCK_PAIR_DSM, 0) != 0 ||
        sxs_subscribe(SXS_EVENT_BACKGROUND, 0,
                      BLOCK_PAIR_BACKGROUND_GC, 0) != 0 ||
        block_variant_init(context, &geometry, &metadata) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    return 0;
}

static sxs_u64 block_policy_condition(struct sxs_policy_context *context)
{
    struct block_wasm_metadata metadata;

    switch (context->pair_id) {
    case BLOCK_PAIR_READ:
        return context->event.nvme.opcode == BLOCK_NVME_READ;
    case BLOCK_PAIR_WRITE:
        return context->event.nvme.opcode == BLOCK_NVME_WRITE;
    case BLOCK_PAIR_DSM:
        return context->event.nvme.opcode == BLOCK_NVME_DSM;
    case BLOCK_PAIR_BACKGROUND_GC:
        if (block_read_metadata(context, &metadata) != 0) {
            return 0;
        }
        return metadata.free_eswds <= metadata.gc_low_watermark;
    default:
        return block_variant_condition(context);
    }
}

static sxs_u64 block_policy_action(struct sxs_policy_context *context)
{
    struct block_wasm_metadata metadata;

    if (block_read_metadata(context, &metadata) != 0) {
        return SXS_WASM_ACTION_ERROR;
    }
    switch (context->pair_id) {
    case BLOCK_PAIR_READ:
        return block_read_action(context, &metadata);
    case BLOCK_PAIR_WRITE:
        return block_write_action(context, &metadata);
    case BLOCK_PAIR_DSM:
        return block_dsm_action(context, &metadata);
    case BLOCK_PAIR_BACKGROUND_GC:
        block_gc(context, &metadata, 0);
        return 0;
    default:
        return block_variant_action(context);
    }
}

SXS_EXPORT_INIT
sxs_s32 sxs_policy_init(void)
{
    struct sxs_policy_context context;
    sxs_s32 result = sxs_context_get(&context);

    return result == 0 ? (sxs_s32)block_policy_init(&context) : result;
}

SXS_EXPORT_CONDITION
sxs_s32 sxs_policy_condition(sxs_u32 pair_id)
{
    struct sxs_policy_context context;
    sxs_s32 result = sxs_context_get(&context);

    if (result != 0 || context.pair_id != pair_id) {
        return result != 0 ? result : -SXS_WASM_EINVAL;
    }
    return (sxs_s32)block_policy_condition(&context);
}

SXS_EXPORT_ACTION
sxs_u64 sxs_policy_action(sxs_u32 pair_id)
{
    struct sxs_policy_context context;

    if (sxs_context_get(&context) != 0 || context.pair_id != pair_id) {
        return SXS_WASM_ACTION_ERROR;
    }
    return block_policy_action(&context);
}
