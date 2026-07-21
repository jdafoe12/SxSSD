#include "tee-v1-guard.h"

uint16_t tee_v1_check_user_lba_range(const struct tee_v1_segment_layout *layout,
                                     uint64_t slba,
                                     uint64_t nlb)
{
    if (tee_v1_lba_range_touches_hidden(layout, slba, nlb)) {
        return NVME_LBA_RANGE | NVME_DNR;
    }

    return NVME_SUCCESS;
}

uint16_t tee_v1_check_write_allowed(const struct tee_v1_segment_layout *layout,
                                    const struct tee_v1_bitmap *protected_bitmap,
                                    const struct tee_v1_bitmap *pending_bitmap,
                                    uint64_t slba,
                                    uint64_t nlb)
{
    uint64_t first_segment = 0;
    uint64_t segment_count = 0;

    if (!tee_v1_lba_range_to_segments(layout, slba, nlb,
                                      &first_segment, &segment_count)) {
        return NVME_LBA_RANGE | NVME_DNR;
    }

    if (tee_v1_bitmap_any_set(protected_bitmap, first_segment, segment_count) ||
        tee_v1_bitmap_any_set(pending_bitmap, first_segment, segment_count)) {
        return NVME_INVALID_FIELD | NVME_DNR;
    }

    return NVME_SUCCESS;
}
