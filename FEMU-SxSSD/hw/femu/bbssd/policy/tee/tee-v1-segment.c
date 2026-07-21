#include "tee-v1-segment.h"

#include <limits.h>
#include <stddef.h>

static bool range_overflows(uint64_t start, uint64_t count)
{
    return count > 0 && start > UINT64_MAX - count;
}

bool tee_v1_segment_layout_init(struct tee_v1_segment_layout *layout,
                                uint64_t total_lbas,
                                uint32_t lba_size,
                                uint64_t requested_hidden_lbas)
{
    uint64_t hidden_lbas = requested_hidden_lbas;

    if (!layout || lba_size != TEE_V1_SEGMENT_SIZE_BYTES || total_lbas == 0) {
        return false;
    }

    if (hidden_lbas >= total_lbas) {
        hidden_lbas = 0;
    }

    layout->total_lbas = total_lbas;
    layout->hidden_lba_count = hidden_lbas;
    layout->visible_lbas = total_lbas - hidden_lbas;
    layout->hidden_start_lba = layout->visible_lbas;
    layout->visible_segments = layout->visible_lbas;
    layout->lba_size = lba_size;

    return true;
}

bool tee_v1_lba_range_touches_hidden(const struct tee_v1_segment_layout *layout,
                                     uint64_t slba,
                                     uint64_t nlb)
{
    if (!layout || nlb == 0 || range_overflows(slba, nlb)) {
        return true;
    }

    return slba >= layout->hidden_start_lba ||
           slba + nlb > layout->hidden_start_lba;
}

bool tee_v1_lba_range_to_segments(const struct tee_v1_segment_layout *layout,
                                  uint64_t slba,
                                  uint64_t nlb,
                                  uint64_t *first_segment,
                                  uint64_t *segment_count)
{
    if (!layout || !first_segment || !segment_count ||
        tee_v1_lba_range_touches_hidden(layout, slba, nlb)) {
        return false;
    }

    *first_segment = slba;
    *segment_count = nlb;
    return true;
}
