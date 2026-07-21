#ifndef TEE_V1_GUARD_H
#define TEE_V1_GUARD_H

#include "tee-v1-bitmap.h"
#include "tee-v1-segment.h"
#include "../femu_policy.h"

#include <stdint.h>

uint16_t tee_v1_check_user_lba_range(const struct tee_v1_segment_layout *layout,
                                     uint64_t slba,
                                     uint64_t nlb);
uint16_t tee_v1_check_write_allowed(const struct tee_v1_segment_layout *layout,
                                    const struct tee_v1_bitmap *protected_bitmap,
                                    const struct tee_v1_bitmap *pending_bitmap,
                                    uint64_t slba,
                                    uint64_t nlb);

#endif
