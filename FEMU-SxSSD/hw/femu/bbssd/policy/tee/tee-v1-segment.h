#ifndef TEE_V1_SEGMENT_H
#define TEE_V1_SEGMENT_H

#include <stdbool.h>
#include <stdint.h>

#define TEE_V1_SEGMENT_SIZE_BYTES 512U
#define TEE_V1_DEFAULT_HIDDEN_LBAS 4096ULL

struct tee_v1_segment_layout {
    uint64_t total_lbas;
    uint64_t visible_lbas;
    uint64_t hidden_start_lba;
    uint64_t hidden_lba_count;
    uint64_t visible_segments;
    uint32_t lba_size;
};

bool tee_v1_segment_layout_init(struct tee_v1_segment_layout *layout,
                                uint64_t total_lbas,
                                uint32_t lba_size,
                                uint64_t requested_hidden_lbas);
bool tee_v1_lba_range_touches_hidden(const struct tee_v1_segment_layout *layout,
                                     uint64_t slba,
                                     uint64_t nlb);
bool tee_v1_lba_range_to_segments(const struct tee_v1_segment_layout *layout,
                                  uint64_t slba,
                                  uint64_t nlb,
                                  uint64_t *first_segment,
                                  uint64_t *segment_count);

#endif
