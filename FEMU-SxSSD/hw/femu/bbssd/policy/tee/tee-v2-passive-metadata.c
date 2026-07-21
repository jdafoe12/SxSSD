#include "tee-v2-passive-metadata.h"

#include <stdlib.h>
#include <string.h>

int tee_v2_passive_from_active(struct tee_v2_passive_metadata *passive,
                               const struct tee_v2_active_metadata *active)
{
    if (!passive || !active || !tee_v2_active_complete(active)) return -1;
    memset(passive, 0, sizeof(*passive));
    passive->segment_locations = malloc(sizeof(uint64_t) * active->segment_count);
    passive->groups = malloc(sizeof(*passive->groups) * active->group_count);
    if (!passive->segment_locations || !passive->groups) {
        tee_v2_passive_metadata_destroy(passive);
        return -1;
    }
    passive->file_id = active->file_id;
    passive->chunk_id = active->chunk_id;
    passive->chunk_size_bytes = active->chunk_size_bytes;
    passive->segment_count = active->segment_count;
    passive->number_coefficient = active->number_coefficient;
    passive->group_count = active->group_count;
    memcpy(passive->segment_locations, active->segment_locations,
           sizeof(uint64_t) * active->segment_count);
    memcpy(passive->groups, active->groups,
           sizeof(*passive->groups) * active->group_count);
    return 0;
}

void tee_v2_passive_metadata_destroy(struct tee_v2_passive_metadata *passive)
{
    if (!passive) return;
    free(passive->segment_locations);
    free(passive->groups);
    memset(passive, 0, sizeof(*passive));
}

bool tee_v2_passive_matches(const struct tee_v2_passive_metadata *passive,
                            uint8_t file_id, uint32_t chunk_id,
                            uint32_t segment_index)
{
    return passive && passive->file_id == file_id &&
           passive->chunk_id == chunk_id && segment_index > 0 &&
           segment_index <= passive->segment_count;
}
