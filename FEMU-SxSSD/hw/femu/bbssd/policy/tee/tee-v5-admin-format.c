#include "tee-v5-admin-format.h"

bool tee_v5_chunk_identity_payload_valid(
    const struct tee_v5_chunk_identity_payload *identity,
    size_t payload_bytes)
{
    return identity && payload_bytes == sizeof(*identity) &&
        identity->reserved[0] == 0 && identity->reserved[1] == 0 &&
        identity->reserved[2] == 0 && identity->chunk_id <= 0x00ffffffU;
}
