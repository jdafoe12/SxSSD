#ifndef TEE_V5_ADMIN_FORMAT_H
#define TEE_V5_ADMIN_FORMAT_H

#include "tee-v4-admin-format.h"

enum tee_v5_admin_command_type {
    TEE_V5_ADMIN_CMD_DELETE = 7,
    TEE_V5_ADMIN_CMD_ABORT_ACTIVE = 8
};

#pragma pack(push, 1)
struct tee_v5_chunk_identity_payload {
    uint8_t file_id;
    uint8_t reserved[3];
    uint32_t chunk_id;
};
#pragma pack(pop)

#define TEE_V5_CHUNK_IDENTITY_PAYLOAD_SIZE \
    ((uint32_t)sizeof(struct tee_v5_chunk_identity_payload))

bool tee_v5_chunk_identity_payload_valid(
    const struct tee_v5_chunk_identity_payload *identity,
    size_t payload_bytes);

#endif
