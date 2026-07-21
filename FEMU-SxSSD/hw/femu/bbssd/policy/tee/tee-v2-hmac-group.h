#ifndef TEE_V2_HMAC_GROUP_H
#define TEE_V2_HMAC_GROUP_H

#include "tee-v2-active-metadata.h"

#include <stddef.h>
#include <stdint.h>

#define TEE_V2_PROTOTYPE_KEY_SIZE 32U

extern const uint8_t tee_v2_prototype_key[TEE_V2_PROTOTYPE_KEY_SIZE];

enum tee_v2_hmac_result {
    TEE_V2_HMAC_NOT_READY = 0,
    TEE_V2_HMAC_VERIFIED = 1,
    TEE_V2_HMAC_REUSED = 2,
    TEE_V2_HMAC_FAILED = -1
};

void tee_v2_hmac_sha256(const uint8_t *key, size_t key_size,
                        const uint8_t *data, size_t data_size,
                        uint8_t output[TEE_V2_HMAC_SIZE]);
enum tee_v2_hmac_result tee_v2_verify_hmac_group(
    struct tee_v2_active_metadata *active,
    struct tee_v2_hmac_group_state *group,
    const uint8_t *key, size_t key_size);

#endif
