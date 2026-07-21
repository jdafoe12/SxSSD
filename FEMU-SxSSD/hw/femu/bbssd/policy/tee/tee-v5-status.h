#ifndef TEE_V5_STATUS_H
#define TEE_V5_STATUS_H

#include <stdint.h>

enum tee_v5_status {
    TEE_V5_STATUS_OK = 0,
    TEE_V5_STATUS_NOT_FOUND = 1,
    TEE_V5_STATUS_BAD_REQUEST = 2,
    TEE_V5_STATUS_NO_PENDING_RESPONSE = 3,
    TEE_V5_STATUS_INTERNAL_ERROR = 4,
    TEE_V5_STATUS_BAD_MAC = 5,
    TEE_V5_STATUS_MALFORMED = 6,
    TEE_V5_STATUS_UNSUPPORTED = 7
};

uint16_t tee_v5_nvme_status_for_policy(enum tee_v5_status status);

#endif
