#include "tee-v5-status.h"

#include "../femu_policy.h"

uint16_t tee_v5_nvme_status_for_policy(enum tee_v5_status status)
{
    return status == TEE_V5_STATUS_INTERNAL_ERROR ?
        NVME_INTERNAL_DEV_ERROR : NVME_SUCCESS;
}
