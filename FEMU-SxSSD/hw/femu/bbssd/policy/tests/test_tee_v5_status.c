#include "../tee/tee-v5-status.h"

#include "../femu_policy.h"

#include <assert.h>
#include <stdio.h>

static void test_policy_status_values_are_wire_stable(void)
{
    assert(TEE_V5_STATUS_OK == 0);
    assert(TEE_V5_STATUS_NOT_FOUND == 1);
    assert(TEE_V5_STATUS_BAD_REQUEST == 2);
    assert(TEE_V5_STATUS_NO_PENDING_RESPONSE == 3);
    assert(TEE_V5_STATUS_INTERNAL_ERROR == 4);
    assert(TEE_V5_STATUS_BAD_MAC == 5);
    assert(TEE_V5_STATUS_MALFORMED == 6);
    assert(TEE_V5_STATUS_UNSUPPORTED == 7);
}

static void test_semantic_policy_results_are_nvme_success(void)
{
    assert(tee_v5_nvme_status_for_policy(TEE_V5_STATUS_OK) == NVME_SUCCESS);
    assert(tee_v5_nvme_status_for_policy(TEE_V5_STATUS_NOT_FOUND) ==
           NVME_SUCCESS);
    assert(tee_v5_nvme_status_for_policy(TEE_V5_STATUS_BAD_REQUEST) ==
           NVME_SUCCESS);
    assert(tee_v5_nvme_status_for_policy(TEE_V5_STATUS_NO_PENDING_RESPONSE) ==
           NVME_SUCCESS);
    assert(tee_v5_nvme_status_for_policy(TEE_V5_STATUS_BAD_MAC) ==
           NVME_SUCCESS);
    assert(tee_v5_nvme_status_for_policy(TEE_V5_STATUS_MALFORMED) ==
           NVME_SUCCESS);
    assert(tee_v5_nvme_status_for_policy(TEE_V5_STATUS_UNSUPPORTED) ==
           NVME_SUCCESS);
}

static void test_internal_failure_has_no_dnr_bit(void)
{
    const uint16_t status =
        tee_v5_nvme_status_for_policy(TEE_V5_STATUS_INTERNAL_ERROR);

    assert(status == NVME_INTERNAL_DEV_ERROR);
    assert((status & NVME_DNR) == 0);
}

int main(void)
{
    test_policy_status_values_are_wire_stable();
    test_semantic_policy_results_are_nvme_success();
    test_internal_failure_has_no_dnr_bit();
    puts("test_tee_v5_status: PASS");
    return 0;
}
