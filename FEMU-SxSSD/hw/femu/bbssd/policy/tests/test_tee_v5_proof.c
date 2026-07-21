#include "../tee/tee-v5-proof.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_error_codes_and_sentinel_are_wire_stable(void)
{
    assert(TEE_V5_PROOF_ERROR_NONE == 0);
    assert(TEE_V5_PROOF_ERROR_HMAC_FAILURE == 1);
    assert(TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE == 2);
    assert(TEE_V5_PROOF_ERROR_DELETE_INTEGRITY == 3);
    assert(TEE_V5_PROOF_ERROR_DELETE_CONFLICT == 4);
    assert(TEE_V5_PROOF_ERROR_INTERNAL == 5);
    assert(TEE_V5_NO_FAILED_SEGMENT == UINT32_MAX);
}

static void test_error_is_one_based_and_survives_queries(void)
{
    struct tee_v3_pending_controller controller;
    struct tee_v3_one_bit_proof proof;
    size_t written = 99;

    memset(&controller, 0, sizeof(controller));
    tee_v5_proof_record_error(&controller,
                              TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE, 3);

    assert(controller.has_error);
    assert(controller.last_error_code ==
           TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE);
    assert(controller.failed_segment_index == 3);

    /* An ordinary query may report the error, but must never consume it. */
    assert(tee_v3_one_bit_proof_query(&controller, 1, 9, 0, NULL, 0,
                                      &written, &proof) ==
           TEE_V3_QUERY_INVALID);
    assert(controller.has_error);
    assert(controller.failed_segment_index == 3);
}

static void test_chunk_lifecycle_explicitly_clears_error(void)
{
    struct tee_v3_pending_controller controller;

    memset(&controller, 0, sizeof(controller));
    tee_v5_proof_record_error(&controller,
                              TEE_V5_PROOF_ERROR_HMAC_FAILURE, 1);
    tee_v5_proof_clear_error(&controller);

    assert(!controller.has_error);
    assert(controller.last_error_code == TEE_V5_PROOF_ERROR_NONE);
    assert(controller.failed_segment_index == TEE_V5_NO_FAILED_SEGMENT);
}

static void test_non_segment_error_uses_no_segment_sentinel(void)
{
    struct tee_v3_pending_controller controller;

    memset(&controller, 0, sizeof(controller));
    tee_v5_proof_record_error(&controller, TEE_V5_PROOF_ERROR_INTERNAL,
                              TEE_V5_NO_FAILED_SEGMENT);
    assert(controller.has_error);
    assert(controller.failed_segment_index == TEE_V5_NO_FAILED_SEGMENT);
}

int main(void)
{
    test_error_codes_and_sentinel_are_wire_stable();
    test_error_is_one_based_and_survives_queries();
    test_chunk_lifecycle_explicitly_clears_error();
    test_non_segment_error_uses_no_segment_sentinel();
    puts("test_tee_v5_proof: PASS");
    return 0;
}
