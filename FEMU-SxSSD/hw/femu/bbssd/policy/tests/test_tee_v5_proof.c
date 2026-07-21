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

struct proof_fixture {
    struct tee_v2_format_config config;
    struct tee_v2_active_metadata active;
    struct tee_v2_cache cache;
    struct tee_v2_write_context write;
    struct tee_v3_pending_controller controller;
};

static void fixture_init(struct proof_fixture *fixture, uint8_t file_id,
                         uint32_t chunk_id)
{
    struct tee_v2_hmac_group_spec group;
    uint8_t hmac[TEE_V2_HMAC_SIZE] = {0};

    memset(fixture, 0, sizeof(*fixture));
    assert(tee_v2_format_config_init(&fixture->config,
                                     TEE_V2_DEFAULT_SEGMENT_SIZE, 4096));
    group.start_segment_index = 1;
    group.group_segment_count = 1;
    group.expected_hmac = hmac;
    assert(tee_v2_active_metadata_init(&fixture->active, &fixture->config,
                                       file_id, chunk_id,
                                       TEE_V2_DEFAULT_SEGMENT_SIZE,
                                       1, 1, &group, 1) == 0);
    assert(tee_v2_cache_init(&fixture->cache, 64, 4) == 0);
    assert(tee_v2_write_context_init(&fixture->write, &fixture->active,
                                     &fixture->cache, 64) == 0);
    tee_v3_pending_init(&fixture->controller, &fixture->write,
                        TEE_V3_DEFAULT_TIMEOUT_OPS);
    fixture->controller.error_precedes_passive = true;
}

static void fixture_destroy(struct proof_fixture *fixture)
{
    tee_v2_write_context_destroy(&fixture->write);
    tee_v2_cache_destroy(&fixture->cache);
    tee_v2_active_metadata_destroy(&fixture->active);
}

static void test_error_is_one_based_and_survives_queries(void)
{
    struct proof_fixture fixture;
    struct tee_v3_one_bit_proof proof;
    size_t written = 99;

    fixture_init(&fixture, 1, 9);
    tee_v5_proof_record_error(&fixture.controller, 1, 9,
                              TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE, 3);

    assert(fixture.controller.has_error);
    assert(fixture.controller.last_error_code ==
           TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE);
    assert(fixture.controller.failed_segment_index == 3);

    /* An ordinary query may report the error, but must never consume it. */
    assert(tee_v3_one_bit_proof_query(&fixture.controller, 1, 9, 0, NULL, 0,
                                      &written, &proof) == TEE_V3_QUERY_OK);
    assert(proof.state == TEE_V3_PROOF_ERROR);
    assert(fixture.controller.has_error);
    assert(fixture.controller.failed_segment_index == 3);
    fixture_destroy(&fixture);
}

static void test_error_is_scoped_to_exact_chunk_identity(void)
{
    struct proof_fixture fixture;
    struct tee_v3_one_bit_proof proof;
    size_t written = 0;

    fixture_init(&fixture, 7, 0x123456U);
    tee_v5_proof_record_error(&fixture.controller, 7, 0x123456U,
                              TEE_V5_PROOF_ERROR_HMAC_FAILURE, 1);
    assert(tee_v3_one_bit_proof_query(&fixture.controller, 8, 0x123456U,
                                      0, NULL, 0, &written, &proof) ==
           TEE_V3_QUERY_NOT_FOUND);
    assert(fixture.controller.has_error);
    fixture_destroy(&fixture);
}

static void test_only_matching_superseding_operation_clears_error(void)
{
    struct tee_v3_pending_controller controller;

    memset(&controller, 0, sizeof(controller));
    tee_v5_proof_record_error(&controller, 7, 0x123456U,
                              TEE_V5_PROOF_ERROR_HMAC_FAILURE, 1);

    /* An absent/unrelated ABORT or other lifecycle event is a no-op. */
    tee_v5_proof_clear_error(&controller, 8, 0x123456U);
    assert(controller.has_error);
    tee_v5_proof_clear_error(&controller, 7, 0x123457U);
    assert(controller.has_error);

    /* A successful superseding operation for the exact identity clears it. */
    tee_v5_proof_clear_error(&controller, 7, 0x123456U);

    assert(!controller.has_error);
    assert(controller.last_error_code == TEE_V5_PROOF_ERROR_NONE);
    assert(controller.failed_segment_index == TEE_V5_NO_FAILED_SEGMENT);
}

static void test_non_segment_error_uses_no_segment_sentinel(void)
{
    struct tee_v3_pending_controller controller;

    memset(&controller, 0, sizeof(controller));
    tee_v5_proof_record_error(&controller, 4, 5,
                              TEE_V5_PROOF_ERROR_INTERNAL,
                              TEE_V5_NO_FAILED_SEGMENT);
    assert(controller.has_error);
    assert(controller.failed_segment_index == TEE_V5_NO_FAILED_SEGMENT);
}

int main(void)
{
    test_error_codes_and_sentinel_are_wire_stable();
    test_error_is_one_based_and_survives_queries();
    test_error_is_scoped_to_exact_chunk_identity();
    test_only_matching_superseding_operation_clears_error();
    test_non_segment_error_uses_no_segment_sentinel();
    puts("test_tee_v5_proof: PASS");
    return 0;
}
