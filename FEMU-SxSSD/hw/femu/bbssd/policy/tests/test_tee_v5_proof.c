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
    assert(tee_v5_proof_record_error(
               &fixture.controller, 1, 9,
               TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE, 3) == 0);

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
    assert(tee_v5_proof_record_error(
               &fixture.controller, 7, 0x123456U,
               TEE_V5_PROOF_ERROR_HMAC_FAILURE, 1) == 0);
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
    assert(tee_v5_proof_record_error(
               &controller, 7, 0x123456U,
               TEE_V5_PROOF_ERROR_HMAC_FAILURE, 1) == 0);

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
    assert(tee_v5_proof_record_error(
               &controller, 4, 5, TEE_V5_PROOF_ERROR_INTERNAL,
               TEE_V5_NO_FAILED_SEGMENT) == 0);
    assert(controller.has_error);
    assert(controller.failed_segment_index == TEE_V5_NO_FAILED_SEGMENT);
}

static void assert_proof_error(struct proof_fixture *fixture,
                               uint8_t file_id, uint32_t chunk_id,
                               int32_t error,
                               uint32_t failed_segment)
{
    struct tee_v3_one_bit_proof proof;
    size_t written = 0;

    assert(tee_v3_one_bit_proof_query(&fixture->controller, file_id, chunk_id,
                                      0, NULL, 0, &written, &proof) ==
           TEE_V3_QUERY_OK);
    assert(proof.state == TEE_V3_PROOF_ERROR);
    assert(proof.last_error_code == error);
    assert(proof.failed_segment_index == failed_segment);
}

static void test_distinct_chunk_errors_survive_and_clear_independently(void)
{
    struct proof_fixture fixture;
    struct tee_v3_one_bit_proof proof;
    size_t written = 0;

    fixture_init(&fixture, 1, 1);
    assert(tee_v5_proof_record_error(
               &fixture.controller, 10, 100,
               TEE_V5_PROOF_ERROR_HMAC_FAILURE, 2) == 0);
    assert(tee_v5_proof_record_error(
               &fixture.controller, 11, 101,
               TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE,
               TEE_V5_NO_FAILED_SEGMENT) == 0);

    assert_proof_error(&fixture, 10, 100,
                       TEE_V5_PROOF_ERROR_HMAC_FAILURE, 2);
    assert_proof_error(&fixture, 11, 101,
                       TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE,
                       TEE_V5_NO_FAILED_SEGMENT);

    tee_v5_proof_clear_error(&fixture.controller, 10, 100);
    assert(tee_v3_one_bit_proof_query(&fixture.controller, 10, 100, 0,
                                      NULL, 0, &written, &proof) ==
           TEE_V3_QUERY_NOT_FOUND);
    assert_proof_error(&fixture, 11, 101,
                       TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE,
                       TEE_V5_NO_FAILED_SEGMENT);
    fixture_destroy(&fixture);
}

static void test_error_table_full_preserves_existing_evidence(void)
{
    struct proof_fixture fixture;
    uint32_t i;

    fixture_init(&fixture, 1, 1);
    /* 64 passive cache identities plus one active-conflict identity. */
    assert(TEE_V5_PROOF_ERROR_CAPACITY == 65);
    for (i = 0; i < TEE_V5_PROOF_ERROR_CAPACITY; i++) {
        assert(tee_v5_proof_record_error(
                   &fixture.controller, 20, 1000 + i,
                   TEE_V5_PROOF_ERROR_DELETE_INTEGRITY, i + 1) == 0);
    }

    /* Deterministic full behavior: never evict evidence; reject the new item. */
    assert(tee_v5_proof_record_error(
               &fixture.controller, 21, 2000,
               TEE_V5_PROOF_ERROR_INTERNAL,
               TEE_V5_NO_FAILED_SEGMENT) == -1);
    for (i = 0; i < TEE_V5_PROOF_ERROR_CAPACITY; i++) {
        assert_proof_error(&fixture, 20, 1000 + i,
                           TEE_V5_PROOF_ERROR_DELETE_INTEGRITY, i + 1);
    }
    fixture_destroy(&fixture);
}

static void test_legacy_global_error_blocks_scoped_insertion(void)
{
    struct proof_fixture fixture;

    fixture_init(&fixture, 1, 1);
    tee_v3_pending_record_error(&fixture.controller, 88, 6);

    /* Global legacy evidence has precedence and cannot be hidden by V5. */
    assert(tee_v5_proof_record_error(
               &fixture.controller, 40, 4000,
               TEE_V5_PROOF_ERROR_DELETE_CONFLICT,
               TEE_V5_NO_FAILED_SEGMENT) == -1);
    assert_proof_error(&fixture, 40, 4000, 88, 6);
    assert_proof_error(&fixture, 41, 4001, 88, 6);
    fixture_destroy(&fixture);
}

static void test_legacy_record_resets_stale_scoped_state(void)
{
    struct proof_fixture fixture;

    fixture_init(&fixture, 1, 1);
    assert(tee_v5_proof_record_error(
               &fixture.controller, 30, 3000,
               TEE_V5_PROOF_ERROR_DELETE_CONFLICT,
               TEE_V5_NO_FAILED_SEGMENT) == 0);

    /* V1-V4's legacy API remains unscoped and replaces stale V5 evidence. */
    tee_v3_pending_record_error(&fixture.controller, 77, 4);
    assert_proof_error(&fixture, 31, 3001, 77, 4);
    fixture_destroy(&fixture);
}

int main(void)
{
    test_error_codes_and_sentinel_are_wire_stable();
    test_error_is_one_based_and_survives_queries();
    test_error_is_scoped_to_exact_chunk_identity();
    test_only_matching_superseding_operation_clears_error();
    test_non_segment_error_uses_no_segment_sentinel();
    test_distinct_chunk_errors_survive_and_clear_independently();
    test_error_table_full_preserves_existing_evidence();
    test_legacy_record_resets_stale_scoped_state();
    test_legacy_global_error_blocks_scoped_insertion();
    puts("test_tee_v5_proof: PASS");
    return 0;
}
