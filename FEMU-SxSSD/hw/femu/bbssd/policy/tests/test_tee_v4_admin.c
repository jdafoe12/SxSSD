#include "../tee/tee-v4-admin.h"

#include "../tee/tee-v1-bitmap.h"
#include "../tee/tee-v2-active-metadata.h"
#include "../tee/tee-v2-cache.h"
#include "../tee/tee-v2-format.h"
#include "../tee/tee-v2-passive-metadata.h"
#include "../tee/tee-v2-write.h"
#include "../tee/tee-v3-policy.h"
#include "../tee/tee-v4-writeback.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void make_request(uint8_t *buffer, uint16_t command_type,
                         uint64_t request_id, uint8_t file_id,
                         uint32_t chunk_id)
{
    struct tee_v4_admin_request_header *header =
        (struct tee_v4_admin_request_header *)buffer;
    struct tee_v4_admin_chunk_query_payload *payload =
        (struct tee_v4_admin_chunk_query_payload *)(buffer + sizeof(*header));

    memset(buffer, 0, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES);
    header->magic = TEE_V4_ADMIN_MAGIC;
    header->version = TEE_V4_ADMIN_VERSION;
    header->command_type = command_type;
    header->request_id = request_id;
    header->payload_len = sizeof(*payload);
    header->flags = TEE_V4_ADMIN_FLAG_SUBMIT;
    payload->file_id = file_id;
    payload->chunk_id = chunk_id;
    payload->page_size = 64;
    assert(tee_v4_admin_sign_request(buffer, sizeof(*header) +
                                             sizeof(*payload)) == 0);
}

static size_t make_control_request(
    uint8_t *buffer, uint32_t flags, uint16_t command_type,
    uint64_t request_id, uint32_t page_index)
{
    struct tee_v4_admin_request_header *header = (void *)buffer;
    size_t bytes = sizeof(*header);

    memset(buffer, 0, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES);
    header->magic = TEE_V4_ADMIN_MAGIC;
    header->version = TEE_V4_ADMIN_VERSION;
    header->command_type = command_type;
    header->request_id = request_id;
    header->flags = flags;
    if (flags == TEE_V4_ADMIN_FLAG_CONTINUE) {
        struct tee_v4_admin_continue_payload *payload =
            (void *)(buffer + sizeof(*header));

        payload->request_id = request_id;
        payload->page_index = page_index;
        header->payload_len = sizeof(*payload);
        bytes += sizeof(*payload);
    }
    assert(tee_v4_admin_sign_request(buffer, bytes) == 0);
    return bytes;
}

static void build_context(struct tee_v2_active_metadata *active,
                          struct tee_v2_cache *cache,
                          struct tee_v2_write_context *write,
                          struct tee_v3_policy_context *v3)
{
    struct tee_v2_format_config cfg;
    struct tee_v2_hmac_group_spec spec;
    uint8_t hmac[TEE_V2_HMAC_SIZE];
    uint32_t i;

    memset(hmac, 0x5a, sizeof(hmac));
    assert(tee_v2_format_config_init(&cfg, TEE_V2_DEFAULT_SEGMENT_SIZE,
                                     4096));
    spec.start_segment_index = 1;
    spec.group_segment_count = 4;
    spec.expected_hmac = hmac;

    assert(tee_v2_active_metadata_init(active, &cfg, 8, 5, 2048, 4, 2,
                                       &spec, 1) == 0);
    for (i = 1; i <= 4; i++) {
        uint8_t segment[512];

        memset(segment, (int)i, sizeof(segment));
        segment[0] = TEE_V2_SEGMENT_MAGIC;
        segment[1] = 8;
        segment[2] = 5;
        segment[3] = 0;
        segment[4] = 0;
        segment[5] = (uint8_t)i;
        segment[6] = 0;
        segment[7] = 0;
        segment[8] = 0;
        assert(tee_v2_active_record_segment(active, i, 100 + i, segment) == 0);
    }
    active->groups[0].verified = true;
    assert(tee_v2_cache_init(cache, 4096, 4) == 0);
    assert(tee_v2_write_context_init(write, active, cache, 4096) == 0);
    {
        struct tee_v2_passive_metadata passive;

        assert(tee_v2_passive_from_active(&passive, active) == 0);
        assert(tee_v2_cache_store_passive(cache, &passive) == 0);
        tee_v2_passive_metadata_destroy(&passive);
    }
    tee_v3_policy_context_init(v3, write, NULL);
}

static void test_signed_summary_and_locations(void)
{
    struct tee_v2_active_metadata active;
    struct tee_v2_cache cache;
    struct tee_v2_write_context write;
    struct tee_v3_policy_context v3;
    struct tee_v4_admin admin;
    uint8_t request[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
    uint8_t response[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
    struct tee_v4_admin_response_header *header =
        (struct tee_v4_admin_response_header *)response;
    size_t written = 0;

    build_context(&active, &cache, &write, &v3);
    assert(tee_v4_admin_init(&admin, &v3, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                             4096) == 0);

    make_request(request, TEE_V4_ADMIN_CMD_READ_SUMMARY, 11, 8, 5);
    assert(tee_v4_admin_submit(&admin, request,
                               sizeof(struct tee_v4_admin_request_header) +
                                   sizeof(struct tee_v4_admin_chunk_query_payload)) == 0);
    {
        size_t fetch_bytes = make_control_request(
            request, TEE_V4_ADMIN_FLAG_FETCH,
            TEE_V4_ADMIN_CMD_READ_SUMMARY, 11, 0);
        assert(tee_v4_admin_fetch(&admin, request, fetch_bytes,
                              response, sizeof(response),
                              &written) == 0);
    }
    assert(header->status == TEE_V4_ADMIN_STATUS_OK);
    assert(header->total_items == 1);
    assert(((struct tee_v3_read_summary *)(response + sizeof(*header)))
               ->segment_count == 4);

    make_request(request, TEE_V4_ADMIN_CMD_READ_LOCATIONS, 12, 8, 5);
    assert(tee_v4_admin_submit(&admin, request,
                               sizeof(struct tee_v4_admin_request_header) +
                                   sizeof(struct tee_v4_admin_chunk_query_payload)) == 0);
    {
        size_t fetch_bytes = make_control_request(
            request, TEE_V4_ADMIN_FLAG_FETCH,
            TEE_V4_ADMIN_CMD_READ_LOCATIONS, 12, 0);
        assert(tee_v4_admin_fetch(&admin, request, fetch_bytes,
                              response, sizeof(response),
                              &written) == 0);
    }
    assert(header->total_items == 4);
    assert(((uint64_t *)(response + sizeof(*header)))[0] == 101);

    tee_v4_admin_destroy(&admin);
    tee_v2_write_context_destroy(&write);
    tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}


static void test_authenticated_fetch_continue_and_pending_lifecycle(void)
{
    struct tee_v2_active_metadata active;
    struct tee_v2_cache cache;
    struct tee_v2_write_context write;
    struct tee_v3_policy_context v3;
    struct tee_v4_admin admin;
    uint8_t request[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
    uint8_t response[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
    uint32_t items[5] = {10, 20, 30, 40, 50};
    size_t bytes;
    size_t written = 0;
    struct tee_v4_admin_response_header *header = (void *)response;

    build_context(&active, &cache, &write, &v3);
    assert(tee_v4_admin_init(&admin, &v3, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                             4096) == 0);
    assert(tee_v4_admin_response_prepare_items(
               &admin.pending, TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS, 70,
               TEE_V4_ADMIN_STATUS_OK, items, 5, sizeof(items[0]), 2) == 0);

    bytes = make_control_request(request, TEE_V4_ADMIN_FLAG_FETCH,
                                 TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS, 70, 0);
    request[TEE_V4_ADMIN_REQUEST_MAC_OFFSET] ^= 1;
    assert(tee_v4_admin_fetch(&admin, request, bytes, response,
                              sizeof(response), &written) != 0);
    assert(admin.pending.valid);

    bytes = make_control_request(request, TEE_V4_ADMIN_FLAG_FETCH,
                                 TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS, 70, 0);
    assert(tee_v4_admin_fetch(&admin, request, bytes - 1, response,
                              sizeof(response), &written) != 0);
    assert(admin.pending.valid);
    assert(tee_v4_admin_fetch(&admin, request, bytes, response,
                              sizeof(response), &written) == 0);
    assert(header->page_index == 0);

    bytes = make_control_request(request, TEE_V4_ADMIN_FLAG_CONTINUE,
                                 TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS, 70, 1);
    ((struct tee_v4_admin_continue_payload *)(
         request + sizeof(struct tee_v4_admin_request_header)))->request_id++;
    assert(tee_v4_admin_continue(&admin, request, bytes, response,
                                 sizeof(response), &written) != 0);
    assert(admin.pending.valid);

    bytes = make_control_request(request, TEE_V4_ADMIN_FLAG_CONTINUE,
                                 TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS, 70, 1);
    assert(tee_v4_admin_continue(&admin, request, bytes, response,
                                 sizeof(response), &written) == 0);
    assert(header->page_index == 1);
    assert(header->start_item == 2);
    assert(((uint32_t *)(response + sizeof(*header)))[0] == 30);

    make_request(request, TEE_V4_ADMIN_CMD_READ_SUMMARY, 71, 8, 5);
    assert(tee_v4_admin_submit(&admin, request,
        sizeof(struct tee_v4_admin_request_header) +
        sizeof(struct tee_v4_admin_chunk_query_payload)) == 0);
    assert(admin.pending.request_id == 71);

    /* A valid MAC from the wrong operation domain cannot authorize FETCH. */
    assert(tee_v4_admin_fetch(
               &admin, request,
               sizeof(struct tee_v4_admin_request_header) +
                   sizeof(struct tee_v4_admin_chunk_query_payload),
               response, sizeof(response), &written) != 0);
    assert(admin.pending.request_id == 71);

    /* Exact-size validation rejects trailing bytes without replacing pending. */
    assert(tee_v4_admin_submit(
               &admin, request,
               sizeof(struct tee_v4_admin_request_header) +
                   sizeof(struct tee_v4_admin_chunk_query_payload) + 1) != 0);
    assert(admin.pending.valid);
    assert(admin.pending.request_id == 71);

    tee_v4_admin_destroy(&admin);
    tee_v2_write_context_destroy(&write);
    tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}

struct sync_log { int calls; int result; };

static int sync_flush(void *opaque,
                      const struct tee_v4_transaction_record *records,
                      uint32_t count)
{
    struct sync_log *log = opaque;
    (void)records;
    (void)count;
    log->calls++;
    return log->result;
}

static void test_authenticated_sync_failure_and_retry(void)
{
    struct tee_v2_active_metadata active;
    struct tee_v2_cache cache;
    struct tee_v2_write_context write;
    struct tee_v3_policy_context v3;
    struct tee_v4_admin admin;
    struct tee_v4_writeback wb;
    struct tee_v4_transaction_record records[2];
    struct sync_log log = {0, -1};
    uint8_t request[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
    size_t request_bytes;

    build_context(&active, &cache, &write, &v3);
    assert(tee_v4_writeback_init(&wb, records, 2, 1000,
                                 sync_flush, &log) == 0);
    assert(tee_v4_writeback_record_relocation(&wb, 8, 5, 1, 101, 201) == 0);
    assert(tee_v4_admin_init(&admin, &v3, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                             4096) == 0);
    tee_v4_admin_set_writeback(&admin, &wb);

    request_bytes = make_control_request(
        request, TEE_V4_ADMIN_FLAG_SUBMIT,
        TEE_V4_ADMIN_CMD_SYNC_METADATA, 80, 0);
    assert(tee_v4_admin_submit(&admin, request, request_bytes) != 0);
    assert(log.calls == 1);
    assert(wb.pending_count == 1);

    log.result = 0;
    request_bytes = make_control_request(
        request, TEE_V4_ADMIN_FLAG_SUBMIT,
        TEE_V4_ADMIN_CMD_SYNC_METADATA, 81, 0);
    assert(tee_v4_admin_submit(&admin, request, request_bytes) == 0);
    assert(log.calls == 2);
    assert(wb.pending_count == 0);

    tee_v4_admin_destroy(&admin);
    tee_v2_write_context_destroy(&write);
    tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}

static void test_bad_mac_is_rejected(void)
{
    struct tee_v2_active_metadata active;
    struct tee_v2_cache cache;
    struct tee_v2_write_context write;
    struct tee_v3_policy_context v3;
    struct tee_v4_admin admin;
    uint8_t request[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];

    build_context(&active, &cache, &write, &v3);
    assert(tee_v4_admin_init(&admin, &v3, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                             4096) == 0);
    make_request(request, TEE_V4_ADMIN_CMD_READ_SUMMARY, 13, 8, 5);
    request[TEE_V4_ADMIN_REQUEST_MAC_OFFSET] ^= 0xff;
    assert(tee_v4_admin_submit(&admin, request,
                               sizeof(struct tee_v4_admin_request_header) +
                                   sizeof(struct tee_v4_admin_chunk_query_payload)) != 0);

    tee_v4_admin_destroy(&admin);
    tee_v2_write_context_destroy(&write);
    tee_v2_cache_destroy(&cache);
    tee_v2_active_metadata_destroy(&active);
}

int main(void)
{
    test_signed_summary_and_locations();
    test_bad_mac_is_rejected();
    test_authenticated_fetch_continue_and_pending_lifecycle();
    test_authenticated_sync_failure_and_retry();
    puts("test_tee_v4_admin: PASS");
    return 0;
}
