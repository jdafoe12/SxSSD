#include "../tee/tee-v4-admin.h"

#include "../tee/tee-v1-bitmap.h"
#include "../tee/tee-v2-active-metadata.h"
#include "../tee/tee-v2-cache.h"
#include "../tee/tee-v2-format.h"
#include "../tee/tee-v2-passive-metadata.h"
#include "../tee/tee-v2-write.h"
#include "../tee/tee-v3-policy.h"

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
    payload->file_id = file_id;
    payload->chunk_id = chunk_id;
    payload->page_size = 64;
    assert(tee_v4_admin_sign_request(buffer, sizeof(*header) +
                                             sizeof(*payload)) == 0);
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
    assert(tee_v4_admin_fetch(&admin, response, sizeof(response),
                              &written) == 0);
    assert(header->status == TEE_V4_ADMIN_STATUS_OK);
    assert(header->total_items == 1);
    assert(((struct tee_v3_read_summary *)(response + sizeof(*header)))
               ->segment_count == 4);

    make_request(request, TEE_V4_ADMIN_CMD_READ_LOCATIONS, 12, 8, 5);
    assert(tee_v4_admin_submit(&admin, request,
                               sizeof(struct tee_v4_admin_request_header) +
                                   sizeof(struct tee_v4_admin_chunk_query_payload)) == 0);
    assert(tee_v4_admin_fetch(&admin, response, sizeof(response),
                              &written) == 0);
    assert(header->total_items == 4);
    assert(((uint64_t *)(response + sizeof(*header)))[0] == 101);

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
    puts("test_tee_v4_admin: PASS");
    return 0;
}
