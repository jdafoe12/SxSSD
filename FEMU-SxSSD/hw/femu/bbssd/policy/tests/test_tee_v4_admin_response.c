#include "../tee/tee-v4-admin-response.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_paged_items_are_materialized(void)
{
    struct tee_v4_admin_response pending;
    uint64_t locations[7] = {100, 101, 102, 103, 104, 105, 106};
    uint8_t out[TEE_V4_ADMIN_RESPONSE_HEADER_SIZE + sizeof(uint64_t) * 3];
    struct tee_v4_admin_response_header *header =
        (struct tee_v4_admin_response_header *)out;
    uint64_t *payload = (uint64_t *)(out + sizeof(*header));
    size_t written = 0;

    assert(tee_v4_admin_response_init(&pending,
                                      sizeof(uint64_t) * 16) == 0);
    assert(tee_v4_admin_response_prepare_items(
               &pending, TEE_V4_ADMIN_CMD_READ_LOCATIONS, 55,
               TEE_V4_ADMIN_STATUS_OK, locations, 7, sizeof(uint64_t),
               3) == 0);
    assert(tee_v4_admin_response_materialize_page(&pending, 1, out,
                                                  sizeof(out),
                                                  &written) == 0);

    assert(written == sizeof(*header) + sizeof(uint64_t) * 3);
    assert(header->request_id == 55);
    assert(header->command_type == TEE_V4_ADMIN_CMD_READ_LOCATIONS);
    assert(header->total_items == 7);
    assert(header->start_item == 3);
    assert(header->returned_items == 3);
    assert(header->total_pages == 3);
    assert(payload[0] == 103);
    assert(payload[2] == 105);

    tee_v4_admin_response_destroy(&pending);
}

static void test_empty_status_response_is_valid(void)
{
    struct tee_v4_admin_response pending;
    uint8_t out[TEE_V4_ADMIN_RESPONSE_HEADER_SIZE];
    struct tee_v4_admin_response_header *header =
        (struct tee_v4_admin_response_header *)out;
    size_t written = 0;

    assert(tee_v4_admin_response_init(&pending, 128) == 0);
    assert(tee_v4_admin_response_prepare_items(
               &pending, TEE_V4_ADMIN_CMD_SYNC_METADATA, 12,
               TEE_V4_ADMIN_STATUS_OK, NULL, 0, 0, 8) == 0);
    assert(tee_v4_admin_response_materialize_page(&pending, 0, out,
                                                  sizeof(out),
                                                  &written) == 0);

    assert(written == sizeof(*header));
    assert(header->total_items == 0);
    assert(header->returned_items == 0);
    assert(header->total_pages == 1);

    tee_v4_admin_response_destroy(&pending);
}

static void test_invalid_page_is_rejected(void)
{
    struct tee_v4_admin_response pending;
    uint32_t items[2] = {1, 2};
    uint8_t out[TEE_V4_ADMIN_RESPONSE_HEADER_SIZE + sizeof(items)];
    size_t written = 99;

    assert(tee_v4_admin_response_init(&pending, 128) == 0);
    assert(tee_v4_admin_response_prepare_items(
               &pending, TEE_V4_ADMIN_CMD_ONE_BIT_PROOF, 7,
               TEE_V4_ADMIN_STATUS_OK, items, 2, sizeof(uint32_t),
               2) == 0);
    assert(tee_v4_admin_response_materialize_page(&pending, 2, out,
                                                  sizeof(out),
                                                  &written) != 0);
    assert(written == 0);

    tee_v4_admin_response_destroy(&pending);
}

int main(void)
{
    test_paged_items_are_materialized();
    test_empty_status_response_is_valid();
    test_invalid_page_is_rejected();
    puts("test_tee_v4_admin_response: PASS");
    return 0;
}
