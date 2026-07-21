#include "../tee/tee-v4-admin-format.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void test_request_header_validation_and_mac_span(void)
{
    struct tee_v4_admin_request_header req;
    size_t span = 0;

    memset(&req, 0, sizeof(req));
    req.magic = TEE_V4_ADMIN_MAGIC;
    req.version = TEE_V4_ADMIN_VERSION;
    req.command_type = TEE_V4_ADMIN_CMD_READ_LOCATIONS;
    req.request_id = 99;
    req.payload_len = 64;
    req.flags = 0;

    assert(sizeof(req) == TEE_V4_ADMIN_REQUEST_HEADER_SIZE);
    assert(TEE_V4_ADMIN_REQUEST_MAC_OFFSET == 24);
    assert(tee_v4_admin_request_valid(&req, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES));
    assert(tee_v4_admin_mac_span(&req, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                                 &span));
    assert(span == TEE_V4_ADMIN_REQUEST_MAC_OFFSET + 64);

    req.payload_len = TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES;
    assert(!tee_v4_admin_request_valid(&req,
                                       TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES));
}

static void test_response_header_and_pagination(void)
{
    struct tee_v4_admin_response_header rsp;

    memset(&rsp, 0, sizeof(rsp));
    tee_v4_admin_response_header_init(
        &rsp, TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS, 1234,
        TEE_V4_ADMIN_STATUS_OK, 17, 4, 5, 2);

    assert(sizeof(rsp) == TEE_V4_ADMIN_RESPONSE_HEADER_SIZE);
    assert(rsp.magic == TEE_V4_ADMIN_MAGIC);
    assert(rsp.version == TEE_V4_ADMIN_VERSION);
    assert(rsp.request_id == 1234);
    assert(rsp.command_type == TEE_V4_ADMIN_CMD_READ_HMAC_GROUPS);
    assert(rsp.status == TEE_V4_ADMIN_STATUS_OK);
    assert(rsp.total_items == 17);
    assert(rsp.item_size == 4);
    assert(rsp.total_pages == 4);
    assert(rsp.page_index == 2);
    assert(rsp.start_item == 10);
    assert(rsp.returned_items == 5);
}

static void test_continue_request_payload(void)
{
    struct tee_v4_admin_continue_payload payload;

    memset(&payload, 0, sizeof(payload));
    payload.request_id = 42;
    payload.page_index = 3;

    assert(sizeof(payload) == TEE_V4_ADMIN_CONTINUE_PAYLOAD_SIZE);
    assert(payload.request_id == 42);
    assert(payload.page_index == 3);
}

int main(void)
{
    test_request_header_validation_and_mac_span();
    test_response_header_and_pagination();
    test_continue_request_payload();
    puts("test_tee_v4_admin_format: PASS");
    return 0;
}
