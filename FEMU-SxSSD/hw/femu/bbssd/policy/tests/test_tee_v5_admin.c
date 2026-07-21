#include "../tee/tee-v5-admin.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct request_with_identity {
    struct tee_v4_admin_request_header header;
    struct tee_v5_chunk_identity_payload identity;
};

struct callback_state {
    unsigned calls;
    uint8_t file_id;
    uint32_t chunk_id;
    int result;
};

static int abort_active(void *opaque, uint8_t file_id, uint32_t chunk_id)
{
    struct callback_state *state = opaque;

    state->calls++;
    state->file_id = file_id;
    state->chunk_id = chunk_id;
    return state->result;
}

static void make_submit(struct request_with_identity *request,
                        uint16_t command, uint64_t request_id,
                        uint8_t file_id, uint32_t chunk_id)
{
    memset(request, 0, sizeof(*request));
    request->header.magic = TEE_V4_ADMIN_MAGIC;
    request->header.version = TEE_V4_ADMIN_VERSION;
    request->header.command_type = command;
    request->header.request_id = request_id;
    request->header.payload_len = sizeof(request->identity);
    request->header.flags = TEE_V4_ADMIN_FLAG_SUBMIT;
    request->identity.file_id = file_id;
    request->identity.chunk_id = chunk_id;
    assert(tee_v4_admin_sign_request(request, sizeof(*request)) == 0);
}

static void make_fetch(struct tee_v4_admin_request_header *request,
                       uint16_t command, uint64_t request_id)
{
    memset(request, 0, sizeof(*request));
    request->magic = TEE_V4_ADMIN_MAGIC;
    request->version = TEE_V4_ADMIN_VERSION;
    request->command_type = command;
    request->request_id = request_id;
    request->flags = TEE_V4_ADMIN_FLAG_FETCH;
    assert(tee_v4_admin_sign_request(request, sizeof(*request)) == 0);
}

static int fetch_status(struct tee_v5_admin *admin, uint16_t command,
                        uint64_t request_id)
{
    struct tee_v4_admin_request_header fetch;
    struct tee_v4_admin_response_header response;
    size_t written = 0;

    make_fetch(&fetch, command, request_id);
    assert(tee_v5_admin_fetch(admin, &fetch, sizeof(fetch), &response,
                              sizeof(response), &written) == 0);
    assert(written == sizeof(response));
    assert(response.command_type == command);
    assert(response.request_id == request_id);
    return response.status;
}

static void test_unsupported_command_is_fetchable_policy_response(void)
{
    struct tee_v3_policy_context policy;
    struct tee_v5_admin admin;
    struct request_with_identity request;

    memset(&policy, 0, sizeof(policy));
    assert(tee_v5_admin_init(&admin, &policy,
                             TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES, 128) == 0);
    make_submit(&request, 99, 10, 1, 2);
    assert(tee_v5_admin_submit(&admin, &request, sizeof(request)) == 0);
    assert(fetch_status(&admin, 99, 10) == TEE_V5_STATUS_UNSUPPORTED);
    tee_v5_admin_destroy(&admin);
}

static void test_bad_mac_and_malformed_request_preserve_pending(void)
{
    struct tee_v3_policy_context policy;
    struct tee_v5_admin admin;
    struct request_with_identity good;
    struct request_with_identity bad;

    memset(&policy, 0, sizeof(policy));
    assert(tee_v5_admin_init(&admin, &policy,
                             TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES, 128) == 0);
    make_submit(&good, 99, 20, 1, 2);
    assert(tee_v5_admin_submit(&admin, &good, sizeof(good)) == 0);

    make_submit(&bad, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 21, 1, 2);
    bad.header.request_mac[0] ^= 0x80;
    assert(tee_v5_admin_submit(&admin, &bad, sizeof(bad)) == -1);
    assert(fetch_status(&admin, 99, 20) == TEE_V5_STATUS_UNSUPPORTED);

    make_submit(&bad, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 22, 1, 2);
    bad.header.payload_len--;
    assert(tee_v4_admin_sign_request(&bad, sizeof(bad)) == 0);
    assert(tee_v5_admin_submit(&admin, &bad, sizeof(bad)) == -1);
    assert(fetch_status(&admin, 99, 20) == TEE_V5_STATUS_UNSUPPORTED);
    tee_v5_admin_destroy(&admin);
}

static void test_fetch_without_matching_pending_is_explicit_response(void)
{
    struct tee_v3_policy_context policy;
    struct tee_v5_admin admin;

    memset(&policy, 0, sizeof(policy));
    assert(tee_v5_admin_init(&admin, &policy,
                             TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES, 128) == 0);
    assert(fetch_status(&admin, TEE_V4_ADMIN_CMD_READ_SUMMARY, 30) ==
           TEE_V5_STATUS_NO_PENDING_RESPONSE);
    tee_v5_admin_destroy(&admin);
}

static void test_abort_is_exact_and_idempotent(void)
{
    struct tee_v3_policy_context policy;
    struct tee_v5_admin admin;
    struct request_with_identity request;
    struct callback_state callback = {0};

    memset(&policy, 0, sizeof(policy));
    assert(tee_v5_admin_init(&admin, &policy,
                             TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES, 128) == 0);
    tee_v5_admin_set_abort_handler(&admin, abort_active, &callback);

    make_submit(&request, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 40, 7, 0x123456U);
    assert(tee_v5_admin_submit(&admin, &request, sizeof(request)) == 0);
    assert(callback.calls == 1);
    assert(callback.file_id == 7);
    assert(callback.chunk_id == 0x123456U);
    assert(fetch_status(&admin, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 40) ==
           TEE_V5_STATUS_OK);

    /* A handler may report that the exact active identity is already absent. */
    callback.result = 1;
    make_submit(&request, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 41, 7, 0x123456U);
    assert(tee_v5_admin_submit(&admin, &request, sizeof(request)) == 0);
    assert(callback.calls == 2);
    assert(fetch_status(&admin, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 41) ==
           TEE_V5_STATUS_OK);
    tee_v5_admin_destroy(&admin);
}

static void test_out_of_range_chunk_is_malformed_without_dispatch(void)
{
    struct tee_v3_policy_context policy;
    struct tee_v5_admin admin;
    struct request_with_identity pending;
    struct request_with_identity malformed;
    struct callback_state callback = {0};

    memset(&policy, 0, sizeof(policy));
    assert(tee_v5_admin_init(&admin, &policy,
                             TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES, 128) == 0);
    tee_v5_admin_set_abort_handler(&admin, abort_active, &callback);

    /* The largest 24-bit chunk id is valid and reaches the handler. */
    make_submit(&malformed, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 50, 7,
                0x00ffffffU);
    assert(tee_v5_admin_submit(&admin, &malformed, sizeof(malformed)) == 0);
    assert(callback.calls == 1);
    assert(fetch_status(&admin, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 50) ==
           TEE_V5_STATUS_OK);

    make_submit(&pending, 99, 51, 1, 2);
    assert(tee_v5_admin_submit(&admin, &pending, sizeof(pending)) == 0);
    make_submit(&malformed, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 52, 7,
                0x01000000U);
    assert(tee_v5_admin_submit(&admin, &malformed, sizeof(malformed)) == -1);
    assert(callback.calls == 1);
    assert(fetch_status(&admin, 99, 51) == TEE_V5_STATUS_UNSUPPORTED);
    tee_v5_admin_destroy(&admin);
}

int main(void)
{
    test_unsupported_command_is_fetchable_policy_response();
    test_bad_mac_and_malformed_request_preserve_pending();
    test_fetch_without_matching_pending_is_explicit_response();
    test_abort_is_exact_and_idempotent();
    test_out_of_range_chunk_is_malformed_without_dispatch();
    puts("test_tee_v5_admin: PASS");
    return 0;
}
