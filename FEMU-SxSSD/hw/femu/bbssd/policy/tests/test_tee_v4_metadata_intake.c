#include "../tee/tee-v4-admin.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct intake_log {
    int calls;
    int result;
    struct tee_v4_admin_active_metadata_payload header;
    struct tee_v4_admin_hmac_group_wire groups[2];
};

static int record_intake(
    void *opaque,
    const struct tee_v4_admin_active_metadata_payload *header,
    const struct tee_v4_admin_hmac_group_wire *groups)
{
    struct intake_log *log = opaque;
    log->calls++;
    log->header = *header;
    if (header->group_count <= 2) {
        memcpy(log->groups, groups, header->group_count * sizeof(*groups));
    }
    return log->result;
}

static size_t make_intake(uint8_t *request, uint64_t request_id,
                          uint32_t group_count)
{
    struct tee_v4_admin_request_header *request_header = (void *)request;
    struct tee_v4_admin_active_metadata_payload *payload =
        (void *)(request + sizeof(*request_header));
    struct tee_v4_admin_hmac_group_wire *groups =
        (void *)(payload + 1);
    size_t payload_bytes = sizeof(*payload) + group_count * sizeof(*groups);
    size_t request_bytes = sizeof(*request_header) + payload_bytes;
    uint32_t i;

    memset(request, 0, TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES);
    request_header->magic = TEE_V4_ADMIN_MAGIC;
    request_header->version = TEE_V4_ADMIN_VERSION;
    request_header->command_type = TEE_V4_ADMIN_CMD_SET_ACTIVE_METADATA;
    request_header->request_id = request_id;
    request_header->payload_len = (uint32_t)payload_bytes;
    request_header->flags = TEE_V4_ADMIN_FLAG_SUBMIT;
    payload->file_id = 9;
    payload->chunk_id = 17;
    payload->chunk_size_bytes = 2048;
    payload->segment_count = 4;
    payload->number_coefficient = 2;
    payload->group_count = group_count;
    for (i = 0; i < group_count; i++) {
        groups[i].start_segment_index = 1 + i * 2;
        groups[i].group_segment_count = 2;
        memset(groups[i].expected_hmac, (int)(0x40 + i),
               sizeof(groups[i].expected_hmac));
    }
    assert(tee_v4_admin_sign_request(request, request_bytes) == 0);
    return request_bytes;
}

static void resign(uint8_t *request, size_t bytes)
{
    assert(tee_v4_admin_sign_request(request, bytes) == 0);
}

static void test_valid_intake_and_callback_failure_atomicity(void)
{
    struct tee_v3_policy_context policy;
    struct tee_v4_admin admin;
    struct intake_log log;
    uint8_t request[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
    uint32_t old_item = 123;
    size_t bytes;

    memset(&policy, 0, sizeof(policy));
    memset(&log, 0, sizeof(log));
    assert(tee_v4_admin_init(&admin, &policy,
                             TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES, 4096) == 0);
    tee_v4_admin_set_metadata_intake(&admin, record_intake, &log);

    bytes = make_intake(request, 300, 2);
    assert(tee_v4_admin_submit(&admin, request, bytes) == 0);
    assert(log.calls == 1);
    assert(log.header.file_id == 9);
    assert(log.header.chunk_id == 17);
    assert(log.groups[1].start_segment_index == 3);
    assert(admin.pending.valid && admin.pending.request_id == 300);

    assert(tee_v4_admin_response_prepare_items(
               &admin.pending, TEE_V4_ADMIN_CMD_READ_LOCATIONS, 301,
               TEE_V4_ADMIN_STATUS_OK, &old_item, 1, sizeof(old_item), 1) == 0);
    log.result = -1;
    bytes = make_intake(request, 302, 2);
    assert(tee_v4_admin_submit(&admin, request, bytes) != 0);
    assert(log.calls == 2);
    assert(admin.pending.valid);
    assert(admin.pending.request_id == 301);
    assert(admin.pending.command_type == TEE_V4_ADMIN_CMD_READ_LOCATIONS);
    tee_v4_admin_destroy(&admin);
}

static void test_malformed_intake_is_rejected_before_callback(void)
{
    struct tee_v3_policy_context policy;
    struct tee_v4_admin admin;
    struct intake_log log;
    uint8_t request[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
    struct tee_v4_admin_active_metadata_payload *payload =
        (void *)(request + sizeof(struct tee_v4_admin_request_header));
    struct tee_v4_admin_hmac_group_wire *groups = (void *)(payload + 1);
    size_t bytes;

    memset(&policy, 0, sizeof(policy));
    memset(&log, 0, sizeof(log));
    assert(tee_v4_admin_init(&admin, &policy,
                             TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES, 4096) == 0);
    tee_v4_admin_set_metadata_intake(&admin, record_intake, &log);

    bytes = make_intake(request, 310, 2);
    assert(tee_v4_admin_submit(&admin, request, bytes - 1) != 0);

    bytes = make_intake(request, 311, 2);
    payload->group_count = 1;
    resign(request, bytes);
    assert(tee_v4_admin_submit(&admin, request, bytes) != 0);

    bytes = make_intake(request, 312, 2);
    payload->reserved[0] = 1;
    resign(request, bytes);
    assert(tee_v4_admin_submit(&admin, request, bytes) != 0);

    bytes = make_intake(request, 313, 2);
    payload->segment_count = 0;
    resign(request, bytes);
    assert(tee_v4_admin_submit(&admin, request, bytes) != 0);

    bytes = make_intake(request, 314, 2);
    payload->number_coefficient = 0;
    resign(request, bytes);
    assert(tee_v4_admin_submit(&admin, request, bytes) != 0);

    bytes = make_intake(request, 315, 2);
    groups[1].start_segment_index = 4;
    groups[1].group_segment_count = 2;
    resign(request, bytes);
    assert(tee_v4_admin_submit(&admin, request, bytes) != 0);

    assert(log.calls == 0);
    tee_v4_admin_destroy(&admin);
}

int main(void)
{
    test_valid_intake_and_callback_failure_atomicity();
    test_malformed_intake_is_rejected_before_callback();
    puts("test_tee_v4_metadata_intake: PASS");
    return 0;
}
