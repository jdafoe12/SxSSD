#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Drive the actual static NVMe callbacks and policy handlers. */
#include "../tee-ftl-v5-policy.c"

static uint8_t host_input[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
static uint8_t host_output[TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES];
static uint32_t host_input_bytes;
static uint32_t host_output_bytes;

struct test_admin_command {
    uint8_t bytes[40];
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
};

static uint16_t read_command_buffer(struct NvmeCommandEvent *event,
                                    void *dst, uint32_t length)
{
    (void)event;
    if (length != host_input_bytes) return NVME_INVALID_FIELD | NVME_DNR;
    memcpy(dst, host_input, length);
    return NVME_SUCCESS;
}

static uint16_t write_command_buffer(struct NvmeCommandEvent *event,
                                     const void *src, uint32_t length)
{
    (void)event;
    assert(length <= sizeof(host_output));
    memcpy(host_output, src, length);
    host_output_bytes = length;
    return NVME_SUCCESS;
}

static uint16_t dispatch(uint8_t opcode, uint32_t request_bytes,
                         struct FtlPolicyAPI *api)
{
    struct test_admin_command command;
    struct NvmeCommandEvent event;

    memset(&command, 0, sizeof(command));
    memset(&event, 0, sizeof(event));
    command.cdw12 = request_bytes;
    event.opcode = opcode;
    event.is_admin = true;
    event.cmd = &command;
    host_input_bytes = request_bytes;
    host_output_bytes = 0;
    assert(tee_v5_admin_condition(NULL, &event, api, NULL));
    (void)tee_v5_admin_callback(NULL, &event, api, NULL);
    return event.status;
}

static size_t make_identity(uint16_t command, uint64_t request_id,
                            uint8_t file_id, uint32_t chunk_id)
{
    struct tee_v4_admin_request_header *header = (void *)host_input;
    struct tee_v5_chunk_identity_payload *payload = (void *)(header + 1);
    size_t bytes = sizeof(*header) + sizeof(*payload);

    memset(host_input, 0, sizeof(host_input));
    header->magic = TEE_V4_ADMIN_MAGIC;
    header->version = TEE_V4_ADMIN_VERSION;
    header->command_type = command;
    header->request_id = request_id;
    header->payload_len = sizeof(*payload);
    header->flags = TEE_V4_ADMIN_FLAG_SUBMIT;
    payload->file_id = file_id;
    payload->chunk_id = chunk_id;
    assert(tee_v4_admin_sign_request(host_input, bytes) == 0);
    return bytes;
}

static size_t make_query(uint16_t command, uint64_t request_id,
                         uint8_t file_id, uint32_t chunk_id)
{
    struct tee_v4_admin_request_header *header = (void *)host_input;
    struct tee_v4_admin_chunk_query_payload *payload = (void *)(header + 1);
    size_t bytes = sizeof(*header) + sizeof(*payload);

    memset(host_input, 0, sizeof(host_input));
    header->magic = TEE_V4_ADMIN_MAGIC;
    header->version = TEE_V4_ADMIN_VERSION;
    header->command_type = command;
    header->request_id = request_id;
    header->payload_len = sizeof(*payload);
    header->flags = TEE_V4_ADMIN_FLAG_SUBMIT;
    payload->file_id = file_id;
    payload->chunk_id = chunk_id;
    payload->page_size = 8;
    assert(tee_v4_admin_sign_request(host_input, bytes) == 0);
    return bytes;
}

static size_t make_fetch(uint16_t command, uint64_t request_id)
{
    struct tee_v4_admin_request_header *header = (void *)host_input;

    memset(host_input, 0, sizeof(host_input));
    header->magic = TEE_V4_ADMIN_MAGIC;
    header->version = TEE_V4_ADMIN_VERSION;
    header->command_type = command;
    header->request_id = request_id;
    header->flags = TEE_V4_ADMIN_FLAG_FETCH;
    assert(tee_v4_admin_sign_request(host_input, sizeof(*header)) == 0);
    return sizeof(*header);
}

static int32_t fetch_status(struct FtlPolicyAPI *api, uint16_t command,
                            uint64_t request_id)
{
    struct tee_v4_admin_response_header *response = (void *)host_output;
    size_t bytes = make_fetch(command, request_id);

    assert(dispatch(TEE_V4_ADMIN_FETCH_OPCODE, (uint32_t)bytes, api) ==
           NVME_SUCCESS);
    assert(host_output_bytes >= sizeof(*response));
    assert(response->command_type == command);
    assert(response->request_id == request_id);
    return response->status;
}

static size_t make_metadata(uint64_t request_id, uint8_t file_id,
                            uint32_t chunk_id,
                            const uint8_t segments[2][TEE_V2_DEFAULT_SEGMENT_SIZE])
{
    struct tee_v4_admin_request_header *header = (void *)host_input;
    struct tee_v4_admin_active_metadata_payload *payload =
        (void *)(header + 1);
    struct tee_v4_admin_hmac_group_wire *groups = (void *)(payload + 1);
    size_t payload_bytes = sizeof(*payload) + 2 * sizeof(*groups);
    size_t bytes = sizeof(*header) + payload_bytes;
    uint32_t i;

    memset(host_input, 0, sizeof(host_input));
    header->magic = TEE_V4_ADMIN_MAGIC;
    header->version = TEE_V4_ADMIN_VERSION;
    header->command_type = TEE_V4_ADMIN_CMD_SET_ACTIVE_METADATA;
    header->request_id = request_id;
    header->payload_len = (uint32_t)payload_bytes;
    header->flags = TEE_V4_ADMIN_FLAG_SUBMIT;
    payload->file_id = file_id;
    payload->chunk_id = chunk_id;
    payload->chunk_size_bytes = 2 * TEE_V2_DEFAULT_SEGMENT_SIZE;
    payload->segment_count = 2;
    payload->number_coefficient = 2;
    payload->group_count = 2;
    for (i = 0; i < 2; i++) {
        groups[i].start_segment_index = i + 1;
        groups[i].group_segment_count = 1;
        tee_v2_hmac_sha256(tee_v2_prototype_key,
                           TEE_V2_PROTOTYPE_KEY_SIZE, segments[i],
                           TEE_V2_DEFAULT_SEGMENT_SIZE,
                           groups[i].expected_hmac);
    }
    assert(tee_v4_admin_sign_request(host_input, bytes) == 0);
    return bytes;
}

static void prepare_segments(
    uint8_t file_id, uint32_t chunk_id,
    uint8_t segments[2][TEE_V2_DEFAULT_SEGMENT_SIZE])
{
    uint32_t i;
    for (i = 0; i < 2; i++) {
        memset(segments[i], (int)(0x31 + i), TEE_V2_DEFAULT_SEGMENT_SIZE);
        segments[i][0] = TEE_V2_SEGMENT_MAGIC;
        segments[i][1] = file_id;
        segments[i][2] = (uint8_t)chunk_id;
        segments[i][3] = (uint8_t)(chunk_id >> 8);
        segments[i][4] = (uint8_t)(chunk_id >> 16);
        segments[i][5] = (uint8_t)(i + 1);
        segments[i][6] = 0;
        segments[i][7] = 0;
        segments[i][8] = 0;
    }
}

static void submit_and_promote(struct FtlPolicyAPI *api, uint64_t request_id,
                               uint8_t file_id, uint32_t chunk_id,
                               uint64_t first_location)
{
    uint8_t segments[2][TEE_V2_DEFAULT_SEGMENT_SIZE];
    size_t bytes;
    uint32_t i;

    prepare_segments(file_id, chunk_id, segments);
    bytes = make_metadata(request_id, file_id, chunk_id, segments);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, api) ==
           NVME_SUCCESS);
    assert(g_v2_active_valid);
    for (i = 0; i < 2; i++) {
        enum tee_v2_write_result result = tee_v2_apply_segment_after_media(
            &g_v2_write, true, first_location + i, segments[i],
            TEE_V2_DEFAULT_SEGMENT_SIZE);
        assert(result != TEE_V2_WRITE_ERROR &&
               result != TEE_V2_WRITE_REJECTED);
    }
    assert(g_v2_write.active_promoted);
    assert(tee_v2_cache_find_passive(&g_v2_cache, file_id, chunk_id));
}

static int fail_image_write(void *opaque, const uint8_t *data, size_t size)
{
    (void)opaque;
    (void)data;
    (void)size;
    return -1;
}

static int fail_transaction_flush(
    void *opaque, const struct tee_v4_transaction_record *records,
    uint32_t count)
{
    (void)opaque;
    (void)records;
    (void)count;
    return -1;
}

static void initialize_policy_state(void)
{
    struct tee_v2_active_metadata bootstrap;
    struct tee_v2_hmac_group_spec group;
    uint8_t hmac[TEE_V2_HMAC_SIZE] = {0};

    assert(tee_v1_segment_layout_init(&g_v1_layout, 300, 512, 64));
    assert(tee_v2_format_config_init(&g_v2_config,
                                     TEE_V2_DEFAULT_SEGMENT_SIZE, 4096));
    group.start_segment_index = 1;
    group.group_segment_count = 1;
    group.expected_hmac = hmac;
    assert(tee_v2_active_metadata_init(&bootstrap, &g_v2_config,
                                       99, 1, 512, 1, 1,
                                       &group, 1) == 0);
    assert(tee_v2_cache_init(&g_v2_cache, g_v1_layout.visible_segments, 8) == 0);
    assert(tee_v2_write_context_init(&g_v2_write, &bootstrap, &g_v2_cache,
                                     g_v1_layout.visible_segments) == 0);
    g_v2_active = bootstrap;
    g_v2_active_valid = true;
    g_v2_write.active = &g_v2_active;

    g_v4_backend.capacity = (size_t)(g_v1_layout.hidden_lba_count *
                                     g_v1_layout.lba_size);
    g_v4_backend.bytes = calloc(g_v4_backend.capacity, 1);
    assert(g_v4_backend.bytes);
    assert(tee_v3_storage_init(&g_v4_storage, &g_v1_layout,
                               tee_v4_write_hidden_image,
                               &g_v4_backend) == 0);
    tee_v3_policy_context_init(&g_v4_policy, &g_v2_write, &g_v4_storage);
    assert(tee_v4_writeback_init(&g_v4_writeback,
                                 g_v4_pending_transactions,
                                 TEE_V4_DEFAULT_RELOCATION_BATCH_MAX,
                                 TEE_V4_DEFAULT_RELOCATION_TIMEOUT_OPS,
                                 tee_v4_flush_transactions,
                                 &g_v4_policy) == 0);
    tee_v2_write_set_promotion_hook(&g_v2_write, tee_v4_persist_promotion,
                                    &g_v4_policy);
    assert(tee_v5_admin_init(&g_v5_admin, &g_v4_policy,
                             TEE_V4_ADMIN_DEFAULT_BUFFER_BYTES,
                             TEE_V4_RESPONSE_ITEM_BYTES) == 0);
    tee_v4_admin_set_writeback(&g_v5_admin.v4, &g_v4_writeback);
    tee_v4_admin_set_metadata_intake(&g_v5_admin.v4,
                                     tee_v4_intake_active_metadata, NULL);
    tee_v5_admin_set_abort_handler(&g_v5_admin,
                                   tee_v5_abort_active_handler, NULL);
    tee_v5_admin_set_delete_handler(&g_v5_admin,
                                    tee_v5_delete_chunk_handler,
                                    &g_v4_policy);
}

static void test_continuous_v1_to_v5_nvme_flow(void)
{
    struct FtlPolicyAPI api;
    struct tee_v4_admin_response_header *response = (void *)host_output;
    struct tee_v3_one_bit_proof *proof = (void *)(response + 1);
    struct tee_v2_passive_metadata *record;
    uint8_t bitmap_before[64];
    uint64_t locations_before[2];
    size_t bytes;

    memset(&api, 0, sizeof(api));
    api.read_cmd_buffer = read_command_buffer;
    api.write_cmd_buffer = write_command_buffer;
    initialize_policy_state();

    submit_and_promote(&api, 100, 12, 34, 101);
    bytes = make_query(TEE_V4_ADMIN_CMD_READ_SUMMARY, 101, 12, 34);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, TEE_V4_ADMIN_CMD_READ_SUMMARY, 101) ==
           TEE_V5_STATUS_OK);

    /* Promotion leaves matching active identity: DELETE must not abort it. */
    bytes = make_identity(TEE_V5_ADMIN_CMD_DELETE, 102, 12, 34);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, TEE_V5_ADMIN_CMD_DELETE, 102) ==
           TEE_V5_STATUS_BAD_REQUEST);
    assert(g_v2_active_valid);
    assert(tee_v2_cache_find_passive(&g_v2_cache, 12, 34));

    bytes = make_identity(TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 103, 12, 34);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 103) ==
           TEE_V5_STATUS_OK);
    assert(!g_v2_active_valid);

    bytes = make_identity(TEE_V5_ADMIN_CMD_DELETE, 104, 12, 34);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, TEE_V5_ADMIN_CMD_DELETE, 104) ==
           TEE_V5_STATUS_OK);
    assert(!tee_v2_cache_find_passive(&g_v2_cache, 12, 34));
    assert(!tee_v2_cache_is_protected(&g_v2_cache, 101));
    assert(!tee_v2_cache_is_protected(&g_v2_cache, 102));

    bytes = make_query(TEE_V4_ADMIN_CMD_READ_SUMMARY, 105, 12, 34);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, TEE_V4_ADMIN_CMD_READ_SUMMARY, 105) ==
           TEE_V5_STATUS_NOT_FOUND);
    bytes = make_query(TEE_V4_ADMIN_CMD_ONE_BIT_PROOF, 106, 12, 34);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, TEE_V4_ADMIN_CMD_ONE_BIT_PROOF, 106) ==
           TEE_V5_STATUS_NOT_FOUND);

    submit_and_promote(&api, 107, 13, 35, 111);
    bytes = make_identity(TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 108, 13, 35);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 108) ==
           TEE_V5_STATUS_OK);
    record = tee_v2_cache_find_passive(&g_v2_cache, 13, 35);
    assert(record && record->segment_count == 2);

    /* Keep a second passive chunk to prove V5 policy errors stay scoped. */
    submit_and_promote(&api, 120, 14, 36, 121);
    bytes = make_identity(TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 121, 14, 36);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, TEE_V5_ADMIN_CMD_ABORT_ACTIVE, 121) ==
           TEE_V5_STATUS_OK);

    record = tee_v2_cache_find_passive(&g_v2_cache, 13, 35);
    assert(record && record->segment_count == 2);
    assert(g_v2_cache.protected_bitmap.byte_count <= sizeof(bitmap_before));
    memcpy(bitmap_before, g_v2_cache.protected_bitmap.bits,
           g_v2_cache.protected_bitmap.byte_count);
    memcpy(locations_before, record->segment_locations,
           sizeof(locations_before));
    g_v4_storage.write = fail_image_write;

    bytes = make_identity(TEE_V5_ADMIN_CMD_DELETE, 122, 13, 35);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_INTERNAL_DEV_ERROR);
    assert((NVME_INTERNAL_DEV_ERROR & NVME_DNR) == 0);
    record = tee_v2_cache_find_passive(&g_v2_cache, 13, 35);
    assert(record && record->segment_count == 2);
    assert(memcmp(record->segment_locations, locations_before,
                  sizeof(locations_before)) == 0);
    assert(memcmp(g_v2_cache.protected_bitmap.bits, bitmap_before,
                  g_v2_cache.protected_bitmap.byte_count) == 0);

    bytes = make_query(TEE_V4_ADMIN_CMD_ONE_BIT_PROOF, 123, 13, 35);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, TEE_V4_ADMIN_CMD_ONE_BIT_PROOF, 123) ==
           TEE_V5_STATUS_OK);
    assert(proof->state == TEE_V3_PROOF_ERROR);
    assert(proof->last_error_code == TEE_V5_PROOF_ERROR_PERSISTENCE_FAILURE);
    assert(proof->failed_segment_index == TEE_V5_NO_FAILED_SEGMENT);

    bytes = make_query(TEE_V4_ADMIN_CMD_ONE_BIT_PROOF, 124, 14, 36);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, TEE_V4_ADMIN_CMD_ONE_BIT_PROOF, 124) ==
           TEE_V5_STATUS_OK);
    assert(proof->state == TEE_V3_PROOF_DONE);
    assert(proof->done_bit == 1);

    /* The policy must retain more than eight simultaneously supported
     * failure identities (bounded by 64 passive entries plus one active). */
    tee_v5_proof_clear_error(&g_v4_policy.pending, 13, 35);
    for (uint32_t i = 0; i < 9; i++) {
        uint32_t missing = 0;
        size_t missing_written = 0;

        g_v2_active_valid = true;
        g_v2_active.file_id = (uint8_t)(40 + i);
        g_v2_active.chunk_id = 4000 + i;
        assert(tee_v5_delete_chunk_handler(&g_v4_policy,
                                           g_v2_active.file_id,
                                           g_v2_active.chunk_id) == 2);
        assert(tee_v3_one_bit_proof_query(
                   &g_v4_policy.pending, g_v2_active.file_id,
                   g_v2_active.chunk_id, 0, &missing, 1,
                   &missing_written, proof) == TEE_V3_QUERY_OK);
        assert(proof->state == TEE_V3_PROOF_ERROR);
        assert(proof->last_error_code == TEE_V5_PROOF_ERROR_DELETE_CONFLICT);
    }
    g_v2_active_valid = false;

    /* DELETE existence is resolved before writeback synchronization. An
     * absent identity remains NOT_FOUND even with a failing pending flush,
     * and must not consume a proof-error slot. */
    assert(tee_v4_writeback_record_relocation(&g_v4_writeback, 1, 1, 1,
                                               10, 11) == 0);
    g_v4_writeback.flush = fail_transaction_flush;
    assert(tee_v5_delete_chunk_handler(&g_v4_policy, 90, 9000) == 1);
    {
        uint32_t missing = 0;
        size_t missing_written = 0;
        assert(tee_v3_one_bit_proof_query(&g_v4_policy.pending, 90, 9000,
                                           0, &missing, 1,
                                           &missing_written, proof) ==
               TEE_V3_QUERY_NOT_FOUND);
    }

    /* No-pending response and unsupported command remain explicit. */
    assert(fetch_status(&api, 99, 999) ==
           TEE_V5_STATUS_NO_PENDING_RESPONSE);
    bytes = make_identity(99, 125, 1, 1);
    assert(dispatch(TEE_V4_ADMIN_SUBMIT_OPCODE, (uint32_t)bytes, &api) ==
           NVME_SUCCESS);
    assert(fetch_status(&api, 99, 125) == TEE_V5_STATUS_UNSUPPORTED);

    tee_v5_admin_destroy(&g_v5_admin);
    tee_v2_write_context_destroy(&g_v2_write);
    tee_v2_cache_destroy(&g_v2_cache);
    if (g_v2_active_valid) tee_v2_active_metadata_destroy(&g_v2_active);
    free(g_v4_backend.bytes);
}

int main(void)
{
    test_continuous_v1_to_v5_nvme_flow();
    puts("test_tee_v5_policy_flow: PASS");
    return 0;
}
